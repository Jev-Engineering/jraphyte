"""Windows SID/SDDL trustee-alias regressions for the v1/v4 phase fences and the
packaged phase-authority receipt validator.

Windows serializes some numeric SIDs in a DACL string as SDDL aliases (the
Users group S-1-5-32-545 is ``BU``; a machine's built-in Administrator, RID 500,
is ``LA``). The v1 fence, the v4 guarded fence and ``PhaseAuthority.verify_fence``
must recognize their own deny ACE under either spelling while still rejecting a
different trustee (including a distinct account/domain SID that shares RID 500),
mask, ACE type, inheritance flag or digest.

Every fixture is a fresh owned temporary directory. Only ACEs this test added
to files and directories beneath it are ever removed, in ``finally``-equivalent
cleanup; no ancestor or shared ACL is changed. Identities that are not the
running account are only ever *represented* in real DACLs here; actual denied
opens are asserted for the group alias (the process token holds Users) and for
the process's own natural identity, never claimed for a simulated identity.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from trace_gc import phase_authority as authority
from trace_gc.canonical import bytes_digest, dumps
from trace_gc.errors import ContractError
from trace_gc.phase_authority import PhaseAuthority, directory_dacl_sddl

WINDOWS = os.name == "nt"
USERS_SID = "S-1-5-32-545"      # serialized by Windows as the alias BU
GUESTS_SID = "S-1-5-32-546"     # an unrelated trustee, serialized as BG
FOREIGN_RID500_SID = "S-1-5-21-1111111111-2222222222-3333333333-500"  # fabricated domain
PARENT_ACE = "(D;;LC;;;{sid})"
FILE_ACE = "(D;;DCLC;;;{sid})"
TEMP_PREFIX = "jraphyte-phase-trustee-"
NAMES = ("checkpoint.sqlite3", "graph.sqlite3", "budget.sqlite3",
         "application-journal.sqlite3", "controller.lock")


def _call(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(list(args), capture_output=True, text=True, timeout=30)


def _icacls(*args: str) -> None:
    result = _call("icacls.exe", *args)
    assert result.returncode == 0, result.stderr or result.stdout


def _current_sid() -> str:
    from src.paper_pilot_phase_cutover import _current_sid as current
    return current()


def _account_prefix() -> str:
    prefix = re.fullmatch(r"(S-1-5-21-\d+-\d+-\d+)-\d+", _current_sid())
    assert prefix is not None, "test requires a machine/domain account SID"
    return prefix.group(1)


def _local_rid500_sid() -> str:
    # The runner's account domain's built-in Administrator, derived from the
    # runner's own SID so no account lookup or account change is needed.
    return _account_prefix() + "-500"


def _plain_account_sid() -> str:
    current = _current_sid()
    return current if not current.endswith("-500") else _account_prefix() + "-1001"


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


class OwnedTree:
    """A disposable tree whose every ACL edit is confined beneath ``base``."""

    def __init__(self, test: unittest.TestCase):
        self.test = test
        self.temp = tempfile.TemporaryDirectory(prefix=TEMP_PREFIX)
        test.addCleanup(self.cleanup)
        self.base = Path(self.temp.name)
        assert self.base.name.startswith(TEMP_PREFIX)
        self.sids = {USERS_SID, GUESTS_SID, _current_sid(), _local_rid500_sid()}

    def owned(self, path: Path) -> Path:
        resolved = Path(path).resolve()
        if not resolved.is_relative_to(self.base.resolve()):
            raise AssertionError(f"refusing ACL change outside fixture: {path}")
        return resolved

    def cleanup(self):
        # Lift only the deny/allow ACEs this test could have added; the tree is
        # then removed. The temporary directory's own ancestors are never edited.
        for path in [self.base, *self.base.rglob("*")]:
            if path.exists() and path != self.base:
                for sid in self.sids:
                    _call("icacls.exe", str(self.owned(path)), "/remove:d", "*" + sid)
                # The one explicit grant any case adds (Users, on its own parent).
                _call("icacls.exe", str(self.owned(path)), "/remove:g", "*" + USERS_SID)
        self.temp.cleanup()
        self.test.assertFalse(self.base.exists())


def _authority(receipt: Path, old: Path, archived: Path) -> PhaseAuthority:
    """The exact receipt-validation context: binding fields verify_fence reads."""
    instance = object.__new__(PhaseAuthority)
    instance.binding = {"fence_receipt_path": str(receipt),
                        "fence_receipt_sha256": bytes_digest(receipt.read_bytes()),
                        "old_root_path": str(old), "archived_old_root_path": str(archived)}
    instance._archived_lock_file = None
    return instance


class _Identity:
    """Pin the fence's current-owner seam to one SID, or leave it natural."""
    def __init__(self, module, sid):
        self.module, self.sid = module, sid

    def __enter__(self):
        self.patch = (patch.object(self.module, "_current_sid", return_value=self.sid)
                      if self.sid is not None else None)
        if self.patch:
            self.patch.start()

    def __exit__(self, *exc):
        if self.patch:
            self.patch.stop()


@unittest.skipUnless(WINDOWS, "Windows SID/SDDL contract")
class SharedTrusteeHelperTests(unittest.TestCase):
    def test_real_windows_serialization_of_builtin_and_foreign_sids(self):
        self.assertEqual(authority.canonical_dacl_trustee(USERS_SID), "BU")
        self.assertEqual(authority.canonical_dacl_trustee("S-1-5-18"), "SY")
        self.assertEqual(authority.canonical_dacl_trustee("S-1-1-0"), "WD")
        self.assertEqual(authority.canonical_dacl_trustee("BU"), "BU")
        self.assertEqual(authority.canonical_dacl_trustee("S-1-5-21-1-2-3-1001"),
                         "S-1-5-21-1-2-3-1001")
        injected = "S-1-5-18)(A;;FA;;;WD"
        self.assertEqual(authority.canonical_dacl_trustee(injected), injected)
        self.assertEqual(authority.canonical_dacl_trustee(FOREIGN_RID500_SID),
                         FOREIGN_RID500_SID)

    def test_distinct_rid500_accounts_never_collapse(self):
        local, foreign, plain = _local_rid500_sid(), FOREIGN_RID500_SID, _plain_account_sid()
        near = (_account_prefix().rsplit("-", 1)[0] + "-"
                + str(int(_account_prefix().rsplit("-", 1)[1]) + 1) + "-500")
        canonical = {sid: authority.canonical_dacl_trustee(sid)
                     for sid in (local, foreign, plain, near)}
        self.assertEqual(len(set(canonical.values())), 4, canonical)
        self.assertEqual(canonical[foreign], foreign)
        self.assertEqual(canonical[near], near)
        sids = {"local": local, "foreign": foreign, "plain": plain, "near": near}
        for ace_name, ace_sid in sids.items():
            for spelling in (canonical[ace_sid], ace_sid):   # alias form and numeric form
                parent = "D:AI(D;;LC;;;" + spelling + ")(A;OICIID;FA;;;SY)"
                file = "D:AI(D;;DCLC;;;" + spelling + ")(A;ID;FA;;;SY)"
                for query_name, query_sid in sids.items():
                    same = ace_name == query_name
                    label = (ace_name, spelling, query_name)
                    self.assertEqual(authority.dacl_has_ace(parent, PARENT_ACE, query_sid),
                                     same, label)
                    self.assertEqual(authority.dacl_has_ace(file, FILE_ACE, query_sid),
                                     same, label)
                    self.assertEqual(authority.dacl_has_deny_trustee(parent, query_sid),
                                     same, label)

    def test_only_the_trustee_field_is_normalized(self):
        self.assertTrue(authority.dacl_has_ace("D:(D;;LC;;;BU)", PARENT_ACE, USERS_SID))
        self.assertTrue(authority.dacl_has_ace("D:(D;;LC;;;" + USERS_SID + ")",
                                               PARENT_ACE, USERS_SID))
        for text in ("D:(D;;LC;;;BG)",            # different trustee
                     "D:(D;;DC;;;BU)",            # different mask
                     "D:(D;;LCWP;;;BU)",          # broader mask
                     "D:(D;OI;LC;;;BU)",          # inheritance flag added
                     "D:(D;CI;LC;;;BU)",
                     "D:(A;;LC;;;BU)",            # allow, not deny
                     "D:(OD;;LC;;;BU)"):          # object deny
            self.assertFalse(authority.dacl_has_ace(text, PARENT_ACE, USERS_SID), text)
        self.assertFalse(authority.dacl_has_ace("D:(D;;LC;;;BU)", FILE_ACE, USERS_SID))
        # ACE order and extra ACEs stay visible to the caller's list comparison.
        self.assertEqual(authority.canonical_dacl_aces("D:AI(D;;LC;;;BU)(A;ID;FA;;;SY)"),
                         ["(D;;LC;;;BU)", "(A;ID;FA;;;SY)"])
        self.assertEqual(authority.canonical_dacl_aces(
            "D:(A;ID;FA;;;SY)(D;;LC;;;" + USERS_SID + ")"),
            ["(A;ID;FA;;;SY)", "(D;;LC;;;BU)"])
        # An allow ACE or a deny of another trustee is not an owner deny.
        self.assertFalse(authority.dacl_has_deny_trustee("D:(A;;FA;;;BU)", USERS_SID))
        self.assertFalse(authority.dacl_has_deny_trustee("D:(D;;FX;;;BA)", USERS_SID))
        self.assertTrue(authority.dacl_has_deny_trustee("D:(D;;FX;;;BU)", USERS_SID))

    def test_matches_the_reviewed_v2_canonicalization(self):
        from src import paper_pilot_phase_cutover_guarded_v2 as v2
        for sid in (USERS_SID, "S-1-5-18", "S-1-1-0", _local_rid500_sid(),
                    FOREIGN_RID500_SID, _plain_account_sid(), "BU", "LA"):
            self.assertEqual(authority.canonical_dacl_trustee(sid),
                             v2._canonical_trustee(sid), sid)


class OffWindowsContractTests(unittest.TestCase):
    """The same contract on every platform: no OS, no numeric-SID guessing."""

    def test_numeric_sid_fails_closed_without_windows(self):
        with patch.object(authority, "_is_windows", return_value=False):
            for sid in (USERS_SID, FOREIGN_RID500_SID, "S-1-5-21-1-2-3-500"):
                with self.assertRaises(ContractError) as caught:
                    authority.canonical_dacl_trustee(sid)
                self.assertEqual(caught.exception.code, "PHASE_PLATFORM")
            # A literal LA is never mapped to a caller-selected numeric SID, in
            # either direction: the numeric query cannot be answered, not guessed.
            with self.assertRaises(ContractError):
                authority.dacl_has_ace("D:(D;;LC;;;LA)", PARENT_ACE, FOREIGN_RID500_SID)
            with self.assertRaises(ContractError):
                authority.canonical_dacl_aces("D:(D;;LC;;;" + FOREIGN_RID500_SID + ")")

    def test_alias_and_non_sid_text_pass_through_without_windows(self):
        with patch.object(authority, "_is_windows", return_value=False):
            for text in ("LA", "BU", "SY", "S-1-5-18)(A;;FA;;;WD", "", "S-1-5"):
                self.assertEqual(authority.canonical_dacl_trustee(text), text)
            self.assertTrue(authority.dacl_has_ace("D:(D;;LC;;;BU)", PARENT_ACE, "BU"))
            self.assertFalse(authority.dacl_has_ace("D:(D;;LC;;;BU)", PARENT_ACE, "LA"))
            self.assertFalse(authority.dacl_has_ace("D:(D;;LC;;;LA)", PARENT_ACE, "BA"))


@unittest.skipUnless(WINDOWS, "Windows NTFS DACL contract")
class ReceiptValidatorTests(unittest.TestCase):
    """PhaseAuthority.verify_fence against a real DACL spelled by Windows."""

    def setUp(self):
        self.tree = OwnedTree(self)
        base = self.tree.base
        self.parent = base / "old-app"
        self.old = self.parent / "state"
        self.archived = base / "archive" / "state"
        self.parent.mkdir()
        self.archived.mkdir(parents=True)
        self.files = {}
        for name in NAMES:
            body = ("validator:" + name).encode()
            (self.archived / name).write_bytes(body)
            self.files[name] = bytes_digest(body)
        self.receipt = base / "fence.json"

    def _write_receipt(self, deny_sid, *, dacl_sha=None, files=None):
        raw = directory_dacl_sddl(self.parent)
        body = {"version": "paper-pilot-phase-namespace-fence-v1",
                "old_root_path": str(self.old), "archived_root_path": str(self.archived),
                "old_parent_dacl_sha256": dacl_sha or bytes_digest(raw.encode("utf-8")),
                "archived_files_sha256": files or self.files,
                "deny_sid": deny_sid, "status": "OLD_PATH_FENCED_NEW_PHASE_ALLOWED"}
        self.receipt.write_bytes((dumps(body) + "\n").encode("utf-8"))
        return raw

    def _verify(self):
        _authority(self.receipt, self.old, self.archived).verify_fence()

    def _rejected(self):
        with self.assertRaises(ContractError) as caught:
            self._verify()
        self.assertEqual(caught.exception.code, "PHASE_FENCE")

    def test_group_alias_parent_deny_is_accepted_with_raw_digest_pin(self):
        _icacls(str(self.parent), "/deny", "*" + USERS_SID + ":(AD)")
        raw = self._write_receipt(USERS_SID)
        # The OS really spells the numeric receipt SID as the alias, so a
        # literal numeric substring cannot be found; the receipt digest still
        # pins the raw, un-normalized serialization.
        self.assertIn("(D;;LC;;;BU)", raw)
        self.assertNotIn(USERS_SID, raw)
        self.assertEqual(json_digest(self.receipt, "old_parent_dacl_sha256"),
                         bytes_digest(raw.encode("utf-8")))
        self._verify()

    def test_machine_rid500_parent_deny_is_accepted(self):
        sid = _local_rid500_sid()
        _icacls(str(self.parent), "/deny", "*" + sid + ":(AD)")
        self._write_receipt(sid)
        self._verify()

    def test_natural_runner_identity_parent_deny_is_accepted(self):
        sid = _current_sid()   # LA on a hosted RID-500 runner, numeric otherwise
        _icacls(str(self.parent), "/deny", "*" + sid + ":(AD)")
        self._write_receipt(sid)
        self._verify()

    def test_distinct_rid500_and_other_trustees_are_not_the_receipt_trustee(self):
        local = _local_rid500_sid()
        _icacls(str(self.parent), "/deny", "*" + local + ":(AD)")
        for wrong in (FOREIGN_RID500_SID, _plain_account_sid(), USERS_SID, GUESTS_SID):
            if wrong == local:
                continue
            self._write_receipt(wrong)
            self._rejected()
        self._write_receipt(local)
        self._verify()

    def test_wrong_trustee_alias_deny_is_rejected(self):
        _icacls(str(self.parent), "/deny", "*" + GUESTS_SID + ":(AD)")
        self._write_receipt(USERS_SID)
        self._rejected()

    def test_wrong_mask_flags_or_type_are_rejected(self):
        for args in (("/deny", "*" + USERS_SID + ":(WD)"),            # different mask
                     ("/deny", "*" + USERS_SID + ":(OI)(AD)"),        # inheritance flag
                     ("/grant", "*" + USERS_SID + ":(AD)")):          # allow, not deny
            _icacls(str(self.parent), "/remove:d", "*" + USERS_SID)
            _icacls(str(self.parent), "/remove:g", "*" + USERS_SID)
            _icacls(str(self.parent), *args)
            self._write_receipt(USERS_SID)
            self._rejected()

    def test_absent_deny_and_changed_pins_are_rejected(self):
        self._write_receipt(USERS_SID)
        self._rejected()                                              # no deny at all
        _icacls(str(self.parent), "/deny", "*" + USERS_SID + ":(AD)")
        self._write_receipt(USERS_SID, dacl_sha="0" * 64)
        self._rejected()                                              # raw digest pin
        self._write_receipt(USERS_SID)
        self._verify()
        (self.archived / "graph.sqlite3").write_bytes(b"changed")
        self._rejected()                                              # archive bytes pin


def json_digest(path: Path, key: str) -> str:
    from trace_gc.canonical import loads
    return loads(path.read_bytes())[key]


class _FenceCase(unittest.TestCase):
    """Shared owned layout for the v1 and v4 entry points."""

    module = None

    def setUp(self):
        if not WINDOWS:
            self.skipTest("Windows ACL contract")
        self.tree = OwnedTree(self)
        base = self.tree.base
        self.parent = base / "old-app"
        self.old = self.parent / "state"
        self.archive = base / "archive" / "state"
        self.receipts = base / "receipts"
        self.old.mkdir(parents=True)
        self.archive.parent.mkdir()
        self.receipts.mkdir()
        self.content = {}
        for name in NAMES:
            body = b"0" if name == "controller.lock" else ("owned:" + name).encode()
            (self.old / name).write_bytes(body)
            self.content[name] = bytes_digest(body)
        for name in ("source-stage.lock", "phase-stage.lock"):
            (self.parent / name).write_bytes(b"0")
        self._pin()

    def _pin(self):
        self.parent_acl_sha = _sha(directory_dacl_sddl(self.parent))
        self.file_acl_sha = {name: _sha(directory_dacl_sddl(self.old / name))
                             for name in NAMES}

    def identity(self, sid):
        return _Identity(self.module, sid)

    def archived_hashes(self):
        return {name: bytes_digest((self.archive / name).read_bytes()) for name in NAMES}

    def assert_validator_accepts(self, receipt: Path):
        _authority(receipt, self.old, self.archive).verify_fence()

    def attempt_open(self, path: Path) -> subprocess.CompletedProcess:
        return _call(sys.executable, "-c",
                     "from pathlib import Path; import sys; Path(sys.argv[1]).open('a+b').close()",
                     str(path))


class V1FenceTrusteeTests(_FenceCase):
    @classmethod
    def setUpClass(cls):
        from src import paper_pilot_phase_cutover as module
        cls.module = module

    def setUp(self):
        super().setUp()
        self.archive = self.tree.base / "archive" / "historical-state"
        self.receipt = self.tree.base / "control" / "fence-receipt.json"
        self.receipt.parent.mkdir()

    def invoke(self, sid):
        return self.module.fence_closed_old_phase(
            old_root=self.old, archived_root=self.archive,
            expected_file_sha256=self.content, deny_sid=sid, receipt_path=self.receipt)

    def test_group_alias_identity_fences_replays_and_validates(self):
        with self.identity(USERS_SID):
            first = self.invoke(USERS_SID)
            self.assertEqual(first["status"], "OLD_PATH_FENCED_NEW_PHASE_ALLOWED")
            raw = directory_dacl_sddl(self.parent)
            self.assertIn("(D;;LC;;;BU)", raw)
            self.assertFalse(self.old.exists())
            self.assertEqual(self.archived_hashes(), self.content)
            # Live denial: Users is in this process token, so recreation is refused.
            with self.assertRaises((PermissionError, OSError)):
                self.old.mkdir()
            self.assertEqual(first, self.invoke(USERS_SID))
        # The receipt keeps the numeric SID and the raw (alias-spelled) digest.
        from trace_gc.canonical import loads
        body = loads(self.receipt.read_bytes())
        self.assertEqual(body["deny_sid"], USERS_SID)
        self.assertEqual(body["old_parent_dacl_sha256"], bytes_digest(raw.encode("utf-8")))
        self.assert_validator_accepts(self.receipt)

    def test_crash_after_parent_deny_retries_to_the_identical_receipt(self):
        with self.identity(USERS_SID):
            with patch.object(self.module.os, "rename",
                              side_effect=PermissionError("injected rename failure")):
                with self.assertRaises(PermissionError):
                    self.invoke(USERS_SID)
            self.assertTrue(self.old.exists())
            self.assertFalse(self.archive.exists())
            self.assertFalse(self.receipt.exists())
            self.assertIn("(D;;LC;;;BU)", directory_dacl_sddl(self.parent))
            recovered = self.invoke(USERS_SID)
            self.assertEqual(recovered["status"], "OLD_PATH_FENCED_NEW_PHASE_ALLOWED")
            self.assertEqual(recovered, self.invoke(USERS_SID))
        self.assertEqual(self.archived_hashes(), self.content)
        self.assert_validator_accepts(self.receipt)

    def test_unrelated_parent_deny_is_preserved_and_does_not_satisfy_the_barrier(self):
        _icacls(str(self.parent), "/deny", "*" + GUESTS_SID + ":(AD)")
        with self.identity(USERS_SID):
            self.assertNotIn("(D;;LC;;;BU)", directory_dacl_sddl(self.parent))
            self.assertEqual(self.invoke(USERS_SID)["status"],
                             "OLD_PATH_FENCED_NEW_PHASE_ALLOWED")
        raw = directory_dacl_sddl(self.parent)
        self.assertIn("(D;;LC;;;BG)", raw)
        self.assertIn("(D;;LC;;;BU)", raw)
        self.assert_validator_accepts(self.receipt)

    def test_machine_rid500_identity_fences_and_validates(self):
        # Representation evidence for the LA spelling: the process is not this
        # account, so no denied-open is claimed for it here.
        sid = _local_rid500_sid()
        with self.identity(sid):
            result = self.invoke(sid)
            self.assertEqual(result["status"], "OLD_PATH_FENCED_NEW_PHASE_ALLOWED")
            self.assertTrue(authority.dacl_has_ace(
                directory_dacl_sddl(self.parent), PARENT_ACE, sid))
            self.assertEqual(result, self.invoke(sid))
        self.assert_validator_accepts(self.receipt)

    def test_natural_runner_identity_fences_with_live_denied_recreation(self):
        sid = _current_sid()   # LA on a hosted RID-500 runner
        result = self.invoke(sid)
        self.assertEqual(result["status"], "OLD_PATH_FENCED_NEW_PHASE_ALLOWED")
        self.assertTrue(authority.dacl_has_ace(
            directory_dacl_sddl(self.parent), PARENT_ACE, sid))
        with self.assertRaises((PermissionError, OSError)):
            self.old.mkdir()
        self.assertEqual(result, self.invoke(sid))
        self.assertEqual(self.archived_hashes(), self.content)
        self.assert_validator_accepts(self.receipt)

    def test_wrong_hash_still_holds_before_any_acl_change(self):
        before = directory_dacl_sddl(self.parent)
        with self.identity(USERS_SID):
            with self.assertRaises(ContractError):
                self.module.fence_closed_old_phase(
                    old_root=self.old, archived_root=self.archive,
                    expected_file_sha256={**self.content, "graph.sqlite3": "0" * 64},
                    deny_sid=USERS_SID, receipt_path=self.receipt)
        self.assertEqual(directory_dacl_sddl(self.parent), before)
        self.assertTrue(self.old.exists())
        self.assertFalse(self.receipt.exists())

    def test_sid_that_is_not_the_current_owner_is_rejected(self):
        before = directory_dacl_sddl(self.parent)
        with self.identity(USERS_SID):
            with self.assertRaises(ContractError):
                self.invoke(GUESTS_SID)
        self.assertEqual(directory_dacl_sddl(self.parent), before)
        self.assertTrue(self.old.exists())


class V4FenceTrusteeTests(_FenceCase):
    @classmethod
    def setUpClass(cls):
        from src import paper_pilot_phase_cutover_guarded_v4 as module
        cls.module = module

    def setUp(self):
        super().setUp()
        self.receipts = self.tree.base / "receipts"

    def invoke(self, sid):
        return self.module.fence_closed_old_phase_guarded(
            old_root=self.old, archived_root=self.archive,
            expected_file_sha256=self.content,
            source_stage_lock=self.parent / "source-stage.lock",
            phase_stage_lock=self.parent / "phase-stage.lock", deny_sid=sid,
            expected_parent_dacl_sha256=self.parent_acl_sha,
            expected_file_dacl_sha256=self.file_acl_sha,
            barrier_receipt_path=self.receipts / "barrier.json",
            fence_receipt_path=self.receipts / "fence.json")

    def test_group_alias_identity_fences_with_live_denials_replays_and_validates(self):
        seen = {}
        actual_rename = self.module.os.rename

        def observe_then_rename(source, destination):
            for name in NAMES:
                seen[name] = self.attempt_open(self.old / name).returncode != 0
            return actual_rename(source, destination)
        with self.identity(USERS_SID):
            with patch.object(self.module.os, "rename", side_effect=observe_then_rename):
                result = self.invoke(USERS_SID)
            self.assertEqual(result["status"], "OLD_PATH_FENCED_NEW_PHASE_ALLOWED")
            self.assertEqual(seen, {name: True for name in NAMES}, seen)
            raw = directory_dacl_sddl(self.parent)
            self.assertIn("(D;;LC;;;BU)", raw)
            self.assertFalse(self.old.exists())
            self.assertEqual(self.archived_hashes(), self.content)
            for name in NAMES:       # per-file denies are restored away in the archive
                self.assertFalse(self.module._file_deny(self.archive / name, USERS_SID))
            self.assertEqual(result, self.invoke(USERS_SID))
        from trace_gc.canonical import loads
        recorded = loads((self.receipts / "barrier.json").read_bytes())
        self.assertEqual(recorded["sid"], USERS_SID)
        self.assertEqual(loads((self.receipts / "fence.json").read_bytes())
                         ["old_parent_dacl_sha256"], bytes_digest(raw.encode("utf-8")))
        self.assert_validator_accepts(self.receipts / "fence.json")

    def test_crash_after_first_alias_deny_replays(self):
        actual = self.module._icacls
        calls = {"count": 0}

        def first_deny_then_crash(path, *args):
            actual(path, *args)
            calls["count"] += 1
            if calls["count"] == 1:
                raise RuntimeError("injected post-controller-deny crash")
        with self.identity(USERS_SID):
            with patch.object(self.module, "_icacls", side_effect=first_deny_then_crash):
                with self.assertRaisesRegex(RuntimeError, "injected"):
                    self.invoke(USERS_SID)
            self.assertIn("(D;;DCLC;;;BU)",
                          directory_dacl_sddl(self.old / "controller.lock"))
            self.assertTrue(self.module._file_deny(self.old / "controller.lock", USERS_SID))
            self.assertNotEqual(self.attempt_open(self.old / "controller.lock").returncode, 0)
            self.assertEqual(self.invoke(USERS_SID)["status"],
                             "OLD_PATH_FENCED_NEW_PHASE_ALLOWED")
        self.assert_validator_accepts(self.receipts / "fence.json")

    def test_failed_rename_retains_alias_denial_then_same_request_recovers(self):
        with self.identity(USERS_SID):
            with patch.object(self.module.os, "rename",
                              side_effect=PermissionError("injected rename failure")):
                with self.assertRaises(PermissionError):
                    self.invoke(USERS_SID)
            self.assertTrue(self.old.exists())
            self.assertFalse(self.archive.exists())
            for name in NAMES:
                self.assertTrue(self.module._file_deny(self.old / name, USERS_SID))
            self.assertEqual(self.invoke(USERS_SID)["status"],
                             "OLD_PATH_FENCED_NEW_PHASE_ALLOWED")
        self.assertEqual(self.archived_hashes(), self.content)

    def test_crash_after_rename_replays_archive_identity(self):
        actual = self.module._icacls

        def fail_first_archive_restore(path, *args):
            if "/remove:d" in args:
                raise RuntimeError("injected archive restore crash")
            return actual(path, *args)
        with self.identity(USERS_SID):
            with patch.object(self.module, "_icacls", side_effect=fail_first_archive_restore):
                with self.assertRaisesRegex(RuntimeError, "injected"):
                    self.invoke(USERS_SID)
            self.assertFalse(self.old.exists())
            self.assertTrue(self.archive.exists())
            self.assertEqual(self.invoke(USERS_SID)["status"],
                             "OLD_PATH_FENCED_NEW_PHASE_ALLOWED")
        self.assertEqual(self.archived_hashes(), self.content)
        self.assert_validator_accepts(self.receipts / "fence.json")

    def test_preexisting_alias_file_deny_is_preserved_and_rejected(self):
        path = self.old / "checkpoint.sqlite3"
        _icacls(str(path), "/deny", "*" + USERS_SID + ":(X)")
        prior = directory_dacl_sddl(path)
        self.assertIn(";;;BU)", prior)
        self.file_acl_sha[path.name] = _sha(prior)
        with self.identity(USERS_SID):
            with self.assertRaisesRegex(Exception, "existing owner deny"):
                self.invoke(USERS_SID)
        self.assertEqual(directory_dacl_sddl(path), prior)
        self.assertFalse((self.receipts / "barrier.json").exists())
        self.assertTrue(self.old.exists())

    def test_preexisting_alias_parent_deny_is_preserved_and_rejected(self):
        _icacls(str(self.parent), "/deny", "*" + USERS_SID + ":(X)")
        prior = directory_dacl_sddl(self.parent)
        self.assertIn(";;;BU)", prior)
        # Changing the parent ACL re-propagates inheritance to its children, so
        # re-pin them: only the owner deny may reject.
        self._pin()
        with self.identity(USERS_SID):
            with self.assertRaisesRegex(Exception, "existing owner deny"):
                self.invoke(USERS_SID)
        self.assertEqual(directory_dacl_sddl(self.parent), prior)
        self.assertFalse((self.receipts / "barrier.json").exists())

    def test_preexisting_deny_for_a_different_trustee_is_not_an_owner_deny(self):
        path = self.old / "checkpoint.sqlite3"
        _icacls(str(path), "/deny", "*" + GUESTS_SID + ":(X)")
        prior = directory_dacl_sddl(path)
        self.assertIn(";;;BG)", prior)
        self.file_acl_sha[path.name] = _sha(prior)
        with self.identity(USERS_SID):
            self.assertEqual(self.invoke(USERS_SID)["status"],
                             "OLD_PATH_FENCED_NEW_PHASE_ALLOWED")
        archived = directory_dacl_sddl(self.archive / path.name)
        self.assertTrue(self.module._same_effective_dacl(prior, archived))
        self.assertIn(";;;BG)", archived)

    def test_machine_rid500_identity_fences_and_validates(self):
        # Representation evidence for the LA spelling (see the V1 case).
        sid = _local_rid500_sid()
        with self.identity(sid):
            result = self.invoke(sid)
            self.assertEqual(result["status"], "OLD_PATH_FENCED_NEW_PHASE_ALLOWED")
            self.assertTrue(authority.dacl_has_ace(
                directory_dacl_sddl(self.parent), PARENT_ACE, sid))
            self.assertEqual(result, self.invoke(sid))
        self.assert_validator_accepts(self.receipts / "fence.json")

    def test_natural_runner_identity_fences_with_live_denied_opens(self):
        sid = _current_sid()   # LA on a hosted RID-500 runner
        seen = {}
        actual_rename = self.module.os.rename

        def observe_then_rename(source, destination):
            for name in NAMES:
                seen[name] = self.attempt_open(self.old / name).returncode != 0
            return actual_rename(source, destination)
        with patch.object(self.module.os, "rename", side_effect=observe_then_rename):
            result = self.invoke(sid)
        self.assertEqual(seen, {name: True for name in NAMES}, seen)
        self.assertEqual(result["status"], "OLD_PATH_FENCED_NEW_PHASE_ALLOWED")
        self.assertEqual(result, self.invoke(sid))
        self.assert_validator_accepts(self.receipts / "fence.json")

    def test_distinct_rid500_sid_is_not_the_owner_deny(self):
        # A deny for the local RID-500 account is not a deny for the plain runner
        # account, and neither is accepted as the foreign RID-500 domain's deny.
        local = _local_rid500_sid()
        path = self.old / "checkpoint.sqlite3"
        _icacls(str(path), "/deny", "*" + local + ":(X)")
        raw = directory_dacl_sddl(path)
        self.assertTrue(self.module._owner_deny_present(raw, local), raw)
        self.assertFalse(self.module._owner_deny_present(raw, FOREIGN_RID500_SID), raw)
        plain = _plain_account_sid()
        if plain != local:
            self.assertFalse(self.module._owner_deny_present(raw, plain), raw)
        self.assertFalse(self.module._file_deny(path, FOREIGN_RID500_SID))


class V4QuiescenceTrusteeTests(_FenceCase):
    @classmethod
    def setUpClass(cls):
        from src import paper_pilot_phase_cutover_guarded_v4 as module
        cls.module = module

    def setUp(self):
        super().setUp()
        self.auth = {"quiescence": "b" * 64, "fence": "c" * 64}
        self.quiescence_sha = None

    def _prepare(self, sid):
        body = self.module.held_quiescence_receipt_body(
            old_root=self.old, archived_root=self.archive,
            expected_file_sha256=self.content,
            source_stage_lock=self.parent / "source-stage.lock",
            phase_stage_lock=self.parent / "phase-stage.lock", deny_sid=sid,
            expected_parent_dacl_sha256=self.parent_acl_sha,
            expected_file_dacl_sha256=self.file_acl_sha,
            quiescence_authorization_sha256=self.auth["quiescence"])
        self.quiescence_sha = bytes_digest((dumps(body) + "\n").encode())

    def call(self, sid, observer=None):
        return self.module.quiescence_then_fence_guarded(
            old_root=self.old, archived_root=self.archive,
            expected_file_sha256=self.content,
            source_stage_lock=self.parent / "source-stage.lock",
            phase_stage_lock=self.parent / "phase-stage.lock", deny_sid=sid,
            expected_parent_dacl_sha256=self.parent_acl_sha,
            expected_file_dacl_sha256=self.file_acl_sha,
            quiescence_authorization_sha256=self.auth["quiescence"],
            fence_authorization_sha256=self.auth["fence"],
            quiescence_receipt_path=self.receipts / "quiescence.json",
            expected_quiescence_receipt_sha256=self.quiescence_sha,
            barrier_receipt_path=self.receipts / "barrier.json",
            fence_receipt_path=self.receipts / "fence.json", observer=observer)

    def test_continuous_lock_fence_under_alias_identity_and_alias_replay(self):
        with self.identity(USERS_SID):
            self._prepare(USERS_SID)
            result = self.call(USERS_SID)
            self.assertEqual(result["status"], "OLD_PATH_FENCED_NEW_PHASE_ALLOWED")
            self.assertFalse(result["reconciled"])
            self.assertEqual(bytes_digest((self.receipts / "quiescence.json").read_bytes()),
                             self.quiescence_sha)
            replay = self.call(USERS_SID)
            self.assertTrue(replay["reconciled"])
            self.assertEqual(replay["receipt_sha256"], result["receipt_sha256"])
        self.assertIn("(D;;LC;;;BU)", directory_dacl_sddl(self.parent))
        self.assertEqual(self.archived_hashes(), self.content)
        self.assert_validator_accepts(self.receipts / "fence.json")

    def test_partial_controller_deny_replay_passes_none_handle_to_observer(self):
        from contextlib import contextmanager

        @contextmanager
        def lease():
            yield
        original = self.module._icacls

        def crash_after_controller_deny(path, *args):
            result = original(path, *args)
            if Path(path) == self.old / "controller.lock" and args[:1] == ("/deny",):
                raise RuntimeError("injected first deny loss")
            return result
        with self.identity(USERS_SID):
            self._prepare(USERS_SID)
            with patch.object(self.module, "_icacls", side_effect=crash_after_controller_deny):
                with self.assertRaisesRegex(RuntimeError, "first deny loss"):
                    self.call(USERS_SID, observer=lambda **kwargs: lease())
            observed = []

            def replay_observer(**kwargs):
                observed.append(kwargs["controller_handle"])
                self.assertEqual(set(kwargs["writable_database_names"]),
                                 set(NAMES) - {"controller.lock"})
                return lease()
            self.assertTrue(self.call(USERS_SID, observer=replay_observer)["reconciled"])
            self.assertEqual(observed, [None])
        self.assert_validator_accepts(self.receipts / "fence.json")

    def test_partial_database_deny_replay_excludes_only_the_denied_database(self):
        from contextlib import contextmanager

        @contextmanager
        def lease():
            yield
        target = self.old / "checkpoint.sqlite3"
        original = self.module._icacls

        def crash_after_database_deny(path, *args):
            result = original(path, *args)
            if Path(path) == target and args[:1] == ("/deny",):
                raise RuntimeError("injected database deny loss")
            return result
        with self.identity(USERS_SID):
            self._prepare(USERS_SID)
            with patch.object(self.module, "_icacls", side_effect=crash_after_database_deny):
                with self.assertRaisesRegex(RuntimeError, "database deny loss"):
                    self.call(USERS_SID, observer=lambda **kwargs: lease())
            observed = []

            def replay_observer(**kwargs):
                observed.append(kwargs["writable_database_names"])
                return lease()
            self.assertTrue(self.call(USERS_SID, observer=replay_observer)["reconciled"])
        self.assertEqual(set(observed[0]), set(NAMES) - {"controller.lock", target.name})


class PhaseOwnershipTests(_FenceCase):
    """A real PhaseAuthority over a real alias-spelled fence: inactive, current, tampered."""

    @classmethod
    def setUpClass(cls):
        from src import paper_pilot_phase_cutover as v1
        from src import paper_pilot_phase_cutover_guarded_v4 as v4
        cls.module, cls.v4 = v1, v4

    def setUp(self):
        super().setUp()
        from trace_gc.trust import IssuerPolicy, Signer, TrustStore
        self.archive = self.tree.base / "archive" / "historical-state"
        self.fence = self.tree.base / "control" / "fence-receipt.json"
        self.fence.parent.mkdir()
        self.phase = self.tree.base / "phase"
        self.phase.mkdir()
        (self.phase / "phase.lock").write_bytes(b"0")
        self.signer = Signer.ephemeral("authored-phase-reviewer")
        self.trust = TrustStore()
        self.trust.enroll(self.signer.issuer, IssuerPolicy(
            self.signer.public_key(), "authored-phase-reviewer",
            frozenset({"AUTHORIZATION"}), frozenset({"PHASE_ACTIVATE"}),
            frozenset({"isolated-test"}), frozenset({"LIVE"}), can_review=True))

    def fence_v1(self, sid):
        with self.identity(sid):
            return self.module.fence_closed_old_phase(
                old_root=self.old, archived_root=self.archive,
                expected_file_sha256=self.content, deny_sid=sid, receipt_path=self.fence)

    def binding(self, fence: Path, activation_sha="0" * 64) -> dict:
        return {"phase_id": "authored-phase", "run_id": "authored-run",
                "capsule_sha256": "a" * 64, "implementation_sha256": "b" * 64,
                "activation_path": str(self.phase / "active.json"),
                "activation_sha256": activation_sha, "activation_epoch": 1,
                "phase_lock_path": str(self.phase / "phase.lock"),
                "fence_receipt_path": str(fence),
                "fence_receipt_sha256": bytes_digest(fence.read_bytes()),
                "old_root_path": str(self.old), "archived_old_root_path": str(self.archive),
                "capsule_path": str(self.phase / "capsule.json"),
                "authorization_path": str(self.phase / "auth.json"),
                "authorization_sha256": "c" * 64}

    def phase_authority(self, fence: Path, *, activate: bool) -> PhaseAuthority:
        sha = "0" * 64
        if activate:
            probe = PhaseAuthority(self.binding(fence), self.trust)
            try:
                receipt = self.signer.issue("AUTHORIZATION", probe.activation_payload(),
                                            lifetime_seconds=3600)
            finally:
                probe.close()
            raw = (dumps(receipt) + "
").encode("utf-8")
            (self.phase / "active.json").write_bytes(raw)
            sha = bytes_digest(raw)
        instance = PhaseAuthority(self.binding(fence, sha), self.trust)
        self.addCleanup(instance.close)
        return instance

    def assert_rejected(self, scope, code):
        with self.assertRaises(ContractError) as caught:
            with scope:
                self.fail("phase scope entered")
        self.assertEqual(caught.exception.code, code)

    def test_fenced_inactive_phase_stages_but_cannot_write_until_activated(self):
        self.fence_v1(USERS_SID)
        self.assertIn("(D;;LC;;;BU)", directory_dacl_sddl(self.parent))
        inactive = self.phase_authority(self.fence, activate=False)
        with inactive.staging():
            pass                                           # fenced: staging is allowed
        self.assert_rejected(inactive.write(), "PHASE_INACTIVE")   # but nothing is current
        self.assertFalse((self.phase / "active.json").exists())

    def test_activated_current_phase_writes_and_a_fence_replay_keeps_it_current(self):
        first = self.fence_v1(USERS_SID)
        current = self.phase_authority(self.fence, activate=True)
        with current.write():
            pass
        current.check()
        with current.staging():
            pass
        self.assertEqual(first, self.fence_v1(USERS_SID))   # same-request replay
        current.check()
        self.assertEqual({name: bytes_digest((self.archive / name).read_bytes())
                          for name in NAMES}, self.content)

    def test_current_phase_over_the_v4_alias_fence(self):
        receipts = self.tree.base / "v4-receipts"
        receipts.mkdir()
        with _Identity(self.v4, USERS_SID):
            self.v4.fence_closed_old_phase_guarded(
                old_root=self.old, archived_root=self.archive,
                expected_file_sha256=self.content,
                source_stage_lock=self.parent / "source-stage.lock",
                phase_stage_lock=self.parent / "phase-stage.lock", deny_sid=USERS_SID,
                expected_parent_dacl_sha256=self.parent_acl_sha,
                expected_file_dacl_sha256=self.file_acl_sha,
                barrier_receipt_path=receipts / "barrier.json",
                fence_receipt_path=receipts / "fence.json")
        current = self.phase_authority(receipts / "fence.json", activate=True)
        with current.write():
            pass

    def test_removed_parent_deny_rejects_staging_and_current_writes(self):
        self.fence_v1(USERS_SID)
        current = self.phase_authority(self.fence, activate=True)
        current.check()
        _icacls(str(self.parent), "/remove:d", "*" + USERS_SID)
        for scope in (current.staging(), current.write()):
            self.assert_rejected(scope, "PHASE_FENCE")

    def test_changed_archive_byte_rejects_a_current_phase(self):
        self.fence_v1(USERS_SID)
        current = self.phase_authority(self.fence, activate=True)
        current.check()
        (self.archive / "graph.sqlite3").write_bytes(b"changed")
        self.assert_rejected(current.write(), "PHASE_FENCE")
        self.assert_rejected(current.staging(), "PHASE_FENCE")

    def test_natural_runner_identity_fence_is_current(self):
        sid = _current_sid()   # LA on a hosted RID-500 runner
        self.module.fence_closed_old_phase(
            old_root=self.old, archived_root=self.archive,
            expected_file_sha256=self.content, deny_sid=sid, receipt_path=self.fence)
        current = self.phase_authority(self.fence, activate=True)
        with current.write():
            pass


if __name__ == "__main__":
    unittest.main()
