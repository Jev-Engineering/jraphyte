"""Native Windows trustee-alias regressions for the v1/v4 phase fences and the packaged
phase-authority receipt validator.

Windows serializes some numeric SIDs in a DACL string as SDDL aliases (the Users group
S-1-5-32-545 is ``BU``; a machine's built-in Administrator, RID 500, is ``LA``). The v1
fence, the v4 guarded fence and ``PhaseAuthority.verify_fence`` must recognize their own
deny ACE under either spelling while rejecting a different trustee (including a distinct
account/domain SID that shares RID 500), mask, ACE type, inheritance flag or digest.

These classes need a real Windows host (real icacls, NTFS, msvcrt, SID translation) and
are skipped elsewhere; ``test_paper_pilot_phase_trustees_model.py`` runs the same logic
everywhere against a labelled model. Every fixture is an owned temporary directory; only
ACEs this test added beneath it are removed. Identities that are not the running account
are only ever *represented* in real DACLs; denied opens are asserted for the group alias
(the process token holds Users) and for the process's own identity, never for a simulated
one. Phase acceptance always goes through the real ``PhaseAuthority`` constructor, a
signed activation pointer, and both ``write()`` and ``staging()``.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from tests.phase_trustee_harness import (
    FILE_ACE, FOREIGN_RID500_SID, GUESTS_SID, NAMES, PARENT_ACE, USERS_SID, PhaseHarness,
    PhaseOwnershipScenarios, ReceiptValidatorScenarios, SUPPORTED_CONTEXT_ENV, Sids,
    assert_fence_refused_before_effects, producer_context_supported, sha as _sha)
from tools import windows_fixture_acl, windows_native_acl
from trace_gc import phase_authority as authority
from trace_gc.canonical import bytes_digest, dumps, loads
from trace_gc.errors import ContractError
from trace_gc.phase_authority import directory_dacl_sddl

WINDOWS = os.name == "nt"
TEMP_PREFIX = "jraphyte-phase-trustee-"


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
    return _account_prefix() + "-500"


def _plain_account_sid() -> str:
    current = _current_sid()
    return current if not current.endswith("-500") else _account_prefix() + "-1001"


def _near_rid500_sid() -> str:
    head, last = _account_prefix().rsplit("-", 1)
    return head + "-" + str(int(last) + 1) + "-500"


def _native_sids() -> Sids:
    return Sids(natural=_current_sid(), local500=_local_rid500_sid(),
                plain=_plain_account_sid(), near500=_near_rid500_sid())


class OwnedTree:
    """A disposable tree whose every ACL edit is confined beneath ``base``."""

    def __init__(self, test: unittest.TestCase):
        self.test = test
        self.temp = tempfile.TemporaryDirectory(prefix=TEMP_PREFIX)
        self.hold = windows_native_acl.ChildStopHold()
        test.addCleanup(self.cleanup)
        self.base = Path(self.temp.name)
        assert self.base.name.startswith(TEMP_PREFIX)
        # The fabricated foreign SID is absent: icacls cannot resolve it, so the one test that
        # installs it removes and verifies it through the native descriptor API itself.
        self.sids = {USERS_SID, GUESTS_SID, _current_sid(),
                     _local_rid500_sid(), _plain_account_sid(), _near_rid500_sid()}

    def owned(self, path: Path) -> Path:
        resolved = Path(path).resolve()
        if not resolved.is_relative_to(self.base.resolve()):
            raise AssertionError(f"refusing ACL change outside fixture: {path}")
        return resolved

    def cleanup(self):
        # A launched child that is not shown stopped keeps the whole tree: nothing is restored or
        # removed beneath it, and the temporary directory's finalizer is detached.
        self.hold.settle(self.temp, self._lift_acls)
        self.test.assertFalse(self.base.exists())

    def _lift_acls(self):
        # Lift only the deny/allow ACEs this test could have added; the tree is
        # then removed. The temporary directory's own ancestors are never edited.
        for path in [self.base, *self.base.rglob("*")]:
            if path.exists() and path != self.base:
                for sid in self.sids:
                    _call("icacls.exe", str(self.owned(path)), "/remove:d", "*" + sid)
                # The one explicit grant any case adds (Users, on its own parent).
                _call("icacls.exe", str(self.owned(path)), "/remove:g", "*" + USERS_SID)


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
        near = _near_rid500_sid()
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



@unittest.skipUnless(WINDOWS, "Windows NTFS DACL contract")
class NativeReceiptValidatorTests(ReceiptValidatorScenarios, unittest.TestCase):
    """The real PhaseAuthority against a real DACL that Windows spells."""

    def setUp(self):
        self.tree = OwnedTree(self)
        base = self.tree.base
        self.sids = _native_sids()
        self.parent = base / "old-app"
        self.old = self.parent / "state"
        self.archived = base / "archive" / "state"
        self.parent.mkdir()
        self.archived.mkdir(parents=True)
        # Explicit, protected and verified before any deny or pin (tools/windows_fixture_acl.py).
        windows_fixture_acl.stabilize_owned_fixture(
            base, [("parent", self.parent)], read=directory_dacl_sddl)
        self.files = {}
        for name in NAMES:
            body = ("validator:" + name).encode()
            (self.archived / name).write_bytes(body)
            self.files[name] = bytes_digest(body)
        self.receipt = base / "fence.json"
        self.harness = PhaseHarness(self, base, self.old, self.archived)

    def raw(self):
        return directory_dacl_sddl(self.parent)

    def deny(self, sid, spec):
        if sid == FOREIGN_RID500_SID:
            self.deny_without_account_lookup(sid, spec)
        else:
            _icacls(str(self.parent), "/deny", "*" + sid + ":" + spec)

    def deny_without_account_lookup(self, sid, spec):
        """Install the deny for a SID no machine knows, and prove what Windows really stored."""
        self.assertEqual(spec, "(AD)")
        native = windows_native_acl.WindowsNative()
        before, owner_before = self.raw(), native.read_owner(self.parent)
        installed = windows_native_acl.deny_by_descriptor(native, self.parent, sid)
        self.addCleanup(self.remove_foreign_deny, native, sid)
        self.assertTrue(installed["installed_exactly"],
                        windows_native_acl.components_message("installation", installed["components"]))
        after = self.raw()
        self.assertEqual(installed["before"], before)
        self.assertEqual(installed["after"], after)
        before_aces = windows_native_acl.split_dacl(before)[1]
        after_aces = windows_native_acl.split_dacl(after)[1]
        self.assertEqual(after_aces, ["(D;;LC;;;" + sid + ")"] + before_aces)
        self.assertEqual(len(after_aces), len(before_aces) + 1)
        kind, flags, mask, object_guid, inherited_guid, trustee = after_aces[0][1:-1].split(";")
        self.assertEqual((kind, flags, mask, object_guid, inherited_guid, trustee),
                         ("D", "", "LC", "", "", sid))
        self.assertEqual(native.read_owner(self.parent), owner_before)
        self.assertEqual(installed["owner_after"], owner_before)
        self.assertNotEqual(_sha(before), _sha(after))
        self.assertTrue(authority.dacl_has_ace(after, PARENT_ACE, sid))
        self.assertFalse(authority.dacl_has_ace(after, PARENT_ACE, self.sids.local500))

    def remove_foreign_deny(self, native, sid):
        self.assertTrue(windows_native_acl.remove_descriptor_deny(native, self.parent, sid))
        self.assertNotIn("(D;;LC;;;" + sid + ")", self.raw())

    def grant(self, sid, spec):
        _icacls(str(self.parent), "/grant", "*" + sid + ":" + spec)

    def lift_deny(self, sid):
        _icacls(str(self.parent), "/remove:d", "*" + sid)

    def lift_grant(self, sid):
        _icacls(str(self.parent), "/remove:g", "*" + sid)


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
        # Explicit, protected and verified before the first pin, so no pin depends on what
        # the temporary parent passes down (see tools/windows_fixture_acl.py).
        windows_fixture_acl.stabilize_owned_fixture(
            self.tree.base, [("parent", self.parent), ("state", self.old)]
            + [("file:" + name, self.old / name) for name in sorted(NAMES)],
            read=directory_dacl_sddl)
        self._pin()
        self._harness = None

    @property
    def harness(self):
        if self._harness is None:
            self._harness = PhaseHarness(self, self.tree.base, self.old, self.archive)
        return self._harness

    def _pin(self):
        self.parent_acl_sha = _sha(directory_dacl_sddl(self.parent))
        self.file_acl_sha = {name: _sha(directory_dacl_sddl(self.old / name))
                             for name in NAMES}

    def identity(self, sid):
        return _Identity(self.module, sid)

    def archived_hashes(self):
        return {name: bytes_digest((self.archive / name).read_bytes()) for name in NAMES}

    def assert_validator_accepts(self, receipt: Path):
        instance = self.harness.authority(receipt, activate=True)
        instance.check()
        with instance.staging():
            pass

    def assert_old_path_recreation_denied(self):
        windows_native_acl.require_recreation_denied(windows_native_acl.WindowsNative(), self.parent, self.old)
        self.assertFalse(self.old.exists())

    def supported_producer(self, sid) -> bool:
        return producer_context_supported(self, self.tree.base, sid)

    def without_token_gate(self):
        """The v1 token gate has its own native and modeled tests; this keeps it out of cases that
        exercise receipts, replay and ownership, and is never used where recreation is asserted."""
        patcher = patch.object(self.module, "_require_denial_enforced")
        patcher.start()
        self.addCleanup(patcher.stop)

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

    def assert_refused_before_effects(self, sid):
        assert_fence_refused_before_effects(
            self, lambda: self.invoke(sid), parent=self.parent, old=self.old, archive=self.archive,
            receipt=self.receipt, content=self.content)

    def test_group_alias_identity_fences_replays_and_validates(self):
        with self.identity(USERS_SID):
            if not self.supported_producer(USERS_SID):
                # Fail closed: the original token is not refused beneath the deny, so nothing
                # was fenced; the supported-context run below holds the strict positive path.
                self.assert_refused_before_effects(USERS_SID)
                return
            first = self.invoke(USERS_SID)
            self.assertEqual(first["status"], "OLD_PATH_FENCED_NEW_PHASE_ALLOWED")
            raw = directory_dacl_sddl(self.parent)
            self.assertIn("(D;;LC;;;BU)", raw)
            self.assertFalse(self.old.exists())
            self.assertEqual(self.archived_hashes(), self.content)
            # Live denial: Users is in this process token, so recreation is refused.
            self.assert_old_path_recreation_denied()
            self.assertEqual(first, self.invoke(USERS_SID))
        # The receipt keeps the numeric SID and the raw (alias-spelled) digest.
        from trace_gc.canonical import loads
        body = loads(self.receipt.read_bytes())
        self.assertEqual(body["deny_sid"], USERS_SID)
        self.assertEqual(body["old_parent_dacl_sha256"], bytes_digest(raw.encode("utf-8")))
        self.assert_validator_accepts(self.receipt)

    def test_crash_after_parent_deny_retries_to_the_identical_receipt(self):
        self.without_token_gate()
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
        self.without_token_gate()
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
        self.without_token_gate()
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
        if not self.supported_producer(sid):
            self.assert_refused_before_effects(sid)
            return
        result = self.invoke(sid)
        self.assertEqual(result["status"], "OLD_PATH_FENCED_NEW_PHASE_ALLOWED")
        self.assertTrue(authority.dacl_has_ace(
            directory_dacl_sddl(self.parent), PARENT_ACE, sid))
        self.assert_old_path_recreation_denied()
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

    STRICT_PRODUCER_CASES = (
        "tests.test_paper_pilot_phase_trustees_v1_v4.V1FenceTrusteeTests"
        ".test_group_alias_identity_fences_replays_and_validates",
        "tests.test_paper_pilot_phase_trustees_v1_v4.V1FenceTrusteeTests"
        ".test_natural_runner_identity_fences_with_live_denied_recreation",
        "tests.test_paper_pilot_phase_fence.PhaseNamespaceFenceTests"
        ".test_exact_replay_after_closed_directory_move")
    STRICT_RUNNER = (
        "import json, sys, unittest\n"
        "from tools import windows_native_acl\n"
        "held = windows_native_acl.WindowsNative().privileges()\n"
        "with open(sys.argv[1] + '.token.json', 'w', encoding='utf-8') as token:\n"
        "    json.dump({'enabled': sorted(n for n, e in held if e), 'disabled': sorted(n for n, e in held if not e)}, token)\n"
        "names = sys.argv[2:]\n"
        "suite = unittest.defaultTestLoader.loadTestsFromNames(names)\n"
        "with open(sys.argv[1], 'w', encoding='utf-8') as out:\n"
        "    result = unittest.TextTestRunner(stream=out, verbosity=0).run(suite)\n"
        "sys.exit(0 if result.wasSuccessful() and result.testsRun == len(names) else 1)\n")

    def test_the_strict_positive_producer_path_runs_in_a_restricted_primary_token_child(self):
        """The original-token acceptance gate, forced: the child's ORIGINAL process token is a copy
        of this one with every privilege removed, and the supported-context branch is required, so
        the child fails unless the production producer fences and recreation is refused. Nothing
        here is accepted on a thread impersonating a stripped token, and a context that is not
        supported fails this test rather than passing the refusal branch."""
        native = windows_native_acl.WindowsNative()
        out = self.tree.base / "strict-producer-child.txt"
        with patch.dict(os.environ, {SUPPORTED_CONTEXT_ENV: "required"}):
            launch = self.tree.hold.launch(
                native, [sys.executable, "-c", self.STRICT_RUNNER, str(out), *self.STRICT_PRODUCER_CASES],
                Path.cwd(), timeout=900)
        report = out.read_text(encoding="utf-8") if out.exists() else ""
        self.assertEqual(windows_native_acl.launch_defects(launch), [], windows_native_acl.redact(str(launch)))
        self.assertEqual(
            {key: launch[key] for key in ("launched", "completed", "exit_code", "timed_out", "cleanup_verified")},
            {"launched": True, "completed": True, "exit_code": 0, "timed_out": False, "cleanup_verified": True},
            "restricted-primary child did not accept: " + windows_native_acl.redact(
                str(launch) + " " + report[-6000:]))
        self.assertIn("Ran 3 tests", report)
        self.assertTrue(report.rstrip().endswith("OK"), report[-500:])
        identity = json.loads(Path(str(out) + ".token.json").read_text(encoding="utf-8"))
        self.assertLessEqual(set(identity["enabled"]), {"SeChangeNotifyPrivilege"}, identity)
        self.assertTrue(identity["disabled"] or identity["enabled"], identity)


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



class _Ownership(PhaseOwnershipScenarios):
    """Real PhaseAuthority + RunBudget over a fence created by the real helper (mixin)."""

    def setUp(self):
        super().setUp()
        self.archive = self.tree.base / "archive" / "historical-state"
        self.fence_receipt = self.make_fence()

    def remove_parent_deny(self):
        _icacls(str(self.parent), "/remove:d", "*" + USERS_SID)

    def tamper_archive(self):
        (self.archive / "graph.sqlite3").write_bytes(b"changed")


class V1PhaseOwnershipTests(_Ownership, _FenceCase):
    def make_fence(self):
        from src import paper_pilot_phase_cutover as v1
        self.module = v1
        self.without_token_gate()
        control = self.tree.base / "control"
        control.mkdir()
        receipt = control / "fence-receipt.json"
        with self.identity(USERS_SID):
            v1.fence_closed_old_phase(old_root=self.old, archived_root=self.archive,
                                      expected_file_sha256=self.content, deny_sid=USERS_SID,
                                      receipt_path=receipt)
        self.assertIn("(D;;LC;;;BU)", directory_dacl_sddl(self.parent))
        return receipt

    def test_second_opener_waits_for_the_held_write_scope_then_enters(self):
        first = self.harness.authority(self.fence_receipt, activate=True)
        second = self.harness.peer(first)
        entered, finished = threading.Event(), threading.Event()
        failure = []

        def contender():
            try:
                with second.write():
                    entered.set()
            except BaseException as error:        # reported on the main thread
                failure.append(error)
            finally:
                finished.set()
        with first.write():
            worker = threading.Thread(target=contender)
            worker.start()
            self.assertFalse(entered.wait(1.5), "a second writer entered the held phase")
        self.assertTrue(finished.wait(20), "waiting writer never completed")
        worker.join()
        self.assertEqual(failure, [])
        self.assertTrue(entered.is_set())


class V4PhaseOwnershipTests(_Ownership, _FenceCase):
    def make_fence(self):
        from src import paper_pilot_phase_cutover_guarded_v4 as v4
        self.module = v4
        with self.identity(USERS_SID):
            v4.fence_closed_old_phase_guarded(
                old_root=self.old, archived_root=self.archive,
                expected_file_sha256=self.content,
                source_stage_lock=self.parent / "source-stage.lock",
                phase_stage_lock=self.parent / "phase-stage.lock", deny_sid=USERS_SID,
                expected_parent_dacl_sha256=self.parent_acl_sha,
                expected_file_dacl_sha256=self.file_acl_sha,
                barrier_receipt_path=self.receipts / "barrier.json",
                fence_receipt_path=self.receipts / "fence.json")
        return self.receipts / "fence.json"


if __name__ == "__main__":
    unittest.main()
