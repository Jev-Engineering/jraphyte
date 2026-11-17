"""Native Windows trustee-alias regressions for the v1 and v4 phase fences and the packaged
``PhaseAuthority.verify_fence`` receipt validator (issue #110).

Windows writes some numeric SIDs in DACL text as SDDL aliases: the Users group
``S-1-5-32-545`` is ``BU`` and the machine's built-in Administrator (RID 500, the hosted
runner's own identity) is ``LA``. A literal ``(D;;LC;;;S-1-...)`` substring check cannot see
those ACEs. These cases run the real fences and the real validator against DACLs Windows
itself spelled, and reject a different trustee (including a distinct domain SID that shares
RID 500), mask, ACE type, flag or digest. They need native Windows and are skipped elsewhere;
``test_paper_pilot_phase_trustees_model.py`` is the portable, modeled counterpart. Every ACL
edit stays inside an owned temporary directory.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from src import paper_pilot_phase_cutover as v1
from src import paper_pilot_phase_cutover_guarded_v4 as v4
from tests.windows_privilege_scope import privileges_disabled
from tools import windows_fixture_acl
from trace_gc import phase_authority as authority
from trace_gc.canonical import bytes_digest, dumps
from trace_gc.errors import ContractError

USERS_SID, GUESTS_SID, ADMINS_SID = "S-1-5-32-545", "S-1-5-32-546", "S-1-5-32-544"
FOREIGN_RID500_SID = "S-1-5-21-1111111111-2222222222-3333333333-500"  # fabricated domain
PARENT_ACE, FILE_ACE = v1.DENY_PARENT_ACE, v4.DENY_FILE_ACE
TEMP_PREFIX = "jraphyte-phase-trustee-"


def _icacls(*args: str) -> None:
    result = subprocess.run(["icacls.exe", *args], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr or result.stdout


def _account_prefix() -> str:
    prefix = re.fullmatch(r"(S-1-5-21-\d+-\d+-\d+)-\d+", v1._current_sid())
    assert prefix is not None, "test requires a machine/domain account SID"
    return prefix.group(1)


def _local_rid500_sid() -> str:
    return _account_prefix() + "-500"


def _near_rid500_sid() -> str:
    head, last = _account_prefix().rsplit("-", 1)
    return head + "-" + str(int(last) + 1) + "-500"


class OwnedTree(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix=TEMP_PREFIX)
        self.addCleanup(self._cleanup)
        self.base = Path(self.temp.name)
        self.sids = {USERS_SID, GUESTS_SID, ADMINS_SID, v1._current_sid(), _local_rid500_sid()}

    def _cleanup(self):
        for path in self.base.rglob("*"):
            for sid in self.sids:
                subprocess.run(["icacls.exe", str(path), "/remove:d", "*" + sid],
                               capture_output=True, text=True, timeout=30)
        self.temp.cleanup()
        self.assertFalse(self.base.exists())

    def stabilize(self, *targets: Path) -> None:
        windows_fixture_acl.stabilize_owned_fixture(
            self.base, [(str(index), path) for index, path in enumerate(targets)],
            read=authority.directory_dacl_sddl)


@unittest.skipUnless(os.name == "nt", "Windows SID/SDDL contract")
class SharedTrusteeHelperTests(OwnedTree):
    def test_numeric_sids_are_spelled_by_windows_and_never_mapped_back(self):
        spell = authority.canonical_dacl_trustee
        self.assertEqual((spell(USERS_SID), spell(GUESTS_SID), spell("S-1-5-18")), ("BU", "BG", "SY"))
        self.assertEqual(spell("BU"), "BU")
        injected = "S-1-5-18)(A;;FA;;;WD"
        self.assertEqual(spell(injected), injected)
        local, foreign, near = _local_rid500_sid(), FOREIGN_RID500_SID, _near_rid500_sid()
        self.assertEqual(spell(foreign), foreign)
        self.assertEqual(spell(near), near)
        self.assertNotIn(spell(local), (foreign, near))
        if v1._current_sid().endswith("-500"):
            # The hosted runner's own RID-500 identity is the reproduction of issue #110.
            self.assertEqual(spell(v1._current_sid()), "LA")

    def test_real_alias_spelled_deny_matches_only_its_own_trustee(self):
        directory = self.base / "parent"
        directory.mkdir()
        self.stabilize(directory)
        for sid in (USERS_SID, _local_rid500_sid()):
            _icacls(str(directory), "/deny", "*" + sid + ":(AD)")
            raw = authority.directory_dacl_sddl(directory)
            if sid == USERS_SID:
                # The OS really spells it as the alias, so a literal comparison misses it.
                self.assertIn("(D;;LC;;;BU)", raw)
                self.assertNotIn(PARENT_ACE.format(sid=sid), raw)
            self.assertTrue(authority.dacl_has_ace(raw, PARENT_ACE, sid), raw)
            self.assertTrue(authority.dacl_has_deny_trustee(raw, sid), raw)
            self.assertFalse(authority.dacl_has_ace(raw, FILE_ACE, sid), raw)
            for other in (FOREIGN_RID500_SID, _near_rid500_sid(), GUESTS_SID, ADMINS_SID):
                self.assertFalse(authority.dacl_has_ace(raw, PARENT_ACE, other), (other, raw))
                self.assertFalse(authority.dacl_has_deny_trustee(raw, other), (other, raw))
            _icacls(str(directory), "/remove:d", "*" + sid)


class _FenceTree(OwnedTree):
    def setUp(self):
        super().setUp()
        self.parent = self.base / "old-app"
        self.old = self.parent / "state"
        self.archived = self.base / "archive" / "state"
        self.control = self.base / "control"
        for path in (self.parent, self.old, self.archived.parent, self.control):
            path.mkdir()
        self.content = {}
        for name in sorted(v1.NAMES):
            body = b"0" if name == "controller.lock" else ("trustee:" + name).encode()
            (self.old / name).write_bytes(body)
            self.content[name] = hashlib.sha256(body).hexdigest()
        self.receipt = self.control / "fence.json"

    def authority_for(self, receipt: Path):
        lock = self.base / "phase.lock"
        lock.write_bytes(b"0")
        binding = {key: str(self.base / key) for key in (
            "activation_path", "capsule_path", "authorization_path")}
        binding.update({
            "phase_id": "authored", "run_id": "authored", "capsule_sha256": "a" * 64,
            "implementation_sha256": "b" * 64, "activation_sha256": "c" * 64,
            "activation_epoch": 1, "authorization_sha256": "d" * 64,
            "phase_lock_path": str(lock), "fence_receipt_path": str(receipt),
            "fence_receipt_sha256": bytes_digest(receipt.read_bytes()),
            "old_root_path": str(self.old), "archived_old_root_path": str(self.archived)})
        phase = authority.PhaseAuthority(binding, trust=None)
        self.addCleanup(phase.close)
        return phase

    def variant(self, **changes) -> Path:
        body = {**json.loads(self.receipt.read_text("utf-8")), **changes}
        path = self.control / ("variant-%d.json" % len(list(self.control.iterdir())))
        path.write_bytes((dumps(body) + "\n").encode("utf-8"))
        return path

    def assert_rejected(self, receipt: Path):
        with self.assertRaises(ContractError) as caught:
            self.authority_for(receipt).verify_fence()
        self.assertEqual(caught.exception.code, "PHASE_FENCE")


@unittest.skipUnless(os.name == "nt", "Windows SID/SDDL contract")
class V1FenceAndReceiptTests(_FenceTree):
    def setUp(self):
        super().setUp()
        self.stabilize(self.parent)

    def fence(self, sid: str):
        with patch.object(v1, "_current_sid", return_value=sid):
            return v1.fence_closed_old_phase(
                old_root=self.old, archived_root=self.archived, expected_file_sha256=self.content,
                deny_sid=sid, receipt_path=self.receipt)

    def test_group_alias_identity_fences_validates_and_rejects_other_trustees(self):
        with privileges_disabled():
            result = self.fence(USERS_SID)
            self.assertEqual(result["status"], "OLD_PATH_FENCED_NEW_PHASE_ALLOWED")
            raw = authority.directory_dacl_sddl(self.parent)
            self.assertIn("(D;;LC;;;BU)", raw)
            with self.assertRaises(PermissionError) as refused:
                self.old.mkdir()
            self.assertEqual(refused.exception.winerror, 5)
            self.assertEqual(self.fence(USERS_SID), result)
        self.authority_for(self.receipt).verify_fence()
        for other in (GUESTS_SID, ADMINS_SID, FOREIGN_RID500_SID, _local_rid500_sid()):
            self.assert_rejected(self.variant(deny_sid=other))
        self.assert_rejected(self.variant(old_parent_dacl_sha256="0" * 64))

    def test_runner_identity_fences_and_distinct_rid500_receipts_are_rejected(self):
        sid = v1._current_sid()
        with privileges_disabled():
            self.assertEqual(self.fence(sid)["status"], "OLD_PATH_FENCED_NEW_PHASE_ALLOWED")
            with self.assertRaises(PermissionError):
                self.old.mkdir()
        self.assertTrue(authority.dacl_has_ace(authority.directory_dacl_sddl(self.parent),
                                               PARENT_ACE, sid))
        self.authority_for(self.receipt).verify_fence()
        for other in (FOREIGN_RID500_SID, _near_rid500_sid(), USERS_SID):
            self.assert_rejected(self.variant(deny_sid=other))

    def test_existing_alias_deny_with_another_mask_holds_before_any_acl_change(self):
        _icacls(str(self.parent), "/deny", "*" + USERS_SID + ":(X)")
        before = authority.directory_dacl_sddl(self.parent)
        self.assertIn(";;;BU)", before)
        with privileges_disabled():
            with self.assertRaises(ContractError) as held:
                self.fence(USERS_SID)
        self.assertEqual(held.exception.detail, "old parent already carries another deny for the fence SID")
        self.assertEqual(authority.directory_dacl_sddl(self.parent), before)
        self.assertTrue(self.old.is_dir())
        self.assertFalse(self.receipt.exists())

    def test_a_wrong_mask_alias_deny_does_not_validate_a_receipt(self):
        with privileges_disabled():
            self.fence(USERS_SID)
        # Swap the exact deny-create for a same-trustee deny with another mask; pin the new digest.
        _icacls(str(self.parent), "/remove:d", "*" + USERS_SID)
        _icacls(str(self.parent), "/deny", "*" + USERS_SID + ":(WD,AD)")
        raw = authority.directory_dacl_sddl(self.parent)
        self.assertIn("(D;;DCLC;;;BU)", raw)
        self.assert_rejected(self.variant(old_parent_dacl_sha256=bytes_digest(raw.encode("utf-8"))))


@unittest.skipUnless(os.name == "nt", "Windows SID/SDDL contract")
class V4AliasIdentityFenceTests(_FenceTree):
    """The real v4 guarded fence as an identity whose DACL trustee is an alias (BU)."""

    def setUp(self):
        super().setUp()
        for name in ("source-stage.lock", "phase-stage.lock"):
            (self.parent / name).write_bytes(b"0")
        self.stabilize(self.parent, self.old, *(self.old / name for name in sorted(v4.NAMES)))
        patcher = patch.object(v4, "_current_sid", return_value=USERS_SID)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.pin()

    def pin(self):
        self.parent_acl = bytes_digest(authority.directory_dacl_sddl(self.parent).encode())
        self.file_acl = {name: bytes_digest(authority.directory_dacl_sddl(self.old / name).encode())
                         for name in v4.NAMES}

    def invoke(self, sid: str = USERS_SID):
        return v4.fence_closed_old_phase_guarded(
            old_root=self.old, archived_root=self.archived, expected_file_sha256=self.content,
            source_stage_lock=self.parent / "source-stage.lock",
            phase_stage_lock=self.parent / "phase-stage.lock", deny_sid=sid,
            expected_parent_dacl_sha256=self.parent_acl, expected_file_dacl_sha256=self.file_acl,
            barrier_receipt_path=self.control / "barrier.json", fence_receipt_path=self.receipt)

    def test_fence_completes_replays_and_its_receipt_validates(self):
        result = self.invoke()
        self.assertEqual(result["status"], "OLD_PATH_FENCED_NEW_PHASE_ALLOWED")
        self.assertFalse(self.old.exists())
        self.assertIn("(D;;LC;;;BU)", authority.directory_dacl_sddl(self.parent))
        for name in v4.NAMES:
            self.assertFalse(v4._file_deny(self.archived / name, USERS_SID))
        self.assertEqual(result, self.invoke())
        self.authority_for(self.receipt).verify_fence()

    def test_crash_after_first_alias_file_deny_replays(self):
        actual, calls = v4._icacls, []

        def first_deny_then_crash(path, *args):
            actual(path, *args)
            calls.append(path)
            if len(calls) == 1:
                raise RuntimeError("injected post-first-deny crash")
        with patch.object(v4, "_icacls", side_effect=first_deny_then_crash):
            with self.assertRaisesRegex(RuntimeError, "injected"):
                self.invoke()
        denied = [name for name in v4.NAMES if "(D;;DCLC;;;BU)" in
                  authority.directory_dacl_sddl(self.old / name)]
        self.assertEqual(len(denied), 1)
        self.assertTrue(v4._file_deny(self.old / denied[0], USERS_SID))
        self.assertEqual(self.invoke()["status"], "OLD_PATH_FENCED_NEW_PHASE_ALLOWED")

    def test_preexisting_alias_owner_deny_is_preserved_and_rejected(self):
        path = self.old / "checkpoint.sqlite3"
        _icacls(str(path), "/deny", "*" + USERS_SID + ":(X)")
        prior = authority.directory_dacl_sddl(path)
        self.assertIn(";;;BU)", prior)
        self.file_acl[path.name] = bytes_digest(prior.encode())
        with self.assertRaisesRegex(ContractError, "existing owner deny"):
            self.invoke()
        self.assertEqual(authority.directory_dacl_sddl(path), prior)
        self.assertFalse((self.control / "barrier.json").exists())
        self.assertTrue(self.old.exists())

    def test_a_deny_for_a_distinct_trustee_is_not_an_owner_deny(self):
        path = self.old / "checkpoint.sqlite3"
        _icacls(str(path), "/deny", "*" + GUESTS_SID + ":(X)")
        prior = authority.directory_dacl_sddl(path)
        self.file_acl[path.name] = bytes_digest(prior.encode())
        self.assertEqual(self.invoke()["status"], "OLD_PATH_FENCED_NEW_PHASE_ALLOWED")
        self.assertTrue(v4._same_effective_dacl(
            prior, authority.directory_dacl_sddl(self.archived / path.name)))


if __name__ == "__main__":
    unittest.main()
