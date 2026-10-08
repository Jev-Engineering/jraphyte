"""Phase-fence trustee contract run against a MODEL of Windows' DACL seams.

The real v1 and v4 fence functions, the real ``PhaseAuthority`` constructor and
signed pointer, and the real ``RunBudget`` consumer run on any platform against
``WindowsModel`` (per-path DACL text, ``icacls`` and SID spelling). This pins the
control flow and the ACE-strictness contract. It is NOT Windows evidence: that is
``test_paper_pilot_phase_trustees_v1_v4.py`` on a native Windows runner.
"""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tests.phase_trustee_harness import (
    FILE_ACE, FOREIGN_RID500_SID, GUESTS_SID, LOCAL_RID500_SID, NAMES, NEAR_RID500_SID,
    PARENT_ACE, PLAIN_ACCOUNT_SID, USERS_SID, PhaseHarness, PhaseOwnershipScenarios,
    ReceiptValidatorScenarios, Sids, WindowsModel, sha)
from trace_gc import phase_authority as authority
from trace_gc.canonical import bytes_digest, dumps, loads
from trace_gc.errors import ContractError
from src import paper_pilot_phase_cutover as v1
from src import paper_pilot_phase_cutover_guarded_v4 as v4

MODEL_SIDS = dict(natural=PLAIN_ACCOUNT_SID, local500=LOCAL_RID500_SID,
                  plain=PLAIN_ACCOUNT_SID, near500=NEAR_RID500_SID)


class OffWindowsContractTests(unittest.TestCase):
    """No operating system, no numeric-SID guessing; identical on every platform."""

    def test_numeric_sid_fails_closed_without_windows(self):
        with patch.object(authority, "_is_windows", return_value=False):
            for sid in (USERS_SID, FOREIGN_RID500_SID, "S-1-5-21-1-2-3-500"):
                with self.assertRaises(ContractError) as caught:
                    authority.canonical_dacl_trustee(sid)
                self.assertEqual(caught.exception.code, "PHASE_PLATFORM")
            with self.assertRaises(ContractError):
                authority.dacl_has_ace("D:(D;;LC;;;LA)", PARENT_ACE, FOREIGN_RID500_SID)
            with self.assertRaises(ContractError):
                authority.canonical_dacl_aces("D:(D;;LC;;;" + FOREIGN_RID500_SID + ")")
            with self.assertRaises(ContractError):
                authority.dacl_has_deny_trustee("D:(D;;LC;;;LA)", LOCAL_RID500_SID)

    def test_alias_and_non_sid_text_pass_through_without_windows(self):
        with patch.object(authority, "_is_windows", return_value=False):
            for text in ("LA", "BU", "SY", "S-1-5-18)(A;;FA;;;WD", "", "S-1-5"):
                self.assertEqual(authority.canonical_dacl_trustee(text), text)
            self.assertTrue(authority.dacl_has_ace("D:(D;;LC;;;BU)", PARENT_ACE, "BU"))
            self.assertFalse(authority.dacl_has_ace("D:(D;;LC;;;BU)", PARENT_ACE, "LA"))
            self.assertFalse(authority.dacl_has_ace("D:(D;;LC;;;LA)", PARENT_ACE, "BA"))

    def test_off_windows_fences_and_authority_still_refuse(self):
        with patch.object(v1.os, "name", "posix"), patch.object(v4.os, "name", "posix"):
            with self.assertRaises(ContractError) as caught:
                v1.fence_closed_old_phase(old_root="/x/state", archived_root="/y/state",
                    expected_file_sha256={}, deny_sid=USERS_SID, receipt_path="/z/r.json")
            self.assertEqual(caught.exception.code, "PHASE_PLATFORM")
            with self.assertRaises(ContractError) as caught:
                v4.fence_closed_old_phase_guarded(old_root="/x/state", archived_root="/y/state",
                    expected_file_sha256={}, source_stage_lock="/x/a", phase_stage_lock="/x/b",
                    deny_sid=USERS_SID, expected_parent_dacl_sha256="0" * 64,
                    expected_file_dacl_sha256={}, barrier_receipt_path="/z/b.json",
                    fence_receipt_path="/z/f.json")
            self.assertEqual(caught.exception.code, "PHASE_PLATFORM")


class ModeledCase(unittest.TestCase):
    """An owned temp tree plus the Windows model, patched into the real code."""

    current_sid = USERS_SID

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="jraphyte-trustee-model-")
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name).resolve()
        self.model = WindowsModel(self, current_sid=self.current_sid, modules=(v1, v4)).start()
        self.parent = self.base / "old-app"
        self.old = self.parent / "state"
        self.archived = self.base / "archive" / "historical-state"
        self.old.mkdir(parents=True)
        self.archived.parent.mkdir()
        (self.base / "control").mkdir()
        self.content = {}
        for name in NAMES:
            body = b"0" if name == "controller.lock" else ("owned:" + name).encode()
            (self.old / name).write_bytes(body)
            self.content[name] = bytes_digest(body)
        for name in ("source-stage.lock", "phase-stage.lock"):
            (self.parent / name).write_bytes(b"0")
        self.harness = PhaseHarness(self, self.base, self.old, self.archived)

    def sddl(self, path) -> str:
        return self.model.sddl(path)

    def acl_pins(self):
        return (sha(self.sddl(self.parent)), {n: sha(self.sddl(self.old / n)) for n in NAMES})

    def assert_phase_accepts(self, fence: Path):
        instance = self.harness.authority(fence, activate=True)
        instance.check()
        with instance.staging():
            pass


class ModeledV1FenceTests(ModeledCase):
    def setUp(self):
        super().setUp()
        self.receipt = self.base / "control" / "fence-receipt.json"

    def invoke(self, sid=None):
        return v1.fence_closed_old_phase(
            old_root=self.old, archived_root=self.archived,
            expected_file_sha256=self.content, deny_sid=sid or self.current_sid,
            receipt_path=self.receipt)

    def test_group_alias_fence_replays_keeps_raw_digest_and_validates(self):
        first = self.invoke()
        raw = self.sddl(self.parent)
        self.assertEqual(first["status"], "OLD_PATH_FENCED_NEW_PHASE_ALLOWED")
        self.assertIn("(D;;LC;;;BU)", raw)
        self.assertNotIn(USERS_SID, raw)
        self.assertFalse(self.old.exists())
        self.assertEqual(first, self.invoke())
        body = loads(self.receipt.read_bytes())
        self.assertEqual(body["deny_sid"], USERS_SID)
        self.assertEqual(body["old_parent_dacl_sha256"], bytes_digest(raw.encode("utf-8")))
        self.assert_phase_accepts(self.receipt)

    def test_interrupted_rename_retries_to_the_identical_receipt(self):
        with patch.object(v1.os, "rename", side_effect=PermissionError("injected")):
            with self.assertRaises(PermissionError):
                self.invoke()
        self.assertTrue(self.old.exists() and not self.receipt.exists())
        self.assertIn("(D;;LC;;;BU)", self.sddl(self.parent))
        recovered = self.invoke()
        self.assertEqual(recovered, self.invoke())
        self.assert_phase_accepts(self.receipt)

    def test_unrelated_parent_deny_is_preserved_and_not_the_barrier(self):
        self.model.icacls(["icacls.exe", str(self.parent), "/deny", "*" + GUESTS_SID + ":(AD)"])
        self.assertFalse(authority.dacl_has_ace(self.sddl(self.parent), PARENT_ACE, USERS_SID))
        self.invoke()
        raw = self.sddl(self.parent)
        self.assertEqual(raw.count("(D;;LC;;;BG)"), 1)
        self.assertEqual(raw.count("(D;;LC;;;BU)"), 1)

    def test_wrong_hash_and_foreign_sid_hold_before_any_acl_change(self):
        before = self.sddl(self.parent)
        with self.assertRaises(ContractError):
            v1.fence_closed_old_phase(
                old_root=self.old, archived_root=self.archived, deny_sid=USERS_SID,
                expected_file_sha256={**self.content, "graph.sqlite3": "0" * 64},
                receipt_path=self.receipt)
        with self.assertRaises(ContractError):
            self.invoke(GUESTS_SID)
        self.assertEqual(self.sddl(self.parent), before)
        self.assertTrue(self.old.exists() and not self.receipt.exists())

    def test_a_local_administrator_deny_is_not_the_foreign_rid500_deny(self):
        # Another domain's RID-500 owner must not treat the local LA deny as its own.
        self.model.icacls(["icacls.exe", str(self.parent), "/deny",
                           "*" + LOCAL_RID500_SID + ":(AD)"])
        with patch.object(v1, "_current_sid", return_value=FOREIGN_RID500_SID):
            self.invoke(FOREIGN_RID500_SID)
        raw = self.sddl(self.parent)
        self.assertEqual(raw.count("(D;;LC;;;LA)"), 1)
        self.assertEqual(raw.count("(D;;LC;;;" + FOREIGN_RID500_SID + ")"), 1)
        self.assertEqual(loads(self.receipt.read_bytes())["deny_sid"], FOREIGN_RID500_SID)


class ModeledLocalRid500FenceTests(ModeledV1FenceTests):
    current_sid = LOCAL_RID500_SID

    def test_group_alias_fence_replays_keeps_raw_digest_and_validates(self):
        self.invoke()
        raw = self.sddl(self.parent)
        self.assertIn("(D;;LC;;;LA)", raw)
        self.assertNotIn(LOCAL_RID500_SID, raw)
        self.assertEqual(self.invoke(), self.invoke())
        self.assert_phase_accepts(self.receipt)

    test_unrelated_parent_deny_is_preserved_and_not_the_barrier = None
    test_wrong_hash_and_foreign_sid_hold_before_any_acl_change = None
    test_interrupted_rename_retries_to_the_identical_receipt = None
    test_a_local_administrator_deny_is_not_the_foreign_rid500_deny = None

    def test_foreign_rid500_deny_is_not_the_local_account_deny(self):
        self.model.icacls(["icacls.exe", str(self.parent), "/deny",
                           "*" + FOREIGN_RID500_SID + ":(AD)"])
        self.invoke()
        raw = self.sddl(self.parent)
        self.assertEqual(raw.count("(D;;LC;;;LA)"), 1)
        self.assertEqual(raw.count("(D;;LC;;;" + FOREIGN_RID500_SID + ")"), 1)


class ModeledV4FenceTests(ModeledCase):
    def setUp(self):
        super().setUp()
        self.receipts = self.base / "receipts"
        self.receipts.mkdir()
        self.pin()

    def pin(self):
        self.parent_pin, self.file_pins = self.acl_pins()

    def invoke(self, sid=None):
        return v4.fence_closed_old_phase_guarded(
            old_root=self.old, archived_root=self.archived,
            expected_file_sha256=self.content,
            source_stage_lock=self.parent / "source-stage.lock",
            phase_stage_lock=self.parent / "phase-stage.lock", deny_sid=sid or self.current_sid,
            expected_parent_dacl_sha256=self.parent_pin,
            expected_file_dacl_sha256=self.file_pins,
            barrier_receipt_path=self.receipts / "barrier.json",
            fence_receipt_path=self.receipts / "fence.json")

    def test_group_alias_fence_denies_every_file_restores_and_validates(self):
        original = {n: self.sddl(self.old / n) for n in NAMES}
        denied = {}
        real_rename = v4.os.rename

        def observe(source, destination):
            denied.update({n: authority.dacl_has_ace(self.sddl(self.old / n), FILE_ACE, USERS_SID)
                           for n in NAMES})
            return real_rename(source, destination)
        with patch.object(v4.os, "rename", side_effect=observe):
            result = self.invoke()
        self.assertEqual(result["status"], "OLD_PATH_FENCED_NEW_PHASE_ALLOWED")
        self.assertEqual(denied, {n: True for n in NAMES})
        self.assertIn("(D;;LC;;;BU)", self.sddl(self.parent))
        for name in NAMES:               # exact original ACEs restored, no allow copy
            self.assertEqual(self.sddl(self.archived / name), original[name])
            self.assertFalse(v4._file_deny(self.archived / name, USERS_SID))
        self.assertEqual(result, self.invoke())
        recorded = loads((self.receipts / "barrier.json").read_bytes())
        self.assertEqual(recorded["sid"], USERS_SID)
        self.assert_phase_accepts(self.receipts / "fence.json")

    def test_crash_after_first_alias_deny_replays(self):
        real = v4._icacls
        calls = []

        def first_then_crash(path, *args):
            real(path, *args)
            calls.append(path)
            if len(calls) == 1:
                raise RuntimeError("injected post-controller-deny crash")
        with patch.object(v4, "_icacls", side_effect=first_then_crash):
            with self.assertRaisesRegex(RuntimeError, "injected"):
                self.invoke()
        self.assertIn("(D;;DCLC;;;BU)", self.sddl(self.old / "controller.lock"))
        self.assertEqual(self.invoke()["status"], "OLD_PATH_FENCED_NEW_PHASE_ALLOWED")
        self.assert_phase_accepts(self.receipts / "fence.json")

    def test_crash_after_rename_replays_archive_identity(self):
        real = v4._icacls

        def fail_restore(path, *args):
            if "/remove:d" in args:
                raise RuntimeError("injected archive restore crash")
            return real(path, *args)
        with patch.object(v4, "_icacls", side_effect=fail_restore):
            with self.assertRaisesRegex(RuntimeError, "injected"):
                self.invoke()
        self.assertTrue(self.archived.exists() and not self.old.exists())
        self.assertEqual(self.invoke()["status"], "OLD_PATH_FENCED_NEW_PHASE_ALLOWED")
        self.assert_phase_accepts(self.receipts / "fence.json")

    def test_preexisting_alias_file_deny_is_preserved_and_rejected(self):
        path = self.old / "checkpoint.sqlite3"
        self.model.icacls(["icacls.exe", str(path), "/deny", "*" + USERS_SID + ":(X)"])
        prior = self.sddl(path)
        self.assertIn(";;;BU)", prior)
        self.pin()
        with self.assertRaisesRegex(ContractError, "existing owner deny"):
            self.invoke()
        self.assertEqual(self.sddl(path), prior)
        self.assertFalse((self.receipts / "barrier.json").exists())

    def test_preexisting_alias_parent_deny_is_preserved_and_rejected(self):
        self.model.icacls(["icacls.exe", str(self.parent), "/deny", "*" + USERS_SID + ":(X)"])
        prior = self.sddl(self.parent)
        self.pin()
        with self.assertRaisesRegex(ContractError, "existing owner deny"):
            self.invoke()
        self.assertEqual(self.sddl(self.parent), prior)

    def test_deny_for_a_different_trustee_is_not_an_owner_deny(self):
        path = self.old / "checkpoint.sqlite3"
        self.model.icacls(["icacls.exe", str(path), "/deny", "*" + GUESTS_SID + ":(X)"])
        prior = self.sddl(path)
        self.pin()
        self.assertEqual(self.invoke()["status"], "OLD_PATH_FENCED_NEW_PHASE_ALLOWED")
        self.assertEqual(self.sddl(self.archived / path.name), prior)

    def test_local_administrator_deny_is_not_a_foreign_rid500_owner_deny(self):
        path = self.old / "checkpoint.sqlite3"
        self.model.icacls(["icacls.exe", str(path), "/deny", "*" + LOCAL_RID500_SID + ":(X)"])
        raw = self.sddl(path)
        self.assertIn(";;;LA)", raw)
        self.assertTrue(v4._owner_deny_present(raw, LOCAL_RID500_SID))
        for other in (FOREIGN_RID500_SID, NEAR_RID500_SID, PLAIN_ACCOUNT_SID, USERS_SID):
            self.assertFalse(v4._owner_deny_present(raw, other), other)
            self.assertFalse(v4._file_deny(path, other), other)

    def test_continuous_lock_wrapper_fences_under_the_alias(self):
        body = v4.held_quiescence_receipt_body(
            old_root=self.old, archived_root=self.archived,
            expected_file_sha256=self.content,
            source_stage_lock=self.parent / "source-stage.lock",
            phase_stage_lock=self.parent / "phase-stage.lock", deny_sid=USERS_SID,
            expected_parent_dacl_sha256=self.parent_pin,
            expected_file_dacl_sha256=self.file_pins,
            quiescence_authorization_sha256="b" * 64)
        quiescence = bytes_digest((dumps(body) + "\n").encode())

        def call():
            return v4.quiescence_then_fence_guarded(
                old_root=self.old, archived_root=self.archived,
                expected_file_sha256=self.content,
                source_stage_lock=self.parent / "source-stage.lock",
                phase_stage_lock=self.parent / "phase-stage.lock", deny_sid=USERS_SID,
                expected_parent_dacl_sha256=self.parent_pin,
                expected_file_dacl_sha256=self.file_pins,
                quiescence_authorization_sha256="b" * 64,
                fence_authorization_sha256="c" * 64,
                quiescence_receipt_path=self.receipts / "quiescence.json",
                expected_quiescence_receipt_sha256=quiescence,
                barrier_receipt_path=self.receipts / "barrier.json",
                fence_receipt_path=self.receipts / "fence.json", observer=None)
        first = call()
        self.assertFalse(first["reconciled"])
        replay = call()
        self.assertTrue(replay["reconciled"])
        self.assertEqual(replay["receipt_sha256"], first["receipt_sha256"])
        self.assert_phase_accepts(self.receipts / "fence.json")


class StrictAceContractTests(unittest.TestCase):
    """ACE count, order, flags, rights and non-trustee fields are compared exactly."""

    def setUp(self):
        model = WindowsModel(self, modules=()).start()
        self.model = model
        self.base = "D:AI(A;ID;FA;;;BA)(A;ID;0x1200a9;;;BU)(A;ID;FA;;;SY)"

    def test_same_acl_only_trustee_spelling_may_differ(self):
        numeric = "D:AI(A;ID;FA;;;BA)(A;ID;0x1200a9;;;" + USERS_SID + ")(A;ID;FA;;;SY)"
        self.assertTrue(v4._same_effective_dacl(self.base, numeric))
        self.assertTrue(v4._same_effective_dacl(self.base, "D:" + self.base[4:]))   # AI is ignored
        for label, other in (
                ("explicit allow copy", "D:AI(A;ID;FA;;;BA)(A;ID;0x1200a9;;;BU)(A;ID;FA;;;SY)(A;;0x1200a9;;;BU)"),
                ("explicit allow copy in place", "D:AI(A;ID;FA;;;BA)(A;;0x1200a9;;;BU)(A;ID;FA;;;SY)"),
                ("dropped ACE", "D:AI(A;ID;FA;;;BA)(A;ID;FA;;;SY)"),
                ("reordered", "D:AI(A;ID;0x1200a9;;;BU)(A;ID;FA;;;BA)(A;ID;FA;;;SY)"),
                ("rights", "D:AI(A;ID;FA;;;BA)(A;ID;0x1200a8;;;BU)(A;ID;FA;;;SY)"),
                ("type", "D:AI(A;ID;FA;;;BA)(D;ID;0x1200a9;;;BU)(A;ID;FA;;;SY)"),
                ("flags", "D:AI(A;ID;FA;;;BA)(A;CIID;0x1200a9;;;BU)(A;ID;FA;;;SY)"),
                ("trustee", "D:AI(A;ID;FA;;;BA)(A;ID;0x1200a9;;;BG)(A;ID;FA;;;SY)"),
                ("protection", "D:PAI(A;ID;FA;;;BA)(A;ID;0x1200a9;;;BU)(A;ID;FA;;;SY)")):
            self.assertFalse(v4._same_effective_dacl(self.base, other), label)

    def test_admission_diff_allows_exactly_one_owner_deny(self):
        deny_file = "(D;;DCLC;;;BU)"
        added = "D:AI" + deny_file + self.base[4:]
        self.assertTrue(v4._only_admission_dacl_added(self.base, added, USERS_SID))
        numeric = "D:AI(D;;DCLC;;;" + USERS_SID + ")" + self.base[4:]
        self.assertTrue(v4._only_admission_dacl_added(self.base, numeric, USERS_SID))
        self.assertTrue(v4._only_admission_dacl_added(self.base, self.base, USERS_SID))  # before the deny
        for label, current in (
                ("deny plus allow copy", added + "(A;;0x1200a9;;;BU)"),
                ("deny with wider rights", "D:AI(D;;DCLCWD;;;BU)" + self.base[4:]),
                ("deny with a flag", "D:AI(D;OI;DCLC;;;BU)" + self.base[4:]),
                ("deny for another trustee", "D:AI(D;;DCLC;;;BG)" + self.base[4:]),
                ("deny for foreign rid500", "D:AI(D;;DCLC;;;" + FOREIGN_RID500_SID + ")" + self.base[4:]),
                ("two owner denies", "D:AI" + deny_file * 2 + self.base[4:]),
                ("reordered base", "D:AI" + deny_file + "(A;ID;0x1200a9;;;BU)(A;ID;FA;;;BA)(A;ID;FA;;;SY)"),
                ("dropped base ACE", "D:AI" + deny_file + "(A;ID;FA;;;BA)(A;ID;FA;;;SY)")):
            self.assertFalse(v4._only_admission_dacl_added(self.base, current, USERS_SID), label)

    def test_parent_admission_diff_allows_exactly_one_owner_deny(self):
        parent = "D:PAI(A;;FA;;;BA)(A;OICIID;FA;;;SY)"
        self.assertTrue(v4._only_parent_admission_added(
            parent, "D:PAI(D;;LC;;;BU)(A;;FA;;;BA)(A;OICIID;FA;;;SY)", USERS_SID))
        for label, current in (
                ("extra allow", "D:PAI(D;;LC;;;BU)(A;;FA;;;BA)(A;OICIID;FA;;;SY)(A;;LC;;;BU)"),
                ("wrong rights", "D:PAI(D;;DCLC;;;BU)(A;;FA;;;BA)(A;OICIID;FA;;;SY)"),
                ("inheritable deny", "D:PAI(D;OICI;LC;;;BU)(A;;FA;;;BA)(A;OICIID;FA;;;SY)"),
                ("foreign rid500", "D:PAI(D;;LC;;;" + FOREIGN_RID500_SID + ")(A;;FA;;;BA)(A;OICIID;FA;;;SY)"),
                ("protection dropped", "D:AI(D;;LC;;;BU)(A;;FA;;;BA)(A;OICIID;FA;;;SY)")):
            self.assertFalse(v4._only_parent_admission_added(parent, current, USERS_SID), label)

    def test_owner_deny_matches_only_the_same_sid_in_any_spelling(self):
        sids = {"users": USERS_SID, "local": LOCAL_RID500_SID, "foreign": FOREIGN_RID500_SID,
                "near": NEAR_RID500_SID, "plain": PLAIN_ACCOUNT_SID, "guests": GUESTS_SID}
        for ace_name, ace_sid in sids.items():
            for spelling in (self.model.spell(ace_sid), ace_sid):
                parent = "D:AI(D;;LC;;;" + spelling + ")(A;OICIID;FA;;;SY)"
                file = "D:AI(D;;DCLC;;;" + spelling + ")(A;ID;FA;;;SY)"
                for query_name, query in sids.items():
                    label = (ace_name, spelling, query_name)
                    same = ace_name == query_name
                    self.assertEqual(authority.dacl_has_ace(parent, PARENT_ACE, query), same, label)
                    self.assertEqual(authority.dacl_has_ace(file, FILE_ACE, query), same, label)
                    self.assertEqual(authority.dacl_has_deny_trustee(parent, query), same, label)

    def test_only_the_trustee_field_is_normalized(self):
        self.assertTrue(authority.dacl_has_ace("D:(D;;LC;;;BU)", PARENT_ACE, USERS_SID))
        self.assertTrue(authority.dacl_has_ace("D:(D;;LC;;;" + USERS_SID + ")",
                                               PARENT_ACE, USERS_SID))
        for text in ("D:(D;;LC;;;BG)", "D:(D;;DC;;;BU)", "D:(D;;LCWP;;;BU)", "D:(D;OI;LC;;;BU)",
                     "D:(D;CI;LC;;;BU)", "D:(A;;LC;;;BU)", "D:(OD;;LC;;;BU)"):
            self.assertFalse(authority.dacl_has_ace(text, PARENT_ACE, USERS_SID), text)
        self.assertFalse(authority.dacl_has_ace("D:(D;;LC;;;BU)", FILE_ACE, USERS_SID))
        self.assertEqual(authority.canonical_dacl_aces("D:AI(D;;LC;;;BU)(A;ID;FA;;;SY)"),
                         ["(D;;LC;;;BU)", "(A;ID;FA;;;SY)"])
        self.assertEqual(authority.canonical_dacl_aces(
            "D:(A;ID;FA;;;SY)(D;;LC;;;" + USERS_SID + ")"), ["(A;ID;FA;;;SY)", "(D;;LC;;;BU)"])
        self.assertFalse(authority.dacl_has_deny_trustee("D:(A;;FA;;;BU)", USERS_SID))
        self.assertFalse(authority.dacl_has_deny_trustee("D:(D;;FX;;;BA)", USERS_SID))
        self.assertTrue(authority.dacl_has_deny_trustee("D:(D;;FX;;;BU)", USERS_SID))

    def test_injected_trustee_text_is_not_translated_or_matched(self):
        injected = "S-1-5-18)(A;;FA;;;WD"
        self.assertEqual(authority.canonical_dacl_trustee(injected), injected)
        self.assertFalse(authority.dacl_has_ace("D:(D;;LC;;;BU)(A;;FA;;;WD)", PARENT_ACE, injected))


class ModeledReceiptValidatorTests(ReceiptValidatorScenarios, ModeledCase):
    def setUp(self):
        super().setUp()
        self.sids = Sids(**MODEL_SIDS)
        for name in NAMES:      # the validator inspects the archived tree
            body = ("validator:" + name).encode()
            (self.old / name).write_bytes(body)
        self.old.rename(self.archived)
        self.files = {n: bytes_digest((self.archived / n).read_bytes()) for n in NAMES}
        self.receipt = self.base / "fence.json"

    def raw(self):
        return self.sddl(self.parent)

    def _icacls(self, verb, sid, spec=None):
        args = ["icacls.exe", str(self.parent), verb, "*" + sid + (":" + spec if spec else "")]
        self.model.icacls(args)

    def deny(self, sid, spec):
        self._icacls("/deny", sid, spec)

    def grant(self, sid, spec):
        self._icacls("/grant", sid, spec)

    def lift_deny(self, sid):
        self._icacls("/remove:d", sid)

    def lift_grant(self, sid):
        self._icacls("/remove:g", sid)


class ModeledPhaseOwnershipTests(PhaseOwnershipScenarios, ModeledCase):
    def setUp(self):
        super().setUp()
        self.fence_receipt = self.base / "control" / "fence-receipt.json"
        v1.fence_closed_old_phase(old_root=self.old, archived_root=self.archived,
                                  expected_file_sha256=self.content, deny_sid=USERS_SID,
                                  receipt_path=self.fence_receipt)
        self.assertIn("(D;;LC;;;BU)", self.sddl(self.parent))

    def remove_parent_deny(self):
        self.model.icacls(["icacls.exe", str(self.parent), "/remove:d", "*" + USERS_SID])

    def tamper_archive(self):
        (self.archived / "graph.sqlite3").write_bytes(b"changed")


    def test_second_opener_is_excluded_while_a_write_scope_is_held(self):
        first = self.harness.authority(self.fence_receipt, activate=True)
        second = self.harness.peer(first)
        with first.write():
            with self.assertRaises(OSError):
                with second.write():
                    self.fail("two current writers entered the phase together")
            with first.staging():            # re-entrant for the holder
                pass
        with second.write():
            pass


class ModeledV4PhaseOwnershipTests(ModeledPhaseOwnershipTests):
    """The same phase scenarios over a fence sealed by the guarded v4 helper."""

    def setUp(self):
        ModeledCase.setUp(self)
        self.receipts = self.base / "receipts"
        self.receipts.mkdir()
        parent_pin, file_pins = self.acl_pins()
        v4.fence_closed_old_phase_guarded(
            old_root=self.old, archived_root=self.archived,
            expected_file_sha256=self.content,
            source_stage_lock=self.parent / "source-stage.lock",
            phase_stage_lock=self.parent / "phase-stage.lock", deny_sid=USERS_SID,
            expected_parent_dacl_sha256=parent_pin, expected_file_dacl_sha256=file_pins,
            barrier_receipt_path=self.receipts / "barrier.json",
            fence_receipt_path=self.receipts / "fence.json")
        self.fence_receipt = self.receipts / "fence.json"


class InstalledToolModelTests(unittest.TestCase):
    """The installed-wheel checker's Windows branch, driven over the model (not native)."""

    @staticmethod
    def load_tool():
        import importlib.util
        path = Path(__file__).resolve().parents[1] / "tools" / "installed_phase_authority_check.py"
        spec = importlib.util.spec_from_file_location("installed_phase_authority_check", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_every_windows_check_passes_against_the_model(self):
        tool = self.load_tool()
        model = WindowsModel(self, current_sid=PLAIN_ACCOUNT_SID, modules=()).start()
        for name, value in (("call", lambda *args: model.icacls(list(args))),
                            ("current_sid", lambda: PLAIN_ACCOUNT_SID)):
            patcher = patch.object(tool, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        report = tool.Report()
        tool.native(report)
        windows = report.data["windows_checks"]
        self.assertEqual([name for name, passed in windows.items() if not passed], [])
        self.assertEqual(len(windows), 29)
        for name in ("alias_deny_accepted_write_and_staging",
                     "fenced_inactive_stages_but_rejects_current_write",
                     "rejected_write_leaves_ledger_unchanged",
                     "foreign_rid500_deny_rejected_for_local_account",
                     "machine_rid500_deny_rejected_for_foreign_domain_rid500"):
            self.assertTrue(windows[name], name)

    def test_portable_checks_reject_a_wrong_declared_digest(self):
        tool = self.load_tool()
        report = tool.Report()
        tool.portable(report, {"phase_authority.py": "0" * 64})
        checks = report.data["portable_checks"]
        self.assertFalse(checks["installed_matches_reviewed_source:phase_authority.py"])
        self.assertTrue(checks["numeric_sid_fails_closed_without_windows"])
        self.assertFalse(report.ok)
        self.assertEqual(report.data["windows_checks"], {})


if __name__ == "__main__":
    unittest.main()
