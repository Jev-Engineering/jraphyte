"""Portable, MODELED trustee-alias tests for the v1/v4 fences and ``verify_fence`` (#110).

These run on every platform against a small labelled model of three Windows seams: how
Windows spells a numeric SID in DACL text (``_windows_trustee``), the DACL text of a path
(``directory_dacl_sddl``) and ``icacls``. The real fence and validator code runs unchanged
on top of the model. This is not native Windows evidence: the native counterparts are
``test_paper_pilot_phase_trustees_v1_v4.py`` and ``test_paper_pilot_phase_fence.py``.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from src import paper_pilot_phase_cutover as v1
from src import paper_pilot_phase_cutover_guarded_v4 as v4
from trace_gc import phase_authority as authority
from trace_gc.canonical import bytes_digest, dumps
from trace_gc.errors import ContractError

USERS_SID, GUESTS_SID = "S-1-5-32-545", "S-1-5-32-546"
LOCAL_RID500_SID = "S-1-5-21-100-200-300-500"       # this modeled machine's Administrator
FOREIGN_RID500_SID = "S-1-5-21-111-222-333-500"     # another domain, same RID 500
NEAR_RID500_SID = "S-1-5-21-100-200-301-500"        # differs only in the last sub-authority
PLAIN_SID = "S-1-5-21-100-200-300-1001"             # an account with no alias
ALIASES = {USERS_SID: "BU", GUESTS_SID: "BG", LOCAL_RID500_SID: "LA", "S-1-5-18": "SY",
           "S-1-5-32-544": "BA"}
PARENT, FILE = v1.DENY_PARENT_ACE, v4.DENY_FILE_ACE


class _NtOs:
    """``os`` as the fences see it on Windows; directory creation consults the model."""

    name = "nt"

    def __init__(self, model):
        self._model = model

    def __getattr__(self, attribute):
        return getattr(os, attribute)

    def mkdir(self, path, *args, **kwargs):
        if self._model.refuses_creation(Path(path)):
            error = PermissionError(13, "modeled access denied")
            error.winerror = 5
            raise error
        if self._model.mkdir_error is not None:
            raise self._model.mkdir_error
        os.mkdir(path, *args, **kwargs)

    def rmdir(self, path):
        if self._model.rmdir_fails:
            raise PermissionError(13, "modeled removal failure")
        os.rmdir(path)

    def rename(self, source, destination):
        original = self._model.key(source)
        replacement = self._model.key(destination)
        os.rename(source, destination)
        for key in list(self._model.dacls):
            if Path(key).is_relative_to(original):
                moved = Path(replacement) / Path(key).relative_to(original)
                self._model.dacls[str(moved)] = self._model.dacls.pop(key)


class WindowsModel:
    """DACL text per path, ``icacls`` deny/remove, and SID spelling. A model, not Windows."""

    def __init__(self, test, current_sid):
        self.current_sid = current_sid
        self.dacls: dict[str, tuple[str, list[str]]] = {}
        self.token_bypasses_deny = False      # e.g. a token whose privileges let it create
        self.marks_auto_inherited = False     # Windows adds AI when it rewrites an unprotected DACL
        self.restore_exit = 0
        self.restore_adds_ai = False
        self.deny_exit = 0
        self.deny_timeout = False
        self.mkdir_error = None
        self.rmdir_fails = False
        nt = _NtOs(self)
        for item in (patch.object(authority, "_is_windows", return_value=True),
                     patch.object(authority, "_windows_trustee", side_effect=self.spell),
                     patch.object(authority, "directory_dacl_sddl", side_effect=self.sddl),
                     patch.object(authority, "os", nt),
                     patch.object(v1, "directory_dacl_sddl", side_effect=self.sddl),
                     patch.object(v1, "_current_sid", side_effect=lambda: self.current_sid),
                     patch.object(v1, "subprocess", self), patch.object(v1, "os", nt)):
            item.start()
            test.addCleanup(item.stop)

    @staticmethod
    def spell(sid):
        return ALIASES.get(sid, sid)

    def key(self, path):
        return str(Path(path).resolve())

    def sddl(self, path):
        flags, aces = self.dacls.setdefault(self.key(path), ("", ["(A;OICIID;FA;;;SY)"]))
        return "D:" + flags + "".join(aces)

    def set(self, path, flags, aces):
        self.dacls[self.key(path)] = (flags, list(aces))

    def refuses_creation(self, path):
        if self.token_bypasses_deny:
            return False
        trustee = self.spell(self.current_sid)
        return any(ace.startswith("(D;;") and ace.endswith(";;;" + trustee + ")") and
                   "LC" in ace.split(";")[2] for ace in self.dacls.get(self.key(path.parent), ("", []))[1])

    # ``subprocess`` seen by v1 ------------------------------------------------------------
    SubprocessError = subprocess.SubprocessError

    def run(self, args, **kwargs):
        assert args[0] == "icacls.exe", args
        path, verb, spec = args[1], args[2], args[3]
        if verb == "/save":
            original = self.key(Path(kwargs["cwd"]) / path)
            Path(spec).write_text(json.dumps([original, self.dacls[original]]), encoding="utf-8")
            return subprocess.CompletedProcess(args, 0)
        if verb == "/restore":
            original, (flags, aces) = json.loads(Path(spec).read_text(encoding="utf-8"))
            assert Path(original).parent == Path(path).resolve()
            if not self.restore_exit:
                self.set(original, flags + ("AI" if self.restore_adds_ai else ""), aces)
            return subprocess.CompletedProcess(args, self.restore_exit)
        self.sddl(path)
        flags, aces = self.dacls[self.key(path)]
        trustee = self.spell(spec.lstrip("*").split(":")[0])
        if verb == "/deny":
            mask = {"(AD)": "LC", "(WD,AD)": "DCLC"}[spec.split(":", 1)[1]]
            aces = ["(D;;" + mask + ";;;" + trustee + ")"] + [
                ace for ace in aces if ace != "(A;;" + mask + ";;;" + trustee + ")"]

        elif verb == "/remove:d":
            aces = [ace for ace in aces if not (ace.startswith("(D;;") and ace.endswith(";;;" + trustee + ")"))]
        else:
            raise AssertionError(verb)
        if self.marks_auto_inherited and "P" not in flags and "AI" not in flags:
            flags += "AI"
        self.dacls[self.key(path)] = (flags, aces)
        if verb == "/deny" and self.deny_timeout:
            raise subprocess.TimeoutExpired(args, kwargs["timeout"])
        return subprocess.CompletedProcess(args, self.deny_exit if verb == "/deny" else 0)


class ModeledFence(unittest.TestCase):
    sid = USERS_SID

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.base = base
        self.parent, self.archived, self.control = base / "old-app", base / "archive" / "state", base / "control"
        self.old = self.parent / "state"
        for path in (self.parent, self.old, self.archived.parent, self.control):
            path.mkdir()
        self.content = {}
        for name in sorted(v1.NAMES):
            (self.old / name).write_bytes(name.encode())
            self.content[name] = hashlib.sha256(name.encode()).hexdigest()
        self.receipt = self.control / "fence.json"
        self.model = WindowsModel(self, self.sid)
        self.model.set(self.parent, "P", ["(A;OICI;FA;;;SY)", "(A;OICI;FA;;;BA)"])

    def fence(self):
        return v1.fence_closed_old_phase(old_root=self.old, archived_root=self.archived,
                                         expected_file_sha256=self.content, deny_sid=self.sid,
                                         receipt_path=self.receipt)

    def hold(self, detail):
        with self.assertRaises(ContractError) as caught:
            self.fence()
        self.assertEqual((caught.exception.code, caught.exception.detail), ("PHASE_FENCE", detail))

    def assert_no_effect(self, before):
        self.assertEqual(self.model.sddl(self.parent), before)
        self.assertTrue(self.old.is_dir())
        self.assertFalse(self.archived.exists() or self.receipt.exists())
        self.assertEqual([path.name for path in self.parent.iterdir()], ["state"])

    def validate(self, receipt=None, **changes):
        receipt = receipt or self.receipt
        if changes:
            body = {**json.loads(receipt.read_text("utf-8")), **changes}
            receipt = self.control / ("variant-%d.json" % len(list(self.control.iterdir())))
            receipt.write_bytes((dumps(body) + "\n").encode("utf-8"))
        lock = self.base / "phase.lock"
        lock.write_bytes(b"0")
        binding = {key: str(self.base / key) for key in (
            "activation_path", "capsule_path", "authorization_path")}
        binding.update({"phase_id": "m", "run_id": "m", "capsule_sha256": "a" * 64,
                        "implementation_sha256": "b" * 64, "activation_sha256": "c" * 64,
                        "activation_epoch": 1, "authorization_sha256": "d" * 64,
                        "phase_lock_path": str(lock), "fence_receipt_path": str(receipt),
                        "fence_receipt_sha256": bytes_digest(receipt.read_bytes()),
                        "old_root_path": str(self.old), "archived_old_root_path": str(self.archived)})
        phase = authority.PhaseAuthority(binding, trust=None)
        try:
            phase.verify_fence()
        finally:
            phase.close()

    def assert_rejected(self, **changes):
        with self.assertRaises(ContractError) as caught:
            self.validate(**changes)
        self.assertEqual(caught.exception.code, "PHASE_FENCE")


class ModeledAliasFenceTests(ModeledFence):
    def test_unsupported_conditional_ace_is_refused_without_truncation(self):
        with self.assertRaisesRegex(ContractError, "unsupported DACL ACE syntax"):
            authority.canonical_dacl_aces('D:P(XA;;LC;;;BU;(@User.Title == "Fixture"))')

    def test_the_literal_check_cannot_see_the_alias_spelled_deny(self):
        # The issue #110 mechanism: Windows spells the numeric SID as BU in DACL text.
        result = self.fence()
        sddl = self.model.sddl(self.parent)
        self.assertEqual(result["status"], "OLD_PATH_FENCED_NEW_PHASE_ALLOWED")
        self.assertIn("(D;;LC;;;BU)", sddl)
        self.assertNotIn("(D;;LC;;;%s)" % self.sid, sddl)
        self.assertEqual(json.loads(self.receipt.read_text("utf-8"))["deny_sid"], self.sid)
        self.assertEqual(json.loads(self.receipt.read_text("utf-8"))["old_parent_dacl_sha256"],
                         bytes_digest(sddl.encode("utf-8")))
        self.assertEqual(self.fence(), result)
        self.validate()

    def test_receipts_naming_any_other_trustee_or_digest_are_rejected(self):
        self.fence()
        for other in (GUESTS_SID, LOCAL_RID500_SID, FOREIGN_RID500_SID, PLAIN_SID):
            self.assert_rejected(deny_sid=other)
        # A receipt must name the numeric SID; alias text is never accepted in its place.
        for other in ("BU", "bu", " " + USERS_SID, None, 545):
            self.assert_rejected(deny_sid=other)
        self.assert_rejected(old_parent_dacl_sha256="0" * 64)

    def test_a_wrong_mask_type_or_flag_deny_does_not_validate(self):
        self.fence()
        for ace in ("(D;;DCLC;;;BU)", "(D;OI;LC;;;BU)", "(D;ID;LC;;;BU)", "(A;;LC;;;BU)",
                    "(OD;;LC;;;BU)", "(D;;LC;;;BG)"):
            self.model.set(self.parent, "P", [ace, "(A;OICI;FA;;;SY)", "(A;OICI;FA;;;BA)"])
            digest = bytes_digest(self.model.sddl(self.parent).encode("utf-8"))
            self.assert_rejected(old_parent_dacl_sha256=digest)

    def test_existing_same_trustee_deny_with_another_mask_holds_before_any_change(self):
        self.model.set(self.parent, "P", ["(D;;FX;;;BU)", "(A;OICI;FA;;;SY)"])
        before = self.model.sddl(self.parent)
        self.hold("old parent already carries another deny for the fence SID")
        self.assert_no_effect(before)

    def test_archive_moved_without_the_parent_deny_holds(self):
        os.rename(self.old, self.archived)
        self.hold("archive moved without durable parent deny")


class ModeledRid500Tests(ModeledFence):
    sid = LOCAL_RID500_SID

    def test_machine_rid500_fences_as_la_and_distinct_rid500_sids_stay_distinct(self):
        self.fence()
        self.assertIn("(D;;LC;;;LA)", self.model.sddl(self.parent))
        self.validate()
        for other in (FOREIGN_RID500_SID, NEAR_RID500_SID, PLAIN_SID):
            self.assertEqual(authority.canonical_dacl_trustee(other), other)
            self.assert_rejected(deny_sid=other)


class ModeledTokenGateTests(ModeledFence):
    def test_a_token_that_is_not_refused_holds_and_the_added_deny_is_removed_exactly(self):
        self.model.token_bypasses_deny = True
        before = self.model.sddl(self.parent)
        self.hold(v1.TOKEN_NOT_REFUSED)
        self.assert_no_effect(before)

    def test_an_unprotected_parent_with_new_control_flags_is_restored(self):
        self.model.token_bypasses_deny = True
        self.model.marks_auto_inherited = True
        self.model.set(self.parent, "", ["(A;OICIID;FA;;;SY)"])
        before = self.model.sddl(self.parent)
        self.hold("old parent DACL changed beyond the exact deny-create ACE")
        self.assert_no_effect(before)
        self.model.restore_adds_ai = True
        self.hold("old parent DACL changed beyond the exact deny-create ACE"
                  "; original parent DACL restoration could not be verified"
                  " (DACL differs from its pre-state)")
        self.assertEqual(self.model.sddl(self.parent), "D:AI(A;OICIID;FA;;;SY)")
        self.assertTrue(self.old.is_dir() and not self.receipt.exists())

    def test_a_protected_parent_restores_exactly_under_the_same_marking(self):
        self.model.token_bypasses_deny = True
        self.model.marks_auto_inherited = True
        before = self.model.sddl(self.parent)
        self.hold(v1.TOKEN_NOT_REFUSED)
        self.assert_no_effect(before)

    def test_a_restoration_that_exits_nonzero_is_not_trusted(self):
        self.model.token_bypasses_deny = True
        self.model.restore_exit = 5
        self.hold(v1.TOKEN_NOT_REFUSED + "; original parent DACL restoration could not be verified"
                  " (icacls exit 5)")

    def test_success_status_with_a_removed_grant_holds_and_restores_the_grant(self):
        self.model.set(self.parent, "P", ["(A;;LC;;;BU)", "(A;OICI;FA;;;BA)"])
        before = self.model.sddl(self.parent)
        self.hold("old parent DACL changed beyond the exact deny-create ACE")
        self.assert_no_effect(before)

    def test_nonzero_or_timeout_after_mutation_restores_the_grant(self):
        self.model.set(self.parent, "P", ["(A;;LC;;;BU)", "(A;OICI;FA;;;BA)"])
        before = self.model.sddl(self.parent)
        for timeout in (False, True):
            with self.subTest(timeout=timeout):
                self.model.deny_exit = 5
                self.model.deny_timeout = timeout
                self.hold("could not deny old state recreation")
                self.assert_no_effect(before)

    def test_acl_readback_error_rolls_back_the_new_deny(self):
        before = self.model.sddl(self.parent)
        with patch.object(v1, "directory_dacl_sddl", side_effect=[
                before, ContractError("PHASE_FENCE", "private diagnostic"), before]):
            self.hold(v1.DACL_UNVERIFIED)
        self.assert_no_effect(before)

    def test_acl_comparison_error_rolls_back_the_new_deny(self):
        before = self.model.sddl(self.parent)
        with patch.object(v1, "dacl_has_ace", side_effect=[
                False, ContractError("PHASE_FENCE", "private diagnostic")]):
            self.hold(v1.DACL_UNVERIFIED)
        self.assert_no_effect(before)

    def test_rollback_readback_error_reports_restoration_as_unverified(self):
        before = self.model.sddl(self.parent)
        with patch.object(v1, "directory_dacl_sddl", side_effect=[
                before, OSError("private readback diagnostic"),
                ContractError("PHASE_FENCE", "private rollback diagnostic")]):
            self.hold(v1.DACL_UNVERIFIED + "; original parent DACL restoration could not be verified"
                      " (restored DACL could not be read)")
        self.assert_no_effect(before)

    def test_a_refusal_with_another_error_is_not_a_denial(self):
        self.model.token_bypasses_deny = True
        error = OSError(2, "modeled missing path")
        error.winerror = 3
        self.model.mkdir_error = error
        before = self.model.sddl(self.parent)
        self.hold(v1.DENIAL_UNVERIFIED)
        self.assert_no_effect(before)

    def test_a_probe_directory_that_cannot_be_removed_is_reported(self):
        self.model.token_bypasses_deny = True
        self.model.rmdir_fails = True
        self.hold(v1.TOKEN_NOT_REFUSED + "; the probe directory was not removed")
        self.assertFalse(self.receipt.exists())

    def test_a_replay_never_removes_a_deny_it_did_not_add(self):
        result = self.fence()
        self.model.token_bypasses_deny = True
        after = self.model.sddl(self.parent)
        self.hold(v1.TOKEN_NOT_REFUSED)
        self.assertEqual(self.model.sddl(self.parent), after)
        self.model.token_bypasses_deny = False
        self.assertEqual(self.fence(), result)


class ModeledV4TokenGateTests(ModeledFence):
    def test_parent_deny_must_refuse_creation_before_rename_and_on_archive_replay(self):
        source, phase = [self.parent / name for name in ("source-stage.lock", "phase-stage.lock")]
        for lock in (source, phase):
            lock.write_bytes(b"0")
        barrier = self.control / "barrier.json"
        parent_pin = bytes_digest(self.model.sddl(self.parent).encode())
        file_pins = {name: bytes_digest(self.model.sddl(self.old / name).encode())
                     for name in v4.NAMES}

        def fence():
            return v4.fence_closed_old_phase_guarded(
                old_root=self.old, archived_root=self.archived, expected_file_sha256=self.content,
                source_stage_lock=source, phase_stage_lock=phase, deny_sid=self.sid,
                expected_parent_dacl_sha256=parent_pin, expected_file_dacl_sha256=file_pins,
                barrier_receipt_path=barrier, fence_receipt_path=self.receipt)

        with patch.object(v4, "os", v1.os), patch.object(v4, "subprocess", self.model), \
             patch.object(v4, "_current_sid", return_value=self.sid), \
             patch.object(v4, "directory_dacl_sddl", side_effect=self.model.sddl), \
             patch.object(v4, "_stage_lock", side_effect=lambda path: path.open("r+b")):
            self.model.token_bypasses_deny = True
            with self.assertRaisesRegex(ContractError, v1.TOKEN_NOT_REFUSED):
                fence()
            self.assertTrue(self.old.is_dir() and barrier.is_file())
            self.assertFalse(self.archived.exists() or self.receipt.exists())
            self.assertTrue(v4.dacl_has_ace(self.model.sddl(self.parent), PARENT, self.sid))
            self.model.token_bypasses_deny = False
            result = fence()
            self.model.token_bypasses_deny = True
            with self.assertRaisesRegex(ContractError, v1.TOKEN_NOT_REFUSED):
                fence()
            self.assertFalse(self.old.exists())
            self.model.token_bypasses_deny = False
            self.assertEqual(fence(), result)


class SharedHelperContractTests(unittest.TestCase):
    def setUp(self):
        for item in (patch.object(authority, "_is_windows", return_value=True),
                     patch.object(authority, "_windows_trustee", side_effect=WindowsModel.spell)):
            item.start()
            self.addCleanup(item.stop)

    def test_only_the_trustee_field_is_normalized(self):
        for sid, alias in ((USERS_SID, "BU"), (LOCAL_RID500_SID, "LA")):
            for spelling in (sid, alias):
                self.assertTrue(authority.dacl_has_ace("D:(D;;LC;;;%s)" % spelling, PARENT, sid))
                self.assertTrue(authority.dacl_has_ace("D:AI(D;;DCLC;;;%s)(A;ID;FA;;;SY)" % spelling,
                                                       FILE, sid))
            for text in ("D:(D;;DCLC;;;%s)", "D:(D;OI;LC;;;%s)", "D:(A;;LC;;;%s)", "D:(OD;;LC;;;%s)"):
                self.assertFalse(authority.dacl_has_ace(text % alias, PARENT, sid), text)
        self.assertEqual(authority.canonical_dacl_ace("(D;;LC;;;%s)" % USERS_SID), "(D;;LC;;;BU)")
        self.assertEqual(authority.canonical_dacl_ace("(OA;;CR;guid;;S-1-5-32-545)"),
                         "(OA;;CR;guid;;BU)")
        self.assertEqual(authority.canonical_dacl_ace("(D;;LC;;S-1-5-32-545)"),
                         "(D;;LC;;S-1-5-32-545)")
        injected = "S-1-5-18)(A;;FA;;;WD"
        self.assertEqual(authority.canonical_dacl_trustee(injected), injected)

    def test_distinct_rid500_and_other_trustees_never_match(self):
        sids = (LOCAL_RID500_SID, FOREIGN_RID500_SID, NEAR_RID500_SID, PLAIN_SID, USERS_SID)
        for ace_sid in sids:
            for spelling in {authority.canonical_dacl_trustee(ace_sid), ace_sid}:
                text = "D:(D;;LC;;;%s)(A;OICIID;FA;;;SY)" % spelling
                for query in sids:
                    same = query == ace_sid
                    self.assertEqual(authority.dacl_has_ace(text, PARENT, query), same, (spelling, query))
                    self.assertEqual(authority.dacl_has_deny_trustee(text, query), same, (spelling, query))
                    self.assertEqual(v4._owner_deny_present(text, query), same, (spelling, query))

    def test_v4_dacl_comparisons_use_canonical_trustees_and_keep_order_and_flags(self):
        original = "D:(A;ID;FA;;;SY)(A;ID;FA;;;BA)"
        good = "D:AI(D;;DCLC;;;BU)(A;ID;FA;;;SY)(A;ID;FA;;;BA)"
        self.assertTrue(v4._only_admission_dacl_added(original, good, USERS_SID))
        for current in ("D:AI(D;;DCLC;;;BG)(A;ID;FA;;;SY)(A;ID;FA;;;BA)",
                        "D:AI(D;;DC;;;BU)(A;ID;FA;;;SY)(A;ID;FA;;;BA)",
                        "D:AI(D;OI;DCLC;;;BU)(A;ID;FA;;;SY)(A;ID;FA;;;BA)",
                        "D:AI(D;;DCLC;;;BU)(A;ID;FA;;;BA)(A;ID;FA;;;SY)",
                        "D:AI(D;;DCLC;;;BU)(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;;FR;;;WD)",
                        "D:PAI(D;;DCLC;;;BU)(A;ID;FA;;;SY)(A;ID;FA;;;BA)"):
            self.assertFalse(v4._only_admission_dacl_added(original, current, USERS_SID), current)
        self.assertTrue(v4._only_parent_admission_added(
            "D:(A;OICIID;FA;;;SY)", "D:AI(D;;LC;;;LA)(A;OICIID;FA;;;SY)", LOCAL_RID500_SID))
        self.assertFalse(v4._only_parent_admission_added(
            "D:(A;OICIID;FA;;;SY)", "D:AI(D;;LC;;;LA)(A;OICIID;FA;;;SY)", FOREIGN_RID500_SID))
        self.assertTrue(v4._same_effective_dacl("D:(D;;DCLC;;;LA)", "D:AI(D;;DCLC;;;%s)" % LOCAL_RID500_SID))
        self.assertFalse(v4._same_effective_dacl("D:(D;;DCLC;;;LA)", "D:(D;;DCLC;;;%s)" % FOREIGN_RID500_SID))


class OffWindowsContractTests(unittest.TestCase):
    def test_numeric_sids_fail_closed_off_windows_and_other_text_passes_through(self):
        with patch.object(authority, "_is_windows", return_value=False):
            with self.assertRaises(ContractError) as caught:
                authority.canonical_dacl_trustee(USERS_SID)
            self.assertEqual(caught.exception.code, "PHASE_PLATFORM")
            self.assertEqual(authority.canonical_dacl_trustee("BU"), "BU")
            with self.assertRaises(ContractError):
                authority.dacl_has_ace("D:(D;;LC;;;BU)", PARENT, USERS_SID)


if __name__ == "__main__":
    unittest.main()
