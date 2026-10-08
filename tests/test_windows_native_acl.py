"""Descriptor installation without an account lookup, and the directory-creation denial probe.

The platform-independent cases run the real helper logic against a labelled fake of the Win32
layer. They show that each observed outcome gets its own verdict, that only a refusal for the full
original token passes (creation by either route fails whatever the privileges or the stripped
token say), that a deny whose trustee Windows reads back as an alias is found and removed by its
full SID, that a restoration is verified for control and protection flags, ordered ACEs and
owner, and that nothing sensitive reaches the report. The Windows-only cases run the same helpers
on an owned temporary directory against the real descriptor, token and access-check APIs; they
assert facts that do not depend on why a given host does or does not refuse ``mkdir``.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from tests import test_paper_pilot_phase_trustees_v1_v4 as v1_v4
from tools import windows_fence_diagnostics
from tools import windows_fixture_acl
from tools import windows_native_acl as native_acl

WINDOWS = os.name == "nt"
FOREIGN = "S-1-5-21-1111111111-2222222222-3333333333-500"
MACHINE = "S-1-5-21-4444444444-5555555555-6666666666-500"
NEAR_MACHINE = "S-1-5-21-4444444444-5555555555-6666666667-500"
USERS = "S-1-5-32-545"
BASE = "D:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)"
PROTECTED = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)"
ALIASES = {MACHINE: "LA", USERS: "BU"}
ROUTES = ("os.mkdir", "CreateDirectoryW")
SCRIPT = Path(native_acl.__file__).resolve()


class FakeNative:
    """A labelled model of the Win32 layer: one DACL string, scripted creation outcomes."""

    def __init__(self, *, dacl=BASE, stripped_creates=False, full_creates=False,
                 enabled=("SeChangeNotifyPrivilege",), disabled=("SeBackupPrivilege",),
                 stripped_mask=0x1F01FF & ~0x4, full_mask=0x1F01FF & ~0x4, routes=ROUTES,
                 codes=None, unremoved=()):
        self.dacl, self.owner = dacl, "O:BA"
        self.creates = {True: stripped_creates, False: full_creates}
        self.enabled, self.disabled = tuple(enabled), tuple(disabled)
        self.masks = {True: stripped_mask, False: full_mask}
        self.routes = tuple(routes)
        self.codes, self.unremoved = dict(codes or {}), set(unremoved)
        self.calls, self.removed = [], []

    def privileges(self):
        return [(name, True) for name in self.enabled] + [(name, False) for name in self.disabled]

    def filesystem(self, path):
        return "NTFS"

    def canonical_trustee(self, sid):
        return ALIASES.get(sid, sid)

    def read_dacl(self, path):
        return self.dacl

    def read_owner(self, path):
        return self.owner

    def apply_dacl(self, path, sddl, protection="auto"):
        self.applied = getattr(self, "applied", []) + [protection]
        self.dacl = sddl

    def access_mask(self, path, stripped):
        return self.masks[stripped]

    def try_create_directory(self, path, stripped, route="os.mkdir"):
        self.calls.append(("directory", "stripped" if stripped else "full", route))
        if self.creates[stripped] and route in self.routes:
            self.removed.append(str(path))
            return {"created": True, "removed": "directory" not in self.unremoved}
        return {"created": False, "winerror": self.codes.get((stripped, route), 5)}

    def try_create_file(self, path, stripped):
        self.calls.append(("file", "stripped" if stripped else "full"))
        return {"created": True, "removed": "file" not in self.unremoved}


class AliasingNative(FakeNative):
    """Windows reads a well-known or machine-local numeric trustee back as its alias."""

    def apply_dacl(self, path, sddl, protection="auto"):
        self.applied = getattr(self, "applied", []) + [protection]

        def spell(match):
            return ";;;" + ALIASES.get(match.group(1), match.group(1)) + ")"
        self.dacl = re.sub(r";;;(S-1-[0-9-]+)\)", spell, sddl)


class ProtectionDroppingNative(AliasingNative):
    """Restores every ACE exactly but loses the DACL protection flag."""

    def apply_dacl(self, path, sddl):
        super().apply_dacl(path, sddl.replace("D:PAI", "D:AI"))


class OwnerChangingNative(AliasingNative):
    def apply_dacl(self, path, sddl):
        super().apply_dacl(path, sddl)
        self.owner = "O:SY"


class DescriptorTextTests(unittest.TestCase):
    def test_an_ace_is_inserted_first_and_removed_exactly_once(self):
        ace = "(D;;LC;;;" + FOREIGN + ")"
        added = native_acl.with_ace_first(BASE, ace)
        self.assertEqual(added, "D:AI" + ace + "(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)")
        self.assertEqual(native_acl.split_dacl(added)[1][0], ace)
        self.assertEqual(native_acl.without_ace(added, ace), BASE)
        twice = native_acl.with_ace_first(added, ace)
        self.assertEqual(native_acl.without_ace(twice, ace), added)
        with self.assertRaises(ValueError):
            native_acl.without_ace(BASE, ace)

    def test_text_that_is_not_one_plain_dacl_is_refused(self):
        for text in ("", "O:BAD:(A;;FA;;;SY)", BASE + "S:(AU;SA;FA;;;WD)", "D:(A;;FA;;;SY"):
            with self.subTest(text):
                with self.assertRaises(ValueError):
                    native_acl.split_dacl(text)

    def test_deny_by_descriptor_installs_one_exact_ace_and_keeps_the_owner(self):
        fake = FakeNative()
        done = native_acl.deny_by_descriptor(fake, Path("parent"), FOREIGN)
        self.assertEqual(done["ace"], "(D;;LC;;;" + FOREIGN + ")")
        self.assertEqual(native_acl.split_dacl(done["after"])[1],
                         [done["ace"]] + native_acl.split_dacl(BASE)[1])
        self.assertEqual(done["owner_before"], done["owner_after"])
        self.assertTrue(done["installed_exactly"])
        self.assertTrue(native_acl.remove_descriptor_deny(fake, Path("parent"), FOREIGN))
        self.assertEqual(fake.dacl, BASE)
        with self.assertRaises(ValueError):
            native_acl.remove_descriptor_deny(fake, Path("parent"), FOREIGN)

    def test_a_deny_that_windows_reads_back_as_an_alias_is_found_and_removed_by_its_full_sid(self):
        for sid, alias in ((MACHINE, "LA"), (USERS, "BU")):
            with self.subTest(sid):
                fake = AliasingNative(dacl=PROTECTED)
                done = native_acl.deny_by_descriptor(fake, Path("parent"), sid)
                self.assertTrue(done["installed_exactly"])
                self.assertEqual(native_acl.split_dacl(fake.dacl)[1][0], "(D;;LC;;;%s)" % alias)
                self.assertNotIn(done["ace"], native_acl.split_dacl(fake.dacl)[1])
                with self.assertRaises(ValueError):
                    native_acl.without_ace(fake.dacl, done["ace"])
                self.assertTrue(native_acl.deny_present(fake, Path("parent"), sid))
                self.assertTrue(native_acl.remove_descriptor_deny(fake, Path("parent"), sid))
                self.assertEqual(fake.dacl, PROTECTED)
                self.assertFalse(native_acl.deny_present(fake, Path("parent"), sid))

    def test_an_installation_that_is_not_exact_is_not_reported_as_installed(self):
        class LastNative(AliasingNative):
            def apply_dacl(self, path, sddl):
                control, aces = native_acl.split_dacl(sddl)
                super().apply_dacl(path, native_acl.join_dacl(control, [*aces[1:], aces[0]]))

        class DroppingNative(AliasingNative):
            def apply_dacl(self, path, sddl):
                control, aces = native_acl.split_dacl(sddl)
                super().apply_dacl(path, native_acl.join_dacl(control, aces[:-1]))
        cases = {"order": LastNative, "protection": ProtectionDroppingNative,
                 "owner": OwnerChangingNative, "lost ace": DroppingNative}
        for label, cls in cases.items():
            with self.subTest(label):
                done = native_acl.deny_by_descriptor(cls(dacl=PROTECTED), Path("parent"), FOREIGN)
                self.assertFalse(done["installed_exactly"])
        self.assertTrue(native_acl.deny_by_descriptor(AliasingNative(dacl=PROTECTED), Path("parent"),
                                                      FOREIGN)["installed_exactly"])

    def test_removal_takes_only_the_intended_ace_and_never_collapses_distinct_rid500_sids(self):
        start = ("D:PAI(D;;LC;;;LA)(D;;LC;;;%s)(D;;DC;;;LA)(D;OICI;LC;;;LA)(A;;LC;;;LA)(A;OICI;FA;;;SY)"
                 % FOREIGN)
        fake = AliasingNative(dacl=start)
        self.assertTrue(native_acl.remove_descriptor_deny(fake, Path("parent"), MACHINE))
        self.assertEqual(fake.dacl, "D:PAI(D;;LC;;;%s)(D;;DC;;;LA)(D;OICI;LC;;;LA)(A;;LC;;;LA)(A;OICI;FA;;;SY)"
                         % FOREIGN)
        self.assertTrue(native_acl.remove_descriptor_deny(fake, Path("parent"), FOREIGN))
        self.assertEqual(fake.dacl, "D:PAI(D;;DC;;;LA)(D;OICI;LC;;;LA)(A;;LC;;;LA)(A;OICI;FA;;;SY)")
        for other in (FOREIGN, NEAR_MACHINE, "S-1-5-21-4444444444-5555555555-6666666666-1001"):
            with self.subTest(other):
                before = fake.dacl
                self.assertFalse(native_acl.deny_present(fake, Path("parent"), other))
                with self.assertRaises(ValueError):
                    native_acl.remove_descriptor_deny(fake, Path("parent"), other)
                self.assertEqual(fake.dacl, before)
        twice = AliasingNative(dacl="D:PAI(D;;LC;;;LA)(A;OICI;FA;;;SY)(D;;LC;;;LA)")
        self.assertTrue(native_acl.remove_descriptor_deny(twice, Path("parent"), MACHINE))
        self.assertEqual(twice.dacl, "D:PAI(A;OICI;FA;;;SY)(D;;LC;;;LA)")
        foreign_only = AliasingNative(dacl="D:PAI(D;;LC;;;%s)(A;OICI;FA;;;SY)" % FOREIGN)
        with self.assertRaises(ValueError):
            native_acl.remove_descriptor_deny(foreign_only, Path("parent"), MACHINE)
        self.assertEqual(foreign_only.dacl, "D:PAI(D;;LC;;;%s)(A;OICI;FA;;;SY)" % FOREIGN)

    def test_a_removal_that_drops_protection_or_changes_the_owner_is_reported_as_failed(self):
        for label, cls in (("protection", ProtectionDroppingNative), ("owner", OwnerChangingNative)):
            with self.subTest(label):
                fake = cls(dacl=PROTECTED)
                fake.dacl = "D:PAI(D;;LC;;;LA)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)"
                self.assertFalse(native_acl.remove_descriptor_deny(fake, Path("parent"), MACHINE))
                self.assertNotIn("(D;;LC;;;LA)", fake.dacl)

    def test_restoration_names_each_component_that_differs(self):
        fake = AliasingNative(dacl=PROTECTED)
        owner = fake.owner
        path = Path("parent")
        self.assertEqual(native_acl.restoration(fake, path, PROTECTED, owner),
                         {"control": True, "aces": True, "owner": True, "verified": True})
        spelled = PROTECTED.replace("(A;OICI;FA;;;BA)", "(A;OICI;FA;;;" + USERS + ")")
        self.assertTrue(native_acl.restoration(AliasingNative(dacl=PROTECTED.replace(
            "(A;OICI;FA;;;BA)", "(A;OICI;FA;;;BU)")), path, spelled, owner)["verified"])
        cases = {
            "control": (PROTECTED.replace("D:PAI", "D:AI"), owner, "control"),
            "aces": (PROTECTED.replace("(A;OICI;FA;;;BA)", ""), owner, "aces"),
            "order": ("D:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;FA;;;OW)", owner, "aces"),
            "flags": (PROTECTED.replace("OICI;FA;;;SY", "OI;FA;;;SY"), owner, "aces"),
            "owner": (PROTECTED, "O:SY", "owner"),
        }
        for label, (dacl, now_owner, component) in cases.items():
            with self.subTest(label):
                drifted = AliasingNative(dacl=dacl)
                drifted.owner = now_owner
                result = native_acl.restoration(drifted, path, PROTECTED, owner)
                self.assertFalse(result["verified"])
                self.assertFalse(result[component])
                self.assertEqual(sum(1 for value in result.values() if not value), 2)


class VerdictTests(unittest.TestCase):
    def report(self, **options):
        return native_acl.recreation_report(FakeNative(**options), Path("parent"), Path("parent") / "state")

    def test_a_denial_for_both_tokens_is_the_denied_verdict(self):
        report = self.report()
        self.assertEqual(report["verdict"], "DENIED")
        self.assertFalse(report["cause_established"])

    def test_only_a_refusal_is_accepted(self):
        self.assertEqual(native_acl.ACCEPTED_VERDICTS, ("DENIED",))

    def test_full_token_creation_by_either_route_fails_whatever_the_privileges_or_the_stripped_token_say(self):
        bypass = dict(enabled=("SeChangeNotifyPrivilege", "SeBackupPrivilege", "SeRestorePrivilege"),
                      disabled=())
        for route in ROUTES:
            for label, options in (
                    ("bypass privilege enabled and AccessCheck denies", bypass),
                    ("no privilege", {}),
                    ("AccessCheck grants the right", dict(full_mask=0x1F01FF))):
                with self.subTest(route=route, case=label):
                    fake = FakeNative(full_creates=True, routes=(route,), **options)
                    with self.assertRaises(AssertionError) as caught:
                        native_acl.require_recreation_denied(fake, Path("parent"), Path("parent") / "state")
                    report = json.loads(str(caught.exception).split(": ", 1)[1])
                    self.assertTrue(report["verdict"].startswith("FULL_TOKEN_CREATES"), report["verdict"])
                    self.assertTrue(report[{"os.mkdir": "mkdir"}.get(route, "mkdir_CreateDirectoryW")]
                                    ["full"]["created"])
                    self.assertFalse(report["cause_established"])
                    self.assertNotIn(report["verdict"], native_acl.ACCEPTED_VERDICTS)

    def test_every_other_outcome_is_refused_with_its_own_verdict(self):
        cases = [
            ("FULL_TOKEN_CREATES_UNEXPLAINED", dict(full_creates=True)),
            ("FULL_TOKEN_CREATES_UNEXPLAINED", dict(full_creates=True, enabled=("SeChangeNotifyPrivilege",),
                                                    disabled=("SeBackupPrivilege", "SeRestorePrivilege"))),
            ("FULL_TOKEN_CREATES_UNEXPLAINED", dict(full_creates=True, enabled=("SeRestorePrivilege",),
                                                    full_mask=0x1F01FF)),
            ("FULL_TOKEN_CREATES_WHILE_BYPASS_PRIVILEGE_ENABLED",
             dict(full_creates=True, enabled=("SeBackupPrivilege",))),
            ("KERNEL_CREATE_IGNORES_DACL", dict(stripped_creates=True, full_creates=True)),
            ("DACL_GRANTS_ADD_SUBDIRECTORY", dict(stripped_creates=True, full_creates=True, stripped_mask=0x1F01FF)),
        ]
        for expected, options in cases:
            with self.subTest(expected, options=options):
                report = self.report(**options)
                self.assertEqual(report["verdict"], expected)
                self.assertNotIn(report["verdict"], native_acl.ACCEPTED_VERDICTS)
                fake = FakeNative(**options)
                with self.assertRaises(AssertionError) as caught:
                    native_acl.require_recreation_denied(fake, Path("parent"), Path("parent") / "state")
                self.assertIn(expected, str(caught.exception))
                self.assertEqual(json.loads(str(caught.exception).split(": ", 1)[1])["verdict"], expected)

    def test_a_refusal_that_is_not_access_denied_is_not_a_denial_for_any_route_or_token(self):
        for code, meaning in ((2, "file not found"), (3, "path not found"), (32, "sharing violation"),
                               (87, "invalid parameter"), (112, "disk full"), (123, "invalid name"),
                               (183, "already exists"), (None, "no Windows error at all")):
            for stripped in (True, False):
                for route in ROUTES:
                    with self.subTest(code=code, meaning=meaning, stripped=stripped, route=route):
                        options = dict(codes={(stripped, route): code})
                        report = self.report(**options)
                        self.assertEqual(report["verdict"], "REFUSED_WITHOUT_ACCESS_DENIED")
                        self.assertEqual(report["non_denial_outcomes"],
                                         [{"route": route, "token": "stripped" if stripped else "full",
                                           "winerror": code}])
                        self.assertNotIn(report["verdict"], native_acl.ACCEPTED_VERDICTS)
                        with self.assertRaises(AssertionError) as caught:
                            native_acl.require_recreation_denied(
                                FakeNative(**options), Path("parent"), Path("parent") / "state")
                        facts = json.loads(str(caught.exception).split(": ", 1)[1])
                        self.assertEqual(facts["non_denial_outcomes"], report["non_denial_outcomes"])

    def test_only_error_access_denied_counts_as_a_refusal_and_every_outcome_is_checked(self):
        self.assertEqual(native_acl.ERROR_ACCESS_DENIED, 5)
        report = self.report()
        self.assertEqual(report["non_denial_outcomes"], [])
        for key in ("mkdir", "mkdir_CreateDirectoryW"):
            for label in ("stripped", "full"):
                self.assertEqual(report[key][label], {"created": False, "winerror": 5}, (key, label))
        mixed = self.report(codes={(True, "os.mkdir"): 3, (False, "CreateDirectoryW"): 183})
        self.assertEqual([(o["route"], o["token"], o["winerror"]) for o in mixed["non_denial_outcomes"]],
                         [("os.mkdir", "stripped", 3), ("CreateDirectoryW", "full", 183)])

    def test_an_outcome_that_carries_no_windows_error_is_not_a_denial(self):
        report = self.report()
        report["mkdir_CreateDirectoryW"]["full"] = {"created": False}
        self.assertEqual(native_acl.classify(report), "REFUSED_WITHOUT_ACCESS_DENIED")
        self.assertEqual(native_acl.non_denial_outcomes(report),
                         [{"route": "CreateDirectoryW", "token": "full", "winerror": None}])

    def test_a_creation_still_outranks_an_unrelated_failure_on_another_probe(self):
        report = self.report(full_creates=True, routes=("os.mkdir",), codes={(False, "CreateDirectoryW"): 3})
        self.assertEqual(report["verdict"], "FULL_TOKEN_CREATES_UNEXPLAINED")

    def test_a_probe_that_does_not_verifiably_remove_what_it_created_fails_the_gate(self):
        for kind in ("file", "directory"):
            with self.subTest(kind):
                fake = FakeNative(unremoved=(kind,), stripped_creates=kind == "directory",
                                  full_creates=kind == "directory")
                report = native_acl.recreation_report(fake, Path("parent"), Path("parent") / "state")
                self.assertFalse(report["probe_cleanup_verified"])
                with self.assertRaises(AssertionError):
                    native_acl.require_recreation_denied(fake, Path("parent"), Path("parent") / "state")
        denied_but_dirty = FakeNative(unremoved=("file",))
        report = native_acl.recreation_report(denied_but_dirty, Path("parent"), Path("parent") / "state")
        self.assertEqual(report["verdict"], "DENIED")
        with self.assertRaises(AssertionError) as caught:
            native_acl.require_recreation_denied(denied_but_dirty, Path("parent"), Path("parent") / "state")
        self.assertFalse(json.loads(str(caught.exception).split(": ", 1)[1])["probe_cleanup_verified"])
        self.assertTrue(native_acl.recreation_report(
            FakeNative(), Path("parent"), Path("parent") / "state")["probe_cleanup_verified"])

    def test_creation_by_either_route_counts_as_creation(self):
        base = self.report()
        self.assertEqual(base["verdict"], "DENIED")
        for route in ("mkdir", "mkdir_CreateDirectoryW"):
            report = json.loads(json.dumps(base))
            report[route]["full"] = {"created": True, "removed": True}
            self.assertEqual(native_acl.classify(report), "FULL_TOKEN_CREATES_UNEXPLAINED", route)
            report[route]["stripped"] = {"created": True, "removed": True}
            self.assertEqual(native_acl.classify(report), "KERNEL_CREATE_IGNORES_DACL", route)

    def test_a_denied_probe_passes_and_returns_its_report(self):
        report = native_acl.require_recreation_denied(FakeNative(), Path("parent"), Path("parent") / "state")
        self.assertEqual(report["verdict"], "DENIED")

    def test_the_privilege_stripped_token_is_attempted_before_the_full_token_by_every_route(self):
        fake = FakeNative()
        native_acl.recreation_report(fake, Path("parent"), Path("parent") / "state")
        directories = [call for call in fake.calls if call[0] == "directory"]
        self.assertEqual(directories, [("directory", "stripped", "os.mkdir"),
                                       ("directory", "stripped", "CreateDirectoryW"),
                                       ("directory", "full", "os.mkdir"),
                                       ("directory", "full", "CreateDirectoryW")])

    def test_the_report_has_no_path_or_machine_identifier(self):
        fake = FakeNative(dacl="D:PAI(D;;LC;;;" + MACHINE + ")(A;OICI;FA;;;SY)")
        report = native_acl.recreation_report(fake, Path("secret-parent"), Path("secret-parent") / "secret-state")
        text = json.dumps(report)
        self.assertNotIn("secret", text)
        self.assertNotIn("4444444444", text)
        self.assertIn("S-1-5-21-<machine>-500", text)


class CandidateMatrixTests(unittest.TestCase):
    def test_every_shape_is_tried_and_every_original_dacl_is_restored(self):
        fake = FakeNative()
        matrix = native_acl.candidate_matrix(fake, MACHINE, lambda label: Path(label))
        self.assertEqual(sorted(matrix["shapes"]), sorted(native_acl.CANDIDATE_SHAPES))
        self.assertTrue(matrix["cleanup_verified"])
        self.assertEqual(fake.dacl, BASE)
        self.assertIn("(D;;LC;;;" + MACHINE + ")",
                      matrix["shapes"]["current_LC"]["installed_dacl"].replace("S-1-5-21-<machine>-500", MACHINE))
        for label, entry in matrix["shapes"].items():
            self.assertEqual(entry["restored"],
                             {"control": True, "aces": True, "owner": True, "verified": True}, label)
            self.assertEqual(sorted(entry["mkdir"]), ["full", "stripped"], label)

    def test_a_restore_that_does_not_take_effect_fails_the_cleanup_verdict(self):
        class Sticky(FakeNative):
            def apply_dacl(self, path, sddl):
                if "(D;" in sddl:
                    self.dacl = sddl
        fake = Sticky()
        matrix = native_acl.candidate_matrix(fake, MACHINE, lambda label: Path(label))
        self.assertFalse(matrix["cleanup_verified"])
        self.assertFalse(matrix["shapes"]["current_LC"]["restored"]["verified"])
        self.assertTrue(matrix["shapes"]["control_no_deny"]["restored"]["verified"])

    def test_a_created_probe_directory_that_is_not_removed_fails_the_matrix_cleanup(self):
        fake = FakeNative(stripped_creates=True, full_creates=True, unremoved=("directory",))
        matrix = native_acl.candidate_matrix(fake, MACHINE, lambda label: Path(label))
        self.assertFalse(matrix["cleanup_verified"])
        self.assertFalse(matrix["shapes"]["current_LC"]["probe_cleanup_verified"])
        clean = native_acl.candidate_matrix(
            FakeNative(stripped_creates=True, full_creates=True), MACHINE, lambda label: Path(label))
        self.assertTrue(clean["cleanup_verified"])
        self.assertEqual(sorted(clean["shapes"]["current_LC"]["mkdir_CreateDirectoryW"]), ["full", "stripped"])

    def test_the_actual_fence_probe_is_not_verified_when_its_own_probe_cleanup_is_not(self):
        fake = AliasingNative(dacl=PROTECTED, unremoved=("file",))
        done = native_acl.probe_actual_fence_shape(fake, lambda label: Path(label), MACHINE)
        self.assertTrue(done["restored"]["verified"])
        self.assertFalse(done["verified"])

    def test_a_failed_step_is_recorded_and_the_cleanup_is_not_reported_verified(self):
        class Failing(FakeNative):
            def access_mask(self, path, stripped):
                raise native_acl.NativeError("AccessCheck", 5)
        fake = Failing()
        matrix = native_acl.candidate_matrix(fake, MACHINE, lambda label: Path(label))
        self.assertFalse(matrix["cleanup_verified"])
        self.assertEqual(matrix["shapes"]["current_LC"]["error"], {"type": "NativeError", "code": 5})
        self.assertEqual(fake.dacl, BASE)

    def test_a_restoration_that_keeps_every_ace_but_loses_protection_is_not_verified(self):
        fake = ProtectionDroppingNative(dacl=PROTECTED)
        matrix = native_acl.candidate_matrix(fake, MACHINE, lambda label: Path(label))
        self.assertFalse(matrix["cleanup_verified"])
        self.assertEqual(matrix["shapes"]["control_no_deny"]["restored"],
                         {"control": False, "aces": True, "owner": True, "verified": False})
        self.assertEqual(native_acl.split_dacl(fake.dacl)[0], "AI")

    def test_a_restoration_that_changes_the_owner_is_not_verified(self):
        fake = OwnerChangingNative(dacl=PROTECTED)
        matrix = native_acl.candidate_matrix(fake, MACHINE, lambda label: Path(label))
        self.assertFalse(matrix["cleanup_verified"])
        self.assertEqual(matrix["shapes"]["control_no_deny"]["restored"],
                         {"control": True, "aces": True, "owner": False, "verified": False})

    def test_the_actual_fence_shape_probe_restores_and_verifies_its_parent(self):
        fake = AliasingNative(dacl=PROTECTED)
        done = native_acl.probe_actual_fence_shape(fake, lambda label: Path(label), MACHINE)
        self.assertEqual(done["restored"]["verified"], True)
        self.assertEqual(fake.dacl, PROTECTED)
        self.assertEqual(done["report"]["verdict"], "DENIED")
        drift = ProtectionDroppingNative(dacl=PROTECTED)
        done = native_acl.probe_actual_fence_shape(drift, lambda label: Path(label), MACHINE)
        self.assertEqual(done["restored"], {"control": False, "aces": True, "owner": True, "verified": False})


class RedactionTests(unittest.TestCase):
    SAMPLES = ("D:PAI(D;;LC;;;S-1-5-21-1111111111-2222222222-3333333333-500)(A;;FA;;;S-1-12-1-1-2-3-4)",
               "O:S-1-5-21-4444444444-5555555555-6666666666-1001", "S-1-5-32-545", "no sid here", "")

    def test_the_local_redaction_matches_the_diagnostics_sanitizer(self):
        for text in self.SAMPLES:
            self.assertEqual(native_acl.redact(text), windows_fence_diagnostics.redact(text), text)

    def test_machine_and_directory_sub_authorities_are_masked_and_the_rid_is_kept(self):
        masked = native_acl.redact(self.SAMPLES[0])
        self.assertIn("S-1-5-21-<machine>-500", masked)
        self.assertIn("S-1-12-1-<directory>", masked)
        self.assertNotIn("1111111111", masked)
        self.assertEqual(native_acl.redact(self.SAMPLES[2]), self.SAMPLES[2])

    def test_loading_the_module_by_path_edits_neither_the_path_nor_the_imports(self):
        code = (
            "import importlib.util, sys\n"
            "paths, modules = list(sys.path), set(sys.modules)\n"
            "spec = importlib.util.spec_from_file_location('loaded_by_path', %r)\n"
            "module = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(module)\n"
            "appeared = {name.split('.')[0] for name in set(sys.modules) - modules}\n"
            "print(sys.path == paths, sorted(appeared & {'trace_gc', 'src', 'tools'}))\n" % str(SCRIPT))
        done = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True,
                              cwd=tempfile.gettempdir(), timeout=60)
        self.assertEqual((done.returncode, done.stdout.strip()), (0, "True []"), done.stderr)


class SourceScriptTests(unittest.TestCase):
    """``python tools/windows_native_acl.py`` in a fresh interpreter, from another directory."""

    def run_script(self, *arguments):
        environment = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
        done = subprocess.run([sys.executable, str(SCRIPT), *arguments], capture_output=True, text=True,
                              cwd=tempfile.gettempdir(), env=environment, timeout=300)
        return done, json.loads(done.stdout)

    def test_a_fresh_interpreter_runs_the_script_past_its_checkout_imports(self):
        done, report = self.run_script("--stages-only")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertNotEqual(report.get("error", {}).get("type"), "ModuleNotFoundError", report)
        self.assertEqual(report["completed_stages"][:2], ["bootstrap", "checkout_imports"], report)
        if WINDOWS:
            self.assertEqual(report["completed_stages"], ["bootstrap", "checkout_imports", "native_api", "identity"])
            self.assertNotIn("error", report)
        else:
            self.assertEqual(report["error"], {"code": None, "stage": "native_api", "type": "NativeError"})
        self.assertEqual(report["os_name"], os.name)

    def test_the_full_report_names_its_stages_and_has_no_path_or_account(self):
        done, report = self.run_script()
        self.assertNotEqual(report.get("error", {}).get("type"), "ModuleNotFoundError", report)
        self.assertEqual(report["completed_stages"][:2], ["bootstrap", "checkout_imports"], report)
        text = done.stdout
        self.assertNotIn(tempfile.gettempdir(), text)
        self.assertNotRegex(text, r"S-1-5-21-\d+-\d+-\d+-\d+")
        if WINDOWS:
            self.assertEqual(done.returncode, 0 if report["cleanup_verified"] else 1, done.stderr)
            for section in ("matrix", "actual_fence_shape", "privilege_isolation",
                            "installation_observation", "restricted_primary_child"):
                self.assertIn(section, report, report)
        else:
            self.assertEqual(done.returncode, 0, done.stderr)

    def test_the_child_entry_writes_a_report_and_nothing_else(self):
        with tempfile.TemporaryDirectory(prefix="jraphyte-native-acl-") as temp:
            out = Path(temp) / "child.json"
            done = subprocess.run([sys.executable, str(SCRIPT), "--child-recreation-probe",
                                   temp, str(Path(temp) / "state"), str(out)],
                                  capture_output=True, text=True, timeout=120)
            self.assertEqual((done.returncode, done.stdout), (0, ""), done.stderr)
            body = json.loads(out.read_text(encoding="utf-8"))
            if WINDOWS:
                self.assertIn(body["verdict"], ("DACL_GRANTS_ADD_SUBDIRECTORY", "DENIED"))
                self.assertIs(body["probe_cleanup_verified"], True)
                self.assertFalse((Path(temp) / "state").exists())
            else:
                self.assertEqual(body["error"]["type"], "NativeError")


class InstallationComponentTests(unittest.TestCase):
    ACE = "(D;;LC;;;" + USERS + ")"

    def components(self, after, *, before=PROTECTED, owner_after="O:BA", native=None):
        return native_acl.installation_components(native or AliasingNative(), before, after,
                                                  self.ACE, "O:BA", owner_after)

    def test_an_exact_installation_reports_every_component_as_exact(self):
        components = self.components(native_acl.with_ace_first(PROTECTED, "(D;;LC;;;BU)"))
        self.assertTrue(components["installed_exactly"], components)
        self.assertEqual(components["control"], {"before": "PAI", "after": "PAI", "unchanged": True})
        aces = components["aces"]
        self.assertEqual((aces["count_before"], aces["count_after"], aces["new_ace_first"]), (3, 4, True))
        self.assertEqual((aces["explicit_after"], aces["inherited_after"]), (4, 0))
        self.assertEqual((aces["unexpected_after"], aces["missing_after"]), ([], []))

    def test_a_flipped_auto_inheritance_flag_is_named_and_is_not_exact(self):
        components = self.components(native_acl.with_ace_first("D:AI" + PROTECTED[len("D:PAI"):], "(D;;LC;;;BU)"))
        self.assertFalse(components["installed_exactly"])
        self.assertEqual(components["control"], {"before": "PAI", "after": "AI", "unchanged": False})
        self.assertTrue(components["aces"]["exact"])

    def test_a_copied_ace_is_unexpected_and_is_not_exact(self):
        before = BASE
        copied = "D:AI(D;;LC;;;BU)(A;;FA;;;SY)(A;;FA;;;BA)(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)"
        components = self.components(copied, before=before)
        self.assertFalse(components["installed_exactly"])
        self.assertEqual(components["aces"]["unexpected_after"], ["(A;;FA;;;BA)", "(A;;FA;;;SY)"])
        self.assertEqual(components["aces"]["missing_after"], [])
        self.assertEqual((components["aces"]["inherited_before"], components["aces"]["inherited_after"]), (2, 2))
        self.assertEqual((components["aces"]["explicit_before"], components["aces"]["explicit_after"]), (0, 3))

    def test_a_missing_ace_a_reordered_ace_and_an_owner_change_are_each_not_exact(self):
        for label, after, owner in (
                ("missing", "D:PAI(D;;LC;;;BU)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", "O:BA"),
                ("reordered", "D:PAI(A;OICI;FA;;;SY)(D;;LC;;;BU)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)", "O:BA"),
                ("owner", native_acl.with_ace_first(PROTECTED, "(D;;LC;;;BU)"), "O:SY")):
            with self.subTest(label):
                components = self.components(after, owner_after=owner)
                self.assertFalse(components["installed_exactly"])
        self.assertEqual(self.components("D:PAI(D;;LC;;;BU)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
                         ["aces"]["missing_after"], ["(A;OICI;FA;;;OW)"])

    def test_the_facts_carry_no_machine_sid(self):
        before = "D:PAI(A;OICI;FA;;;" + FOREIGN + ")"
        after = native_acl.with_ace_first(before, "(D;;LC;;;" + MACHINE + ")")
        components = native_acl.installation_components(
            FakeNative(), before, after, "(D;;LC;;;" + MACHINE + ")",
            "O:" + FOREIGN, "O:" + FOREIGN)
        text = json.dumps(components)
        self.assertNotIn("1111111111", text)
        self.assertNotIn("4444444444", text)
        self.assertIn("S-1-5-21-<machine>-500", text)

    def test_deny_by_descriptor_returns_the_components_behind_its_boolean(self):
        fake = AliasingNative(dacl=PROTECTED)
        done = native_acl.deny_by_descriptor(fake, Path("x"), USERS)
        self.assertEqual(done["installed_exactly"], done["components"]["installed_exactly"])
        self.assertTrue(done["installed_exactly"])
        self.assertEqual(fake.applied, ["auto"])
        native_acl.deny_by_descriptor(FakeNative(dacl=PROTECTED), Path("x"), USERS, protection="none")
        message = native_acl.components_message("installation", done["components"])
        self.assertTrue(message.startswith("installation: {"))

    def test_the_protection_argument_reaches_the_native_layer_only_when_it_is_not_auto(self):
        fake = FakeNative(dacl=PROTECTED)
        native_acl.deny_by_descriptor(fake, Path("x"), USERS, protection="none")
        self.assertEqual(fake.applied, ["none"])

    def test_restoration_components_agree_with_the_restoration_verdict(self):
        for fake in (AliasingNative(dacl=PROTECTED), ProtectionDroppingNative(dacl=PROTECTED),
                     OwnerChangingNative(dacl=PROTECTED)):
            fake.apply_dacl(Path("x"), PROTECTED)
            components = native_acl.restoration_components(fake, Path("x"), PROTECTED, "O:BA")
            verdict = native_acl.restoration(fake, Path("x"), PROTECTED, "O:BA")
            self.assertEqual(components["verified"], verdict["verified"], type(fake).__name__)
            self.assertEqual(components["control"]["same"], verdict["control"])
            self.assertEqual(components["aces"]["same"], verdict["aces"])
            self.assertEqual(components["owner"]["same"], verdict["owner"])


class RestorationComponentTests(unittest.TestCase):
    def test_each_component_difference_is_named_and_fails_verification(self):
        for label, fake, component in (
                ("aces", FakeNative(dacl="D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"), "aces"),
                ("control", FakeNative(dacl="D:AI" + PROTECTED[len("D:PAI"):]), "control"),
                ("owner", OwnerChangingNative(dacl=PROTECTED), "owner")):
            with self.subTest(label):
                fake.owner = "O:SY" if label == "owner" else fake.owner
                found = native_acl.restoration_components(fake, Path("x"), PROTECTED, "O:BA")
                self.assertIs(found[component]["same"], False)
                self.assertIs(found["verified"], False)
        same = native_acl.restoration_components(FakeNative(dacl=PROTECTED), Path("x"), PROTECTED, "O:BA")
        self.assertEqual((same["control"]["same"], same["aces"]["same"], same["owner"]["same"], same["verified"]),
                         (True, True, True, True))


class PrivilegeFake(FakeNative):
    """Creation succeeds unless the token keeps the one privilege named in ``needs``."""

    def __init__(self, needs=None, **kwargs):
        super().__init__(enabled=("SeBackupPrivilege", "SeChangeNotifyPrivilege"),
                         disabled=("SeIncreaseQuotaPrivilege",), **kwargs)
        self.needs = needs

    def try_create_directory(self, path, stripped, route="os.mkdir", delete=(), impersonate=False):
        self.calls.append(("directory", stripped, route, tuple(delete), impersonate))
        every = {name for name, _ in self.privileges()}
        kept = set() if stripped else every - set(delete)
        if self.needs is not None and self.needs in kept:
            return {"created": True, "removed": True}
        return {"created": False, "winerror": 5}


class PrivilegeIsolationTests(unittest.TestCase):
    def isolate(self, needs):
        return native_acl.privilege_isolation(PrivilegeFake(needs), Path("parent"), Path("parent/state"))

    def test_the_single_privilege_whose_removal_turns_creation_into_a_denial_is_named(self):
        report = self.isolate("SeBackupPrivilege")
        self.assertEqual(report["single_removals_that_turn_creation_into_access_denied"], ["SeBackupPrivilege"])
        self.assertEqual(report["single_retentions_that_still_create"], ["SeBackupPrivilege"])
        self.assertEqual(report["outcomes"]["original_process_token"], {"created": True, "removed": True})
        self.assertEqual(report["outcomes"]["impersonated_copy_all_removed"], {"created": False, "winerror": 5})

    def test_a_token_that_is_always_refused_names_no_privilege(self):
        report = self.isolate(None)
        self.assertEqual(report["single_removals_that_turn_creation_into_access_denied"], [])
        self.assertEqual(report["single_retentions_that_still_create"], [])
        self.assertEqual(report["enabled"], ["SeBackupPrivilege", "SeChangeNotifyPrivilege"])

    def test_the_report_never_establishes_a_cause_and_verifies_its_cleanup(self):
        for needs in ("SeBackupPrivilege", None):
            report = self.isolate(needs)
            self.assertIs(report["cause_established"], False)
            self.assertIs(report["probe_cleanup_verified"], True)

    def test_a_refusal_with_another_code_is_not_a_turn_into_access_denied(self):
        class Other(PrivilegeFake):
            def try_create_directory(self, path, stripped, route="os.mkdir", delete=(), impersonate=False):
                outcome = super().try_create_directory(path, stripped, route, delete, impersonate)
                return {"created": False, "winerror": 3} if delete and not outcome["created"] else outcome
        report = native_acl.privilege_isolation(Other("SeBackupPrivilege"), Path("p"), Path("p/s"))
        self.assertEqual(report["single_removals_that_turn_creation_into_access_denied"], [])

    def test_a_directory_that_is_created_and_not_removed_fails_the_cleanup(self):
        class Leaky(PrivilegeFake):
            def try_create_directory(self, *args, **kwargs):
                outcome = super().try_create_directory(*args, **kwargs)
                return {**outcome, "removed": False} if outcome["created"] else outcome
        report = native_acl.privilege_isolation(Leaky("SeBackupPrivilege"), Path("p"), Path("p/s"))
        self.assertIs(report["probe_cleanup_verified"], False)

    def test_the_fence_shape_run_installs_the_parent_deny_and_restores_it(self):
        fake = PrivilegeFake("SeBackupPrivilege", dacl=PROTECTED)
        done = native_acl.privilege_isolation_on_fence_shape(fake, lambda label: Path(label), MACHINE)
        self.assertIs(done["verified"], True)
        self.assertEqual(fake.dacl, PROTECTED)
        self.assertTrue(done["restored"]["verified"])

    def test_a_restoration_that_loses_protection_is_not_verified(self):
        class Dropping(PrivilegeFake):
            def apply_dacl(self, path, sddl, protection="auto"):
                self.dacl = sddl.replace("D:PAI", "D:AI")
        done = native_acl.privilege_isolation_on_fence_shape(
            Dropping("SeBackupPrivilege", dacl=PROTECTED), lambda label: Path(label), MACHINE)
        self.assertIs(done["verified"], False)
        self.assertFalse(done["restored"]["control"]["same"])


class InstallationObservationTests(unittest.TestCase):
    def test_each_shape_reports_its_components_and_restores_its_own_original(self):
        fakes = {}

        def make(label):
            fakes[label] = Path(label)
            return Path(label)
        fake = AliasingNative(dacl=PROTECTED)
        report = native_acl.installation_observation(fake, MACHINE, make, lambda path: None)
        for label in ("unprotected_inherited_auto_flag", "unprotected_inherited_no_flag",
                      "stabilized_protected_auto_flag"):
            self.assertTrue(report[label]["installed"]["installed_exactly"], label)
            self.assertTrue(report[label]["restored"]["verified"], label)
        self.assertEqual(fake.applied, ["auto", "auto", "none", "auto", "auto", "auto"])
        self.assertTrue(report["stabilized_install_and_restoration_exact"])

    def test_the_stabilized_verdict_is_false_when_the_stabilized_install_is_not_exact(self):
        class Flipping(AliasingNative):
            def apply_dacl(self, path, sddl, protection="auto"):
                super().apply_dacl(path, sddl, protection)
                if "(D;" in sddl:
                    self.dacl = self.dacl.replace("D:PAI", "D:AI", 1)
        report = native_acl.installation_observation(Flipping(dacl=PROTECTED), MACHINE,
                                                     lambda label: Path(label), lambda path: None)
        self.assertFalse(report["stabilized_install_and_restoration_exact"])
        self.assertEqual(report["stabilized_protected_auto_flag"]["installed"]["control"]["after"], "AI")

    def test_a_failing_shape_is_recorded_with_its_type_only(self):
        def fail(label):
            raise OSError("secret path")
        report = native_acl.installation_observation(AliasingNative(), MACHINE, fail, lambda path: None)
        self.assertEqual(report["unprotected_inherited_auto_flag"], {"error": {"type": "OSError", "code": None}})
        self.assertNotIn("secret", json.dumps(report))
        self.assertFalse(report["stabilized_install_and_restoration_exact"])


class PerFixtureNative(AliasingNative):
    """One descriptor per fixture, keyed by the directory name. A write that holds no deny (a
    restoration) misbehaves for the fixtures in ``bad`` in the manner ``how``; a write that holds
    the deny (an installation) raises for ``install_raises`` and reads back with the protection
    flag toggled for ``inexact``."""

    def __init__(self, bad=(), how="protection", install_raises=(), inexact=()):
        super().__init__()
        self.state, self.owners = {}, {}
        self.bad, self.how = set(bad), how
        self.install_raises, self.inexact = set(install_raises), set(inexact)

    @staticmethod
    def key(path):
        return Path(path).name

    def read_dacl(self, path):
        key = self.key(path)
        return self.state.setdefault(key, PROTECTED if key.startswith("stabilized") else BASE)

    def read_owner(self, path):
        return self.owners.get(self.key(path), "O:BA")

    @staticmethod
    def toggled(text):
        return text.replace("D:PAI", "D:AI", 1) if text.startswith("D:PAI") else text.replace("D:AI", "D:PAI", 1)

    def apply_dacl(self, path, sddl, protection="auto"):
        key, installing = self.key(path), "(D;" in sddl
        if installing and key in self.install_raises:
            raise OSError("install refused")
        stored = re.sub(r";;;(S-1-[0-9-]+)\)", lambda m: ";;;" + ALIASES.get(m.group(1), m.group(1)) + ")", sddl)
        if installing and key in self.inexact:
            stored = self.toggled(stored)
        if not installing and key in self.bad:
            if self.how == "raises":
                raise OSError("restore refused")
            if self.how == "ignored":
                return
            if self.how == "protection":
                stored = self.toggled(stored)
            elif self.how == "owner":
                self.owners[key] = "O:SY"
            elif self.how == "extra_ace":
                stored += "(A;;FA;;;WD)"
        self.state[key] = stored


LABELS = ("unprotected_inherited_auto_flag", "unprotected_inherited_no_flag", "stabilized_protected_auto_flag")
STABILIZED = "stabilized_protected_auto_flag"
RESTORATION_FAILURES = ("protection", "owner", "extra_ace", "ignored", "raises")


class InstallationRestorationTests(unittest.TestCase):
    """The restoration of EVERY attempted fixture is verified on its own; an installation that
    reads back inexactly is a different fact from a restoration that cannot be shown."""

    @staticmethod
    def observe(native):
        return native_acl.installation_observation(native, MACHINE, lambda label: Path(label), lambda path: None)

    def test_a_clean_run_verifies_every_restoration(self):
        report = self.observe(PerFixtureNative())
        self.assertIs(report["restoration_verified"], True)
        self.assertEqual(report["restoration_unverified"], [])
        for label in LABELS:
            self.assertIs(report[label]["restoration_verified"], True, label)
            self.assertTrue(report[label]["installed"]["installed_exactly"], label)
        self.assertIs(report["stabilized_install_and_restoration_exact"], True)
        self.assertIs(native_acl.installation_section_verified(report), True)

    def test_a_restoration_failure_of_any_one_fixture_is_unverified_for_that_fixture_alone(self):
        for label in LABELS:
            for how in RESTORATION_FAILURES:
                with self.subTest(label=label, how=how):
                    report = self.observe(PerFixtureNative(bad=(label,), how=how))
                    self.assertEqual(report["restoration_unverified"], [label])
                    self.assertIs(report["restoration_verified"], False)
                    self.assertIs(report[label]["restoration_verified"], False)
                    for other in LABELS:
                        if other != label:
                            self.assertIs(report[other]["restoration_verified"], True, other)
                    self.assertFalse(native_acl.installation_section_verified(report))
                    self.assertIs(report["stabilized_install_and_restoration_exact"], label != STABILIZED)
                    self.assertTrue(report[label]["installed"]["installed_exactly"])
                    if how == "raises":
                        self.assertEqual(report[label]["error"], {"type": "OSError", "code": None})
                        self.assertNotIn("restored", report[label])
                    else:
                        self.assertNotIn("error", report[label])
                        self.assertIs(report[label]["restored"]["verified"], False)
                    self.assertNotIn("refused", json.dumps(report))

    def test_the_stabilized_aggregate_alone_misses_an_unprotected_restoration_failure(self):
        for label in LABELS[:2]:
            for how in RESTORATION_FAILURES:
                with self.subTest(label=label, how=how):
                    report = self.observe(PerFixtureNative(bad=(label,), how=how))
                    self.assertIs(report["stabilized_install_and_restoration_exact"], True)
                    self.assertIs(native_acl.installation_section_verified(report), False)

    def test_two_failed_restorations_are_both_listed(self):
        report = self.observe(PerFixtureNative(bad=(LABELS[0], LABELS[2]), how="owner"))
        self.assertEqual(report["restoration_unverified"], [LABELS[0], LABELS[2]])

    def test_an_inexact_unprotected_installation_with_a_verified_restoration_is_not_a_restoration_failure(self):
        report = self.observe(PerFixtureNative(inexact=LABELS[:2]))
        for label in LABELS[:2]:
            self.assertIs(report[label]["installed"]["installed_exactly"], False, label)
            self.assertIs(report[label]["restoration_verified"], True, label)
        self.assertIs(report["restoration_verified"], True)
        self.assertEqual(report["restoration_unverified"], [])
        self.assertIs(native_acl.installation_section_verified(report), True)

    def test_an_inexact_stabilized_installation_stays_unclean_with_a_verified_restoration(self):
        report = self.observe(PerFixtureNative(inexact=(STABILIZED,)))
        self.assertIs(report[STABILIZED]["installed"]["installed_exactly"], False)
        self.assertIs(report["restoration_verified"], True)
        self.assertIs(report["stabilized_install_and_restoration_exact"], False)
        self.assertIs(native_acl.installation_section_verified(report), False)

    def test_an_installation_that_raises_is_recorded_and_its_restoration_is_still_verified(self):
        for label in LABELS:
            with self.subTest(label):
                report = self.observe(PerFixtureNative(install_raises=(label,)))
                self.assertEqual(report[label]["error"], {"type": "OSError", "code": None})
                self.assertNotIn("installed", report[label])
                self.assertIs(report[label]["restored"]["verified"], True)
                self.assertIs(report["restoration_verified"], True)
                self.assertIs(native_acl.installation_section_verified(report), label != STABILIZED)

    def test_an_installation_that_raises_and_a_restoration_that_cannot_be_shown_is_unverified(self):
        for label in LABELS:
            with self.subTest(label):
                report = self.observe(PerFixtureNative(install_raises=(label,), bad=(label,), how="raises"))
                self.assertEqual(report[label]["error"], {"type": "OSError", "code": None})
                self.assertEqual(report["restoration_unverified"], [label])
                self.assertIs(native_acl.installation_section_verified(report), False)

    def test_a_fixture_that_fails_before_anything_is_captured_has_nothing_to_restore(self):
        def fail_one(label):
            if label == LABELS[1]:
                raise OSError("no directory")
            return Path(label)
        report = native_acl.installation_observation(PerFixtureNative(), MACHINE, fail_one, lambda path: None)
        self.assertEqual(report[LABELS[1]], {"error": {"type": "OSError", "code": None}})
        self.assertEqual(report["restoration_unverified"], [])
        self.assertIs(report["restoration_verified"], True)
        self.assertIs(native_acl.installation_section_verified(report), True)

        def cannot_stabilize(path):
            raise OSError("no stabilization")
        report = native_acl.installation_observation(
            PerFixtureNative(), MACHINE, lambda label: Path(label), cannot_stabilize)
        self.assertNotIn("restoration_verified", report[STABILIZED])
        self.assertIs(report["stabilized_install_and_restoration_exact"], False)
        self.assertIs(native_acl.installation_section_verified(report), False)

    def test_the_section_verdict_needs_both_facts_to_be_exactly_true(self):
        for body, clean in (({}, False),
                            ({"stabilized_install_and_restoration_exact": True}, False),
                            ({"restoration_verified": True}, False),
                            ({"stabilized_install_and_restoration_exact": True, "restoration_verified": False}, False),
                            ({"stabilized_install_and_restoration_exact": False, "restoration_verified": True}, False),
                            ({"stabilized_install_and_restoration_exact": 1, "restoration_verified": True}, False),
                            ({"stabilized_install_and_restoration_exact": True, "restoration_verified": "yes"}, False),
                            ({"stabilized_install_and_restoration_exact": True, "restoration_verified": True}, True)):
            with self.subTest(body):
                self.assertIs(native_acl.installation_section_verified(body), clean)


class FakeProcessApi:
    """Scripted kernel seam for ``run_contained``: every call is recorded, every result scripted."""

    def __init__(self, *, job=(100, None), start=(200, 300, None), assign=(True, None),
                 resume=(True, None), waits=((0, None),), terminate_job=(True, None),
                 terminate_process=(True, None), exit_code=(True, 0, None), active=((0, None),),
                 close_fails=(), raise_on_wait=None):
        self.script = dict(job=job, start=start, assign=assign, resume=resume,
                           terminate_job=terminate_job, terminate_process=terminate_process,
                           exit_code=exit_code)
        self.waits, self.active, self.close_fails = list(waits), list(active), set(close_fails)
        self.raise_on_wait = raise_on_wait
        self.calls, self.retained = [], []

    def _next(self, queue):
        return queue.pop(0) if len(queue) > 1 else queue[0]

    def create_job(self):
        self.calls.append("create_job")
        return self.script["job"]

    def start(self):
        self.calls.append("start")
        return self.script["start"]

    def assign(self, job, process):
        self.calls.append("assign")
        return self.script["assign"]

    def resume(self, thread):
        self.calls.append("resume")
        return self.script["resume"]

    def wait(self, handle, milliseconds):
        self.calls.append(("wait", milliseconds))
        if self.raise_on_wait:
            raise self.raise_on_wait
        return self._next(self.waits)

    def terminate_job(self, job, code):
        self.calls.append("terminate_job")
        return self.script["terminate_job"]

    def terminate_process(self, process, code):
        self.calls.append("terminate_process")
        return self.script["terminate_process"]

    def exit_code(self, process):
        self.calls.append("exit_code")
        return self.script["exit_code"]

    def active_processes(self, job):
        self.calls.append("active")
        return self._next(self.active)

    def close(self, handle):
        self.calls.append(("close", handle))
        return handle not in self.close_fails

    def pause(self, milliseconds):
        self.calls.append("pause")

    def retain(self, handles):
        self.retained.extend(handles)

    def closed(self):
        return sorted(call[1] for call in self.calls if isinstance(call, tuple) and call[0] == "close")


class CausalProcessApi(FakeProcessApi):
    """Kernel seam whose process state follows from what was actually done to it: a job
    termination stops only a process assigned to that job (an empty job ends nothing), a direct
    termination stops the process only when it succeeds and is effective, and an unassigned
    suspended child is never signaled, and a job never holds it, until it is terminated directly."""

    def __init__(self, *, raise_on_assign=None, terminate_process_ineffective=False,
                 exits_after_resume=True, **script):
        super().__init__(**script)
        self.raise_on_assign, self.terminate_process_ineffective = raise_on_assign, terminate_process_ineffective
        self.exits_after_resume = exits_after_resume
        self.assigned = self.resumed = self.signaled = False
        self.stopped_by = None

    def assign(self, job, process):
        if self.raise_on_assign:
            self.calls.append("assign")
            raise self.raise_on_assign
        result = super().assign(job, process)
        self.assigned = bool(result[0])
        return result

    def resume(self, thread):
        result = super().resume(thread)
        self.resumed = bool(result[0])
        if self.resumed and self.exits_after_resume:
            self.signaled, self.stopped_by = True, "exit"
        return result

    def wait(self, handle, milliseconds):
        self.calls.append(("wait", milliseconds))
        if self.raise_on_wait:
            raise self.raise_on_wait
        return (0, None) if self.signaled else (native_acl.WAIT_TIMEOUT, None)

    def terminate_job(self, job, code):
        result = super().terminate_job(job, code)
        if result[0] and self.assigned and not self.signaled:
            self.signaled, self.stopped_by = True, "terminate_job"
        return result

    def terminate_process(self, process, code):
        result = super().terminate_process(process, code)
        if result[0] and not self.terminate_process_ineffective and not self.signaled:
            self.signaled, self.stopped_by = True, "terminate_process"
        return result

    def active_processes(self, job):
        self.calls.append("active")
        return (1 if self.assigned and not self.signaled else 0), None


class UnassignedChildTests(unittest.TestCase):
    """A child that was started suspended but could not be assigned to the job is owned and alive
    outside it: only a direct ``TerminateProcess`` stops it, and only a final wait that sees it
    signaled establishes that."""

    def run_it(self, **script):
        api = CausalProcessApi(**script)
        report, retained = native_acl.run_contained(api, 5.0, grace_ms=300)
        return api, report, retained

    def test_the_model_does_not_signal_an_unassigned_child_when_the_empty_job_is_terminated(self):
        api = CausalProcessApi(assign=(False, 5))
        api.start()
        self.assertEqual(api.assign(100, 200), (False, 5))
        self.assertEqual(api.terminate_job(100, 1), (True, None))
        self.assertEqual((api.wait(200, 10)[0], api.active_processes(100)[0]), (native_acl.WAIT_TIMEOUT, 0))
        api.terminate_process(200, 1)
        self.assertEqual((api.wait(200, 10)[0], api.stopped_by), (0, "terminate_process"))

    def test_an_unassigned_child_is_terminated_directly_and_seen_signaled(self):
        api, report, retained = self.run_it(assign=(False, 5))
        self.assertEqual(api.stopped_by, "terminate_process")
        self.assertNotIn("resume", api.calls)
        self.assertIn("terminate_process", api.calls)
        self.assertNotIn("terminate_job", api.calls)
        self.assertEqual((report["launched"], report["completed"], report["terminated"],
                          report["final_wait"], report["child_stopped"], report["cleanup_verified"],
                          report["handles_retained"]), (False, False, True, "signaled", True, True, False))
        self.assertIn({"api": "AssignProcessToJobObject", "code": 5}, report["errors"])
        self.assertEqual((retained, api.closed()), ([], [100, 200, 300]))

    def test_an_unassigned_child_whose_direct_termination_fails_is_not_stopped_and_stays_owned(self):
        api, report, retained = self.run_it(assign=(False, 5), terminate_process=(False, 5))
        self.assertFalse(api.signaled)
        self.assertEqual((report["terminated"], report["final_wait"], report["child_stopped"],
                          report["cleanup_verified"], report["handles_retained"]),
                         (False, "timeout", False, False, True))
        self.assertEqual(report["terminate_errors"], [{"api": "TerminateProcess", "code": 5}])
        self.assertEqual((sorted(retained), api.closed()), ([100, 200, 300], []))

    def test_a_direct_termination_that_reports_success_but_leaves_the_child_unsignaled_is_not_stopped(self):
        api, report, retained = self.run_it(assign=(False, 5), terminate_process_ineffective=True)
        self.assertEqual((report["terminated"], report["final_wait"], report["child_stopped"],
                          report["cleanup_verified"], report["handles_retained"]),
                         (True, "timeout", False, False, True))
        self.assertEqual((sorted(retained), api.closed()), ([100, 200, 300], []))

    def test_the_job_termination_stops_an_assigned_child_that_cannot_be_resumed(self):
        api, report, retained = self.run_it(resume=(False, 5))
        self.assertEqual(api.stopped_by, "terminate_job")
        self.assertNotIn("terminate_process", api.calls)
        self.assertEqual((report["launched"], report["child_stopped"], report["cleanup_verified"], retained),
                         (False, True, True, []))

    def test_a_child_that_outlives_its_wait_is_stopped_by_the_job_termination(self):
        api, report, _ = self.run_it(exits_after_resume=False)
        self.assertEqual((api.stopped_by, report["timed_out"], report["child_stopped"]),
                         ("terminate_job", True, True))
        self.assertNotIn("terminate_process", api.calls)

    def test_an_assigned_child_whose_job_termination_fails_falls_back_to_the_process(self):
        api, report, _ = self.run_it(exits_after_resume=False, terminate_job=(False, 5))
        self.assertEqual((api.stopped_by, report["child_stopped"]), ("terminate_process", True))
        self.assertEqual(report["terminate_errors"], [{"api": "TerminateJobObject", "code": 5}])

    def test_an_assignment_that_raises_terminates_the_child_directly_and_keeps_the_handles(self):
        api = CausalProcessApi(raise_on_assign=RuntimeError("boom"))
        with self.assertRaises(RuntimeError):
            native_acl.run_contained(api, 5.0)
        self.assertEqual(api.stopped_by, "terminate_process")
        self.assertNotIn("terminate_job", api.calls)
        self.assertEqual((sorted(api.retained), api.closed()), ([100, 200, 300], []))

    def test_a_wait_that_raises_after_assignment_terminates_the_job_and_keeps_the_handles(self):
        api = CausalProcessApi(exits_after_resume=False, raise_on_wait=RuntimeError("boom"))
        with self.assertRaises(RuntimeError):
            native_acl.run_contained(api, 5.0)
        self.assertEqual(api.stopped_by, "terminate_job")
        self.assertEqual((sorted(api.retained), api.closed()), ([100, 200, 300], []))


class RunContainedTests(unittest.TestCase):
    def run_it(self, **script):
        api = FakeProcessApi(**script)
        report, retained = native_acl.run_contained(api, 5.0, grace_ms=300)
        return api, report, retained

    def test_a_process_that_exits_zero_in_time_is_completed_and_every_handle_is_closed(self):
        api, report, retained = self.run_it()
        self.assertEqual((report["launched"], report["completed"], report["exit_code"],
                          report["timed_out"], report["cleanup_verified"]), (True, True, 0, False, True))
        self.assertEqual((retained, api.closed()), ([], [100, 200, 300]))
        self.assertEqual(report["errors"], [])
        self.assertNotIn("terminate_job", api.calls)
        self.assertLess(api.calls.index("assign"), api.calls.index("resume"))

    def test_child_stopped_is_true_only_when_the_process_is_seen_signaled_and_the_job_is_empty(self):
        for label, script, stopped in (
                ("exits in time", {}, True),
                ("timeout then signaled", dict(waits=((native_acl.WAIT_TIMEOUT, None), (0, None)),
                                               exit_code=(True, 1, None)), True),
                ("never signaled", dict(waits=((native_acl.WAIT_TIMEOUT, None), (native_acl.WAIT_TIMEOUT, None)),
                                        terminate_job=(False, 5), terminate_process=(False, 5)), False),
                ("final wait failed", dict(waits=((native_acl.WAIT_TIMEOUT, None), (native_acl.WAIT_FAILED, 6))), False),
                ("descendant remains", dict(active=((1, None),)), False),
                ("job cannot be queried", dict(active=((None, 6),)), False),
                ("exit code unreadable", dict(exit_code=(False, None, 6)), True),
                ("still-active placeholder after the wait", dict(exit_code=(True, native_acl.STILL_ACTIVE, None)), True),
                ("handle will not close", dict(close_fails=(200,)), True),
                ("job not created", dict(job=(None, 5)), True),
                ("process not created", dict(start=(None, None, 2)), True)):
            with self.subTest(label):
                _, report, _ = self.run_it(**script)
                self.assertIs(report["child_stopped"], stopped, report)

    def test_a_timeout_terminates_the_job_and_is_never_a_completed_run(self):
        api, report, retained = self.run_it(waits=((native_acl.WAIT_TIMEOUT, None), (0, None)),
                                            exit_code=(True, 1, None))
        self.assertEqual((report["timed_out"], report["wait_failed"], report["terminated"],
                          report["final_wait"], report["completed"], report["cleanup_verified"]),
                         (True, False, True, "signaled", False, True))
        self.assertIn("terminate_job", api.calls)

    def test_a_failed_wait_is_reported_with_its_error_and_is_not_a_timeout(self):
        api, report, _ = self.run_it(waits=((native_acl.WAIT_FAILED, 6), (0, None)),
                                     exit_code=(True, 1, None))
        self.assertEqual((report["wait_failed"], report["timed_out"], report["completed"]), (True, False, False))
        self.assertIn({"api": "WaitForSingleObject", "code": 6}, report["errors"])
        self.assertIn("terminate_job", api.calls)

    def test_a_process_that_survives_termination_keeps_its_handles_and_fails_cleanup(self):
        api, report, retained = self.run_it(
            waits=((native_acl.WAIT_TIMEOUT, None), (native_acl.WAIT_TIMEOUT, None)),
            terminate_job=(False, 5), terminate_process=(False, 5), active=((1, None),))
        self.assertEqual((report["completed"], report["cleanup_verified"], report["handles_retained"],
                          report["final_wait"]), (False, False, True, "timeout"))
        self.assertIs(report["terminated"], False)
        self.assertEqual(sorted(retained), [100, 200, 300])
        self.assertEqual(api.closed(), [])
        self.assertEqual({item["api"] for item in report["terminate_errors"]},
                         {"TerminateJobObject", "TerminateProcess"})

    def test_a_job_termination_that_fails_falls_back_to_the_process_and_is_reported(self):
        api, report, _ = self.run_it(waits=((native_acl.WAIT_TIMEOUT, None), (0, None)),
                                     terminate_job=(False, 5), exit_code=(True, 1, None))
        self.assertEqual((report["terminated"], report["terminate_errors"]),
                         (True, [{"api": "TerminateJobObject", "code": 5}]))
        self.assertIn("terminate_process", api.calls)

    def test_a_failed_final_wait_is_not_a_verified_cleanup(self):
        _, report, retained = self.run_it(
            waits=((native_acl.WAIT_TIMEOUT, None), (native_acl.WAIT_FAILED, 6)), active=((0, None),))
        self.assertEqual((report["final_wait"], report["cleanup_verified"], report["handles_retained"]),
                         ("failed", False, True))
        self.assertTrue(retained)

    def test_the_still_active_placeholder_is_never_an_exit_code(self):
        _, report, retained = self.run_it(exit_code=(True, native_acl.STILL_ACTIVE, None))
        self.assertEqual((report["still_active"], report["exit_code"], report["completed"],
                          report["cleanup_verified"]), (True, None, False, False))
        self.assertTrue(retained)

    def test_an_exit_code_that_cannot_be_read_is_reported_and_not_completed(self):
        _, report, _ = self.run_it(exit_code=(False, None, 6))
        self.assertEqual((report["exit_code"], report["completed"]), (None, False))
        self.assertIn({"api": "GetExitCodeProcess", "code": 6}, report["errors"])

    def test_a_nonzero_exit_is_reported_as_is(self):
        _, report, _ = self.run_it(exit_code=(True, 3, None))
        self.assertEqual((report["exit_code"], report["completed"], report["cleanup_verified"]), (3, True, True))

    def test_a_descendant_left_in_the_job_is_terminated_and_the_run_is_not_completed(self):
        api, report, retained = self.run_it(active=((2, None), (1, None), (0, None)))
        self.assertEqual((report["descendants_terminated"], report["completed"],
                          report["job_active_processes"], report["cleanup_verified"]), (True, False, 0, True))
        self.assertIn("terminate_job", api.calls)
        self.assertEqual(retained, [])

    def test_a_descendant_that_cannot_be_removed_fails_cleanup_and_keeps_the_job(self):
        _, report, retained = self.run_it(active=((1, None),))
        self.assertEqual((report["job_active_processes"], report["cleanup_verified"], report["handles_retained"]),
                         (1, False, True))
        self.assertIn(100, retained)

    def test_a_job_that_cannot_be_queried_is_not_a_verified_cleanup(self):
        _, report, _ = self.run_it(active=((None, 6),))
        self.assertEqual((report["job_active_processes"], report["cleanup_verified"]), (None, False))
        self.assertIn({"api": "QueryInformationJobObject", "code": 6}, report["errors"])

    def test_a_process_that_cannot_be_contained_is_never_resumed_and_is_terminated(self):
        api = CausalProcessApi(assign=(False, 5))
        report, _ = native_acl.run_contained(api, 5.0, grace_ms=300)
        self.assertEqual((report["launched"], report["completed"]), (False, False))
        self.assertNotIn("resume", api.calls)
        self.assertIn("terminate_process", api.calls)
        self.assertEqual(api.stopped_by, "terminate_process")
        self.assertIn({"api": "AssignProcessToJobObject", "code": 5}, report["errors"])

    def test_a_process_that_cannot_be_resumed_is_terminated_and_not_launched(self):
        api, report, _ = self.run_it(resume=(False, 5))
        self.assertEqual((report["launched"], report["completed"]), (False, False))
        self.assertIn("terminate_job", api.calls)
        self.assertNotIn(("wait", 5000), api.calls)

    def test_a_job_that_cannot_be_created_starts_nothing(self):
        api, report, retained = self.run_it(job=(None, 5))
        self.assertEqual((report["launched"], report["winerror"], retained), (False, 5, []))
        self.assertNotIn("start", api.calls)

    def test_a_launch_that_fails_reports_its_error_and_closes_the_job(self):
        api, report, retained = self.run_it(start=(None, None, 2))
        self.assertEqual((report["launched"], report["winerror"], retained), (False, 2, []))
        self.assertEqual(api.closed(), [100])
        self.assertNotIn("assign", api.calls)

    def test_a_handle_that_cannot_be_closed_fails_cleanup_and_stays_owned(self):
        _, report, retained = self.run_it(close_fails=(200,))
        self.assertEqual((report["cleanup_verified"], report["completed"], report["handles_retained"],
                          retained), (False, False, True, [200]))

    def test_an_unexpected_error_terminates_the_job_keeps_the_handles_and_propagates(self):
        api = FakeProcessApi(raise_on_wait=RuntimeError("boom"))
        with self.assertRaises(RuntimeError):
            native_acl.run_contained(api, 5.0)
        self.assertIn("terminate_job", api.calls)
        self.assertEqual(sorted(api.retained), [100, 200, 300])
        self.assertEqual(api.closed(), [])


class FakePrivilegeApi:
    def __init__(self, attributes, *, fail=(), ignore_restore=False, enable_noop=False,
                 side_effect=None, fail_readback_after=None):
        self.attributes, self.fail, self.ignore_restore = dict(attributes), set(fail), ignore_restore
        self.enable_noop, self.side_effect = enable_noop, side_effect
        self.fail_readback_after, self.reads, self.adjustments = fail_readback_after, 0, []

    def privilege_attributes(self):
        self.reads += 1
        if self.fail_readback_after is not None and self.reads > self.fail_readback_after:
            raise native_acl.NativeError("GetTokenInformation", 5)
        return dict(self.attributes)

    def adjust_privilege(self, name, attributes):
        self.adjustments.append((name, attributes))
        step = "enable" if attributes & 2 else "restore"
        if step in self.fail:
            raise native_acl.NativeError("AdjustTokenPrivileges", 5)
        if (step == "restore" and self.ignore_restore) or (step == "enable" and self.enable_noop):
            return
        self.attributes[name] = (self.attributes[name] & ~2) | (attributes & 2)
        if self.side_effect and step == "restore":
            other, value = self.side_effect
            self.attributes[other] = value


class PrivilegeScopeTests(unittest.TestCase):
    NAME = "SeIncreaseQuotaPrivilege"

    def api(self, **kwargs):
        return FakePrivilegeApi({self.NAME: 0, "SeBackupPrivilege": 3, "SeDebugPrivilege": 0}, **kwargs)

    def test_a_disabled_privilege_is_enabled_inside_and_disabled_again(self):
        api = self.api()
        with native_acl.privilege_scope(api, self.NAME):
            self.assertTrue(api.attributes[self.NAME] & 2)
        self.assertEqual(api.attributes, {self.NAME: 0, "SeBackupPrivilege": 3, "SeDebugPrivilege": 0})

    def test_an_enabled_privilege_stays_enabled_afterwards(self):
        api = self.api()
        with native_acl.privilege_scope(api, "SeBackupPrivilege"):
            pass
        self.assertEqual(api.attributes["SeBackupPrivilege"], 3)
        self.assertEqual(api.adjustments[-1], ("SeBackupPrivilege", 2))

    def test_the_used_for_access_bit_does_not_count_as_a_change(self):
        api = FakePrivilegeApi({self.NAME: 0})
        with native_acl.privilege_scope(api, self.NAME):
            api.attributes[self.NAME] |= 0x80000000
        api.attributes[self.NAME] |= 0x80000000
        self.assertEqual(api.attributes[self.NAME] & 7, 0)

    def test_a_body_error_propagates_and_the_token_is_restored(self):
        api = self.api()
        with self.assertRaises(ValueError):
            with native_acl.privilege_scope(api, self.NAME):
                raise ValueError("body")
        self.assertEqual(api.attributes[self.NAME], 0)

    def test_a_restoration_that_fails_raises_even_over_a_body_error(self):
        api = self.api(fail=("restore",))
        with self.assertRaises(native_acl.PrivilegeRestorationError) as caught:
            with native_acl.privilege_scope(api, self.NAME):
                raise ValueError("body")
        self.assertIsInstance(caught.exception.__context__, ValueError)
        self.assertIn("restore_failed", caught.exception.details["problems"])
        self.assertEqual(caught.exception.details["changed"], [self.NAME])

    def test_a_restoration_that_reports_success_but_changes_nothing_is_not_trusted(self):
        api = self.api(ignore_restore=True)
        with self.assertRaises(native_acl.PrivilegeRestorationError) as caught:
            with native_acl.privilege_scope(api, self.NAME):
                pass
        self.assertEqual(caught.exception.details["problems"], ["inventory_changed"])

    def test_another_privilege_that_changed_is_a_change(self):
        api = self.api(side_effect=("SeDebugPrivilege", 2))
        with self.assertRaises(native_acl.PrivilegeRestorationError) as caught:
            with native_acl.privilege_scope(api, self.NAME):
                pass
        self.assertEqual(caught.exception.details["changed"], ["SeDebugPrivilege"])

    def test_an_inventory_that_cannot_be_read_back_is_not_a_verified_restoration(self):
        api = self.api(fail_readback_after=2)
        with self.assertRaises(native_acl.PrivilegeRestorationError) as caught:
            with native_acl.privilege_scope(api, self.NAME):
                pass
        self.assertIn("readback_failed", caught.exception.details["problems"])

    def test_an_absent_privilege_changes_nothing_and_says_so(self):
        api = self.api()
        with self.assertRaises(native_acl.NativeError) as caught:
            with native_acl.privilege_scope(api, "SeNoSuchPrivilege"):
                self.fail("must not run")
        self.assertEqual(caught.exception.api, "privilege_absent")
        self.assertEqual(api.adjustments, [])

    def test_an_enable_that_does_not_take_effect_never_runs_the_body_and_restores(self):
        api = self.api(enable_noop=True)
        with self.assertRaises(native_acl.NativeError):
            with native_acl.privilege_scope(api, self.NAME):
                self.fail("must not run")
        self.assertEqual(api.attributes[self.NAME], 0)

    def test_an_enable_that_fails_is_reported_as_that_failure(self):
        api = self.api(fail=("enable",))
        with self.assertRaises(native_acl.NativeError) as caught:
            with native_acl.privilege_scope(api, self.NAME):
                self.fail("must not run")
        self.assertNotIsInstance(caught.exception, native_acl.PrivilegeRestorationError)


class StubC:
    """The few ctypes names the process adapter uses, with the Windows-only error slot faked."""

    def __init__(self):
        import ctypes
        self.__dict__.update(Structure=ctypes.Structure, c_void_p=ctypes.c_void_p, c_longlong=ctypes.c_longlong,
                             c_ulonglong=ctypes.c_ulonglong, c_size_t=ctypes.c_size_t, sizeof=ctypes.sizeof,
                             byref=ctypes.byref, create_unicode_buffer=ctypes.create_unicode_buffer)
        self.error = 0

    def set_last_error(self, value):
        self.error = value

    def get_last_error(self):
        return self.error


class StubNative:
    def __init__(self, results, *, restoration_error=None, enable_error=None):
        from ctypes import wintypes
        self.c, self.w = StubC(), wintypes
        self.results, self.entered, self.exited = list(results), 0, 0
        self.restoration_error, self.enable_error = restoration_error, enable_error
        self.advapi = self
        self.kernel = self

    def CreateProcessAsUserW(self, *args):
        created = args[-1]._obj
        code, handles = self.results.pop(0)
        self.c.error = code
        if handles:
            created.hProcess, created.hThread = handles
            return True
        return False

    def privilege_enabled(self, name):
        stub = self
        from contextlib import contextmanager

        @contextmanager
        def scope():
            if stub.enable_error:
                raise stub.enable_error
            stub.entered += 1
            try:
                yield
            finally:
                stub.exited += 1
                if stub.restoration_error:
                    raise stub.restoration_error
        return scope()


class ProcessApiLaunchTests(unittest.TestCase):
    def api(self, native):
        return native_acl._ProcessApi(native, 1, ["python"], ".")

    def test_a_launch_that_needs_the_quota_privilege_retries_once_inside_the_scope(self):
        native = StubNative([(1314, None), (0, (7, 8))])
        api = self.api(native)
        self.assertEqual(api.start(), (7, 8, None))
        self.assertEqual((api.quota_enabled, native.entered, native.exited, api.restoration_error), (True, 1, 1, None))

    def test_any_other_launch_error_is_final_and_enables_nothing(self):
        native = StubNative([(2, None)])
        api = self.api(native)
        self.assertEqual(api.start(), (None, None, 2))
        self.assertEqual((api.quota_enabled, native.entered), (False, 0))

    def test_a_privilege_that_cannot_be_enabled_leaves_the_original_failure(self):
        native = StubNative([(1314, None)], enable_error=native_acl.NativeError("AdjustTokenPrivileges", 1300))
        api = self.api(native)
        self.assertEqual(api.start(), (None, None, 1314))
        self.assertFalse(api.quota_enabled)

    def test_a_failed_privilege_restoration_after_a_started_process_keeps_the_process_and_is_recorded(self):
        failure = native_acl.PrivilegeRestorationError({"privilege": "x", "problems": ["inventory_changed"],
                                                       "changed": ["x"]})
        native = StubNative([(1314, None), (0, (7, 8))], restoration_error=failure)
        api = self.api(native)
        self.assertEqual(api.start(), (7, 8, None))
        self.assertIs(api.restoration_error, failure)


class ChildEvidenceTests(unittest.TestCase):
    GOOD_LAUNCH = {"launched": True, "completed": True, "exit_code": 0, "timed_out": False,
                   "cleanup_verified": True, "child_stopped": True}

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="jraphyte-child-evidence-")
        self.addCleanup(self.temp.cleanup)
        self.out = Path(self.temp.name) / "child.json"

    def report(self, body):
        self.out.write_text(body if isinstance(body, str) else json.dumps(body), encoding="utf-8")

    GOOD = {"filesystem": {"type": "NTFS"}, "enabled_privileges": [], "disabled_privileges": [],
            "parent_dacl": "D:P", "access_check": {}, "mkdir": {}, "mkdir_CreateDirectoryW": {},
            "file_control": {}, "non_denial_outcomes": [], "probe_cleanup_verified": True,
            "verdict": "DENIED", "cause_established": False}

    def test_a_complete_launch_with_a_valid_report_has_no_reasons(self):
        self.report(self.GOOD)
        child, reasons = native_acl.child_evidence(self.GOOD_LAUNCH, self.out)
        self.assertEqual((child, reasons), (self.GOOD, []))

    def test_each_defect_is_a_named_reason_and_none_is_a_pass(self):
        cases = {
            "launch_failed": ({**self.GOOD_LAUNCH, "launched": False}, self.GOOD),
            "timed_out": ({**self.GOOD_LAUNCH, "timed_out": True}, self.GOOD),
            "wait_incomplete": ({**self.GOOD_LAUNCH, "wait_failed": True}, self.GOOD),
            "nonzero_or_missing_exit": ({**self.GOOD_LAUNCH, "exit_code": 1}, self.GOOD),
            "launch_not_completed": ({**self.GOOD_LAUNCH, "completed": False}, self.GOOD),
            "launch_cleanup_unverified": ({**self.GOOD_LAUNCH, "cleanup_verified": False}, self.GOOD),
            "child_stop_unestablished": ({**self.GOOD_LAUNCH, "child_stopped": False}, self.GOOD),
            "child_report_malformed": (self.GOOD_LAUNCH, "{not json"),
            "child_reported_error": (self.GOOD_LAUNCH, {"error": {"type": "OSError", "code": None}}),
            "child_verdict_missing_or_unknown": (self.GOOD_LAUNCH, {**self.GOOD, "verdict": "MAYBE"}),
            "child_cleanup_unverified": (self.GOOD_LAUNCH, {**self.GOOD, "probe_cleanup_verified": False}),
            "child_report_incomplete": (self.GOOD_LAUNCH, {"verdict": "DENIED", "probe_cleanup_verified": True}),
        }
        for reason, (launch, body) in cases.items():
            with self.subTest(reason):
                self.report(body)
                _, reasons = native_acl.child_evidence(launch, self.out)
                self.assertIn(reason, reasons)

    def test_the_exit_code_alone_is_never_acceptance(self):
        self.assertEqual(native_acl.launch_defects(self.GOOD_LAUNCH), [])
        for field, value, reason in (
                ("handles_retained", True, "handles_retained"),
                ("privilege_restoration", {"verified": False}, "privilege_restoration_unverified"),
                ("errors", [{"api": "CloseHandle", "code": None}], "launch_errors"),
                ("still_active", True, "wait_incomplete"),
                ("completed", False, "launch_not_completed"),
                ("cleanup_verified", False, "launch_cleanup_unverified"),
                ("child_stopped", False, "child_stop_unestablished"),
                ("child_stopped", None, "child_stop_unestablished")):
            with self.subTest(field):
                self.assertIn(reason, native_acl.launch_defects({**self.GOOD_LAUNCH, field: value}))
        self.assertEqual(native_acl.launch_defects({**self.GOOD_LAUNCH, "privilege_restoration": {"verified": True}}), [])

    def test_a_missing_report_is_a_reason(self):
        _, reasons = native_acl.child_evidence(self.GOOD_LAUNCH, self.out)
        self.assertEqual(reasons, ["child_report_missing"])

    def test_a_report_that_is_not_an_object_is_an_error_report(self):
        self.report("[1]")
        child, reasons = native_acl.child_evidence(self.GOOD_LAUNCH, self.out)
        self.assertEqual((child, reasons), (None, ["child_reported_error"]))

    def test_no_report_that_is_not_a_complete_object_is_evidence_including_json_null(self):
        for label, text in (("null", "null"), ("number", "0"), ("string", '"DENIED"'), ("true", "true"),
                            ("array", "[]"), ("array of one report", json.dumps([self.GOOD]))):
            with self.subTest(label):
                self.report(text)
                child, reasons = native_acl.child_evidence(self.GOOD_LAUNCH, self.out)
                self.assertEqual((child, reasons), (None, ["child_reported_error"]))
        for label, body in (("empty object", {}),
                            ("verdict and cleanup only", {"verdict": "DENIED", "probe_cleanup_verified": True}),
                            ("only the fields it names", {"cause_established": False})):
            with self.subTest(label):
                self.report(body)
                _, reasons = native_acl.child_evidence(self.GOOD_LAUNCH, self.out)
                self.assertTrue(reasons, label)
        for field in native_acl.CHILD_REPORT_FIELDS:
            with self.subTest("without " + field):
                self.report({key: value for key, value in self.GOOD.items() if key != field})
                _, reasons = native_acl.child_evidence(self.GOOD_LAUNCH, self.out)
                self.assertTrue(reasons, field)
                if field not in ("verdict", "probe_cleanup_verified"):
                    self.assertEqual(reasons, ["child_report_incomplete"])
        self.assertEqual(set(native_acl.CHILD_REPORT_FIELDS), set(self.GOOD))

    def test_a_report_with_only_a_launch_defect_free_null_is_never_complete_evidence(self):
        for text in ("null", "0", "[]", "{}"):
            with self.subTest(text):
                self.report(text)
                _, reasons = native_acl.child_evidence(self.GOOD_LAUNCH, self.out)
                self.assertNotEqual(reasons, [])

    def test_the_section_separates_restoration_from_launch_evidence(self):
        class Launcher(FakeNative):
            def __init__(self, launch, body, **kwargs):
                super().__init__(dacl=PROTECTED, **kwargs)
                self.launch, self.body = launch, body

            def run_with_restricted_primary_token(self, argv, cwd, timeout=900.0):
                if self.body is not None:
                    Path(argv[-1]).write_text(
                        self.body if isinstance(self.body, str) else json.dumps(self.body), encoding="utf-8")
                return self.launch
        base = Path(self.temp.name)

        count = iter(range(100))

        def make(label):
            path = base / ("%s-%d" % (label, next(count)))
            path.mkdir()
            return path
        done = native_acl.restricted_primary_child_report(
            Launcher(self.GOOD_LAUNCH, self.GOOD), make, MACHINE, lambda path: None)
        self.assertEqual((done["restoration_verified"], done["evidence_complete"], done["not_run"]),
                         (True, True, []))
        self.assertIs(done["cause_established"], False)
        leaky = native_acl.restricted_primary_child_report(
            Launcher(self.GOOD_LAUNCH, self.GOOD, full_creates=True, unremoved=("directory",)),
            make, MACHINE, lambda path: None)
        self.assertEqual((leaky["restoration_verified"], leaky["evidence_complete"]), (False, True))
        failed = native_acl.restricted_primary_child_report(
            Launcher({"launched": False, "winerror": 2, "child_stopped": True}, None), make, MACHINE,
            lambda path: None)
        self.assertEqual((failed["restoration_verified"], failed["evidence_complete"]), (True, False))
        self.assertIn("launch_failed", failed["not_run"])
        self.assertIn("child_report_missing", failed["not_run"])
        for label, body in (("null", "null"), ("number", "0"), ("array", "[]"), ("empty", {}),
                            ("incomplete", {"verdict": "DENIED", "probe_cleanup_verified": True}),
                            ("error", {"error": {"type": "OSError", "code": None}})):
            with self.subTest("section with a " + label + " report"):
                bad = native_acl.restricted_primary_child_report(
                    Launcher(self.GOOD_LAUNCH, body), make, MACHINE, lambda path: None)
                self.assertEqual((bad["restoration_verified"], bad["evidence_complete"]), (True, False))
                self.assertTrue(bad["not_run"])
                self.assertFalse(native_acl.child_section_verified(bad))

    def test_a_child_that_may_still_run_leaves_the_fixture_and_asks_the_caller_to_keep_it(self):
        class Launcher(FakeNative):
            def __init__(self, launch, error=None):
                super().__init__(dacl=PROTECTED)
                self.launch, self.error, self.restores, self.launched = launch, error, 0, False

            def run_with_restricted_primary_token(self, argv, cwd, timeout=900.0):
                self.launched = True
                if self.error:
                    raise self.error
                return self.launch

            def apply_dacl(self, path, sddl, protection="auto"):
                self.restores += self.launched
                return super().apply_dacl(path, sddl, protection)
        base = Path(self.temp.name)
        count = iter(range(100))

        def make(label):
            path = base / ("%s-%d" % (label, next(count)))
            path.mkdir()
            return path
        for label, launch in (("not stopped", {**self.GOOD_LAUNCH, "child_stopped": False,
                                               "cleanup_verified": False, "handles_retained": True}),
                              ("stop not reported", {key: value for key, value in self.GOOD_LAUNCH.items()
                                                     if key != "child_stopped"})):
            with self.subTest(label):
                hold, native = [], Launcher(launch)
                done = native_acl.restricted_primary_child_report(
                    native, make, MACHINE, lambda path: None, hold=hold)
                self.assertEqual(native.restores, 0)
                self.assertEqual(hold, ["child_stop_unestablished"])
                self.assertEqual((done["fixture_retained"], done["restoration_verified"],
                                  done["evidence_complete"]), (True, False, False))
                self.assertEqual(done["restored"], {"verified": False, "skipped": "child_stop_unestablished"})
                self.assertIn("child_stop_unestablished", done["not_run"])
        with self.subTest("launcher raised"):
            hold, native = [], Launcher(None, RuntimeError("boom"))
            with self.assertRaises(RuntimeError):
                native_acl.restricted_primary_child_report(native, make, MACHINE, lambda path: None, hold=hold)
            self.assertEqual((native.restores, hold), (0, ["child_stop_unestablished"]))
        for label, launch in (("stopped", self.GOOD_LAUNCH),
                              ("never started", {"launched": False, "winerror": 2, "child_stopped": True})):
            with self.subTest(label):
                hold, native = [], Launcher(launch)
                done = native_acl.restricted_primary_child_report(
                    native, make, MACHINE, lambda path: None, hold=hold)
                self.assertEqual((native.restores, hold, done["fixture_retained"]), (1, [], False))
                self.assertTrue(done["restored"]["verified"])

    def test_the_section_requires_a_report_object_whatever_the_evidence_reasons_say(self):
        from unittest import mock

        class Launcher(FakeNative):
            def __init__(self):
                super().__init__(dacl=PROTECTED)

            def run_with_restricted_primary_token(self, argv, cwd, timeout=900.0):
                return ChildEvidenceTests.GOOD_LAUNCH
        base = Path(self.temp.name)
        count = iter(range(100))

        def make(label):
            path = base / ("%s-%d" % (label, next(count)))
            path.mkdir()
            return path
        for report in (None, [], 0, "DENIED"):
            with self.subTest(repr(report)):
                with mock.patch.object(native_acl, "child_evidence", return_value=(report, [])):
                    done = native_acl.restricted_primary_child_report(
                        Launcher(), make, MACHINE, lambda path: None)
                self.assertEqual((done["evidence_complete"], done["child_verdict"]), (False, None))
                self.assertIsNone(done["child"])
                self.assertFalse(native_acl.child_section_verified(done))

    def test_the_standalone_section_is_clean_only_with_restoration_and_complete_evidence(self):
        for restored, complete, clean in ((True, True, True), (True, False, False),
                                          (False, True, False), (False, False, False)):
            self.assertIs(native_acl.child_section_verified(
                {"restoration_verified": restored, "evidence_complete": complete}), clean)

    def run_main(self, child, **overrides):
        from unittest import mock
        import contextlib
        import io
        import src.paper_pilot_phase_cutover as cutover
        good = {"matrix": {"cleanup_verified": True}, "actual_fence_shape": {"verified": True},
                "privilege_isolation": {"verified": True},
                "installation_observation": {"stabilized_install_and_restoration_exact": True,
                                             "restoration_verified": True}}
        good.update(overrides)
        patches = [mock.patch.object(native_acl, "bootstrap_checkout"),
                   mock.patch.object(native_acl, "WindowsNative"),
                   mock.patch.object(cutover, "_current_sid", return_value=MACHINE)]
        for name, section in (("candidate_matrix", "matrix"),
                              ("probe_actual_fence_shape", "actual_fence_shape"),
                              ("privilege_isolation_on_fence_shape", "privilege_isolation"),
                              ("installation_observation", "installation_observation")):
            patches.append(mock.patch.object(native_acl, name, side_effect=self.producer(good[section])))
        patches.append(mock.patch.object(native_acl, "restricted_primary_child_report",
                                         side_effect=self.producer(child)))
        out = io.StringIO()
        with contextlib.ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            stack.enter_context(contextlib.redirect_stdout(out))
            code = native_acl.main([])
        return code, json.loads(out.getvalue())

    @staticmethod
    def producer(body):
        if callable(body):
            return body

        def produce(*args, **kwargs):
            if isinstance(body, Exception):
                raise body
            return body
        return produce

    def test_main_exit_and_json_follow_the_restricted_primary_section_at_runtime(self):
        complete = {"restoration_verified": True, "evidence_complete": True, "not_run": []}
        code, report = self.run_main(complete)
        self.assertEqual((code, report["cleanup_verified"]), (0, True))
        self.assertEqual(report["completed_stages"][-1], "restricted_primary_child")
        self.assertEqual(report["restricted_primary_child"], complete)
        for body in ({"restoration_verified": True, "evidence_complete": False,
                      "not_run": ["launch_failed"]},
                     {"restoration_verified": False, "evidence_complete": True, "not_run": []},
                     {"restoration_verified": False, "evidence_complete": False,
                      "not_run": ["child_report_missing"]}):
            code, report = self.run_main(body)
            self.assertEqual((code, report["cleanup_verified"]), (1, False), body)
            self.assertIn("restricted_primary_child", report["completed_stages"])
        code, report = self.run_main(RuntimeError("launch"))
        self.assertEqual((code, report["cleanup_verified"]), (1, False))
        self.assertEqual(report["restricted_primary_child"]["error"]["type"], "RuntimeError")
        self.assertNotIn("restricted_primary_child", report["completed_stages"])

    def test_main_exit_and_json_fail_closed_on_a_null_or_incomplete_child_report(self):
        real_section = native_acl.restricted_primary_child_report
        class Launcher(FakeNative):
            def __init__(self, text, **kwargs):
                super().__init__(dacl=PROTECTED, **kwargs)
                self.text = text

            def run_with_restricted_primary_token(self, argv, cwd, timeout=900.0):
                Path(argv[-1]).write_text(self.text, encoding="utf-8")
                return ChildEvidenceTests.GOOD_LAUNCH
        for label, text, reason in (("null", "null", "child_reported_error"),
                                    ("number", "7", "child_reported_error"),
                                    ("empty", "{}", "child_report_incomplete"),
                                    ("incomplete", json.dumps({"verdict": "DENIED", "probe_cleanup_verified": True}),
                                     "child_report_incomplete")):
            with self.subTest(label):
                def section(native, make_directory, sid, stabilize, hold=None, text=text):
                    return real_section(Launcher(text), make_directory, sid, lambda path: None, hold=hold)
                code, report = self.run_main(section)
                self.assertEqual((code, report["cleanup_verified"]), (1, False))
                self.assertEqual(report["restricted_primary_child"].get("error"), None, report)
                self.assertFalse(report["restricted_primary_child"]["evidence_complete"])
                self.assertIn(reason, report["restricted_primary_child"]["not_run"])

    def test_main_keeps_the_fixture_root_while_a_child_may_still_run(self):
        roots = []

        def producer(native, make_directory, sid, stabilize, hold=None):
            roots.append(make_directory("probe").parent)
            hold.append("child_stop_unestablished")
            return {"restoration_verified": False, "evidence_complete": False,
                    "not_run": ["child_stop_unestablished"], "fixture_retained": True}
        code, report = self.run_main(producer)
        self.addCleanup(shutil.rmtree, roots[0], ignore_errors=True)
        self.assertEqual((code, report["cleanup_verified"], report["fixture_retained"]), (1, False, True))
        self.assertTrue(roots[0].is_dir() and (roots[0] / "probe").is_dir())
        self.assertNotIn(str(roots[0]), json.dumps(report))
        roots.clear()

        def finished(native, make_directory, sid, stabilize, hold=None):
            roots.append(make_directory("probe").parent)
            return {"restoration_verified": True, "evidence_complete": True, "not_run": []}
        code, report = self.run_main(finished)
        self.assertEqual((code, report["cleanup_verified"], "fixture_retained" in report), (0, True, False))
        self.assertFalse(roots[0].exists())
        roots.clear()

        def failed(native, make_directory, sid, stabilize, hold=None):
            roots.append(make_directory("probe").parent)
            hold.append("child_stop_unestablished")
            raise RuntimeError("launcher raised")
        code, report = self.run_main(failed)
        self.addCleanup(shutil.rmtree, roots[0], ignore_errors=True)
        self.assertEqual((code, report["cleanup_verified"], report["fixture_retained"]), (1, False, True))
        self.assertTrue(roots[0].is_dir())

    def test_a_held_fixture_is_unclean_even_when_the_section_body_looks_complete(self):
        roots = []

        def producer(native, make_directory, sid, stabilize, hold=None):
            roots.append(make_directory("probe").parent)
            hold.append("child_stop_unestablished")
            return {"restoration_verified": True, "evidence_complete": True, "not_run": []}
        code, report = self.run_main(producer)
        self.addCleanup(shutil.rmtree, roots[0], ignore_errors=True)
        self.assertEqual((code, report["cleanup_verified"], report["fixture_retained"]), (1, False, True))

    def test_main_stays_unclean_when_any_earlier_section_is_unverified(self):
        complete = {"restoration_verified": True, "evidence_complete": True, "not_run": []}
        for section, body in (("matrix", {"cleanup_verified": False}),
                              ("actual_fence_shape", {"verified": False}),
                              ("privilege_isolation", {"verified": False}),
                              ("installation_observation",
                               {"stabilized_install_and_restoration_exact": False, "restoration_verified": True}),
                              ("installation_observation",
                               {"stabilized_install_and_restoration_exact": True, "restoration_verified": False}),
                              ("installation_observation", {"stabilized_install_and_restoration_exact": True})):
            code, report = self.run_main(complete, **{section: body})
            self.assertEqual((code, report["cleanup_verified"]), (1, False), (section, body))

    def installation_through_main(self, native):
        real = native_acl.installation_observation

        def section(_native, sid, make_directory, _stabilize):
            return real(native, sid, make_directory, lambda path: None)
        complete = {"restoration_verified": True, "evidence_complete": True, "not_run": []}
        return self.run_main(complete, installation_observation=section)

    def test_main_is_clean_when_every_fixture_restoration_is_verified(self):
        code, report = self.installation_through_main(PerFixtureNative())
        self.assertEqual((code, report["cleanup_verified"]), (0, True))
        self.assertIs(report["installation_observation"]["restoration_verified"], True)
        self.assertIn("installation_observation", report["completed_stages"])

    def test_main_is_unclean_for_each_selective_restoration_failure_or_exception(self):
        for label in LABELS:
            for how in RESTORATION_FAILURES:
                with self.subTest(label=label, how=how):
                    code, report = self.installation_through_main(PerFixtureNative(bad=(label,), how=how))
                    section = report["installation_observation"]
                    self.assertEqual((code, report["cleanup_verified"]), (1, False))
                    self.assertEqual(section["restoration_unverified"], [label])
                    self.assertIs(section["restoration_verified"], False)
                    self.assertNotIn("error", section)
                    self.assertIn("installation_observation", report["completed_stages"])
                    self.assertEqual(report["completed_stages"][-1], "restricted_primary_child")
                    self.assertNotIn("fixture_retained", report)
                    self.assertNotIn("refused", json.dumps(report))

    def test_main_stays_clean_for_an_inexact_unprotected_installation_that_was_restored(self):
        code, report = self.installation_through_main(PerFixtureNative(inexact=LABELS[:2]))
        self.assertEqual((code, report["cleanup_verified"]), (0, True))
        self.assertIs(report["installation_observation"][LABELS[0]]["installed"]["installed_exactly"], False)

    def test_main_stays_unclean_for_an_inexact_stabilized_installation_even_when_restored(self):
        code, report = self.installation_through_main(PerFixtureNative(inexact=(STABILIZED,)))
        self.assertEqual((code, report["cleanup_verified"]), (1, False))
        self.assertIs(report["installation_observation"]["restoration_verified"], True)

    def test_main_is_unclean_when_an_installation_raises_and_its_restoration_cannot_be_shown(self):
        code, report = self.installation_through_main(
            PerFixtureNative(install_raises=(LABELS[0],), bad=(LABELS[0],), how="raises"))
        self.assertEqual((code, report["cleanup_verified"]), (1, False))
        self.assertEqual(report["installation_observation"]["restoration_unverified"], [LABELS[0]])


class LaunchingNative:
    """Stands in for ``WindowsNative`` where only the restricted-primary launch outcome matters."""

    def __init__(self, outcome):
        self.outcome, self.launches = outcome, []

    def __call__(self):
        return self

    def read_dacl(self, path):
        return BASE

    def run_with_restricted_primary_token(self, argv, cwd, timeout=900.0):
        self.launches.append((list(argv), timeout))
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return dict(self.outcome)


STOPPED = {"launched": True, "completed": True, "child_stopped": True}
UNSTOPPED = {"launched": True, "completed": False, "child_stopped": False}
ACCOUNT = "S-1-5-21-4444444444-5555555555-6666666666-1001"
NEVER_STARTED = {"launched": False, "completed": False, "child_stopped": True, "winerror": 2}


def run_case(case_class, name):
    result = unittest.TestResult()
    unittest.TestSuite([case_class(name)]).run(result)
    return result


class ChildStopFixtureOwnershipTests(unittest.TestCase):
    """The direct launcher consumers restore and remove their fixtures only after the launch shows
    its child stopped. These are portable models of the teardown; whether a Windows child really
    outlives a failed assertion was never observed."""

    def test_the_hold_follows_the_launch_outcome(self):
        for label, outcome, reasons in (
                ("stopped", STOPPED, []),
                ("failed before the process was created", NEVER_STARTED, []),
                ("child not shown stopped", UNSTOPPED, ["child_stop_unestablished"]),
                ("child_stopped absent", {"launched": True}, ["child_stop_unestablished"]),
                ("child_stopped truthy but not True", {"child_stopped": 1}, ["child_stop_unestablished"]),
                ("launcher raised", RuntimeError("boom"), ["launcher_raised"])):
            with self.subTest(label):
                hold = native_acl.ChildStopHold()
                native = LaunchingNative(outcome)
                if isinstance(outcome, BaseException):
                    with self.assertRaises(RuntimeError):
                        hold.launch(native, ["x"], Path("."), timeout=3)
                else:
                    self.assertEqual(hold.launch(native, ["x"], Path("."), timeout=3), outcome)
                self.assertEqual((hold.reasons, hold.held), (reasons, bool(reasons)))
                self.assertEqual(native.launches, [(["x"], 3)])

    def test_a_second_clean_launch_does_not_clear_an_earlier_hold(self):
        hold = native_acl.ChildStopHold()
        hold.launch(LaunchingNative(UNSTOPPED), ["x"], Path("."))
        hold.launch(LaunchingNative(STOPPED), ["x"], Path("."))
        self.assertEqual(hold.reasons, ["child_stop_unestablished"])

    def test_settle_restores_then_removes_only_when_nothing_is_held(self):
        temp = tempfile.TemporaryDirectory(prefix="jraphyte-hold-")
        events = []
        native_acl.ChildStopHold().settle(temp, lambda: events.append(Path(temp.name).is_dir()))
        self.assertEqual(events, [True])
        self.assertFalse(Path(temp.name).exists())

    def test_settle_keeps_the_directory_restores_nothing_and_survives_collection_when_held(self):
        import gc
        temp = tempfile.TemporaryDirectory(prefix="jraphyte-hold-")
        root = Path(temp.name)
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        (root / "state").mkdir()
        hold, restored = native_acl.ChildStopHold(), []
        hold.launch(LaunchingNative(UNSTOPPED), ["x"], root)
        with self.assertRaises(AssertionError) as caught:
            hold.settle(temp, lambda: restored.append(True))
        self.assertIn("child_stop_unestablished", str(caught.exception))
        self.assertEqual(restored, [])
        self.assertFalse(temp._finalizer.alive)
        del temp, caught
        gc.collect()
        self.assertTrue((root / "state").is_dir())

    def test_a_failed_restoration_keeps_the_directory_and_its_finalizer_detached(self):
        temp = tempfile.TemporaryDirectory(prefix="jraphyte-hold-")
        root = Path(temp.name)
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)

        def failing():
            raise AssertionError("restoration unverified")
        with self.assertRaisesRegex(AssertionError, "restoration unverified"):
            native_acl.ChildStopHold().settle(temp, failing)
        self.assertTrue(root.is_dir())
        self.assertFalse(temp._finalizer.alive)

    def descriptor_case(self, outcome, name="test_probe"):
        roots, removed = [], []

        class Probe(NativeDescriptorTests):
            __unittest_skip__ = False

            def setUp(case):
                super().setUp()
                roots.append(Path(case.temp.name))
                (roots[0] / "parent" / "marker").write_text("x", encoding="utf-8")

            def test_probe(case):
                case.deny(FOREIGN)
                case.hold.launch(case.native, ["child"], roots[0], timeout=1)
        native = LaunchingNative(outcome)
        with mock.patch.object(native_acl, "WindowsNative", native), \
                mock.patch.object(windows_fixture_acl, "stabilize_owned_fixture"), \
                mock.patch.object(native_acl, "deny_by_descriptor",
                                  return_value={"installed_exactly": True, "components": {}}), \
                mock.patch.object(native_acl, "deny_present", return_value=True), \
                mock.patch.object(native_acl, "remove_descriptor_deny",
                                  side_effect=lambda *a: removed.append(a[2]) or True):
            result = run_case(Probe, name)
        self.addCleanup(shutil.rmtree, roots[0], ignore_errors=True)
        return result, roots[0], removed

    def test_the_native_descriptor_tests_restore_and_remove_after_a_stopped_or_never_started_child(self):
        for label, outcome in (("stopped", STOPPED), ("never started", NEVER_STARTED)):
            with self.subTest(label):
                result, root, removed = self.descriptor_case(outcome)
                self.assertEqual((result.errors, result.failures), ([], []))
                self.assertEqual(removed, [FOREIGN])
                self.assertFalse(root.exists())

    def test_the_native_descriptor_tests_keep_the_fixture_and_fail_when_the_child_may_still_run(self):
        for label, outcome in (("not shown stopped", UNSTOPPED), ("launcher raised", RuntimeError("boom"))):
            with self.subTest(label):
                result, root, removed = self.descriptor_case(outcome)
                problems = " ".join(text for _, text in result.errors + result.failures)
                self.assertIn("fixture retained", problems)
                self.assertEqual(removed, [])
                self.assertTrue((root / "parent" / "marker").is_file())

    def test_each_native_launcher_test_routes_its_launch_through_the_hold(self):
        for name in ("test_a_child_with_a_restricted_primary_token_reports_through_a_file",
                     "test_a_child_that_outlives_its_timeout_is_terminated_and_is_not_a_completed_run",
                     "test_a_descendant_the_child_leaves_behind_is_contained_and_terminated",
                     "test_a_child_that_never_starts_reports_its_windows_error"):
            for label, outcome in (("not shown stopped", UNSTOPPED), ("launcher raised", RuntimeError("boom"))):
                with self.subTest(name, outcome=label):
                    result, root, removed = self.descriptor_case(outcome, name)
                    problems = " ".join(text for _, text in result.errors + result.failures)
                    self.assertIn("fixture retained", problems)
                    self.assertEqual(removed, [])
                    self.assertTrue((root / "parent" / "marker").is_file())

    def owned_tree_case(self, outcome):
        calls, roots = [], []

        class Probe(unittest.TestCase):
            def test_probe(case):
                tree = v1_v4.OwnedTree(case)
                roots.append(tree.base)
                (tree.base / "state").mkdir()
                tree.hold.launch(LaunchingNative(outcome), ["child"], tree.base, timeout=1)
        with mock.patch.object(v1_v4, "_call", side_effect=lambda *a: calls.append(a)), \
                mock.patch.object(v1_v4, "_current_sid", return_value=ACCOUNT):
            result = run_case(Probe, "test_probe")
        self.addCleanup(shutil.rmtree, roots[0], ignore_errors=True)
        return result, roots[0], calls

    def test_the_owned_tree_lifts_acls_and_removes_itself_after_a_stopped_child(self):
        result, root, calls = self.owned_tree_case(STOPPED)
        self.assertEqual((result.errors, result.failures), ([], []))
        self.assertTrue(calls and all(call[0] == "icacls.exe" for call in calls))
        self.assertFalse(root.exists())

    def test_the_owned_tree_touches_nothing_and_fails_when_the_child_may_still_run(self):
        for label, outcome in (("not shown stopped", UNSTOPPED), ("launcher raised", RuntimeError("boom"))):
            with self.subTest(label):
                result, root, calls = self.owned_tree_case(outcome)
                problems = " ".join(text for _, text in result.errors + result.failures)
                self.assertIn("fixture retained", problems)
                self.assertEqual(calls, [])
                self.assertTrue((root / "state").is_dir())

    def strict_producer_case(self, outcome):
        calls, roots = [], []

        class Probe(v1_v4.V1FenceTrusteeTests):
            __unittest_skip__ = False

            def setUp(case):
                case.tree = v1_v4.OwnedTree(case)
                roots.append(case.tree.base)
        name = "test_the_strict_positive_producer_path_runs_in_a_restricted_primary_token_child"
        with mock.patch.object(v1_v4, "_call", side_effect=lambda *a: calls.append(a)), \
                mock.patch.object(v1_v4, "_current_sid", return_value=ACCOUNT), \
                mock.patch.object(v1_v4.windows_native_acl, "WindowsNative", LaunchingNative(outcome)):
            result = run_case(Probe, name)
        self.addCleanup(shutil.rmtree, roots[0], ignore_errors=True)
        return result, roots[0], calls

    def test_the_strict_producer_test_routes_its_launch_through_the_hold(self):
        result, root, calls = self.strict_producer_case(UNSTOPPED)
        problems = " ".join(text for _, text in result.errors + result.failures)
        self.assertIn("child_stop_unestablished", problems)
        self.assertIn("fixture retained", problems)
        self.assertEqual(calls, [])
        self.assertTrue(root.is_dir())
        result, root, calls = self.strict_producer_case(NEVER_STARTED)
        problems = " ".join(text for _, text in result.errors + result.failures)
        self.assertNotIn("fixture retained", problems)
        self.assertIn("launched", problems)
        self.assertFalse(root.exists())


@unittest.skipUnless(WINDOWS, "real descriptor, token and access-check APIs")
class NativeDescriptorTests(unittest.TestCase):
    def setUp(self):
        self.native = native_acl.WindowsNative()
        self.temp = tempfile.TemporaryDirectory(prefix="jraphyte-native-acl-")
        self.hold = native_acl.ChildStopHold()
        self.denied = []
        self.addCleanup(self.settle)
        self.parent = Path(self.temp.name) / "parent"
        self.parent.mkdir()
        windows_fixture_acl.stabilize_owned_fixture(
            Path(self.temp.name), [("parent", self.parent)], read=self.native.read_dacl)

    def settle(self):
        self.hold.settle(self.temp, lambda: [self.remove(sid) for sid in reversed(self.denied)])

    def deny(self, sid):
        self.denied.append(sid)
        done = native_acl.deny_by_descriptor(self.native, self.parent, sid)
        self.assertTrue(done["installed_exactly"],
                        native_acl.components_message("installation", done["components"]))
        return done

    def remove(self, sid):
        if native_acl.deny_present(self.native, self.parent, sid):
            self.assertTrue(native_acl.remove_descriptor_deny(self.native, self.parent, sid))

    def test_an_unresolvable_sid_is_installed_read_back_exactly_and_removed(self):
        before, owner = self.native.read_dacl(self.parent), self.native.read_owner(self.parent)
        done = self.deny(FOREIGN)
        ace_list = native_acl.split_dacl(self.native.read_dacl(self.parent))[1]
        self.assertEqual(ace_list, [done["ace"]] + native_acl.split_dacl(before)[1])
        self.assertEqual(done["ace"].split(";"), ["(D", "", "LC", "", "", FOREIGN + ")"])
        self.assertEqual(self.native.read_owner(self.parent), owner)
        self.assertTrue(native_acl.remove_descriptor_deny(self.native, self.parent, FOREIGN))
        self.assertEqual(native_acl.split_dacl(self.native.read_dacl(self.parent))[1],
                         native_acl.split_dacl(before)[1])
        self.assertTrue(native_acl.restoration(self.native, self.parent, before, owner)["verified"])

    def test_the_token_lists_enabled_and_disabled_privileges_by_name(self):
        privileges = dict(self.native.privileges())
        self.assertTrue(privileges["SeChangeNotifyPrivilege"])
        self.assertTrue(all(name.startswith("Se") and name.endswith("Privilege") for name in privileges))

    def test_access_check_honours_a_descriptor_deny_of_the_running_account(self):
        from src.paper_pilot_phase_cutover import _current_sid
        sid = _current_sid()
        for stripped in (True, False):
            self.assertTrue(self.native.access_mask(self.parent, stripped) & native_acl.FILE_ADD_SUBDIRECTORY,
                            "the disposable parent must grant the right before any deny")
        self.deny(sid)
        for stripped in (True, False):
            mask = self.native.access_mask(self.parent, stripped)
            self.assertEqual(mask & native_acl.FILE_ADD_SUBDIRECTORY, 0, stripped)
            self.assertTrue(mask & native_acl.FILE_ADD_FILE, stripped)

    def test_the_probe_sees_creation_and_removes_what_it_created_when_nothing_denies_it(self):
        report = native_acl.recreation_report(self.native, self.parent, self.parent / "state")
        for label in ("stripped", "full"):
            self.assertEqual(report["mkdir"][label], {"created": True, "removed": True}, label)
            self.assertEqual(report["mkdir_CreateDirectoryW"][label], {"created": True, "removed": True}, label)
            self.assertEqual(report["file_control"][label], {"created": True, "removed": True}, label)
            self.assertTrue(report["access_check"][label]["add_subdirectory"], label)
        self.assertEqual(report["verdict"], "DACL_GRANTS_ADD_SUBDIRECTORY")
        self.assertEqual(sorted(self.parent.iterdir()), [])
        self.assertIn(report["filesystem"], ("NTFS", "ReFS"))

    def test_failures_that_are_not_access_denied_carry_their_own_windows_error(self):
        missing = self.parent / "no-such-parent" / "child"
        existing = self.parent / "already-there"
        existing.mkdir()
        for stripped in (True, False):
            for route in ROUTES:
                with self.subTest(stripped=stripped, route=route):
                    self.assertEqual(self.native.try_create_directory(missing, stripped, route),
                                     {"created": False, "winerror": 3})
                    self.assertEqual(self.native.try_create_directory(existing, stripped, route),
                                     {"created": False, "winerror": 183})
        self.assertEqual(sorted(path.name for path in self.parent.iterdir()), ["already-there"])

    def test_a_deny_that_windows_spells_as_an_alias_is_removed_by_its_full_sid(self):
        before, owner = self.native.read_dacl(self.parent), self.native.read_owner(self.parent)
        done = self.deny(USERS)
        stored = native_acl.split_dacl(self.native.read_dacl(self.parent))[1]
        self.assertEqual(stored[0], "(D;;LC;;;BU)")
        self.assertNotIn(done["ace"], stored)
        self.assertEqual(self.native.canonical_trustee(USERS), "BU")
        with self.assertRaises(ValueError):
            native_acl.without_ace(self.native.read_dacl(self.parent), done["ace"])
        self.assertTrue(native_acl.remove_descriptor_deny(self.native, self.parent, USERS))
        self.assertTrue(native_acl.restoration(self.native, self.parent, before, owner)["verified"])
        self.assertEqual(native_acl.split_dacl(self.native.read_dacl(self.parent)),
                         native_acl.split_dacl(before))

    def test_removal_keeps_other_trustees_and_never_confuses_distinct_rid500_sids(self):
        from src.paper_pilot_phase_cutover import _current_sid
        match = re.fullmatch(r"(S-1-5-21-[0-9]+-[0-9]+-[0-9]+)-[0-9]+", _current_sid())
        if match is None:
            self.skipTest("a machine or domain account is required to name this host's RID-500 SID")
        local500 = match.group(1) + "-500"
        before, owner = self.native.read_dacl(self.parent), self.native.read_owner(self.parent)
        self.deny(FOREIGN)
        self.deny(USERS)
        self.deny(local500)
        stored = native_acl.split_dacl(self.native.read_dacl(self.parent))[1]
        self.assertEqual(stored[0], "(D;;LC;;;" + self.native.canonical_trustee(local500) + ")")
        self.assertIn("(D;;LC;;;" + FOREIGN + ")", stored)
        self.assertNotEqual(self.native.canonical_trustee(local500), FOREIGN)
        self.assertTrue(native_acl.remove_descriptor_deny(self.native, self.parent, local500))
        self.assertTrue(native_acl.deny_present(self.native, self.parent, FOREIGN))
        self.assertTrue(native_acl.deny_present(self.native, self.parent, USERS))
        self.assertFalse(native_acl.deny_present(self.native, self.parent, local500))
        with self.assertRaises(ValueError):
            native_acl.remove_descriptor_deny(self.native, self.parent, local500)
        self.assertTrue(native_acl.remove_descriptor_deny(self.native, self.parent, FOREIGN))
        self.assertTrue(native_acl.deny_present(self.native, self.parent, USERS))
        self.assertTrue(native_acl.remove_descriptor_deny(self.native, self.parent, USERS))
        self.assertTrue(native_acl.restoration(self.native, self.parent, before, owner)["verified"])

    def test_a_protected_dacl_stays_protected_through_install_and_removal(self):
        control, aces = native_acl.split_dacl(self.native.read_dacl(self.parent))
        self.native.apply_dacl(self.parent, native_acl.join_dacl("PAI", aces))
        before, owner = self.native.read_dacl(self.parent), self.native.read_owner(self.parent)
        self.assertTrue(native_acl.split_dacl(before)[0].startswith("P"), before)
        self.deny(FOREIGN)
        self.assertTrue(native_acl.split_dacl(self.native.read_dacl(self.parent))[0].startswith("P"))
        self.assertTrue(native_acl.remove_descriptor_deny(self.native, self.parent, FOREIGN))
        self.assertTrue(native_acl.restoration(self.native, self.parent, before, owner)["verified"])

    def test_a_stabilized_parent_installs_and_restores_exactly_with_per_component_facts(self):
        before, owner = self.native.read_dacl(self.parent), self.native.read_owner(self.parent)
        self.assertTrue(native_acl.split_dacl(before)[0].startswith("P"), before)
        done = self.deny(FOREIGN)
        components = done["components"]
        self.assertTrue(components["installed_exactly"], native_acl.components_message("installation", components))
        self.assertTrue(components["control"]["unchanged"])
        self.assertEqual(components["aces"]["count_after"], components["aces"]["count_before"] + 1)
        self.assertEqual((components["aces"]["unexpected_after"], components["aces"]["missing_after"]), ([], []))
        self.assertTrue(native_acl.remove_descriptor_deny(self.native, self.parent, FOREIGN))
        again = native_acl.restoration_components(self.native, self.parent, before, owner)
        self.assertTrue(again["verified"], native_acl.components_message("restoration", again))
        self.assertNotIn("S-1-5-21-%s" % FOREIGN.split("-")[4], json.dumps(components))

    def test_a_privilege_that_is_present_but_disabled_is_enabled_only_inside_the_context(self):
        disabled = [name for name, enabled in self.native.privileges() if not enabled]
        if not disabled:
            self.skipTest("this token has no disabled privilege to enable")
        name = disabled[0]
        with self.native.privilege_enabled(name):
            self.assertTrue(dict(self.native.privileges())[name])
        self.assertFalse(dict(self.native.privileges())[name])
        self.assertEqual(len(self.native.privilege_luid(name)), 8)

    def test_privilege_isolation_on_the_fence_shape_reports_without_a_cause_and_restores(self):
        from src.paper_pilot_phase_cutover import _current_sid
        counter = iter(range(1000))

        def make(label):
            path = Path(self.temp.name) / ("isolation-%d" % next(counter))
            path.mkdir()
            windows_fixture_acl.stabilize_owned_fixture(
                Path(self.temp.name), [(label, path)], read=self.native.read_dacl)
            return path
        done = native_acl.privilege_isolation_on_fence_shape(self.native, make, _current_sid())
        self.assertTrue(done["verified"], native_acl.components_message("isolation", done))
        isolation = done["isolation"]
        self.assertIs(isolation["cause_established"], False)
        self.assertEqual(sorted(isolation["outcomes"]["remove_only"]), isolation["enabled"])
        self.assertIn("SeChangeNotifyPrivilege", isolation["enabled"])
        for outcome in (isolation["outcomes"]["original_process_token"],
                        isolation["outcomes"]["impersonated_copy_all_removed"]):
            self.assertIn("created" if outcome["created"] else "winerror", outcome)

    def test_a_child_with_a_restricted_primary_token_reports_through_a_file(self):
        out = Path(self.temp.name) / "child.json"
        target = self.parent / "state"
        launch = self.hold.launch(
            self.native,
            [sys.executable, str(SCRIPT), "--child-recreation-probe", str(self.parent), str(target), str(out)],
            Path(self.temp.name), timeout=120)
        self.assertEqual(native_acl.launch_defects(launch), [], launch)
        self.assertEqual({key: launch[key] for key in ("launched", "completed", "exit_code", "timed_out",
                                                       "cleanup_verified", "job_active_processes",
                                                       "handles_retained", "errors", "child_stopped")},
                         {"launched": True, "completed": True, "exit_code": 0, "timed_out": False,
                          "cleanup_verified": True, "job_active_processes": 0,
                          "handles_retained": False, "errors": [], "child_stopped": True}, launch)
        body = json.loads(out.read_text(encoding="utf-8"))
        self.assertNotIn("error", body)
        self.assertEqual(body["verdict"], "DACL_GRANTS_ADD_SUBDIRECTORY")
        self.assertEqual(body["enabled_privileges"], ["SeChangeNotifyPrivilege"])
        self.assertFalse(target.exists())
        self.assertTrue(body["probe_cleanup_verified"])

    def test_a_child_that_outlives_its_timeout_is_terminated_and_is_not_a_completed_run(self):
        launch = self.hold.launch(
            self.native, [sys.executable, "-c", "import time; time.sleep(120)"], Path(self.temp.name), timeout=2)
        self.assertEqual((launch["launched"], launch["timed_out"], launch["completed"], launch["terminated"],
                          launch["final_wait"], launch["cleanup_verified"], launch["job_active_processes"],
                          launch["child_stopped"]),
                         (True, True, False, True, "signaled", True, 0, True), launch)

    def test_a_descendant_the_child_leaves_behind_is_contained_and_terminated(self):
        code = ("import subprocess, sys; "
                "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)']); ")
        launch = self.hold.launch(
            self.native, [sys.executable, "-c", code], Path(self.temp.name), timeout=60)
        self.assertEqual((launch["exit_code"], launch["descendants_terminated"], launch["completed"],
                          launch["cleanup_verified"], launch["job_active_processes"],
                          launch["child_stopped"]),
                         (0, True, False, True, 0, True), launch)

    def test_the_privilege_inventory_is_identical_after_a_scope_over_an_enabled_and_a_disabled_privilege(self):
        def state():
            return {name: value & native_acl.PRIVILEGE_STATE_MASK
                    for name, value in self.native.privilege_attributes().items()}
        before = state()
        for name in sorted(before):
            if name in ("SeChangeNotifyPrivilege", "SeIncreaseQuotaPrivilege"):
                with self.native.privilege_enabled(name):
                    self.assertTrue(self.native.privilege_attributes()[name] & 2)
                self.assertEqual(state(), before, name)

    def test_a_child_that_never_starts_reports_its_windows_error(self):
        launch = self.hold.launch(
            self.native, [str(Path(self.temp.name) / "no-such.exe")], Path(self.temp.name), timeout=5)
        self.assertEqual((launch["launched"], launch["exit_code"]), (False, None))
        self.assertIn(launch["winerror"], (2, 3))


if __name__ == "__main__":
    unittest.main()
