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
import tempfile
import unittest

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

    def apply_dacl(self, path, sddl):
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

    def apply_dacl(self, path, sddl):
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


@unittest.skipUnless(WINDOWS, "real descriptor, token and access-check APIs")
class NativeDescriptorTests(unittest.TestCase):
    def setUp(self):
        self.native = native_acl.WindowsNative()
        self.temp = tempfile.TemporaryDirectory(prefix="jraphyte-native-acl-")
        self.addCleanup(self.temp.cleanup)
        self.parent = Path(self.temp.name) / "parent"
        self.parent.mkdir()

    def deny(self, sid):
        done = native_acl.deny_by_descriptor(self.native, self.parent, sid)
        self.addCleanup(self.remove, sid)
        self.assertTrue(done["installed_exactly"])
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


if __name__ == "__main__":
    unittest.main()
