"""Owned-fixture ACL stabilization: verification logic (any OS) and its native effect (Windows).

The platform-independent cases check the argument construction, the ownership boundary and
the fixed-code verification with fake ``icacls`` and DACL reads. The Windows-only cases run
the real ``icacls`` on a disposable tree and are the ones that can show, on a real host,
whether a stabilized fixture really survives the guard's own deny/remove without any change
to its ACE list. Nothing here relaxes a production comparison.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from src import paper_pilot_phase_cutover_guarded_v2 as guarded
from tools import windows_fixture_acl as fixture

DIR_OK = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)"
FILE_OK = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)"
SECRET = r"C:\\Users\\private-account\\secret-dir"
TEMP_PREFIX = "jraphyte-fixture-acl-"


class ProblemCodeTests(unittest.TestCase):
    def test_the_stabilized_shapes_have_no_problems_in_any_order(self):
        self.assertEqual(fixture.fixture_acl_problems(DIR_OK, True), [])
        self.assertEqual(fixture.fixture_acl_problems(FILE_OK, False), [])
        self.assertEqual(fixture.fixture_acl_problems("D:PAI(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)", False), [])

    def test_each_departure_has_its_own_fixed_code(self):
        for sddl, is_dir, expected in (
                (DIR_OK.replace("D:P", "D:"), True, ["NOT_PROTECTED"]),
                (FILE_OK.replace("D:P", "D:AI"), False, ["NOT_PROTECTED"]),
                ("D:(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;OW)", False, ["NOT_PROTECTED", "INHERITED_ACE"]),
                ("D:P(A;OICIID;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)", True, ["INHERITED_ACE"]),
                ("D:P(D;;DCLC;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)", False, ["NON_ALLOW_ACE", "UNREVIEWED_RIGHTS"]),
                ("D:P(A;;FR;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)", False, ["UNREVIEWED_RIGHTS"]),
                (FILE_OK.replace("(A;;FA;;;SY)", "(A;OICI;FA;;;SY)"), False, ["UNREVIEWED_FLAGS"]),
                (DIR_OK.replace("(A;OICI;FA;;;SY)", "(A;;FA;;;SY)"), True, ["UNREVIEWED_FLAGS"]),
                (FILE_OK + "(A;;FA;;;WD)", False, ["UNREVIEWED_TRUSTEES"]),
                ("D:P(A;;FA;;;SY)(A;;FA;;;BA)", False, ["UNREVIEWED_TRUSTEES"]),
                (FILE_OK + "(A;;FA;;;SY)", False, ["UNREVIEWED_TRUSTEES"]),
                ("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;S-1-5-21-1-2-3-500)", False, ["UNREVIEWED_TRUSTEES"]),
                ("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA)", False, ["MALFORMED_ACE", "UNREVIEWED_TRUSTEES"])):
            self.assertEqual(fixture.fixture_acl_problems(sddl, is_dir), expected, sddl)

    def test_an_added_everyone_read_allow_reports_both_rights_and_trustee(self):
        # The shape icacls /grant *S-1-1-0:(R) leaves behind: a read-only ACE for a trustee outside the trio.
        self.assertEqual(fixture.fixture_acl_problems(FILE_OK + "(A;;FR;;;WD)", False),
                         ["UNREVIEWED_RIGHTS", "UNREVIEWED_TRUSTEES"])
        self.assertEqual(fixture.fixture_acl_problems(DIR_OK + "(A;OICI;FR;;;WD)", True),
                         ["UNREVIEWED_RIGHTS", "UNREVIEWED_TRUSTEES"])
        self.assertEqual(fixture.fixture_acl_problems("D:P(A;;FR;;;WD)" + FILE_OK[3:], False),
                         ["UNREVIEWED_RIGHTS", "UNREVIEWED_TRUSTEES"])

    def test_a_barrier_deny_is_never_part_of_the_stabilized_shape(self):
        self.assertEqual(fixture.fixture_acl_problems("D:P(D;;DCLC;;;BU)" + FILE_OK[3:], False),
                         ["NON_ALLOW_ACE", "UNREVIEWED_RIGHTS", "UNREVIEWED_TRUSTEES"])

    def test_the_grant_is_the_base_trio_with_inheritance_removed_first(self):
        self.assertEqual(fixture.grant_arguments(True),
                         ["/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)(F)",
                          "*S-1-5-32-544:(OI)(CI)(F)", "*S-1-3-4:(OI)(CI)(F)"])
        self.assertEqual(fixture.grant_arguments(False),
                         ["/inheritance:r", "/grant:r", "*S-1-5-18:(F)", "*S-1-5-32-544:(F)", "*S-1-3-4:(F)"])
        # No principal beyond the CPython 0o700 base trio (SYSTEM, Administrators, Owner Rights).
        self.assertEqual([alias for alias, _ in fixture.REVIEWED_ALLOWS], ["SY", "BA", "OW"])


class StabilizeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix=TEMP_PREFIX)
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.folder = self.base / "state"
        self.folder.mkdir()
        self.file = self.folder / "a.bin"
        self.file.write_bytes(b"0")
        self.targets = [("state", self.folder), ("file:a.bin", self.file)]
        self.calls = []

    def run_ok(self, command, **options):
        self.calls.append((command, options))
        return subprocess.CompletedProcess(command, 0, "", "")

    def read(self, path):
        return DIR_OK if Path(path).is_dir() else FILE_OK

    def test_every_target_gets_its_own_protecting_grant_in_order_and_is_verified(self):
        fixture.stabilize_owned_fixture(self.base, self.targets, read=self.read, run=self.run_ok)
        self.assertEqual([command for command, _ in self.calls], [
            ["icacls.exe", str(self.folder), *fixture.grant_arguments(True)],
            ["icacls.exe", str(self.file), *fixture.grant_arguments(False)]])
        self.assertTrue(all(options["timeout"] == fixture.TIMEOUT_SECONDS for _, options in self.calls))

    def test_nothing_outside_the_fixture_or_the_fixture_itself_is_ever_changed(self):
        for label, path in (("base", self.base), ("parent", self.base.parent),
                            ("outside", self.base.parent / "elsewhere"),
                            ("dotdot", self.folder / ".." / ".." / "x")):
            with self.assertRaises(fixture.FixtureAclError) as caught:
                fixture.stabilize_owned_fixture(self.base, [("state", self.folder), (label, path)],
                                                read=self.read, run=self.run_ok)
            self.assertEqual(caught.exception.problems, [(label, "OUTSIDE_OWNED_FIXTURE")])
        self.assertEqual(self.calls, [])

    def test_a_failed_or_timed_out_icacls_is_reported_and_later_targets_are_still_attempted(self):
        results = iter((subprocess.CompletedProcess([], 5, "", SECRET),))

        def first_fails_second_times_out(command, **options):
            self.calls.append(command)
            try:
                return next(results)
            except StopIteration:
                raise subprocess.TimeoutExpired(command, 30)
        with self.assertRaises(fixture.FixtureAclError) as caught:
            fixture.stabilize_owned_fixture(self.base, self.targets, read=self.read,
                                            run=first_fails_second_times_out)
        self.assertEqual(caught.exception.problems, [("state", "ICACLS_FAILED"), ("file:a.bin", "ICACLS_FAILED")])
        self.assertEqual(len(self.calls), 2)

    def test_a_dacl_that_is_not_the_stabilized_shape_fails_with_codes_not_text(self):
        def read(path):
            if Path(path).is_dir():
                return DIR_OK
            raise OSError(SECRET)
        with self.assertRaises(fixture.FixtureAclError) as caught:
            fixture.stabilize_owned_fixture(self.base, self.targets, read=read, run=self.run_ok)
        self.assertEqual(caught.exception.problems, [("file:a.bin", "DACL_UNREADABLE")])
        wide = DIR_OK + "(A;OICI;FR;;;WD)"
        with self.assertRaises(fixture.FixtureAclError) as caught:
            fixture.stabilize_owned_fixture(self.base, self.targets, read=lambda p: wide if Path(p).is_dir()
                                            else FILE_OK, run=self.run_ok)
        self.assertEqual(caught.exception.problems, [("state", "UNREVIEWED_RIGHTS"), ("state", "UNREVIEWED_TRUSTEES")])
        for error in (caught.exception, fixture.FixtureAclError([("x", "ICACLS_FAILED")])):
            self.assertNotIn("private-account", repr(error) + str(error))


def _icacls(*args: str) -> None:
    result = subprocess.run(["icacls.exe", *args], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr or result.stdout


@unittest.skipUnless(os.name == "nt", "Windows ACL contract")
class NativeStabilizedFixtureTests(unittest.TestCase):
    def setUp(self):
        self.sid = guarded._current_sid()
        self.temp = tempfile.TemporaryDirectory(prefix=TEMP_PREFIX)
        self.addCleanup(self._cleanup)
        self.base = Path(self.temp.name)
        self.folder = self.base / "old-app"
        self.state = self.folder / "state"
        self.state.mkdir(parents=True)
        self.file = self.state / "controller.lock"
        self.file.write_bytes(b"0")
        self.targets = [("parent", self.folder), ("state", self.state), ("file", self.file)]

    def _cleanup(self):
        for target in (self.folder, self.file):
            if target.exists():
                subprocess.run(["icacls.exe", str(target), "/remove:d", "*" + self.sid],
                               capture_output=True, text=True, timeout=30)
        self.temp.cleanup()
        self.assertFalse(self.base.exists())

    def stabilize(self):
        fixture.stabilize_owned_fixture(self.base, self.targets, read=guarded.directory_dacl_sddl)

    def test_the_real_dacls_are_protected_explicit_and_exactly_the_reviewed_trio(self):
        self.stabilize()
        for _, path in self.targets:
            sddl = guarded.directory_dacl_sddl(path)
            self.assertEqual(fixture.fixture_acl_problems(sddl, path.is_dir()), [], sddl)
            self.assertNotIn("ID", sddl)
        # The runner can still use its own fixture.
        self.file.write_bytes(b"1")
        self.assertEqual(self.file.read_bytes(), b"1")

    def test_the_stabilized_fixture_survives_a_real_deny_and_removal_without_gaining_any_ace(self):
        self.stabilize()
        original_dir = guarded.directory_dacl_sddl(self.folder)
        original_file = guarded.directory_dacl_sddl(self.file)
        _icacls(str(self.file), "/deny", "*" + self.sid + ":(WD,AD)")
        _icacls(str(self.folder), "/deny", "*" + self.sid + ":(AD)")
        now_file = guarded.directory_dacl_sddl(self.file)
        now_dir = guarded.directory_dacl_sddl(self.folder)
        # The unchanged production comparisons: only the admission deny was added.
        self.assertTrue(guarded._only_admission_dacl_added(original_file, now_file, self.sid), now_file)
        self.assertTrue(guarded._only_parent_admission_added(original_dir, now_dir, self.sid), now_dir)
        self.assertEqual(len(guarded._aces(now_file)), len(guarded._aces(original_file)) + 1)
        self.assertEqual(len(guarded._aces(now_dir)), len(guarded._aces(original_dir)) + 1)
        _icacls(str(self.file), "/remove:d", "*" + self.sid)
        _icacls(str(self.folder), "/remove:d", "*" + self.sid)
        self.assertTrue(guarded._same_effective_dacl(original_file, guarded.directory_dacl_sddl(self.file)))
        self.assertTrue(guarded._same_effective_dacl(original_dir, guarded.directory_dacl_sddl(self.folder)))

    def test_a_later_unreviewed_grant_is_reported_by_the_verification(self):
        self.stabilize()
        _icacls(str(self.file), "/grant", "*S-1-1-0:(R)")
        self.assertEqual(fixture.fixture_acl_problems(guarded.directory_dacl_sddl(self.file), False),
                         ["UNREVIEWED_RIGHTS", "UNREVIEWED_TRUSTEES"])

    def test_the_fixture_base_itself_is_never_touched(self):
        before = guarded.directory_dacl_sddl(self.base)
        with self.assertRaises(fixture.FixtureAclError):
            fixture.stabilize_owned_fixture(self.base, [("base", self.base)], read=guarded.directory_dacl_sddl)
        self.stabilize()
        self.assertEqual(guarded.directory_dacl_sddl(self.base), before)


if __name__ == "__main__":
    unittest.main()
