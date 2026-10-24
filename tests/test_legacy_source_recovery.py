"""Safe archive recovery tests; synthetic parser pins are NOT legacy conformance."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch
import warnings
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import recover_legacy_core as recovery


class LegacyRecoveryTests(unittest.TestCase):
    # Only archive parsing/creation is tested with this synthetic pin. The CLI
    # offers no option to substitute the repository's reviewed legacy pin.
    DATA = b"raise AssertionError('recovery must never execute this member')\n"
    MEMBER = "saved-project/trace_gc/data/upstream/graph_synthesis/core.py"

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.archive = self.root / "source.zip"
        self.output = self.root / "verified-core.py"
        self.pin = recovery.git_blob(self.DATA)
        self.mock_pin = patch.object(recovery, "PINNED_CORE_BLOB", self.pin)
        self.mock_pin.start()
        self.addCleanup(self.mock_pin.stop)

    def write_archive(self, entries=None):
        with ZipFile(self.archive, "w", compression=ZIP_DEFLATED) as archive:
            for name, data in entries if entries is not None else [(self.MEMBER, self.DATA)]:
                archive.writestr(name, data)

    def rejected(self, code, **kwargs):
        with self.assertRaisesRegex(recovery.RecoveryError, "^" + code + "$"):
            recovery.recover_core(self.archive, destination=self.output, **kwargs)
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.root.glob(".trace-pinned-core-*")), [])

    def test_exact_bytes_recovered_without_execution_or_new_authority(self):
        self.write_archive()
        result = recovery.recover_core(self.archive, destination=self.output)
        self.assertEqual(self.output.read_bytes(), self.DATA)
        self.assertEqual(result["core_git_blob"], self.pin)
        self.assertFalse(result["code_executed"])
        self.assertFalse(result["existing_files_overwritten"])
        self.assertEqual(result["legacy_conformance"], "NOT_RUN_BY_RECOVERY")
        self.assertEqual(result["production_qualification"], "NOT_ESTABLISHED")

    def test_verify_only_never_creates_destination(self):
        self.write_archive()
        report = recovery.recover_core(self.archive)
        self.assertFalse(report["destination_created"])
        self.assertFalse(self.output.exists())

    def test_wrong_pin_rejected_before_output_or_execution(self):
        self.write_archive([(self.MEMBER, self.DATA + b"# substituted\n")])
        self.rejected("UPSTREAM_PIN_MISMATCH")

    def test_missing_core_rejected(self):
        self.write_archive([("README.md", b"No core supplied.")])
        self.rejected("PINNED_MEMBER_MISSING")

    def test_multiple_members_require_explicit_disambiguation(self):
        other = "other/graph_synthesis/core.py"
        self.write_archive([(self.MEMBER, self.DATA), (other, self.DATA)])
        self.rejected("PINNED_MEMBER_AMBIGUOUS")
        report = recovery.recover_core(self.archive, destination=self.output, member=self.MEMBER)
        self.assertEqual(report["archive_member"], self.MEMBER)

    def test_explicit_member_cannot_bypass_pin_or_suffix(self):
        self.write_archive([("arbitrary.py", self.DATA), (self.MEMBER, b"wrong")])
        self.rejected("PINNED_MEMBER_MISSING", member="arbitrary.py")
        self.rejected("UPSTREAM_PIN_MISMATCH", member=self.MEMBER)

    def test_duplicate_member_refused_even_when_bytes_match(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            self.write_archive([(self.MEMBER, self.DATA), (self.MEMBER, self.DATA)])
        self.rejected("DUPLICATE_ARCHIVE_MEMBER")

    def test_traversal_absolute_drive_and_backslash_members_refused(self):
        for name in ("../outside", "/absolute", "C:/core.py", "a\\b", "safe/../outside", "./relative"):
            with self.subTest(name=name):
                self.write_archive([(self.MEMBER, self.DATA), (name, b"not extracted")])
                if "\\" in name and os.name == "nt":
                    # zipfile normalizes backslashes in names passed to writestr
                    # on Windows. Rewrite the equal-length header names so the
                    # reader actually receives the unsafe member being tested.
                    raw = self.archive.read_bytes()
                    normalized = name.replace("\\", "/").encode("ascii")
                    literal = name.encode("ascii")
                    self.archive.write_bytes(raw.replace(normalized, literal))
                with ZipFile(self.archive) as archive:
                    self.assertIn(name, [entry.orig_filename for entry in archive.infolist()])
                self.rejected("UNSAFE_ARCHIVE_MEMBER")

    def test_archive_core_and_member_count_limits(self):
        self.write_archive()
        with patch.object(recovery, "MAX_ARCHIVE_BYTES", 5):
            self.rejected("ARCHIVE_TOO_LARGE")
        with patch.object(recovery, "MAX_CORE_BYTES", 5):
            self.rejected("CORE_SIZE_LIMIT")
        with patch.object(recovery, "MAX_MEMBERS", 0):
            self.rejected("TOO_MANY_ARCHIVE_MEMBERS")

    def test_symlink_member_is_not_source_code(self):
        member = ZipInfo(self.MEMBER)
        member.create_system = 3
        member.external_attr = (stat.S_IFLNK | 0o777) << 16
        self.write_archive([(member, self.DATA)])
        self.rejected("PINNED_MEMBER_NOT_REGULAR")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "named pipes are unavailable on this platform")
    def test_named_pipe_is_rejected_without_waiting_for_a_writer(self):
        os.mkfifo(self.archive)
        self.rejected("ARCHIVE_NOT_REGULAR")

    def test_invalid_zip_is_a_structured_input_failure(self):
        self.archive.write_bytes(b"not a zip")
        self.rejected("INVALID_ARCHIVE")

    def test_existing_destination_is_never_overwritten(self):
        self.write_archive()
        self.output.write_bytes(b"owned-existing-content")
        with self.assertRaisesRegex(recovery.RecoveryError, "DESTINATION_EXISTS"):
            recovery.recover_core(self.archive, destination=self.output)
        self.assertEqual(self.output.read_bytes(), b"owned-existing-content")

    def test_existing_destination_symlink_is_not_followed(self):
        self.write_archive()
        target = self.root / "owned.txt"
        target.write_bytes(b"owned")
        try:
            self.output.symlink_to(target)
        except OSError as exc:
            if os.name == "nt" and getattr(exc, "winerror", None) == 1314:
                self.skipTest("Windows symlink creation privilege unavailable")
            raise
        with self.assertRaisesRegex(recovery.RecoveryError, "DESTINATION_EXISTS"):
            recovery.recover_core(self.archive, destination=self.output)
        self.assertEqual(target.read_bytes(), b"owned")
        self.assertTrue(self.output.is_symlink())

    def test_create_race_has_only_one_winner(self):
        self.write_archive()
        def recover(_):
            try:
                recovery.recover_core(self.archive, destination=self.output)
                return "CREATED"
            except recovery.RecoveryError as error:
                return str(error)
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(recover, range(2)))
        self.assertCountEqual(results, ["CREATED", "DESTINATION_EXISTS"])
        self.assertEqual(self.output.read_bytes(), self.DATA)
        self.assertEqual(list(self.root.glob(".trace-pinned-core-*")), [])

    def test_unsupported_atomic_create_fails_without_partial_output(self):
        self.write_archive()
        with patch.object(recovery.os, "link", side_effect=OSError("unsupported")):
            self.rejected("ATOMIC_CREATE_UNAVAILABLE")

    def test_missing_parent_is_not_silently_created(self):
        self.write_archive()
        self.output = self.root / "missing" / "core.py"
        self.rejected("DESTINATION_PARENT_MISSING")
        self.assertFalse(self.output.parent.exists())

    def test_cli_failure_does_not_echo_sensitive_input_paths(self):
        self.archive = self.root / "private-user-filename.zip"
        errors = io.StringIO()
        with redirect_stderr(errors):
            status = recovery.main([str(self.archive), "--verify-only"])
        self.assertEqual(status, 1)
        self.assertNotIn(str(self.archive), errors.getvalue())
        self.assertEqual(json.loads(errors.getvalue())["code"], "FileNotFoundError")

    def test_cli_success_is_machine_readable_and_not_conformance(self):
        self.write_archive()
        output = io.StringIO()
        with redirect_stdout(output):
            status = recovery.main([str(self.archive), "--verify-only"])
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(output.getvalue())["legacy_conformance"], "NOT_RUN_BY_RECOVERY")


class ActualLegacyPinRecoveryTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("TRACE_GC_LEGACY_CORE"), "exact pinned upstream source supplied externally")
    def test_external_exact_pin_round_trips_through_archive_and_loader(self):
        from trace_gc.legacy import load_pinned_core
        data = Path(os.environ["TRACE_GC_LEGACY_CORE"]).read_bytes()
        self.assertEqual(recovery.git_blob(data), recovery.PINNED_CORE_BLOB)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive, target = root / "source.zip", root / "core.py"
            with ZipFile(archive, "w") as bundle:
                bundle.writestr("graph_synthesis/core.py", data)
            report = recovery.recover_core(archive, destination=target)
            self.assertEqual(report["core_git_blob"], recovery.PINNED_CORE_BLOB)
            self.assertEqual(target.read_bytes(), data)
            module = load_pinned_core(target)
            self.assertTrue(callable(module.GraphStore))


if __name__ == "__main__":
    unittest.main()
