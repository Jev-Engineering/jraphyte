"""A partially recovered source tree is not a full release test suite."""
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from release_suite import RELEASE_TEST_FILES, check_suite_inventory, main, test_origin_counts


class ReleaseSuiteInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "tests").mkdir()

    def make(self, name):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("raise AssertionError('inventory must not execute test modules')\n")

    def symlink_or_skip(self, link, target, *, directory=False):
        try:
            link.symlink_to(target, target_is_directory=directory)
        except OSError as exc:
            if os.name == "nt" and getattr(exc, "winerror", None) == 1314:
                self.skipTest("Windows symlink creation privilege unavailable")
            raise

    def test_complete_inventory_passes_without_executing_any_module(self):
        expected = ("tests/test_a.py", "tests/test_b.py")
        for name in expected:
            self.make(name)
        report = check_suite_inventory(self.root, expected=expected)
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["required_modules"], 2)
        self.assertIn("does not prove current-main provenance", report["scope"])

    def test_missing_module_fails_even_when_present_tests_could_pass(self):
        self.make("tests/test_a.py")
        report = check_suite_inventory(self.root, expected=("tests/test_a.py", "tests/test_b.py"))
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["missing"], ["tests/test_b.py"])

    def test_unreviewed_extra_test_module_is_reported(self):
        self.make("tests/test_a.py")
        self.make("tests/test_extra.py")
        report = check_suite_inventory(self.root, expected=("tests/test_a.py",))
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["unexpected"], ["tests/test_extra.py"])

    def test_symlink_cannot_satisfy_required_source_module(self):
        target = self.root / "external.py"
        target.write_text("pass\n")
        self.symlink_or_skip(self.root / "tests/test_a.py", target)
        report = check_suite_inventory(self.root, expected=("tests/test_a.py",))
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["nonregular_or_symlinked"], ["tests/test_a.py"])

    def test_dangling_symlink_cannot_satisfy_required_source_module(self):
        self.symlink_or_skip(self.root / "tests/test_a.py", self.root / "absent.py")
        report = check_suite_inventory(self.root, expected=("tests/test_a.py",))
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["nonregular_or_symlinked"], ["tests/test_a.py"])

    def test_missing_tests_directory_does_not_become_an_empty_success(self):
        (self.root / "tests").rmdir()
        report = check_suite_inventory(self.root, expected=("tests/test_a.py",))
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["missing"], ["tests/test_a.py"])

    def test_inventory_rejects_parent_escape(self):
        with self.assertRaises(ValueError):
            check_suite_inventory(self.root, expected=("tests/../elsewhere.py",))

    def test_cli_uses_reviewed_inventory_not_whatever_is_present(self):
        output = io.StringIO()
        with redirect_stdout(output):
            status = main(["--root", str(self.root)])
        report = json.loads(output.getvalue())
        self.assertEqual(status, 1)
        self.assertEqual(report["required_modules"], len(RELEASE_TEST_FILES))
        self.assertEqual(report["discovered_modules"], 0)

    def test_release_runner_stops_before_discovery_on_partial_source(self):
        from unittest.mock import patch
        import run_validation
        self.make("tests/test_a.py")
        with patch.object(run_validation, "ROOT", self.root), patch.object(
                unittest.defaultTestLoader, "discover", side_effect=AssertionError("must not discover")) as discover:
            with redirect_stdout(io.StringIO()):
                self.assertEqual(run_validation.main(), 1)
            discover.assert_not_called()
        report = json.loads((self.root / "VALIDATION_REPORT.json").read_text())
        self.assertEqual(report["test_execution"], "NOT_RUN")
        self.assertEqual(report["tests_run"], 0)
        self.assertEqual(report["status"], "FAIL")
        self.assertNotIn("PASS", report["external_gates"])

    def test_symlinked_tests_directory_cannot_satisfy_inventory(self):
        (self.root / "tests").rmdir()
        target = self.root / "external"
        target.mkdir()
        (target / "test_a.py").write_text("raise AssertionError('never import')\n")
        self.symlink_or_skip(self.root / "tests", target, directory=True)
        report = check_suite_inventory(self.root, expected=("tests/test_a.py",))
        self.assertEqual(report["status"], "FAIL")

    def test_origin_counts_do_not_inflate_baseline_with_initiative_tests(self):
        rows = [{"test": name, "status": "PASS"} for name in (
            "test_runtime_workflows.C.test_one", "test_graphrag_retrieval.C.test_two",
            "test_research_domain_transactions.C.test_three", "test_release_suite.C.test_four")]
        counts = test_origin_counts(rows)
        self.assertEqual(counts, {"current_main_baseline": 2, "initiative": 2,
                                 "other": 0, "graphrag_subset_of_baseline": 1})

    def test_failed_import_or_unknown_module_is_not_claimed_as_baseline(self):
        counts = test_origin_counts([
            {"test": "unittest.loader._FailedTest.test_unknown", "status": "ERROR"},
            {"test": "test_extra.C.test_new", "status": "PASS"}])
        self.assertEqual(counts["other"], 2)
        self.assertEqual(counts["current_main_baseline"], 0)
        self.assertEqual(counts["initiative"], 0)

    def test_manifest_includes_all_existing_baseline_and_new_domain_modules(self):
        self.assertEqual(len(RELEASE_TEST_FILES), len(set(RELEASE_TEST_FILES)))
        self.assertIn("tests/test_parallel_source_v4.py", RELEASE_TEST_FILES)
        self.assertIn("tests/test_runtime_transactions.py", RELEASE_TEST_FILES)
        self.assertIn("tests/test_research_domain_identity_conflicts.py", RELEASE_TEST_FILES)
        self.assertIn("tests/test_research_domain_authority_boundary.py", RELEASE_TEST_FILES)
        self.assertIn("tests/test_legacy_source_recovery.py", RELEASE_TEST_FILES)


if __name__ == "__main__":
    unittest.main()
