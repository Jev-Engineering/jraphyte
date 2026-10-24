"""Failure-path coverage for the sanitized hosted-CI diagnostics tool."""
from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from trace_gc.errors import ContractError

ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "windows_fence_diagnostics_under_test", ROOT / "tools" / "windows_fence_diagnostics.py")
diagnostics = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(diagnostics)

SECRET_TEXT = r"C:\Users\private-account\secret-dir\file.bin S-1-5-21-111-222-333-1001"


class SanitizationTests(unittest.TestCase):
    def test_redact_masks_machine_sub_authorities_only(self):
        self.assertEqual(diagnostics.redact("D:(D;;DCLC;;;S-1-5-21-1-2-3-500)(A;;FA;;;SY)"),
                         "D:(D;;DCLC;;;S-1-5-21-<machine>-500)(A;;FA;;;SY)")

    def test_error_description_never_carries_message_text(self):
        for exc in (ValueError(SECRET_TEXT), OSError(2, SECRET_TEXT, SECRET_TEXT),
                    ContractError("PHASE_FENCE", SECRET_TEXT, path=SECRET_TEXT),
                    subprocess.CalledProcessError(5, ["icacls.exe", SECRET_TEXT])):
            text = json.dumps(diagnostics.describe_error(exc))
            self.assertNotIn("private-account", text)
            self.assertNotIn("secret-dir", text)
            self.assertNotIn("S-1-5-21", text)
        self.assertEqual(diagnostics.describe_error(ContractError("PHASE_FENCE", SECRET_TEXT)),
                         {"type": "ContractError", "category": "PHASE_FENCE"})
        self.assertEqual(diagnostics.describe_error(
            subprocess.CalledProcessError(5, ["icacls.exe"])),
            {"type": "CalledProcessError", "category": "unspecified", "exit_code": 5})

    def test_error_category_is_bounded_to_a_code_shaped_string(self):
        class Odd(Exception):
            code = SECRET_TEXT
        self.assertEqual(diagnostics.describe_error(Odd()),
                         {"type": "Odd", "category": "unspecified"})


@unittest.skipUnless(os.name == "nt", "Windows ACL diagnostics")
class ProbeCleanupTests(unittest.TestCase):
    def setUp(self):
        from src import paper_pilot_phase_cutover_guarded_v2 as guarded
        self.guarded = guarded
        self.real_dacl = guarded.directory_dacl_sddl
        self.sid = guarded._current_sid()
        self.at_exit = {}
        test = self

        class Recording(tempfile.TemporaryDirectory):
            def __exit__(self, *exc):
                # Independent check, before the directory is removed: no owner
                # deny may remain on the probe once the tool's own cleanup ran.
                tree = Path(self.name)
                if (tree / "old-app").exists():
                    guarded = test.guarded
                    leftover = 0
                    for target in [tree / "old-app"] + [tree / folder / name
                                                         for folder in ("old-app/state", "archive/state")
                                                         for name in guarded.NAMES]:
                        if target.exists():
                            if guarded._owner_deny_present(test.real_dacl(target), test.sid):
                                leftover += 1
                                subprocess.run(["icacls.exe", str(target), "/remove:d", "*" + test.sid],
                                               capture_output=True, text=True, timeout=30)
                    test.at_exit["tree_denies"] = leftover
                probe = Path(self.name) / "probe.bin"
                if probe.exists():
                    test.at_exit["deny_present"] = test.guarded._owner_deny_present(
                        test.real_dacl(probe), test.sid)
                    subprocess.run(["icacls.exe", str(probe), "/remove:d", "*" + test.sid],
                                   capture_output=True, text=True, timeout=30)
                return super().__exit__(*exc)
        self.factory = Recording

    def _collect(self):
        return diagnostics.collect(self.guarded, temp_factory=self.factory)

    def test_success_path_reports_and_verifies_cleanup(self):
        report, cleanup_ok = self._collect()
        self.assertNotIn("diagnostic_error", report, report)
        self.assertTrue(report["barrier_recognizes_deny"])
        self.assertTrue(report["owner_deny_detected"])
        self.assertEqual(report["probe_cleanup"],
                         {"icacls_remove_exit": 0, "deny_absent_verified": True})
        self.assertTrue(cleanup_ok)
        self.assertIs(self.at_exit["deny_present"], False)
        rendered = json.dumps(report)
        self.assertNotIn(tempfile.gettempdir(), rendered)
        self.assertNotIn(os.environ.get("USERNAME", "\0"), rendered)
        self.assertNotIn(self.sid.rsplit("-", 1)[0], rendered)   # machine sub-authorities redacted

    def test_dacl_query_failure_still_removes_probe_deny_without_leaking(self):
        calls = {"count": 0}

        def fail_first_read(path):
            calls["count"] += 1
            if calls["count"] == 1:
                raise RuntimeError(SECRET_TEXT)
            return self.real_dacl(path)
        with patch.object(self.guarded, "directory_dacl_sddl", side_effect=fail_first_read):
            report, cleanup_ok = self._collect()
        self.assertEqual(report["diagnostic_error"],
                         {"type": "RuntimeError", "category": "unspecified"})
        self.assertEqual(report["probe_cleanup"],
                         {"icacls_remove_exit": 0, "deny_absent_verified": True})
        self.assertTrue(cleanup_ok)
        self.assertIs(self.at_exit["deny_present"], False)
        self.assertNotIn("private-account", json.dumps(report))

    def test_recognition_failure_still_removes_probe_deny_without_leaking(self):
        with patch.object(self.guarded, "_file_deny",
                          side_effect=ContractError("PHASE_FENCE", SECRET_TEXT, path=SECRET_TEXT)):
            report, cleanup_ok = self._collect()
        self.assertEqual(report["diagnostic_error"],
                         {"type": "ContractError", "category": "PHASE_FENCE"})
        self.assertTrue(cleanup_ok)
        self.assertIs(self.at_exit["deny_present"], False)
        self.assertNotIn("secret-dir", json.dumps(report))

    def test_failed_probe_cleanup_is_reported_and_nonzero(self):
        real_run = subprocess.run
        state = {"faked": False}

        def fake_remove_once(args, *a, **k):
            if "/remove:d" in args and not state["faked"]:
                state["faked"] = True
                return subprocess.CompletedProcess(args, 5, "", "")
            return real_run(args, *a, **k)
        with patch.object(diagnostics.subprocess, "run", side_effect=fake_remove_once):
            report, cleanup_ok = self._collect()
        self.assertEqual(report["probe_cleanup"],
                         {"icacls_remove_exit": 5, "deny_absent_verified": False})
        self.assertFalse(cleanup_ok)
        # The probe deny really was left for this case, and the harness removed it.
        self.assertIs(self.at_exit["deny_present"], True)

    def test_trace_records_sanitized_parent_and_state_file_dacls(self):
        trace, ok = diagnostics.trace_fence(self.guarded, temp_factory=self.factory)
        self.assertTrue(ok, trace)
        self.assertEqual(trace["outcome"], {"status": "OLD_PATH_FENCED_NEW_PHASE_ALLOWED"})
        self.assertEqual(trace["cleanup"], {"paths_checked": 6, "denies_remaining": 0})
        self.assertIs(self.at_exit["tree_denies"], 0)
        targets = [(step["target"], step["operation"]) for step in trace["steps"]]
        self.assertIn(("parent", "deny"), targets)
        self.assertIn(("old:controller.lock", "deny"), targets)
        self.assertIn(("archived:controller.lock", "remove_deny"), targets)
        self.assertTrue(trace["parent_before"].startswith("D:"))
        rendered = json.dumps(trace)
        self.assertNotIn(tempfile.gettempdir(), rendered)
        self.assertNotIn(os.environ.get("USERNAME", "<no-user>"), rendered)
        self.assertNotIn(self.sid.rsplit("-", 1)[0], rendered)

    def test_trace_failure_after_real_denies_still_cleans_up_without_leaking(self):
        with patch.object(self.guarded.os, "rename", side_effect=PermissionError(SECRET_TEXT)):
            trace, ok = diagnostics.trace_fence(self.guarded, temp_factory=self.factory)
        self.assertEqual(trace["outcome"],
                         {"error": {"type": "PermissionError", "category": "unspecified"}})
        # The real denies were in place at the failure, and the tool removed them.
        self.assertTrue(any(step["operation"] == "deny" for step in trace["steps"]))
        self.assertEqual(trace["cleanup"]["denies_remaining"], 0)
        self.assertTrue(ok)
        self.assertIs(self.at_exit["tree_denies"], 0)
        self.assertNotIn("private-account", json.dumps(trace))

    def test_trace_error_detail_is_only_a_constant_safe_string(self):
        for error, expected in (
                (ContractError("PHASE_FENCE", "old parent DACL broadened during fence"),
                 {"type": "ContractError", "category": "PHASE_FENCE",
                  "detail": "old parent DACL broadened during fence"}),
                (ContractError("PHASE_FENCE", SECRET_TEXT),
                 {"type": "ContractError", "category": "PHASE_FENCE"}),
                (ContractError("PHASE_FENCE", "bad detail", path=SECRET_TEXT),
                 {"type": "ContractError", "category": "PHASE_FENCE"})):
            with patch.object(self.guarded, "fence_closed_old_phase_guarded", side_effect=error):
                trace, ok = diagnostics.trace_fence(self.guarded, temp_factory=self.factory)
            self.assertEqual(trace["outcome"], {"error": expected})
            self.assertTrue(ok)

    def test_collect_includes_the_trace_and_its_cleanup_status(self):
        report, cleanup_ok = self._collect()
        self.assertEqual(report["fence_trace"]["outcome"],
                         {"status": "OLD_PATH_FENCED_NEW_PHASE_ALLOWED"})
        self.assertTrue(cleanup_ok)
        with patch.object(diagnostics, "trace_fence",
                          return_value=({"cleanup": {"denies_remaining": 2}}, False)):
            report, cleanup_ok = self._collect()
        self.assertFalse(cleanup_ok)
        self.assertEqual(report["fence_trace"], {"cleanup": {"denies_remaining": 2}})

    def test_main_prints_one_json_object_and_exit_status_follows_cleanup(self):
        for ok, expected in ((True, 0), (False, 1)):
            buffer = io.StringIO()
            with patch.object(diagnostics, "collect", return_value=({"python": "x"}, ok)), \
                    redirect_stdout(buffer):
                self.assertEqual(diagnostics.main(), expected)
            self.assertEqual(json.loads(buffer.getvalue()), {"python": "x"})


if __name__ == "__main__":
    unittest.main()
