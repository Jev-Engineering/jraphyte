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

    def test_outcome_emits_only_fixed_allowlisted_codes_never_free_text(self):
        for text in ("private-account internal project", "private account", "project path",
                     "old parent DACL broadened during fence and private-account",
                     "Old parent DACL broadened during fence", "", "x" * 400):
            outcome = diagnostics._outcome(ContractError("PHASE_FENCE", text))
            self.assertEqual(outcome, {"type": "ContractError", "category": "PHASE_FENCE"}, text)
        self.assertEqual(diagnostics._outcome(ContractError("PHASE_FENCE", "old parent DACL broadened during fence")),
                         {"type": "ContractError", "category": "PHASE_FENCE",
                          "detail_code": "PARENT_BROADENED_DURING_FENCE"})
        # A known constant message with any path attached is not trusted either.
        self.assertNotIn("detail_code", diagnostics._outcome(ContractError(
            "PHASE_FENCE", "old parent DACL broadened during fence", path="private-account")))
        for exc in (ValueError("old parent DACL broadened during fence"),
                    ContractError("PHASE_FENCE", SECRET_TEXT, path=SECRET_TEXT)):
            rendered = json.dumps(diagnostics._outcome(exc))
            self.assertNotIn("detail", rendered.replace("detail_code", ""))
            self.assertNotIn("private-account", rendered)

    def test_every_allowlisted_message_is_a_constant_of_the_guard_and_codes_are_fixed_shape(self):
        source = (ROOT / "src" / "paper_pilot_phase_cutover_guarded_v2.py").read_text()
        for message, code in diagnostics._DETAIL_CODES.items():
            self.assertIn('"' + message + '"', source, message)
            self.assertRegex(code, r"[A-Z][A-Z_]{2,40}")
        self.assertEqual(len(set(diagnostics._DETAIL_CODES.values())), len(diagnostics._DETAIL_CODES))


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

    def test_trace_records_sanitized_dacl_observations_whatever_the_fence_outcome(self):
        trace, ok = diagnostics.trace_fence(self.guarded, temp_factory=self.factory)
        # The fence itself may legitimately fail on a host (that is what is being
        # diagnosed); the observation structure and the verified cleanup may not.
        self.assertTrue(ok, trace.get("cleanup"))
        outcome = trace["outcome"]
        self.assertTrue(outcome == {"status": "OLD_PATH_FENCED_NEW_PHASE_ALLOWED"} or "error" in outcome,
                        outcome)
        labels = {"temp_parent", "base", "parent", "state"} | {"file:" + n for n in self.guarded.NAMES}
        for phase in ("setup", "at_end", "after_remove_d"):
            self.assertEqual(set(trace[phase]), labels, phase)
        for label in labels:
            entry = trace["setup"][label]
            self.assertTrue(entry["sddl"].startswith("D:"), label)
            self.assertEqual(set(entry) & {"protected", "auto_inherited", "ace_count"},
                             {"protected", "auto_inherited", "ace_count"}, label)
        self.assertEqual(trace["cleanup"]["denies_remaining"], 0)
        self.assertIs(self.at_exit["tree_denies"], 0)
        rendered = json.dumps(trace)
        self.assertNotIn(tempfile.gettempdir(), rendered)
        self.assertNotIn(os.environ.get("USERNAME", "<no-user>"), rendered)
        self.assertNotIn(self.sid.rsplit("-", 1)[0], rendered)

    def test_trace_failure_after_real_denies_still_cleans_up_without_leaking(self):
        sid = self.sid

        def real_denies_then_fail(**request):
            # Real icacls denies through the tool's recording wrapper, then a failure,
            # independent of whether the production fence would have got this far.
            self.guarded._icacls(request["old_root"] / "controller.lock", "/deny", "*" + sid + ":(WD,AD)")
            self.guarded._icacls(request["old_root"].parent, "/deny", "*" + sid + ":(AD)")
            raise PermissionError(SECRET_TEXT)
        with patch.object(self.guarded, "fence_closed_old_phase_guarded",
                          side_effect=real_denies_then_fail):
            trace, ok = diagnostics.trace_fence(self.guarded, temp_factory=self.factory)
        self.assertEqual(trace["outcome"],
                         {"error": {"type": "PermissionError", "category": "unspecified"}})
        self.assertEqual([(step["target"], step["operation"]) for step in trace["steps"]],
                         [("old:controller.lock", "deny"), ("parent", "deny")])
        # The real denies were in place at the failure, and the tool removed them.
        for step in trace["steps"]:
            self.assertEqual(set(step["before"]), set(step["after"]))
        self.assertEqual(trace["steps"][1]["before"]["file:controller.lock"]["deny"], 1)
        self.assertEqual(trace["steps"][1]["after"]["parent"]["deny"], 1)
        self.assertEqual(trace["at_end"]["parent"]["deny"], 1)
        self.assertEqual(trace["at_end"]["file:controller.lock"]["deny"], 1)
        self.assertEqual(trace["after_remove_d"]["parent"]["deny"], 0)
        self.assertEqual(trace["cleanup"]["denies_remaining"], 0)
        self.assertEqual(trace["cleanup"]["directory_removal"], "ok")
        self.assertTrue(ok)
        self.assertIs(self.at_exit["tree_denies"], 0)
        self.assertNotIn("private-account", json.dumps(trace))

    def test_trace_error_detail_is_only_a_fixed_allowlisted_code(self):
        for error, expected in (
                (ContractError("PHASE_FENCE", "old parent DACL broadened during fence"),
                 {"type": "ContractError", "category": "PHASE_FENCE",
                  "detail_code": "PARENT_BROADENED_DURING_FENCE"}),
                (ContractError("PHASE_FENCE", SECRET_TEXT),
                 {"type": "ContractError", "category": "PHASE_FENCE"}),
                (ContractError("PHASE_FENCE", "private-account internal project"),
                 {"type": "ContractError", "category": "PHASE_FENCE"}),
                (ContractError("PHASE_FENCE", "bad detail", path=SECRET_TEXT),
                 {"type": "ContractError", "category": "PHASE_FENCE"})):
            with patch.object(self.guarded, "fence_closed_old_phase_guarded", side_effect=error):
                trace, ok = diagnostics.trace_fence(self.guarded, temp_factory=self.factory)
            self.assertEqual(trace["outcome"], {"error": expected})
            self.assertTrue(ok)
            self.assertNotIn("private-account", json.dumps(trace))

    def test_trace_cleanup_continues_after_a_first_target_timeout_and_reports_it(self):
        real_run = subprocess.run
        state = {"timed_out": False}

        def first_removal_times_out(args, *a, **k):
            if "/remove:d" in args and not state["timed_out"]:
                state["timed_out"] = True
                raise subprocess.TimeoutExpired(args, 30)
            return real_run(args, *a, **k)
        sid = self.sid

        def real_denies_then_fail(**request):
            self.guarded._icacls(request["old_root"] / "controller.lock", "/deny", "*" + sid + ":(WD,AD)")
            self.guarded._icacls(request["old_root"].parent, "/deny", "*" + sid + ":(AD)")
            raise PermissionError(SECRET_TEXT)
        with patch.object(self.guarded, "fence_closed_old_phase_guarded", side_effect=real_denies_then_fail), \
                patch.object(diagnostics.subprocess, "run", side_effect=first_removal_times_out):
            trace, ok = diagnostics.trace_fence(self.guarded, temp_factory=self.factory)
        cleanup = trace["cleanup"]
        self.assertFalse(ok)
        self.assertEqual(cleanup["removal_failures"],
                         [{"target": "parent", "error": {"type": "TimeoutExpired", "category": "unspecified"}}])
        self.assertEqual(cleanup["denies_remaining"], 1)
        self.assertEqual(trace["after_remove_d"]["file:controller.lock"]["deny"], 0)
        self.assertEqual(len(cleanup["steps"]), 6)
        # The harness, not the tool, removes the one deny the injected timeout left behind.
        self.assertEqual(self.at_exit["tree_denies"], 1)
        self.assertNotIn("private-account", json.dumps(trace))

    def test_trace_directory_removal_failure_is_not_clean(self):
        outer = self.factory

        class FailsOnRemoval(outer):
            def __exit__(self, *exc):
                super().__exit__(*exc)
                raise OSError(SECRET_TEXT)
        trace, ok = diagnostics.trace_fence(self.guarded, temp_factory=FailsOnRemoval)
        self.assertFalse(ok)
        self.assertEqual(trace["cleanup"]["denies_remaining"], 0)
        self.assertEqual(trace["cleanup"]["directory_removal"], "failed")
        self.assertEqual(trace["cleanup"]["directory_removal_error"],
                         {"type": "OSError", "category": "unspecified"})
        self.assertNotIn("private-account", json.dumps(trace))

    def test_collect_includes_the_trace_and_its_cleanup_status(self):
        report, cleanup_ok = self._collect()
        self.assertIn("outcome", report["fence_trace"])
        self.assertIn("probe_dacl_before_runner_deny", report)
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
