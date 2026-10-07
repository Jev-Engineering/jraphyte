"""Windows-only owned disposable tests for the historical admission barrier.

Every case builds its own fixture inside a unique temporary directory created
by this test, so it never depends on (or creates) any historical task state.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from src import paper_pilot_phase_cutover_guarded_v2 as guarded
from src.paper_pilot_phase_cutover import _current_sid
from trace_gc.budget import RunBudget


TEMP_PREFIX = "jraphyte-fence-"
LIMITS = {"retrieval_requests": 1, "model_calls": 1, "retries": 0,
          "solver_expansions": 1, "review_actions": 1, "request_bytes": 1000}


def _call(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(list(args), capture_output=True, text=True, timeout=30)


class GuardedFenceTests(unittest.TestCase):
    def test_module_load_does_not_require_msvcrt(self):
        path = Path(guarded.__file__)
        spec = importlib.util.spec_from_file_location("guarded_without_msvcrt", path)
        module = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {"msvcrt": None}):
            spec.loader.exec_module(module)
        self.assertTrue(callable(module.fence_closed_old_phase_guarded))

    def setUp(self):
        if os.name != "nt":
            self.skipTest("Windows ACL contract")
        self.sid = _current_sid()
        self.temp = tempfile.TemporaryDirectory(prefix=TEMP_PREFIX)
        self.addCleanup(self._cleanup)
        self.base = Path(self.temp.name)
        # The fixture owns this fresh directory; only paths beneath it are ever
        # given a barrier ACL or have one removed again.
        self.assertTrue(self.base.is_dir())
        self.assertTrue(self.base.name.startswith(TEMP_PREFIX))
        self.root = self.base / "old-app"
        self.root.mkdir()
        self.old = self.root / "state"
        self.old.mkdir()
        self.archive = self.base / "archive" / "state"
        self.archive.parent.mkdir()
        self.receipts = self.base / "receipts"
        self.receipts.mkdir()
        self.sid = _current_sid()
        self.content = {}
        for name in guarded.NAMES:
            if name == "budget.sqlite3":
                continue
            body = b"0" if name == "controller.lock" else ("owned:" + name).encode()
            (self.old / name).write_bytes(body)
            self.content[name] = hashlib.sha256(body).hexdigest()
        # A genuine budget DB makes the contender check causal, not a failure
        # caused by feeding malformed SQLite bytes to the constructor.
        budget = RunBudget(self.old / "budget.sqlite3", "authored", LIMITS)
        budget.close()
        self.content["budget.sqlite3"] = hashlib.sha256(
            (self.old / "budget.sqlite3").read_bytes()).hexdigest()
        for name in ("source-stage.lock", "phase-stage.lock"):
            (self.root / name).write_bytes(b"0")
        self.parent_acl_sha = hashlib.sha256(
            guarded.directory_dacl_sddl(self.root).encode()).hexdigest()
        self.file_acl_sha = {name: hashlib.sha256(
            guarded.directory_dacl_sddl(self.old / name).encode()).hexdigest()
            for name in guarded.NAMES}

    def _owned(self, path: Path) -> Path:
        resolved = Path(path).resolve()
        if not resolved.is_relative_to(self.base.resolve()):
            raise AssertionError(f"refusing ACL change outside fixture: {path}")
        return resolved

    def _cleanup(self):
        # Lift only this test's own deny ACEs so the owned tree can be removed;
        # no ancestor of the temporary directory has its ACL touched.
        if hasattr(self, "root") and self.root.exists():
            _call("icacls.exe", str(self._owned(self.root)), "/remove:d", "*" + self.sid)
        for root in (getattr(self, "old", None), getattr(self, "archive", None)):
            if root is not None and root.exists():
                for name in guarded.NAMES:
                    if (root / name).exists():
                        _call("icacls.exe", str(self._owned(root / name)),
                              "/remove:d", "*" + self.sid)
        self.temp.cleanup()
        self.assertFalse(self.base.exists())

    def invoke(self):
        return guarded.fence_closed_old_phase_guarded(
            old_root=self.old, archived_root=self.archive,
            expected_file_sha256=self.content,
            source_stage_lock=self.root / "source-stage.lock",
            phase_stage_lock=self.root / "phase-stage.lock", deny_sid=self.sid,
            expected_parent_dacl_sha256=self.parent_acl_sha,
            expected_file_dacl_sha256=self.file_acl_sha,
            barrier_receipt_path=self.receipts / "barrier.json",
            fence_receipt_path=self.receipts / "fence.json")

    def test_contender_denied_during_close_to_rename_and_replay(self):
        actual_rename = guarded.os.rename
        seen = {}
        def observe_then_rename(source, destination):
            for name in guarded.NAMES:
                attempt = _call(sys.executable, "-c",
                    "from pathlib import Path; import sys; Path(sys.argv[1]).open('a+b').close()",
                    str(self.old / name))
                seen[name] = attempt.returncode != 0
            read = _call(sys.executable, "-c",
                "from pathlib import Path; import sys; Path(sys.argv[1]).read_bytes()",
                str(self.old / "checkpoint.sqlite3"))
            seen["read_allowed_during_barrier"] = read.returncode == 0
            budget = _call(sys.executable, "-c",
                "from trace_gc.budget import RunBudget; import sys; "
                "RunBudget(sys.argv[1], 'authored', " + repr(LIMITS) + ")",
                str(self.old / "budget.sqlite3"))
            seen["actual_budget_constructor_denied"] = budget.returncode != 0
            for name in ("source-stage.lock", "phase-stage.lock"):
                lock = _call(sys.executable, "-c",
                    "import msvcrt,sys; f=open(sys.argv[1],'r+b'); f.seek(0); "
                    "msvcrt.locking(f.fileno(),msvcrt.LK_NBLCK,1)",
                    str(self.root / name))
                seen[name + "_contender_denied"] = lock.returncode != 0
            return actual_rename(source, destination)
        with patch.object(guarded.os, "rename", side_effect=observe_then_rename):
            result = self.invoke()
        self.assertTrue(all(seen.values()), seen)
        self.assertTrue(result["old_path_absent"])
        self.assertEqual(result, self.invoke())
        self.assertEqual({name: hashlib.sha256((self.archive / name).read_bytes()).hexdigest()
                          for name in guarded.NAMES}, self.content)
        self.assertIn(guarded.DENY_PARENT_ACE.format(sid=self.sid),
                      guarded.directory_dacl_sddl(self.root))
        self.assertFalse(self.old.exists())

    def test_failed_rename_retains_denial_then_same_request_recovers(self):
        with patch.object(guarded.os, "rename", side_effect=PermissionError("injected rename failure")):
            with self.assertRaises(PermissionError):
                self.invoke()
        self.assertTrue(self.old.exists())
        self.assertFalse(self.archive.exists())
        self.assertTrue((self.receipts / "barrier.json").is_file())
        for name in guarded.NAMES:
            self.assertTrue(guarded._file_deny(self.old / name, self.sid))
        self.assertEqual(self.invoke()["status"], "OLD_PATH_FENCED_NEW_PHASE_ALLOWED")

    def test_crash_after_first_deny_replays_with_fixed_path_closed(self):
        actual = guarded._icacls
        calls = {"count": 0}
        def first_deny_then_crash(path, *args):
            actual(path, *args)
            calls["count"] += 1
            if calls["count"] == 1:
                raise RuntimeError("injected post-controller-deny crash")
        with patch.object(guarded, "_icacls", side_effect=first_deny_then_crash):
            with self.assertRaisesRegex(RuntimeError, "injected"):
                self.invoke()
        self.assertTrue(guarded._file_deny(self.old / "controller.lock", self.sid))
        contender = _call(sys.executable, "-c",
            "from pathlib import Path; import sys; Path(sys.argv[1]).open('a+b').close()",
            str(self.old / "controller.lock"))
        self.assertNotEqual(contender.returncode, 0)
        self.assertEqual(self.invoke()["status"], "OLD_PATH_FENCED_NEW_PHASE_ALLOWED")

    def test_crash_after_rename_replays_archive_acl_and_hashes(self):
        actual = guarded._icacls
        def fail_first_archive_restore(path, *args):
            if "/remove:d" in args:
                raise RuntimeError("injected archive restore crash")
            return actual(path, *args)
        with patch.object(guarded, "_icacls", side_effect=fail_first_archive_restore):
            with self.assertRaisesRegex(RuntimeError, "injected"):
                self.invoke()
        self.assertFalse(self.old.exists())
        self.assertTrue(self.archive.exists())
        self.assertEqual(self.invoke()["status"], "OLD_PATH_FENCED_NEW_PHASE_ALLOWED")
        self.assertEqual({name: hashlib.sha256((self.archive / name).read_bytes()).hexdigest()
                          for name in guarded.NAMES}, self.content)

    def test_changed_bytes_and_existing_archive_hold(self):
        (self.old / "budget.sqlite3").write_bytes(b"altered")
        with self.assertRaises(Exception):
            self.invoke()
        self.assertFalse((self.receipts / "barrier.json").exists())
        self.assertTrue(self.old.exists())

    def test_preexisting_other_owner_deny_is_preserved_and_rejected(self):
        path = self.old / "checkpoint.sqlite3"
        self.assertEqual(_call("icacls.exe", str(path), "/deny",
                               "*" + self.sid + ":(X)").returncode, 0)
        prior = guarded.directory_dacl_sddl(path)
        self.file_acl_sha[path.name] = hashlib.sha256(prior.encode()).hexdigest()
        with self.assertRaisesRegex(Exception, "existing owner deny"):
            self.invoke()
        self.assertEqual(guarded.directory_dacl_sddl(path), prior)
        self.assertFalse((self.receipts / "barrier.json").exists())
        self.assertTrue(self.old.exists())

    def test_preexisting_parent_owner_deny_is_preserved_and_rejected(self):
        self.assertEqual(_call("icacls.exe", str(self.root), "/deny",
                               "*" + self.sid + ":(X)").returncode, 0)
        prior = guarded.directory_dacl_sddl(self.root)
        self.parent_acl_sha = hashlib.sha256(prior.encode()).hexdigest()
        # Changing the parent ACL makes Windows re-propagate inheritance to the
        # children (adding AI). Re-pin them so only the owner deny can reject.
        self.file_acl_sha = {name: hashlib.sha256(
            guarded.directory_dacl_sddl(self.old / name).encode()).hexdigest()
            for name in guarded.NAMES}
        with self.assertRaisesRegex(Exception, "existing owner deny"):
            self.invoke()
        self.assertEqual(guarded.directory_dacl_sddl(self.root), prior)
        self.assertFalse((self.receipts / "barrier.json").exists())

    def test_parent_acl_drift_during_replay_holds_before_archive(self):
        with patch.object(guarded.os, "rename", side_effect=PermissionError("injected")):
            with self.assertRaises(PermissionError):
                self.invoke()
        original_rename = guarded.os.rename
        actual_dacl = guarded.directory_dacl_sddl
        def changed_parent(path):
            value = actual_dacl(path)
            if Path(path) == self.root:
                return value + "(A;;FR;;;S-1-1-0)"
            return value
        with patch.object(guarded, "directory_dacl_sddl", side_effect=changed_parent), \
                patch.object(guarded.os, "rename", wraps=original_rename) as rename:
            with self.assertRaisesRegex(Exception, "old parent DACL changed"):
                self.invoke()
            rename.assert_not_called()
        self.assertTrue(self.old.exists())
        self.assertEqual(self.invoke()["status"], "OLD_PATH_FENCED_NEW_PHASE_ALLOWED")


if __name__ == "__main__":
    unittest.main()
