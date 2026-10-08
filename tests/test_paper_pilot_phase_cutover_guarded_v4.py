"""Owned Windows fixture for one held quiescence-to-fence transaction."""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from src import paper_pilot_phase_cutover_guarded_v4 as guarded
from src.paper_pilot_phase_cutover import _current_sid
from tools import windows_fixture_acl
from trace_gc.budget import RunBudget
from trace_gc.canonical import bytes_digest, dumps
from trace_gc.trust import IssuerPolicy, Signer, TrustStore


LIMITS = {"retrieval_requests": 1, "model_calls": 1, "retries": 0,
          "solver_expansions": 1, "review_actions": 1, "request_bytes": 1000}


def invoke(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(list(args), capture_output=True, text=True, timeout=30)


@contextmanager
def _noop_lease():
    yield


class ContinuousFenceTests(unittest.TestCase):
    def setUp(self):
        if os.name != "nt":
            self.skipTest("Windows DACL contract")
        self.temp = tempfile.TemporaryDirectory(prefix="paper-pilot-held-fence-")
        self.addCleanup(self._cleanup)
        self.base = Path(self.temp.name)
        self.parent = self.base / "old-app"
        self.parent.mkdir()
        self.old = self.parent / "state"
        self.old.mkdir()
        self.archive = self.base / "archive" / "state"
        self.archive.parent.mkdir()
        self.out = self.base / "receipts"
        self.out.mkdir()
        self.sid = _current_sid()
        for name in guarded.NAMES - {"budget.sqlite3"}:
            (self.old / name).write_bytes(b"0" if name == "controller.lock" else name.encode())
        budget = RunBudget(self.old / "budget.sqlite3", "authored", LIMITS)
        budget.close()
        for name in ("source-stage.lock", "phase-stage.lock"):
            (self.parent / name).write_bytes(b"0")
        self.files = {name: bytes_digest((self.old / name).read_bytes())
                      for name in guarded.NAMES}
        # Explicit, protected and verified before the first pin (see tools/windows_fixture_acl.py).
        windows_fixture_acl.stabilize_owned_fixture(
            self.base, [("parent", self.parent), ("state", self.old)]
            + [("file:" + name, self.old / name) for name in sorted(guarded.NAMES)],
            read=guarded.directory_dacl_sddl)
        self.parent_acl = bytes_digest(guarded.directory_dacl_sddl(self.parent).encode())
        self.file_acl = {name: bytes_digest(
            guarded.directory_dacl_sddl(self.old / name).encode())
            for name in guarded.NAMES}
        self.signer = Signer.ephemeral("authored-phase-reviewer")
        self.trust = TrustStore()
        self.trust.enroll(self.signer.issuer, IssuerPolicy(
            self.signer.public_key(), "authored-phase-reviewer",
            frozenset({"AUTHORIZATION"}), frozenset({"PHASE_IMPORT"}),
            frozenset({"isolated-test"}), frozenset({"LIVE"}), can_review=True))
        self.auth = {}
        for stage in ("quiescence", "fence"):
            receipt = self.signer.issue("AUTHORIZATION", {
                "kind": "HISTORICAL_PHASE_STAGE", "stage": stage,
                "run_id": "authored-only", "capsule_sha256": "a" * 64,
                "release_fingerprint": ("b" if stage == "quiescence" else "c") * 64})
            self.trust.verify(receipt, "AUTHORIZATION")
            raw = (json.dumps(receipt, sort_keys=True, indent=2) + "\n").encode()
            self.auth[stage] = hashlib.sha256(raw).hexdigest()
        self.quiescence_body = guarded.held_quiescence_receipt_body(
            old_root=self.old, archived_root=self.archive,
            expected_file_sha256=self.files,
            source_stage_lock=self.parent / "source-stage.lock",
            phase_stage_lock=self.parent / "phase-stage.lock",
            deny_sid=self.sid, expected_parent_dacl_sha256=self.parent_acl,
            expected_file_dacl_sha256=self.file_acl,
            quiescence_authorization_sha256=self.auth["quiescence"])
        self.quiescence_sha = bytes_digest((dumps(self.quiescence_body) + "\n").encode())

    def _cleanup(self):
        if hasattr(self, "parent") and self.parent.exists():
            invoke("icacls.exe", str(self.parent), "/remove:d", "*" + self.sid)
        for root in (getattr(self, "old", None), getattr(self, "archive", None)):
            if root is not None and root.exists():
                for name in guarded.NAMES:
                    invoke("icacls.exe", str(root / name), "/remove:d", "*" + self.sid)
        self.temp.cleanup()

    def call(self, observer=None):
        return guarded.quiescence_then_fence_guarded(
            old_root=self.old, archived_root=self.archive,
            expected_file_sha256=self.files,
            source_stage_lock=self.parent / "source-stage.lock",
            phase_stage_lock=self.parent / "phase-stage.lock",
            deny_sid=self.sid,
            expected_parent_dacl_sha256=self.parent_acl,
            expected_file_dacl_sha256=self.file_acl,
            quiescence_authorization_sha256=self.auth["quiescence"],
            fence_authorization_sha256=self.auth["fence"],
            quiescence_receipt_path=self.out / "quiescence.json",
            expected_quiescence_receipt_sha256=self.quiescence_sha,
            barrier_receipt_path=self.out / "barrier.json",
            fence_receipt_path=self.out / "fence.json",
            observer=observer)

    def test_observer_lease_stays_until_five_denies_then_closes_before_rename(self):
        state = {"observed": False, "entered": False, "closed": False,
                 "file_denies": 0, "parent_deny": False}
        @contextmanager
        def lease():
            state["entered"] = True
            try:
                yield
            finally:
                state["closed"] = True
        def observe(*, old_root, archived_root, source_handle,
                    phase_handle, controller_handle, writable_database_names):
            self.assertEqual(old_root, self.old)
            self.assertEqual(archived_root, self.archive)
            self.assertEqual(set(writable_database_names), guarded.NAMES - {"controller.lock"})
            for path in (self.parent / "source-stage.lock",
                         self.parent / "phase-stage.lock", self.old / "controller.lock"):
                probe = invoke(sys.executable, "-c",
                    "import msvcrt,sys;f=open(sys.argv[1],'r+b');f.seek(0);"
                    "msvcrt.locking(f.fileno(),msvcrt.LK_NBLCK,1)", str(path))
                self.assertNotEqual(probe.returncode, 0)
            self.assertFalse((self.out / "quiescence.json").exists())
            state["observed"] = True
            return lease()
        original_acl = guarded._icacls
        original_rename = guarded.os.rename
        def acl(path, *args):
            if args[:1] == ("/deny",):
                self.assertTrue(state["entered"] and not state["closed"])
                if Path(path).parent == self.old:
                    state["file_denies"] += 1
                if Path(path) == self.parent:
                    state["parent_deny"] = True
            return original_acl(path, *args)
        def rename(src, dst):
            self.assertTrue(state["closed"])
            self.assertEqual(state["file_denies"], 5)
            self.assertTrue(state["parent_deny"])
            self.assertEqual(src, self.old)
            self.assertEqual(dst, self.archive)
            return original_rename(src, dst)
        with patch.object(guarded, "_icacls", side_effect=acl), \
             patch.object(guarded.os, "rename", side_effect=rename):
            result = self.call(observer=observe)
        self.assertTrue(state["observed"] and state["closed"])
        self.assertEqual(result["status"], "OLD_PATH_FENCED_NEW_PHASE_ALLOWED")

    def test_observer_rejection_precedes_any_receipt_or_acl_effect(self):
        def reject(**kwargs):
            raise RuntimeError("owner observation rejected")
        with self.assertRaisesRegex(RuntimeError, "owner observation rejected"):
            self.call(observer=reject)
        self.assertFalse(any(self.out.iterdir()))
        self.assertTrue(self.old.is_dir())
        self.assertFalse(self.archive.exists())
        self.assertEqual(bytes_digest(guarded.directory_dacl_sddl(self.parent).encode()),
                         self.parent_acl)
        self.assertEqual({name: bytes_digest(
            guarded.directory_dacl_sddl(self.old / name).encode())
            for name in guarded.NAMES}, self.file_acl)

    def test_barrier_before_first_deny_requires_new_observer_lease(self):
        original = guarded._icacls
        def crash_before_first_deny(path, *args):
            if args[:1] == ("/deny",):
                raise RuntimeError("injected barrier-only loss")
            return original(path, *args)
        with patch.object(guarded, "_icacls", side_effect=crash_before_first_deny):
            with self.assertRaisesRegex(RuntimeError, "barrier-only loss"):
                self.call(observer=lambda **kwargs: _noop_lease())
        self.assertTrue((self.out / "barrier.json").exists())
        self.assertTrue(self.old.is_dir())
        with self.assertRaisesRegex(Exception, "renewed owner observation"):
            self.call()
        observed = []
        def replay_observer(**kwargs):
            observed.append(kwargs['controller_handle'] is not None)
            self.assertEqual(set(kwargs['writable_database_names']),
                             guarded.NAMES - {"controller.lock"})
            return _noop_lease()
        self.assertTrue(self.call(observer=replay_observer)['reconciled'])
        self.assertEqual(observed, [True])

    def test_partial_controller_deny_replay_passes_none_handle_to_observer(self):
        original = guarded._icacls
        def crash_after_controller_deny(path, *args):
            result = original(path, *args)
            if Path(path) == self.old / "controller.lock" and args[:1] == ("/deny",):
                raise RuntimeError("injected first deny loss")
            return result
        with patch.object(guarded, "_icacls", side_effect=crash_after_controller_deny):
            with self.assertRaisesRegex(RuntimeError, "first deny loss"):
                self.call(observer=lambda **kwargs: _noop_lease())
        observed = []
        def replay_observer(**kwargs):
            observed.append(kwargs['controller_handle'])
            self.assertEqual(set(kwargs['writable_database_names']),
                             guarded.NAMES - {"controller.lock"})
            return _noop_lease()
        self.assertTrue(self.call(observer=replay_observer)['reconciled'])
        self.assertEqual(observed, [None])

    def test_partial_database_deny_replay_excludes_denied_database(self):
        target = self.old / "checkpoint.sqlite3"
        original = guarded._icacls
        def crash_after_database_deny(path, *args):
            result = original(path, *args)
            if Path(path) == target and args[:1] == ("/deny",):
                raise RuntimeError("injected database deny loss")
            return result
        with patch.object(guarded, "_icacls", side_effect=crash_after_database_deny):
            with self.assertRaisesRegex(RuntimeError, "database deny loss"):
                self.call(observer=lambda **kwargs: _noop_lease())
        observed = []
        def replay_observer(**kwargs):
            observed.append(kwargs['writable_database_names'])
            return _noop_lease()
        self.assertTrue(self.call(observer=replay_observer)['reconciled'])
        self.assertEqual(set(observed[0]),
                         guarded.NAMES - {"controller.lock", target.name})

    def test_actual_signed_authored_continuous_lock_and_replay(self):
        observed = {}
        original = guarded._write_once
        def at_quiescence(path, body):
            if Path(path).name == "quiescence.json":
                for name in ("source-stage.lock", "phase-stage.lock", "state/controller.lock"):
                    contender = self.parent / name
                    probe = invoke(sys.executable, "-c",
                        "import msvcrt,sys;f=open(sys.argv[1],'r+b');f.seek(0);"
                        "msvcrt.locking(f.fileno(),msvcrt.LK_NBLCK,1)", str(contender))
                    observed[name] = probe.returncode != 0
            return original(path, body)
        with patch.object(guarded, "_write_once", side_effect=at_quiescence):
            result = self.call()
        self.assertTrue(all(observed.values()), observed)
        self.assertEqual(len(observed), 3)
        self.assertFalse(self.old.exists())
        self.assertEqual(bytes_digest((self.out / "quiescence.json").read_bytes()),
                         self.quiescence_sha)
        self.assertEqual(result["quiescence_receipt_sha256"], self.quiescence_sha)
        self.assertFalse(result["reconciled"])
        replay = self.call()
        self.assertTrue(replay["reconciled"])
        self.assertEqual(replay["receipt_sha256"], result["receipt_sha256"])

    def test_wrong_quiescence_pin_has_zero_acl_effect(self):
        self.quiescence_sha = "0" * 64
        with self.assertRaises(Exception):
            self.call()
        self.assertFalse((self.out / "barrier.json").exists())
        self.assertTrue(self.old.exists())
        self.assertFalse(self.archive.exists())

    def test_pre_barrier_crash_holds_for_renewed_owner_review(self):
        original = guarded._write_once
        def crash_after_quiescence(path, body):
            result = original(path, body)
            if Path(path).name == "quiescence.json":
                raise RuntimeError("injected pre-barrier process loss")
            return result
        with patch.object(guarded, "_write_once", side_effect=crash_after_quiescence):
            with self.assertRaisesRegex(RuntimeError, "pre-barrier process loss"):
                self.call()
        self.assertTrue((self.out / "quiescence.json").exists())
        self.assertFalse((self.out / "barrier.json").exists())
        with self.assertRaisesRegex(Exception, "renewed owner review"):
            self.call()
        self.assertTrue(self.old.exists())
        self.assertFalse(self.archive.exists())


if __name__ == "__main__":
    unittest.main()
