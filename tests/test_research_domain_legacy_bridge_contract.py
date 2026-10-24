"""The pinned bridge subclasses the reference backend without running its constructor.

Inherited methods must therefore not depend on attributes that only `__init__` creates.
These tests build a bridge instance around a minimal SQLite store, so they need no
external reviewed core. They are NOT a pinned-core conformance result: the exact
24-check gate (`tools/check_legacy.py --core ...`) is still required.
"""
import sqlite3
import threading
import unittest

from trace_gc.backend import SQLiteReferenceBackend
from trace_gc.canonical import dumps
from trace_gc.errors import ContractError
from trace_gc.legacy import PinnedLegacyBackend


def bridge_without_core(*, tombstone):
    backend = object.__new__(PinnedLegacyBackend)
    backend.path, backend.sandbox, backend._lock = ":memory:", True, threading.RLock()
    backend.db = sqlite3.connect(":memory:", isolation_level=None, check_same_thread=False)
    backend.db.executescript("""
        CREATE TABLE trace_records(id TEXT PRIMARY KEY,hash TEXT NOT NULL,kind TEXT NOT NULL,body TEXT NOT NULL);
        CREATE TABLE trace_erased(id TEXT PRIMARY KEY,hash TEXT NOT NULL,kind TEXT NOT NULL,reason TEXT NOT NULL,erased_at TEXT NOT NULL);
        CREATE TABLE trace_source_status(id TEXT PRIMARY KEY,body TEXT NOT NULL);
    """)
    status = {"active": False, "permission": "DENIED", "epoch": 2, "updated_at": "2026-10-08T00:00:00Z", "tombstone": tombstone}
    backend.db.execute("INSERT INTO trace_source_status VALUES(?,?)", ("source:x", dumps(status)))
    rows = (("source:x", "source", {"text": "removed"}),
            ("evidence:x", "evidence", {"source_snapshot_id": "source:x", "quote": "removed"}),
            ("claim:unrelated", "claim", {"text": "kept"}))
    for ref, kind, body in rows:
        backend.db.execute("INSERT INTO trace_records VALUES(?,?,?,?)", (ref, "0" * 64, kind, dumps(body)))
    return backend


class BridgePhaseAttributeTests(unittest.TestCase):
    def test_bridge_and_reference_class_defaults_are_never_phase_bound(self):
        for cls in (SQLiteReferenceBackend, PinnedLegacyBackend):
            with self.subTest(cls=cls.__name__):
                self.assertIsNone(cls._phase_guard)
                self.assertIsNone(cls._phase_authority)

    def test_erasure_runs_on_a_bridge_instance_without_a_phase_attribute_error(self):
        backend = bridge_without_core(tombstone=True)
        self.addCleanup(backend.db.close)
        self.assertNotIn("_phase_guard", vars(backend))
        result = backend.erase_cached_content("source:x", reason="bridge retention test")
        self.assertEqual(result["status"], "EXACT_REPLAY_UNAVAILABLE")
        self.assertEqual(result["erased_ids"], ["evidence:x", "source:x"])
        self.assertEqual(sorted(r[0] for r in backend.db.execute("SELECT id FROM trace_records")), ["claim:unrelated"])
        self.assertEqual(sorted(r[0] for r in backend.db.execute("SELECT id FROM trace_erased")), ["evidence:x", "source:x"])
        self.assertFalse(backend.db.in_transaction)

    def test_erasure_without_a_committed_tombstone_is_denied_and_changes_nothing(self):
        backend = bridge_without_core(tombstone=False)
        self.addCleanup(backend.db.close)
        before = list(backend.db.iterdump())
        with self.assertRaises(ContractError) as caught:
            backend.erase_cached_content("source:x", reason="not authorized")
        self.assertEqual(caught.exception.code, "ERASURE_AUTHORITY")
        self.assertEqual(list(backend.db.iterdump()), before)
        self.assertFalse(backend.db.in_transaction)


if __name__ == "__main__":
    unittest.main()
