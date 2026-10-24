"""Native Windows: classification-index writes against a real PhaseAuthority.

Uses the real msvcrt phase lock, NTFS deny-create fence receipt and signed activation
pointer. Authored on Linux and NOT_RUN there: it is skipped unless os.name == "nt",
and a Linux skip is never a passed Windows qualification. The hosted `windows-latest`
jobs run it; see docs/research_domain_deployment_gates.md.
"""
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import threading
import unittest

from trace_gc.canonical import bytes_digest, dumps
from trace_gc.errors import ContractError
from trace_gc.phase_authority import PhaseAuthority, binding_sha256
from trace_gc.retrieval.contracts import query
from trace_gc.retrieval.domain_index import SQLiteClassificationIndex
from trace_gc.retrieval.store import SQLiteGraphAdapter
from trace_gc.trust import IssuerPolicy, Signer, TrustStore

if os.name == "nt":
    from src.paper_pilot_phase_cutover import NAMES, _current_sid, fence_closed_old_phase
    from test_research_domain_transactions import DomainFixture
    from trace_gc.backend import SQLiteReferenceBackend

TABLES = SQLiteClassificationIndex.TABLES


@unittest.skipUnless(os.name == "nt", "NOT_RUN: native Windows phase qualification requires NTFS, msvcrt and DACL fencing")
class IndexPhaseOwnershipNativeWindowsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get("ISSUE90_TEST_TMPDIR"))
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.sid = _current_sid()
        old, archived = root / "old-application" / "state", root / "archive" / "historical-state"
        old.mkdir(parents=True)
        archived.parent.mkdir()
        (root / "control").mkdir()
        (root / "graph").mkdir()
        for name in sorted(NAMES):
            if name.endswith(".sqlite3"):
                connection = sqlite3.connect(old / name)
                connection.execute("CREATE TABLE fixture (id INTEGER PRIMARY KEY)")
                connection.commit()
                connection.close()
            else:
                (old / name).write_bytes(b"0")
        hashes = {name: bytes_digest((old / name).read_bytes()) for name in NAMES}
        fence = root / "control" / "fence-receipt.json"
        fence_closed_old_phase(old_root=old, archived_root=archived, expected_file_sha256=hashes,
                               deny_sid=self.sid, receipt_path=fence)
        self.addCleanup(lambda: subprocess.run(["icacls.exe", str(old.parent), "/remove:d", "*" + self.sid],
                                               capture_output=True, text=True, timeout=30))
        lock = root / "control" / "phase.lock"
        lock.write_bytes(b"0")
        for name in ("capsule.json", "authorization.json"):
            (root / "control" / name).write_bytes(b"{}")
        self.pointer = root / "control" / "active.json"
        self.signer = Signer.ephemeral("index-phase-activator")
        self.phase_trust = TrustStore()
        self.phase_trust.enroll(self.signer.issuer, IssuerPolicy(
            self.signer.public_key(), "index-phase-activator", frozenset({"AUTHORIZATION"}),
            frozenset({"PHASE_ACTIVATE"}), frozenset({"isolated-test"}), frozenset({"LIVE"}), can_review=True))
        binding = {"phase_id": "index-phase", "run_id": "authored-only", "capsule_sha256": "a" * 64,
                   "implementation_sha256": "b" * 64, "activation_path": str(self.pointer),
                   "activation_sha256": "0" * 64, "activation_epoch": 1, "phase_lock_path": str(lock),
                   "fence_receipt_path": str(fence), "fence_receipt_sha256": bytes_digest(fence.read_bytes()),
                   "old_root_path": str(old), "archived_old_root_path": str(archived),
                   "capsule_path": str(root / "control" / "capsule.json"),
                   "authorization_path": str(root / "control" / "authorization.json"),
                   "authorization_sha256": "c" * 64}
        draft = PhaseAuthority(binding, self.phase_trust)
        receipt = self.signer.issue("AUTHORIZATION", draft.activation_payload(), lifetime_seconds=3600)
        draft.close()
        self.pointer_bytes = dumps(receipt).encode("utf-8")
        binding["activation_sha256"] = bytes_digest(self.pointer_bytes)
        self.pointer.write_bytes(self.pointer_bytes)
        self.authority = PhaseAuthority(binding, self.phase_trust)
        self.addCleanup(self.authority.close)
        self.authority.check()

        graph = root / "graph" / "graph.db"
        marker = sqlite3.connect(graph)
        marker.execute("CREATE TABLE trace_phase_binding(id INTEGER PRIMARY KEY CHECK(id=1), binding_sha256 TEXT NOT NULL)")
        marker.execute("INSERT INTO trace_phase_binding VALUES(1, ?)", (binding_sha256(self.authority.binding),))
        marker.commit()
        marker.close()

        def factory(path, **kwargs):
            return SQLiteReferenceBackend(graph, phase_authority=self.authority, **kwargs)
        self.f = DomainFixture(root / "unused", backend_factory=factory)
        self.addCleanup(self.f.close)
        self.backend = self.f.backend
        self.f.migrate()
        self.f.publish(self.f.assignment_plan(self.f.assign()))

    def dump(self):
        return list(self.backend.db.iterdump())

    def request(self):
        return query(requesting_component="native-index-phase", security_scope="test", text="Synthetic", strategies=["SOURCE"])

    def deactivate(self):
        self.pointer.rename(self.pointer.with_suffix(".withdrawn"))

    def test_active_phase_creates_the_index_and_rebuilds_it(self):
        adapter = SQLiteGraphAdapter(self.backend, audit_trust=self.f.trust)
        self.assertTrue(adapter.index.tables_exist())
        self.assertTrue(adapter.index.scope_required)
        rebuilt = adapter.rebuild_classification_index(self.request())
        self.assertTrue(adapter.index.last_metrics["persisted"])
        self.assertEqual(rebuilt.classification_rows, adapter.read(self.request()).classification_rows)

    def test_inactive_phase_denies_every_index_write_and_leaves_the_database_unchanged(self):
        adapter = SQLiteGraphAdapter(self.backend, audit_trust=self.f.trust)
        adapter.materialize_classification_index(self.request())
        self.deactivate()
        before = self.dump()
        for action in (adapter.rebuild_classification_index, adapter.materialize_classification_index):
            with self.subTest(action=action.__name__), self.assertRaises(ContractError) as caught:
                action(self.request())
            self.assertEqual(caught.exception.code, "PHASE_INACTIVE")
        self.assertEqual(self.dump(), before)
        self.assertFalse(self.backend.db.in_transaction)

    def test_inactive_phase_denies_constructor_ddl_and_leaves_no_index_tables(self):
        for name in TABLES:
            self.backend.db.execute("DROP TABLE IF EXISTS " + name)
        self.backend.db.execute("DROP INDEX IF EXISTS trace_domain_index_by_source")
        self.deactivate()
        before = self.dump()
        with self.assertRaises(ContractError) as caught:
            SQLiteGraphAdapter(self.backend, audit_trust=self.f.trust)
        self.assertEqual(caught.exception.code, "PHASE_INACTIVE")
        self.assertEqual(self.dump(), before)

    def test_fence_removal_denies_index_writes(self):
        adapter = SQLiteGraphAdapter(self.backend, audit_trust=self.f.trust)
        old_parent = Path(self.authority.binding["old_root_path"]).parent
        subprocess.run(["icacls.exe", str(old_parent), "/remove:d", "*" + self.sid],
                       capture_output=True, text=True, timeout=30, check=True)
        before = self.dump()
        with self.assertRaises(ContractError) as caught:
            adapter.rebuild_classification_index(self.request())
        self.assertEqual(caught.exception.code, "PHASE_FENCE")
        self.assertEqual(self.dump(), before)

    def test_read_on_a_phase_bound_database_never_writes_even_when_inactive(self):
        adapter = SQLiteGraphAdapter(self.backend, audit_trust=self.f.trust)
        reference = adapter.read(self.request())
        for name in ("trace_domain_index_membership", "trace_domain_index_sources", "trace_domain_index_meta"):
            self.backend.db.execute("DELETE FROM " + name)
        self.deactivate()
        before = self.dump()
        view = adapter.read(self.request())
        self.assertEqual(view.classification_rows, reference.classification_rows)
        self.assertFalse(adapter.index.last_metrics["persisted"])
        self.assertEqual(self.dump(), before)

    def test_phase_withdrawn_while_a_rebuild_waits_denies_it_after_the_lock_is_acquired(self):
        adapter = SQLiteGraphAdapter(self.backend, audit_trust=self.f.trust)
        before = self.dump()
        held, release, outcome = threading.Event(), threading.Event(), {}

        def holder():
            with self.authority.write():
                held.set()
                release.wait(30)
                self.deactivate()

        def rebuild():
            try:
                outcome["value"] = adapter.rebuild_classification_index(self.request())
            except BaseException as error:
                outcome["error"] = error

        owner = threading.Thread(target=holder)
        owner.start()
        self.assertTrue(held.wait(30))
        waiter = threading.Thread(target=rebuild)
        waiter.start()
        release.set()
        owner.join(60)
        waiter.join(60)
        self.assertNotIn("value", outcome)
        self.assertEqual(outcome["error"].code, "PHASE_INACTIVE")
        self.assertEqual(self.dump(), before)
        self.assertFalse(self.backend.db.in_transaction)


if __name__ == "__main__":
    unittest.main()
