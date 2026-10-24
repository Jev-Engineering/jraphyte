"""Publication and read isolation against the real disposable reference database."""
from pathlib import Path
import tempfile
import sqlite3
import unittest

from trace_gc.canonical import dumps
from trace_gc.backend import SQLiteReferenceBackend
from trace_gc.legacy import _TransactionConnection
from trace_gc.errors import ContractError
from trace_gc.retrieval.contracts import query
from trace_gc.retrieval.store import SQLiteGraphAdapter
import test_research_domain_conformance as adversarial
from test_research_domain_transactions import DomainFixture


class DomainAuthorityBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.f = DomainFixture(self.directory.name)
        self.addCleanup(self.directory.cleanup)
        self.addCleanup(self.f.close)
        self.f.migrate()

    def request(self, **updates):
        return query(requesting_component="downstream-search", security_scope="test",
                     strategies=["LEXICAL"], text="biology", **updates)

    def database(self):
        # Byte-preservation of every table that contains accepted authority.
        return {name: list(self.f.backend.db.execute("SELECT * FROM " + name))
                for name in ("trace_meta", "trace_state", "trace_source_status", "trace_records", "trace_journal")}

    def corrupt_receipt(self, purpose):
        adversarial.DomainAdversarialAuthorityTests.rewrite_latest_signature_with_consistent_hashes(self, purpose)

    def test_next_publication_refuses_rehashed_invalid_prior_authorization(self):
        plan = self.f.assignment_plan(self.f.assign())
        approvals = self.f.approvals(plan)
        self.corrupt_receipt("AUTHORIZATION")
        before = self.database()
        with self.assertRaises(ContractError) as caught:
            self.f.publish(plan, approvals=approvals)
        self.assertEqual(caught.exception.code, "SIGNATURE_INVALID")
        self.assertEqual(self.database(), before)
        self.assertFalse(self.f.backend.db.in_transaction)

    def test_next_publication_refuses_rehashed_invalid_prior_preflight(self):
        plan = self.f.assignment_plan(self.f.assign())
        approvals = self.f.approvals(plan)
        self.corrupt_receipt("PREFLIGHT")
        before = self.database()
        with self.assertRaises(ContractError) as caught:
            self.f.publish(plan, approvals=approvals)
        self.assertEqual(caught.exception.code, "SIGNATURE_INVALID")
        self.assertEqual(self.database(), before)

    def test_idempotent_retry_does_not_return_forged_persisted_receipt(self):
        plan = self.f.assignment_plan(self.f.assign())
        approvals = self.f.approvals(plan)
        self.f.publish(plan, approvals=approvals)
        self.corrupt_receipt("AUTHORIZATION")
        before = self.database()
        with self.assertRaises(ContractError) as caught:
            self.f.publish(plan, approvals=approvals)
        self.assertEqual(caught.exception.code, "SIGNATURE_INVALID")
        self.assertEqual(self.database(), before)

    def test_publication_cannot_extend_unjournaled_metadata(self):
        plan = self.f.assignment_plan(self.f.assign())
        approvals = self.f.approvals(plan)
        state = self.f.backend.state()
        state["metadata"]["unlogged"] = {"not": "accepted"}
        self.f.backend.db.execute("UPDATE trace_state SET body=? WHERE id=1", (dumps(state),))
        before = self.database()
        with self.assertRaises(ContractError) as caught:
            self.f.publish(plan, approvals=approvals)
        self.assertEqual(caught.exception.code, "BACKEND_AUDIT")
        self.assertEqual(self.database(), before)

    def test_read_does_not_export_an_assignment_before_rollback(self):
        adapter = SQLiteGraphAdapter(self.f.backend, audit_trust=self.f.trust)
        before = adapter.read(self.request())
        plan = self.f.assignment_plan(self.f.assign())
        observed = []
        def interrupted(point):
            if point == "before_commit":
                with self.assertRaises(ContractError) as caught:
                    observed.append(adapter.read(self.request()))
                self.assertEqual(caught.exception.code, "GRAPH_READ_UNCOMMITTED")
                raise RuntimeError("rollback after attempted read")
        with self.assertRaisesRegex(RuntimeError, "rollback after attempted read"):
            self.f.publish(plan, fault=interrupted)
        self.assertEqual(observed, [])
        after = adapter.read(self.request())
        self.assertEqual(after.snapshot_id, before.snapshot_id)
        self.assertEqual(after.classification_rows, before.classification_rows)

    def test_current_status_hook_refuses_caller_transaction(self):
        adapter = SQLiteGraphAdapter(self.f.backend, audit_trust=self.f.trust)
        before = adapter.current_source_status()
        self.f.backend.db.execute("BEGIN IMMEDIATE")
        try:
            with self.assertRaises(ContractError) as caught:
                adapter.current_source_status()
            self.assertEqual(caught.exception.code, "GRAPH_READ_UNCOMMITTED")
            self.assertTrue(self.f.backend.db.in_transaction)
        finally:
            self.f.backend.db.execute("ROLLBACK")
        self.assertEqual(adapter.current_source_status(), before)

    def test_rebuild_refuses_caller_transaction_without_mutating_it(self):
        adapter = SQLiteGraphAdapter(self.f.backend, audit_trust=self.f.trust)
        adapter.read(self.request())
        before = list(self.f.backend.db.execute("SELECT * FROM trace_domain_index_meta"))
        self.f.backend.db.execute("BEGIN")
        try:
            with self.assertRaises(ContractError) as caught:
                adapter.rebuild_classification_index(self.request())
            self.assertEqual(caught.exception.code, "GRAPH_READ_UNCOMMITTED")
            self.assertTrue(self.f.backend.db.in_transaction)
            self.assertEqual(list(self.f.backend.db.execute("SELECT * FROM trace_domain_index_meta")), before)
        finally:
            self.f.backend.db.execute("ROLLBACK")

    def test_authority_recheck_holds_the_sql_write_transaction_even_on_retry(self):
        plan = self.f.assignment_plan(self.f.assign())
        approvals = self.f.approvals(plan)
        backend = self.f.backend
        audit = backend.audit
        calls = []
        competing = sqlite3.connect(backend.path, isolation_level=None, timeout=0)
        self.addCleanup(competing.close)
        def locked_audit(**kwargs):
            self.assertTrue(backend.db.in_transaction)
            with self.assertRaisesRegex(sqlite3.OperationalError, "locked"):
                competing.execute("BEGIN IMMEDIATE")
            calls.append(kwargs.get("trust"))
            return audit(**kwargs)
        backend.audit = locked_audit
        first = self.f.publish(plan, approvals=approvals)
        replay = self.f.publish(plan, approvals=approvals)
        self.assertEqual(calls, [self.f.trust, self.f.trust])
        self.assertFalse(first["replayed"])
        self.assertTrue(replay["replayed"])
        self.assertEqual(first["receipt"], replay["receipt"])

    def test_separate_connection_reads_only_committed_assignment_during_write(self):
        backend = self.f.backend
        with SQLiteReferenceBackend(backend.path, catalog=self.f.catalog, schema_id=self.f.schema,
                                    nodes={}, sandbox=True) as reader:
            adapter = SQLiteGraphAdapter(reader, audit_trust=self.f.trust)
            before = adapter.read(self.request())
            seen = []
            plan = self.f.assignment_plan(self.f.assign())
            def during_commit(point):
                if point == "before_commit":
                    seen.append(adapter.read(self.request()))
            self.f.publish(plan, fault=during_commit)
            self.assertEqual(len(seen), 1)
            self.assertEqual(seen[0].snapshot_id, before.snapshot_id)
            after = adapter.read(self.request())
            self.assertEqual(after.snapshot["graph_version"], before.snapshot["graph_version"] + 1)
            self.assertEqual(after.classification_rows[self.f.source]["domain_ids"], ["research:biology"])

    def test_source_revocation_is_still_available_when_prior_review_is_invalid(self):
        self.corrupt_receipt("AUTHORIZATION")
        old_version = self.f.backend.state()["graph_version"]
        self.f.status_change(permission="DENIED")
        self.assertEqual(self.f.backend.state()["graph_version"], old_version + 1)
        self.assertFalse(self.f.backend.statuses()[self.f.source]["active"])
        self.assertEqual(self.f.backend.statuses()[self.f.source]["permission"], "DENIED")
        with self.assertRaises(ContractError):
            self.f.backend.audit(trust=self.f.trust)


class PinnedBoundaryHookTests(unittest.TestCase):
    """Real SQLite proxy mechanics only: not the unavailable pinned-core gate."""
    def setUp(self):
        self.raw = sqlite3.connect(":memory:", isolation_level=None)
        self.addCleanup(self.raw.close)
        self.raw.execute("CREATE TABLE state(id INTEGER PRIMARY KEY, body TEXT)")
        self.raw.execute("INSERT INTO state VALUES(1, 'committed')")
        self.proxy = _TransactionConnection(self.raw)

    def test_boundary_check_runs_after_begin_before_lookup_without_apply_reentry(self):
        calls = []
        def authority():
            self.assertTrue(self.raw.in_transaction)
            calls.append("authority")
            self.assertEqual(self.proxy.execute("SELECT body FROM state WHERE id=1").fetchone()[0], "committed")
        self.proxy.authority_check = authority
        self.proxy.guard = lambda: calls.append("apply")
        self.proxy.execute("BEGIN IMMEDIATE")
        self.assertEqual(calls, ["authority"])
        self.proxy.execute("SELECT body FROM state WHERE id=1")
        self.assertEqual(calls, ["authority", "apply"])
        self.proxy.execute("ROLLBACK")

    def test_idempotency_lookup_does_not_skip_authority_check(self):
        calls = []
        self.proxy.authority_check = lambda: calls.append("authority")
        self.proxy.guard = lambda: calls.append("apply")
        self.proxy.execute("BEGIN IMMEDIATE")
        self.proxy.execute("SELECT 1")  # Receipt lookup need not read STATE.
        self.proxy.execute("ROLLBACK")
        self.assertEqual(calls, ["authority"])

    def test_boundary_failure_rolls_back_begin_and_clears_checking_state(self):
        calls = []
        def rejected():
            self.proxy.execute("UPDATE state SET body='not committed' WHERE id=1")
            raise ContractError("SIGNATURE_INVALID", "synthetic failure")
        self.proxy.authority_check = rejected
        self.proxy.guard = lambda: calls.append("apply")
        with self.assertRaises(ContractError):
            self.proxy.execute("BEGIN IMMEDIATE")
        self.assertFalse(self.raw.in_transaction)
        self.assertFalse(self.proxy.checking_authority)
        self.assertFalse(self.proxy.guarded)
        self.assertEqual(calls, [])
        self.assertEqual(self.raw.execute("SELECT body FROM state WHERE id=1").fetchone()[0], "committed")
        self.proxy.authority_check = None
        self.proxy.execute("BEGIN IMMEDIATE")
        self.proxy.execute("ROLLBACK")

    def test_failed_nested_begin_preserves_callers_transaction(self):
        calls = []
        self.raw.execute("BEGIN")
        self.raw.execute("UPDATE state SET body='caller-owned' WHERE id=1")
        self.proxy.authority_check = lambda: calls.append("authority")
        with self.assertRaises(sqlite3.OperationalError):
            self.proxy.execute("BEGIN IMMEDIATE")
        self.assertTrue(self.raw.in_transaction)
        self.assertEqual(calls, [])
        self.assertEqual(self.raw.execute("SELECT body FROM state WHERE id=1").fetchone()[0], "caller-owned")
        self.raw.execute("ROLLBACK")


if __name__ == "__main__":
    unittest.main()
