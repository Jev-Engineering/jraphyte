"""Every classification-index DDL, rebuild and write is owned by the phase authority.

A phase double stands in for `PhaseAuthority.write` on Linux: it records whether the
backend lock or a SQL transaction was already held when the phase was entered, and it
can refuse entry the way an inactive or fenced phase does. The real Windows lock,
DACL fence and activation pointer are exercised by
`test_research_domain_index_phase_windows.py`, which does not run on this host.
"""
from contextlib import contextmanager
import tempfile
import unittest

from trace_gc.errors import ContractError
from trace_gc.retrieval.contracts import query
from trace_gc.retrieval.domain_index import SQLiteClassificationIndex

TABLES = SQLiteClassificationIndex.TABLES
from trace_gc.retrieval.store import SQLiteGraphAdapter
from test_research_domain_transactions import DomainFixture

WRITING = ("CREATE", "INSERT", "DELETE", "UPDATE", "DROP", "ALTER", "REPLACE")


class PhaseDouble:
    def __init__(self, backend, *, active=True):
        self.backend, self.active, self.events, self.depth = backend, active, [], 0

    @contextmanager
    def write(self):
        db = self.backend.db
        self.events.append(("phase", self.backend._lock._is_owned(), db.in_transaction))
        if not self.active:
            raise ContractError("PHASE_INACTIVE", "phase authority is inactive or fenced")
        self.depth += 1
        try:
            yield
        finally:
            self.depth -= 1
            self.events.append(("phase-exit", db.in_transaction))


class IndexPhaseOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.f = DomainFixture(self.directory.name)
        self.addCleanup(self.f.close)
        self.f.migrate()
        self.f.publish(self.f.assignment_plan(self.f.assign()))
        self.backend = self.f.backend
        self.drop_index()

    def drop_index(self):
        db = self.backend.db
        for name in TABLES:
            db.execute("DROP TABLE IF EXISTS " + name)
        db.execute("DROP INDEX IF EXISTS trace_domain_index_by_source")
        db.commit()

    def clear_entries(self):
        for name in ("trace_domain_index_membership", "trace_domain_index_sources", "trace_domain_index_meta"):
            self.backend.db.execute("DELETE FROM " + name)
        self.backend.db.commit()

    def bind(self, *, active=True):
        double = PhaseDouble(self.backend, active=active)
        self.backend._phase_guard = double.write
        return double

    def dump(self):
        return list(self.backend.db.iterdump())

    def statements(self):
        seen = []
        self.backend.db.set_trace_callback(lambda sql: seen.append(sql.strip()))
        self.addCleanup(self.backend.db.set_trace_callback, None)
        return seen

    def request(self):
        return query(requesting_component="index-phase-test", security_scope="test", text="Synthetic", strategies=["SOURCE"])

    def writes(self, seen):
        return [s for s in seen if s.upper().startswith(WRITING)]

    def test_constructor_ddl_is_unchanged_when_the_phase_is_inactive_or_fenced(self):
        self.bind(active=False)
        before = self.dump()
        with self.assertRaises(ContractError) as caught:
            SQLiteGraphAdapter(self.backend, audit_trust=self.f.trust)
        self.assertEqual(caught.exception.code, "PHASE_INACTIVE")
        self.assertEqual(self.dump(), before)
        self.assertFalse(self.backend.db.in_transaction)

    def test_constructor_ddl_runs_inside_the_active_phase_with_the_documented_lock_order(self):
        double = self.bind()
        seen = self.statements()
        adapter = SQLiteGraphAdapter(self.backend, audit_trust=self.f.trust)
        self.assertTrue(adapter.index.tables_exist())
        # phase first: neither the backend lock nor a SQL transaction is held on entry
        self.assertEqual(double.events[0], ("phase", False, False))
        begin = next(i for i, s in enumerate(seen) if s == "BEGIN IMMEDIATE")
        ddl = next(i for i, s in enumerate(seen) if s.upper().startswith("CREATE"))
        commit = seen.index("COMMIT")
        self.assertLess(begin, ddl)
        self.assertLess(ddl, commit)
        self.assertEqual(double.events[-1], ("phase-exit", False))

    def test_existing_tables_are_not_rewritten_or_phase_gated_on_construction(self):
        SQLiteGraphAdapter(self.backend, audit_trust=self.f.trust)
        double = self.bind(active=False)
        before = self.dump()
        SQLiteGraphAdapter(self.backend, audit_trust=self.f.trust)
        self.assertEqual(self.dump(), before)
        self.assertEqual(double.events, [])

    def test_rebuild_and_materialize_are_denied_without_changing_database_or_index(self):
        adapter = SQLiteGraphAdapter(self.backend, audit_trust=self.f.trust)
        adapter.materialize_classification_index(self.request())
        double = self.bind(active=False)
        before = self.dump()
        for action in (adapter.rebuild_classification_index, adapter.materialize_classification_index):
            with self.subTest(action=action.__name__), self.assertRaises(ContractError) as caught:
                action(self.request())
            self.assertEqual(caught.exception.code, "PHASE_INACTIVE")
            self.assertEqual(self.dump(), before)
            self.assertFalse(self.backend.db.in_transaction)
        self.assertEqual(len(double.events), 2)

    def test_rebuild_and_materialize_write_only_inside_the_active_phase(self):
        adapter = SQLiteGraphAdapter(self.backend, audit_trust=self.f.trust)
        double = self.bind()
        for action in (adapter.rebuild_classification_index, adapter.materialize_classification_index):
            self.clear_entries()
            seen = self.statements()
            with self.subTest(action=action.__name__):
                view = action(self.request())
                writes = self.writes(seen)
                self.assertTrue(writes)
                begin = seen.index("BEGIN IMMEDIATE")
                self.assertLess(begin, seen.index(writes[0]))
                self.assertEqual(seen[-1], "COMMIT")
                self.assertEqual(view.classification_rows, adapter.read(self.request()).classification_rows)
        self.assertEqual([e[:3] for e in double.events if e[0] == "phase"], [("phase", False, False)] * 2)

    def test_fence_after_construction_denies_later_rebuilds_but_not_reads(self):
        double = self.bind()
        adapter = SQLiteGraphAdapter(self.backend, audit_trust=self.f.trust)
        adapter.materialize_classification_index(self.request())
        double.active = False
        before = self.dump()
        with self.assertRaises(ContractError):
            adapter.rebuild_classification_index(self.request())
        self.assertEqual(self.dump(), before)
        self.assertTrue(adapter.read(self.request()).classification_rows)

    def test_phase_bound_read_never_writes_when_the_index_entry_or_tables_are_absent(self):
        adapter = SQLiteGraphAdapter(self.backend, audit_trust=self.f.trust)
        reference = adapter.read(self.request())
        self.assertTrue(adapter.index.last_metrics["persisted"])
        for damage in (self.clear_entries, self.drop_index):
            with self.subTest(damage=damage.__name__):
                damage()
                double = self.bind(active=False)
                seen = self.statements()
                before = self.dump()
                view = adapter.read(self.request())
                self.assertEqual(self.writes(seen), [])
                self.assertEqual(double.events, [])
                self.assertEqual(view.classification_rows, reference.classification_rows)
                self.assertFalse(adapter.index.last_metrics["persisted"])
                self.assertEqual(self.dump(), before)
                self.assertFalse(self.backend.db.in_transaction)

    def test_phase_bound_adapter_refuses_direct_index_mutation_outside_a_write_scope(self):
        self.bind()
        adapter = SQLiteGraphAdapter(self.backend, audit_trust=self.f.trust)
        self.assertTrue(adapter.index.scope_required)
        before = self.dump()
        with self.assertRaises(ContractError) as caught:
            adapter.index.ensure_tables()
        self.assertEqual(caught.exception.code, "PHASE_GUARD")
        view = adapter.read(self.request())
        with self.assertRaises(ContractError):
            adapter.index.read(self.backend.load_catalog(), view.snapshot_id, rebuild=True)
        self.assertEqual(self.dump(), before)

    def test_index_built_without_a_phase_remains_unscoped_for_unbound_backends(self):
        index = SQLiteClassificationIndex(self.backend.db)
        self.assertFalse(index.scope_required)
        index.ensure_tables()
        self.assertTrue(index.tables_exist())

    def test_a_caller_owned_transaction_is_never_adopted_by_an_index_write(self):
        adapter = SQLiteGraphAdapter(self.backend, audit_trust=self.f.trust)
        self.bind()
        self.backend.db.execute("BEGIN")
        before = self.backend.db.in_transaction
        for action in (adapter.rebuild_classification_index, adapter.materialize_classification_index):
            with self.subTest(action=action.__name__), self.assertRaises(ContractError) as caught:
                action(self.request())
            self.assertEqual(caught.exception.code, "GRAPH_READ_UNCOMMITTED")
            self.assertEqual(self.backend.db.in_transaction, before)
        self.backend.db.execute("ROLLBACK")

    def test_a_caller_owned_transaction_blocks_missing_table_creation_without_closing_it(self):
        self.backend.db.execute("BEGIN")
        with self.assertRaises(ContractError) as caught:
            SQLiteGraphAdapter(self.backend, audit_trust=self.f.trust)
        self.assertEqual(caught.exception.code, "GRAPH_READ_UNCOMMITTED")
        self.assertTrue(self.backend.db.in_transaction)
        self.backend.db.execute("ROLLBACK")


if __name__ == "__main__":
    unittest.main()
