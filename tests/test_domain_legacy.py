"""Actual byte-pinned bridge tests, not a reconstructed or fake GraphStore.

Set TRACE_GC_LEGACY_CORE to the authorized exact upstream source. No download,
production database, live provider call, or production key enrollment occurs.
"""
from copy import deepcopy
from functools import partial
import os
import unittest

import test_domain_publication as fixtures
from trace_gc.canonical import digest, dumps, loads
from trace_gc.catalog import Catalog
from trace_gc.domain_publication import PROJECTION_KEY, ClassificationPublisher
from trace_gc.errors import ContractError
from trace_gc.legacy import PinnedLegacyBackend, load_pinned_core

CORE = os.environ.get("TRACE_GC_LEGACY_CORE")
POLICY = {"version": "synthetic-domain-bridge-test-only", "thresholds": {"related": .9},
          "contracts": {"related": ["YES", "NO"]}, "allowed_modes": ["synthetic"]}


@unittest.skipUnless(CORE, "TRACE_GC_LEGACY_CORE unavailable: exact legacy gate NOT RUN")
class DomainLegacy(unittest.TestCase):
    def setUp(self):
        load_pinned_core(CORE)
        self.f = fixtures.DomainPublication()
        previous = fixtures.BACKEND_FACTORY
        try:
            fixtures.BACKEND_FACTORY = partial(PinnedLegacyBackend, core_path=CORE, legacy_policy=POLICY)
            self.f.setUp()
        finally:
            fixtures.BACKEND_FACTORY = previous
        self.addCleanup(self.f.doCleanups)
        self.assertIs(type(self.f.backend), PinnedLegacyBackend)

    def dump(self):
        db = self.f.backend.db
        tables = [row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        return {name: db.execute('SELECT * FROM "' + name + '" ORDER BY 1').fetchall() for name in tables}

    def test_old_database_migration_preserves_genesis_and_both_journal_prefixes(self):
        before = self.dump()
        meta_before = loads(before["trace_meta"][0][1])
        self.f.migrate()
        after = self.dump()
        meta_after = loads(after["trace_meta"][0][1])
        self.assertEqual(meta_before, {k: v for k, v in meta_after.items() if k != PROJECTION_KEY})
        for table in ("journal", "trace_journal"):
            self.assertEqual(before[table], after[table][:len(before[table])])
        self.assertEqual(meta_before["genesis_hash"], digest(meta_after["genesis_state"]))
        self.assertEqual(self.f.service.audit()["classification_events"], 1)

    def test_no_second_graph_state_table(self):
        self.f.migrate()
        self.f.publish(self.f.plan(self.f.assignment()))
        self.assertNotIn("trace_state", self.dump())
        report = self.f.service.audit()
        self.assertEqual(report["events"], report["upstream"]["events"])

    def test_two_phase_retry_returns_original_receipt_only(self):
        self.f.migrate()
        plan = self.f.plan(self.f.assignment())
        receipts = self.f.receipts(plan)
        first = self.f.publish(plan, receipts=receipts)
        before = self.dump()
        again = self.f.publish(plan, receipts=receipts)
        self.assertTrue(again["replayed"])
        self.assertEqual(first["receipt"], again["receipt"])
        self.assertEqual(set(again), {"replayed", "receipt"})
        self.assertEqual(before, self.dump())

    def test_multi_label_snapshot_hydrates_original_source_and_evidence(self):
        f = self.f
        old = f.c.record(f.source), f.c.record(f.evidence)
        f.migrate()
        assignment = f.assignment()
        f.publish(f.plan(assignment))
        new = Catalog()
        snapshot = f.backend.snapshot(new)
        body = new.get(snapshot, "graph-snapshot")
        self.assertEqual(body[PROJECTION_KEY]["assignments"][f.source]["assignment_id"], assignment)
        self.assertEqual(new.get(assignment)["domain_ids"], ["biology", "computing"])
        self.assertEqual(old, (f.c.record(f.source), f.c.record(f.evidence)))
        f.service.audit()

    def test_classification_durable_reopen(self):
        f = self.f
        f.migrate()
        f.publish(f.plan(f.assignment()))
        before = f.backend.state()
        f.backend.close()
        f.backend = PinnedLegacyBackend(f.path, core_path=CORE, legacy_policy=POLICY,
            catalog=f.c, schema_id=f.schema, nodes={}, sandbox=True)
        f.service = f.new_service()
        self.assertEqual(before, f.backend.state())
        self.assertEqual(f.service.audit()["classification_events"], 2)

    def test_reclassification_preserves_earlier_membership(self):
        f = self.f
        f.migrate()
        first = f.assignment(labels=["biology"])
        f.publish(f.plan(first))
        historical = deepcopy(f.journal())
        second = f.assignment(labels=["computing"], supersedes=first)
        f.publish(f.plan(second))
        self.assertEqual(f.journal()[:len(historical)], historical)
        self.assertEqual(f.backend.state()[PROJECTION_KEY]["assignments"][f.source]["assignment_id"], second)
        self.assertEqual(f.c.get(first)["domain_ids"], ["biology"])
        f.service.audit()

    def test_retirement_appends_without_erasing_assignment(self):
        f = self.f
        f.migrate()
        first = f.assignment()
        f.publish(f.plan(first))
        retired = f.assignment(labels=[], state="RETIRED", supersedes=first)
        f.publish(f.plan(retired))
        self.assertEqual(f.c.get(retired)["state"], "RETIRED")
        self.assertEqual(f.c.get(first)["domain_ids"], ["biology", "computing"])
        f.service.audit()

    def test_revoked_source_cannot_publish_after_preflight(self):
        f = self.f
        f.migrate()
        plan = f.plan(f.assignment())
        receipts = f.receipts(plan)
        f.revoke_source()
        before = self.dump()
        with self.assertRaises(ContractError):
            f.publish(plan, receipts=receipts)
        self.assertEqual(before, self.dump())
        f.service.audit()

    def test_unmediated_upstream_write_is_detected(self):
        f = self.f
        f.backend._store.commit(nodes={}, sources=[], facts=[], expected_version=f.backend.state()["graph_version"], key="unmediated")
        with self.assertRaises(ContractError) as cm:
            f.service.audit()
        self.assertEqual(cm.exception.code, "BACKEND_AUDIT")

    def test_tampered_projection_is_detected(self):
        f = self.f
        f.migrate()
        meta = f.backend._meta()
        meta[PROJECTION_KEY]["revision"] += 1
        f.backend.db.execute("UPDATE trace_meta SET body=? WHERE id=1", (dumps(meta),))
        with self.assertRaises(ContractError) as cm:
            f.service.audit()
        self.assertEqual(cm.exception.code, "BACKEND_AUDIT")

    def test_receipt_changed_independently_from_journal_is_detected(self):
        f = self.f
        f.migrate()
        event = f.journal()[-1]
        event["transaction_receipt"]["idempotency_key"] = "forged"
        f.backend.db.execute("UPDATE trace_journal SET body=? WHERE version=?", (dumps(event), event["version"]))
        with self.assertRaises(ContractError) as cm:
            f.service.audit()
        self.assertEqual(cm.exception.code, "BACKEND_AUDIT")

    def test_fault_rollback_and_retry_all_four_boundaries(self):
        f = self.f
        f.migrate()
        plan = f.plan(f.assignment())
        receipts = f.receipts(plan)
        for stage in ("before_state_write", "after_state_write", "after_journal_write", "before_commit"):
            with self.subTest(stage=stage):
                before = self.dump()
                def fault(point):
                    if point == stage:
                        raise RuntimeError("expected-injected-fault")
                with self.assertRaisesRegex(RuntimeError, "expected-injected-fault"):
                    f.publish(plan, receipts=receipts, fault=fault)
                self.assertEqual(before, self.dump())
                f.service.audit()
        self.assertFalse(f.publish(plan, receipts=receipts)["replayed"])
        self.assertEqual(f.service.audit()["classification_events"], 2)

    def test_pinned_adapter_index_and_historical_reclassification(self):
        from trace_gc.retrieval.store import SQLiteGraphAdapter
        from trace_gc.retrieval.contracts import query
        from trace_gc.retrieval.domain_index import source_membership
        from trace_gc.retrieval.security import AccessFilter, access_policy, grant
        f = self.f
        f.migrate()
        first = f.assignment(labels=["biology"])
        f.publish(f.plan(first))
        adapter = SQLiteGraphAdapter(f.backend, classification_trust=f.trust)
        adapter.rebuild_domain_index()
        request = query(requesting_component="downstream-test", security_scope="tenant-a", graph_version=3)
        before = adapter.read(request)
        second = f.assignment(labels=["computing"], supersedes=first)
        f.publish(f.plan(second))
        adapter.rebuild_domain_index()
        historical = adapter.read(request)
        current = adapter.read({**request, "graph_version": None})
        policy = access_policy(tenant="tenant-a", workspace="test", user="reader",
            grants={"source:" + f.source: grant("tenant-a", "test")})
        def membership(view):
            return source_membership(view, f.source, AccessFilter(policy, view.catalog, view.source_status))
        self.assertEqual(before.snapshot, historical.snapshot)
        self.assertEqual(membership(historical)["domain_ids"], ["biology"])
        self.assertEqual(membership(current)["domain_ids"], ["computing"])
        self.assertNotIn("trace_state", self.dump())
        f.service.audit()

    def test_pinned_adapter_revocation_invalidates_history_index(self):
        from trace_gc.retrieval.store import SQLiteGraphAdapter
        from trace_gc.retrieval.contracts import query
        from trace_gc.retrieval.domain_index import source_membership
        from trace_gc.retrieval.security import AccessFilter, access_policy, grant
        f = self.f
        f.migrate()
        f.publish(f.plan(f.assignment()))
        adapter = SQLiteGraphAdapter(f.backend, classification_trust=f.trust)
        adapter.rebuild_domain_index()
        f.revoke_source()
        request = query(requesting_component="downstream-test", security_scope="tenant-a", graph_version=3)
        with self.assertRaises(ContractError) as cm:
            adapter.read(request)
        self.assertEqual(cm.exception.code, "DOMAIN_INDEX_STALE")
        adapter.rebuild_domain_index()
        view = adapter.read(request)
        policy = access_policy(tenant="tenant-a", workspace="test", user="reader",
            grants={"source:" + f.source: grant("tenant-a", "test")})
        self.assertIsNone(source_membership(view, f.source, AccessFilter(policy, view.catalog, view.source_status, historical=True)))
