"""Reference read projections: authority parity, current revocation and index tampering."""
from copy import deepcopy
import tempfile
import unittest

from trace_gc.canonical import digest, dumps, loads
from trace_gc.catalog import Catalog
from trace_gc.domain_publication import snapshot_body
from trace_gc.errors import ContractError
from trace_gc.retrieval.contracts import query
from trace_gc.retrieval.fixtures import demo_access
from trace_gc.retrieval.security import AccessFilter
from trace_gc.retrieval.service import HybridRetriever
from trace_gc.retrieval.store import GraphReadView, InMemoryGraphAdapter, SQLiteGraphAdapter
from test_research_domain_transactions import DomainFixture


class DomainReadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.f = DomainFixture(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(self.f.close)
        self.adapter = SQLiteGraphAdapter(self.f.backend, audit_trust=self.f.trust)

    def request(self, **changes):
        return query(requesting_component="domain-read-test", security_scope="test", text="Synthetic", strategies=["SOURCE"], **changes)

    def access(self, view, **changes):
        policy = demo_access(view.catalog, view.snapshot_id, scope="test")
        policy.update(changes)
        return AccessFilter(policy, view.catalog, view.source_status, historical=True)

    def events(self):
        return [loads(r[0]) for r in self.f.backend.db.execute("SELECT body FROM trace_journal ORDER BY version")]

    def parity(self, **changes):
        sql = self.adapter.read(self.request(**changes))
        c = self.f.backend.load_catalog()
        snapshots = [c.put("graph-snapshot", snapshot_body(e["state_after"])) for e in self.events()]
        mem = InMemoryGraphAdapter(c, snapshots, self.f.backend.statuses(), self.events()).read(self.request(**changes))
        self.assertEqual(sql.snapshot, mem.snapshot)
        self.assertEqual(sql.classification_rows, mem.classification_rows)
        self.assertEqual(sql.classification_identity, mem.classification_identity)
        self.assertEqual(sql.source_classification(self.f.source, self.access(sql)),
                         mem.source_classification(self.f.source, self.access(mem)))
        return sql

    def test_old_unmigrated_source_is_explicitly_unclassified_without_rewrite(self):
        state = self.f.backend.state()
        v = self.parity()
        self.assertEqual(v.classification_identity["revision"], 0)
        self.assertFalse(v.classification_identity["migrated"])
        self.assertEqual(v.classification_rows[self.f.source]["reason"], "NO_REVIEWED_ASSIGNMENT")
        self.assertEqual(self.f.backend.state(), state)
        self.assertNotIn("classifications", state)

    def test_empty_migrated_projection(self):
        self.f.migrate()
        v = self.parity()
        self.assertEqual(v.classification_identity["revision"], 1)
        self.assertIsNone(v.classification_rows[self.f.source]["assignment_id"])

    def test_multi_domain_current_and_historical_parity(self):
        self.f.migrate()
        first = self.f.assign(["research:biology", "research:chemistry"])
        e = self.f.publish(self.f.assignment_plan(first))
        current = self.parity()
        self.assertEqual(current.classification_rows[self.f.source]["domain_ids"], ["research:biology", "research:chemistry"])
        second = self.f.assign(["research:physics"], previous=first)
        self.f.publish(self.f.assignment_plan(second))
        self.assertEqual(self.parity().classification_rows[self.f.source]["assignment_id"], second)
        historical = self.parity(graph_version=e["receipt"]["version"])
        self.assertEqual(historical.classification_rows[self.f.source]["assignment_id"], first)
        self.assertEqual(historical.snapshot_id, current.snapshot_id)
        self.assertEqual(historical.classification_identity, current.classification_identity)

    def test_explicit_unclassified_and_retired_are_distinguishable(self):
        self.f.migrate()
        first = self.f.assign([])
        self.f.publish(self.f.assignment_plan(first))
        v = self.parity()
        self.assertEqual(v.classification_rows[self.f.source]["status"], "UNCLASSIFIED")
        self.assertEqual(v.classification_rows[self.f.source]["reason"], "ASSIGNED")
        second = self.f.assign([], previous=first, status="RETIRED")
        self.f.publish(self.f.assignment_plan(second))
        self.assertEqual(self.parity().classification_rows[self.f.source]["status"], "RETIRED")

    def test_current_withdrawal_overrides_historical_classification(self):
        self.f.migrate()
        first = self.f.assign()
        e = self.f.publish(self.f.assignment_plan(first))
        self.f.status_change(active=False, permission="READ")
        v = self.parity(graph_version=e["receipt"]["version"])
        self.assertEqual(v.classification_rows[self.f.source]["assignment_id"], first)
        self.assertIsNone(v.source_classification(self.f.source, self.access(v)))
        self.assertFalse(self.access(v).evidence(self.f.evidence))

    def test_current_acl_overrides_historical_assignment(self):
        self.f.migrate()
        self.f.publish(self.f.assignment_plan(self.f.assign()))
        v = self.adapter.read(self.request(graph_version=self.f.backend.state()["graph_version"]))
        access = self.access(v)
        del access.policy["grants"]["source:" + self.f.source]
        self.assertIsNone(v.source_classification(self.f.source, access))

    def test_current_denied_or_tombstone_status_overrides_history(self):
        self.f.migrate()
        e = self.f.publish(self.f.assignment_plan(self.f.assign()))
        self.f.status_change(active=False, permission="DENIED", tombstone=True)
        v = self.parity(graph_version=e["receipt"]["version"])
        self.assertIsNone(v.source_classification(self.f.source, self.access(v)))
        self.assertFalse(self.access(v).evidence(self.f.evidence))

    def test_erasure_explicitly_reports_unavailable_history(self):
        self.f.migrate()
        self.f.publish(self.f.assignment_plan(self.f.assign()))
        self.f.status_change(active=False, permission="DENIED", tombstone=True)
        self.f.backend.erase_cached_content(self.f.source, reason="synthetic erasure")
        with self.assertRaises(ContractError) as caught:
            self.adapter.read(self.request(graph_version=1))
        self.assertEqual(caught.exception.code, "REPLAY_CONTENT_UNAVAILABLE")

    def test_uncommitted_working_catalog_cannot_invent_membership(self):
        self.f.migrate()
        pending = self.f.assign()
        adapter = SQLiteGraphAdapter(self.f.backend, self.f.catalog, audit_trust=self.f.trust)
        v = adapter.read(self.request())
        self.assertIn(pending, v.catalog)
        self.assertIsNone(v.classification_rows[self.f.source]["assignment_id"])
        self.assertEqual(v.classification_rows[self.f.source]["domain_ids"], [])

    def corrupt(self, sql, params=()):
        self.f.backend.db.execute(sql, params)
        with self.assertRaises(ContractError) as caught:
            self.adapter.read(self.request())
        self.assertEqual(caught.exception.code, "DOMAIN_INDEX_CORRUPT")

    def test_tampered_membership_fails_closed(self):
        v = self.adapter.read(self.request())
        self.corrupt("UPDATE trace_domain_index_membership SET domain_id='research:physics' WHERE snapshot_hash=?",
                     (v.catalog.hash(v.snapshot_id),))

    def test_tampered_source_projection_fails_closed(self):
        v = self.adapter.read(self.request())
        row = deepcopy(v.classification_rows[self.f.source]); row["domain_ids"] = ["research:physics"]
        self.corrupt("UPDATE trace_domain_index_sources SET body=? WHERE source_id=?", (dumps(row), self.f.source))

    def test_tampered_header_fails_closed(self):
        self.adapter.read(self.request())
        self.corrupt("UPDATE trace_domain_index_meta SET projection_hash=?", ("0" * 64,))

    def test_orphaned_index_rows_fail_closed(self):
        self.adapter.read(self.request())
        self.corrupt("DELETE FROM trace_domain_index_meta")

    def test_self_consistent_forged_index_is_not_authority(self):
        v = self.adapter.read(self.request())
        forged = deepcopy(v.classification_rows)
        forged[self.f.source]["domain_ids"] = ["research:physics"]
        db = self.f.backend.db
        db.execute("UPDATE trace_domain_index_sources SET body=?", (dumps(forged[self.f.source]),))
        db.execute("UPDATE trace_domain_index_membership SET domain_id='research:physics'")
        self.corrupt("UPDATE trace_domain_index_meta SET rows_hash=?", (digest(forged),))

    def test_explicit_rebuild_preserves_all_authority_and_history(self):
        v = self.adapter.read(self.request())
        db = self.f.backend.db
        history = list(db.execute("SELECT * FROM trace_journal"))
        state = self.f.backend.state()
        db.execute("UPDATE trace_domain_index_membership SET domain_id='research:physics'")
        rebuilt = self.adapter.rebuild_classification_index(self.request())
        self.assertEqual(rebuilt.classification_rows, v.classification_rows)
        self.assertEqual(self.f.backend.state(), state)
        self.assertEqual(list(db.execute("SELECT * FROM trace_journal")), history)
        self.assertEqual(self.adapter.read(self.request()).identity, rebuilt.identity)

    def test_new_snapshot_gets_new_index_not_stale_membership(self):
        v = self.adapter.read(self.request())
        self.f.migrate()
        self.f.publish(self.f.assignment_plan(self.f.assign()))
        after = self.adapter.read(self.request())
        self.assertNotEqual(v.identity, after.identity)
        self.assertNotEqual(v.classification_identity, after.classification_identity)
        self.assertTrue(after.read_metrics["built"])
        self.assertFalse(self.adapter.read(self.request()).read_metrics["built"])
        self.assertEqual(self.adapter.read(self.request(graph_version=1)).classification_rows, v.classification_rows)

    def test_reclassification_invalidates_retrieval_cache(self):
        self.f.migrate()
        before = self.adapter.read(self.request())
        r = HybridRetriever(self.adapter, catalog=self.f.catalog,
                            access_policy=demo_access(before.catalog, before.snapshot_id, scope="test"))
        q = self.request()
        r.retrieve(q); r.retrieve(q)
        self.assertGreater(r.cache.hits, 0)
        self.f.publish(self.f.assignment_plan(self.f.assign()))
        previous_misses = r.cache.misses
        r.retrieve(q)
        self.assertGreater(r.cache.misses, previous_misses)
        self.assertGreater(r.cache.invalidations, 0)

    def test_memory_snapshot_must_agree_with_event(self):
        self.f.migrate()
        self.f.publish(self.f.assignment_plan(self.f.assign()))
        v = self.adapter.read(self.request())
        wrong = deepcopy(v.snapshot)
        wrong["classifications"]["assignments"] = {}
        other = v.catalog.put("graph-snapshot", wrong)
        with self.assertRaises(ContractError) as caught:
            InMemoryGraphAdapter(v.catalog, [other], v.source_status, self.events()).read(self.request())
        self.assertEqual(caught.exception.code, "SNAPSHOT_BINDING")

    def test_forged_read_projection_is_rejected(self):
        v = self.adapter.read(self.request())
        with self.assertRaises(ContractError) as caught:
            GraphReadView(v.catalog, v.snapshot_id, v.source_status, v.available_record_ids, v.events, "untrusted",
                          classification_rows={})
        self.assertEqual(caught.exception.code, "DOMAIN_INDEX_CORRUPT")
