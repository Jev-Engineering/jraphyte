"""Journal-bound domain reads and derived index tests; no deployment qualification."""
from copy import deepcopy
import unittest

import test_domain_publication as fixtures
from trace_gc.canonical import digest, dumps, loads
from trace_gc.catalog import Catalog
from trace_gc.domain_publication import PROJECTION_KEY
from trace_gc.errors import ContractError
from trace_gc.retrieval.contracts import query
from trace_gc.retrieval.domain_index import source_membership
from trace_gc.retrieval.security import AccessFilter, access_policy, grant
from trace_gc.retrieval.store import SQLiteGraphAdapter, InMemoryGraphAdapter


class DomainReads(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.DomainPublication()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        f = self.f
        self.adapter = SQLiteGraphAdapter(f.backend, classification_trust=f.trust)
        self.policy = access_policy(tenant="tenant-a", workspace="test", user="reader",
            grants={"source:" + f.source: grant("tenant-a", "test")})

    def request(self, version=None, **changes):
        return query(requesting_component="downstream-test", security_scope="tenant-a",
                     graph_version=version, **changes)

    def read(self, version=None):
        return self.adapter.read(self.request(version))

    def membership(self, view, policy=None, *, historical=False):
        acl = AccessFilter(policy or self.policy, view.catalog, view.source_status, historical=historical)
        return source_membership(view, self.f.source, acl)

    def classified(self, labels=None):
        self.f.migrate()
        assignment = self.f.assignment(labels=labels)
        self.f.publish(self.f.plan(assignment))
        self.adapter.rebuild_domain_index()
        return assignment

    def memory(self):
        f = self.f
        catalog = f.backend.load_catalog()
        meta = loads(f.backend.db.execute("SELECT body FROM trace_meta WHERE id=1").fetchone()[0])
        events = f.journal()
        snapshots = []
        for state in [meta["genesis_state"]] + [e["state_after"] for e in events]:
            keys = ("graph_version", "schema_id", "schema_hash", "nodes", "assertions", "source_epochs")
            body = {k: state[k] for k in keys}
            if PROJECTION_KEY in state:
                body[PROJECTION_KEY] = state[PROJECTION_KEY]
            snapshots.append(catalog.put("graph-snapshot", body))
        return InMemoryGraphAdapter(catalog, snapshots, f.backend.statuses(), events,
            classification_trust=f.trust, genesis_state=meta["genesis_state"], sandbox=True)

    def assert_error(self, code, fn):
        with self.assertRaises(ContractError) as cm:
            fn()
        self.assertEqual(cm.exception.code, code)

    def test_legacy_unclassified_read_needs_no_index(self):
        view = self.read()
        self.assertEqual(self.membership(view)["state"], "UNCLASSIFIED")
        self.assertEqual(view.classification_revision, 0)
        self.assertNotIn(PROJECTION_KEY, view.snapshot)

    def test_pre_admission_snapshot_does_not_invent_membership(self):
        view = self.read(0)
        self.assertIsNone(self.membership(view))

    def test_migration_requires_explicit_index_rebuild(self):
        self.f.migrate()
        self.assert_error("DOMAIN_INDEX_STALE", self.read)
        report = self.adapter.rebuild_domain_index()
        self.assertEqual(report["row_count"], 0)
        self.assertEqual(report["graph_commits"], 0)
        self.assertEqual(self.membership(self.read())["state"], "UNCLASSIFIED")

    def test_multilabel_membership_uses_exact_assignment_revision(self):
        assignment = self.classified()
        view = self.read()
        membership = self.membership(view)
        self.assertEqual(membership["assignment_id"], assignment)
        self.assertEqual(membership["assignment_revision"], 1)
        self.assertEqual(membership["taxonomy_hash"], self.f.c.hash(self.f.tax))
        self.assertEqual(membership["domain_ids"], ["biology", "computing"])
        self.assertEqual({row[-1] for row in view.domain_index_rows}, {"biology", "computing"})

    def test_reference_memory_current_and_historical_agree(self):
        self.classified()
        memory = self.memory()
        for version in range(self.f.backend.state()["graph_version"] + 1):
            with self.subTest(version=version):
                sql, mem = self.read(version), memory.read(self.request(version))
                self.assertEqual(sql.snapshot, mem.snapshot)
                self.assertEqual(sql.classification_identity, mem.classification_identity)
                self.assertEqual(self.membership(sql), self.membership(mem))
                self.assertEqual(sql.domain_index_rows or [], mem.domain_index_rows or [])

    def test_reclassification_changes_current_identity_not_old_snapshot(self):
        first = self.classified(["biology"])
        old = self.read(3)
        current = self.read()
        before_hashes = [self.f.c.hash(ref) for ref in (self.f.source, self.f.evidence)]
        second = self.f.assignment(labels=["computing"], supersedes=first)
        self.f.publish(self.f.plan(second))
        self.assert_error("DOMAIN_INDEX_STALE", self.read)
        self.adapter.rebuild_domain_index()
        after = self.read()
        self.assertNotEqual(current.identity, after.identity)
        self.assertEqual(old.identity, self.read(3).identity)
        self.assertEqual(old.snapshot, self.read(3).snapshot)
        self.assertEqual(self.membership(after)["domain_ids"], ["computing"])
        self.assertEqual(self.membership(self.read(3))["domain_ids"], ["biology"])
        self.assertEqual(before_hashes, [self.f.c.hash(ref) for ref in (self.f.source, self.f.evidence)])

    def test_reference_memory_reclassified_agree(self):
        first = self.classified(["biology"])
        second = self.f.assignment(labels=["computing"], supersedes=first)
        self.f.publish(self.f.plan(second))
        self.adapter.rebuild_domain_index()
        memory = self.memory()
        for version in (2, 3, 4):
            with self.subTest(version=version):
                self.assertEqual(self.membership(self.read(version)), self.membership(memory.read(self.request(version))))

    def test_reference_memory_explicit_unclassified_agree(self):
        self.f.migrate()
        assignment = self.f.assignment(labels=[], state="UNCLASSIFIED")
        self.f.publish(self.f.plan(assignment))
        self.adapter.rebuild_domain_index()
        sql, mem = self.read(), self.memory().read(self.request())
        self.assertEqual(self.membership(sql), self.membership(mem))
        self.assertEqual(self.membership(sql)["state"], "UNCLASSIFIED")
        self.assertEqual(self.membership(sql)["assignment_id"], assignment)

    def test_retired_assignment_has_no_active_labels(self):
        first = self.classified()
        retired = self.f.assignment(labels=[], state="RETIRED", supersedes=first)
        self.f.publish(self.f.plan(retired))
        self.adapter.rebuild_domain_index()
        self.assertEqual(self.membership(self.read())["state"], "RETIRED")
        self.assertEqual(self.membership(self.read())["domain_ids"], [])
        self.assertEqual(self.membership(self.read(3))["domain_ids"], ["biology", "computing"])

    def test_source_revocation_applies_to_historical_reads_in_both_adapters(self):
        self.classified()
        self.f.revoke_source()
        self.adapter.rebuild_domain_index()
        memory = self.memory()
        for version in (2, 3, 4):
            with self.subTest(version=version):
                for view in (self.read(version), memory.read(self.request(version))):
                    self.assertIsNone(self.membership(view, historical=True))
                    acl = AccessFilter(self.policy, view.catalog, view.source_status, historical=True)
                    self.assertFalse(acl.evidence(self.f.evidence))

    def test_inactive_but_read_source_is_denied_in_historical_mode(self):
        self.classified()
        view = self.read()
        view.source_status[self.f.source]["active"] = False
        self.assertIsNone(self.membership(view, historical=True))
        acl = AccessFilter(self.policy, view.catalog, view.source_status, historical=True)
        self.assertFalse(acl.evidence(self.f.evidence))

    def test_tombstone_applies_to_historical_read(self):
        self.classified()
        self.f.revoke_source(tombstone=True)
        self.adapter.rebuild_domain_index()
        self.assertIsNone(self.membership(self.read(3), historical=True))

    def test_labels_never_grant_access(self):
        self.classified()
        no_grants = access_policy(tenant="tenant-a", workspace="test", user="reader")
        self.assertIsNone(self.membership(self.read(), no_grants))

    def test_wrong_tenant_is_denied_before_membership(self):
        self.classified()
        other = access_policy(tenant="other", workspace="test", user="reader",
            grants={"source:" + self.f.source: grant("other", "test")})
        self.assertIsNone(self.membership(self.read(), other))

    def test_current_read_requires_enrolled_classification_trust(self):
        self.classified()
        self.assert_error("DOMAIN_TRUST_REQUIRED", lambda: SQLiteGraphAdapter(self.f.backend).read(self.request()))

    def test_memory_requires_journal_origin_for_domain_snapshot(self):
        self.classified()
        memory = self.memory()
        memory.genesis_state = None
        self.assert_error("DOMAIN_TRUST_REQUIRED", lambda: memory.read(self.request()))

    def test_memory_cannot_invent_or_remove_membership(self):
        self.classified()
        memory = self.memory()
        latest = memory.snapshot_ids[-1]
        body = memory.catalog.get(latest, "graph-snapshot")
        body.pop(PROJECTION_KEY)
        memory.snapshot_ids[-1] = memory.catalog.put("graph-snapshot", body)
        self.assert_error("DOMAIN_SNAPSHOT_BINDING", lambda: memory.read(self.request()))

    def test_memory_rejects_stale_current_source_status(self):
        self.classified()
        memory = self.memory()
        memory.source_status[self.f.source]["epoch"] += 1
        self.assert_error("DOMAIN_SOURCE_STATUS", lambda: memory.read(self.request()))

    def test_reviewed_but_unpublished_assignment_does_not_become_membership(self):
        self.f.migrate()
        unpublished = self.f.assignment()
        self.adapter = SQLiteGraphAdapter(self.f.backend, self.f.c, classification_trust=self.f.trust)
        self.adapter.rebuild_domain_index()
        view = self.read()
        self.assertIn(unpublished, view.catalog)
        self.assertIsNone(self.membership(view)["assignment_id"])
        self.assertEqual(self.membership(view)["state"], "UNCLASSIFIED")

    def test_tampered_index_rows_fail_even_after_attacker_rehashes_metadata(self):
        self.classified()
        db = self.f.backend.db
        db.execute("UPDATE trace_domain_index SET domain_id='chemistry' WHERE domain_id='biology'")
        rows = sorted(db.execute("SELECT * FROM trace_domain_index").fetchall())
        meta = loads(db.execute("SELECT body FROM trace_domain_index_meta").fetchone()[0])
        meta["rows_hash"] = digest([list(row) for row in rows])
        db.execute("UPDATE trace_domain_index_meta SET body=?", (dumps(meta),))
        self.assert_error("DOMAIN_INDEX_STALE", self.read)
        self.adapter.rebuild_domain_index()
        self.assertEqual(self.membership(self.read())["domain_ids"], ["biology", "computing"])

    def test_deleted_index_row_fails_and_rebuilds(self):
        self.classified()
        self.f.backend.db.execute("DELETE FROM trace_domain_index WHERE domain_id='biology'")
        self.assert_error("DOMAIN_INDEX_STALE", self.read)
        self.adapter.rebuild_domain_index()
        self.assertEqual(len(self.read().domain_index_rows), 2)

    def test_rebuild_changes_no_authoritative_state_or_journal(self):
        self.classified()
        before = self.f.dump()
        self.adapter.rebuild_domain_index()
        self.assertEqual(before, self.f.dump())

    def test_rebuild_rollback_all_fault_points(self):
        self.classified()
        db = self.f.backend.db
        before = db.execute("SELECT * FROM trace_domain_index ORDER BY 1,2,9").fetchall()
        meta = db.execute("SELECT * FROM trace_domain_index_meta").fetchall()
        for point in ("after_index_delete", "after_index_rows", "before_index_commit"):
            with self.subTest(point=point):
                def fault(stage):
                    if point == stage:
                        raise RuntimeError("expected index fault")
                with self.assertRaisesRegex(RuntimeError, "expected index fault"):
                    self.adapter.rebuild_domain_index(fault=fault)
                self.assertEqual(before, db.execute("SELECT * FROM trace_domain_index ORDER BY 1,2,9").fetchall())
                self.assertEqual(meta, db.execute("SELECT * FROM trace_domain_index_meta").fetchall())
                self.read()

    def test_future_snapshot_rejected(self):
        self.assert_error("GRAPH_VERSION_UNAVAILABLE", lambda: self.read(999))

    def test_historical_timestamp_selects_exact_domain_revision(self):
        first = self.classified(["biology"])
        instant = self.f.journal()[-1]["committed_at"]
        second = self.f.assignment(labels=["computing"], supersedes=first)
        self.f.publish(self.f.plan(second))
        self.adapter.rebuild_domain_index()
        view = self.adapter.read(self.request(temporal_scope={"as_of": instant, "valid_at": None, "before_source": None}))
        self.assertEqual(view.snapshot["graph_version"], 3)
        self.assertEqual(self.membership(view)["domain_ids"], ["biology"])
