"""Journal/index parity and current authorization tests using normal imports."""
from copy import deepcopy
import unittest

from trace_gc.canonical import digest, dumps, loads
from trace_gc.catalog import Catalog
from trace_gc.errors import ContractError
from trace_gc.retrieval.contracts import query
from trace_gc.retrieval.domain_projection import projection, snapshot_body, verify_history
from trace_gc.retrieval.store import SQLiteGraphAdapter, InMemoryGraphAdapter
from trace_gc.retrieval.security import AccessFilter, access_policy, grant
import test_domain_publication as fixtures


class DomainReads(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.DomainPublication('test_migration_is_append_only_and_unclassified')
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.a = SQLiteGraphAdapter(self.f.backend, trust=self.f.trust)
        self.f.migrate()
        self.first = self.f.assignment(labels=['biology'])
        self.f.publish(self.f.plan(self.first))
        self.a.rebuild_domain_index()

    def q(self, **kw):
        return query(requesting_component='downstream-search', security_scope='tenant-a', **kw)

    def state(self, view):
        return view.research_domains['source_assignments'][self.f.source]

    def memory(self):
        f = self.f
        c = f.backend.load_catalog()
        genesis = loads(f.backend.db.execute('SELECT body FROM trace_meta').fetchone()[0])['genesis_state']
        events = f.journal()
        ids = [c.put('graph-snapshot', snapshot_body(genesis))]
        ids += [c.put('graph-snapshot', snapshot_body(e['state_after'])) for e in events]
        return InMemoryGraphAdapter(c, ids, f.backend.statuses(), events, trust=f.trust,
                                    genesis_state=genesis, sandbox=True)

    def test_current_projection_is_exact_committed_assignment(self):
        v = self.a.read(self.q())
        self.assertEqual(self.state(v)['assignment_id'], self.first)
        self.assertEqual(self.state(v)['domain_ids'], ['biology'])
        self.assertEqual(v.domain_index, {'biology': [self.f.source]})
        self.assertEqual(v.research_domains['classification_revision'], 2)

    def test_old_versions_remain_unclassified(self):
        for version in (1, 2):
            with self.subTest(version=version):
                self.assertEqual(self.state(self.a.read(self.q(graph_version=version)))['state'], 'UNCLASSIFIED')

    def test_memory_sqlite_parity_all_versions(self):
        m = self.memory()
        for version in range(4):
            with self.subTest(version=version):
                a, b = self.a.read(self.q(graph_version=version)), m.read(self.q(graph_version=version))
                self.assertEqual(a.snapshot, b.snapshot)
                self.assertEqual(a.research_domains, b.research_domains)
                self.assertEqual(a.source_status, b.source_status)

    def test_reclassification_preserves_history_and_changes_identity(self):
        before = self.a.read(self.q())
        second = self.f.assignment(labels=['computing'], supersedes=self.first)
        self.f.publish(self.f.plan(second))
        after = self.a.read(self.q())
        self.assertNotEqual(before.identity, after.identity)
        self.assertEqual(self.state(after)['domain_ids'], ['computing'])
        self.assertEqual(self.state(self.a.read(self.q(graph_version=3)))['domain_ids'], ['biology'])
        self.assertEqual(before.snapshot, self.a.read(self.q(graph_version=3)).snapshot)

    def test_retirement_is_explicit_without_losing_provenance(self):
        second = self.f.assignment(labels=[], state='RETIRED', supersedes=self.first)
        self.f.publish(self.f.plan(second))
        self.a.rebuild_domain_index()
        v = self.a.read(self.q())
        self.assertEqual(self.state(v)['state'], 'RETIRED')
        self.assertEqual(self.state(v)['assignment_id'], second)
        self.assertEqual(v.domain_index, {})

    def test_multilabel_index(self):
        second = self.f.assignment(labels=['biology','computing'], supersedes=self.first)
        self.f.publish(self.f.plan(second))
        self.a.rebuild_domain_index()
        v = self.a.read(self.q())
        self.assertEqual(v.domain_index, {'biology':[self.f.source], 'computing':[self.f.source]})

    def test_stale_row_rejected_and_explicit_repair(self):
        before = self.f.backend.audit()
        self.f.backend.db.execute("UPDATE trace_domain_index SET domain_id='invented' WHERE graph_version=3")
        with self.assertRaisesRegex(ContractError, 'DOMAIN_INDEX_STALE'):
            self.a.read(self.q())
        self.a.rebuild_domain_index()
        self.assertEqual(before, self.f.backend.audit())
        self.assertEqual(self.state(self.a.read(self.q()))['domain_ids'], ['biology'])

    def test_forged_header_cannot_bless_forged_rows(self):
        db = self.f.backend.db
        db.execute("UPDATE trace_domain_index SET domain_id='invented' WHERE graph_version=3")
        db.execute("UPDATE trace_domain_index_heads SET rows_hash=? WHERE graph_version=3", ('f'*64,))
        with self.assertRaisesRegex(ContractError, 'DOMAIN_INDEX_STALE'):
            self.a.read(self.q())

    def test_missing_index_fails_closed(self):
        self.f.backend.db.execute('DROP TABLE trace_domain_index')
        with self.assertRaisesRegex(ContractError, 'DOMAIN_INDEX_UNAVAILABLE'):
            self.a.read(self.q())

    def test_removed_index_row_fails_closed(self):
        self.f.backend.db.execute('DELETE FROM trace_domain_index WHERE graph_version=3')
        with self.assertRaisesRegex(ContractError, 'DOMAIN_INDEX_STALE'):
            self.a.read(self.q())

    def test_added_index_row_fails_closed(self):
        self.f.backend.db.execute("INSERT INTO trace_domain_index VALUES(3,'fake','','','','','',0,'UNCLASSIFIED','')")
        with self.assertRaisesRegex(ContractError, 'DOMAIN_INDEX_STALE'):
            self.a.read(self.q())

    def test_repair_rollback_does_not_damage_authority(self):
        before = self.f.dump()
        self.f.backend.db.execute("CREATE TRIGGER block_rebuild BEFORE INSERT ON trace_domain_index BEGIN SELECT RAISE(ABORT,'fault'); END")
        with self.assertRaisesRegex(Exception, 'fault'):
            self.a.rebuild_domain_index()
        self.assertEqual(before, self.f.dump())
        self.assertEqual(self.state(self.a.read(self.q()))['domain_ids'], ['biology'])

    def test_missing_trust_is_not_a_membership_shortcut(self):
        with self.assertRaisesRegex(ContractError, 'DOMAIN_TRUST_REQUIRED'):
            SQLiteGraphAdapter(self.f.backend).read(self.q())

    def test_revoked_reviewer_rejected_on_historical_read(self):
        self.f.trust.revoke('reviewer')
        with self.assertRaisesRegex(ContractError, 'UNTRUSTED_ISSUER'):
            self.a.read(self.q(graph_version=3))

    def test_missing_journal_on_memory_projection_rejected(self):
        m = self.memory()
        m.events = []
        with self.assertRaisesRegex(ContractError, 'DOMAIN_HISTORY_REQUIRED'):
            m.read(self.q())

    def test_memory_journal_tampering_rejected(self):
        m = self.memory()
        m.events[-1]['state_after']['research_domains']['revision'] += 1
        with self.assertRaisesRegex(ContractError, 'DOMAIN_HISTORY'):
            m.read(self.q())

    def test_memory_forged_snapshot_rejected(self):
        m = self.memory()
        snap = m.catalog.get(m.snapshot_ids[-1])
        snap['research_domains']['assignments'] = {}
        m.snapshot_ids[-1] = m.catalog.put('graph-snapshot', snap)
        with self.assertRaisesRegex(ContractError, 'DOMAIN_SNAPSHOT_BINDING'):
            m.read(self.q())

    def test_memory_projection_cannot_be_downgraded_away(self):
        m = self.memory()
        snap = m.catalog.get(m.snapshot_ids[-1]); snap.pop('research_domains')
        m.snapshot_ids[-1] = m.catalog.put('graph-snapshot', snap)
        with self.assertRaisesRegex(ContractError, 'DOMAIN_SNAPSHOT_BINDING'):
            m.read(self.q())

    def test_current_revocation_changes_identity_of_old_snapshot(self):
        before = self.a.read(self.q(graph_version=3))
        self.f.revoke_source()
        self.a.rebuild_domain_index()
        after = self.a.read(self.q(graph_version=3))
        self.assertEqual(before.snapshot, after.snapshot)
        self.assertNotEqual(before.identity, after.identity)
        policy = access_policy(tenant='tenant-a',workspace='test',user='reader',grants={
            'source:'+self.f.source:grant('tenant-a','test')})
        self.assertFalse(AccessFilter(policy, after.catalog, after.source_status, historical=True).evidence(self.f.evidence))

    def test_inactive_read_permission_alone_does_not_restore_history(self):
        v = self.a.read(self.q(graph_version=3))
        statuses = deepcopy(v.source_status)
        statuses[self.f.source].update(active=False,permission='READ')
        policy = access_policy(tenant='tenant-a',workspace='test',user='reader',grants={
            'source:'+self.f.source:grant('tenant-a','test')})
        self.assertFalse(AccessFilter(policy,v.catalog,statuses,historical=True).evidence(self.f.evidence))

    def test_old_database_without_migration_still_reads(self):
        # Genuine pre-migration state selected from the original journal.
        self.assertNotIn('research_domains', self.a.read(self.q(graph_version=1)).snapshot)

    def test_tombstone_history_still_denied(self):
        self.f.revoke_source(tombstone=True)
        self.a.rebuild_domain_index()
        self.assertTrue(self.a.read(self.q(graph_version=3)).source_status[self.f.source]['tombstone'])

    def test_read_does_not_write_graph_or_index(self):
        before = list(self.f.backend.db.iterdump())
        self.a.read(self.q())
        self.assertEqual(before,list(self.f.backend.db.iterdump()))

    def test_bad_graph_state_is_not_blessed_by_rebuild(self):
        state=self.f.backend.state();state['nodes']['fake']='Thing'
        self.f.backend.db.execute('UPDATE trace_state SET body=?',(dumps(state),))
        with self.assertRaisesRegex(ContractError,'BACKEND_AUDIT'):
            self.a.rebuild_domain_index()

    def test_snapshot_projection_deep_copy(self):
        v = self.a.read(self.q()); p = v.research_domains
        p['source_assignments'][self.f.source]['domain_ids'].append('fake')
        self.assertEqual(self.state(v)['domain_ids'], ['biology'])

    def test_as_of_selects_exact_revision(self):
        stamp = self.f.journal()[1]['committed_at']
        view = self.a.read(self.q(temporal_scope={'as_of':stamp,'valid_at':None,'before_source':None}))
        self.assertEqual(view.snapshot['graph_version'],2)
        self.assertEqual(self.state(view)['state'],'UNCLASSIFIED')

    def test_future_version_is_unavailable(self):
        with self.assertRaisesRegex(ContractError,'GRAPH_VERSION_UNAVAILABLE'):
            self.a.read(self.q(graph_version=999))

    def test_ambiguous_memory_versions_fail(self):
        m=self.memory();s=m.catalog.get(m.snapshot_ids[-1]);s['nodes']['extra']='Thing'
        m.snapshot_ids.append(m.catalog.put('graph-snapshot',s))
        with self.assertRaisesRegex(ContractError,'GRAPH_VERSION_AMBIGUOUS'):
            m.read(self.q())

    def test_proposal_in_working_catalog_does_not_change_membership(self):
        self.f.assignment(labels=['computing'],supersedes=self.first)
        v=SQLiteGraphAdapter(self.f.backend,self.f.c,trust=self.f.trust).read(self.q())
        self.assertEqual(self.state(v)['assignment_id'],self.first)

    def test_sql_uses_composite_domain_lookup_index(self):
        plan=self.f.backend.db.execute("EXPLAIN QUERY PLAN SELECT source_id FROM trace_domain_index WHERE graph_version=? AND domain_id=?",(3,'biology')).fetchall()
        self.assertTrue(any('trace_domain_lookup' in row[-1] for row in plan))

    def test_index_update_rolls_back_with_publication_at_all_fault_points(self):
        a=self.f.assignment(labels=['computing'],supersedes=self.first)
        p=self.f.plan(a)
        receipts=self.f.receipts(p)
        before=list(self.f.backend.db.iterdump())
        for fault_point in ('before_state_write','after_state_write','after_journal_write','before_commit'):
            def fail(point):
                if point==fault_point:raise RuntimeError('index rollback fault')
            with self.subTest(point=fault_point),self.assertRaisesRegex(RuntimeError,'index rollback fault'):
                self.f.publish(p,receipts=receipts,fault=fail)
            self.assertEqual(before,list(self.f.backend.db.iterdump()))
        self.f.publish(p,receipts=receipts)
        self.assertEqual(self.state(self.a.read(self.q()))['domain_ids'],['computing'])

    def test_source_change_updates_index_version_atomically(self):
        self.f.revoke_source()
        v=self.a.read(self.q())
        self.assertEqual(v.snapshot['graph_version'],4)
        self.assertEqual(v.source_status[self.f.source]['permission'],'DENIED')
