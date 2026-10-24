"""Exact-byte pinned legacy integration; synthetic data, no deployed authority.

Set TRACE_GC_LEGACY_CORE to the reviewed file. Missing input is an explicit skip;
a wrong file fails before any import. No substitute source is generated here.
"""
from copy import deepcopy
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from trace_gc.canonical import dumps, loads
from trace_gc.domain_publication import PROJECTION_KEY
from trace_gc.errors import ContractError
from trace_gc.legacy import PinnedLegacyBackend, load_pinned_core
from trace_gc.retrieval.contracts import query
from trace_gc.retrieval.store import SQLiteGraphAdapter
import test_domain_publication as fixtures


def factory(path, **kwargs):
    return PinnedLegacyBackend(path, core_path=os.environ['TRACE_GC_LEGACY_CORE'],
        legacy_policy={'version':'domain-conformance-test-v1', 'thresholds':{'related':.9},
            'contracts':{'related':['YES','NO']}, 'allowed_modes':['synthetic']}, **kwargs)


class DomainLegacy(unittest.TestCase):
    def setUp(self):
        if not os.environ.get('TRACE_GC_LEGACY_CORE'):
            self.skipTest('Exact pinned upstream source not supplied: TRACE_GC_LEGACY_CORE')
        load_pinned_core(os.environ['TRACE_GC_LEGACY_CORE'])
        self.f = fixtures.DomainPublication('test_migration_is_append_only_and_unclassified')
        with patch.object(fixtures, 'BACKEND_FACTORY', factory):
            self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.f.dump = self.dump

    def dump(self):
        db = self.f.backend.db
        tables = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        return {name:db.execute(f'SELECT * FROM "{name}" ORDER BY 1').fetchall() for name in tables}

    def q(self, **changes):
        return query(requesting_component='downstream-search', security_scope='tenant-a', **changes)

    def test_no_second_graph_authority(self):
        f=self.f; f.migrate(); a=f.assignment(); f.publish(f.plan(a))
        self.assertIsNone(f.backend.db.execute("SELECT name FROM sqlite_master WHERE name='trace_state'").fetchone())
        self.assertEqual(f.backend._store.audit()['events'], f.service.audit()['events'])
        self.assertEqual(f.backend._store.snapshot()['version'], f.backend.state()['graph_version'])
        for event in f.journal():
            row=f.backend.db.execute('SELECT hash FROM journal WHERE version=?',(event['version'],)).fetchone()
            self.assertEqual(row[0], event['upstream_journal_hash'])

    def test_migration_preserves_old_genesis_and_journals(self):
        f=self.f; before=self.dump(); meta=loads(before['trace_meta'][0][1])
        source,evidence=f.c.record(f.source),f.c.record(f.evidence)
        f.migrate(); after=self.dump(); current=loads(after['trace_meta'][0][1])
        self.assertEqual(meta['genesis_state'],current['genesis_state'])
        self.assertEqual(meta['genesis_hash'],current['genesis_hash'])
        self.assertEqual(before['journal'],after['journal'][:len(before['journal'])])
        self.assertEqual(before['trace_journal'],after['trace_journal'][:len(before['trace_journal'])])
        self.assertEqual(f.backend.state()[PROJECTION_KEY]['assignments'],{})
        self.assertEqual(source,f.c.record(f.source));self.assertEqual(evidence,f.c.record(f.evidence))

    def test_index_history_and_reclassification(self):
        f=self.f; f.migrate(); a=f.assignment(labels=['biology']); f.publish(f.plan(a))
        adapter=SQLiteGraphAdapter(f.backend,trust=f.trust);adapter.rebuild_domain_index()
        before=adapter.read(self.q());second=f.assignment(labels=['computing'],supersedes=a)
        f.publish(f.plan(second));after=adapter.read(self.q())
        self.assertNotEqual(before.identity,after.identity)
        self.assertEqual(before.snapshot,adapter.read(self.q(graph_version=3)).snapshot)
        self.assertEqual(after.domain_index,{'computing':[f.source]})

    def test_domain_index_atomic_fault_boundaries(self):
        f=self.f; f.migrate();adapter=SQLiteGraphAdapter(f.backend,trust=f.trust);adapter.rebuild_domain_index()
        p=f.plan(f.assignment());receipts=f.receipts(p);before=self.dump()
        for point in ('before_state_write','after_state_write','after_journal_write','before_commit'):
            def fault(p):
                if p==point:raise RuntimeError('legacy domain fault')
            with self.subTest(point=point),self.assertRaisesRegex(RuntimeError,'legacy domain fault'):
                f.publish(p,receipts=receipts,fault=fault)
            self.assertEqual(before,self.dump());self.assertFalse(f.backend.db.in_transaction)
        f.publish(p,receipts=receipts)
        self.assertEqual(adapter.read(self.q()).domain_index,{'biology':[f.source],'computing':[f.source]})

    def test_index_tampering_repair_preserves_both_journals(self):
        f=self.f;f.migrate();f.publish(f.plan(f.assignment()))
        adapter=SQLiteGraphAdapter(f.backend,trust=f.trust);adapter.rebuild_domain_index()
        f.backend.db.execute("UPDATE trace_domain_index SET assignment_hash='forged' WHERE graph_version=3")
        with self.assertRaisesRegex(ContractError,'DOMAIN_INDEX_STALE'):adapter.read(self.q())
        before=f.backend.audit();adapter.rebuild_domain_index();self.assertEqual(before,f.backend.audit())

    def test_retry_rechecks_authority_inside_upstream_begin(self):
        f=self.f;f.migrate();p=f.plan(f.assignment());auth,pre=f.receipts(p);f.publish(p,receipts=(auth,pre))
        before=self.dump();instant=f.time();calls=[]
        def clock():
            calls.append(True)
            if len(calls)==2:f.trust.revoke(f.publisher.issuer)
            return instant
        with patch('trace_gc.domain_publication.now',clock),self.assertRaisesRegex(ContractError,'UNTRUSTED_ISSUER'):
            f.service.publish(f.c,p,authorization=auth,preflight=pre)
        self.assertEqual(before,self.dump());self.assertFalse(f.backend.db.in_transaction)
        self.assertIsNone(f.backend.db.begin_guard)

    def test_current_revocation_governs_legacy_history(self):
        f=self.f;f.migrate();f.publish(f.plan(f.assignment()))
        adapter=SQLiteGraphAdapter(f.backend,trust=f.trust);adapter.rebuild_domain_index()
        f.revoke_source();v=adapter.read(self.q(graph_version=3,mode='HISTORICAL'))
        self.assertFalse(v.source_status[f.source]['active'])
        self.assertEqual(v.research_domains['source_assignments'][f.source]['domain_ids'],['biology','computing'])

    def test_wrong_core_pin_rejected_before_import(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'core.py';p.write_text("raise AssertionError('untrusted source executed')\n")
            with self.assertRaisesRegex(ContractError,'UPSTREAM_PIN_MISMATCH'):load_pinned_core(p)


# The exact same behavioral acceptance assertions are exercised on a separate
# real backend. No SQL graph-state substitute or reconstructed upstream is used.
REUSED = (
 'import_and_review_do_not_publish_or_grant_access',
 'publication_requires_explicit_migration', 'publication_disabled_by_default',
 'publication_and_reclassification_select_exact_predecessor',
 'retirement_is_new_event_not_record_rewrite','unclassified_assignment_roundtrips',
 'all_four_fault_points_rollback_every_table', 'idempotent_retry_has_no_content_or_additional_write',
 'retry_rejects_forged_authorization','retry_rejects_revoked_publisher',
 'retry_after_source_revocation_returns_only_opaque_receipt', 'key_collision_different_plan_is_rejected',
 'stale_graph_after_preflight_rejected','source_revocation_before_preflight_rejected',
 'tombstoned_source_rejected','source_epoch_mismatch_rejected','unadmitted_source_rejected',
 'review_permission_does_not_publish','publish_capability_cannot_migrate',
 'migration_cannot_reset_existing_assignments','revoked_reviewer_cannot_publish_even_after_preflight',
 'model_origin_unenrolled_signer_rejected','wrong_scope_signer_rejected','wrong_mode_signer_rejected',
 'risk_ceiling_rejected','expired_preflight_rejected','catalog_cannot_publish_an_uncommitted_predecessor',
 'source_erasure_makes_exact_semantic_audit_unavailable','old_snapshot_body_is_unchanged',
 'new_snapshot_hydrates_selected_assignment_closure','snapshot_cannot_substitute_assignment_hash',
 'plan_and_receipts_are_causally_bound','forged_plan_assignment_hash_rejected',
 'aliased_plan_identifier_rejected','migration_plan_cannot_carry_source_labels',
 'bool_graph_version_is_invalid','commit_rechecks_expiry_with_fresh_default_clock',
 'review_expiry_is_rechecked_at_commit','signed_but_incomplete_preflight_is_rejected',
 'migration_fault_rolls_back_every_table','active_source_with_denied_read_permission_cannot_publish',
)
for name in REUSED:
    def check(self, n=name):
        getattr(self.f,'test_'+n)()
    check.__name__='test_pinned_'+name
    setattr(DomainLegacy,check.__name__,check)
