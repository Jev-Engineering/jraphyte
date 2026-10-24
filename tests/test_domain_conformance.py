"""Full-module bundle/retry checks; fabricated inputs are not deployment evidence."""
from __future__ import annotations
from copy import deepcopy
from pathlib import Path
from datetime import datetime, timezone
import tempfile
import unittest
from unittest.mock import patch

from trace_gc.backend import SQLiteReferenceBackend
from trace_gc.catalog import Catalog
from trace_gc.canonical import digest
from trace_gc.domain_publication import ClassificationPublisher, AUTHORIZATION, PREFLIGHT, PUBLISH, MIGRATE, VALIDATE_CAPABILITY
from trace_gc.domains import taxonomy, propose, assign, review_payload, REVIEW_PURPOSE, REVIEW_OPERATION
from trace_gc.errors import ContractError
from trace_gc.ledger import make_bundle
from trace_gc.policy import create_policy
from trace_gc.trust import TrustStore
from trace_gc.validation import validate_bundle
import test_domain_publication as pub


class DomainBundleConformanceTests(unittest.TestCase):
    def recorded(self):
        f=pub.DomainPublication();f.tmp=tempfile.TemporaryDirectory();self.addCleanup(f.tmp.cleanup)
        f.path=Path(f.tmp.name)/'recorded-test.sqlite';f.c=Catalog();f.clock=0;f.trust=TrustStore()
        f.schema=f.c.put('schema',{'version':'recorded-fixture-v1','relations':{'related':{'domain':'*','range':'*',
            'symmetric':False,'inverse_of':None,'incompatible':[],'transitive':False,'allow_self':False}}})
        f.source=f.c.source('recorded-test-paper','1','Fabricated recorded-mode fixture.',scope='tenant-a');f.evidence=f.c.evidence(f.source)
        f.tax=taxonomy(f.c,namespace='fixture',version='1',domains=[{'id':'biology','label':'Biology'}])
        f.review=f.enroll('reviewer',{REVIEW_PURPOSE},{REVIEW_OPERATION},can_review=True,modes={'RECORDED'})
        f.validator=f.enroll('validator',{PREFLIGHT},{VALIDATE_CAPABILITY},modes={'RECORDED'})
        f.publisher=f.enroll('publisher',{AUTHORIZATION},{PUBLISH,MIGRATE},modes={'RECORDED'})
        f.source_signer=f.enroll('source-owner',{'SOURCE_STATUS'},{'SOURCE_ADMIT','SOURCE_WITHDRAW'},modes={'RECORDED'})
        f.checkpoint=f.enroll('checkpoint',{'RUN_CHECKPOINT'},set(),modes={'RECORDED'})
        f.backend=SQLiteReferenceBackend(f.path,catalog=f.c,schema_id=f.schema,nodes={},sandbox=False);self.addCleanup(f.backend.close)
        f.service=ClassificationPublisher(f.backend,f.trust,f.validator,security_scope='tenant-a',execution_mode='RECORDED',publication_enabled=True)
        action={'action':'ADMIT','source_hashes':{f.source:f.c.hash(f.source)},'security_scope':'tenant-a','execution_mode':'RECORDED','expected_version':0}
        at=f.time();f.backend.admit_sources(f.c,[f.source],trust=f.trust,authorization=f.source_signer.issue('SOURCE_STATUS',action,issued_at=at),
            security_scope='tenant-a',execution_mode='RECORDED',expected_version=0,key='admit',at=at)
        f.migrate()
        proposal=propose(f.c,source_snapshot_id=f.source,taxonomy_id=f.tax,domain_ids=['biology'],
            method={'kind':'HUMAN','name':'fabricated-review-only','version':'1','artifact_hash':digest('fixture')},
            basis_ids=[f.evidence],source_epoch=0,effective_graph_version=3,execution_mode='RECORDED',created_at=f.time())
        review=f.c.put('receipt',f.review.issue(REVIEW_PURPOSE,review_payload(f.c,proposal,'reviewer'),issued_at=f.time()))
        a=assign(f.c,proposal_id=proposal,review_receipt_id=review,reviewed_by='reviewer',trust=f.trust,at=f.time())
        f.publish(f.plan(a))
        create_policy(f.c,version='bundle-test',scope='tenant-a',population='fabricated-tests',allowed_modes=['RECORDED'])
        return f
    def bundle(self,f,profile='FINALIZED_PUBLISHED',signed=True):
        event=f.journal()[-1]
        tx=next(r['id'] for r in f.c.all('transaction') if r['body']['version']==3)
        return make_bundle(f.c,run_id='fixture-run',execution_mode='RECORDED',security_scope='tenant-a',graph_version=3,
            schema_hash=f.c.hash(f.schema),source_status=f.backend.statuses(),policy_version='bundle-test',profile=profile,
            transaction_id=tx,signer=f.checkpoint if signed else None,created_at=f.time(),ledger_prefix=event['lineage_prefix'])
    def test_classification_published_bundle_full_validator(self):
        f=self.recorded();b=self.bundle(f);result=validate_bundle(b,trust=f.trust,at=f.time())
        self.assertEqual(result['status'],'PASS');self.assertTrue(result['checkpoint_authenticated']);self.assertFalse(result['authorization_granted'])
    def test_classification_bundle_requires_external_checkpoint_trust(self):
        f=self.recorded();b=self.bundle(f)
        with self.assertRaises(ContractError):validate_bundle(b)
    def test_expired_review_is_auditable_but_not_new_authority(self):
        f=self.recorded();b=self.bundle(f,profile='HISTORICAL_REPLAY',signed=False)
        result=validate_bundle(b,trust=f.trust,at=f.time(3600))
        self.assertFalse(result['authorization_granted']);self.assertFalse(result['checkpoint_authenticated'])
    def test_revoked_reviewer_still_invalidates_historical_authenticity(self):
        f=self.recorded();b=self.bundle(f,profile='HISTORICAL_REPLAY',signed=False);f.trust.revoke('reviewer')
        with self.assertRaises(ContractError):validate_bundle(b,trust=f.trust,at=f.time(3600))
    def test_missing_or_forged_primary_transaction_plan_rejected(self):
        f=self.recorded();b=self.bundle(f);txid=b['manifest']['transaction_id']
        tx=next(r for r in b['records'] if r['id']==txid);tx['body']['plan_hash']='0'*64
        with self.assertRaises(ContractError):validate_bundle(b,trust=f.trust,at=f.time())
    def test_existing_source_and_evidence_body_hashes_unchanged_after_bundle(self):
        f=self.recorded();before=[f.c.record(f.source),f.c.record(f.evidence)]
        validate_bundle(self.bundle(f),trust=f.trust,at=f.time())
        self.assertEqual(before,[f.c.record(f.source),f.c.record(f.evidence)])
    def test_synthetic_finalized_publication_remains_forbidden(self):
        f=pub.DomainPublication();f.setUp();self.addCleanup(f.doCleanups);f.migrate();f.publish(f.plan(f.assignment()))
        create_policy(f.c,version='bundle-test',scope='tenant-a',population='synthetic-tests')
        b=make_bundle(f.c,run_id='fixture-run',execution_mode='SYNTHETIC',security_scope='tenant-a',graph_version=3,
            schema_hash=f.c.hash(f.schema),source_status=f.backend.statuses(),policy_version='bundle-test',profile='FINALIZED_PUBLISHED',created_at=f.time())
        with self.assertRaisesRegex(ContractError,'SYNTHETIC_PUBLICATION_FORBIDDEN'):validate_bundle(b,trust=f.trust,at=f.time())


class DomainRetryConformanceTests(unittest.TestCase):
    def setUp(self):
        self.f=pub.DomainPublication();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.f.migrate();self.a=self.f.assignment();self.p=self.f.plan(self.a);self.receipts=self.f.receipts(self.p)
        self.f.publish(self.p,receipts=self.receipts)
    def test_retry_rechecks_expiry_after_acquiring_database_lock(self):
        f=self.f;valid=f.time();expired=f.time(3600);before=f.dump()
        with patch('trace_gc.domain_publication.now',side_effect=[valid,expired]):
            with self.assertRaisesRegex(ContractError,'RECEIPT_EXPIRED'):
                f.service.publish(f.c,self.p,authorization=self.receipts[0],preflight=self.receipts[1])
        self.assertEqual(f.dump(),before)
    def test_retry_rechecks_revocation_after_acquiring_database_lock(self):
        f=self.f;valid=f.time();calls=[];before=f.dump()
        def clock():
            calls.append(1)
            if len(calls)==2:f.trust.revoke('publisher')
            return valid
        with patch('trace_gc.domain_publication.now',side_effect=clock):
            with self.assertRaisesRegex(ContractError,'UNTRUSTED_ISSUER'):
                f.service.publish(f.c,self.p,authorization=self.receipts[0],preflight=self.receipts[1])
        self.assertEqual(f.dump(),before)
