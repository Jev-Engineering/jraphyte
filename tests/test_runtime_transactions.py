"""Real isolated SQLite transaction, concurrency, and generated-sequence tests."""
from __future__ import annotations
import concurrent.futures
import json
import random
import tempfile
import threading
import unittest
from copy import deepcopy
from pathlib import Path

from trace_gc.backend import SQLiteReferenceBackend,CompilerService
from trace_gc.canonical import digest,dumps,loads
from trace_gc.catalog import Catalog
from trace_gc.demo import build_fixture,RUN,SCOPE,POLICY,POPULATION,run_demo
from trace_gc.errors import ContractError
from trace_gc.ledger import make_bundle
from trace_gc.plans import create_plan
from trace_gc.trust import authorize_plan,Signer
from trace_gc.validation import validate_bundle
from test_runtime_contracts import FixtureCase


class TransactionTests(FixtureCase):
    def test_atomic_publication_and_replay(self):
        approvals=self.f.approvals();first=self.f.publish(approvals=approvals)
        replay=self.f.publish(approvals=approvals)
        self.assertFalse(first["replayed"]);self.assertTrue(replay["replayed"])
        self.assertEqual(first["receipt"],replay["receipt"])
        self.assertEqual(self.f.backend.state()["graph_version"],2)
        self.assertEqual(self.f.backend.audit()["events"],2)
    def test_alternative_proof_survives_one_withdrawal(self):
        self.f.publish();self.f.status_change(self.f.source_ids[0])
        edges=self.f.backend.view(self.f.catalog)["edges"]
        self.assertEqual(len(edges),1);self.assertEqual(edges[0]["assertion_ids"],[self.f.candidate_ids[1]])
        self.f.status_change(self.f.source_ids[1]);self.assertEqual(self.f.backend.view(self.f.catalog)["edges"],[])
    def test_inactive_source_is_not_resurrected_by_permission_restore(self):
        self.f.publish();self.f.status_change(self.f.source_ids[0],permission="DENIED")
        self.f.status_change(self.f.source_ids[0],active=True,permission="READ")
        self.assertFalse(self.f.backend.state()["assertions"][self.f.candidate_ids[0]]["active"])
    def test_rollback_at_every_write_boundary(self):
        approvals=self.f.approvals();before=self.f.backend.state();head=self.f.backend.audit()
        for point in ["before_state_write","after_state_write","after_journal_write","before_commit"]:
            def fail(name):
                if name==point:raise RuntimeError("injected interruption")
            with self.subTest(point=point),self.assertRaisesRegex(RuntimeError,"injected"):
                self.f.publish(approvals=approvals,fault=fail)
            self.assertEqual(self.f.backend.state(),before);self.assertEqual(self.f.backend.audit(),head)
        self.f.publish(approvals=approvals);self.assertEqual(self.f.backend.audit()["events"],2)
    def test_stale_version_after_source_change(self):
        approvals=self.f.approvals();self.f.status_change(self.f.source_ids[0])
        self.rejects(lambda:self.f.publish(approvals=approvals),"STALE_GRAPH_VERSION")
        self.assertEqual(self.f.backend.state()["assertions"],{})
    def test_untrusted_signature_cannot_publish(self):
        preflight,approval=self.f.approvals();approval["payload"]["reviewed_by"]="someone-else"
        self.rejects(lambda:self.f.service.publish(self.f.catalog,self.f.plan_id,preflight=preflight,authorization=approval),"SIGNATURE_INVALID")
        self.assertEqual(self.f.backend.state()["graph_version"],1)
    def test_unknown_issuer_cannot_authorize(self):
        rogue=Signer.ephemeral("not-enrolled")
        approval=authorize_plan(rogue,self.f.catalog.get(self.f.plan_id),self.f.catalog.hash(self.f.plan_id),reviewed_by="rogue")
        preflight=self.f.service.preflight(self.f.catalog,self.f.plan_id,reviewed=True)
        self.rejects(lambda:self.f.service.publish(self.f.catalog,self.f.plan_id,preflight=preflight,authorization=approval),"UNTRUSTED_ISSUER")
    def test_revoked_issuer_rejected(self):
        approvals=self.f.approvals();self.f.trust.revoke(self.f.reviewer.issuer)
        self.rejects(lambda:self.f.publish(approvals=approvals),"UNTRUSTED_ISSUER")
    def test_expired_receipt_rejected(self):
        preflight=self.f.service.preflight(self.f.catalog,self.f.plan_id,reviewed=True)
        approval=authorize_plan(self.f.reviewer,self.f.catalog.get(self.f.plan_id),self.f.catalog.hash(self.f.plan_id),
            reviewed_by="isolated-test-reviewer",issued_at="2020-01-01T00:00:00Z",expires_at="2020-01-01T01:00:00Z")
        self.rejects(lambda:self.f.service.publish(self.f.catalog,self.f.plan_id,preflight=preflight,authorization=approval),"RECEIPT_EXPIRED")
    def test_signed_failed_preflight_is_not_a_pass(self):
        preflight,approval=self.f.approvals();payload=deepcopy(preflight["payload"]);payload["checks"]["GLOBAL_FEASIBILITY"]=False
        bad=self.f.validator.issue("PREFLIGHT",payload)
        self.rejects(lambda:self.f.service.publish(self.f.catalog,self.f.plan_id,preflight=bad,authorization=approval),"PREFLIGHT_FAILED")
    def test_default_service_is_analysis_only(self):
        service=CompilerService(self.f.backend,self.f.trust,self.f.validator,policy_version=POLICY,population=POPULATION,security_scope=SCOPE)
        self.rejects(lambda:service.preflight(self.f.catalog,self.f.plan_id,reviewed=True),"ANALYSIS_ONLY")
    def test_analysis_export_never_grants_authority(self):self.assertFalse(validate_bundle(self.f.bundle())["authorization_granted"])
    def test_idempotency_key_with_different_plan_is_conflict(self):
        self.f.publish()
        # Invoke the transaction gate with a changed immutable fingerprint: no new state can be written.
        self.rejects(lambda:self.f.backend._transaction(key="publish-demo",fingerprint="a"*64,expected_version=1,operation={},
            catalog=self.f.catalog,apply=lambda s,t:s,authorization_hash="b"*64,preflight_hash="c"*64),"IDEMPOTENCY_CONFLICT")
    def test_sandbox_cannot_be_reopened_as_production(self):
        self.rejects(lambda:SQLiteReferenceBackend(self.f.root/"graph.sqlite3",catalog=self.f.catalog,schema_id=self.f.schema_id,
                                                   nodes={},sandbox=False),"BACKEND_MODE")
    def test_failed_backend_initialization_releases_database(self):
        with tempfile.TemporaryDirectory() as directory:
            self.rejects(lambda:SQLiteReferenceBackend(Path(directory)/"graph.sqlite3",catalog=self.f.catalog,
                                                       schema_id="missing-schema",nodes={},sandbox=True))
    def test_atomic_journal_binds_verified_lineage_head(self):
        result=self.f.publish();prefix=result["event"]["lineage_prefix"]
        self.assertTrue(prefix);self.assertEqual(result["receipt"]["upstream_head"],prefix[-1]["hash"])
        self.assertIn(self.f.plan_id,{ref for e in prefix for ref in e["record_ids"]})
    def test_invented_lineage_head_rejected(self):
        preflight,approval=self.f.approvals()
        self.rejects(lambda:self.f.service.publish(self.f.catalog,self.f.plan_id,preflight=preflight,authorization=approval,upstream_head="a"*64),"LEDGER_BINDING")
    def test_backend_detects_state_tampering(self):
        state=self.f.backend.state();state["nodes"]["unlogged"]="Person"
        self.f.backend.db.execute("UPDATE trace_state SET body=? WHERE id=1",(dumps(state),))
        self.rejects(self.f.backend.audit,"BACKEND_AUDIT")
    def test_backend_detects_receipt_only_tampering(self):
        self.f.publish();row=self.f.backend.db.execute("SELECT body FROM trace_journal WHERE version=2").fetchone()
        event=loads(row[0]);event["transaction_receipt"]["authorization_hash"]="f"*64
        self.f.backend.db.execute("UPDATE trace_journal SET body=? WHERE version=2",(dumps(event),))
        self.rejects(self.f.backend.audit,"BACKEND_AUDIT")
    def test_replay_from_persisted_immutable_records(self):
        self.f.publish();restored=self.f.backend.load_catalog()
        self.assertEqual(self.f.backend.view(restored),self.f.backend.view(self.f.catalog))
        self.assertEqual(restored.record(self.f.pack_id),self.f.catalog.record(self.f.pack_id))
    def test_erase_revokes_then_reports_exact_replay_loss(self):
        self.f.publish();self.f.status_change(self.f.source_ids[0],permission="DENIED",tombstone=True)
        result=self.f.backend.erase_cached_content(self.f.source_ids[0],reason="isolated retention test")
        self.assertEqual(result["status"],"EXACT_REPLAY_UNAVAILABLE")
        self.rejects(self.f.backend.load_catalog,"REPLAY_CONTENT_UNAVAILABLE")
        self.assertGreater(self.f.backend.audit()["erased_record_count"],0)
    def test_erasure_without_tombstone_denied(self):
        self.rejects(lambda:self.f.backend.erase_cached_content(self.f.source_ids[0],reason="not authorized"),"ERASURE_AUTHORITY")
    def test_revocation_does_not_trust_incomplete_caller_catalog(self):
        self.f.publish();source=self.f.source_ids[0]
        minimal=Catalog([self.f.catalog.record(source)])
        status=self.f.backend.statuses()[source];version=self.f.backend.state()["graph_version"]
        action={"action":"STATUS_CHANGE","source_id":source,"source_hash":minimal.hash(source),"active":False,"permission":"READ",
                "expected_epoch":status["epoch"],"expected_version":version,"security_scope":SCOPE,"reason":"minimal catalog test","tombstone":False}
        self.f.backend.change_source_status(minimal,source,active=False,permission="READ",expected_epoch=status["epoch"],expected_version=version,
            key="minimal-catalog-withdrawal",reason=action["reason"],authorization=self.f.reviewer.issue("SOURCE_STATUS",action),trust=self.f.trust)
        self.assertFalse(self.f.backend.state()["assertions"][self.f.candidate_ids[0]]["active"])
        self.assertTrue(self.f.backend.state()["assertions"][self.f.candidate_ids[1]]["active"])


class ConcurrentAndStatefulTests(unittest.TestCase):
    def test_two_connections_cannot_both_publish_stale_snapshot(self):
        with tempfile.TemporaryDirectory() as temporary:
            f=build_fixture(Path(temporary));other=None
            try:
                c2=Catalog(f.catalog.all());p2=c2.get(f.plan_id);p2["idempotency_key"]="competing-plan";pid2=c2.put("plan",p2)
                other=SQLiteReferenceBackend(f.root/"graph.sqlite3",catalog=c2,schema_id=f.schema_id,nodes={},sandbox=True)
                s2=CompilerService(other,f.trust,f.validator,policy_version=POLICY,population=POPULATION,security_scope=SCOPE,
                    publication_mode="REVIEWED",policy_hash=c2.hash(f.policy_id))
                p1,a1=f.approvals();pre2=s2.preflight(c2,pid2,reviewed=True)
                a2=authorize_plan(f.reviewer,p2,c2.hash(pid2),reviewed_by="isolated-test-reviewer")
                barrier=threading.Barrier(2)
                def publish(service,catalog,pid,pre,auth):
                    barrier.wait()
                    try:return service.publish(catalog,pid,preflight=pre,authorization=auth)["receipt"]["version"]
                    except ContractError as exc:return exc.code
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                    results=[pool.submit(publish,*args) for args in [(f.service,f.catalog,f.plan_id,p1,a1),(s2,c2,pid2,pre2,a2)]]
                    results=[future.result() for future in results]
                self.assertCountEqual(results,[2,"STALE_GRAPH_VERSION"]);self.assertEqual(f.backend.audit()["events"],2)
            finally:
                if other:other.close()
                f.close()
    def test_and_prerequisite_withdrawal_cascades(self):
        with tempfile.TemporaryDirectory() as temporary:
            f=build_fixture(Path(temporary),prerequisite_chain=True)
            try:
                f.publish();f.status_change(f.source_ids[0])
                self.assertEqual(f.backend.view(f.catalog)["edges"],[])
                self.assertFalse(f.backend.state()["assertions"][f.candidate_ids[1]]["active"])
            finally:f.close()
    def test_generated_permission_withdrawal_and_retry_sequences(self):
        # Independent reference state: original proofs only lose validity; status restoration cannot resurrect them.
        for seed in range(4):
            with self.subTest(seed=seed),tempfile.TemporaryDirectory() as temporary:
                f=build_fixture(Path(temporary));rng=random.Random(seed)
                try:
                    approvals=f.approvals();first=f.publish(approvals=approvals);live={0,1}
                    for step in range(24):
                        index=rng.randrange(2);active=bool(rng.randrange(2));permission=rng.choice(["READ","DENIED"])
                        if rng.randrange(4)==0:
                            replay=f.publish(approvals=approvals)
                            self.assertTrue(replay["replayed"]);self.assertEqual(replay["receipt"],first["receipt"])
                        else:
                            f.status_change(f.source_ids[index],active=active,permission=permission,key=f"generated:{seed}:{step}")
                            if not active or permission=="DENIED":live.discard(index)
                        state=f.backend.state();actual={i for i,c in enumerate(f.candidate_ids) if state["assertions"][c]["active"]}
                        self.assertEqual(actual,live)
                        self.assertEqual(len(f.backend.view(f.catalog)["edges"]),int(bool(live)))
                        f.backend.audit()
                finally:f.close()
    def test_synthetic_publication_prohibited_even_with_review_on_non_sandbox(self):
        with tempfile.TemporaryDirectory() as temporary:
            f=build_fixture(Path(temporary),sandbox=False)
            try:
                with self.assertRaisesRegex(ContractError,"SYNTHETIC_PUBLICATION_FORBIDDEN"):f.publish()
                self.assertEqual(f.backend.state()["graph_version"],1)
            finally:f.close()
    def test_finalized_published_bundle_checks_external_trust_and_atomic_anchor(self):
        # Entirely fabricated RECORDED data and ephemeral test keys in a temporary database;
        # this tests a gate, not a claim of independent labels or real deployment.
        with tempfile.TemporaryDirectory() as temporary:
            f=build_fixture(Path(temporary),mode="RECORDED",sandbox=False)
            try:
                result=f.publish();txid=next(r["id"] for r in f.catalog.all("transaction") if r["body"]["version"]==2)
                b=make_bundle(f.catalog,run_id=RUN,execution_mode="RECORDED",security_scope=SCOPE,graph_version=2,
                    schema_hash=f.catalog.hash(f.schema_id),source_status=f.backend.statuses(),policy_version=POLICY,
                    profile="FINALIZED_PUBLISHED",transaction_id=txid,signer=f.checkpoint,ledger_prefix=result["event"]["lineage_prefix"])
                self.assertEqual(validate_bundle(b,trust=f.trust)["status"],"PASS")
                with self.assertRaisesRegex(ContractError,"CHECKPOINT_UNTRUSTED"):validate_bundle(b)
            finally:f.close()
    def test_end_to_end_demo(self):
        result=run_demo();self.assertEqual(result["status"],"PASS");self.assertEqual(result["provider_calls"],0)
        self.assertEqual(result["proofs_after_first_withdrawal"],1);self.assertEqual(result["edges_after_second_withdrawal"],0)
