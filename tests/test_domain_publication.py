"""Reference domain transaction tests, not native/deployment acceptance.

In a complete repository these import SQLiteReferenceBackend normally. A source
subset runner may explicitly supply BACKEND_FACTORY; that run must be reported
as extracted-class coverage, not full-module/release validation.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
import tempfile
import unittest

from trace_gc.canonical import digest, dumps, loads
from trace_gc.catalog import Catalog
from trace_gc.domain_publication import (
    AUTHORIZATION, PREFLIGHT, PUBLISH, MIGRATE, VALIDATE_CAPABILITY,
    ClassificationPublisher, PROJECTION_KEY, authorization_payload, validate_catalog,
)
from trace_gc.domains import REVIEW_PURPOSE, REVIEW_OPERATION, assign, propose, review_payload, taxonomy
from trace_gc.errors import ContractError
from trace_gc.ledger import build_ledger, causal_references
from trace_gc.schema import validate
from trace_gc.trust import IssuerPolicy, Signer, TrustStore

BACKEND_FACTORY = None


class DomainPublication(unittest.TestCase):
    def setUp(self):
        global BACKEND_FACTORY
        if BACKEND_FACTORY is None:
            from trace_gc.backend import SQLiteReferenceBackend
            self.backend_type = SQLiteReferenceBackend
        else:
            self.backend_type = BACKEND_FACTORY
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "graph.sqlite"
        self.c = Catalog()
        self.schema = self.c.put("schema", {"version": "test-v1", "relations": {
            "related": {"domain": "*", "range": "*", "symmetric": True, "inverse_of": None,
                        "incompatible": [], "transitive": False, "allow_self": False}}})
        self.source = self.c.source("paper", "1", "Biology and computing evidence.", scope="tenant-a")
        self.evidence = self.c.evidence(self.source)
        self.tax = taxonomy(self.c, namespace="fixture", version="1", domains=[
            {"id": "biology", "label": "Biology"}, {"id": "computing", "label": "Computing"}])
        self.method = {"kind": "MODEL", "name": "synthetic-test", "version": "1", "artifact_hash": digest("fixture")}
        self.trust = TrustStore()
        self.review = self.enroll("reviewer", {REVIEW_PURPOSE}, {REVIEW_OPERATION}, can_review=True)
        self.validator = self.enroll("validator", {PREFLIGHT}, {VALIDATE_CAPABILITY})
        self.publisher = self.enroll("publisher", {AUTHORIZATION}, {PUBLISH, MIGRATE})
        self.source_signer = self.enroll("source-owner", {"SOURCE_STATUS"},
                                        {"SOURCE_ADMIT", "SOURCE_WITHDRAW", "SOURCE_PERMISSION", "SOURCE_ERASE"})
        self.clock = 0
        self.backend = self.backend_type(self.path, catalog=self.c, schema_id=self.schema, nodes={}, sandbox=True)
        self.addCleanup(lambda: self.backend.close())
        self.service = self.new_service()
        action = {"action": "ADMIT", "source_hashes": {self.source: self.c.hash(self.source)},
                  "security_scope": "tenant-a", "execution_mode": "SYNTHETIC", "expected_version": 0}
        at = self.time()
        self.backend.admit_sources(self.c, [self.source], trust=self.trust,
            authorization=self.source_signer.issue("SOURCE_STATUS", action, issued_at=at),
            security_scope="tenant-a", execution_mode="SYNTHETIC", expected_version=0, key="admit", at=at)

    def time(self, advance=1):
        self.clock += advance
        return (datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=self.clock)).isoformat().replace("+00:00", "Z")

    def enroll(self, name, purposes, operations, *, can_review=False, scopes=None, modes=None, maximum_risk=2):
        signer = Signer.ephemeral(name)
        self.trust.enroll(name, IssuerPolicy(public_key=signer.public_key(), principal=name,
            purposes=frozenset(purposes), operations=frozenset(operations),
            scopes=frozenset(scopes or {"tenant-a"}), modes=frozenset(modes or {"SYNTHETIC"}),
            maximum_risk=maximum_risk, can_review=can_review))
        return signer

    def new_service(self, **kw):
        options = dict(security_scope="tenant-a", execution_mode="SYNTHETIC", publication_enabled=True)
        options.update(kw)
        return ClassificationPublisher(self.backend, self.trust, self.validator, **options)

    def plan(self, assignment_id=None, key=None):
        return self.service.plan(self.c, assignment_id=assignment_id, key=key or f"key-{self.clock}",
                                 run_id="fixture-run", created_at=self.time())

    def receipts(self, plan, *, signer=None):
        preflight = self.service.preflight(self.c, plan, at=self.time())
        auth = (signer or self.publisher).issue(AUTHORIZATION, authorization_payload(self.c, plan), issued_at=self.time())
        return auth, preflight

    def publish(self, plan, *, receipts=None, **kw):
        auth, preflight = receipts or self.receipts(plan)
        return self.service.publish(self.c, plan, authorization=auth, preflight=preflight, at=self.time(), **kw)

    def migrate(self):
        return self.publish(self.plan(key="migration"))

    def assignment(self, *, labels=None, state="CLASSIFIED", supersedes=None, source_epoch=None,
                   effective_version=None, source=None):
        source = source or self.source
        source_epoch = self.backend.statuses().get(source, {"epoch": 0})["epoch"] if source_epoch is None else source_epoch
        p = propose(self.c, source_snapshot_id=source, taxonomy_id=self.tax,
            domain_ids=["biology", "computing"] if labels is None else labels, method=self.method,
            basis_ids=[source], source_epoch=source_epoch, execution_mode="SYNTHETIC", state=state,
            supersedes=supersedes, effective_graph_version=self.backend.state()["graph_version"] + 1 if effective_version is None else effective_version,
            created_at=self.time())
        r = self.c.put("receipt", self.review.issue(REVIEW_PURPOSE, review_payload(self.c, p, "reviewer"), issued_at=self.time()))
        return assign(self.c, proposal_id=p, review_receipt_id=r, reviewed_by="reviewer", trust=self.trust, at=self.time())

    def journal(self):
        return [loads(row[0]) for row in self.backend.db.execute("SELECT body FROM trace_journal ORDER BY version")]

    def dump(self):
        return {table: self.backend.db.execute(f"SELECT * FROM {table} ORDER BY 1").fetchall()
                for table in ("trace_state", "trace_meta", "trace_records", "trace_erased", "trace_source_status", "trace_journal")}

    def assert_code(self, code, fn):
        with self.assertRaises(ContractError) as caught:
            fn()
        self.assertEqual(caught.exception.code, code)

    def revoke_source(self, *, tombstone=False):
        st = self.backend.statuses()[self.source]
        v = self.backend.state()["graph_version"]
        action = {"action": "ERASE" if tombstone else "STATUS_CHANGE", "source_id": self.source,
                  "source_hash": self.c.hash(self.source), "active": False, "permission": "DENIED",
                  "expected_epoch": st["epoch"], "expected_version": v, "security_scope": "tenant-a",
                  "reason": "test revocation", "tombstone": tombstone}
        at = self.time()
        return self.backend.change_source_status(self.c, self.source, active=False, permission="DENIED",
            expected_epoch=st["epoch"], expected_version=v, key=f"revoke-{v}", reason="test revocation",
            authorization=self.source_signer.issue("SOURCE_STATUS", action, issued_at=at),
            trust=self.trust, tombstone=tombstone, at=at)

    def test_migration_is_append_only_and_unclassified(self):
        before = self.dump()
        old_source, old_evidence = self.c.record(self.source), self.c.record(self.evidence)
        result = self.migrate()
        self.assertFalse(result["replayed"])
        self.assertEqual(self.backend.state()[PROJECTION_KEY]["assignments"], {})
        self.assertEqual(self.dump()["trace_meta"], before["trace_meta"])
        self.assertEqual(self.dump()["trace_journal"][:1], before["trace_journal"])
        self.assertEqual(old_source, self.c.record(self.source))
        self.assertEqual(old_evidence, self.c.record(self.evidence))
        self.assertEqual(self.service.audit()["classification_events"], 1)

    def test_import_and_review_do_not_publish_or_grant_access(self):
        before = self.dump()
        self.assignment()
        self.assertEqual(before, self.dump())
        self.assertNotIn(PROJECTION_KEY, self.backend.state())

    def test_publication_requires_explicit_migration(self):
        a = self.assignment()
        p = self.plan(a)
        self.assert_code("DOMAIN_MIGRATION_REQUIRED", lambda: self.service.preflight(self.c, p, at=self.time()))

    def test_publication_disabled_by_default(self):
        self.service = self.new_service(publication_enabled=False)
        p = self.plan()
        self.assert_code("ANALYSIS_ONLY", lambda: self.service.preflight(self.c, p, at=self.time()))

    def test_publication_and_reclassification_select_exact_predecessor(self):
        self.migrate()
        a = self.assignment()
        self.publish(self.plan(a))
        prior = deepcopy(self.journal())
        b = self.assignment(labels=["biology"], supersedes=a)
        self.publish(self.plan(b))
        selected = self.backend.state()[PROJECTION_KEY]["assignments"][self.source]
        self.assertEqual(selected, {"assignment_id": b, "assignment_hash": self.c.hash(b)})
        self.assertEqual(self.journal()[:len(prior)], prior)
        self.assertEqual(prior[-1]["state_after"][PROJECTION_KEY]["assignments"][self.source]["assignment_id"], a)
        self.assertEqual(self.service.audit()["classification_revision"], 3)

    def test_retirement_is_new_event_not_record_rewrite(self):
        self.migrate(); a = self.assignment(); self.publish(self.plan(a))
        old = self.c.record(a)
        b = self.assignment(labels=[], state="RETIRED", supersedes=a)
        self.publish(self.plan(b))
        self.assertEqual(self.c.record(a), old)
        self.assertEqual(self.c.get(b)["state"], "RETIRED")
        self.assertEqual(self.service.audit()["classification_events"], 3)

    def test_unclassified_assignment_roundtrips(self):
        self.migrate(); a = self.assignment(labels=[], state="UNCLASSIFIED"); self.publish(self.plan(a))
        recovered = Catalog(list(reversed(self.backend.load_catalog().all())))
        self.assertEqual(recovered.get(a)["domain_ids"], [])
        self.assertEqual(recovered.get(a)["state"], "UNCLASSIFIED")
        validate_catalog(recovered)
        self.assertEqual(self.service.audit()["classification_events"], 2)

    def test_old_database_reopen_and_hashes(self):
        old = self.dump()
        self.backend.close()
        self.backend = self.backend_type(self.path, catalog=self.c, schema_id=self.schema, nodes={}, sandbox=True)
        self.service = self.new_service()
        self.assertEqual(self.dump(), old)
        self.migrate()
        self.backend.close()
        self.backend = self.backend_type(self.path, catalog=self.c, schema_id=self.schema, nodes={}, sandbox=True)
        self.service = self.new_service()
        self.assertEqual(self.service.audit()["classification_revision"], 1)
        self.assertEqual(self.dump()["trace_meta"], old["trace_meta"])

    def test_all_four_fault_points_rollback_every_table(self):
        self.migrate(); a = self.assignment(); p = self.plan(a); receipts = self.receipts(p)
        before, catalog_before = self.dump(), self.c.all()
        for point in ("before_state_write", "after_state_write", "after_journal_write", "before_commit"):
            with self.subTest(point=point):
                def fault(name):
                    if name == point:
                        raise RuntimeError("injected failure")
                with self.assertRaisesRegex(RuntimeError, "injected failure"):
                    self.publish(p, receipts=receipts, fault=fault)
                self.assertEqual(self.dump(), before)
                self.assertEqual(self.c.all(), catalog_before)
                self.service.audit()
        self.publish(p, receipts=receipts)
        self.assertEqual(self.service.audit()["classification_events"], 2)

    def test_idempotent_retry_has_no_content_or_additional_write(self):
        self.migrate(); a = self.assignment(); p = self.plan(a); receipts = self.receipts(p)
        first = self.publish(p, receipts=receipts); before = self.dump()
        second = self.publish(p, receipts=receipts)
        self.assertTrue(second["replayed"])
        self.assertEqual(first["receipt"], second["receipt"])
        self.assertEqual(set(second), {"receipt", "replayed"})
        self.assertEqual(self.dump(), before)

    def test_retry_rejects_forged_authorization(self):
        self.migrate(); a = self.assignment(); p = self.plan(a); receipts = self.receipts(p)
        self.publish(p, receipts=receipts)
        bad = deepcopy(receipts[0]); bad["signature"] = "AA=="
        self.assert_code("SIGNATURE_INVALID", lambda: self.publish(p, receipts=(bad, receipts[1])))

    def test_retry_rejects_revoked_publisher(self):
        self.migrate(); a = self.assignment(); p = self.plan(a); receipts = self.receipts(p)
        self.publish(p, receipts=receipts); self.trust.revoke("publisher")
        self.assert_code("UNTRUSTED_ISSUER", lambda: self.publish(p, receipts=receipts))

    def test_retry_after_source_revocation_returns_only_opaque_receipt(self):
        self.migrate(); a = self.assignment(); p = self.plan(a); receipts = self.receipts(p)
        first = self.publish(p, receipts=receipts)
        self.revoke_source()
        self.assertEqual(self.publish(p, receipts=receipts)["receipt"], first["receipt"])
        self.assertFalse(self.backend.statuses()[self.source]["active"])
        self.assertEqual(self.service.audit()["classification_events"], 2)

    def test_key_collision_different_plan_is_rejected(self):
        self.migrate(); a = self.assignment(); self.publish(self.plan(a, key="same-key"))
        b = self.assignment(supersedes=a, labels=["biology"])
        p = self.plan(b, key="same-key")
        self.assert_code("IDEMPOTENCY_CONFLICT", lambda: self.publish(p))

    def test_stale_graph_after_preflight_rejected(self):
        p = self.plan(); receipts = self.receipts(p)
        self.revoke_source()
        self.assert_code("STALE_GRAPH_VERSION", lambda: self.publish(p, receipts=receipts))

    def test_source_revocation_before_preflight_rejected(self):
        self.migrate(); self.revoke_source()
        a = self.assignment(); p = self.plan(a)
        self.assert_code("STALE_EVIDENCE", lambda: self.service.preflight(self.c, p, at=self.time()))

    def test_tombstoned_source_rejected(self):
        self.migrate(); self.revoke_source(tombstone=True)
        a = self.assignment(); p = self.plan(a)
        self.assert_code("STALE_EVIDENCE", lambda: self.service.preflight(self.c, p, at=self.time()))

    def test_source_epoch_mismatch_rejected(self):
        self.migrate(); a = self.assignment(source_epoch=99); p = self.plan(a)
        self.assert_code("STALE_SOURCE_EPOCH", lambda: self.service.preflight(self.c, p, at=self.time()))

    def test_unadmitted_source_rejected(self):
        self.migrate()
        source = self.c.source("new-paper", "1", "Unadmitted biology", scope="tenant-a")
        a = self.assignment(source=source); p = self.plan(a)
        self.assert_code("DOMAIN_SOURCE_AUTHORITY", lambda: self.service.preflight(self.c, p, at=self.time()))

    def test_review_permission_does_not_publish(self):
        p = self.plan()
        self.assert_code("RECEIPT_PURPOSE", lambda: self.publish(p, receipts=self.receipts(p, signer=self.review)))

    def test_publish_capability_cannot_migrate(self):
        signer = self.enroll("publication-only", {AUTHORIZATION}, {PUBLISH})
        p = self.plan()
        self.assert_code("DOMAIN_PUBLICATION_AUTHORITY", lambda: self.publish(p, receipts=self.receipts(p, signer=signer)))

    def test_migration_cannot_reset_existing_assignments(self):
        self.migrate(); a = self.assignment(); self.publish(self.plan(a)); p = self.plan()
        self.assert_code("DOMAIN_ALREADY_MIGRATED", lambda: self.service.preflight(self.c, p, at=self.time()))

    def test_revoked_reviewer_cannot_publish_even_after_preflight(self):
        self.migrate(); a = self.assignment(); p = self.plan(a); receipts = self.receipts(p)
        self.trust.revoke("reviewer")
        self.assert_code("UNTRUSTED_ISSUER", lambda: self.publish(p, receipts=receipts))

    def test_model_origin_unenrolled_signer_rejected(self):
        p = self.plan()
        self.assert_code("UNTRUSTED_ISSUER", lambda: self.publish(p, receipts=self.receipts(p, signer=Signer.ephemeral("model"))))

    def test_wrong_scope_signer_rejected(self):
        signer = self.enroll("other-scope", {AUTHORIZATION}, {MIGRATE}, scopes={"tenant-b"})
        p = self.plan()
        self.assert_code("AUTHORIZATION_SCOPE", lambda: self.publish(p, receipts=self.receipts(p, signer=signer)))

    def test_wrong_mode_signer_rejected(self):
        signer = self.enroll("other-mode", {AUTHORIZATION}, {MIGRATE}, modes={"LIVE"})
        p = self.plan()
        self.assert_code("AUTHORIZATION_MODE", lambda: self.publish(p, receipts=self.receipts(p, signer=signer)))

    def test_risk_ceiling_rejected(self):
        signer = self.enroll("low-risk", {AUTHORIZATION}, {MIGRATE}, maximum_risk=1)
        p = self.plan()
        self.assert_code("DOMAIN_PUBLICATION_AUTHORITY", lambda: self.publish(p, receipts=self.receipts(p, signer=signer)))

    def test_expired_preflight_rejected(self):
        p = self.plan(); receipts = self.receipts(p); self.time(601)
        self.assert_code("RECEIPT_EXPIRED", lambda: self.publish(p, receipts=receipts))

    def test_catalog_cannot_publish_an_uncommitted_predecessor(self):
        self.migrate()
        a = self.assignment()
        b = self.assignment(supersedes=a, effective_version=self.backend.state()["graph_version"] + 2)
        # Advance the graph through an unrelated admission, without publishing a.
        source = self.c.source("other", "1", "Other source.", scope="tenant-a")
        v = self.backend.state()["graph_version"]; at = self.time()
        action = {"action": "ADMIT", "source_hashes": {source: self.c.hash(source)},
                  "security_scope": "tenant-a", "execution_mode": "SYNTHETIC", "expected_version": v}
        self.backend.admit_sources(self.c, [source], trust=self.trust,
            authorization=self.source_signer.issue("SOURCE_STATUS", action, issued_at=at),
            security_scope="tenant-a", execution_mode="SYNTHETIC", expected_version=v, key="other-admit", at=at)
        p = self.plan(b)
        self.assert_code("DOMAIN_COMMITTED_PREDECESSOR", lambda: self.service.preflight(self.c, p, at=self.time()))

    def test_tampered_projection_fails_journal_audit(self):
        self.migrate()
        state = self.backend.state(); state[PROJECTION_KEY]["revision"] = 99
        self.backend.db.execute("UPDATE trace_state SET body=? WHERE id=1", (dumps(state),))
        self.assert_code("BACKEND_AUDIT", self.service.audit)

    def test_non_domain_transaction_cannot_sneak_membership_into_audit(self):
        self.migrate()
        def apply(state, statuses):
            state[PROJECTION_KEY]["revision"] += 1
            return state
        self.backend._transaction(key="tamper", fingerprint=digest("test"), expected_version=self.backend.state()["graph_version"],
            operation={"action": "UNRELATED"}, catalog=self.c, apply=apply,
            authorization_hash=digest("test"), preflight_hash=digest("test"), at=self.time())
        self.backend.audit()  # The structural hash chain is valid; semantic audit must still reject.
        self.assert_code("DOMAIN_AUDIT", self.service.audit)

    def test_source_erasure_makes_exact_semantic_audit_unavailable(self):
        self.migrate(); a = self.assignment(); self.publish(self.plan(a))
        self.revoke_source(tombstone=True); self.backend.erase_cached_content(self.source, reason="fixture cleanup")
        self.assert_code("REPLAY_CONTENT_UNAVAILABLE", self.service.audit)

    def test_old_snapshot_body_is_unchanged(self):
        old = self.c.record(self.backend.snapshot(self.c))
        self.migrate()
        self.assertNotIn(PROJECTION_KEY, old["body"])
        self.assertEqual(old, self.c.record(old["id"]))
        validate("graph-snapshot", old["body"])

    def test_new_snapshot_hydrates_selected_assignment_closure(self):
        self.migrate(); a = self.assignment(); self.publish(self.plan(a))
        fresh = Catalog()
        snap_id = self.backend.snapshot(fresh)
        snap = fresh.get(snap_id)
        self.assertEqual(snap[PROJECTION_KEY]["assignments"][self.source]["assignment_id"], a)
        self.assertIn(self.source, fresh)
        self.assertIn(a, fresh)
        validate_catalog(fresh)
        ledger = build_ledger(fresh, run_id="snapshot", execution_mode="SYNTHETIC", created_at=self.time())
        self.assertEqual(ledger[-1]["stage"], "SNAPSHOT")

    def test_snapshot_cannot_substitute_assignment_hash(self):
        self.migrate(); a = self.assignment(); self.publish(self.plan(a))
        snapshot = self.c.get(self.backend.snapshot(self.c))
        snapshot[PROJECTION_KEY]["assignments"][self.source]["assignment_hash"] = "0" * 64
        self.assert_code("DOMAIN_SNAPSHOT_BINDING", lambda: self.c.put("graph-snapshot", snapshot))

    def test_plan_and_receipts_are_causally_bound(self):
        self.migrate(); a = self.assignment(); p = self.plan(a); auth, preflight = self.receipts(p)
        auth_id = self.c.put("receipt", auth); pre_id = self.c.put("receipt", preflight)
        self.assertIn(a, causal_references(self.c.record(p), self.c))
        self.assertIn(p, causal_references(self.c.record(auth_id), self.c))
        self.assertIn(p, causal_references(self.c.record(pre_id), self.c))
        ledger = build_ledger(self.c, run_id="fixture-run", execution_mode="SYNTHETIC", created_at=self.time())
        stage = {ref: event["stage"] for event in ledger for ref in event["record_ids"]}
        self.assertEqual(stage[p], "CLASSIFICATION_PLAN")

    def test_forged_plan_assignment_hash_rejected(self):
        self.migrate(); a = self.assignment(); body = self.c.get(self.plan(a)); body["assignment_hash"] = "0" * 64
        self.assert_code("DOMAIN_PLAN_BINDING", lambda: self.c.put("classification-plan", body))

    def test_aliased_plan_identifier_rejected(self):
        p = self.plan()
        self.assert_code("DOMAIN_PLAN_ID", lambda: self.c.put("classification-plan", self.c.get(p), "alias"))

    def test_migration_plan_cannot_carry_source_labels(self):
        p = self.plan(); body = self.c.get(p); body["assignment_id"] = "not-a-migration"
        self.assert_code("DOMAIN_PLAN_BINDING", lambda: self.c.put("classification-plan", body))

    def test_bool_graph_version_is_invalid(self):
        p = self.plan(); body = self.c.get(p); body["graph_version"] = True
        with self.assertRaises(ContractError):
            self.c.put("classification-plan", body)

    def test_independent_connection_cas_rejects_losing_writer(self):
        other = self.backend_type(self.path, catalog=self.c, schema_id=self.schema, nodes={}, sandbox=True)
        self.addCleanup(other.close)
        service = ClassificationPublisher(other, self.trust, self.validator,
            security_scope="tenant-a", execution_mode="SYNTHETIC", publication_enabled=True)
        p1 = self.plan(key="writer-a"); p2 = service.plan(self.c, assignment_id=None, key="writer-b", run_id="fixture-run", created_at=self.time())
        auth1, pre1 = self.receipts(p1)
        pre2 = service.preflight(self.c, p2, at=self.time())
        auth2 = self.publisher.issue(AUTHORIZATION, authorization_payload(self.c, p2), issued_at=self.time())
        self.publish(p1, receipts=(auth1, pre1))
        self.assert_code("STALE_GRAPH_VERSION", lambda: service.publish(self.c, p2, authorization=auth2, preflight=pre2, at=self.time()))
        self.assertEqual(service.audit()["classification_events"], 1)

    def test_corrupt_semantic_history_blocks_next_plan(self):
        self.migrate()
        def apply(state, statuses):
            state[PROJECTION_KEY]["revision"] += 1
            return state
        self.backend._transaction(key="tamper-plan", fingerprint=digest("test"),
            expected_version=self.backend.state()["graph_version"], operation={"action": "UNRELATED"},
            catalog=self.c, apply=apply, authorization_hash=digest("test"), preflight_hash=digest("test"), at=self.time())
        self.assert_code("DOMAIN_AUDIT", lambda: self.plan())

    def test_concurrent_independent_writers_have_one_winner(self):
        from concurrent.futures import ThreadPoolExecutor
        from threading import Barrier
        other = self.backend_type(self.path, catalog=self.c, schema_id=self.schema, nodes={}, sandbox=True)
        self.addCleanup(other.close)
        service = ClassificationPublisher(other, self.trust, self.validator,
            security_scope="tenant-a", execution_mode="SYNTHETIC", publication_enabled=True)
        p1, p2 = self.plan(key="race-a"), self.plan(key="race-b")
        r1, r2 = self.receipts(p1), self.receipts(p2)
        c1, c2 = Catalog(self.c.all()), Catalog(self.c.all())
        barrier = Barrier(2); at = self.time()
        def execute(svc, catalog, plan, receipts):
            barrier.wait(timeout=5)
            try:
                return svc.publish(catalog, plan, authorization=receipts[0], preflight=receipts[1], at=at)
            except ContractError as exc:
                return exc.code
        with ThreadPoolExecutor(max_workers=2) as pool:
            a = pool.submit(execute, self.service, c1, p1, r1)
            b = pool.submit(execute, service, c2, p2, r2)
            results = [a.result(timeout=15), b.result(timeout=15)]
        self.assertEqual(sum(isinstance(x, dict) for x in results), 1)
        self.assertIn("STALE_GRAPH_VERSION", results)
        self.assertEqual(self.service.audit()["classification_events"], 1)

    def test_commit_rechecks_expiry_with_fresh_default_clock(self):
        from unittest.mock import patch
        p = self.plan(); auth, preflight = self.receipts(p)
        within = self.time()
        expired = self.time(601)
        before = self.dump()
        with patch("trace_gc.domain_publication.now", side_effect=[within, expired]), \
             patch.dict(self.backend._transaction.__globals__, {"now": lambda: expired}):
            self.assert_code("RECEIPT_EXPIRED", lambda: self.service.publish(
                self.c, p, authorization=auth, preflight=preflight))
        self.assertEqual(self.dump(), before)

    def test_review_expiry_is_rechecked_at_commit(self):
        self.migrate(); a = self.assignment(); p = self.plan(a)
        receipt = self.c.get(self.c.get(a)["review_receipt_id"])
        expiry = datetime.fromisoformat(receipt["expires_at"].replace("Z", "+00:00"))
        self.clock = int((expiry - datetime(2026, 1, 1, tzinfo=timezone.utc)).total_seconds()) - 3
        receipts = self.receipts(p)
        self.assert_code("RECEIPT_EXPIRED", lambda: self.publish(p, receipts=receipts))

    def test_signed_but_incomplete_preflight_is_rejected(self):
        p = self.plan(); auth, preflight = self.receipts(p)
        payload = deepcopy(preflight["payload"]); payload["checks"].pop("SOURCE_EPOCH")
        forged = self.validator.issue(PREFLIGHT, payload, issued_at=preflight["issued_at"])
        self.assert_code("DOMAIN_PUBLICATION_AUTHORITY", lambda: self.publish(p, receipts=(auth, forged)))

    def test_migration_fault_rolls_back_every_table(self):
        p = self.plan(); receipts = self.receipts(p); before = self.dump()
        def fault(name):
            if name == "before_commit":
                raise RuntimeError("migration fault")
        with self.assertRaisesRegex(RuntimeError, "migration fault"):
            self.publish(p, receipts=receipts, fault=fault)
        self.assertEqual(before, self.dump())
        self.assertNotIn(PROJECTION_KEY, self.backend.state())

    def test_synthetic_domain_plan_cannot_publish_to_non_sandbox(self):
        other = self.backend_type(Path(self.tmp.name) / "not-a-sandbox.sqlite", catalog=self.c,
                                  schema_id=self.schema, nodes={}, sandbox=False)
        self.addCleanup(other.close)
        service = ClassificationPublisher(other, self.trust, self.validator, security_scope="tenant-a",
                                          execution_mode="SYNTHETIC", publication_enabled=True)
        p = service.plan(self.c, assignment_id=None, key="forbidden", run_id="fixture-run", created_at=self.time())
        self.assert_code("SYNTHETIC_PUBLICATION_FORBIDDEN", lambda: service.preflight(self.c, p, at=self.time()))
        self.assertEqual(other.audit()["events"], 0)

    def test_active_source_with_denied_read_permission_cannot_publish(self):
        self.migrate(); v = self.backend.state()["graph_version"]; at = self.time()
        action = {"action": "STATUS_CHANGE", "source_id": self.source, "source_hash": self.c.hash(self.source),
                  "active": True, "permission": "DENIED", "expected_epoch": 0, "expected_version": v,
                  "security_scope": "tenant-a", "reason": "deny read", "tombstone": False}
        self.backend.change_source_status(self.c, self.source, active=True, permission="DENIED",
            expected_epoch=0, expected_version=v, key="deny-read", reason="deny read", trust=self.trust,
            authorization=self.source_signer.issue("SOURCE_STATUS", action, issued_at=at), at=at)
        a = self.assignment(); p = self.plan(a)
        self.assertTrue(self.backend.statuses()[self.source]["active"])
        self.assert_code("STALE_EVIDENCE", lambda: self.service.preflight(self.c, p, at=self.time()))


if __name__ == "__main__":
    unittest.main()
