"""Actual signed-authority reference transactions; no deployment/Git signature claim."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from trace_gc.backend import CompilerService, SQLiteReferenceBackend
from trace_gc.canonical import digest, dumps, loads
from trace_gc.catalog import Catalog
from trace_gc.compiler import now
from trace_gc.demo import relation
from trace_gc.domain_publication import classification_operation, migration_operation, snapshot_body
from trace_gc.domains import create_assignment, restore_assignment
from trace_gc.errors import ContractError
from trace_gc.plans import create_plan
from trace_gc.policy import create_policy
from trace_gc.trust import IssuerPolicy, Signer, TrustStore, authorize_plan
from test_research_domain_contracts import fixture_catalog, REVIEW


class DomainFixture:
    def __init__(self, root, *, backend_factory=None):
        self.root = Path(root)
        self.catalog, self.taxonomy, self.source, self.evidence = fixture_catalog()
        self.policy = create_policy(self.catalog, version="reviewed-domain-fixture-v1", scope="test", population="synthetic",
                                    mode="REVIEWED", allowed_modes=["SYNTHETIC", "RECORDED"])
        self.schema = self.catalog.put("schema", {"version": "fixture-schema-v1", "relations": {"related": relation("Entity", "Entity")}})
        self.backend = (backend_factory or SQLiteReferenceBackend)(
            self.root / "graph.db", catalog=self.catalog, schema_id=self.schema, nodes={"a": "Entity", "b": "Entity"}, sandbox=True)
        self.trust = TrustStore()
        self.reviewer, self.validator, self.source_admin = [Signer.ephemeral(ref) for ref in ("reviewer", "validator", "source-admin")]
        self.trust.enroll("reviewer", IssuerPolicy(self.reviewer.public_key(), "fixture-reviewer", frozenset({"AUTHORIZATION"}),
                          frozenset({"INITIALIZE_RESEARCH_DOMAINS", "SET_SOURCE_CLASSIFICATION"}),
                          frozenset({"test"}), frozenset({"SYNTHETIC", "RECORDED"}), can_review=True))
        self.trust.enroll("validator", IssuerPolicy(self.validator.public_key(), "fixture-validator", frozenset({"PREFLIGHT"}),
                          frozenset(), frozenset({"test"}), frozenset({"SYNTHETIC", "RECORDED"})))
        self.trust.enroll("source-admin", IssuerPolicy(self.source_admin.public_key(), "fixture-source-admin", frozenset({"SOURCE_STATUS"}),
                          frozenset({"SOURCE_ADMIT", "SOURCE_WITHDRAW", "SOURCE_PERMISSION", "SOURCE_ERASE"}),
                          frozenset({"test"}), frozenset({"SYNTHETIC", "RECORDED"})))
        self.service = self.service_for(self.backend)
        action = {"action": "ADMIT", "source_hashes": {self.source: self.catalog.hash(self.source)}, "security_scope": "test",
                  "execution_mode": "SYNTHETIC", "expected_version": 0}
        self.backend.admit_sources(self.catalog, [self.source], trust=self.trust,
                                    authorization=self.source_admin.issue("SOURCE_STATUS", action), security_scope="test",
                                    execution_mode="SYNTHETIC", expected_version=0, key="admit")

    def close(self):
        self.backend.close()

    def service_for(self, backend, **changes):
        options = dict(policy_version="reviewed-domain-fixture-v1", population="synthetic", security_scope="test",
                       policy_hash=self.catalog.hash(self.policy), publication_mode="REVIEWED", classification_enabled=True,
                       classification_taxonomy_hashes=frozenset({self.catalog.hash(self.taxonomy)}))
        options.update(changes)
        return CompilerService(backend, self.trust, self.validator, **options)

    def plan(self, ops, *, key=None, catalog=None, backend=None):
        c, b = catalog or self.catalog, backend or self.backend
        snapshot = b.snapshot(c)
        return create_plan(c, run_id="domain-fixture", snapshot_id=snapshot, operations=ops, security_scope="test",
                           execution_mode="SYNTHETIC", idempotency_key=key or "write-" + str(b.state()["graph_version"]),
                           policy_version="reviewed-domain-fixture-v1", source_status=b.statuses())

    def approvals(self, plan, *, catalog=None, service=None):
        c, s = catalog or self.catalog, service or self.service
        preflight = s.preflight(c, plan, reviewed=True)
        auth = authorize_plan(self.reviewer, c.get(plan, "plan"), c.hash(plan), reviewed_by="fixture-reviewer")
        return auth, preflight

    def publish(self, plan, *, approvals=None, catalog=None, service=None, **kwargs):
        c, s = catalog or self.catalog, service or self.service
        auth, preflight = approvals or self.approvals(plan, catalog=c, service=s)
        return s.publish(c, plan, authorization=auth, preflight=preflight, **kwargs)

    def migrate(self):
        return self.publish(self.plan([migration_operation(operation_id="initialize", reason="Synthetic old-database migration")]))

    def assign(self, labels=None, *, previous=None, catalog=None, review=None, status=None):
        c = catalog or self.catalog
        ref = create_assignment(c, source_snapshot_id=self.source, taxonomy_id=self.taxonomy,
                                domain_ids=["research:biology"] if labels is None else labels,
                                review=review or REVIEW, classifier_id="fixture-reviewer", classifier_version="fixture-v1",
                                supersedes=previous, status=status)
        return ref

    def assignment_plan(self, ref, **kwargs):
        return self.plan([classification_operation(kwargs.get("catalog") or self.catalog, ref, operation_id="assign")], **kwargs)

    def status_change(self, *, active=False, permission="READ", tombstone=False):
        status = self.backend.statuses()[self.source]
        action = {"action": "ERASE" if tombstone else "STATUS_CHANGE", "source_id": self.source,
                  "source_hash": self.catalog.hash(self.source), "active": active, "permission": permission,
                  "expected_epoch": status["epoch"], "expected_version": self.backend.state()["graph_version"],
                  "security_scope": "test", "reason": "fixture change", "tombstone": tombstone}
        return self.backend.change_source_status(self.catalog, self.source, active=active, permission=permission,
                     expected_epoch=status["epoch"], expected_version=self.backend.state()["graph_version"],
                     key="status-" + str(status["epoch"]), reason="fixture change", tombstone=tombstone,
                     authorization=self.source_admin.issue("SOURCE_STATUS", action), trust=self.trust)


class DomainTransactionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.f = DomainFixture(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(self.f.close)

    def rejects(self, action, code=None):
        with self.assertRaises(ContractError) as caught:
            action()
        if code is not None:
            self.assertEqual(caught.exception.code, code)

    def test_migration_appends_without_rewriting_genesis_or_history(self):
        b = self.f.backend
        before_meta = loads(b.db.execute("SELECT body FROM trace_meta").fetchone()[0])
        before_journal = list(b.db.execute("SELECT * FROM trace_journal"))
        source, evidence = self.f.catalog.record(self.f.source), self.f.catalog.record(self.f.evidence)
        old_snapshot = b.snapshot(self.f.catalog)
        self.f.migrate()
        self.assertEqual(loads(b.db.execute("SELECT body FROM trace_meta").fetchone()[0]), before_meta)
        self.assertEqual(list(b.db.execute("SELECT * FROM trace_journal WHERE version=1")), before_journal)
        self.assertNotIn("classifications", self.f.catalog.get(old_snapshot))
        self.assertEqual(b.state()["classifications"], {"contract_version": 1, "revision": 1, "assignments": {}})
        self.assertEqual(b.load_catalog().record(self.f.source), source)
        self.assertEqual(b.load_catalog().record(self.f.evidence), evidence)
        self.assertTrue(b.audit(trust=self.f.trust)["classification_authority_verified"])

    def test_classification_commit_and_authenticated_idempotent_retry(self):
        self.f.migrate()
        ref = self.f.assign(["research:biology", "research:computer-science"])
        plan = self.f.assignment_plan(ref)
        approvals = self.f.approvals(plan)
        first = self.f.publish(plan, approvals=approvals)
        repeated = self.f.publish(plan, approvals=approvals)
        self.assertFalse(first["replayed"])
        self.assertTrue(repeated["replayed"])
        self.assertEqual(first["receipt"], repeated["receipt"])
        self.assertEqual(first["receipt"]["classification_revision"], 2)
        self.assertEqual(self.f.backend.state()["classifications"]["assignments"], {self.f.source: ref})
        self.assertEqual(self.f.backend.audit(trust=self.f.trust)["classification_events"], 2)

    def test_unclassified_reclassification_retirement_and_compensating_rollback(self):
        self.f.migrate()
        first = self.f.assign([])
        self.f.publish(self.f.assignment_plan(first))
        second = self.f.assign(["research:physics"], previous=first)
        self.f.publish(self.f.assignment_plan(second))
        third = self.f.assign([], previous=second, status="RETIRED")
        self.f.publish(self.f.assignment_plan(third))
        restored = restore_assignment(self.f.catalog, current_assignment_id=third, restore_assignment_id=second,
                                      review=REVIEW, classifier_id="fixture-reviewer", classifier_version="fixture-v1")
        self.f.publish(self.f.assignment_plan(restored))
        self.assertEqual(self.f.catalog.get(restored)["effective_revision"], 4)
        self.assertEqual(self.f.catalog.get(restored)["domain_ids"], ["research:physics"])
        self.assertEqual(self.f.catalog.get(third)["status"], "RETIRED")
        self.assertEqual(self.f.backend.audit()["classification_events"], 5)

    def test_classification_requires_explicit_migration(self):
        ref = self.f.assign()
        self.rejects(lambda: self.f.assignment_plan(ref), "DOMAIN_MIGRATION_REQUIRED")

    def test_migration_is_not_repeated_or_combined(self):
        self.f.migrate()
        self.rejects(lambda: self.f.plan([migration_operation(operation_id="again", reason="No reset")]), "DOMAIN_MIGRATION")

    def test_old_database_reopen_audit_and_new_snapshot_identity(self):
        before = self.f.backend.state()
        other = SQLiteReferenceBackend(self.f.root / "graph.db", catalog=self.f.catalog, schema_id=self.f.schema, nodes={}, sandbox=True)
        try:
            self.assertEqual(other.state(), before)
            self.assertNotIn("classifications", other.state())
            other.audit()
        finally:
            other.close()
        old_snapshot = self.f.backend.snapshot(self.f.catalog)
        self.f.migrate()
        new_snapshot = self.f.backend.snapshot(self.f.catalog)
        self.assertNotEqual(old_snapshot, new_snapshot)
        again = SQLiteReferenceBackend(self.f.root / "graph.db", catalog=self.f.catalog, schema_id=self.f.schema, nodes={}, sandbox=True)
        try:
            self.assertEqual(again.state(), self.f.backend.state())
            again.audit(trust=self.f.trust)
        finally:
            again.close()

    def test_every_fault_point_rolls_back_state_records_and_journal(self):
        self.f.migrate()
        ref = self.f.assign()
        plan = self.f.assignment_plan(ref)
        approvals = self.f.approvals(plan)
        tables = ("trace_state", "trace_meta", "trace_source_status", "trace_records", "trace_journal")
        before = {t: list(self.f.backend.db.execute("SELECT * FROM " + t)) for t in tables}
        for target in ("before_state_write", "after_state_write", "after_journal_write", "before_commit"):
            def fault(name):
                if name == target:
                    raise RuntimeError("injected " + name)
            with self.assertRaises(RuntimeError):
                self.f.publish(plan, approvals=approvals, fault=fault)
            self.assertEqual(before, {t: list(self.f.backend.db.execute("SELECT * FROM " + t)) for t in tables})
            self.f.backend.audit(trust=self.f.trust)
        self.f.publish(plan, approvals=approvals)

    def test_stale_graph_cas(self):
        self.f.migrate()
        ref = self.f.assign()
        plan = self.f.assignment_plan(ref)
        approvals = self.f.approvals(plan)
        self.f.status_change(active=True)
        self.rejects(lambda: self.f.publish(plan, approvals=approvals), "STALE_GRAPH_VERSION")

    def test_stale_source_epoch_in_plan(self):
        self.f.migrate()
        ref = self.f.assign()
        plan = self.f.assignment_plan(ref)
        body = self.f.catalog.get(plan)
        body["source_epochs"][self.f.source] += 1
        forged = self.f.catalog.put("plan", body)
        self.rejects(lambda: self.f.service.preflight(self.f.catalog, forged, reviewed=True), "STALE_SOURCE_EPOCH")

    def test_current_source_withdrawal_blocks_new_classification(self):
        self.f.migrate()
        self.f.status_change()
        ref = self.f.assign()
        self.rejects(lambda: self.f.assignment_plan(ref), "STALE_EVIDENCE")

    def test_altered_signature_is_rejected_even_on_idempotent_retry(self):
        self.f.migrate()
        ref = self.f.assign()
        plan = self.f.assignment_plan(ref)
        auth, preflight = self.f.approvals(plan)
        self.f.publish(plan, approvals=(auth, preflight))
        bad = deepcopy(auth)
        bad["signature"] = "A" * 88
        self.rejects(lambda: self.f.publish(plan, approvals=(bad, preflight)), "SIGNATURE_INVALID")

    def test_model_key_cannot_review(self):
        self.f.migrate()
        ref = self.f.assign()
        plan = self.f.assignment_plan(ref)
        model = Signer.ephemeral("model")
        self.f.trust.enroll("model", IssuerPolicy(model.public_key(), "fixture-reviewer", frozenset({"AUTHORIZATION"}),
                            frozenset({"SET_SOURCE_CLASSIFICATION"}), frozenset({"test"}), frozenset({"SYNTHETIC"}), can_review=False))
        preflight = self.f.service.preflight(self.f.catalog, plan, reviewed=True)
        auth = authorize_plan(model, self.f.catalog.get(plan), self.f.catalog.hash(plan), reviewed_by="fixture-reviewer")
        self.rejects(lambda: self.f.publish(plan, approvals=(auth, preflight)), "REVIEW_AUTHORITY")

    def test_model_proposal_cannot_enter_plan(self):
        self.f.migrate()
        review = {"status": "PROPOSED", "reviewer_id": None, "reviewed_at": None, "rationale": "Model suggestion"}
        ref = self.f.assign(review=review)
        self.rejects(lambda: self.f.assignment_plan(ref), "DOMAIN_REVIEW")

    def test_review_attribution_must_match_signature_principal(self):
        self.f.migrate()
        ref = self.f.assign(review={**REVIEW, "reviewer_id": "someone-else"})
        plan = self.f.assignment_plan(ref)
        self.rejects(lambda: self.f.publish(plan), "DOMAIN_REVIEW")

    def test_future_review_rejected(self):
        self.f.migrate()
        ref = self.f.assign(review={**REVIEW, "reviewed_at": "2999-01-01T00:00:00Z"})
        plan = self.f.assignment_plan(ref)
        self.rejects(lambda: self.f.publish(plan), "DOMAIN_REVIEW")

    def test_application_must_enable_classification(self):
        plan = self.f.plan([migration_operation(operation_id="init", reason="test")])
        disabled = self.f.service_for(self.f.backend, classification_enabled=False)
        self.rejects(lambda: disabled.preflight(self.f.catalog, plan, reviewed=True), "DOMAIN_PUBLICATION_DISABLED")

    def test_taxonomy_must_be_application_pinned(self):
        self.f.migrate()
        ref = self.f.assign()
        plan = self.f.assignment_plan(ref)
        unpinned = self.f.service_for(self.f.backend, classification_taxonomy_hashes=frozenset())
        self.rejects(lambda: unpinned.preflight(self.f.catalog, plan, reviewed=True), "DOMAIN_TAXONOMY_UNTRUSTED")

    def test_predecessor_is_authoritative_not_merely_in_catalog(self):
        self.f.migrate()
        first = self.f.assign()
        uncommitted_successor = self.f.assign(["research:mathematics"], previous=first)
        self.rejects(lambda: self.f.assignment_plan(uncommitted_successor), "DOMAIN_REVISION")

    def test_two_assignments_to_same_source_in_one_plan_rejected(self):
        self.f.migrate()
        ref = self.f.assign()
        ops = [classification_operation(self.f.catalog, ref, operation_id=name) for name in ("one", "two")]
        self.rejects(lambda: self.f.plan(ops), "DOMAIN_REVISION")

    def test_operation_hash_binding(self):
        self.f.migrate()
        ref = self.f.assign()
        op = classification_operation(self.f.catalog, ref, operation_id="assign")
        op["taxonomy_hash"] = "0" * 64
        self.rejects(lambda: self.f.plan([op]), "DOMAIN_OPERATION_BINDING")

    def test_classification_does_not_bypass_global_graph_validation(self):
        self.f.migrate()
        ref = self.f.assign()
        snapshot = self.f.backend.snapshot(self.f.catalog)
        body = self.f.catalog.get(snapshot)
        body["assertions"]["invalid-existing-edge"] = {"assertion": {"subject": "missing", "predicate": "related", "object": "b", "qualifiers": {}},
                       "evidence_ids": [], "prerequisites": [], "active": True, "revision": 1}
        malformed = self.f.catalog.put("graph-snapshot", body)
        self.rejects(lambda: create_plan(self.f.catalog, run_id="domain-fixture", snapshot_id=malformed,
            operations=[classification_operation(self.f.catalog, ref, operation_id="assign")], security_scope="test",
            execution_mode="SYNTHETIC", idempotency_key="invalid", policy_version="reviewed-domain-fixture-v1",
            source_status=self.f.backend.statuses()), "UNKNOWN_NODE")

    def test_two_connections_compare_and_swap_one_winner(self):
        self.f.migrate()
        c1, c2 = Catalog(self.f.catalog.all()), Catalog(self.f.catalog.all())
        first = self.f.assign(["research:biology"], catalog=c1)
        second = self.f.assign(["research:physics"], catalog=c2)
        other = SQLiteReferenceBackend(self.f.root / "graph.db", catalog=c2, schema_id=self.f.schema, nodes={}, sandbox=True)
        try:
            s2 = self.f.service_for(other)
            p1 = self.f.assignment_plan(first, catalog=c1, key="first")
            p2 = self.f.assignment_plan(second, catalog=c2, backend=other, key="second")
            a1 = self.f.approvals(p1, catalog=c1)
            a2 = self.f.approvals(p2, catalog=c2, service=s2)
            def publish(args):
                plan, c, service, approvals = args
                try:
                    return self.f.publish(plan, catalog=c, service=service, approvals=approvals)["replayed"]
                except ContractError as exc:
                    return exc.code
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(publish, [(p1, c1, self.f.service, a1), (p2, c2, s2, a2)]))
            self.assertEqual(results.count(False), 1)
            self.assertEqual(results.count("STALE_GRAPH_VERSION"), 1)
            self.f.backend.audit(trust=self.f.trust)
        finally:
            other.close()

    def test_reopen_historical_audit_after_reclassification(self):
        self.f.migrate()
        first = self.f.assign()
        result = self.f.publish(self.f.assignment_plan(first))
        second = self.f.assign(["research:physics"], previous=first)
        self.f.publish(self.f.assignment_plan(second))
        old = loads(self.f.backend.db.execute("SELECT body FROM trace_journal WHERE version=?", (result["receipt"]["version"],)).fetchone()[0])
        self.assertEqual(old["state_after"]["classifications"]["assignments"][self.f.source], first)
        self.f.backend.audit(trust=self.f.trust)

    def test_tampered_stored_approval_detected(self):
        self.f.migrate()
        ref = self.f.assign()
        result = self.f.publish(self.f.assignment_plan(ref))
        auth_hash = result["event"]["authorization_hash"]
        for rid, body in self.f.backend.db.execute("SELECT id,body FROM trace_records WHERE kind='receipt'"):
            receipt = loads(body)
            if digest(receipt) == auth_hash:
                receipt["payload"]["reviewed_by"] = "forged"
                self.f.backend.db.execute("UPDATE trace_records SET body=? WHERE id=?", (dumps(receipt), rid))
                break
        self.rejects(lambda: self.f.backend.audit(trust=self.f.trust), "BACKEND_AUDIT")

    def test_audit_without_trust_does_not_claim_authenticated_history(self):
        self.f.migrate()
        self.assertFalse(self.f.backend.audit()["classification_authority_verified"])
        self.assertTrue(self.f.backend.audit(trust=self.f.trust)["classification_authority_verified"])


if __name__ == "__main__":
    unittest.main()
