"""Exercise classification integrity with actual synthetic transactions and signatures."""
from copy import deepcopy
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from trace_gc.canonical import digest, dumps, loads
from trace_gc.catalog import Catalog
from trace_gc.conformance import legacy_test_policy
from trace_gc.domain_publication import migration_operation
from trace_gc.errors import ContractError
from trace_gc.ledger import make_bundle
from trace_gc.legacy import PinnedLegacyBackend
from trace_gc.plans import create_plan
from trace_gc.trust import IssuerPolicy, Signer, authorize_plan
from trace_gc.validation import validate_bundle
from test_research_domain_transactions import DomainFixture


class PublicationRegressions:
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.f = DomainFixture(temp.name, backend_factory=self.backend_factory)
        self.addCleanup(self.f.close)
        self.b = self.f.backend
        self.ordinary = Signer.ephemeral("ordinary-reviewer")
        self.f.trust.enroll(self.ordinary.issuer, IssuerPolicy(self.ordinary.public_key(), "fixture-operator",
            frozenset({"AUTHORIZATION", "RUN_CHECKPOINT"}), frozenset({"PROPOSE_SCHEMA_MIGRATION"}),
            frozenset({"test"}), frozenset({"SYNTHETIC", "RECORDED"}), can_review=True))

    def ordinary_plan(self, *, mode="SYNTHETIC"):
        c = self.f.catalog
        schema = c.get(self.f.schema, "schema")
        schema["version"] = "new-fixture-schema"
        target = c.put("schema", schema)
        impact = {"before_schema_hash": c.hash(self.f.schema), "target_schema_hash": c.hash(target),
                  "affected_assertion_ids": [], "affected_node_ids": []}
        return create_plan(c, run_id="domain-fixture", snapshot_id=self.b.snapshot(c), operations=[{
            "id": "propose-schema", "operation": "PROPOSE_SCHEMA_MIGRATION", "risk_class": "R5",
            "target_schema_id": target, "mapping": {}, "impact": impact, "reason": "Synthetic schema proposal",
        }], security_scope="test", execution_mode=mode, idempotency_key=f"proposal-{self.b.state()['graph_version']}",
            policy_version="reviewed-domain-fixture-v1", source_status=self.b.statuses())

    def ordinary_approvals(self, plan):
        c = self.f.catalog
        return (authorize_plan(self.ordinary, c.get(plan), c.hash(plan), reviewed_by="fixture-operator"),
                self.f.service.preflight(c, plan, reviewed=True))

    def erase_source(self):
        self.f.status_change(permission="DENIED", tombstone=True)
        erased = self.b.erase_cached_content(self.f.source, reason="Synthetic erasure fixture")["erased_ids"]
        self.assertIn(self.f.source, erased)
        self.assertIn(self.f.evidence, erased)
        survivors = [record for record in self.f.catalog.all() if record["id"] not in erased]
        plans = {record["hash"] for record in survivors if record["kind"] == "plan"}
        self.f.catalog = Catalog(record for record in survivors if record["kind"] != "receipt"
                                 or record["body"]["purpose"] not in {"AUTHORIZATION", "PREFLIGHT"}
                                 or record["body"]["payload"]["plan_hash"] in plans)
        return erased

    def test_old_erasure_with_unrelated_erased_plan_allows_migration_and_retry(self):
        plan = self.ordinary_plan()
        self.f.publish(plan, approvals=self.ordinary_approvals(plan))
        erased = self.erase_source()
        self.assertIn(plan, erased)
        self.assertEqual(self.b.audit(trust=self.f.trust)["classification_replay"], "PASS")
        self.f.migrate()
        approved = self.b.audit(trust=self.f.trust)
        self.assertTrue(approved["classification_authority_verified"])
        plan = self.ordinary_plan()
        approvals = self.ordinary_approvals(plan)
        first = self.f.publish(plan, approvals=approvals)
        again = self.f.publish(plan, approvals=approvals)
        self.assertTrue(again["replayed"])
        self.assertEqual(again["receipt"], first["receipt"])
        self.assertEqual(first["receipt"]["classification_revision"], 1)

    def test_erased_classification_proof_leaves_ordinary_writes_and_retry_available(self):
        self.f.migrate()
        classification = self.f.assignment_plan(self.f.assign())
        classification_approvals = self.f.approvals(classification)
        self.f.publish(classification, approvals=classification_approvals)
        projection = self.b.state()["classifications"]
        historical_catalog = self.f.catalog
        self.erase_source()
        audit = self.b.audit(trust=self.f.trust)
        self.assertEqual(audit["classification_replay"], "UNAVAILABLE_ERASED_CONTENT")
        self.assertFalse(audit["classification_authority_verified"])
        with self.assertRaisesRegex(ContractError, "REPLAY_CONTENT_UNAVAILABLE"):
            self.f.publish(classification, approvals=classification_approvals, catalog=historical_catalog)
        plan = self.ordinary_plan()
        approvals = self.ordinary_approvals(plan)
        first = self.f.publish(plan, approvals=approvals)
        self.assertEqual(self.b.state()["classifications"], projection)
        self.assertEqual(self.f.publish(plan, approvals=approvals)["receipt"], first["receipt"])

    def test_revoked_historical_reviewer_blocks_authenticated_audit_but_not_ordinary_writes(self):
        self.f.migrate()
        self.f.trust.revoke(self.f.reviewer.issuer)
        with self.assertRaisesRegex(ContractError, "UNTRUSTED_ISSUER"):
            self.b.audit(trust=self.f.trust)
        plan = self.ordinary_plan()
        approvals = self.ordinary_approvals(plan)
        self.assertFalse(self.f.publish(plan, approvals=approvals)["replayed"])
        self.assertTrue(self.f.publish(plan, approvals=approvals)["replayed"])

    def test_expiry_during_history_audit_uses_acceptance_clock(self):
        plan_id = self.f.plan([migration_operation(operation_id="initialize", reason="Synthetic clock fixture")])
        auth, preflight = self.f.approvals(plan_id)
        audit = self.b.audit
        current = max(auth["issued_at"], preflight["issued_at"])
        def advance_clock(**kwargs):
            nonlocal current
            result = audit(**kwargs)
            current = auth["expires_at"]
            return result
        before = self.b.state()
        with patch("trace_gc.backend.now", side_effect=lambda: current), patch.object(self.b, "audit", advance_clock):
            with self.assertRaisesRegex(ContractError, "RECEIPT_EXPIRED"):
                self.f.publish(plan_id, approvals=(auth, preflight))
        self.assertEqual(self.b.state(), before)
        self.assertFalse(self.b.db.in_transaction)

        accepted_at = max(auth["issued_at"], preflight["issued_at"])
        with patch("trace_gc.backend.now", side_effect=[accepted_at, accepted_at]):
            receipt = self.f.publish(plan_id, approvals=(auth, preflight))["receipt"]
        self.assertEqual(receipt["committed_at"], accepted_at)
        self.assertTrue(self.b.audit(trust=self.f.trust)["classification_authority_verified"])


class ReferencePublicationRegressions(PublicationRegressions, unittest.TestCase):
    backend_factory = None

    def test_journal_key_must_match_signed_plan(self):
        event = deepcopy(self.f.migrate()["event"])
        event["idempotency_key"] = "changed-key"
        event["transaction_receipt"]["idempotency_key"] = "changed-key"
        event["hash"] = digest({k: v for k, v in event.items() if k not in {"hash", "transaction_receipt"}})
        event["transaction_receipt"]["event_hash"] = event["hash"]
        self.b.db.execute("UPDATE trace_journal SET key=?,body=?,hash=? WHERE version=?",
                          (event["idempotency_key"], dumps(event), event["hash"], event["version"]))
        with self.assertRaisesRegex(ContractError, "DOMAIN_AUDIT.*key"):
            self.b.audit(trust=self.f.trust)

    def test_finalized_bundle_requires_exact_legacy_receipt_fields_and_key(self):
        plan = self.ordinary_plan(mode="RECORDED")
        result = self.f.publish(plan, approvals=self.ordinary_approvals(plan))
        receipt = result["receipt"]
        for mutation in ({}, {"idempotency_key": "changed-key"},
                         {"classification_revision": 1, "classification_hash": "0" * 64}):
            with self.subTest(mutation=mutation):
                c = Catalog(record for record in self.f.catalog.all()
                            if record["kind"] != "transaction" or record["body"] != receipt)
                transaction = c.put("transaction", {**receipt, **mutation})
                bundle = make_bundle(c, run_id="domain-fixture", execution_mode="RECORDED", security_scope="test",
                    graph_version=receipt["version"], schema_hash=c.hash(self.f.schema), source_status=self.b.statuses(),
                    policy_version="reviewed-domain-fixture-v1", profile="FINALIZED_PUBLISHED", signer=self.ordinary,
                    transaction_id=transaction, ledger_prefix=result["event"]["lineage_prefix"])
                if mutation:
                    with self.assertRaisesRegex(ContractError, "TRANSACTION_PLAN_BINDING"):
                        validate_bundle(bundle, trust=self.f.trust)
                else:
                    self.assertEqual(validate_bundle(bundle, trust=self.f.trust)["status"], "PASS")


@unittest.skipUnless(os.environ.get("TRACE_GC_LEGACY_CORE"), "Exact pinned upstream core.py is required")
class PinnedPublicationRegressions(PublicationRegressions, unittest.TestCase):
    def backend_factory(self, path: Path, **kwargs):
        return PinnedLegacyBackend(path, core_path=os.environ["TRACE_GC_LEGACY_CORE"],
                                   legacy_policy=legacy_test_policy(), **kwargs)
