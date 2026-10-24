"""Complete bundle validation with real modules and synthetic isolated inputs.

RECORDED exercises that contract branch; it is not real provider/deployment data.
No extracted-class harness, monkeypatched backend, or publication key is shipped.
"""
from copy import deepcopy
import unittest

import test_domain_publication as fixtures
from trace_gc.canonical import digest, dumps, loads
from trace_gc.catalog import Catalog
from trace_gc.domain_publication import validate_published_transaction
from trace_gc.errors import ContractError
from trace_gc.ledger import make_bundle
from trace_gc.policy import create_policy
from trace_gc.validation import validate_bundle


class DomainBundles(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.DomainPublication()
        self.f.EXECUTION_MODE = "RECORDED"
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        f = self.f
        self.checkpoint = f.enroll("checkpoint", {"RUN_CHECKPOINT"}, set())
        create_policy(f.c, version="fixture-policy", scope="tenant-a", population="fixture",
                      mode="REVIEWED", allowed_modes=["RECORDED"])
        f.migrate()
        self.assignment = f.assignment()
        self.plan = f.plan(self.assignment)
        self.result = f.publish(self.plan)
        self.event = f.journal()[-1]
        self.transaction_id = "transaction:" + digest({"kind": "transaction", "body": self.result["receipt"]})
        f.backend.snapshot(f.c)

    def bundle(self, *, catalog=None, transaction_id=None, profile="FINALIZED_PUBLISHED", signer=True):
        f = self.f
        return make_bundle(catalog or f.c, run_id="fixture-run", execution_mode="RECORDED",
            security_scope="tenant-a", graph_version=f.backend.state()["graph_version"],
            schema_hash=f.c.hash(f.schema), source_status=f.backend.statuses(),
            policy_version="fixture-policy", transaction_id=transaction_id or self.transaction_id,
            profile=profile, created_at=f.time(), signer=self.checkpoint if signer else None,
            ledger_prefix=self.event["lineage_prefix"])

    def verify(self, bundle):
        return validate_bundle(bundle, trust=self.f.trust, at=self.f.time())

    def test_full_published_bundle_round_trip(self):
        result = self.verify(loads(dumps(self.bundle())))
        self.assertEqual(result["status"], "PASS")
        self.assertTrue(result["lineage_complete"])
        self.assertTrue(result["checkpoint_authenticated"])
        self.assertFalse(result["authorization_granted"])
        self.assertEqual(result["graph_commits"], 0)
        self.assertEqual(result["model_calls"], 0)

    def test_full_analysis_bundle_round_trip(self):
        result = self.verify(loads(dumps(self.bundle(profile="FINALIZED_ANALYSIS", signer=False))))
        self.assertEqual(result["status"], "PASS")
        self.assertFalse(result["checkpoint_authenticated"])

    def test_published_requires_application_trust(self):
        with self.assertRaises(ContractError) as cm:
            validate_bundle(self.bundle(), at=self.f.time())
        self.assertEqual(cm.exception.code, "CHECKPOINT_UNTRUSTED")

    def test_published_requires_checkpoint(self):
        with self.assertRaises(ContractError) as cm:
            self.verify(self.bundle(signer=False))
        self.assertEqual(cm.exception.code, "CHECKPOINT_UNTRUSTED")

    def altered_transaction_bundle(self, **changes):
        records = [r for r in self.f.c.all() if r["id"] != self.transaction_id]
        catalog = Catalog(records)
        transaction = {**self.result["receipt"], **changes}
        new_id = catalog.put("transaction", transaction)
        return self.bundle(catalog=catalog, transaction_id=new_id)

    def test_signed_rehashed_bundle_cannot_change_idempotency_key(self):
        with self.assertRaises(ContractError) as cm:
            self.verify(self.altered_transaction_bundle(idempotency_key="different-key"))
        self.assertEqual(cm.exception.code, "TRANSACTION_PLAN_BINDING")

    def test_signed_rehashed_bundle_cannot_change_operation(self):
        with self.assertRaises(ContractError) as cm:
            self.verify(self.altered_transaction_bundle(operation_hash=digest("other-operation")))
        self.assertEqual(cm.exception.code, "TRANSACTION_PLAN_BINDING")

    def test_signed_rehashed_bundle_cannot_change_base_state(self):
        with self.assertRaises(ContractError) as cm:
            self.verify(self.altered_transaction_bundle(before_hash=digest("other-state")))
        self.assertEqual(cm.exception.code, "TRANSACTION_PLAN_BINDING")

    def test_signed_rehashed_bundle_cannot_change_committed_version(self):
        with self.assertRaises(ContractError) as cm:
            self.verify(self.altered_transaction_bundle(version=999))
        self.assertEqual(cm.exception.code, "TRANSACTION_VERSION")

    def test_missing_receipt_is_rejected(self):
        with self.assertRaises(ContractError) as cm:
            self.verify(self.altered_transaction_bundle(authorization_hash=digest("missing")))
        self.assertEqual(cm.exception.code, "TRANSACTION_RECEIPT_MISSING")

    def test_preflight_cannot_be_replaced_with_authorization(self):
        with self.assertRaises(ContractError) as cm:
            self.verify(self.altered_transaction_bundle(preflight_hash=self.result["receipt"]["authorization_hash"]))
        self.assertEqual(cm.exception.code, "RECEIPT_PURPOSE")

    def test_commit_before_authorization_fails(self):
        with self.assertRaises(ContractError) as cm:
            self.verify(self.altered_transaction_bundle(committed_at="2026-01-01T00:00:00Z"))
        self.assertEqual(cm.exception.code, "RECEIPT_EXPIRED")

    def test_current_reviewer_revocation_applies(self):
        bundle = self.bundle()
        self.f.trust.revoke("reviewer")
        with self.assertRaises(ContractError) as cm:
            self.verify(bundle)
        self.assertEqual(cm.exception.code, "UNTRUSTED_ISSUER")

    def test_current_publisher_revocation_applies(self):
        bundle = self.bundle()
        self.f.trust.revoke("publisher")
        with self.assertRaises(ContractError) as cm:
            self.verify(bundle)
        self.assertEqual(cm.exception.code, "UNTRUSTED_ISSUER")

    def test_validation_does_not_change_source_or_evidence(self):
        original = [self.f.c.record(ref) for ref in (self.f.source, self.f.evidence)]
        before = self.f.dump()
        self.verify(self.bundle())
        self.assertEqual(original, [self.f.c.record(ref) for ref in (self.f.source, self.f.evidence)])
        self.assertEqual(before, self.f.dump())

    def test_forged_snapshot_assignment_is_rejected_by_full_validator(self):
        bundle = self.bundle(profile="FINALIZED_ANALYSIS", signer=False)
        for record in bundle["records"]:
            if record["kind"] == "graph-snapshot":
                record["body"]["research_domains"]["assignments"][self.f.source]["assignment_hash"] = digest("forged")
                record["hash"] = digest({"kind": record["kind"], "body": record["body"]})
                break
        with self.assertRaises(ContractError) as cm:
            self.verify(bundle)
        self.assertEqual(cm.exception.code, "DOMAIN_SNAPSHOT_BINDING")
