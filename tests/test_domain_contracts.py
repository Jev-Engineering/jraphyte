"""Synthetic contract/Ed25519/ledger tests; not deployment qualification."""
from __future__ import annotations
import json
from copy import deepcopy
from pathlib import Path
import subprocess
import sys
import unittest

from trace_gc.canonical import digest
from trace_gc.catalog import Catalog
from trace_gc.domains import (VERSION, REVIEW_PURPOSE, REVIEW_OPERATION, taxonomy,
                              propose, assign, review_payload, validate_catalog)
from trace_gc.errors import ContractError
from trace_gc.ledger import make_bundle, build_ledger, validate_ledger, references
from trace_gc.schema import validate
from trace_gc.trust import Signer, TrustStore, IssuerPolicy

T0 = "2026-01-01T00:00:00Z"
T1 = "2026-01-01T00:00:01Z"
T2 = "2026-01-01T00:00:02Z"
T3 = "2026-01-01T00:00:03Z"
END = "2026-01-01T00:10:00Z"


class DomainContracts(unittest.TestCase):
    def setUp(self):
        self.c = Catalog()
        self.source = self.c.source("paper-a", "v1", "Graph methods for biological evidence.", scope="tenant-a")
        self.evidence = self.c.evidence(self.source)
        self.taxonomy = taxonomy(self.c, namespace="test-research", version="1.0.0", domains=[
            {"id": "research", "label": "Research"},
            {"id": "biology", "label": "Biology", "parent_ids": ["research"]},
            {"id": "computer-science", "label": "Computer science", "parent_ids": ["research"]},
        ])
        self.method = {"kind": "MODEL", "name": "synthetic-classifier", "version": "1.0.0", "artifact_hash": digest("fixture-only")}
        self.signer = Signer.ephemeral("test-reviewer")
        self.trust = self.enroll()

    def enroll(self, **overrides):
        config = dict(public_key=self.signer.public_key(), principal="reviewer-a",
                      purposes=frozenset({REVIEW_PURPOSE}), operations=frozenset({REVIEW_OPERATION}),
                      scopes=frozenset({"tenant-a"}), modes=frozenset({"SYNTHETIC"}),
                      can_review=True, maximum_risk=2)
        config.update(overrides)
        t = TrustStore(); t.enroll(self.signer.issuer, IssuerPolicy(**config))
        return t

    def proposal(self, **changes):
        values = dict(source_snapshot_id=self.source, taxonomy_id=self.taxonomy,
                      domain_ids=["computer-science", "biology"], method=self.method,
                      basis_ids=[self.evidence], source_epoch=0, effective_graph_version=1,
                      created_at=T0, execution_mode="SYNTHETIC")
        values.update(changes)
        return propose(self.c, **values)

    def receipt(self, proposal_id, *, who="reviewer-a", signer=None, issued_at=T1):
        body = (signer or self.signer).issue(REVIEW_PURPOSE, review_payload(self.c, proposal_id, who),
                                            issued_at=issued_at, expires_at=END)
        return self.c.put("receipt", body)

    def assignment(self, proposal_id=None, **changes):
        p = proposal_id or self.proposal()
        receipt_id = changes.pop("review_receipt_id", None)
        if receipt_id is None: receipt_id = self.receipt(p)
        values = dict(proposal_id=p, review_receipt_id=receipt_id,
                      reviewed_by="reviewer-a", trust=self.trust, at=T2)
        values.update(changes)
        return assign(self.c, **values)

    def mutate_proposal(self, key, value):
        b = self.c.get(self.proposal(), "classification-proposal"); b[key] = value
        return self.c.put("classification-proposal", b)

    def assert_code(self, code, f):
        with self.assertRaises(ContractError) as caught: f()
        self.assertEqual(caught.exception.code, code)

    def test_ids_are_content_addressed_and_order_independent(self):
        p = self.proposal()
        self.assertEqual(p, self.proposal(domain_ids=["biology", "computer-science"]))
        self.assertEqual(p, "classification-proposal:" + self.c.hash(p))

    def test_records_are_defensively_copied(self):
        p = self.proposal(); b = self.c.get(p); b["domain_ids"].clear()
        self.assertEqual(self.c.get(p)["domain_ids"], ["biology", "computer-science"])

    def test_old_source_and_evidence_bytes_unchanged(self):
        old = [self.c.record(self.source), self.c.record(self.evidence)]
        self.assignment()
        self.assertEqual(old, [self.c.record(self.source), self.c.record(self.evidence)])

    def test_unknown_label_rejected(self):
        self.assert_code("DOMAIN_UNKNOWN", lambda: self.proposal(domain_ids=["does-not-exist"]))

    def test_labels_not_implicitly_expanded_to_parents(self):
        p = self.proposal(domain_ids=["biology"])
        self.assertEqual(self.c.get(p)["domain_ids"], ["biology"])

    def test_forged_source_hash_rejected(self):
        self.assert_code("DOMAIN_SOURCE_HASH", lambda: self.mutate_proposal("source_hash", "0"*64))

    def test_forged_security_scope_rejected(self):
        self.assert_code("DOMAIN_SOURCE_SCOPE", lambda: self.mutate_proposal("security_scope", "tenant-b"))

    def test_taxonomy_hash_rejected(self):
        self.assert_code("DOMAIN_TAXONOMY_BINDING", lambda: self.mutate_proposal("taxonomy_hash", "0"*64))

    def test_taxonomy_version_rejected(self):
        self.assert_code("DOMAIN_TAXONOMY_BINDING", lambda: self.mutate_proposal("taxonomy_version", "2.0.0"))

    def test_unclassified_roundtrip(self):
        p = self.proposal(state="UNCLASSIFIED", domain_ids=[]); a = self.assignment(p)
        loaded = Catalog(reversed(self.c.all()))
        self.assertEqual(loaded.record(a), self.c.record(a))
        self.assertEqual(loaded.get(a)["domain_ids"], [])

    def test_classified_requires_nonempty_labels(self):
        self.assert_code("DOMAIN_STATE", lambda: self.proposal(domain_ids=[]))

    def test_unclassified_cannot_have_labels(self):
        self.assert_code("DOMAIN_STATE", lambda: self.proposal(state="UNCLASSIFIED"))

    def test_retirement_requires_predecessor(self):
        self.assert_code("DOMAIN_REVISION", lambda: self.proposal(state="RETIRED", domain_ids=[]))

    def test_retirement_appends_without_changing_prior(self):
        a = self.assignment(); before = self.c.record(a)
        p = self.proposal(state="RETIRED", domain_ids=[], supersedes=a, effective_graph_version=2, created_at=T2)
        rid = self.receipt(p, issued_at=T3)
        b = self.assignment(p, review_receipt_id=rid, at=T3)
        self.assertEqual(self.c.get(b)["revision"], 2)
        self.assertEqual(self.c.record(a), before)

    def test_effective_version_must_advance(self):
        a = self.assignment()
        self.assert_code("DOMAIN_REVISION", lambda: self.proposal(supersedes=a, effective_graph_version=1))

    def test_successor_cannot_predate_predecessor_review(self):
        a = self.assignment()
        self.assert_code("DOMAIN_REVISION", lambda: self.proposal(
            supersedes=a, effective_graph_version=2, created_at=T0))

    def test_successor_can_be_created_at_predecessor_review_time(self):
        a = self.assignment()
        p = self.proposal(supersedes=a, effective_graph_version=2, created_at=T1)
        self.assertEqual(self.c.get(p)["revision"], 2)

    def test_noninitial_revision_rejected(self):
        self.assert_code("DOMAIN_REVISION", lambda: self.mutate_proposal("revision", 2))

    def test_predecessor_hash_rejected(self):
        a = self.assignment(); p = self.proposal(supersedes=a, effective_graph_version=2, created_at=T2)
        b = self.c.get(p); b["supersedes_hash"] = "0"*64
        self.assert_code("DOMAIN_REVISION", lambda: self.c.put("classification-proposal", b))

    def test_competing_reviewed_revisions_rejected(self):
        self.assignment()
        p = self.proposal(domain_ids=["biology"])
        self.assert_code("DOMAIN_AMBIGUOUS_REVISION", lambda: self.assignment(p))

    def test_competing_proposals_are_not_publication(self):
        self.proposal(); self.proposal(domain_ids=["biology"])
        self.assertEqual(self.c.all("classification-assignment"), [])

    def test_boolean_revision_rejected(self):
        self.assert_code("SCHEMA_ERROR", lambda: self.mutate_proposal("revision", True))

    def test_unsupported_method_rejected(self):
        self.assert_code("SCHEMA_ERROR", lambda: self.proposal(method={**self.method, "kind": "UNTRUSTED_MAGIC"}))

    def test_floating_method_version_rejected(self):
        self.assert_code("DOMAIN_VERSION", lambda: self.proposal(method={**self.method, "version": "latest"}))

    def test_unrelated_basis_rejected(self):
        other = self.c.source("paper-b", "v1", "Other paper", scope="tenant-a")
        self.assert_code("DOMAIN_BASIS", lambda: self.proposal(basis_ids=[self.c.evidence(other)]))

    def test_unsupported_basis_kind_rejected(self):
        self.assert_code("DOMAIN_BASIS", lambda: self.proposal(basis_ids=[self.c.claim("label claim")]))

    def test_duplicate_labels_rejected(self):
        self.assert_code("SCHEMA_ERROR", lambda: self.proposal(domain_ids=["biology", "biology"]))

    def test_duplicate_basis_rejected(self):
        self.assert_code("SCHEMA_ERROR", lambda: self.proposal(basis_ids=[self.evidence, self.evidence]))

    def test_taxonomy_cycle_rejected(self):
        self.assert_code("DOMAIN_TAXONOMY_CYCLE", lambda: taxonomy(self.c, namespace="cycle", version="v1", domains=[
            {"id": "a", "label": "A", "parent_ids": ["b"]}, {"id": "b", "label": "B", "parent_ids": ["a"]}]))

    def test_taxonomy_dangling_parent_rejected(self):
        self.assert_code("DOMAIN_TAXONOMY", lambda: taxonomy(self.c, namespace="orphan", version="v1", domains=[
            {"id": "a", "label": "A", "parent_ids": ["missing"]}]))

    def test_taxonomy_same_version_cannot_change_meaning(self):
        self.assert_code("DOMAIN_TAXONOMY_REVISION", lambda: taxonomy(self.c, namespace="test-research", version="1.0.0",
                         domains=[{"id": "biology", "label": "Unrelated changed definition"}]))

    def test_valid_signature_from_unenrolled_signer_rejected(self):
        p=self.proposal(); other=Signer.ephemeral("unknown")
        self.assert_code("UNTRUSTED_ISSUER", lambda: self.assignment(p,review_receipt_id=self.receipt(p, signer=other)))

    def test_forged_review_signature_rejected(self):
        p=self.proposal(); r=self.c.get(self.receipt(p)); r["signature"]="AA=="
        rid=self.c.put("receipt",r)
        self.assert_code("SIGNATURE_INVALID",lambda:self.assignment(p,review_receipt_id=rid))

    def test_review_principal_must_match_enrollment(self):
        p=self.proposal(); rid=self.receipt(p,who="pretend-reviewer")
        self.assert_code("DOMAIN_REVIEW_AUTHORITY",lambda:self.assignment(p,review_receipt_id=rid,reviewed_by="pretend-reviewer"))

    def test_model_key_without_review_capability_rejected(self):
        self.assert_code("DOMAIN_REVIEW_AUTHORITY",lambda:self.assignment(trust=self.enroll(can_review=False)))

    def test_missing_operation_capability_rejected(self):
        self.assert_code("DOMAIN_REVIEW_AUTHORITY",lambda:self.assignment(trust=self.enroll(operations=frozenset())))

    def test_insufficient_risk_capability_rejected(self):
        self.assert_code("DOMAIN_REVIEW_AUTHORITY",lambda:self.assignment(trust=self.enroll(maximum_risk=1)))

    def test_review_scope_rejected(self):
        self.assert_code("AUTHORIZATION_SCOPE",lambda:self.assignment(trust=self.enroll(scopes=frozenset({"tenant-b"}))))

    def test_review_mode_rejected(self):
        self.assert_code("AUTHORIZATION_MODE",lambda:self.assignment(trust=self.enroll(modes=frozenset({"LIVE"}))))

    def test_expired_review_rejected(self):
        self.assert_code("RECEIPT_EXPIRED",lambda:self.assignment(at=END))

    def test_revoked_reviewer_rejected(self):
        self.trust.revoke(self.signer.issuer)
        self.assert_code("UNTRUSTED_ISSUER",lambda:self.assignment())

    def test_review_cannot_precede_proposal(self):
        p=self.proposal(created_at=T2)
        self.assert_code("DOMAIN_REVIEW_TIME",lambda:self.receipt(p))

    def test_review_target_tampering_rejected(self):
        p=self.proposal(); r=self.c.get(self.receipt(p)); r["payload"]["proposal_hash"]="0"*64
        self.assert_code("DOMAIN_REVIEW_BINDING",lambda:self.c.put("receipt",r))

    def test_assignment_cannot_change_approved_labels(self):
        a=self.assignment(); b=self.c.get(a); b["domain_ids"]=["biology"]
        self.assert_code("DOMAIN_PROPOSAL_BINDING",lambda:self.c.put("classification-assignment",b))

    def test_assignment_has_no_authority_flag(self):
        a=self.assignment()
        self.assertIs(self.c.get(a)["authorization_granted"],False)
        self.assertNotIn("permission",self.c.get(a))

    def test_arbitrary_classification_record_id_rejected(self):
        p=self.proposal(); r=self.c.record(p); r["id"]="forged:alias"
        self.assert_code("DOMAIN_RECORD_ID",lambda:self.c.add(r))

    def test_source_text_basis(self):
        p=self.proposal(basis_ids=[self.source]); self.assignment(p)
        validate_catalog(self.c,trust=self.trust,at=T2)

    def test_roundtrip_does_not_autoenroll_review_signer(self):
        self.assignment(); c=Catalog(reversed(self.c.all()))
        self.assert_code("UNTRUSTED_ISSUER",lambda:validate_catalog(c,trust=TrustStore(),at=T2))

    def test_failed_add_does_not_pollute_catalog(self):
        before=self.c.all()
        self.assert_code("DOMAIN_UNKNOWN",lambda:self.proposal(domain_ids=["missing"]))
        self.assertEqual(self.c.all(),before)

    def test_bundle_and_causal_ledger_roundtrip(self):
        a=self.assignment()
        self.c.put("policy",{"version":"fixture-v1","mode":"ANALYSIS_ONLY","security_scope":"tenant-a",
              "population":"synthetic","allowed_modes":["SYNTHETIC"],"maximum_risk":"R2",
              "qualification_metric":"ERRORS_PER_ACCEPTED_ACTION","required_checks":["fixture-only"]})
        status={self.source:{"active":True,"permission":"READ","epoch":0,"updated_at":T0,"tombstone":False}}
        bundle=make_bundle(self.c,run_id="domain-test",execution_mode="SYNTHETIC",security_scope="tenant-a",
                           graph_version=0,schema_hash=digest("fixture-schema"),source_status=status,
                           policy_version="fixture-v1",created_at=T3)
        validate("bundle",bundle)
        loaded=Catalog(json.loads(json.dumps(bundle))["records"])
        self.assertTrue(validate_ledger(bundle,loaded)["lineage_complete"])
        self.assertEqual(loaded.record(a),self.c.record(a))
        events={ref:e for e in bundle["ledger"] for ref in e["record_ids"]}
        b=self.c.get(a)
        self.assertLess(events[b["proposal_id"]]["sequence"],events[b["review_receipt_id"]]["sequence"])
        self.assertLess(events[b["review_receipt_id"]]["sequence"],events[a]["sequence"])
        self.assertEqual(events[a]["created_at"],b["reviewed_at"])
        self.assertIn((b["review_receipt_id"],"receipt"),references(self.c.record(a)))

    def test_append_only_ledger_preserves_original_prefix(self):
        before=build_ledger(self.c,run_id="domain-test",execution_mode="SYNTHETIC",created_at=T0)
        self.assignment()
        after=build_ledger(self.c,run_id="domain-test",execution_mode="SYNTHETIC",created_at=T3,prefix=before)
        self.assertEqual(after[:len(before)],before)

    def test_generated_schema_trees_match_and_are_reproducible(self):
        root=Path(__file__).resolve().parents[1]
        before={p.name:p.read_bytes() for p in (root/"schemas/runtime").glob("*.schema.json")}
        subprocess.run([sys.executable,str(root/"tools/build_schemas.py")],cwd=root,check=True,stdout=subprocess.PIPE)
        after={p.name:p.read_bytes() for p in (root/"schemas/runtime").glob("*.schema.json")}
        self.assertEqual(before,after)
        self.assertEqual(after,{p.name:p.read_bytes() for p in (root/"trace_gc/data/schemas").glob("*.schema.json")})


if __name__=="__main__": unittest.main()
