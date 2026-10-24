"""Research-domain v1 contracts, independent of real taxonomy/deployment approval."""
from copy import deepcopy
from pathlib import Path
import unittest

from trace_gc.canonical import digest, dumps, loads
from trace_gc.catalog import Catalog
from trace_gc.domains import create_assignment, reference_taxonomy, validate_catalog, verify_assignment, verify_taxonomy
from trace_gc.errors import ContractError
from trace_gc.ledger import make_bundle
from trace_gc.policy import create_policy
from trace_gc.validation import validate_bundle

STAMP = "2026-09-27T00:00:00Z"
REVIEW = {"status": "APPROVED", "reviewer_id": "fixture-reviewer", "reviewed_at": STAMP,
          "rationale": "Synthetic fixture review; not independent deployment qualification."}


def fixture_catalog():
    catalog = Catalog()
    body = reference_taxonomy()["body"]
    body["review"] = deepcopy(REVIEW)
    taxonomy_id = catalog.put("research-domain-taxonomy", body)
    source = catalog.source("paper-one", "snapshot-one", "A paper about computation and biology.", scope="test")
    evidence = catalog.evidence(source)
    return catalog, taxonomy_id, source, evidence


class DomainContractTests(unittest.TestCase):
    def setUp(self):
        self.catalog, self.taxonomy, self.source, self.evidence = fixture_catalog()

    def assign(self, labels=None, **kwargs):
        return create_assignment(self.catalog, source_snapshot_id=self.source, taxonomy_id=self.taxonomy,
                                 domain_ids=["research:biology", "research:computer-science"] if labels is None else labels,
                                 review=deepcopy(REVIEW), classifier_id="fixture-reviewer", classifier_version="fixture-v1", **kwargs)

    def rejects(self, action, code=None):
        with self.assertRaises(ContractError) as caught:
            action()
        if code is not None:
            self.assertEqual(caught.exception.code, code)

    def altered(self, ref, **changes):
        body = self.catalog.get(ref)
        body.update(changes)
        return self.catalog.put(self.catalog.record(ref)["kind"], body)

    def test_deterministic_multilabel_assignment_and_source_hash_preservation(self):
        originals = [self.catalog.record(self.source), self.catalog.record(self.evidence)]
        a = self.assign()
        b = self.assign(["research:computer-science", "research:biology", "research:biology"])
        self.assertEqual(a, b)
        self.assertEqual(verify_assignment(self.catalog, a)["domain_ids"], ["research:biology", "research:computer-science"])
        self.assertEqual(originals, [self.catalog.record(self.source), self.catalog.record(self.evidence)])

    def test_explicit_unclassified(self):
        ref = self.assign([])
        self.assertEqual(verify_assignment(self.catalog, ref)["status"], "UNCLASSIFIED")

    def test_supersession_and_retirement(self):
        one = self.assign()
        two = self.assign(["research:mathematics"], supersedes=one)
        three = self.assign([], supersedes=two, status="RETIRED")
        self.assertEqual(verify_assignment(self.catalog, three)["effective_revision"], 3)
        self.assertEqual(self.catalog.get(one)["domain_ids"], ["research:biology", "research:computer-science"])
        validate_catalog(self.catalog)

    def test_unknown_domain_rejected_without_orphan_record(self):
        count = len(self.catalog.all())
        self.rejects(lambda: self.assign(["research:invented"]), "DOMAIN_MEMBERSHIP")
        self.assertEqual(len(self.catalog.all()), count)

    def test_non_content_addressed_id_rejected(self):
        ref = self.assign()
        record = self.catalog.record(ref)
        record["id"] = "classification-assignment:caller-chosen"
        self.rejects(lambda: self.catalog.add(record), "DOMAIN_ID")

    def test_forged_source_hash(self):
        ref = self.altered(self.assign(), source_hash="0" * 64)
        self.rejects(lambda: verify_assignment(self.catalog, ref), "DOMAIN_SOURCE_HASH")

    def test_forged_source_scope(self):
        ref = self.altered(self.assign(), security_scope="other-tenant")
        self.rejects(lambda: verify_assignment(self.catalog, ref), "DOMAIN_SCOPE")

    def test_forged_taxonomy_hash(self):
        ref = self.altered(self.assign(), taxonomy_hash="0" * 64)
        self.rejects(lambda: verify_assignment(self.catalog, ref), "DOMAIN_TAXONOMY_HASH")

    def test_unsupported_provenance_method(self):
        self.rejects(lambda: self.assign(method="MODEL_AUTHORIZES"), "SCHEMA_ERROR")

    def test_cross_source_provenance_rejected(self):
        other = self.catalog.source("other", "1", "Other paper", scope="test")
        span = self.catalog.evidence(other)
        self.rejects(lambda: self.assign(basis_ids=[span]), "DOMAIN_PROVENANCE")

    def test_claim_is_not_a_source_classification_basis(self):
        claim = self.catalog.claim("Potential finding")
        self.rejects(lambda: self.assign(basis_ids=[claim]), "DOMAIN_PROVENANCE")

    def test_forged_basis_hash(self):
        ref = self.assign()
        body = self.catalog.get(ref)
        body["provenance"]["basis"][0]["record_hash"] = "f" * 64
        forged = self.catalog.put("classification-assignment", body)
        self.rejects(lambda: verify_assignment(self.catalog, forged), "DOMAIN_PROVENANCE")

    def test_revision_gap_rejected(self):
        one = self.assign()
        two = self.assign(["research:mathematics"], supersedes=one)
        forged = self.altered(two, effective_revision=4)
        self.rejects(lambda: verify_assignment(self.catalog, forged), "DOMAIN_REVISION")

    def test_ambiguous_reviewed_revision_rejected(self):
        self.assign()
        self.assign(["research:physics"])
        self.rejects(lambda: validate_catalog(self.catalog), "DOMAIN_REVISION")

    def test_missing_review_identity_rejected(self):
        body = self.catalog.get(self.assign())
        body["review"]["reviewer_id"] = None
        self.rejects(lambda: self.catalog.put("classification-assignment", body), "DOMAIN_REVIEW")

    def test_proposals_are_not_approved_assignments(self):
        review = {"status": "PROPOSED", "reviewer_id": None, "reviewed_at": None,
                  "rationale": "An untrusted classifier suggestion."}
        ref = create_assignment(self.catalog, source_snapshot_id=self.source, taxonomy_id=self.taxonomy,
                                domain_ids=["research:biology"], review=review, classifier_id="model",
                                classifier_version="pinned-model-revision", method="MODEL_ASSISTED")
        self.assertEqual(verify_assignment(self.catalog, ref)["review"]["status"], "PROPOSED")
        self.rejects(lambda: self.assign(["research:mathematics"], supersedes=ref), "DOMAIN_REVIEW")

    def test_hierarchy_cycle_rejected(self):
        body = self.catalog.get(self.taxonomy)
        body["domains"][0]["parent_ids"] = [body["domains"][1]["id"]]
        body["domains"][1]["parent_ids"] = [body["domains"][0]["id"]]
        self.rejects(lambda: self.catalog.put("research-domain-taxonomy", body), "DOMAIN_TAXONOMY")

    def test_unknown_hierarchy_parent_rejected(self):
        body = self.catalog.get(self.taxonomy)
        body["domains"][0]["parent_ids"] = ["research:missing"]
        self.rejects(lambda: self.catalog.put("research-domain-taxonomy", body), "DOMAIN_TAXONOMY")

    def test_taxonomy_id_cannot_be_repurposed_or_removed(self):
        for mutate in (lambda b: b["domains"][0].update(definition="A different meaning"),
                       lambda b: b["domains"].pop(0)):
            body = self.catalog.get(self.taxonomy)
            body.update(version=2, supersedes=self.taxonomy, supersedes_hash=self.catalog.hash(self.taxonomy))
            mutate(body)
            ref = self.catalog.put("research-domain-taxonomy", body)
            self.rejects(lambda: verify_taxonomy(self.catalog, ref), "DOMAIN_TAXONOMY")

    def test_retired_taxonomy_term_cannot_be_assigned(self):
        body = self.catalog.get(self.taxonomy)
        body["domains"][0]["status"] = "RETIRED"
        body.update(version=2, supersedes=self.taxonomy, supersedes_hash=self.catalog.hash(self.taxonomy))
        self.taxonomy = self.catalog.put("research-domain-taxonomy", body)
        self.rejects(lambda: self.assign(["research:biology"]), "DOMAIN_MEMBERSHIP")

    def test_multilabel_unclassified_ledger_and_bundle_roundtrip(self):
        self.assign(basis_ids=[self.evidence])
        other = self.catalog.source("unclassified-paper", "v1", "Unclassified source.", scope="test")
        create_assignment(self.catalog, source_snapshot_id=other, taxonomy_id=self.taxonomy, domain_ids=[],
                          review=REVIEW, classifier_id="fixture-reviewer", classifier_version="fixture-v1")
        create_policy(self.catalog, version="p1", scope="test", population="synthetic-only")
        from trace_gc.demo import relation
        schema = self.catalog.put("schema", {"version": "s1", "relations": {"related": relation("Entity", "Entity")}})
        statuses = {r["id"]: {"active": True, "permission": "READ", "epoch": 0,
                               "updated_at": STAMP, "tombstone": False} for r in self.catalog.all("source")}
        bundle = make_bundle(self.catalog, run_id="domain-contract", execution_mode="SYNTHETIC", security_scope="test",
                             graph_version=0, schema_hash=self.catalog.hash(schema), source_status=statuses,
                             policy_version="p1", created_at=STAMP)
        copied = loads(dumps(bundle))
        result = validate_bundle(copied)
        self.assertEqual(result["status"], "PASS")
        self.assertFalse(result["authorization_granted"])
        self.assertTrue({"DOMAIN_TAXONOMY", "CLASSIFICATION"} <= {e["stage"] for e in bundle["ledger"]})
        self.assertEqual(Catalog(copied["records"]).record(self.source), self.catalog.record(self.source))

    def test_packaged_reference_taxonomy_is_proposed_not_deployment_review(self):
        record = reference_taxonomy()
        self.assertEqual(record["body"]["review"]["status"], "PROPOSED")
        self.assertEqual(record["hash"], digest({"kind": record["kind"], "body": record["body"]}))
        Catalog([record])

    def test_both_generated_schema_trees_match(self):
        root = Path(__file__).resolve().parents[1]
        for file in (root / "schemas/runtime").glob("*.json"):
            self.assertEqual(file.read_bytes(), (root / "trace_gc/data/schemas" / file.name).read_bytes())


if __name__ == "__main__":
    unittest.main()
