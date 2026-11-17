"""Recorded review chronology of contract records; claimed reviews, not authentication."""
from copy import deepcopy
import unittest

from trace_gc.catalog import Catalog
from trace_gc.domains import create_assignment, verify_assignment, verify_taxonomy, validate_catalog
from trace_gc.errors import ContractError
from test_research_domain_contracts import fixture_catalog, REVIEW, STAMP


def reviewed(at):
    return {**REVIEW, "reviewed_at": at}


class ReviewOrderTests(unittest.TestCase):
    def setUp(self):
        self.c, self.taxonomy, self.source, self.evidence = fixture_catalog()

    def assignment(self, *, taxonomy=None, review=None, previous=None):
        return create_assignment(self.c, source_snapshot_id=self.source,
            taxonomy_id=taxonomy or self.taxonomy, domain_ids=["research:biology"],
            review=review or deepcopy(REVIEW), classifier_id="fixture-reviewer",
            classifier_version="chronology-regression-v1", supersedes=previous)

    def taxonomy_successor(self, previous, at):
        body = self.c.get(previous)
        body.update(version=body["version"] + 1, supersedes=previous,
                    supersedes_hash=self.c.hash(previous), review=reviewed(at))
        return self.c.put("research-domain-taxonomy", body)

    def reject_order(self, action):
        with self.assertRaises(ContractError) as caught:
            action()
        self.assertEqual(caught.exception.code, "DOMAIN_REVIEW_ORDER")

    def test_assignment_cannot_be_reviewed_before_its_exact_taxonomy(self):
        body = self.c.get(self.taxonomy)
        body["review"] = reviewed("2026-09-27T01:00:00Z")
        later = self.c.put("research-domain-taxonomy", body)
        before = self.c.all()
        self.reject_order(lambda: self.assignment(taxonomy=later))
        self.assertEqual(self.c.all(), before)  # Rejected constructors leave no orphan.

    def test_reclassification_cannot_backdate_predecessor_review(self):
        first = self.assignment(review=reviewed("2026-09-27T02:00:00Z"))
        self.reject_order(lambda: self.assignment(previous=first, review=reviewed("2026-09-27T01:00:00Z")))

    def test_taxonomy_cannot_backdate_predecessor_review(self):
        bad = self.taxonomy_successor(self.taxonomy, "2026-09-26T23:59:59Z")
        self.reject_order(lambda: verify_taxonomy(self.c, bad))

    def test_later_taxonomy_cannot_hide_backdated_ancestor(self):
        bad = self.taxonomy_successor(self.taxonomy, "2026-09-26T23:59:59Z")
        newest = self.taxonomy_successor(bad, "2026-09-27T04:00:00Z")
        self.reject_order(lambda: verify_taxonomy(self.c, newest))

    def test_direct_catalog_insertion_does_not_bypass_complete_validation(self):
        first = self.assignment(review=reviewed("2026-09-27T02:00:00Z"))
        body = self.c.get(first)
        body.update(effective_revision=2, supersedes=first, supersedes_hash=self.c.hash(first),
                    review=reviewed("2026-09-27T01:00:00Z"))
        forged = self.c.put("classification-assignment", body)
        self.reject_order(lambda: verify_assignment(self.c, forged))
        self.reject_order(lambda: validate_catalog(self.c))

    def test_equal_review_instants_with_different_offsets_are_valid(self):
        first = self.assignment(review=reviewed("2026-09-27T01:00:00+01:00"))
        second = self.assignment(previous=first, review=reviewed(STAMP))
        self.assertEqual(verify_assignment(self.c, second)["effective_revision"], 2)
        taxonomy = self.taxonomy_successor(self.taxonomy, "2026-09-26T20:00:00-04:00")
        self.assertEqual(verify_taxonomy(self.c, taxonomy)["version"], 2)

    def test_proposal_has_no_fabricated_review_time(self):
        ref = self.assignment(review={"status": "PROPOSED", "reviewer_id": None,
            "reviewed_at": None, "rationale": "Unapproved test proposal."})
        self.assertIsNone(verify_assignment(self.c, ref)["review"]["reviewed_at"])

    def test_monotone_history_preserves_source_evidence_and_previous_hashes(self):
        originals = [self.c.record(self.source), self.c.record(self.evidence), self.c.record(self.taxonomy)]
        first = self.assignment()
        frozen = self.c.record(first)
        second = self.assignment(previous=first, review=reviewed("2026-09-27T01:00:00Z"))
        validate_catalog(Catalog(self.c.all()))
        self.assertEqual(self.c.record(first), frozen)
        self.assertEqual([self.c.record(r["id"]) for r in originals], originals)
        self.assertEqual(verify_assignment(self.c, second)["supersedes_hash"], frozen["hash"])


if __name__ == "__main__":
    unittest.main()
