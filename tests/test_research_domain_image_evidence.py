"""Image-derived sources through domain-scoped retrieval, citations and revocation.

The image path is the delivered one: ``tools.image_evidence_fixtures`` renders a
lawful authored PDF, ``trace_gc.pdf_image_evidence`` renders/reviews/hands it off
(real PyMuPDF and Pillow), and the resulting source/evidence enter the existing
synthetic ``domain_corpus`` through the existing classification, snapshot, ACL
and retrieval contracts. The review is the authored fixture attestation of
``test_pdf_image_evidence``, not an independent human review. No OCR engine runs,
no private paper is used, and none of this is empirical acceptance (issues 10/11).
The graph fact is placed into the fixture snapshot by this test; ``handoff`` itself
never writes an assertion.
"""
from __future__ import annotations

from copy import deepcopy
import unittest
from unittest import mock

from trace_gc.catalog import Catalog
from trace_gc.canonical import bytes_digest, text_digest
from trace_gc.domains import create_assignment, verify_assignment
from trace_gc.errors import ContractError
from trace_gc.pdf_image_evidence import (CHECKS, REPRESENTATION, handoff, image_candidate, render_source,
                                         review_image)
from trace_gc.retrieval.contracts import RetrievalBudget, query
from trace_gc.retrieval.domains import research_domain_scope
from trace_gc.retrieval.fixtures import SCOPE, demo_access, domain_corpus
from trace_gc.retrieval.integration import validate_record
from trace_gc.retrieval.service import GraphRAGQueryService, HybridRetriever, validate_context
from trace_gc.retrieval.store import InMemoryGraphAdapter
from tools.image_evidence_fixtures import TEXT, synthetic_pdf

try:
    import fitz  # noqa: F401
    import PIL  # noqa: F401
    AVAILABLE = True
except ImportError:
    AVAILABLE = False

HELD_TEXT = "Unreviewed transcription mentions plasmid."
REVIEW = {"status": "APPROVED", "reviewer_id": "synthetic-domain-fixture", "reviewed_at": "2026-09-27T00:00:00Z",
          "rationale": "Fabricated contract test labels; not independent human research review."}
EDGE = "e-image"
BIOLOGY = ["research:biology"]


class SpyEmbedding:
    version = "image-domain-embedding-spy-fixture-v1"

    def __init__(self):
        self.seen = []

    def embed(self, texts):
        self.seen.extend(texts)
        return [[1.0, 0.0] for _ in texts]


@unittest.skipUnless(AVAILABLE, "PyMuPDF and Pillow required for image evidence")
class ImageDomainBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pdf = synthetic_pdf()
        cls.raw = TEXT.encode()
        cls.released = cls.reviewed()

    @classmethod
    def candidate(cls, text=TEXT, **kwargs):
        metadata, _, _ = render_source(cls.pdf, dpi=72, crop=None)
        args = dict(source_id="authored-synthetic", transcription=text, raw_output=cls.raw,
                    engine="authored-fixture-not-ocr", revision="fixture-v1", configuration={"inference": False},
                    dpi=72, input_crop_sha256=metadata["crop"]["png_sha256"])
        args.update(kwargs)
        return image_candidate(cls.pdf, **args)

    @classmethod
    def reviewed(cls, candidate=None, **kwargs):
        args = dict(reviewer="synthetic-test-attestation", reviewer_kind="assistant",
                    reviewed_at="2026-09-28T12:00:00Z", disposition="complete", checks={k: True for k in CHECKS})
        args.update(kwargs)
        return review_image(candidate or cls.candidate(), pdf_bytes=cls.pdf, raw_output=cls.raw, **args)

    def setUp(self):
        self.f = domain_corpus()
        self.c = self.f["catalog"]
        self.result = handoff(self.c, deepcopy(self.released), pdf_bytes=self.pdf, raw_output=self.raw, scope=SCOPE)
        self.assertEqual(self.result["status"], "REVIEWED_TEXT_EVIDENCE")
        self.budget = RetrievalBudget(maximum_tokens=150000, maximum_latency_ms=20000,
                                      maximum_edges=100, maximum_nodes=100, maximum_source_spans=100)

    def install(self, source_id, evidence_id, *, domains=BIOLOGY, basis=None):
        """Add one accepted fact backed by the image-derived evidence, classified and ACL-granted."""
        c, f = self.c, self.f
        assignment = create_assignment(c, source_snapshot_id=source_id, taxonomy_id=f["taxonomy_id"],
            domain_ids=list(domains), review=REVIEW, classifier_id="synthetic-image-domain-fixture",
            classifier_version="fixture-v1", basis_ids=basis)
        snapshot = c.get(f["snapshot_id"], "graph-snapshot")
        snapshot["nodes"]["Paper-I"] = "Document"
        snapshot["assertions"][EDGE] = {"assertion": {"subject": "Paper-I", "predicate": "uses_method",
            "object": "Method-randomized", "qualifiers": {}}, "evidence_ids": [evidence_id],
            "prerequisites": [], "active": True, "revision": 1}
        snapshot["source_epochs"][source_id] = 1
        snapshot["classifications"]["assignments"][source_id] = assignment
        snapshot["classifications"]["revision"] += 1
        statuses = f["adapter"].source_status
        statuses[source_id] = {"active": True, "permission": "READ", "epoch": 1,
                               "updated_at": "2026-09-28T00:00:00Z", "tombstone": False}
        snapshot_id = c.put("graph-snapshot", snapshot)
        adapter = InMemoryGraphAdapter(c, [f["previous_snapshot_id"], snapshot_id], statuses)
        access = demo_access(c, snapshot_id)
        f.update(snapshot_id=snapshot_id, adapter=adapter, access=access,
                 retriever=HybridRetriever(adapter, catalog=c, access_policy=access),
                 image_source_id=source_id, image_evidence_id=evidence_id, image_assignment_id=assignment)
        return assignment

    def install_released(self, **kwargs):
        kwargs.setdefault("basis", [self.result["evidence_id"]])
        return self.install(self.result["source_snapshot_id"], self.result["evidence_id"], **kwargs)

    def scope(self, domains=BIOLOGY):
        return research_domain_scope(self.c, self.f["taxonomy_id"], list(domains))

    def request(self, strategies=None, domains=BIOLOGY, **changes):
        return query(requesting_component="downstream-search", security_scope=SCOPE,
                     strategies=strategies or ["LEXICAL"], budget=self.budget,
                     focus_entities=changes.pop("focus_entities", []), text=changes.pop("text", ""),
                     include_conflicts=changes.pop("include_conflicts", False),
                     research_domain_scope=changes.pop("research_domain_scope", self.scope(domains)), **changes)

    def context(self, request):
        r = self.f["retriever"]
        result_id = r.retrieve(request)
        result = self.c.get(result_id, "retrieval-result")
        context = self.c.get(result["graph_context_id"], "graph-context")
        validate_context(self.c, result["graph_context_id"], current_access=r.access_policy,
                         current_status=self.f["adapter"].source_status)
        validate_record(self.c, self.c.record(result["lineage_id"]))
        validate_record(self.c, self.c.record(result_id))
        return context, result

    def image_items(self, context):
        return [i for i in context["items"] if self.f["image_source_id"] in i["source_ids"]]

    def forge_source(self, image=None, **overrides):
        """Store a source claiming image lineage that bypasses ``handoff`` (Catalog.add does not check it)."""
        if image is None:
            image_id = self.result["image_evidence_id"]
            body = self.c.get(self.result["source_snapshot_id"], "source")
        else:
            image_id = self.c.put("image-evidence-v1", image)
            body = {"source_id": image["source_id"], "version": self.c.hash(image_id),
                    "representation": REPRESENTATION, "text": image["transcription"],
                    "text_hash": image["transcription_sha256"], "security_scope": SCOPE,
                    "parser_version": REPRESENTATION, "raw_document_hash": image["source_sha256"],
                    "image_evidence_id": image_id}
        body.update(overrides)
        source_id = self.c.put("source", body)
        return source_id, self.c.evidence(source_id)


class ReleasedImageEvidenceTests(ImageDomainBase):
    def test_handoff_identity_and_hashes_are_exact(self):
        c, r = self.c, self.result
        image_id, source_id, evidence_id = r["image_evidence_id"], r["source_snapshot_id"], r["evidence_id"]
        source, evidence = c.get(source_id, "source"), c.get(evidence_id, "evidence")
        self.assertEqual(source["representation"], REPRESENTATION)
        self.assertEqual(source["parser_version"], REPRESENTATION)
        self.assertEqual(source["image_evidence_id"], image_id)
        self.assertEqual(source["version"], c.hash(image_id))
        self.assertEqual(source["raw_document_hash"], bytes_digest(self.pdf))
        self.assertEqual(source["text_hash"], text_digest(TEXT))
        self.assertEqual(evidence["source_hash"], c.hash(source_id))
        self.assertEqual((evidence["quote"], evidence["start"], evidence["end"]), (TEXT, 0, len(TEXT)))
        self.assertEqual((r["admitted"], r["graph_writes"]), (False, 0))
        c.verify_evidence(evidence_id)

    def test_classification_basis_is_the_verified_image_span(self):
        assignment_id = self.install_released()
        assignment = verify_assignment(self.c, assignment_id)
        evidence_id = self.result["evidence_id"]
        self.assertEqual(assignment["source_hash"], self.c.hash(self.result["source_snapshot_id"]))
        self.assertEqual(assignment["provenance"]["basis"],
                         [{"record_id": evidence_id, "record_hash": self.c.hash(evidence_id)}])
        self.assertEqual(assignment["domain_ids"], BIOLOGY)

    def test_released_authorized_classified_evidence_is_selected_by_each_evidence_channel(self):
        self.install_released()
        self.f["retriever"].embedding = SpyEmbedding()
        source_id, evidence_id = self.f["image_source_id"], self.f["image_evidence_id"]
        cases = {"LEXICAL": {"text": "stable"}, "VECTOR": {"text": "stable"},
                 "SOURCE": {"source_scope": [source_id]}, "EVIDENCE": {"focus_entities": ["Paper-I"]}}
        for strategy, changes in cases.items():
            with self.subTest(strategy=strategy):
                context, result = self.context(self.request([strategy], **changes))
                own = [i for i in self.image_items(context) if i["kind"] == "EVIDENCE"]
                self.assertEqual([i["canonical_ref"] for i in own], [evidence_id], (strategy, context["items"]))
                item = own[0]
                self.assertEqual(item["evidence_ids"], [evidence_id])
                self.assertEqual(item["source_ids"], [source_id])
                self.assertIn(TEXT, item["text"])
                self.assertFalse(item["instruction_authority"])
                self.assertEqual(item["research_domain"]["source_assignments"],
                                 {source_id: self.f["image_assignment_id"]})
                self.assertIn(evidence_id, context["selected_evidence_ids"])
                lineage = self.c.get(result["lineage_id"], "retrieval-lineage")
                self.assertTrue(any(row["item_id"] == item["id"] and strategy in row["methods"]
                                    for row in lineage["candidates"]))
        self.assertIn(TEXT, self.f["retriever"].embedding.seen)

    def test_graph_edge_backed_by_image_evidence_is_selected_in_domain(self):
        self.install_released()
        context, _ = self.context(self.request(["NEIGHBORHOOD"], focus_entities=["Paper-I"]))
        edges = [i for i in context["items"] if i["kind"] == "EDGE" and EDGE in i["assertion_ids"]]
        self.assertTrue(edges, context["items"])
        self.assertIn(self.f["image_evidence_id"], edges[0]["evidence_ids"])
        self.assertIn(self.f["image_source_id"], edges[0]["source_ids"])

    def test_answer_cites_the_exact_image_span_and_rejects_forged_citations(self):
        self.install_released()
        answer = GraphRAGQueryService(self.f["retriever"]).query(self.request(text="stable"))["context"]
        source_id, evidence_id = self.f["image_source_id"], self.f["image_evidence_id"]
        citations = answer["citations"]
        self.assertEqual([x["evidence_id"] for x in citations], [evidence_id])
        self.assertEqual(citations[0], {"evidence_id": evidence_id, "source_snapshot_id": source_id,
            "source_id": "authored-synthetic", "source_hash": self.c.hash(source_id),
            "start": 0, "end": len(TEXT), "quote": TEXT})
        validate_record(self.c, self.c.record(self.c.put("graphrag-answer", deepcopy(answer))))
        forgeries = {"quote": TEXT + " Invented.", "source_hash": self.c.hash(self.result["image_evidence_id"]),
                     "start": 1, "end": len(TEXT) - 1, "source_id": "another-source",
                     "source_snapshot_id": self.result["image_evidence_id"]}
        for key, value in forgeries.items():
            with self.subTest(forged=key):
                body = deepcopy(answer)
                body["citations"][0][key] = value
                with self.assertRaisesRegex(ContractError, "PROVENANCE_MISMATCH"):
                    validate_record(self.c, self.c.record(self.c.put("graphrag-answer", body)))
        removed = deepcopy(answer)
        removed["citations"] = []
        with self.assertRaisesRegex(ContractError, "PROVENANCE_MISMATCH"):
            validate_record(self.c, self.c.record(self.c.put("graphrag-answer", removed)))


class ImageExclusionTests(ImageDomainBase):
    def setUp(self):
        super().setUp()
        self.install_released()
        self.source_id = self.f["image_source_id"]
        self.evidence_id = self.f["image_evidence_id"]

    def assert_excluded(self, context, spy=None):
        self.assertEqual(self.image_items(context), [])
        self.assertNotIn(self.evidence_id, context["selected_evidence_ids"])
        if spy is not None:
            self.assertNotIn(TEXT, spy.seen)

    def test_wrong_domain_selection_excludes_image_evidence_on_every_channel(self):
        spy = self.f["retriever"].embedding = SpyEmbedding()
        for domains in (["research:chemistry"], ["research:mathematics"]):
            for strategy, changes in (("LEXICAL", {"text": "stable"}), ("VECTOR", {"text": "stable"}),
                                      ("SOURCE", {"source_scope": [self.source_id]}),
                                      ("EVIDENCE", {"focus_entities": ["Paper-I"]}),
                                      ("NEIGHBORHOOD", {"focus_entities": ["Paper-I"]})):
                with self.subTest(domains=domains, strategy=strategy):
                    context, _ = self.context(self.request([strategy], domains=domains, include_historical=True, **changes))
                    self.assert_excluded(context, spy)

    def test_missing_source_grant_or_wrong_principal_excludes_without_verifying_or_embedding(self):
        spy = self.f["retriever"].embedding = SpyEmbedding()
        for name in ("missing_grant", "wrong_user"):
            with self.subTest(case=name):
                policy = deepcopy(self.f["access"])
                if name == "missing_grant":
                    del policy["grants"]["source:" + self.source_id]
                else:
                    policy["grants"]["source:" + self.source_id]["users"] = ["someone-else"]
                self.f["retriever"].set_access_policy(policy)
                for strategy, changes in (("LEXICAL", {"text": "stable"}), ("VECTOR", {"text": "stable"}),
                                          ("NEIGHBORHOOD", {"focus_entities": ["Paper-I"]})):
                    context, _ = self.context(self.request([strategy], **changes))
                    self.assert_excluded(context, spy)

    def test_revoked_inactive_denied_or_tombstoned_source_is_excluded_current_and_historical(self):
        statuses = self.f["adapter"].source_status
        original = deepcopy(statuses[self.source_id])
        spy = self.f["retriever"].embedding = SpyEmbedding()
        for change in ({"active": False}, {"permission": "DENIED"}, {"tombstone": True},
                       {"tombstone": True, "active": False, "permission": "DENIED"}):
            for historical in (False, True):
                with self.subTest(change=change, historical=historical):
                    statuses[self.source_id] = {**original, **change}
                    extra = {"include_historical": True, "mode": "HISTORICAL"} if historical else {}
                    for strategy, changes in (("LEXICAL", {"text": "stable"}), ("VECTOR", {"text": "stable"}),
                                              ("SOURCE", {"source_scope": [self.source_id]}),
                                              ("NEIGHBORHOOD", {"focus_entities": ["Paper-I"]})):
                        context, _ = self.context(self.request([strategy], **changes, **extra))
                        self.assert_excluded(context, spy)
        statuses[self.source_id] = original

    def test_exclusion_is_specific_to_the_revoked_image_source(self):
        self.f["adapter"].source_status[self.source_id]["active"] = False
        context, _ = self.context(self.request(["LEXICAL"], text="randomized", include_historical=True, mode="HISTORICAL"))
        self.assertIn(self.f["evidence"]["e-method"], context["selected_evidence_ids"])
        self.assert_excluded(context)

    def test_revocation_after_retrieval_invalidates_the_stored_context(self):
        _, result = self.context(self.request(text="stable"))
        self.f["adapter"].source_status[self.source_id].update(active=False, epoch=2)
        with self.assertRaises(ContractError):
            self.f["retriever"].validate_live_context(result["graph_context_id"])


class ImageAuthorityTests(ImageDomainBase):
    """Current image-evidence validation is authoritative for an authorized reader."""

    def retrieve_code(self, source_id, evidence_id):
        self.install(source_id, evidence_id)
        with self.assertRaises(ContractError) as caught:
            self.f["retriever"].retrieve(self.request(text="stable"))
        return caught.exception.code

    def test_source_binding_fields_are_rechecked_at_retrieval(self):
        for name in ("parser_version", "version", "raw_document_hash", "text", "other_image_record"):
            with self.subTest(mutation=name):
                self.setUp()
                overrides = {
                    "parser_version": {"parser_version": "identity-v1"},
                    "version": {"version": "stale-version"},
                    "raw_document_hash": {"raw_document_hash": "0" * 64},
                    "text": {"text": TEXT + " Added.", "text_hash": text_digest(TEXT + " Added.")},
                    "other_image_record": {"image_evidence_id": self.c.put(
                        "image-evidence-v1", self.reviewed(self.candidate(source_id="other-synthetic")))},
                }[name]
                source_id, evidence_id = self.forge_source(**overrides)
                self.assertEqual(self.retrieve_code(source_id, evidence_id), "IMAGE_SOURCE_BINDING")

    def test_missing_image_record_fails_closed(self):
        source_id, evidence_id = self.forge_source(image_evidence_id="image-evidence-v1:" + "0" * 64)
        self.assertEqual(self.retrieve_code(source_id, evidence_id), "MISSING_REFERENCE")

    def test_image_lineage_on_another_representation_is_a_schema_error(self):
        body = self.c.get(self.result["source_snapshot_id"], "source")
        with self.assertRaises(ContractError):
            self.c.put("source", {**body, "representation": "utf8-text-v1"})
        del body["image_evidence_id"]
        with self.assertRaises(ContractError):
            self.c.put("source", body)

    def test_image_record_changed_after_review_is_stale(self):
        image = self.c.get(self.result["image_evidence_id"], "image-evidence-v1")
        image["transcription"] += " Hallucinated words."
        image["transcription_sha256"] = text_digest(image["transcription"])
        source_id, evidence_id = self.forge_source(image)
        self.assertEqual(self.retrieve_code(source_id, evidence_id), "IMAGE_REVIEW_STALE")

    def test_held_image_records_stored_outside_handoff_are_not_retrievable(self):
        failed = {k: k != "notation" for k in CHECKS}
        held = {
            "unreviewed": self.candidate(HELD_TEXT),
            "failed_check": self.reviewed(self.candidate(HELD_TEXT), checks=failed),
            "partial_review": self.reviewed(self.candidate(HELD_TEXT), disposition="partial"),
            "unverified_revision": self.reviewed(self.candidate(HELD_TEXT, revision="unknown")),
            "truncated_ocr": self.reviewed(self.candidate(HELD_TEXT, output_status="truncated")),
        }
        for name, image in held.items():
            with self.subTest(held=name):
                self.setUp()
                source_id, evidence_id = self.forge_source(image)
                self.install(source_id, evidence_id)
                with self.assertRaises(ContractError) as caught:
                    self.f["retriever"].retrieve(self.request(text="plasmid"))
                self.assertEqual(caught.exception.code, "IMAGE_REVIEW_REQUIRED")

    def retrieve_context(self, request):
        """Retrieve once, returning the context and every evidence id passed to Catalog.verify_evidence."""
        original = Catalog.verify_evidence
        with mock.patch.object(Catalog, "verify_evidence", autospec=True, side_effect=original) as spy:
            result_id = self.f["retriever"].retrieve(request)
        result = self.c.get(result_id, "retrieval-result")
        return self.c.get(result["graph_context_id"], "graph-context"), [call.args[1] for call in spy.call_args_list]

    def deny_source(self, source_id):
        policy = deepcopy(self.f["access"])
        del policy["grants"]["source:" + source_id]
        self.f["retriever"].set_access_policy(policy)

    # Phases: (1) authority/projection integrity of accepted classification assignments is
    # evaluated for every reader, before the ACL filter exists, and covers an evidence-span
    # basis (including image lineage) but not a source-record basis; (2) candidate evaluation,
    # selection, context text and embedding input are ACL-gated per reader.
    def test_unauthorized_reader_with_source_record_basis_never_has_invalid_lineage_evaluated(self):
        source_id, evidence_id = self.forge_source(self.candidate(HELD_TEXT))
        self.install(source_id, evidence_id)   # default basis: the source record, not the image span
        self.deny_source(source_id)
        spy = self.f["retriever"].embedding = SpyEmbedding()
        for strategy in ("LEXICAL", "VECTOR"):
            context, verified = self.retrieve_context(self.request([strategy], text="plasmid"))
            self.assertEqual(self.image_items(context), [])
            self.assertNotIn(evidence_id, context["selected_evidence_ids"])
            self.assertNotIn(evidence_id, verified)
        self.assertNotIn(HELD_TEXT, spy.seen)

    def test_unauthorized_reader_with_evidence_span_basis_is_validated_at_authority_then_excluded(self):
        self.install_released()   # classification basis is the image evidence span
        evidence_id = self.f["image_evidence_id"]
        self.deny_source(self.f["image_source_id"])
        spy = self.f["retriever"].embedding = SpyEmbedding()
        for strategy, changes in (("LEXICAL", {"text": "stable"}), ("VECTOR", {"text": "stable"}),
                                  ("NEIGHBORHOOD", {"focus_entities": ["Paper-I"]})):
            with self.subTest(strategy=strategy):
                context, verified = self.retrieve_context(self.request([strategy], **changes))
                # Intended boundary: authority validation of the accepted projection ran for this
                # reader even though they have no grant; the candidate was still excluded.
                self.assertIn(evidence_id, verified)
                self.assertEqual(self.image_items(context), [])
                self.assertNotIn(evidence_id, context["selected_evidence_ids"])
                self.assertNotIn(TEXT, repr(context["items"]))
        self.assertNotIn(TEXT, spy.seen)

    def test_invalid_authoritative_image_fails_the_whole_query_for_every_reader(self):
        self.install_released()
        image_id, source_id = self.result["image_evidence_id"], self.f["image_source_id"]
        broken = Catalog(r for r in self.c.all() if r["id"] != image_id)
        adapter = InMemoryGraphAdapter(broken, [self.f["previous_snapshot_id"], self.f["snapshot_id"]],
                                       self.f["adapter"].source_status)
        request = self.request(text="stable")
        denied = deepcopy(self.f["access"])
        del denied["grants"]["source:" + source_id]
        failures = []
        for policy in (self.f["access"], denied):
            retriever = HybridRetriever(adapter, catalog=broken, access_policy=policy)
            with self.assertRaises(ContractError) as caught:
                retriever.retrieve(request)
            failures.append((caught.exception.code, str(caught.exception)))
        # No per-edge skip and no reader-dependent signal: both readers fail identically.
        self.assertEqual(failures[0], failures[1])
        self.assertEqual(failures[0][0], "MISSING_REFERENCE")

    def test_classification_basis_cannot_cite_a_source_with_invalid_lineage(self):
        source_id, evidence_id = self.forge_source(parser_version="identity-v1")
        before = len(self.c.all("classification-assignment"))
        with self.assertRaises(ContractError) as caught:
            create_assignment(self.c, source_snapshot_id=source_id, taxonomy_id=self.f["taxonomy_id"],
                domain_ids=BIOLOGY, review=REVIEW, classifier_id="synthetic-image-domain-fixture",
                classifier_version="fixture-v1", basis_ids=[evidence_id])
        self.assertEqual(caught.exception.code, "IMAGE_SOURCE_BINDING")
        self.assertEqual(len(self.c.all("classification-assignment")), before)


class HeldHandoffNeverReachesRetrievalTests(ImageDomainBase):
    def test_held_candidates_store_nothing_and_are_not_retrievable(self):
        failed = {k: k != "reading_order" for k in CHECKS}
        cases = {
            "image_source_review_required": self.candidate(HELD_TEXT),
            "image_review_check_failed": self.reviewed(self.candidate(HELD_TEXT), checks=failed),
            "image_review_ambiguous": self.reviewed(self.candidate(HELD_TEXT), disposition="ambiguous"),
            "ocr_revision_unverified": self.reviewed(self.candidate(HELD_TEXT, revision="unknown")),
            "ocr_truncated": self.reviewed(self.candidate(HELD_TEXT, output_status="truncated")),
        }
        for reason, candidate in cases.items():
            with self.subTest(reason=reason):
                before = [r["id"] for r in self.c.all()]
                outcome = handoff(self.c, candidate, pdf_bytes=self.pdf, raw_output=self.raw, scope=SCOPE)
                self.assertEqual((outcome["status"], outcome["reason"], outcome["admitted"]), ("HELD", reason, False))
                self.assertEqual([r["id"] for r in self.c.all()], before)
                self.assertFalse([r for r in self.c.all("source") if r["body"]["text"] == HELD_TEXT])
        # The released image from setUp remains the only image-derived source.
        self.install_released()
        spy = self.f["retriever"].embedding = SpyEmbedding()
        for strategy in ("LEXICAL", "VECTOR"):
            context, _ = self.context(self.request([strategy], text="plasmid"))
            self.assertFalse([i for i in context["items"] if "plasmid" in i["text"]])
        self.assertIn(TEXT, spy.seen)
        self.assertNotIn(HELD_TEXT, spy.seen)


if __name__ == "__main__":
    unittest.main()
