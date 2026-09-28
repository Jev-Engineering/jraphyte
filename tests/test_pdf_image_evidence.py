import copy
import unittest

from trace_gc.canonical import bytes_digest, digest, text_digest
from trace_gc.catalog import Catalog
from trace_gc.compiler import _references, materialize
from trace_gc.errors import ContractError
from trace_gc.ledger import build_ledger, make_bundle, references
from trace_gc.pdf_image_evidence import (CHECKS, candidate_hash, correct_transcription, fallback_route, handoff,
    held_reason, image_candidate, render_source, review_image, verify_artifacts)
from tools.image_evidence_fixtures import TEXT, synthetic_pdf

try:
    import fitz
    import PIL
    AVAILABLE = True
except ImportError:
    AVAILABLE = False


@unittest.skipUnless(AVAILABLE, "PyMuPDF and Pillow required for image evidence")
class ImageEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pdf = synthetic_pdf()
        cls.raw = TEXT.encode()

    def candidate(self, pdf=None, text=TEXT, **kwargs):
        pdf = self.pdf if pdf is None else pdf
        metadata, _, _ = render_source(pdf, dpi=kwargs.get("dpi", 72), crop=kwargs.get("crop"))
        args = dict(source_id="authored-synthetic", transcription=text, raw_output=self.raw,
            engine="authored-fixture-not-ocr", revision="fixture-v1", configuration={"inference": False}, dpi=72,
            input_crop_sha256=metadata["crop"]["png_sha256"])
        args.update(kwargs)
        return image_candidate(pdf, **args)

    def reviewed(self, candidate=None, pdf=None, **kwargs):
        args = dict(reviewer="synthetic-test-attestation", reviewer_kind="assistant",
            reviewed_at="2026-09-28T12:00:00Z", disposition="complete", checks={k: True for k in CHECKS})
        args.update(kwargs)
        return review_image(candidate or self.candidate(pdf), pdf_bytes=pdf or self.pdf, raw_output=self.raw, **args)

    def test_image_only_and_corrupt_layer_reach_review_without_native_offsets(self):
        for pdf in (self.pdf, synthetic_pdf(corrupt=True)):
            candidate = self.candidate(pdf)
            self.assertIsNone(candidate["review"])
            self.assertEqual(held_reason(candidate), "image_source_review_required")
            self.assertNotIn("spans", candidate)
            catalog = Catalog()
            result = handoff(catalog, self.reviewed(candidate, pdf), pdf_bytes=pdf, raw_output=self.raw, scope="test")
            self.assertEqual(result["status"], "REVIEWED_TEXT_EVIDENCE")
            evidence = catalog.get(result["evidence_id"])
            self.assertEqual(evidence["quote"], TEXT)
            self.assertEqual((evidence["start"], evidence["end"]), (0, len(TEXT)))
            self.assertEqual(evidence["offset_unit"], "UNICODE_CODEPOINT")
            self.assertFalse(result["admitted"])
        self.assertEqual(self.candidate()["native_observation"]["state"], "absent")
        with fitz.open(stream=synthetic_pdf(corrupt=True), filetype="pdf") as document:
            self.assertEqual(document[0].get_text().strip(), "X" * 12)
        # Available text is not proof of accurate Unicode mapping. An explicitly
        # requested image review also handles valid-but-wrong native characters.

    def test_rotation_scale_round_trip_and_exact_crop(self):
        for rotation in (0, 90, 180, 270):
            pdf = synthetic_pdf(rotation=rotation)
            metadata, page, crop = render_source(pdf, dpi=144, crop=[10, 20, 300, 400])
            matrix = fitz.Matrix(metadata["render"]["pdf_to_pixels"])
            inverse = fitz.Matrix(metadata["render"]["pixels_to_pdf"])
            for point in (fitz.Point(0, 0), fitz.Point(100, 80), fitz.Point(600, 240)):
                actual = point * matrix * inverse
                self.assertLess(abs(point - actual), 0.0001)
            c = self.candidate(pdf, dpi=144, crop=[10, 20, 300, 400], input_crop_sha256=bytes_digest(crop))
            verify_artifacts(c, pdf_bytes=pdf, raw_output=self.raw, page_png=page, crop_png=crop)

    def test_crops_distinguish_repeated_text_locations(self):
        pdf = synthetic_pdf(repeated=True)
        a = self.candidate(pdf, crop=[0, 55, 600, 100])
        b = self.candidate(pdf, crop=[0, 120, 600, 165])
        self.assertNotEqual(candidate_hash(a), candidate_hash(b))
        reviewed = self.reviewed(a, pdf)
        reviewed["crop"] = b["crop"]
        with self.assertRaises(ContractError):
            held_reason(reviewed)

    def test_crop_out_of_bounds_or_estimated_coordinates_rejected(self):
        for box in ([-1, 0, 20, 20], [0, 0, 601, 240], [1, 1, 1, 10], [0.5, 0, 10, 10]):
            with self.assertRaises(ContractError):
                render_source(self.pdf, dpi=72, crop=box)
        changed = self.candidate()
        changed["crop"]["location_basis"] = "model-estimate"
        with self.assertRaises(ContractError):
            held_reason(changed)

    def test_source_image_crop_raw_output_and_transform_tampering(self):
        c = self.reviewed()
        for kwargs in ({"pdf_bytes": synthetic_pdf(rotation=90)}, {"raw_output": b"invented"},
                       {"page_png": b"changed"}, {"crop_png": b"changed"}):
            args = {"pdf_bytes": self.pdf, "raw_output": self.raw, **kwargs}
            with self.assertRaises(ContractError):
                verify_artifacts(c, **args)
        c["render"]["pdf_to_pixels"][0] = 2
        c["review"]["candidate_sha256"] = candidate_hash(c)
        with self.assertRaises(ContractError):
            verify_artifacts(c, pdf_bytes=self.pdf, raw_output=self.raw)

    def test_edited_text_invalidates_review_even_if_text_hash_recomputed(self):
        c = self.reviewed()
        c["transcription"] += " Hallucinated words."
        c["transcription_sha256"] = text_digest(c["transcription"])
        with self.assertRaises(ContractError):
            handoff(Catalog(), c, pdf_bytes=self.pdf, raw_output=self.raw, scope="test")

    def test_attributed_unicode_correction_requires_a_new_review(self):
        previous = self.reviewed()
        corrected = correct_transcription(previous, transcription="We measure spin-½.", editor="test editor",
            editor_kind="assistant", edited_at="2026-09-28T13:00:00Z", reason="Authored correction fixture.")
        self.assertEqual(corrected["correction"]["previous_candidate_sha256"], candidate_hash(previous))
        self.assertEqual(corrected["ocr"], previous["ocr"])
        self.assertEqual(held_reason(corrected), "image_source_review_required")
        catalog = Catalog()
        result = handoff(catalog, self.reviewed(corrected), pdf_bytes=self.pdf, raw_output=self.raw, scope="test")
        evidence = catalog.get(result["evidence_id"])
        self.assertEqual(evidence["quote"], "We measure spin-½.")
        self.assertEqual(evidence["end"], len(evidence["quote"]))
        self.assertNotEqual(evidence["end"], len(evidence["quote"].encode("utf-8")))

    def test_hallucination_equation_reading_order_and_boundary_failures_stay_held(self):
        for failed in CHECKS:
            text = TEXT.replace("x = 2", "x = 3") if failed == "notation" else TEXT + " Invented claim."
            checks = {k: k != failed for k in CHECKS}
            candidate = self.reviewed(self.candidate(text=text), checks=checks)
            catalog = Catalog()
            result = handoff(catalog, candidate, pdf_bytes=self.pdf, raw_output=self.raw, scope="test")
            self.assertEqual(result["reason"], "image_review_check_failed")
            self.assertEqual(catalog.all(), [])

    def test_explicit_held_states_and_complete_text_budget(self):
        for state in ("partial", "absent", "ambiguous", "uncertain_equation", "error"):
            self.assertEqual(held_reason(self.reviewed(disposition=state)), "image_review_" + state)
        for state in ("truncated", "error"):
            self.assertEqual(held_reason(self.reviewed(self.candidate(output_status=state))), "ocr_" + state)
        self.assertEqual(held_reason(self.reviewed(), max_characters=2), "complete_transcription_exceeds_character_budget")
        self.assertEqual(held_reason(self.reviewed(), max_text_bytes=2), "complete_transcription_exceeds_byte_budget")
        self.assertEqual(held_reason(self.reviewed(self.candidate(input_crop_sha256=None))), "ocr_input_provenance_unverified")
        self.assertEqual(held_reason(self.reviewed(self.candidate(revision="unknown"))), "ocr_revision_unverified")

    def test_catalog_span_verification_closure_and_ledger_keep_image_lineage(self):
        catalog = Catalog()
        result = handoff(catalog, self.reviewed(), pdf_bytes=self.pdf, raw_output=self.raw, scope="test")
        source_id, image_id = result["source_snapshot_id"], result["image_evidence_id"]
        self.assertEqual(references(catalog.record(source_id)), [(image_id, "image-evidence-v1")])
        self.assertEqual(_references(catalog, source_id), [(image_id, "image-evidence-v1", "reviewed-image-lineage")])
        events = build_ledger(catalog, run_id="test", execution_mode="SYNTHETIC")
        self.assertEqual([e["record_ids"][0] for e in events], [image_id, source_id, result["evidence_id"]])
        transported = Catalog(catalog.all())
        transported.verify_evidence(result["evidence_id"])
        missing = Catalog(r for r in catalog.all() if r["id"] != image_id)
        with self.assertRaises(ContractError):
            missing.verify_evidence(result["evidence_id"])
        changed = catalog.get(source_id)
        changed["text"] += "x"; changed["text_hash"] = text_digest(changed["text"])
        wrong = catalog.put("source", changed)
        with self.assertRaises(ContractError):
            catalog.verify_evidence(catalog.evidence(wrong))

    def test_existing_native_evidence_and_fallback_remain_separate(self):
        catalog = Catalog()
        native = catalog.source("native-paper", "v1", "Native Unicode α = 2", scope="test")
        evidence = catalog.evidence(native, 7, 16)
        catalog.verify_evidence(evidence)
        assessment = {"proposal": True, "text": "native text"}
        before = copy.deepcopy(assessment)
        self.assertEqual(fallback_route(assessment)["route"], "existing_native_source_review")
        self.assertEqual(assessment, before)
        self.assertFalse(fallback_route({"proposal": False}, self.reviewed())["admitted"])

    def test_materialization_and_final_analysis_bundle_include_image_record(self):
        from trace_gc.demo import relation
        from trace_gc.policy import create_policy
        from trace_gc.validation import validate_bundle
        catalog = Catalog()
        result = handoff(catalog, self.reviewed(), pdf_bytes=self.pdf, raw_output=self.raw, scope="test")
        source, image = result["source_snapshot_id"], result["image_evidence_id"]
        claim = catalog.claim(TEXT)
        schema = catalog.put("schema", {"version": "image-test-v1", "relations": {"supports": relation("Document", "Claim")}})
        snapshot = catalog.put("graph-snapshot", {"graph_version": 0, "schema_id": schema,
            "schema_hash": catalog.hash(schema), "nodes": {"authored-synthetic": "Document", claim: "Claim"},
            "assertions": {}, "source_epochs": {source: 0}})
        candidate = catalog.candidate(id_="image-test-candidate", run_id="test", claim_id=claim,
            evidence_ids=[result["evidence_id"]], assertion={"subject": "authored-synthetic", "predicate": "supports", "object": claim, "qualifiers": {}})
        state, closure, _ = materialize(catalog, [candidate], [], snapshot)
        self.assertEqual(state["evidence"][0]["text"], TEXT)
        self.assertIn(image, closure["record_ids"])
        create_policy(catalog, version="image-test-policy", scope="test", population="authored-fixture")
        bundle = make_bundle(catalog, run_id="test", execution_mode="SYNTHETIC", security_scope="test",
            graph_version=0, schema_hash=catalog.hash(schema), source_status={source: {"active": False,
                "permission": "DENIED", "epoch": 0, "updated_at": "2026-09-28T12:00:00Z", "tombstone": False}},
            policy_version="image-test-policy")
        self.assertEqual(validate_bundle(bundle)["status"], "PASS")
        self.assertFalse(validate_bundle(bundle)["checkpoint_authenticated"])


if __name__ == "__main__":
    unittest.main()
