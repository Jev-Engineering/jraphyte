"""Authored PDF fixtures; none are real-paper qualification evidence."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from trace_gc.canonical import bytes_digest, digest
from trace_gc.pdf_notation_parallel_v4 import capture_notation
from trace_gc.pdf_source_parallel_v4 import source_lines, json_bytes
from trace_gc.reviewed_notation import CHECKS, REVIEW_VERSION, derive_reviewed, prepare_evidence

AVAILABLE = importlib.util.find_spec("fitz") is not None and importlib.util.find_spec("PIL") is not None


def fixture(kind="script", *, context=False, rotation=0, cropbox=False, extra_mark=False, extra_script=False, painted_rule=False):
    import fitz
    doc = fitz.open()
    page = doc.new_page(width=300, height=300)
    page.insert_text((80, 150), "x", fontname="tiit", fontsize=10)
    if kind in ("script", "both"):
        page.insert_text((84.44, 146), "2", fontname="tiro", fontsize=7)
    if kind == "both":
        page.insert_text((84.44, 153), "q", fontname="tiro", fontsize=7)
    if kind in ("diacritic", "fake_mark"):
        page.insert_text((80, 146), "^" if kind == "diacritic" else "b", fontname="tiro", fontsize=8)
    if extra_mark:
        page.insert_text((80, 144), "~", fontname="tiro", fontsize=8)
    if extra_script:
        page.insert_text((84.44, 146), "2", fontname="tiro", fontsize=7)
    if painted_rule:
        page.draw_line((79, 143), (85, 143), width=.4)
    if context:
        page.insert_text((95, 150), "prose", fontname="tiro", fontsize=10)
    if cropbox:
        page.set_cropbox(fitz.Rect(13, 17, 280, 280))
    page.set_rotation(rotation)
    pdf = doc.tobytes()
    doc.close()
    with fitz.open(stream=pdf, filetype="pdf") as reread:
        native = source_lines(reread[0])
    sidecar, _ = capture_notation(pdf, native)
    return pdf, json_bytes(native), json_bytes(sidecar)


def review_for(blobs, *, crop=None, kind="scripts", drop_sub=False):
    sidecar = json.loads(blobs[2])
    width, height = sidecar["source"]["render"]["width"], sidecar["source"]["render"]["height"]
    crop = crop or [0, 0, width, height]
    evidence, page, cropped = prepare_evidence(*blobs, crop)
    chars = {c["raw"]: c["id"] for c in sidecar["characters"]}
    if kind == "scripts":
        expression = {"kind": kind, "base": chars["x"], "sub": None if drop_sub else chars.get("q"), "sup": chars.get("2")}
    else:
        expression = {"kind": "diacritic", "base": chars["x"], "mark": chars.get("^", chars.get("b")), "combining": "\u0302"}
    used = {v for k, v in expression.items() if k not in ("kind", "combining") and v is not None}
    excluded = [c["glyph"]["id"] for c in evidence["scope"] if c["glyph"]["id"] not in used]
    review = {"version": REVIEW_VERSION, "evidence_sha256": digest(evidence), "crop": crop,
              "expression": expression, "exclusions": [{"glyph_ids": excluded, "role": "context", "reason": "Authored surrounding context."}] if excluded else [],
              "reviewer": "authored-test-reviewer", "reviewer_kind": "internal_assistant",
              "reviewed_at": "2026-01-01T00:00:00Z", "checks": dict.fromkeys(CHECKS, True),
              "notes": "Authored test attestation, not an actual development-paper review.",
              "exposure": "authored_fixture", "independent_review": False,
              "review_stage": "source_image_before_derivative_acceptance", "execution_mode": "SYNTHETIC_AUTHORED",
              "semantic_role": "mathematical_notation"}
    return review, evidence, page, cropped


def derive(blobs, review):
    raw = json_bytes(review)
    return derive_reviewed(*blobs, raw, expected_review_sha256=bytes_digest(raw), expected_reviewer="authored-test-reviewer")


@unittest.skipUnless(AVAILABLE, "optional PyMuPDF/Pillow authored fixtures")
class ReviewedNotationTests(unittest.TestCase):
    def test_exact_superscript_retains_raw_offsets_and_never_admits(self):
        blobs = fixture()
        before = copy.deepcopy(blobs)
        review, evidence, _, _ = review_for(blobs)
        result = derive(blobs, review)
        self.assertEqual(result["status"], "REVIEWED_FRAGMENT_DERIVATIVE")
        self.assertEqual(result["derived_unicode"]["text"], "x²")
        self.assertIn("<msup>", result["mathml"])
        self.assertEqual(blobs, before)
        self.assertEqual([v["glyph"]["raw"] for v in evidence["scope"]], ["x", "2"])
        self.assertFalse(result["proposal"])
        self.assertFalse(result["graph_admission_enabled"])
        self.assertIsNone(result["section_owner"])
        self.assertEqual(result["promotion_effect"], "none")

    def test_combined_script_mathml_does_not_invent_unicode_q_subscript(self):
        blobs = fixture("both")
        result = derive(blobs, review_for(blobs)[0])
        self.assertEqual(result["status"], "REVIEWED_FRAGMENT_DERIVATIVE")
        self.assertIn("<msubsup>", result["mathml"])
        self.assertIsNone(result["derived_unicode"]["text"])
        self.assertEqual(len(result["relation_witnesses"]), 2)

    def test_excluded_or_cropped_counterpart_holds(self):
        blobs = fixture("both")
        result = derive(blobs, review_for(blobs, drop_sub=True)[0])
        self.assertEqual(result["held_reason"], "script_counterpart_omitted_or_ambiguous")
        self.assertIsNone(result["mathml"])

    def test_diacritic_is_explicit_decomposed_unicode_with_raw_hat_retained(self):
        blobs = fixture("diacritic")
        result = derive(blobs, review_for(blobs, kind="diacritic")[0])
        self.assertEqual(result["status"], "REVIEWED_FRAGMENT_DERIVATIVE")
        self.assertEqual(result["derived_unicode"]["text"], "x\u0302")
        self.assertIn('<mover accent="true">', result["mathml"])
        self.assertEqual(json.loads(blobs[2])["characters"][1]["raw"], "^")

    def test_letter_cannot_be_reinterpreted_as_a_hat(self):
        blobs = fixture("fake_mark")
        result = derive(blobs, review_for(blobs, kind="diacritic")[0])
        self.assertEqual(result["status"], "HELD")
        self.assertEqual(result["held_reason"], "unsupported_or_mismatched_accent_mapping")

    def test_additional_accent_is_not_silently_excluded(self):
        blobs = fixture("diacritic", extra_mark=True)
        result = derive(blobs, review_for(blobs, kind="diacritic")[0])
        self.assertEqual(result["held_reason"], "diacritic_base_or_mark_ambiguous")

    def test_unmodeled_accent_or_script_cannot_be_excluded_as_context(self):
        blobs = fixture("diacritic", extra_script=True)
        self.assertEqual(derive(blobs, review_for(blobs, kind="diacritic")[0])["held_reason"], "diacritic_with_scripts_unsupported")
        blobs = fixture(extra_mark=True)
        self.assertEqual(derive(blobs, review_for(blobs)[0])["held_reason"], "unsupported_overhead_glyph")

    def test_actual_vector_overline_in_fragment_remains_held(self):
        blobs = fixture(painted_rule=True)
        self.assertEqual(derive(blobs, review_for(blobs)[0])["held_reason"], "unmodeled_painted_rule_in_fragment")

    def test_uncertain_mapping_visibility_and_orientation_block_typed_output(self):
        from trace_gc.reviewed_notation import _compile, NotationHold
        blobs = fixture()
        review, evidence, _, _ = review_for(blobs)
        for reason in ("trace_unicode_unresolved", "trace_origin_ambiguous", "rawdict_trace_unicode_disagreement",
                       "font_resource_ambiguous", "nonhorizontal_character", "nonvisible_trace_paint"):
            altered = copy.deepcopy(evidence); altered["scope"][0]["glyph"]["uncertainty"].append(reason)
            with self.subTest(reason=reason), self.assertRaises(NotationHold): _compile(review["expression"], altered)

    def test_every_crop_glyph_including_context_requires_explicit_partition(self):
        blobs = fixture(context=True)
        review, evidence, _, _ = review_for(blobs)
        self.assertTrue(review["exclusions"])
        accepted = derive(blobs, review)
        self.assertEqual(accepted["coverage"]["scope_glyph_count"], len(evidence["scope"]))
        review["exclusions"] = []
        held = derive(blobs, review)
        self.assertEqual(held["held_reason"], "notation_glyph_coverage_incomplete_or_duplicate")

    def test_duplicate_glyph_or_outside_scope_exclusion_holds(self):
        blobs = fixture()
        for ids in ([0], [999]):
            review = review_for(blobs)[0]
            review["exclusions"] = [{"glyph_ids": ids, "role": "context", "reason": "Invalid test."}]
            self.assertEqual(derive(blobs, review)["status"], "HELD")

    def test_false_whitespace_exclusion_is_rejected(self):
        blobs = fixture(context=True)
        review = review_for(blobs)[0]
        review["exclusions"][0]["role"] = "whitespace"
        with self.assertRaisesRegex(ValueError, "false_whitespace"):
            derive(blobs, review)

    def test_glyph_clipped_by_observed_crop_holds(self):
        blobs = fixture()
        review = review_for(blobs, crop=[161, 260, 180, 315])[0]
        self.assertEqual(derive(blobs, review)["held_reason"], "notation_glyph_clipped_by_crop")

    def test_every_rotation_with_nonzero_cropbox_maps_real_glyph_inventory(self):
        for rotation in (0, 90, 180, 270):
            with self.subTest(rotation=rotation):
                blobs = fixture(rotation=rotation, cropbox=True)
                review, evidence, _, _ = review_for(blobs)
                result = derive(blobs, review)
                self.assertEqual(result["status"], "REVIEWED_FRAGMENT_DERIVATIVE")
                self.assertEqual(evidence["image"]["render"]["rotation_degrees"], rotation)
                self.assertTrue(all(v["fully_inside_crop"] for v in evidence["scope"]))

    def test_tampered_sidecar_glyph_mapping_and_native_fail_replay(self):
        blobs = fixture()
        for name in ("sidecar", "native"):
            changed = list(blobs)
            if name == "sidecar":
                obj = json.loads(blobs[2]); obj["characters"][1]["raw"] = "3"; changed[2] = json_bytes(obj)
            else:
                obj = json.loads(blobs[1]); obj[0]["text"] = "y"; changed[1] = json_bytes(obj)
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "notation_(sidecar_replay_mismatch|projection_not_exact)"):
                prepare_evidence(*changed, [0, 0, 600, 600])

    def test_hash_pin_and_review_identity_must_match_external_expectations(self):
        blobs = fixture()
        raw = json_bytes(review_for(blobs)[0])
        for sha, reviewer in (("0"*64, "authored-test-reviewer"), (bytes_digest(raw), "someone-else")):
            with self.assertRaises(ValueError):
                derive_reviewed(*blobs, raw, expected_review_sha256=sha, expected_reviewer=reviewer)

    def test_review_claims_cannot_impersonate_unseen_independent_authority(self):
        blobs = fixture()
        for key, value in (("independent_review", True), ("exposure", "unseen"), ("reviewer_kind", "independent_human"),
                           ("review_stage", "before_original_predictions"), ("reviewed_at", "2999-01-01T00:00:00Z")):
            review = review_for(blobs)[0]; review[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                derive(blobs, review)

    def test_missing_false_or_extra_review_checks_block(self):
        blobs = fixture()
        for variant in ("missing", "false", "extra"):
            review = review_for(blobs)[0]
            if variant == "missing": del review["checks"]["occlusion"]
            if variant == "false": review["checks"]["glyph_mapping"] = False
            if variant == "extra": review["checks"]["graph_approved"] = True
            with self.subTest(variant=variant), self.assertRaises(ValueError): derive(blobs, review)

    def test_unsupported_fraction_and_nonnumeric_ids_stay_unaccepted(self):
        blobs = fixture()
        review = review_for(blobs)[0]
        review["expression"] = {"kind": "fraction"}
        self.assertEqual(derive(blobs, review)["held_reason"], "unsupported_notation_expression")
        for bad in (True, 0.0, "0"):
            review = review_for(blobs)[0]; review["expression"]["base"] = bad
            with self.assertRaises(ValueError): derive(blobs, review)

    def test_review_cannot_switch_actual_source_or_crop(self):
        blobs = fixture()
        review = review_for(blobs)[0]
        review["crop"] = [1, 1, 590, 590]
        with self.assertRaisesRegex(ValueError, "evidence_changed"): derive(blobs, review)

    def test_mutable_inputs_are_snapshotted_before_replay(self):
        blobs = [bytearray(v) for v in fixture()]
        review = review_for(blobs)[0]
        original = capture_notation
        def mutate_after_snapshot(pdf, native):
            blobs[0][:] = b"modified caller buffer"
            return original(pdf, native)
        with patch("trace_gc.reviewed_notation.capture_notation", side_effect=mutate_after_snapshot):
            self.assertEqual(derive(blobs, review)["status"], "REVIEWED_FRAGMENT_DERIVATIVE")


@unittest.skipUnless(AVAILABLE, "optional PyMuPDF/Pillow authored fixtures")
class PublicationTests(unittest.TestCase):
    def setup_inputs(self, root, review=True):
        blobs = fixture()
        contents = dict(zip(("source", "native", "sidecar"), blobs))
        if review: contents["review"] = json_bytes(review_for(blobs)[0])
        for key, raw in contents.items(): (root/key).write_bytes(raw)
        return {key: {"relative": key, "sha256": bytes_digest(raw)} for key, raw in contents.items()}

    def test_reviewed_publication_is_idempotent_and_pins_runtime_code_inputs(self):
        from src.parallel_source_v4 import reviewed_notation as cli
        with tempfile.TemporaryDirectory() as tmp, patch.object(cli, "runtime_receipt", return_value={"test": "synthetic"}), \
                patch.object(cli, "method_hashes", return_value={"test": "synthetic"}):
            root = Path(tmp); inputs = self.setup_inputs(root)
            first = cli.run(root, inputs, "output", reviewer="authored-test-reviewer")
            self.assertEqual(first, cli.run(root, inputs, "output", reviewer="authored-test-reviewer"))
            receipt = json.loads((root/"output/receipt.json").read_bytes())
            self.assertEqual(receipt["inputs"], inputs)
            self.assertEqual(receipt["production_graph_writes"], 0)

    def test_input_mutation_after_derivation_blocks_completion_receipt(self):
        from src.parallel_source_v4 import reviewed_notation as cli
        with tempfile.TemporaryDirectory() as tmp, patch.object(cli, "runtime_receipt", return_value={}):
            root = Path(tmp); inputs = self.setup_inputs(root)
            original = cli.derive_reviewed
            def mutate(*args, **kwargs):
                result = original(*args, **kwargs); (root/"native").write_bytes(b"changed"); return result
            with patch.object(cli, "derive_reviewed", side_effect=mutate), self.assertRaisesRegex(ValueError, "input_changed"):
                cli.run(root, inputs, "output", reviewer="authored-test-reviewer")
            self.assertFalse((root/"output/receipt.json").exists())

    def test_caller_descriptor_mutation_cannot_relabel_measured_source(self):
        from src.parallel_source_v4 import reviewed_notation as cli
        with tempfile.TemporaryDirectory() as tmp, patch.object(cli, "runtime_receipt", return_value={}):
            root = Path(tmp); inputs = self.setup_inputs(root); pinned = copy.deepcopy(inputs)
            original = cli.derive_reviewed
            def mutate(*args, **kwargs):
                result = original(*args, **kwargs)
                inputs["source"]["relative"] = "a-different-unmeasured-file"
                return result
            with patch.object(cli, "derive_reviewed", side_effect=mutate):
                cli.run(root, inputs, "output", reviewer="authored-test-reviewer")
            recorded = json.loads((root/"output/receipt.json").read_bytes())
            self.assertEqual(recorded["inputs"], pinned)

    def test_runtime_code_change_or_path_traversal_blocks(self):
        from src.parallel_source_v4 import reviewed_notation as cli
        with tempfile.TemporaryDirectory() as tmp, patch.object(cli, "runtime_receipt", return_value={}):
            root = Path(tmp); inputs = self.setup_inputs(root)
            with patch.object(cli, "method_hashes", side_effect=[{"first": "a"}, {"second": "b"}]), \
                    self.assertRaisesRegex(ValueError, "code_or_runtime_changed"):
                cli.run(root, inputs, "output", reviewer="authored-test-reviewer")
            self.assertFalse((root/"output/receipt.json").exists())
            inputs["source"]["relative"] = "../outside"
            with self.assertRaises(ValueError): cli.run(root, inputs, "output", reviewer="authored-test-reviewer")

    def test_packet_without_review_remains_wait_with_no_derivative(self):
        from src.parallel_source_v4 import reviewed_notation as cli
        with tempfile.TemporaryDirectory() as tmp, patch.object(cli, "runtime_receipt", return_value={}):
            root = Path(tmp); inputs = self.setup_inputs(root, review=False)
            result = cli.run(root, inputs, "packet", crop=[0, 0, 600, 600])
            self.assertEqual(result["status"], "WAIT_SOURCE_IMAGE_REVIEW")
            self.assertNotIn("mathml", json.loads((root/"packet/result.json").read_bytes()))
