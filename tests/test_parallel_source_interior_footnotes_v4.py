"""Authored source-bound exclusions; no empirical source text or quality labels."""
from copy import deepcopy
import re
import unittest

from test_parallel_source_v4 import ABSTRACT, PARAMS, assess, doc, line
from trace_gc.pdf_source_parallel_v4 import digest_value, validate_source_spans
from trace_gc.pdf_structure_parallel_v4 import (_interior_footnotes, seal, verify_assessment,
    verify_interior_footnote_exclusion)
from src.parallel_source_v4.retrieval import extract_fields, verify_source_bound_assessment
from src.parallel_source_v4.promotion_io import _review_spans
from src.parallel_source_v4.promotion_review import apply_closure_review


def note_line(i, text, y=700):
    result = line(i,text,y,size=8)
    end = re.match(r"[0-9]+[a-z]?|[*†‡]+",text).end()
    edge = 40+3*end
    common = result["spans"][0]
    result["bbox"][1] = y-1
    result["spans"] = [dict(common,start=0,end=end,text=text[:end],size=6,bbox=[40,y-1,edge,y+5]),
        dict(common,start=end,end=len(text),text=text[end:],bbox=[edge+.5,y+2,280,y+10.5])]
    return result


def fixture(*, marker="1", superscript=True, italic=False, before_period=False,
            note_text=None, note_y=700, duplicate=False, closure=True):
    prose = "Abstract "+ABSTRACT
    point = prose.index(".") + (0 if before_period else 1)
    text = prose[:point]+marker+prose[point:]
    first = line(0, text, 100, right=550)
    common = first["spans"][0]
    first["spans"] = [dict(common, start=0, end=point, text=text[:point],
        flags=2 if italic else 0, bbox=[40,100,180,112]),
        dict(common, start=point, end=point+len(marker), text=marker,
             flags=1 if superscript else 0, size=6, bbox=[180,98,184,106]),
        dict(common, start=point+len(marker), end=len(text), text=text[point+len(marker):],
             bbox=[184,100,550,112])]
    native = [first]
    if closure:
        native.append(line(len(native), "Keywords: measurements", 160, right=550))
    labels = {}
    if note_text is not False:
        labels[len(native)] = "footnote"
        native.append(note_line(len(native), note_text or marker+" Supporting source code.", note_y))
    if duplicate:
        labels[len(native)] = "footnote"
        native.append(note_line(len(native), marker+" Another source note.", note_y+30))
    return native, doc(native, labels=labels), point


class InteriorFootnoteTests(unittest.TestCase):
    def test_only_marker_removed_and_unsplit_assessment_preserved(self):
        native, document, point = fixture()
        original_native = deepcopy(native)
        result = assess(native, document)
        self.assertTrue(result["proposal"], result)
        self.assertEqual(result["text"], ABSTRACT)
        self.assertEqual(native, original_native)
        proof = result["interior_footnote_exclusion"]
        parent = proof["original_assessment"]
        verify_assessment(parent)
        verify_assessment(result)
        self.assertEqual(proof["original_assessment_sha256"], parent["assessment_sha256"])
        self.assertTrue(proof["applied"])
        self.assertEqual(proof["excluded_spans"][0]["start"], point)
        self.assertEqual(proof["excluded_spans"][0]["end"], point+1)
        self.assertEqual(proof["span_joiners"], [""])
        for spans in (result["spans"], proof["excluded_spans"], proof["decisions"][0]["source_spans"]):
            validate_source_spans(spans, native)
        positions = lambda spans: [(s["line_id"], i) for s in spans for i in range(s["start"], s["end"])]
        self.assertEqual(positions(result["spans"]), [p for p in positions(parent["spans"]) if p != (0,point)])
        self.assertFalse(result["eligible_for_jev"])
        self.assertFalse(result["verified_admission"])

    def test_marker_need_not_be_decimal_one(self):
        for marker in ("2", "12", "*", "†"):
            with self.subTest(marker=marker):
                native, document, _ = fixture(marker=marker)
                result = assess(native, document)
                self.assertTrue(result["proposal"], result)
                self.assertEqual(result["text"], ABSTRACT)

    def test_missing_duplicate_or_nonfooter_note_holds_without_deletion(self):
        for options in ({"note_text":False}, {"duplicate":True}, {"note_y":300}):
            with self.subTest(options=options):
                native, document, _ = fixture(**options)
                result = assess(native, document)
                self.assertFalse(result["proposal"], result)
                self.assertIn(".1 ",result["text"])
                self.assertIsNone(result["section_owner"])
                self.assertFalse(result["interior_footnote_exclusion"]["applied"])

    def test_note_full_native_marker_cannot_be_cropped_or_normalized(self):
        for marker in ("11", "21", "1a"):
            for crop in (False, True):
                with self.subTest(marker=marker, crop=crop):
                    native, document, _ = fixture(note_text=marker+" Supporting source code.")
                    if crop:
                        document["texts"][-1]["text"] = "1 Supporting source code."
                    result = assess(native, document)
                    self.assertFalse(result["proposal"], result)
                    self.assertIn(".1 ", result["text"])

    def test_baseline_number_is_never_a_footnote_exclusion(self):
        native, document, _ = fixture(superscript=False)
        result = assess(native, document)
        self.assertIn(".1 ",result["text"])
        self.assertNotIn("interior_footnote_exclusion",result)

    def test_italic_math_base_and_before_punctuation_are_held(self):
        for options in ({"italic":True}, {"before_period":True}):
            with self.subTest(options=options):
                native, document, _ = fixture(**options)
                result = assess(native, document)
                self.assertFalse(result["proposal"],result)
                self.assertIn("1",result["text"])
                self.assertFalse(result["interior_footnote_exclusion"]["applied"])

    def test_missing_closure_is_not_repaired_by_note(self):
        native, document, _ = fixture(closure=False)
        result = assess(native,document)
        self.assertFalse(result["proposal"])
        self.assertNotIn("interior_footnote_exclusion",result)

    def test_note_label_cannot_turn_numbered_body_heading_into_footnote(self):
        native, document, _ = fixture(note_text="1 Introduction to another section.")
        result = assess(native,document)
        self.assertFalse(result["proposal"],result)
        self.assertIn(".1 ",result["text"])

    def test_source_run_raised_flag_needs_smaller_and_raised_box(self):
        for attack in ("size", "bbox", "after_style"):
            with self.subTest(attack=attack):
                native, document, _ = fixture()
                if attack == "size":native[0]["spans"][1]["size"] = 10
                if attack == "bbox":native[0]["spans"][1]["bbox"] = [180,100,184,112]
                if attack == "after_style":native[0]["spans"][2]["flags"] = 2
                result = assess(native,document)
                self.assertFalse(result["proposal"],result)
                self.assertIn(".1 ",result["text"])

    def test_source_alignment_hold_is_never_cleared(self):
        native, document, _ = fixture()
        document["texts"][0]["text"] += " Invented missing source material."
        result = assess(native,document)
        self.assertFalse(result["proposal"])
        self.assertNotIn("interior_footnote_exclusion",result)

    def test_no_transform_on_nonproposed_parent(self):
        native, document, _ = fixture()
        result = assess(native,document)["interior_footnote_exclusion"]["original_assessment"]
        for status in ("uncertain", "partial", "error"):
            value = {**result,"status":status,"proposal":False}
            before = deepcopy(value)
            self.assertEqual(_interior_footnotes(value,native,[]),before)

    def test_multiple_markers_and_mixed_evidence_are_atomic(self):
        for missing_second_note in (False, True):
            with self.subTest(missing_second_note=missing_second_note):
                native, _, _ = fixture()
                text = native[0]["text"].replace("response.", "response.2")
                native[0]["text"] = text
                spans, start = [], 0
                for index, match in enumerate(re.finditer(r"(?<=[.!?])[12](?= )",text)):
                    common = line(0,text)["spans"][0]
                    edge = 180+index*120
                    spans.append(dict(common,start=start,end=match.start(),text=text[start:match.start()],
                                      bbox=[40 if index==0 else edge-116,100,edge,112]))
                    spans.append(dict(common,start=match.start(),end=match.end(),text=match.group(),flags=1,size=6,
                                      bbox=[edge,98,edge+4,106]))
                    start = match.end()
                spans.append(dict(common,start=start,end=len(text),text=text[start:],bbox=[edge+4,100,550,112]))
                native[0]["spans"] = spans
                labels = {2:"footnote"}
                if not missing_second_note:
                    labels[3] = "footnote"
                    native.append(note_line(3,"2 Additional source code.",730))
                result = assess(native,doc(native,labels=labels))
                proof = result["interior_footnote_exclusion"]
                if missing_second_note:
                    self.assertFalse(result["proposal"])
                    self.assertFalse(proof["applied"])
                    self.assertIn(".1 ",result["text"])
                    self.assertIn(".2 ",result["text"])
                else:
                    self.assertTrue(result["proposal"],result)
                    self.assertEqual(result["text"],ABSTRACT)
                    self.assertEqual(len(proof["excluded_spans"]),2)
                verify_assessment(proof["original_assessment"])
                verify_assessment(result)

    def test_existing_line_break_and_split_joiners_are_preserved(self):
        native, _, _ = fixture()
        tail = ABSTRACT[ABSTRACT.index("The resulting"):]
        first = native[0]
        first["text"] = first["text"][:-len(tail)].rstrip()
        first["spans"][-1].update(end=len(first["text"]),text=first["text"][first["spans"][-1]["start"]:])
        native = [first,line(1,tail,130,right=550),line(2,"Keywords: measurements",170,right=550),native[-1]]
        native[-1]["id"] = 3
        result = assess(native,doc(native,labels={3:"footnote"}))
        self.assertTrue(result["proposal"],result)
        proof = result["interior_footnote_exclusion"]
        self.assertEqual(result["text"],ABSTRACT[:-len(tail)].rstrip()+"\n"+tail)
        self.assertEqual(proof["span_joiners"],["","\n"])
        reconstructed = result["spans"][0]["text"]
        for joiner,span in zip(proof["span_joiners"],result["spans"][1:]):
            reconstructed += joiner+span["text"]
        self.assertEqual(reconstructed,result["text"])
        self.assertEqual(extract_fields("wrapped",native,abstract_assessment=result,**PARAMS)["abstract"],result["text"])

    def test_unlinked_scientific_superscript_is_preserved(self):
        native, document, _ = fixture(marker="2",before_period=True,note_text=False,italic=True)
        result = assess(native,document)
        self.assertTrue(result["proposal"],result)
        self.assertIn("perturbations2.",result["text"])
        self.assertNotIn("interior_footnote_exclusion",result)

    def test_disconnected_marker_boxes_cannot_remove_native_character(self):
        for box in ([500,98,504,106],[180,10,184,18],[180,100,184,112]):
            with self.subTest(box=box):
                native,document,_ = fixture()
                native[0]["spans"][1]["bbox"] = box
                result = assess(native,document)
                self.assertFalse(result["proposal"],result)
                self.assertFalse(result["interior_footnote_exclusion"]["applied"])
                self.assertIn(".1 ",result["text"])

    def test_source_owned_page_footer_note_is_supported(self):
        native,_,_ = fixture()
        result = assess(native,doc(native,labels={2:"page_footer"}))
        self.assertTrue(result["proposal"],result)
        self.assertEqual(result["text"],ABSTRACT)
        self.assertEqual(result["interior_footnote_exclusion"]["decisions"][0]["note_marker_span"]["text"],"1")

    def test_footer_label_without_native_raised_note_marker_is_insufficient(self):
        native,_,_ = fixture()
        native[-1] = line(2,"1 Supporting source code.",700,size=8)
        result = assess(native,doc(native,labels={2:"page_footer"}))
        self.assertFalse(result["proposal"],result)
        self.assertIn(".1 ",result["text"])

    def test_cropped_footer_prose_does_not_establish_note_ownership(self):
        native,document,_ = fixture()
        document["texts"][-1]["text"] = "1 Supporting"
        result = assess(native,document)
        self.assertFalse(result["proposal"],result)
        self.assertIn(".1 ",result["text"])

    def test_unlabelled_duplicate_native_note_keeps_marker_held(self):
        native, _, _ = fixture(duplicate=True)
        result = assess(native, doc(native, labels={2:"footnote"}))
        self.assertFalse(result["proposal"], result)
        self.assertIn(".1 ", result["text"])

    def test_fields_and_promotion_read_back_exact_verified_exclusion(self):
        native, document, _ = fixture()
        result = assess(native, document)
        verify_interior_footnote_exclusion(result, native)
        fields = extract_fields("authored", native, abstract_assessment=result, **PARAMS)
        self.assertEqual(fields["abstract"], ABSTRACT)
        self.assertTrue(fields["retrieval_only"])
        self.assertFalse(fields["eligible_for_jev"])
        self.assertFalse(fields["field_provenance"]["abstract"]["source_reviewed"])
        _review_spans({"boundary":{"representation":"native_spans", "status":"pass",
            "reference_spans":result["spans"], "excluded_spans":[{"role":"footnote",
                "spans":result["interior_footnote_exclusion"]["excluded_spans"]}]}}, native, ABSTRACT)
        # Real harness fields are sealed later without replacing the parent.
        result.update(conversion_stage={"status":"success"}, source_hash_verification="verified_by_offline_harness")
        seal(result)
        verify_source_bound_assessment(result, native, **PARAMS)

    def test_consumer_rejects_resealed_tampering_of_proof_and_correction(self):
        native, document, _ = fixture()
        original = assess(native, document)
        for attack in ("note_label", "note_text", "note_box", "parent_seal", "parent_hash",
                       "joins", "excluded", "decision", "kept_order", "text", "closing"):
            with self.subTest(attack=attack):
                result = deepcopy(original)
                proof = result["interior_footnote_exclusion"]
                if attack == "note_label":proof["note_regions"][0]["label"] = "text"
                if attack == "note_text":proof["note_regions"][0]["text"] += " Fabricated text."
                if attack == "note_box":proof["note_regions"][0]["bbox"][0] += 10
                if attack == "parent_seal":proof["original_assessment"]["text"] += " Fabricated text."
                if attack == "parent_hash":proof["original_assessment_sha256"] = "f"*64
                if attack == "joins":proof["span_joiners"][0] = "\n"
                if attack == "excluded":proof["excluded_spans"][0]["start"] -= 1
                if attack == "decision":proof["decisions"][0]["attachment_geometry"]["marker_bbox"][0] += 1
                if attack == "kept_order":result["spans"].reverse()
                if attack == "text":result["text"] = result["text"].replace("networks", "models")
                if attack == "closing":result["closing_boundary"] = {"kind":"invented"}
                seal(result)
                with self.assertRaises(ValueError):
                    extract_fields("authored", native, abstract_assessment=result, **PARAMS)

    def test_null_or_empty_exclusion_cannot_bypass_native_text_verifier(self):
        native, document, _ = fixture()
        original = assess(native, document)
        for proof in (None, {}, [], False):
            result = {**original,"interior_footnote_exclusion":proof,"text":"Fabricated prose."}
            seal(result)
            with self.assertRaisesRegex(ValueError,"unsupported_interior_footnote"):
                extract_fields("authored",native,abstract_assessment=result,**PARAMS)

    def test_consumer_replays_source_geometry_even_if_all_hashes_are_resealed(self):
        native, document, _ = fixture()
        result = assess(native, document)
        native[0]["spans"][1]["bbox"] = [500,98,504,106]
        proof = result["interior_footnote_exclusion"]
        parent = proof["original_assessment"]
        parent["native_sha256"] = result["native_sha256"] = digest_value(native)
        seal(parent)
        proof["original_assessment_sha256"] = parent["assessment_sha256"]
        seal(result)
        with self.assertRaisesRegex(ValueError,"proof_does_not_replay"):
            verify_source_bound_assessment(result,native,**PARAMS)

    def test_consumer_requires_unique_parent_and_exact_native_identity(self):
        native, document, _ = fixture()
        result = assess(native, document)
        duplicate = deepcopy(native[0])
        duplicate.update(id=3,block_id=3,bbox=[40,300,550,312])
        native.append(duplicate)
        with self.assertRaisesRegex(ValueError,"parent_scope_or_source"):
            verify_source_bound_assessment(result,native,**PARAMS)
        proof = result["interior_footnote_exclusion"]
        parent = proof["original_assessment"]
        parent["native_sha256"] = result["native_sha256"] = digest_value(native)
        seal(parent)
        proof["original_assessment_sha256"] = parent["assessment_sha256"]
        seal(result)
        with self.assertRaisesRegex(ValueError,"parent_not_unique_or_current"):
            verify_source_bound_assessment(result,native,**PARAMS)

    def test_unresolved_marker_stays_held_in_fields_and_closure_adapter(self):
        native, document, _ = fixture(note_text=False)
        result = assess(native, document)
        self.assertFalse(result["proposal"])
        self.assertEqual(extract_fields("authored",native,abstract_assessment=result,**PARAMS)["abstract"],"")
        with self.assertRaisesRegex(ValueError,"cannot_resolve_interior_footnote"):
            apply_closure_review(result,{},native=native,source_identity={},pdf_bytes=b"",
                load_asset=lambda _: b"",fidelity_reference={},evaluated_at="2026-09-28T00:00:00Z")


if __name__ == "__main__":
    unittest.main()
