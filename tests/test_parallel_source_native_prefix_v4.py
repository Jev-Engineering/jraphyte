"""Authored raw-native prefix fixtures; no external paper data is embedded."""
import copy
import unittest

from trace_gc.pdf_source_parallel_v4 import locate, validate_source_spans
from trace_gc.pdf_structure_parallel_v4 import verify_assessment
from tests.test_parallel_source_v4 import ABSTRACT, BODY, assess, doc, line as styled_line


def line(index, text, y=100):
    return {"id": index, "block_id": index, "line_in_block": 0, "page_no": 1,
            "text": text, "bbox": [40, y, 500, y + 12], "spans": []}


class NativeLeadingPrefixTests(unittest.TestCase):
    def located(self, requested, source, expected_start=0):
        native = [line(0, source)]
        before = copy.deepcopy(native)
        result = locate(requested, native)
        self.assertEqual(result["status"], "located")
        self.assertEqual(result["spans"][0]["start"], expected_start)
        self.assertEqual(result["text"], requested.strip())
        validate_source_spans(result["spans"], native)
        self.assertEqual(native, before)
        return result

    def held(self, requested, native):
        before = copy.deepcopy(native)
        result = locate(requested, native)
        self.assertEqual(result["status"], "unlocated")
        self.assertEqual(result["spans"], [])
        self.assertEqual(native, before)

    def test_exact_raw_prefix_is_retained(self):
        for text in ("|x| = y.", "∂t remains positive.", "√x + y.",
                     "(x + y).", "|−x| + y.", "| x| = y."):
            with self.subTest(text=text):
                self.located(text, text)

    def test_requested_prefix_can_follow_native_heading_without_absorbing_it(self):
        text = "(We derive stable transport bounds.)"
        self.located(text, "Abstract: " + text, len("Abstract: "))

    def test_missing_requested_prefix_is_held(self):
        self.held("√x + y.", [line(0, "x + y.")])

    def test_different_raw_operator_is_held(self):
        self.held("√x + y.", [line(0, "+x + y.")])

    def test_prefix_cannot_cross_native_line_boundary(self):
        self.held("√x + y.", [line(0, "√", 80), line(1, "x + y.")])

    def test_prefix_cannot_cross_intervening_alphanumeric(self):
        self.held("|µ(ξ)| ≲ |ξ|−β/2,", [line(0, "|bµ(ξ)| ≲ |ξ|−β/2,")])

    def test_different_prefixes_cannot_disambiguate_canonical_occurrences(self):
        result = locate("√x + y.", [line(0, "√x + y."), line(1, "+x + y.", 200)])
        self.assertEqual(result["status"], "ambiguous")
        self.assertEqual(result["spans"], [])

    def test_duplicate_exact_prefixes_stay_ambiguous(self):
        result = locate("√x + y.", [line(0, "√x + y."), line(1, "√x + y.", 200)])
        self.assertEqual(result["status"], "ambiguous")
        self.assertEqual(result["spans"], [])

    def test_no_prefix_does_not_absorb_heading_separator(self):
        text = "We establish stable transport bounds."
        self.located(text, "Abstract — " + text, len("Abstract — "))

    def test_requested_operator_cannot_reuse_heading_separator(self):
        self.held("∂x describes transport.", [line(0, "Abstract—x describes transport.")])

    def test_no_prefix_does_not_absorb_neighboring_opening_punctuation(self):
        text = "We establish stable transport bounds."
        self.located(text, "(" + text, 1)

    def test_query_indentation_does_not_fabricate_native_whitespace(self):
        self.located("  √x + y.\n", "√x + y.")

    def test_operator_only_query_stays_unlocated(self):
        self.held("∂", [line(0, "∂")])

    def test_control_glyph_mapping_is_not_a_prefix_repair(self):
        self.held("\x00x + y.", [line(0, "\x00x + y.")])

    def test_combining_mark_is_not_a_prefix_repair(self):
        self.held("\u0302x + y.", [line(0, "\u0302x + y.")])

    def test_prefix_cannot_contain_a_line_break(self):
        self.held("√\nx + y.", [line(0, "√\nx + y.")])

    def test_prefix_cannot_attach_to_a_different_fuzzy_operand(self):
        text = "xy " + "We establish stable transport bounds under specified external conditions. " * 2
        self.held("∂" + text, [line(0, "∂" + text[1:])])


class PrefixHoldContinuationTests(unittest.TestCase):
    def fixture(self):
        native = [styled_line(0, "Abstract", 70), styled_line(1, ABSTRACT, 100),
                  styled_line(2, "∂x = y.", 130), styled_line(3, BODY, 160),
                  styled_line(4, "1 Introduction", 200)]
        source = doc(native, labels={0: "section_header", 4: "section_header"})
        source["texts"][2]["text"] = "∂ ∂x = y."
        return native, source

    def assert_held(self, result):
        self.assertFalse(result["proposal"])
        self.assertFalse(result["complete_candidate"])
        self.assertFalse(result["eligible_for_jev"])
        self.assertFalse(result["verified_admission"])
        self.assertEqual(result["spans"], [])
        self.assertIsNone(result["section_owner"])
        verify_assessment(result)

    def test_source_bracketed_continuation_is_retained_only_as_uncertain_text(self):
        native, source = self.fixture()
        result = assess(native, source)
        self.assert_held(result)
        self.assertEqual(result["status"], "uncertain")
        self.assertIn(ABSTRACT, result["text"])
        self.assertIn("∂ ∂x = y.", result["text"])
        self.assertIn(BODY, result["text"])
        self.assertNotIn("Introduction", result["text"])
        self.assertEqual(result["reasons"], ["requested_leading_prefix_not_source_bound"])
        held = [entry for entry in result["region_ownership"] if "continuity" in entry]
        self.assertEqual(len(held), 1)
        self.assertEqual(held[0]["decision"], "held")
        self.assertFalse(held[0]["candidate_native_extent"]["accepted"])
        self.assertFalse(held[0]["continuity"]["accepted"])
        self.assertNotIn("source_spans", held[0])
        validate_source_spans(held[0]["candidate_native_extent"]["spans"], native)

    def test_missing_source_closure_does_not_enable_continuation(self):
        native, source = self.fixture()
        native = native[:-1]
        source = doc(native, labels={0: "section_header"})
        source["texts"][2]["text"] = "∂ ∂x = y."
        result = assess(native, source)
        self.assert_held(result)
        self.assertNotIn(BODY, result["text"])

    def test_unverified_source_opening_does_not_enable_continuation(self):
        native, source = self.fixture()
        native[0] = styled_line(0, "Graphical Abstract", 70)
        result = assess(native, source)
        self.assert_held(result)
        self.assertNotIn(BODY, result["text"])

    def test_unlocated_next_region_does_not_enable_continuation(self):
        native, source = self.fixture()
        source["texts"][3]["text"] = "This invented continuation has no source evidence at all."
        result = assess(native, source)
        self.assert_held(result)
        self.assertNotIn("invented continuation", result["text"])

    def test_model_box_cannot_bridge_to_other_source_column(self):
        native, source = self.fixture()
        native[3] = styled_line(3, BODY, 160, x=320, right=560)
        source["texts"][3]["prov"][0]["bbox"].update(l=40, r=560)
        result = assess(native, source)
        self.assert_held(result)
        self.assertNotIn(BODY, result["text"])

    def test_intervening_heading_cannot_be_skipped(self):
        native, source = self.fixture()
        native[3] = styled_line(3, "1 Introduction", 160)
        native[4] = styled_line(4, BODY, 200)
        native.append(styled_line(5, "2 Methods", 240))
        source = doc(native, labels={0: "section_header", 3: "section_header", 5: "section_header"})
        source["texts"][2]["text"] = "∂ ∂x = y."
        result = assess(native, source)
        self.assert_held(result)
        self.assertNotIn(BODY, result["text"])

    def test_large_native_gap_cannot_enable_continuation(self):
        native, source = self.fixture()
        native[3] = styled_line(3, BODY, 260)
        native[4] = styled_line(4, "1 Introduction", 300)
        source = doc(native, labels={0: "section_header", 4: "section_header"})
        source["texts"][2]["text"] = "∂ ∂x = y."
        result = assess(native, source)
        self.assert_held(result)
        self.assertNotIn(BODY, result["text"])


if __name__ == "__main__":
    unittest.main()
