"""Authored native-geometry challenges; no paper or notation certification."""
import copy
import unittest

from trace_gc.pdf_geometry_parallel_v4 import logical_rows
from trace_gc.pdf_source_parallel_v4 import locate, validate_source_spans


def line(i, text, box, block, index, size=10):
    return {"id": i, "text": text, "bbox": list(box), "page_no": 1,
            "block_id": block, "line_in_block": index,
            "spans": [{"start": 0, "end": len(text), "text": text,
                       "bbox": list(box), "size": size, "font": "Regular",
                       "flags": 0, "color": 0}]}


def radical():
    return [line(0, "An earlier paragraph row establishes ownership.", [40, 80, 300, 90], 1, 0),
            line(1, "√", [150, 94, 158, 104], 9, 0),
            line(2, "Our bound equals ", [40, 100, 150, 110], 1, 1),
            line(3, "x and remains stable.", [158, 100, 300, 110], 2, 0),
            line(4, "A following paragraph row corroborates ownership.", [40, 120, 300, 130], 2, 1)]


def stacked_seam():
    left = line(0, "Our parameter λ2", [40, 98, 204, 110], 1, 0)
    right = line(1, "q) is stable.", [200, 100, 300, 111], 2, 0)
    left["spans"] = [
        {**left["spans"][0], "end": 14, "text": left["text"][:14], "bbox": [40, 100, 194, 110]},
        {**left["spans"][0], "start": 14, "end": 15, "text": "λ", "bbox": [194, 100, 200, 110], "flags": 2},
        {**left["spans"][0], "start": 15, "end": 16, "text": "2", "bbox": [200, 98, 204, 105], "size": 7, "flags": 1}]
    right["spans"] = [
        {**right["spans"][0], "end": 1, "text": "q", "bbox": [200, 104, 204, 111], "size": 7, "flags": 2},
        {**right["spans"][0], "start": 1, "text": right["text"][1:], "bbox": [204.4, 100, 300, 110]}]
    return [left, right,
            line(2, "The next complete row supports the paragraph.", [40, 112, 300, 122], 2, 1),
            line(3, "A further complete row supports the paragraph.", [40, 124, 300, 134], 2, 2)]


class MathRowTests(unittest.TestCase):
    def test_cross_block_radical_has_exact_order_and_source_identity(self):
        native = radical(); original = copy.deepcopy(native)
        result = locate("Our bound equals √x and remains stable.", native)
        self.assertEqual(result["status"], "located")
        self.assertFalse(result["column_change"])
        self.assertEqual([s["line_id"] for s in result["spans"]], [2, 1, 3])
        validate_source_spans(result["spans"], native)
        self.assertEqual(native, original)
        self.assertTrue(result["logical_geometry"]["notation_review_required"])

    def test_radical_before_paragraph_in_native_order_is_not_omitted(self):
        native = radical(); first = native.pop(1); native.insert(0, first)
        query = " ".join(native[i]["text"] for i in (1, 2, 3, 4))
        result = locate(query, native)
        self.assertEqual(result["status"], "located")
        self.assertFalse(result["column_change"])
        self.assertEqual([s["line_id"] for s in result["spans"]], [0, 2, 1, 3, 4])
        self.assertIn("√", result["text"])

    def test_operator_needs_both_flanks_and_two_sided_paragraph_support(self):
        for removed in (0, 2, 3, 4):
            with self.subTest(removed=removed):
                native = [n for n in radical() if n["id"] != removed]
                self.assertFalse(any(len(r["lines"]) > 1 and any(n["id"] == 1 for n in r["lines"])
                                     for r in logical_rows(native)))

    def test_letter_control_and_rotated_symbol_do_not_use_operator_rule(self):
        for text, direction in (("x", [1, 0]), ("\x00", [1, 0]), ("√", [0, 1])):
            native = radical(); native[1]["text"] = text
            native[1]["spans"][0]["text"] = text; native[1]["dir"] = direction
            self.assertFalse(any({1, 2, 3} <= {n["id"] for n in r["lines"]} for r in logical_rows(native)))

    def test_gap_and_competing_gutter_keep_operator_held(self):
        native = radical(); native[3]["bbox"][0] += 4
        self.assertFalse(any({1, 2, 3} <= {n["id"] for n in r["lines"]} for r in logical_rows(native)))

    def test_operator_needs_unique_flanks_and_exact_run_partition(self):
        for change in ("duplicate_flank", "wrong_run_text", "outside_box", "multi_symbol", "unowned_support"):
            with self.subTest(change=change):
                native = radical()
                if change == "duplicate_flank":
                    extra = copy.deepcopy(native[2]); extra["id"] = 8
                    native.append(extra)
                if change == "wrong_run_text":native[1]["spans"][0]["text"] = "x"
                if change == "outside_box":native[1]["spans"][0]["bbox"][0] -= 20
                if change == "multi_symbol":native[1]["text"] = "√+"
                if change == "unowned_support":native[0]["block_id"] = native[4]["block_id"] = 8
                self.assertFalse(any({1, 2, 3} <= {n["id"] for n in r["lines"]} for r in logical_rows(native)))

    def test_geometry_never_resolves_duplicate_text_occurrences(self):
        native = radical()
        duplicate = copy.deepcopy(native)
        for item in duplicate:
            item["id"] += 20
            item["block_id"] += 20
            item["bbox"][1] += 200; item["bbox"][3] += 200
            for run in item["spans"]:
                run["bbox"][1] += 200; run["bbox"][3] += 200
        result = locate("Our bound equals √x and remains stable.", native+duplicate)
        self.assertEqual(result["status"], "ambiguous")
        self.assertEqual(result["spans"], [])
        native = radical() + [line(5, "Other left column text", [40, 112, 150, 122], 3, 0),
                              line(6, "Other right column text", [158, 112, 300, 122], 4, 0)]
        self.assertFalse(any({1, 2, 3} <= {n["id"] for n in r["lines"]} for r in logical_rows(native)))

    def test_overlapping_math_seam_needs_source_runs_and_two_following_rows(self):
        native = stacked_seam(); original = copy.deepcopy(native)
        result = locate("Our parameter λ2q) is stable.", native)
        self.assertEqual(result["status"], "located")
        self.assertFalse(result["column_change"])
        self.assertEqual([s["line_id"] for s in result["spans"]], [0, 1])
        self.assertTrue(result["logical_geometry"]["notation_review_required"])
        self.assertEqual(native, original)
        for change in ("one_row", "no_math_base", "unowned_rows", "no_start", "overprint", "run_gap", "wrong_run_text", "nonfinite_box", "rotated", "duplicate_support_level"):
            with self.subTest(change=change):
                native = stacked_seam()
                if change == "one_row":native.pop()
                if change == "no_math_base":native[0]["spans"][-2]["flags"] = 0
                if change == "unowned_rows":native[2]["block_id"] = native[3]["block_id"] = 8
                if change == "no_start":native[0]["line_in_block"] = 3
                if change == "overprint":native[1]["spans"][0]["bbox"][1:4:2] = [98, 105]
                if change == "run_gap":native[0]["spans"][-1]["start"] = 14
                if change == "wrong_run_text":native[0]["spans"][-1]["text"] = "3"
                if change == "nonfinite_box":native[0]["spans"][-1]["bbox"][0] = float("nan")
                if change == "rotated":native[1]["dir"] = [0, 1]
                if change == "duplicate_support_level":native[3]["bbox"][1:4:2] = native[2]["bbox"][1:4:2]
                self.assertFalse(any({0, 1} <= {n["id"] for n in r["lines"]} for r in logical_rows(native)))

    def test_stacked_seam_is_raw_offsets_not_a_typed_transcription(self):
        native = stacked_seam()
        result = locate("Our parameter λ2q) is stable.", native)
        validate_source_spans(result["spans"], native)
        self.assertEqual(result["text"], "Our parameter λ2\nq) is stable.")
        self.assertNotIn("λ₂", result["text"])
        self.assertTrue(result["logical_geometry"]["notation_review_required"])
        proof = result["logical_geometry"]["rows"][0]["joins"][0]
        self.assertEqual([(r["line_id"], r["start"], r["end"]) for r in proof["native_runs"]],
                         [(0,14,15), (0,15,16), (1,0,1), (1,1,13)])


if __name__ == "__main__":
    unittest.main()
