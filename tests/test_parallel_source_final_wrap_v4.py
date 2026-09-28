"""Authored final-wrap ownership challenges, not empirical notation review."""
import copy
import unittest

from trace_gc.pdf_source_parallel_v4 import locate, validate_source_spans, validate_lines, _chains
from trace_gc.pdf_geometry_parallel_v4 import logical_rows
from trace_gc.pdf_structure_parallel_v4 import assess_document
from src.parallel_source_v4.adapters import document
from tests.test_parallel_source_math_rows_v4 import line


def paragraph():
    return [line(1, "√", [150,94,158,104],9,0),
            line(0, "Our preceding paragraph line establishes the original argument.", [40,80,300,90],1,0),
            line(2, "Our bound equals ", [40,100,150,110],1,1),
            line(3, "x and remains stable.", [158,100,300,110],2,0),
            line(4, "The following complete line corroborates paragraph ownership.", [40,112,300,122],2,1),
            line(5, "Another complete line finishes the explanation of the result", [40,124,300,134],2,2),
            line(6, "for this bound.", [40,136,115,146],2,3)]


def query(native):
    return " ".join(n["text"] for n in native if n["id"] != 1)


def repaired_chain(native, **kwargs):
    return any([n["id"] for n in chain] == [0,2,1,3,4,5,6] for chain in _chains(native, **kwargs))


class FinalWrapTests(unittest.TestCase):
    def test_short_final_wrap_keeps_raw_operator_and_exact_offsets(self):
        native = paragraph(); before = copy.deepcopy(native)
        result = locate(query(native),native)
        self.assertEqual(result["status"],"located")
        self.assertFalse(result["column_change"])
        self.assertEqual([s["line_id"] for s in result["spans"]],[0,2,1,3,4,5,6])
        self.assertIn("√",result["text"])
        validate_source_spans(result["spans"],native)
        self.assertEqual(native,before)
        self.assertTrue(result["logical_geometry"]["notation_review_required"])
        self.assertEqual(result["chain_evidence"][0]["version"],"native-terminal-wrap-chain-v1")
        self.assertEqual(result["chain_evidence"][0]["support_native_line_ids"],[4,5])

    def test_missing_ownership_spacing_or_style_cannot_extend_chain(self):
        for change in ("other_block","index_gap","one_full_row","size","font","bold","color","large_gap","indent","rotated","no_terminal_sentence"):
            with self.subTest(change=change):
                native=paragraph();last=native[-1]
                if change=="other_block":last["block_id"]=8
                if change=="index_gap":last["line_in_block"]=5
                if change=="one_full_row":native[-3]["block_id"]=8
                if change=="size":last["spans"][0]["size"]=7
                if change=="font":last["spans"][0]["font"]="Other"
                if change=="bold":last["spans"][0]["flags"]=16
                if change=="color":last["spans"][0]["color"]=123
                if change=="large_gap":last["bbox"][1:4:2]=[180,190]
                if change=="indent":last["bbox"][0:3:2]=[180,255]
                if change=="rotated":last["dir"]=[0,1]
                if change=="no_terminal_sentence":last["text"]="for this bound";last["spans"][0].update(end=14,text=last["text"])
                self.assertFalse(repaired_chain(native))

    def test_other_lane_at_same_height_does_not_become_terminal_wrap(self):
        native=paragraph()+[line(7,"Other column.",[180,136,300,146],8,0)]
        self.assertFalse(repaired_chain(native))

    def test_a_later_line_in_owner_block_prevents_terminal_claim(self):
        native=paragraph()+[line(7,"Later same-block source text.",[40,160,300,170],2,4)]
        self.assertFalse(repaired_chain(native))

    def test_region_filter_cannot_hide_later_owner_line(self):
        native=paragraph()+[line(7,"Later same-block source text.",[40,160,300,170],2,4)]
        result=locate(query(native[:-1]),native,region_boxes=[[40,70,300,150]])
        self.assertNotIn("chain_evidence",result)
        self.assertNotIn(1,[s["line_id"] for s in result.get("spans",[])])

    def test_region_filter_excluding_terminal_cannot_append_it(self):
        native=paragraph()
        result=locate(query(native[:-1]),native,region_boxes=[[40,70,300,134]])
        self.assertEqual(result["status"],"located")
        self.assertNotIn(6,[s["line_id"] for s in result["spans"]])
        self.assertNotIn("chain_evidence",result)

    def test_duplicate_source_ids_fail_before_assessment_chains(self):
        native=paragraph();native.append(copy.deepcopy(native[-1]))
        native[-1]["block_id"]=30
        with self.assertRaisesRegex(ValueError,"duplicate_native_line_id"):
            validate_lines(native,[600,800])
        result=assess_document(document([]),native_lines=native,page_size=[600,800],
                               source_sha256="a"*64,page_sha256="b"*64)
        self.assertEqual(result["status"],"error")
        self.assertFalse(result["proposal"])
        self.assertFalse(result["eligible_for_jev"])
        self.assertEqual(result["spans"],[])

    def test_duplicate_native_index_and_intervening_source_are_not_owned_wraps(self):
        for extra in (line(7,"Other terminal.",[40,136,115,146],2,3),
                      line(7,"Intervening separate source.",[40,134.5,300,135.5],8,0)):
            self.assertFalse(repaired_chain(paragraph()+[extra]))

    def test_duplicate_paragraph_occurrences_remain_ambiguous(self):
        native=paragraph();other=copy.deepcopy(native)
        for n in other:
            n["id"]+=20;n["block_id"]+=20
            n["bbox"][1]+=220;n["bbox"][3]+=220
            for run in n["spans"]:run["bbox"][1]+=220;run["bbox"][3]+=220
        result=locate(query(native),native+other)
        self.assertEqual(result["status"],"ambiguous")
        self.assertEqual(result["spans"],[])


if __name__=="__main__":unittest.main()
