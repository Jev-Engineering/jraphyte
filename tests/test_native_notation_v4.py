"""Authored notation evidence; relation candidates never qualify transcription."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from trace_gc.pdf_notation_parallel_v4 import _project, _rules, capture_notation, relation_candidates
from trace_gc.pdf_source_parallel_v4 import source_lines, json_bytes


def char(i, raw, x, y, *, size=10, width=5, flags=2, uncertainty=()):
    return {"id": i, "native_ref": {"line_id": i, "start": 0, "end": 1}, "raw": raw,
            "bbox": [x, y-size, x+width, y+2], "origin": [x, y], "size": size,
            "flags": flags, "direction": [1, 0], "uncertainty": list(uncertainty)}


def rule(x0=10, x1=15, y=98):
    return {"id": 0, "x0": x0, "x1": x1, "y": y, "stroke_width": .4}


def projection_fixture(text="x", trace_unicode=None):
    chars = [{"c": c, "origin": [10+i*5, 100], "bbox": [10+i*5, 90, 15+i*5, 102], "synthetic": False} for i, c in enumerate(text)]
    line = {"bbox": [10, 90, 10+len(text)*5, 102], "dir": [1, 0], "wmode": 0,
            "spans": [{"font": "TestFont", "size": 10, "flags": 2, "chars": chars}]}
    raw = {"blocks": [{"type": 0, "lines": [line]}]}
    native = [{"id": 7, "block_id": 0, "line_in_block": 0, "text": text, "bbox": line["bbox"]}]
    trace = [{"font": "TestFont", "dir": [1, 0], "seqno": 0, "type": 0, "opacity": 1,
              "chars": [(ord(c) if trace_unicode is None else trace_unicode, i, chars[i]["origin"], chars[i]["bbox"]) for i, c in enumerate(text)]}]
    return raw, native, trace


class ProjectionTests(unittest.TestCase):
    def test_exact_offsets_and_controls_are_preserved_without_unicode_replacement(self):
        raw, native, trace = projection_fixture("\x00\ufffd")
        before = copy.deepcopy((raw, native, trace))
        chars, reason = _project(raw, native, trace, [])
        self.assertIsNone(reason)
        self.assertEqual("".join(c["raw"] for c in chars), "\x00\ufffd")
        self.assertEqual([c["native_ref"] for c in chars], [{"line_id": 7, "start": i, "end": i+1} for i in range(2)])
        self.assertTrue(all("native_unicode_unresolved" in c["uncertainty"] for c in chars))
        self.assertEqual((raw, native, trace), before)

    def test_font_glyph_replacement_is_explicitly_unresolved(self):
        chars, _ = _project(*projection_fixture("b", 0xfffd), [])
        self.assertEqual(chars[0]["raw"], "b")
        self.assertIn("trace_unicode_unresolved", chars[0]["uncertainty"])
        self.assertIn("rawdict_trace_unicode_disagreement", chars[0]["uncertainty"])
        self.assertEqual(chars[0]["trace_witnesses"][0]["glyph_id"], 0)

    def test_same_origin_overprint_is_not_silently_disambiguated(self):
        raw, native, trace = projection_fixture()
        trace.append(copy.deepcopy(trace[0]))
        trace[1]["opacity"] = 0
        chars, _ = _project(raw, native, trace, [])
        self.assertEqual(len(chars[0]["trace_witnesses"]), 2)
        self.assertIn("trace_origin_ambiguous", chars[0]["uncertainty"])
        self.assertIn("nonvisible_trace_paint", chars[0]["uncertainty"])

    def test_synthetic_space_and_unmatched_ligature_components_remain_raw(self):
        raw, native, trace = projection_fixture("fi ")
        raw["blocks"][0]["lines"][0]["spans"][0]["chars"][2]["synthetic"] = True
        trace[0]["chars"] = [(0xfb01, 4, [10, 100], [10, 90, 20, 102])]
        chars, _ = _project(raw, native, trace, [])
        self.assertEqual("".join(c["raw"] for c in chars), "fi ")
        self.assertIn("rawdict_trace_unicode_disagreement", chars[0]["uncertainty"])
        self.assertIn("trace_origin_unmatched", chars[1]["uncertainty"])
        self.assertIn("rawdict_synthetic_character", chars[2]["uncertainty"])

    def test_length_order_codepoint_box_or_block_mismatch_holds_whole_projection(self):
        for kind in ("length", "order", "unicode", "box", "block", "line_count"):
            raw, native, trace = projection_fixture("xy")
            if kind == "length": native[0]["text"] = "x"
            if kind == "order": native[0]["text"] = "yx"
            if kind == "unicode": native[0]["text"] = "x\u212a"
            if kind == "box": native[0]["bbox"] = [11, 90, 20, 102]
            if kind == "block": native[0]["block_id"] = 5
            if kind == "line_count": native.append(copy.deepcopy(native[0]))
            with self.subTest(kind=kind):
                chars, reason = _project(raw, native, trace, [])
                self.assertIsNone(chars)
                self.assertIn("mismatch", reason)

    def test_rotation_is_retained_and_blocks_relation_eligibility(self):
        raw, native, trace = projection_fixture()
        raw["blocks"][0]["lines"][0]["dir"] = [0, -1]
        chars, _ = _project(raw, native, trace, [])
        self.assertEqual(chars[0]["direction"], [0, -1])
        self.assertIn("nonhorizontal_character", chars[0]["uncertainty"])

    def test_missing_or_conflicting_font_program_identity_is_unresolved(self):
        fixture = projection_fixture()
        chars, _ = _project(*fixture, [])
        self.assertIn("font_resource_unmatched", chars[0]["uncertainty"])
        fonts = [{"name": "ABC+TestFont", "embedded_sha256": "a"*64},
                 {"name": "DEF+TestFont", "embedded_sha256": "b"*64}]
        chars, _ = _project(*fixture, fonts)
        self.assertIn("font_resource_ambiguous", chars[0]["uncertainty"])
        self.assertEqual(chars[0]["font_program_status"], "ambiguous")
        self.assertEqual(relation_candidates(chars, []), [])

    def test_matched_standard_font_without_embedded_bytes_is_explicit(self):
        chars, _ = _project(*projection_fixture(), [{"name": "TestFont", "embedded_sha256": None}])
        self.assertEqual(chars[0]["font_program_status"], "not_embedded")
        self.assertEqual(chars[0]["font_refs"], [0])
        self.assertNotIn("font_resource_unmatched", chars[0]["uncertainty"])


class GeometryTests(unittest.TestCase):
    def check_held(self, relations):
        for relation in relations:
            self.assertFalse(relation["accepted"])
            self.assertEqual(relation["status"], "unreviewed_geometry_candidate")
            self.assertIn("ownership_unreviewed", relation["uncertainty"])
            self.assertIn("semantic_role_unreviewed", relation["uncertainty"])

    def test_measured_superscript_and_subscript_candidates(self):
        chars = [char(0, "λ", 10, 100), char(1, "2", 15, 96, size=7), char(2, "q", 15, 103, size=7)]
        relations = relation_candidates(chars, [])
        self.assertEqual({r["role"] for r in relations}, {"subscript_candidate", "superscript_candidate"})
        self.check_held(relations)

    def test_fraction_requires_actual_rule_and_both_sides(self):
        chars = [char(0, "1", 10, 95, size=7), char(1, "2", 10, 105, size=7)]
        self.assertEqual(relation_candidates(chars, []), [])
        relations = relation_candidates(chars, [rule()])
        self.assertEqual(relations[0]["kind"], "fraction")
        self.assertEqual(relations[0]["numerator"], [0])
        self.assertEqual(relations[0]["denominator"], [1])
        self.check_held(relations)
        self.assertEqual(relation_candidates(chars[:1], [rule()]), [])

    def test_separate_column_members_are_not_a_fraction(self):
        chars = [char(0, "1", 10, 95, size=7), char(1, "2", 100, 105, size=7)]
        self.assertEqual(relation_candidates(chars, [rule()]), [])

    def test_radical_requires_one_rule_and_operand_with_one_baseline(self):
        chars = [char(0, "√", 5, 98), char(1, "T", 10, 106)]
        relation = relation_candidates(chars, [rule(10, 15, 98)])[0]
        self.assertEqual((relation["kind"], relation["radical"], relation["radicand"]), ("radical", 0, [1]))
        self.check_held([relation])
        self.assertEqual(relation_candidates(chars, []), [])
        self.assertEqual(relation_candidates(chars, [rule(), {**rule(), "id": 1}]), [])
        stacked = chars + [char(2, "x", 10, 110)]
        self.assertFalse(any(r["kind"] == "radical" for r in relation_candidates(stacked, [rule()])))

    def test_missing_or_ambiguous_glyphs_do_not_seed_relations(self):
        for reason in ("trace_unicode_unresolved", "nonhorizontal_character", "trace_origin_ambiguous", "nonvisible_trace_paint"):
            with self.subTest(reason=reason):
                chars = [char(0, "√", 5, 98, uncertainty=[reason]), char(1, "T", 10, 106)]
                self.assertEqual(relation_candidates(chars, [rule()]), [])

    def test_small_prose_footnote_and_tied_bases_do_not_become_certified_scripts(self):
        ordinary = [char(0, "e", 10, 100, flags=0), char(1, "1", 15, 96, size=7)]
        self.assertEqual(relation_candidates(ordinary, []), [])
        tied = [char(0, "x", 10, 100), char(1, "y", 10, 100), char(2, "2", 15, 96, size=7)]
        self.assertEqual(relation_candidates(tied, []), [])
        italic_footnote = [char(0, "e", 10, 100), char(1, "1", 15, 96, size=7)]
        self.check_held(relation_candidates(italic_footnote, []))

    def test_table_or_underline_geometry_never_implies_semantic_fraction(self):
        table = [char(0, "A", 10, 95, size=7), char(1, "B", 10, 105, size=7)]
        self.check_held(relation_candidates(table, [rule()]))

    def test_competing_fraction_radical_interpretations_are_explicit(self):
        chars = [char(0, "√", 5, 98), char(1, "T", 10, 106), char(2, "x", 10, 95, size=7)]
        relations = relation_candidates(chars, [rule()])
        self.assertEqual({r["kind"] for r in relations}, {"fraction", "radical"})
        self.assertTrue(all("competing_rule_interpretation" in r["uncertainty"] for r in relations))
        self.check_held(relations)

    def test_vertical_or_transparent_rules_are_excluded(self):
        drawing = {"type": "s", "stroke_opacity": 1, "width": .4, "seqno": 0, "items": [("l", (10, 98), (15, 98))]}
        self.assertEqual(len(_rules([drawing])), 1)
        self.assertEqual(_rules([{**drawing, "stroke_opacity": 0}]), [])
        self.assertEqual(_rules([{**drawing, "items": [("l", (10, 90), (10, 100))]}]), [])


@unittest.skipUnless(importlib.util.find_spec("pymupdf"), "optional PyMuPDF required")
class CaptureTests(unittest.TestCase):
    def authored(self, transform=False):
        import pymupdf
        with pymupdf.open() as doc:
            page = doc.new_page(width=400, height=400)
            page.insert_text((60, 100), "x", fontname="tiit", fontsize=10)
            page.insert_text((65, 95), "2", fontsize=7)
            if transform:
                page.set_cropbox(pymupdf.Rect(20, 20, 380, 380))
                page.set_rotation(90)
            payload = doc.tobytes()
        with pymupdf.open(stream=payload, filetype="pdf") as doc:
            native = source_lines(doc[0])
        return payload, native

    def test_real_pdf_has_exact_native_projection_and_never_admits(self):
        pdf, native = self.authored()
        before = copy.deepcopy(native)
        sidecar, png = capture_notation(pdf, native)
        self.assertEqual(sidecar["rawdict_projection"], "exact")
        self.assertEqual(native, before)
        self.assertTrue(png.startswith(b"\x89PNG"))
        self.assertFalse(sidecar["accepted"])
        self.assertFalse(sidecar["proposal"])
        self.assertIsNone(sidecar["scientific_transcription"])
        self.assertIsNone(sidecar["section_owner"])
        self.assertTrue(sidecar["relations"])

    def test_nonzero_crop_and_rotation_are_bound(self):
        pdf, native = self.authored(True)
        sidecar, _ = capture_notation(pdf, native)
        coordinates = sidecar["source"]["coordinates"]
        self.assertEqual(coordinates["cropbox"], [20, 20, 380, 380])
        self.assertEqual(coordinates["page_rotation"], 90)
        self.assertNotEqual(coordinates["rotation_matrix"], [1, 0, 0, 1, 0, 0])

    def test_native_tampering_is_a_typed_hold(self):
        pdf, native = self.authored()
        native[0]["text"] = "wrong"
        sidecar, _ = capture_notation(pdf, native)
        self.assertEqual(sidecar["reason"], "fresh_native_identity_mismatch")
        self.assertEqual(sidecar["characters"], [])
        self.assertEqual(sidecar["relations"], [])

    def test_direct_api_freezes_mutable_pdf_buffer_and_rejects_typed_native_alias(self):
        import pymupdf
        pdf, native = self.authored()
        mutable = bytearray(pdf)
        original = pymupdf.open
        def mutate_caller_buffer(*args, **kwargs):
            mutable[:] = b"changed after capture"
            return original(*args, **kwargs)
        with patch.object(pymupdf, "open", side_effect=mutate_caller_buffer):
            sidecar, _ = capture_notation(mutable, native)
        self.assertEqual(sidecar["native_identity"], "exact")
        native[0]["id"] = False  # False == 0 in Python, but identity types differ.
        sidecar, _ = capture_notation(pdf, native)
        self.assertEqual(sidecar["reason"], "fresh_native_identity_mismatch")

    def test_file_binding_immutable_output_and_input_race(self):
        from src.parallel_source_v4 import notation
        pdf, native = self.authored()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "source.pdf").write_bytes(pdf)
            (root / "native.json").write_bytes(json_bytes(native))
            lock = root / "runtime.json"
            lock.write_text("{}")
            runtime = {"environment": {}, "lock_sha256": notation.digest(lock)}
            kwargs = {"source_sha256": notation.digest(root / "source.pdf"), "native_sha256": notation.digest(root / "native.json"), "runtime_lock": lock}
            with patch.object(notation, "method_hashes", return_value={"authored": "bound"}), patch.object(notation, "runtime_receipt", return_value=runtime):
                result = notation.prepare(root, "source.pdf", "native.json", "output", **kwargs)
                self.assertFalse(result["accepted"])
                self.assertEqual(notation.prepare(root, "source.pdf", "native.json", "output", **kwargs), result)
                with self.assertRaisesRegex(ValueError, "input_hash_mismatch"):
                    notation.prepare(root, "source.pdf", "native.json", "wrong", **{**kwargs, "source_sha256": "0"*64})
                original = notation.capture_notation
                def swap(*args):
                    out = original(*args)
                    (root / "source.pdf").write_bytes(b"changed")
                    return out
                with patch.object(notation, "capture_notation", side_effect=swap):
                    with self.assertRaisesRegex(ValueError, "notation_input_changed"):
                        notation.prepare(root, "source.pdf", "native.json", "raced", **kwargs)
                self.assertFalse((root / "raced" / "notation.json").exists())


if __name__ == "__main__":
    unittest.main()
