import copy
import hashlib
import json
import unittest

try:
    import pymupdf
except ImportError:
    pymupdf = None

from trace_gc.scientific_ink_geometry import InkGeometryError, capture_accurate_glyph_bounds


@unittest.skipIf(pymupdf is None, "optional PDF stack unavailable")
class ScientificInkGeometryTests(unittest.TestCase):
    def setUp(self):
        from trace_gc.pdf_notation_parallel_v4 import capture_notation
        from trace_gc.pdf_source_parallel_v4 import source_lines
        with pymupdf.open() as doc:
            page = doc.new_page()
            page.insert_text((100, 100), "1", fontsize=11)
            page.draw_line((99, 102), (108, 102), width=0.4)
            page.insert_text((100, 113), "2", fontsize=11)
            page.insert_text((130, 113), "external prose", fontsize=11)
            self.pdf = doc.tobytes()
        with pymupdf.open(stream=self.pdf, filetype="pdf") as doc:
            self.native = source_lines(doc[0])
        self.notation, _ = capture_notation(self.pdf, self.native)
        self.sidecar = json.dumps(self.notation, ensure_ascii=False).encode("utf-8")

    def test_drawing_hulls_resolve_metric_overlap_and_leave_parent_settings(self):
        before = pymupdf.TOOLS.unset_quad_corrections()
        result = capture_accurate_glyph_bounds(self.pdf, self.native, self.sidecar)
        self.assertEqual(before, pymupdf.TOOLS.unset_quad_corrections())
        numerator = next(g for g in result["glyphs"] if g["raw"] == "1")
        denominator = next(g for g in result["glyphs"] if g["raw"] == "2")
        self.assertGreater(numerator["box"][3], 102)
        self.assertLess(numerator["ink_box"][3], 101.8)
        self.assertGreater(denominator["ink_box"][1], 102.2)
        self.assertEqual(len(result["glyphs"]), len(self.notation["characters"]))
        self.assertEqual(result["accurate_bbox_evidence"]["source_pdf_sha256"],
                         hashlib.sha256(self.pdf).hexdigest())
        self.assertFalse(result["visibility_verified"])
        self.assertFalse(result["accepted"])

    def test_rejects_another_original_pdf_or_native_projection(self):
        with self.assertRaisesRegex(InkGeometryError, "another_pdf"):
            capture_accurate_glyph_bounds(self.pdf + b"\n", self.native, self.sidecar)
        changed = copy.deepcopy(self.native)
        changed[0]["text"] = "forged"
        with self.assertRaisesRegex(InkGeometryError, "another_native"):
            capture_accurate_glyph_bounds(self.pdf, changed, self.sidecar)

    def test_rejects_forged_glyph_and_nominal_box_in_bound_sidecar(self):
        for key, value in (("raw", "9"), ("bbox", [0, 0, 1, 1])):
            changed = copy.deepcopy(self.notation)
            changed["characters"][0][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(InkGeometryError, "sidecar_mismatch"):
                capture_accurate_glyph_bounds(self.pdf, self.native,
                    json.dumps(changed).encode("utf-8"))

    def test_rejects_render_drift_even_when_native_identity_matches(self):
        changed = copy.deepcopy(self.notation)
        changed["source"]["render"]["png_sha256"] = "0" * 64
        with self.assertRaises(InkGeometryError):
            capture_accurate_glyph_bounds(self.pdf, self.native,
                json.dumps(changed).encode("utf-8"))

    def test_malformed_source_identity_and_timeout_fail_with_domain_error(self):
        for source in ([], None, "forged"):
            changed = copy.deepcopy(self.notation)
            changed["source"] = source
            with self.subTest(source=source), self.assertRaises(InkGeometryError):
                capture_accurate_glyph_bounds(self.pdf, self.native,
                    json.dumps(changed).encode("utf-8"))
        for timeout in (True, 0, -1, float("nan"), float("inf"), "60"):
            with self.subTest(timeout=timeout), self.assertRaises(InkGeometryError):
                capture_accurate_glyph_bounds(self.pdf, self.native, self.sidecar, timeout=timeout)


if __name__ == "__main__":
    unittest.main()
