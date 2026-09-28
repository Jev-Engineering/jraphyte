"""Versioned, non-admitting native notation evidence.

This sidecar preserves the native representation. Geometry produces review
candidates, never replacement Unicode, a scientific transcription, or ownership.
"""
from __future__ import annotations

import hashlib
import math
import unicodedata
from copy import deepcopy
from collections import defaultdict

from .pdf_source_parallel_v4 import digest_value, source_lines

VERSION = "native-notation-sidecar-v1"
RELATION_VERSION = "native-notation-geometry-candidates-v1"
ORIGIN_TOLERANCE_PT = .001


def _sha(payload):
    return hashlib.sha256(payload).hexdigest()


def _finite(values):
    return all(isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v) for v in values)


def _horizontal(direction):
    return len(direction) == 2 and _finite(direction) and abs(direction[0] - 1) < 1e-6 and abs(direction[1]) < 1e-6


def _ref(line_id, offset):
    return {"line_id": line_id, "start": offset, "end": offset + 1}


def _font_records(page):
    records = []
    for xref, ext, kind, name, resource, encoding, referencer in page.get_fonts(full=True):
        embedded = page.parent.extract_font(xref)[3] if xref else b""
        records.append({"xref": xref, "extension": ext, "type": kind, "name": name,
                        "resource": resource, "encoding": encoding, "referencer": referencer,
                        "embedded_sha256": _sha(embedded) if embedded else None})
    return records


def _project(raw, native, trace, fonts):
    """Exact RAWDICT projection; trace is a separate, possibly ambiguous witness."""
    chars, raw_lines = [], []
    trace_index = defaultdict(list)
    for ti, item in enumerate(trace):
        for gi, glyph in enumerate(item["chars"]):
            key = (item["font"], *(math.floor(v / ORIGIN_TOLERANCE_PT) for v in glyph[2]))
            trace_index[key].append((ti, gi, item, glyph))
    for bi, block in enumerate(raw["blocks"]):
        if block.get("type") != 0:
            continue
        for li, line in enumerate(block.get("lines", [])):
            raw_lines.append((bi, li, line))
    if len(raw_lines) != len(native):
        return None, "rawdict_line_count_mismatch"
    for (bi, li, line), old in zip(raw_lines, native):
        raw_text = "".join(c["c"] for s in line["spans"] for c in s["chars"])
        if (raw_text != old["text"] or list(line["bbox"]) != old["bbox"] or
                bi != old["block_id"] or li != old["line_in_block"]):
            return None, "rawdict_native_projection_mismatch"
        offset = 0
        for si, span in enumerate(line["spans"]):
            for ci, char in enumerate(span["chars"]):
                if len(char["c"]) != 1 or not _finite((*char["origin"], *char["bbox"], span["size"])):
                    return None, "unsupported_rawdict_character_geometry"
                witnesses = []
                ox, oy = (math.floor(v / ORIGIN_TOLERANCE_PT) for v in char["origin"])
                for dx in (-1, 0, 1):
                    for dy in (-1, 0, 1):
                        for ti, gi, item, glyph in trace_index[(span["font"], ox + dx, oy + dy)]:
                            if max(abs(a - b) for a, b in zip(glyph[2], char["origin"])) <= ORIGIN_TOLERANCE_PT:
                                witnesses.append({"trace_span": ti, "trace_char": gi, "unicode": glyph[0],
                                    "glyph_id": glyph[1], "origin": list(glyph[2]), "bbox": list(glyph[3]),
                                    "font": item["font"], "direction": list(item["dir"]), "seqno": item["seqno"],
                                    "paint_type": item["type"], "opacity": item["opacity"]})
                codepoint = ord(char["c"])
                uncertainty = []
                if codepoint == 0xfffd or unicodedata.category(char["c"])[0] == "C":
                    uncertainty.append("native_unicode_unresolved")
                if any(w["unicode"] == 0xfffd for w in witnesses):
                    uncertainty.append("trace_unicode_unresolved")
                if len(witnesses) > 1:
                    uncertainty.append("trace_origin_ambiguous")
                elif not witnesses:
                    uncertainty.append("trace_origin_unmatched")
                elif witnesses[0]["unicode"] != codepoint:
                    uncertainty.append("rawdict_trace_unicode_disagreement")
                if char.get("synthetic", False):
                    uncertainty.append("rawdict_synthetic_character")
                if not _horizontal(line["dir"]):
                    uncertainty.append("nonhorizontal_character")
                if any(w["paint_type"] not in (0, 1) or w["opacity"] <= 0 for w in witnesses):
                    uncertainty.append("nonvisible_trace_paint")
                font_refs = [i for i, f in enumerate(fonts) if f["name"].split("+", 1)[-1] == span["font"]]
                font_programs = {fonts[i]["embedded_sha256"] for i in font_refs}
                if not font_refs:
                    uncertainty.append("font_resource_unmatched")
                elif len(font_programs) > 1:
                    uncertainty.append("font_resource_ambiguous")
                chars.append({"id": len(chars), "native_ref": _ref(old["id"], offset), "raw": char["c"],
                    "rawdict_ref": {"block": bi, "line": li, "span": si, "char": ci},
                    "origin": list(char["origin"]), "bbox": list(char["bbox"]),
                    "direction": list(line["dir"]), "writing_mode": line["wmode"],
                    "font": span["font"], "size": span["size"], "flags": span["flags"],
                    "font_refs": font_refs,
                    "font_program_status": "unmatched" if not font_refs else "ambiguous" if len(font_programs) > 1 else
                        "not_embedded" if font_programs == {None} else "embedded_hash_bound",
                    "trace_witnesses": witnesses, "uncertainty": uncertainty,
                    "visibility": "paint_metadata_only_occlusion_unreviewed"})
                offset += 1
    return chars, None


def _rules(drawings):
    output = []
    for di, drawing in enumerate(drawings):
        if drawing.get("type") not in ("s", "fs") or drawing.get("stroke_opacity", 0) <= 0:
            continue
        width = drawing.get("width", 0)
        if not _finite([width]) or not 0 < width <= 1:
            continue
        for ii, item in enumerate(drawing["items"]):
            if item[0] != "l":
                continue
            a, b = list(item[1]), list(item[2])
            if not _finite(a + b) or abs(a[1] - b[1]) > .01:
                continue
            x0, x1 = sorted((a[0], b[0]))
            if not 1 <= x1 - x0 <= 160:
                continue
            output.append({"id": len(output), "drawing_index": di, "item_index": ii,
                           "seqno": drawing["seqno"], "x0": x0, "x1": x1, "y": (a[1] + b[1]) / 2,
                           "stroke_width": width, "stroke_opacity": drawing["stroke_opacity"],
                           "visibility": "paint_metadata_only_occlusion_unreviewed"})
    return output


def _eligible(char):
    return (not char["uncertainty"] and not char["raw"].isspace() and
            char["size"] > 0 and char["bbox"][2] > char["bbox"][0] and
            char["bbox"][3] > char["bbox"][1])


def _math_base(char):
    # Typography is a candidate-generation cue, never proof of semantic role.
    category = unicodedata.category(char["raw"])
    return category[0] in "LN" and (bool(char["flags"] & 2) or ord(char["raw"]) > 127)


def relation_candidates(chars, rules):
    """Describe measured arrangements. Every candidate still needs source review."""
    usable = [c for c in chars if _eligible(c)]
    output = []

    def add(kind, members, evidence, **extra):
        output.append({"id": len(output), "version": RELATION_VERSION, "kind": kind,
                       "character_ids": members, "evidence": evidence, **extra,
                       "status": "unreviewed_geometry_candidate", "accepted": False,
                       "uncertainty": ["semantic_role_unreviewed", "ownership_unreviewed", "occlusion_unreviewed"]})

    fraction_members = set()
    for rule in rules:
        above, below = [], []
        for c in usable:
            if c["bbox"][0] < rule["x0"] - .75 or c["bbox"][2] > rule["x1"] + .75:
                continue
            dy = c["origin"][1] - rule["y"]
            if -1.25 * c["size"] <= dy < -.2:
                above.append(c)
            elif .2 < dy <= 1.25 * c["size"]:
                below.append(c)
        if not above or not below:
            continue
        # Disconnected columns and prose far outside the actual rule are not joined.
        if max(c["origin"][1] for c in above) >= min(c["origin"][1] for c in below):
            continue
        numerator = [c["id"] for c in above]
        denominator = [c["id"] for c in below]
        fraction_members.update(numerator + denominator)
        add("fraction", numerator + denominator, {"rule_id": rule["id"], "member_order": "native_offset_order_within_each_role"},
            numerator=numerator, denominator=denominator)

    for radical in usable:
        if radical["raw"] != "√":
            continue
        matching = [r for r in rules if abs(r["x0"] - radical["bbox"][2]) <= .2 * radical["size"] and
                    abs(r["y"] - radical["origin"][1]) <= .25 * radical["size"]]
        if len(matching) != 1:
            continue
        rule = matching[0]
        operands = [c for c in usable if c["id"] != radical["id"] and
                    c["bbox"][0] >= rule["x0"] - .5 and c["bbox"][2] <= rule["x1"] + .5 and
                    .2 < c["origin"][1] - rule["y"] <= 1.25 * c["size"]]
        if not operands or max(c["origin"][1] for c in operands) - min(c["origin"][1] for c in operands) > .2 * radical["size"]:
            continue
        ids = [c["id"] for c in operands]
        add("radical", [radical["id"], *ids], {"rule_id": rule["id"]}, radical=radical["id"], radicand=ids)

    for script in usable:
        if script["id"] in fraction_members:
            continue
        choices = []
        for base in usable:
            if base["id"] == script["id"] or not _math_base(base) or script["size"] > .85 * base["size"]:
                continue
            dx = script["bbox"][0] - base["bbox"][2]
            dy = script["origin"][1] - base["origin"][1]
            if -.15 * base["size"] <= dx <= .45 * base["size"] and .12 * base["size"] <= abs(dy) <= .85 * base["size"]:
                choices.append((abs(dx), base, dy))
        choices.sort(key=lambda item: (item[0], item[1]["id"]))
        if not choices or (len(choices) > 1 and abs(choices[0][0] - choices[1][0]) < .1):
            continue
        dx, base, dy = choices[0]
        add("script", [base["id"], script["id"]], {"horizontal_edge_distance_pt": dx, "baseline_delta_pt": dy,
            "size_ratio": script["size"] / base["size"]}, base=base["id"], script=script["id"],
            role="superscript_candidate" if dy < 0 else "subscript_candidate")
    for candidate in output:
        rule_id = candidate["evidence"].get("rule_id")
        competitors = [other["id"] for other in output if rule_id is not None and
                       other["evidence"].get("rule_id") == rule_id and other["kind"] != candidate["kind"]]
        if competitors:
            candidate["competing_candidate_ids"] = competitors
            candidate["uncertainty"].append("competing_rule_interpretation")
    return output


def capture_notation(pdf_bytes: bytes, native: list[dict]):
    """Capture physical page one from the same original byte buffer that is hashed."""
    import pymupdf

    if not isinstance(pdf_bytes, (bytes, bytearray)) or not isinstance(native, list):
        raise ValueError("notation_requires_pdf_bytes_and_native_list")
    pdf_bytes, native = bytes(pdf_bytes), deepcopy(native)
    identity = {"original_pdf_sha256": _sha(pdf_bytes), "native_content_sha256": digest_value(native),
                "physical_page": 1, "pymupdf_version": pymupdf.VersionBind, "mupdf_version": pymupdf.VersionFitz}
    base = {"version": VERSION, "relation_version": RELATION_VERSION, "source": identity,
            "status": "diagnostic_only", "accepted": False, "proposal": False,
            "section_owner": None, "admission": "held", "scientific_transcription": None,
            "claim": "Geometry candidates are measured arrangements, not certified notation or section ownership."}
    with pymupdf.open(stream=pdf_bytes, filetype="pdf") as document:
        page = document[0]
        pixmap = page.get_pixmap(matrix=pymupdf.Matrix(2, 2), alpha=False)
        image = pixmap.tobytes("png")
        identity.update({"page_size": [page.rect.width, page.rect.height],
                         "coordinates": {"text_frame": "pymupdf_unrotated_page_coordinates",
                             "cropbox": list(page.cropbox), "mediabox": list(page.mediabox),
                             "page_rotation": page.rotation, "transformation_matrix": list(page.transformation_matrix),
                             "rotation_matrix": list(page.rotation_matrix), "derotation_matrix": list(page.derotation_matrix)},
                         "render": {"dpi": 144, "matrix": [2, 0, 0, 2, 0, 0], "alpha": False,
                                    "width": pixmap.width, "height": pixmap.height, "png_sha256": _sha(image)}})
        if digest_value(source_lines(page)) != digest_value(native):
            return {**base, "status": "held", "reason": "fresh_native_identity_mismatch", "characters": [], "rules": [], "relations": []}, image
        fonts = _font_records(page)
        characters, reason = _project(page.get_text("rawdict", sort=True), native, page.get_texttrace(), fonts)
        if reason:
            return {**base, "status": "held", "reason": reason, "characters": [], "rules": [], "relations": []}, image
        rules = _rules(page.get_drawings())
        relations = relation_candidates(characters, rules)
        return {**base, "native_identity": "exact", "rawdict_projection": "exact", "fonts": fonts,
                "characters": characters, "rules": rules, "relations": relations,
                "unresolved_character_ids": [c["id"] for c in characters if c["uncertainty"] and not c["raw"].isspace()]}, image
