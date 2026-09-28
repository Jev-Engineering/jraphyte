"""Source-reviewed, non-admitting notation fragments with exact glyph coverage.

This API records the caller's actual review; it cannot perform or authenticate a
visual review. The separately supplied review hash pins that attestation. Nothing
in this module changes native text, certifies a section, or authorizes a graph.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import unicodedata
from xml.sax.saxutils import escape

from .canonical import bytes_digest, digest, loads
from .pdf_image_evidence import render_source
from .pdf_notation_parallel_v4 import capture_notation
from .pdf_source_parallel_v4 import digest_value

VERSION = "reviewed-notation-fragment-v1"
EVIDENCE_VERSION = "notation-fragment-evidence-v1"
REVIEW_VERSION = "notation-fragment-review-v1"
UNICODE_VERSION = "notation-fragment-unicode-v1"
CHECKS = ("source_image", "glyph_mapping", "reading_order", "semantic_role",
          "occlusion", "complete_fragment", "exclusions")
EXCLUSIONS = {"context", "whitespace", "other_expression", "unresolved_source_glyph"}
# Explicit source-reviewed mappings, never applied to raw native characters.
ACCENTS = {"^": "\u0302", "\u02c6": "\u0302", "~": "\u0303", "\u02dc": "\u0303",
           "\u00af": "\u0304", "\u02c9": "\u0304", "\u02d9": "\u0307", "\u00a8": "\u0308",
           "\u00b4": "\u0301", "`": "\u0300", "\u02d8": "\u0306", "\u02c7": "\u030c",
           "\u02da": "\u030a"}
SUPERSCRIPTS = dict(zip("0123456789+-=()in", "⁰¹²³⁴⁵⁶⁷⁸⁹⁺⁻⁼⁽⁾ⁱⁿ"))
SUBSCRIPTS = dict(zip("0123456789+-=()aehijklmnoprstuvx", "₀₁₂₃₄₅₆₇₈₉₊₋₌₍₎ₐₑₕᵢⱼₖₗₘₙₒₚᵣₛₜᵤᵥₓ"))


class NotationHold(ValueError):
    """An intact source/review packet contains an unsupported fragment."""


def _require(condition, reason):
    if not condition:
        raise ValueError(reason)


def _hold(condition, reason):
    if not condition:
        raise NotationHold(reason)


def _keys(value, expected, reason):
    _require(type(value) is dict and set(value) == set(expected), reason)


def _time(value):
    _require(type(value) is str and value.endswith("Z"), "review_time_requires_utc")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise ValueError("invalid_review_time") from None


def _pixel_box(box, matrix):
    a, b, c, d, e, f = matrix
    points = [(a*x+c*y+e, b*x+d*y+f) for x, y in
              ((box[0], box[1]), (box[2], box[1]), (box[2], box[3]), (box[0], box[3]))]
    return [min(p[0] for p in points), min(p[1] for p in points),
            max(p[0] for p in points), max(p[1] for p in points)]


def prepare_evidence(pdf_bytes: bytes, native_bytes: bytes, sidecar_bytes: bytes,
                     crop: list[int]) -> tuple[dict, bytes, bytes]:
    """Replay the original bytes and produce an image packet for actual review.

    The crop is observed rendered-pixel geometry. Its glyph inventory includes
    every intersecting RAWDICT box, including whitespace and uncertain mappings.
    Historical sidecar producer metadata stays historical; its core is replayed.
    """
    _require(all(isinstance(v, (bytes, bytearray)) for v in (pdf_bytes, native_bytes, sidecar_bytes)),
             "notation_bytes_required")
    pdf_bytes, native_bytes, sidecar_bytes = map(bytes, (pdf_bytes, native_bytes, sidecar_bytes))
    native, sidecar = loads(native_bytes), loads(sidecar_bytes)
    _require(type(sidecar) is dict, "notation_sidecar_object_required")
    fresh, original_render = capture_notation(pdf_bytes, native)
    _require(fresh["status"] == "diagnostic_only" and fresh.get("rawdict_projection") == "exact",
             "notation_projection_not_exact")
    _require(digest_value({k: sidecar.get(k) for k in fresh}) == digest_value(fresh),
             "notation_sidecar_replay_mismatch")
    if "sidecar_sha256" in sidecar:
        _require(sidecar["sidecar_sha256"] == digest_value({k: v for k, v in sidecar.items() if k != "sidecar_sha256"}),
                 "notation_sidecar_digest_mismatch")
    _require(bytes_digest(original_render) == fresh["source"]["render"]["png_sha256"],
             "notation_original_render_mismatch")
    image, page_png, crop_png = render_source(pdf_bytes, physical_page=1, dpi=144, crop=deepcopy(crop))
    scope, outside = [], []
    x0, y0, x1, y1 = image["crop"]["bbox"]
    for char in fresh["characters"]:
        box = _pixel_box(char["bbox"], image["render"]["pdf_to_pixels"])
        if box[0] < x1 and box[2] > x0 and box[1] < y1 and box[3] > y0:
            scope.append({"glyph": deepcopy(char), "pixel_bbox": box,
                          "fully_inside_crop": x0 <= box[0] and y0 <= box[1] and box[2] <= x1 and box[3] <= y1})
        else:
            outside.append(char["id"])
    _require(scope, "notation_empty_crop")
    accents, nearby_scripts, overhead = [], [], []
    scope_ids = {v["glyph"]["id"] for v in scope}
    usable = [c for c in fresh["characters"] if not c["uncertainty"] and c["size"] > 0]
    for mark in usable:
        if mark["raw"] in ACCENTS and mark["id"] in scope_ids:
            accents.extend({"base": base["id"], "mark": mark["id"]} for base in usable
                           if base["id"] != mark["id"] and _diacritic_geometry(base, mark))
    # Candidate generation is deliberately incomplete. Check the original page
    # geometry as well, so an unmapped accent or a roman-font exponent cannot be
    # hidden just by omitting it from the crop or excluding it as context.
    for base in usable:
        if base["id"] not in scope_ids or unicodedata.category(base["raw"])[0] not in "LN":
            continue
        for other in fresh["characters"]:
            if other["id"] == base["id"] or other["raw"].isspace() or other["size"] <= 0:
                continue
            size = base["size"]
            dx, dy = other["bbox"][0] - base["bbox"][2], other["origin"][1] - base["origin"][1]
            if other["size"] <= .85*size and -.15*size <= dx <= .45*size and .12*size <= abs(dy) <= .85*size:
                nearby_scripts.append({"base": base["id"], "script": other["id"]})
            if _diacritic_geometry(base, other):
                overhead.append({"base": base["id"], "glyph": other["id"]})
    evidence = {"version": EVIDENCE_VERSION, "source_sha256": bytes_digest(pdf_bytes),
                "native_file_sha256": bytes_digest(native_bytes), "native_sha256": digest_value(native),
                "sidecar_file_sha256": bytes_digest(sidecar_bytes), "replayed_core_sha256": digest_value(fresh),
                "image": image, "scope": scope, "outside_crop_glyph_ids": outside,
                "page_glyph_count": len(fresh["characters"]),
                "relations": deepcopy(fresh["relations"]),
                "rules": deepcopy(fresh["rules"]), "diacritic_geometry_candidates": accents,
                "nearby_script_glyphs": nearby_scripts, "overhead_glyphs": overhead,
                "coverage_claim": "all_intersecting_glyph_boxes_in_observed_crop_only"}
    return evidence, page_png, crop_png


def _eligible(char):
    _hold(not char["uncertainty"], "glyph_mapping_or_visibility_unresolved")
    _hold(unicodedata.category(char["raw"])[0] not in "CZ" and char["raw"] != "\ufffd",
          "unsupported_glyph_unicode")
    _hold(char["size"] > 0 and char["direction"] == [1.0, 0.0] and char["writing_mode"] == 0,
          "unsupported_glyph_direction")


def _diacritic_geometry(base, mark):
    size = base["size"]
    center = (mark["bbox"][0] + mark["bbox"][2]) / 2
    dy = mark["origin"][1] - base["origin"][1]
    return (unicodedata.category(base["raw"])[0] == "L" and
            .45 <= mark["size"] / size <= 1.25 and
            base["bbox"][0] - .1*size <= center <= base["bbox"][2] + .1*size and
            -.9*size <= dy <= -.12*size)


def _compile(node, evidence):
    """Only one bounded expression: one base and one/two scripts or one accent."""
    _require(type(node) is dict, "notation_expression_object_required")
    kind = node.get("kind")
    scope = {v["glyph"]["id"]: v for v in evidence["scope"]}

    def glyph(gid):
        _require(type(gid) is int and gid in scope, "notation_glyph_outside_scope")
        record = scope[gid]
        _hold(record["fully_inside_crop"], "notation_glyph_clipped_by_crop")
        char = record["glyph"]
        _eligible(char)
        return char

    relations = evidence["relations"]
    witnesses = []
    if kind == "scripts":
        _keys(node, ("kind", "base", "sub", "sup"), "notation_script_fields")
        base = glyph(node["base"])
        _hold(unicodedata.category(base["raw"])[0] in "LN", "unsupported_script_base")
        _require(node["sub"] is not None or node["sup"] is not None, "notation_script_missing")
        used = [node["base"]]
        parts = {}
        unicode_parts = {}
        for role, table in (("sub", SUBSCRIPTS), ("sup", SUPERSCRIPTS)):
            gid = node[role]
            if gid is None:
                continue
            script = glyph(gid)
            _hold(unicodedata.category(script["raw"])[0] in "LN" or script["raw"] in "+-=()−",
                  "unsupported_script_character")
            matching = [r for r in relations if r["kind"] == "script" and r["base"] == base["id"] and
                        r["script"] == gid and r["role"] == ("subscript_candidate" if role == "sub" else "superscript_candidate")]
            _hold(len(matching) == 1, "script_geometry_not_uniquely_corroborated")
            witnesses.append(deepcopy(matching[0]))
            used.append(gid)
            parts[role] = "<mtext>" + escape(script["raw"]) + "</mtext>"
            unicode_parts[role] = table.get(script["raw"])
        _require(len(set(used)) == len(used), "notation_duplicate_glyph")
        # A cropped/excluded counterpart cannot turn a combined script into a
        # partial correction. Other relation kinds remain unsupported.
        attached = {r["script"] for r in relations if r["kind"] == "script" and r["base"] == base["id"]}
        _hold(attached == set(used[1:]), "script_counterpart_omitted_or_ambiguous")
        nearby = {r["script"] for r in evidence["nearby_script_glyphs"] if r["base"] == base["id"]}
        _hold(nearby == set(used[1:]), "unsupported_nearby_script_glyph")
        _hold(not any(r["base"] == base["id"] for r in evidence["overhead_glyphs"]), "unsupported_overhead_glyph")
        _hold(not any(r["kind"] != "script" and set(r["character_ids"]) & set(used) for r in relations),
              "competing_notation_relation")
        body = "<mtext>" + escape(base["raw"]) + "</mtext>"
        tag = "msubsup" if len(parts) == 2 else "msub" if "sub" in parts else "msup"
        mathml = "<" + tag + ">" + body + parts.get("sub", "") + parts.get("sup", "") + "</" + tag + ">"
        unicode_text = (base["raw"] + unicode_parts.get("sub", "") + unicode_parts.get("sup", "")
                        if all(v is not None for v in unicode_parts.values()) else None)
    elif kind == "diacritic":
        _keys(node, ("kind", "base", "mark", "combining"), "notation_diacritic_fields")
        base, mark = glyph(node["base"]), glyph(node["mark"])
        _require(base["id"] != mark["id"], "notation_duplicate_glyph")
        _hold(mark["raw"] in ACCENTS and node["combining"] == ACCENTS[mark["raw"]],
              "unsupported_or_mismatched_accent_mapping")
        _hold(_diacritic_geometry(base, mark), "diacritic_geometry_not_corroborated")
        connected = [v for v in evidence["diacritic_geometry_candidates"]
                     if v["base"] == base["id"] or v["mark"] == mark["id"]]
        _hold(connected == [{"base": base["id"], "mark": mark["id"]}], "diacritic_base_or_mark_ambiguous")
        above = [r["glyph"] for r in evidence["overhead_glyphs"] if r["base"] == base["id"]]
        _hold(above == [mark["id"]], "unsupported_overhead_glyph")
        _hold(not any(r["base"] == base["id"] for r in evidence["nearby_script_glyphs"]), "diacritic_with_scripts_unsupported")
        used = [base["id"], mark["id"]]
        _hold(not any(set(r["character_ids"]) & set(used) for r in relations), "competing_notation_relation")
        witnesses = [{"kind": "diacritic_geometry_v1", "character_ids": used,
                      "base_origin": base["origin"], "mark_origin": mark["origin"],
                      "mapping": {"raw_mark": mark["raw"], "combining": node["combining"]}}]
        mathml = '<mover accent="true"><mtext>' + escape(base["raw"]) + "</mtext><mo>" + escape(mark["raw"]) + "</mo></mover>"
        unicode_text = base["raw"] + node["combining"]  # Deliberately no NFC/NFKC rewrite.
    else:
        raise NotationHold("unsupported_notation_expression")
    boxes = [scope[i]["glyph"]["bbox"] for i in used]
    extent = [min(b[0] for b in boxes), min(b[1] for b in boxes), max(b[2] for b in boxes), max(b[3] for b in boxes)]
    _hold(not any(r["x0"] < extent[2] and r["x1"] > extent[0] and extent[1] <= r["y"] <= extent[3]
                  for r in evidence["rules"]), "unmodeled_painted_rule_in_fragment")
    return used, witnesses, '<math xmlns="http://www.w3.org/1998/Math/MathML">' + mathml + "</math>", unicode_text


def derive_reviewed(pdf_bytes: bytes, native_bytes: bytes, sidecar_bytes: bytes,
                    review_bytes: bytes, *, expected_review_sha256: str,
                    expected_reviewer: str, now: str | None = None) -> dict:
    """Replay and validate a separately pinned attributed review; never admit it.

    Authorship is a caller-supplied attestation, not authenticated authority.
    `now` is an explicit deterministic clock for authored offline tests/readback.
    """
    _require(all(isinstance(v, (bytes, bytearray)) for v in (pdf_bytes, native_bytes, sidecar_bytes, review_bytes)),
             "notation_bytes_required")
    pdf_bytes, native_bytes, sidecar_bytes, review_bytes = map(bytes, (pdf_bytes, native_bytes, sidecar_bytes, review_bytes))
    _require(bytes_digest(review_bytes) == expected_review_sha256, "notation_review_hash_mismatch")
    review = loads(review_bytes)
    _keys(review, ("version", "evidence_sha256", "crop", "expression", "exclusions", "reviewer",
                   "reviewer_kind", "reviewed_at", "checks", "notes", "exposure", "independent_review",
                   "review_stage", "execution_mode", "semantic_role"), "notation_review_fields")
    _require(review["version"] == REVIEW_VERSION, "notation_review_version")
    _require(type(expected_reviewer) is str and expected_reviewer.strip() and review["reviewer"] == expected_reviewer,
             "notation_reviewer_mismatch")
    _require(review["reviewer_kind"] in ("internal_assistant", "internal_human") and review["independent_review"] is False,
             "notation_review_authority_claim")
    _require(review["execution_mode"] in ("REAL_EXPOSED_DEVELOPMENT", "SYNTHETIC_AUTHORED"), "notation_execution_mode")
    _require(review["exposure"] == ("previously_exposed_development" if review["execution_mode"] == "REAL_EXPOSED_DEVELOPMENT"
                                     else "authored_fixture"), "notation_exposure_claim")
    _require(review["review_stage"] == "source_image_before_derivative_acceptance", "notation_review_stage")
    _require(_time(review["reviewed_at"]) <= (_time(now) if now else datetime.now(timezone.utc)), "notation_future_review")
    _keys(review["checks"], CHECKS, "notation_review_checks")
    _require(all(v is True for v in review["checks"].values()), "notation_incomplete_review")
    _require(type(review["notes"]) is str and review["notes"].strip(), "notation_review_notes_required")
    _require(review["semantic_role"] in ("mathematical_notation", "linguistic_diacritic"), "notation_semantic_role")
    evidence, _, _ = prepare_evidence(pdf_bytes, native_bytes, sidecar_bytes, review["crop"])
    _require(digest(evidence) == review["evidence_sha256"], "notation_review_evidence_changed")
    result = {"version": VERSION, "status": "HELD", "review_sha256": expected_review_sha256,
              "review": deepcopy(review), "evidence": evidence, "evidence_sha256": digest(evidence),
              "scope": "reviewed_fragment_only", "section_owner": None, "proposal": False,
              "graph_admission_enabled": False, "promotion_effect": "none", "native_modified": False,
              "mathml": None, "derived_unicode": None, "coverage": None, "relation_witnesses": [],
              "review_authentication": "unsigned_attribution_pinned_by_external_expected_hash"}
    try:
        used, witnesses, mathml, unicode_text = _compile(review["expression"], evidence)
        _hold(review["expression"]["kind"] == "diacritic" or review["semantic_role"] == "mathematical_notation",
              "script_role_not_mathematical")
        excluded = []
        _require(type(review["exclusions"]) is list, "notation_exclusions_list_required")
        for row in review["exclusions"]:
            _keys(row, ("glyph_ids", "role", "reason"), "notation_exclusion_fields")
            _require(row["role"] in EXCLUSIONS and type(row["reason"]) is str and row["reason"].strip(),
                     "notation_exclusion_reason")
            _require(type(row["glyph_ids"]) is list and row["glyph_ids"] and all(type(i) is int for i in row["glyph_ids"]),
                     "notation_exclusion_ids")
            excluded.extend(row["glyph_ids"])
            if row["role"] == "whitespace":
                _require(all(next((v["glyph"]["raw"].isspace() for v in evidence["scope"] if v["glyph"]["id"] == i), False)
                             for i in row["glyph_ids"]), "notation_false_whitespace_exclusion")
        coverage = used + excluded
        scope_ids = [v["glyph"]["id"] for v in evidence["scope"]]
        _hold(len(set(coverage)) == len(coverage) and set(coverage) == set(scope_ids), "notation_glyph_coverage_incomplete_or_duplicate")
        result.update(status="REVIEWED_FRAGMENT_DERIVATIVE", mathml=mathml,
                      derived_unicode={"version": UNICODE_VERSION, "text": unicode_text,
                                       "status": "available" if unicode_text is not None else "no_lossless_unicode_script_mapping"},
                      coverage={"included_glyph_ids": used, "excluded_glyph_ids": excluded,
                                "scope_glyph_count": len(scope_ids), "complete_within_crop": True,
                                "whole_abstract_coverage": False}, relation_witnesses=witnesses)
    except NotationHold as exc:
        result["held_reason"] = str(exc)
    result["derivative_sha256"] = digest(result)
    return result
