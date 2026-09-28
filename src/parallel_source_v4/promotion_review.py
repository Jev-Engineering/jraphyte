"""Attributed closure reviews for exact native text; never OCR or graph admission."""
from __future__ import annotations

from copy import deepcopy
import datetime as dt
import hashlib
import json
import math
from io import BytesIO

from trace_gc.pdf_source_parallel_v4 import digest_value, normalize, validate_source_spans
from trace_gc.pdf_structure_parallel_v4 import seal, verify_assessment
from .fidelity import evaluate_fidelity

VERSION = "native-closure-review-v1"
CHECKS = {"transcription", "reading_order", "boundaries", "notation", "no_page_continuation"}
FIELDS = {"version", "assessment_sha256", "text_sha256", "source_sha256", "page_sha256",
          "image_sha256", "native_sha256", "physical_page", "decision", "reviewer", "reviewer_kind",
          "reviewed_at", "independent_review", "exposure", "source_before_predictions", "checks",
          "accepted_spans", "excluded_spans", "excluded_regions", "closure"}


def _positions(spans: list[dict], native: list[dict]) -> list[tuple]:
    validate_source_spans(spans, native)
    positions = []
    for span in spans:
        if (type(span["start"]) is not int or type(span["end"]) is not int or isinstance(span["line_id"], bool)
                or type(span.get("page_no")) is not int or span["page_no"] != 1):
            raise ValueError("closure_review_requires_typed_native_offsets")
        positions.extend((str(span["line_id"]), i) for i in range(span["start"], span["end"]))
        if len(positions) > 100_000:
            raise ValueError("closure_review_span_budget_exceeded")
    if len(positions) != len(set(positions)):
        raise ValueError("closure_review_native_spans_overlap")
    return positions


def _image_asset(asset: dict, page, load_asset, *, expected_page: int,
                 expected_hash: str | None = None) -> dict:
    """Read exact bytes through the containing adapter; compare the full source page."""
    import fitz
    from PIL import Image, ImageChops
    if (not isinstance(asset, dict) or set(asset) != {"relative", "sha256", "physical_page", "dpi"}
            or type(asset["physical_page"]) is not int or asset["physical_page"] != expected_page
            or type(asset["dpi"]) is not int or asset["dpi"] != 120):
        raise ValueError("closure_review_full_page_image_asset_required")
    raw = load_asset(asset["relative"])
    if hashlib.sha256(raw).hexdigest() != asset["sha256"] or expected_hash is not None and asset["sha256"] != expected_hash:
        raise ValueError("closure_review_image_hash_mismatch")
    if page.rect.width * page.rect.height * (120/72)**2 > 100_000_000:
        raise ValueError("closure_review_image_pixel_budget_exceeded")
    pixels = page.get_pixmap(dpi=120, colorspace=fitz.csRGB, alpha=False)
    rendered = Image.frombytes("RGB", (pixels.width, pixels.height), pixels.samples)
    with Image.open(BytesIO(raw)) as image:
        if image.format != "PNG":
            raise ValueError("closure_review_png_asset_required")
        if image.size != rendered.size:
            raise ValueError("closure_review_image_is_not_full_source_page")
        observed = image.convert("RGB")
        # The frozen first-page preparations permit <=2 channel-value changes
        # from insert_pdf antialiasing. New page-two assets must render exactly.
        difference = max(channel[1] for channel in ImageChops.difference(observed, rendered).getextrema())
        if difference > (2 if expected_page == 1 else 0):
            raise ValueError("closure_review_image_does_not_depict_original_page")
    return {"physical_page": expected_page, "sha256": asset["sha256"], "dpi": 120,
            "width": rendered.width, "height": rendered.height}


def _native_page_asset(asset, page, load_asset) -> dict:
    """Page-two evidence uses PyMuPDF's actual page dict, never page-one spans."""
    if (not isinstance(asset, dict) or set(asset) != {"relative", "sha256", "physical_page", "representation"}
            or type(asset["physical_page"]) is not int or asset["physical_page"] != 2 or
            asset["representation"] != "pymupdf-page-dict-v1"):
        raise ValueError("closure_review_page_two_native_asset_required")
    raw = load_asset(asset["relative"])
    if hashlib.sha256(raw).hexdigest() != asset["sha256"]:
        raise ValueError("closure_review_page_two_native_hash_mismatch")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("closure_review_duplicate_native_json_key")
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=unique,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid_native_number")))
    # Text-only dict excludes embedded binary images; the independently checked
    # full page image carries all visible regions, backgrounds and typography.
    import fitz
    expected = page.get_text("dict", flags=fitz.TEXTFLAGS_DICT & ~fitz.TEXT_PRESERVE_IMAGES)
    if digest_value(value) != digest_value(expected):
        raise ValueError("closure_review_page_two_native_readback_mismatch")
    return {"physical_page": 2, "sha256": asset["sha256"], "representation": asset["representation"]}


def _follows(box, last):
    return (box[1] >= last[3] - 2 and
            min(box[2], last[2]) - max(box[0], last[0]) > .1 * min(box[2]-box[0], last[2]-last[0]))


def _excluded_regions(regions, image, page, accepted, native, image_bytes):
    import fitz
    from PIL import Image
    if hashlib.sha256(image_bytes).hexdigest() != image["sha256"]:
        raise ValueError("closure_review_image_changed_between_reads")
    if not isinstance(regions, list):
        raise ValueError("closure_review_image_regions_required")
    lines = {str(line["id"]): line for line in native}
    accepted_boxes = [fitz.Rect(lines[str(span["line_id"])]["bbox"]) * page.rotation_matrix * fitz.Matrix(120/72, 120/72)
                      for span in accepted]
    following = False
    for region in regions:
        if (not isinstance(region, dict) or set(region) != {"role", "bbox", "image_sha256", "physical_page", "coordinate_system"}
                or region["role"] not in {"metadata", "body", "footnote", "other"}
                or type(region["physical_page"]) is not int or region["physical_page"] != 1
                or region["coordinate_system"] != "full-page-image-pixels-top-left"
                or region["image_sha256"] != image["sha256"]):
            raise ValueError("closure_review_excluded_image_region_identity_invalid")
        box = region["bbox"]
        if (not isinstance(box, list) or len(box) != 4 or
                any(type(x) not in (int, float) or not math.isfinite(x) for x in box) or
                not 0 <= box[0] < box[2] <= image["width"] or not 0 <= box[1] < box[3] <= image["height"]):
            raise ValueError("closure_review_excluded_image_region_out_of_bounds")
        if any((fitz.Rect(box) & accepted_box).get_area() > 0 for accepted_box in accepted_boxes):
            raise ValueError("closure_review_image_region_overlaps_accepted_native_line")
        with Image.open(BytesIO(image_bytes)) as observed:
            minimum, maximum = observed.crop(tuple(box)).convert("L").getextrema()
            if maximum - minimum < 8:
                raise ValueError("closure_review_transition_image_region_is_blank")
        if region["role"] != "footnote" and _follows(box, list(accepted_boxes[-1])):
            following = True
    return following


def apply_closure_review(prediction: dict, review: dict, *, native: list[dict],
                         source_identity: dict, pdf_bytes: bytes, load_asset,
                         fidelity_reference: dict, evaluated_at: str) -> tuple[dict, dict]:
    """Return a new sealed assessment only after exact source and fidelity checks.

    Originals, transcription and graph admission remain unchanged. Partial,
    absent, error and truncated results cannot use this closure-only adapter.
    """
    import fitz
    verify_assessment(prediction)
    if "interior_footnote_exclusion" in prediction:
        # This adapter may certify closure of unchanged held native prose; it
        # cannot settle an unresolved marker or replace an existing exclusion.
        raise ValueError("closure_review_cannot_resolve_interior_footnote")
    if not isinstance(review, dict) or set(review) != FIELDS or review["version"] != VERSION:
        raise ValueError("invalid_native_closure_review_contract")
    if (prediction.get("status") != "uncertain" or prediction.get("proposal") is not False or
            prediction.get("conversion_status") != "success" or not prediction.get("text", "").strip()):
        raise ValueError("closure_review_requires_held_native_text_candidate")
    if (len(prediction["text"]) > 4000 or len(prediction["text"].encode("utf-8")) > 16000 or
            prediction.get("request_budget", {}).get("status") != "within_budget"):
        raise ValueError("closure_review_cannot_relax_request_budgets")
    identities = {"assessment_sha256": prediction["assessment_sha256"], "text_sha256": prediction["text_sha256"],
                  "source_sha256": source_identity["source_sha256"], "page_sha256": source_identity["page_sha256"],
                  "image_sha256": source_identity["image_sha256"], "native_sha256": digest_value(native)}
    if any(review.get(k) != v for k, v in identities.items()) or any(
            prediction.get(k) != identities[k] for k in ("source_sha256", "page_sha256", "native_sha256")):
        raise ValueError("closure_review_targets_another_assessment_or_source")
    if hashlib.sha256(pdf_bytes).hexdigest() != identities["source_sha256"]:
        raise ValueError("closure_review_original_pdf_changed")
    if (type(review["physical_page"]) is not int or review["physical_page"] != 1 or review["decision"] != "complete" or
            review["reviewer_kind"] not in {"assistant", "human"} or not isinstance(review["reviewer"], str) or
            not review["reviewer"].strip() or review["independent_review"] is not False or
            review["exposure"] != "previously_examined_development" or review["source_before_predictions"] is not False):
        raise ValueError("closure_review_requires_honest_attributed_development_scope")
    stamp = dt.datetime.fromisoformat(review["reviewed_at"].replace("Z", "+00:00"))
    evaluation = dt.datetime.fromisoformat(evaluated_at.replace("Z", "+00:00"))
    if stamp.tzinfo is None or evaluation.tzinfo is None or stamp > evaluation:
        raise ValueError("closure_review_time_invalid_or_post_evaluation")
    if (not isinstance(review["checks"], dict) or set(review["checks"]) != CHECKS or
            any(value is not True for value in review["checks"].values())):
        raise ValueError("closure_review_has_unresolved_accuracy_or_scope_checks")
    accepted = review["accepted_spans"]
    positions = _positions(accepted, native)
    if not positions or normalize("\n".join(span["text"] for span in accepted)) != normalize(prediction["text"]):
        raise ValueError("closure_review_cannot_rewrite_or_reorder_candidate_text")
    excluded_positions = []
    for excluded in review["excluded_spans"]:
        if set(excluded) != {"role", "spans"} or excluded["role"] not in {"metadata", "body", "footnote", "other"}:
            raise ValueError("closure_review_excluded_role_invalid")
        excluded_positions.extend(_positions(excluded["spans"], native))
    if set(positions) & set(excluded_positions) or len(excluded_positions) != len(set(excluded_positions)):
        raise ValueError("closure_review_conflicting_native_ownership")
    closure = review["closure"]
    if (not isinstance(closure, dict) or set(closure) != {"kind", "page_one_image", "next_page"} or
            closure["kind"] not in {"reviewed_section_transition", "reviewed_title_page_end"}):
        raise ValueError("closure_review_requires_explicit_source_closure_kind")
    assets = []
    with fitz.open(stream=pdf_bytes, filetype="pdf") as pdf:
        if not len(pdf):
            raise ValueError("closure_review_original_page_missing")
        assets.append(_image_asset(closure["page_one_image"], pdf[0], load_asset,
                                  expected_page=1, expected_hash=identities["image_sha256"]))
        image_follows = _excluded_regions(review["excluded_regions"], assets[0], pdf[0], accepted, native,
                                          load_asset(closure["page_one_image"]["relative"]))
        if closure["kind"] == "reviewed_section_transition":
            by_id = {str(line["id"]): line for line in native}
            last = accepted[-1]
            native_follows = any(group["role"] != "footnote" and any(
                span["text"].strip() and
                ((str(span["line_id"]) == str(last["line_id"]) and span["start"] >= last["end"]) or
                 _follows(by_id[str(span["line_id"])]["bbox"], by_id[str(last["line_id"])]["bbox"]))
                for span in group["spans"]) for group in review["excluded_spans"])
            if not (native_follows or image_follows) or closure["next_page"] is not None:
                raise ValueError("reviewed_transition_requires_excluded_source_extent")
        elif len(pdf) == 1:
            if closure["next_page"] != {"document_end": True}:
                raise ValueError("reviewed_title_page_end_requires_actual_document_end")
        else:
            following = closure["next_page"]
            if not isinstance(following, dict) or set(following) != {"image", "native"}:
                raise ValueError("closure_review_page_two_image_and_native_required")
            assets.append(_image_asset(following["image"], pdf[1], load_asset, expected_page=2))
            assets.append(_native_page_asset(following["native"], pdf[1], load_asset))
    result = deepcopy(prediction)
    review_hash = digest_value(review)
    result.update(status="complete", proposal=True, complete_candidate=True, section_owner="abstract",
        spans=deepcopy(accepted), closing_boundary={"kind": closure["kind"], "review_sha256": review_hash,
            "source_spans": [span for group in review["excluded_spans"] for span in deepcopy(group["spans"])]},
        reasons=["attributed_source_closure_review"], original_assessment_sha256=prediction["assessment_sha256"],
        manual_closure_review_sha256=review_hash, eligible_for_jev=False, verified_admission=False,
        admission="source_review_required")
    result = seal(result)
    fidelity = evaluate_fidelity(result, fidelity_reference, evaluated_at=evaluated_at)
    if fidelity["verified_correct_proposal"] is not True:
        raise ValueError("closure_review_requires_verified_boundary_order_and_notation")
    return result, {"version": VERSION, "original_assessment_sha256": prediction["assessment_sha256"],
        "review_sha256": review_hash, "derived_assessment_sha256": result["assessment_sha256"],
        "reviewer_kind": review["reviewer_kind"], "independent_review": False,
        "exposure": review["exposure"], "source_before_predictions": False,
        "closure_kind": closure["kind"], "asset_hashes": assets,
        "excluded_image_region_count": len(review["excluded_regions"]), "graph_admission_enabled": False}
