"""Source-image review and immutable derived-text handoff, without graph writes.

Hashes prove consistency. An attributed review is an accuracy attestation, not
a signature, independent qualification, or automatic acceptance of OCR output.
Images and native text are separate representations; no native span is invented.
"""
from __future__ import annotations

from copy import deepcopy
from io import BytesIO
import math
from typing import TYPE_CHECKING

from .canonical import bytes_digest, digest, text_digest
from .errors import boundary, require
from .schema import validate

if TYPE_CHECKING:
    from .catalog import Catalog

REPRESENTATION = "reviewed-image-transcription-v1"
CHECKS = ("transcription", "reading_order", "boundaries", "notation")


def _png(image) -> bytes:
    output = BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


@boundary
def render_source(pdf_bytes: bytes, *, physical_page: int = 1, dpi: int = 144,
                  crop: list[int] | None = None) -> tuple[dict, bytes, bytes]:
    """Render one byte snapshot; crop is an observed pixel rectangle, never OCR geometry."""
    import fitz
    import PIL
    from PIL import Image
    require(type(physical_page) is int and physical_page >= 1, "IMAGE_PAGE", "physical page is one based")
    require(type(dpi) is int and 36 <= dpi <= 600, "IMAGE_SCALE", "DPI outside supported range")
    with fitz.open(stream=pdf_bytes, filetype="pdf") as document:
        require(physical_page <= len(document), "IMAGE_PAGE", "physical page absent")
        page = document[physical_page - 1]
        scale = dpi / 72
        require(page.rect.width * page.rect.height * scale * scale <= 100_000_000,
                "IMAGE_BUDGET", "render exceeds pixel budget")
        pixmap = page.get_pixmap(matrix=fitz.Matrix(scale, scale), colorspace=fitz.csRGB, alpha=False)
        require(pixmap.width * pixmap.height <= 100_000_000, "IMAGE_BUDGET", "render exceeds pixel budget")
        page_image = Image.frombytes("RGB", (pixmap.width, pixmap.height), pixmap.samples)
        bbox = [0, 0, pixmap.width, pixmap.height] if crop is None else list(crop)
        require(len(bbox) == 4 and all(type(v) is int for v in bbox) and
                0 <= bbox[0] < bbox[2] <= pixmap.width and 0 <= bbox[1] < bbox[3] <= pixmap.height,
                "IMAGE_CROP_BOUNDS", "crop must be within the rendered page")
        cropped = page_image.crop(tuple(bbox))
        page_png, crop_png = _png(page_image), _png(cropped)
        matrix = page.rotation_matrix * fitz.Matrix(scale, scale) * fitz.Matrix(1, 0, 0, 1, -pixmap.x, -pixmap.y)
        inverse = ~matrix
        unrotated = page.rect * page.derotation_matrix
        native = page.get_text("text")
        bad = sum(c == "\ufffd" or (ord(c) < 32 and c not in "\n\r\t") for c in native)
        native_state = "absent" if not native.strip() else "suspect_encoding" if bad else "available"
        render = {"renderer": "PyMuPDF", "renderer_version": fitz.VersionBind,
            "mupdf_version": fitz.VersionFitz, "pillow_version": PIL.__version__, "dpi": dpi,
            "rotation_degrees": page.rotation, "unrotated_page_rect": list(unrotated),
            "pdf_to_pixels": list(matrix), "pixels_to_pdf": list(inverse),
            "pixmap_origin": [pixmap.x, pixmap.y], "dimensions": [pixmap.width, pixmap.height],
            "colorspace": "RGB", "coordinate_system": "unrotated-mupdf-page-points-to-rendered-top-left-pixels-v1",
            "page_png_sha256": bytes_digest(page_png), "page_pixels_sha256": bytes_digest(page_image.tobytes())}
        source_hash = bytes_digest(pdf_bytes)
        page_identity = digest({"source_sha256": source_hash, "physical_page": physical_page,
                                "rotation": page.rotation, "unrotated_page_rect": list(unrotated)})
        metadata = {"source_sha256": source_hash, "physical_page": physical_page,
            "page_identity_sha256": page_identity, "render": render,
            "crop": {"bbox": bbox, "dimensions": list(cropped.size),
                "coordinate_system": "rendered-top-left-pixel-edges-half-open-v1",
                "location_basis": "observed-source-image", "png_sha256": bytes_digest(crop_png),
                "pixels_sha256": bytes_digest(cropped.tobytes())},
            "native_observation": {"state": native_state, "text_sha256": text_digest(native),
                "character_count": len(native), "replacement_or_control_count": bad}}
    return metadata, page_png, crop_png


def candidate_hash(candidate: dict) -> str:
    return digest({k: v for k, v in candidate.items() if k != "review"})


@boundary
def image_candidate(pdf_bytes: bytes, *, source_id: str, transcription: str,
                    raw_output: bytes, engine: str, revision: str, configuration: dict,
                    physical_page: int = 1, dpi: int = 144, crop: list[int] | None = None,
                    input_crop_sha256: str | None = None, output_status: str = "complete",
                    fallback_reason: str = "image_review_requested") -> dict:
    metadata, _, _ = render_source(pdf_bytes, physical_page=physical_page, dpi=dpi, crop=crop)
    if input_crop_sha256 is not None:
        require(input_crop_sha256 == metadata["crop"]["png_sha256"], "OCR_INPUT_MISMATCH", "OCR input was another crop")
    candidate = {"version": "pdf-image-evidence-v1", "source_id": source_id, **metadata,
        "fallback_reason": fallback_reason,
        "ocr": {"engine": engine, "revision": revision,
            "configuration": deepcopy(configuration), "configuration_sha256": digest(configuration),
            "raw_output_sha256": bytes_digest(raw_output), "raw_output_bytes": len(raw_output),
            "input_crop_sha256": input_crop_sha256,
            "input_binding": "verified-crop" if input_crop_sha256 is not None else "unverified-cache",
            "output_status": output_status},
        "transcription": transcription, "transcription_sha256": text_digest(transcription), "correction": None, "review": None}
    validate("image-evidence-v1", candidate)
    return candidate


@boundary
def validate_image_record(candidate: dict) -> None:
    """Portable semantic integrity; artifact re-rendering is a separate required gate."""
    validate("image-evidence-v1", candidate)
    require(text_digest(candidate["transcription"]) == candidate["transcription_sha256"] and
            digest(candidate["ocr"]["configuration"]) == candidate["ocr"]["configuration_sha256"],
            "IMAGE_INTEGRITY", "transcription or OCR configuration changed")
    crop, render = candidate["crop"], candidate["render"]
    x0, y0, x1, y1 = crop["bbox"]
    width, height = render["dimensions"]
    require(0 <= x0 < x1 <= width and 0 <= y0 < y1 <= height and
            crop["dimensions"] == [x1 - x0, y1 - y0], "IMAGE_CROP_BOUNDS", "invalid crop geometry")
    forward, inverse = render["pdf_to_pixels"], render["pixels_to_pdf"]
    require(all(math.isfinite(v) for v in forward + inverse), "IMAGE_TRANSFORM", "nonfinite transform")
    def apply(point, matrix):
        x, y = point; a, b, c, d, e, f = matrix
        return (a*x + c*y + e, b*x + d*y + f)
    rect = render["unrotated_page_rect"]
    corners = [(rect[x], rect[y]) for x, y in ((0, 1), (2, 1), (2, 3), (0, 3))]
    require(rect[0] < rect[2] and rect[1] < rect[3], "IMAGE_TRANSFORM", "invalid page rectangle")
    for point in corners:
        restored = apply(apply(point, forward), inverse)
        require(all(abs(a-b) < 0.001 for a, b in zip(point, restored)), "IMAGE_TRANSFORM", "transform is not invertible")
    mapped = [apply(point, forward) for point in corners]
    require(-1 < min(p[0] for p in mapped) <= 1 and -1 < min(p[1] for p in mapped) <= 1 and
            abs(max(p[0] for p in mapped) - width) <= 1 and abs(max(p[1] for p in mapped) - height) <= 1,
            "IMAGE_TRANSFORM", "page transform does not fit rendered dimensions")
    require(candidate["page_identity_sha256"] == digest({"source_sha256": candidate["source_sha256"],
        "physical_page": candidate["physical_page"], "rotation": render["rotation_degrees"],
        "unrotated_page_rect": rect}), "IMAGE_PAGE_IDENTITY", "physical page identity changed")
    require(candidate["ocr"]["input_binding"] == ("verified-crop" if candidate["ocr"]["input_crop_sha256"] is not None else "unverified-cache"),
            "OCR_INPUT_MISMATCH", "inconsistent input binding")
    if candidate["ocr"]["input_crop_sha256"] is not None:
        require(candidate["ocr"]["input_crop_sha256"] == crop["png_sha256"], "OCR_INPUT_MISMATCH", "different OCR input")
    review = candidate["review"]
    if review is not None:
        require(review["candidate_sha256"] == candidate_hash(candidate), "IMAGE_REVIEW_STALE", "source, crop or transcription changed")


@boundary
def verify_artifacts(candidate: dict, *, pdf_bytes: bytes, raw_output: bytes,
                     page_png: bytes | None = None, crop_png: bytes | None = None) -> None:
    validate_image_record(candidate)
    require(bytes_digest(raw_output) == candidate["ocr"]["raw_output_sha256"] and
            len(raw_output) == candidate["ocr"]["raw_output_bytes"], "OCR_OUTPUT_MISMATCH", "raw OCR output changed")
    require(bytes_digest(pdf_bytes) == candidate["source_sha256"], "IMAGE_SOURCE_CHANGED", "original PDF changed")
    metadata, expected_page, expected_crop = render_source(pdf_bytes, physical_page=candidate["physical_page"],
        dpi=candidate["render"]["dpi"], crop=candidate["crop"]["bbox"])
    require(all(candidate[key] == value for key, value in metadata.items()),
            "IMAGE_RENDER_MISMATCH", "renderer, transform, native observation, page or crop differs")
    require(page_png is None or page_png == expected_page, "IMAGE_PAGE_MISMATCH", "page image changed")
    require(crop_png is None or crop_png == expected_crop, "IMAGE_CROP_MISMATCH", "crop image changed")


@boundary
def review_image(candidate: dict, *, pdf_bytes: bytes, raw_output: bytes,
                 reviewer: str, reviewer_kind: str, reviewed_at: str, disposition: str,
                 checks: dict[str, bool], notes: str = "") -> dict:
    """Record the caller's actual visual review; this function does not perform it."""
    verify_artifacts(candidate, pdf_bytes=pdf_bytes, raw_output=raw_output)
    result = deepcopy(candidate)
    result["review"] = {"candidate_sha256": candidate_hash(candidate), "reviewer": reviewer,
        "reviewer_kind": reviewer_kind, "reviewed_at": reviewed_at, "independent_review": False,
        "disposition": disposition, "checks": deepcopy(checks), "notes": notes}
    validate_image_record(result)
    return result


@boundary
def correct_transcription(candidate: dict, *, transcription: str, editor: str,
                          editor_kind: str, edited_at: str, reason: str) -> dict:
    """New candidate, original raw OCR retained, and any previous review invalidated."""
    validate_image_record(candidate)
    result = deepcopy(candidate)
    result.update(transcription=transcription, transcription_sha256=text_digest(transcription), review=None,
        correction={"previous_candidate_sha256": candidate_hash(candidate),
            "previous_transcription_sha256": candidate["transcription_sha256"],
            "editor": editor, "editor_kind": editor_kind, "edited_at": edited_at, "reason": reason})
    validate_image_record(result)
    return result


def held_reason(candidate: dict, *, max_characters: int = 4000, max_text_bytes: int = 16000) -> str | None:
    validate_image_record(candidate)
    if candidate["ocr"]["output_status"] != "complete":
        return "ocr_" + candidate["ocr"]["output_status"]
    review = candidate["review"]
    if review is None:
        return "image_source_review_required"
    if review["disposition"] != "complete":
        return "image_review_" + review["disposition"]
    if not all(review["checks"].values()):
        return "image_review_check_failed"
    # Old cached outputs can be inspected, but missing original input/model
    # provenance is never silently converted into a fully verified OCR run.
    if candidate["ocr"]["input_binding"] != "verified-crop":
        return "ocr_input_provenance_unverified"
    if candidate["ocr"]["revision"].lower() in {"unknown", "unrecorded"}:
        return "ocr_revision_unverified"
    text = candidate["transcription"]
    if not text.strip():
        return "image_transcription_absent"
    if len(text) > max_characters:
        return "complete_transcription_exceeds_character_budget"
    if len(text.encode("utf-8")) > max_text_bytes:
        return "complete_transcription_exceeds_byte_budget"
    return None


@boundary
def verify_image_source(catalog: Catalog, source: dict) -> None:
    """Check portable lineage in every consumer of the unchanged text-span contract."""
    if source["representation"] != REPRESENTATION:
        require("image_evidence_id" not in source, "IMAGE_SOURCE_BINDING", "image lineage on another representation")
        return
    image = catalog.get(source["image_evidence_id"], "image-evidence-v1")
    require(held_reason(image) is None, "IMAGE_REVIEW_REQUIRED", "image transcription is held")
    require(source["source_id"] == image["source_id"] and source["text"] == image["transcription"] and
            source["text_hash"] == image["transcription_sha256"] and
            source["raw_document_hash"] == image["source_sha256"] and
            source["version"] == catalog.hash(source["image_evidence_id"]) and
            source["parser_version"] == REPRESENTATION,
            "IMAGE_SOURCE_BINDING", "derived text or image lineage changed")


@boundary
def handoff(catalog: Catalog, candidate: dict, *, pdf_bytes: bytes, raw_output: bytes,
            scope: str) -> dict:
    """Return review-held or immutable text evidence. Never create an assertion or graph write."""
    verify_artifacts(candidate, pdf_bytes=pdf_bytes, raw_output=raw_output)
    reason = held_reason(candidate)
    if reason:
        return {"status": "HELD", "reason": reason, "admitted": False}
    image_id = catalog.put("image-evidence-v1", candidate)
    source_id = catalog.put("source", {"source_id": candidate["source_id"],
        "version": catalog.hash(image_id), "representation": REPRESENTATION,
        "text": candidate["transcription"], "text_hash": candidate["transcription_sha256"],
        "security_scope": scope, "parser_version": REPRESENTATION,
        "raw_document_hash": candidate["source_sha256"], "image_evidence_id": image_id})
    evidence_id = catalog.evidence(source_id)
    catalog.verify_evidence(evidence_id)
    return {"status": "REVIEWED_TEXT_EVIDENCE", "image_evidence_id": image_id,
        "source_snapshot_id": source_id, "evidence_id": evidence_id,
        "admitted": False, "graph_writes": 0, "independent_review": False}


def fallback_route(native_assessment: dict | None, candidate: dict | None = None) -> dict:
    """Select a review queue, without changing native assessment or claiming admission."""
    if native_assessment and native_assessment.get("proposal") is True:
        return {"route": "existing_native_source_review", "admitted": False}
    return {"route": "image_source_review", "admitted": False,
            "reason": held_reason(candidate) if candidate is not None else "image_evidence_required"}
