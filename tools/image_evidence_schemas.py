"""Additive image lineage contracts; original Unicode text spans stay unchanged."""
from copy import deepcopy


def extend(schemas):
    s = {"type": "string", "minLength": 1}
    h = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    def obj(properties):
        return {"type": "object", "properties": deepcopy(properties),
                "required": list(properties), "additionalProperties": False}
    def vector(length, integer=False):
        return {"type": "array", "items": {"type": "integer" if integer else "number"},
                "minItems": length, "maxItems": length}
    nullable = lambda value: {"anyOf": [value, {"type": "null"}]}
    checks = obj({key: {"type": "boolean"} for key in
                  ("transcription", "reading_order", "boundaries", "notation")})
    review = obj({"candidate_sha256": h, "reviewer": s,
        "reviewer_kind": {"enum": ["assistant", "human"]},
        "reviewed_at": {"type": "string", "format": "date-time"},
        "independent_review": {"const": False},
        "disposition": {"enum": ["complete", "partial", "absent", "ambiguous", "uncertain_equation", "error"]},
        "checks": checks, "notes": {"type": "string"}})
    schemas["image-evidence-v1"] = obj({
        "version": {"const": "pdf-image-evidence-v1"}, "source_id": s,
        "source_sha256": h, "physical_page": {"type": "integer", "minimum": 1},
        "page_identity_sha256": h,
        "render": obj({"renderer": {"const": "PyMuPDF"}, "renderer_version": s,
            "mupdf_version": s, "pillow_version": s,
            "dpi": {"type": "integer", "minimum": 36, "maximum": 600},
            "rotation_degrees": {"enum": [0, 90, 180, 270]},
            "unrotated_page_rect": vector(4), "pdf_to_pixels": vector(6),
            "pixels_to_pdf": vector(6), "pixmap_origin": vector(2, True),
            "dimensions": vector(2, True), "colorspace": {"const": "RGB"},
            "coordinate_system": {"const": "unrotated-mupdf-page-points-to-rendered-top-left-pixels-v1"},
            "page_png_sha256": h, "page_pixels_sha256": h}),
        "crop": obj({"bbox": vector(4, True), "dimensions": vector(2, True),
            "coordinate_system": {"const": "rendered-top-left-pixel-edges-half-open-v1"},
            "location_basis": {"const": "observed-source-image"},
            "png_sha256": h, "pixels_sha256": h}),
        "native_observation": obj({"state": {"enum": ["absent", "suspect_encoding", "available"]},
            "text_sha256": h, "character_count": {"type": "integer", "minimum": 0},
            "replacement_or_control_count": {"type": "integer", "minimum": 0}}),
        "fallback_reason": {"enum": ["native_absent", "native_corrupt", "native_uncertain", "image_review_requested"]},
        "ocr": obj({"engine": s, "revision": s, "configuration_sha256": h,
            "configuration": {"type": "object"}, "raw_output_sha256": h,
            "raw_output_bytes": {"type": "integer", "minimum": 0},
            "input_crop_sha256": nullable(h),
            "input_binding": {"enum": ["verified-crop", "unverified-cache"]},
            "output_status": {"enum": ["complete", "truncated", "error"]}}),
        "transcription": {"type": "string"}, "transcription_sha256": h,
        "correction": nullable(obj({"previous_candidate_sha256": h, "previous_transcription_sha256": h,
            "editor": s, "editor_kind": {"enum": ["assistant", "human"]},
            "edited_at": {"type": "string", "format": "date-time"}, "reason": s})),
        "review": nullable(review)})
    schemas["record"]["properties"]["kind"]["enum"].append("image-evidence-v1")
    source = schemas["source"]
    source["properties"]["image_evidence_id"] = deepcopy(s)
    source["allOf"] = [{"if": {"properties": {"representation": {"const": "reviewed-image-transcription-v1"}}},
        "then": {"required": ["image_evidence_id"]},
        "else": {"not": {"required": ["image_evidence_id"]}}}]
