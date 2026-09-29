"""Regenerate glyph drawing bounds without changing the caller's PDF settings.

Accurate bounds describe glyph drawing hulls, not final-page visibility or
scientific interpretation. The separate verifier still requires source review.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
from pathlib import Path
import subprocess
import sys

from .canonical import loads
from .pdf_source_parallel_v4 import digest_value


class InkGeometryError(ValueError):
    """Original-source glyph geometry could not be independently regenerated."""


def _code_identity() -> dict[str, str]:
    folder = Path(__file__).resolve().parent
    return {p.relative_to(folder.parent).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(folder.rglob("*.py"))}


# PyMuPDF's accurate box mode needs a global quad setting. A fresh isolated
# interpreter contains that setting, and establishes ordinary extraction first.
_CAPTURE = r'''
import base64, hashlib, json, sys
request = json.loads(sys.stdin.buffer.read().decode("utf-8"))
sys.path.insert(0, request["module_root"])
import pymupdf
from trace_gc.pdf_notation_parallel_v4 import capture_notation
from trace_gc.pdf_source_parallel_v4 import digest_value
pdf = base64.b64decode(request["pdf"], validate=True)
notation, image = capture_notation(pdf, request["native"])
if notation.get("native_identity") != "exact" or notation.get("rawdict_projection") != "exact":
    raise ValueError("fresh_original_projection_not_exact")
if getattr(pymupdf, "TEXT_ACCURATE_BBOXES", None) != 512:
    raise ValueError("accurate_bbox_mode_unavailable")
pymupdf.TOOLS.unset_quad_corrections(True)
with pymupdf.open(stream=pdf, filetype="pdf") as document:
    raw = document[0].get_text("rawdict", sort=True,
        flags=pymupdf.TEXTFLAGS_RAWDICT | pymupdf.TEXT_ACCURATE_BBOXES)
    glyphs = []
    for bi, block in enumerate(raw["blocks"]):
        if block.get("type") != 0:
            continue
        for li, line in enumerate(block["lines"]):
            for si, span in enumerate(line["spans"]):
                for ci, char in enumerate(span["chars"]):
                    glyphs.append({"raw": char["c"], "origin": list(char["origin"]),
                        "font": span["font"], "size": span["size"],
                        "rawdict_ref": {"block": bi, "line": li, "span": si, "char": ci},
                        "ink_box": list(char["bbox"])})
ordinary = notation["characters"]
if len(glyphs) != len(ordinary):
    raise ValueError("accurate_glyph_count_changed")
for original, accurate in zip(ordinary, glyphs):
    if any(original[key] != accurate[key]
           for key in ("raw", "origin", "font", "size", "rawdict_ref")):
        raise ValueError("accurate_glyph_identity_changed")
    accurate.update(id=original["id"], box=original["bbox"])
print(json.dumps({"notation_semantic_sha256": digest_value(notation),
    "source": notation["source"], "glyphs": glyphs,
    "page_render_sha256": hashlib.sha256(image).hexdigest()},
    ensure_ascii=True, allow_nan=False))
'''


def capture_accurate_glyph_bounds(pdf_bytes: bytes, native: list[dict],
                                  notation_bytes: bytes, *, timeout: float = 60) -> dict:
    """Bind exact nominal and accurate glyph boxes to original PDF and sidecar.

The original notation sidecar must regenerate exactly under the interpreter
used by the caller. IDs, raw characters, fonts, origins, sizes and rawdict
positions must match one-to-one before any ink box is returned. Spaces may
have zero-height ink boxes. Fraction operands need nondegenerate boxes in the
packet verifier. Occlusion, clipping and scientific scope are separate gates.
    """
    if not isinstance(pdf_bytes, bytes) or not pdf_bytes or not isinstance(native, list):
        raise InkGeometryError("original_pdf_and_native_required")
    if not isinstance(notation_bytes, bytes):
        raise InkGeometryError("original_notation_bytes_required")
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0:
        raise InkGeometryError("positive_finite_capture_timeout_required")
    try:
        notation = loads(notation_bytes.decode("utf-8"))
    except (UnicodeError, ValueError):
        raise InkGeometryError("invalid_notation_sidecar") from None
    pdf_sha = hashlib.sha256(pdf_bytes).hexdigest()
    if not isinstance(notation, dict) or not isinstance(notation.get("source"), dict):
        raise InkGeometryError("invalid_notation_source_identity")
    render = notation["source"].get("render")
    if not isinstance(render, dict) or not isinstance(render.get("png_sha256"), str):
        raise InkGeometryError("invalid_notation_render_identity")
    if notation["source"].get("original_pdf_sha256") != pdf_sha:
        raise InkGeometryError("notation_targets_another_pdf")
    try:
        native_sha = digest_value(native)
    except (TypeError, ValueError):
        raise InkGeometryError("invalid_native_projection") from None
    if notation["source"].get("native_content_sha256") != native_sha:
        raise InkGeometryError("notation_targets_another_native_projection")
    code = _code_identity()
    request = {"module_root": str(Path(__file__).resolve().parent.parent),
               "pdf": base64.b64encode(pdf_bytes).decode("ascii"), "native": native}
    try:
        process = subprocess.run([sys.executable, "-I", "-B", "-c", _CAPTURE],
            input=json.dumps(request, ensure_ascii=True, allow_nan=False).encode("utf-8"),
            capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired, TypeError, ValueError, UnicodeError) as exc:
        raise InkGeometryError("isolated_glyph_capture_unavailable") from exc
    if process.returncode:
        # Child stderr can contain private source/path details; expose a stable
        # reason rather than copying it into a public caller log or receipt.
        raise InkGeometryError("isolated_original_glyph_capture_failed")
    if _code_identity() != code:
        raise InkGeometryError("glyph_capture_code_changed")
    try:
        captured = loads(process.stdout.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise InkGeometryError("invalid_isolated_capture_response") from exc
    if (not isinstance(captured, dict)
            or not isinstance(captured.get("source"), dict)
            or not isinstance(captured["source"].get("pymupdf_version"), str)
            or not isinstance(captured.get("glyphs"), list)
            or not isinstance(captured.get("page_render_sha256"), str)):
        raise InkGeometryError("invalid_isolated_capture_response")
    if captured.get("notation_semantic_sha256") != digest_value(notation):
        raise InkGeometryError("fresh_notation_sidecar_mismatch")
    if captured["page_render_sha256"] != render["png_sha256"]:
        raise InkGeometryError("fresh_source_render_mismatch")
    return {
        "version": "original-pdf-accurate-glyph-hulls-v1",
        "accurate_bbox_evidence": {
            "source_pdf_sha256": pdf_sha,
            "notation_sha256": hashlib.sha256(notation_bytes).hexdigest(),
            "pymupdf_version": captured["source"]["pymupdf_version"],
            "text_accurate_bboxes_flag": 512,
            "quad_corrections_disabled": True,
            "source_mode": "original_pdf_fresh_rawdict",
        },
        "notation_semantic_sha256": captured["notation_semantic_sha256"],
        "capture_code_sha256": code,
        "native_sha256": notation["source"]["native_content_sha256"],
        "page_render_sha256": captured["page_render_sha256"],
        "glyphs": captured["glyphs"],
        "admission": "source_review_required",
        "accepted": False,
        "visibility_verified": False,
    }
