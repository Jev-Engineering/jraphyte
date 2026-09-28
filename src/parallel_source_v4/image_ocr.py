"""Private, immutable image-review preparation and local-only OCR handoff.

All file arguments are relative to an explicit external data root. Inspect the
rendered page/crop before recording review. No provider or graph API is called.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from trace_gc.canonical import bytes_digest, digest as semantic_digest, loads
from trace_gc.catalog import Catalog
from trace_gc.errors import ContractError
from trace_gc.pdf_image_evidence import (candidate_hash, correct_transcription, handoff, image_candidate,
    render_source, review_image, verify_artifacts)
from .common import REPO, child, data_root, digest, within, write_once


def code_identity() -> dict:
    paths = list((REPO / "trace_gc").rglob("*.py")) + list((REPO / "src/parallel_source_v4").glob("*.py"))
    paths += list((REPO / "schemas/runtime").glob("*.json"))
    paths += [REPO / "tools/windows_image_ocr.ps1"]
    return {p.relative_to(REPO).as_posix(): digest(p) for p in sorted(paths)}


def write_bytes_once(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, filename = tempfile.mkstemp(dir=path.parent, prefix=".image-", suffix=".tmp")
    temporary = Path(filename)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload); stream.flush(); os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            if path.read_bytes() != payload:
                raise ValueError("immutable_image_artifact_conflict") from None
    finally:
        temporary.unlink(missing_ok=True)


def prepare(root: Path, source: str, output: str, *, source_id: str,
            physical_page: int = 1, dpi: int = 144, crop=None) -> dict:
    source_path, folder = child(root, source), child(root, output)
    code = code_identity()
    pdf = source_path.read_bytes()
    metadata, page_png, crop_png = render_source(pdf, physical_page=physical_page, dpi=dpi, crop=crop)
    if source_path.read_bytes() != pdf or code_identity() != code:
        raise ValueError("image_preparation_input_changed")
    receipt = {"version": "image-review-preparation-v1", "source_relative": source,
        "source_id": source_id, "metadata": metadata, "code_sha256": code,
        "new_paid_api_calls": 0, "production_graph_writes": 0}
    write_bytes_once(within(root, folder / "page.png"), page_png)
    write_bytes_once(within(root, folder / "crop.png"), crop_png)
    write_once(within(root, folder / "preparation.json"), receipt)
    return receipt


def prepared(root: Path, relative: str):
    folder = child(root, relative)
    files = {name: within(root, folder / name) for name in ("preparation.json", "page.png", "crop.png")}
    raw = files["preparation.json"].read_bytes()
    receipt = loads(raw.decode("utf-8"))
    if receipt.get("version") != "image-review-preparation-v1":
        raise ValueError("unsupported_image_preparation")
    source = child(root, receipt["source_relative"])
    pdf = source.read_bytes()
    metadata, page_png, crop_png = render_source(pdf, physical_page=receipt["metadata"]["physical_page"],
        dpi=receipt["metadata"]["render"]["dpi"], crop=receipt["metadata"]["crop"]["bbox"])
    if (metadata != receipt["metadata"] or files["page.png"].read_bytes() != page_png or
            files["crop.png"].read_bytes() != crop_png):
        raise ValueError("image_preparation_source_or_artifact_changed")
    inputs = {source: bytes_digest(pdf), files["preparation.json"]: bytes_digest(raw),
        files["page.png"]: bytes_digest(page_png), files["crop.png"]: bytes_digest(crop_png)}
    return folder, receipt, pdf, inputs


def recheck(inputs: dict, code: dict) -> None:
    if any(digest(path) != expected for path, expected in inputs.items()):
        raise ValueError("image_input_changed_before_publication")
    if code_identity() != code:
        raise ValueError("image_code_changed_before_publication")


def recognize(root: Path, preparation: str, output: str, *, cached_output: str | None = None) -> dict:
    code = code_identity()
    folder, receipt, pdf, inputs = prepared(root, preparation)
    destination = child(root, output)
    destination.mkdir(parents=True, exist_ok=True)
    if cached_output:
        path = child(root, cached_output)
        raw = path.read_bytes(); inputs[path] = bytes_digest(raw)
        cached = loads(raw.decode("utf-8"))
        if not isinstance(cached, dict) or not isinstance(cached.get("raw_text"), str):
            raise ValueError("cached_ocr_record_requires_raw_text")
        text = cached["raw_text"]
        engine, revision = "cached-olmOCR-unverified", "unrecorded"
        configuration = {"cache_only": True, "original_configuration": "unrecorded"}
        input_hash = None
        state = "truncated" if cached.get("status") in {"truncated", "length", "max_tokens"} else "complete" if cached.get("status") == "success" else "error"
    else:
        if sys.platform != "win32":
            raise ValueError("windows_local_ocr_unavailable_use_explicit_cached_output")
        raw_path = within(root, destination / "raw-ocr.json")
        if raw_path.exists():
            raise ValueError("fresh_local_ocr_requires_new_output_directory")
        process = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-File",
            str(REPO / "tools/windows_image_ocr.ps1"), "-CropPath", str(folder / "crop.png"),
            "-OutputPath", str(raw_path)], capture_output=True, text=True, timeout=180)
        if process.returncode:
            # Private provider/path errors never enter a public receipt or stdout.
            raise ValueError("installed_windows_ocr_failed_or_unavailable")
        raw = raw_path.read_bytes(); inputs[raw_path] = bytes_digest(raw)
        local = loads(raw.decode("utf-8"))
        engine, revision, configuration = local["engine"], local["revision"], local["configuration"]
        input_hash, state, text = local["input_crop_sha256"], local["output_status"], local["text"]
    metadata = receipt["metadata"]
    candidate = image_candidate(pdf, source_id=receipt["source_id"], transcription=text, raw_output=raw,
        engine=engine, revision=revision, configuration=configuration,
        input_crop_sha256=input_hash, output_status=state,
        physical_page=metadata["physical_page"], dpi=metadata["render"]["dpi"], crop=metadata["crop"]["bbox"],
        fallback_reason={"absent": "native_absent", "suspect_encoding": "native_corrupt"}.get(
            metadata["native_observation"]["state"], "native_uncertain"))
    recheck(inputs, code)
    write_bytes_once(within(root, destination / "raw-ocr.json"), raw)
    write_once(within(root, destination / "candidate.json"), candidate)
    result = {"version": "image-ocr-execution-v1", "status": "SOURCE_REVIEW_REQUIRED",
        "candidate_sha256": candidate_hash(candidate), "preparation_sha256": inputs[folder / "preparation.json"],
        "code_sha256": code, "new_local_ocr_calls": 0 if cached_output else 1,
        "new_paid_api_calls": 0, "production_graph_writes": 0}
    write_once(within(root, destination / "execution.json"), result)
    return result


def reviewed_handoff(root: Path, preparation: str, ocr_output: str, review: str, output: str, *, scope: str) -> dict:
    code = code_identity()
    _, preparation_receipt, pdf, inputs = prepared(root, preparation)
    folder = child(root, ocr_output)
    blobs = {name: within(root, folder / name).read_bytes() for name in ("candidate.json", "raw-ocr.json")}
    inputs.update({within(root, folder / name): bytes_digest(raw) for name, raw in blobs.items()})
    review_path = child(root, review); review_bytes = review_path.read_bytes()
    inputs[review_path] = bytes_digest(review_bytes)
    candidate = loads(blobs["candidate.json"].decode("utf-8"))
    if (candidate.get("source_id") != preparation_receipt["source_id"] or
            any(candidate.get(key) != value for key, value in preparation_receipt["metadata"].items())):
        raise ValueError("candidate_targets_another_preparation")
    attestation = loads(review_bytes.decode("utf-8"))
    if attestation.pop("candidate_sha256", None) != candidate_hash(candidate):
        raise ValueError("review_targets_another_candidate")
    reviewed = review_image(candidate, pdf_bytes=pdf, raw_output=blobs["raw-ocr.json"], **attestation)
    catalog = Catalog()
    result = handoff(catalog, reviewed, pdf_bytes=pdf, raw_output=blobs["raw-ocr.json"], scope=scope)
    recheck(inputs, code)
    destination = child(root, output)
    write_once(within(root, destination / "reviewed-image.json"), reviewed)
    write_once(within(root, destination / "catalog-records.json"), catalog.all())
    receipt = {**result, "code_sha256": code, "candidate_sha256": candidate_hash(candidate),
        "review_sha256": bytes_digest(review_bytes), "source_sha256": candidate["source_sha256"],
        "catalog_sha256": semantic_digest(catalog.all()), "new_paid_api_calls": 0, "production_graph_writes": 0}
    write_once(within(root, destination / "handoff.json"), receipt)
    return receipt


def correct(root: Path, ocr_output: str, correction: str, output: str) -> dict:
    """A correction is a new unreviewed candidate; retain the old immutable folder."""
    code = code_identity()
    folder = child(root, ocr_output)
    paths = {name: within(root, folder / name) for name in ("candidate.json", "raw-ocr.json")}
    blobs = {name: path.read_bytes() for name, path in paths.items()}
    edit_path = child(root, correction); edit_raw = edit_path.read_bytes()
    edit = loads(edit_raw.decode("utf-8"))
    candidate = loads(blobs["candidate.json"].decode("utf-8"))
    if edit.pop("candidate_sha256", None) != candidate_hash(candidate):
        raise ValueError("correction_targets_another_candidate")
    corrected = correct_transcription(candidate, **edit)
    inputs = {paths[name]: bytes_digest(raw) for name, raw in blobs.items()}
    inputs[edit_path] = bytes_digest(edit_raw)
    recheck(inputs, code)
    destination = child(root, output)
    write_once(within(root, destination / "candidate.json"), corrected)
    write_bytes_once(within(root, destination / "raw-ocr.json"), blobs["raw-ocr.json"])
    receipt = {"status": "SOURCE_REVIEW_REQUIRED", "candidate_sha256": candidate_hash(corrected),
        "previous_candidate_sha256": candidate_hash(candidate), "correction_sha256": bytes_digest(edit_raw),
        "code_sha256": code, "new_local_ocr_calls": 0, "new_paid_api_calls": 0, "production_graph_writes": 0}
    write_once(within(root, destination / "correction.json"), receipt)
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=["prepare", "ocr", "correct", "handoff"])
    parser.add_argument("--data-root", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--source"); parser.add_argument("--source-id")
    parser.add_argument("--physical-page", type=int, default=1)
    parser.add_argument("--dpi", type=int, default=144)
    parser.add_argument("--crop", nargs=4, type=int)
    parser.add_argument("--preparation"); parser.add_argument("--cached-output")
    parser.add_argument("--ocr-output"); parser.add_argument("--review"); parser.add_argument("--scope")
    parser.add_argument("--correction")
    args = parser.parse_args()
    required = {"prepare": ("source", "source_id"), "ocr": ("preparation",),
                "correct": ("ocr_output", "correction"),
                "handoff": ("preparation", "ocr_output", "review", "scope")}[args.stage]
    if any(getattr(args, name) is None for name in required):
        parser.error("stage is missing required arguments: " + ", ".join(required))
    try:
        root = data_root(args.data_root)
        if args.stage == "prepare":
            result = prepare(root, args.source, args.output, source_id=args.source_id,
                physical_page=args.physical_page, dpi=args.dpi, crop=args.crop)
        elif args.stage == "ocr":
            result = recognize(root, args.preparation, args.output, cached_output=args.cached_output)
        elif args.stage == "correct":
            result = correct(root, args.ocr_output, args.correction, args.output)
        else:
            result = reviewed_handoff(root, args.preparation, args.ocr_output, args.review, args.output, scope=args.scope)
        print(json.dumps({"status": result.get("status", "IMAGE_REVIEW_PREPARED"),
                          "receipt_sha256": semantic_digest(result)}))
        return 0
    except (ContractError, ValueError, OSError, KeyError, TypeError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({"status": "BLOCKED", "error": exc.code if isinstance(exc, ContractError) else type(exc).__name__}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
