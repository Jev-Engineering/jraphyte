"""Source-bound full-region repair packets; never transcription or promotion.

This module is deliberately outside the extraction method-map seed directory.
Its own bytes and the dependency map are pinned separately in every packet.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import datetime as dt
import hashlib
from io import BytesIO
import json
import math
from pathlib import Path
import re

from trace_gc.pdf_source_parallel_v4 import digest_value, json_bytes, source_lines, validate_source_spans
from trace_gc.pdf_structure_parallel_v4 import verify_assessment
from trace_gc.pdf_image_evidence import render_source
from trace_gc.pdf_notation_parallel_v4 import capture_notation
from src.parallel_source_v4.common import child, data_root, digest, method_hashes, write_once
from src.parallel_source_v4.fields import parse_bound_json
from src.parallel_source_v4.image_ocr import write_bytes_once
from src.parallel_source_v4.promotion_observation import validate_failures
from src.parallel_source_v4.runtime import DEFAULT_RUNTIME_LOCK, runtime_receipt

VERSION = "notation-repair-cohort-v1"
PRIMARY = "parallel_structure_v4"
ASSETS = {"source", "page", "image", "native", "assessment"}
SHA = re.compile(r"[0-9a-f]{64}\Z")
POLICY = {
    "scope": "whole_selected_abstract_and_visible_surroundings",
    "prior_failure": "retained_until_separate_full_region_review",
    "typed_fragment": "fragment_only_no_implemented_abstract_composer",
    "image_route": "existing_source_bound_failed_native_replacement_requires_fresh_execution_and_reviews",
    "unsupported_representation": "hold",
    "source_admission": False, "graph_admission": False, "promotion_effect": "none",
}


def require(condition, code):
    if not condition:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def code_identity():
    return {"packet_tool_sha256": digest(Path(__file__)), "dependencies": method_hashes()}


class Inputs:
    def __init__(self, root):
        self.root, self.hashes = root, {}

    def read(self, descriptor, *, json_value=False):
        require(type(descriptor) is dict and set(descriptor) == {"relative", "sha256"}
                and type(descriptor["sha256"]) is str and SHA.fullmatch(descriptor["sha256"]), "invalid_packet_asset_descriptor")
        path = child(self.root, descriptor["relative"])
        raw = path.read_bytes()
        require(sha(raw) == descriptor["sha256"], "packet_input_hash_mismatch")
        require(path not in self.hashes or self.hashes[path] == descriptor["sha256"], "packet_input_identity_conflict")
        self.hashes[path] = descriptor["sha256"]
        return parse_bound_json(raw) if json_value else raw

    def recheck(self):
        require(all(digest(path) == value for path, value in self.hashes.items()), "packet_input_changed")


def _source(payloads, prediction):
    """Decode exactly the hashed buffers; never reopen a path during verification."""
    import fitz
    from PIL import Image, ImageChops
    native = parse_bound_json(payloads["native"])
    with (fitz.open(stream=payloads["source"], filetype="pdf") as original,
          fitz.open(stream=payloads["page"], filetype="pdf") as saved):
        require(len(original) > 0 and len(saved) == 1, "packet_first_page_required")
        page = original[0]
        current = source_lines(page)
        require(digest_value(native) == digest_value(current), "packet_native_source_mismatch")
        left, right = page.get_pixmap(dpi=120, alpha=False), saved[0].get_pixmap(dpi=120, alpha=False)
        require((left.width, left.height) == (right.width, right.height), "packet_saved_page_dimensions_mismatch")
        a = Image.frombytes("RGB", (left.width, left.height), left.samples)
        b = Image.frombytes("RGB", (right.width, right.height), right.samples)
        require(max(v[1] for v in ImageChops.difference(a, b).getextrema()) <= 2, "packet_saved_page_render_mismatch")
        with Image.open(BytesIO(payloads["image"])) as observed:
            observed = observed.convert("RGB")
            require(observed.size == a.size and observed.tobytes() == a.tobytes(), "packet_review_image_not_original")
        require(prediction.get("page_size") == [page.rect.width, page.rect.height], "packet_page_size_mismatch")
    verify_assessment(prediction)
    require(prediction.get("status") == "complete" and prediction.get("proposal") is True
            and prediction.get("complete_candidate") is True and prediction.get("section_owner") == "abstract"
            and prediction.get("transcription") == "native_pdf"
            and type(prediction.get("physical_page")) is int and prediction["physical_page"] == 1,
            "packet_requires_original_complete_native_proposal")
    require(prediction.get("source_sha256") == sha(payloads["source"])
            and prediction.get("page_sha256") == sha(payloads["page"])
            and prediction.get("native_sha256") == digest_value(native), "packet_assessment_source_mismatch")
    spans = prediction.get("spans")
    require(type(spans) is list and bool(spans), "packet_selected_spans_required")
    for span in spans:
        require(type(span.get("page_no")) is int and span["page_no"] == 1
                and type(span.get("start")) is int and type(span.get("end")) is int, "packet_typed_native_offsets_required")
    # Reject untrusted ranges before iterating or allocating selected positions.
    validate_source_spans(spans, native)
    require(sum(span["end"]-span["start"] for span in spans) <= 100_000, "packet_selected_extent_budget_exceeded")
    positions = set()
    for span in spans:
        for offset in range(span["start"], span["end"]):
            position = (str(span["line_id"]), offset)
            require(position not in positions, "packet_overlapping_selected_spans")
            positions.add(position)
    require("\n".join(span["text"] for span in spans) == prediction["text"], "packet_candidate_text_differs_from_spans")
    return native, positions


def _packet(payloads, observations, sid, evaluated_at, scope):
    prediction = parse_bound_json(payloads["assessment"])
    native, positions = _source(payloads, prediction)
    identity = {"source_sha256": sha(payloads["source"]), "page_sha256": sha(payloads["page"]),
                "image_sha256": sha(payloads["image"]), "native_identity": {"native_sha256": digest_value(native)}}
    failures = validate_failures(observations, prediction, identity, evaluated_at=evaluated_at)
    require(any(item["dimension"] == "notation" for item in failures), "packet_requires_observed_notation_failure")
    sidecar, _ = capture_notation(payloads["source"], native)
    metadata, full_image, _ = render_source(payloads["source"], dpi=144)
    # A bounding rectangle is navigation context, never section ownership.
    matrix = metadata["render"]["pdf_to_pixels"]
    points = []
    for span in prediction["spans"]:
        x0, y0, x1, y1 = span["bbox"]
        a, b, c, d, e, f = matrix
        points.extend((a*x+c*y+e, b*x+d*y+f) for x, y in ((x0,y0),(x1,y0),(x0,y1),(x1,y1)))
    width, height = metadata["render"]["dimensions"]
    crop = [max(0, math.floor(min(x for x,y in points))-16), max(0, math.floor(min(y for x,y in points))-16),
            min(width, math.ceil(max(x for x,y in points))+16), min(height, math.ceil(max(y for x,y in points))+16)]
    _, _, region_image = render_source(payloads["source"], dpi=144, crop=crop)
    selected, context, unresolved = [], [], []
    for glyph in sidecar.get("characters", []):
        ref = glyph["native_ref"]
        if (str(ref["line_id"]), ref["start"]) in positions:
            selected.append(glyph["id"])
            if glyph["uncertainty"] and not glyph["raw"].isspace():
                unresolved.append(glyph["id"])
        else:
            context.append(glyph["id"])
    result = {"version": "notation-full-region-review-packet-v1", "case_id": sid,
              "status": "WAIT_FULL_REGION_SOURCE_REVIEW", "policy": POLICY,
              "source_identity": identity, "original_assessment_sha256": prediction["assessment_sha256"],
              "negative_observations": failures, "negative_observations_sha256": digest_value(failures),
              "candidate_text_is_unrepaired_native": True, "native_candidate_text": prediction["text"],
              "ordered_selected_spans": prediction["spans"], "closing_boundary_is_prior_candidate_evidence": prediction.get("closing_boundary"),
              "page_render": metadata, "navigation_crop": crop, "crop_implies_section_ownership": False,
              "selected_glyph_ids": selected, "outside_selected_extent_glyph_ids": context,
              "unresolved_selected_glyph_ids": unresolved, "notation_sidecar_state": sidecar["status"],
              "notation_sidecar_reason": sidecar.get("reason"),
              "required_reviews": ["entire_original_abstract_and_all_subsections", "every_visible_notation_role_and_mapping",
                  "reading_order_and_all_plain_text", "closure_and_nonabstract_exclusions", "each_correction_against_original_image",
                  "whole_region_fidelity_after_any_fragment_or_image_edit"],
              "review": None, "corrected_transcription": None, "selected_repair_route": None,
              "prior_exposure": scope, "source_before_predictions": False,
              "execution_mode": "SYNTHETIC_AUTHORED" if scope == "authored_fixture" else "EXPOSED_DEVELOPMENT_PREPARATION",
              "independent_human_review_claimed": False, "proposal": False, "graph_admission_enabled": False}
    return {"packet.json": json_bytes(result)+b"\n", "notation.json": json_bytes(sidecar)+b"\n",
            "page.png": full_image, "region.png": region_image}


def build(root, descriptor, *, evaluated_at, runtime_lock=DEFAULT_RUNTIME_LOCK):
    descriptor = deepcopy(descriptor)
    inputs = Inputs(root)
    protocol = inputs.read(deepcopy(descriptor), json_value=True)
    require(type(protocol) is dict and set(protocol) == {"version", "scope", "results", "native_manifest", "reviews", "cases"}
            and protocol["version"] == VERSION and protocol["scope"] in {"previously_examined_development", "authored_fixture"},
            "invalid_packet_cohort_protocol")
    stamp = dt.datetime.fromisoformat(evaluated_at.replace("Z", "+00:00"))
    require(stamp.tzinfo is not None and stamp <= dt.datetime.now(dt.timezone.utc), "packet_evaluation_time_invalid")
    code, runtime = code_identity(), runtime_receipt(runtime_lock)
    results = inputs.read(protocol["results"], json_value=True)
    native_manifest = inputs.read(protocol["native_manifest"], json_value=True)
    reviews = inputs.read(protocol["reviews"], json_value=True)
    require(reviews.get("version") == "promotion-fidelity-review-v1" and type(reviews.get("cases")) is dict,
            "packet_failure_review_supplement_required")
    required = {sid for sid, value in reviews["cases"].items()
                if any(item.get("dimension") == "notation" for item in value.get("candidate_observations", []))}
    require(type(protocol["cases"]) is dict and bool(required) and set(protocol["cases"]) == required,
            "packet_cohort_must_include_every_notation_failure")
    require(results.get("native_manifest_sha256") == protocol["native_manifest"]["sha256"]
            and native_manifest.get("mode") == "fresh"
            and native_manifest.get("experiment_sha256") == results.get("experiment_sha256"), "packet_run_native_manifest_mismatch")
    native_cases = {value["id"]: value for value in native_manifest["cases"]}
    require(len(native_cases) == len(native_manifest["cases"]), "packet_duplicate_native_case")
    outputs = {}
    run_parent = Path(protocol["results"]["relative"]).parent.as_posix()
    for sid, assets in sorted(protocol["cases"].items()):
        require(re.fullmatch(r"f\d{3}", sid) and type(assets) is dict and set(assets) == ASSETS, "packet_case_assets_required")
        relative = f"assessments/{PRIMARY}/{sid}.json"
        require(assets["assessment"]["relative"] == run_parent + "/" + relative
                and assets["assessment"]["sha256"] == results["assessment_files_sha256"].get(relative), "packet_assessment_not_in_frozen_run")
        case = native_cases[sid]
        require(assets["native"]["relative"] == case["native_relative"] and assets["native"]["sha256"] == case["file_sha256"]
                and all(assets[k]["sha256"] == case[k+"_sha256"] for k in ("source", "page", "image")), "packet_case_manifest_identity_mismatch")
        payloads = {key: inputs.read(value) for key, value in assets.items()}
        require(digest_value(parse_bound_json(payloads["native"])) == case["native_sha256"], "packet_native_semantic_hash_mismatch")
        files = _packet(payloads, reviews["cases"][sid]["candidate_observations"], sid, evaluated_at, protocol["scope"])
        outputs.update({sid+"/"+name: raw for name, raw in files.items()})
    inputs.recheck()
    require(code_identity() == code and runtime_receipt(runtime_lock) == runtime, "packet_code_or_runtime_changed")
    summary = {"version": VERSION, "status": "PREPARED_REVIEW_EVIDENCE_NOT_APPLIED", "protocol": descriptor,
               "evaluated_at": evaluated_at, "scope": protocol["scope"], "case_ids": sorted(required), "case_count": len(required),
               "input_sha256": {p.relative_to(root).as_posix(): h for p,h in inputs.hashes.items()},
               "outputs": {name: sha(raw) for name, raw in outputs.items()}, "code": code, "runtime": runtime,
               "prior_run_method_hashes": results.get("execution_identity", {}).get("method_hashes"),
               "current_extraction_run_claimed": False, "resolved_failure_count": 0,
               "production_graph_writes": 0, "model_calls": 0, "new_paid_api_calls": 0, "policy": POLICY}
    return summary, outputs, inputs


def prepare(root, descriptor, output, *, evaluated_at, runtime_lock=DEFAULT_RUNTIME_LOCK):
    summary, outputs, inputs = build(root, descriptor, evaluated_at=evaluated_at, runtime_lock=runtime_lock)
    folder = child(root, output)
    require(not folder.exists(), "packet_output_directory_already_exists")
    def recheck():
        inputs.recheck()
        require(code_identity() == summary["code"] and runtime_receipt(runtime_lock) == summary["runtime"], "packet_code_or_runtime_changed")
    try:
        for name, raw in outputs.items():
            write_bytes_once(child(folder, name), raw)
        recheck()
        require(all(digest(child(folder, name)) == expected for name, expected in summary["outputs"].items()), "packet_output_changed")
        receipt_sha = write_once(folder / "receipt.json", summary)
        recheck()
        require(digest(folder / "receipt.json") == receipt_sha
                and all(digest(child(folder, name)) == expected for name, expected in summary["outputs"].items()), "packet_output_changed")
    except Exception:
        write_once(folder / "INVALIDATED.json", {"status": "BLOCKED", "reason": "packet_publication_integrity_failed"})
        raise
    return {"status": summary["status"], "receipt_sha256": receipt_sha, "case_count": summary["case_count"], "resolved_failure_count": 0}


def verify(root, receipt_descriptor, *, runtime_lock=DEFAULT_RUNTIME_LOCK):
    receipt_descriptor = deepcopy(receipt_descriptor)
    inputs = Inputs(root)
    recorded = inputs.read(receipt_descriptor, json_value=True)
    folder = child(root, receipt_descriptor["relative"]).parent
    require(not (folder / "INVALIDATED.json").exists(), "packet_publication_was_invalidated")
    rebuilt, outputs, sources = build(root, recorded["protocol"], evaluated_at=recorded["evaluated_at"], runtime_lock=runtime_lock)
    require(digest_value(recorded) == digest_value(rebuilt), "packet_receipt_replay_mismatch")
    require(all(child(folder, name).read_bytes() == raw for name, raw in outputs.items()), "packet_output_readback_mismatch")
    sources.recheck(); inputs.recheck()
    require(code_identity() == rebuilt["code"] and runtime_receipt(runtime_lock) == rebuilt["runtime"]
            and not (folder / "INVALIDATED.json").exists(), "packet_final_readback_failed")
    require(all(digest(child(folder, name)) == rebuilt["outputs"][name] for name in outputs), "packet_output_changed")
    inputs.recheck(); sources.recheck()
    return {"status": "VERIFIED_PREPARATION_ONLY", "case_count": rebuilt["case_count"], "resolved_failure_count": 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "verify"))
    parser.add_argument("--data-root", required=True)
    parser.add_argument("--input", required=True)
    parser.add_argument("--input-sha256", required=True)
    parser.add_argument("--output")
    parser.add_argument("--evaluated-at")
    parser.add_argument("--runtime-lock", type=Path, default=DEFAULT_RUNTIME_LOCK)
    args = parser.parse_args()
    try:
        root = data_root(args.data_root)
        descriptor = {"relative": args.input, "sha256": args.input_sha256}
        if args.command == "prepare":
            require(bool(args.output) and bool(args.evaluated_at), "packet_prepare_requires_output_and_time")
            result = prepare(root, descriptor, args.output, evaluated_at=args.evaluated_at, runtime_lock=args.runtime_lock)
        else:
            require(args.output is None and args.evaluated_at is None, "packet_verify_uses_recorded_inputs")
            result = verify(root, descriptor, runtime_lock=args.runtime_lock)
        print(json.dumps(result)); return 0
    except Exception as exc:
        print(json.dumps({"status": "BLOCKED", "reason": "packet_verification_failed", "error_class": type(exc).__name__})); return 2


if __name__ == "__main__":
    raise SystemExit(main())
