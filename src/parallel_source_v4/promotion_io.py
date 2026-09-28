"""Authorized local promotion-receipt audit; no release or graph mutation."""
from __future__ import annotations

import argparse
from copy import deepcopy
import datetime as dt
import hashlib
import json
from pathlib import Path
import re

from trace_gc.pdf_source_parallel_v4 import digest_value, json_bytes, validate_source_spans
from trace_gc.pdf_structure_parallel_v4 import verify_assessment, verify_interior_footnote_exclusion
from . import extraction
from .common import REPO, child, data_root, digest, method_hashes, verify_files, write_once
from .fidelity import compare_notation, evaluate_fidelity, FIDELITY_METRIC_VERSION, LEGACY_METRIC_VERSION
from .fidelity_report import read_bound
from .metrics import score_case
from .promotion import CASE_IDS, CONFIGURATION, METHODS, PRIMARY, VERSION, configuration, evaluate, gate, redacted_cases
from .promotion_review import apply_closure_review
from .promotion_image import apply_image_route, validate_manifest, POLICY as IMAGE_POLICY
from .promotion_observation import validate_failures, apply_failures
from .runtime import DEFAULT_RUNTIME_LOCK, InputGateError, runtime_receipt

_HASH = re.compile(r"[0-9a-f]{64}")
_FROZEN_FOLDERS = {"validation_expanded200", "validation_v2", "validation_200_10k", "sample_comparison_100"}


def _evaluation_time(value: str | None) -> str:
    now = dt.datetime.now(dt.timezone.utc)
    value = value or now.isoformat()
    stamp = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if stamp.tzinfo is None or stamp > now:
        raise ValueError("acceptance_time_requires_timezone_and_cannot_be_future")
    return value


def _review_spans(review: dict, native: list[dict], reference_text: str) -> None:
    """Source-review offsets must also read back; the metric alone compares positions."""
    boundary = review.get("boundary", {})
    if boundary.get("representation") != "native_spans" or boundary.get("status") != "pass":
        return
    lines = {str(line["id"]): line for line in native}
    spans = list(boundary.get("reference_spans", []))
    for excluded in boundary.get("excluded_spans", []):
        spans.extend(excluded.get("spans", []))
    if not spans:
        raise ValueError("reviewed_native_spans_missing")
    for span in spans:
        line = lines.get(str(span.get("line_id")))
        start, end = span.get("start"), span.get("end")
        if (line is None or type(span.get("page_no")) is not int or span["page_no"] != 1 or type(start) is not int or type(end) is not int
                or not 0 <= start < end <= len(line["text"])):
            raise ValueError("reviewed_native_span_out_of_bounds")
        if "text" in span and span["text"] != line["text"][start:end]:
            raise ValueError("reviewed_native_span_readback_mismatch")
    text = "\n".join(lines[str(span["line_id"])]["text"][span["start"]:span["end"]]
                     for span in boundary.get("reference_spans", []))
    if compare_notation(text, reference_text)["status"] != "pass":
        raise ValueError("reviewed_reference_text_differs_from_native_extent")


def _analyze(root: Path, *, run_relative: str, run_sha256: str, configuration_relative: str,
             source_map_relative: str, review_relative: str | None = None,
             review_sha256: str | None = None, evaluated_at: str | None = None,
             image_relative: str | None = None, image_sha256: str | None = None,
             runtime_lock: Path = DEFAULT_RUNTIME_LOCK) -> dict:
    """Rebuild acceptance from source-bound artifacts, never reported PASS fields."""
    evaluated_at = _evaluation_time(evaluated_at)
    code = method_hashes()
    inputs = {}
    def remember(relative, sha):
        if relative in inputs and inputs[relative] != sha:
            raise ValueError("acceptance_input_changed_between_reads")
        inputs[relative] = sha
    def load(relative):
        value, sha = read_bound(child(root, relative))
        remember(relative, sha)
        return value
    def load_asset(relative):
        raw = child(root, relative).read_bytes()
        remember(relative, hashlib.sha256(raw).hexdigest())
        return raw
    config = configuration(load(configuration_relative))
    mapping = load(source_map_relative)
    run = child(root, run_relative)
    if run == root:
        raise ValueError("experiment_subdirectory_required")
    saved_gate = load(run_relative + "/preflight.json")
    results = load(run_relative + "/results.json")
    if not isinstance(run_sha256, str) or not _HASH.fullmatch(run_sha256) or inputs[run_relative + "/results.json"] != run_sha256:
        raise ValueError("externally_pinned_experiment_results_sha256_required")
    image_cases, image_code = {}, None
    if config["image_evidence_policy"] == IMAGE_POLICY:
        from .image_ocr import code_identity
        image_code = code_identity()
        if not image_relative or not isinstance(image_sha256, str) or not _HASH.fullmatch(image_sha256):
            raise ValueError("image_enabled_policy_requires_pinned_all_200_routes")
        manifest = load(image_relative)
        if inputs[image_relative] != image_sha256:
            raise ValueError("image_route_manifest_hash_mismatch")
        image_cases = validate_manifest(manifest, case_ids=CASE_IDS, run_sha256=run_sha256, configuration_sha256=digest_value(config))
    elif image_relative is not None or image_sha256 is not None:
        raise ValueError("native_only_policy_cannot_consume_image_routes")
    protocol = load(run_relative + "/protocol.json")
    native_manifest = load(run_relative + "/native_manifest.json")
    reviews = {}
    if bool(review_relative) != bool(review_sha256):
        raise ValueError("review_path_and_expected_hash_required_together")
    if review_relative:
        if not isinstance(review_sha256, str) or not _HASH.fullmatch(review_sha256):
            raise ValueError("expected_review_sha256_required")
        supplement = load(review_relative)
        if inputs[review_relative] != review_sha256:
            raise ValueError("fidelity_review_hash_mismatch")
        if (not isinstance(supplement, dict) or set(supplement) != {"version", "cases"}
                or supplement["version"] != "promotion-fidelity-review-v1"
                or not isinstance(supplement["cases"], dict) or set(supplement["cases"])-CASE_IDS):
            raise ValueError("invalid_fidelity_review_supplement")
        reviews = supplement["cases"]
    current = extraction.preflight(root, mapping, methods=METHODS, replay_saved=True,
                                   native_mode="fresh", runtime_lock=runtime_lock)
    if current["status"] != "PASS":
        raise InputGateError(current.get("reason", "acceptance_preflight_blocked"))
    if current["method_hashes"] != code or saved_gate != extraction.public_preflight(current):
        raise ValueError("experiment_preflight_identity_is_stale_or_altered")
    for relative, sha in current["input_file_hashes"].items():
        remember(relative, sha)
    identities = ("runtime", "method_hashes", "native_mode", "native_manifest_sha256",
                  "extractor_identity", "native_comparison")
    if (results.get("cohort") != "regression200" or
            results.get("status") not in {"COMPLETE_OFFLINE_ASSESSMENT_NOT_QUALIFICATION",
                "FAILED_REGRESSION_PRESERVATION_GATE", "FAILED_SAVED_REPLAY_GATE"} or
            results.get("automatic_fallback_enabled") is not False or
            results.get("production_graph_writes") != 0 or results.get("new_paid_api_calls") != 0 or
            results.get("experiment_sha256") != digest_value(saved_gate) or
            results.get("execution_identity") != {key: current[key] for key in identities} or
            protocol.get("cohort") != "regression200_already_examined" or protocol.get("method_hashes") != code or
            results.get("native_manifest_sha256") != inputs[run_relative + "/native_manifest.json"]):
        raise ValueError("inconsistent_or_non_regression_experiment_identity")
    frozen_at = dt.datetime.fromisoformat(protocol["frozen_at"].replace("Z", "+00:00"))
    evaluation = dt.datetime.fromisoformat(evaluated_at.replace("Z", "+00:00"))
    if frozen_at.tzinfo is None or frozen_at > evaluation:
        raise ValueError("experiment_occurs_after_acceptance_evaluation")
    if set(results["details"]) != set(METHODS):
        raise ValueError("all_four_experiment_arms_required")
    assessment_files = results.get("assessment_files_sha256", {})
    if set(assessment_files) != {f"assessments/{method}/{sid}.json" for method in METHODS for sid in CASE_IDS}:
        raise ValueError("complete_measured_assessment_output_manifest_required")
    manifest_cases = native_manifest.get("cases", [])
    if (native_manifest.get("mode") != "fresh" or len(manifest_cases) != 200 or
            {x["id"] for x in manifest_cases} != CASE_IDS or
            native_manifest.get("experiment_sha256") != results["experiment_sha256"] or
            native_manifest.get("extractor_identity") != current["extractor_identity"]):
        raise ValueError("invalid_experiment_native_manifest")
    manifest_by_id = {x["id"]: x for x in manifest_cases}
    prior_rows = {}
    for method in METHODS:
        rows = results["details"][method]
        if len(rows) != 200 or {x["id"] for x in rows} != CASE_IDS:
            raise ValueError("experiment_arm_missing_original_cases")
        prior_rows[method] = {row["id"]: row for row in rows}
    details = {name: [] for name in METHODS}
    automatic = {name: [] for name in METHODS}
    derived, closure_audits, closure_errors = {}, {}, []
    observed_failures = {}
    image_audits, image_errors, image_selected = {}, [], []
    baseline, replay, review_readback_errors = [], [], []
    for case in current["cases"]:
        sid, native = case["id"], case["native_lines"]
        relative = run_relative + "/native/" + sid + ".json"
        saved_native = load(relative)
        identity = manifest_by_id[sid]
        expected_native = {**case["native_identity"], "file_sha256": inputs[relative], "native_relative": relative}
        if saved_native != native or identity != expected_native:
            raise ValueError("native_representation_differs_from_current_verified_source")
        reference = current["labels"][sid]
        reviewed_reference = dict(reference)
        if sid in reviews:
            supplement = reviews[sid]
            if (not isinstance(supplement, dict) or not {"status", "text", "fidelity_review"} <= set(supplement)
                    or set(supplement) - {"status", "text", "fidelity_review", "closure_review", "image_reference", "candidate_observations"}
                    or supplement["status"] != reference["status"] or not isinstance(supplement["text"], str)):
                raise ValueError("fidelity_supplement_cannot_change_frozen_scope")
            reviewed_reference.update(supplement)
            try:
                _review_spans(supplement["fidelity_review"], native, supplement["text"])
            except (KeyError, TypeError, ValueError, AttributeError):
                review_readback_errors.append(sid)
        for method in METHODS:
            relative = run_relative + "/assessments/" + method + "/" + sid + ".json"
            prediction = load(relative)
            if inputs[relative] != assessment_files[f"assessments/{method}/{sid}.json"]:
                raise ValueError("assessment_differs_from_pinned_measured_output")
            verify_assessment(prediction)
            if (type(prediction.get("proposal")) is not bool or type(prediction.get("complete_candidate")) is not bool or
                    type(prediction.get("physical_page")) is not int or prediction["physical_page"] != 1 or
                    prediction.get("verified_admission") is not False or prediction.get("eligible_for_jev") is not False or
                    any(prediction.get(key) != case[key] for key in ("source_sha256", "page_sha256"))):
                raise ValueError("assessment_scope_source_or_admission_mismatch")
            if prediction.get("native_sha256") != case["native_identity"]["native_sha256"]:
                if prediction.get("status") not in {"error", "truncated"} or prediction["proposal"] or prediction["spans"]:
                    raise ValueError("assessment_native_identity_missing_or_mismatched")
            validate_source_spans(prediction["spans"], native)
            verify_interior_footnote_exclusion(prediction, native)
            for evidence in [prediction.get("closing_boundary") or {}, *prediction.get("region_ownership", [])]:
                validate_source_spans(evidence.get("source_spans", []), native)
                if evidence.get("marker_span"):
                    validate_source_spans([evidence["marker_span"]], native)
            prior = prior_rows[method][sid]
            reference_flags = {**reference, "math_review_required": bool(reference.get("math_review_required") or sid in extraction.MATH_HOLDS)}
            row = score_case(sid, prediction, reference_flags, evaluated_at=evaluated_at)
            for key in ("gold", "predicted", "proposed", "precision", "recall", "boundary_match", "text_match_98", "boundary_and_98_match"):
                if row[key] != prior[key]:
                    raise ValueError("saved_metrics_do_not_match_sealed_assessment")
            reviewed_reference["math_review_required"] = reference_flags["math_review_required"]
            row["fidelity"] = evaluate_fidelity(prediction, reviewed_reference, evaluated_at=evaluated_at)
            observations = reviews.get(sid, {}).get("candidate_observations") if method == PRIMARY else None
            if observations is not None:
                observations = validate_failures(observations, prediction, case, evaluated_at=evaluated_at)
                row["fidelity"] = apply_failures(row["fidelity"], prediction, observations)
                observed_failures[sid] = [{"dimension": item["dimension"], "status": "fail",
                    "assessment_sha256": item["assessment_sha256"], "observation_sha256": digest_value(item)}
                    for item in observations]
            automatic[method].append(deepcopy(row))
            closure_review = reviews.get(sid, {}).get("closure_review") if method == PRIMARY else None
            if closure_review is not None:
                try:
                    amended, audit = apply_closure_review(prediction, closure_review, native=native,
                        source_identity=case, pdf_bytes=load_asset(mapping[sid]), load_asset=load_asset,
                        fidelity_reference=reviewed_reference, evaluated_at=evaluated_at)
                    derived[sid] = amended
                    closure_audits[sid] = audit
                    row = score_case(sid, amended, reference_flags, evaluated_at=evaluated_at)
                    row["fidelity"] = evaluate_fidelity(amended, reviewed_reference, evaluated_at=evaluated_at)
                except (OSError, RuntimeError, ValueError, KeyError, TypeError, AttributeError):
                    closure_errors.append(sid)
            if method == PRIMARY and image_cases:
                try:
                    # Frozen labels also contain IDs and annotation metadata.
                    # Only scope/text are an unreviewed fallback; neither the
                    # metadata nor a native review certifies image fidelity.
                    image_reference = reviews.get(sid, {}).get("image_reference",
                        {key: reference[key] for key in ("status", "text")})
                    if (not isinstance(image_reference, dict) or image_reference.get("status") != reference["status"]
                            or set(image_reference)-{"status", "text", "fidelity_review", "math_review_required"}):
                        raise ValueError("image_reference_cannot_change_frozen_scope")
                    image_reference = {**image_reference, "math_review_required": reference_flags["math_review_required"]}
                    amended, audit = apply_image_route(prediction, derived.get(sid, prediction), image_cases[sid],
                        source_identity=case,
                        pdf_bytes=load_asset(mapping[sid]) if image_cases[sid].get("route") == "image_review" else None,
                        load_json=load, load_asset=load_asset, fidelity_reference=image_reference, evaluated_at=evaluated_at,
                        native_failure_policy=config.get("native_failure_policy", "disabled"), candidate_failures=observations)
                    image_audits[sid] = audit
                    if amended is not None:
                        derived[sid] = amended
                        image_selected.append(sid)
                        row = score_case(sid, amended, reference_flags, evaluated_at=evaluated_at)
                        row["fidelity"] = evaluate_fidelity(amended, image_reference, evaluated_at=evaluated_at)
                except (OSError, RuntimeError, ValueError, KeyError, TypeError, AttributeError):
                    image_errors.append(sid)
            if observations:
                row["fidelity"] = apply_failures(row["fidelity"], derived.get(sid, prediction), observations)
            details[method].append(row)
        old_prediction = current["baseline_predictions"][sid]
        previous = load("validation_expanded200/assessments/structure_v2/" + sid + ".json")
        replay.append({"id": sid, "same_text": old_prediction.get("text") == previous.get("text"),
            "same_status": old_prediction.get("status") == previous.get("status"),
            "same_proposal": old_prediction.get("eligible_for_jev") == previous.get("eligible_for_jev"),
            "same_assessment_digest": old_prediction.get("assessment_sha256") == previous.get("assessment_sha256")})
        baseline.append(score_case(sid, {**old_prediction, "proposal": old_prediction.get("eligible_for_jev", False),
                                        "eligible_for_jev": False}, reference, evaluated_at=evaluated_at))
    result = evaluate(details, baseline, replay, provenance_verified=True)
    automated_result = evaluate(automatic, baseline, replay, provenance_verified=True)
    result.update(automatic_assessment={"status": automated_result["status"], "gates": automated_result["gates"],
                  "arms": automated_result["arms"], "cases": redacted_cases(automatic)},
                  manual_closure={"applied_ids": sorted(closure_audits), "blocked_ids": sorted(closure_errors),
                                  "count": len(closure_audits), "evidence": closure_audits,
                                  "claim": "attributed development review; never independent qualification"},
                  image_review={"enabled": bool(image_cases), "applied_ids": image_selected,
                                "count": len(image_selected), "blocked_ids": image_errors, "cases": image_audits,
                                "corrected_transcription_count": sum(x.get("corrected_transcription") is True for x in image_audits.values()),
                                "held_ids": [sid for sid, audit in image_audits.items() if audit["status"] == "HELD"],
                                "claim": "attributed image proposals; no automatic OCR or graph admission"},
                  candidate_failure_observations=observed_failures,
                  derived_assessments=derived,
                  derived_assessment_files_sha256={"reviewed-assessments/" + sid + ".json":
                      hashlib.sha256(json_bytes(value)+b"\n").hexdigest() for sid, value in sorted(derived.items())})
    if review_readback_errors:
        result["gates"]["review_source_readback"] = gate("BLOCKED", "review_spans_require_native_readback", case_ids=review_readback_errors)
        from .promotion import aggregate_status
        result["status"] = aggregate_status(result["gates"])
        result["eligible_for_reviewed_selector_release"] = False
    if closure_errors:
        from .promotion import aggregate_status
        result["gates"]["manual_closure_readback"] = gate("BLOCKED", "manual_closure_evidence_invalid_or_unresolved", case_ids=closure_errors)
        result["status"] = aggregate_status(result["gates"])
        result["eligible_for_reviewed_selector_release"] = False
    if image_cases:
        from .promotion import aggregate_status
        result["gates"]["image_route"] = gate("PASS" if image_selected and not image_errors else "BLOCKED",
            "fresh_exact_tree_image_exercise_and_all_200_routes_required", accepted_ids=image_selected,
            blocked_ids=image_errors, route_count=len(image_audits))
        result["status"] = aggregate_status(result["gates"])
        result["eligible_for_reviewed_selector_release"] = result["status"] == "PASS"
    extraction.verify_preflight_inputs(root, current, runtime_lock)
    verify_files(root, inputs)
    if method_hashes() != code:
        raise ValueError("acceptance_code_changed_during_audit")
    if image_code is not None and code_identity() != image_code:
        raise ValueError("acceptance_image_code_changed_during_audit")
    result.update(configuration=config, configuration_sha256=digest_value(config), evaluated_at=evaluated_at,
        method_hashes=code, runtime=current["runtime"], input_file_hashes=inputs,
        input_manifest_sha256=digest_value(inputs), verified_input_count=len(inputs),
        legacy_metric_version=LEGACY_METRIC_VERSION, fidelity_metric_version=FIDELITY_METRIC_VERSION,
        cases=redacted_cases(details), review_supplement_sha256=review_sha256,
        image_manifest_sha256=image_sha256, image_code_sha256=image_code,
        invocation={"run_relative": run_relative, "run_sha256": run_sha256, "configuration_relative": configuration_relative,
                    "source_map_relative": source_map_relative, "review_relative": review_relative,
                    "review_sha256": review_sha256, "image_relative": image_relative, "image_sha256": image_sha256},
        postrun_source_code_runtime_recheck="PASS", independent_qualification=False)
    return result


def analyze(root: Path, **kwargs) -> dict:
    try:
        return _analyze(root, **kwargs)
    except (InputGateError, OSError, RuntimeError, ValueError, KeyError, TypeError, AttributeError) as exc:
        code = exc.code if isinstance(exc, InputGateError) else str(exc) if type(exc) is ValueError and re.fullmatch(r"[a-z0-9_]+", str(exc)) else "acceptance_input_or_identity_invalid"
        return {"version": VERSION, "status": "BLOCKED", "reason": code,
                "gates": {"provenance": gate("BLOCKED", code)},
                "eligible_for_reviewed_selector_release": False,
                "automatic_fallback_enabled": False, "graph_admission_enabled": False,
                "new_paid_api_calls": 0, "production_graph_writes": 0}


def publish(root: Path, output_relative: str, result: dict, *, runtime_lock: Path = DEFAULT_RUNTIME_LOCK) -> dict:
    output = child(root, output_relative)
    if output == root or output.exists() or output.relative_to(root).parts[0] in _FROZEN_FOLDERS:
        raise ValueError("new_acceptance_output_directory_required")
    invocation = result.get("invocation", {})
    if invocation.get("run_relative"):
        run = child(root, invocation["run_relative"])
        if output == run or run in output.parents or output in run.parents:
            raise ValueError("acceptance_output_must_not_overlap_experiment")
    # Analysis and publication are distinct operations. Recheck their shared
    # identity immediately before writing; release verification repeats it later.
    if "method_hashes" in result:
        verify_files(root, result["input_file_hashes"])
        if method_hashes() != result["method_hashes"] or runtime_receipt(runtime_lock) != result["runtime"]:
            raise ValueError("acceptance_identity_changed_before_publication")
        if result.get("image_code_sha256") is not None:
            from .image_ocr import code_identity
            if code_identity() != result["image_code_sha256"]:
                raise ValueError("acceptance_image_identity_changed_before_publication")
    for sid, value in result.get("derived_assessments", {}).items():
        relative = "reviewed-assessments/" + sid + ".json"
        actual = write_once(child(root, output_relative + "/" + relative), value)
        if actual != result["derived_assessment_files_sha256"][relative]:
            raise ValueError("derived_assessment_publication_hash_mismatch")
    private_hash = write_once(child(root, output_relative + "/acceptance.json"), result)
    public = {key: value for key, value in result.items() if key not in {"input_file_hashes", "invocation", "derived_assessments"}}
    public["private_acceptance_sha256"] = private_hash
    write_once(child(root, output_relative + "/public-receipt.json"), public)
    return public


def verify(root: Path, receipt_relative: str, expected_sha256: str, *,
           configuration_relative: str, source_map_relative: str,
           runtime_lock: Path = DEFAULT_RUNTIME_LOCK) -> dict:
    """Expected hash comes from a trusted release record, never from the receipt."""
    if not isinstance(expected_sha256, str) or not _HASH.fullmatch(expected_sha256):
        raise ValueError("externally_pinned_acceptance_sha256_required")
    receipt, actual = read_bound(child(root, receipt_relative))
    if actual != expected_sha256 or receipt.get("version") != VERSION or receipt.get("status") != "PASS":
        raise ValueError("missing_altered_or_nonpassing_promotion_receipt")
    directory = child(root, receipt_relative).parent
    derived = receipt.get("derived_assessments", {})
    expected_outputs = receipt.get("derived_assessment_files_sha256", {})
    if set(expected_outputs) != {"reviewed-assessments/" + sid + ".json" for sid in derived} or set(derived)-CASE_IDS:
        raise ValueError("invalid_derived_assessment_output_manifest")
    for sid, expected in derived.items():
        relative = "reviewed-assessments/" + sid + ".json"
        value, sha = read_bound(child(directory, relative))
        if sha != expected_outputs[relative] or value != expected:
            raise ValueError("derived_assessment_changed_after_publication")
        verify_assessment(value)
    arguments = dict(receipt["invocation"])
    arguments.update(configuration_relative=configuration_relative, source_map_relative=source_map_relative,
                     evaluated_at=receipt["evaluated_at"], runtime_lock=runtime_lock)
    current = analyze(root, **arguments)
    if current != receipt or current.get("eligible_for_reviewed_selector_release") is not True:
        raise ValueError("stale_configuration_or_quality_receipt")
    if digest(child(root, receipt_relative)) != expected_sha256:
        raise ValueError("acceptance_receipt_changed_during_verification")
    verify_files(directory, expected_outputs)
    return {"status": "PASS", "acceptance_sha256": expected_sha256,
            "configuration_sha256": current["configuration_sha256"],
            "automatic_fallback_enabled": False, "graph_admission_enabled": False,
            "release_selection_performed": False, "production_graph_writes": 0}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=("assess", "verify", "rollback-plan"))
    parser.add_argument("--data-root", required=True)
    parser.add_argument("--configuration", required=True)
    parser.add_argument("--source-map", required=True)
    parser.add_argument("--runtime-lock", type=Path, default=DEFAULT_RUNTIME_LOCK)
    parser.add_argument("--run"); parser.add_argument("--run-sha256"); parser.add_argument("--output")
    parser.add_argument("--review"); parser.add_argument("--review-sha256")
    parser.add_argument("--image-manifest"); parser.add_argument("--image-manifest-sha256")
    parser.add_argument("--receipt"); parser.add_argument("--receipt-sha256")
    args = parser.parse_args()
    if args.stage == "assess" and (not args.run or not args.run_sha256 or not args.output):
        parser.error("assess requires --run, --run-sha256 and --output")
    if args.stage != "assess" and (not args.receipt or not args.receipt_sha256):
        parser.error("verification requires --receipt and --receipt-sha256")
    try:
        root = data_root(args.data_root)
        common = dict(configuration_relative=args.configuration, source_map_relative=args.source_map,
                      runtime_lock=args.runtime_lock)
        if args.stage == "assess":
            result = publish(root, args.output, analyze(root, run_relative=args.run, run_sha256=args.run_sha256,
                review_relative=args.review, review_sha256=args.review_sha256,
                image_relative=args.image_manifest, image_sha256=args.image_manifest_sha256,
                **common), runtime_lock=args.runtime_lock)
        else:
            result = verify(root, args.receipt, args.receipt_sha256, **common)
            if args.stage == "rollback-plan":
                result.update(action="operator_may_restore_verified_previous_configuration",
                    disable_current_candidate_first=True, activate_automatically=False,
                    requires_operator_review=True)
        print(json.dumps({key: result[key] for key in ("status", "reason", "private_acceptance_sha256", "acceptance_sha256", "action") if key in result}))
        return 0 if result["status"] == "PASS" else 1 if result["status"] == "FAIL" else 2
    except (OSError, RuntimeError, ValueError, KeyError, TypeError, AttributeError) as exc:
        print(json.dumps({"status": "BLOCKED", "reason": "promotion_verification_or_publication_failed", "error_class": type(exc).__name__}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
