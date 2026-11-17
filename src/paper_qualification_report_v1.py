"""Allowlisted aggregate reporting and source-free run readiness checks."""
from __future__ import annotations

import argparse
import importlib.util
import json
import math
from pathlib import Path
import re

from src.paper_qualification_v1 import (Artifacts, EvidenceError, METHODS, PHASES, QUOTAS,
    REQUIRED_PREREGISTRATION_DOCUMENTS, REVIEW_POLICY, VERSION as EVALUATION_VERSION,
    evaluator_identity, exact, read_preregistration,
    read_study_bundle, require, summarize, verify_published)
from src.parallel_source_v4.common import child, data_root as authorized_root, write_once
from src.parallel_source_v4.runtime import DEFAULT_RUNTIME_LOCK, runtime_receipt
from trace_gc.cli import read_trust
from trace_gc.pdf_source_parallel_v4 import digest_value

VERSION = "paper-qualification-aggregate-report-v1"
STAGES = ("converters", "ocr", "source_review", "adjudication", "candidate_review", "evaluation")
CLAIM = ("Redacted aggregate only; internally attributed source-first review, no independent human validation; "
    "first-page abstract scope only, not validation of later-page ingestion, graph publication or generated answers; "
    "synthetic or authored inputs are not empirical evidence.")
SCOPE = "first_page_abstract_extraction_only"
REDACTED_REASON = "unrecognized_reason_redacted"
REASONS = {REDACTED_REASON, "missing_or_invalid_bound_study_evidence",
    "external_review_trust_required", "artifact_bytes_changed",
    "regression_prerequisite_changed_during_qualification", "code_or_runtime_changed_during_evaluation",
    "execution_descriptor_required", "execution_not_bound_to_evaluation", "report_output_exists",
    "publication_invalidated_or_not_evaluation", "publication_completion_required"}
SHA = re.compile(r"[0-9a-f]{64}")
STATUSES = {"PASS", "FAIL", "BLOCKED", "AUTHORED_CONTRACT_PASS_NOT_QUALIFICATION"}
SELECTIONS = {"automatic_primary_before_review", "diagnostic_only"}
REFERENCES = {"complete", "partial_on_page_one", "no_abstract_text", "uncertain"}
ROUTES = {"native_or_hold", "image_review"}
COUNTS = tuple("n accepted strict_correct false_accepts resolved_complete unresolved accepted_unresolved conservative_recall_denominator".split())
RATES = tuple("coverage precision_lower_97_5 recall_lower_97_5 conservative_recall optimistic_recall".split())
INTERVALS = ("precision_interval_95", "recall_interval_95")
TIMINGS = ("elapsed_seconds", "cpu_seconds", "review_active_seconds")
STAGE_COUNTS = ("calls", "failures", "retries", "review_count")
IMAGES = ("image_proposals", "corrected_image_proposals", "raw_image_matches_final")
SUMMARY_KEYS = set(summarize([]))
FIELDS = set(COUNTS + RATES + INTERVALS + TIMINGS + STAGE_COUNTS + IMAGES) | set("""
version source_evaluation_version status reason_code qualification_pass independent_human_qualification
claim scope review_policy overall strata checks missing_representation measured_arms selection primary
challenge image_counts sample_counts screened_exposure_count all_sampled_case_count primary_n
challenge_case_count reference_status_counts route_counts costs paid_calls paid_spend_usd graph_writes
stages stage failure_totals execution_bound rejected_partial_or_absent_accepts_count source_evaluation_sha256
""".split())
CHECKS = {"minimum_accepted", "minimum_resolved_complete", "zero_false_accepts", "strict_precision",
    "strict_complete_recall", "reference_resolution"} | {f"challenge_{name}_{kind}" for name in QUOTAS
    for kind in ("safety", "utility", "actual_image_route")}
VOCABULARY = CHECKS | FIELDS | set(STAGES) | set(QUOTAS) | {k+":complete" for k in QUOTAS} | set(METHODS) | STATUSES | SELECTIONS | REFERENCES | ROUTES | {REVIEW_POLICY, VERSION, EVALUATION_VERSION, CLAIM, SCOPE, "unrecognized_reason_redacted"}


def integer(value):
    require(type(value) is int and value >= 0, "nonnegative_integer_required")
    return value


def number(value, *, rate=False):
    require(value is None or type(value) in (int, float) and math.isfinite(value)
        and value >= 0 and (not rate or value <= 1), "invalid_report_number")
    return value


def _redacted_summary(summary):
    exact(summary, SUMMARY_KEYS, "summary_contract_required")
    result = {key: integer(summary[key]) for key in COUNTS}
    result.update({key: number(summary[key], rate=True) for key in RATES})
    for key in INTERVALS:
        value = summary[key]
        require(type(value) is list and len(value) == 2, "summary_interval_required")
        result[key] = [number(v, rate=True) for v in value]
    require(type(summary["optimistic_recall_assumption"]) is str, "summary_assumption_required")
    rejected = summary["rejected_partial_or_absent_accepts"]
    require(type(rejected) is list and all(type(v) is str for v in rejected), "summary_rejected_list_required")
    result["rejected_partial_or_absent_accepts_count"] = len(rejected)
    return result


def aggregate_metrics(primary_rows, challenge_rows, strata):
    exact(strata, QUOTAS, "fixed_challenge_strata_required")
    overall = _redacted_summary(summarize(primary_rows))
    summarize(challenge_rows)
    by_id = {row["work_id"]: row for row in challenge_rows}
    require(not {r["work_id"] for r in primary_rows} & set(by_id), "challenge_primary_overlap")
    reports = {}
    for name, ids in strata.items():
        require(type(ids) is list and all(type(v) is str for v in ids)
            and len(ids) == len(set(ids)) and set(ids) <= set(by_id), "invalid_challenge_membership")
        reports[name] = _redacted_summary(summarize([by_id[sid] for sid in ids]))
    return {"overall": overall, "strata": reports}


def summaries(values):
    exact(values, QUOTAS, "fixed_challenge_strata_required")
    return {name: _redacted_summary(values[name]) for name in QUOTAS}


def reason_code(value):
    return value if type(value) is str and value in REASONS else REDACTED_REASON


def build_report(evaluation, *, execution=None):
    require(isinstance(evaluation, dict), "evaluation_required")
    e = evaluation
    status = e.get("status")
    require(e.get("version") == EVALUATION_VERSION and status in STATUSES
        and e.get("independent_human_qualification") is False
        and type(e.get("graph_writes")) is int and e["graph_writes"] == 0
        and type(e.get("paid_calls")) is int and e["paid_calls"] == 0
        and e.get("qualification_pass") is (status == "PASS"), "evaluation_contract_required")
    result = {"version": VERSION, "source_evaluation_version": EVALUATION_VERSION,
        "status": status, "qualification_pass": status == "PASS",
        "independent_human_qualification": False, "claim": CLAIM, "scope": SCOPE}
    if status == "BLOCKED" and "primary" not in e:
        result["reason_code"] = reason_code(e.get("reason"))
        assert_redacted(result)
        return result
    require(e.get("review_policy") == REVIEW_POLICY, "review_policy_required")
    result.update(review_policy=REVIEW_POLICY, overall=_redacted_summary(e["primary"]),
        strata=summaries(e["challenge"]))
    require(isinstance(e["checks"], dict) and all(k in CHECKS and type(v) is bool for k, v in e["checks"].items()), "invalid_report_checks")
    result["checks"] = {k: v for k, v in e["checks"].items()}
    missing = e["missing_representation"]
    require(type(missing) is list and all(type(v) is str and v in set(QUOTAS) | {k+":complete" for k in QUOTAS}
        for v in missing), "invalid_missing_representation")
    result["missing_representation"] = [v for v in missing]
    exact(e["measured_arms"], METHODS, "measured_arms_required")
    result["measured_arms"] = {}
    for method in METHODS:
        arm = e["measured_arms"][method]
        require(arm["selection"] in SELECTIONS, "invalid_arm_selection")
        result["measured_arms"][method] = {"selection": arm["selection"],
            "primary": _redacted_summary(arm["primary"]), "challenge": summaries(arm["challenge"])}
    exact(e["image_counts"], IMAGES, "image_counts_required")
    result["image_counts"] = {k: integer(e["image_counts"][k]) for k in IMAGES}
    total = integer(e["all_sampled_case_count"])
    primary_n = result["overall"]["n"]
    result["sample_counts"] = {"screened_exposure_count": integer(e["screened_exposure_count"]),
        "all_sampled_case_count": total, "primary_n": primary_n, "challenge_case_count": integer(total-primary_n)}
    require(isinstance(e["cases"], dict) and len(e["cases"]) == total, "case_count_mismatch")
    for field, allowed, output in (("reference_status", REFERENCES, "reference_status_counts"),
            ("route", ROUTES, "route_counts")):
        counts = {k: 0 for k in sorted(allowed)}
        for row in e["cases"].values():
            require(row.get(field) in allowed, "invalid_case_category")
            counts[row[field]] += 1
        result[output] = counts
    result.update(costs=None, stages=None, failure_totals=None, execution_bound=execution is not None)
    if execution is not None:
        require(execution.get("version") == "paper-four-arm-execution-v1", "execution_version_required")
        costs = execution["costs"]
        result["costs"] = {"paid_calls": integer(costs["paid_calls"]),
            "graph_writes": integer(costs["graph_writes"]), "paid_spend_usd": number(costs["paid_spend_usd"])}
        require(all(v == 0 for v in result["costs"].values()), "unauthorized_paid_or_graph_execution")
        stages = execution["stage_reports"]
        require(type(stages) is list and len(stages) == len(STAGES), "all_stage_reports_required")
        result["stages"] = []
        for row in stages:
            exact(row, {"stage", *TIMINGS, *STAGE_COUNTS}, "stage_contract_required")
            require(row["stage"] in STAGES, "unknown_stage")
            result["stages"].append({"stage": row["stage"],
                **{k: number(row[k]) for k in TIMINGS}, **{k: integer(row[k]) for k in STAGE_COUNTS}})
        require({r["stage"] for r in result["stages"]} == set(STAGES), "all_stage_reports_required")
        result["stages"].sort(key=lambda row: row["stage"])
        result["failure_totals"] = {k: sum(r[k] for r in result["stages"]) for k in ("failures", "retries")}
    assert_redacted(result)
    return result


def assert_redacted(report):
    def walk(value, path=()):
        valid = True
        if isinstance(value, dict):
            for key, item in value.items():
                require(type(key) is str and key in VOCABULARY, "report_redaction_violation")
                walk(item, (*path, key))
        elif isinstance(value, list):
            for item in value:
                walk(item, path)
        elif type(value) is str:
            valid = (bool(SHA.fullmatch(value)) if path == ("source_evaluation_sha256",) else
                value in REASONS if path == ("reason_code",) else value in VOCABULARY)
        elif type(value) is float:
            valid = math.isfinite(value)
        else:
            valid = value is None or type(value) in (int, bool)
        require(valid, "report_redaction_violation")
    walk(report)


def write_report(data_root, output_relative, evaluation_descriptor, *, execution_descriptor=None,
                 expected_preregistration_sha256=None, trust=None, runtime_lock=DEFAULT_RUNTIME_LOCK):
    root = authorized_root(data_root)
    output = child(root, output_relative)
    require(not output.exists(), "report_output_exists")
    store = Artifacts(root)
    evaluation = store.json(evaluation_descriptor)
    folder = child(root, evaluation_descriptor["relative"]).parent
    require(Path(evaluation_descriptor["relative"]).name == "evaluation.json",
            "publication_invalidated_or_not_evaluation")
    verify_published(root, evaluation_descriptor, expected_preregistration_sha256=expected_preregistration_sha256,
        trust=trust, runtime_lock=runtime_lock, qualification_only=False)
    execution = None
    if "input_hashes" in evaluation:
        bundle = read_study_bundle(store, evaluation["invocation"]["bundle_descriptor"])
        bound = bundle["execution"]
        require((execution_descriptor is None or execution_descriptor == bound)
            and evaluation["input_hashes"].get(bound["relative"]) == bound["sha256"],
            "execution_not_bound_to_evaluation")
        execution = store.json(bound)
    else:
        require(execution_descriptor is None, "execution_not_bound_to_evaluation")
    report = build_report(evaluation, execution=execution)
    report["source_evaluation_sha256"] = evaluation_descriptor["sha256"]
    assert_redacted(report)
    store.recheck()
    require(not (folder/"publication-invalidated.json").exists(), "publication_invalidated_or_not_evaluation")
    return {"relative": output_relative, "sha256": write_once(output, report)}


def _validate_preregistration_descriptors(root, pointer_relative, pointer):
    directory = child(root, Path(pointer_relative).parent.as_posix())

    def validate(relative, sha256):
        require(isinstance(relative, str) and relative and isinstance(sha256, str) and SHA.fullmatch(sha256),
                "artifact_descriptor_required")
        require(child(directory, relative) != directory, "artifact_descriptor_required")

    documents = pointer.get("base_protocol_and_additive_amendments")
    require(isinstance(documents, dict) and REQUIRED_PREREGISTRATION_DOCUMENTS <= documents.keys(),
            "base_protocol_and_both_frame_amendments_required")
    for relative, sha256 in documents.items():
        validate(relative, sha256)
    frames = pointer.get("frames")
    exact(frames, {"recent", "historical"}, "frozen_preregistration_pointer_required")
    for frame in frames.values():
        require(isinstance(frame, dict), "artifact_descriptor_required")
        validate(frame.get("identity_projection_relative"), frame.get("sha256"))


def _fresh_output_path(root, relative):
    output = child(root, relative)
    if output == root or output.exists():
        return False
    for parent in output.parents:
        if parent.exists():
            return parent.is_dir()
    return False


def preflight(args):
    checks, identity = {}, None
    def check(name, action):
        try:
            checks[name] = action() is not False
        except Exception:
            checks[name] = False
    check("data_root", lambda: authorized_root(args.data_root))
    store, bundle = None, None
    def json_path(relative):
        return child(store.root, relative).suffix.lower() == ".json"
    def load_bundle():
        nonlocal store, bundle
        store = Artifacts(authorized_root(args.data_root))
        require(json_path(args.bundle), "study_bundle_contract_required")
        candidate = read_study_bundle(store, {"relative": args.bundle, "sha256": args.bundle_sha256})
        require(set(candidate["roles"]) == {"custodian", "source_reviewer", "adjudicator",
            "candidate_reviewer", "operator"} and len(candidate["phases"]) == len(PHASES),
            "study_bundle_contract_required")
        bundle = candidate
    def load_preregistration():
        if bundle is None:
            return False
        require(json_path(bundle["preregistration"]["relative"]), "frozen_preregistration_pointer_required")
        pointer = read_preregistration(store, bundle, args.preregistration_sha256)
        _validate_preregistration_descriptors(store.root, bundle["preregistration"]["relative"], pointer)
        store.recheck()
    check("bundle", load_bundle)
    check("preregistration", load_preregistration)
    check("output_available", lambda: _fresh_output_path(authorized_root(args.data_root), args.output))
    for name in ("fitz", "PIL"):
        check(name, lambda name=name: importlib.util.find_spec(name) is not None)
    def identify():
        nonlocal identity
        identity = digest_value(evaluator_identity())
    check("evaluator_identity", identify)
    check("runtime_receipt", lambda: runtime_receipt(Path(args.runtime_lock) if args.runtime_lock else DEFAULT_RUNTIME_LOCK))
    return {"status": "READY" if all(checks.values()) else "NOT_READY", "checks": checks,
        "evaluator_code_sha256": identity}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("report", "preflight"):
        command = commands.add_parser(name)
        command.add_argument("--data-root", required=True)
        command.add_argument("--output", required=True)
        if name == "report":
            for flag in ("evaluation", "evaluation-sha256", "execution", "execution-sha256"):
                command.add_argument("--"+flag, required=flag.startswith("evaluation"))
            command.add_argument("--preregistration-sha256")
            command.add_argument("--trust", type=Path, help="application-owned public issuer configuration")
        else:
            for flag in ("bundle", "bundle-sha256", "preregistration-sha256"):
                command.add_argument("--"+flag, required=True)
        command.add_argument("--runtime-lock", help="defaults to the evaluator's DEFAULT_RUNTIME_LOCK")
    args = parser.parse_args(argv)
    try:
        if args.command == "preflight":
            result = preflight(args)
            code = 0 if result["status"] == "READY" else 2
        else:
            require(bool(args.execution) == bool(args.execution_sha256), "execution_descriptor_required")
            execution = {"relative": args.execution, "sha256": args.execution_sha256} if args.execution else None
            written = write_report(args.data_root, args.output,
                {"relative": args.evaluation, "sha256": args.evaluation_sha256}, execution_descriptor=execution,
                expected_preregistration_sha256=args.preregistration_sha256,
                trust=read_trust(args.trust) if args.trust else None,
                runtime_lock=Path(args.runtime_lock) if args.runtime_lock else DEFAULT_RUNTIME_LOCK)
            result = {"sha256": written["sha256"]}
            code = 0
    except (ValueError, OSError, KeyError, TypeError, AttributeError, OverflowError) as error:
        result = {"status": "BLOCKED", "reason_code": reason_code(str(error)) if isinstance(error, EvidenceError)
            else "missing_or_invalid_input"}
        code = 2
    print(json.dumps(result, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
