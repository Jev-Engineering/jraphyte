"""Frozen paper-study evaluation; no graph qualification, source download or inference.

The statistical unit is a work in the bounded preregistered frame. Signed phase
records attest the custodian's chronology; signatures do not establish human
independence, truthful observation, or statistical representativeness.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import re

from trace_gc.canonical import digest
from trace_gc.errors import ContractError
from trace_gc.pdf_source_parallel_v4 import digest_value, validate_source_spans
from trace_gc.pdf_structure_parallel_v4 import verify_assessment
from trace_gc.qualification import upper_error_bound
from trace_gc.trust import TrustStore
from src.parallel_source_v4.common import child, method_hashes, write_once
from src.parallel_source_v4.fidelity import evaluate_fidelity, compare_notation
from src.parallel_source_v4.promotion import configuration, METHODS, PRIMARY
from src.parallel_source_v4.promotion_io import verify as verify_regression, _review_spans
from src.parallel_source_v4.runtime import DEFAULT_RUNTIME_LOCK, runtime_receipt
from src.parallel_source_v4.extraction import predict

VERSION = "paper-qualification-evaluation-v1"
REVIEW_POLICY = "internal-attributed-blinded-source-first-v1"
SEED = "jraphyte-issue20-20260928-protocol-v1"
QUOTAS = {"partial": 20, "absent": 20, "structured": 20, "multiple_columns": 20,
          "title_page": 20, "notation": 40, "image_only": 20, "broken_mapping": 20}
TARGETS = {"accepted_applicable_fidelity_dimensions_observed_pass": 1.0,
    "accepted_unresolved_reference_policy": "Precision failure; never certified success",
    "alpha_per_primary_one_sided_exact_bound": .025,
    "challenge_complete_recall_point_min": .8, "challenge_recall_min_complete_denominator": 10,
    "max_unresolved_primary": 20, "minimum_accepted": 200, "minimum_resolved_complete": 200,
    "strict_complete_recall_lower": .8, "strict_precision_lower": .98,
    "unresolved_recall_policy": "Include every unresolved case in denominator as missed complete opportunity",
    "zero_observed_false_accepts": True}
SAMPLING = {"broken_mapping_complete_min_n": 10, "challenge_pooled_into_primary": False,
    "challenge_quotas": QUOTAS, "challenge_union_max_n": 180, "historical_screen_n": 600,
    "image_only_complete_min_n": 10, "prediction_dependent_selection_allowed": False,
    "primary_n": 400,
    "rank_algorithm": "sha256(UTF8(seed + NUL + role + NUL + normalized_work_id)); lexical work tie-break",
    "recent_screen_n": 600}
REFERENCE_REVIEW = {"candidate_review_separate_from_reference_context": True,
    "external_independent_human_claim": False, "fixed_reference_audit_fraction": .1,
    "kind": "internal_assistant", "reviewer_identities": None,
    "source_before_prediction": True, "unresolved_and_disagreements_preserved": True}
PHASES = ("configuration_frozen", "cohort_frozen", "references_frozen", "predictions_frozen")
CLARIFICATION = {"version": "paper-evaluator-preselection-clarification-v1",
    "normalized_rank_identity": "lowercase_versionless_arxiv_colon_work_id",
    "normalization_collisions": "one_work_never_multiple_sample_units",
    "audit_pool": "resolved_references_excluding_mandatory_uncertainty_or_image_adjudication",
    "audit_rounding": "ceil_pool_size_times_0.1", "audit_rank_role": "reference-audit",
    "seed_frames_denominators_thresholds_exposure_exclusions_unchanged": True}
SHA = re.compile(r"[0-9a-f]{64}")
RESOLVED = {"complete", "partial_on_page_one", "no_abstract_text"}
DIMENSIONS = ("notation", "boundary", "reading_order", "source_location")
CACHE_OUTPUTS = {"parallel_structure_v4": {"docling", "docling_document"},
    "parallel_grobid_v4": {"grobid"}, "parallel_mineru_v4": {"mineru"}, "parallel_olmocr_v4": {"olmocr"}}
CACHE_NAMES = set().union(*CACHE_OUTPUTS.values())


class EvidenceError(ValueError):
    """Missing, inconsistent or invalid evidence, never a statistical failure."""


def require(condition, reason):
    if not condition:
        raise EvidenceError(reason)


def instant(value):
    require(isinstance(value, str), "timezone_aware_timestamp_required")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise EvidenceError("timezone_aware_timestamp_required") from None
    require(result.tzinfo is not None, "timezone_aware_timestamp_required")
    return result


def exact(value, fields, reason):
    require(isinstance(value, dict) and set(value) == set(fields), reason)


def work_id(value):
    require(isinstance(value, str) and re.fullmatch(
        r"arxiv:(?:\d{4}\.\d{4,5}|[a-z][a-z.-]+/\d{7})", value) is not None,
        "normalized_versionless_arxiv_work_id_required")
    return value


def normalize_work_id(value):
    require(isinstance(value, str), "arxiv_work_identity_required")
    return work_id(re.sub(r"v[1-9][0-9]*$", "", value.strip().lower()))


def rank(values, role):
    require(len(values) == len(set(values)), "duplicate_work_identity")
    for value in values:
        work_id(value)
    return sorted(values, key=lambda value: (hashlib.sha256(
        (SEED+"\0"+role+"\0"+value).encode("utf8")).hexdigest(), value))


def lower_bound(success, total, alpha=.025):
    require(type(success) is int and type(total) is int and 0 <= success <= total,
            "invalid_binomial_counts")
    if not total:
        return None
    return 1.0-upper_error_bound(total-success, total, 1.0-alpha)


def interval(success, total):
    if not total:
        return [None, None]
    return [lower_bound(success, total), upper_error_bound(success, total, .975)]


def summarize(rows):
    """Rows are derived from bound assessments and reviews, never input scores."""
    require(isinstance(rows, list) and len({r["work_id"] for r in rows}) == len(rows),
            "unique_case_rows_required")
    for row in rows:
        require(row["reference_status"] in RESOLVED | {"uncertain"}, "unknown_reference_scope")
        require(type(row["accepted"]) is bool and type(row["strict_correct"]) is bool,
                "boolean_decisions_required")
        require(not row["strict_correct"] or row["accepted"] and row["reference_status"] == "complete",
                "strict_correct_requires_accepted_complete")
    accepted = sum(r["accepted"] for r in rows)
    correct = sum(r["strict_correct"] for r in rows)
    complete = sum(r["reference_status"] == "complete" for r in rows)
    unresolved = sum(r["reference_status"] == "uncertain" for r in rows)
    accepted_unresolved = sum(r["accepted"] and r["reference_status"] == "uncertain" for r in rows)
    denominator = complete+unresolved
    return {"n": len(rows), "accepted": accepted, "strict_correct": correct,
        "false_accepts": accepted-correct, "resolved_complete": complete, "unresolved": unresolved,
        "accepted_unresolved": accepted_unresolved, "conservative_recall_denominator": denominator,
        "coverage": accepted/len(rows) if rows else None,
        "precision_lower_97_5": lower_bound(correct, accepted),
        "recall_lower_97_5": lower_bound(correct, denominator),
        "precision_interval_95": interval(correct, accepted),
        "recall_interval_95": interval(correct, denominator),
        "conservative_recall": correct/denominator if denominator else None,
        "optimistic_recall": (correct+accepted_unresolved)/(complete+accepted_unresolved)
            if complete+accepted_unresolved else None,
        "optimistic_recall_assumption": "Unresolved accepts are correct complete references; unresolved holds are not complete.",
        "rejected_partial_or_absent_accepts": [r["work_id"] for r in rows
            if r["accepted"] and r["reference_status"] in RESOLVED-{"complete"}]}


def statistical_gates(primary, challenges, strata):
    """All v1 numerical gates; challenge rows never enter primary estimates."""
    require(len(primary) == 400, "fixed_primary_400_required")
    require(not {r["work_id"] for r in primary} & {r["work_id"] for r in challenges},
            "challenge_primary_overlap")
    require(len(challenges) <= 180 and set(strata) == set(QUOTAS), "fixed_challenge_strata_required")
    p = summarize(primary)
    checks = {"minimum_accepted": p["accepted"] >= 200,
        "minimum_resolved_complete": p["resolved_complete"] >= 200,
        "zero_false_accepts": p["false_accepts"] == 0,
        "strict_precision": p["precision_lower_97_5"] is not None and p["precision_lower_97_5"] >= .98,
        "strict_complete_recall": p["recall_lower_97_5"] is not None and p["recall_lower_97_5"] >= .8,
        "reference_resolution": p["unresolved"] <= 20}
    reports, missing = {}, []
    by_id = {r["work_id"]: r for r in challenges}
    require(set().union(*(set(v) for v in strata.values())) == set(by_id), "challenge_union_mismatch")
    for name, quota in QUOTAS.items():
        ids = strata[name]
        require(len(ids) == len(set(ids)) and set(ids) <= set(by_id), "invalid_challenge_membership")
        values = summarize([by_id[sid] for sid in ids])
        if len(ids) < quota:
            missing.append(name)
        if name in {"image_only", "broken_mapping"} and values["resolved_complete"] < 10:
            missing.append(name+":complete")
        checks["challenge_"+name+"_safety"] = values["false_accepts"] == 0
        if values["resolved_complete"] >= 10:
            checks["challenge_"+name+"_utility"] = values["conservative_recall"] >= .8
        if name in {"image_only", "broken_mapping"}:
            checks["challenge_"+name+"_actual_image_route"] = all(
                not by_id[sid]["strict_correct"] or by_id[sid]["route"] == "image_review" for sid in ids)
        reports[name] = values
    return {"status": "BLOCKED" if missing else "FAIL" if not all(checks.values()) else "PASS",
        "primary": p, "challenge": reports, "checks": checks, "missing_representation": missing,
        "primary_confidence_claim": "Two one-sided 97.5% exact bounds; at least 95% joint coverage under the preregistered binomial model.",
        "population_scope": "Bounded returned recent OAI frame; historical hep-th challenge is descriptive and separate."}


class Artifacts:
    """Read/parse one buffer, retain its digest, and recheck before publication."""
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.seen = {}

    def bytes(self, descriptor):
        exact(descriptor, {"relative", "sha256"}, "artifact_descriptor_required")
        require(isinstance(descriptor["sha256"], str) and SHA.fullmatch(descriptor["sha256"]), "artifact_hash_required")
        path = child(self.root, descriptor["relative"])
        raw = path.read_bytes()
        observed = hashlib.sha256(raw).hexdigest()
        require(observed == descriptor["sha256"], "artifact_bytes_changed")
        require(descriptor["relative"] not in self.seen or self.seen[descriptor["relative"]] == observed,
                "artifact_changed_between_reads")
        self.seen[descriptor["relative"]] = observed
        return raw

    @staticmethod
    def parse(raw):
        def unique(pairs):
            value = {}
            for key, item in pairs:
                require(key not in value, "duplicate_json_key")
                value[key] = item
            return value
        return json.loads(raw, object_pairs_hook=unique,
            parse_constant=lambda _: (_ for _ in ()).throw(EvidenceError("nonfinite_json")))

    def json(self, descriptor):
        return self.parse(self.bytes(descriptor))

    def verify(self, descriptor):
        exact(descriptor, {"relative", "sha256"}, "artifact_descriptor_required")
        require(isinstance(descriptor["sha256"], str) and SHA.fullmatch(descriptor["sha256"]), "artifact_hash_required")
        with child(self.root, descriptor["relative"]).open("rb") as handle:
            observed = hashlib.file_digest(handle, "sha256").hexdigest()
        require(observed == descriptor["sha256"], "artifact_bytes_changed")
        require(descriptor["relative"] not in self.seen or self.seen[descriptor["relative"]] == observed,
                "artifact_changed_between_reads")
        self.seen[descriptor["relative"]] = observed

    def recheck(self):
        for relative, sha in self.seen.items():
            with child(self.root, relative).open("rb") as handle:
                require(hashlib.file_digest(handle, "sha256").hexdigest() == sha, "artifact_changed_during_evaluation")


def validate_protocol(protocol):
    require(protocol.get("schema_version") == "source-first-qualification-preregistration-v1"
        and protocol.get("seed") == SEED and protocol.get("targets") == TARGETS
        and protocol.get("sampling") == SAMPLING and protocol.get("reference_review") == REFERENCE_REVIEW,
        "preregistered_sampling_review_or_targets_changed")
    require(protocol.get("configuration", {}).get("measured_arms") == list(METHODS)
        and protocol["configuration"].get("image_evidence_required") is True
        and protocol["configuration"].get("native_only_receipt_sufficient") is False,
        "preregistered_image_and_four_arm_contract_required")


def verify_phases(receipts, *, trust, study_id, execution_mode, artifact_hashes, roles, at):
    require(isinstance(receipts, list) and len(receipts) == 4, "four_signed_phases_required")
    require(set(roles) == {"custodian", "source_reviewer", "adjudicator", "candidate_reviewer", "operator"},
            "assigned_internal_roles_required")
    for role in roles.values():
        exact(role, {"principal", "context_id", "reviewer_kind", "model_version"}, "attributed_role_contract_required")
        require(all(isinstance(role[k], str) and role[k] for k in ("principal", "context_id"))
            and role["reviewer_kind"] == "assistant"
            and (role["model_version"] is None or isinstance(role["model_version"], str)), "honest_internal_role_required")
    require(roles["source_reviewer"]["context_id"] != roles["candidate_reviewer"]["context_id"]
        and roles["source_reviewer"]["context_id"] != roles["operator"]["context_id"]
        and roles["adjudicator"]["context_id"] not in {roles["source_reviewer"]["context_id"], roles["candidate_reviewer"]["context_id"]},
        "reference_context_leakage")
    previous, times = None, []
    for phase, receipt in zip(PHASES, receipts):
        issuer = trust.verify(receipt, "RUN_CHECKPOINT", at=at)
        expected_role = "operator" if phase == "predictions_frozen" else "custodian"
        require(issuer.can_review and issuer.principal == roles[expected_role]["principal"], "phase_issuer_role_mismatch")
        expected = {"contract": VERSION, "study_id": study_id, "execution_mode": execution_mode, "phase": phase,
            "artifact_hashes": artifact_hashes[phase], "previous_receipt_sha256": previous,
            "review_policy": REVIEW_POLICY, "independent_human_review": False,
            "context_id": roles[expected_role]["context_id"]}
        require(receipt["payload"] == expected, "signed_phase_artifact_or_order_mismatch")
        stamp = instant(receipt["issued_at"])
        require(not times or times[-1] < stamp, "strict_phase_chronology_required")
        times.append(stamp)
        previous = digest(receipt)
    return dict(zip(PHASES, times))


def validate_selection(value):
    exact(value, {"recent_frame", "historical_frame", "exposed_work_ids", "identity_exclusions",
        "primary", "recent_screen", "historical_screen", "screen", "challenge", "reconciled_at", "exposure_snapshot"}, "selection_contract_required")
    recent, historical = value["recent_frame"], value["historical_frame"]
    require(len(recent) == 2000 and len(historical) == 2000, "both_frozen_2000_work_frames_required")
    rank(recent, "primary"); rank(historical, "historical-screen")
    require(not set(recent) & set(historical), "frame_work_overlap")
    exposed = value["exposed_work_ids"]
    require(len(exposed) == len(set(exposed)), "duplicate_exposure_identity")
    for sid in exposed:
        work_id(sid)
    excluded = set(exposed)
    for exclusion in value["identity_exclusions"]:
        exact(exclusion, {"work_id", "reason", "evidence_sha256"}, "identity_exclusion_contract_required")
        work_id(exclusion["work_id"])
        require(exclusion["reason"] in {"same_work", "same_doi", "same_source", "same_page", "previous_exposure"}
            and isinstance(exclusion["evidence_sha256"], str) and SHA.fullmatch(exclusion["evidence_sha256"]),
            "unavailable_or_error_case_cannot_be_replaced")
        require(exclusion["work_id"] not in excluded, "duplicate_identity_exclusion")
        excluded.add(exclusion["work_id"])
    recent_rank = rank([x for x in recent if x not in excluded], "primary")
    historical_rank = rank([x for x in historical if x not in excluded], "historical-screen")
    require(len(recent_rank) >= 1000 and len(historical_rank) >= 600, "insufficient_eligible_frame")
    require(value["primary"] == recent_rank[:400] and value["recent_screen"] == recent_rank[400:1000]
        and value["historical_screen"] == historical_rank[:600], "frozen_rank_selection_mismatch")
    screened = set(value["recent_screen"]+value["historical_screen"])
    require(isinstance(value["screen"], dict) and set(value["screen"]) == screened, "all_1200_source_screens_required")
    selected, memberships = set(), {}
    for sid, item in value["screen"].items():
        exact(item, {"strata", "image_first", "prediction_access", "reviewed_at", "context_id"}, "source_screen_contract_required")
        require(isinstance(item["strata"], list) and len(item["strata"]) == len(set(item["strata"]))
            and set(item["strata"]) <= set(QUOTAS) and item["image_first"] is True
            and item["prediction_access"] is False, "source_only_screen_required")
        require(not {"partial", "absent"} <= set(item["strata"]), "contradictory_screen_scope")
    for name, quota in QUOTAS.items():
        eligible = [sid for sid, item in value["screen"].items() if name in item["strata"]]
        selected.update(rank(eligible, "challenge:"+name)[:quota])
    require(value["challenge"] == sorted(selected), "challenge_selection_mismatch")
    for name in QUOTAS:
        memberships[name] = sorted(sid for sid in selected if name in value["screen"][sid]["strata"])
    return set(value["primary"]) | selected, screened, memberships


def reconcile_exposure(snapshot, prior, selection):
    """The cohort seal binds the current work, byte and DOI exposure inventory."""
    exact(snapshot, {"version", "reconciled_at", "entries"}, "current_exposure_snapshot_required")
    require(snapshot["version"] == "paper-exposure-snapshot-v1"
        and snapshot["reconciled_at"] == selection["reconciled_at"]
        and isinstance(snapshot["entries"], list), "current_exposure_snapshot_mismatch")
    entries = {}
    for item in snapshot["entries"]:
        exact(item, {"work_id", "source_sha256", "page_sha256", "dois"}, "exposure_alias_inventory_required")
        sid = work_id(item["work_id"])
        require(sid not in entries, "duplicate_exposure_identity")
        for key in ("source_sha256", "page_sha256", "dois"):
            values = item[key]
            require(isinstance(values, list) and len(values) == len(set(values)), "unique_exposure_aliases_required")
            require(all(isinstance(v, str) and (SHA.fullmatch(v) if key != "dois" else
                v == v.strip().lower() and v.startswith("10.") and "/" in v) for v in values), "invalid_exposure_alias")
        entries[sid] = item
    require(set(entries) == set(selection["exposed_work_ids"]), "exposure_selection_inventory_mismatch")
    for item in prior:
        sid = normalize_work_id(item["work_id"])
        require(sid in entries and all(set(item[key]) <= set(entries[sid][key])
            for key in ("source_sha256", "page_sha256")), "prior_exposure_registry_not_preserved")
    return {key: {value for item in entries.values() for value in item[key]}
        for key in ("source_sha256", "page_sha256", "dois")}


def verify_review_order(records, *, evaluated_ids, roles, source_hashes, times):
    """The signed reference phase binds these access and decision records."""
    require(isinstance(records, dict) and set(records) == evaluated_ids, "every_reference_review_required")
    resolved = []
    for sid, record in records.items():
        exact(record, {"reference", "initial_reference", "history", "events", "unresolved_disagreement",
            "requires_adjudication", "audit_completed", "audit_material_error", "full_dimension_audit_completed"},
            "reference_record_contract_required")
        reference = record["reference"]
        require(reference.get("status") in RESOLVED | {"uncertain"}, "reference_scope_required")
        require(all(type(record[k]) is bool for k in ("unresolved_disagreement", "requires_adjudication",
            "audit_completed", "audit_material_error", "full_dimension_audit_completed")), "review_flags_required")
        require(not record["unresolved_disagreement"] or reference["status"] == "uncertain",
                "unresolved_disagreement_cannot_certify_reference")
        require(isinstance(record["history"], list) and record["history"]
            and record["history"][0] == record["initial_reference"] and record["history"][-1] == reference,
            "initial_and_final_review_decisions_must_be_preserved")
        events = record["events"]
        require(isinstance(events, list) and events, "source_access_events_required")
        previous = times["cohort_frozen"]
        decisions = [digest(x) for x in record["history"]]
        require(len(decisions) == len(set(decisions)), "duplicate_reference_decision_history")
        decision_index = 0
        for index, event in enumerate(events):
            exact(event, {"kind", "context_id", "at", "input_sha256", "decision_sha256"}, "review_event_contract_required")
            kind = event["kind"]
            require(kind in {"image_inspection", "native_readback", "adjudication", "audit", "source_unavailable"},
                    "unknown_reference_access_event")
            role = "adjudicator" if kind in {"adjudication", "audit"} else "source_reviewer"
            require(event["context_id"] == roles[role]["context_id"], "reference_role_context_mismatch")
            stamp = instant(event["at"])
            require(previous <= stamp < times["references_frozen"], "reference_review_outside_blinded_window")
            previous = stamp
            inputs = event["input_sha256"]
            require(isinstance(inputs, list) and len(inputs) == len(set(inputs)), "reference_input_manifest_required")
            allowed = source_hashes[sid]
            if index == 0:
                require(kind == "source_unavailable" and not inputs and reference["status"] == "uncertain"
                    or kind == "image_inspection" and inputs == [allowed["image"]], "original_image_must_precede_native_or_prediction")
            else:
                require((set(inputs) <= set(allowed.values()) and bool(inputs)) or
                    (not allowed and not inputs and kind == "adjudication" and reference["status"] == "uncertain"),
                    "reference_context_received_non_source_input")
            require(event["decision_sha256"] in decisions, "review_decision_not_in_preserved_history")
            current_index = decisions.index(event["decision_sha256"])
            require((index == 0 and current_index == 0) or (index > 0 and decision_index <= current_index <= decision_index+1),
                "reference_decision_history_out_of_order")
            decision_index = current_index
        require(decision_index == len(decisions)-1, "review_decisions_lack_access_receipts")
        unresolved_history = any(h.get("status") == "uncertain" or h.get("status") == "complete" and
            any(h.get("fidelity_review", {}).get(d, {}).get("status") != "pass" for d in ("notation", "boundary"))
            for h in record["history"])
        mandatory = record["requires_adjudication"] or unresolved_history or reference.get("fidelity_review", {}).get("boundary", {}).get("representation") == "image_regions"
        if mandatory:
            require(any(e["kind"] == "adjudication" and e["decision_sha256"] == decisions[-1] for e in events),
                "final_notation_or_image_reference_requires_adjudication")
        if reference["status"] in RESOLVED and not mandatory:
            resolved.append(sid)
    audit_ids = rank(resolved, "reference-audit")[:math.ceil(len(resolved)*.1)]
    for sid in audit_ids:
        require(records[sid]["audit_completed"] and any(e["kind"] == "audit"
            and e["decision_sha256"] == digest(records[sid]["reference"]) for e in records[sid]["events"]),
                "fixed_ten_percent_reference_audit_missing")
    if any(r["audit_material_error"] for r in records.values()):
        require(all(r["full_dimension_audit_completed"] and any(e["kind"] == "adjudication"
            and e["decision_sha256"] == digest(r["reference"]) for e in r["events"])
            for r in records.values()),
                "material_reference_error_requires_full_dimension_audit")
    return audit_ids


def _source(store, value):
    exact(value, {"available", "source", "page", "image", "native", "unavailable_reason", "doi"}, "source_record_contract_required")
    require(type(value["available"]) is bool, "source_availability_required")
    if not value["available"]:
        require(all(value[k] is None for k in ("source", "page", "image", "native"))
            and value["unavailable_reason"] in {"unavailable", "corrupt", "encrypted"}, "unavailable_source_keeps_denominator")
        return None, {}
    require(value["unavailable_reason"] is None, "available_source_cannot_have_error")
    # Render, parse and compare the exact buffers whose identities were checked.
    # Reopening a pathname would permit a transient valid-image swap between
    # the initial and final hashes of an invalid image.
    import fitz
    from io import BytesIO
    from PIL import Image, ImageChops
    from trace_gc.pdf_source_parallel_v4 import source_lines
    raw = {key: store.bytes(value[key]) for key in ("source", "page", "image", "native")}
    recorded_native = store.parse(raw["native"])
    with fitz.open(stream=raw["source"], filetype="pdf") as source, fitz.open(stream=raw["page"], filetype="pdf") as page:
        require(len(source) > 0 and len(page) == 1, "expected_single_first_page_extract")
        left, right = (document[0].get_pixmap(dpi=120, alpha=False) for document in (source, page))
        require((left.width,left.height) == (right.width,right.height), "cached_page_does_not_match_first_physical_page")
        if left.samples != right.samples:
            a = Image.frombytes("RGB", (left.width,left.height), left.samples)
            b = Image.frombytes("RGB", (right.width,right.height), right.samples)
            require(max(channel[1] for channel in ImageChops.difference(a,b).getextrema()) <= 2,
                "cached_page_does_not_match_first_physical_page")
        with Image.open(BytesIO(raw["image"])) as image:
            image = image.convert("RGB")
            require(image.size == (left.width,left.height) and image.tobytes() == left.samples,
                "review_image_not_original_first_page")
        native = source_lines(source[0])
        require(digest_value(native) == digest_value(recorded_native), "native_review_spans_not_from_original_first_page")
    return native, {key: value[key]["sha256"] for key in ("source", "page", "image", "native")}


def image_transition(closure, *, png, crop):
    """Verify a nonblank, disjoint following source witness in original pixels."""
    from io import BytesIO
    from PIL import Image
    exact(closure, {"kind", "excluded_regions"}, "prospective_image_transition_witness_required")
    require(closure["kind"] == "reviewed_section_transition", "prospective_image_title_page_adapter_required")
    require(isinstance(closure["excluded_regions"], list) and closure["excluded_regions"], "image_transition_regions_required")
    following = False
    with Image.open(BytesIO(png)) as image:
        width, height = image.size
        for box in closure["excluded_regions"]:
            require(isinstance(box, list) and len(box) == 4 and all(type(x) in (int, float) and math.isfinite(x) for x in box)
                and 0 <= box[0] < box[2] <= width and 0 <= box[1] < box[3] <= height
                and not (min(box[2], crop[2]) > max(box[0], crop[0]) and min(box[3], crop[3]) > max(box[1], crop[1])),
                "image_transition_region_conflicts_with_abstract")
            minimum, maximum = image.crop(tuple(box)).convert("L").getextrema()
            require(maximum-minimum >= 8, "image_transition_region_is_blank")
            following = following or (box[1] >= crop[3]-2 and
                min(box[2], crop[2])-max(box[0], crop[0]) > .1*min(box[2]-box[0], crop[2]-crop[0]))
    require(following, "following_source_transition_required")


def native_failure(store, descriptor, *, original, source, roles, times):
    """A durable negative observation never certifies a replacement by itself."""
    failure = store.json(descriptor)
    exact(failure, {"version", "assessment_sha256", "text_sha256", "source_sha256", "page_sha256",
        "native_sha256", "image_sha256", "dimension", "status", "reviewer", "context_id", "reviewed_at",
        "observed_mismatch", "source_image_inspected"}, "explicit_failed_native_review_required")
    require(failure["version"] == "paper-candidate-failure-v1"
        and original.get("proposal") is True
        and all(failure[k] == original[k] for k in ("assessment_sha256", "text_sha256", "source_sha256", "page_sha256", "native_sha256"))
        and failure["image_sha256"] == source["image"]["sha256"]
        and failure["dimension"] in {"notation", "boundary", "reading_order"} and failure["status"] == "fail"
        and failure["reviewer"] == roles["candidate_reviewer"]["principal"]
        and failure["context_id"] == roles["candidate_reviewer"]["context_id"]
        and times["references_frozen"] < instant(failure["reviewed_at"]) <= times["predictions_frozen"]
        and isinstance(failure["observed_mismatch"], str) and bool(failure["observed_mismatch"].strip())
        and failure["source_image_inspected"] is True, "healthy_or_stale_native_cannot_be_replaced")
    store.bytes(source["image"])
    return failure


def _image_candidate(store, value, *, source, selected, original, reference, code, image_access, roles, times, at):
    """Prospective image lineage; no development exposure label is manufactured."""
    from trace_gc.pdf_image_evidence import candidate_hash, verify_artifacts, held_reason, handoff
    from trace_gc.catalog import Catalog
    from trace_gc.canonical import text_digest
    exact(value, {"preparation", "execution", "candidate", "raw_ocr", "crop", "catalog", "handoff", "scope_review", "review_context_id", "access_events"},
            "typed_image_lineage_required")
    require(value["review_context_id"] == roles["candidate_reviewer"]["context_id"], "candidate_context_mismatch")
    candidate, preparation, execution = (store.json(value[k]) for k in ("candidate", "preparation", "execution"))
    allowed_inputs = {source["image"]["sha256"], source["source"]["sha256"], original["assessment_sha256"]}
    allowed_inputs.update(value[k]["sha256"] for k in ("candidate", "raw_ocr", "crop", "preparation", "execution"))
    require(isinstance(value["access_events"], list) and value["access_events"], "candidate_access_log_required")
    last = times["references_frozen"]
    observed_source = False
    observed_original = False
    for event in value["access_events"]:
        exact(event, {"context_id", "at", "input_sha256"}, "candidate_access_event_contract_required")
        require(event["context_id"] == roles["candidate_reviewer"]["context_id"]
            and last < instant(event["at"]) <= times["predictions_frozen"]
            and isinstance(event["input_sha256"], list) and bool(event["input_sha256"])
            and set(event["input_sha256"]) <= allowed_inputs, "candidate_context_received_reference_or_stale_input")
        last = instant(event["at"])
        observed_source = observed_source or source["image"]["sha256"] in event["input_sha256"]
        observed_original = observed_original or original["assessment_sha256"] in event["input_sha256"]
    require(observed_source, "candidate_review_original_image_required")
    require(not original.get("proposal") or observed_original, "failed_native_assessment_review_access_required")
    raw, crop = store.bytes(value["raw_ocr"]), store.bytes(value["crop"])
    raw_record = store.json(value["raw_ocr"])
    require(candidate.get("source_sha256") == source["source"]["sha256"]
        and candidate.get("physical_page") == 1, "image_source_identity_mismatch")
    verify_artifacts(candidate, pdf_bytes=store.bytes(source["source"]), raw_output=raw,
        page_png=store.bytes(source["image"]), crop_png=crop)
    require(preparation.get("version") == "image-review-preparation-v1" and preparation.get("code_sha256") == code
        and preparation.get("source_id") == candidate["source_id"]
        and preparation.get("source_relative") == source["source"]["relative"]
        and preparation.get("new_paid_api_calls") == 0 and preparation.get("production_graph_writes") == 0
        and execution.get("preparation_sha256") == value["preparation"]["sha256"]
        and all(preparation.get("metadata", {}).get(k) == candidate[k] for k in
            ("source_sha256", "physical_page", "page_identity_sha256", "render", "crop", "native_observation")),
        "image_preparation_lineage_mismatch")
    require(execution.get("version") == "image-ocr-execution-v1" and execution.get("status") == "SOURCE_REVIEW_REQUIRED"
        and execution.get("code_sha256") == code and type(execution.get("new_local_ocr_calls")) is int
        and execution.get("new_local_ocr_calls") == 1
        and execution.get("new_paid_api_calls") == 0 and execution.get("production_graph_writes") == 0,
        "genuine_current_local_image_execution_required")
    require(raw_record.get("version") == "windows-local-image-ocr-v1" and raw_record.get("engine") == "Windows.Media.Ocr"
        and raw_record.get("configuration", {}).get("local_only") is True
        and raw_record["configuration"].get("implementation_sha256") == code["tools/windows_image_ocr.ps1"]
        and all(candidate["ocr"][k] == raw_record.get(k) for k in
            ("engine", "revision", "configuration", "input_crop_sha256", "output_status")), "local_image_engine_identity_mismatch")
    require(raw_record["engine"] == image_access["engine"] and raw_record["revision"] == image_access["revision"]
        and raw_record["configuration"] == image_access["decoding"], "image_ocr_frozen_access_configuration_mismatch")
    initial = deepcopy(candidate)
    initial.update(transcription=raw_record["text"], transcription_sha256=text_digest(raw_record["text"]), correction=None, review=None)
    require(execution.get("candidate_sha256") == candidate_hash(initial), "raw_image_candidate_lineage_mismatch")
    correction = candidate.get("correction")
    if correction:
        require(correction["previous_candidate_sha256"] == candidate_hash(initial)
            and correction["previous_transcription_sha256"] == initial["transcription_sha256"], "image_correction_lineage_mismatch")
    else:
        require(candidate["transcription"] == raw_record["text"], "unrecorded_image_correction")
    review = candidate.get("review")
    require(review and review.get("reviewer") == roles["candidate_reviewer"]["principal"]
        and review.get("reviewer_kind") == "assistant" and review.get("independent_review") is False
        and last <= instant(review["reviewed_at"]) <= times["predictions_frozen"],
        "attributed_candidate_review_after_reference_seal_required")
    if correction:
        require(correction.get("editor") == roles["candidate_reviewer"]["principal"]
            and correction.get("editor_kind") == "assistant"
            and times["references_frozen"] < instant(correction["edited_at"]) <= instant(review["reviewed_at"]),
            "image_correction_attribution_or_order_invalid")
    require(held_reason(candidate) is None, "held_image_cannot_be_accepted")
    scope = store.json(value["scope_review"])
    exact(scope, {"version", "candidate_sha256", "source_sha256", "image_sha256", "decision", "reviewer", "context_id",
        "reviewed_at", "native_image_disagreement_examined", "no_page_continuation", "closure"}, "prospective_image_scope_required")
    require(scope["version"] == "paper-image-scope-review-v1" and scope["candidate_sha256"] == candidate_hash(candidate)
        and scope["source_sha256"] == source["source"]["sha256"] and scope["image_sha256"] == source["image"]["sha256"]
        and scope["decision"] == "complete" and scope["reviewer"] == roles["candidate_reviewer"]["principal"]
        and scope["context_id"] == roles["candidate_reviewer"]["context_id"]
        and instant(review["reviewed_at"]) <= instant(scope["reviewed_at"]) <= times["predictions_frozen"]
        and scope["native_image_disagreement_examined"] is True and scope["no_page_continuation"] is True,
        "image_scope_identity_or_review_mismatch")
    image_transition(scope["closure"], png=store.bytes(source["image"]), crop=candidate["crop"]["bbox"])
    require(selected.get("closing_boundary") == {"kind": scope["closure"]["kind"], "review_sha256": digest_value(scope)},
        "image_selected_closure_not_bound_to_scope")
    recorded, receipt = store.json(value["catalog"]), store.json(value["handoff"])
    source_records = [r for r in recorded if r.get("kind") == "source"]
    require(len(source_records) == 1, "one_image_source_record_required")
    catalog = Catalog()
    rebuilt = handoff(catalog, candidate, pdf_bytes=store.bytes(source["source"]), raw_output=raw,
        scope=source_records[0]["body"]["security_scope"])
    require(recorded == catalog.all() and all(receipt.get(k) == v for k, v in rebuilt.items())
        and receipt.get("catalog_sha256") == digest(recorded) and receipt.get("code_sha256") == code
        and receipt.get("new_paid_api_calls") == 0 and receipt.get("production_graph_writes") == 0,
        "image_handoff_lineage_mismatch")
    require(selected.get("representation") == "reviewed-image-transcription-v1" and selected.get("spans") == []
        and selected.get("text") == candidate["transcription"] and selected.get("image_candidate_sha256") == candidate_hash(candidate)
        and selected.get("original_assessment_sha256") == original["assessment_sha256"]
        and selected.get("image_sha256") == source["image"]["sha256"]
        and selected.get("image_regions") == [{"page_no": 1, "coord_origin": "TOPLEFT", "bbox": candidate["crop"]["bbox"]}],
        "selected_image_representation_mismatch")
    require(reference.get("fidelity_review", {}).get("boundary", {}).get("representation") == "image_regions",
            "separately_frozen_image_reference_required")
    proof = reference.get("source_extent_proof")
    exact(proof, {"version", "image_sha256", "closure"}, "source_first_image_extent_proof_required")
    require(proof["version"] == "paper-image-reference-extent-v1"
        and proof["image_sha256"] == source["image"]["sha256"], "image_reference_extent_source_mismatch")
    image_transition(proof["closure"], png=store.bytes(source["image"]), crop=candidate["crop"]["bbox"])
    transcription = reference.get("typed_transcription")
    exact(transcription, {"version", "text_sha256", "image_sha256", "spans"}, "typed_image_reference_transcription_required")
    require(transcription["version"] == "source-first-image-reference-v1"
        and transcription["text_sha256"] == hashlib.sha256(reference["text"].encode("utf8")).hexdigest()
        and transcription["image_sha256"] == source["image"]["sha256"], "typed_reference_identity_mismatch")
    position = 0
    for span in transcription["spans"]:
        exact(span, {"start", "end", "text", "page_no"}, "typed_reference_codepoint_span_required")
        require(type(span["start"]) is int and type(span["end"]) is int and type(span["page_no"]) is int
            and span["page_no"] == 1 and span["start"] == position and position < span["end"] <= len(reference["text"])
            and span["text"] == reference["text"][position:span["end"]], "typed_reference_offset_readback_mismatch")
        position = span["end"]
    require(position == len(reference["text"]) and position > 0, "entire_image_reference_extent_required")
    return {"corrected": bool(correction), "raw_transcription_matches_final": candidate["transcription"] == raw_record["text"]}


def evaluator_identity():
    code = method_hashes()
    path = Path(__file__).resolve()
    code[path.relative_to(path.parents[1]).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    statistics = path.parents[1]/"trace_gc/qualification.py"
    code["trace_gc/qualification.py"] = hashlib.sha256(statistics.read_bytes()).hexdigest()
    return code


def replay_converters(store, case, *, predictions, source_identity, native, page_size, access, execution, times):
    """Reproduce each sealed arm from its typed, producer-bound cache inputs."""
    require(set(case["converter_inputs"]) == CACHE_NAMES and set(case["producer_receipts"]) == set(METHODS),
        "all_converter_cache_and_producer_receipts_required")
    hashes, paths = {}, {}
    for name, descriptor in case["converter_inputs"].items():
        store.json(descriptor)
        hashes[name], paths[name] = descriptor["sha256"], child(store.root, descriptor["relative"])
    for method in METHODS:
        receipt = store.json(case["producer_receipts"][method])
        exact(receipt, {"version", "method", "engine", "revision", "access_sha256", "source_sha256", "page_sha256",
            "configuration_sha256", "runtime_sha256", "code_sha256", "limits_sha256", "started_at", "completed_at",
            "execution_kind", "status", "output_sha256", "raw_response", "new_paid_api_calls", "production_graph_writes"},
            "typed_converter_producer_receipt_required")
        engine = access["methods"][method]
        require(receipt["version"] == "paper-converter-execution-v1" and receipt["method"] == method
            and receipt["execution_kind"] == "LOCAL_CONVERTER" and receipt["engine"] == engine["engine"]
            and receipt["revision"] == engine["revision"] and receipt["access_sha256"] == digest(engine)
            and receipt["source_sha256"] == source_identity["source"] and receipt["page_sha256"] == source_identity["page"]
            and receipt["configuration_sha256"] == execution["configuration_sha256"]
            and receipt["runtime_sha256"] == digest(execution["runtime"])
            and receipt["code_sha256"] == execution["code_sha256"] and receipt["limits_sha256"] == digest(execution["limits"])
            and receipt["status"] in {"success", "error", "truncated"}
            and type(receipt["new_paid_api_calls"]) is int and receipt["new_paid_api_calls"] == 0
            and type(receipt["production_graph_writes"]) is int and receipt["production_graph_writes"] == 0,
            "converter_source_access_policy_or_runtime_mismatch")
        require(times["references_frozen"] < instant(receipt["started_at"]) <= instant(receipt["completed_at"])
            <= instant(execution["completed_at"]), "converter_generation_before_reference_freeze")
        require(receipt["output_sha256"] == {name: hashes[name] for name in CACHE_OUTPUTS[method]},
            "converter_output_cache_binding_mismatch")
        store.bytes(receipt["raw_response"])
        rebuilt = predict(method, paths, {"source_sha256": source_identity["source"], "page_sha256": source_identity["page"],
            "native_lines": native, "page_size": page_size}, expected_input_hashes=hashes)
        require(rebuilt == predictions[method], "assessment_not_derived_from_recorded_converter_output")


def _evaluate(root, bundle_descriptor, *, expected_preregistration_sha256, trust, at, runtime_lock):
    from src.parallel_source_v4.image_ocr import code_identity
    store = Artifacts(root)
    bundle = store.json(bundle_descriptor)
    exact(bundle, {"version", "study_id", "execution_mode", "preregistration", "configuration", "regression",
        "source_map", "access", "sampling", "screening", "sources", "references", "execution", "roles", "phases"},
        "study_bundle_contract_required")
    require(bundle["version"] == VERSION and isinstance(bundle["study_id"], str) and bundle["study_id"], "study_identity_required")
    require(bundle["execution_mode"] in {"REAL_LOCAL", "AUTHORED_CONTRACT_TEST"}, "explicit_study_mode_required")
    require(bundle["preregistration"]["sha256"] == expected_preregistration_sha256,
            "externally_pinned_preregistration_required")
    pointer = store.json(bundle["preregistration"])
    require(pointer.get("schema_version") == "qualification-preregistration-current-v1"
        and pointer.get("numeric_targets_unchanged") is True and pointer.get("reference_review_occurred") is False,
        "frozen_preregistration_pointer_required")
    base = str(Path(bundle["preregistration"]["relative"]).parent).replace("\\", "/")
    documents = {}
    for relative, sha in pointer["base_protocol_and_additive_amendments"].items():
        descriptor = {"relative": base+"/"+relative, "sha256": sha}
        documents[relative] = store.bytes(descriptor)
    required = {"protocol.json", "protocol.md", "amendment-02/protocol-amendment.md",
        "amendment-03/protocol-amendment.md", "amendment-04/evaluator-clarification.json", "metadata-inventory/exposure-registry.jsonl"}
    require(required <= set(documents), "base_protocol_and_both_frame_amendments_required")
    protocol = store.json({"relative": base+"/protocol.json", "sha256": pointer["base_protocol_and_additive_amendments"]["protocol.json"]})
    validate_protocol(protocol)
    require(store.json({"relative": base+"/amendment-04/evaluator-clarification.json",
        "sha256": pointer["base_protocol_and_additive_amendments"]["amendment-04/evaluator-clarification.json"]}) == CLARIFICATION,
        "approved_preselection_identity_and_audit_rules_required")
    config = configuration(store.json(bundle["configuration"]))
    require(config["image_evidence_policy"] == "source-bound-attributed-image-review-v1", "image_enabled_configuration_required")
    # This check runs before opening any selected PDF/image/native artifact.
    regression_artifact = store.json(bundle["regression"])
    regression = verify_regression(store.root, bundle["regression"]["relative"], bundle["regression"]["sha256"],
        configuration_relative=bundle["configuration"]["relative"], source_map_relative=bundle["source_map"]["relative"],
        runtime_lock=runtime_lock)
    store.json(bundle["source_map"])
    require(regression.get("status") == "PASS", "exact_image_enabled_regression_pass_required")
    for relative, sha in regression_artifact["input_file_hashes"].items():
        store.verify({"relative": relative, "sha256": sha})
    regression_directory = str(Path(bundle["regression"]["relative"]).parent).replace("\\", "/")
    for relative, sha in regression_artifact["derived_assessment_files_sha256"].items():
        store.verify({"relative": regression_directory+"/"+relative, "sha256": sha})
    code, image_code, runtime = evaluator_identity(), code_identity(), runtime_receipt(runtime_lock)
    access = store.json(bundle["access"])
    exact(access, {"version", "methods", "image_ocr", "code_sha256", "image_code_sha256", "runtime", "configuration_sha256",
        "limits", "new_paid_api_calls", "production_graph_writes"}, "converter_access_contract_required")
    require(access["version"] == "paper-local-access-v1" and access["code_sha256"] == code
        and access["image_code_sha256"] == image_code and access["runtime"] == runtime
        and access["configuration_sha256"] == digest_value(config) and access["new_paid_api_calls"] == 0
        and access["production_graph_writes"] == 0, "frozen_access_code_runtime_or_policy_mismatch")
    require(set(access["methods"]) == set(METHODS), "genuine_all_four_converter_access_required")
    probe_times = []
    expected_engines = {"parallel_structure_v4": "docling", "parallel_grobid_v4": "grobid",
        "parallel_mineru_v4": "mineru", "parallel_olmocr_v4": "olmocr", "image": "Windows.Media.Ocr"}
    for method, engine in {**access["methods"], "image": access["image_ocr"]}.items():
        exact(engine, {"status", "engine", "revision", "assets", "probe", "license", "device", "prompt_sha256", "decoding"},
            "converter_identity_and_local_probe_required")
        require(engine["status"] == "AVAILABLE_VERIFIED_LOCAL" and engine["engine"] == expected_engines[method]
            and all(isinstance(engine[k], str) and bool(engine[k].strip()) for k in ("revision", "license", "device"))
            and isinstance(engine["assets"], list) and bool(engine["assets"])
            and (engine["prompt_sha256"] is None or isinstance(engine["prompt_sha256"], str) and SHA.fullmatch(engine["prompt_sha256"]))
            and isinstance(engine["decoding"], dict), "genuine_converter_assets_unavailable")
        for descriptor in engine["assets"]+[engine["probe"]]:
            store.verify(descriptor)
        probe = store.json(engine["probe"])
        exact(probe, {"version", "engine", "revision", "asset_sha256", "exit_code", "local_only", "stdout", "completed_at"},
            "typed_converter_readiness_probe_required")
        require(probe["version"] == "paper-local-readiness-v1" and probe["engine"] == engine["engine"]
            and probe["revision"] == engine["revision"] and probe["asset_sha256"] == [a["sha256"] for a in engine["assets"]]
            and type(probe["exit_code"]) is int and probe["exit_code"] == 0 and probe["local_only"] is True,
            "converter_readiness_probe_mismatch")
        store.bytes(probe["stdout"])
        probe_times.append(instant(probe["completed_at"]))
    exact(access["limits"], {"request_characters", "request_tokens", "retries", "timeout_seconds", "device_concurrency", "crop_policy"},
        "fixed_execution_limits_required")
    require(all(type(access["limits"][k]) is int and access["limits"][k] > 0
        for k in ("request_characters", "request_tokens", "timeout_seconds", "device_concurrency"))
        and type(access["limits"]["retries"]) is int and access["limits"]["retries"] >= 0
        and isinstance(access["limits"]["crop_policy"], str) and access["limits"]["crop_policy"], "invalid_fixed_execution_limits")
    hashes = {k: bundle[k]["sha256"] for k in ("preregistration", "configuration", "regression", "source_map", "access")}
    hashes["roles"] = digest(bundle["roles"])
    phase_hashes = {PHASES[0]: deepcopy(hashes)}
    for phase, additions in zip(PHASES[1:], (("sampling", "sources"), ("screening", "references"), ("execution",))):
        hashes.update({k: bundle[k]["sha256"] for k in additions})
        phase_hashes[phase] = deepcopy(hashes)
    times = verify_phases(bundle["phases"], trust=trust, study_id=bundle["study_id"], execution_mode=bundle["execution_mode"], artifact_hashes=phase_hashes,
        roles=bundle["roles"], at=at)
    require(instant(protocol["registered_utc"]) < times["configuration_frozen"], "preregistration_must_precede_source_access")
    require(all(stamp < times["configuration_frozen"] for stamp in probe_times), "genuine_converter_access_must_precede_source_review")
    sampling, screening = store.json(bundle["sampling"]), store.json(bundle["screening"])
    exact(screening, {"screen", "challenge"}, "separate_source_screen_artifact_required")
    selection = {**sampling, **screening}
    evaluated_ids, screened_ids, strata = validate_selection(selection)
    require(not selection["identity_exclusions"], "verified_alias_replacement_adapter_required")
    require(times["configuration_frozen"] <= instant(selection["reconciled_at"]) < times["cohort_frozen"],
            "exposure_reconciliation_before_cohort_freeze_required")
    frame_versions, frame_dois = {}, {}
    for role, frame in pointer["frames"].items():
        projected = store.json({"relative": base+"/"+frame["identity_projection_relative"], "sha256": frame["sha256"]})
        require([normalize_work_id(x["work_id"]) for x in projected] == selection[role+"_frame"], "sampling_does_not_match_frozen_metadata_frame")
        for item in projected:
            sid = normalize_work_id(item["work_id"])
            frame_versions[sid] = item["version_id"]
            if item.get("doi"):
                frame_dois[sid] = item["doi"].strip().lower()
    exposure = [store.parse(line) for line in documents["metadata-inventory/exposure-registry.jsonl"].splitlines() if line]
    known = reconcile_exposure(store.json(selection["exposure_snapshot"]), exposure, selection)
    known_source, known_page = known["source_sha256"], known["page_sha256"]
    require(not {frame_dois[sid] for sid in set(selection["primary"]) | screened_ids if sid in frame_dois} & known["dois"],
        "selected_work_doi_was_previously_exposed")
    for sid, item in selection["screen"].items():
        require(item["context_id"] == bundle["roles"]["source_reviewer"]["context_id"]
            and times["cohort_frozen"] <= instant(item["reviewed_at"]) < times["references_frozen"], "screening_after_prediction_or_wrong_context")
    sources, references = store.json(bundle["sources"]), store.json(bundle["references"])
    require(set(sources) == set(selection["primary"]) | screened_ids, "all_1600_assigned_source_outcomes_required")
    require(set(references) == evaluated_ids, "every_evaluated_reference_required")
    natives, source_hashes = {}, {}
    seen_source, seen_page, seen_doi = set(), set(), set()
    for sid, source in sources.items():
        exact(source, {"version_id", "assets"}, "pinned_source_version_required")
        require(source["version_id"] == frame_versions[sid], "source_version_drift")
        native, identity = _source(store, source["assets"])
        natives[sid], source_hashes[sid] = native, identity
        if identity:
            require(identity["source"] not in known_source | seen_source and identity["page"] not in known_page | seen_page,
                    "source_or_page_alias_or_exposure")
            seen_source.add(identity["source"]); seen_page.add(identity["page"])
        doi = source["assets"]["doi"]
        require(doi == frame_dois.get(sid), "doi_projection_mismatch")
        if doi:
            require(doi not in seen_doi, "duplicate_doi_work_alias")
            seen_doi.add(doi)
    audit_ids = verify_review_order(references, evaluated_ids=evaluated_ids, roles=bundle["roles"],
        source_hashes=source_hashes, times=times)
    execution = store.json(bundle["execution"])
    exact(execution, {"version", "started_at", "completed_at", "code_sha256", "image_code_sha256", "runtime",
        "configuration_sha256", "limits", "cases", "costs", "stage_reports"}, "execution_contract_required")
    require(execution["version"] == "paper-four-arm-execution-v1" and execution["code_sha256"] == code
        and execution["image_code_sha256"] == image_code and execution["runtime"] == runtime
        and execution["configuration_sha256"] == digest_value(config) and execution["limits"] == access["limits"],
        "execution_policy_code_runtime_or_limits_drift")
    require(times["references_frozen"] < instant(execution["started_at"]) <= instant(execution["completed_at"])
        <= times["predictions_frozen"] <= instant(at), "predictions_precede_reference_seal")
    require(set(execution["cases"]) == evaluated_ids, "all_sampled_predictions_required")
    require(execution["costs"].get("paid_calls") == 0 and execution["costs"].get("paid_spend_usd") == 0
        and execution["costs"].get("graph_writes") == 0, "unauthorized_paid_or_graph_execution")
    require(isinstance(execution["stage_reports"], list) and execution["stage_reports"], "timing_failure_and_review_reports_required")
    stage_names = set()
    for stage in execution["stage_reports"]:
        exact(stage, {"stage", "elapsed_seconds", "cpu_seconds", "failures", "retries", "calls", "review_count", "review_active_seconds"},
            "stage_cost_report_contract_required")
        require(stage["stage"] not in stage_names, "duplicate_stage_report")
        stage_names.add(stage["stage"])
        require(all(type(stage[k]) is int and stage[k] >= 0 for k in ("failures", "retries", "calls", "review_count")),
            "nonnegative_stage_counts_required")
        require(all(stage[k] is None or type(stage[k]) in (int, float) and math.isfinite(stage[k]) and stage[k] >= 0
            for k in ("elapsed_seconds", "cpu_seconds", "review_active_seconds")), "honest_available_or_null_timing_required")
    require(stage_names == {"converters", "ocr", "source_review", "adjudication", "candidate_review", "evaluation"},
        "all_execution_and_review_stage_reports_required")
    rows, image_counts = {}, {"image_proposals": 0, "corrected_image_proposals": 0, "raw_image_matches_final": 0}
    arm_rows = {method: {} for method in METHODS}
    for sid in sorted(evaluated_ids):
        case = execution["cases"][sid]
        exact(case, {"assessments", "selected", "route", "image_evidence", "native_failure", "converter_inputs", "producer_receipts", "failure_history"},
                "case_execution_contract_required")
        require(set(case["assessments"]) == set(METHODS), "all_four_genuine_outputs_required")
        require(isinstance(case["failure_history"], list), "original_execution_failures_must_be_preserved")
        predictions = {method: store.json(descriptor) for method, descriptor in case["assessments"].items()}
        selected = store.json(case["selected"])
        reference = references[sid]["reference"]
        tags = selection["screen"].get(sid, {}).get("strata", [])
        require(not ("partial" in tags and reference["status"] != "partial_on_page_one"
            or "absent" in tags and reference["status"] != "no_abstract_text"), "screen_and_reference_scope_disagree")
        native, identity = natives[sid], source_hashes[sid]
        if native is not None:
            import fitz
            with fitz.open(stream=store.bytes(sources[sid]["assets"]["page"]), filetype="pdf") as page:
                size = [page[0].rect.width, page[0].rect.height]
            replay_converters(store, case, predictions=predictions, source_identity=identity, native=native,
                page_size=size, access=access, execution=execution, times=times)
        else:
            require(case["converter_inputs"] == {} and case["producer_receipts"] == {},
                "unavailable_source_cannot_claim_converter_execution")
        for prediction in [*predictions.values(), selected]:
            verify_assessment(prediction)
            require(type(prediction.get("proposal")) is bool and type(prediction.get("physical_page")) is int
                and prediction.get("physical_page") == 1
                and prediction.get("eligible_for_jev") is False and prediction.get("verified_admission") is False,
                "assessment_scope_or_admission_mismatch")
            if native is None:
                require(not prediction["proposal"] and not prediction.get("text") and not prediction.get("spans"),
                        "unavailable_source_cannot_propose")
            else:
                require(prediction.get("source_sha256") == identity["source"] and prediction.get("page_sha256") == identity["page"],
                        "assessment_source_binding_mismatch")
                if prediction.get("representation") != "reviewed-image-transcription-v1":
                    require(prediction.get("native_sha256") == digest_value(native) or prediction.get("status") in {"error", "truncated"}
                        and not prediction["proposal"] and not prediction.get("spans"), "assessment_native_binding_mismatch")
                    validate_source_spans(prediction.get("spans", []), native)
        if reference["status"] in RESOLVED and native is None:
            raise EvidenceError("unavailable_reference_must_remain_unresolved")
        if native is not None and reference["status"] == "complete":
            review = reference.get("fidelity_review", {})
            require(review.get("reviewer") == bundle["roles"]["source_reviewer"]["principal"]
                and review.get("reviewer_kind") == "assistant" and review.get("independent_review") is False
                and review.get("source_before_predictions") is True
                and review.get("source_sha256") == identity["source"] and review.get("page_sha256") == identity["page"]
                and instant(review["reviewed_at"]) < times["references_frozen"], "source_first_attributed_reference_required")
            require(all(review.get(d, {}).get("status") == "pass" for d in ("notation", "boundary")),
                "uncertain_reference_extent_or_notation_must_remain_unresolved")
            _review_spans(review, native, reference["text"])
        original = predictions[PRIMARY]
        if case["route"] == "native_or_hold":
            require(selected == original and case["image_evidence"] is None and case["native_failure"] is None,
                    "unmeasured_native_selection_or_fallback")
        elif case["route"] == "image_review":
            require(native is not None and selected["proposal"] is True, "accepted_typed_image_required")
            if original["proposal"]:
                require(config.get("native_failure_policy") == "source-bound-failed-native-image-replacement-v1",
                    "native_replacement_policy_not_enabled")
                failure = native_failure(store, case["native_failure"], original=original, source=sources[sid]["assets"],
                    roles=bundle["roles"], times=times)
                if failure["dimension"] in {"notation", "reading_order"}:
                    require(compare_notation(original["text"], selected["text"])["status"] != "pass", "known_bad_transcription_not_repaired")
            else:
                require(case["native_failure"] is None, "held_native_does_not_need_fabricated_failure")
            image = _image_candidate(store, case["image_evidence"], source=sources[sid]["assets"], selected=selected,
                original=original, reference=reference, code=image_code, image_access=access["image_ocr"],
                roles=bundle["roles"], times=times, at=at)
            image_counts["image_proposals"] += 1
            image_counts["corrected_image_proposals"] += image["corrected"]
            image_counts["raw_image_matches_final"] += image["raw_transcription_matches_final"]
        else:
            raise EvidenceError("unknown_or_unmeasured_selection_route")
        fidelity = evaluate_fidelity(selected, reference, evaluated_at=at)
        correct = fidelity["verified_correct_proposal"] is True and all(
            fidelity.get(d, {}).get("status") == "pass" for d in DIMENSIONS)
        rows[sid] = {"work_id": sid, "reference_status": reference["status"], "accepted": selected["proposal"],
            "strict_correct": correct, "route": case["route"], "fidelity_dimensions": {d:fidelity.get(d, {}).get("status") for d in DIMENSIONS},
            "automatic_proposed": original["proposal"], "automatic_verified": evaluate_fidelity(original, reference, evaluated_at=at)["verified_correct_proposal"]}
        for method, prediction in predictions.items():
            measured = evaluate_fidelity(prediction, reference, evaluated_at=at)
            arm_rows[method][sid] = {"work_id": sid, "reference_status": reference["status"],
                "accepted": prediction["proposal"], "strict_correct": measured["verified_correct_proposal"] is True
                    and all(measured.get(d, {}).get("status") == "pass" for d in DIMENSIONS),
                "route": "native_automatic", "assessment_sha256": prediction["assessment_sha256"],
                "status": prediction["status"], "fidelity_dimensions": {d:measured.get(d, {}).get("status") for d in DIMENSIONS}}
    report = statistical_gates([rows[sid] for sid in selection["primary"]], [rows[sid] for sid in selection["challenge"]], strata)
    require(verify_regression(store.root, bundle["regression"]["relative"], bundle["regression"]["sha256"],
        configuration_relative=bundle["configuration"]["relative"], source_map_relative=bundle["source_map"]["relative"],
        runtime_lock=runtime_lock) == regression, "regression_prerequisite_changed_during_qualification")
    store.recheck()
    require(evaluator_identity() == code and code_identity() == image_code and runtime_receipt(runtime_lock) == runtime,
            "code_or_runtime_changed_during_evaluation")
    authored = bundle["execution_mode"] == "AUTHORED_CONTRACT_TEST"
    return {**report, "version": VERSION, "study_id": bundle["study_id"],
        "qualification_pass": report["status"] == "PASS" and not authored,
        "status": "AUTHORED_CONTRACT_PASS_NOT_QUALIFICATION" if report["status"] == "PASS" and authored else report["status"],
        "review_policy": REVIEW_POLICY, "independent_human_qualification": False, "graph_qualification_registered": False,
        "graph_writes": 0, "paid_calls": 0, "review_audit_ids": audit_ids,
        "screened_exposure_count": 1200, "all_sampled_case_count": len(rows), "image_counts": image_counts,
        "measured_arms": {method: {"selection": "automatic_primary_before_review" if method == PRIMARY else "diagnostic_only",
            "primary": summarize([values[sid] for sid in selection["primary"]]),
            "challenge": {name: summarize([values[sid] for sid in members]) for name, members in strata.items()},
            "cases": values} for method, values in arm_rows.items()},
        "cases": rows, "input_hashes": store.seen, "code_sha256": code, "image_code_sha256": image_code,
        "runtime": runtime, "evaluated_at": at, "postrun_recheck": "PASS",
        "invocation": {"bundle_descriptor": bundle_descriptor, "expected_preregistration_sha256": expected_preregistration_sha256},
        "claim": "Internally attributed source-first study only. The generic graph QualificationRegistry is unchanged."}


def _trust_identity(trust):
    """Observe current application authority without copying or enrolling it."""
    require(isinstance(trust, TrustStore), "external_review_trust_required")
    issuers = {}
    for issuer, policy in sorted(trust._issuers.items()):
        values = asdict(policy)
        issuers[issuer] = {key: value.hex() if isinstance(value, bytes) else
            sorted(value) if isinstance(value, (set, frozenset)) else value for key, value in values.items()}
    return digest_value({"issuers": issuers, "revoked": sorted(trust._revoked)})


def evaluate(root, bundle_descriptor, *, expected_preregistration_sha256, trust: TrustStore,
             at=None, runtime_lock=DEFAULT_RUNTIME_LOCK):
    """Fail closed; expected raw hashes and issuer enrollment come from the caller.

    This function neither enrolls trust keys nor creates a signed review claim.
    It opens no selected source before the existing exact #19 verifier passes.
    """
    at = at or datetime.now(timezone.utc).isoformat()
    try:
        bundle_descriptor = deepcopy(bundle_descriptor)
        trust_identity = _trust_identity(trust)
        require(instant(at) <= datetime.now(timezone.utc), "evaluation_time_cannot_be_future")
        result = _evaluate(root, bundle_descriptor, expected_preregistration_sha256=expected_preregistration_sha256,
            trust=trust, at=at, runtime_lock=runtime_lock)
        require(_trust_identity(trust) == trust_identity, "review_trust_changed_during_evaluation")
        return result
    except (EvidenceError, ContractError, OSError, RuntimeError, ValueError, KeyError, TypeError, AttributeError, IndexError, OverflowError) as error:
        reason = str(error) if isinstance(error, EvidenceError) else "missing_or_invalid_bound_study_evidence"
        return {"version": VERSION, "status": "BLOCKED", "reason": reason, "qualification_pass": False,
            "independent_human_qualification": False, "graph_qualification_registered": False,
            "graph_writes": 0, "paid_calls": 0}


def _public_summary(result, private_hash):
    """Deterministic redaction; the public claim is derived from the pinned result."""
    excluded = {"input_hashes", "cases", "review_audit_ids", "study_id", "invocation"}
    public = {key: value for key, value in result.items() if key not in excluded}
    if "measured_arms" in public:
        public["measured_arms"] = {method: {key: value for key, value in arm.items() if key != "cases"}
            for method, arm in public["measured_arms"].items()}
    public["private_evaluation_sha256"] = private_hash
    return public


def publish(root, output_relative, result, *, expected_preregistration_sha256=None, trust=None,
            runtime_lock=DEFAULT_RUNTIME_LOCK):
    """Recompute under external trust before publishing any evidence-bearing claim."""
    from src.parallel_source_v4.image_ocr import code_identity
    result = deepcopy(result)
    root = Path(root).resolve()
    output = child(root, output_relative)
    require(output != root and not output.exists(), "fresh_evaluation_output_directory_required")
    require(result.get("version") == VERSION and result.get("graph_qualification_registered") is False,
            "paper_evaluation_result_required")
    store = None
    if "input_hashes" not in result:
        exact(result, {"version", "status", "reason", "qualification_pass", "independent_human_qualification",
            "graph_qualification_registered", "graph_writes", "paid_calls"}, "unverified_publication_result_rejected")
        require(result["status"] == "BLOCKED" and result["qualification_pass"] is False
            and result["independent_human_qualification"] is False and result["graph_writes"] == 0 and result["paid_calls"] == 0
            and isinstance(result["reason"], str) and re.fullmatch(r"[a-z0-9_]+", result["reason"]),
            "unverified_publication_result_rejected")
    else:
        require(isinstance(trust, TrustStore) and isinstance(expected_preregistration_sha256, str)
            and SHA.fullmatch(expected_preregistration_sha256), "external_publication_trust_anchors_required")
        invocation = result.get("invocation", {})
        require(invocation.get("expected_preregistration_sha256") == expected_preregistration_sha256,
            "publication_preregistration_trust_anchor_mismatch")
        trust_identity = _trust_identity(trust)
        rebuilt = evaluate(root, **invocation, trust=trust, at=result.get("evaluated_at"), runtime_lock=runtime_lock)
        require(digest_value(rebuilt) == digest_value(result), "evaluation_result_changed_before_publication")
        require(_trust_identity(trust) == trust_identity, "review_trust_changed_before_publication")
        store = Artifacts(root)
        for relative, sha in result["input_hashes"].items():
            path = child(root, relative)
            require(output != path and output not in path.parents and path not in output.parents,
                    "evaluation_output_overlaps_input")
            store.verify({"relative": relative, "sha256": sha})
        require(evaluator_identity() == result["code_sha256"] and code_identity() == result["image_code_sha256"]
            and runtime_receipt(runtime_lock) == result["runtime"], "evaluation_changed_before_publication")
    # Own one fresh publication directory; preserve attempted artifacts on any
    # failure. A completion marker is not sufficient without current replay.
    output.mkdir(parents=True, exist_ok=False)
    written = {}
    published = Artifacts(root)
    def record(name, value):
        sha = write_once(output/name, value)
        written[name] = sha
        published.verify({"relative": (output/name).relative_to(root).as_posix(), "sha256": sha})
        return sha
    def recheck():
        if store is not None:
            store.recheck()
            require(_trust_identity(trust) == trust_identity, "review_trust_changed_during_publication")
            require(evaluator_identity() == result["code_sha256"] and code_identity() == result["image_code_sha256"]
                and runtime_receipt(runtime_lock) == result["runtime"], "evaluation_changed_during_publication")
        published.recheck()
        require(not (output/"publication-invalidated.json").exists(), "publication_invalidated")
    try:
        private_hash = record("evaluation.json", result)
        public_hash = record("public-summary.json", _public_summary(result, private_hash))
        recheck()
        completion_hash = record("publication-complete.json", {"version": "paper-evaluation-publication-v1",
            "evaluation_sha256": private_hash, "public_summary_sha256": public_hash,
            "status": result["status"], "qualification_pass": result["qualification_pass"],
            "graph_qualification_registered": False})
        recheck()
    except Exception:
        marker = {"version": "paper-evaluation-publication-invalidation-v1", "status": "BLOCKED",
            "reason": "publication_write_or_final_integrity_check_failed", "qualification_pass": False,
            "graph_qualification_registered": False, "attempted_artifact_sha256": written}
        invalidation_hash = write_once(output/"publication-invalidated.json", marker)
        return {"status": "BLOCKED", "qualification_pass": False, "graph_qualification_registered": False,
            "reason": marker["reason"], "invalidation_sha256": invalidation_hash,
            "attempted_artifact_sha256": written}
    return {"status": result["status"], "qualification_pass": result["qualification_pass"],
        "private_evaluation_sha256": private_hash, "public_summary_sha256": public_hash,
        "publication_complete_sha256": completion_hash,
        "graph_qualification_registered": False}


def verify_published(root, receipt_descriptor, *, expected_preregistration_sha256, trust,
                     runtime_lock=DEFAULT_RUNTIME_LOCK):
    """Recompute the complete study before trusting a privately pinned PASS."""
    receipt_descriptor = deepcopy(receipt_descriptor)
    trust_identity = _trust_identity(trust)
    store = Artifacts(root)
    directory = child(store.root, receipt_descriptor["relative"]).parent
    require(not (directory/"publication-invalidated.json").exists(), "publication_invalidated")
    recorded = store.json(receipt_descriptor)
    require(recorded.get("status") == "PASS" and recorded.get("qualification_pass") is True,
            "nonpassing_or_authored_study_cannot_qualify")
    marker_relative = (directory/"publication-complete.json").relative_to(store.root).as_posix()
    marker_path = child(store.root, marker_relative)
    require(marker_path.is_file(), "publication_completion_required")
    raw = marker_path.read_bytes()
    store.seen[marker_relative] = hashlib.sha256(raw).hexdigest()
    marker = store.parse(raw)
    exact(marker, {"version", "evaluation_sha256", "public_summary_sha256", "status", "qualification_pass",
        "graph_qualification_registered"}, "publication_completion_contract_required")
    require(marker["version"] == "paper-evaluation-publication-v1"
        and marker["evaluation_sha256"] == receipt_descriptor["sha256"] and marker["status"] == "PASS"
        and marker["qualification_pass"] is True and marker["graph_qualification_registered"] is False,
        "publication_completion_identity_mismatch")
    public = store.json({"relative": (directory/"public-summary.json").relative_to(store.root).as_posix(),
        "sha256": marker["public_summary_sha256"]})
    require(digest_value(public) == digest_value(_public_summary(recorded, receipt_descriptor["sha256"])),
            "public_summary_does_not_match_private_evaluation")
    invocation = recorded["invocation"]
    require(invocation["expected_preregistration_sha256"] == expected_preregistration_sha256,
            "preregistration_trust_anchor_mismatch")
    current = evaluate(root, **invocation, trust=trust, at=recorded["evaluated_at"], runtime_lock=runtime_lock)
    require(digest_value(current) == digest_value(recorded), "qualification_evidence_changed_after_publication")
    store.recheck()
    require(_trust_identity(trust) == trust_identity, "review_trust_changed_during_verification")
    require(not (directory/"publication-invalidated.json").exists(), "publication_invalidated")
    return {"status": "PASS", "qualification_pass": True, "evaluation_sha256": receipt_descriptor["sha256"],
        "review_policy": REVIEW_POLICY, "independent_human_qualification": False, "graph_qualification_registered": False}
