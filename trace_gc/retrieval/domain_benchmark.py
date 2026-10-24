"""Measured domain workloads; evidence origin is never inferred from timing results.

The application supplies the worker factory, corpus provenance and requirements.
The bundled driver deliberately supplies fabricated data, not deployment evidence.
No benchmark result grants publication or production acceptance.
"""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import asdict, dataclass
import math
import time
from typing import Any, Callable
from ..canonical import digest
from ..errors import require
from .contracts import validate_query


@dataclass(frozen=True)
class WorkloadRequirements:
    decision_owner: str
    evidence_origin: str
    corpus_manifest_hash: str
    isolation_requirements: tuple[str, ...]
    isolation_reviewed: bool
    p95_latency_ms: float
    p99_latency_ms: float
    concurrency: int
    repeats: int

    def __post_init__(self):
        require(bool(self.decision_owner) and self.evidence_origin in {"SYNTHETIC", "REPRESENTATIVE_REVIEWED"},
                "BENCHMARK_PROTOCOL", "explicit owner and evidence origin required")
        require(len(self.corpus_manifest_hash) == 64 and all(c in "0123456789abcdef" for c in self.corpus_manifest_hash),
                "BENCHMARK_PROTOCOL", "exact corpus manifest hash required")
        require(type(self.isolation_reviewed) is bool and all(isinstance(x, str) and x for x in self.isolation_requirements),
                "BENCHMARK_PROTOCOL", "explicit isolation requirements and review state required")
        require(all(type(x) in {int, float} and math.isfinite(x) and x > 0 for x in (self.p95_latency_ms, self.p99_latency_ms)),
                "BENCHMARK_PROTOCOL", "finite positive predeclared latency objectives required")
        require(self.p99_latency_ms >= self.p95_latency_ms and type(self.concurrency) is int and
                1 <= self.concurrency <= 32 and type(self.repeats) is int and 1 <= self.repeats <= 1000,
                "BENCHMARK_PROTOCOL", "ordered SLOs and bounded concurrency/repetition required")


def percentiles(samples: list[float]) -> dict[str, float | None]:
    """Nearest-rank percentiles. Empty samples are unknown, never zero latency."""
    require(all(type(x) in {int, float} and math.isfinite(x) and x >= 0 for x in samples),
            "BENCHMARK_METRIC", "finite nonnegative measurements required")
    values = sorted(samples)
    return {f"p{p}": values[max(0, math.ceil(p * len(values) / 100) - 1)] if values else None for p in (50, 95, 99)}


def graph_shape(snapshot: dict[str, Any]) -> dict[str, Any]:
    degrees = {n: 0 for n in snapshot["nodes"]}
    active = [f for f in snapshot["assertions"].values() if f["active"]]
    for f in active:
        for n in (f["assertion"]["subject"], f["assertion"]["object"]):
            degrees[n] = degrees.get(n, 0) + 1
    total = sum(degrees.values())
    top = sum(sorted(degrees.values(), reverse=True)[:max(1, math.ceil(len(degrees) / 100))])
    return {"nodes": len(degrees), "active_assertions": len(active), "maximum_degree": max(degrees.values(), default=0),
            "top_one_percent_degree_share": top / total if total else 0.0}


def run_workload(worker_factory: Callable[[], Any], cases: list[dict[str, Any]],
                 requirements: WorkloadRequirements) -> dict[str, Any]:
    """Each worker owns its connection/retriever and closes it, including on failure.

    Workers implement execute(query)->metrics and close(). They must connect to
    the same declared authority when testing shared-storage concurrency. No
    untrusted import path or model-supplied backend is executed by this function.
    """
    require(bool(cases) and len(cases) <= 128 and len({c["id"] for c in cases}) == len(cases),
            "BENCHMARK_PROTOCOL", "unique bounded query cases required")
    for case in cases:
        require(set(case) == {"id", "query", "expected_evidence_ids"} and bool(case["id"]) and
                type(case["expected_evidence_ids"]) is list, "BENCHMARK_PROTOCOL", "explicit case/quality labels required")
        validate_query(case["query"])
    requirements_json = asdict(requirements)
    requirements_json["isolation_requirements"] = list(requirements.isolation_requirements)
    protocol = {"requirements": requirements_json, "cases": deepcopy(cases),
                "percentile_method": "nearest-rank", "measures": "full-retriever-call",
                "quality_unit": "manually-declared-required-evidence-recall"}
    # Seal requirements before executing any measurement. No threshold tuning to results.
    protocol_hash = digest(protocol)
    def work(worker_id):
        worker = worker_factory()
        rows = []
        try:
            for repeat in range(requirements.repeats):
                for case in cases:
                    started = time.perf_counter()
                    measured = worker.execute(deepcopy(case["query"]))
                    elapsed = (time.perf_counter() - started) * 1000
                    selected = set(measured.pop("selected_evidence_ids"))
                    wanted = set(case["expected_evidence_ids"])
                    rows.append({"worker": worker_id, "repeat": repeat, "case_id": case["id"],
                                 "latency_ms": elapsed, "missing_required_evidence_count": len(wanted - selected),
                                 "required_evidence_count": len(wanted), "selected_evidence_count": len(selected),
                                 **measured})
            return rows
        finally:
            worker.close()
    start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=requirements.concurrency) as executor:
        groups = list(executor.map(work, range(requirements.concurrency)))
    elapsed = time.perf_counter() - start
    rows = [r for group in groups for r in group]
    per_case = {}
    for case in cases:
        selected = [r for r in rows if r["case_id"] == case["id"]]
        wanted = sum(r["required_evidence_count"] for r in selected)
        missing = sum(r["missing_required_evidence_count"] for r in selected)
        per_case[case["id"]] = {"samples": len(selected), "latency_ms": percentiles([r["latency_ms"] for r in selected]),
                               "required_evidence_recall": (wanted - missing) / wanted if wanted else None,
                               "missed_required_evidence": missing,
                               "cache_hits": sum(int(r.get("cache_hit", False)) for r in selected),
                               "partial_responses": sum(r.get("response_status") == "PARTIAL" for r in selected)}
    latency = percentiles([r["latency_ms"] for r in rows])
    return {"version": "domain-workload-v1", "protocol": protocol, "protocol_hash": protocol_hash,
            "evidence_origin": requirements.evidence_origin, "queries": len(rows), "duration_seconds": elapsed,
            "throughput_queries_per_second": len(rows) / elapsed, "latency_ms": latency, "per_case": per_case,
            "rows": rows, "latency_slo_met": latency["p95"] <= requirements.p95_latency_ms and latency["p99"] <= requirements.p99_latency_ms,
            "production_qualified": False, "placement_decision": "REQUIRES_OWNER_REVIEW",
            "limitations": ["Measurements do not establish corpus representativeness or review authority.",
                            "Synthetic labels cannot settle production storage placement.",
                            "No distributed performance or automatic write qualification is inferred."]}
