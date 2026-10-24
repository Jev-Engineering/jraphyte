"""Measured query/write workloads with explicit synthetic/representative boundaries.

The default command runs only fabricated data and disposable reference databases.
Applications may reuse the recorder with representative cases and their existing
trusted services. The recorder never creates permissions, approvals, or signers.
"""
from __future__ import annotations

from collections import Counter
from contextlib import contextmanager
import re
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import dataclass, field
import math
from pathlib import Path
import platform
import tempfile
import threading
from time import perf_counter_ns
from typing import Any, Callable

from ..canonical import digest, loads, write
from ..domain_publication import classification_identity, empty_projection
from ..errors import ContractError, require
from .telemetry import measure_retrieval

VERSION = "research-domain-workloads-v1.1"


def percentiles(values: list[float]) -> dict[str, float | int | None]:
    """Nearest-rank quantiles, including small-sample count (not confidence bounds)."""
    require(all(type(x) in (int, float) and math.isfinite(x) and x >= 0 for x in values),
            "WORKLOAD_METRIC", "finite nonnegative observations required")
    ordered = sorted(values)
    result: dict[str, Any] = {"count": len(ordered)}
    for label, p in (("p50", .5), ("p95", .95), ("p99", .99)):
        result[label] = ordered[max(0, math.ceil(p * len(ordered)) - 1)] if ordered else None
    result["maximum"] = max(ordered) if ordered else None
    return result


def topology(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Actual active original-assertion degree, not canonicalized edge cardinality.

    Administrative telemetry can reveal graph size and belongs behind a separate
    operational access boundary. It is not emitted into end-user query contexts.
    """
    degree = Counter({ref: 0 for ref in snapshot["nodes"]})
    active = 0
    for fact in snapshot["assertions"].values():
        if fact["active"]:
            active += 1
            degree.update({fact["assertion"]["subject"], fact["assertion"]["object"]})
    values = sorted(degree.values())
    n, total = len(values), sum(values)
    gini = (2 * sum((i + 1) * value for i, value in enumerate(values)) / (n * total) - (n + 1) / n) if n and total else 0.0
    top = max(1, math.ceil(n * .01))
    return {"nodes": n, "active_original_assertions": active, "degree": percentiles(values),
            "degree_gini": gini, "top_one_percent_node_degree_share": sum(values[-top:]) / total if total else 0.0,
            "degree_definition": "incident active original assertions; a self-loop is counted once"}


@dataclass(frozen=True)
class QueryCase:
    case_id: str
    request: dict[str, Any]
    relevant_evidence_ids: frozenset[str] = field(default_factory=frozenset)
    required_contradictions: tuple[frozenset[str], ...] = ()
    forbidden_source_ids: frozenset[str] = field(default_factory=frozenset)
    pair_id: str | None = None

    def __post_init__(self):
        require(bool(self.case_id), "WORKLOAD_CASE", "stable case ID required")
        require(all(len(pair) >= 2 for pair in self.required_contradictions),
                "WORKLOAD_CASE", "a contradiction expectation needs both evidence sides")


class WorkloadRecorder:
    """Bounded thread-safe telemetry sink. No embedded query/source text or secrets."""
    def __init__(self, *, input_manifest: dict[str, Any], maximum_samples: int = 100000):
        require(type(maximum_samples) is int and maximum_samples > 0, "WORKLOAD_METRIC", "positive sample bound required")
        require(input_manifest.get("data_kind") in {"SYNTHETIC", "REPRESENTATIVE_CANDIDATE"} and
                all(isinstance(input_manifest.get(k), str) and input_manifest[k] for k in
                    ("corpus_hash", "labels_hash", "protocol_id")),
                "WORKLOAD_INPUT", "explicit corpus, label and protocol provenance required")
        self.input_manifest = deepcopy(input_manifest)
        require(all(re.fullmatch(r"[0-9a-f]{64}", input_manifest[k]) for k in ("corpus_hash", "labels_hash")),
                "WORKLOAD_INPUT", "corpus and labels must be bound to SHA-256 digests")
        self.maximum_samples = maximum_samples
        self._reserved = 0
        self.samples: list[dict[str, Any]] = []
        self._lock = threading.RLock()

    def append(self, sample: dict[str, Any]) -> None:
        with self._lock:
            require(len(self.samples) + self._reserved < self.maximum_samples, "WORKLOAD_LIMIT", "telemetry sample bound reached")
            self.samples.append(deepcopy(sample))

    @contextmanager
    def slot(self):
        # Reserve BEFORE work: exhausted telemetry capacity must not turn a
        # successfully committed publication into a reporting exception afterward.
        with self._lock:
            require(len(self.samples) + self._reserved < self.maximum_samples,
                    "WORKLOAD_LIMIT", "telemetry sample bound reached before execution")
            self._reserved += 1
        recorder = self
        class Slot:
            submitted = False
            def append(self, sample):
                with recorder._lock:
                    require(not self.submitted, "WORKLOAD_METRIC", "one measurement per reserved operation")
                    recorder.samples.append(deepcopy(sample))
                    recorder._reserved -= 1
                    self.submitted = True
        slot = Slot()
        try:
            yield slot
        finally:
            with self._lock:
                if not slot.submitted:
                    self._reserved -= 1

    def report(self) -> dict[str, Any]:
        with self._lock:
            require(self._reserved == 0, "WORKLOAD_INCOMPLETE", "operations are still being measured")
            samples = deepcopy(self.samples)
        queries = [s for s in samples if s["kind"] == "QUERY"]
        writes = [s for s in samples if s["kind"] == "PUBLICATION"]
        groups = {}
        for operation in {s["operation"] for s in samples}:
            rows = [s for s in samples if s["operation"] == operation]
            groups[operation] = {"latency_ms": percentiles([s["elapsed_ms"] for s in rows]),
                                 "outcomes": dict(Counter(s["outcome"] for s in rows))}
        # Costs include failed work. Quality is meaningful only for returned
        # contexts; a denial is not a zero-error/zero-recall retrieval success.
        successful = [q for q in queries if q.get("completed", q["outcome"] in {"COMPLETE", "PARTIAL", "EMPTY"})
                      and isinstance(q.get("quality"), dict)]
        measured = [q for q in queries if "measurements" in q and "cache_delta" in q]
        quality = {}
        for scoped in (False, True):
            rows = [q for q in successful if q["domain_scoped"] == scoped]
            recalls = [q["quality"]["evidence_recall"] for q in rows if q["quality"]["evidence_recall"] is not None]
            quality["scoped" if scoped else "unscoped"] = {
                "queries": len(rows), "labeled_queries": len(recalls),
                "mean_evidence_recall": sum(recalls) / len(recalls) if recalls else None,
                "missed_contradiction_pairs": sum(q["quality"]["missed_contradiction_pairs"] for q in rows),
                "forbidden_sources_returned": sum(q["quality"]["forbidden_sources_returned"] for q in rows)}
        paired = {}
        for pair_id in sorted({q["pair_id"] for q in successful if q["pair_id"] is not None}):
            paired[pair_id] = {}
            for scoped in (False, True):
                rows = [q for q in successful if q["pair_id"] == pair_id and q["domain_scoped"] == scoped]
                recalls = [q["quality"]["evidence_recall"] for q in rows if q["quality"]["evidence_recall"] is not None]
                paired[pair_id]["scoped" if scoped else "unscoped"] = {
                    "queries": len(rows), "latency_ms": percentiles([q["elapsed_ms"] for q in rows]),
                    "mean_evidence_recall": sum(recalls) / len(recalls) if recalls else None,
                    "missed_contradiction_pairs": sum(q["quality"]["missed_contradiction_pairs"] for q in rows)}
        hops = Counter()
        for row in measured:
            hops.update(row["measurements"]["domain_hops"])
        committed = [w for w in writes if w["outcome"] == "COMMITTED"]
        cross = sum(w["write_domains"]["cross_domain_batch"] for w in committed)
        return {"version": VERSION, "status": "MEASURED_NOT_QUALIFIED", "input_manifest": self.input_manifest,
                "environment": {"python": platform.python_version(), "platform": platform.platform()},
                "sample_count": len(samples), "operations": dict(sorted(groups.items())),
                "query_latency_ms": percentiles([q["elapsed_ms"] for q in queries]),
                "query_outcomes": {"completed": len(successful), "rejected_or_error": len(queries) - len(successful)},
                "telemetry_coverage": {"queries": len(queries), "measured_queries": len(measured),
                                       "unmeasured_queries": len(queries) - len(measured)},
                "publication_latency_ms": percentiles([w["elapsed_ms"] for w in writes]),
                "committed_publication_latency_ms": percentiles([w["elapsed_ms"] for w in committed]),
                "acl_elapsed_ms": percentiles([q["measurements"]["acl_elapsed_ms"] for q in measured]),
                "index_validation_ms": percentiles([q["adapter_metrics"]["validation_seconds"] * 1000
                    for q in measured if "validation_seconds" in q.get("adapter_metrics", {})]),
                "authority_audit_ms": percentiles([q["adapter_metrics"]["authority_audit_seconds"] * 1000
                    for q in measured if "authority_audit_seconds" in q.get("adapter_metrics", {})]),
                "cache": {name: sum(q["cache_delta"][name] for q in measured)
                          for name in ("hits", "misses", "invalidations", "evictions")},
                "domain_hops": dict(sorted(hops.items())), "quality": quality, "paired_comparison": paired,
                "writes": {"committed": len(committed), "cross_domain_batches": cross,
                           "cross_domain_batch_rate": cross / len(committed) if committed else None,
                           "replayed": sum(w["outcome"] == "REPLAYED" for w in writes),
                           "rejected": sum(w["outcome"] not in {"COMMITTED", "REPLAYED"} for w in writes)},
                "qualification": {"representativeness": "NOT_ESTABLISHED", "independent_labels": "NOT_ESTABLISHED",
                                  "deployment_slos": "NOT_EVALUATED", "storage_decision_owner": "NOT_SELECTED",
                                  "production_backend": "NOT_QUALIFIED"},
                "limitations": ["No synthetic node count or latency threshold authorizes physical sharding.",
                    "Nearest-rank quantiles have no statistical confidence claim; inspect sample counts.",
                    "ACL/cache/traversal costs include recorded rejections and operational errors; quality excludes them.",
                    "Missing telemetry on imported legacy rows is reported as unmeasured, not imputed as zero cost.",
                    "Cross-domain hops count executed path/community/required-closure transitions, including revalidation; not network RPCs.",
                    "Write latency excludes caller plan preparation/signing and includes trusted publish validation/commit.",
                    "Hash-bound representative-candidate metadata is not an approval or independent qualification."],
                "samples": samples}


def measure_query(retriever: Any, case: QueryCase, recorder: WorkloadRecorder) -> str:
    with recorder.slot() as slot:
        return _measure_query(retriever, case, slot)


def _measure_query(retriever: Any, case: QueryCase, recorder: Any) -> str:
    # Hold the service's existing lock across its telemetry snapshot as well as
    # the request. Different services/adapters/connections may still run concurrently.
    with retriever._lock:
        before = {name: getattr(retriever.cache, name) for name in ("hits", "misses", "invalidations", "evictions")}
        started = perf_counter_ns()
        result_id = None
        # Malformed requests still need failure telemetry. Hashing a NaN or
        # invalid Unicode must not replace the retriever's original exception.
        try:
            request_hash = digest(case.request)
            request_hash_status = "HASHED"
        except ContractError:
            request_hash = None
            request_hash_status = "UNAVAILABLE_NONCANONICAL_REQUEST"
        with measure_retrieval() as measurements:
            try:
                result_id = retriever.retrieve(case.request)
                result = retriever.catalog.get(result_id, "retrieval-result")
                context = retriever.catalog.get(result["graph_context_id"], "graph-context")
                outcome = result["status"]
            except Exception as exc:
                # Preserve the exact exception for the caller. Do not log its
                # message, stack, provider response, or any query/source text.
                recorder.append({"kind": "QUERY", "case_id": case.case_id, "pair_id": case.pair_id,
                    "operation": "query:rejected", "request_hash": request_hash, "request_hash_status": request_hash_status,
                    "outcome": exc.code if isinstance(exc, ContractError) else "ERROR",
                    "completed": False, "error_type": type(exc).__name__,
                    "domain_scoped": case.request.get("research_domain_scope") is not None,
                    "elapsed_ms": (perf_counter_ns() - started) / 1_000_000,
                    "graph_version": None, "classification_identity": None, "quality": None,
                    "adapter_metrics": deepcopy(retriever.last_read_metrics),
                    "measurements": measurements.as_dict(),
                    "cache_delta": {name: getattr(retriever.cache, name) - previous for name, previous in before.items()}})
                raise
        elapsed = (perf_counter_ns() - started) / 1_000_000
        evidence = set(context["selected_evidence_ids"])
        sources = {s for item in context["items"] for s in item["source_ids"]}
        scope = case.request.get("research_domain_scope")
        sample = {"kind": "QUERY", "case_id": case.case_id, "pair_id": case.pair_id,
            "operation": "query:" + ("scoped:" if scope else "unscoped:") + "+".join(case.request["retrieval_strategy"]),
            "request_hash": request_hash, "request_hash_status": request_hash_status, "outcome": outcome, "elapsed_ms": elapsed, "domain_scoped": scope is not None,
            "completed": True, "error_type": None,
            "graph_version": context["graph_version"], "classification_identity": context["classification_identity"],
            "adapter_metrics": deepcopy(retriever.last_read_metrics), "measurements": measurements.as_dict(),
            "cache_delta": {name: getattr(retriever.cache, name) - previous for name, previous in before.items()},
            "quality": {"evidence_recall": len(evidence & case.relevant_evidence_ids) / len(case.relevant_evidence_ids)
                        if case.relevant_evidence_ids else None,
                        "missed_contradiction_pairs": sum(not pair <= evidence for pair in case.required_contradictions),
                        "forbidden_sources_returned": len(sources & case.forbidden_source_ids)},
            "usage": deepcopy(result["usage"]), "selected_assertion_count": len(context["retrieved_edges"]),
            "selected_source_count": len(sources), "context_hash": retriever.catalog.hash(result["graph_context_id"])}
        recorder.append(sample)
        return result_id


def _source_labels(catalog, state, source_id):
    assignment_id = state.get("classifications", empty_projection())["assignments"].get(source_id)
    if assignment_id is None:
        return set()
    assignment = catalog.get(assignment_id, "classification-assignment")
    return {(assignment["taxonomy_hash"], label) for label in assignment["domain_ids"]}


def measure_publication(service: Any, catalog: Any, plan_id: str, recorder: WorkloadRecorder, *,
                        authorization: dict[str, Any], preflight: dict[str, Any]) -> dict[str, Any]:
    with recorder.slot() as slot:
        return _measure_publication(service, catalog, plan_id, slot, authorization=authorization, preflight=preflight)


def _measure_publication(service: Any, catalog: Any, plan_id: str, recorder: Any, *,
                        authorization: dict[str, Any], preflight: dict[str, Any]) -> dict[str, Any]:
    """No approving authority here: callers must supply the normal signed receipts."""
    started = perf_counter_ns()
    try:
        result = service.publish(catalog, plan_id, authorization=authorization, preflight=preflight)
    except ContractError as exc:
        recorder.append({"kind": "PUBLICATION", "operation": "publication", "plan_hash": catalog.hash(plan_id),
                         "outcome": exc.code, "elapsed_ms": (perf_counter_ns() - started) / 1_000_000})
        raise
    elapsed = (perf_counter_ns() - started) / 1_000_000
    event = result["event"]
    backend = service.backend
    with backend._lock:
        # Use the exact committed predecessor, not a racy earlier current-state read.
        if event["version"] == 1:
            before = loads(backend.db.execute("SELECT body FROM trace_meta WHERE id=1").fetchone()[0])["genesis_state"]
        else:
            before = loads(backend.db.execute("SELECT body FROM trace_journal WHERE version=?", (event["version"] - 1,)).fetchone()[0])["state_after"]
        after = event["state_after"]
        refs = set(catalog.get(plan_id, "plan")["source_epochs"])
        labels = set().union(*(_source_labels(catalog, state, ref) for ref in refs for state in (before, after))) if refs else set()
        multi = sum(len(_source_labels(catalog, after, ref)) > 1 for ref in refs)
    recorder.append({"kind": "PUBLICATION", "operation": "publication", "plan_hash": catalog.hash(plan_id),
        "outcome": "REPLAYED" if result["replayed"] else "COMMITTED", "elapsed_ms": elapsed,
        "event_hash": event["hash"], "graph_version": event["version"], "classification_identity": classification_identity(after),
        "write_domains": {"touched_sources": len(refs), "distinct_taxonomy_domain_pairs": len(labels),
                          "multi_domain_sources_after": multi, "cross_domain_batch": len(labels) > 1},
        "write_definition": "domain union of exact pre/post source assignments touched by the signed plan; retries are not writes"})
    return result


def run_query_workload(factory: Callable[[], Any], cases: list[QueryCase], recorder: WorkloadRecorder, *,
                       repetitions: int = 3, workers: int = 1) -> None:
    require(type(repetitions) is int and repetitions > 0 and type(workers) is int and 1 <= workers <= 32 and bool(cases),
            "WORKLOAD_INPUT", "nonempty cases, positive repetitions and 1..32 workers required")
    def execute(worker):
        retriever = factory()
        try:
            for _ in range(repetitions):
                for case in cases:
                    measure_query(retriever, case, recorder)
        finally:
            # Backend ownership is the factory/caller's responsibility. Closing an
            # arbitrary injected authority here could disrupt another reader/writer.
            pass
    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(execute, range(workers)))


def run_reference_domain_workload(output: str | Path | None = None, *, repetitions: int = 3, workers: int = 2) -> dict[str, Any]:
    """Offline synthetic smoke, not representative or deployment-like qualification."""
    from .contracts import query, RetrievalBudget
    from .domains import research_domain_scope
    from .fixtures import domain_corpus, demo_access, SCOPE as READ_SCOPE
    from .service import HybridRetriever, RetrievalCache
    from .store import InMemoryGraphAdapter, SQLiteGraphAdapter
    from ..backend import CompilerService
    from ..catalog import Catalog
    from ..compiler import now
    from ..demo import build_fixture, POLICY, POPULATION, SCOPE, RUN
    from ..domain_publication import classification_operation, migration_operation
    from ..domains import reference_taxonomy, create_assignment
    from ..plans import create_plan
    from ..trust import Signer, IssuerPolicy, authorize_plan

    fixture = domain_corpus()
    c = fixture["catalog"]
    snapshot = c.get(fixture["snapshot_id"])
    scope = research_domain_scope(c, fixture["taxonomy_id"], ["research:biology"])
    budget = RetrievalBudget(maximum_nodes=100, maximum_edges=100, maximum_source_spans=100,
                             maximum_tokens=150000, maximum_latency_ms=30000)
    cases = []
    for name, strategies, text, focus in (("lexical-conflict", ["LEXICAL"], "improves", []),
            ("vector-conflict", ["VECTOR"], "improves", []),
            ("path", ["PATH"], "Acme", ["Acme"]), ("community", ["COMMUNITY"], "Acme", ["Acme"])):
        relevant = frozenset({fixture["evidence"]["e-support"], fixture["evidence"]["e-refute"]}) if "conflict" in name else frozenset()
        contradictions = (relevant,) if relevant else ()
        for selection in (None, scope):
            case_id = name + (":scoped" if selection else ":unscoped")
            request = query(requesting_component="downstream-search", security_scope=READ_SCOPE, strategies=strategies,
                            text=text, focus_entities=focus, hop_limit=2, research_domain_scope=selection,
                            include_conflicts=True, budget=budget)
            cases.append(QueryCase(case_id, request, relevant, contradictions, pair_id=name))
    denied_case = QueryCase("acl-scope-rejected", query(requesting_component="downstream-search",
        security_scope="not-authorized:" + READ_SCOPE, strategies=["LEXICAL"], text="improves",
        research_domain_scope=scope, budget=budget))
    protocol_cases = [*cases, denied_case]
    recorder = WorkloadRecorder(input_manifest={"data_kind": "SYNTHETIC", "protocol_id": VERSION,
        "corpus_hash": c.hash(fixture["snapshot_id"]), "labels_hash": digest({case.case_id: {"relevant_evidence": sorted(case.relevant_evidence_ids),
            "required_contradictions": [sorted(pair) for pair in case.required_contradictions],
            "forbidden_sources": sorted(case.forbidden_source_ids), "pair_id": case.pair_id} for case in protocol_cases}),
        "query_protocol_hash": digest({case.case_id: case.request for case in protocol_cases}),
        "expected_query_rejections": {denied_case.case_id: "SECURITY_SCOPE"},
        "label_origin": "FABRICATED_FIXTURE_NOT_INDEPENDENT", "owner": None, "slo": None,
        "isolation_requirements": None, "concurrency": {"workers": workers, "repetitions_per_worker": repetitions,
          "kind": "same-process threads over immutable in-memory reference snapshots; not deployment-like concurrency"}})
    def factory():
        copied = Catalog(c.all())
        adapter = InMemoryGraphAdapter(copied, fixture["adapter"].snapshot_ids, fixture["adapter"].source_status)
        return HybridRetriever(adapter, catalog=copied, access_policy=fixture["retriever"].access_policy,
                               cache=RetrievalCache(capacity=4))
    run_query_workload(factory, cases, recorder, repetitions=repetitions, workers=workers)
    # One separately declared negative case exercises failure cost accounting.
    # It cannot be included as a successful quality observation or an access grant.
    try:
        measure_query(factory(), denied_case, recorder)
    except ContractError as exc:
        require(exc.code == "SECURITY_SCOPE", "WORKLOAD_EXPECTATION", "unexpected negative-case outcome")
    else:
        raise ContractError("WORKLOAD_EXPECTATION", "unauthorized scope was not rejected")
    # Separate actual SQLite write/read/cache-churn phase. Its timing is not mixed
    # into a claim that the in-memory graph represents a deployment database.
    with tempfile.TemporaryDirectory(prefix="trace-domain-workload-") as directory:
        f = build_fixture(Path(directory))
        try:
            f.publish()
            sqlite_inputs = {"snapshot_hash": f.catalog.hash(f.backend.snapshot(f.catalog)),
                "source_hashes": sorted(f.catalog.hash(ref) for ref in f.source_ids),
                "evidence_hashes": sorted(f.catalog.hash(ref) for ref in f.evidence_ids),
                "label_origin": "FABRICATED_FIXTURE_NOT_INDEPENDENT"}
            signer = Signer.ephemeral("workload-reviewer")
            f.trust.enroll(signer.issuer, IssuerPolicy(signer.public_key(), "synthetic-workload-reviewer",
                frozenset({"AUTHORIZATION"}), frozenset({"INITIALIZE_RESEARCH_DOMAINS", "SET_SOURCE_CLASSIFICATION"}),
                frozenset({SCOPE}), frozenset({"SYNTHETIC"}), can_review=True))
            taxonomy = reference_taxonomy()["body"]
            review = {"status": "APPROVED", "reviewer_id": "synthetic-workload-reviewer", "reviewed_at": now(),
                      "rationale": "Fabricated offline workload; not independently reviewed scientific labels"}
            taxonomy["review"] = review
            taxonomy_id = f.catalog.put("research-domain-taxonomy", taxonomy)
            service = CompilerService(f.backend, f.trust, f.validator, policy_version=POLICY, population=POPULATION,
                security_scope=SCOPE, publication_mode="REVIEWED", policy_hash=f.catalog.hash(f.policy_id),
                classification_enabled=True, classification_taxonomy_hashes=frozenset({f.catalog.hash(taxonomy_id)}))
            def publish(ops, key):
                pid = create_plan(f.catalog, run_id=RUN, snapshot_id=f.backend.snapshot(f.catalog), operations=ops,
                    security_scope=SCOPE, execution_mode="SYNTHETIC", idempotency_key=key,
                    policy_version=POLICY, source_status=f.backend.statuses())
                auth = authorize_plan(signer, f.catalog.get(pid), f.catalog.hash(pid), reviewed_by="synthetic-workload-reviewer")
                preflight = service.preflight(f.catalog, pid, reviewed=True)
                result = measure_publication(service, f.catalog, pid, recorder, authorization=auth, preflight=preflight)
                measure_publication(service, f.catalog, pid, recorder, authorization=auth, preflight=preflight)
                return result
            publish([migration_operation(operation_id="initialize", reason="Synthetic workload migration")], "workload-initialize")
            reader = HybridRetriever(SQLiteGraphAdapter(f.backend, audit_trust=f.trust), catalog=f.catalog,
                access_policy=demo_access(f.catalog, f.backend.snapshot(f.catalog), scope=SCOPE), cache=RetrievalCache(capacity=4))
            labels = research_domain_scope(f.catalog, taxonomy_id, ["research:biology"])
            request = query(requesting_component="downstream-search", security_scope=SCOPE, strategies=["LEXICAL"],
                text="Aster", research_domain_scope=labels, include_conflicts=False, budget=budget)
            previous = None
            for revision in range(1, max(3, repetitions) + 1):
                assignment = create_assignment(f.catalog, source_snapshot_id=f.source_ids[0], taxonomy_id=taxonomy_id,
                    domain_ids=["research:biology", "research:chemistry"] if revision % 2 else ["research:physics"],
                    classifier_id="synthetic-workload-reviewer", classifier_version=VERSION, review=review, supersedes=previous)
                publish([classification_operation(f.catalog, assignment, operation_id="assign")], "workload-assign-" + str(revision))
                previous = assignment
                expected = frozenset({f.evidence_ids[0]}) if revision % 2 else frozenset()
                case = QueryCase("sqlite-reclassification-" + str(revision), request, expected)
                measure_query(reader, case, recorder)
                measure_query(reader, case, recorder)
            historical_version = f.backend.state()["graph_version"]
            f.status_change(f.source_ids[0])
            # A historically matching assignment must still exclude the now-revoked source.
            revoked_case = QueryCase("sqlite-historical-current-revocation", {**request, "graph_version": historical_version,
                 "include_historical": True}, forbidden_source_ids=frozenset({f.source_ids[0]}))
            measure_query(reader, revoked_case, recorder)
            # Actual concurrent writers against TWO connections to ONE SQLite
            # authority. The stale loser is recorded, never treated as a write.
            from ..backend import SQLiteReferenceBackend
            concurrent = SQLiteReferenceBackend(f.backend.path, catalog=f.catalog, schema_id=f.schema_id,
                nodes=f.backend.state()["nodes"], sandbox=True)
            try:
                jobs = []
                for i, backend in enumerate((f.backend, concurrent)):
                    cc = Catalog(f.catalog.all())
                    assignment = create_assignment(cc, source_snapshot_id=f.source_ids[1], taxonomy_id=taxonomy_id,
                        domain_ids=["research:chemistry"] if i else ["research:physics"], classifier_id="synthetic-workload-reviewer",
                        classifier_version=VERSION, review=review)
                    pid = create_plan(cc, run_id=RUN, snapshot_id=backend.snapshot(cc),
                        operations=[classification_operation(cc, assignment, operation_id="concurrent-assign")],
                        security_scope=SCOPE, execution_mode="SYNTHETIC", idempotency_key="concurrent-" + str(i),
                        policy_version=POLICY, source_status=backend.statuses())
                    ss = CompilerService(backend, f.trust, f.validator, policy_version=POLICY, population=POPULATION,
                        security_scope=SCOPE, publication_mode="REVIEWED", policy_hash=cc.hash(f.policy_id),
                        classification_enabled=True, classification_taxonomy_hashes=frozenset({cc.hash(taxonomy_id)}))
                    auth = authorize_plan(signer, cc.get(pid), cc.hash(pid), reviewed_by="synthetic-workload-reviewer")
                    jobs.append((ss, cc, pid, auth, ss.preflight(cc, pid, reviewed=True)))
                barrier = threading.Barrier(2)
                def concurrent_publish(job):
                    ss, cc, pid, auth, preflight = job
                    barrier.wait(timeout=10)
                    try:
                        measure_publication(ss, cc, pid, recorder, authorization=auth, preflight=preflight)
                        return "COMMITTED"
                    except ContractError as exc:
                        return exc.code
                with ThreadPoolExecutor(max_workers=2) as pool:
                    concurrent_outcomes = list(pool.map(concurrent_publish, jobs))
                require(sorted(concurrent_outcomes) == ["COMMITTED", "STALE_GRAPH_VERSION"],
                        "WORKLOAD_CONCURRENCY", "exactly one of two same-version writers must commit")
            finally:
                concurrent.close()
            audit = f.backend.audit(trust=f.trust)
            sqlite_topology = topology(f.backend.state())
            try:
                index_pages = dict(f.backend.db.execute("SELECT name,sum(pgsize) FROM dbstat WHERE name LIKE 'trace_domain_index_%' OR name LIKE 'sqlite_autoindex_trace_domain_index_%' GROUP BY name"))
            except Exception:
                index_pages = None
            sizes = {"index_btree_bytes_by_object": index_pages, "index_btree_measurement": "dbstat" if index_pages is not None else "UNAVAILABLE",
                     "page_bytes": f.backend.db.execute("PRAGMA page_size").fetchone()[0] * f.backend.db.execute("PRAGMA page_count").fetchone()[0],
                     "main_file_bytes": Path(f.backend.path).stat().st_size,
                     "wal_file_bytes": Path(f.backend.path + "-wal").stat().st_size if Path(f.backend.path + "-wal").exists() else 0,
                     "scope": "local reference database/WAL only; not resident set size or a distributed index"}
        finally:
            f.close()
    report = recorder.report()
    report.update(topology={"memory_read_fixture": topology(snapshot), "sqlite_write_fixture": sqlite_topology},
                  sqlite_storage=sizes, sqlite_input_manifest=sqlite_inputs, sqlite_audit=audit, concurrent_write_outcomes=concurrent_outcomes,
                  provider_calls=0, production_graph_writes=0,
                  placement_decision="DEFERRED_PENDING_REPRESENTATIVE_DATA_OWNER_ISOLATION_AND_SLOS")
    # Linux process-wide observations, not an isolated workload's memory demand.
    memory = {"scope": "entire harness process, including previously imported modules", "resident_bytes": None,
              "peak_resident_bytes": None}
    if platform.system() == "Linux":
        import resource
        memory["peak_resident_bytes"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
        try:
            for line in Path("/proc/self/status").read_text().splitlines():
                if line.startswith("VmRSS:"):
                    memory["resident_bytes"] = int(line.split()[1]) * 1024
        except (OSError, ValueError):
            pass
    report["process_memory"] = memory
    from ..canonical import bytes_digest
    module_root = Path(__file__).parent
    report["implementation_hashes"] = {name: bytes_digest((module_root / name).read_bytes()) for name in
        ("workloads.py", "telemetry.py", "service.py", "store.py", "domain_index.py", "domains.py", "security.py", "strategies.py", "fixtures.py")}
    report["implementation_hashes"].update({"../" + name: bytes_digest((module_root.parent / name).read_bytes()) for name in
        ("backend.py", "domains.py", "domain_publication.py", "plans.py", "trust.py", "compiler.py", "canonical.py", "demo.py")})
    report["reproduction"] = {"command": "python -m trace_gc domain-workload --output REPORT.json --repetitions " + str(repetitions) + " --workers " + str(workers),
                              "timings_and_ephemeral_receipt_hashes": "expected to differ between runs"}
    if output is not None:
        write(Path(output), report)
    return report
