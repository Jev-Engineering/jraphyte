"""Four executable GraphRAG lifecycles; all observations and sources are synthetic.

Existing signed sandbox authorization remains mandatory for every demonstration
commit. No retrieval function has a mutation capability or production credential.
"""
from __future__ import annotations
import argparse
import json
import tempfile
from pathlib import Path
from typing import Any
from ..adapter import record_response
from ..canonical import write
from ..demo import build_fixture, RUN, SCOPE, POLICY, POPULATION
from ..errors import require
from ..ledger import make_bundle
from ..plans import add_operation, create_plan
from ..validation import validate_bundle
from .contracts import RetrievalBudget, query
from .fixtures import demo_access
from .planner import RetrievalPlanner, UpstreamGraphRAG
from .service import HybridRetriever, GraphRAGQueryService
from .store import SQLiteGraphAdapter


def synthetic_response(catalog, pack_id: str, semantic_label: str) -> list[str]:
    """Deterministic test oracle, NOT an actual Jev response or evaluated model."""
    pack = catalog.get(pack_id, "pack")
    answers = {}
    for q in pack["questions"]:
        labels = [x["label"] for x in q["criteria"]]
        require(semantic_label in labels, "FIXTURE_LABEL", semantic_label)
        probabilities = {label: .95 if label == semantic_label else .05/(len(labels)-1) for label in labels}
        answers[q["id"]] = {"type": "choice", "choice": semantic_label,
                             "probabilities": probabilities, "confidence": .5}
    body = {"model": pack["model_version"], "answers": answers,
            "usage": {"input_tokens": 100, "output_tokens": 20}}
    return record_response(catalog, pack_id, json.dumps(body, separators=(",", ":")).encode())


def admit(fixture, document: str, text: str, *, name: str) -> str:
    """Use the already implemented source admission transaction and trust store."""
    c = fixture.catalog
    source_id = c.source(document, name, text, scope=SCOPE)
    version = fixture.backend.state()["graph_version"]
    admission = {"action": "ADMIT", "source_hashes": {source_id: c.hash(source_id)},
                 "security_scope": SCOPE, "execution_mode": "SYNTHETIC", "expected_version": version}
    fixture.backend.admit_sources(c, [source_id], trust=fixture.trust,
        authorization=fixture.reviewer.issue("SOURCE_STATUS", admission), security_scope=SCOPE,
        execution_mode="SYNTHETIC", expected_version=version, key="admit:"+name)
    return c.evidence(source_id)


def retriever_for(fixture):
    c = fixture.catalog
    snapshot = fixture.backend.snapshot(c)
    return HybridRetriever(SQLiteGraphAdapter(fixture.backend, c, audit_trust=fixture.trust), catalog=c,
        access_policy=demo_access(c, snapshot, scope=SCOPE), run_budget=fixture.budget)


def reviewed_publish(fixture, run, *, name: str) -> dict[str, Any]:
    """Explicit ephemeral sandbox reviewer authorizes the original CompilerService."""
    c = fixture.catalog
    selected = c.get(run.batch_id, "resolution-batch")["selected_ids"]
    require(len(selected) == 1, "FIXTURE_SELECTION", "scenario expects one selected hypothesis")
    operation = add_operation(c, run.resolution_ids[0], run.evaluation_id, operation_id="add:"+name)
    snapshot = c.get(c.get(run.result_ids[-1], "retrieval-result")["graph_context_id"], "graph-context")["snapshot_id"]
    fixture.plan_id = create_plan(c, run_id=RUN, snapshot_id=snapshot, operations=[operation],
        security_scope=SCOPE, execution_mode="SYNTHETIC", idempotency_key="publish:"+name,
        policy_version=POLICY, source_status=fixture.backend.statuses())
    return fixture.publish()


def execute(fixture, candidate_id, *, label="SUPPORTS", question_type=None, adaptive=False):
    r = retriever_for(fixture)
    if adaptive:
        planner = RetrievalPlanner()
    else:
        task = question_type or ("IDENTITY" if fixture.catalog.get(candidate_id, "candidate")["candidate_kind"] == "IDENTITY" else "ASSERTION")
        planner = RetrievalPlanner({task: [["ENTITY", "SOURCE", "NEIGHBORHOOD", "PROVENANCE", "CONFLICT", "TEMPORAL", "SCHEMA"]]*5})
    def callback(pack_id):
        pack = fixture.catalog.get(pack_id, "pack")
        has_graph = any(i["kind"] == "EDGE" for ctx in pack["state"]["graph_context"] for i in ctx["items"])
        return synthetic_response(fixture.catalog, pack_id, "INSUFFICIENT" if adaptive and not has_graph else label)
    # For the static scenario a declared one-hop override is needed at tier zero.
    # Use the planner's tier one as the initial static plan rather than bypass it.
    if not adaptive:
        class FirstHopPlanner(RetrievalPlanner):
            def plan(self, catalog, **kwargs):
                kwargs["tier"] = max(1, kwargs.get("tier", 0))
                return super().plan(catalog, **kwargs)
        planner = FirstHopPlanner(planner.policies)
    return UpstreamGraphRAG(r, planner).run(candidate_id=candidate_id, execute=callback,
        run_budget=fixture.budget, policy_version=POLICY, population=POPULATION,
        question_type=question_type, budget=RetrievalBudget(maximum_tokens=50000, maximum_latency_ms=10000))


def downstream(fixture, focus, *, text="", historical=False):
    r = retriever_for(fixture)
    return GraphRAGQueryService(r).query(query(requesting_component="downstream-research", security_scope=SCOPE,
        focus_entities=focus, text=text, strategies=["CLAIM", "NEIGHBORHOOD", "PATH", "PROVENANCE", "CONFLICT", "DECISION"],
        include_historical=historical, budget=RetrievalBudget(maximum_tokens=100000, maximum_latency_ms=10000)))


def export(fixture, name, run, answer, commit, output):
    c = fixture.catalog
    snapshot = fixture.backend.snapshot(c)
    bundle = make_bundle(c, run_id=RUN, execution_mode="SYNTHETIC", security_scope=SCOPE,
        graph_version=c.get(snapshot, "graph-snapshot")["graph_version"], schema_hash=c.hash(fixture.schema_id),
        source_status=fixture.backend.statuses(), policy_version=POLICY)
    validation = validate_bundle(bundle, trust=fixture.trust)
    result = {"scenario": name, "status": "PASS", "execution_mode": "SYNTHETIC", "provider_calls": 0,
        "production_graph_writes": 0, "retrieval_rounds": len(run.result_ids), "stop_reason_before_review": run.stop_reason,
        "policy_outcome_before_review": c.get(run.evaluation_id, "evaluation")["outcome"],
        "selected_candidates": c.get(run.batch_id, "resolution-batch")["selected_ids"],
        "resolver_decisions": run.resolution_ids, "retrieval_results": run.result_ids, "expansions": run.expansion_ids,
        "commit_version": commit["receipt"]["version"], "downstream_graph_version": answer["context"]["graph_version"],
        "downstream_assertions": sorted({a for i in answer["context"]["items"] for a in i["assertion_ids"]}),
        "downstream_conflicts": sum(i["kind"] == "CONFLICT" for i in answer["context"]["items"]),
        "canonical_citations": len(answer["context"]["citations"]), "validation": validation,
        "qualification": "NOT_QUALIFIED; explicit sandbox review only"}
    if output:
        target = Path(output)/name
        target.mkdir(parents=True, exist_ok=True)
        write(target/"bundle.json", bundle)
        write(target/"answer_context.json", answer)
        write(target/"result.json", result)
    return result


def run_scenarios(output: str | Path | None=None) -> dict[str, Any]:
    reports = []
    with tempfile.TemporaryDirectory(prefix="trace-graphrag-scenarios-") as root:
        # A: an existing alias becomes retrieval context for a second identity link.
        f = build_fixture(Path(root)/"A", candidate_count=1)
        try:
            c = f.catalog
            evidence = admit(f, "identity-register", "Person A, Person B and Person C are aliases in this fabricated registry.", name="identity")
            claim = c.claim("Person A, Person B and Person C refer to the same person.")
            for suffix, other in (("known-alias", "person-c"), ("new-mention", "person-b")):
                candidate = c.candidate(id_=suffix, run_id=RUN, assertion={"subject": "person-a", "predicate": "same_as", "object": other, "qualifiers": {}},
                    claim_id=claim, evidence_ids=[evidence], kind="IDENTITY")
                run = execute(f, candidate, label="MATCH", question_type="IDENTITY")
                commit = reviewed_publish(f, run, name=suffix)
            answer = downstream(f, ["person-a", "person-b"])
            require("new-mention" in {a for i in answer["context"]["items"] for a in i["assertion_ids"]}, "SCENARIO", "identity not visible")
            reports.append(export(f, "A_entity_resolution", run, answer, commit, output))
        finally:
            f.close()
        # B: opposite source claims coexist; neither summary settles their truth.
        text = "Intervention X improves outcome Y in population P."
        f = build_fixture(Path(root)/"B", candidate_count=1, fixture_claim_text=text,
                          fixture_document_id="Paper-A", fixture_extra_nodes={"Paper-B": "Document"})
        try:
            f.publish()
            evidence = admit(f, "Paper-B", "Intervention X did not improve outcome Y in population P; method N differs from method M.", name="contradiction")
            candidate = f.catalog.candidate(id_="paper-b-refutation", run_id=RUN,
                assertion={"subject": "Paper-B", "predicate": "refutes", "object": f.claim_id, "qualifiers": {}}, claim_id=f.claim_id, evidence_ids=[evidence])
            run = execute(f, candidate, label="CONTRADICTS", question_type="CLAIM_RECONCILIATION")
            commit = reviewed_publish(f, run, name="preserve-opposing-source")
            answer = downstream(f, [f.claim_id])
            require(any(i["kind"] == "CONFLICT" for i in answer["context"]["items"]), "SCENARIO", "opposing source evidence hidden")
            reports.append(export(f, "B_contradictory_evidence", run, answer, commit, output))
        finally:
            f.close()
        # C: original support task compiles a condition-specific research claim.
        f = build_fixture(Path(root)/"C", candidate_count=1, make_plan=False,
            fixture_claim_text="In a fabricated randomized study of population P, intervention X improves outcome Y under condition C.",
            fixture_document_id="Paper-C")
        try:
            candidate = f.candidate_ids[0]
            run = execute(f, candidate, question_type="SCIENTIFIC")
            commit = reviewed_publish(f, run, name="scientific-source-claim")
            answer = downstream(f, [f.claim_id], text="intervention X population P")
            require(bool(answer["context"]["citations"]), "SCENARIO", "scientific claim lacks source citations")
            reports.append(export(f, "C_research_paper_synthesis", run, answer, commit, output))
        finally:
            f.close()
        # D: graph context changes a synthetic semantic outcome on a fresh branch.
        f = build_fixture(Path(root)/"D", candidate_count=1)
        try:
            f.publish()
            old = f.catalog.get(f.candidate_ids[0], "candidate")
            candidate = f.catalog.candidate(id_="expanded-candidate", run_id=RUN, assertion=old["assertion"], claim_id=old["claim_id"], evidence_ids=old["evidence_ids"])
            run = execute(f, candidate, adaptive=True)
            require(len(run.result_ids) >= 2, "SCENARIO", "uncertainty did not expand retrieval")
            commit = reviewed_publish(f, run, name="after-expansion-review")
            answer = downstream(f, ["document-demo", f.claim_id])
            reports.append(export(f, "D_uncertainty_expansion", run, answer, commit, output))
        finally:
            f.close()
    report = {"status": "PASS", "scenarios": reports, "provider_calls": 0, "production_graph_writes": 0,
              "scope": "Synthetic integration tests, not empirical evidence of GraphRAG accuracy or calibration."}
    if output:
        write(Path(output)/"scenario_report.json", report)
    return report

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    print(json.dumps(run_scenarios(args.output), indent=2))
