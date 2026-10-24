"""Task/risk-aware planning and finite evidence acquisition through the existing pipeline."""
from __future__ import annotations
from dataclasses import dataclass
from copy import deepcopy
import time
from typing import Any, Callable
from ..catalog import Catalog
from ..compiler import compile_pack, now
from ..canonical import digest
from ..errors import require
from ..programs import question
from ..resolver import solve, project_resolutions, primary_observation
from ..qualification import evaluate_policy
from .contracts import RetrievalBudget, VERSION, query
from .service import HybridRetriever

POLICIES = {
    "IDENTITY": [["ENTITY", "SOURCE"], ["NEIGHBORHOOD", "LEXICAL", "EVIDENCE"],
                 ["PATH", "PROVENANCE", "DECISION"], ["CONFLICT", "ONTOLOGY"], ["COMMUNITY", "VECTOR"]],
    "ASSERTION": [["ENTITY", "SOURCE"], ["NEIGHBORHOOD", "LEXICAL", "VECTOR", "EVIDENCE"],
                  ["PATH", "PROVENANCE"], ["CONFLICT", "TEMPORAL", "DECISION"], ["COMMUNITY", "GLOBAL"]],
    "CLAIM_RECONCILIATION": [["CLAIM", "EVIDENCE"], ["CONFLICT", "RELATION", "LEXICAL"],
                             ["PROVENANCE", "TEMPORAL"], ["PATH", "DECISION", "VECTOR"], ["COMMUNITY", "GLOBAL"]],
    "ONTOLOGY": [["ENTITY", "SCHEMA"], ["ONTOLOGY", "NEIGHBORHOOD"], ["PATH", "PROVENANCE"],
                 ["LEXICAL", "VECTOR"], ["COMMUNITY", "GLOBAL"]],
    "TEMPORAL": [["ENTITY", "SOURCE"], ["TEMPORAL", "RELATION"], ["PROVENANCE", "DECISION"],
                 ["PATH", "CONFLICT"], ["COMMUNITY", "GLOBAL"]],
    "SCIENTIFIC": [["CLAIM", "SOURCE"], ["LEXICAL", "VECTOR", "RELATION", "CONFLICT"],
                   ["PATH", "PROVENANCE"], ["TEMPORAL", "DECISION"], ["COMMUNITY", "GLOBAL"]],
}

class RetrievalPlanner:
    version = "task-risk-tier-planner-v1"
    def __init__(self, policies: dict[str, list[list[str]]] | None = None, *, policy_version: str = "retrieval-routing-v1"):
        self.policies = deepcopy(policies or POLICIES)
        self.policy_version = policy_version
        require(bool(policy_version) and policy_version != "latest", "RETRIEVAL_POLICY", "pin policy version")

    def plan(self, catalog: Catalog, *, candidate_id: str | None, question_type: str, risk_class: str,
             known_entities: list[str], known_relations: list[str], budget: RetrievalBudget,
             uncertainty: float | None = None, retrieval_history: list[str] | None = None, tier: int = 0,
             research_domain_scope: dict[str, Any] | None = None) -> str:
        require(question_type in self.policies and risk_class in {f"R{i}" for i in range(6)}, "RETRIEVAL_PLAN", "task/risk not installed")
        require(type(tier) is int and 0 <= tier <= 4, "RETRIEVAL_PLAN", "automatic tiers are 0..4; tier 5 is human-guided")
        if candidate_id:
            catalog.get(candidate_id, "candidate")
        methods = list(dict.fromkeys(m for layer in self.policies[question_type][:tier+1] for m in layer))
        if int(risk_class[1:]) >= 4 and tier >= 1:
            methods = list(dict.fromkeys(methods + ["CONFLICT", "PROVENANCE"]))
        hop = min(budget.maximum_hops, tier)
        body = {"version": self.version, "candidate_id": candidate_id,
            "question_type": question_type, "risk_class": risk_class, "known_entities": sorted(set(known_entities)),
            "known_relations": sorted(set(known_relations)), "uncertainty": uncertainty,
            "retrieval_history": list(retrieval_history or []), "tier": tier,
            "steps": [{"strategy": m, "max_hops": hop} for m in methods], "expansion_policy": "ON_UNCERTAINTY",
            "budget": budget.to_dict(), "policy_version": self.policy_version, "created_at": now()}
        if research_domain_scope is not None:
            body["version"] = "task-risk-tier-planner-domain-v2"
            body["research_domain_scope"] = deepcopy(research_domain_scope)
        return catalog.put("retrieval-plan", body)

    def request(self, catalog: Catalog, plan_id: str, *, security_scope: str, text: str,
                retrieval_round: int, **changes: Any) -> dict[str, Any]:
        plan = catalog.get(plan_id, "retrieval-plan")
        selected = plan.get("research_domain_scope")
        require("research_domain_scope" not in changes or changes["research_domain_scope"] == selected,
                "DOMAIN_PLAN_BINDING", "query cannot change the planned domain scope")
        if selected is not None:
            changes["research_domain_scope"] = deepcopy(selected)
        return query(requesting_component="upstream-synthesis", security_scope=security_scope,
            candidate_id=plan["candidate_id"], text=text, focus_entities=plan["known_entities"],
            strategies=[s["strategy"] for s in plan["steps"]], budget=RetrievalBudget(**plan["budget"]),
            hop_limit=max((s["max_hops"] for s in plan["steps"]), default=0),
            focus_relationships=plan["known_relations"], target_information=[plan["question_type"]],
            retrieval_round=retrieval_round, **changes)


def request_evidence(catalog: Catalog, evaluation_id: str) -> tuple[str, str]:
    """Route semantic INSUFFICIENT to acquisition, not to a fabricated probability cutoff.

    Original evaluation stays immutable. Unqualified but semantically sufficient
    decisions stop for review rather than searching until a desired answer appears.
    """
    evaluation = catalog.get(evaluation_id, "evaluation")
    observation = primary_observation(catalog, evaluation["candidate_id"], evaluation["observation_ids"])
    if observation is not None and observation["semantic_outcome"] == "INSUFFICIENT":
        branch = deepcopy(evaluation)
        branch.update(outcome="RETRIEVE_MORE_EVIDENCE", reason="Atomic semantic outcome is INSUFFICIENT; bounded acquisition requested.", created_at=now())
        return catalog.put("evaluation", branch), "RETRIEVE_MORE_EVIDENCE"
    if evaluation["outcome"] == "ABSTAIN":
        return evaluation_id, "HUMAN_REVIEW_REQUIRED"
    return evaluation_id, evaluation["outcome"]


@dataclass
class UpstreamRun:
    result_ids: list[str]
    expansion_ids: list[str]
    pack_ids: list[str]
    observation_ids: list[str]
    batch_id: str
    resolution_ids: list[str]
    evaluation_id: str
    stop_reason: str


class UpstreamGraphRAG:
    """Coordinates retrieval -> closure -> Jev -> existing resolver/policy.

    The executor is the existing TypeSafeAdapter (or explicit test recorder).
    This class intentionally has no mutation backend or authorization capability.
    """
    def __init__(self, retriever: HybridRetriever, planner: RetrievalPlanner | None = None):
        self.retriever, self.planner = retriever, planner or RetrievalPlanner()

    def run(self, *, candidate_id: str, execute: Callable[[str], list[str]], run_budget: Any,
            policy_version: str, population: str, budget: RetrievalBudget | None = None,
            question_type: str | None = None, risk_class: str | None = None, model_version: str = "jev-1.13.0",
            registry: Any = None, qualification_id: str | None = None,
            token_counter: Any = None, tokenizer_version: str = "utf8-byte-estimate-v1",
            query_overrides: dict[str, Any] | None = None, reranker: Any = None) -> UpstreamRun:
        c = self.retriever.catalog
        candidate = c.get(candidate_id, "candidate")
        limits = budget or RetrievalBudget()
        kind = question_type or ("IDENTITY" if candidate["candidate_kind"] == "IDENTITY" else "ASSERTION")
        risk = risk_class or ("R4" if candidate["candidate_kind"] == "IDENTITY" else "R2")
        require(run_budget.run_id == candidate["run_id"], "BUDGET_SCOPE", "retrieval/synthesis run differs")
        if self.retriever.run_budget is None:
            self.retriever.run_budget = run_budget
        require(self.retriever.run_budget.run_id == run_budget.run_id, "BUDGET_SCOPE", "retriever budget belongs to another run")
        results: list[str] = []
        expansions: list[str] = []
        packs: list[str] = []
        all_observations: list[str] = []
        known: dict[str, str] = {}
        confidence_before = None
        decision_before = None
        units = 0
        retrieval_elapsed_ms = 0.0
        stop = "MAXIMUM_ROUNDS"
        last_batch = last_evaluation = ""
        resolutions: list[str] = []
        for round_ in range(limits.maximum_rounds):
            remaining_cost = max(0, limits.maximum_cost_units - units)
            remaining_ms = max(0, limits.maximum_latency_ms - int(retrieval_elapsed_ms))
            if not remaining_cost or not remaining_ms:
                stop = "RETRIEVAL_BUDGET_EXHAUSTED"
                break
            current = RetrievalBudget(**{**limits.to_dict(), "maximum_cost_units": remaining_cost,
                                         "maximum_latency_ms": remaining_ms})
            plan_id = self.planner.plan(c, candidate_id=candidate_id, question_type=kind, risk_class=risk,
                known_entities=[candidate["assertion"]["subject"], candidate["assertion"]["object"]],
                known_relations=[candidate["assertion"]["predicate"]], budget=current,
                uncertainty=None if confidence_before is None else 1-confidence_before,
                retrieval_history=results, tier=min(round_, 4),
                research_domain_scope=(query_overrides or {}).get("research_domain_scope"))
            request = self.planner.request(c, plan_id, security_scope=self.retriever.access_policy["tenant"],
                text=c.get(candidate["claim_id"], "claim")["text"], retrieval_round=round_, **(query_overrides or {}))
            result_id = self.retriever.retrieve(request, plan_id=plan_id)
            result = c.get(result_id, "retrieval-result")
            context = c.get(result["graph_context_id"], "graph-context")
            units += int(result["usage"]["cost_units"])
            retrieval_elapsed_ms += c.get(result["lineage_id"], "retrieval-lineage")["latency_ms"]
            information = {i["id"]: digest({k: i[k] for k in ("text", "evidence_ids", "record_refs", "trust_class", "current_status")}) for i in context["items"]}
            novel = sorted(ref for ref, content in information.items() if known.get(ref) != content)
            known.update(information)
            if reranker is not None and context["items"]:
                result_id = reranker.rerank(self.retriever, result_id, candidate_id=candidate_id)
                result = c.get(result_id, "retrieval-result")
                context = c.get(result["graph_context_id"], "graph-context")
            task = "IDENTITY" if candidate["candidate_kind"] == "IDENTITY" else "SUPPORT"
            pack_id = compile_pack(c, id_=f"graphrag-pack:{candidate_id}:{round_}:{result_id[-16:]}",
                run_id=candidate["run_id"], candidate_ids=[candidate_id],
                questions=[question(candidate_id, id_=f"semantic-{round_}", task=task)], snapshot_id=context["snapshot_id"],
                security_scope=self.retriever.access_policy["tenant"], execution_mode=candidate["execution_mode"],
                model_version=model_version, graph_context_ids=[result["graph_context_id"]], source_retrieval_ids=[result_id],
                token_counter=token_counter, tokenizer_version=tokenizer_version)
            from .service import validate_current_context
            validate_current_context(self.retriever, result["graph_context_id"], pack_id=pack_id)
            observations = execute(pack_id)
            validate_current_context(self.retriever, result["graph_context_id"], pack_id=pack_id)
            require(bool(observations) and all(c.get(x, "observation")["pack_id"] == pack_id for x in observations),
                    "REQUEST_BINDING", "executor returned observations for a different pack")
            last_batch = solve(c, run_id=candidate["run_id"], candidate_ids=[candidate_id], observation_ids=observations,
                               snapshot_id=context["snapshot_id"], budget=run_budget)
            resolutions = project_resolutions(c, last_batch)
            evaluation = evaluate_policy(c, candidate_id=candidate_id, batch_id=last_batch, policy_version=policy_version,
                population=population, registry=registry, qualification_id=qualification_id)
            last_evaluation, action = request_evidence(c, evaluation)
            primary = primary_observation(c, candidate_id, observations)
            confidence = primary["raw_confidence"] if primary else None
            saturated = round_ > 0 and not novel
            stop_now = None
            if action != "RETRIEVE_MORE_EVIDENCE":
                stop_now = {"ACCEPT": "SUFFICIENT_QUALIFIED_EVIDENCE", "REJECT": "CANDIDATE_REJECTED",
                            "HUMAN_REVIEW_REQUIRED": "HUMAN_REVIEW_REQUIRED"}.get(action, action)
            elif c.get(last_batch, "resolution-batch")["status"] == "INFEASIBLE":
                stop_now = "CONSTRAINT_FAILURE"
            elif result["status"] == "PARTIAL":
                stop_now = "RETRIEVAL_BUDGET_EXHAUSTED"
            elif saturated:
                stop_now = "RETRIEVAL_SATURATED"
            elif round_+1 >= limits.maximum_rounds:
                stop_now = "MAXIMUM_ROUNDS"
            expansion = {"version": VERSION, "candidate_id": candidate_id, "retrieval_round": round_,
                "reason_for_expansion": "INITIAL_CONTEXT" if round_ == 0 else "INSUFFICIENT_SEMANTIC_EVIDENCE",
                "previous_result_id": results[-1] if results else None, "result_id": result_id,
                "decision_ids": [last_evaluation] + resolutions, "new_information_added": novel,
                "new_relevant_information_per_round": len(novel), "confidence_before": confidence_before,
                "confidence_after": confidence, "confidence_change": None if confidence is None or confidence_before is None else confidence-confidence_before,
                "decision_before": decision_before, "decision_after": action, "decision_change": action != decision_before,
                "stop_reason": stop_now, "cost_units": int(result["usage"]["cost_units"]),
                "latency_ms": c.get(result["lineage_id"], "retrieval-lineage")["latency_ms"], "created_at": now()}
            expansions.append(c.put("retrieval-expansion", expansion))
            results.append(result_id)
            packs.append(pack_id)
            all_observations.extend(observations)
            confidence_before, decision_before = confidence, action
            if stop_now:
                stop = stop_now
                break
        return UpstreamRun(results, expansions, packs, all_observations, last_batch, resolutions, last_evaluation, stop)
