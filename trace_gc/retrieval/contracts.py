"""Versioned retrieval contracts. Scores are utilities, never calibrated truth."""
from __future__ import annotations
from dataclasses import asdict, dataclass, field
from typing import Any
from ..canonical import digest
from datetime import datetime, timezone

def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def timestamp(value: str):
    from ..compiler import timestamp as parse
    return parse(value)
from ..errors import require

VERSION = "trace-retrieval-v1"
DOMAIN_VERSION = "trace-retrieval-domain-v2"
STRATEGIES = (
    "ENTITY", "LEXICAL", "VECTOR", "NEIGHBORHOOD", "PATH", "COMMUNITY", "GLOBAL",
    "ONTOLOGY", "SCHEMA", "RELATION", "PROVENANCE", "EVIDENCE", "CONFLICT",
    "DECISION", "TEMPORAL", "SOURCE", "SIMILAR_CASE", "CLAIM",
)
MODES = ("CONSENSUS", "BALANCED_EVIDENCE", "CONTRADICTIONS_ONLY", "PROVENANCE_ONLY",
         "HISTORICAL", "LATEST_VALID_STATE")
TRUST = ("VERIFIED_GRAPH_FACT", "PROVISIONAL_GRAPH_FACT", "DERIVED_GRAPH_FACT",
         "CONFLICTED_GRAPH_FACT", "SUPERSEDED_GRAPH_FACT", "HISTORICAL_GRAPH_FACT",
         "UNVERIFIED_GRAPH_CONTEXT")
KINDS = ("retrieval-query", "retrieval-plan", "graph-access", "graph-context",
         "retrieval-result", "retrieval-expansion", "retrieval-lineage", "graphrag-answer",
         "retrieval-replay", "retrieval-evaluation")
FAILURES = (
    "ENTITY_NOT_RETRIEVED", "RELEVANT_EDGE_NOT_RETRIEVED", "RELEVANT_PATH_NOT_RETRIEVED",
    "CONTRADICTION_NOT_RETRIEVED", "WRONG_COMMUNITY_RETRIEVED", "ONTOLOGY_CONTEXT_MISSING",
    "PROVENANCE_CONTEXT_MISSING", "HISTORICAL_CONTEXT_MISSING", "IRRELEVANT_GRAPH_CONTEXT",
    "GRAPH_CONTEXT_OVERLOAD", "VECTOR_RETRIEVAL_MISS", "GRAPH_TRAVERSAL_MISS", "RANKING_FAILURE",
    "STALE_GRAPH_CONTEXT", "SUPERSEDED_FACT_USED", "TEMPORALLY_INVALID_CONTEXT", "RETRIEVAL_LOOP",
    "RETRIEVAL_BUDGET_EXHAUSTED",
)

@dataclass(frozen=True)
class RetrievalBudget:
    maximum_hops: int = 2
    maximum_paths: int = 12
    maximum_nodes: int = 40
    maximum_edges: int = 40
    maximum_communities: int = 3
    maximum_provenance_depth: int = 4
    maximum_decisions: int = 12
    maximum_source_spans: int = 20
    maximum_tokens: int = 16000
    maximum_latency_ms: int = 2000
    maximum_cost_units: int = 10000
    maximum_candidates: int = 1000
    maximum_rounds: int = 4
    maximum_semantic_items: int = 8

    def __post_init__(self) -> None:
        require(all(type(x) is int and x >= 0 for x in asdict(self).values()),
                "RETRIEVAL_BUDGET", "nonnegative integer resource limits required")
        require(self.maximum_hops <= 8 and self.maximum_provenance_depth <= 16 and
                1 <= self.maximum_rounds <= 8, "RETRIEVAL_BUDGET", "depth/round safety cap exceeded")

    def to_dict(self) -> dict[str, int]:
        return asdict(self)


def query(*, requesting_component: str, security_scope: str, focus_entities: list[str] | None = None,
          text: str = "", candidate_id: str | None = None, decision_id: str | None = None,
          strategies: list[str] | None = None, budget: RetrievalBudget | None = None,
          mode: str = "BALANCED_EVIDENCE", research_domain_scope: list[str] | None = None, **changes: Any) -> dict[str, Any]:
    limits = budget or RetrievalBudget()
    body = {"version": VERSION, "requesting_component": requesting_component,
            "security_scope": security_scope, "candidate_id": candidate_id, "decision_id": decision_id,
            "text": text, "focus_entities": sorted(set(focus_entities or [])), "focus_relationships": [],
            "target_information": [], "hop_limit": min(1, limits.maximum_hops), "allowed_relation_types": [],
            "excluded_relation_types": [], "temporal_scope": {"as_of": None, "valid_at": None, "before_source": None},
            "graph_version": None, "ontology_scope": [], "source_scope": [], "community_scope": [],
            "include_provenance": True, "include_conflicts": True, "include_historical": False,
            "include_superseded": False, "retrieval_strategy": ["ENTITY", "NEIGHBORHOOD", "EVIDENCE", "CONFLICT"] if strategies is None else list(strategies),
            "ranking_strategy": "evidence-utility-v1", "mode": mode, "budget": limits.to_dict(),
            "retrieval_round": 0, "created_at": now()}
    if research_domain_scope is not None:
        body["version"] = DOMAIN_VERSION
        body["research_domain_scope"] = research_domain_scope
    require(set(changes) <= set(body), "RETRIEVAL_QUERY", "unknown query fields")
    body.update(changes)
    if body["mode"] == "LATEST_VALID_STATE" and body["temporal_scope"]["valid_at"] is None:
        body["temporal_scope"] = {**body["temporal_scope"], "valid_at": body["created_at"]}
    validate_query(body)
    return body


def validate_query(body: dict[str, Any]) -> None:
    from ..schema import validate
    validate("retrieval-query", body)
    if "research_domain_scope" in body:
        require(body["research_domain_scope"] == sorted(set(body["research_domain_scope"])),
                "RESEARCH_DOMAIN_SCOPE", "unique sorted namespace/domain keys required")
    limits = RetrievalBudget(**body["budget"])
    require(body["hop_limit"] <= limits.maximum_hops, "RETRIEVAL_BUDGET", "hop request exceeds budget")
    require(not set(body["allowed_relation_types"]) & set(body["excluded_relation_types"]),
            "RELATION_FILTER", "allowlist and denylist overlap")
    require(body["retrieval_round"] < limits.maximum_rounds, "RETRIEVAL_LOOP", "round cap")
    for field in ("as_of", "valid_at"):
        if body["temporal_scope"][field] is not None:
            timestamp(body["temporal_scope"][field])
    require(body["ranking_strategy"] in {"evidence-utility-v1", "rrf-v1", "lexical-first-v1"},
            "RANKING_STRATEGY", "ranking implementation not installed")


def item_id(kind: str, canonical_ref: str, members: list[str] | None = None) -> str:
    return f"{kind.lower()}:{digest([canonical_ref, sorted(members or [])])[:24]}"
