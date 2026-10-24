"""Additive GraphRAG contracts to the existing standalone schema generator."""
from copy import deepcopy


def extend(schemas):
    S = {"type": "string", "minLength": 1}
    TEXT = {"type": "string"}
    N = {"type": "integer", "minimum": 0}
    NUM = {"type": "number"}
    B = {"type": "boolean"}
    T = {"type": "string", "format": "date-time"}
    H = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    def arr(item=S, unique=False):
        return {"type": "array", "items": deepcopy(item), **({"uniqueItems": True} if unique else {})}
    IDS = arr(S, True)
    def obj(props, optional=()):
        return {"type": "object", "properties": deepcopy(props), "required": [x for x in props if x not in optional], "additionalProperties": False}
    def mapping(item):
        return {"type": "object", "additionalProperties": deepcopy(item)}
    def nullable(item):
        return {"anyOf": [deepcopy(item), {"type": "null"}]}
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from trace_gc.retrieval.contracts import KINDS, STRATEGIES, MODES, TRUST, VERSION, DOMAIN_VERSION, RetrievalBudget
    kinds = schemas["record"]["properties"]["kind"]["enum"]
    kinds.extend(k for k in KINDS if k not in kinds)
    budget = obj({k: N for k in RetrievalBudget().to_dict()})
    temporal = obj({"as_of": nullable(T), "valid_at": nullable(T), "before_source": nullable(S)})
    status = obj({"active": B, "permission": {"enum": ["READ", "DENIED"]}, "epoch": N, "updated_at": T, "tombstone": B})
    risk = {"enum": [f"R{i}" for i in range(6)]}
    schemas["graph-access"] = obj({"version": S, "tenant": S, "workspace": S, "user": S, "roles": IDS, "clearance": N,
        "grants": mapping(obj({"tenant": S, "workspace": S, "users": IDS, "roles": IDS, "classification": N}))})
    schemas["retrieval-query"] = obj({"version": {"const": VERSION}, "requesting_component": S, "security_scope": S,
        "candidate_id": nullable(S), "decision_id": nullable(S), "text": TEXT, "focus_entities": IDS,
        "focus_relationships": IDS, "target_information": IDS, "hop_limit": N,
        "allowed_relation_types": IDS, "excluded_relation_types": IDS, "temporal_scope": temporal,
        "graph_version": nullable(N), "ontology_scope": IDS, "source_scope": IDS, "community_scope": IDS,
        "include_provenance": B, "include_conflicts": B, "include_historical": B, "include_superseded": B,
        "retrieval_strategy": arr({"enum": list(STRATEGIES)}, True), "ranking_strategy": S,
        "mode": {"enum": list(MODES)}, "budget": budget, "retrieval_round": N, "created_at": T})
    domain_scope = {"type": "array", "uniqueItems": True, "maxItems": 64,
        "items": {"type": "string", "maxLength": 257,
            "pattern": "^(?:@unclassified|[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*/[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*)$"}}
    domain_binding = obj({"classification_revision": N, "projection_hash": H})
    q = schemas["retrieval-query"]
    q["properties"]["version"] = {"enum": [VERSION, DOMAIN_VERSION]}
    q["properties"]["research_domain_scope"] = deepcopy(domain_scope)
    q["allOf"] = [{"if": {"properties": {"version": {"const": DOMAIN_VERSION}}},
        "then": {"required": ["research_domain_scope"]},
        "else": {"not": {"required": ["research_domain_scope"]}}}]
    schemas["retrieval-plan"] = obj({"version": S, "candidate_id": nullable(S), "question_type": S, "risk_class": risk,
        "known_entities": IDS, "known_relations": IDS, "uncertainty": nullable(NUM), "retrieval_history": IDS,
        "tier": N, "steps": arr(obj({"strategy": {"enum": list(STRATEGIES)}, "max_hops": N})),
        "expansion_policy": {"const": "ON_UNCERTAINTY"}, "budget": budget, "policy_version": S, "created_at": T})
    item = obj({"id": S, "kind": {"enum": ["NODE", "EDGE", "PATH", "COMMUNITY", "CONFLICT", "PROVENANCE", "ONTOLOGY", "SCHEMA", "EVIDENCE", "CLAIM", "DECISION", "HYPOTHESIS"]},
        "canonical_ref": S, "member_assertion_ids": IDS, "assertion_ids": IDS, "entity_ids": IDS, "evidence_ids": IDS,
        "source_ids": IDS, "decision_ids": IDS, "observation_ids": IDS, "transaction_ids": IDS, "plan_ids": IDS,
        "record_refs": IDS, "relation_types": IDS, "text": TEXT, "trust_class": {"enum": list(TRUST)},
        "current_status": S, "graph_version": N, "created_at": nullable(T), "superseded_at": nullable(T),
        "provenance_complete": B, "risk_class": risk, "calibration": obj({"qualified": {"const": False}, "note": S}),
        "generated_summary": B, "data_origin": {"enum": ["GENERATED_SUMMARY", "SOURCE_DERIVED"]},
        "instruction_authority": {"const": False}})
    item["properties"].update({"research_domain_scope": deepcopy(domain_scope),
        "research_domain_binding": deepcopy(domain_binding),
        "research_domain_closure": mapping(arr({"enum": ["ANCHOR", "CONTRADICTION", "IDENTITY", "PREREQUISITE"]}, True)),
        "research_domain_assignments": mapping(obj({
            "assignment_id": nullable(S), "assignment_hash": nullable(H),
            "taxonomy_id": nullable(S), "taxonomy_hash": nullable(H), "taxonomy_version": nullable(S),
            "assignment_revision": N, "state": {"enum": ["CLASSIFIED", "UNCLASSIFIED", "RETIRED"]},
            "domain_ids": IDS}))})
    schemas["graph-context"] = obj({"version": S, "query_id": S, "snapshot_id": S, "graph_version": N,
        "security_scope": S, "access_id": S, "source_status": mapping(status), "available_record_ids": IDS,
        "focus_entities": IDS, "items": arr(item), "retrieved_nodes": IDS, "retrieved_edges": IDS,
        "retrieved_paths": IDS, "communities": IDS, "ontology_fragments": IDS, "schema_fragments": IDS,
        "provenance_refs": IDS, "decision_refs": IDS, "conflict_refs": IDS, "temporal_scope": temporal,
        "retrieval_methods": IDS, "strategy_versions": mapping(S), "ranking_scores": mapping(NUM), "selected_evidence_ids": IDS,
        "retrieval_fingerprint": H, "embedding_version": S, "adapter_version": S, "created_at": T})
    usage = mapping(NUM)
    candidate = obj({"item_id": S, "kind": S, "score": NUM, "features": mapping(NUM), "methods": IDS})
    selected = obj({"item_id": S, "reason": S})
    schemas["retrieval-lineage"] = obj({"version": S, "query_id": S, "graph_context_id": S, "plan_id": nullable(S),
        "requesting_component": S, "graph_version": N, "retrieval_strategies": IDS, "strategy_versions": mapping(S),
        "candidates": arr(candidate), "selected": arr(selected), "discarded": arr(selected),
        "budget": budget, "usage": usage, "cache_key": H, "cache_hit": B, "cache_version": S,
        "embedding_version": S, "ranking_strategy": S, "score_type": {"const": "POLICY_UTILITY_NOT_PROBABILITY"},
        "stop_reason": S, "latency_ms": NUM, "cost_units": N, "created_at": T})
    schemas["graph-context"]["properties"]["reranking_observation_ids"] = IDS
    schemas["graph-context"]["properties"]["reranking_base_context_id"] = S
    schemas["retrieval-result"] = obj({"version": S, "query_id": S, "graph_context_id": S, "lineage_id": S,
        "plan_id": nullable(S), "source_evidence_ids": IDS, "status": {"enum": ["COMPLETE", "PARTIAL", "EMPTY"]},
        "warnings": IDS, "usage": usage, "created_at": T})
    schemas["retrieval-expansion"] = obj({"version": S, "candidate_id": S, "retrieval_round": N,
        "reason_for_expansion": S, "previous_result_id": nullable(S), "result_id": S, "decision_ids": IDS,
        "new_information_added": IDS, "new_relevant_information_per_round": N,
        "confidence_before": nullable(NUM), "confidence_after": nullable(NUM), "confidence_change": nullable(NUM),
        "decision_before": nullable(S), "decision_after": S, "decision_change": B,
        "stop_reason": nullable(S), "cost_units": N, "latency_ms": NUM, "created_at": T})
    citation = obj({"evidence_id": S, "source_snapshot_id": S, "source_id": S, "source_hash": H,
                    "start": N, "end": N, "quote": TEXT})
    schemas["graphrag-answer"] = obj({"version": S, "query_id": S, "result_id": S, "graph_context_id": S,
        "graph_version": N, "mode": {"enum": list(MODES)}, "answer_status": {"const": "CONTEXT_ONLY"},
        "items": arr(item), "citations": arr(citation), "warnings": IDS, "can_mutate_graph": {"const": False}, "created_at": T})
    schemas["retrieval-replay"] = obj({"version": S, "original_result_id": S, "replayed_result_id": S,
        "changed_parameters": {"type": "object"}, "original_graph_version": N, "replayed_graph_version": N,
        "original_selected_ids": IDS, "replayed_selected_ids": IDS, "added_ids": IDS, "removed_ids": IDS,
        "observation_hashes_preserved": mapping(H), "new_observation_ids": IDS,
        "synthesis_comparison": {"type": "object"}, "authorization_granted": {"const": False}, "created_at": T})
    schemas["retrieval-evaluation"] = obj({"version": S, "dataset_hash": H, "split": S, "label_origin": S,
        "metrics": {"type": "object"}, "configuration": {"type": "object"}, "result_ids": IDS,
        "production_qualified": {"const": False}, "created_at": T})
    for name in ("retrieval-plan", "graph-context", "retrieval-lineage", "graphrag-answer"):
        schemas[name]["properties"]["research_domain_scope"] = deepcopy(domain_scope)
        if name != "retrieval-plan":
            schemas[name]["properties"]["research_domain_binding"] = deepcopy(domain_binding)
    lineage = {"graph_retrieval_query_ids": IDS, "graph_context_ids": IDS,
               "source_retrieval_ids": IDS, "evidence_closure_id": S, "retrieval_fingerprint": H}
    for kind in ("pack", "observation", "resolution"):
        schemas[kind]["properties"].update(deepcopy(lineage))
    schemas["pack"]["properties"]["materializer_version"] = {"enum": ["materializer-v1", "materializer-v1+graph-v1"]}
    schemas["pack"]["properties"]["packing_version"] = {"anyOf": [{"const": "complete-closure-v1"},
        {"type": "string", "pattern": "^minimum-source-graph-v1:[0-9a-f]{64}$"}]}
    # A new reviewed program; old question semantics and hashes remain unchanged.
    q = schemas["pack"]["properties"]["questions"]["items"]
    q["properties"]["task"]["enum"].append("GRAPH_RELEVANCE")
    q["properties"]["context_item_id"] = S
