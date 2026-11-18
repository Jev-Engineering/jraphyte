"""Append policy branches without rewriting or fabricating model observations."""
from __future__ import annotations
from copy import deepcopy
from typing import Any
from .canonical import digest
from .catalog import Catalog
from .errors import require
from .qualification import evaluate_policy
from .ledger import make_bundle
from .validation import validate_bundle

RETRIEVAL_REPLAY_PARAMETERS = frozenset({
    "retrieval_strategy", "hop_limit", "budget", "include_provenance",
    "include_conflicts", "include_historical", "include_superseded",
    "ranking_strategy", "graph_version", "temporal_scope", "mode",
    "allowed_relation_types", "excluded_relation_types", "ontology_scope",
    "community_scope", "source_scope", "research_domain_scope",
})


def replay_analysis_policy(bundle: dict[str,Any], policy: dict[str,Any], *, trust=None, at: str | None=None) -> dict[str,Any]:
    """Return an explicitly unsigned, analysis-only branch. Never authorize writes.

    Original observations, policies, plans and their hashes are retained. The new
    branch is a partial analysis artifact until an authorized issuer checkpoints
    it. Expired demo signatures are not promoted into a new trusted checkpoint.
    """
    require(policy.get("mode")=="ANALYSIS_ONLY","REPLAY_MODE","CLI replay cannot mint a qualified/authorized result")
    # Validate the original material/provenance even when no external trust was supplied.
    validate_bundle(bundle,trust=trust,at=at)
    catalog=Catalog(bundle["records"])
    previous={r["id"]:r["hash"] for r in catalog.all("observation")}
    catalog.put("policy",deepcopy(policy))
    for batch in catalog.all("resolution-batch"):
        for candidate_id in batch["body"]["candidate_ids"]:
            evaluate_policy(catalog,candidate_id=candidate_id,batch_id=batch["id"],
                policy_version=policy["version"],population=policy["population"])
    require(previous=={r["id"]:r["hash"] for r in catalog.all("observation")},"REPLAY_OBSERVATION_CHANGED","observations are immutable")
    m=bundle["manifest"]
    result=make_bundle(catalog,run_id=m["run_id"],execution_mode=m["execution_mode"],security_scope=m["security_scope"],
        graph_version=m["graph_version"],schema_hash=m["schema_hash"],source_status=m["source_status"],
        policy_version=policy["version"],profile="HISTORICAL_REPLAY" if m["profile"]=="HISTORICAL_REPLAY" else "PARTIAL_ANALYSIS")
    validate_bundle(result)
    return result


def replay_retrieval(retriever, original_result_id: str, changes: dict[str, Any], *, synthesize=None) -> str:
    """Counterfactual retrieval branch; original observations and graph remain intact.

    ``synthesize(new_result_id)`` may invoke the existing compiler/adapter/resolver
    to create NEW observations. This API never grants publication authority.
    Current permissions still apply to historical snapshots.
    """
    from .compiler import now
    from .retrieval.contracts import VERSION
    from .retrieval.integration import context_observations, observation_sources_readable, observation_uses_result, validate_record
    from .retrieval.security import AccessFilter
    from .domain_publication import classification_identity
    c = retriever.catalog
    require(set(changes) <= RETRIEVAL_REPLAY_PARAMETERS, "REPLAY_SCOPE",
            "replay cannot change tenant, candidate or requesting role")
    validate_record(c, c.record(original_result_id))
    original = c.get(original_result_id, "retrieval-result")
    context = c.get(original["graph_context_id"], "graph-context")
    retriever.validate_live_context(original["graph_context_id"])
    request = c.get(original["query_id"], "retrieval-query")
    before = {r["id"]: r["hash"] for r in c.all("observation")}
    request.update(graph_version=context["graph_version"], created_at=now())
    request.update(deepcopy(changes))
    result_id = retriever.retrieve(request)
    new_result = c.get(result_id, "retrieval-result")
    new_context = c.get(new_result["graph_context_id"], "graph-context")
    require(context["graph_version"] != new_context["graph_version"] or
            context["snapshot_id"] == new_context["snapshot_id"], "DOMAIN_REVISION",
            "the same graph version must resolve to the same snapshot")
    if synthesize is not None:
        retriever.validate_live_context(new_result["graph_context_id"])
    comparison = synthesize(result_id) if synthesize is not None else {"status": "NOT_RUN", "reason": "No synthesis executor supplied."}
    after = {r["id"]: r["hash"] for r in c.all("observation")}
    require(all(after.get(ref) == value for ref, value in before.items()), "REPLAY_OBSERVATION_CHANGED", "original receipts are immutable")
    retriever.validate_live_context(original["graph_context_id"])
    statuses = retriever.validate_live_context(new_result["graph_context_id"])
    access = AccessFilter(retriever.access_policy, c, statuses)

    original_refs = context_observations(context)
    preserved = {}
    for ref, value in before.items():
        linked = observation_uses_result(c, ref, original_result_id, context["security_scope"])
        if (linked or (ref in original_refs and access.decision(ref))) and observation_sources_readable(c, ref, access):
            preserved[ref] = value
    new_refs = sorted(set(after) - set(before))
    require(all(observation_uses_result(c, ref, result_id, new_context["security_scope"]) and observation_sources_readable(c, ref, access)
                for ref in new_refs), "REPLAY_OBSERVATION_LINEAGE", "new receipt does not cite the replayed result with readable sources")
    old_ids = {i["id"] for i in context["items"]}
    new_ids = {i["id"] for i in new_context["items"]}
    receipt = {"version": VERSION, "original_result_id": original_result_id,
        "replayed_result_id": result_id, "changed_parameters": deepcopy(changes),
        "original_graph_version": context["graph_version"], "replayed_graph_version": new_context["graph_version"],
        "original_classification_identity": context.get("classification_identity", classification_identity(c.get(context["snapshot_id"], "graph-snapshot"))),
        "replayed_classification_identity": new_context["classification_identity"],
        "original_research_domain_scope": c.get(original["query_id"], "retrieval-query").get("research_domain_scope"),
        "replayed_research_domain_scope": new_context["research_domain_scope"],
        "original_selected_ids": sorted(old_ids), "replayed_selected_ids": sorted(new_ids),
        "added_ids": sorted(new_ids-old_ids), "removed_ids": sorted(old_ids-new_ids),
        "observation_hashes_preserved": preserved, "new_observation_ids": new_refs,
        "synthesis_comparison": comparison, "authorization_granted": False, "created_at": now()}
    validate_record(c, {"kind": "retrieval-replay", "body": receipt})
    return c.put("retrieval-replay", receipt)
