"""Additive Minimum Evidence Closure / Decision IR integration."""
from __future__ import annotations
from copy import deepcopy
from typing import Any
from ..canonical import digest
from ..catalog import Catalog
from ..errors import ContractError, require

LINEAGE_FIELDS = ("graph_retrieval_query_ids", "graph_context_ids", "source_retrieval_ids", "evidence_closure_id", "retrieval_fingerprint")


def lineage_fields(catalog: Catalog, contexts: list[str], results: list[str], closure_hash: str) -> dict[str, Any]:
    require(len(contexts) == len(set(contexts)) and len(results) == len(set(results)), "DUPLICATE_ID", "retrieval lineage")
    bodies = [catalog.get(x, "graph-context") for x in sorted(contexts)]
    for ref in results:
        result = catalog.get(ref, "retrieval-result")
        require(result["graph_context_id"] in contexts, "RETRIEVAL_LINEAGE", "result context omitted from pack")
    return {"graph_retrieval_query_ids": sorted({b["query_id"] for b in bodies}), "graph_context_ids": sorted(contexts),
            "source_retrieval_ids": sorted(results), "evidence_closure_id": "closure:" + closure_hash,
            "retrieval_fingerprint": digest(sorted({b["retrieval_fingerprint"] for b in bodies}))}


def validate_pack_lineage(catalog: Catalog, pack: dict[str, Any], *, current_access=None, current_status=None) -> None:
    present = {k for k in LINEAGE_FIELDS if k in pack}
    if not present:
        require(pack["materializer_version"] == "materializer-v1" and pack["packing_version"] == "complete-closure-v1",
                "RETRIEVAL_LINEAGE", "version claims retrieval without lineage")
        return
    if current_access is not None:
        require(current_status is not None, "SOURCE_STATUS_CAPABILITY", "live pack authorization requires current source status")
        _validate_live_pack_closure(catalog, pack, current_access, current_status)
    require(present == set(LINEAGE_FIELDS), "RETRIEVAL_LINEAGE", "all retrieval lineage fields required")
    expected = lineage_fields(catalog, pack["graph_context_ids"], pack["source_retrieval_ids"], pack["closure"]["hash"])
    require(all(pack[k] == expected[k] for k in LINEAGE_FIELDS), "RETRIEVAL_LINEAGE", "pack lineage differs")
    require(pack["materializer_version"] == "materializer-v1+graph-v1" and
            pack["packing_version"] == "minimum-source-graph-v1:" + expected["retrieval_fingerprint"],
            "RETRIEVAL_LINEAGE", "retrieval policy must change qualification applicability")
    from .service import validate_context
    for ref in pack["graph_context_ids"]:
        context = catalog.get(ref, "graph-context")
        request = catalog.get(context["query_id"], "retrieval-query")
        require(context["snapshot_id"] == pack["snapshot_id"] and context["security_scope"] == pack["security_scope"],
                "STALE_GRAPH_CONTEXT", "retrieval/pack snapshot or scope differs")
        require(request["requesting_component"].startswith("upstream") and request["candidate_id"] in pack["candidate_ids"],
                "RETRIEVAL_ROLE", "upstream candidate-bound query required")
        validate_context(catalog, ref, current_access=current_access, current_status=current_status)
        if current_access is not None:
            continue
        from .security import AccessFilter
        policy = catalog.get(context["access_id"], "graph-access")
        statuses = current_status if current_status is not None else context["source_status"]
        acl = AccessFilter(policy, catalog, statuses)
        for source_id in pack["closure"]["source_snapshot_ids"]:
            require(acl.source(source_id), "ACCESS_DENIED", "model closure source not currently authorized")
        for candidate_id in pack["candidate_ids"]:
            candidate = catalog.get(candidate_id, "candidate")
            require(acl.allows("node", candidate["assertion"]["subject"]) and
                    acl.allows("node", candidate["assertion"]["object"]), "ACCESS_DENIED", "candidate endpoints not authorized")


def _validate_live_pack_closure(catalog: Catalog, pack: dict[str, Any], policy, statuses) -> None:
    from ..adapter import validate_observation
    from .security import AccessFilter
    from .service import validate_context
    access = AccessFilter(policy, catalog, statuses)
    pending, seen = [pack], set()
    while pending:
        current = pending.pop()
        access.require_scope(current["security_scope"])
        for ref in current["closure"]["source_snapshot_ids"]:
            require(access.source(ref), "ACCESS_DENIED", "model closure source not currently authorized")
        for ref in current["closure"]["record_ids"]:
            record = catalog.record(ref)
            if record["kind"] == "candidate":
                assertion = record["body"]["assertion"]
                require(all(access.allows("node", assertion[field]) for field in ("subject", "object")),
                        "ACCESS_DENIED", "model closure candidate endpoints not currently authorized")
        for ref in current["prior_observation_ids"]:
            require(access.decision(ref), "ACCESS_DENIED", "prior model observation not currently authorized")
            validate_observation(catalog, ref)
            prior_pack_id = catalog.get(ref, "observation")["pack_id"]
            if prior_pack_id in seen:
                continue
            seen.add(prior_pack_id)
            prior_pack = catalog.get(prior_pack_id, "pack")
            for context_id in prior_pack.get("graph_context_ids", []):
                validate_context(catalog, context_id, current_access=policy, current_status=statuses)
            pending.append(prior_pack)


def validate_observation_lineage(observation: dict[str, Any], pack: dict[str, Any]) -> None:
    require({k: observation[k] for k in LINEAGE_FIELDS if k in observation} ==
            {k: pack[k] for k in LINEAGE_FIELDS if k in pack}, "RETRIEVAL_LINEAGE", "observation changed pack lineage")


def resolution_lineage(catalog: Catalog, observations: list[str]) -> dict[str, Any]:
    bodies = [catalog.get(x, "observation") for x in observations]
    bodies = [x for x in bodies if "graph_context_ids" in x]
    if not bodies:
        return {}
    return {"graph_retrieval_query_ids": sorted({r for b in bodies for r in b["graph_retrieval_query_ids"]}),
            "graph_context_ids": sorted({r for b in bodies for r in b["graph_context_ids"]}),
            "source_retrieval_ids": sorted({r for b in bodies for r in b["source_retrieval_ids"]}),
            "evidence_closure_id": bodies[0]["evidence_closure_id"] if len(bodies) == 1 else
                                   "closures:" + digest(sorted({b["evidence_closure_id"] for b in bodies})),
            "retrieval_fingerprint": bodies[0]["retrieval_fingerprint"] if len(bodies) == 1 else
                                     digest(sorted({b["retrieval_fingerprint"] for b in bodies}))}


def context_observations(context: dict[str, Any]) -> set[str]:
    return {ref for item in context["items"] for ref in item["observation_ids"]} | set(context.get("reranking_observation_ids", []))


def observation_uses_result(catalog: Catalog, ref: str, result_id: str, security_scope: str) -> bool:
    observation = catalog.get(ref, "observation")
    if observation["pack_id"] not in catalog:
        return False
    pack = catalog.get(observation["pack_id"], "pack")
    if not (observation["security_scope"] == pack["security_scope"] == security_scope and
            result_id in pack.get("source_retrieval_ids", [])):
        return False
    result = catalog.get(result_id, "retrieval-result")
    request = catalog.get(result["query_id"], "retrieval-query")
    candidate = observation["candidate_id"]
    return (result["graph_context_id"] in pack["graph_context_ids"] and
            request["candidate_id"] == candidate and candidate in pack["candidate_ids"])


def observation_sources_readable(catalog: Catalog, ref: str, access) -> bool:
    observation = catalog.get(ref, "observation")
    if observation["pack_id"] not in catalog or observation["candidate_id"] not in catalog:
        return False
    pack = catalog.get(observation["pack_id"], "pack")
    if observation["security_scope"] != access.policy["tenant"]:
        return False
    try:
        validate_pack_lineage(catalog, pack, current_access=access.policy, current_status=access.statuses)
        if "graph_context_ids" not in pack:
            _validate_live_pack_closure(catalog, pack, access.policy, access.statuses)
    except ContractError:
        return False
    return True


def references(kind: str, body: dict[str, Any]) -> list[tuple[str, str]]:
    refs: list[tuple[str, str]] = []
    def add(key, expected):
        value = body.get(key)
        if value is not None:
            refs.extend((x, expected) for x in (value if isinstance(value, list) else [value]))
    if kind == "retrieval-query":
        add("candidate_id", "candidate"); add("decision_id", "*")
    elif kind == "retrieval-plan":
        add("candidate_id", "candidate"); add("retrieval_history", "retrieval-result")
    elif kind == "graph-context":
        add("query_id", "retrieval-query"); add("snapshot_id", "graph-snapshot"); add("access_id", "graph-access")
        add("provenance_refs", "*"); add("selected_evidence_ids", "evidence"); add("reranking_observation_ids", "observation"); add("reranking_base_context_id", "graph-context")
    elif kind == "retrieval-lineage":
        add("query_id", "retrieval-query"); add("graph_context_id", "graph-context"); add("plan_id", "retrieval-plan")
    elif kind == "retrieval-result":
        add("query_id", "retrieval-query"); add("graph_context_id", "graph-context")
        add("lineage_id", "retrieval-lineage"); add("plan_id", "retrieval-plan"); add("source_evidence_ids", "evidence")
    elif kind == "retrieval-expansion":
        add("candidate_id", "candidate"); add("previous_result_id", "retrieval-result"); add("result_id", "retrieval-result"); add("decision_ids", "*")
    elif kind == "graphrag-answer":
        add("query_id", "retrieval-query"); add("result_id", "retrieval-result"); add("graph_context_id", "graph-context")
    elif kind == "retrieval-replay":
        add("original_result_id", "retrieval-result"); add("replayed_result_id", "retrieval-result"); add("new_observation_ids", "observation")
        add("replay_access_id", "graph-access")
        if "replayed_classification_identity" in body:
            refs.extend((ref, "observation") for ref in body["observation_hashes_preserved"])
    elif kind == "retrieval-evaluation":
        add("result_ids", "retrieval-result")
    if kind in {"retrieval-query", "retrieval-plan"} and body.get("research_domain_scope") is not None:
        refs.append((body["research_domain_scope"]["taxonomy_id"], "research-domain-taxonomy"))
    if kind in {"pack", "observation", "resolution"}:
        add("graph_context_ids", "graph-context"); add("graph_retrieval_query_ids", "retrieval-query")
        add("source_retrieval_ids", "retrieval-result")
    return refs


def validate_record(catalog: Catalog, record: dict[str, Any]) -> None:
    kind, b = record["kind"], record["body"]
    if kind == "retrieval-query":
        from .contracts import validate_query
        validate_query(b)
        from .domains import validate_scope
        validate_scope(catalog, b.get("research_domain_scope"))
    elif kind == "retrieval-plan":
        from .domains import validate_scope
        validate_scope(catalog, b.get("research_domain_scope"))
    elif kind == "graph-context":
        from .service import validate_context
        validate_context(catalog, record["id"])
    elif kind == "retrieval-result":
        context = catalog.get(b["graph_context_id"], "graph-context")
        lineage = catalog.get(b["lineage_id"], "retrieval-lineage")
        require(b["query_id"] == context["query_id"] == lineage["query_id"] and
                lineage["graph_context_id"] == b["graph_context_id"] and
                b["source_evidence_ids"] == context["selected_evidence_ids"] and
                b["usage"] == lineage["usage"] and b["plan_id"] == lineage["plan_id"], "RETRIEVAL_LINEAGE", "result binding differs")
    elif kind == "retrieval-lineage":
        context = catalog.get(b["graph_context_id"], "graph-context")
        require(b["graph_version"] == context["graph_version"] and b["query_id"] == context["query_id"],
                "RETRIEVAL_LINEAGE", "lineage query/version differs")
        if b["plan_id"] is not None:
            request = catalog.get(b["query_id"], "retrieval-query")
            plan = catalog.get(b["plan_id"], "retrieval-plan")
            require(plan["candidate_id"] == request["candidate_id"] and
                    digest(plan.get("research_domain_scope")) == digest(request.get("research_domain_scope")),
                    "RETRIEVAL_PLAN_BINDING", "candidate or research-domain scope differs")
        require(all(len(x) == len({row["item_id"] for row in x}) for x in (b["selected"], b["discarded"], b["candidates"])),
                "RETRIEVAL_LINEAGE", "duplicate selection accounting")
        require({r["item_id"]: r["score"] for r in b["candidates"] if r["item_id"] in context["ranking_scores"]} == context["ranking_scores"],
                "RETRIEVAL_LINEAGE", "context and lineage ranking scores differ")
        selected = {x["item_id"] for x in b["selected"]}
        discarded = {x["item_id"] for x in b["discarded"]}
        candidates = {x["item_id"] for x in b["candidates"]}
        require(selected == {x["id"] for x in context["items"]} and not selected & discarded and
                selected | discarded == candidates, "RETRIEVAL_LINEAGE", "selection accounting differs")
        if "classification_identity" in context:
            require("research_domain_scope" in b and
                    digest(b.get("classification_identity")) == digest(context["classification_identity"]) and
                    digest(b["research_domain_scope"]) == digest(context["research_domain_scope"]),
                    "DOMAIN_REVISION", "lineage classification identity or scope differs")
    elif kind == "retrieval-replay":
        from ..adapter import validate_observation
        from ..compiler import validate_pack
        from ..domain_publication import classification_identity
        from ..replay import RETRIEVAL_REPLAY_PARAMETERS
        from .security import AccessFilter
        from .service import validate_context
        results = {prefix: catalog.get(b[prefix + "_result_id"], "retrieval-result")
                   for prefix in ("original", "replayed")}
        contexts = {prefix: catalog.get(result["graph_context_id"], "graph-context") for prefix, result in results.items()}
        if "replay_access_id" not in b and all("classification_identity" not in context and "research_domain_scope" not in context
               for context in contexts.values()) and not any(
                   prefix + field in b for prefix in contexts for field in ("_classification_identity", "_research_domain_scope")):
            return
        require("replay_access_id" in b, "REPLAY_SCOPE", "domain-aware replay requires a bound disclosure policy")
        require(set(b["changed_parameters"]) <= RETRIEVAL_REPLAY_PARAMETERS,
                "REPLAY_SCOPE", "replay changes a protected query parameter")
        requests = {}
        for prefix, result in results.items():
            context = contexts[prefix]
            request = catalog.get(result["query_id"], "retrieval-query")
            requests[prefix] = request
            require(result["query_id"] == context["query_id"] and
                    b[prefix + "_graph_version"] == context["graph_version"] and
                    b[prefix + "_selected_ids"] == sorted(i["id"] for i in context["items"]),
                    "RETRIEVAL_LINEAGE", "replay context version or selection differs")
            identity_key, scope_key = prefix + "_classification_identity", prefix + "_research_domain_scope"
            require(identity_key in b and scope_key in b and
                    digest(b[identity_key]) == digest(classification_identity(catalog.get(context["snapshot_id"], "graph-snapshot"))) and
                    digest(b[scope_key]) == digest(request.get("research_domain_scope")),
                    "DOMAIN_REVISION", "replay classification identity or scope differs")
        original, replayed = contexts["original"], contexts["replayed"]
        replayed_policy = catalog.get(replayed["access_id"], "graph-access")
        policy = catalog.get(b["replay_access_id"], "graph-access")
        require(all(policy[k] == replayed_policy[k] for k in ("tenant", "workspace", "user")),
                "REPLAY_SCOPE", "replay changed the authenticated principal")
        for result in results.values():
            validate_context(catalog, result["graph_context_id"], current_access=policy, current_status=replayed["source_status"])
        require(original["graph_version"] != replayed["graph_version"] or
                original["snapshot_id"] == replayed["snapshot_id"], "DOMAIN_REVISION",
                "the same graph version must resolve to the same snapshot")
        expected = {**requests["original"], "graph_version": original["graph_version"],
                    "created_at": requests["replayed"]["created_at"], **b["changed_parameters"]}
        require(digest(expected) == digest(requests["replayed"]), "REPLAY_SCOPE", "replayed query differs from declared changes")
        old_ids, new_ids = set(b["original_selected_ids"]), set(b["replayed_selected_ids"])
        require(b["added_ids"] == sorted(new_ids - old_ids) and b["removed_ids"] == sorted(old_ids - new_ids),
                "RETRIEVAL_LINEAGE", "replay selection delta differs")
        preserved, new_refs = b["observation_hashes_preserved"], b["new_observation_ids"]
        require(len(new_refs) == len(set(new_refs)) and not set(new_refs) & preserved.keys(),
                "REPLAY_OBSERVATION_LINEAGE", "preserved and newly emitted receipts must be distinct")
        comparison = b["synthesis_comparison"]
        require(comparison == {"observation_ids": new_refs} or (not new_refs and comparison == {
                "status": "NOT_RUN", "reason": "No synthesis executor supplied."}),
                "REPLAY_OBSERVATION_LINEAGE", "comparison must be derived from authorized receipts")
        original_refs = context_observations(original)
        access = AccessFilter(policy, catalog, replayed["source_status"])
        for ref, value in preserved.items():
            observation = catalog.record(ref, "observation")
            require(observation["hash"] == value and access.decision(ref) and observation_sources_readable(catalog, ref, access) and
                    (ref in original_refs or observation_uses_result(
                        catalog, ref, b["original_result_id"], original["security_scope"])),
                    "REPLAY_OBSERVATION_LINEAGE", "preserved receipt hash or original result attribution differs")
        for ref in new_refs:
            require(access.decision(ref) and observation_sources_readable(catalog, ref, access) and
                    observation_uses_result(catalog, ref, b["replayed_result_id"], replayed["security_scope"]),
                    "REPLAY_OBSERVATION_LINEAGE", "new receipt does not cite the replayed result")
        verified_packs = set()
        for ref in sorted(set(preserved) | set(new_refs)):
            validate_observation(catalog, ref)
            pack_id = catalog.get(ref, "observation")["pack_id"]
            if pack_id not in verified_packs:
                validate_pack(catalog, catalog.get(pack_id, "pack"))
                verified_packs.add(pack_id)
    elif kind == "resolution":
        expected = resolution_lineage(catalog, b["observation_ids"])
        require({k: b[k] for k in LINEAGE_FIELDS if k in b} == expected, "RETRIEVAL_LINEAGE", "resolver lineage differs")
    elif kind == "graphrag-answer":
        result = catalog.get(b["result_id"], "retrieval-result")
        request = catalog.get(b["query_id"], "retrieval-query")
        require(result["graph_context_id"] == b["graph_context_id"] and result["query_id"] == b["query_id"] and
                b["mode"] == request["mode"], "RETRIEVAL_LINEAGE", "answer result/query/mode binding differs")
        context = catalog.get(b["graph_context_id"], "graph-context")
        require(b["items"] == context["items"] and b["query_id"] == context["query_id"] and
                b["graph_version"] == context["graph_version"], "RETRIEVAL_LINEAGE", "answer context differs")
        if "classification_identity" in context:
            require("research_domain_scope" in b and
                    digest(b.get("classification_identity")) == digest(context["classification_identity"]) and
                    digest(b["research_domain_scope"]) == digest(context["research_domain_scope"]),
                    "DOMAIN_REVISION", "answer classification identity or scope differs")
        require(sorted(x["evidence_id"] for x in b["citations"]) == context["selected_evidence_ids"],
                "PROVENANCE_MISMATCH", "answer must cite every selected canonical evidence span once")
        for citation in b["citations"]:
            evidence = catalog.get(citation["evidence_id"], "evidence")
            require(citation["evidence_id"] in context["selected_evidence_ids"] and
                    all(citation[k] == evidence[k] for k in ("source_snapshot_id", "source_hash", "start", "end", "quote")),
                    "PROVENANCE_MISMATCH", "answer citation changed")
            require(citation["source_id"] == catalog.get(evidence["source_snapshot_id"], "source")["source_id"],
                    "PROVENANCE_MISMATCH", "answer source document ID changed")
