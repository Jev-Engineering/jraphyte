"""Additive Minimum Evidence Closure / Decision IR integration."""
from __future__ import annotations
from copy import deepcopy
from typing import Any
from ..canonical import digest
from ..catalog import Catalog
from ..errors import require

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
        from .security import AccessFilter
        policy = current_access or catalog.get(context["access_id"], "graph-access")
        statuses = current_status if current_status is not None else context["source_status"]
        acl = AccessFilter(policy, catalog, statuses)
        for source_id in pack["closure"]["source_snapshot_ids"]:
            require(acl.allows("source", source_id), "ACCESS_DENIED", "model closure source not authorized")
        for candidate_id in pack["candidate_ids"]:
            candidate = catalog.get(candidate_id, "candidate")
            require(acl.allows("node", candidate["assertion"]["subject"]) and
                    acl.allows("node", candidate["assertion"]["object"]), "ACCESS_DENIED", "candidate endpoints not authorized")


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


def references(kind: str, body: dict[str, Any]) -> list[tuple[str, str]]:
    refs: list[tuple[str, str]] = []
    def add(key, expected):
        value = body.get(key)
        if value is not None:
            refs.extend((x, expected) for x in (value if isinstance(value, list) else [value]))
    if kind == "retrieval-query":
        add("candidate_id", "candidate"); add("decision_id", "*")
        if "research_domain_scope" in body:
            refs.append((body["research_domain_scope"]["taxonomy_id"], "research-domain-taxonomy"))
    elif kind == "retrieval-plan":
        add("candidate_id", "candidate"); add("retrieval_history", "retrieval-result")
        if "research_domain_scope" in body:
            refs.append((body["research_domain_scope"]["taxonomy_id"], "research-domain-taxonomy"))
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
    elif kind == "retrieval-evaluation":
        add("result_ids", "retrieval-result")
    if kind in {"pack", "observation", "resolution"}:
        add("graph_context_ids", "graph-context"); add("graph_retrieval_query_ids", "retrieval-query")
        add("source_retrieval_ids", "retrieval-result")
    return refs


def validate_record(catalog: Catalog, record: dict[str, Any]) -> None:
    kind, b = record["kind"], record["body"]
    if kind == "retrieval-query":
        from .contracts import validate_query
        validate_query(b)
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
        require(b.get("research_domain_binding") == context.get("research_domain_binding"), "DOMAIN_CONTEXT_BINDING", "lineage changed classification selection")
        require(b["graph_version"] == context["graph_version"] and b["query_id"] == context["query_id"],
                "RETRIEVAL_LINEAGE", "lineage query/version differs")
        require(all(len(x) == len({row["item_id"] for row in x}) for x in (b["selected"], b["discarded"], b["candidates"])),
                "RETRIEVAL_LINEAGE", "duplicate selection accounting")
        require({r["item_id"]: r["score"] for r in b["candidates"] if r["item_id"] in context["ranking_scores"]} == context["ranking_scores"],
                "RETRIEVAL_LINEAGE", "context and lineage ranking scores differ")
        selected = {x["item_id"] for x in b["selected"]}
        discarded = {x["item_id"] for x in b["discarded"]}
        candidates = {x["item_id"] for x in b["candidates"]}
        require(selected == {x["id"] for x in context["items"]} and not selected & discarded and
                selected | discarded == candidates, "RETRIEVAL_LINEAGE", "selection accounting differs")
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
        require(sorted(x["evidence_id"] for x in b["citations"]) == context["selected_evidence_ids"],
                "PROVENANCE_MISMATCH", "answer must cite every selected canonical evidence span once")
        for citation in b["citations"]:
            evidence = catalog.get(citation["evidence_id"], "evidence")
            require(citation["evidence_id"] in context["selected_evidence_ids"] and
                    all(citation[k] == evidence[k] for k in ("source_snapshot_id", "source_hash", "start", "end", "quote")),
                    "PROVENANCE_MISMATCH", "answer citation changed")
            require(citation["source_id"] == catalog.get(evidence["source_snapshot_id"], "source")["source_id"],
                    "PROVENANCE_MISMATCH", "answer source document ID changed")
