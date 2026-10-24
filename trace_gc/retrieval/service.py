"""Hybrid evidence/graph retrieval, auditable ranking, caching and downstream API."""
from __future__ import annotations
from collections import OrderedDict
from copy import deepcopy
import threading
from typing import Any, Callable
from ..canonical import digest
from ..catalog import Catalog
from ..compiler import now
from ..errors import ContractError, require
from .budget import BudgetMeter, conservative_tokens
from .contracts import RetrievalBudget, STRATEGIES, VERSION, validate_query
from .items import canonical_item, conflict_pairs, visible_edges
from .security import AccessFilter
from .store import GraphQueryAdapter, GraphReadView
from .strategies import BuiltinStrategy, GraphRetriever, SearchSpace
from .vector import EmbeddingModel, HashingEmbedding, terms


class RetrievalCache:
    """Bounded, deep-copy LRU. Authorization and source epochs are part of every key."""
    version = "acl-snapshot-lru-v1"
    def __init__(self, capacity: int = 128):
        require(type(capacity) is int and capacity >= 0, "CACHE_CONFIG", "nonnegative capacity")
        self.capacity = capacity
        self._entries: OrderedDict[str, list[dict[str, Any]]] = OrderedDict()
        self._lock = threading.RLock()
        self.hits = self.misses = self.invalidations = 0

    def get(self, key: str) -> list[dict[str, Any]] | None:
        with self._lock:
            if key not in self._entries:
                self.misses += 1
                return None
            self.hits += 1
            self._entries.move_to_end(key)
            return deepcopy(self._entries[key])

    def put(self, key: str, value: list[dict[str, Any]]) -> None:
        with self._lock:
            if not self.capacity:
                return
            self._entries[key] = deepcopy(value)
            self._entries.move_to_end(key)
            while len(self._entries) > self.capacity:
                self._entries.popitem(last=False)

    def invalidate(self) -> None:
        with self._lock:
            self.invalidations += len(self._entries)
            self._entries.clear()


def ranking_features(item: dict[str, Any], query: dict[str, Any], similarity: float = 0.0) -> dict[str, float]:
    wanted = terms(query["text"])
    lexical = len(wanted & terms(item["text"])) / max(1, len(wanted))
    distance = len(item["assertion_ids"]) if item["kind"] == "PATH" else 1
    return {"lexical_overlap": lexical, "semantic_similarity": similarity,
            "entity_relevance": float(bool(set(query["focus_entities"]) & set(item["entity_ids"]))),
            "graph_distance_utility": 1.0 / max(1, distance),
            "relation_relevance": float(bool(set(query["focus_relationships"]) & set(item["relation_types"]))),
            "provenance_completeness": float(item["provenance_complete"]),
            "contradiction_value": float(item["trust_class"] == "CONFLICTED_GRAPH_FACT" or item["kind"] == "CONFLICT"),
            "canonical_source": float(item["kind"] == "EVIDENCE"),
            "community_relevance": float(item["kind"] == "COMMUNITY"),
            "temporal_relevance": float(query["temporal_scope"]["valid_at"] is not None),
            "historical_penalty": float(item["trust_class"] in {"SUPERSEDED_GRAPH_FACT", "HISTORICAL_GRAPH_FACT"})}


def score(features: dict[str, float], strategy: str) -> float:
    if strategy == "lexical-first-v1":
        return 10*features["lexical_overlap"] + features["entity_relevance"] + features["contradiction_value"]
    return (3*features["lexical_overlap"] + 3*features["semantic_similarity"] +
            2*features["entity_relevance"] + features["graph_distance_utility"] +
            features["relation_relevance"] + features["provenance_completeness"] +
            3*features["contradiction_value"] + features["canonical_source"] - .5*features["historical_penalty"])


def effective_strategies(query: dict[str, Any]) -> list[str]:
    methods = list(query["retrieval_strategy"])
    if query["mode"] == "PROVENANCE_ONLY":
        return ["PROVENANCE"] if query["include_provenance"] else []
    if query["mode"] == "CONTRADICTIONS_ONLY":
        return ["CONFLICT"]
    graph_methods = set(methods) - {"LEXICAL", "VECTOR", "SOURCE", "EVIDENCE"}
    if query["include_conflicts"] and (graph_methods or "research_domain_scope" in query) and "CONFLICT" not in methods:
        methods.append("CONFLICT")
    # Conflict discovery runs before general context, so a cheap cap cannot silently
    # spend its entire budget on only the supporting side of a known contradiction.
    return sorted(dict.fromkeys(methods), key=lambda x: (x != "CONFLICT", methods.index(x)))


def retrieval_fingerprint(query, versions, embedding_version, adapter_version, acl_version, domain_binding=None):
    """The precise retrieval configuration participates in qualification/replay scope."""
    methods = effective_strategies(query)
    base = digest({"retrieval": VERSION, "strategies": versions, "embedding": embedding_version,
                              "adapter": adapter_version, "ranking": query["ranking_strategy"],
                              "budget": query["budget"], "methods": methods, "hop_limit": query["hop_limit"],
                              "mode": query["mode"], "relation_filters": [query["allowed_relation_types"], query["excluded_relation_types"]],
                              "history": [query["include_historical"], query["include_superseded"]],
                              "provenance": query["include_provenance"], "acl_version": acl_version})

    if "research_domain_scope" in query:
        require(domain_binding is not None and domain_binding["scope"] == query["research_domain_scope"], "DOMAIN_CONTEXT_BINDING", "exact domain selection required")
        return digest({"base": base, "domain": domain_binding})
    return base


class HybridRetriever:
    """One retrieval service for two roles; neither role commits graph state.

    The authenticated application supplies access_policy, not the untrusted query.
    A shared RunBudget can additionally cap requests across retries/processes.
    """
    version = VERSION
    def __init__(self, adapter: GraphQueryAdapter, *, access_policy: dict[str, Any],
                 catalog: Catalog | None = None, embedding: EmbeddingModel | None = None,
                 strategies: dict[str, GraphRetriever] | None = None, cache: RetrievalCache | None = None,
                 run_budget: Any = None, token_counter: Callable[[Any], int] = conservative_tokens):
        self.adapter = adapter
        self.access_policy = deepcopy(access_policy)
        self.catalog = catalog if catalog is not None else Catalog()
        self.embedding = embedding or HashingEmbedding()
        self.strategies = {name: BuiltinStrategy(name) for name in STRATEGIES}
        self.strategies.update(strategies or {})
        require(all(isinstance(x, str) and bool(x) and x not in {"latest", "default"}
                    for x in [self.embedding.version, adapter.version] + [s.version for s in self.strategies.values()]),
                "RETRIEVAL_VERSION", "pin every embedding, adapter and strategy implementation version")
        self.cache = cache if cache is not None else RetrievalCache()
        self.run_budget, self.token_counter = run_budget, token_counter
        self._last_read_identity: str | None = None
        self._lock = threading.RLock()

    def set_access_policy(self, policy: dict[str, Any]) -> None:
        """Trusted application ACL refresh; revocation invalidates every cached result."""
        from ..schema import validate
        validate("graph-access", policy)
        with self._lock:
            self.access_policy = deepcopy(policy)
            self.cache.invalidate()

    def retrieve(self, query: dict[str, Any], *, plan_id: str | None = None) -> str:
        with self._lock:
            return self._retrieve(deepcopy(query), plan_id=plan_id)

    def _retrieve(self, query: dict[str, Any], *, plan_id: str | None = None) -> str:
        validate_query(query)
        meter = BudgetMeter(RetrievalBudget(**query["budget"]))
        if self.run_budget is not None:
            self.run_budget.consume("retrieval_requests")
        view = self.adapter.read(query)
        # Current source status participates in identity even for an old graph version.
        access = AccessFilter(self.access_policy, view.catalog, view.source_status,
                              historical=query["include_historical"] or query["mode"] == "HISTORICAL")
        access.require_scope(query["security_scope"])
        from .domain_scope import binding, DomainFilter
        selected_domain = binding(view, query)
        if selected_domain is not None:
            require(view.domain_index_rows is not None or view.classification_projection is None, "DOMAIN_HISTORY_REQUIRED", "adapter must verify committed classification history")
            DomainFilter(view, access, query, {}, [])
        for record in view.catalog.all():
            self.catalog.add(record)
        if plan_id is not None:
            plan = self.catalog.get(plan_id, "retrieval-plan")
            require(plan["candidate_id"] == query["candidate_id"], "RETRIEVAL_PLAN_BINDING", "candidate differs")
            require(plan.get("research_domain_scope") == query.get("research_domain_scope"),
                    "DOMAIN_PLAN_BINDING", "query changed the planned domain scope")
        query_id = self.catalog.put("retrieval-query", query)
        access_id = self.catalog.put("graph-access", self.access_policy)
        methods = effective_strategies(query)
        versions = {name: self.strategies[name].version for name in methods}
        fingerprint = retrieval_fingerprint(query, versions, self.embedding.version,
                                            view.adapter_version, self.access_policy["version"], selected_domain)
        key_query = {k: v for k, v in query.items() if k not in {"created_at", "retrieval_round"}}
        key = digest({"view": view.identity, "query": key_query, "acl": access.fingerprint,
                      "retrieval_fingerprint": fingerprint})
        if self._last_read_identity != view.identity:
            self.cache.invalidate()
            self._last_read_identity = view.identity
        candidates = self.cache.get(key)
        cache_hit = candidates is not None
        partial = False
        meter.used["graph_queries"] = 1  # Consistent read, including on a cache hit.
        stop = "SEARCH_COMPLETE"
        if candidates is None:
            candidates_by_id: dict[str, dict[str, Any]] = {}
            try:
                meter.check()
                # ACL filtering precedes path expansion, embeddings and semantic models.
                visible = visible_edges(view, access, query, meter)
                conflicts = conflict_pairs(visible, view.catalog.get(view.snapshot["schema_id"], "schema")["relations"], meter)
                space = SearchSpace(view, access, query, visible, conflicts, meter, self.embedding)
                for name in methods:
                    meter.check()
                    if name not in {"LEXICAL", "VECTOR", "SOURCE", "EVIDENCE"}:
                        meter.used["graph_queries"] += 1
                    for rank, raw_item in enumerate(self.strategies[name].retrieve(space), 1):
                        meter.check()
                        similarity = raw_item.pop("_semantic_similarity", 0.0)
                        # Plugins may return candidates; they cannot forge source text,
                        # trust classes, provenance or access labels.
                        canonical = canonical_item(view, access, query, kind=raw_item["kind"],
                            ref=raw_item["canonical_ref"], members=raw_item["member_assertion_ids"],
                            edges=visible, conflicts=conflicts, meter=meter)
                        require(canonical == raw_item, "CONTEXT_MATERIALIZATION", "retriever changed canonical context")
                        features = ranking_features(canonical, query, similarity)
                        row = candidates_by_id.setdefault(canonical["id"], {"item": canonical, "methods": [],
                            "features": features, "score": score(features, query["ranking_strategy"]), "rrf": 0.0})
                        row["methods"] = sorted(set(row["methods"] + [name]))
                        row["features"]["semantic_similarity"] = max(similarity, row["features"]["semantic_similarity"])
                        row["score"] = score(row["features"], query["ranking_strategy"])
                        row["rrf"] += 1/(60+rank)
            except ContractError as exc:
                if exc.code != "RETRIEVAL_BUDGET_EXHAUSTED":
                    raise
                partial, stop = True, "RETRIEVAL_BUDGET_EXHAUSTED"
            candidates = list(candidates_by_id.values())
            if not partial:
                self.cache.put(key, candidates)
        if selected_domain is not None:
            # A provider callback or concurrent authority update may revoke a
            # source while candidates are being computed. Do not return stale
            # membership/text, even when the graph selector is historical.
            fresh = self.adapter.read(query)
            meter.used["graph_queries"] += 1
            require(fresh.identity == view.identity and self.access_policy == access.policy,
                    "STALE_GRAPH_CONTEXT", "authority or access changed during scoped retrieval")
        selected, discarded, rows = [], [], []
        seen = {resource: set() for resource in ("nodes", "edges", "paths", "communities", "decisions", "source_spans")}
        ranked = sorted(candidates, key=lambda r: (r["item"]["kind"] != "CONFLICT",
                        -(r["rrf"] if query["ranking_strategy"] == "rrf-v1" else r["score"]), r["item"]["id"]))
        blocked_conflict_members: set[str] = set()
        for row in ranked:
            item = row["item"]
            utility = row["rrf"] if query["ranking_strategy"] == "rrf-v1" else row["score"]
            rows.append({"item_id": item["id"], "kind": item["kind"], "score": utility,
                         "features": row["features"], "methods": row["methods"]})
            reported_tokens = self.token_counter(item)
            require(type(reported_tokens) is int and reported_tokens >= 0, "TOKEN_ACCOUNTING", "invalid retrieval token count")
            tokens = max(conservative_tokens(item), reported_tokens)
            if blocked_conflict_members & set(item["assertion_ids"]):
                accepted, reason = False, "incomplete_conflict_pair_blocked"
            else:
                try:
                    meter.check()
                    accepted, reason = meter.accept(item, tokens, seen)
                except ContractError as exc:
                    if exc.code != "RETRIEVAL_BUDGET_EXHAUSTED":
                        raise
                    accepted, reason = False, "latency_budget"
            if not accepted and item["kind"] == "CONFLICT":
                blocked_conflict_members.update(item["assertion_ids"])
            if accepted:
                selected.append(item)
            else:
                partial = True
                discarded.append({"item_id": item["id"], "reason": reason})
        if discarded and stop == "SEARCH_COMPLETE":
            stop = "CONTEXT_BUDGET_REACHED"
        selected_ids = {i["id"] for i in selected}
        evidence_ids = sorted({e for i in selected for e in i["evidence_ids"]})
        source_ids = sorted({s for i in selected for s in i["source_ids"]})
        # Internal lineage stores only IDs needed to revalidate selected material.
        available = sorted({r for i in selected for r in i["record_refs"] if r in view.available_record_ids})
        body = {"version": VERSION, "query_id": query_id, "snapshot_id": view.snapshot_id,
                "graph_version": view.snapshot["graph_version"], "security_scope": query["security_scope"],
                "access_id": access_id, "source_status": {s: status for s, status in view.source_status.items() if access.allows("source", s)},
                "available_record_ids": available, "focus_entities": [x for x in query["focus_entities"] if access.allows("node", x)],
                "items": selected, "retrieved_nodes": sorted(seen["nodes"]), "retrieved_edges": sorted(seen["edges"]),
                "retrieved_paths": sorted(seen["paths"]), "communities": sorted(seen["communities"]),
                "ontology_fragments": sorted(i["id"] for i in selected if i["kind"] == "ONTOLOGY"),
                "schema_fragments": sorted(i["id"] for i in selected if i["kind"] == "SCHEMA"),
                "provenance_refs": sorted({r for i in selected for r in i["record_refs"]}),
                "decision_refs": sorted(seen["decisions"]),
                "conflict_refs": sorted(i["id"] for i in selected if i["kind"] == "CONFLICT"),
                "temporal_scope": query["temporal_scope"], "retrieval_methods": methods,
                "ranking_scores": {r["item_id"]: r["score"] for r in rows if r["item_id"] in selected_ids},
                "selected_evidence_ids": evidence_ids, "retrieval_fingerprint": fingerprint,
                "embedding_version": self.embedding.version, "adapter_version": view.adapter_version,
                "strategy_versions": versions, "created_at": now()}
        if selected_domain is not None:
            body["research_domain_binding"] = selected_domain
        context_id = self.catalog.put("graph-context", body)
        lineage = {"version": VERSION, "query_id": query_id, "graph_context_id": context_id, "plan_id": plan_id,
                   "requesting_component": query["requesting_component"], "graph_version": body["graph_version"],
                   "retrieval_strategies": methods, "strategy_versions": versions, "candidates": rows,
                   "selected": [{"item_id": i["id"], "reason": "atomic_conflict_pair" if i["kind"] == "CONFLICT" else "bounded_utility"} for i in selected],
                   "discarded": discarded, "budget": query["budget"], "usage": deepcopy(meter.used),
                   "cache_key": key, "cache_hit": cache_hit, "cache_version": self.cache.version,
                   "embedding_version": self.embedding.version, "ranking_strategy": query["ranking_strategy"],
                   "score_type": "POLICY_UTILITY_NOT_PROBABILITY", "stop_reason": stop,
                   "latency_ms": meter.elapsed_ms, "cost_units": meter.used["cost_units"], "created_at": now()}
        if selected_domain is not None:
            lineage["research_domain_binding"] = selected_domain
        lineage_id = self.catalog.put("retrieval-lineage", lineage)
        warnings = [stop] if partial else []
        if blocked_conflict_members:
            warnings.append("CONFLICT_PAIR_EXCLUDED_BY_BUDGET")
        if not query["include_conflicts"]:
            warnings.append("CONFLICT_SEARCH_DISABLED_BY_REQUEST")
        if any(i["generated_summary"] for i in selected):
            warnings.append("SUMMARIES_ARE_NOT_CANONICAL_EVIDENCE")
        if any(i["trust_class"] in {"HISTORICAL_GRAPH_FACT", "SUPERSEDED_GRAPH_FACT"} for i in selected):
            warnings.append("HISTORICAL_OR_SUPERSEDED_CONTEXT")
        return self.catalog.put("retrieval-result", {"version": VERSION, "query_id": query_id,
            "graph_context_id": context_id, "lineage_id": lineage_id, "plan_id": plan_id,
            "source_evidence_ids": evidence_ids, "status": "PARTIAL" if partial else "COMPLETE" if selected else "EMPTY",
            "warnings": sorted(set(warnings)), "usage": deepcopy(meter.used), "created_at": now()})


def validate_context(catalog: Catalog, context_id: str, *, current_access: dict[str, Any] | None = None,
                     current_status: dict[str, Any] | None = None) -> None:
    """Reconstruct selected data, typed projections and source attribution exactly."""
    context = catalog.get(context_id, "graph-context")
    query = catalog.get(context["query_id"], "retrieval-query")
    validate_query(query)
    snap = catalog.get(context["snapshot_id"], "graph-snapshot")
    require(context["graph_version"] == snap["graph_version"] and context["security_scope"] == query["security_scope"],
            "STALE_GRAPH_CONTEXT", "query/snapshot/scope differs")
    require(query["graph_version"] is None or query["graph_version"] == snap["graph_version"],
            "STALE_GRAPH_CONTEXT", "explicit graph version differs")
    policy = catalog.get(context["access_id"], "graph-access")
    require(set(context["strategy_versions"]) == set(effective_strategies(query)) and
            context["retrieval_methods"] == effective_strategies(query), "RETRIEVAL_CONFIGURATION", "strategies differ")
    base_fingerprint = retrieval_fingerprint(query, context["strategy_versions"], context["embedding_version"],
                                            context["adapter_version"], policy["version"], context.get("research_domain_binding"))
    if "reranking_observation_ids" not in context:
        require("reranking_base_context_id" not in context and context["retrieval_fingerprint"] == base_fingerprint,
                "RETRIEVAL_CONFIGURATION", "retrieval fingerprint differs")
    else:
        from .reranker import validate_reranked_context
        validate_reranked_context(catalog, context)
    statuses = current_status if current_status is not None else context["source_status"]
    access = AccessFilter(current_access or policy, catalog, statuses,
                          historical=query["include_historical"] or query["mode"] == "HISTORICAL")
    access.require_scope(query["security_scope"])
    view = GraphReadView(catalog, context["snapshot_id"], statuses, set(context["available_record_ids"]), [], context["adapter_version"])
    from .domain_scope import binding
    require(context.get("research_domain_binding") == binding(view, query), "DOMAIN_CONTEXT_BINDING", "context changed selected taxonomy/projection")
    # Reconstruct conflicts using the complete authorized snapshot, including their
    # sources. Persisted context statuses include selected conflicts' source spans.
    edges = visible_edges(view, access, query)
    conflicts = conflict_pairs(edges, catalog.get(snap["schema_id"], "schema")["relations"])
    ids = [i["id"] for i in context["items"]]
    require(len(ids) == len(set(ids)), "DUPLICATE_ID", "context item IDs")
    for item in context["items"]:
        expected = canonical_item(view, access, query, kind=item["kind"], ref=item["canonical_ref"],
                                  members=item["member_assertion_ids"], edges=edges, conflicts=conflicts)
        require(item == expected, "CONTEXT_MATERIALIZATION", "source-derived context differs from canonical records")
    projections = {"retrieved_nodes": {e for i in context["items"] for e in i["entity_ids"]},
                   "retrieved_edges": {e for i in context["items"] for e in i["assertion_ids"]},
                   "selected_evidence_ids": {e for i in context["items"] for e in i["evidence_ids"]},
                   "decision_refs": {e for i in context["items"] for e in i["decision_ids"]},
                   "provenance_refs": {e for i in context["items"] for e in i["record_refs"]},
                   "retrieved_paths": {i["id"] for i in context["items"] if i["kind"] == "PATH"},
                   "communities": {i["id"] for i in context["items"] if i["kind"] == "COMMUNITY"},
                   "conflict_refs": {i["id"] for i in context["items"] if i["kind"] == "CONFLICT"},
                   "ontology_fragments": {i["id"] for i in context["items"] if i["kind"] == "ONTOLOGY"},
                   "schema_fragments": {i["id"] for i in context["items"] if i["kind"] == "SCHEMA"}}
    for field, values in projections.items():
        require(context[field] == sorted(values), "CONTEXT_PROJECTION", field)
    require(set(context["ranking_scores"]) == set(ids), "CONTEXT_PROJECTION", "ranking coverage")
    meter = BudgetMeter(RetrievalBudget(**query["budget"]))
    seen = {r: set() for r in ("nodes", "edges", "paths", "communities", "decisions", "source_spans")}
    for item in context["items"]:
        # Validation uses the conservative offline upper bound. Provider-aware
        # packing remains a separately qualified live-adapter requirement.
        ok, reason = meter.accept(item, conservative_tokens(item), seen)
        require(ok, "GRAPH_CONTEXT_OVERLOAD", reason)


class GraphRAGQueryService:
    """Downstream search/QA/agent evidence contexts, not an answer-truth oracle."""
    def __init__(self, retriever: HybridRetriever):
        self.retriever = retriever

    def query(self, request: dict[str, Any]) -> dict[str, Any]:
        require(request["requesting_component"].startswith("downstream"), "RETRIEVAL_ROLE", "downstream role required")
        result_id = self.retriever.retrieve(request)
        c = self.retriever.catalog
        result = c.get(result_id, "retrieval-result")
        context = c.get(result["graph_context_id"], "graph-context")
        validate_context(c, result["graph_context_id"], current_access=self.retriever.access_policy)
        citations = []
        for ref in context["selected_evidence_ids"]:
            evidence = c.get(ref, "evidence")
            source = c.get(evidence["source_snapshot_id"], "source")
            citations.append({"evidence_id": ref, "source_snapshot_id": evidence["source_snapshot_id"],
                              "source_id": source["source_id"], "source_hash": evidence["source_hash"],
                              "start": evidence["start"], "end": evidence["end"], "quote": evidence["quote"]})
        warnings = list(result["warnings"])
        if any(i["assertion_ids"] and not i["provenance_complete"] for i in context["items"]):
            warnings.append("INCOMPLETE_PROVENANCE_NOT_TRUSTED_TRUTH")
        if context["conflict_refs"]:
            warnings.append("CONFLICTING_EVIDENCE_PRESENT")
        if not context["items"]:
            warnings.append("NO_AUTHORIZED_CONTEXT")
        answer = {"version": VERSION, "query_id": result["query_id"], "result_id": result_id,
                  "graph_context_id": result["graph_context_id"], "graph_version": context["graph_version"],
                  "mode": request["mode"], "answer_status": "CONTEXT_ONLY", "items": context["items"],
                  "citations": citations, "warnings": sorted(set(warnings)), "can_mutate_graph": False, "created_at": now()}
        answer_id = c.put("graphrag-answer", answer)
        return {"answer_context_id": answer_id, "context": answer}


def validate_current_context(retriever, context_id, *, pack_id=None):
    """Application-owned recheck before/after a scoped semantic callback."""
    c = retriever.catalog
    context = c.get(context_id, "graph-context")
    request = c.get(context["query_id"], "retrieval-query")
    if "research_domain_scope" not in request:
        return
    request["graph_version"] = context["graph_version"]
    view = retriever.adapter.read(request)
    require(view.catalog.hash(view.snapshot_id) == c.hash(context["snapshot_id"]),
            "STALE_GRAPH_CONTEXT", "selected snapshot no longer available exactly")
    validate_context(c, context_id, current_access=retriever.access_policy, current_status=view.source_status)
    if pack_id is not None:
        from ..compiler import validate_pack
        validate_pack(c, c.get(pack_id, "pack"), source_status=view.source_status,
                      current_graph_access=retriever.access_policy)
