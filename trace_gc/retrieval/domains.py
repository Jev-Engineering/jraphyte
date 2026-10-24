"""One authorized research-domain predicate for every retrieval candidate channel.

A scope chooses topical anchors. Required, authorized evidence/identity/conflict
closure travels atomically with an anchor; it is not used as an independent
out-of-domain lexical/vector candidate. Labels never confer permission or truth.
"""
from __future__ import annotations

from collections import defaultdict, deque
from copy import deepcopy
from typing import Any

from ..canonical import digest
from ..constraints import normalize
from ..catalog import Catalog
from ..domains import verify_taxonomy
from ..errors import require
from ..schema import validate

DOMAIN_SELECTION_VERSION = "authorized-research-domain-selection-v1"
LITERAL_CONFLICTS = "literal-v1"
AUTHORIZED_IDENTITY_CONFLICTS = "authorized-identity-v1"


def identity_aware_scope(query: dict[str, Any]) -> bool:
    """Missing selection pins preserve previously serialized literal semantics."""
    scope = query.get("research_domain_scope")
    mode = (scope or {}).get("conflict_resolution", LITERAL_CONFLICTS)
    require(mode in {LITERAL_CONFLICTS, AUTHORIZED_IDENTITY_CONFLICTS},
            "RESEARCH_DOMAIN_SCOPE", "unknown conflict-resolution implementation")
    return scope is not None and mode == AUTHORIZED_IDENTITY_CONFLICTS


def research_domain_scope(catalog: Catalog, taxonomy_id: str, domain_ids: list[str], *,
                          match: str = "ANY", include_unclassified: bool = False,
                          include_descendants: bool = False,
                          conflict_resolution: str = AUTHORIZED_IDENTITY_CONFLICTS) -> dict[str, Any]:
    body = {"contract_version": 1, "taxonomy_id": taxonomy_id, "taxonomy_hash": catalog.hash(taxonomy_id),
            "domain_ids": sorted(set(domain_ids)), "match": match,
            "include_unclassified": include_unclassified, "include_descendants": include_descendants,
            "conflict_resolution": conflict_resolution}
    validate_scope(catalog, body)
    return body


def validate_scope(catalog: Catalog, scope: dict[str, Any] | None) -> set[str]:
    if scope is None:
        return set()
    validate("research-domain-scope", scope)
    require(scope["domain_ids"] == sorted(set(scope["domain_ids"])), "RESEARCH_DOMAIN_SCOPE", "domain IDs must be canonical")
    require(bool(scope["domain_ids"]) or scope["include_unclassified"],
            "RESEARCH_DOMAIN_SCOPE", "an empty selection must explicitly request unclassified material")
    taxonomy = verify_taxonomy(catalog, scope["taxonomy_id"])
    require(catalog.hash(scope["taxonomy_id"]) == scope["taxonomy_hash"],
            "RESEARCH_DOMAIN_SCOPE", "taxonomy hash does not match the requested immutable version")
    require(taxonomy["review"]["status"] == "APPROVED", "RESEARCH_DOMAIN_SCOPE", "query taxonomy has not been reviewed")
    active = {row["id"]: row for row in taxonomy["domains"] if row["status"] == "ACTIVE"}
    require(set(scope["domain_ids"]) <= set(active), "RESEARCH_DOMAIN_SCOPE", "unknown or retired domain ID")
    selected = set(scope["domain_ids"])
    if scope["include_descendants"]:
        while True:
            following = selected | {ref for ref, row in active.items() if selected.intersection(row["parent_ids"])}
            if following == selected:
                break
            selected = following
    return selected


class ResearchDomainSelection:
    """Trusted per-read selection derived from an already ACL-filtered graph.

    The taxonomy pin is exact: unrelated or differently versioned taxonomies do
    not silently share an ID namespace. A later taxonomy requires explicit
    reclassification or an explicit query for its predecessor version.
    """
    def __init__(self, view, access, query: dict[str, Any], edges: dict[str, Any],
                 conflicts: list[list[str]], meter=None):
        self.view, self.access, self.query = view, access, query
        self.scope = deepcopy(query.get("research_domain_scope"))
        self.enabled = self.scope is not None
        self._identity_aware = identity_aware_scope(query)
        self._identity_predicates: dict[str, str] = {}
        self.edges, self.conflicts, self.meter = edges, conflicts, meter
        self.selected_domains = validate_scope(view.catalog, self.scope)
        self._source_rows: dict[str, dict[str, Any]] = {}
        self._edge_sources: dict[str, set[str]] = {}
        self._incident: dict[str, set[str]] = defaultdict(set)
        self._evidence_edges: dict[str, set[str]] = defaultdict(set)
        self._identity_incident: dict[str, set[str]] = defaultdict(set)
        self._equivalence_incident: dict[str, set[str]] = defaultdict(set)
        self._conflict_neighbors: dict[str, set[str]] = defaultdict(set)
        self._same_as: dict[str, str] = {}
        self._closure_cache: dict[tuple[frozenset[str], bool], tuple[frozenset[str], bool]] = {}
        self._unavailable: set[str] = set()
        self._node_seed_cache: dict[str, set[str]] = {}
        self._candidate_cache: dict[tuple, bool] = {}
        self.contributing_edges: set[str] = set(edges) if not self.enabled else set()
        self.allowed_edges = edges
        if not self.enabled:
            return
        c = view.catalog
        relations = c.get(view.snapshot["schema_id"], "schema")["relations"]
        for source_id in view.snapshot["source_epochs"]:
            self.work()
            # Never examine a denied source's assignment to choose membership.
            row = view.source_classification(source_id, access)
            if row is not None:
                self._source_rows[source_id] = row
        for ref, fact in edges.items():
            self.work()
            # Defense in depth: callers cannot supply an unfiltered edge map.
            require(access.edge(ref, fact), "ACCESS_DENIED", "domain selection requires authorized current evidence")
            a = fact["assertion"]
            predicate = normalize(a, relations)[1] if self._identity_aware else a["predicate"]
            self._identity_predicates[ref] = predicate
            usable_identity = fact["active"] or not self._identity_aware
            sources = {c.get(e, "evidence")["source_snapshot_id"] for e in fact["evidence_ids"]}
            self._edge_sources[ref] = sources
            for node in (a["subject"], a["object"]):
                self._incident[node].add(ref)
                self._same_as.setdefault(node, node)
                if usable_identity and predicate in {"same_as", "different_from"}:
                    self._identity_incident[node].add(ref)
                if usable_identity and predicate == "same_as":
                    self._equivalence_incident[node].add(ref)
            for evidence_id in fact["evidence_ids"]:
                self._evidence_edges[evidence_id].add(ref)
            if self.search_edge(ref) and self.contributes(sources):
                self.contributing_edges.add(ref)
            if usable_identity and predicate == "same_as":
                left, right = self._root(a["subject"]), self._root(a["object"])
                self._same_as[max(left, right)] = min(left, right)
        self._equivalent_nodes: dict[str, set[str]] = defaultdict(set)
        for node in self._same_as:
            self._equivalent_nodes[self._root(node)].add(node)
        for pair in conflicts:
            for left in pair:
                self._conflict_neighbors[left].update(set(pair) - {left})
        self._unavailable = self._unprovable_edges()
        if self._unavailable:
            # An anchor whose required proof cannot be fully produced under current
            # authority is excluded whole, never returned with a truncated proof.
            for ref in sorted(self.contributing_edges):
                if self._closure(frozenset({ref}), probe=True)[1]:
                    self.contributing_edges.discard(ref)
            self._node_seed_cache.clear()
        included = self.closure(self.contributing_edges)
        self.allowed_edges = {ref: fact for ref, fact in edges.items() if ref in included}

    def work(self, count: int = 1) -> None:
        if self.meter is not None:
            self.meter.work(count)

    def _root(self, node: str) -> str:
        root = self._same_as[node]
        while root != self._same_as[root]:
            root = self._same_as[root]
        while self._same_as[node] != root:
            next_node = self._same_as[node]
            self._same_as[node] = root
            node = next_node
        return root

    def search_edge(self, ref: str) -> bool:
        if not self.enabled:
            return True
        from .items import compatible_relation
        fact = self.edges[ref]
        return (compatible_relation(fact["assertion"]["predicate"], self.query) and
                (not self.query["source_scope"] or bool(self._edge_sources.get(ref, set()).intersection(self.query["source_scope"]))))

    def labels(self, sources: set[str]) -> tuple[set[str], bool, bool]:
        labels: set[str] = set()
        unclassified = False
        # Missing proof is not an invitation to classify arbitrary nodes/decisions.
        if not sources or not sources <= self._source_rows.keys():
            return labels, False, False
        for source_id in sources:
            row = self._source_rows[source_id]
            if row["status"] in {"UNCLASSIFIED", "RETIRED"}:
                unclassified = True
            elif row["taxonomy_id"] == self.scope["taxonomy_id"] and row["taxonomy_hash"] == self.scope["taxonomy_hash"]:
                labels.update(row["domain_ids"])
        return labels, unclassified, True

    def matches(self, sources: set[str]) -> bool:
        if not self.enabled:
            return True
        labels, unclassified, authorized = self.labels(sources)
        if not authorized:
            return False
        if self.scope["include_unclassified"] and unclassified:
            return True
        requested = set(self.scope["domain_ids"])
        if not requested:
            return False
        if self.scope["match"] == "ANY":
            return bool(labels & self.selected_domains)
        # ALL with descendants means each requested branch has a matching label,
        # not that a source must have every descendant label simultaneously.
        if not self.scope["include_descendants"]:
            return requested <= labels
        for domain in requested:
            branch = {**self.scope, "domain_ids": [domain]}
            if not labels.intersection(validate_scope(self.view.catalog, branch)):
                return False
        return True

    def contributes(self, sources: set[str]) -> bool:
        labels, unclassified, authorized = self.labels(sources)
        return authorized and (bool(labels & self.selected_domains) or
                               (self.scope["include_unclassified"] and unclassified))

    def sources_for_edges(self, refs: set[str]) -> set[str]:
        return set().union(*(self._edge_sources.get(ref, set()) for ref in refs)) if refs else set()

    def node_basis(self, node: str) -> set[str]:
        if node not in self._node_seed_cache:
            # Only authorized same-as links propagate identity. Different-from
            # remains explanatory closure, never equivalence or a domain grant.
            aliases = self._equivalent_nodes.get(self._root(node), {node}) if node in self._same_as else {node}
            refs = set().union(*(self._incident.get(alias, set()) for alias in aliases))
            self._node_seed_cache[node] = refs & self.contributing_edges
        return self._node_seed_cache[node]

    def decision_evidence(self, ref: str) -> set[str]:
        c = self.view.catalog
        body = c.get(ref)
        evidence = set(body.get("evidence_ids", []))
        if body.get("candidate_id") in c:
            evidence.update(c.get(body["candidate_id"], "candidate")["evidence_ids"])
        return evidence

    def basis(self, kind: str, ref: str, members: list[str] | None = None) -> set[str]:
        if not self.enabled:
            return set()
        if kind in {"EDGE", "PROVENANCE"}:
            return {ref}
        if kind in {"PATH", "COMMUNITY", "CONFLICT"}:
            return set(members or [])
        if kind in {"NODE", "CLAIM"}:
            return set(self.node_basis(ref))
        if kind == "EVIDENCE":
            return self._evidence_edges.get(ref, set()) & self.contributing_edges
        if kind in {"DECISION", "HYPOTHESIS"}:
            return set().union(*(self._evidence_edges.get(e, set()) for e in self.decision_evidence(ref))) & self.contributing_edges
        if kind in {"SCHEMA", "ONTOLOGY"}:
            rule = self.view.catalog.get(self.view.snapshot["schema_id"], "schema")["relations"].get(ref)
            if rule is None:
                return set()
            types = {rule["domain"], rule["range"]} - {"*"}
            return {edge_id for edge_id in self.contributing_edges
                    if self.edges[edge_id]["assertion"]["predicate"] == ref or
                    any(self.view.snapshot["nodes"].get(node) in types
                        for node in (self.edges[edge_id]["assertion"]["subject"], self.edges[edge_id]["assertion"]["object"]))}
        return set()

    def allows(self, kind: str, ref: str, members: list[str] | None = None) -> bool:
        if not self.enabled:
            return True
        key = kind, ref, tuple(members or [])
        if key in self._candidate_cache:
            return self._candidate_cache[key]
        c, snap = self.view.catalog, self.view.snapshot
        permitted = False
        if kind == "EVIDENCE":
            if ref in self.view.available_record_ids and self.access.evidence(ref):
                permitted = self.matches({c.get(ref, "evidence")["source_snapshot_id"]})
        elif kind in {"NODE", "CLAIM"}:
            if self.access.allows("node", ref) and (kind == "NODE" or ref in self.view.available_record_ids):
                permitted = self.matches(self.sources_for_edges(self.node_basis(ref)))
        elif kind in {"DECISION", "HYPOTHESIS"}:
            if ref in self.view.available_record_ids and self.access.decision(ref):
                evidence = self.decision_evidence(ref)
                if all(self.access.evidence(e) for e in evidence):
                    permitted = self.matches({c.get(e, "evidence")["source_snapshot_id"] for e in evidence})
        elif kind in {"SCHEMA", "ONTOLOGY"}:
            if self.access.allows("schema", snap["schema_id"]):
                permitted = self.matches(self.sources_for_edges(self.basis(kind, ref, members)))
        else:
            refs = {ref} if kind in {"EDGE", "PROVENANCE"} else set(members or [])
            if refs and refs <= self.allowed_edges.keys():
                anchors = {edge_id for edge_id in refs if self.search_edge(edge_id)}
                if kind == "CONFLICT" or anchors == refs:
                    permitted = self.matches(self.sources_for_edges(anchors))
        self._candidate_cache[key] = bool(permitted)
        return bool(permitted)

    def require_candidate(self, kind: str, ref: str, members: list[str] | None = None) -> None:
        require(self.allows(kind, ref, members), "RESEARCH_DOMAIN_SCOPE", "candidate is not an authorized topical anchor")

    def _measure_hop(self, left: str, right: str) -> None:
        from .telemetry import active, domain_hop
        if not active():
            return
        def membership(ref):
            return {(self._source_rows[source]["taxonomy_hash"], label)
                    for source in self._edge_sources[ref]
                    if source in self._source_rows
                    for label in self._source_rows[source]["domain_ids"]}
        domain_hop(membership(left), membership(right), channel="required_closure")

    def _unprovable_edges(self) -> set[str]:
        """Edges whose transitive fact prerequisites are absent from the authorized universe."""
        state: dict[str, bool] = {}
        for root in sorted(self.edges):
            if root in state:
                continue
            stack = [(root, iter(sorted(self.edges[root]["prerequisites"])))]
            state.setdefault(root, False)
            while stack:
                ref, parents = stack[-1]
                for parent in parents:
                    self.work()
                    if parent not in self.edges:
                        state[ref] = True
                    elif parent not in state:
                        state[parent] = False
                        stack.append((parent, iter(sorted(self.edges[parent]["prerequisites"]))))
                        break
                    elif state[parent]:
                        state[ref] = True
                else:
                    stack.pop()
                    if stack and state[ref]:
                        state[stack[-1][0]] = True
        return {ref for ref, bad in state.items() if bad}

    def closure(self, seeds: set[str]) -> set[str]:
        return self._closure(frozenset(seeds), probe=False)[0]

    def _closure(self, key: frozenset[str], *, probe: bool) -> tuple[set[str], bool]:
        if (key, probe) in self._closure_cache:
            return set(self._closure_cache[(key, probe)][0]), self._closure_cache[(key, probe)][1]
        seeds = key
        blocked = False
        included: set[str] = set()
        expanded: dict[str, bool] = {}
        pending = deque((ref, True) for ref in sorted(seeds))
        while pending:
            edge_id, expand_distinctions = pending.popleft()
            # Revisit at most once when an equivalence-only proof later becomes
            # a genuine selected/conflicting fact. False never downgrades True.
            if edge_id in expanded and (expanded[edge_id] or not expand_distinctions):
                continue
            self.work()
            require(edge_id in self.edges, "ACCESS_DENIED", "closure references an unauthorized edge")
            if edge_id in self._unavailable:
                require(probe, "ACCESS_DENIED", "closure requires an unauthorized or unavailable prerequisite")
                blocked = True
                continue
            included.add(edge_id)
            expanded[edge_id] = expand_distinctions
            a = self.edges[edge_id]["assertion"]
            for parent in sorted(self.edges[edge_id]["prerequisites"]):
                if not probe:
                    self._measure_hop(edge_id, parent)
                pending.append((parent, True))
            for other in sorted(self._conflict_neighbors.get(edge_id, set())):
                if not probe:
                    self._measure_hop(edge_id, other)
                pending.append((other, expand_distinctions))
            # Same-as proofs may be transitive. Different-from is a direct
            # distinction: bring the other endpoint's equivalence proof, but
            # never expand A != B != C, including through aliases of B.
            extend = expand_distinctions and self._identity_predicates[edge_id] != "different_from"
            for node in (a["subject"], a["object"]):
                for other in sorted(self._equivalence_incident.get(node, set())):
                    if not probe:
                        self._measure_hop(edge_id, other)
                    pending.append((other, extend))
                if extend:
                    for other in sorted(self._identity_incident.get(node, set())):
                        if self._identity_predicates[other] == "different_from":
                            if not probe:
                                self._measure_hop(edge_id, other)
                            pending.append((other, False))
        self._closure_cache[(key, probe)] = (frozenset(included), blocked)
        return included, blocked

    def item_metadata(self, source_ids: list[str], seeds: set[str], closure: set[str]) -> dict[str, Any]:
        return {"version": DOMAIN_SELECTION_VERSION, "scope_hash": digest(self.scope),
                "classification_hash": self.view.classification_identity["hash"],
                "anchor_assertion_ids": sorted(seeds), "closure_assertion_ids": sorted(closure - seeds),
                "source_assignments": {source_id: self._source_rows[source_id]["assignment_id"] for source_id in source_ids}}
