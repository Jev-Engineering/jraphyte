"""Topical anchor selection and indivisible, authorized evidence closure.

The application supplies the ACL; the adapter supplies journal-bound membership.
A query supplies neither. Namespace-qualified topics do not imply ancestry or
permission. Every candidate producer and canonical materializer uses this rule.
"""
from __future__ import annotations

from copy import deepcopy
from typing import Any

from ..canonical import dumps
from ..errors import require

SCOPE_VERSION = "trace-retrieval-domain-v2"
UNCLASSIFIED = "@unclassified"


def binding(view) -> dict[str, Any]:
    p = view.research_domains
    return {"classification_revision": p["classification_revision"],
            "projection_hash": p["projection_hash"]}


class DomainMembership:
    def __init__(self, view, access, query, edges, conflicts, meter=None):
        self.view, self.access, self.query = view, access, query
        self.catalog, self.snapshot = view.catalog, view.snapshot
        self.scope = frozenset(query.get("research_domain_scope", []))
        self.enabled = bool(self.scope)
        self.visible, self.conflicts, self.meter = edges, conflicts, meter
        self.projection = view.research_domains
        self.identity = {"classification_revision": self.projection["classification_revision"],
                         "projection_hash": self.projection["projection_hash"]}
        self._source_matches = {}
        self.anchors = {}
        for ref, fact in edges.items():
            self.work()
            if not self.enabled or any(self.evidence(e) for e in fact["evidence_ids"]):
                self.anchors[ref] = fact
        self.nodes = {n for fact in self.anchors.values()
                      for n in (fact["assertion"]["subject"], fact["assertion"]["object"])}
        # Source/document nodes may be anchors before a graph assertion exists.
        for source in self.projection["source_assignments"]:
            self.work()
            if self.source(source):
                logical = self.catalog.get(source, "source")["source_id"]
                if access.allows("node", logical):
                    self.nodes.add(logical)
        self.relations = {fact["assertion"]["predicate"] for fact in self.anchors.values()}
        target = query.get("candidate_id")
        if target in self.catalog and self.decision(target):
            candidate = self.catalog.get(target, "candidate")
            self.relations.add(candidate["assertion"]["predicate"])

    def work(self):
        if self.meter is not None:
            self.meter.work()

    def source(self, ref: str) -> bool:
        # Access/status is checked before consulting topical membership.
        status = self.access.statuses.get(ref)
        if not (self.access.allows("source", ref) and status and status["active"] and
                status["permission"] == "READ" and not status["tombstone"]):
            return False
        if ref not in self.catalog or self.catalog.get(ref, "source")["security_scope"] != self.access.policy["tenant"]:
            return False
        if not self.enabled:
            return True
        if ref not in self._source_matches:
            row = self.projection["source_assignments"].get(ref)
            if row is None:
                matched = False  # Not admitted at the selected graph version.
            elif row["state"] in {"UNCLASSIFIED", "RETIRED"}:
                matched = UNCLASSIFIED in self.scope
            else:
                taxonomy = self.catalog.get(row["taxonomy_id"], "research-domain-taxonomy")
                matched = any(f"{taxonomy['namespace']}/{topic}" in self.scope and
                    (self.view.domain_index is None or ref in self.view.domain_index.get(topic, []))
                    for topic in row["domain_ids"])
            self._source_matches[ref] = matched
        return self._source_matches[ref]

    def evidence(self, ref: str) -> bool:
        return (self.access.evidence(ref) and
                self.source(self.catalog.get(ref, "evidence")["source_snapshot_id"]))

    def decision(self, ref: str) -> bool:
        if not self.access.decision(ref):
            return False
        b = self.catalog.get(ref)
        evidence = set(b.get("evidence_ids", []))
        if b.get("candidate_id") in self.catalog:
            evidence.update(self.catalog.get(b["candidate_id"], "candidate")["evidence_ids"])
        return not self.enabled or any(self.evidence(e) for e in evidence)

    def eligible(self, kind: str, ref: str, members=None) -> bool:
        if not self.enabled:
            return True  # Canonical materialization still enforces all ACLs.
        if kind == "EVIDENCE":
            return self.evidence(ref)
        if kind in {"NODE", "CLAIM"}:
            return self.access.allows("node", ref) and ref in self.nodes
        if kind in {"DECISION", "HYPOTHESIS"}:
            return self.decision(ref)
        if kind in {"ONTOLOGY", "SCHEMA"}:
            return self.access.allows("schema", self.snapshot["schema_id"]) and ref in self.relations
        if kind in {"EDGE", "PROVENANCE"}:
            return ref in self.anchors
        if kind in {"PATH", "COMMUNITY"}:
            return bool(members) and all(x in self.anchors for x in members)
        if kind == "CONFLICT":
            return bool(members) and any(x in self.anchors for x in members) and sorted(members) in self.conflicts
        return False

    def closure(self, roots: set[str]) -> tuple[set[str], dict[str, set[str]]]:
        """Include required proof, identity and conflict links without granting ACLs.

        A closure is one candidate's atomic budget unit. It is never truncated to
        fit. Work is charged before iteration; a cap withholds the candidate.
        """
        selected = set(roots)
        reasons = {ref: ({"ANCHOR"} if ref in self.anchors else {"CONTRADICTION"}) for ref in roots}
        pending = set(roots)
        while pending:
            self.work()
            current, pending = pending, set()
            endpoints = {n for ref in current for n in
                         (self.visible[ref]["assertion"]["subject"], self.visible[ref]["assertion"]["object"])}
            additions: dict[str, set[str]] = {}
            for ref in current:
                for parent in self.visible[ref]["prerequisites"]:
                    self.work()
                    require(parent in self.visible, "DOMAIN_CLOSURE_UNAVAILABLE", "required authorized prerequisite unavailable")
                    additions.setdefault(parent, set()).add("PREREQUISITE")
            for ref, fact in self.visible.items():
                self.work()
                a = fact["assertion"]
                if a["predicate"] in {"same_as", "different_from"} and endpoints & {a["subject"], a["object"]}:
                    additions.setdefault(ref, set()).add("IDENTITY")
            if self.query["include_conflicts"]:
                for pair in self.conflicts:
                    self.work()
                    if set(pair) & current:
                        for ref in pair:
                            additions.setdefault(ref, set()).add("CONTRADICTION")
            for ref, why in additions.items():
                if ref not in selected:
                    selected.add(ref)
                    pending.add(ref)
                reasons.setdefault(ref, set()).update(why)
        return selected, reasons

    def materialize(self, item: dict[str, Any]) -> dict[str, Any]:
        require(self.eligible(item["kind"], item["canonical_ref"], item["member_assertion_ids"]),
                "RESEARCH_DOMAIN_SCOPE", "candidate is not an authorized domain anchor")
        result = deepcopy(item)
        roots = set(item["assertion_ids"])
        if self.enabled and not roots:
            entities, evidence = set(item["entity_ids"]), set(item["evidence_ids"])
            for ref, fact in self.anchors.items():
                self.work()
                a = fact["assertion"]
                if (entities & {a["subject"], a["object"]} or evidence & set(fact["evidence_ids"]) or
                    (item["kind"] in {"ONTOLOGY", "SCHEMA"} and a["predicate"] == item["canonical_ref"])):
                    roots.add(ref)
        closure, reasons = self.closure(roots) if self.enabled else (set(), {})
        extra = closure - set(item["assertion_ids"])
        if extra:
            result["assertion_ids"] = sorted(closure | set(item["assertion_ids"]))
            result["entity_ids"] = sorted(set(item["entity_ids"]) |
                {n for ref in closure for n in (self.visible[ref]["assertion"]["subject"], self.visible[ref]["assertion"]["object"])})
            result["evidence_ids"] = sorted(set(item["evidence_ids"]) | {e for ref in closure for e in self.visible[ref]["evidence_ids"]})
            result["source_ids"] = sorted({self.catalog.get(e, "evidence")["source_snapshot_id"] for e in result["evidence_ids"]})
            result["record_refs"] = sorted(set(item["record_refs"]) | set(result["source_ids"]) | set(result["evidence_ids"]))
            result["relation_types"] = sorted(set(item["relation_types"]) | {self.visible[ref]["assertion"]["predicate"] for ref in closure})
            result["text"] = dumps({"anchor": item["text"], "authorized_domain_closure": [
                {"assertion_id": ref, "assertion": self.visible[ref]["assertion"], "reasons": sorted(reasons[ref])}
                for ref in sorted(extra)]})
            # Closure facts are not promoted into fully audited provenance merely
            # because their anchor had a complete compiler decision chain.
            result["provenance_complete"] = False
            if any(set(pair) <= closure for pair in self.conflicts):
                result["trust_class"] = "CONFLICTED_GRAPH_FACT"
            elif result["trust_class"] == "VERIFIED_GRAPH_FACT":
                result["trust_class"] = "PROVISIONAL_GRAPH_FACT"
        result["research_domain_binding"] = deepcopy(self.identity)
        result["research_domain_scope"] = sorted(self.scope)
        result["research_domain_closure"] = {ref: sorted(why) for ref, why in sorted(reasons.items())}
        sources = set(result["source_ids"])
        # A node/schema-only anchor still explains which committed proof selected it.
        sources.update(self.catalog.get(e, "evidence")["source_snapshot_id"]
                       for ref in roots for e in self.visible[ref]["evidence_ids"])
        if item["kind"] in {"NODE", "CLAIM"}:
            sources.update(source for source in self.projection["source_assignments"]
                if self.source(source) and self.catalog.get(source, "source")["source_id"] == item["canonical_ref"])
        result["research_domain_assignments"] = {
            source: deepcopy(self.projection["source_assignments"][source])
            for source in sorted(sources) if source in self.projection["source_assignments"]}
        return result
