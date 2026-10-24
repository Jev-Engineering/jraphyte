"""Topical candidate anchors and authorized explanatory closure, never ACLs.

This module is shared by all candidate producers and canonical reconstruction.
Only exact assignments selected by an application-owned read adapter are used.
"""
from __future__ import annotations
from copy import deepcopy
from ..canonical import digest
from ..errors import require
from .domain_index import source_membership

VERSION = "trace-retrieval-domain-v1"


def scope(*, taxonomy_id: str, taxonomy_hash: str, domain_ids: list[str],
          include_unclassified: bool = False) -> dict:
    """Exact taxonomy identity; matching is explicit ANY, without ancestor expansion."""
    return {"taxonomy_id": taxonomy_id, "taxonomy_hash": taxonomy_hash,
            "domain_ids": sorted(set(domain_ids)), "include_unclassified": include_unclassified,
            "match": "ANY_EXPLICIT_LABEL"}


def binding(view, query):
    selected = query.get("research_domain_scope")
    if selected is None:
        return None
    return {"scope": deepcopy(selected), "scope_hash": digest(selected),
            "projection_hash": view.classification_identity,
            "projection_revision": view.classification_revision}


class DomainFilter:
    def __init__(self, view, access, query, edges, conflicts, meter=None):
        self.view, self.access, self.query = view, access, query
        self.edges, self.conflicts, self.meter = edges, conflicts, meter
        self.scope = query.get("research_domain_scope")
        self._source = {}
        self._work = 0
        if self.scope is not None:
            access.require_scope(query["security_scope"])
            tax = view.catalog.get(self.scope["taxonomy_id"], "research-domain-taxonomy")
            require(view.catalog.hash(self.scope["taxonomy_id"]) == self.scope["taxonomy_hash"],
                    "DOMAIN_TAXONOMY_BINDING", "query taxonomy hash differs")
            require(set(self.scope["domain_ids"]) <= {d["id"] for d in tax["domains"]},
                    "DOMAIN_UNKNOWN", "unknown query domain ID")
        self._traversable = None

    def work(self):
        self._work += 1
        require(self._work <= self.query["budget"]["maximum_cost_units"], "RETRIEVAL_BUDGET_EXHAUSTED", "domain closure work budget")
        if self.meter is not None:
            self.meter.work()

    def source_anchor(self, source_id):
        if self.scope is None:
            return self.access.source(source_id)
        if source_id not in self._source:
            # Do not inspect a denied source's topical metadata or original text.
            membership = source_membership(self.view, source_id, self.access)
            self._source[source_id] = bool(membership is not None and (
                (membership["state"] == "UNCLASSIFIED" and self.scope["include_unclassified"]) or
                (membership["state"] == "CLASSIFIED" and
                 membership["taxonomy_id"] == self.scope["taxonomy_id"] and
                 membership["taxonomy_hash"] == self.scope["taxonomy_hash"] and
                 set(membership["domain_ids"]) & set(self.scope["domain_ids"]))))
        return self._source[source_id]

    def evidence_anchor(self, evidence_id):
        if not self.access.evidence(evidence_id):
            return False
        return self.source_anchor(self.view.catalog.get(evidence_id, "evidence")["source_snapshot_id"])

    def edge_anchor(self, ref):
        fact = self.edges.get(ref)
        return bool(fact is not None and self.access.edge(ref, fact) and
                    any(self.evidence_anchor(e) for e in fact["evidence_ids"]))

    def roots(self, kind, ref, members=None):
        if kind in {"EDGE", "PROVENANCE"}:
            return {ref} if ref in self.edges else set()
        if kind in {"PATH", "COMMUNITY", "CONFLICT"}:
            return set(members or []) & self.edges.keys()
        if kind in {"NODE", "CLAIM"}:
            return {r for r, f in self.edges.items() if self.edge_anchor(r) and
                    ref in (f["assertion"]["subject"], f["assertion"]["object"])}
        evidence = set()
        if kind == "EVIDENCE":
            evidence.add(ref)
        elif kind in {"DECISION", "HYPOTHESIS"}:
            body = self.view.catalog.get(ref)
            evidence.update(body.get("evidence_ids", []))
            if body.get("candidate_id") in self.view.catalog:
                evidence.update(self.view.catalog.get(body["candidate_id"], "candidate")["evidence_ids"])
        elif kind in {"ONTOLOGY", "SCHEMA"}:
            return {r for r, f in self.edges.items() if f["assertion"]["predicate"] == ref and self.edge_anchor(r)}
        return {r for r, f in self.edges.items() if evidence & set(f["evidence_ids"])}

    def anchor(self, kind, ref, members=None):
        if self.scope is None:
            return True  # Original candidate/materialization ACL checks still apply.
        if kind == "EVIDENCE":
            return ref in self.view.available_record_ids and self.evidence_anchor(ref)
        if kind in {"EDGE", "PROVENANCE"}:
            return self.edge_anchor(ref)
        if kind in {"PATH", "COMMUNITY", "CONFLICT"}:
            return bool(members) and all(r in self.edges for r in members) and any(self.edge_anchor(r) for r in members)
        if kind in {"NODE", "CLAIM"}:
            if not self.access.allows("node", ref):
                return False
            if self.roots(kind, ref):
                return True
            for source_id in self.view.snapshot["source_epochs"]:
                self.work()
                if self.source_anchor(source_id) and self.view.catalog.get(source_id, "source")["source_id"] == ref:
                    return True
            return False
        if kind in {"ONTOLOGY", "SCHEMA"}:
            return self.access.allows("schema", self.view.snapshot["schema_id"]) and bool(self.roots(kind, ref))
        if kind in {"DECISION", "HYPOTHESIS"}:
            if ref not in self.view.available_record_ids or not self.access.decision(ref):
                return False
            b = self.view.catalog.get(ref)
            ids = list(b.get("evidence_ids", []))
            if b.get("candidate_id") in self.view.catalog:
                ids += self.view.catalog.get(b["candidate_id"], "candidate")["evidence_ids"]
            return any(self.evidence_anchor(e) for e in ids)
        return False

    def closure(self, roots):
        """Required proofs, explicit identity links and refutations; no free traversal."""
        selected = set(roots)
        require(selected <= self.edges.keys(), "DOMAIN_CLOSURE_UNAVAILABLE", "required root unavailable")
        changed = True
        while changed:
            changed = False
            extra = set()
            entities = {n for r in selected for n in (self.edges[r]["assertion"]["subject"], self.edges[r]["assertion"]["object"])}
            for ref in sorted(selected):
                self.work()
                deps = set(self.edges[ref]["prerequisites"])
                require(deps <= self.edges.keys(), "DOMAIN_CLOSURE_UNAVAILABLE", "required proof not authorized or temporally available")
                extra.update(deps)
            # Explicit identity links are explanatory records, not inferred equality.
            for ref, fact in self.edges.items():
                self.work()
                a = fact["assertion"]
                if a["predicate"] in {"same_as", "different_from"} and entities & {a["subject"], a["object"]}:
                    extra.add(ref)
            if self.query["include_conflicts"]:
                for pair in self.conflicts:
                    self.work()
                    if selected & set(pair):
                        extra.update(pair)
            if extra - selected:
                selected.update(extra)
                changed = True
        return selected

    def traversable(self, ref):
        if self.scope is None:
            return True
        if self._traversable is None:
            self._traversable = self.closure({r for r in self.edges if self.edge_anchor(r)})
        return ref in self._traversable

    def enrich(self, item):
        if self.scope is None:
            return item
        kind, ref, members = item["kind"], item["canonical_ref"], item["member_assertion_ids"]
        require(self.anchor(kind, ref, members), "DOMAIN_OUTSIDE_SCOPE", "candidate has no authorized domain anchor")
        roots = self.roots(kind, ref, members)
        closed = self.closure(roots)
        c = self.view.catalog
        # Canonical item text remains unchanged. Closure facts are separate, exact
        # originals, so a summary/path cannot relabel them as its own assertion.
        facts = [{"assertion_id": r, **deepcopy(self.edges[r]["assertion"]),
                  "evidence_ids": list(self.edges[r]["evidence_ids"])} for r in sorted(closed)]
        evidence = set(item["evidence_ids"]) | {e for r in closed for e in self.edges[r]["evidence_ids"]}
        require(all(self.access.evidence(e) for e in evidence), "ACCESS_DENIED", "closure evidence unavailable")
        sources = {c.get(e, "evidence")["source_snapshot_id"] for e in evidence}
        memberships = {s: source_membership(self.view, s, self.access) for s in sorted(sources)}
        require(all(m is not None for m in memberships.values()), "ACCESS_DENIED", "closure source unavailable at selected version")
        from .items import provenance
        for r in sorted(closed - set(item["assertion_ids"])):
            p = provenance(self.view, r, self.access, self.query["budget"]["maximum_provenance_depth"])
            item["provenance_complete"] = item["provenance_complete"] and p["complete"]
            if self.query["include_provenance"]:
                for field in ("decision_ids", "observation_ids", "transaction_ids", "plan_ids"):
                    item[field] = sorted(set(item[field]) | set(p[field]))
        item["assertion_ids"] = sorted(set(item["assertion_ids"]) | closed)
        item["entity_ids"] = sorted(set(item["entity_ids"]) | {n for r in closed for n in
            (self.edges[r]["assertion"]["subject"], self.edges[r]["assertion"]["object"])})
        item["relation_types"] = sorted(set(item["relation_types"]) | {self.edges[r]["assertion"]["predicate"] for r in closed})
        item["evidence_ids"], item["source_ids"] = sorted(evidence), sorted(sources)
        refs = set(item["record_refs"]) | evidence | sources
        for field in ("decision_ids", "observation_ids", "transaction_ids", "plan_ids"):
            refs.update(item[field])
        for m in memberships.values():
            if m["assignment_id"] is not None:
                refs.update((m["assignment_id"], m["taxonomy_id"]))
        item["record_refs"] = sorted(refs)
        item["research_domain_context"] = {**binding(self.view, self.query),
            "anchor_assertion_ids": sorted(roots), "closure_assertions": facts,
            "source_memberships": memberships, "authorization_granted": False}
        return item
