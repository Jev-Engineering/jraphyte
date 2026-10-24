"""Pluggable algorithms over an ACL-filtered, bounded graph view."""
from __future__ import annotations
from collections import deque
from dataclasses import dataclass
from typing import Any, Iterable, Protocol
from ..canonical import digest, dumps
from ..errors import ContractError
from .budget import BudgetMeter
from .items import canonical_item
from .security import AccessFilter
from .store import GraphReadView
from .vector import EmbeddingModel, cosine, terms

@dataclass
class SearchSpace:
    view: GraphReadView
    access: AccessFilter
    query: dict[str, Any]
    edges: dict[str, Any]
    conflicts: list[list[str]]
    meter: BudgetMeter
    embedding: EmbeddingModel
    domain: Any = None

    def __post_init__(self):
        if "research_domain_scope" in self.query:
            from .domain_scope import DomainMembership
            self.domain = DomainMembership(self.view, self.access, self.query, self.edges, self.conflicts, self.meter)
            if self.domain.enabled:
                self.edges = self.domain.anchors
                self.conflicts = [pair for pair in self.conflicts if any(ref in self.edges for ref in pair)]

    def eligible(self, kind, ref, members=None):
        return self.domain is None or self.domain.eligible(kind, ref, members)

    def make(self, kind: str, ref: str, members: list[str] | None = None) -> dict[str, Any]:
        self.meter.work(candidate=True)
        return canonical_item(self.view, self.access, self.query, kind=kind, ref=ref, members=members,
                              edges=self.edges if self.domain is None else self.domain.visible,
                              conflicts=self.conflicts if self.domain is None else self.domain.conflicts, domain=self.domain)

    def adjacency(self) -> dict[str, list[tuple[str, str]]]:
        result: dict[str, list[tuple[str, str]]] = {}
        for ref, fact in self.edges.items():
            self.meter.work()
            a = fact["assertion"]
            result.setdefault(a["subject"], []).append((a["object"], ref))
            result.setdefault(a["object"], []).append((a["subject"], ref))
        return result

class GraphRetriever(Protocol):
    name: str
    version: str
    def retrieve(self, space: SearchSpace) -> Iterable[dict[str, Any]]: ...


class BuiltinStrategy:
    version = "bounded-strategies-v1"
    def __init__(self, name: str):
        self.name = name

    def retrieve(self, space: SearchSpace) -> Iterable[dict[str, Any]]:
        q, c, snap, m = space.query, space.view.catalog, space.view.snapshot, space.meter
        focus = {x for x in q["focus_entities"] if space.access.allows("node", x)}
        text_terms = terms(q["text"])
        name = self.name
        if name in {"ENTITY", "CLAIM"}:
            candidates = sorted(snap["nodes"]) if name == "ENTITY" else sorted(r["id"] for r in c.all("claim"))
            for ref in candidates:
                m.work()
                if not space.access.allows("node", ref) or not space.eligible("NODE" if name == "ENTITY" else "CLAIM", ref):
                    continue
                if ref in focus or (text_terms and text_terms & terms(ref if name == "ENTITY" else c.get(ref, "claim")["text"])):
                    if name == "ENTITY" or ref in space.view.available_record_ids:
                        yield space.make("NODE" if name == "ENTITY" else "CLAIM", ref)
        elif name in {"NEIGHBORHOOD", "PATH"}:
            if q["hop_limit"] == 0:
                return
            adj = space.adjacency()
            queue = deque((ref, [ref], []) for ref in sorted(focus))
            visited_edges: set[str] = set()
            paths_seen: set[tuple[str, ...]] = set()
            while queue:
                m.work()
                node, nodes, path = queue.popleft()
                if len(path) >= q["hop_limit"]:
                    continue
                for target, ref in adj.get(node, []):
                    m.work()
                    if target in nodes:
                        continue
                    next_path = path + [ref]
                    if name == "NEIGHBORHOOD" and ref not in visited_edges:
                        visited_edges.add(ref)
                        yield space.make("EDGE", ref)
                    elif name == "PATH" and len(next_path) >= 2:
                        identity = min(tuple(next_path), tuple(reversed(next_path)))
                        if identity not in paths_seen:
                            paths_seen.add(identity)
                            yield space.make("PATH", digest(list(identity)), next_path)
                    queue.append((target, nodes+[target], next_path))
        elif name in {"LEXICAL", "VECTOR", "SOURCE", "EVIDENCE"}:
            evidence = []
            relevant_sources = set(q["source_scope"])
            linked_evidence = {e for f in space.edges.values()
                               if focus & {f["assertion"]["subject"], f["assertion"]["object"]}
                               for e in f["evidence_ids"]}
            if q["candidate_id"] in c:
                linked_evidence.update(c.get(q["candidate_id"], "candidate")["evidence_ids"])
            for r in sorted(c.all("evidence"), key=lambda r: r["id"]):
                m.work()
                ref, b = r["id"], r["body"]
                if ref not in space.view.available_record_ids or not space.access.evidence(ref) or not space.eligible("EVIDENCE", ref):
                    continue
                if relevant_sources and b["source_snapshot_id"] not in relevant_sources:
                    continue
                if name == "VECTOR":
                    # Stop before embedding an unbounded corpus, including authorized data.
                    if len(evidence) >= m.limits.maximum_candidates:
                        break
                    evidence.append((ref, b["quote"]))
                elif name == "LEXICAL":
                    if text_terms & terms(b["quote"]):
                        yield space.make("EVIDENCE", ref)
                elif ref in linked_evidence or relevant_sources:
                    yield space.make("EVIDENCE", ref)
            if name == "VECTOR" and evidence:
                m.work(len(evidence))
                m.used["vector_queries"] += 1
                # Only authorized original spans reach the injectable embedding model.
                vectors = space.embedding.embed([q["text"]] + [text for _, text in evidence])
                m.check()  # Adapters must also enforce their own I/O deadline.
                from ..errors import require
                require(len(vectors) == len(evidence)+1, "EMBEDDING_VECTOR", "embedding count mismatch")
                scored = [(cosine(vectors[0], vector), ref) for (ref, _), vector in zip(evidence, vectors[1:])]
                for similarity, ref in sorted(scored, key=lambda x: (-x[0], x[1])):
                    if similarity > 0:
                        item = space.make("EVIDENCE", ref)
                        item["_semantic_similarity"] = similarity
                        yield item
        elif name in {"ONTOLOGY", "SCHEMA"}:
            if not space.access.allows("schema", snap["schema_id"]):
                return
            relations = c.get(snap["schema_id"], "schema")["relations"]
            for ref, rule in sorted(relations.items()):
                m.work()
                relevant = (ref in q["focus_relationships"] or ref in q["ontology_scope"] or
                            rule["domain"] in q["ontology_scope"] or rule["range"] in q["ontology_scope"] or
                            (q["candidate_id"] in c and c.get(q["candidate_id"], "candidate")["assertion"]["predicate"] == ref))
                if not relevant or not space.eligible("ONTOLOGY" if name == "ONTOLOGY" else "SCHEMA", ref):
                    continue
                try:
                    yield space.make("ONTOLOGY" if name == "ONTOLOGY" else "SCHEMA", ref)
                except ContractError as exc:
                    if exc.code not in {"SCHEMA_CONTEXT", "ONTOLOGY_SCOPE"}:
                        raise
            if name == "ONTOLOGY":
                # Typed ancestry/siblings are graph assertions, not invented rules.
                frontier = set(q["ontology_scope"] or focus)
                visited = set()
                for _ in range(q["hop_limit"]):
                    following = set()
                    for edge_ref, fact in space.edges.items():
                        m.work()
                        a = fact["assertion"]
                        if a["predicate"] not in {"subclass_of", "subClassOf", "is_a", "type", "instance_of"}:
                            continue
                        if edge_ref not in visited and (not frontier or frontier & {a["subject"], a["object"]}):
                            visited.add(edge_ref)
                            following.update([a["subject"], a["object"]])
                            yield space.make("EDGE", edge_ref)
                    frontier = following
                    if not frontier:
                        break
        elif name == "CONFLICT":
            for pair in space.conflicts:
                m.work()
                conflict_edges = space.edges if space.domain is None else space.domain.visible
                entities = {x for ref in pair for x in (conflict_edges[ref]["assertion"]["subject"], conflict_edges[ref]["assertion"]["object"])}
                if not focus or focus & entities:
                    yield space.make("CONFLICT", digest(pair), pair)
                    for ref in pair:
                        if space.eligible("EDGE", ref):
                            yield space.make("EDGE", ref)
        elif name in {"DECISION", "SIMILAR_CASE"}:
            for record in sorted(c.all(), key=lambda r: r["id"]):
                m.work()
                if record["kind"] not in {"resolution", "evaluation", "observation", "candidate"} or record["id"] not in space.view.available_record_ids:
                    continue
                if not space.access.decision(record["id"]) or not space.eligible("DECISION", record["id"]):
                    continue
                b = record["body"]
                if q["candidate_id"] is not None and (b.get("candidate_id") == q["candidate_id"] or record["id"] == q["candidate_id"]):
                    # Do not retrieve the current hypothesis or its in-flight votes
                    # as corroboration in subsequent acquisition rounds.
                    continue
                is_hypothesis = record["kind"] == "candidate"
                if is_hypothesis and not (q["include_historical"] or q["mode"] == "HISTORICAL"):
                    continue
                candidate = b if is_hypothesis else (c.get(b["candidate_id"], "candidate") if b.get("candidate_id") in c else None)
                entities = {candidate["assertion"]["subject"], candidate["assertion"]["object"]} if candidate else set()
                outcome = b.get("outcome", b.get("semantic_outcome", ""))
                past = outcome in {"NOT_SELECTED", "REJECT", "ABSTAIN", "HUMAN_REVIEW", "UNRESOLVED", "RETRIEVE_MORE_EVIDENCE"}
                if past and not (q["include_historical"] or q["mode"] == "HISTORICAL" or q["decision_id"] == record["id"]):
                    continue
                if (record["id"] == q["decision_id"] or focus & entities or
                    (name == "SIMILAR_CASE" and text_terms & terms(dumps(candidate or {})))):
                    yield space.make("HYPOTHESIS" if is_hypothesis else "DECISION", record["id"])
        elif name in {"RELATION", "TEMPORAL", "PROVENANCE", "GLOBAL"}:
            for ref, fact in space.edges.items():
                m.work()
                a = fact["assertion"]
                if q["focus_relationships"] and a["predicate"] not in q["focus_relationships"]:
                    continue
                if focus and not focus & {a["subject"], a["object"]} and name != "GLOBAL":
                    continue
                if name == "TEMPORAL" and not (q["temporal_scope"]["valid_at"] or a["qualifiers"] or q["include_historical"]):
                    continue
                if name == "GLOBAL" and text_terms and not (text_terms & terms(dumps(a)) or focus & {a["subject"], a["object"]}):
                    continue
                yield space.make("PROVENANCE" if name == "PROVENANCE" else "EDGE", ref)
        elif name == "COMMUNITY":
            # Bounded connected-component summaries: no LLM, no hidden-node traversal.
            adj = space.adjacency()
            seen: set[str] = set()
            for root in sorted(focus or set(adj)):
                if root in seen:
                    continue
                nodes, members, queue = set(), set(), deque([root])
                while queue:
                    m.work()
                    node = queue.popleft()
                    if node in nodes:
                        continue
                    nodes.add(node)
                    if len(nodes) > m.limits.maximum_nodes:
                        break
                    for target, edge in adj.get(node, []):
                        m.work()
                        if len(members) >= m.limits.maximum_edges:
                            break
                        members.add(edge)
                        if target not in nodes:
                            queue.append(target)
                seen.update(nodes)
                if members:
                    ref = "community-" + digest(sorted(members))[:20]
                    if not q["community_scope"] or ref in q["community_scope"]:
                        yield space.make("COMMUNITY", ref, sorted(members))
