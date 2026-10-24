"""Canonical context construction and provenance classification, never graph truth."""
from __future__ import annotations
from typing import Any
from ..canonical import dumps
from ..compiler import timestamp
from ..errors import require
from .contracts import item_id
from .security import AccessFilter
from .store import GraphReadView


def provenance(view: GraphReadView, assertion_id: str, access: AccessFilter, max_depth: int = 4) -> dict[str, Any]:
    """Return only available, authorized proof records. Depth zero means no chain."""
    c, v = view.catalog, view.snapshot["graph_version"]
    fact = view.snapshot["assertions"][assertion_id]
    result: dict[str, Any] = {"transaction_ids": [], "decision_ids": [], "observation_ids": [],
                              "plan_ids": [], "evidence_ids": [], "source_ids": [], "complete": False}
    if max_depth < 1:
        return result
    # Material is never inferred from a summary or from an unrelated nearby edge.
    for plan in sorted(c.all("plan"), key=lambda r: r["id"]):
        matching = [op for op in plan["body"]["operations"]
                    if op.get("assertion_id") == assertion_id and op["operation"].startswith("ADD_")
                    and op.get("assertion") == fact["assertion"]
                    and set(op.get("evidence_ids", [])) == set(fact["evidence_ids"])]
        if not matching:
            continue
        tx = [r for r in c.all("transaction") if r["body"]["plan_hash"] == plan["hash"] and r["body"]["version"] <= v]
        if not tx:
            continue
        for op in matching:
            decision_id = op.get("resolution_id")
            if not decision_id or not access.decision(decision_id):
                continue
            result["transaction_ids"].extend(r["id"] for r in tx)
            result["plan_ids"].append(plan["id"])
            result["decision_ids"].append(decision_id)
            if max_depth >= 2:
                result["observation_ids"].extend(x for x in c.get(decision_id, "resolution")["observation_ids"]
                                                  if access.decision(x))
            if max_depth >= 3:
                result["evidence_ids"].extend(e for e in fact["evidence_ids"] if access.evidence(e))
            if max_depth >= 4:
                result["source_ids"].extend(c.get(e, "evidence")["source_snapshot_id"] for e in result["evidence_ids"])
    for key in result:
        if key != "complete":
            result[key] = sorted(set(result[key]))
    result["complete"] = bool(result["transaction_ids"] and result["decision_ids"] and
                              result["observation_ids"] and result["source_ids"] and
                              set(result["evidence_ids"]) == set(fact["evidence_ids"]))
    return result


def valid_at(fact: dict[str, Any], when: str | None) -> bool:
    if when is None:
        return True
    q = fact["assertion"]["qualifiers"]
    # Invalid temporal annotations fail closed; time filters are never delegated to Jev.
    try:
        t = timestamp(when)
        start = timestamp(q["valid_from"]) if q.get("valid_from") else None
        end = timestamp(q["valid_until"]) if q.get("valid_until") else None
        return (start is None or start <= t) and (end is None or t < end) and not (start and end and start >= end)
    except ValueError:
        return False


def compatible_relation(predicate: str, query: dict[str, Any]) -> bool:
    return (not query["allowed_relation_types"] or predicate in query["allowed_relation_types"]) and \
           predicate not in query["excluded_relation_types"]


def visible_edges(view: GraphReadView, access: AccessFilter, query: dict[str, Any], meter=None) -> dict[str, dict[str, Any]]:
    result = {}
    historical = query["include_historical"] or query["mode"] == "HISTORICAL"
    for ref, fact in sorted(view.snapshot["assertions"].items()):
        if meter is not None:
            meter.work()
        if not access.edge(ref, fact) or not compatible_relation(fact["assertion"]["predicate"], query):
            continue
        if not fact["active"]:
            superseded = bool(fact["assertion"]["qualifiers"].get("superseded_by"))
            if superseded and not query["include_superseded"]:
                continue
            if not superseded and not historical:
                continue
        if query["mode"] == "LATEST_VALID_STATE" and not fact["active"]:
            continue
        if not valid_at(fact, query["temporal_scope"]["valid_at"]):
            continue
        if query["source_scope"] and not any(view.catalog.get(e, "evidence")["source_snapshot_id"] in query["source_scope"]
                                             for e in fact["evidence_ids"]):
            continue
        result[ref] = fact
    return result


def conflict_pairs(edges: dict[str, dict[str, Any]], relations: dict[str, Any], meter=None) -> list[list[str]]:
    """Find explicit incompatible predicates, including cross-paper support/refutation."""
    groups: dict[str, list[str]] = {}
    for ref, fact in edges.items():
        groups.setdefault(fact["assertion"]["object"], []).append(ref)
    result = []
    for members in groups.values():
        for i, left in enumerate(members):
            a = edges[left]["assertion"]
            for right in members[i+1:]:
                if meter is not None:
                    meter.work()
                b = edges[right]["assertion"]
                opposite = b["predicate"] in relations.get(a["predicate"], {}).get("incompatible", []) or \
                           a["predicate"] in relations.get(b["predicate"], {}).get("incompatible", [])
                same_question = a["subject"] == b["subject"] or {a["predicate"], b["predicate"]} == {"supports", "refutes"}
                # Disjoint validity intervals represent change, not simultaneous conflict.
                qa, qb = a["qualifiers"], b["qualifiers"]
                disjoint = False
                try:
                    disjoint = bool((qa.get("valid_until") and qb.get("valid_from") and timestamp(qa["valid_until"]) <= timestamp(qb["valid_from"])) or
                                    (qb.get("valid_until") and qa.get("valid_from") and timestamp(qb["valid_until"]) <= timestamp(qa["valid_from"])))
                except ValueError:
                    pass
                if opposite and same_question and not disjoint:
                    result.append(sorted([left, right]))
    return sorted(result)


def canonical_item(view: GraphReadView, access: AccessFilter, query: dict[str, Any], *, kind: str,
                   ref: str, members: list[str] | None = None, edges: dict[str, Any] | None = None,
                   conflicts: list[list[str]] | None = None, domain=None) -> dict[str, Any]:
    """Reconstruct all source-derived text from immutable originals, not caller text."""
    c, snap = view.catalog, view.snapshot
    edges = visible_edges(view, access, query) if edges is None else edges
    relations = c.get(snap["schema_id"], "schema")["relations"]
    conflicts = conflict_pairs(edges, relations) if conflicts is None else conflicts
    members = list(members or [])
    if "research_domain_scope" in query and domain is None:
        from .domain_scope import DomainMembership
        domain = DomainMembership(view, access, query, edges, conflicts)
    if domain is not None:
        require(domain.eligible(kind, ref, members), "RESEARCH_DOMAIN_SCOPE", "not an authorized domain anchor")
    evidence_ids: set[str] = set()
    assertion_ids: list[str] = []
    entities: set[str] = set()
    decisions: set[str] = set()
    observations: set[str] = set()
    transactions: set[str] = set()
    plans: set[str] = set()
    record_refs: set[str] = set()
    text, predicates = "", set()
    complete = False
    status = "UNVERIFIED_GRAPH_CONTEXT"
    current_status = "CONTEXT"
    created_at = superseded_at = None
    generated = kind in {"COMMUNITY", "PROVENANCE"}
    if kind == "NODE":
        require(ref in snap["nodes"] and access.allows("node", ref), "ACCESS_DENIED", "node not accessible")
        entities.add(ref)
        text = dumps({"entity_id": ref, "type": snap["nodes"][ref]})
    elif kind in {"EDGE", "PATH", "COMMUNITY", "CONFLICT", "PROVENANCE"}:
        assertion_ids = [ref] if kind in {"EDGE", "PROVENANCE"} else members
        require(bool(assertion_ids) and all(x in edges for x in assertion_ids), "ACCESS_DENIED", "edge/member unavailable")
        if kind == "PATH":
            require(len(assertion_ids) <= query["hop_limit"], "RETRIEVAL_BUDGET", "path exceeds hop limit")
            for left, right in zip(assertion_ids, assertion_ids[1:]):
                a, b = edges[left]["assertion"], edges[right]["assertion"]
                require(bool({a["subject"], a["object"]} & {b["subject"], b["object"]}), "PATH_INVALID", "disconnected path")
        if kind == "CONFLICT":
            require(sorted(assertion_ids) in conflicts, "CONFLICT_INVALID", "not a canonical incompatibility")
        all_complete = True
        any_inactive = any(not edges[x]["active"] for x in assertion_ids)
        any_superseded = any(edges[x]["assertion"]["qualifiers"].get("superseded_by") for x in assertion_ids)
        is_conflict = any(x in pair for x in assertion_ids for pair in conflicts)
        for edge_id in assertion_ids:
            fact = edges[edge_id]
            a = fact["assertion"]
            entities.update([a["subject"], a["object"]])
            predicates.add(a["predicate"])
            evidence_ids.update(fact["evidence_ids"])
            p = provenance(view, edge_id, access, query["budget"]["maximum_provenance_depth"])
            all_complete = all_complete and p["complete"]
            if query["include_provenance"]:
                decisions.update(p["decision_ids"])
                observations.update(p["observation_ids"])
                transactions.update(p["transaction_ids"])
                plans.update(p["plan_ids"])
        complete = all_complete and query["include_provenance"]
        status = ("SUPERSEDED_GRAPH_FACT" if any_superseded and any_inactive else
                  "HISTORICAL_GRAPH_FACT" if any_inactive or query["mode"] == "HISTORICAL" else
                  "CONFLICTED_GRAPH_FACT" if is_conflict else
                  "DERIVED_GRAPH_FACT" if kind in {"PATH", "COMMUNITY", "PROVENANCE"} else
                  "VERIFIED_GRAPH_FACT" if complete and all(c.get(x, "observation")["execution_mode"] != "SYNTHETIC" for x in observations) else
                  "PROVISIONAL_GRAPH_FACT" if evidence_ids else "UNVERIFIED_GRAPH_CONTEXT")
        current_status = "INACTIVE" if any_inactive else "ACTIVE"
        # Edges and paths remain exact structured assertions, not generated claims.
        text = dumps([{"assertion_id": x, **edges[x]["assertion"]} for x in assertion_ids])
        if generated:
            text = "NONCANONICAL RETRIEVAL SUMMARY: " + text
        if transactions:
            created_at = min(c.get(x, "transaction")["committed_at"] for x in transactions)
        if any_superseded:
            superseded_at = next((edges[x]["assertion"]["qualifiers"].get("superseded_at") for x in assertion_ids
                                  if edges[x]["assertion"]["qualifiers"].get("superseded_at")), None)
    elif kind in {"ONTOLOGY", "SCHEMA"}:
        require(ref in relations and compatible_relation(ref, query), "SCHEMA_CONTEXT", "relation unavailable")
        require(not query["ontology_scope"] or ref in query["ontology_scope"] or
                relations[ref]["domain"] in query["ontology_scope"] or relations[ref]["range"] in query["ontology_scope"],
                "ONTOLOGY_SCOPE", "outside scope")
        # Schema access is explicit; schema names can themselves be sensitive.
        require(access.allows("schema", snap["schema_id"]), "ACCESS_DENIED", "schema not accessible")
        predicates.add(ref)
        record_refs.add(snap["schema_id"])
        text = dumps({"relation": ref, **relations[ref]})
    elif kind in {"EVIDENCE", "CLAIM", "DECISION", "HYPOTHESIS"}:
        require(ref in view.available_record_ids, "HISTORICAL_CONTEXT_MISSING", "record not available at snapshot")
        record_refs.add(ref)
        if kind == "EVIDENCE":
            require(access.evidence(ref), "ACCESS_DENIED", "source not readable")
            evidence_ids.add(ref)
            text = c.get(ref, "evidence")["quote"]
        elif kind == "CLAIM":
            require(access.allows("node", ref), "ACCESS_DENIED", "claim not readable")
            entities.add(ref)
            text = c.get(ref, "claim")["text"]
        else:
            require(access.decision(ref), "ACCESS_DENIED", "decision not readable")
            b = c.get(ref)
            decisions.add(ref)
            if kind == "HYPOTHESIS":
                require(c.record(ref)["kind"] == "candidate", "CONTEXT_KIND", "hypothesis must reference a candidate")
                require(query["include_historical"] or query["mode"] == "HISTORICAL", "HISTORICAL_CONTEXT_MISSING", "hypotheses require explicit history")
                require(ref != query["candidate_id"], "SELF_CONTEXT", "candidate cannot substantiate itself")
                entities.update([b["assertion"]["subject"], b["assertion"]["object"]])
                text = dumps({"candidate_id": ref, "assertion": b["assertion"], "claim": c.get(b["claim_id"], "claim")["text"], "status": "PROPOSED_NOT_GRAPH_TRUTH"})
            evidence_ids.update(b.get("evidence_ids", []))
            if b.get("candidate_id") in c:
                candidate = c.get(b["candidate_id"], "candidate")
                evidence_ids.update(candidate["evidence_ids"])
                entities.update([candidate["assertion"]["subject"], candidate["assertion"]["object"]])
            if kind != "HYPOTHESIS":
                text = dumps({k: b[k] for k in ("candidate_id", "outcome", "semantic_outcome", "status", "reason", "risk_class") if k in b})
            current_status = "PROPOSED_NOT_GRAPH_TRUTH" if kind == "HYPOTHESIS" else b.get("outcome", b.get("semantic_outcome", b.get("status", "UNKNOWN")))
            created_at = b.get("completed_at", b.get("created_at"))
            status = "HISTORICAL_GRAPH_FACT"
    else:
        require(False, "CONTEXT_KIND", kind)
    sources = sorted({c.get(x, "evidence")["source_snapshot_id"] for x in evidence_ids})
    record_refs.update(evidence_ids | decisions | observations | transactions | plans)
    record_refs.update(sources)
    risk = max((c.get(x).get("risk_class", "R0") for x in decisions), default="R0")
    result = {"id": item_id(kind, ref, members), "kind": kind, "canonical_ref": ref, "member_assertion_ids": members,
            "assertion_ids": assertion_ids, "entity_ids": sorted(entities), "evidence_ids": sorted(evidence_ids),
            "source_ids": sources, "decision_ids": sorted(decisions), "observation_ids": sorted(observations),
            "transaction_ids": sorted(transactions), "plan_ids": sorted(plans), "record_refs": sorted(record_refs),
            "relation_types": sorted(predicates), "text": text, "trust_class": status, "current_status": current_status,
            "graph_version": snap["graph_version"], "created_at": created_at, "superseded_at": superseded_at,
            "provenance_complete": complete, "risk_class": risk,
            "calibration": {"qualified": False, "note": "Retrieval status is not a calibrated truth probability."},
            "generated_summary": generated, "data_origin": "GENERATED_SUMMARY" if generated else "SOURCE_DERIVED",
            "instruction_authority": False}
    return domain.materialize(result) if domain is not None else result
