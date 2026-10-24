"""Synthetic retrieval corpus. Demonstrates contracts, not real scientific findings."""
from __future__ import annotations
from copy import deepcopy
from typing import Any
from ..catalog import Catalog
from ..compiler import now
from ..demo import relation
from .security import access_policy, grant
from .store import InMemoryGraphAdapter
from .service import HybridRetriever

SCOPE = "retrieval-sandbox"
WORKSPACE = "reference-fixtures"


def demo_access(catalog: Catalog, snapshot_id: str, *, scope: str = SCOPE) -> dict[str, Any]:
    """Explicit allow-all WITHIN an isolated fixture, never a production default."""
    snapshot = catalog.get(snapshot_id, "graph-snapshot")
    grants = {"node:"+ref: grant(scope, WORKSPACE) for ref in snapshot["nodes"]}
    grants.update({"edge:"+ref: grant(scope, WORKSPACE) for ref in snapshot["assertions"]})
    grants.update({"source:"+r["id"]: grant(scope, WORKSPACE) for r in catalog.all("source")
                   if r["body"]["security_scope"] == scope})
    grants.update({"decision:"+r["id"]: grant(scope, WORKSPACE) for r in catalog.all()
                   if r["kind"] in {"observation", "resolution", "evaluation", "candidate"}})
    grants["schema:"+snapshot["schema_id"]] = grant(scope, WORKSPACE)
    return access_policy(tenant=scope, workspace=WORKSPACE, user="fixture-user", roles=["researcher"], grants=grants)


def corpus() -> dict[str, Any]:
    c = Catalog()
    claim = c.claim("Intervention X improves outcome Y in population P.")
    relations = {"owns": relation("Organization", "Organization"),
                 "partnered_with": relation("Organization", "Organization"),
                 "subsidiary_of": relation("Organization", "Organization"),
                 "same_as": relation("*", "*", symmetric=True, transitive=True),
                 "different_from": relation("*", "*", symmetric=True),
                 "supports": relation("Document", "Claim", incompatible=["refutes"]),
                 "refutes": relation("Document", "Claim", incompatible=["supports"]),
                 "replicates": relation("Document", "Document"),
                 "uses_method": relation("Document", "Method"),
                 "uses_dataset": relation("Document", "Dataset"),
                 "subclass_of": relation("Type", "Type")}
    schema_id = c.put("schema", {"version": "retrieval-fixture-schema-v1", "relations": relations})
    nodes = {"Acme": "Organization", "Bar": "Organization", "Foo": "Organization", "Baz": "Organization",
             "Acme-Holdings": "Organization", "Paper-A": "Document", "Paper-B": "Document", "Paper-C": "Document",
             "Method-randomized": "Method", "Dataset-P": "Dataset", "Organization": "Type", "Entity": "Type", claim: "Claim"}
    rows = [
        ("e-owns", "Acme", "owns", "Bar", "Acme owns Bar.", {}, True),
        ("e-path", "Bar", "owns", "Foo", "Bar owns Foo.", {}, True),
        ("e-alias", "Acme", "same_as", "Acme-Holdings", "Acme and Acme Holdings name the same organization.", {}, True),
        ("e-partner", "Acme", "partnered_with", "Foo", "Acme partnered with Foo in 2023.", {"valid_from": "2023-01-01T00:00:00Z", "valid_until": "2024-03-01T00:00:00Z"}, True),
        ("e-old", "Foo", "subsidiary_of", "Baz", "Foo was a subsidiary of Baz until February 2024.",
         {"valid_from": "2020-01-01T00:00:00Z", "valid_until": "2024-03-01T00:00:00Z", "superseded_by": "e-new", "superseded_at": "2024-03-01T00:00:00Z"}, False),
        ("e-new", "Foo", "subsidiary_of", "Acme", "Foo became a subsidiary of Acme in March 2024.", {"valid_from": "2024-03-01T00:00:00Z"}, True),
        ("e-support", "Paper-A", "supports", claim, "Intervention X improves outcome Y in population P under method M.", {"population": "P"}, True),
        ("e-refute", "Paper-B", "refutes", claim, "Intervention X did not improve outcome Y in population P under method N.", {"population": "P"}, True),
        ("e-replicate", "Paper-C", "replicates", "Paper-A", "Paper C replicates the method of Paper A.", {}, True),
        ("e-method", "Paper-A", "uses_method", "Method-randomized", "Paper A used a randomized method.", {}, True),
        ("e-dataset", "Paper-B", "uses_dataset", "Dataset-P", "Paper B evaluated Dataset P.", {}, True),
        ("e-ontology", "Organization", "subclass_of", "Entity", "Organization is a subtype of Entity.", {}, True),
    ]
    facts, sources, evidence, statuses = {}, {}, {}, {}
    for ref, subject, predicate, object_, text, qualifiers, active in rows:
        source = c.source(subject if predicate in {"supports", "refutes"} else "source-"+ref, "1", text, scope=SCOPE)
        ev = c.evidence(source)
        sources[ref], evidence[ref] = source, ev
        statuses[source] = {"active": True, "permission": "READ", "epoch": 1, "updated_at": "2024-04-01T00:00:00Z", "tombstone": False}
        facts[ref] = {"assertion": {"subject": subject, "predicate": predicate, "object": object_, "qualifiers": qualifiers},
                      "evidence_ids": [ev], "prerequisites": [], "active": active, "revision": 1}
    old = deepcopy(facts)
    old.pop("e-new")
    old["e-old"]["active"] = True
    old["e-old"]["assertion"]["qualifiers"].pop("superseded_by")
    old["e-old"]["assertion"]["qualifiers"].pop("superseded_at")
    common = {"schema_id": schema_id, "schema_hash": c.hash(schema_id), "nodes": nodes,
              "source_epochs": {ref: 1 for ref in statuses}}
    previous = c.put("graph-snapshot", {**common, "graph_version": 1, "assertions": old})
    snapshot = c.put("graph-snapshot", {**common, "graph_version": 2, "assertions": facts})
    access = demo_access(c, snapshot)
    adapter = InMemoryGraphAdapter(c, [previous, snapshot], statuses)
    retriever = HybridRetriever(adapter, catalog=c, access_policy=access)
    return {"catalog": c, "schema_id": schema_id, "claim_id": claim, "snapshot_id": snapshot,
            "previous_snapshot_id": previous, "sources": sources, "evidence": evidence, "statuses": statuses,
            "access": access, "adapter": adapter, "retriever": retriever}


def domain_corpus() -> dict[str, Any]:
    """Fabricated multi-domain accepted read fixture, NOT representative research.

    This does not publish graph state or enroll a production trust authority.
    Transaction conformance must use the signed reference backend separately.
    """
    from ..domains import reference_taxonomy, create_assignment
    f = corpus()
    c = f["catalog"]
    review = {"status": "APPROVED", "reviewer_id": "synthetic-domain-fixture",
              "reviewed_at": "2026-09-27T00:00:00Z", "rationale": "Fabricated contract test labels; not independent human research review."}
    taxonomy = reference_taxonomy()["body"]
    taxonomy["review"] = review
    taxonomy["provenance"]["basis"] = "Synthetic classification fixture only; no real corpus or deployment qualification."
    taxonomy_id = c.put("research-domain-taxonomy", taxonomy)
    labels = {
        "e-owns": ["research:biology"], "e-path": ["research:biology", "research:chemistry"],
        "e-alias": ["research:physics"], "e-partner": ["research:physics"], "e-old": ["research:physics"],
        "e-new": ["research:chemistry"], "e-support": ["research:biology", "research:chemistry"],
        "e-refute": ["research:physics"], "e-method": ["research:biology"],
        "e-dataset": ["research:physics"], "e-ontology": ["research:biology"],
    }
    assignments = {}
    for edge_id, domains in labels.items():
        source_id = f["sources"][edge_id]
        assignments[source_id] = create_assignment(c, source_snapshot_id=source_id, taxonomy_id=taxonomy_id,
            domain_ids=domains, review=review, classifier_id="synthetic-domain-fixture", classifier_version="fixture-v1")
    snapshot = c.get(f["snapshot_id"], "graph-snapshot")
    snapshot["classifications"] = {"contract_version": 1, "revision": 2, "assignments": assignments}
    snapshot_id = c.put("graph-snapshot", snapshot)
    adapter = InMemoryGraphAdapter(c, [f["previous_snapshot_id"], snapshot_id], f["statuses"])
    access = demo_access(c, snapshot_id)
    f.update(snapshot_id=snapshot_id, taxonomy_id=taxonomy_id, assignments=assignments, adapter=adapter,
             access=access, retriever=HybridRetriever(adapter, catalog=c, access_policy=access), label_origin="SYNTHETIC_NOT_INDEPENDENT")
    return f
