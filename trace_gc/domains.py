"""Versioned topical metadata, not ontology types, ACLs, or scientific truth.

Catalog records may contain proposed or claimed-reviewed metadata. Only the
application-owned publication boundary can make an assignment authoritative;
review fields and model output alone never grant a publication capability.
"""
from __future__ import annotations

from copy import deepcopy
from importlib.resources import files
from typing import TYPE_CHECKING, Any

from .canonical import digest, loads, text_digest
from .errors import boundary, require

if TYPE_CHECKING:
    from .catalog import Catalog

KINDS = frozenset({"research-domain-taxonomy", "classification-assignment"})
CONTRACT_VERSION = 1


def _sorted_unique(values: list[str], code: str) -> None:
    require(values == sorted(set(values)), code, "use sorted, unique identifiers")


def _review(review: dict[str, Any]) -> None:
    from .compiler import timestamp
    approved = review["status"] == "APPROVED"
    require((review["reviewer_id"] is not None) == approved and
            (review["reviewed_at"] is not None) == approved,
            "DOMAIN_REVIEW", "approval must identify the reviewer and review time; proposals must not")
    if approved:
        timestamp(review["reviewed_at"])


def verify_review_order(later: dict[str, Any], earlier: dict[str, Any], *, relationship: str) -> None:
    """Compare recorded approval instants, not wall-clock time during replay.

    Proposals make no approval claim. Equal instants are valid (including
    equivalent timezone offsets); immutable source and journal bytes are untouched.
    This is a consistency check, not authentication of either review statement.
    """
    if later["status"] == earlier["status"] == "APPROVED":
        from .compiler import timestamp
        require(timestamp(earlier["reviewed_at"]) <= timestamp(later["reviewed_at"]),
                "DOMAIN_REVIEW_ORDER", relationship + " approval chronology differs")


def validate_record(record: dict[str, Any]) -> None:
    """Local semantic checks; cross-record checks occur after catalog loading."""
    if record["kind"] not in KINDS:
        return
    require(record["id"] == f'{record["kind"]}:{record["hash"]}',
            "DOMAIN_ID", "domain contracts require content-addressed IDs")
    body = record["body"]
    _review(body["review"])
    require((body["supersedes"] is None) == (body["supersedes_hash"] is None),
            "DOMAIN_REVISION", "predecessor ID and hash must occur together")
    if record["kind"] == "research-domain-taxonomy":
        ids = [term["id"] for term in body["domains"]]
        _sorted_unique(ids, "DOMAIN_TAXONOMY")
        parents = {term["id"]: term["parent_ids"] for term in body["domains"]}
        for ref, refs in parents.items():
            _sorted_unique(refs, "DOMAIN_TAXONOMY")
            require(set(refs) <= set(ids) and ref not in refs,
                    "DOMAIN_TAXONOMY", "unknown or self-referential hierarchy parent")
        # Iterative topological validation avoids recursion limits on input taxonomies.
        pending = {ref: set(refs) for ref, refs in parents.items()}
        while pending:
            ready = {ref for ref, refs in pending.items() if not refs}
            require(bool(ready), "DOMAIN_TAXONOMY", "taxonomy hierarchy is cyclic")
            pending = {ref: refs - ready for ref, refs in pending.items() if ref not in ready}
        revision = body["version"]
    else:
        _sorted_unique(body["domain_ids"], "DOMAIN_MEMBERSHIP")
        require(bool(body["domain_ids"]) == (body["status"] == "CLASSIFIED"),
                "DOMAIN_MEMBERSHIP", "unclassified and retired assignments have no labels")
        basis_ids = [item["record_id"] for item in body["provenance"]["basis"]]
        _sorted_unique(basis_ids, "DOMAIN_PROVENANCE")
        require(body["status"] != "RETIRED" or body["supersedes"] is not None,
                "DOMAIN_REVISION", "retirement must supersede an assignment")
        revision = body["effective_revision"]
    require((revision == 1) == (body["supersedes"] is None),
            "DOMAIN_REVISION", "revision one has no predecessor; every later revision has one")


@boundary
def verify_taxonomy(catalog: Catalog, taxonomy_id: str) -> dict[str, Any]:
    """Verify an append-only taxonomy lineage and prevent identifier repurposing."""
    current = catalog.get(taxonomy_id, "research-domain-taxonomy")
    selected = deepcopy(current)
    seen = {taxonomy_id}
    while current["supersedes"] is not None:
        previous_id = current["supersedes"]
        require(previous_id not in seen, "DOMAIN_REVISION", "taxonomy lineage cycle")
        seen.add(previous_id)
        previous = catalog.get(previous_id, "research-domain-taxonomy")
        require(catalog.hash(previous_id) == current["supersedes_hash"], "DOMAIN_TAXONOMY_HASH", previous_id)
        require(previous["taxonomy_key"] == current["taxonomy_key"] and
                previous["version"] + 1 == current["version"], "DOMAIN_REVISION", "taxonomy lineage gap")
        verify_review_order(current["review"], previous["review"], relationship="taxonomy successor")
        before = {term["id"]: term for term in previous["domains"]}
        after = {term["id"]: term for term in current["domains"]}
        require(before.keys() <= after.keys(), "DOMAIN_TAXONOMY", "retire IDs instead of removing them")
        for ref, term in before.items():
            require(after[ref]["definition"] == term["definition"], "DOMAIN_TAXONOMY",
                    "an existing domain ID cannot be assigned a different meaning")
            require(term["status"] != "RETIRED" or after[ref]["status"] == "RETIRED",
                    "DOMAIN_TAXONOMY", "retired domain IDs cannot be reused")
        current = previous
    return selected


@boundary
def verify_assignment(catalog: Catalog, assignment_id: str) -> dict[str, Any]:
    """Bind labels, provenance, and revision to the exact immutable source."""
    selected = catalog.get(assignment_id, "classification-assignment")
    current, seen = selected, {assignment_id}
    while True:
        source_id = current["source_snapshot_id"]
        source = catalog.get(source_id, "source")
        require(catalog.hash(source_id) == current["source_hash"] and
                text_digest(source["text"]) == source["text_hash"], "DOMAIN_SOURCE_HASH", source_id)
        require(source["security_scope"] == current["security_scope"], "DOMAIN_SCOPE", source_id)
        taxonomy = verify_taxonomy(catalog, current["taxonomy_id"])
        require(catalog.hash(current["taxonomy_id"]) == current["taxonomy_hash"],
                "DOMAIN_TAXONOMY_HASH", current["taxonomy_id"])
        verify_review_order(current["review"], taxonomy["review"], relationship="assignment/taxonomy")
        active = {term["id"] for term in taxonomy["domains"] if term["status"] == "ACTIVE"}
        require(set(current["domain_ids"]) <= active, "DOMAIN_MEMBERSHIP", "unknown or retired taxonomy ID")
        for basis in current["provenance"]["basis"]:
            record = catalog.record(basis["record_id"])
            require(record["hash"] == basis["record_hash"], "DOMAIN_PROVENANCE", "basis hash differs")
            require(record["kind"] in {"source", "evidence"}, "DOMAIN_PROVENANCE",
                    "classification basis must be a source or an exact source span")
            if record["kind"] == "source":
                require(record["id"] == source_id, "DOMAIN_PROVENANCE", "basis belongs to another source")
            else:
                catalog.verify_evidence(record["id"])
                require(record["body"]["source_snapshot_id"] == source_id,
                        "DOMAIN_PROVENANCE", "basis span belongs to another source")
        previous_id = current["supersedes"]
        if previous_id is None:
            break
        require(previous_id not in seen, "DOMAIN_REVISION", "assignment lineage cycle")
        seen.add(previous_id)
        previous = catalog.get(previous_id, "classification-assignment")
        require(catalog.hash(previous_id) == current["supersedes_hash"], "DOMAIN_REVISION", "predecessor hash differs")
        require(previous["effective_revision"] + 1 == current["effective_revision"] and
                all(previous[key] == current[key] for key in ("source_snapshot_id", "source_hash", "security_scope")),
                "DOMAIN_REVISION", "reclassification must retain the exact source and consecutive revision")
        require(previous["review"]["status"] == "APPROVED", "DOMAIN_REVIEW", "cannot supersede an unreviewed proposal")
        verify_review_order(current["review"], previous["review"], relationship="assignment successor")
        current = previous
    return deepcopy(selected)


def validate_catalog(catalog: Catalog) -> None:
    """Validate complete bundles, rejecting ambiguous claimed-approved revisions."""
    assigned: dict[tuple[str, int], str] = {}
    taxonomies: dict[tuple[str, int], str] = {}
    for record in catalog.all():
        if record["kind"] == "research-domain-taxonomy":
            body = verify_taxonomy(catalog, record["id"])
            key, revisions = (body["taxonomy_key"], body["version"]), taxonomies
        elif record["kind"] == "classification-assignment":
            body = verify_assignment(catalog, record["id"])
            key, revisions = (body["source_snapshot_id"], body["effective_revision"]), assigned
        else:
            continue
        if body["review"]["status"] == "APPROVED":
            require(key not in revisions or revisions[key] == record["id"],
                    "DOMAIN_REVISION", "ambiguous approved revision in one bundle")
            revisions[key] = record["id"]


def references(kind: str, body: dict[str, Any]) -> list[tuple[str, str]]:
    if kind not in KINDS:
        return []
    refs = []
    if body["supersedes"] is not None:
        refs.append((body["supersedes"], kind))
    if kind == "classification-assignment":
        refs.extend([(body["source_snapshot_id"], "source"),
                     (body["taxonomy_id"], "research-domain-taxonomy")])
        refs.extend((item["record_id"], "*") for item in body["provenance"]["basis"])
    return list(dict.fromkeys(refs))


def create_assignment(catalog: Catalog, *, source_snapshot_id: str, taxonomy_id: str,
                      domain_ids: list[str], review: dict[str, Any], classifier_id: str,
                      classifier_version: str, method: str = "HUMAN_REVIEW", status: str | None = None,
                      supersedes: str | None = None, basis_ids: list[str] | None = None) -> str:
    """Build an immutable proposal/claimed-reviewed record; this does not publish it."""
    source = catalog.get(source_snapshot_id, "source")
    previous = catalog.get(supersedes, "classification-assignment") if supersedes else None
    body = {"contract_version": CONTRACT_VERSION, "source_snapshot_id": source_snapshot_id,
            "source_hash": catalog.hash(source_snapshot_id), "security_scope": source["security_scope"],
            "taxonomy_id": taxonomy_id, "taxonomy_hash": catalog.hash(taxonomy_id),
            "domain_ids": sorted(set(domain_ids)), "status": status or ("CLASSIFIED" if domain_ids else "UNCLASSIFIED"),
            "effective_revision": previous["effective_revision"] + 1 if previous else 1,
            "supersedes": supersedes, "supersedes_hash": catalog.hash(supersedes) if supersedes else None,
            "provenance": {"method": method, "classifier_id": classifier_id, "classifier_version": classifier_version,
                           "basis": [{"record_id": ref, "record_hash": catalog.hash(ref)}
                                     for ref in sorted(set(basis_ids if basis_ids is not None else [source_snapshot_id]))]},
            "review": deepcopy(review)}
    # Validate using a scratch catalog so rejected constructors leave no orphan record.
    from .catalog import Catalog
    scratch = Catalog(catalog.all())
    assignment_id = scratch.put("classification-assignment", body)
    verify_assignment(scratch, assignment_id)
    return catalog.add(scratch.record(assignment_id))


def reference_taxonomy() -> dict[str, Any]:
    """Packaged proposed reference taxonomy, explicitly not deployment approval."""
    return loads(files("trace_gc").joinpath("data/research_domains/reference_taxonomy_v1.json").read_bytes())


def restore_assignment(catalog: Catalog, *, current_assignment_id: str, restore_assignment_id: str,
                       review: dict[str, Any], classifier_id: str, classifier_version: str) -> str:
    """Create a compensating successor; never overwrite or decrement a revision."""
    current = verify_assignment(catalog, current_assignment_id)
    target = verify_assignment(catalog, restore_assignment_id)
    require(all(current[key] == target[key] for key in ("source_snapshot_id", "source_hash", "security_scope")),
            "DOMAIN_REVISION", "rollback target belongs to a different source snapshot")
    require(target["effective_revision"] <= current["effective_revision"],
            "DOMAIN_REVISION", "rollback target is not historical")
    return create_assignment(catalog, source_snapshot_id=current["source_snapshot_id"], taxonomy_id=target["taxonomy_id"],
                             domain_ids=target["domain_ids"], status=target["status"], review=review,
                             classifier_id=classifier_id, classifier_version=classifier_version,
                             supersedes=current_assignment_id,
                             basis_ids=[item["record_id"] for item in target["provenance"]["basis"]])
