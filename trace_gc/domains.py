"""Immutable research-domain records, not graph state or an authorization store.

Catalog membership does not publish an assignment. Only a committed graph
snapshot may choose an assignment; do not select by scanning for the newest
record. Topic labels never replace source status or application ACL checks.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, TYPE_CHECKING

from .canonical import digest, text_digest
from .errors import boundary, require
from .schema import validate

if TYPE_CHECKING:
    from .catalog import Catalog
    from .trust import TrustStore

VERSION = "trace-research-domain-v1"
KINDS = frozenset({"research-domain-taxonomy", "classification-proposal", "classification-assignment"})
REVIEW_PURPOSE = "CLASSIFICATION_REVIEW"
REVIEW_OPERATION = "CLASSIFY_SOURCE"
ASSIGNMENT_ONLY = frozenset({"proposal_id", "proposal_hash", "review_receipt_id",
                             "review_receipt_hash", "reviewed_approver", "reviewed_at"})


def _stamp(value: str) -> datetime:
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(result.tzinfo is not None, "DOMAIN_TIME", "timezone required")
    return result.astimezone(timezone.utc)


def _record(kind: str, body: dict[str, Any]) -> dict[str, Any]:
    h = digest({"kind": kind, "body": body})
    return {"id": f"{kind}:{h}", "kind": kind, "hash": h, "body": deepcopy(body)}


def _pinned(version: str) -> None:
    require(version.strip() == version and version.lower() not in
            {"latest", "main", "head", "unknown", "unversioned", "*"},
            "DOMAIN_VERSION", "an explicit immutable version is required")


def references(kind: str, body: dict[str, Any]) -> list[tuple[str, str]]:
    if kind == "receipt" and body["purpose"] == REVIEW_PURPOSE:
        return [(body["payload"]["proposal_id"], "classification-proposal")]
    if kind not in {"classification-proposal", "classification-assignment"}:
        return []
    refs = [(body["source_snapshot_id"], "source"),
            (body["taxonomy_id"], "research-domain-taxonomy")]
    refs.extend((p["record_id"], "source" if p["locator"] == "SOURCE_TEXT" else "evidence")
                for p in body["basis"])
    if body["supersedes"] is not None:
        refs.append((body["supersedes"], "classification-assignment"))
    if kind == "classification-assignment":
        refs.extend([(body["proposal_id"], "classification-proposal"),
                     (body["review_receipt_id"], "receipt")])
    return list(dict.fromkeys(refs))


def _taxonomy(catalog: Catalog, record: dict[str, Any]) -> None:
    b = record["body"]
    _pinned(b["version"])
    ids = [d["id"] for d in b["domains"]]
    require(ids == sorted(set(ids)), "DOMAIN_TAXONOMY", "domain IDs must be unique and sorted")
    require("unclassified" not in ids, "DOMAIN_TAXONOMY", "unclassified is a state, not a topical label")
    parents = {d["id"]: set(d["parent_ids"]) for d in b["domains"]}
    for d in b["domains"]:
        require(d["parent_ids"] == sorted(parents[d["id"]]) and
                parents[d["id"]] <= parents.keys(), "DOMAIN_TAXONOMY", "invalid parent IDs/order")
    # Iterative Kahn traversal avoids recursion on attacker-controlled hierarchy.
    children = {i: set() for i in ids}
    for child, deps in parents.items():
        for parent in deps:
            children[parent].add(child)
    pending = {i: len(deps) for i, deps in parents.items()}
    ready = [i for i, count in pending.items() if not count]
    visited = 0
    while ready:
        current = ready.pop()
        visited += 1
        for child in children[current]:
            pending[child] -= 1
            if not pending[child]:
                ready.append(child)
    require(visited == len(ids), "DOMAIN_TAXONOMY_CYCLE", "cyclic hierarchy")
    for old in catalog.all("research-domain-taxonomy"):
        ob = old["body"]
        if (ob["namespace"], ob["version"]) == (b["namespace"], b["version"]):
            require(old["hash"] == record["hash"], "DOMAIN_TAXONOMY_REVISION",
                    "one namespace/version cannot name two definitions")


def _proposal(catalog: Catalog, body: dict[str, Any]) -> None:
    source = catalog.get(body["source_snapshot_id"], "source")
    require(catalog.hash(body["source_snapshot_id"]) == body["source_hash"],
            "DOMAIN_SOURCE_HASH", "source snapshot hash differs")
    require(source["security_scope"] == body["security_scope"],
            "DOMAIN_SOURCE_SCOPE", "topic labels cannot change source scope")
    require(text_digest(source["text"]) == source["text_hash"],
            "DOMAIN_SOURCE_HASH", "source text differs from its immutable binding")
    taxonomy = catalog.get(body["taxonomy_id"], "research-domain-taxonomy")
    require(catalog.hash(body["taxonomy_id"]) == body["taxonomy_hash"] and
            taxonomy["version"] == body["taxonomy_version"],
            "DOMAIN_TAXONOMY_BINDING", "taxonomy hash/version differs")
    labels = body["domain_ids"]
    require(labels == sorted(set(labels)), "DOMAIN_LABELS", "labels must be unique and sorted")
    require(set(labels) <= {d["id"] for d in taxonomy["domains"]},
            "DOMAIN_UNKNOWN", "unknown taxonomy ID")
    require((body["state"] == "CLASSIFIED") == bool(labels),
            "DOMAIN_STATE", "classified requires labels; unclassified/retired require none")
    _pinned(body["method"]["version"])
    _stamp(body["created_at"])
    basis_ids = [p["record_id"] for p in body["basis"]]
    require(basis_ids == sorted(set(basis_ids)), "DOMAIN_BASIS", "unique sorted basis required")
    for basis in body["basis"]:
        r = catalog.record(basis["record_id"])
        require(r["hash"] == basis["record_hash"], "DOMAIN_BASIS", "basis hash differs")
        if basis["locator"] == "SOURCE_TEXT":
            require(r["kind"] == "source" and r["id"] == body["source_snapshot_id"],
                    "DOMAIN_BASIS", "basis must name this exact source")
        else:
            require(r["kind"] == "evidence" and
                    r["body"]["source_snapshot_id"] == body["source_snapshot_id"],
                    "DOMAIN_BASIS", "evidence basis must belong to this source")
            catalog.verify_evidence(r["id"])
    if body["supersedes"] is None:
        require(body["supersedes_hash"] is None and body["revision"] == 1 and
                body["state"] != "RETIRED", "DOMAIN_REVISION", "invalid initial assignment")
    else:
        prior = catalog.get(body["supersedes"], "classification-assignment")
        require(catalog.hash(body["supersedes"]) == body["supersedes_hash"],
                "DOMAIN_REVISION", "predecessor hash differs")
        require((prior["source_snapshot_id"], prior["source_hash"], prior["security_scope"]) ==
                (body["source_snapshot_id"], body["source_hash"], body["security_scope"]),
                "DOMAIN_REVISION", "predecessor belongs to another source")
        require(body["revision"] == prior["revision"] + 1 and
                body["effective_graph_version"] > prior["effective_graph_version"] and
                body["source_epoch"] >= prior["source_epoch"] and
                _stamp(body["created_at"]) >= _stamp(prior["reviewed_at"]),
                "DOMAIN_REVISION", "revision/version/epoch/time must advance consistently")


def review_payload(catalog: Catalog, proposal_id: str, reviewed_by: str) -> dict[str, Any]:
    proposal = catalog.get(proposal_id, "classification-proposal")
    return {"proposal_id": proposal_id, "proposal_hash": catalog.hash(proposal_id),
            "security_scope": proposal["security_scope"], "execution_mode": proposal["execution_mode"],
            "reviewed_by": reviewed_by, "operation": REVIEW_OPERATION,
            "risk_class": "R2", "authorization_granted": False}


@boundary
def validate_record(catalog: Catalog, record: dict[str, Any], *,
                    trust: TrustStore | None = None, at: str | None = None) -> None:
    kind = record["kind"]
    if kind == "receipt" and record["body"]["purpose"] == REVIEW_PURPOSE:
        receipt = record["body"]
        payload = receipt["payload"]
        require(payload == review_payload(catalog, payload["proposal_id"], payload["reviewed_by"]),
                "DOMAIN_REVIEW_BINDING", "review payload differs from exact proposal")
        proposal = catalog.get(payload["proposal_id"], "classification-proposal")
        require(_stamp(proposal["created_at"]) <= _stamp(receipt["issued_at"]) <
                _stamp(receipt["expires_at"]), "DOMAIN_REVIEW_TIME", "invalid review interval")
        if trust is not None:
            issuer = trust.verify(receipt, REVIEW_PURPOSE, at=at)
            require(issuer.can_review and issuer.principal == payload["reviewed_by"] and
                    REVIEW_OPERATION in issuer.operations and issuer.maximum_risk >= 2,
                    "DOMAIN_REVIEW_AUTHORITY", "reviewer lacks enrolled classification capability")
        return
    if kind not in KINDS:
        return
    validate(kind, record["body"])
    require(record == _record(kind, record["body"]), "DOMAIN_RECORD_ID",
            "classification record IDs must be content-addressed")
    if kind == "research-domain-taxonomy":
        _taxonomy(catalog, record)
        return
    body = record["body"]
    _proposal(catalog, body)
    if kind == "classification-proposal":
        return
    proposal = catalog.get(body["proposal_id"], "classification-proposal")
    require(catalog.hash(body["proposal_id"]) == body["proposal_hash"] and
            {k: v for k, v in body.items() if k not in ASSIGNMENT_ONLY} == proposal,
            "DOMAIN_PROPOSAL_BINDING", "reviewed assignment differs from proposal")
    receipt = catalog.get(body["review_receipt_id"], "receipt")
    require(catalog.hash(body["review_receipt_id"]) == body["review_receipt_hash"] and
            receipt["purpose"] == REVIEW_PURPOSE and
            receipt["payload"] == review_payload(catalog, body["proposal_id"], body["reviewed_approver"]),
            "DOMAIN_REVIEW_BINDING", "review receipt attribution or target differs")
    require(body["reviewed_at"] == receipt["issued_at"] and
            _stamp(receipt["issued_at"]) >= _stamp(proposal["created_at"]),
            "DOMAIN_REVIEW_TIME", "review predates proposal")
    if trust is not None:
        issuer = trust.verify(receipt, REVIEW_PURPOSE, at=at)
        require(issuer.can_review and issuer.principal == body["reviewed_approver"] and
                REVIEW_OPERATION in issuer.operations and issuer.maximum_risk >= 2,
                "DOMAIN_REVIEW_AUTHORITY", "reviewer lacks enrolled classification capability")
    for other in catalog.all("classification-assignment"):
        ob = other["body"]
        if ob["source_snapshot_id"] == body["source_snapshot_id"] and (
                ob["revision"] == body["revision"] or
                ob["effective_graph_version"] == body["effective_graph_version"]):
            require(other["hash"] == record["hash"], "DOMAIN_AMBIGUOUS_REVISION",
                    "two assignments compete for one source revision/version")


@boundary
def validate_catalog(catalog: Catalog, *, trust: TrustStore | None = None,
                     at: str | None = None) -> None:
    """Validate references only after all records of a bundle have been loaded."""
    for kind in sorted(KINDS | {"receipt"}):
        for record in catalog.all(kind):
            validate_record(catalog, record, trust=trust, at=at)


@boundary
def taxonomy(catalog: Catalog, *, namespace: str, version: str,
             domains: list[dict[str, Any]]) -> str:
    values = deepcopy(domains)
    for item in values:
        item["parent_ids"] = sorted(item.get("parent_ids", []))
    return catalog.put("research-domain-taxonomy", {
        "contract_version": VERSION, "namespace": namespace, "version": version,
        "domains": sorted(values, key=lambda d: d["id"]),
        "unclassified_semantics": "EXPLICIT_STATE_WITH_NO_LABELS",
        "membership_semantics": "EXPLICIT_LABELS_NO_IMPLICIT_ANCESTORS",
        "authorization_granted": False,
    })


@boundary
def propose(catalog: Catalog, *, source_snapshot_id: str, taxonomy_id: str,
            domain_ids: list[str], method: dict[str, Any], basis_ids: list[str],
            source_epoch: int, effective_graph_version: int, created_at: str,
            state: str = "CLASSIFIED", execution_mode: str = "RECORDED",
            supersedes: str | None = None) -> str:
    source = catalog.get(source_snapshot_id, "source")
    tx = catalog.get(taxonomy_id, "research-domain-taxonomy")
    basis = []
    for ref in sorted(basis_ids):
        record = catalog.record(ref)
        require(record["kind"] in {"source", "evidence"}, "DOMAIN_BASIS", "unsupported provenance")
        basis.append({"record_id": ref, "record_hash": record["hash"],
                      "locator": "SOURCE_TEXT" if record["kind"] == "source" else "EVIDENCE_SPAN"})
    previous = None if supersedes is None else catalog.get(supersedes, "classification-assignment")
    return catalog.put("classification-proposal", {
        "contract_version": VERSION, "source_snapshot_id": source_snapshot_id,
        "source_hash": catalog.hash(source_snapshot_id), "security_scope": source["security_scope"],
        "source_epoch": source_epoch, "taxonomy_id": taxonomy_id,
        "taxonomy_hash": catalog.hash(taxonomy_id), "taxonomy_version": tx["version"],
        "domain_ids": sorted(domain_ids), "state": state, "method": deepcopy(method),
        "basis": basis, "revision": 1 if previous is None else previous["revision"] + 1,
        "effective_graph_version": effective_graph_version, "supersedes": supersedes,
        "supersedes_hash": None if supersedes is None else catalog.hash(supersedes),
        "execution_mode": execution_mode, "created_at": created_at, "authorization_granted": False,
    })


@boundary
def assign(catalog: Catalog, *, proposal_id: str, review_receipt_id: str,
           reviewed_by: str, trust: TrustStore, at: str | None = None) -> str:
    """Create a reviewed record; does NOT publish it or mutate graph/source status."""
    require(trust is not None, "DOMAIN_REVIEW_AUTHORITY", "application trust required")
    body = {**catalog.get(proposal_id, "classification-proposal"),
            "proposal_id": proposal_id, "proposal_hash": catalog.hash(proposal_id),
            "review_receipt_id": review_receipt_id, "review_receipt_hash": catalog.hash(review_receipt_id),
            "reviewed_approver": reviewed_by,
            "reviewed_at": catalog.get(review_receipt_id, "receipt")["issued_at"]}
    record = _record("classification-assignment", body)
    validate_record(catalog, record, trust=trust, at=at)
    return catalog.add(record)
