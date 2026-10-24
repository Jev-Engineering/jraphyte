"""Classification operations lowered through the existing trusted plan boundary.

No function in this module can commit graph state. Migration and rollback are
ordinary reviewed, append-only plans; SQLite and the pinned bridge share their
existing transaction and journal boundaries.
"""
from __future__ import annotations

from copy import deepcopy
from typing import Any, TYPE_CHECKING

from .canonical import digest, loads
from .domains import verify_assignment
from .errors import require
from .schema import validate

if TYPE_CHECKING:
    from .catalog import Catalog
    from .trust import TrustStore

OPERATIONS = frozenset({"INITIALIZE_RESEARCH_DOMAINS", "SET_SOURCE_CLASSIFICATION"})
SNAPSHOT_FIELDS = ("graph_version", "schema_id", "schema_hash", "nodes", "assertions", "source_epochs")


def snapshot_body(state: dict[str, Any]) -> dict[str, Any]:
    body = {key: deepcopy(state[key]) for key in SNAPSHOT_FIELDS}
    if "classifications" in state:
        body["classifications"] = deepcopy(state["classifications"])
    return body


def empty_projection() -> dict[str, Any]:
    # Revision zero is a read interpretation of an unmigrated snapshot, never a
    # silent mutation of its serialized bytes or its original content hash.
    return {"contract_version": 1, "revision": 0, "assignments": {}}


def classification_identity(snapshot: dict[str, Any]) -> dict[str, Any]:
    projection = snapshot.get("classifications", empty_projection())
    return {"contract_version": 1, "revision": projection["revision"],
            "hash": digest(projection), "migrated": "classifications" in snapshot}


def verify_projection(catalog: Catalog, snapshot: dict[str, Any]) -> dict[str, Any]:
    projection = snapshot.get("classifications")
    if projection is None:
        return empty_projection()
    validate("classification-projection", projection)
    require(set(projection["assignments"]) <= set(snapshot["source_epochs"]),
            "DOMAIN_SOURCE_NOT_ADMITTED", "assignment source is not present in the snapshot")
    for source_id, assignment_id in projection["assignments"].items():
        assignment = verify_assignment(catalog, assignment_id)
        require(assignment["source_snapshot_id"] == source_id, "DOMAIN_PROJECTION", "assignment/source key differs")
        require(assignment["review"]["status"] == "APPROVED" and
                catalog.get(assignment["taxonomy_id"], "research-domain-taxonomy")["review"]["status"] == "APPROVED",
                "DOMAIN_REVIEW", "the accepted projection cannot contain unreviewed metadata")
    return deepcopy(projection)


def classification_operation(catalog: Catalog, assignment_id: str, *, operation_id: str) -> dict[str, Any]:
    assignment = verify_assignment(catalog, assignment_id)
    return {"id": operation_id, "operation": "SET_SOURCE_CLASSIFICATION", "risk_class": "R1",
            "assignment_id": assignment_id, "assignment_hash": catalog.hash(assignment_id),
            "source_snapshot_id": assignment["source_snapshot_id"], "source_hash": assignment["source_hash"],
            "taxonomy_id": assignment["taxonomy_id"], "taxonomy_hash": assignment["taxonomy_hash"],
            "expected_assignment_id": assignment["supersedes"], "expected_assignment_hash": assignment["supersedes_hash"]}


def migration_operation(*, operation_id: str, reason: str) -> dict[str, Any]:
    return {"id": operation_id, "operation": "INITIALIZE_RESEARCH_DOMAINS", "risk_class": "R1", "reason": reason}


def apply_operations(catalog: Catalog, snapshot: dict[str, Any], operations: list[dict[str, Any]], *,
                     security_scope: str) -> dict[str, Any] | None:
    """Pure prospective projection; every caller must still validate the full graph."""
    domain_ops = [op for op in operations if op["operation"] in OPERATIONS]
    if not domain_ops:
        return deepcopy(snapshot.get("classifications"))
    projection = verify_projection(catalog, snapshot)
    migrations = [op for op in domain_ops if op["operation"] == "INITIALIZE_RESEARCH_DOMAINS"]
    if migrations:
        require(len(operations) == 1 and "classifications" not in snapshot,
                "DOMAIN_MIGRATION", "initialize exactly once in its own append-only transaction")
        require(migrations[0]["risk_class"] == "R1", "RISK_UNDERCLASSIFIED", "classification migration")
        return {"contract_version": 1, "revision": 1, "assignments": {}}
    require("classifications" in snapshot, "DOMAIN_MIGRATION_REQUIRED", "publish a reviewed initialization plan first")
    changed_sources: set[str] = set()
    for op in domain_ops:
        require(op["risk_class"] == "R1", "RISK_UNDERCLASSIFIED", op["id"])
        assignment = verify_assignment(catalog, op["assignment_id"])
        source_id = assignment["source_snapshot_id"]
        require(source_id not in changed_sources, "DOMAIN_REVISION", "one assignment per source in a transaction")
        changed_sources.add(source_id)
        require(source_id in snapshot["source_epochs"], "DOMAIN_SOURCE_NOT_ADMITTED", source_id)
        require(assignment["security_scope"] == security_scope, "DOMAIN_SCOPE", source_id)
        require(assignment["review"]["status"] == "APPROVED", "DOMAIN_REVIEW", "a proposal is not publishable")
        expected = classification_operation(catalog, op["assignment_id"], operation_id=op["id"])
        require(op == expected, "DOMAIN_OPERATION_BINDING", "operation must bind the exact source, taxonomy and assignment")
        require(projection["assignments"].get(source_id) == op["expected_assignment_id"],
                "DOMAIN_REVISION", "assignment predecessor is not the current authoritative revision")
        if op["expected_assignment_id"] is not None:
            require(catalog.hash(op["expected_assignment_id"]) == op["expected_assignment_hash"],
                    "DOMAIN_REVISION", "current assignment hash differs")
        projection["assignments"][source_id] = op["assignment_id"]
    projection["revision"] += 1
    # Verify the result independently of the operation constructor.
    verify_projection(catalog, {**snapshot, "classifications": projection})
    return projection


def verify_review_attribution(catalog: Catalog, plan: dict[str, Any], reviewer_id: str | None,
                              *, at: str, approval_issued_at: str | None = None) -> None:
    from .compiler import timestamp
    for op in plan["operations"]:
        if op["operation"] not in OPERATIONS:
            continue
        require(reviewer_id is not None, "REVIEW_REQUIRED", "domain changes always require trusted review")
        if op["operation"] == "SET_SOURCE_CLASSIFICATION":
            assignment = verify_assignment(catalog, op["assignment_id"])
            require(assignment["review"]["status"] == "APPROVED" and
                    assignment["review"]["reviewer_id"] == reviewer_id,
                    "DOMAIN_REVIEW", "assignment review must match the authenticated plan reviewer")
            require(timestamp(assignment["review"]["reviewed_at"]) <= timestamp(at),
                    "DOMAIN_REVIEW", "classification review is in the future")
            if approval_issued_at is not None:
                require(timestamp(assignment["review"]["reviewed_at"]) <= timestamp(approval_issued_at),
                        "DOMAIN_REVIEW_ORDER", "signed approval predates its claimed classification review")


def receipt_projection(state: dict[str, Any]) -> dict[str, Any]:
    if "classifications" not in state:
        return {}
    identity = classification_identity(state)
    return {"classification_revision": identity["revision"], "classification_hash": identity["hash"]}



def verify_preflight_payload(preflight: dict[str, Any], plan: dict[str, Any], plan_hash: str, *,
                             policy_version: str, population: str, reviewed: bool) -> None:
    from .plans import REQUIRED_CHECKS
    required = preflight["payload"].get("review_required")
    expected = {"plan_hash": plan_hash, "graph_version": plan["graph_version"], "schema_hash": plan["schema_hash"],
                "source_epochs": plan["source_epochs"], "checks": {key: True for key in sorted(REQUIRED_CHECKS)},
                "run_id": plan["run_id"], "security_scope": plan["security_scope"], "execution_mode": plan["execution_mode"],
                "policy_version": policy_version, "population": population, "review_required": required}
    require(type(required) is bool and preflight["payload"] == expected and (not required or reviewed),
            "PREFLIGHT_FAILED", "invalid/missing checks or required review")

def audit_history(backend: Any, *, trust: TrustStore | None = None) -> dict[str, Any]:
    """Recompute classification transitions, optionally authenticating signed plans.

    A hash-chain-only audit is not advertised as origin authentication. Content
    erasure preserves journal hashes but necessarily makes exact replay unavailable.
    The enclosing backend audit first checks the existing chain/state/record hashes.
    """
    if backend.db.execute("SELECT 1 FROM trace_erased LIMIT 1").fetchone() is not None:
        return {"classification_replay": "UNAVAILABLE_ERASED_CONTENT", "classification_authority_verified": False}
    catalog = backend.load_catalog()
    previous = loads(backend.db.execute("SELECT body FROM trace_meta WHERE id=1").fetchone()[0])["genesis_state"]
    statuses: dict[str, Any] = {}
    domain_events = 0
    receipts = {digest(r["body"]): r["body"] for r in catalog.all("receipt")}
    for (text,) in backend.db.execute("SELECT body FROM trace_journal ORDER BY version"):
        event = loads(text)
        operation = event["operation"]
        after = event["state_after"]
        verify_projection(catalog, snapshot_body(after))
        expected = deepcopy(previous.get("classifications"))
        if operation.get("action") == "PUBLISH_PLAN":
            plan = catalog.get(operation["plan_id"], "plan")
            domain_ops = [op for op in plan["operations"] if op["operation"] in OPERATIONS]
            if domain_ops:
                domain_events += 1
                require(catalog.hash(operation["plan_id"]) == operation["plan_hash"],
                        "DOMAIN_AUDIT", "classification plan hash differs")
                require(catalog.get(plan["snapshot_id"], "graph-snapshot") == snapshot_body(previous),
                        "DOMAIN_AUDIT", "classification plan is not based on the prior authoritative state")
                require(plan["graph_version"] == previous["graph_version"] and
                        plan.get("classification_revision") == (previous.get("classifications") or {}).get("revision"),
                        "DOMAIN_AUDIT", "classification compare-and-swap revision differs")
                for source_id, epoch in plan["source_epochs"].items():
                    status = statuses.get(source_id)
                    require(status is not None and status["epoch"] == epoch and status["active"] and
                            status["permission"] == "READ" and not status["tombstone"],
                            "DOMAIN_AUDIT", "classification used a stale or unauthorized source epoch")
                from .plans import validate_plan
                prospective = validate_plan(catalog, plan, source_status=statuses)
                expected = prospective.get("classifications")
                require(prospective["nodes"] == after["nodes"] and prospective["assertions"] == after["assertions"],
                        "DOMAIN_AUDIT", "classification event differs from the fully validated prospective graph")
                require(event["authorization_hash"] in receipts and event["preflight_hash"] in receipts,
                        "DOMAIN_AUDIT", "classification approvals are missing")
                authorization, preflight = receipts[event["authorization_hash"]], receipts[event["preflight_hash"]]
                verify_preflight_payload(preflight, plan, operation["plan_hash"],
                                         policy_version=operation["policy_version"], population=operation["population"],
                                         reviewed=authorization["payload"].get("reviewed_by") is not None)
                verify_review_attribution(catalog, plan, authorization["payload"].get("reviewed_by"),
                                          at=event["committed_at"], approval_issued_at=authorization["issued_at"])
                if trust is not None:
                    from .trust import verify_authorization
                    reviewed = verify_authorization(trust, authorization, plan, operation["plan_hash"],
                                                    at=event["committed_at"], sandbox=backend.sandbox)
                    require(reviewed, "REVIEW_REQUIRED", "classification history is not reviewed")
                    trust.verify(preflight, "PREFLIGHT", at=event["committed_at"])
        require(after.get("classifications") == expected, "DOMAIN_AUDIT",
                "classification state changed outside a reviewed classification operation")
        require({k: event["transaction_receipt"].get(k) for k in receipt_projection(after)} == receipt_projection(after),
                "DOMAIN_AUDIT", "receipt classification identity differs")
        previous, statuses = after, event["source_status"]
    return {"classification_replay": "PASS", "classification_events": domain_events,
            "classification_authority_verified": trust is not None and domain_events > 0}
