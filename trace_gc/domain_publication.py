"""Classification operations lowered through the existing trusted plan boundary.

No function in this module can commit graph state. Migration and rollback are
ordinary reviewed, append-only plans; SQLite and the pinned bridge share their
existing transaction and journal boundaries.
"""
from __future__ import annotations

from copy import deepcopy
from typing import Any, TYPE_CHECKING

from .canonical import digest, loads
from .domains import create_assignment, verify_assignment
from .errors import ContractError, require
from .schema import validate

if TYPE_CHECKING:
    from .catalog import Catalog
    from .trust import TrustStore

OPERATIONS = frozenset({"INITIALIZE_RESEARCH_DOMAINS", "SET_SOURCE_CLASSIFICATION"})
SNAPSHOT_FIELDS = ("graph_version", "schema_id", "schema_hash", "nodes", "assertions", "source_epochs")


def has_classification_operations(plan: dict[str, Any]) -> bool:
    return any(op["operation"] in OPERATIONS for op in plan["operations"])


def snapshot_body(state: dict[str, Any]) -> dict[str, Any]:
    body = {key: deepcopy(state[key]) for key in SNAPSHOT_FIELDS}
    if "classifications" in state:
        body["classifications"] = deepcopy(state["classifications"])
    return body


def empty_projection() -> dict[str, Any]:
    # Revision zero is a read interpretation of an unmigrated snapshot, never a
    # silent mutation of its serialized bytes or its original content hash.
    return {"contract_version": 1, "revision": 0, "assignments": {}}


def _stored_projection(state: dict[str, Any]) -> dict[str, Any] | None:
    if "classifications" not in state:
        return None
    projection = state["classifications"]
    validate("classification-projection", projection)
    return projection


def classification_identity(snapshot: dict[str, Any]) -> dict[str, Any]:
    stored = _stored_projection(snapshot)
    projection = stored if stored is not None else empty_projection()
    return {"contract_version": 1, "revision": projection["revision"],
            "hash": digest(projection), "migrated": stored is not None}


def verify_projection(catalog: Catalog, snapshot: dict[str, Any]) -> dict[str, Any]:
    projection = _stored_projection(snapshot)
    if projection is None:
        return empty_projection()
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



def restore_assignment(catalog: Catalog, *, current_assignment_id: str, restore_assignment_id: str,
                       review: dict[str, Any], classifier_id: str, classifier_version: str) -> str:
    """Create a compensating successor with labels from an earlier revision."""
    current = verify_assignment(catalog, current_assignment_id)
    predecessor = current["supersedes"]
    while predecessor is not None and predecessor != restore_assignment_id:
        predecessor = catalog.get(predecessor, "classification-assignment")["supersedes"]
    require(predecessor is not None, "DOMAIN_REVISION", "restore target must precede the current assignment")
    target = catalog.get(restore_assignment_id, "classification-assignment")
    return create_assignment(catalog, source_snapshot_id=current["source_snapshot_id"], taxonomy_id=target["taxonomy_id"],
                             domain_ids=target["domain_ids"], status=target["status"], review=review,
                             classifier_id=classifier_id, classifier_version=classifier_version,
                             supersedes=current_assignment_id,
                             basis_ids=[item["record_id"] for item in target["provenance"]["basis"]])

def migration_operation(*, operation_id: str, reason: str) -> dict[str, Any]:
    return {"id": operation_id, "operation": "INITIALIZE_RESEARCH_DOMAINS", "risk_class": "R1", "reason": reason}


def apply_operations(catalog: Catalog, snapshot: dict[str, Any], operations: list[dict[str, Any]], *,
                     security_scope: str) -> dict[str, Any] | None:
    """Pure prospective projection; every caller must still validate the full graph."""
    domain_ops = [op for op in operations if op["operation"] in OPERATIONS]
    if not domain_ops:
        return deepcopy(_stored_projection(snapshot))
    projection = verify_projection(catalog, snapshot)
    initialized = "classifications" in snapshot
    migrations = [op for op in domain_ops if op["operation"] == "INITIALIZE_RESEARCH_DOMAINS"]
    if migrations:
        require(len(operations) == 1 and not initialized,
                "DOMAIN_MIGRATION", "initialize exactly once in its own append-only transaction")
        require(migrations[0]["risk_class"] == "R1", "RISK_UNDERCLASSIFIED", "classification migration")
        return {"contract_version": 1, "revision": 1, "assignments": {}}
    require(initialized, "DOMAIN_MIGRATION_REQUIRED", "publish a reviewed initialization plan first")
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




def verify_transaction_receipt(event: dict[str, Any], *, backend: str) -> None:
    operation = event["operation"]
    expected = {key: event[key] for key in ("version", "idempotency_key", "before_hash", "after_hash", "previous_hash",
                                            "authorization_hash", "preflight_hash", "upstream_head", "committed_at")}
    expected.update(backend=backend, plan_hash=operation.get("plan_hash", digest(operation)),
                    event_hash=event["hash"], operation_hash=digest(operation), **receipt_projection(event["state_after"]))
    require(event["transaction_receipt"] == expected, "BACKEND_AUDIT", "receipt was altered independently of the journal")


def verify_preflight_payload(preflight: dict[str, Any], plan: dict[str, Any], plan_hash: str, *,
                             policy_version: str, population: str, reviewed: bool) -> None:
    from .plans import REQUIRED_CHECKS
    required = preflight["payload"].get("review_required")
    expected = {"plan_hash": plan_hash, "graph_version": plan["graph_version"], "schema_hash": plan["schema_hash"],
                "source_epochs": plan["source_epochs"], "checks": {key: True for key in sorted(REQUIRED_CHECKS)},
                "run_id": plan["run_id"], "security_scope": plan["security_scope"], "execution_mode": plan["execution_mode"],
                "policy_version": policy_version, "population": population, "review_required": required}
    require(type(required) is bool and digest(preflight["payload"]) == digest(expected) and (not required or reviewed),
            "PREFLIGHT_FAILED", "invalid/missing checks or required review")

def apply_publication_state(catalog, state, plan, statuses):
    from .plans import validate_plan

    prospective = validate_plan(catalog, plan, source_status=statuses)
    state["nodes"] = prospective["nodes"]
    state["assertions"] = prospective["assertions"]
    if "classifications" in prospective:
        state["classifications"] = prospective["classifications"]
    for op in plan["operations"]:
        if op["operation"] == "APPLY_SCHEMA_MIGRATION":
            state["schema_id"] = op["target_schema_id"]
            state["schema_hash"] = catalog.hash(op["target_schema_id"])
        elif op["operation"] == "PROPOSE_SCHEMA_MIGRATION":
            state["schema_proposals"][op["id"]] = deepcopy(op)
        elif op["operation"] == "ATTACH_CANDIDATE_METADATA":
            state["metadata"].setdefault(op["candidate_id"], {})[op["id"]] = deepcopy(op["metadata"])
    return state


def _verify_classification_event(catalog, event, plan, previous, previous_projection, statuses, receipts, *, trust, sandbox):
    operation = event["operation"]
    after = event["state_after"]
    require(event["authorization_hash"] in receipts and event["preflight_hash"] in receipts,
            "DOMAIN_AUDIT", "classification approvals are missing")
    authorization, preflight = receipts[event["authorization_hash"]], receipts[event["preflight_hash"]]
    policy = catalog.get(plan["policy_id"], "policy")
    require(operation["policy_version"] == policy["version"] and operation["population"] == policy["population"]
            and operation["security_scope"] == plan["security_scope"],
            "DOMAIN_AUDIT", "publication policy or scope differs from the plan")
    verify_preflight_payload(preflight, plan, operation["plan_hash"],
                             policy_version=policy["version"], population=policy["population"],
                             reviewed=authorization["payload"].get("reviewed_by") is not None)
    if trust is not None:
        from .trust import verify_authorization
        reviewed = verify_authorization(trust, authorization, plan, operation["plan_hash"],
                                        at=event["committed_at"], sandbox=sandbox)
        require(reviewed, "REVIEW_REQUIRED", "classification history is not reviewed")
        trust.verify(preflight, "PREFLIGHT", at=event["committed_at"])
    verify_review_attribution(catalog, plan, authorization["payload"].get("reviewed_by"),
                              at=event["committed_at"], approval_issued_at=authorization["issued_at"])
    require(digest(catalog.get(plan["snapshot_id"], "graph-snapshot")) == digest(snapshot_body(previous)),
            "DOMAIN_AUDIT", "classification plan is not based on the prior authoritative state")
    previous_revision = previous_projection["revision"] if previous_projection is not None else None
    require(plan["graph_version"] == previous["graph_version"] and
            plan.get("classification_revision") == previous_revision,
            "DOMAIN_AUDIT", "classification compare-and-swap revision differs")
    for source_id, epoch in plan["source_epochs"].items():
        status = statuses.get(source_id)
        require(status is not None and status["epoch"] == epoch and status["active"] and
                status["permission"] == "READ" and not status["tombstone"],
                "DOMAIN_AUDIT", "classification used a stale or unauthorized source epoch")
    prospective = apply_publication_state(catalog, deepcopy(previous), plan, statuses)
    prospective["graph_version"] = previous["graph_version"] + 1
    prospective["source_epochs"] = {ref: status["epoch"] for ref, status in statuses.items()}
    require(digest(prospective) == digest(after) and digest(event["source_status"]) == digest(statuses),
            "DOMAIN_AUDIT", "classification event differs from the complete validated publication state")
    return _stored_projection(prospective)


def _source_status_changes(event, previous, statuses):
    from .compiler import timestamp

    operation = event["operation"]
    action, recorded = operation.get("action"), event["source_status"]
    changes = {}
    if action in {"ADMIT", "STATUS_CHANGE", "ERASE"}:
        require(type(operation.get("expected_version")) is int and
                operation["expected_version"] == previous["graph_version"],
                "DOMAIN_AUDIT", "source operation graph version differs")
    if action == "ADMIT":
        for ref in operation["source_hashes"]:
            if ref in statuses:
                require(not statuses[ref]["tombstone"], "DOMAIN_AUDIT", "source readmission after tombstone")
                continue
            updated_at = recorded[ref]["updated_at"]
            timestamp(updated_at)
            changes[ref] = {"active": True, "permission": "READ", "epoch": 0,
                            "updated_at": updated_at, "tombstone": False}
    elif action in {"STATUS_CHANGE", "ERASE"}:
        ref = operation["source_id"]
        old = statuses.get(ref)
        active, permission, tombstone = operation["active"], operation["permission"], operation["tombstone"]
        require(old is not None and not old["tombstone"] and type(operation["expected_epoch"]) is int and
                old["epoch"] == operation["expected_epoch"] and
                type(active) is bool and permission in {"READ", "DENIED"} and tombstone is (action == "ERASE") and
                (not tombstone or (not active and permission == "DENIED")),
                "DOMAIN_AUDIT", "invalid source operation precondition")
        updated_at = recorded[ref]["updated_at"]
        timestamp(updated_at)
        changes[ref] = {"active": active, "permission": permission, "epoch": old["epoch"] + 1,
                        "updated_at": updated_at, "tombstone": tombstone}
    expected = {**statuses, **changes}
    epochs = {ref: status["epoch"] for ref, status in expected.items()}
    require(digest(recorded) == digest(expected) and digest(event["state_after"]["source_epochs"]) == digest(epochs),
            "DOMAIN_AUDIT", "source statuses differ from the recorded operation")
    return changes


def audit_history(backend: Any, *, trust: TrustStore | None = None,
                  required_sources: tuple[str, ...] = ()) -> dict[str, Any]:
    """Recompute classification transitions, optionally authenticating signed plans.

    A hash-chain-only audit is not advertised as origin authentication. Content
    erasure preserves journal hashes but necessarily makes exact replay unavailable.
    The enclosing backend audit first checks the existing chain/state/record hashes.
    """
    previous = loads(backend.db.execute("SELECT body FROM trace_meta WHERE id=1").fetchone()[0])["genesis_state"]
    previous_projection = _stored_projection(previous)
    require(previous_projection is None, "DOMAIN_AUDIT",
            "classification genesis must be unmigrated; initialization requires a reviewed transaction")
    erased = dict(backend.db.execute("SELECT id,hash FROM trace_erased"))
    if erased:
        from .catalog import Catalog
        catalog = Catalog({"id": ref, "hash": hash_, "kind": kind, "body": loads(body)}
                          for ref, hash_, kind, body in backend.db.execute("SELECT id,hash,kind,body FROM trace_records"))
    else:
        catalog = backend.load_catalog()
    statuses: dict[str, Any] = {}
    domain_events = 0
    missing_proof = False
    receipts = {digest(r["body"]): r["body"] for r in catalog.all("receipt")}
    source_history: dict[str, list[dict[str, Any]]] = {}
    checked_authority = set()

    def authenticate_sources(refs):
        if trust is None:
            return
        for ref in refs:
            require(ref in source_history, "DOMAIN_AUDIT", "classification source admission proof is missing")
            for event in source_history[ref]:
                operation = event["operation"]
                action = operation["action"]
                source_hash = operation["source_hashes"][ref] if action == "ADMIT" else operation["source_hash"]
                require(source_hash == catalog.hash(ref) and
                        operation["security_scope"] == catalog.get(ref, "source")["security_scope"],
                        "DOMAIN_AUDIT", "source authority bound different bytes or scope")
                if event["hash"] in checked_authority:
                    continue
                receipt = receipts.get(event["authorization_hash"])
                require(receipt is not None, "REPLAY_CONTENT_UNAVAILABLE", "source authorization bytes are unavailable")
                record_hash = digest({"kind": "receipt", "body": receipt})
                require(event["record_hashes"].get(f"receipt:{record_hash}") == record_hash,
                        "DOMAIN_AUDIT", "source authorization record is not journal-bound")
                issuer = trust.verify(receipt, "SOURCE_STATUS", at=event["committed_at"])
                require(digest(receipt["payload"]) == digest(operation),
                        "DOMAIN_AUDIT", "source authorization differs from the journal")
                if action == "ADMIT":
                    capability = "SOURCE_ADMIT"
                elif action == "ERASE":
                    capability = "SOURCE_ERASE"
                else:
                    capability = "SOURCE_PERMISSION" if operation["active"] else "SOURCE_WITHDRAW"
                require(capability in issuer.operations, "DOMAIN_AUDIT", "source operation was not authorized")
                checked_authority.add(event["hash"])

    for (text,) in backend.db.execute("SELECT body FROM trace_journal ORDER BY version"):
        event = loads(text)
        operation = event["operation"]
        after = event["state_after"]
        current_projection = _stored_projection(after)
        for ref in _source_status_changes(event, previous, statuses):
            source_history.setdefault(ref, []).append(event)
        changed = current_projection != previous_projection
        expected = previous_projection
        if operation.get("action") == "PUBLISH_PLAN":
            plan_id = operation["plan_id"]
            plan_hash = operation["plan_hash"]
            require(event["record_hashes"].get(plan_id) == plan_hash, "DOMAIN_AUDIT", "publication plan is not journal-bound")
            if plan_id not in catalog and erased.get(plan_id) == plan_hash:
                # An ordinary plan can lose its snapshot and plan during erasure.
                # A classified transition without its signed plan cannot be authenticated.
                if changed:
                    missing_proof = True
                    expected = current_projection
            else:
                plan = catalog.get(plan_id, "plan")
                require(catalog.hash(plan_id) == plan_hash, "DOMAIN_AUDIT", "publication plan hash differs")
                require(event["idempotency_key"] == plan["idempotency_key"] == event["transaction_receipt"]["idempotency_key"],
                        "DOMAIN_AUDIT", "publication event and receipt key differ from the signed plan")
                if has_classification_operations(plan):
                    domain_events += 1
                    snapshot_id = plan["snapshot_id"]
                    if snapshot_id not in catalog and snapshot_id in erased and has_classification_operations(plan):
                        # The signed plan retains the snapshot reference. The
                        # journal already retains exactly these metadata bytes.
                        snapshot = snapshot_body(previous)
                        snapshot_hash = digest({"kind": "graph-snapshot", "body": snapshot})
                        require(erased[snapshot_id] == event["record_hashes"].get(snapshot_id) == snapshot_hash,
                                "DOMAIN_AUDIT", "erased snapshot metadata does not match the signed plan")
                        catalog.put("graph-snapshot", snapshot, id_=snapshot_id)
                    try:
                        authenticate_sources(plan["source_epochs"])
                        expected = _verify_classification_event(catalog, event, plan, previous, previous_projection,
                            statuses, receipts, trust=trust, sandbox=backend.sandbox)
                    except ContractError as exc:
                        if exc.code != "MISSING_REFERENCE" or exc.detail not in erased or (
                            event["record_hashes"].get(exc.detail) != erased[exc.detail]
                        ):
                            raise
                        missing_proof = True
                        expected = current_projection
        require(current_projection == expected, "DOMAIN_AUDIT",
                "classification state changed outside a reviewed classification operation")
        previous, previous_projection, statuses = after, current_projection, event["source_status"]
    if missing_proof:
        return {"classification_replay": "UNAVAILABLE_ERASED_CONTENT", "classification_authority_verified": False}
    authenticate_sources(required_sources)
    return {"classification_replay": "PASS", "classification_events": domain_events,
            "classification_authority_verified": trust is not None and domain_events > 0}
