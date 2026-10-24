"""Reviewed domain publication through the existing reference graph journal.

This application-owned service is not a query API, a replacement graph store,
or a qualified deployment adapter. Importing a plan or reviewed assignment into
Catalog never publishes it. Migration and publication require separate enrolled
capabilities. No signing key is generated or enrolled by this module.
"""
from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from typing import Any, Callable, TYPE_CHECKING

from .canonical import digest, loads
from .domains import _stamp, validate_record as validate_assignment
from .errors import boundary, require
from .schema import validate

if TYPE_CHECKING:
    from .backend import SQLiteReferenceBackend
    from .catalog import Catalog
    from .trust import Signer, TrustStore

VERSION = "trace-domain-publication-v1"
PROJECTION_KEY = "research_domains"
KINDS = frozenset({"classification-plan"})
MIGRATE = "MIGRATE_CLASSIFICATION_STATE"
PUBLISH = "PUBLISH_CLASSIFICATION"
PREFLIGHT = "CLASSIFICATION_PREFLIGHT"
AUTHORIZATION = "CLASSIFICATION_PUBLISH"
VALIDATE_CAPABILITY = "VALIDATE_CLASSIFICATION"
CHECKS = frozenset({"EXACT_RECORDS", "REVIEW_AUTHORITY",
                    "CURRENT_SOURCE_STATUS", "SOURCE_EPOCH", "GRAPH_CAS",
                    "COMMITTED_PREDECESSOR", "JOURNAL_INTEGRITY", "SANDBOX_MODE"})


def now() -> str:
    from .compiler import now as compiler_now
    return compiler_now()


def references(kind: str, body: dict[str, Any]) -> list[tuple[str, str]]:
    if kind == "classification-plan":
        refs = [(ref, "source") for ref in body["source_hashes"]]
        if body["assignment_id"] is not None:
            refs += [(body["assignment_id"], "classification-assignment"),
                     (body["taxonomy_id"], "research-domain-taxonomy")]
        return refs
    if kind == "receipt" and body["purpose"] in {PREFLIGHT, AUTHORIZATION}:
        return [(body["payload"]["plan_id"], "classification-plan")]
    if kind == "graph-snapshot" and PROJECTION_KEY in body:
        return [(entry["assignment_id"], "classification-assignment")
                for entry in body[PROJECTION_KEY]["assignments"].values()]
    return []


@boundary
def validate_plan_record(catalog: Catalog, record: dict[str, Any]) -> None:
    if record["kind"] != "classification-plan":
        return
    plan = record["body"]
    validate("classification-plan", plan)
    h = digest({"kind": record["kind"], "body": plan})
    require(record["id"] == f"classification-plan:{h}" and record["hash"] == h,
            "DOMAIN_PLAN_ID", "plan must be content-addressed")
    require(set(plan["source_epochs"]) == set(plan["source_hashes"]),
            "DOMAIN_PLAN_BINDING", "source epoch/hash sets differ")
    if plan["action"] == MIGRATE:
        require(not plan["source_hashes"] and
                all(plan[k] is None for k in ("assignment_id", "assignment_hash", "taxonomy_id", "taxonomy_hash")),
                "DOMAIN_PLAN_BINDING", "migration only initializes an empty projection")
        return
    assignment = catalog.get(plan["assignment_id"], "classification-assignment")
    source_id = assignment["source_snapshot_id"]
    require(plan["assignment_hash"] == catalog.hash(plan["assignment_id"]) and
            plan["taxonomy_id"] == assignment["taxonomy_id"] and
            plan["taxonomy_hash"] == assignment["taxonomy_hash"] == catalog.hash(plan["taxonomy_id"]) and
            plan["security_scope"] == assignment["security_scope"] and
            plan["execution_mode"] == assignment["execution_mode"] and
            plan["source_hashes"] == {source_id: assignment["source_hash"]} and
            plan["source_epochs"] == {source_id: assignment["source_epoch"]},
            "DOMAIN_PLAN_BINDING", "plan differs from reviewed assignment")
    require(assignment["effective_graph_version"] == plan["graph_version"] + 1,
            "DOMAIN_EFFECTIVE_VERSION", "assignment must take effect at this commit")
    require(_stamp(plan["created_at"]) >= _stamp(assignment["reviewed_at"]),
            "DOMAIN_PLAN_TIME", "plan predates review")


def authorization_payload(catalog: Catalog, plan_id: str) -> dict[str, Any]:
    """An exact signing payload, never a self-issued authorization."""
    plan = catalog.get(plan_id, "classification-plan")
    return {"plan_id": plan_id, "plan_hash": catalog.hash(plan_id),
            "operation": plan["action"], "security_scope": plan["security_scope"],
            "execution_mode": plan["execution_mode"], "risk_class": "R2",
            "authorization_granted": True}


def preflight_payload(catalog: Catalog, plan_id: str) -> dict[str, Any]:
    plan = catalog.get(plan_id, "classification-plan")
    return {"plan_id": plan_id, "plan_hash": catalog.hash(plan_id),
            "security_scope": plan["security_scope"], "execution_mode": plan["execution_mode"],
            "graph_version": plan["graph_version"], "base_state_hash": plan["base_state_hash"],
            "source_epochs": deepcopy(plan["source_epochs"]),
            "checks": {check: True for check in sorted(CHECKS)}}


def _receipt(trust: TrustStore, receipt: dict[str, Any], purpose: str,
             payload: dict[str, Any], capability: str, *, at: str) -> None:
    issuer = trust.verify(receipt, purpose, at=at)
    require(receipt["payload"] == payload and capability in issuer.operations and
            issuer.maximum_risk >= 2, "DOMAIN_PUBLICATION_AUTHORITY",
            "exact signed payload and enrolled capability are required")


def _transition(catalog: Catalog, plan: dict[str, Any], state: dict[str, Any],
                statuses: dict[str, Any], *, trust: TrustStore, at: str,
                sandbox: bool) -> dict[str, Any]:
    """Pure semantic replay, shared by commit validation and historical audit."""
    require(plan["execution_mode"] != "SYNTHETIC" or sandbox,
            "SYNTHETIC_PUBLICATION_FORBIDDEN", "synthetic plans require a sandbox")
    require(state["graph_version"] == plan["graph_version"] and
            digest(state) == plan["base_state_hash"],
            "STALE_GRAPH_VERSION", "graph version or complete state hash differs")
    require(_stamp(plan["created_at"]) <= _stamp(at), "DOMAIN_PLAN_TIME", "future plan")
    out = deepcopy(state)
    if plan["action"] == MIGRATE:
        require(PROJECTION_KEY not in state, "DOMAIN_ALREADY_MIGRATED",
                "migration cannot reset or replace a projection")
        out[PROJECTION_KEY] = {"contract_version": VERSION, "revision": 1, "assignments": {}}
        return out
    require(PROJECTION_KEY in state, "DOMAIN_MIGRATION_REQUIRED", "explicit append-only migration required")
    assignment_record = catalog.record(plan["assignment_id"], "classification-assignment")
    validate_assignment(catalog, assignment_record, trust=trust, at=at)
    assignment = assignment_record["body"]
    source_id = assignment["source_snapshot_id"]
    status = statuses.get(source_id)
    require(status is not None and status["active"] and status["permission"] == "READ" and
            not status["tombstone"], "STALE_EVIDENCE", "source is not currently readable")
    require(status["epoch"] == plan["source_epochs"][source_id],
            "STALE_SOURCE_EPOCH", "source changed after review")
    projection = out[PROJECTION_KEY]
    require(projection["contract_version"] == VERSION, "DOMAIN_PROJECTION_VERSION", "unsupported projection")
    prior = projection["assignments"].get(source_id)
    require((None if prior is None else prior["assignment_id"]) == assignment["supersedes"] and
            (None if prior is None else prior["assignment_hash"]) == assignment["supersedes_hash"],
            "DOMAIN_COMMITTED_PREDECESSOR", "predecessor is not the committed assignment")
    projection["assignments"][source_id] = {
        "assignment_id": plan["assignment_id"], "assignment_hash": plan["assignment_hash"]}
    projection["revision"] += 1
    return out


class ClassificationPublisher:
    """Privileged reference-only service; never constructed from query/model input.

    The whole-graph migration capability is a deployment/migration authority, not
    a per-source review permission. A security scope is pinned by the application.
    Enabling this service does not qualify the backend for production.
    """
    def __init__(self, backend: SQLiteReferenceBackend, trust: TrustStore, validator_signer: Signer,
                 *, security_scope: str, execution_mode: str,
                 publication_enabled: bool = False):
        require(type(publication_enabled) is bool and bool(security_scope) and
                execution_mode in {"SYNTHETIC", "RECORDED", "LIVE"},
                "DOMAIN_SERVICE_CONFIG", "explicit application configuration required")
        # Pinned legacy/native adapters must implement their own authority binding.
        # A subclass or lookalike cannot silently gain the SQLite sidecar path.
        require(type(backend).__name__ == "SQLiteReferenceBackend" and
                type(backend).__module__ == "trace_gc.backend",
                "DOMAIN_BACKEND_UNQUALIFIED", "only the reference backend is supported")
        self.backend, self.trust, self.signer = backend, trust, validator_signer
        self.scope, self.mode, self.enabled = security_scope, execution_mode, publication_enabled

    @contextmanager
    def _read(self):
        with self.backend._lock:
            own = not self.backend.db.in_transaction
            if own:
                self.backend.db.execute("BEGIN")
            try:
                yield
                if own:
                    self.backend.db.execute("COMMIT")
            except BaseException:
                if own and self.backend.db.in_transaction:
                    self.backend.db.execute("ROLLBACK")
                raise

    def _config(self, plan: dict[str, Any]) -> None:
        require(self.enabled, "ANALYSIS_ONLY", "domain publication is disabled")
        require(plan["security_scope"] == self.scope and plan["execution_mode"] == self.mode,
                "DOMAIN_SERVICE_SCOPE", "plan differs from application scope/mode")
        require(self.mode != "SYNTHETIC" or self.backend.sandbox,
                "SYNTHETIC_PUBLICATION_FORBIDDEN", "synthetic plans require a sandbox")

    @boundary
    def plan(self, catalog: Catalog, *, assignment_id: str | None,
             key: str, run_id: str, created_at: str | None = None) -> str:
        """Create a proposal for a transaction; no graph mutation or permission grant."""
        when = created_at or now()
        with self._read():
            self.audit()
            state = self.backend.state()
            assignment = None if assignment_id is None else catalog.get(assignment_id, "classification-assignment")
            body = {"contract_version": VERSION, "action": MIGRATE if assignment is None else PUBLISH,
                    "run_id": run_id, "graph_version": state["graph_version"], "base_state_hash": digest(state),
                    "idempotency_key": key, "security_scope": self.scope, "execution_mode": self.mode,
                    "assignment_id": assignment_id,
                    "assignment_hash": None if assignment is None else catalog.hash(assignment_id),
                    "taxonomy_id": None if assignment is None else assignment["taxonomy_id"],
                    "taxonomy_hash": None if assignment is None else assignment["taxonomy_hash"],
                    "source_hashes": {} if assignment is None else {assignment["source_snapshot_id"]: assignment["source_hash"]},
                    "source_epochs": {} if assignment is None else {assignment["source_snapshot_id"]: assignment["source_epoch"]},
                    "created_at": when}
            return catalog.put("classification-plan", body)

    def _check(self, catalog: Catalog, plan_id: str, state: dict[str, Any],
               statuses: dict[str, Any], *, at: str) -> dict[str, Any]:
        plan = catalog.get(plan_id, "classification-plan")
        validate_plan_record(catalog, catalog.record(plan_id))
        self._config(plan)
        for source_id, expected_hash in plan["source_hashes"].items():
            row = self.backend.db.execute("SELECT hash,kind,body FROM trace_records WHERE id=?", (source_id,)).fetchone()
            require(row is not None and row[0] == expected_hash and row[1] == "source" and
                    digest({"kind": "source", "body": loads(row[2])}) == expected_hash,
                    "DOMAIN_SOURCE_AUTHORITY", "source must be admitted with these exact bytes")
        return _transition(catalog, plan, state, statuses, trust=self.trust, at=at, sandbox=self.backend.sandbox)

    @boundary
    def preflight(self, catalog: Catalog, plan_id: str, *, at: str | None = None) -> dict[str, Any]:
        when = at or now()
        with self._read():
            self.audit()
            self._check(catalog, plan_id, self.backend.state(), self.backend.statuses(), at=when)
            receipt = self.signer.issue(PREFLIGHT, preflight_payload(catalog, plan_id), issued_at=when)
            _receipt(self.trust, receipt, PREFLIGHT, preflight_payload(catalog, plan_id),
                     VALIDATE_CAPABILITY, at=when)
            return receipt

    @boundary
    def publish(self, catalog: Catalog, plan_id: str, *, authorization: dict[str, Any],
                preflight: dict[str, Any], at: str | None = None,
                fault: Callable[[str], None] | None = None) -> dict[str, Any]:
        from .catalog import Catalog
        from .ledger import build_ledger
        when = at or now()
        frozen = Catalog(catalog.all())
        authorization, preflight = deepcopy(authorization), deepcopy(preflight)
        plan = frozen.get(plan_id, "classification-plan")
        validate_plan_record(frozen, frozen.record(plan_id))
        self._config(plan)

        def verify(instant):
            _receipt(self.trust, authorization, AUTHORIZATION, authorization_payload(frozen, plan_id),
                     plan["action"], at=instant)
            _receipt(self.trust, preflight, PREFLIGHT, preflight_payload(frozen, plan_id),
                     VALIDATE_CAPABILITY, at=instant)
            require(_stamp(plan["created_at"]) <= _stamp(preflight["issued_at"]) <= _stamp(authorization["issued_at"]),
                    "DOMAIN_PUBLICATION_TIME", "preflight/authorization predates its input")

        # The existing transaction primitive returns retries before invoking apply.
        # Authenticate a retry before returning even an already-committed receipt.
        verify(when)
        frozen.put("receipt", authorization)
        frozen.put("receipt", preflight)
        lineage = build_ledger(frozen, run_id=plan["run_id"], execution_mode=plan["execution_mode"], created_at=when)
        operation = {"action": plan["action"], "plan_id": plan_id, "plan_hash": frozen.hash(plan_id)}

        def apply(state, statuses):
            # Default-clock checks must be fresh after waiting for the database
            # lock. Explicit `at` is only for application-owned recorded/tests.
            instant = at or now()
            verify(instant)
            self.audit()
            return self._check(frozen, plan_id, state, statuses, at=instant)

        result = self.backend._transaction(
            key=plan["idempotency_key"], fingerprint=digest(operation), expected_version=plan["graph_version"],
            operation=operation, catalog=frozen, apply=apply,
            authorization_hash=digest(authorization), preflight_hash=digest(preflight),
            upstream_head=lineage[-1]["hash"] if lineage else None, lineage_prefix=lineage,
            at=at, fault=fault)
        # Only after a successful commit; rollback leaves the caller catalog intact.
        if not result["replayed"]:
            for record in frozen.all():
                catalog.add(record)
        # A publisher is not a content reader: do not expose historical
        # assertions/source state through an idempotent retry response.
        return {"replayed": result["replayed"], "receipt": result["receipt"]}

    @boundary
    def audit(self) -> dict[str, Any]:
        """Administrative semantic audit, not an authorized content-retrieval API.

        Review and publication signatures are checked at each commit instant with
        the application-enrolled trust store. Missing erased content fails closed.
        No live backend, pinned-legacy, or operational gate is implied.
        """
        with self._read():
            report = self.backend.audit()
            catalog = self.backend.load_catalog()
            meta = loads(self.backend.db.execute("SELECT body FROM trace_meta WHERE id=1").fetchone()[0])
            before, statuses = meta["genesis_state"], {}
            require(PROJECTION_KEY not in before, "DOMAIN_AUDIT", "domains may not rewrite old genesis")
            receipts = {digest(r["body"]): r["body"] for r in catalog.all("receipt")}
            domain_events = 0
            for (body,) in self.backend.db.execute("SELECT body FROM trace_journal ORDER BY version"):
                event = loads(body)
                operation = event["operation"]
                if operation["action"] in {MIGRATE, PUBLISH}:
                    plan_id = operation["plan_id"]
                    plan_record = catalog.record(plan_id, "classification-plan")
                    validate_plan_record(catalog, plan_record)
                    plan = plan_record["body"]
                    require(operation == {"action": plan["action"], "plan_id": plan_id, "plan_hash": plan_record["hash"]} and
                            event["idempotency_key"] == plan["idempotency_key"] and
                            event["fingerprint"] == digest(operation), "DOMAIN_AUDIT", "operation/plan differs")
                    when = event["committed_at"]
                    auth = receipts.get(event["authorization_hash"])
                    preflight = receipts.get(event["preflight_hash"])
                    require(auth is not None and preflight is not None, "DOMAIN_AUDIT", "signed receipts missing")
                    _receipt(self.trust, auth, AUTHORIZATION, authorization_payload(catalog, plan_id), plan["action"], at=when)
                    _receipt(self.trust, preflight, PREFLIGHT, preflight_payload(catalog, plan_id), VALIDATE_CAPABILITY, at=when)
                    require(_stamp(plan["created_at"]) <= _stamp(preflight["issued_at"]) <= _stamp(auth["issued_at"]),
                            "DOMAIN_PUBLICATION_TIME", "publication chronology differs")
                    expected = _transition(catalog, plan, before, statuses, trust=self.trust, at=when, sandbox=self.backend.sandbox)
                    expected["graph_version"] += 1
                    expected["source_epochs"] = {ref: status["epoch"] for ref, status in statuses.items()}
                    require(expected == event["state_after"] and statuses == event["source_status"],
                            "DOMAIN_AUDIT", "domain transaction changed unrelated graph or source state")
                    domain_events += 1
                else:
                    require(before.get(PROJECTION_KEY) == event["state_after"].get(PROJECTION_KEY),
                            "DOMAIN_AUDIT", "non-domain transaction changed classification projection")
                before, statuses = event["state_after"], event["source_status"]
            return {**report, "classification_events": domain_events,
                    "classification_revision": before.get(PROJECTION_KEY, {}).get("revision", 0)}


@boundary
def validate_record(catalog: Catalog, record: dict[str, Any], *,
                    trust: TrustStore | None = None, at: str | None = None) -> None:
    kind, body = record["kind"], record["body"]
    if kind == "classification-plan":
        validate_plan_record(catalog, record)
    elif kind == "receipt" and body["purpose"] in {PREFLIGHT, AUTHORIZATION}:
        plan_id = body["payload"]["plan_id"]
        plan = catalog.get(plan_id, "classification-plan")
        expected = preflight_payload(catalog, plan_id) if body["purpose"] == PREFLIGHT else authorization_payload(catalog, plan_id)
        require(body["payload"] == expected, "DOMAIN_PUBLICATION_BINDING", "receipt differs from plan")
        require(_stamp(plan["created_at"]) <= _stamp(body["issued_at"]),
                "DOMAIN_PUBLICATION_TIME", "receipt predates plan")
        if trust is not None:
            capability = VALIDATE_CAPABILITY if body["purpose"] == PREFLIGHT else plan["action"]
            _receipt(trust, body, body["purpose"], expected, capability, at=at or now())
    elif kind == "graph-snapshot" and PROJECTION_KEY in body:
        for source_id, entry in body[PROJECTION_KEY]["assignments"].items():
            assignment = catalog.get(entry["assignment_id"], "classification-assignment")
            require(entry["assignment_hash"] == catalog.hash(entry["assignment_id"]) and
                    source_id == assignment["source_snapshot_id"] and source_id in body["source_epochs"] and
                    assignment["effective_graph_version"] <= body["graph_version"],
                    "DOMAIN_SNAPSHOT_BINDING", "projection does not match the exact assignment/version")


def validate_catalog(catalog: Catalog, *, trust: TrustStore | None = None,
                     at: str | None = None) -> None:
    for record in catalog.all():
        validate_record(catalog, record, trust=trust, at=at)


def hydrate_projection(catalog: Catalog, state: dict[str, Any], persisted: Catalog) -> None:
    """Load the selected assignments' immutable closure for an admin snapshot.

    Caller catalogs cannot substitute source/assignment bytes. This does not
    provide ACL-filtered graph retrieval; GraphReadView integration is separate.
    """
    from .ledger import references as record_references
    from .references import topological_order
    records, deps = {}, {}
    pending = [entry["assignment_id"] for entry in state[PROJECTION_KEY]["assignments"].values()]
    while pending:
        ref = pending.pop()
        if ref in records:
            continue
        record = persisted.record(ref)
        records[ref] = record
        deps[ref] = {target for target, _ in record_references(record)}
        pending.extend(deps[ref] - records.keys())
    for ref in topological_order(deps):
        catalog.add(records[ref])
