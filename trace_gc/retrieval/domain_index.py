"""Rebuildable topical index over the authenticated graph journal.

Index maintenance changes derived tables only. It never publishes a classification,
changes a source permission, or becomes a second accepted graph. Readers fail closed
on stale/missing/tampered index rows; an application explicitly requests rebuild.
"""
from __future__ import annotations
from copy import deepcopy
from typing import Any, Callable
from ..canonical import digest, dumps, loads
from ..domain_publication import (
    MIGRATE, PUBLISH, PROJECTION_KEY, _transition, validate_published_transaction,
)
from ..errors import boundary, require

VERSION = "trace-domain-index-v1"
COLUMNS = ("effective_version", "source_id", "assignment_id", "assignment_hash",
           "taxonomy_id", "taxonomy_hash", "assignment_state", "assignment_revision", "domain_id")


def _rows(catalog, assignment_id):
    body = catalog.get(assignment_id, "classification-assignment")
    common = (body["effective_graph_version"], body["source_snapshot_id"], assignment_id,
              catalog.hash(assignment_id), body["taxonomy_id"], body["taxonomy_hash"],
              body["state"], body["revision"])
    # The empty marker denotes an explicitly unclassified/retired assignment,
    # never a taxonomy ID, wildcard permission, or omitted source.
    return [(*common, label) for label in body["domain_ids"] or [""]]


@boundary
def validate_history(catalog, events: list[dict[str, Any]], genesis: dict[str, Any], trust, *, sandbox: bool):
    """Replay domain transitions using the same checks as the publication boundary."""
    require(trust is not None and genesis is not None, "DOMAIN_TRUST_REQUIRED",
            "application trust and exact genesis are required for domain history")
    require(PROJECTION_KEY not in genesis and genesis["graph_version"] == 0,
            "DOMAIN_AUDIT", "classification cannot be backfilled into genesis")
    before, statuses, previous, rows = deepcopy(genesis), {}, None, []
    for version, event in enumerate(events, 1):
        core = {k: v for k, v in event.items() if k not in {"hash", "transaction_receipt"}}
        require(event["version"] == version and event["previous_hash"] == previous and
                event["before_hash"] == digest(before) and digest(core) == event["hash"] and
                event["state_after"]["graph_version"] == version and
                digest(event["state_after"]) == event["after_hash"],
                "DOMAIN_AUDIT", "journal sequence, state, or hash differs")
        require(event["state_after"]["source_epochs"] ==
                {ref: status["epoch"] for ref, status in event["source_status"].items()},
                "DOMAIN_AUDIT", "journal source epochs differ")
        operation = event["operation"]
        if operation.get("action") in {MIGRATE, PUBLISH}:
            record = catalog.record(operation["plan_id"], "classification-plan")
            plan = record["body"]
            require(operation == {"action": plan["action"], "plan_id": record["id"], "plan_hash": record["hash"]} and
                    event["fingerprint"] == digest(operation) and
                    event["idempotency_key"] == plan["idempotency_key"],
                    "DOMAIN_AUDIT", "domain event/plan binding differs")
            receipt = event["transaction_receipt"]
            for field in ("version", "idempotency_key", "before_hash", "after_hash", "previous_hash",
                          "authorization_hash", "preflight_hash", "upstream_head", "committed_at"):
                require(receipt[field] == event[field], "DOMAIN_AUDIT", "journal receipt differs")
            require(receipt["event_hash"] == event["hash"], "DOMAIN_AUDIT", "receipt event hash differs")
            validate_published_transaction(catalog, receipt, record, trust=trust)
            # Exact signed plan and all referenced immutable bytes must have been
            # present at this event, not injected later into a working catalog.
            from ..ledger import causal_references
            pending, seen = [record["id"]], set()
            receipts = {digest(r["body"]): r["id"] for r in catalog.all("receipt")}
            pending.extend(receipts[h] for h in (event["authorization_hash"], event["preflight_hash"]))
            while pending:
                ref = pending.pop()
                if ref in seen:
                    continue
                seen.add(ref)
                require(event["record_hashes"].get(ref) == catalog.hash(ref),
                        "DOMAIN_AUDIT", "classification dependency was not committed with the plan")
                pending.extend(causal_references(catalog.record(ref), catalog) - seen)
            expected = _transition(catalog, plan, before, statuses, trust=trust,
                                   at=event["committed_at"], sandbox=sandbox)
            expected["graph_version"] += 1
            expected["source_epochs"] = {ref: status["epoch"] for ref, status in statuses.items()}
            require(expected == event["state_after"] and statuses == event["source_status"],
                    "DOMAIN_AUDIT", "domain publication changed unrelated state")
            if plan["assignment_id"] is not None:
                rows.extend(_rows(catalog, plan["assignment_id"]))
        else:
            require(before.get(PROJECTION_KEY) == event["state_after"].get(PROJECTION_KEY),
                    "DOMAIN_AUDIT", "non-domain event changed classification")
        before, statuses, previous = event["state_after"], event["source_status"], event["hash"]
    return {"projection": deepcopy(before.get(PROJECTION_KEY)), "rows": sorted(rows),
            "graph_version": before["graph_version"], "head_hash": previous,
            "source_status": deepcopy(statuses)}


def selected_rows(rows, graph_version):
    latest = {}
    for row in rows:
        if row[0] <= graph_version:
            latest[row[1]] = max(latest.get(row[1], -1), row[0])
    return [row for row in rows if row[0] == latest.get(row[1])]


def metadata(history):
    return {"version": VERSION, "graph_version": history["graph_version"],
            "authority_head": history["head_hash"],
            "rows_hash": digest([list(row) for row in history["rows"]])}


def _inputs(backend, trust):
    backend.audit()
    catalog = backend.load_catalog()
    events = [loads(row[0]) for row in backend.db.execute("SELECT body FROM trace_journal ORDER BY version")]
    genesis = loads(backend.db.execute("SELECT body FROM trace_meta WHERE id=1").fetchone()[0])["genesis_state"]
    return catalog, events, genesis, validate_history(catalog, events, genesis, trust, sandbox=backend.sandbox)


@boundary
def rebuild(backend, trust, *, fault: Callable[[str], None] | None = None):
    """Explicit administrative rebuild in the existing database, never a new authority."""
    with backend._lock:
        require(not backend.db.in_transaction, "DOMAIN_INDEX_TRANSACTION", "rebuild needs its own transaction")
        backend.db.execute("BEGIN IMMEDIATE")
        try:
            _, _, _, history = _inputs(backend, trust)
            db = backend.db
            db.execute("""CREATE TABLE IF NOT EXISTS trace_domain_index(
                effective_version INTEGER NOT NULL, source_id TEXT NOT NULL,
                assignment_id TEXT NOT NULL, assignment_hash TEXT NOT NULL,
                taxonomy_id TEXT NOT NULL, taxonomy_hash TEXT NOT NULL,
                assignment_state TEXT NOT NULL, assignment_revision INTEGER NOT NULL,
                domain_id TEXT NOT NULL, PRIMARY KEY(source_id,effective_version,domain_id))""")
            db.execute("CREATE INDEX IF NOT EXISTS trace_domain_lookup ON trace_domain_index(taxonomy_id,domain_id,effective_version,source_id)")
            db.execute("CREATE TABLE IF NOT EXISTS trace_domain_index_meta(id INTEGER PRIMARY KEY CHECK(id=1),body TEXT NOT NULL)")
            db.execute("DELETE FROM trace_domain_index")
            if fault:
                fault("after_index_delete")
            db.executemany("INSERT INTO trace_domain_index VALUES(?,?,?,?,?,?,?,?,?)", history["rows"])
            if fault:
                fault("after_index_rows")
            value = metadata(history)
            db.execute("INSERT OR REPLACE INTO trace_domain_index_meta VALUES(1,?)", (dumps(value),))
            if fault:
                fault("before_index_commit")
            db.execute("COMMIT")
            return {"status": "REBUILT", "row_count": len(history["rows"]), **value,
                    "authorization_granted": False, "graph_commits": 0}
        except BaseException:
            if backend.db.in_transaction:
                backend.db.execute("ROLLBACK")
            raise


@boundary
def verify(backend, history):
    """Caller holds a consistent authority/index read transaction."""
    tables = {row[0] for row in backend.db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    require({"trace_domain_index", "trace_domain_index_meta"} <= tables, "DOMAIN_INDEX_STALE", "rebuild the missing derived index")
    row = backend.db.execute("SELECT body FROM trace_domain_index_meta WHERE id=1").fetchone()
    require(row is not None and loads(row[0]) == metadata(history),
            "DOMAIN_INDEX_STALE", "index is not anchored to the current journal head")
    columns = ",".join(COLUMNS)
    actual = sorted(backend.db.execute("SELECT " + columns + " FROM trace_domain_index").fetchall())
    require(actual == history["rows"], "DOMAIN_INDEX_STALE", "derived rows differ from committed assignments")


def read_rows(backend, graph_version):
    columns = ",".join("i." + name for name in COLUMNS)
    return sorted(backend.db.execute("SELECT " + columns + " FROM trace_domain_index i "
        "WHERE i.effective_version <= ? AND i.effective_version=(SELECT MAX(j.effective_version) "
        "FROM trace_domain_index j WHERE j.source_id=i.source_id AND j.effective_version<=?)",
        (graph_version, graph_version)).fetchall())


def source_membership(view, source_id, acl):
    """Current ACL/status FIRST, then selected-version topical metadata.

    None is inaccessible/not-yet-admitted, not an empty topical label. Unknown
    membership on an admitted readable source is explicitly UNCLASSIFIED.
    """
    if not acl.source(source_id) or source_id not in view.snapshot["source_epochs"]:
        return None
    projection = view.classification_projection
    entry = (projection or {}).get("assignments", {}).get(source_id)
    if entry is None:
        return {"state": "UNCLASSIFIED", "domain_ids": [], "assignment_id": None,
                "assignment_hash": None, "assignment_revision": 0, "taxonomy_id": None,
                "taxonomy_hash": None, "taxonomy_version": None,
                "projection_hash": view.classification_identity,
                "projection_revision": view.classification_revision}
    assignment = view.catalog.get(entry["assignment_id"], "classification-assignment")
    require(entry["assignment_hash"] == view.catalog.hash(entry["assignment_id"]) and
            assignment["source_snapshot_id"] == source_id and
            assignment["source_hash"] == view.catalog.hash(source_id) and
            assignment["effective_graph_version"] <= view.snapshot["graph_version"],
            "DOMAIN_SNAPSHOT_BINDING", "assignment differs from the selected source snapshot")
    return {"state": assignment["state"], "domain_ids": list(assignment["domain_ids"]),
            "assignment_id": entry["assignment_id"], "assignment_hash": entry["assignment_hash"],
            "assignment_revision": assignment["revision"], "taxonomy_id": assignment["taxonomy_id"],
            "taxonomy_hash": assignment["taxonomy_hash"], "taxonomy_version": assignment["taxonomy_version"],
            "projection_hash": view.classification_identity,
            "projection_revision": view.classification_revision}
