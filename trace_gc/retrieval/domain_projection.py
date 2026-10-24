"""Journal-bound topical membership and a disposable same-database read index.

All interfaces here are privileged adapter internals. Labels never authorize a
read. A query cannot supply these values. Index repair changes derived tables
only; no accepted graph, genesis, receipt, source, or evidence is rewritten.
"""
from __future__ import annotations

from copy import deepcopy
import sqlite3
from typing import Any

from ..canonical import digest, loads
from ..catalog import Catalog
from ..domain_publication import (AUTHORIZATION, PREFLIGHT, MIGRATE, PUBLISH,
    PROJECTION_KEY, VALIDATE_CAPABILITY, _receipt, _transition,
    authorization_payload, preflight_payload, validate_plan_record)
from ..domains import _stamp
from ..errors import require

VERSION = "trace-domain-read-v1"
SNAPSHOT_FIELDS = ("graph_version", "schema_id", "schema_hash", "nodes", "assertions", "source_epochs")
COLUMNS = ("graph_version", "source_id", "assignment_id", "assignment_hash",
           "taxonomy_id", "taxonomy_hash", "taxonomy_version", "assignment_revision", "state", "domain_id")


def snapshot_body(state: dict[str, Any]) -> dict[str, Any]:
    body = {k: deepcopy(state[k]) for k in SNAPSHOT_FIELDS}
    if PROJECTION_KEY in state:
        body[PROJECTION_KEY] = deepcopy(state[PROJECTION_KEY])
    return body


def projection(catalog: Catalog, snapshot: dict[str, Any]) -> dict[str, Any]:
    """Reconstruct classification identity without claiming source access."""
    from ..domain_publication import validate_record
    record = {"kind": "graph-snapshot", "body": snapshot}
    validate_record(catalog, record)
    committed = snapshot.get(PROJECTION_KEY)
    entries = {} if committed is None else committed["assignments"]
    result = {}
    taxonomies = {}
    for source in sorted(snapshot["source_epochs"]):
        entry = entries.get(source)
        if entry is None:
            result[source] = {"assignment_id": None, "assignment_hash": None,
                "taxonomy_id": None, "taxonomy_hash": None, "taxonomy_version": None,
                "assignment_revision": 0, "state": "UNCLASSIFIED", "domain_ids": []}
            continue
        a = catalog.get(entry["assignment_id"], "classification-assignment")
        result[source] = {**entry, "taxonomy_id": a["taxonomy_id"], "taxonomy_hash": a["taxonomy_hash"],
            "taxonomy_version": a["taxonomy_version"], "assignment_revision": a["revision"],
            "state": a["state"], "domain_ids": list(a["domain_ids"])}
        taxonomies[a["taxonomy_id"]] = {"hash": a["taxonomy_hash"], "version": a["taxonomy_version"]}
    return {"contract_version": VERSION, "graph_version": snapshot["graph_version"],
            "classification_revision": 0 if committed is None else committed["revision"],
            "projection_hash": digest(committed), "taxonomy_revisions": taxonomies,
            "source_assignments": result}


def verify_history(catalog: Catalog, genesis: dict[str, Any], events: list[dict[str, Any]],
                   *, trust, sandbox: bool) -> dict[int, dict[str, Any]]:
    """Replay classification transitions at their commit time with current trust.

    Revoked issuer keys fail closed even for older versions. Old review expiry
    does not retroactively invalidate a commit: signatures are checked at that
    commit instant. This does not replace source status or ACL checks at read.
    """
    from ..ledger import build_ledger
    require(trust is not None, "DOMAIN_TRUST_REQUIRED", "application trust required for domain history")
    require(genesis["graph_version"] == 0 and PROJECTION_KEY not in genesis,
            "DOMAIN_HISTORY", "original pre-classification genesis required")
    states = {0: deepcopy(genesis)}
    before, statuses, previous = deepcopy(genesis), {}, None
    receipts = {digest(r["body"]): r["body"] for r in catalog.all("receipt")}
    for v, event in enumerate(events, 1):
        core = {k: b for k, b in event.items() if k not in {"hash", "transaction_receipt"}}
        require(event["version"] == v and event["previous_hash"] == previous and
                event["before_hash"] == digest(before) and event["hash"] == digest(core) and
                event["after_hash"] == digest(event["state_after"]) and
                event["state_after"]["graph_version"] == v,
                "DOMAIN_HISTORY", "journal chain/state identity differs")
        for ref, expected in event["record_hashes"].items():
            require(catalog.hash(ref) == expected, "DOMAIN_HISTORY", "journaled record differs")
        op = event["operation"]
        if op.get("action") in {MIGRATE, PUBLISH}:
            r = catalog.record(op["plan_id"], "classification-plan")
            validate_plan_record(catalog, r)
            p, when = r["body"], event["committed_at"]
            require(op == {"action": p["action"], "plan_id": r["id"], "plan_hash": r["hash"]} and
                    event["idempotency_key"] == p["idempotency_key"] and event["fingerprint"] == digest(op),
                    "DOMAIN_HISTORY", "classification operation differs from signed plan")
            auth, preflight = receipts.get(event["authorization_hash"]), receipts.get(event["preflight_hash"])
            require(auth is not None and preflight is not None, "DOMAIN_HISTORY", "publication receipts missing")
            _receipt(trust, auth, AUTHORIZATION, authorization_payload(catalog, r["id"]), p["action"], at=when)
            _receipt(trust, preflight, PREFLIGHT, preflight_payload(catalog, r["id"]), VALIDATE_CAPABILITY, at=when)
            require(_stamp(p["created_at"]) <= _stamp(preflight["issued_at"]) <= _stamp(auth["issued_at"]),
                    "DOMAIN_PUBLICATION_TIME", "classification chronology differs")
            expected = _transition(catalog, p, before, statuses, trust=trust, at=when, sandbox=sandbox)
            expected["graph_version"] += 1
            expected["source_epochs"] = {ref: s["epoch"] for ref, s in statuses.items()}
            require(expected == event["state_after"] and statuses == event["source_status"],
                    "DOMAIN_HISTORY", "classification changed unrelated authority")
            prefix = event.get("lineage_prefix", [])
            require(bool(prefix) and prefix[-1]["hash"] == event["upstream_head"] and
                    r["id"] in {ref for e in prefix for ref in e["record_ids"]},
                    "DOMAIN_HISTORY", "missing publication lineage")
            refs = {ref for e in prefix for ref in e["record_ids"]}
            bound = Catalog(catalog.record(ref) for ref in refs)
            require(build_ledger(bound, run_id=p["run_id"], execution_mode=p["execution_mode"], prefix=prefix) == prefix,
                    "DOMAIN_HISTORY", "publication lineage differs")
        else:
            require(before.get(PROJECTION_KEY) == event["state_after"].get(PROJECTION_KEY),
                    "DOMAIN_HISTORY", "unrelated transaction changed domain membership")
        tx = event["transaction_receipt"]
        require(tx["event_hash"] == event["hash"] and tx["version"] == v and
                tx["before_hash"] == event["before_hash"] and tx["after_hash"] == event["after_hash"] and
                tx["operation_hash"] == digest(op) and tx["authorization_hash"] == event["authorization_hash"] and
                tx["preflight_hash"] == event["preflight_hash"] and tx["upstream_head"] == event["upstream_head"],
                "DOMAIN_HISTORY", "transaction receipt differs")
        before, statuses, previous = event["state_after"], event["source_status"], event["hash"]
        states[v] = deepcopy(before)
    return states


def index_rows(catalog: Catalog, state: dict[str, Any]) -> list[tuple]:
    p = projection(catalog, snapshot_body(state))
    return sorted((state["graph_version"], source, a["assignment_id"] or "", a["assignment_hash"] or "",
                   a["taxonomy_id"] or "", a["taxonomy_hash"] or "", a["taxonomy_version"] or "",
                   a["assignment_revision"], a["state"], domain)
                  for source, a in p["source_assignments"].items() for domain in (a["domain_ids"] or [""]))


def rebuild_index(backend, *, trust) -> dict[str, Any]:
    """Explicit administrative repair. Authoritative rows are never changed."""
    with backend._lock:
        require(not backend.db.in_transaction, "DOMAIN_INDEX_TRANSACTION", "repair needs its own transaction")
        backend.db.execute("BEGIN IMMEDIATE")
        try:
            authority = backend.audit()
            c = backend.load_catalog()
            genesis = loads(backend.db.execute("SELECT body FROM trace_meta WHERE id=1").fetchone()[0])["genesis_state"]
            events = [loads(r[0]) for r in backend.db.execute("SELECT body FROM trace_journal ORDER BY version")]
            states = verify_history(c, genesis, events, trust=trust, sandbox=backend.sandbox)
            backend.db.execute("""CREATE TABLE IF NOT EXISTS trace_domain_index (
                graph_version INTEGER NOT NULL, source_id TEXT NOT NULL,
                assignment_id TEXT NOT NULL, assignment_hash TEXT NOT NULL,
                taxonomy_id TEXT NOT NULL, taxonomy_hash TEXT NOT NULL, taxonomy_version TEXT NOT NULL,
                assignment_revision INTEGER NOT NULL, state TEXT NOT NULL, domain_id TEXT NOT NULL,
                PRIMARY KEY (graph_version, source_id, domain_id))""")
            backend.db.execute("CREATE INDEX IF NOT EXISTS trace_domain_lookup ON trace_domain_index(graph_version, domain_id, source_id)")
            backend.db.execute("CREATE TABLE IF NOT EXISTS trace_domain_index_heads(graph_version INTEGER PRIMARY KEY, rows_hash TEXT NOT NULL, state_hash TEXT NOT NULL)")
            backend.db.execute("DELETE FROM trace_domain_index")
            backend.db.execute("DELETE FROM trace_domain_index_heads")
            count = 0
            for version, state in states.items():
                rows = index_rows(c, state)
                backend.db.executemany("INSERT INTO trace_domain_index VALUES(?,?,?,?,?,?,?,?,?,?)", rows)
                backend.db.execute("INSERT INTO trace_domain_index_heads VALUES(?,?,?)",
                    (version, digest([list(row) for row in rows]), digest(state)))
                count += len(rows)
            require(backend.audit() == authority, "DOMAIN_INDEX_AUTHORITY", "repair changed authority")
            backend.db.execute("COMMIT")
            return {"status": "REBUILT", "versions": len(states), "rows": count,
                    "authority_changed": False, "authority_head": authority["head_hash"]}
        except BaseException:
            if backend.db.in_transaction:
                backend.db.execute("ROLLBACK")
            raise


def verified_index(backend, catalog: Catalog, state: dict[str, Any]) -> dict[str, list[str]]:
    version = state["graph_version"]
    try:
        header = backend.db.execute("SELECT rows_hash,state_hash FROM trace_domain_index_heads WHERE graph_version=?", (version,)).fetchone()
        rows = backend.db.execute("SELECT " + ",".join(COLUMNS) +
            " FROM trace_domain_index WHERE graph_version=? ORDER BY graph_version,source_id,domain_id", (version,)).fetchall()
    except sqlite3.OperationalError as exc:
        require(False, "DOMAIN_INDEX_UNAVAILABLE", "explicit index rebuild required")
    expected = index_rows(catalog, state)
    require(header is not None and header == (digest([list(r) for r in expected]), digest(state)) and rows == expected,
            "DOMAIN_INDEX_STALE", "derived index differs from journal; explicit rebuild required")
    result: dict[str, list[str]] = {}
    for row in rows:
        if row[-1]:
            result.setdefault(row[-1], []).append(row[1])
    return result


def update_installed_index(backend, state: dict[str, Any]) -> None:
    """Maintain an already-built projection inside its owning write transaction."""
    require(backend.db.in_transaction, "DOMAIN_INDEX_TRANSACTION", "atomic write transaction required")
    if backend.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='trace_domain_index'").fetchone() is None:
        return
    rows = index_rows(backend.load_catalog(), state)
    # A graph version is immutable. A collision is corruption, never an upsert.
    backend.db.executemany("INSERT INTO trace_domain_index VALUES(?,?,?,?,?,?,?,?,?,?)", rows)
    backend.db.execute("INSERT INTO trace_domain_index_heads VALUES(?,?,?)",
        (state["graph_version"], digest([list(row) for row in rows]), digest(state)))
