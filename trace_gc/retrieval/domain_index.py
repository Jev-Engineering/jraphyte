"""Rebuildable research-domain index. Its inputs are accepted snapshot records.

This index is an acceleration structure, never an authorization or publication
store. The reference implementation compares its contents against the authority
on every read; it intentionally makes no production-scale performance claim.
"""
from __future__ import annotations

from copy import deepcopy
from time import perf_counter
from typing import Any

from ..canonical import digest, dumps, loads
from ..catalog import Catalog
from ..domain_publication import classification_identity, verify_projection
from ..errors import require

INDEX_VERSION = "trace-domain-index-v1"


def authoritative_rows(catalog: Catalog, snapshot: dict[str, Any]) -> dict[str, dict[str, Any]]:
    projection = verify_projection(catalog, snapshot)
    result = {}
    for source_id in sorted(snapshot["source_epochs"]):
        source = catalog.get(source_id, "source")
        assignment_id = projection["assignments"].get(source_id)
        assignment = catalog.get(assignment_id, "classification-assignment") if assignment_id else None
        result[source_id] = {
            "source_snapshot_id": source_id, "source_hash": catalog.hash(source_id),
            "security_scope": source["security_scope"], "assignment_id": assignment_id,
            "assignment_hash": catalog.hash(assignment_id) if assignment_id else None,
            "effective_revision": assignment["effective_revision"] if assignment else 0,
            "taxonomy_id": assignment["taxonomy_id"] if assignment else None,
            "taxonomy_hash": assignment["taxonomy_hash"] if assignment else None,
            "domain_ids": deepcopy(assignment["domain_ids"]) if assignment else [],
            "status": assignment["status"] if assignment else "UNCLASSIFIED",
            "reason": "ASSIGNED" if assignment else "NO_REVIEWED_ASSIGNMENT",
        }
    return result


class SQLiteClassificationIndex:
    """Index in the same database, independently disposable without losing history.

    Call methods while holding the backend's lock and an existing consistent
    transaction. Empty/new snapshot entries are built from authority. Corrupt
    entries fail closed until an explicit rebuild; no index bytes are promoted.
    """
    def __init__(self, db: Any):
        self.db = db
        self.last_metrics: dict[str, Any] = {}

    def ensure_tables(self) -> None:
        # Individual statements, not executescript (which implicitly commits).
        self.db.execute("CREATE TABLE IF NOT EXISTS trace_domain_index_meta("
                        "snapshot_hash TEXT PRIMARY KEY, version TEXT NOT NULL, projection_hash TEXT NOT NULL, "
                        "rows_hash TEXT NOT NULL, row_count INTEGER NOT NULL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS trace_domain_index_sources("
                        "snapshot_hash TEXT NOT NULL, source_id TEXT NOT NULL, body TEXT NOT NULL, "
                        "PRIMARY KEY(snapshot_hash,source_id))")
        self.db.execute("CREATE TABLE IF NOT EXISTS trace_domain_index_membership("
                        "snapshot_hash TEXT NOT NULL, taxonomy_hash TEXT NOT NULL, domain_id TEXT NOT NULL, "
                        "source_id TEXT NOT NULL, PRIMARY KEY(snapshot_hash,taxonomy_hash,domain_id,source_id))")
        self.db.execute("CREATE INDEX IF NOT EXISTS trace_domain_index_by_source ON "
                        "trace_domain_index_membership(snapshot_hash,source_id)")

    @staticmethod
    def membership(rows: dict[str, dict[str, Any]]) -> list[tuple[str, str, str]]:
        return sorted((row["taxonomy_hash"] or "", domain, source_id)
                      for source_id, row in rows.items() for domain in (row["domain_ids"] or [""]))

    def read(self, catalog: Catalog, snapshot_id: str, *, rebuild: bool = False) -> dict[str, dict[str, Any]]:
        start = perf_counter()
        snapshot = catalog.get(snapshot_id, "graph-snapshot")
        snapshot_hash = catalog.hash(snapshot_id)
        rows = authoritative_rows(catalog, snapshot)
        projection_hash = classification_identity(snapshot)["hash"]
        rows_hash = digest(rows)
        memberships = self.membership(rows)
        expected_meta = (INDEX_VERSION, projection_hash, rows_hash, len(rows))
        existing = self.db.execute("SELECT version,projection_hash,rows_hash,row_count "
                                   "FROM trace_domain_index_meta WHERE snapshot_hash=?", (snapshot_hash,)).fetchone()
        if rebuild:
            for table in ("trace_domain_index_membership", "trace_domain_index_sources", "trace_domain_index_meta"):
                self.db.execute(f"DELETE FROM {table} WHERE snapshot_hash=?", (snapshot_hash,))
            existing = None
        if existing is None:
            orphan_count = sum(self.db.execute(f"SELECT count(*) FROM {table} WHERE snapshot_hash=?", (snapshot_hash,)).fetchone()[0]
                               for table in ("trace_domain_index_sources", "trace_domain_index_membership"))
            require(orphan_count == 0, "DOMAIN_INDEX_CORRUPT", "orphaned index rows; explicitly rebuild from authority")
            self.db.executemany("INSERT INTO trace_domain_index_sources VALUES(?,?,?)",
                                [(snapshot_hash, source_id, dumps(row)) for source_id, row in rows.items()])
            self.db.executemany("INSERT INTO trace_domain_index_membership VALUES(?,?,?,?)",
                                [(snapshot_hash, *member) for member in memberships])
            self.db.execute("INSERT INTO trace_domain_index_meta VALUES(?,?,?,?,?)", (snapshot_hash, *expected_meta))
        else:
            require(existing == expected_meta, "DOMAIN_INDEX_CORRUPT", "index metadata differs from authoritative snapshot")
        actual = {source_id: loads(body) for source_id, body in self.db.execute(
            "SELECT source_id,body FROM trace_domain_index_sources WHERE snapshot_hash=? ORDER BY source_id", (snapshot_hash,))}
        actual_members = list(self.db.execute("SELECT taxonomy_hash,domain_id,source_id FROM trace_domain_index_membership "
                                             "WHERE snapshot_hash=? ORDER BY taxonomy_hash,domain_id,source_id", (snapshot_hash,)))
        require(actual == rows and actual_members == memberships, "DOMAIN_INDEX_CORRUPT", "index rows differ from authority")
        self.last_metrics = {"version": INDEX_VERSION, "source_rows": len(rows), "membership_rows": len(memberships),
                             "logical_bytes": len(dumps(rows).encode("utf-8")), "built": existing is None,
                             "validation_seconds": perf_counter() - start}
        return actual
