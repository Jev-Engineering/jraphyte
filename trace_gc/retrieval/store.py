"""Read adapters over the existing graph authority; algorithms never write it."""
from __future__ import annotations
from contextlib import contextmanager, nullcontext
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable
from ..canonical import digest, loads
from ..catalog import Catalog
from ..compiler import timestamp
from ..errors import require
from ..domain_publication import snapshot_body, classification_identity
from .domain_index import authoritative_rows, SQLiteClassificationIndex

@dataclass
class GraphReadView:
    catalog: Catalog
    snapshot_id: str
    source_status: dict[str, Any]
    available_record_ids: set[str]
    events: list[dict[str, Any]]
    adapter_version: str
    classification_rows: dict[str, dict[str, Any]] | None = None
    read_metrics: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        expected = authoritative_rows(self.catalog, self.snapshot)
        require(self.classification_rows is None or self.classification_rows == expected,
                "DOMAIN_INDEX_CORRUPT", "read projection differs from accepted snapshot")
        self.classification_rows = expected

    @property
    def classification_identity(self) -> dict[str, Any]:
        return classification_identity(self.snapshot)

    def source_classification(self, source_id: str, access: Any) -> dict[str, Any] | None:
        # Authorization and PRESENT source status precede any membership selection.
        if not access.source(source_id):
            return None
        row = self.classification_rows.get(source_id)
        return deepcopy(row) if row is not None else None

    @property
    def snapshot(self) -> dict[str, Any]:
        return self.catalog.get(self.snapshot_id, "graph-snapshot")

    @property
    def identity(self) -> str:
        return digest({"snapshot": self.catalog.hash(self.snapshot_id), "classifications": self.classification_identity, "source_status": self.source_status,
                       "available": sorted(ref for ref in self.available_record_ids
                            if ref in self.catalog and self.catalog.record(ref)["kind"] not in {
                                "retrieval-query", "retrieval-plan", "graph-access", "graph-context", "retrieval-result",
                                "retrieval-expansion", "retrieval-lineage", "graphrag-answer", "retrieval-replay", "retrieval-evaluation"}),
                       "adapter": self.adapter_version})

@runtime_checkable
class GraphQueryAdapter(Protocol):
    version: str
    def read(self, query: dict[str, Any]) -> GraphReadView: ...
    def current_source_status(self) -> dict[str, Any]: ...


class InMemoryGraphAdapter:
    """Immutable-snapshot reference adapter, useful for tests and custom stores."""
    version = "memory-snapshot-domain-v1"

    def __init__(self, catalog: Catalog, snapshot_ids: list[str], source_status: dict[str, Any],
                 events: list[dict[str, Any]] | None = None):
        self.catalog, self.snapshot_ids, self.source_status = catalog, list(snapshot_ids), deepcopy(source_status)
        self.events = deepcopy(events or [])

    def current_source_status(self) -> dict[str, Any]:
        return deepcopy(self.source_status)

    def read(self, query: dict[str, Any]) -> GraphReadView:
        version = resolve_version(query, self.events)
        candidates = [x for x in self.snapshot_ids if version is None or
                      self.catalog.get(x, "graph-snapshot")["graph_version"] == version]
        require(bool(candidates), "GRAPH_VERSION_UNAVAILABLE", "requested snapshot unavailable")
        selected = max(candidates, key=lambda x: self.catalog.get(x, "graph-snapshot")["graph_version"])
        v = self.catalog.get(selected, "graph-snapshot")["graph_version"]
        require(len({self.catalog.hash(ref) for ref in candidates
                     if self.catalog.get(ref, "graph-snapshot")["graph_version"] == v}) == 1,
                "GRAPH_VERSION_AMBIGUOUS", "one accepted snapshot is required per graph version")
        history = [e for e in self.events if e["version"] <= v]
        selected_events = [e for e in history if e["version"] == v]
        if selected_events:
            require(self.catalog.get(selected, "graph-snapshot") == snapshot_body(selected_events[-1]["state_after"]),
                    "SNAPSHOT_BINDING", "memory snapshot differs from its authoritative event")
        available = set().union(*(set(e.get("record_hashes", {})) for e in history)) if history else set()
        # A custom adapter without an event journal can retrieve snapshot facts,
        # but cannot assert when historical decisions became known.
        if version is None:
            available |= {r["id"] for r in self.catalog.all()}
        available.add(selected)
        return GraphReadView(self.catalog, selected, deepcopy(self.source_status), available, history, self.version)


def resolve_version(query: dict[str, Any], events: list[dict[str, Any]]) -> int | None:
    version = query["graph_version"]
    t = query["temporal_scope"]
    historical_version = None
    if t["as_of"]:
        available = [e["version"] for e in events if timestamp(e["committed_at"]) <= timestamp(t["as_of"])]
        historical_version = max(available, default=0)
    if t["before_source"]:
        matches = [e["version"] for e in events if t["before_source"] in e.get("record_hashes", {})]
        require(bool(matches), "SOURCE_HISTORY_UNAVAILABLE", "source arrival is not journaled")
        before = min(matches) - 1
        historical_version = before if historical_version is None else min(before, historical_version)
    require(version is None or historical_version is None or version == historical_version,
            "TEMPORAL_SCOPE_CONFLICT", "version and temporal selectors disagree")
    return historical_version if historical_version is not None else version


class SQLiteGraphAdapter:
    """Consistent read of SQLiteReferenceBackend or its pinned legacy bridge.

    Reuses state/journal/records. Does not maintain an alternate authoritative graph.
    Current permissions and tombstones govern even historical snapshot retrieval.
    """
    version = "sqlite-trace-domain-read-v1.1"

    def __init__(self, backend: Any, catalog: Catalog | None = None, *, audit_trust: Any = None):
        self.backend, self.working_catalog, self.audit_trust = backend, catalog, audit_trust
        self.index = SQLiteClassificationIndex(backend.db, scope_required=self._phase_guard() is not None)
        if not self.index.tables_exist():
            with self._index_write():
                self.index.ensure_tables()

    def _phase_guard(self):
        return getattr(self.backend, "_phase_guard", None)

    @contextmanager
    def _index_write(self):
        """Every index DDL/rebuild/write: phase owner, then backend lock, then SQL write lock.

        Same order as backend transactions. A caller-owned transaction is never
        adopted: the write would otherwise commit or roll back with its fate.
        """
        backend = self.backend
        guard = self._phase_guard()
        with (guard() if guard is not None else nullcontext()):
            with backend._lock:
                require(not backend.db.in_transaction, "GRAPH_READ_UNCOMMITTED",
                        "index writes require a committed connection, not a caller-owned transaction")
                backend.db.execute("BEGIN IMMEDIATE")
                self.index.scope_depth += 1
                try:
                    yield
                    backend.db.execute("COMMIT")
                except BaseException:
                    if backend.db.in_transaction:
                        backend.db.execute("ROLLBACK")
                    raise
                finally:
                    self.index.scope_depth -= 1

    def current_source_status(self) -> dict[str, Any]:
        with self.backend._lock:
            require(not self.backend.db.in_transaction, "GRAPH_READ_UNCOMMITTED",
                    "current-status reads require a committed connection, not a caller-owned transaction")
            return self.backend.statuses()

    def rebuild_classification_index(self, query: dict[str, Any]) -> GraphReadView:
        return self._read(query, rebuild=True)

    def materialize_classification_index(self, query: dict[str, Any]) -> GraphReadView:
        """Persist the verified index entry for a snapshot (phase-bound reads never do)."""
        return self._read(query, materialize=True)

    def read(self, query: dict[str, Any]) -> GraphReadView:
        return self._read(query)

    def _read(self, query: dict[str, Any], *, rebuild: bool = False, materialize: bool = False) -> GraphReadView:
        if rebuild or materialize:
            with self._index_write():
                return self._view(query, rebuild=rebuild, persist=True)
        backend = self.backend
        with backend._lock:
            # A reentrant same-connection call can see a complete but uncommitted
            # journal and export a graph version that subsequently rolls back.
            # Reject it without committing, rolling back, or altering that caller's
            # transaction. A separate connection sees only committed versions.
            require(not backend.db.in_transaction, "GRAPH_READ_UNCOMMITTED",
                    "use a separate committed read connection during publication")
            backend.db.execute("BEGIN")
            try:
                # A phase-bound database is never mutated by an ordinary read; an
                # absent index entry is derived from authority and left unwritten.
                view = self._view(query, rebuild=False, persist=self._phase_guard() is None)
                backend.db.execute("COMMIT")
                return view
            except BaseException:
                if backend.db.in_transaction:
                    backend.db.execute("ROLLBACK")
                raise

    def _view(self, query: dict[str, Any], *, rebuild: bool, persist: bool) -> GraphReadView:
        from time import perf_counter
        start = perf_counter()
        backend = self.backend
        audit_start = perf_counter()
        require(backend.sandbox or self.audit_trust is not None or not
                (backend.state().get("classifications") or query.get("research_domain_scope")),
                "CLASSIFICATION_TRUST_REQUIRED", "non-sandbox domain reads require application-enrolled audit trust")
        backend.audit(trust=self.audit_trust)
        audit_seconds = perf_counter() - audit_start
        events = [loads(row[0]) for row in backend.db.execute("SELECT body FROM trace_journal ORDER BY version")]
        version = resolve_version(query, events)
        state = backend.state()
        require(version is None or version <= state["graph_version"], "GRAPH_VERSION_UNAVAILABLE", "future snapshot")
        if version is not None and version != state["graph_version"]:
            if version == 0:
                state = loads(backend.db.execute("SELECT body FROM trace_meta WHERE id=1").fetchone()[0])["genesis_state"]
            else:
                matches = [e for e in events if e["version"] == version]
                require(bool(matches), "GRAPH_VERSION_UNAVAILABLE", "snapshot not journaled")
                state = matches[0]["state_after"]
        catalog = backend.load_catalog()
        history = [e for e in events if e["version"] <= state["graph_version"]]
        available = set().union(*(set(e["record_hashes"]) for e in history))
        available |= {r["id"] for r in catalog.all("transaction") if r["body"]["version"] <= state["graph_version"]}
        body = snapshot_body(state)
        snapshot_id = catalog.put("graph-snapshot", body)
        # Compute/validate index ONLY from persisted authority, never proposals
        # carried in the caller's mutable working catalog.
        rows = self.index.read(catalog, snapshot_id, rebuild=rebuild, persist=persist)
        if self.working_catalog is not None and version is None:
            for record in self.working_catalog.all():
                catalog.add(record)
            available |= {r["id"] for r in self.working_catalog.all()}
        available.add(snapshot_id)
        result = GraphReadView(catalog, snapshot_id, backend.statuses(), available, history, self.version,
                               classification_rows=rows,
                               read_metrics={"authority_audit_seconds": audit_seconds, **self.index.last_metrics,
                                             "read_seconds": perf_counter() - start})
        return result
