"""Read adapters over the existing graph authority; algorithms never write it."""
from __future__ import annotations
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable
from ..canonical import digest, loads
from ..catalog import Catalog
from ..compiler import timestamp
from ..errors import require

@dataclass
class GraphReadView:
    catalog: Catalog
    snapshot_id: str
    source_status: dict[str, Any]
    available_record_ids: set[str]
    events: list[dict[str, Any]]
    adapter_version: str
    domain_index_rows: list[tuple] | None = None

    @property
    def classification_projection(self):
        # Internal trusted read view; public consumers must still apply ACLs.
        return deepcopy(self.snapshot.get("research_domains"))

    @property
    def classification_identity(self) -> str:
        return digest(self.classification_projection)

    @property
    def classification_revision(self) -> int:
        return (self.classification_projection or {}).get("revision", 0)

    @property
    def snapshot(self) -> dict[str, Any]:
        return self.catalog.get(self.snapshot_id, "graph-snapshot")

    @property
    def identity(self) -> str:
        return digest({"snapshot": self.catalog.hash(self.snapshot_id), "source_status": self.source_status,
                       "available": sorted(ref for ref in self.available_record_ids
                            if ref in self.catalog and self.catalog.record(ref)["kind"] not in {
                                "retrieval-query", "retrieval-plan", "graph-access", "graph-context", "retrieval-result",
                                "retrieval-expansion", "retrieval-lineage", "graphrag-answer", "retrieval-replay", "retrieval-evaluation"}),
                       "adapter": self.adapter_version})

@runtime_checkable
class GraphQueryAdapter(Protocol):
    version: str
    def read(self, query: dict[str, Any]) -> GraphReadView: ...


class InMemoryGraphAdapter:
    """Immutable-snapshot reference adapter, useful for tests and custom stores."""
    version = "memory-snapshot-domain-v2"

    def __init__(self, catalog: Catalog, snapshot_ids: list[str], source_status: dict[str, Any],
                 events: list[dict[str, Any]] | None = None, *, classification_trust=None,
                 genesis_state: dict[str, Any] | None = None, sandbox: bool = False):
        self.classification_trust = classification_trust
        self.genesis_state, self.sandbox = deepcopy(genesis_state), sandbox
        self.catalog, self.snapshot_ids, self.source_status = catalog, list(snapshot_ids), deepcopy(source_status)
        self.events = deepcopy(events or [])

    def read(self, query: dict[str, Any]) -> GraphReadView:
        version = resolve_version(query, self.events)
        candidates = [x for x in self.snapshot_ids if version is None or
                      self.catalog.get(x, "graph-snapshot")["graph_version"] == version]
        require(bool(candidates), "GRAPH_VERSION_UNAVAILABLE", "requested snapshot unavailable")
        selected = max(candidates, key=lambda x: self.catalog.get(x, "graph-snapshot")["graph_version"])
        v = self.catalog.get(selected, "graph-snapshot")["graph_version"]
        history = [e for e in self.events if e["version"] <= v]
        available = set().union(*(set(e.get("record_hashes", {})) for e in history)) if history else set()
        # A custom adapter without an event journal can retrieve snapshot facts,
        # but cannot assert when historical decisions became known.
        if version is None:
            available |= {r["id"] for r in self.catalog.all()}
        available.add(selected)
        catalog = Catalog(self.catalog.all())
        snapshot = catalog.get(selected, "graph-snapshot")
        rows = None
        if "research_domains" in snapshot or any(e.get("operation", {}).get("action") in {
                "MIGRATE_CLASSIFICATION_STATE", "PUBLISH_CLASSIFICATION"} for e in history):
            from .domain_index import validate_history, selected_rows
            verified = validate_history(catalog, history, self.genesis_state,
                                        self.classification_trust, sandbox=self.sandbox)
            require(verified["projection"] == snapshot.get("research_domains") and
                    verified["graph_version"] == v, "DOMAIN_SNAPSHOT_BINDING", "snapshot differs from domain journal")
            require(self.events and self.source_status == self.events[-1]["source_status"],
                    "DOMAIN_SOURCE_STATUS", "in-memory source status is not the current journal projection")
            rows = selected_rows(verified["rows"], v)
        return GraphReadView(catalog, selected, deepcopy(self.source_status), available, history, self.version, rows)


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
    version = "sqlite-trace-read-domain-v2"

    def __init__(self, backend: Any, catalog: Catalog | None = None, *, classification_trust=None):
        self.backend, self.working_catalog = backend, catalog
        self.classification_trust = classification_trust

    def rebuild_domain_index(self, *, fault=None):
        from .domain_index import rebuild
        return rebuild(self.backend, self.classification_trust, fault=fault)

    def read(self, query: dict[str, Any]) -> GraphReadView:
        backend = self.backend
        with backend._lock:
            own = not backend.db.in_transaction
            if own:
                backend.db.execute("BEGIN")
            try:
                backend.audit()
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
                rows = None
                if any("research_domains" in event["state_after"] for event in events):
                    from .domain_index import validate_history, verify, read_rows
                    genesis = loads(backend.db.execute("SELECT body FROM trace_meta WHERE id=1").fetchone()[0])["genesis_state"]
                    verified = validate_history(catalog, events, genesis, self.classification_trust,
                                                sandbox=backend.sandbox)
                    verify(backend, verified)
                    rows = read_rows(backend, state["graph_version"])
                history = [e for e in events if e["version"] <= state["graph_version"]]
                available = set().union(*(set(e["record_hashes"]) for e in history))
                available |= {r["id"] for r in catalog.all("transaction") if r["body"]["version"] <= state["graph_version"]}
                if self.working_catalog is not None and version is None:
                    for record in self.working_catalog.all():
                        catalog.add(record)
                    available |= {r["id"] for r in self.working_catalog.all()}
                body = {k: state[k] for k in ("graph_version", "schema_id", "schema_hash", "nodes", "assertions", "source_epochs")}
                if "research_domains" in state:
                    body["research_domains"] = deepcopy(state["research_domains"])
                snapshot_id = catalog.put("graph-snapshot", body)
                available.add(snapshot_id)
                result = GraphReadView(catalog, snapshot_id, backend.statuses(), available, history, self.version, rows)
                if own:
                    backend.db.execute("COMMIT")
                return result
            except BaseException:
                if own and backend.db.in_transaction:
                    backend.db.execute("ROLLBACK")
                raise
