"""Sandbox operational checks over actual adapters, not deployment certification."""
from __future__ import annotations
from pathlib import Path
import sqlite3
import tempfile
import time
from ..canonical import digest
from ..errors import ContractError, require
from .store import SQLiteGraphAdapter


def check_sandbox_backup_recovery(backend, *, reopen, classification_trust, query):
    """Use SQLite's online backup and test an isolated copy. Never touch production.

    `reopen(path)` is a trusted application-owned factory for the exact same
    backend/core/policy, not a module name supplied by a query or model.
    """
    require(backend.sandbox is True, "OPERATIONAL_SCOPE", "this helper permits disposable sandbox stores only")
    started = time.perf_counter()
    adapter = SQLiteGraphAdapter(backend, classification_trust=classification_trust)
    original = adapter.read(query)
    before = backend.audit()
    raw = getattr(backend.db, "raw", backend.db)
    checks = []
    with tempfile.TemporaryDirectory(prefix="trace-domain-recovery-") as tmp:
        backup = Path(tmp) / "backup.sqlite3"
        with backend._lock:
            require(not raw.in_transaction, "OPERATIONAL_SCOPE", "backup requires no caller-owned transaction")
            connection = sqlite3.connect(backup)
            try:
                raw.backup(connection)
            finally:
                connection.close()
        checks.append("sqlite_online_backup_completed")
        recovered = reopen(backup)
        try:
            view = SQLiteGraphAdapter(recovered, classification_trust=classification_trust).read(query)
            require(view.snapshot == original.snapshot and view.source_status == original.source_status and
                    recovered.audit()["head_hash"] == before["head_hash"], "RECOVERY_MISMATCH", "backup changed authority")
            checks.extend(["reopened_native_backend_audit", "exact_snapshot_and_current_source_status"])
            recovered.db.execute("UPDATE trace_domain_index SET domain_id='forged-domain' WHERE rowid=(SELECT MIN(rowid) FROM trace_domain_index)")
            try:
                SQLiteGraphAdapter(recovered, classification_trust=classification_trust).read(query)
            except ContractError as exc:
                require(exc.code in {"DOMAIN_INDEX_STALE", "DOMAIN_INDEX_TAMPERED"}, "RECOVERY_MISMATCH", str(exc))
            else:
                raise ContractError("RECOVERY_MISMATCH", "tampered derived index was served")
            checks.append("corrupt_backup_index_fails_closed")
            a = SQLiteGraphAdapter(recovered, classification_trust=classification_trust)
            a.rebuild_domain_index()
            require(a.read(query).snapshot == original.snapshot and recovered.audit()["head_hash"] == before["head_hash"],
                    "RECOVERY_MISMATCH", "index rebuild changed authority")
            checks.append("explicit_index_rebuild_restores_read_without_graph_write")
        finally:
            recovered.close()
    require(backend.audit() == before, "RECOVERY_MISMATCH", "operational check changed original authority")
    return {"version": "domain-sandbox-operations-v1", "status": "PASS", "checks": checks,
            "checks_run": len(checks), "backend_class": type(backend).__name__, "scope": "SYNTHETIC_SANDBOX_ONLY",
            "snapshot_hash": digest(original.snapshot), "authority_head": before["head_hash"],
            "duration_ms": (time.perf_counter() - started) * 1000, "production_qualified": False,
            "deployment_gates_not_run": ["selected-deployment-identity", "operator-authority", "production-acl-and-revocation-propagation",
                                         "backend-native-deadline-and-cancellation", "deployment-concurrency-slos", "residency-and-retention",
                                         "representative-corpus-quality", "independent-operational-review"]}
