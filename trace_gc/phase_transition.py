"""Explicit, application-owned PaperPilot phase handoff.

An export is read-only against the old runtime. Import is a separate, signed
operation in a new checkpoint; it never edits the historical OPEN or events.
This module contains no provider, PDF reader, or graph publication client.
"""
from __future__ import annotations

import base64
import os
from pathlib import Path
import sqlite3
import uuid
from typing import Any

from .canonical import bytes_digest, digest, dumps, loads
from .errors import require

CAPSULE_VERSION = "paper-pilot-phase-capsule-v1"
AUTH_VERSION = "paper-pilot-phase-authorization-v1"
ATTEMPT_NAMES = frozenset({"semantic-attempt-started.json", "semantic-response.raw",
    "semantic-local-execution.json", "semantic-execution-outcome.json",
    "semantic-import-result.json"})


def _read_once(path: str | Path, expected_sha256: str) -> bytes:
    raw = Path(path).read_bytes()
    require(bytes_digest(raw) == expected_sha256, "PHASE_BYTES_CHANGED", "pinned phase bytes changed")
    return raw


def _tables(connection: sqlite3.Connection) -> dict[str, Any]:
    """All user schema objects and table rows under caller-owned quiescence."""
    objects = connection.execute("SELECT type,name,tbl_name,sql FROM sqlite_master "
                                 "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name").fetchall()
    result = {"objects": [list(row) for row in objects], "tables": {}}
    for kind, name, _table, _sql in objects:
        if kind != "table":
            continue
        require(type(name) is str and name.replace("_", "").isalnum(),
                "PHASE_SQLITE", "unexpected table name")
        body = connection.execute(f'SELECT * FROM "{name}"').fetchall()
        encoded = [[base64.b64encode(v).decode("ascii") if isinstance(v, bytes) else v
                    for v in row] for row in body]
        result["tables"][name] = {"rows_sha256": digest(sorted(encoded, key=dumps)),
                                   "row_count": len(encoded)}
    return result


def logical_state(connection: sqlite3.Connection) -> str:
    return digest(_tables(connection))


def _file_logical(path: Path) -> str:
    sidecars = (path.with_name(path.name + "-wal"),
                path.with_name(path.name + "-shm"))
    require(not any(sidecar.exists() for sidecar in sidecars),
            "PHASE_SQLITE", "uncheckpointed or foreign SQLite sidecar")
    # Every destination writer is closed before this readback. Inspect only
    # the checkpointed main database, without creating WAL/SHM artifacts.
    connection = sqlite3.connect(f"file:{path.as_posix()}?mode=ro&immutable=1", uri=True)
    try:
        connection.execute("PRAGMA query_only=ON")
        return logical_state(connection)
    finally:
        connection.close()
        require(not any(sidecar.exists() for sidecar in sidecars),
                "PHASE_SQLITE", "SQLite sidecar appeared during logical read")


def _backup(source: sqlite3.Connection, target: Path) -> str:
    require(not target.exists(), "PHASE_BACKUP_EXISTS", "backup must be new")
    target.parent.mkdir(parents=True, exist_ok=True)
    destination = sqlite3.connect(target)
    try:
        source.backup(destination)
        destination.commit()
        require(logical_state(source) == logical_state(destination),
                "PHASE_BACKUP_DRIFT", "backup differs from source")
    finally:
        destination.close()
    return bytes_digest(target.read_bytes())


def _replay_events(rows: list[list[Any]]) -> tuple[dict[str, dict], str]:
    previous = None
    requests: dict[str, dict] = {}
    require(bool(rows), "PHASE_CHECKPOINT", "old checkpoint empty")
    for expected_seq, row in enumerate(rows, 1):
        seq, raw, hash_ = row
        event = loads(raw)
        require(seq == expected_seq and event["previous"] == previous and digest(event) == hash_,
                "PHASE_CHECKPOINT", "old checkpoint chain changed")
        previous = hash_
        if seq == 1:
            require(event["kind"] == "OPEN", "PHASE_CHECKPOINT", "old OPEN missing")
            continue
        value = event["value"]
        if event["kind"] == "INTENT":
            require(value["id"] not in requests, "PHASE_CHECKPOINT", "duplicate old request")
            requests[value["id"]] = loads(dumps(value))
        elif event["kind"] == "RESULT":
            require(value["id"] in requests and "result" not in requests[value["id"]],
                    "PHASE_CHECKPOINT", "orphan or duplicate old result")
            requests[value["id"]]["result"] = value["result"]
        else:
            require(False, "PHASE_CHECKPOINT", "unrecognized old event")
    return requests, previous


def verify_capsule(capsule: dict[str, Any]) -> tuple[dict[str, dict], str]:
    require(capsule.get("version") == CAPSULE_VERSION and
            set(capsule) == {"version", "run_id", "config", "old_implementation",
                             "checkpoint_events", "checkpoint_head", "blobs",
                             "catalog_records", "database_state", "database_backup_sha256",
                             "graph_state", "source_statuses", "budget_snapshot",
                             "application_journal_events", "application_journal_head",
                             "external_semantic_intent_sha256", "external_semantic_intent",
                             "external_semantic_intent_base64", "attempt_manifest_sha256",
                             "attempt_manifest", "attempt_manifest_base64", "attempt_inventory",
                             "source_receipt_sha256", "source_open_sha256"},
            "PHASE_CAPSULE", "capsule fields changed")
    requests, head = _replay_events(capsule["checkpoint_events"])
    require(head == capsule["checkpoint_head"] and
            loads(capsule["checkpoint_events"][0][1])["value"]["config"] == capsule["config"] and
            loads(capsule["checkpoint_events"][0][1])["value"]["implementation"] == capsule["old_implementation"],
            "PHASE_CAPSULE", "old OPEN binding differs")
    prior_records = []
    for _, raw, _ in capsule["checkpoint_events"][1:]:
        event = loads(raw)
        if event["kind"] == "RESULT":
            prior_records = event["value"]["records"]
    require(digest(prior_records) == digest(capsule["catalog_records"]),
            "PHASE_CAPSULE", "final old catalog differs from checkpoint")
    for sha, encoded in capsule["blobs"].items():
        require(bytes_digest(base64.b64decode(encoded, validate=True)) == sha,
                "PHASE_BLOB", "old blob changed")
    for row in requests.values():
        kind = row["kind"]
        if kind not in {"PREPARE_SOURCE", "PREPARE_SOURCE_IMAGE"} or "result" not in row:
            continue
        args, result = row["args"], row["result"]
        refs = {args["pdf_sha256"], result["page_png_blob"]}
        if kind == "PREPARE_SOURCE_IMAGE":
            refs.update([args["raw_output_sha256"], result["crop_png_blob"]])
        require(refs.issubset(capsule["blobs"]), "PHASE_BLOB",
                "historical source evidence is missing from the capsule")
    require(capsule["application_journal_events"] and
            capsule["application_journal_head"] == capsule["application_journal_events"][-1][2],
            "PHASE_JOURNAL", "application journal absent or changed")
    prior = None
    for index, (seq, raw, recorded_hash) in enumerate(capsule["application_journal_events"], 1):
        event = loads(raw)
        require(seq == index and event["previous"] == prior and digest(event) == recorded_hash,
                "PHASE_JOURNAL", "application journal chain changed")
        prior = recorded_hash
    require(loads(capsule["application_journal_events"][0][1])["kind"] == "FREEZE" and
            capsule["budget_snapshot"]["run_id"] == capsule["run_id"] and
            set(capsule["database_state"]) == {"checkpoint", "graph", "budget", "application_journal"},
            "PHASE_CAPSULE", "historical FREEZE or budget differs")
    intent, manifest = capsule["external_semantic_intent"], capsule["attempt_manifest"]
    intent_raw = base64.b64decode(capsule["external_semantic_intent_base64"], validate=True)
    manifest_raw = base64.b64decode(capsule["attempt_manifest_base64"], validate=True)
    require(bytes_digest(intent_raw) == capsule["external_semantic_intent_sha256"] and
            loads(intent_raw) == intent and
            bytes_digest(manifest_raw) == capsule["attempt_manifest_sha256"] and
            loads(manifest_raw) == manifest,
            "PHASE_INTENT", "external intent or attempt manifest bytes changed")
    compiled = [row for row in requests.values() if row["kind"] == "COMPILE"]
    require(len(compiled) == 1 and "result" in compiled[0] and
            all("result" in row for row in requests.values()) and
            compiled[0]["result"]["state"] == "WAIT_SEMANTIC_RESPONSE" and
            not any(row["kind"] == "SEMANTIC_RESPONSE" for row in requests.values()) and
            compiled[0]["id"] == intent["compile_id"] and
            compiled[0]["result"]["pack_sha256"] == intent["pack_sha256"] and
            compiled[0]["result"]["request_sha256"] == intent["request_sha256"] and
            intent["version"] == "issue23-semantic-intent-v1" and
            intent["automatic_retry"] is False and intent["attempts_authorized"] == 1 and
            intent["graph_writes"] == 0 and
            capsule["budget_snapshot"]["used"]["model_calls"] == 1 and
            capsule["budget_snapshot"]["used"]["request_bytes"] > 0 and
            capsule["budget_snapshot"]["used"]["retries"] == 0,
            "PHASE_INTENT", "external intent, reservation or completed compile differs")
    require(set(manifest) == {"version", "run_id", "intent_sha256", "artifacts",
                               "source_receipts", "source_open_sha256", "expected_budget_used"} and
            manifest["version"] == "paper-pilot-phase-attempt-manifest-v1" and
            manifest["run_id"] == capsule["run_id"] and
            manifest["intent_sha256"] == capsule["external_semantic_intent_sha256"] and
            manifest["source_open_sha256"] == capsule["source_open_sha256"] and
            manifest["expected_budget_used"] == capsule["budget_snapshot"]["used"] and
            set(manifest["artifacts"]) == ATTEMPT_NAMES and
            manifest["artifacts"] == capsule["attempt_inventory"] and
            manifest["source_receipts"] == capsule["source_receipt_sha256"],
            "PHASE_INTENT", "attempt or source manifest differs")
    return requests, head


def verify_import_authorization(trust, receipt: dict, *, capsule_sha256: str,
                                target_implementation_sha256: str, run_id: str,
                                historical: bool = False) -> None:
    policy = trust.verify(receipt, "AUTHORIZATION",
                          at=receipt["issued_at"] if historical else None)
    expected = {"version": AUTH_VERSION, "operation": "PHASE_IMPORT",
                "capsule_sha256": capsule_sha256,
                "target_implementation_sha256": target_implementation_sha256,
                "run_id": run_id}
    require(receipt["payload"] == expected and "PHASE_IMPORT" in policy.operations and
            policy.can_review, "PHASE_AUTHORITY", "exact reviewed phase authorization required")


def restore_target(*, capsule_path: str | Path, capsule_sha256: str,
                   target_root: str | Path, authorization: dict, trust,
                   target_implementation_sha256: str, phase_authority) -> dict:
    """Hold the shared phase lock through the entire inactive restore."""
    from .phase_authority import PhaseAuthority
    require(type(phase_authority) is PhaseAuthority,
            "PHASE_CONFIG", "exact phase authority required")
    with phase_authority.staging():
        return _restore_target_locked(capsule_path=capsule_path,
            capsule_sha256=capsule_sha256, target_root=target_root,
            authorization=authorization, trust=trust,
            target_implementation_sha256=target_implementation_sha256,
            phase_authority=phase_authority)


def _restore_target_locked(*, capsule_path: str | Path, capsule_sha256: str,
                   target_root: str | Path, authorization: dict, trust,
                   target_implementation_sha256: str, phase_authority) -> dict:
    """Restore verified graph/budget backups into a new, inactive phase.

    This uses SQLite's backup API. It does not issue any graph operation or
    budget consumption and never copies the old checkpoint OPEN as active.
    """
    capsule_file = Path(capsule_path).resolve(strict=True)
    from .phase_authority import PhaseAuthority, binding_sha256
    require(type(phase_authority) is PhaseAuthority and phase_authority.trust is trust and
            phase_authority.binding["capsule_path"] == str(capsule_file) and
            phase_authority.binding["capsule_sha256"] == capsule_sha256 and
            phase_authority.binding["implementation_sha256"] == target_implementation_sha256 and
            phase_authority.binding["run_id"] == loads(_read_once(capsule_file, capsule_sha256))["run_id"] and
            not Path(phase_authority.binding["activation_path"]).exists(),
            "PHASE_CONFIG", "inactive exact target phase binding required")
    phase_authority.verify_fence()
    require(not Path(capsule_path).is_symlink(), "PHASE_PATH", "capsule symlink denied")
    raw = _read_once(capsule_file, capsule_sha256)
    capsule = loads(raw)
    verify_capsule(capsule)
    verify_import_authorization(trust, authorization,
        capsule_sha256=capsule_sha256,
        target_implementation_sha256=target_implementation_sha256,
        run_id=capsule["run_id"])
    root = Path(target_root).resolve(strict=False)
    require(not root.is_relative_to(capsule_file.parent) and
            not capsule_file.parent.is_relative_to(root) and
            not any(part.is_symlink() for part in (Path(target_root), Path(target_root).parent)),
            "PHASE_DESTINATION", "disjoint target required")
    backups = {}
    for name, expected in capsule["database_backup_sha256"].items():
        source = capsule_file.parent / (name + ".sqlite3")
        require(source.is_file() and not source.is_symlink() and
                bytes_digest(source.read_bytes()) == expected,
                "PHASE_BACKUP", "backup bytes changed")
        connection = sqlite3.connect(f"file:{source.as_posix()}?mode=ro&immutable=1", uri=True)
        try:
            connection.execute("PRAGMA query_only=ON")
            require(logical_state(connection) == capsule["database_state"][name],
                    "PHASE_BACKUP", "backup logical state changed")
        finally:
            connection.close()
        backups[name] = source
    require(set(backups) == {"checkpoint", "graph", "budget", "application_journal"},
            "PHASE_BACKUP", "all four source stores required")
    if root.exists():
        require(root.is_dir() and not any(path.is_symlink() for path in root.iterdir()) and
                {path.name for path in root.iterdir()} <=
                {"graph.sqlite3", "budget.sqlite3", "phase-restore.json",
                 "graph.sqlite3.pending", "budget.sqlite3.pending"} |
                {path.name for path in root.iterdir() if any(
                    path.name.startswith(name + ".sqlite3.failed.")
                    for name in ("graph", "budget"))},
                "PHASE_DESTINATION", "partial target has unknown content")
    else:
        root.mkdir(parents=True)
    for name in ("graph", "budget"):
        require(bytes_digest(backups[name].read_bytes()) == capsule["database_backup_sha256"][name],
                "PHASE_BACKUP", "backup changed during restore")
        target = root / (name + ".sqlite3")
        if target.exists():
            existing = sqlite3.connect(f"file:{target.as_posix()}?mode=ro&immutable=1", uri=True)
            try:
                existing.execute("PRAGMA query_only=ON")
                state = _tables(existing)
                marker = state["tables"].pop("trace_phase_binding", None)
                state["objects"] = [row for row in state["objects"]
                                    if row[1] != "trace_phase_binding"]
                require(digest(state) == capsule["database_state"][name],
                        "PHASE_BACKUP", "partial restored store changed")
                if marker is not None:
                    require(existing.execute("SELECT binding_sha256 FROM trace_phase_binding WHERE id=1")
                            .fetchall() == [(binding_sha256(phase_authority.binding),)],
                            "PHASE_BACKUP", "partial binding changed")
            finally:
                existing.close()
        else:
            source = sqlite3.connect(f"file:{backups[name].as_posix()}?mode=ro&immutable=1", uri=True)
            source.execute("PRAGMA query_only=ON")
            pending = target.with_name(target.name + ".pending")
            if pending.exists():
                try:
                    probe = sqlite3.connect(f"file:{pending.as_posix()}?mode=ro&immutable=1", uri=True)
                    try:
                        probe.execute("PRAGMA query_only=ON")
                        complete = logical_state(probe) == capsule["database_state"][name]
                    finally:
                        probe.close()
                except sqlite3.DatabaseError:
                    complete = False
                if not complete:
                    pending.rename(target.with_name(target.name + ".failed." + uuid.uuid4().hex))
            if not pending.exists():
                destination = sqlite3.connect(pending)
                try:
                    source.backup(destination)
                    destination.commit()
                    require(logical_state(destination) == capsule["database_state"][name],
                            "PHASE_BACKUP", "restored logical state changed")
                finally:
                    destination.close()
            try:
                os.replace(pending, target)
            finally:
                source.close()
    for name in ("graph", "budget"):
        destination = sqlite3.connect(root / (name + ".sqlite3"))
        try:
            existing = destination.execute("SELECT name FROM sqlite_master WHERE type='table' "
                                           "AND name='trace_phase_binding'").fetchone()
            if existing is None:
                destination.execute("CREATE TABLE trace_phase_binding "
                                    "(id INTEGER PRIMARY KEY CHECK(id=1), binding_sha256 TEXT NOT NULL)")
                destination.execute("INSERT INTO trace_phase_binding VALUES (1,?)",
                                    (binding_sha256(phase_authority.binding),))
                destination.commit()
        finally:
            destination.close()
    require(all(bytes_digest(backups[name].read_bytes()) == expected
                for name, expected in capsule["database_backup_sha256"].items()),
            "PHASE_BACKUP", "source backup changed during target restore")
    receipt = {"version": "paper-pilot-phase-restore-v1",
               "status": "INACTIVE_RESTORED_NO_MODEL_CALL",
               "capsule_sha256": capsule_sha256, "run_id": capsule["run_id"],
               "graph_logical_sha256": capsule["database_state"]["graph"],
               "budget_logical_sha256": capsule["database_state"]["budget"],
               "bound_graph_logical_sha256": _file_logical(root / "graph.sqlite3"),
               "bound_budget_logical_sha256": _file_logical(root / "budget.sqlite3"),
               "target_implementation_sha256": target_implementation_sha256}
    path = root / "phase-restore.json"
    receipt_raw = dumps(receipt).encode("utf-8") + b"\n"
    if path.exists():
        require(path.read_bytes() == receipt_raw,
                "PHASE_BACKUP", "existing restore receipt conflicts")
    else:
        with path.open("xb") as handle:
            handle.write(receipt_raw)
            handle.flush(); os.fsync(handle.fileno())
    require(loads(path.read_bytes()) == receipt, "PHASE_BACKUP", "restore receipt changed")
    return receipt


def _activation_events(db):
    previous = None
    events = []
    for expected, (seq, raw, hash_) in enumerate(db.execute(
            "SELECT seq,body,hash FROM events ORDER BY seq"), 1):
        event = loads(raw)
        require(seq == expected and event["previous"] == previous and digest(event) == hash_,
                "PHASE_ACTIVATION", "phase event chain changed")
        events.append(event)
        previous = hash_
    return events, previous


def activate_imported_phase(*, pilot, controller, phase_authority,
                            activation_receipt: dict) -> dict:
    """Publish the signed active pointer after exact inactive import readback.

    A preexisting identical pointer reconciles a lost return value. Conflicting
    bytes never replace an already active phase. The application retains its
    original historical archive and owns the signed activation authority.
    """
    from .phase_authority import PhaseAuthority
    require(type(phase_authority) is PhaseAuthority and
            pilot._phase_authority is phase_authority and
            controller.pilot is pilot and pilot._phase_imported and
            pilot.phase_import == phase_authority.binding,
            "PHASE_ACTIVATION", "same imported pilot, controller and authority required")
    binding = phase_authority.binding
    pointer = Path(binding["activation_path"])
    require(pointer.is_absolute() and pointer.parent.is_dir() and
            not pointer.is_symlink() and not pointer.parent.is_symlink(),
            "PHASE_ACTIVATION", "preexisting private activation parent required")
    raw = (dumps(activation_receipt) + "\n").encode("utf-8")
    require(bytes_digest(raw) == binding["activation_sha256"],
            "PHASE_ACTIVATION", "activation receipt bytes differ from binding")
    with phase_authority.staging():
        active = pointer.exists()
        if active:
            require(pointer.read_bytes() == raw, "PHASE_ACTIVATION",
                    "conflicting active phase pointer")
        phase_authority.verify_activation_receipt(activation_receipt, historical=active)
        capsule = loads(_read_once(binding["capsule_path"], binding["capsule_sha256"]))
        imported, _ = verify_capsule(capsule)
        authorization = loads(_read_once(binding["authorization_path"], binding["authorization_sha256"]))
        verify_import_authorization(pilot.trust, authorization,
            capsule_sha256=binding["capsule_sha256"],
            target_implementation_sha256=binding["implementation_sha256"],
            run_id=binding["run_id"], historical=True)
        checkpoint, head = _activation_events(pilot.db)
        journal, _ = _activation_events(controller.db)
        require(len(checkpoint) >= 2 and checkpoint[0]["kind"] == "OPEN" and
                checkpoint[1] == {"kind": "IMPORT_PHASE", "value": {
                    "capsule_sha256": binding["capsule_sha256"],
                    "authorization_sha256": binding["authorization_sha256"]},
                    "previous": digest(checkpoint[0])} and head == pilot._head and
                len(journal) >= 2 and journal[0]["kind"] == "FREEZE" and
                journal[0]["manifest"] == controller.manifest and
                journal[0]["pilot_head"] == digest(checkpoint[0]) and
                journal[1]["kind"] == "APPLICATION_PHASE_IMPORT" and
                journal[1]["capsule_sha256"] == binding["capsule_sha256"] and
                journal[1]["old_journal_head"] == capsule["application_journal_head"] and
                journal[1]["old_pilot_head"] == capsule["checkpoint_head"] and
                all(pilot.requests.get(id_) == row for id_, row in imported.items()),
                "PHASE_ACTIVATION", "imported phase history changed")
        if active:
            pilot.budget._verify_phase_floor(capsule["budget_snapshot"])
        else:
            require(len(checkpoint) == len(journal) == 2 and pilot.requests == imported and
                    pilot._matches_imported_state(capsule),
                    "PHASE_ACTIVATION", "inactive imported state changed")
        pilot._verify_imported_blobs(capsule)
        controller._check_actions()
        pilot.backend.audit()
        if not active:
            temporary = pointer.parent / ("." + pointer.name + "." + uuid.uuid4().hex + ".tmp")
            with temporary.open("xb") as stream:
                stream.write(raw)
                stream.flush(); os.fsync(stream.fileno())
            try:
                os.link(temporary, pointer)
            except FileExistsError:
                require(pointer.read_bytes() == raw, "PHASE_ACTIVATION",
                        "conflicting concurrent active phase pointer")
            finally:
                temporary.unlink(missing_ok=True)
        phase_authority._current()
    return {"status": "ACTIVE_IMPORTED_PHASE_EXACT", "activation_sha256": bytes_digest(raw),
            "phase_id": binding["phase_id"], "run_id": binding["run_id"],
            "model_calls": 0, "graph_writes": 0}
