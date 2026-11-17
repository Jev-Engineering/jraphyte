"""Durable, application-owned paper pilot; no provider or production graph client.

The private checkpoint is a cache of intent and evidence, never graph authority.
Only the existing source-admission and CompilerService publication APIs mutate
the isolated reference graph. Model execution and reviews belong to the caller.
"""
from __future__ import annotations

import base64
from contextlib import nullcontext
import importlib.metadata
import json
import os
from pathlib import Path
import sqlite3
import sys
import threading

from .adapter import record_response, validate_observation
from .backend import CompilerService, SQLiteReferenceBackend
from .canonical import bytes_digest, digest, dumps, loads, text_digest
from .compiler import compile_pack, now, timestamp, validate_pack
from .errors import boundary, require
from .paper_ingestion import CHECKS, _native_text, reviewed_page_source, verify_page_source
from .pdf_image_evidence import (render_source, image_candidate, candidate_hash,
    review_image, handoff, verify_artifacts, verify_image_source, CHECKS as IMAGE_CHECKS)
from .plans import add_operation, create_plan
from .programs import question
from .qualification import evaluate_policy
from .resolver import project_resolutions, solve
from .schema import validate
from .trust import verify_observation_attestation

VERSION = "paper-pilot-v1"


def implementation_identity() -> dict:
    root = Path(__file__).resolve().parent
    paths = sorted(list(root.rglob("*.py")) + list((root / "data/schemas").glob("*.json")))
    return {"files": {p.relative_to(root).as_posix(): bytes_digest(p.read_bytes()) for p in paths},
            "python": sys.version, "packages": {name: importlib.metadata.version(name)
                for name in ("jsonschema", "cryptography", "PyMuPDF", "Pillow")}}


class _PauseAnswer(Exception):
    def __init__(self, prompt):
        self.prompt = prompt


class PaperPilot:
    """One controller per private run directory; injected capabilities only.

    ``config`` freezes run_id, security_scope, execution_mode (LIVE/SYNTHETIC),
    documents (source_id/version/document_sha256/physical_pages), questions,
    semantic_model (provider/model_id/model_revision/tokenizer_id), answer_model,
    and cohort_manifest_sha256. The caller owns the ACL, trust and budget.
    """

    @boundary
    def __init__(self, root, *, config, catalog, backend, service, budget, current_access,
                 token_counter=None, semantic_profile=None, phase_import=None,
                 phase_authority=None):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        require(type(backend) is SQLiteReferenceBackend and type(service) is CompilerService and
                service.backend is backend and Path(backend.path).resolve() == self.root / "graph.sqlite3",
                "PILOT_BACKEND", "owned isolated SQLite reference backend required")
        require(Path(budget.path).resolve() == self.root / "budget.sqlite3" and callable(current_access),
                "PILOT_CONFIG", "owned durable budget and application ACL callback required")
        self.catalog, self.backend, self.service, self.budget = catalog, backend, service, budget
        self.trust, self.current_access, self.token_counter = service.trust, current_access, token_counter
        self.config = loads(dumps(config))
        self.semantic_profile = loads(dumps(semantic_profile))
        self.phase_import = loads(dumps(phase_import)) if phase_import is not None else None
        self._phase_authority = phase_authority
        self._old_lock_file = None
        self._phase_imported = False
        self._historical_request_ids = frozenset()
        require(set(config) == {"run_id", "security_scope", "execution_mode", "documents", "questions",
                "semantic_model", "answer_model", "cohort_manifest_sha256"}, "PILOT_CONFIG", "exact config fields required")
        require(config["execution_mode"] in {"LIVE", "SYNTHETIC"} and
                (config["execution_mode"] != "SYNTHETIC" or backend.sandbox) and
                config["run_id"] == budget.run_id and config["security_scope"] == service.scope and
                service.publication_mode == "REVIEWED" and bool(service.policy_hash),
                "PILOT_CONFIG", "explicit reviewed publication, mode, scope and budget binding required")
        require(bool(config["documents"]) and bool(config["questions"]) and
                all(type(q) is str and q.strip() for q in config["questions"]), "PILOT_CONFIG", "frozen cohort and questions required")
        require(len({d["source_id"] for d in config["documents"]}) == len(config["documents"]),
                "PILOT_CONFIG", "duplicate document identity")
        for row in config["documents"]:
            require(set(row) == {"source_id", "version", "document_sha256", "physical_pages"} and
                    row["source_id"] and row["version"] and row["physical_pages"] and
                    all(type(p) is int and p > 0 for p in row["physical_pages"]), "PILOT_CONFIG", "invalid document frame")
            self._sha(row["document_sha256"])
        self._sha(config["cohort_manifest_sha256"])
        for model in (config["semantic_model"], config["answer_model"]):
            require(set(model) == {"provider", "model_id", "model_revision", "tokenizer_id"} and
                    all(type(v) is str and v.strip() for v in model.values()), "PILOT_MODEL", "pinned model identity required")
        require(config["execution_mode"] != "LIVE" or callable(token_counter),
                "PILOT_MODEL", "real semantic requests require application tokenizer")
        if semantic_profile is not None:
            from .semantic_profile import validate_profile
            validate_profile(semantic_profile)
            require(config["semantic_model"] == {"provider": semantic_profile["provider"],
                    "model_id": semantic_profile["model_id"], "model_revision": semantic_profile["revision"],
                    "tokenizer_id": "tokenizer-sha256:" + semantic_profile["tokenizer_sha256"]},
                    "PILOT_MODEL", "local profile differs from frozen application model")
        self._identity = implementation_identity()
        if self.phase_import is None:
            require(phase_authority is None and backend._phase_authority is None and
                    budget._phase_authority is None,
                    "PHASE_CONFIG", "unphased pilot cannot own phase-bound stores")
        else:
            from .phase_authority import PhaseAuthority
            require(type(phase_authority) is PhaseAuthority and
                    phase_authority.binding == self.phase_import and
                    phase_authority.binding["implementation_sha256"] == digest(self._identity) and
                    backend._phase_authority is phase_authority and
                    budget._phase_authority is phase_authority,
                    "PHASE_CONFIG", "all target stores require one exact phase authority")
        self._mutex = threading.RLock()
        self._lock_file = (self.root / "controller.lock").open("a+b")
        self.db = None
        phase_scope = None
        phase_entered = False
        try:
            self._lock_file.seek(0)
            if os.name == "nt":
                import msvcrt
                if self._lock_file.read(1) == b"":
                    self._lock_file.write(b"0"); self._lock_file.flush()
                self._lock_file.seek(0)
                msvcrt.locking(self._lock_file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self._lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if self.phase_import is not None:
                required = {"phase_id", "run_id", "capsule_sha256", "implementation_sha256",
                            "activation_path", "activation_sha256", "activation_epoch",
                            "phase_lock_path", "fence_receipt_path", "fence_receipt_sha256",
                            "old_root_path", "archived_old_root_path", "capsule_path",
                            "authorization_path", "authorization_sha256"}
                require(set(self.phase_import) == required and
                        self.phase_import["run_id"] == self.config["run_id"],
                        "PHASE_CONFIG", "exact imported phase fields required")
                old_lock = (Path(self.phase_import["archived_old_root_path"]) / "controller.lock").resolve(strict=True)
                require(old_lock.name == "controller.lock" and old_lock.parent != self.root,
                        "PHASE_CONFIG", "archived historical controller lock required")
                self._old_lock_file = old_lock.open("r+b")
                if os.name == "nt":
                    import msvcrt
                    self._old_lock_file.seek(0)
                    msvcrt.locking(self._old_lock_file.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self._old_lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
                phase_authority.bind_archived_lock(self._old_lock_file)
                phase_scope = (phase_authority.write() if
                    Path(self.phase_import["activation_path"]).exists() else
                    phase_authority.staging())
                phase_scope.__enter__()
                phase_entered = True
            self.db = sqlite3.connect(self.root / "checkpoint.sqlite3", isolation_level=None)
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.executescript("""
                CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY, body TEXT NOT NULL, hash TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS blobs(hash TEXT PRIMARY KEY, body BLOB NOT NULL);
            """)
            self.requests = {}
            events = self.db.execute("SELECT seq,body,hash FROM events ORDER BY seq").fetchall()
            self._head = None
            expected = {"config": self.config, "implementation": self._identity,
                        "semantic_profile": self.semantic_profile,
                        "budget_limits": budget.snapshot()["limits"], "schema_hash": backend.state()["schema_hash"],
                        "policy_hash": service.policy_hash, "population": service.population,
                        "policy_version": service.policy_version, "sandbox": backend.sandbox}
            if self.phase_import is not None:
                expected["phase_import"] = self.phase_import
            self._application_binding = digest({k: v for k, v in expected.items() if k != "implementation"})
            for index, (seq, raw, hash_) in enumerate(events, 1):
                event = loads(raw)
                require(seq == index and event["previous"] == self._head and digest(event) == hash_,
                        "PILOT_CHECKPOINT", "checkpoint event chain differs")
                self._head = hash_
                if index == 1:
                    require(event["kind"] == "OPEN" and event["value"] == expected,
                            "PILOT_CONFIG_CHANGED", "run, code, runtime or application configuration changed")
                else:
                    self._apply(event)
            if not events:
                self._append("OPEN", expected)
            if self.phase_import is not None:
                backend.bind_phase_guard(phase_authority.write)
                budget.bind_phase_guard(phase_authority.write)
            backend.audit()
            for record in backend.load_catalog().all():
                if record["id"] in catalog:
                    require(catalog.record(record["id"]) == record, "PILOT_RECORD_CHANGED", "checkpoint differs from graph record")
                else:
                    catalog.add(record)
            for hash_, body in self.db.execute("SELECT hash,body FROM blobs"):
                require(bytes_digest(body) == hash_, "PILOT_BLOB_CHANGED", "private evidence bytes differ")
        except BaseException:
            self.close()
            raise
        finally:
            if phase_entered:
                phase_scope.__exit__(None, None, None)

    @staticmethod
    def _sha(value):
        require(type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value),
                "PILOT_HASH", "lowercase SHA-256 required")

    def close(self):
        if self.db is not None:
            self.db.close(); self.db = None
        if not self._lock_file.closed:
            self._lock_file.close()  # OS releases the lock, including on process exit.
        if self._old_lock_file is not None and not self._old_lock_file.closed:
            if self._phase_authority is not None:
                self._phase_authority.unbind_archived_lock(self._old_lock_file)
            self._old_lock_file.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def _apply(self, event):
        value = event["value"]
        if event["kind"] == "INTENT":
            require(value["id"] not in self.requests, "PILOT_CHECKPOINT", "duplicate intent")
            self.requests[value["id"]] = value
        elif event["kind"] == "RESULT":
            request = self.requests[value["id"]]
            require("result" not in request, "PILOT_CHECKPOINT", "duplicate completion")
            for record in value["records"]:
                self.catalog.add(record)
            request["result"] = value["result"]
        elif event["kind"] == "IMPORT_PHASE":
            from .phase_transition import _read_once, verify_capsule, verify_import_authorization
            require(self.phase_import is not None and not self._phase_imported and
                    value == {"capsule_sha256": self.phase_import["capsule_sha256"],
                              "authorization_sha256": self.phase_import["authorization_sha256"]},
                    "PHASE_IMPORT", "phase import event differs")
            capsule = loads(_read_once(self.phase_import["capsule_path"],
                                       self.phase_import["capsule_sha256"]))
            authorization = loads(_read_once(self.phase_import["authorization_path"],
                                              self.phase_import["authorization_sha256"]))
            verify_import_authorization(self.trust, authorization,
                capsule_sha256=self.phase_import["capsule_sha256"],
                target_implementation_sha256=digest(self._identity),
                run_id=self.config["run_id"], historical=True)
            imported, _ = verify_capsule(capsule)
            require(capsule["run_id"] == self.config["run_id"] and
                    capsule["config"] == self.config and not self.requests,
                    "PHASE_IMPORT", "import run/config/request inventory differs")
            # Activation verifies the starting state before publishing the signed
            # pointer. An active phase can have advanced its graph and budget.
            if not Path(self.phase_import["activation_path"]).exists():
                require(self._matches_imported_state(capsule),
                        "PHASE_IMPORT", "inactive target state differs from capsule")
            self._verify_imported_blobs(capsule)
            # The raw checkpoint preserves insertion order used by wire_request.
            # Canonical capsule catalog JSON has the same verified records but
            # sorts their keys, which can change the reserved adapter bytes.
            records = [loads(row[1])["value"]["records"]
                       for row in capsule["checkpoint_events"]
                       if loads(row[1])["kind"] == "RESULT"][-1]
            for record in records:
                self.catalog.add(record)
            self.requests.update(imported)
            self._historical_request_ids = frozenset(imported)
            self._phase_imported = True
        else:
            require(False, "PILOT_CHECKPOINT", "unknown event")

    def _append(self, kind, value):
        event = {"kind": kind, "value": value, "previous": self._head}
        hash_ = digest(event)
        # Pack wire requests preserve insertion order; canonical digest is separate.
        transport = json.dumps(event, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        self.db.execute("INSERT INTO events(body,hash) VALUES (?,?)", (transport, hash_))
        self._head = hash_
        if kind != "OPEN":
            self._apply(event)

    def _blob(self, data):
        require(type(data) is bytes and 0 < len(data) <= 64 * 1024 * 1024,
                "PILOT_BLOB", "nonempty bounded bytes required")
        hash_ = bytes_digest(data)
        self.db.execute("INSERT OR IGNORE INTO blobs VALUES (?,?)", (hash_, data))
        require(self._read_blob(hash_) == data, "PILOT_BLOB_CHANGED", "blob differs")
        return hash_

    def _read_blob(self, hash_):
        row = self.db.execute("SELECT body FROM blobs WHERE hash=?", (hash_,)).fetchone()
        require(row is not None and bytes_digest(row[0]) == hash_, "PILOT_BLOB_CHANGED", "evidence missing or changed")
        return bytes(row[0])

    def _matches_imported_state(self, capsule):
        return (self.backend.state() == capsule["graph_state"] and
                self.backend.statuses() == capsule["source_statuses"] and
                self.budget.snapshot() == capsule["budget_snapshot"])

    def _verify_imported_blobs(self, capsule):
        for sha in capsule["blobs"]:
            self._read_blob(sha)

    def _step(self, id_, kind, args, action):
        with self._mutex, (self._phase_authority.write() if self._phase_authority is not None else nullcontext()):
            if self.phase_import is not None:
                require(self._phase_imported, "PHASE_INACTIVE", "historical phase import incomplete")
            require(type(id_) is str and bool(id_), "PILOT_REQUEST", "stable request ID required")
            require(implementation_identity() == self._identity, "PILOT_CODE_CHANGED", "implementation changed during run")
            require(self.service.backend is self.backend and self.service.trust is self.trust and
                    self.service.scope == self.config["security_scope"] and self.service.publication_mode == "REVIEWED" and
                    self.budget.run_id == self.config["run_id"] and
                    digest({"config": self.config, "budget_limits": self.budget.snapshot()["limits"],
                            "semantic_profile": self.semantic_profile,
                            "schema_hash": self.backend.state()["schema_hash"], "policy_hash": self.service.policy_hash,
                            "population": self.service.population, "policy_version": self.service.policy_version,
                            "sandbox": self.backend.sandbox,
                            **({"phase_import": self.phase_import} if self.phase_import is not None else {})}) == self._application_binding,
                    "PILOT_CONFIG_CHANGED", "application capability or configuration changed during run")
            args = loads(dumps(args))
            if id_ not in self.requests:
                self._append("INTENT", {"id": id_, "kind": kind, "args": args, "created_at": now()})
            intent = self.requests[id_]
            require(intent["kind"] == kind and intent["args"] == args,
                    "PILOT_IDEMPOTENCY_CONFLICT", "same request ID has different immutable input")
            if "result" not in intent:
                result = action(intent["created_at"])
                require(implementation_identity() == self._identity, "PILOT_CODE_CHANGED", "implementation changed during stage")
                self._append("RESULT", {"id": id_, "result": result, "records": self.catalog.all()})
            return loads(dumps(self.requests[id_]["result"]))

    def _require_active_phase(self):
        require(self._phase_imported and self._phase_authority is not None,
                "PHASE_INACTIVE", "historical phase import incomplete")
        self._phase_authority.check()

    def import_phase(self, *, capsule_path, capsule_sha256, authorization):
        """Materialize verified old requests and blobs once, before activation."""
        require(self._phase_authority is not None,
                "PHASE_IMPORT", "phase authority required")
        with self._mutex, self._phase_authority.staging():
            require(not Path(self.phase_import["activation_path"]).exists(),
                    "PHASE_INACTIVE", "phase already activated")
            return self._import_phase_locked(capsule_path=capsule_path,
                capsule_sha256=capsule_sha256, authorization=authorization)

    def _import_phase_locked(self, *, capsule_path, capsule_sha256, authorization):
        from .phase_transition import _read_once, verify_capsule, verify_import_authorization
        require(self.phase_import is not None and
                str(Path(capsule_path).resolve(strict=True)) ==
                    str(Path(self.phase_import["capsule_path"]).resolve(strict=True)) and
                capsule_sha256 == self.phase_import["capsule_sha256"],
                "PHASE_IMPORT", "unapproved capsule")
        raw = _read_once(capsule_path, capsule_sha256)
        capsule = loads(raw)
        requests, _ = verify_capsule(capsule)
        require(authorization == loads(_read_once(self.phase_import["authorization_path"],
                                                  self.phase_import["authorization_sha256"])),
                "PHASE_AUTHORITY", "import authorization file differs")
        verify_import_authorization(self.trust, authorization,
            capsule_sha256=capsule_sha256,
            target_implementation_sha256=digest(self._identity),
            run_id=self.config["run_id"])
        if self._phase_imported:
            # Reconcile a durable import whose caller lost the return value.
            # Only the untouched, inactive two-event transition can replay.
            events = [loads(row[0]) for row in self.db.execute(
                "SELECT body FROM events ORDER BY seq")]
            require(len(events) == 2 and events[0]["kind"] == "OPEN" and
                    events[1] == {"kind": "IMPORT_PHASE", "value": {
                        "capsule_sha256": capsule_sha256,
                        "authorization_sha256": self.phase_import["authorization_sha256"]},
                        "previous": digest(events[0])} and
                    self._head == digest(events[1]) and self.requests == requests and
                    capsule["config"] == self.config and
                    capsule["run_id"] == self.config["run_id"] and
                    self._matches_imported_state(capsule),
                    "PHASE_IMPORT", "import replay differs from durable transition")
            self._verify_imported_blobs(capsule)
            return {"status": "PHASE_IMPORTED_HELD", "capsule_sha256": capsule_sha256,
                    "checkpoint_head": self._head, "model_calls": 0}
        require(capsule["config"] == self.config and capsule["run_id"] == self.config["run_id"] and
                not self.requests and self._matches_imported_state(capsule),
                "PHASE_IMPORT", "new phase is not an exact target")
        for sha, encoded in capsule["blobs"].items():
            body = base64.b64decode(encoded, validate=True)
            require(bytes_digest(body) == sha, "PHASE_BLOB", "import blob differs")
            self.db.execute("INSERT OR IGNORE INTO blobs(hash,body) VALUES (?,?)", (sha, body))
        self._verify_imported_blobs(capsule)
        self._append("IMPORT_PHASE", {"capsule_sha256": capsule_sha256,
                                     "authorization_sha256": self.phase_import["authorization_sha256"]})
        require(set(self.requests) == set(requests), "PHASE_IMPORT", "request projection differs")
        return {"status": "PHASE_IMPORTED_HELD", "capsule_sha256": capsule_sha256,
                "checkpoint_head": self._head, "model_calls": 0}

    def _result(self, id_, kind):
        row = self.requests.get(id_)
        require(row is not None and row["kind"] == kind and "result" in row,
                "PILOT_WAIT", "required prior stage is incomplete")
        return row["result"]

    def _payload(self, action, **fields):
        return {"version": VERSION, "action": action, "run_id": self.config["run_id"],
                "security_scope": self.config["security_scope"], "execution_mode": self.config["execution_mode"], **fields}

    def _trusted(self, receipt, purpose, operation, payload, *, review=False):
        # Verify historical execution/review time, but honor current issuer revocation.
        policy = self.trust.verify(receipt, purpose, at=receipt["issued_at"])
        require(timestamp(receipt["issued_at"]) <= timestamp(now()) and receipt["payload"] == payload and
                operation in policy.operations, "PILOT_ATTESTATION", "signed receipt does not authorize this exact action")
        if review:
            require(policy.can_review and policy.principal == payload["reviewer"] and
                    payload["reviewer_kind"] in {"human", "assistant"} and
                    payload["reviewed_at"] == receipt["issued_at"], "PILOT_REVIEW", "trusted attributed review required")

    def _access(self):
        policy = loads(dumps(self.current_access()))
        validate("graph-access", policy)
        require(policy["tenant"] == self.config["security_scope"], "PILOT_ACCESS", "authenticated scope differs")
        return policy

    def _stamp(self):
        with self.backend._lock:
            snapshot = self.backend.snapshot(self.catalog)
            statuses = self.backend.statuses()
        return {"snapshot_id": snapshot, "statuses_sha256": digest(statuses), "access_sha256": digest(self._access())}

    def _fresh(self, stamp):
        require(self._stamp() == stamp, "PILOT_STALE", "graph, source status or application permission changed; new request required")

    @boundary
    def prepare_native_page(self, id_, *, pdf_bytes, source_id, version, physical_page, start, end):
        pdf_bytes = bytes(pdf_bytes)
        allowed = {r["source_id"]: r for r in self.config["documents"]}.get(source_id)
        require(allowed is not None and allowed["version"] == version and
                allowed["document_sha256"] == bytes_digest(pdf_bytes) and physical_page in allowed["physical_pages"],
                "PILOT_COHORT", "source or physical page outside frozen frame")
        blob = self._blob(pdf_bytes)
        args = dict(pdf_sha256=blob, source_id=source_id, version=version, physical_page=physical_page, start=start, end=end)
        def prepare(_):
            metadata, png, _ = render_source(pdf_bytes, physical_page=physical_page, dpi=144)
            native = _native_text(pdf_bytes, physical_page)
            require(type(start) is int and type(end) is int and 0 <= start < end <= len(native) and native[start:end].strip(),
                    "PILOT_SPAN", "nonempty exact native span required")
            packet = {**args, "render": metadata["render"], "native_text_sha256": text_digest(native),
                      "excerpt": native[start:end], "excerpt_sha256": text_digest(native[start:end])}
            return {"state": "WAIT_SOURCE_REVIEW", "packet": packet, "packet_sha256": digest(packet),
                    "page_png_blob": self._blob(png)}
        return self._step(id_, "PREPARE_SOURCE", args, prepare)

    def source_review_payload(self, prepared_id, *, reviewer, reviewer_kind, reviewed_at, checks):
        prepared = self._result(prepared_id, "PREPARE_SOURCE")
        return self._payload("REVIEW_NATIVE_PAGE", packet_sha256=prepared["packet_sha256"],
            reviewer=reviewer, reviewer_kind=reviewer_kind, reviewed_at=reviewed_at, checks=checks)

    @boundary
    def source_review_material(self, prepared_id):
        """Authorized application reviewer gets original bytes, page image and text.

        This is private source material, not a portable public receipt or authority.
        """
        prepared = self._result(prepared_id, "PREPARE_SOURCE")
        packet = prepared["packet"]
        pdf = self._read_blob(packet["pdf_sha256"])
        native = _native_text(pdf, packet["physical_page"])
        png = self._read_blob(prepared["page_png_blob"])
        require(digest(packet) == prepared["packet_sha256"] and text_digest(native) == packet["native_text_sha256"] and
                bytes_digest(png) == packet["render"]["page_png_sha256"], "PILOT_SOURCE_CHANGED", "review material differs")
        return {"packet": loads(dumps(packet)), "pdf_bytes": pdf, "page_png_bytes": png, "native_text": native}

    @boundary
    def prepare_image_page(self, id_, *, pdf_bytes, source_id, version, physical_page,
                           crop_bbox, transcription, producer, raw_output,
                           fallback_reason="native_absent", native_defect_note=None):
        """Freeze a manually produced image transcription and its exact observed crop."""
        require(isinstance(pdf_bytes, (bytes, bytearray, memoryview)) and
                isinstance(raw_output, (bytes, bytearray, memoryview)),
                "PILOT_IMAGE_PRODUCER", "original PDF and raw manual transcription must be bytes")
        pdf_bytes, raw_output = bytes(pdf_bytes), bytes(raw_output)
        allowed = {r["source_id"]: r for r in self.config["documents"]}.get(source_id)
        require(allowed is not None and allowed["version"] == version and
                allowed["document_sha256"] == bytes_digest(pdf_bytes) and
                physical_page in allowed["physical_pages"], "PILOT_COHORT", "image page outside frozen frame")
        require(type(producer) is str and producer.strip() and type(transcription) is str and
                transcription.strip() and raw_output == transcription.encode("utf-8"),
                "PILOT_IMAGE_PRODUCER", "manual transcription and raw output required")
        require(fallback_reason in {"native_absent", "native_corrupt"} and
                ((fallback_reason == "native_absent" and native_defect_note is None) or
                 (fallback_reason == "native_corrupt" and type(native_defect_note) is str and
                  native_defect_note.strip())), "PILOT_IMAGE_ROUTE", "explicit native defect required")
        pdf_hash, raw_hash = self._blob(pdf_bytes), self._blob(raw_output)
        args = dict(pdf_sha256=pdf_hash, raw_output_sha256=raw_hash, source_id=source_id,
                    version=version, physical_page=physical_page, crop_bbox=crop_bbox,
                    transcription=transcription, producer=producer,
                    fallback_reason=fallback_reason, native_defect_note=native_defect_note)
        def prepare(_):
            metadata, page_png, crop_png = render_source(pdf_bytes, physical_page=physical_page,
                                                        dpi=144, crop=crop_bbox)
            require(fallback_reason != "native_absent" or metadata["native_observation"]["state"] == "absent",
                    "PILOT_IMAGE_ROUTE", "native text is present on purported image-only page")
            full_page = crop_bbox == [0, 0, *metadata["render"]["dimensions"]]
            configuration = {"producer": producer,
                "method": "visual-reading-of-original-full-page" if full_page else "visual-reading-of-original-crop"}
            if native_defect_note is not None:
                configuration["native_defect_note"] = native_defect_note
            candidate = image_candidate(pdf_bytes, source_id=source_id, transcription=transcription,
                raw_output=raw_output, engine="manual-visual-transcription", revision="manual-v1",
                configuration=configuration,
                physical_page=physical_page, dpi=144, crop=crop_bbox,
                input_crop_sha256=metadata["crop"]["png_sha256"], fallback_reason=fallback_reason)
            verify_artifacts(candidate, pdf_bytes=pdf_bytes, raw_output=raw_output,
                             page_png=page_png, crop_png=crop_png)
            return {"state": "WAIT_IMAGE_SOURCE_REVIEW", "candidate": candidate,
                    "candidate_sha256": candidate_hash(candidate),
                    "page_png_blob": self._blob(page_png), "crop_png_blob": self._blob(crop_png)}
        return self._step(id_, "PREPARE_SOURCE_IMAGE", args, prepare)

    @boundary
    def image_review_material(self, prepared_id):
        prepared = self._result(prepared_id, "PREPARE_SOURCE_IMAGE")
        candidate = prepared["candidate"]
        pdf = self._read_blob(candidate["source_sha256"])
        raw = self._read_blob(candidate["ocr"]["raw_output_sha256"])
        page_png = self._read_blob(prepared["page_png_blob"])
        crop_png = self._read_blob(prepared["crop_png_blob"])
        verify_artifacts(candidate, pdf_bytes=pdf, raw_output=raw,
                         page_png=page_png, crop_png=crop_png)
        require(candidate_hash(candidate) == prepared["candidate_sha256"],
                "PILOT_SOURCE_CHANGED", "image candidate changed")
        return {"candidate": loads(dumps(candidate)), "pdf_bytes": pdf,
                "raw_output_bytes": raw, "page_png_bytes": page_png, "crop_png_bytes": crop_png}

    def image_review_payload(self, prepared_id, *, reviewer, reviewer_kind, reviewed_at, checks):
        prepared = self._result(prepared_id, "PREPARE_SOURCE_IMAGE")
        return self._payload("REVIEW_IMAGE_PAGE", candidate_sha256=prepared["candidate_sha256"],
            reviewer=reviewer, reviewer_kind=reviewer_kind, reviewed_at=reviewed_at, checks=checks)

    @boundary
    def accept_image_review(self, id_, *, prepared_id, receipt):
        prepared = self._result(prepared_id, "PREPARE_SOURCE_IMAGE")
        p = receipt["payload"]
        expected = self.image_review_payload(prepared_id, **{k: p[k] for k in
            ("reviewer", "reviewer_kind", "reviewed_at", "checks")})
        self._trusted(receipt, "SOURCE_STATUS", "PAPER_SOURCE_REVIEW", expected, review=True)
        require(set(p["checks"]) == set(IMAGE_CHECKS) and all(v is True for v in p["checks"].values()),
                "PILOT_REVIEW", "all image review checks must pass")
        def accept(_):
            material = self.image_review_material(prepared_id)
            candidate = material["candidate"]
            reviewed = review_image(candidate, pdf_bytes=material["pdf_bytes"],
                raw_output=material["raw_output_bytes"], reviewer=p["reviewer"],
                reviewer_kind=p["reviewer_kind"], reviewed_at=p["reviewed_at"],
                disposition="complete", checks=p["checks"])
            result = handoff(self.catalog, reviewed, pdf_bytes=material["pdf_bytes"],
                raw_output=material["raw_output_bytes"], scope=self.config["security_scope"])
            require(result["status"] == "REVIEWED_TEXT_EVIDENCE" and not result["admitted"],
                    "PILOT_REVIEW", "image transcription remains held")
            self.budget.consume("review_actions")
            self.catalog.put("receipt", receipt)
            return {"state": "WAIT_SOURCE_ADMISSION", "source_id": result["source_snapshot_id"],
                    "evidence_id": result["evidence_id"], "prepared_id": prepared_id,
                    "reviewed_candidate": reviewed}
        result = self._step(id_, "REVIEW_SOURCE_IMAGE", {"prepared_id": prepared_id,
                                                          "receipt": receipt}, accept)
        self._verify_image_review_result(result, prepared_id)
        return result

    def _verify_image_review_result(self, result, prepared_id):
        material = self.image_review_material(prepared_id)
        reviewed = result["reviewed_candidate"]
        verify_artifacts(reviewed, pdf_bytes=material["pdf_bytes"],
                         raw_output=material["raw_output_bytes"],
                         page_png=material["page_png_bytes"], crop_png=material["crop_png_bytes"])
        require(candidate_hash(reviewed) == candidate_hash(material["candidate"]) and
                self.catalog.get(self.catalog.get(result["source_id"], "source")["image_evidence_id"],
                                 "image-evidence-v1") == reviewed,
                "PILOT_SOURCE_CHANGED", "reviewed image source changed")
        verify_image_source(self.catalog, self.catalog.get(result["source_id"], "source"))

    def _reviewed_source(self, prepared, p):
        packet = prepared["packet"]
        source = reviewed_page_source(self.catalog, pdf_bytes=self._read_blob(packet["pdf_sha256"]),
            **{k: packet[k] for k in ("source_id", "version", "physical_page", "start", "end")},
            security_scope=self.config["security_scope"],
            **{k: p[k] for k in ("reviewer", "reviewer_kind", "reviewed_at", "checks")})
        body = self.catalog.get(source, "source")
        require(digest(packet) == prepared["packet_sha256"] and body["text_hash"] == packet["excerpt_sha256"] and
                body["page_lineage"]["native_text_sha256"] == packet["native_text_sha256"] and
                body["page_lineage"]["page_png_sha256"] == packet["render"]["page_png_sha256"],
                "PILOT_SOURCE_CHANGED", "reviewed page differs from packet")
        allowed = {r["source_id"]: r for r in self.config["documents"]}.get(packet["source_id"])
        require(allowed is not None and allowed["version"] == packet["version"] and
                allowed["document_sha256"] == packet["pdf_sha256"] and packet["physical_page"] in allowed["physical_pages"],
                "PILOT_COHORT", "reviewed source differs from frozen frame")
        return source

    @boundary
    def accept_source_review(self, id_, *, prepared_id, receipt):
        prepared = self._result(prepared_id, "PREPARE_SOURCE")
        p = receipt["payload"]
        expected = self.source_review_payload(prepared_id, **{k: p[k] for k in ("reviewer", "reviewer_kind", "reviewed_at", "checks")})
        self._trusted(receipt, "SOURCE_STATUS", "PAPER_SOURCE_REVIEW", expected, review=True)
        require(set(p["checks"]) == set(CHECKS) and all(v is True for v in p["checks"].values()),
                "PILOT_REVIEW", "all source checks must pass")
        def accept(_):
            source = self._reviewed_source(prepared, p)
            self.budget.consume("review_actions")
            self.catalog.put("receipt", receipt)
            return {"state": "WAIT_SOURCE_ADMISSION", "source_id": source,
                    "evidence_id": self.catalog.evidence(source), "prepared_id": prepared_id}
        result = self._step(id_, "REVIEW_SOURCE", {"prepared_id": prepared_id, "receipt": receipt}, accept)
        source = self._reviewed_source(prepared, p)
        require(result["source_id"] == source and result["evidence_id"] == self.catalog.evidence(source),
                "PILOT_SOURCE_CHANGED", "cached source or evidence differs from authenticated review")
        return result

    def _source(self, ref, *, admitted=True):
        matches = [r for r in self.requests.values() if r["kind"] in {"REVIEW_SOURCE", "REVIEW_SOURCE_IMAGE"}
                   and r.get("result", {}).get("source_id") == ref]
        require(len(matches) == 1, "PILOT_SOURCE_REVIEW", "source lacks exactly one pilot review")
        row = matches[0]
        if row["kind"] == "REVIEW_SOURCE":
            self.accept_source_review(row["id"], **row["args"])
            prepared = self._result(row["args"]["prepared_id"], "PREPARE_SOURCE")
            verify_page_source(self.catalog.get(ref, "source"), pdf_bytes=self._read_blob(prepared["packet"]["pdf_sha256"]))
        else:
            self.accept_image_review(row["id"], **row["args"])
        if admitted:
            from .retrieval.security import AccessFilter
            statuses = self.backend.statuses()
            evidence = row["result"]["evidence_id"]
            require(AccessFilter(self._access(), self.catalog, statuses).evidence(evidence),
                    "PILOT_SOURCE_ACCESS", "source is withdrawn, denied or unauthorized")

    def admission_payload(self, review_ids, *, expected_version):
        require(type(review_ids) is list and review_ids, "PILOT_SOURCE", "review IDs required")
        rows = [self.requests.get(r) for r in review_ids]
        require(all(row is not None and row["kind"] in {"REVIEW_SOURCE", "REVIEW_SOURCE_IMAGE"} and
                    "result" in row for row in rows), "PILOT_SOURCE_REVIEW", "review missing")
        refs = sorted(row["result"]["source_id"] for row in rows)
        require(refs and len(refs) == len(set(refs)), "PILOT_SOURCE", "unique reviewed sources required")
        for index, ref in enumerate(refs):
            for other in refs[index + 1:]:
                require(not self._source_overlap(ref, other), "PILOT_SOURCE", "overlapping reviewed source")
        return {"action": "ADMIT", "source_hashes": {r: self.catalog.hash(r) for r in refs},
                "security_scope": self.config["security_scope"], "execution_mode": self.config["execution_mode"],
                "expected_version": expected_version}

    def _source_overlap(self, left_ref, right_ref):
        left, right = [self.catalog.get(ref, "source") for ref in (left_ref, right_ref)]
        if left["source_id"] != right["source_id"] or left["raw_document_hash"] != right["raw_document_hash"]:
            return False
        def region(source):
            if source["representation"] == "reviewed-native-pdf-page-v1":
                item = source["page_lineage"]
                return item["physical_page"], "native", (item["start"], item["end"])
            image = self.catalog.get(source["image_evidence_id"], "image-evidence-v1")
            return image["physical_page"], "image", image["crop"]["bbox"]
        left_page, left_kind, left_region = region(left)
        right_page, right_kind, right_region = region(right)
        if left_page != right_page:
            return False
        if left_kind != right_kind:
            return True  # No native-to-pixel alignment was reviewed.
        if left_kind == "native":
            return max(left_region[0], right_region[0]) < min(left_region[1], right_region[1])
        a, b = left_region, right_region
        return max(a[0], b[0]) < min(a[2], b[2]) and max(a[1], b[1]) < min(a[3], b[3])

    def _committed(self, key, *, authorization, operation_hash=None, plan_hash=None, preflight_hash=None):
        self.backend.audit()
        rows = [r["body"] for r in self.backend.load_catalog().all("transaction") if r["body"]["idempotency_key"] == key]
        require(len(rows) <= 1, "PILOT_TRANSACTION", "duplicate backend receipt")
        if rows:
            receipt = rows[0]
            require(receipt["authorization_hash"] == digest(authorization) and
                    (operation_hash is None or receipt["operation_hash"] == operation_hash) and
                    (plan_hash is None or receipt["plan_hash"] == plan_hash) and
                    (preflight_hash is None or receipt["preflight_hash"] == preflight_hash),
                    "PILOT_TRANSACTION", "backend receipt differs from durable intent")
            return {"state": "TRANSACTION_RECORDED", "receipt": receipt,
                    "historical_receipt_only": True}

    @boundary
    def admit_sources(self, id_, *, review_ids, expected_version, authorization, after_commit=None):
        args = dict(review_ids=review_ids, expected_version=expected_version, authorization=authorization)
        payload = self.admission_payload(review_ids, expected_version=expected_version)
        key = self.config["run_id"] + ":admit:" + id_
        def admit(_):
            recovered = self._committed(key, authorization=authorization, operation_hash=digest(payload))
            if recovered:
                return recovered
            for new_ref in payload["source_hashes"]:
                for old_ref, status in self.backend.statuses().items():
                    if new_ref != old_ref and status["active"] and not status["tombstone"]:
                        require(not self._source_overlap(new_ref, old_ref),
                                "PILOT_SOURCE", "new source overlaps already admitted source")
            for ref in payload["source_hashes"]:
                self._source(ref, admitted=False)
            result = self.backend.admit_sources(self.catalog, list(payload["source_hashes"]), trust=self.trust,
                authorization=authorization, security_scope=self.config["security_scope"],
                execution_mode=self.config["execution_mode"], expected_version=expected_version, key=key)
            if after_commit is not None:
                after_commit()  # fault injection: simulate controller loss after authoritative commit.
            return {"state": "TRANSACTION_RECORDED", "receipt": result["receipt"], "historical_receipt_only": True}
        result = self._step(id_, "ADMIT", args, admit)
        require(result == self._committed(key, authorization=authorization, operation_hash=digest(payload)),
                "PILOT_TRANSACTION", "checkpoint receipt differs from authoritative graph journal")
        return result

    def _pack_fresh(self, compile_id):
        result = self._result(compile_id, "COMPILE")
        self._fresh(result["stamp"])
        pack = self.catalog.get(result["pack_id"], "pack")
        validate_pack(self.catalog, pack, source_status=self.backend.statuses())
        from .retrieval.security import AccessFilter
        acl = AccessFilter(self._access(), self.catalog, self.backend.statuses())
        for ref in pack["closure"]["source_snapshot_ids"]:
            self._source(ref)
        for ref in pack["candidate_ids"]:
            a = self.catalog.get(ref, "candidate")["assertion"]
            require(acl.allows("node", a["subject"]) and acl.allows("node", a["object"]),
                    "PILOT_ACCESS", "candidate endpoints denied")
        self._fresh(result["stamp"])
        return result, pack

    @boundary
    def semantic_execution_context(self, compile_id):
        """Fresh application callback for a separately authorized local execution.

        This does not reserve another model call, sign a response or run a model.
        The durable COMPILE intent must already exist.
        """
        result, pack = self._pack_fresh(compile_id)
        context = {"pack_sha256": self.catalog.hash(result["pack_id"]),
                   "graph_version": pack["graph_version"], "schema_hash": pack["schema_hash"],
                   "source_status": self.backend.statuses(), "graph_access": self._access()}
        self._fresh(result["stamp"])
        return context

    @boundary
    def compile_candidates(self, id_, *, candidates):
        """Candidates are explicit application proposals, not inferred facts."""
        def compile_(created):
            stamp = self._stamp()
            ids = []
            for index, candidate in enumerate(candidates):
                require(set(candidate) == {"assertion", "claim_id", "evidence_ids"}, "PILOT_CANDIDATE", "bounded assertion candidate required")
                for ev in candidate["evidence_ids"]:
                    self._source(self.catalog.get(ev, "evidence")["source_snapshot_id"])
                ids.append(self.catalog.candidate(id_=f"{self.config['run_id']}:{id_}:candidate:{index}",
                    run_id=self.config["run_id"], mode=self.config["execution_mode"],
                    generator="application-proposal-v1", **candidate))
            model = self.config["semantic_model"]
            from .semantic_profile import model_version
            pinned_model = model_version(self.semantic_profile) if self.semantic_profile is not None else model["model_id"]
            pack = compile_pack(self.catalog, id_=f"{self.config['run_id']}:{id_}:pack", run_id=self.config["run_id"],
                candidate_ids=ids, questions=[question(ref, id_=f"q{i}") for i, ref in enumerate(ids)],
                snapshot_id=stamp["snapshot_id"], security_scope=self.config["security_scope"],
                execution_mode=self.config["execution_mode"], model_version=pinned_model, model_profile=self.semantic_profile,
                tokenizer_version=model["tokenizer_id"], token_counter=self.token_counter, created_at=created)
            self._fresh(stamp)
            body = self.catalog.get(pack, "pack")
            self.budget.consume_many({"model_calls": 1, "request_bytes": len(base64.b64decode(body["request_base64"]))})
            return {"state": "WAIT_SEMANTIC_RESPONSE", "pack_id": pack, "pack_sha256": self.catalog.hash(pack),
                    "request_base64": body["request_base64"], "request_sha256": body["wire_request_hash"],
                    "stamp": stamp, "external_execution_only": True, "automatic_retry": False}
        result = self._step(id_, "COMPILE", {"candidates": candidates}, compile_)
        self._pack_fresh(id_)
        return result

    def execution_payload(self, stage_id, *, kind, response_sha256, generated_at, usage, cost,
                          response_source, provider_request_id, local_execution_sha256=None):
        require(kind in {"SEMANTIC", "ANSWER"}, "PILOT_EXECUTION", "unsupported execution kind")
        result = self._result(stage_id, "COMPILE" if kind == "SEMANTIC" else "PREPARE_ANSWER")
        extra = {}
        if kind == "SEMANTIC" and self.semantic_profile is not None:
            self._sha(local_execution_sha256)
            extra = {"local_execution_sha256": local_execution_sha256, "model_profile_sha256": digest(self.semantic_profile)}
        else:
            require(local_execution_sha256 is None, "PILOT_EXECUTION", "unexpected local execution lineage")
        return self._payload(kind + "_RESPONSE", stage_id=stage_id,
            model=self.config["semantic_model" if kind == "SEMANTIC" else "answer_model"],
            pack_sha256=result.get("pack_sha256"), request_sha256=result["request_sha256"],
            response_sha256=response_sha256, generated_at=generated_at, usage=usage, cost=cost,
            response_source=response_source, provider_request_id=provider_request_id, **extra)

    def _execution(self, stage_id, kind, response, receipt, local_execution=None):
        p = receipt["payload"]
        fields = ("generated_at", "usage", "cost", "response_source", "provider_request_id")
        expected = self.execution_payload(stage_id, kind=kind, response_sha256=bytes_digest(response),
            local_execution_sha256=digest(local_execution) if local_execution is not None else None, **{k: p[k] for k in fields})
        self._trusted(receipt, "OBSERVATION", kind + "_IMPORT", expected)
        require(p["response_source"] == "ACTUAL_MODEL_EXECUTION" or
                (self.config["execution_mode"] == "SYNTHETIC" and p["response_source"] == "AUTHORED_SYNTHETIC"),
                "PILOT_EXECUTION", "real mode requires authenticated actual model output")
        require(type(p["provider_request_id"]) is str and bool(p["provider_request_id"]) and
                set(p["usage"]) == {"input_tokens", "output_tokens"} and
                all(type(v) is int and v >= 0 for v in p["usage"].values()) and
                set(p["cost"]) == {"amount", "currency"} and p["cost"]["currency"] == "USD" and
                type(p["cost"]["amount"]) in {int, float} and p["cost"]["amount"] >= 0,
                "PILOT_EXECUTION", "actual usage, USD cost and execution identity required")
        if local_execution is not None:
            require(p["usage"] == {"input_tokens": local_execution["input_tokens"], "output_tokens": local_execution["output_tokens"]} and
                    p["generated_at"] == local_execution["completed_at"] and
                    p["response_source"] == local_execution["response_source"] and p["cost"]["amount"] == local_execution["cost_usd"] and
                    local_execution["execution_preflight_sha256"] == digest(self.semantic_execution_context(stage_id)),
                    "PILOT_EXECUTION", "signed execution receipt differs from local model readback")
        require(timestamp(self.requests[stage_id]["created_at"]) <= timestamp(p["generated_at"]) <= timestamp(receipt["issued_at"]),
                "PILOT_EXECUTION", "execution time outside request/receipt interval")

    def _one_import(self, id_, kind, stage_key, stage_id):
        require(not any(row["id"] != id_ and row["kind"] == kind and row["args"][stage_key] == stage_id
                        for row in self.requests.values()), "PILOT_EXECUTION_ALREADY_IMPORTED",
                "one external outcome per exported request; unknown outcomes require reconciliation")

    @boundary
    def record_semantic_response(self, id_, *, compile_id, response, execution_receipt, local_execution=None):
        require(compile_id not in self._historical_request_ids,
                "PHASE_HISTORICAL_REQUEST", "phase import does not authorize an outcome for a historical compile")
        result, pack = self._pack_fresh(compile_id)
        require(type(response) is bytes, "PILOT_EXECUTION", "original response bytes required")
        self._execution(compile_id, "SEMANTIC", response, execution_receipt, local_execution)
        self._one_import(id_, "SEMANTIC_RESPONSE", "compile_id", compile_id)
        def record(_):
            ids = record_response(self.catalog, result["pack_id"], response,
                                  completed_at=execution_receipt["payload"]["generated_at"], local_execution=local_execution)
            if local_execution is None and all(self.catalog.get(ref, "observation")["status"] == "OK" for ref in ids):
                require(loads(response)["usage"] == execution_receipt["payload"]["usage"],
                        "PILOT_EXECUTION", "wire usage differs from execution receipt")
            # Execution receipts are private orchestration evidence. OBSERVATION
            # catalog receipts have the existing, narrower observation_hash contract.
            self._fresh(result["stamp"])
            return {"state": "WAIT_OBSERVATION_ATTESTATION", "observation_ids": ids, "compile_id": compile_id}
        arguments = {"compile_id": compile_id, "response_blob": self._blob(response), "execution_receipt": execution_receipt}
        if local_execution is not None:
            arguments["local_execution"] = local_execution
        return self._step(id_, "SEMANTIC_RESPONSE", arguments, record)

    @boundary
    def resolve_plan(self, id_, *, response_id, attestations):
        response = self._result(response_id, "SEMANTIC_RESPONSE")
        imported = self.requests[response_id]["args"]
        self._execution(response["compile_id"], "SEMANTIC", self._read_blob(imported["response_blob"]), imported["execution_receipt"], imported.get("local_execution"))
        compiled, pack = self._pack_fresh(response["compile_id"])
        expected_ids = record_response(self.catalog, compiled["pack_id"], self._read_blob(imported["response_blob"]),
            completed_at=imported["execution_receipt"]["payload"]["generated_at"], local_execution=imported.get("local_execution"))
        require(response["compile_id"] == imported["compile_id"] and response["observation_ids"] == expected_ids,
                "PILOT_EXECUTION", "checkpoint observations differ from authenticated model exchange")
        require(set(attestations) == set(response["observation_ids"]), "PILOT_ATTESTATION", "exact observation attestation coverage required")
        for ref, receipt in attestations.items():
            validate_observation(self.catalog, ref)
            verify_observation_attestation(self.trust, receipt, self.catalog.record(ref, "observation"))
        def resolve(created):
            for receipt in attestations.values():
                self.catalog.put("receipt", receipt)
            batch = solve(self.catalog, run_id=self.config["run_id"], candidate_ids=pack["candidate_ids"],
                observation_ids=response["observation_ids"], snapshot_id=pack["snapshot_id"], budget=self.budget, created_at=created)
            resolutions = project_resolutions(self.catalog, batch)
            operations, evaluations = [], []
            for resolution in resolutions:
                r = self.catalog.get(resolution, "resolution")
                ev = evaluate_policy(self.catalog, candidate_id=r["candidate_id"], batch_id=batch,
                    policy_version=self.service.policy_version, population=self.service.population, at=created)
                evaluations.append(ev)
                if r["outcome"] == "SELECTED":
                    operations.append(add_operation(self.catalog, resolution, ev, operation_id="add:" + r["candidate_id"]))
            self._fresh(compiled["stamp"])
            plan = create_plan(self.catalog, run_id=self.config["run_id"], snapshot_id=pack["snapshot_id"],
                operations=operations, security_scope=self.config["security_scope"], execution_mode=self.config["execution_mode"],
                idempotency_key=self.config["run_id"] + ":publish:" + id_, policy_version=self.service.policy_version,
                source_status=self.backend.statuses(), created_at=created) if operations else None
            return {"state": "WAIT_PLAN_REVIEW" if plan else "HELD_NO_SELECTED_OPERATION", "plan_id": plan,
                    "batch_id": batch, "resolution_ids": resolutions, "evaluation_ids": evaluations,
                    "compile_id": response["compile_id"], "response_id": response_id}
        return self._step(id_, "RESOLVE", {"response_id": response_id, "attestations": attestations}, resolve)

    @boundary
    def preflight_plan(self, id_, *, resolve_id):
        result = self._result(resolve_id, "RESOLVE")
        self.resolve_plan(resolve_id, **self.requests[resolve_id]["args"])
        self._pack_fresh(result["compile_id"])
        require(result["plan_id"] is not None, "PILOT_WAIT", "no selected plan")
        def preflight(_):
            receipt = self.service.preflight(self.catalog, result["plan_id"], reviewed=True)
            self.catalog.put("receipt", receipt)
            return {"state": "WAIT_AUTHORIZATION", "preflight": receipt, "resolve_id": resolve_id}
        return self._step(id_, "PREFLIGHT", {"resolve_id": resolve_id}, preflight)

    @boundary
    def publish_plan(self, id_, *, preflight_id, authorization, after_commit=None):
        preflight = self._result(preflight_id, "PREFLIGHT")
        resolved = self._result(preflight["resolve_id"], "RESOLVE")
        plan_id = resolved["plan_id"]
        plan = self.catalog.get(plan_id, "plan")
        def publish(_):
            recovered = self._committed(plan["idempotency_key"], authorization=authorization,
                plan_hash=self.catalog.hash(plan_id), preflight_hash=digest(preflight["preflight"]))
            if recovered:
                return recovered
            self.resolve_plan(preflight["resolve_id"], **self.requests[preflight["resolve_id"]]["args"])
            self._pack_fresh(resolved["compile_id"])
            self.budget.consume("review_actions")
            result = self.service.publish(self.catalog, plan_id, authorization=authorization, preflight=preflight["preflight"])
            if after_commit is not None:
                after_commit()
            return {"state": "TRANSACTION_RECORDED", "receipt": result["receipt"], "historical_receipt_only": True}
        result = self._step(id_, "PUBLISH", {"preflight_id": preflight_id, "authorization": authorization}, publish)
        require(result == self._committed(plan["idempotency_key"], authorization=authorization,
                plan_hash=self.catalog.hash(plan_id), preflight_hash=digest(preflight["preflight"])),
                "PILOT_TRANSACTION", "checkpoint receipt differs from authoritative graph journal")
        return result

    @boundary
    def retrieve(self, id_, *, request):
        from .retrieval.service import GraphRAGQueryService, HybridRetriever
        from .retrieval.store import SQLiteGraphAdapter
        require(request["text"] in self.config["questions"] and request["requesting_component"].startswith("downstream") and
                not request["include_historical"] and not request["include_superseded"],
                "PILOT_QUERY", "frozen current-state downstream question required")
        def retrieve_(_):
            stamp = self._stamp()
            retriever = HybridRetriever(SQLiteGraphAdapter(self.backend, self.catalog), catalog=self.catalog,
                                        access_policy=self._access(), run_budget=self.budget)
            result = GraphRAGQueryService(retriever).query(request)
            for citation in result["context"]["citations"]:
                self._source(citation["source_snapshot_id"])
            self._fresh(stamp)
            return {"state": "CONTEXT_ONLY", "context_id": result["answer_context_id"], "stamp": stamp}
        result = self._step(id_, "RETRIEVE", {"request": request}, retrieve_)
        self._fresh(result["stamp"])
        return result

    def _answer_args(self, retrieval_id, question_text):
        result = self._result(retrieval_id, "RETRIEVE")
        self._fresh(result["stamp"])
        require(question_text in self.config["questions"] and
                question_text == self.requests[retrieval_id]["args"]["request"]["text"],
                "PILOT_QUERY", "answer question differs from frozen retrieval")
        for citation in self.catalog.get(result["context_id"], "graphrag-answer")["citations"]:
            self._source(citation["source_snapshot_id"])
        model = self.config["answer_model"]
        return dict(context_id=result["context_id"], current_access=self._access(), question=question_text,
                    model_id=model["model_id"], model_revision=model["model_revision"], tokenizer_id=model["tokenizer_id"])

    @boundary
    def prepare_answer(self, id_, *, retrieval_id, question_text):
        from .paper_answer import draft_answer
        args = self._answer_args(retrieval_id, question_text)
        def prepare(_):
            def pause(prompt):
                raise _PauseAnswer(prompt)
            try:
                draft = draft_answer(self.catalog, self.backend, generate=pause, **args)
                return {"state": draft["status"], "draft": draft}
            except _PauseAnswer as stopped:
                self._answer_args(retrieval_id, question_text)
                self.budget.consume_many({"model_calls": 1, "request_bytes": len(stopped.prompt)})
                return {"state": "WAIT_ANSWER_RESPONSE", "request_sha256": bytes_digest(stopped.prompt),
                        "request_base64": base64.b64encode(stopped.prompt).decode("ascii"),
                        "external_execution_only": True, "automatic_retry": False}
        return self._step(id_, "PREPARE_ANSWER", {"retrieval_id": retrieval_id, "question_text": question_text}, prepare)

    @boundary
    def record_answer_response(self, id_, *, prepared_id, response, execution_receipt):
        from .paper_answer import draft_answer
        prepared = self._result(prepared_id, "PREPARE_ANSWER")
        args = self.requests[prepared_id]["args"]
        answer_args = self._answer_args(**args)
        require(prepared["state"] == "WAIT_ANSWER_RESPONSE" and type(response) is bytes, "PILOT_WAIT", "no pending answer request")
        self._execution(prepared_id, "ANSWER", response, execution_receipt)
        self._one_import(id_, "ANSWER_RESPONSE", "prepared_id", prepared_id)
        def record(_):
            def actual(prompt):
                require(bytes_digest(prompt) == prepared["request_sha256"], "PILOT_PROMPT_CHANGED", "answer request differs")
                return response
            draft = draft_answer(self.catalog, self.backend, generate=actual, **answer_args)
            return {"state": "WAIT_ANSWER_REVIEW" if draft["review_required"] else draft["status"],
                    "draft": draft, "prepared_id": prepared_id}
        return self._step(id_, "ANSWER_RESPONSE", {"prepared_id": prepared_id,
            "response_blob": self._blob(response), "execution_receipt": execution_receipt}, record)

    def answer_review_payload(self, response_id, *, reviewer, reviewer_kind, reviewed_at, claim_support):
        draft = self._result(response_id, "ANSWER_RESPONSE")["draft"]
        return self._payload("REVIEW_ANSWER", draft_sha256=draft["sha256"], reviewer=reviewer,
            reviewer_kind=reviewer_kind, reviewed_at=reviewed_at, claim_support=claim_support)

    @boundary
    def review_answer(self, id_, *, response_id, receipt):
        from .paper_answer import review_answer
        result = self._result(response_id, "ANSWER_RESPONSE")
        imported = self.requests[response_id]["args"]
        self._execution(result["prepared_id"], "ANSWER", self._read_blob(imported["response_blob"]), imported["execution_receipt"])
        require(result["prepared_id"] == imported["prepared_id"] and
                result["draft"]["response_sha256"] == imported["response_blob"],
                "PILOT_EXECUTION", "draft differs from authenticated external answer")
        p = receipt["payload"]
        fields = {k: p[k] for k in ("reviewer", "reviewer_kind", "reviewed_at", "claim_support")}
        self._trusted(receipt, "SOURCE_STATUS", "PAPER_ANSWER_REVIEW",
                      self.answer_review_payload(response_id, **fields), review=True)
        args = self.requests[result["prepared_id"]]["args"]
        self._answer_args(**args)
        def review(_):
            self.budget.consume("review_actions")
            reviewed = review_answer(self.catalog, self.backend, draft=result["draft"],
                expected_draft_sha256=result["draft"]["sha256"], current_access=self._access(), **fields)
            self.catalog.put("receipt", receipt)
            return {"state": reviewed["status"], "review": reviewed, "issue_23_complete": False}
        return self._step(id_, "REVIEW_ANSWER", {"response_id": response_id, "receipt": receipt}, review)

    def status(self):
        """Historical workflow status, never current source/answer authorization."""
        return {"version": VERSION, "run_id": self.config["run_id"], "execution_mode": self.config["execution_mode"],
                "requests": [{"id": r["id"], "kind": r["kind"], "state": r.get("result", {}).get("state", "INTENT_PENDING")}
                             for r in self.requests.values()], "checkpoint_head": self._head,
                "budget": self.budget.snapshot(), "backend_audit": self.backend.audit(),
                "provider_calls_by_service": 0, "production_graph_writes": 0, "issue_23_complete": False}
