"""Owned SQLite restore/replay regressions for issue 102; no live phase state."""
from __future__ import annotations

from contextlib import nullcontext
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

# A direct -I test invocation must import this checkout, not an installed copy.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from trace_gc.canonical import bytes_digest
from trace_gc.budget import RunBudget
from trace_gc.errors import ContractError
from trace_gc.phase_authority import PhaseAuthority
from trace_gc import phase_transition as transition
from trace_gc.trust import IssuerPolicy, Signer, TrustStore


class PhaseRestoreSidecarTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get("ISSUE102_TEST_TMPDIR"))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.capsule_dir = self.root / "capsule"
        self.capsule_dir.mkdir()
        backup_hashes, logical = {}, {}
        for name in ("checkpoint", "graph", "budget", "application_journal"):
            db = self.capsule_dir / f"{name}.sqlite3"
            if name == "budget":
                limits = {"retrieval_requests": 1, "model_calls": 1, "retries": 0,
                          "solver_expansions": 1, "review_actions": 1,
                          "request_bytes": 14120}
                with RunBudget(db, "authored-sidecar-run", limits) as budget:
                    budget.db.execute("PRAGMA journal_mode=WAL")
                    budget.consume_many({"model_calls": 1, "request_bytes": 14120})
                    self.assertEqual(budget.snapshot()["used"]["model_calls"], 1)
            else:
                connection = sqlite3.connect(db)
                try:
                    connection.execute("PRAGMA journal_mode=WAL")
                    connection.execute("CREATE TABLE retained (id INTEGER PRIMARY KEY, value TEXT)")
                    connection.execute("INSERT INTO retained VALUES (1, ?)", (name + "-preserved",))
                    connection.commit()
                finally:
                    connection.close()
            self.assertFalse(Path(str(db) + "-wal").exists())
            backup_hashes[name] = bytes_digest(db.read_bytes())
            reader = sqlite3.connect(f"file:{db.as_posix()}?mode=ro&immutable=1", uri=True)
            try:
                logical[name] = transition.logical_state(reader)
            finally:
                reader.close()
        self.capsule = {"run_id": "authored-sidecar-run",
                        "database_backup_sha256": backup_hashes,
                        "database_state": logical}
        self.capsule_path = self.capsule_dir / "capsule.json"
        self.capsule_path.write_bytes(json.dumps(self.capsule, sort_keys=True).encode())
        self.capsule_sha = bytes_digest(self.capsule_path.read_bytes())
        self.target = self.root / "inactive-target"
        self.signer = Signer.ephemeral("authored-phase-reviewer")
        self.trust = TrustStore()
        self.trust.enroll(self.signer.issuer, IssuerPolicy(
            self.signer.public_key(), "authored reviewer", frozenset({"AUTHORIZATION"}),
            frozenset({"PHASE_IMPORT"}), frozenset({"authored-run"}),
            frozenset({"SYNTHETIC"}), can_review=True))
        self.identity = "authored-target-identity"
        self.authorization = self.signer.issue("AUTHORIZATION", {
            "version": transition.AUTH_VERSION, "operation": "PHASE_IMPORT",
            "capsule_sha256": self.capsule_sha,
            "target_implementation_sha256": self.identity,
            "run_id": self.capsule["run_id"]})
        authority = object.__new__(PhaseAuthority)
        authority.binding = {
            "capsule_path": str(self.capsule_path.resolve()),
            "capsule_sha256": self.capsule_sha,
            "implementation_sha256": self.identity,
            "run_id": self.capsule["run_id"],
            "activation_path": str(self.root / "inactive-pointer.json"),
        }
        authority.trust = self.trust
        authority.staging = lambda: nullcontext()
        authority.verify_fence = lambda: None
        self.authority = authority

    def restore(self, authorization=None):
        # The capsule/fence are synthetic; SQLite restore, signed PHASE_IMPORT,
        # byte pins, phase binding, inventory and exact replay remain real.
        with patch.object(transition, "verify_capsule", lambda body: None):
            return transition.restore_target(
                capsule_path=self.capsule_path, capsule_sha256=self.capsule_sha,
                target_root=self.target,
                authorization=self.authorization if authorization is None else authorization,
                trust=self.trust, target_implementation_sha256=self.identity,
                phase_authority=self.authority)

    def assert_only_restored_files(self):
        self.assertEqual({p.name for p in self.target.iterdir()},
                         {"graph.sqlite3", "budget.sqlite3", "phase-restore.json"})

    def assert_archived_state(self):
        self.assertEqual(self.capsule["database_backup_sha256"], {
            name: bytes_digest((self.capsule_dir / f"{name}.sqlite3").read_bytes())
            for name in self.capsule["database_backup_sha256"]})
        self.assertEqual(bytes_digest(self.capsule_path.read_bytes()), self.capsule_sha)
        self.assertFalse(Path(self.authority.binding["activation_path"]).exists())

    def assert_restored_state(self):
        for name in ("graph", "budget"):
            db = self.target / f"{name}.sqlite3"
            connection = sqlite3.connect(db.as_uri() + "?mode=ro&immutable=1", uri=True)
            try:
                self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone(), ("ok",))
                state = transition._tables(connection)
                state["tables"].pop("trace_phase_binding")
                state["objects"] = [row for row in state["objects"]
                                    if row[1] != "trace_phase_binding"]
                self.assertEqual(transition.digest(state), self.capsule["database_state"][name])
                if name == "budget":
                    used = json.loads(connection.execute(
                        "SELECT used FROM trace_budgets WHERE run_id=?",
                        (self.capsule["run_id"],)).fetchone()[0])
                    self.assertEqual((used["model_calls"], used["request_bytes"], used["retries"]),
                                     (1, 14120, 0))
            finally:
                connection.close()
        self.assert_only_restored_files()
        self.assert_archived_state()

    def restore_until_process_exit(self):
        pid = os.fork()
        if pid == 0:
            try:
                self.restore()
            finally:
                os._exit(2)
        _, status = os.waitpid(pid, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 91)
        self.assert_archived_state()

    @unittest.skipUnless(hasattr(os, "fork"), "requires a process interruption fixture")
    def test_process_interruption_between_create_and_insert_replays(self):
        original = sqlite3.connect

        class InterruptedConnection(sqlite3.Connection):
            def execute(self, statement, *args, **kwargs):
                result = super().execute(statement, *args, **kwargs)
                if statement.startswith("CREATE TABLE trace_phase_binding"):
                    if self.in_transaction:
                        os._exit(91)
                return result

        def connect(path, *args, **kwargs):
            if path == ":memory:":
                kwargs["factory"] = InterruptedConnection
            return original(path, *args, **kwargs)

        with patch.object(sqlite3, "connect", side_effect=connect):
            self.restore_until_process_exit()
        self.assertEqual(list(self.target.iterdir()), [])
        self.assertEqual(self.restore()["status"], "INACTIVE_RESTORED_NO_MODEL_CALL")
        self.assert_restored_state()

    @unittest.skipUnless(hasattr(os, "fork"), "requires a process interruption fixture")
    def test_process_interruption_after_stage_before_database_publish_replays(self):
        def interrupt(source, destination):
            os._exit(91)

        with patch.object(os, "replace", side_effect=interrupt):
            self.restore_until_process_exit()
        staged = self.target / "graph.sqlite3.pending"
        self.assertEqual(list(self.target.iterdir()), [staged])
        original = staged.stat()
        raw = staged.read_bytes()
        self.restore()
        graph = self.target / "graph.sqlite3"
        self.assertEqual(graph.stat().st_ino, original.st_ino)
        self.assertEqual(graph.read_bytes(), raw)
        self.assert_restored_state()

    @unittest.skipUnless(hasattr(os, "fork"), "requires a process interruption fixture")
    def test_process_interruption_during_receipt_write_replays(self):
        original = Path.open

        class InterruptedReceipt:
            def __init__(self, stream):
                self.stream = stream

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                pass

            def write(self, raw):
                self.stream.write(raw[:23])
                self.stream.flush()
                os.fsync(self.stream.fileno())
                os._exit(91)

        def open_path(path, *args, **kwargs):
            stream = original(path, *args, **kwargs)
            if path.name.startswith("phase-restore.json.") and args == ("xb",):
                return InterruptedReceipt(stream)
            return stream

        with patch.object(Path, "open", open_path):
            self.restore_until_process_exit()
        self.assertFalse((self.target / "phase-restore.json").exists())
        pending, = self.target.glob("phase-restore.json.*.pending")
        prefix = pending.read_bytes()
        self.assertEqual(len(prefix), 23)
        self.restore()
        self.assertTrue((self.target / "phase-restore.json").read_bytes().startswith(prefix))
        self.assert_restored_state()

    @unittest.skipUnless(hasattr(os, "fork"), "requires a process interruption fixture")
    def test_process_interruption_after_receipt_link_replays_without_replacement(self):
        link = os.link

        def interrupt(source, destination):
            link(source, destination)
            os._exit(91)

        with patch.object(os, "link", side_effect=interrupt):
            self.restore_until_process_exit()
        receipt = self.target / "phase-restore.json"
        original = receipt.stat()
        raw = receipt.read_bytes()
        self.assertEqual(original.st_nlink, 2)
        self.restore()
        self.assertEqual(receipt.stat().st_ino, original.st_ino)
        self.assertEqual(receipt.read_bytes(), raw)
        self.assert_restored_state()

    def test_mismatched_final_binding_and_receipt_leave_target_unchanged(self):
        self.restore()
        receipt = self.target / "phase-restore.json"
        raw = receipt.read_bytes()
        receipt.write_bytes(raw[:23])
        before = {item.name: item.read_bytes() for item in self.target.iterdir()}
        with self.assertRaisesRegex(ContractError, "existing restore receipt conflicts"):
            self.restore()
        self.assertEqual({item.name: item.read_bytes() for item in self.target.iterdir()}, before)
        receipt.write_bytes(raw)
        budget = self.target / "budget.sqlite3"
        with sqlite3.connect(budget) as connection:
            connection.execute("UPDATE trace_phase_binding SET binding_sha256='different'")
        connection.close()
        before = {item.name: item.read_bytes() for item in self.target.iterdir()}
        with self.assertRaisesRegex(ContractError, "partial binding changed"):
            self.restore()
        self.assertEqual({item.name: item.read_bytes() for item in self.target.iterdir()}, before)
        self.assert_archived_state()

    def assert_pending_preflight_holds(self, rejected_pending):
        before = {item.name: item.read_bytes() for item in self.target.iterdir()}
        inspect_store = transition._restore_store_state

        def inspect(path, expected, binding, *, pending=False):
            if pending and path == rejected_pending:
                raise ContractError("PHASE_BACKUP", "partial binding changed")
            return inspect_store(path, expected, binding, pending=pending)

        with patch.object(transition, "_restore_store_state", side_effect=inspect):
            with self.assertRaisesRegex(ContractError, "partial binding changed") as caught:
                self.restore()
        self.assertEqual(caught.exception.code, "PHASE_BACKUP")
        self.assertEqual({item.name: item.read_bytes() for item in self.target.iterdir()}, before)
        self.assert_archived_state()

    def test_pending_store_check_runs_beside_an_exact_final_and_receipt(self):
        self.restore()
        for name in ("graph", "budget"):
            with self.subTest(store=name):
                final = self.target / f"{name}.sqlite3"
                pending = self.target / f"{name}.sqlite3.pending"
                pending.write_bytes(final.read_bytes())
                self.assert_pending_preflight_holds(pending)
                pending.unlink()  # Disposable fixture only.
        self.assert_restored_state()

    def test_all_pending_store_checks_finish_before_recovery_changes_either_store(self):
        self.target.mkdir()
        for name in ("graph", "budget"):
            pending = self.target / f"{name}.sqlite3.pending"
            pending.write_bytes((self.capsule_dir / f"{name}.sqlite3").read_bytes())
        self.assert_pending_preflight_holds(self.target / "budget.sqlite3.pending")
        self.assertFalse((self.target / "graph.sqlite3").exists())
        self.assertFalse((self.target / "budget.sqlite3").exists())
        self.assertFalse((self.target / "phase-restore.json").exists())

    def test_legacy_unbound_database_and_pending_backup_reconcile(self):
        self.target.mkdir()
        graph = self.target / "graph.sqlite3"
        graph.write_bytes((self.capsule_dir / graph.name).read_bytes())
        pending = self.target / "budget.sqlite3.pending"
        raw = (self.capsule_dir / "budget.sqlite3").read_bytes()
        pending.write_bytes(raw)
        self.restore()
        preserved, = self.target.glob("budget.sqlite3.failed.*")
        self.assertEqual(preserved.read_bytes(), raw)
        self.assert_archived_state()
        preserved.unlink()  # Disposable fixture only.
        self.assert_restored_state()

    def test_unknown_staged_receipt_is_preserved(self):
        self.restore()
        receipt = self.target / "phase-restore.json"
        binding = transition.digest(self.authority.binding)
        pending = receipt.with_name(f"{receipt.name}.{binding}.pending")
        pending.write_bytes(b"foreign")
        before = {item.name: item.read_bytes() for item in self.target.iterdir()}
        with self.assertRaisesRegex(ContractError, "pending restore receipt conflicts"):
            self.restore()
        self.assertEqual({item.name: item.read_bytes() for item in self.target.iterdir()}, before)

    def test_staged_sidecars_and_unrelated_receipt_alias_are_preserved(self):
        self.restore()
        sidecar = self.target / "graph.sqlite3.pending-wal"
        sidecar.write_bytes(b"foreign staged WAL")
        with self.assertRaisesRegex(ContractError, "partial target has unknown content"):
            self.restore()
        self.assertEqual(sidecar.read_bytes(), b"foreign staged WAL")
        sidecar.unlink()  # Disposable fixture only.
        receipt = self.target / "phase-restore.json"
        alias = self.root / "unrelated-receipt.json"
        os.link(receipt, alias)
        with self.assertRaisesRegex(ContractError, "partial target has aliased content"):
            self.restore()
        self.assertEqual(receipt.read_bytes(), alias.read_bytes())
        self.assert_archived_state()

    def test_wal_readback_creates_no_sidecars(self):
        graph = self.capsule_dir / "graph.sqlite3"
        self.assertEqual(transition._file_logical(graph),
                         self.capsule["database_state"]["graph"])
        self.assertFalse(Path(str(graph) + "-wal").exists())
        self.assertFalse(Path(str(graph) + "-shm").exists())

    def test_sidecar_appearing_during_readback_is_rejected_and_preserved(self):
        graph = self.capsule_dir / "graph.sqlite3"
        wal = Path(str(graph) + "-wal")
        original = transition.logical_state

        def concurrent_sidecar(connection):
            result = original(connection)
            wal.write_bytes(b"foreign-during-readback")
            return result

        with patch.object(transition, "logical_state", side_effect=concurrent_sidecar):
            with self.assertRaisesRegex(ContractError,
                                        "SQLite sidecar appeared during logical read"):
                transition._file_logical(graph)
        self.assertEqual(wal.read_bytes(), b"foreign-during-readback")

    def test_signed_restore_and_lost_coordinator_result_reconcile_exactly(self):
        first = self.restore()
        self.assertEqual(first["status"], "INACTIVE_RESTORED_NO_MODEL_CALL")
        self.assert_only_restored_files()
        self.assertEqual(first["bound_graph_logical_sha256"],
                         transition._file_logical(self.target / "graph.sqlite3"))
        self.assertEqual(first["bound_budget_logical_sha256"],
                         transition._file_logical(self.target / "budget.sqlite3"))
        receipt_before = (self.target / "phase-restore.json").read_bytes()
        graph_before = (self.target / "graph.sqlite3").read_bytes()
        budget_before = (self.target / "budget.sqlite3").read_bytes()
        # The external coordinator result is intentionally absent. Repeating
        # the same signed request must read back the durable public result.
        self.assertEqual(self.restore(), first)
        self.assert_only_restored_files()
        self.assertEqual((self.target / "phase-restore.json").read_bytes(), receipt_before)
        self.assertEqual((self.target / "graph.sqlite3").read_bytes(), graph_before)
        self.assertEqual((self.target / "budget.sqlite3").read_bytes(), budget_before)
        self.assert_restored_state()

    def test_foreign_wal_and_shm_rejected_without_cleanup(self):
        self.restore()
        graph = self.target / "graph.sqlite3"
        for suffix, raw in (("-wal", b""),
                            ("-wal", b"foreign-uncheckpointed-data"),
                            ("-shm", b"foreign-shared-memory")):
            sidecar = Path(str(graph) + suffix)
            sidecar.write_bytes(raw)
            with self.assertRaises(ContractError) as caught:
                transition._file_logical(graph)
            self.assertEqual(caught.exception.code, "PHASE_SQLITE")
            with self.assertRaisesRegex(ContractError, "partial target has unknown content"):
                self.restore()
            self.assertEqual(sidecar.read_bytes(), raw)
            sidecar.unlink()  # Disposable fixture only.
        self.assert_only_restored_files()

    def test_interruption_after_markers_before_receipt_reconciles(self):
        with patch.object(transition, "_file_logical",
                          side_effect=RuntimeError("authored interruption after markers")):
            with self.assertRaisesRegex(RuntimeError, "authored interruption"):
                self.restore()
        self.assertTrue((self.target / "graph.sqlite3").is_file())
        self.assertTrue((self.target / "budget.sqlite3").is_file())
        self.assertFalse((self.target / "phase-restore.json").exists())
        self.assertEqual({p.name for p in self.target.iterdir()},
                         {"graph.sqlite3", "budget.sqlite3"})
        recovered = self.restore()
        self.assertEqual(recovered["status"], "INACTIVE_RESTORED_NO_MODEL_CALL")
        self.assert_only_restored_files()

    def test_changed_capsule_binding_authorization_and_foreign_target_hold(self):
        self.restore()
        target_before = {p.name: p.read_bytes() for p in self.target.iterdir()}
        backups_before = {name: (self.capsule_dir / f"{name}.sqlite3").read_bytes()
                          for name in self.capsule["database_backup_sha256"]}
        self.authority.binding["implementation_sha256"] = "changed"
        with self.assertRaises(ContractError):
            self.restore()
        self.authority.binding["implementation_sha256"] = self.identity
        stale = self.signer.issue("AUTHORIZATION", self.authorization["payload"],
            issued_at="2020-01-01T00:00:00Z", expires_at="2020-01-01T00:01:00Z")
        with self.assertRaises(ContractError):
            self.restore(stale)
        (self.target / "foreign.txt").write_bytes(b"unreviewed")
        with self.assertRaisesRegex(ContractError, "partial target has unknown content"):
            self.restore()
        self.assertEqual((self.target / "foreign.txt").read_bytes(), b"unreviewed")
        (self.target / "foreign.txt").unlink()  # Disposable fixture only.
        self.assertEqual({p.name: p.read_bytes() for p in self.target.iterdir()},
                         target_before)
        self.capsule_path.write_bytes(self.capsule_path.read_bytes() + b" ")
        with self.assertRaisesRegex(ContractError, "pinned phase bytes changed"):
            self.restore()
        self.assertEqual({p.name: p.read_bytes() for p in self.target.iterdir()},
                         target_before)
        self.assertEqual({name: (self.capsule_dir / f"{name}.sqlite3").read_bytes()
                          for name in backups_before}, backups_before)

    def test_signed_conflicting_import_authorizations_leave_restored_state_unchanged(self):
        self.restore()
        target_before = {p.name: p.read_bytes() for p in self.target.iterdir()}
        backups_before = {name: (self.capsule_dir / f"{name}.sqlite3").read_bytes()
                          for name in self.capsule["database_backup_sha256"]}
        for field, wrong in (("capsule_sha256", "0" * 64),
                             ("target_implementation_sha256", "other-target"),
                             ("run_id", "other-run")):
            with self.subTest(field=field):
                payload = dict(self.authorization["payload"])
                payload[field] = wrong
                conflicting = self.signer.issue("AUTHORIZATION", payload)
                with self.assertRaisesRegex(ContractError,
                                            "exact reviewed phase authorization required"):
                    self.restore(conflicting)
                self.assertEqual({p.name: p.read_bytes() for p in self.target.iterdir()},
                                 target_before)
                self.assertEqual({name: (self.capsule_dir / f"{name}.sqlite3").read_bytes()
                                  for name in backups_before}, backups_before)


if __name__ == "__main__":
    unittest.main()
