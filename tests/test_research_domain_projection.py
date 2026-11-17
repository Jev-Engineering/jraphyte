"""Pure snapshot and classification operation contracts, independent of storage."""
from contextlib import closing
from pathlib import Path
import sqlite3
from types import SimpleNamespace
import unittest

from trace_gc.canonical import digest, dumps, load
from trace_gc.domain_publication import (
    apply_operations, audit_history, classification_identity, classification_operation, migration_operation,
    receipt_projection, snapshot_body, verify_projection,
)
from trace_gc.domains import create_assignment
from trace_gc.errors import ContractError
from trace_gc.schema import validate
from test_research_domain_contracts import REVIEW, fixture_catalog


class PublicationProjectionTests(unittest.TestCase):
    def setUp(self):
        self.catalog, self.taxonomy, self.source, _ = fixture_catalog()
        self.state = {"graph_version": 1, "schema_id": "schema:fixture", "schema_hash": "0" * 64,
                      "nodes": {}, "assertions": {}, "source_epochs": {self.source: 0}}

    def test_initialization_is_explicit_and_preserves_historical_snapshot_bytes(self):
        original = snapshot_body(self.state)
        migration = migration_operation(operation_id="initialize", reason="Reviewed migration fixture")
        projection = apply_operations(self.catalog, original, [migration], security_scope="test")
        self.assertEqual(classification_identity(original)["revision"], 0)
        self.assertFalse(classification_identity(original)["migrated"])
        self.assertEqual(original, self.state)
        self.assertEqual(projection, {"contract_version": 1, "revision": 1, "assignments": {}})
        with self.assertRaises(ContractError) as caught:
            apply_operations(self.catalog, {**original, "classifications": projection}, [migration], security_scope="test")
        self.assertEqual(caught.exception.code, "DOMAIN_MIGRATION")

    def test_projection_binds_exact_assignment_source_and_taxonomy_hashes(self):
        assignment = create_assignment(self.catalog, source_snapshot_id=self.source, taxonomy_id=self.taxonomy,
            domain_ids=["research:biology"], review=REVIEW, classifier_id="fixture-reviewer", classifier_version="1")
        operation = classification_operation(self.catalog, assignment, operation_id="classify")
        self.assertEqual(operation["assignment_hash"], self.catalog.hash(assignment))
        self.assertEqual(operation["source_hash"], self.catalog.hash(self.source))
        self.assertEqual(operation["taxonomy_hash"], self.catalog.hash(self.taxonomy))
        snapshot = {**self.state, "classifications": {"contract_version": 1, "revision": 1, "assignments": {}}}
        projection = apply_operations(self.catalog, snapshot, [operation], security_scope="test")
        self.assertEqual(projection["assignments"], {self.source: assignment})
        self.assertEqual(snapshot["classifications"]["assignments"], {})
        for field in ("assignment_hash", "source_hash", "taxonomy_hash"):
            with self.subTest(field=field), self.assertRaises(ContractError) as caught:
                apply_operations(self.catalog, snapshot, [{**operation, field: "0" * 64}], security_scope="test")
            self.assertEqual(caught.exception.code, "DOMAIN_OPERATION_BINDING")

    def test_only_omission_represents_an_unmigrated_projection(self):
        migration = migration_operation(operation_id="initialize", reason="Reviewed migration fixture")
        assignment = {"operation": "SET_SOURCE_CLASSIFICATION"}
        self.assertEqual(verify_projection(self.catalog, self.state)["revision"], 0)
        self.assertEqual(receipt_projection(self.state), {})
        self.assertIsNone(apply_operations(self.catalog, self.state, [], security_scope="test"))
        with self.assertRaises(ContractError) as caught:
            apply_operations(self.catalog, self.state, [assignment], security_scope="test")
        self.assertEqual(caught.exception.code, "DOMAIN_MIGRATION_REQUIRED")

        for invalid in (None, {}, {"contract_version": 1, "revision": 0, "assignments": {}},
                        {"contract_version": 1.0, "revision": 1, "assignments": {}},
                        {"contract_version": 1, "revision": 1.0, "assignments": {}}):
            state = {**self.state, "classifications": invalid}
            checks = {
                "identity": lambda: classification_identity(state),
                "receipt": lambda: receipt_projection(state),
                "projection": lambda: verify_projection(self.catalog, state),
                "unrelated plan": lambda: apply_operations(self.catalog, state, [], security_scope="test"),
                "initialization": lambda: apply_operations(self.catalog, state, [migration], security_scope="test"),
                "assignment": lambda: apply_operations(self.catalog, state, [assignment], security_scope="test"),
            }
            for boundary, check in checks.items():
                with self.subTest(value=invalid, boundary=boundary):
                    with self.assertRaises(ContractError) as caught:
                        check()
                    self.assertEqual(caught.exception.code, "SCHEMA_ERROR")

    def test_audit_distinguishes_omission_from_null_at_genesis_and_in_the_journal(self):
        with closing(sqlite3.connect(":memory:")) as db:
            db.executescript("""
                CREATE TABLE trace_meta (id INTEGER PRIMARY KEY, body TEXT);
                CREATE TABLE trace_journal (version INTEGER PRIMARY KEY, body TEXT);
                CREATE TABLE trace_erased (id TEXT PRIMARY KEY, hash TEXT);
            """)
            backend = SimpleNamespace(db=db, load_catalog=lambda: self.catalog)
            genesis = {**self.state, "graph_version": 0, "source_epochs": {}}
            status = {"active": True, "permission": "READ", "epoch": 0,
                      "updated_at": "2026-01-01T00:00:00Z", "tombstone": False}
            event = {"operation": {"action": "ADMIT", "expected_version": 0,
                                   "source_hashes": {self.source: self.catalog.hash(self.source)}},
                     "source_status": {self.source: status}, "state_after": self.state}
            db.execute("INSERT INTO trace_meta VALUES (1, ?)", (dumps({"genesis_state": genesis}),))
            db.execute("INSERT INTO trace_journal VALUES (1, ?)", (dumps(event),))
            self.assertEqual(audit_history(backend)["classification_replay"], "PASS")

            invalid = {**self.state, "classifications": None}
            db.execute("UPDATE trace_journal SET body = ?", (dumps({**event, "state_after": invalid}),))
            with self.assertRaises(ContractError) as caught:
                audit_history(backend)
            self.assertEqual(caught.exception.code, "SCHEMA_ERROR")

            db.execute("UPDATE trace_journal SET body = ?", (dumps(event),))
            db.execute("UPDATE trace_meta SET body = ?", (dumps({"genesis_state": {**genesis, "classifications": None}}),))
            with self.assertRaises(ContractError) as caught:
                audit_history(backend)
            self.assertEqual(caught.exception.code, "SCHEMA_ERROR")

    def test_historical_snapshot_plan_and_receipts_still_validate(self):
        path = Path(__file__).resolve().parents[1] / "examples/runtime/historical_bundle.json"
        records = load(path)["records"]
        for kind in ("graph-snapshot", "plan", "transaction"):
            with self.subTest(kind=kind):
                matching = [record for record in records if record["kind"] == kind]
                self.assertTrue(matching)
                for record in matching:
                    body = record["body"]
                    validate(kind, body)
                    self.assertNotIn("classification_revision", body)
                    if kind == "graph-snapshot":
                        self.assertTrue(body["source_epochs"])
                        self.assertNotIn("classifications", body)
                        body = snapshot_body(body)
                    self.assertEqual(digest({"kind": kind, "body": body}), record["hash"])
