"""Pure snapshot and classification operation contracts, independent of storage."""
import unittest

from trace_gc.domain_publication import (
    apply_operations, classification_identity, classification_operation, migration_operation, snapshot_body,
)
from trace_gc.domains import create_assignment
from trace_gc.errors import ContractError
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
