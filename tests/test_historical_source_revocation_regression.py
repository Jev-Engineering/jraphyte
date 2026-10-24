"""Current source controls apply to both current and historical evidence reads.

These tests use the actual Catalog and AccessFilter, not a mock authorization
implementation. Run from a complete jraphyte checkout after applying the patch.
"""
from copy import deepcopy
import unittest

from trace_gc.catalog import Catalog
from trace_gc.retrieval.security import AccessFilter, access_policy, grant


class CurrentSourceRevocationTests(unittest.TestCase):
    def setUp(self):
        self.catalog = Catalog()
        self.source_id = self.catalog.source(
            "revocation-regression", "1", "Source-bound evidence.", scope="tenant-a"
        )
        self.evidence_id = self.catalog.evidence(self.source_id)
        self.status = {
            "permission": "READ", "active": True, "tombstone": False, "epoch": 1
        }
        self.policy = access_policy(
            tenant="tenant-a", workspace="workspace-a", user="reader",
            grants={
                f"source:{self.source_id}": grant(
                    "tenant-a", "workspace-a", users=["reader"]
                )
            },
        )

    def check_both_modes(self, expected, *, status=None, policy=None, missing=False):
        statuses = {} if missing else {
            self.source_id: deepcopy(self.status if status is None else status)
        }
        for historical in (False, True):
            with self.subTest(historical=historical):
                access = AccessFilter(
                    self.policy if policy is None else policy,
                    self.catalog, statuses, historical=historical,
                )
                self.assertEqual(bool(access.evidence(self.evidence_id)), expected)

    def test_current_active_read_is_allowed(self):
        self.check_both_modes(True)

    def test_inactive_source_remains_denied_with_read_permission(self):
        self.check_both_modes(False, status={**self.status, "active": False})

    def test_read_permission_revocation_remains_denied(self):
        self.check_both_modes(False, status={**self.status, "permission": "DENY"})

    def test_tombstone_remains_denied_with_active_read_status(self):
        self.check_both_modes(False, status={**self.status, "tombstone": True})

    def test_missing_current_status_is_denied(self):
        self.check_both_modes(False, missing=True)

    def test_missing_source_grant_is_denied(self):
        self.check_both_modes(False, policy={**self.policy, "grants": {}})

    def test_wrong_principal_is_denied(self):
        self.check_both_modes(False, policy={**self.policy, "user": "other-reader"})

    def test_wrong_workspace_grant_is_denied(self):
        policy = deepcopy(self.policy)
        policy["grants"][f"source:{self.source_id}"]["workspace"] = "other-workspace"
        self.check_both_modes(False, policy=policy)

    def test_source_tenant_is_not_replaced_by_a_grant(self):
        policy = access_policy(
            tenant="tenant-b", workspace="workspace-a", user="reader",
            grants={
                f"source:{self.source_id}": grant(
                    "tenant-b", "workspace-a", users=["reader"]
                )
            },
        )
        self.check_both_modes(False, policy=policy)

    def test_historical_edge_cannot_reintroduce_inactive_evidence(self):
        policy = deepcopy(self.policy)
        for key in ("node:subject", "node:object", "edge:assertion"):
            policy["grants"][key] = grant(
                "tenant-a", "workspace-a", users=["reader"]
            )
        fact = {
            "assertion": {"subject": "subject", "object": "object"},
            "evidence_ids": [self.evidence_id],
        }
        for historical in (False, True):
            with self.subTest(historical=historical):
                access = AccessFilter(
                    policy, self.catalog,
                    {self.source_id: {**self.status, "active": False}},
                    historical=historical,
                )
                self.assertFalse(access.edge("assertion", fact))

    def test_source_and_evidence_hashes_are_unchanged(self):
        source_hash = self.catalog.hash(self.source_id)
        evidence_hash = self.catalog.hash(self.evidence_id)
        self.check_both_modes(True)
        self.check_both_modes(False, status={**self.status, "active": False})
        self.assertEqual(self.catalog.hash(self.source_id), source_hash)
        self.assertEqual(self.catalog.hash(self.evidence_id), evidence_hash)


if __name__ == "__main__":
    unittest.main()
