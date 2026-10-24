"""Request authority is revalidated under the owner lock, including idempotent retries.

Each case lets pre-lock validation pass, then changes the clock, trust root,
reviewer policy or application policy before the transaction is acquired. The
accepted database must remain byte-identical and no transaction may stay open.
"""
from dataclasses import replace
from datetime import timedelta
import os
import tempfile
import threading
import unittest
from unittest.mock import patch

from trace_gc.compiler import now, timestamp
from trace_gc.errors import ContractError
from trace_gc.trust import authorize_plan
from test_research_domain_transactions import DomainFixture


def shifted(seconds):
    return (timestamp(now()) + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


class RetryRevalidationMixin:
    def make_fixture(self, root):
        return DomainFixture(root)

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.f = self.make_fixture(self.directory.name)
        self.addCleanup(self.f.close)
        self.f.migrate()
        self.plan = self.f.assignment_plan(self.f.assign())

    def approvals(self, *, auth_lifetime_seconds=3600):
        plan_body = self.f.catalog.get(self.plan, "plan")
        preflight = self.f.service.preflight(self.f.catalog, self.plan, reviewed=True)
        auth = authorize_plan(self.f.reviewer, plan_body, self.f.catalog.hash(self.plan), reviewed_by="fixture-reviewer",
                              expires_at=shifted(auth_lifetime_seconds))
        return auth, preflight

    def database(self):
        backend = self.f.backend
        return {name: list(backend.db.execute("SELECT * FROM " + name))
                for name in ("trace_meta", "trace_source_status", "trace_records", "trace_journal")}

    def between_validation_and_lock(self, mutation):
        """Run `mutation` after pre-lock validation but before the transaction is acquired."""
        backend, original = self.f.backend, self.f.backend._transaction
        def delayed(**kwargs):
            mutation()
            return original(**kwargs)
        patcher = patch.object(backend, "_transaction", delayed)
        patcher.start()
        self.addCleanup(patcher.stop)

    def assertRetryRejected(self, approvals, code):
        before = self.database()
        with self.assertRaises(ContractError) as caught:
            self.f.publish(self.plan, approvals=approvals)
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(self.database(), before)
        self.assertFalse(self.f.backend.db.in_transaction)

    def test_valid_retry_still_returns_the_original_receipt(self):
        approvals = self.approvals()
        first = self.f.publish(self.plan, approvals=approvals)
        self.between_validation_and_lock(lambda: None)
        retry = self.f.publish(self.plan, approvals=approvals)
        self.assertFalse(first["replayed"])
        self.assertTrue(retry["replayed"])
        self.assertEqual(first["receipt"], retry["receipt"])

    def advance_clock(self, seconds):
        clock = patch("trace_gc.trust.now", lambda: shifted(seconds))
        def start():
            clock.start()
            self.addCleanup(clock.stop)
        self.between_validation_and_lock(start)

    def test_retry_within_credential_lifetime_after_clock_advance_is_accepted(self):
        approvals = self.approvals()
        self.f.publish(self.plan, approvals=approvals)
        self.advance_clock(30)
        retry = self.f.publish(self.plan, approvals=approvals)
        self.assertTrue(retry["replayed"])

    def test_authorization_expiring_while_waiting_rejects_idempotent_retry(self):
        approvals = self.approvals(auth_lifetime_seconds=120)
        self.f.publish(self.plan, approvals=approvals)
        self.advance_clock(300)
        self.assertRetryRejected(approvals, "RECEIPT_EXPIRED")

    def test_preflight_expiring_while_waiting_rejects_idempotent_retry(self):
        approvals = self.approvals(auth_lifetime_seconds=86400)
        self.f.publish(self.plan, approvals=approvals)
        self.advance_clock(1000)
        self.assertRetryRejected(approvals, "RECEIPT_EXPIRED")

    def test_credential_expiring_while_waiting_rejects_first_commit_without_state_change(self):
        approvals = self.approvals(auth_lifetime_seconds=120)
        version = self.f.backend.state()["graph_version"]
        self.advance_clock(300)
        self.assertRetryRejected(approvals, "RECEIPT_EXPIRED")
        self.assertEqual(self.f.backend.state()["graph_version"], version)

    def test_reviewer_revocation_while_waiting_rejects_idempotent_retry(self):
        approvals = self.approvals()
        self.f.publish(self.plan, approvals=approvals)
        self.between_validation_and_lock(lambda: self.f.trust.revoke("reviewer"))
        self.assertRetryRejected(approvals, "UNTRUSTED_ISSUER")

    def test_validator_revocation_while_waiting_rejects_idempotent_retry(self):
        approvals = self.approvals()
        self.f.publish(self.plan, approvals=approvals)
        self.between_validation_and_lock(lambda: self.f.trust.revoke("validator"))
        self.assertRetryRejected(approvals, "UNTRUSTED_ISSUER")

    def test_reviewer_losing_review_authority_while_waiting_rejects_idempotent_retry(self):
        approvals = self.approvals()
        self.f.publish(self.plan, approvals=approvals)
        def demote():
            issuers = self.f.trust._issuers
            issuers["reviewer"] = replace(issuers["reviewer"], can_review=False)
        self.between_validation_and_lock(demote)
        self.assertRetryRejected(approvals, "REVIEW_AUTHORITY")

    def test_application_disabling_classification_while_waiting_rejects_idempotent_retry(self):
        approvals = self.approvals()
        self.f.publish(self.plan, approvals=approvals)
        self.between_validation_and_lock(lambda: setattr(self.f.service, "classification_enabled", False))
        self.assertRetryRejected(approvals, "DOMAIN_PUBLICATION_DISABLED")

    def test_application_unpinning_taxonomy_while_waiting_rejects_idempotent_retry(self):
        approvals = self.approvals()
        self.f.publish(self.plan, approvals=approvals)
        self.between_validation_and_lock(lambda: setattr(self.f.service, "classification_taxonomy_hashes", frozenset()))
        self.assertRetryRejected(approvals, "DOMAIN_TAXONOMY_UNTRUSTED")

    def test_application_policy_pin_change_while_waiting_rejects_idempotent_retry(self):
        approvals = self.approvals()
        self.f.publish(self.plan, approvals=approvals)
        self.between_validation_and_lock(lambda: setattr(self.f.service, "policy_hash", "0" * 64))
        self.assertRetryRejected(approvals, "ANALYSIS_ONLY")

    def test_blocked_retry_observes_a_change_made_while_it_waited_for_the_owner_lock(self):
        approvals = self.approvals()
        self.f.publish(self.plan, approvals=approvals)
        backend, original = self.f.backend, self.f.backend._transaction
        held, release, entered = threading.Event(), threading.Event(), threading.Event()
        outcome = {}
        def holder():
            with backend._lock:
                held.set()
                release.wait(30)
        def delayed(**kwargs):
            entered.set()
            return original(**kwargs)
        def retry():
            try:
                outcome["value"] = self.f.publish(self.plan, approvals=approvals)
            except BaseException as exc:
                outcome["error"] = exc
        with patch.object(backend, "_transaction", delayed):
            owner = threading.Thread(target=holder)
            owner.start()
            self.assertTrue(held.wait(30))
            waiter = threading.Thread(target=retry)
            waiter.start()
            self.assertTrue(entered.wait(30))
            self.f.trust.revoke("reviewer")
            release.set()
            waiter.join(60)
            owner.join(60)
        self.assertNotIn("value", outcome)
        self.assertEqual(outcome["error"].code, "UNTRUSTED_ISSUER")
        self.assertFalse(backend.db.in_transaction)


class ReferenceBackendRetryRevalidationTests(RetryRevalidationMixin, unittest.TestCase):
    pass


@unittest.skipUnless(os.environ.get("TRACE_GC_LEGACY_CORE"),
                     "External pinned core.py not supplied; not a passed pinned-backend gate")
class PinnedBackendRetryRevalidationTests(RetryRevalidationMixin, unittest.TestCase):
    def test_blocked_retry_observes_a_change_made_while_it_waited_for_the_owner_lock(self):
        self.skipTest("the pinned upstream SQLite connection is thread-affine; covered by the hook proxy and sequential cases")

    def make_fixture(self, root):
        from trace_gc.conformance import legacy_test_policy
        from trace_gc.legacy import PinnedLegacyBackend
        def factory(path, **kwargs):
            return PinnedLegacyBackend(path, core_path=os.environ["TRACE_GC_LEGACY_CORE"],
                                       legacy_policy=legacy_test_policy(), **kwargs)
        return DomainFixture(root, backend_factory=factory)


if __name__ == "__main__":
    unittest.main()
