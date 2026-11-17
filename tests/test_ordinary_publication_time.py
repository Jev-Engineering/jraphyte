"""Ordinary publication uses one acceptance time on both SQLite adapters."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from trace_gc.canonical import loads
from trace_gc.conformance import legacy_test_policy
from trace_gc.demo import build_fixture
from trace_gc.legacy import PinnedLegacyBackend
from trace_gc.trust import authorize_plan


ACCEPTED_AT = "2030-01-01T00:00:00Z"
LATER = "2030-01-01T00:00:01Z"
EXPIRED = "2030-01-02T00:00:00Z"


class OrdinaryPublicationTimeMixin:
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.fixture = self.make_fixture(Path(directory.name))
        self.addCleanup(self.fixture.close)
        f = self.fixture
        self.preflight = f.service.preflight(f.catalog, f.plan_id, reviewed=True, at=ACCEPTED_AT)
        self.authorization = authorize_plan(
            f.reviewer, f.catalog.get(f.plan_id, "plan"), f.catalog.hash(f.plan_id),
            reviewed_by="isolated-test-reviewer", issued_at=ACCEPTED_AT, expires_at=EXPIRED,
        )

    def publish(self, *, at=None):
        f = self.fixture
        return f.service.publish(f.catalog, f.plan_id, preflight=self.preflight,
                                 authorization=self.authorization, at=at)

    def assert_committed_time(self, result, verify):
        self.assertFalse(result["replayed"])
        backend = self.fixture.backend
        row = backend.db.execute("SELECT body FROM trace_journal WHERE version=?",
                                 (result["receipt"]["version"],)).fetchone()
        self.assertEqual(loads(row[0]), result["event"])
        self.assertEqual(result["event"]["committed_at"], ACCEPTED_AT)
        self.assertEqual(result["receipt"]["committed_at"], ACCEPTED_AT)
        self.assertEqual(
            [(call.args[1], call.kwargs["at"]) for call in verify.call_args_list],
            [("AUTHORIZATION", ACCEPTED_AT), ("PREFLIGHT", ACCEPTED_AT)],
        )
        self.assertFalse(backend.db.in_transaction)

    def test_implicit_time_is_sampled_once_under_write_ownership(self):
        times = iter((ACCEPTED_AT, LATER))

        def clock():
            self.assertTrue(self.fixture.backend.db.in_transaction)
            return next(times)

        trust = self.fixture.trust
        with patch("trace_gc.backend.now", side_effect=clock) as reference_clock, \
                patch("trace_gc.legacy.now", side_effect=clock) as legacy_clock, \
                patch.object(trust, "verify", wraps=trust.verify) as verify:
            result = self.publish()
        self.assertEqual(reference_clock.call_count + legacy_clock.call_count, 1)
        self.assert_committed_time(result, verify)

    def test_explicit_time_is_committed_and_expired_retry_returns_original_receipt(self):
        trust = self.fixture.trust
        with patch("trace_gc.backend.now", return_value=EXPIRED), \
                patch("trace_gc.legacy.now", return_value=EXPIRED), \
                patch.object(trust, "verify", wraps=trust.verify) as verify:
            first = self.publish(at=ACCEPTED_AT)
            self.assert_committed_time(first, verify)
            verify.reset_mock()
            retry = self.publish()
            verify.assert_not_called()
        self.assertTrue(retry["replayed"])
        self.assertEqual(retry["receipt"], first["receipt"])
        self.assertEqual(retry["event"], first["event"])
        self.assertFalse(self.fixture.backend.db.in_transaction)


class ReferenceOrdinaryPublicationTimeTests(OrdinaryPublicationTimeMixin, unittest.TestCase):
    def make_fixture(self, root):
        return build_fixture(root)


@unittest.skipUnless(os.environ.get("TRACE_GC_LEGACY_CORE"), "External pinned core.py not supplied")
class PinnedOrdinaryPublicationTimeTests(OrdinaryPublicationTimeMixin, unittest.TestCase):
    def make_fixture(self, root):
        def factory(path, **kwargs):
            return PinnedLegacyBackend(path, core_path=os.environ["TRACE_GC_LEGACY_CORE"],
                                       legacy_policy=legacy_test_policy(), **kwargs)
        return build_fixture(root, backend_factory=factory)
