"""Execute the reference classification journal lifecycle in temporary SQLite."""
import unittest

from trace_gc.domain_conformance import run_domain_conformance


class PublicationConformanceTests(unittest.TestCase):
    def test_reference_classification_conformance_runs_all_write_boundaries_and_replay(self):
        result = run_domain_conformance()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["backend"], "sqlite-reference-v1")
        self.assertEqual(result["classification_events"], 4)
        self.assertEqual(result["checks_run"], len(result["checks"]))
        self.assertEqual({check for check in result["checks"] if check.startswith("classification_rollback:")}, {
            "classification_rollback:before_state_write", "classification_rollback:after_state_write",
            "classification_rollback:after_journal_write", "classification_rollback:before_commit",
        })
        self.assertIn("signed_classification_stale_graph_cas", result["checks"])
        self.assertIn("classification_planning_rejects_stale_predecessor", result["checks"])
        self.assertIn("classification_preflight_rejects_stale_source_epoch", result["checks"])
        self.assertIn("authenticated_scoped_lexical_retrieval", result["checks"])
        self.assertIn("historical_assignment_replay", result["checks"])
        self.assertIn("classified_database_reopen_authenticated_audit", result["checks"])
        self.assertEqual(result["provider_calls"], 0)
        self.assertEqual(result["production_graph_writes"], 0)
