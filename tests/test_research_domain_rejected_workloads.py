"""Rejected/error queries must not disappear from measured workload costs."""
import json
import threading
from types import SimpleNamespace
import unittest

from trace_gc.errors import ContractError
from trace_gc.retrieval.contracts import query, RetrievalBudget
from trace_gc.retrieval.fixtures import domain_corpus, SCOPE
from trace_gc.retrieval.telemetry import active, measured_acl, domain_hop
from trace_gc.retrieval.workloads import QueryCase, measure_query
from test_research_domain_workloads import recorder


class RejectedRetriever:
    """Deterministic instrumentation fixture, not retrieval/backend qualification."""
    def __init__(self, error):
        self.error = error
        self._lock = threading.RLock()
        self.cache = SimpleNamespace(hits=0, misses=0, invalidations=0, evictions=0)
        self.last_read_metrics = {}

    @measured_acl("fixture_source")
    def retrieve(self, request):
        self.cache.misses += 1
        self.cache.invalidations += 1
        # These stand for already-authorized synthetic transitions followed by a
        # later failure, not a claim that denied data was traversed.
        domain_hop({("fixture-tax", "a")}, {("fixture-tax", "b")}, channel="fixture")
        raise self.error


class RejectedWorkloadTests(unittest.TestCase):
    def attempt(self, error=None):
        error = error if error is not None else ContractError("ACCESS_DENIED", "PRIVATE_ERROR_MESSAGE")
        retriever, sink = RejectedRetriever(error), recorder()
        request = query(requesting_component="downstream-search", security_scope="test", strategies=["LEXICAL"],
                        text="PRIVATE_QUERY_TEXT")
        with self.assertRaises(type(error)) as caught:
            measure_query(retriever, QueryCase("opaque-case", request), sink)
        self.assertIs(caught.exception, error)
        self.assertFalse(active())
        return sink.report()

    def test_rejected_acl_time_and_calls_are_retained(self):
        report = self.attempt()
        self.assertEqual(report["acl_elapsed_ms"]["count"], 1)
        self.assertGreater(report["acl_elapsed_ms"]["p50"], 0)
        self.assertEqual(report["samples"][0]["measurements"]["acl_calls"], {"fixture_source": 1})

    def test_rejected_cache_churn_is_not_dropped(self):
        report = self.attempt()
        self.assertEqual(report["cache"], {"hits": 0, "misses": 1, "invalidations": 1, "evictions": 0})

    def test_authorized_work_before_a_later_rejection_is_measured(self):
        report = self.attempt()
        self.assertEqual(report["domain_hops"]["fixture:transitions"], 1)
        self.assertEqual(report["domain_hops"]["fixture:disjoint_domain_transitions"], 1)

    def test_operational_error_is_recorded_and_original_exception_rethrown(self):
        report = self.attempt(RuntimeError("PRIVATE_PROVIDER_ERROR"))
        self.assertEqual(report["sample_count"], 1)
        self.assertEqual(report["samples"][0]["outcome"], "ERROR")
        self.assertEqual(report["samples"][0]["error_type"], "RuntimeError")

    def test_error_messages_and_query_text_are_not_logged(self):
        report = self.attempt(RuntimeError("PRIVATE_PROVIDER_ERROR"))
        text = json.dumps(report)
        self.assertNotIn("PRIVATE_PROVIDER_ERROR", text)
        self.assertNotIn("PRIVATE_QUERY_TEXT", text)
        self.assertEqual(report["sample_count"], 1)  # Empty telemetry is not redaction.

    def test_rejection_never_masquerades_as_empty_success_or_zero_quality(self):
        report = self.attempt(ContractError("EMPTY", "malformed custom strategy error code"))
        sample = report["samples"][0]
        self.assertFalse(sample["completed"])
        self.assertIsNone(sample["quality"])
        self.assertEqual(report["query_outcomes"], {"completed": 0, "rejected_or_error": 1})

    def test_rejected_query_retains_scope_pair_and_request_identity(self):
        report = self.attempt()
        sample = report["samples"][0]
        self.assertFalse(sample["domain_scoped"])
        self.assertIsNone(sample["pair_id"])
        self.assertEqual(len(sample["request_hash"]), 64)
        self.assertIsNone(sample["classification_identity"])
        self.assertIsNone(sample["graph_version"])

    def test_manual_legacy_rows_report_missing_measurements_not_zero_cost(self):
        sink = recorder()
        sink.append({"kind": "QUERY", "operation": "legacy:rejected", "outcome": "ACCESS_DENIED", "elapsed_ms": 1})
        report = sink.report()
        self.assertEqual(report["telemetry_coverage"], {"queries": 1, "measured_queries": 0, "unmeasured_queries": 1})
        self.assertEqual(report["acl_elapsed_ms"]["count"], 0)
        self.assertIsNone(report["acl_elapsed_ms"]["p50"])

    def test_success_and_rejection_both_count_cost_but_only_success_counts_quality(self):
        f = domain_corpus()
        sink = recorder()
        request = query(requesting_component="downstream-search", security_scope=SCOPE, strategies=["LEXICAL"],
                        text="improves", budget=RetrievalBudget(maximum_tokens=100000, maximum_latency_ms=20000))
        measure_query(f["retriever"], QueryCase("success", request), sink)
        denied = {**request, "security_scope": "not-the-authorized-scope"}
        with self.assertRaises(ContractError):
            measure_query(f["retriever"], QueryCase("denied", denied), sink)
        report = sink.report()
        self.assertEqual(report["acl_elapsed_ms"]["count"], 2)
        self.assertEqual(report["quality"]["unscoped"]["queries"], 1)
        self.assertEqual(report["query_outcomes"], {"completed": 1, "rejected_or_error": 1})

    def test_failed_read_does_not_reuse_previous_adapter_timing(self):
        f = domain_corpus()
        r, sink = f["retriever"], recorder()
        r.last_read_metrics = {"validation_seconds": 999, "authority_audit_seconds": 999}
        # Invalid request fails BEFORE adapter.read, so neither old metric belongs
        # to this attempt. The guard is also required outside workload recording.
        with self.assertRaises(ContractError):
            r.retrieve({"unexpected": True})
        self.assertEqual(r.last_read_metrics, {})
        with self.assertRaises(ContractError):
            measure_query(r, QueryCase("bad-request", {"unexpected": True}), sink)
        report = sink.report()
        self.assertEqual(report["samples"][0]["adapter_metrics"], {})
        self.assertEqual(report["authority_audit_ms"]["count"], 0)
        self.assertEqual(report["index_validation_ms"]["count"], 0)

    def test_noncanonical_rejected_request_does_not_mask_original_error(self):
        for value in (float("nan"), "\\ud800"):
            # Construct the surrogate explicitly; never write it into artifacts.
            value = chr(0xD800) if isinstance(value, str) else value
            error = ContractError("FIXTURE_ORIGINAL_REJECTION", "PRIVATE_ERROR_MESSAGE")
            r, sink = RejectedRetriever(error), recorder()
            request = {"invalid": value}
            with self.subTest(type=type(value).__name__), self.assertRaises(ContractError) as caught:
                measure_query(r, QueryCase("noncanonical", request), sink)
            self.assertIs(caught.exception, error)
            report = sink.report()
            self.assertIsNone(report["samples"][0]["request_hash"])
            self.assertEqual(report["samples"][0]["request_hash_status"], "UNAVAILABLE_NONCANONICAL_REQUEST")
            json.dumps(report, allow_nan=False)  # Invalid input is not copied into telemetry.


if __name__ == "__main__":
    unittest.main()
