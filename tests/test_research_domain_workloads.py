"""Measured workload plumbing, never representative labels or a sharding claim."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock

from trace_gc.canonical import digest
from trace_gc.domain_publication import migration_operation
from trace_gc.errors import ContractError
from trace_gc.retrieval.contracts import query, RetrievalBudget
from trace_gc.retrieval.domains import research_domain_scope
from trace_gc.retrieval.fixtures import domain_corpus, SCOPE
from trace_gc.retrieval.security import AccessFilter
from trace_gc.retrieval.telemetry import active, measure_retrieval, measured_acl, domain_hop
from trace_gc.retrieval.workloads import (QueryCase, WorkloadRecorder, percentiles, topology, measure_query,
                                        measure_publication, run_query_workload, run_reference_domain_workload)
from test_research_domain_transactions import DomainFixture


def recorder(**changes):
    manifest = {"data_kind": "SYNTHETIC", "corpus_hash": "a" * 64, "labels_hash": "b" * 64,
                "protocol_id": "synthetic-workload-test-v1"}
    return WorkloadRecorder(input_manifest=manifest, **changes)


class WorkloadMetricTests(unittest.TestCase):
    def test_percentiles_are_nearest_rank_with_actual_sample_count(self):
        self.assertEqual(percentiles([5, 1, 4, 3, 2]), {"count": 5, "p50": 3, "p95": 5, "p99": 5, "maximum": 5})
        self.assertEqual(percentiles([])["p99"], None)
        self.assertEqual(percentiles([7])["p50"], 7)

    def test_invalid_measurements_do_not_produce_plausible_percentiles(self):
        for values in ([True], [-1], [float("nan")], [float("inf")]):
            with self.subTest(values=values), self.assertRaises(ContractError):
                percentiles(values)

    def test_equal_node_counts_can_have_different_high_degree_skew(self):
        def graph(pairs):
            return {"nodes": {str(i): "Entity" for i in range(101)},
                    "assertions": {str(i): {"active": True, "assertion": {"subject": str(a), "object": str(b)}}
                                   for i, (a, b) in enumerate(pairs)}}
        star = topology(graph([(0, i) for i in range(1, 101)]))
        chain = topology(graph([(i - 1, i) for i in range(1, 101)]))
        self.assertEqual(star["nodes"], chain["nodes"])
        self.assertEqual(star["active_original_assertions"], chain["active_original_assertions"])
        self.assertEqual(star["degree"]["maximum"], 100)
        self.assertEqual(chain["degree"]["maximum"], 2)
        self.assertGreater(star["degree_gini"], chain["degree_gini"])
        self.assertNotIn("shard", json.dumps(star))

    def test_nested_acl_calls_count_but_do_not_double_time(self):
        @measured_acl("inner")
        def inner():
            return True
        @measured_acl("outer")
        def outer():
            return inner()
        with measure_retrieval() as measurement:
            self.assertTrue(outer())
        self.assertEqual(dict(measurement.acl_calls), {"outer": 1, "inner": 1})
        self.assertGreater(measurement.acl_elapsed_ns, 0)
        self.assertEqual(measurement._acl_depth, 0)
        self.assertFalse(active())

    def test_acl_exceptions_do_not_leak_measurement_context(self):
        @measured_acl("reject")
        def reject():
            raise ContractError("ACCESS_DENIED", "test")
        with self.assertRaises(ContractError), measure_retrieval() as measurement:
            reject()
        self.assertEqual(measurement.acl_calls["reject"], 1)
        self.assertEqual(measurement._acl_depth, 0)
        self.assertFalse(active())

    def test_concurrent_measurements_are_isolated(self):
        barrier = threading.Barrier(2)
        @measured_acl("check")
        def check():
            return True
        def work(count):
            with measure_retrieval() as measurement:
                barrier.wait(timeout=5)
                for _ in range(count):
                    check()
                return dict(measurement.acl_calls)
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(list(pool.map(work, [3, 7])), [{"check": 3}, {"check": 7}])

    def test_cross_domain_unknown_and_overlapping_transitions_are_distinct(self):
        with measure_retrieval() as m:
            domain_hop({("tax", "bio")}, {("tax", "physics")}, channel="path")
            domain_hop({("tax", "bio")}, {("tax", "bio"), ("tax", "chem")}, channel="path")
            domain_hop(set(), {("tax", "bio")}, channel="path")
        self.assertEqual(m.domain_hops["path:transitions"], 3)
        self.assertEqual(m.domain_hops["path:disjoint_domain_transitions"], 1)
        self.assertEqual(m.domain_hops["path:membership_changing_transitions"], 2)
        self.assertEqual(m.domain_hops["path:unclassified_transitions"], 1)

    def test_capacity_is_reserved_before_a_publication_can_happen(self):
        r = recorder(maximum_samples=1)
        r.append({"kind": "QUERY", "operation": "occupied", "outcome": "REFUSED", "elapsed_ms": 0})
        service = Mock()
        with self.assertRaises(ContractError) as caught:
            measure_publication(service, Mock(), "plan", r, authorization={}, preflight={})
        self.assertEqual(caught.exception.code, "WORKLOAD_LIMIT")
        service.publish.assert_not_called()

    def test_representative_candidate_metadata_does_not_mint_qualification(self):
        r = WorkloadRecorder(input_manifest={"data_kind": "REPRESENTATIVE_CANDIDATE", "corpus_hash": "a" * 64,
            "labels_hash": "b" * 64, "protocol_id": "unsigned-input-metadata", "owner": "claimed-owner"})
        self.assertEqual(r.report()["qualification"]["representativeness"], "NOT_ESTABLISHED")
        self.assertEqual(r.report()["qualification"]["production_backend"], "NOT_QUALIFIED")

    def test_recorder_rejects_unbound_inputs(self):
        with self.assertRaises(ContractError):
            WorkloadRecorder(input_manifest={"data_kind": "SYNTHETIC", "corpus_hash": "not-a-hash", "labels_hash": "b" * 64,
                                            "protocol_id": "test"})


class WorkloadExecutionTests(unittest.TestCase):
    def test_actual_query_measurements_preserve_retrieval_and_do_not_log_source_text(self):
        f = domain_corpus()
        c, retriever = f["catalog"], f["retriever"]
        scope = research_domain_scope(c, f["taxonomy_id"], ["research:biology"])
        request = query(requesting_component="downstream-search", security_scope=SCOPE, strategies=["LEXICAL"],
            text="improves", research_domain_scope=scope, budget=RetrievalBudget(maximum_tokens=100000, maximum_latency_ms=20000))
        reference = c.get(c.get(retriever.retrieve(request))["graph_context_id"])["items"]
        r = recorder()
        required = frozenset({f["evidence"]["e-support"], f["evidence"]["e-refute"]})
        result_id = measure_query(retriever, QueryCase("public-case-id", request, required, (required,)), r)
        self.assertEqual(c.get(c.get(result_id)["graph_context_id"])["items"], reference)
        sample = r.report()["samples"][0]
        self.assertEqual(sample["quality"]["evidence_recall"], 1)
        self.assertEqual(sample["quality"]["missed_contradiction_pairs"], 0)
        self.assertGreater(sample["measurements"]["acl_calls"]["source"], 0)
        self.assertGreater(sample["measurements"]["acl_elapsed_ms"], 0)
        self.assertNotIn(c.get(f["evidence"]["e-support"])["quote"], json.dumps(sample))
        self.assertEqual(sample["cache_delta"]["hits"], 1)

    def test_schedule_continues_after_recorded_rejection_and_error(self):
        fixture = domain_corpus()
        retriever = fixture["retriever"]
        request = query(requesting_component="downstream-search", security_scope=SCOPE,
                        strategies=["LEXICAL"], text="improves")
        denied = QueryCase("denied", {**request, "security_scope": "different-scope"})
        valid = QueryCase("valid", request)
        with self.subTest("standalone preserves retrieval exception"):
            rows = recorder()
            with self.assertRaises(ContractError) as rejected:
                measure_query(retriever, denied, rows)
            self.assertEqual(rejected.exception.code, "SECURITY_SCOPE")
            self.assertEqual(rows.report()["query_outcomes"], {"completed": 0, "rejected_or_error": 1})

        rows = recorder()
        retrieve = retriever.retrieve

        def occasionally_fails(request):
            if request["text"] == "synthetic-error":
                raise RuntimeError("synthetic adapter failure")
            return retrieve(request)

        retriever.retrieve = occasionally_fails
        failed = QueryCase("adapter-error", {**request, "text": "synthetic-error"})
        run_query_workload(lambda: retriever, [denied, failed, valid], rows, repetitions=2)
        samples = rows.report()["samples"]
        self.assertEqual([row["case_id"] for row in samples], ["denied", "adapter-error", "valid"] * 2)
        self.assertEqual([row["outcome"] for row in samples[:2]], ["SECURITY_SCOPE", "ERROR"])
        self.assertEqual(rows.report()["query_outcomes"], {"completed": 2, "rejected_or_error": 4})

    def test_schedule_propagates_capacity_factory_and_measurement_failures(self):
        case = QueryCase("case", {})
        workspace = Mock()
        workspace._lock = threading.RLock()
        workspace.retrieve.side_effect = RuntimeError("synthetic retrieval failure")
        rows = recorder(maximum_samples=1)
        with self.assertRaises(ContractError) as capacity:
            run_query_workload(lambda: workspace, [case, case], rows, repetitions=1)
        self.assertEqual(capacity.exception.code, "WORKLOAD_LIMIT")
        self.assertEqual(workspace.retrieve.call_count, 1)
        self.assertEqual(rows.report()["query_outcomes"], {"completed": 0, "rejected_or_error": 1})

        with self.assertRaisesRegex(RuntimeError, "factory failure"):
            run_query_workload(Mock(side_effect=RuntimeError("factory failure")), [case], recorder())
        workspace.retrieve.side_effect = None
        workspace.retrieve.return_value = "result"
        workspace.catalog.get.side_effect = RuntimeError("measurement failure")
        rows = recorder()
        with self.assertRaisesRegex(RuntimeError, "measurement failure"):
            run_query_workload(lambda: workspace, [case], rows)
        self.assertEqual(rows.report()["sample_count"], 0)

    def test_unsigned_publication_fails_and_is_counted_as_rejected_not_written(self):
        with tempfile.TemporaryDirectory() as directory:
            f = DomainFixture(directory)
            try:
                pid = f.plan([migration_operation(operation_id="initialize", reason="test")])
                auth, preflight = f.approvals(pid)
                auth["signature"] = "AA=="
                r = recorder()
                before = f.backend.state()
                with self.assertRaises(ContractError):
                    measure_publication(f.service, f.catalog, pid, r, authorization=auth, preflight=preflight)
                self.assertEqual(f.backend.state(), before)
                self.assertEqual(r.report()["writes"], {"committed": 0, "cross_domain_batches": 0,
                    "cross_domain_batch_rate": None, "replayed": 0, "rejected": 1})
            finally:
                f.close()

    def test_synthetic_smoke_runs_real_reference_writes_indexes_churn_and_cas(self):
        report = run_reference_domain_workload(repetitions=1, workers=1)
        self.assertEqual(report["input_manifest"]["data_kind"], "SYNTHETIC")
        self.assertEqual(report["status"], "MEASURED_NOT_QUALIFIED")
        self.assertEqual(report["sample_count"], 26)
        rates = report["phase_rates"]
        memory = rates["memory_read_schedule"]
        sqlite = rates["sqlite_mixed"]
        self.assertGreater(memory["wall_seconds"], 0)
        self.assertGreater(sqlite["wall_seconds"], 0)
        self.assertEqual((memory["query_attempts"], memory["query_completions"]), (8, 8))
        self.assertAlmostEqual(memory["attempts_per_second"], 8 / memory["wall_seconds"])
        self.assertAlmostEqual(memory["completions_per_second"], 8 / memory["wall_seconds"])
        self.assertEqual(sqlite["committed_signed_plans"], 5)
        self.assertAlmostEqual(sqlite["committed_signed_plans_per_second"], 5 / sqlite["wall_seconds"])
        # The integrated protocol includes rejected requests and exact identity
        # implementation pins; neither prior branch's coverage may be discarded.
        from trace_gc.canonical import bytes_digest
        import trace_gc
        package = Path(trace_gc.__file__).resolve().parent  # works from a checkout or an installed wheel
        self.assertEqual(report["implementation_hashes"]["items.py"],
                         bytes_digest((package / "retrieval/items.py").read_bytes()))
        self.assertEqual(report["implementation_hashes"]["../constraints.py"],
                         bytes_digest((package / "constraints.py").read_bytes()))
        self.assertEqual(report["query_outcomes"], {"completed": 15, "rejected_or_error": 1})
        self.assertEqual(report["telemetry_coverage"], {"queries": 16, "measured_queries": 16, "unmeasured_queries": 0})
        self.assertEqual(report["acl_elapsed_ms"]["count"], 16)
        denied = next(row for row in report["samples"] if row.get("case_id") == "acl-scope-rejected")
        self.assertEqual(denied["outcome"], "SECURITY_SCOPE")
        self.assertFalse(denied["completed"])
        self.assertIsNone(denied["quality"])
        self.assertEqual(report["writes"]["committed"], 5)
        self.assertEqual(report["writes"]["replayed"], 4)
        self.assertEqual(report["writes"]["rejected"], 1)
        self.assertCountEqual(report["concurrent_write_outcomes"], ["COMMITTED", "STALE_GRAPH_VERSION"])
        self.assertEqual(report["index_validation_ms"]["count"], 7)
        self.assertEqual(report["index_latency_ms_by_mode"]["VERIFIED"]["count"], 7)
        self.assertEqual(report["cold_projection"]["mode"], "PROJECTED")
        self.assertEqual([row["mode"] for row in report["index_preparations"]],
                         ["REBUILT", "MATERIALIZED", "MATERIALIZED"])
        self.assertTrue(all(row["logical_source_row_bytes"] > 0 for row in report["index_preparations"]))
        self.assertEqual(report["publication_domain_coverage"], {"committed": 5, "classified": 5})
        self.assertGreater(report["cache"]["hits"], 0)
        self.assertGreater(report["cache"]["invalidations"], 0)
        self.assertGreater(report["domain_hops"]["path:transitions"], 0)
        self.assertEqual(report["quality"]["scoped"]["forbidden_sources_returned"], 0)
        self.assertEqual(report["paired_comparison"]["lexical-conflict"]["scoped"]["missed_contradiction_pairs"], 0)
        lexical = report["paired_comparison"]["lexical-conflict"]
        self.assertIsNotNone(lexical["unscoped"]["missing_structured_conflicts"])
        self.assertIsNotNone(lexical["scoped"]["missing_structured_conflicts"])
        self.assertIsNone(report["paired_comparison"]["path"]["scoped"]["missing_structured_conflicts"])
        self.assertEqual(report["production_graph_writes"], 0)
        self.assertEqual(report["provider_calls"], 0)

    def test_even_repetitions_prove_withdrawal_on_matching_historical_snapshot(self):
        report = run_reference_domain_workload(repetitions=4, workers=1)
        control = report["revocation_control"]
        self.assertEqual(control["graph_version"] + 1, control["last_classification_graph_version"])
        self.assertTrue(control["source_and_evidence_visible_before_withdrawal"])
        self.assertTrue(control["source_excluded_after_withdrawal"])
        self.assertFalse(control["positive_control_in_query_sample_count"])
        revoked, = (row for row in report["samples"] if row.get("case_id") == "sqlite-historical-current-revocation")
        self.assertEqual(revoked["graph_version"], control["graph_version"])
        self.assertEqual(revoked["quality"]["forbidden_sources_returned"], 0)
        self.assertEqual(report["query_outcomes"], {"completed": 41, "rejected_or_error": 1})
        self.assertEqual(report["sample_count"], 54)
