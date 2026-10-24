"""Protocol arithmetic and actual sandbox recovery tests, not deployment results."""
import unittest
from trace_gc.canonical import digest
from trace_gc.errors import ContractError
from trace_gc.retrieval.domain_benchmark import WorkloadRequirements, percentiles, run_workload, graph_shape
from trace_gc.retrieval.contracts import query


class DomainWorkload(unittest.TestCase):
    def requirements(self, **changes):
        values = dict(decision_owner="test-protocol-not-deployment-owner", evidence_origin="SYNTHETIC",
            corpus_manifest_hash=digest("fabricated"), isolation_requirements=("disposable-local-test",),
            isolation_reviewed=False, p95_latency_ms=10000, p99_latency_ms=20000, concurrency=2, repeats=2)
        values.update(changes)
        return WorkloadRequirements(**values)

    def test_empty_metrics_unknown(self):
        self.assertEqual(percentiles([]), {"p50": None, "p95": None, "p99": None})

    def test_nearest_rank(self):
        self.assertEqual(percentiles(list(range(1, 101))), {"p50": 50, "p95": 95, "p99": 99})

    def test_nonfinite_rejected(self):
        for value in [float("inf"), float("nan"), -1, True]:
            with self.subTest(value=value), self.assertRaises(ContractError):
                percentiles([value])

    def test_invalid_protocol(self):
        for changes in [{"evidence_origin": "PRODUCTION"}, {"concurrency": True}, {"corpus_manifest_hash": "x"},
                        {"repeats": 0}, {"p99_latency_ms": 1}, {"p95_latency_ms": float("nan")}]:
            with self.subTest(changes=changes), self.assertRaises(ContractError):
                self.requirements(**changes)

    def test_actual_counts_and_quality_accounting(self):
        closed = []
        class Worker:
            def execute(self, q):
                return {"selected_evidence_ids": ["a"], "cache_hit": False, "response_status": "COMPLETE"}
            def close(self):
                closed.append(1)
        req = self.requirements()
        cases = [{"id": "case", "query": query(requesting_component="downstream-test", security_scope="test"),
                  "expected_evidence_ids": ["a", "b"]}]
        result = run_workload(Worker, cases, req)
        self.assertEqual(result["queries"], 4)
        self.assertEqual(len(closed), 2)
        self.assertEqual(result["per_case"]["case"]["required_evidence_recall"], .5)
        self.assertFalse(result["production_qualified"])
        self.assertEqual(result["placement_decision"], "REQUIRES_OWNER_REVIEW")
        self.assertEqual(result["protocol_hash"], digest(result["protocol"]))

    def test_workers_closed_on_error(self):
        closed = []
        class Worker:
            def execute(self, q):
                raise RuntimeError("injected")
            def close(self):
                closed.append(1)
        with self.assertRaises(RuntimeError):
            run_workload(Worker, [{"id": "case", "query": query(requesting_component="downstream-test", security_scope="test"),
                                  "expected_evidence_ids": []}], self.requirements(concurrency=1))
        self.assertEqual(closed, [1])

    def test_graph_shape_skew(self):
        result = graph_shape({"nodes": {"a": "N", "b": "N", "c": "N"}, "assertions": {
            "ab": {"active": True, "assertion": {"subject": "a", "object": "b"}},
            "ac": {"active": True, "assertion": {"subject": "a", "object": "c"}}}})
        self.assertEqual(result["maximum_degree"], 2)
        self.assertEqual(result["top_one_percent_degree_share"], .5)


class DomainRecovery(unittest.TestCase):
    def fixture(self):
        import test_domain_publication as fixtures
        f = fixtures.DomainPublication()
        f.setUp()
        self.addCleanup(f.doCleanups)
        f.migrate()
        f.publish(f.plan(f.assignment()))
        from trace_gc.retrieval.store import SQLiteGraphAdapter
        SQLiteGraphAdapter(f.backend, classification_trust=f.trust).rebuild_domain_index()
        return f

    def test_reference_online_backup_native_reopen_and_corrupt_index_recovery(self):
        from trace_gc.backend import SQLiteReferenceBackend
        from trace_gc.retrieval.domain_operations import check_sandbox_backup_recovery
        f = self.fixture()
        report = check_sandbox_backup_recovery(f.backend, classification_trust=f.trust,
            query=query(requesting_component="downstream-test", security_scope="tenant-a"),
            reopen=lambda path: SQLiteReferenceBackend(path, catalog=f.c, schema_id=f.schema,
                                                       nodes=f.backend.state()["nodes"], sandbox=True))
        self.assertEqual(report["checks_run"], 5)
        self.assertFalse(report["production_qualified"])
        self.assertEqual(report["backend_class"], "SQLiteReferenceBackend")

    def test_non_sandbox_rejected_before_backup(self):
        from trace_gc.retrieval.domain_operations import check_sandbox_backup_recovery
        class Backend:
            sandbox = False
        with self.assertRaises(ContractError):
            check_sandbox_backup_recovery(Backend(), reopen=lambda p: self.fail("must not open"),
                                         classification_trust=None, query={})
