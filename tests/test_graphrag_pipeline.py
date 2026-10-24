from __future__ import annotations
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from trace_gc.demo import build_fixture, fixture_response, RUN, SCOPE, POLICY, POPULATION
from trace_gc.adapter import record_response, validate_observation, TypeSafeAdapter
from trace_gc.catalog import Catalog
from trace_gc.compiler import compile_pack, validate_pack
from trace_gc.canonical import digest
from trace_gc.errors import ContractError
from trace_gc.ledger import make_bundle, build_ledger
from trace_gc.plans import add_operation, create_plan, required_sources
from trace_gc.programs import question
from trace_gc.retrieval.contracts import query, RetrievalBudget
from trace_gc.retrieval.fixtures import demo_access
from trace_gc.retrieval.store import SQLiteGraphAdapter
from trace_gc.retrieval.service import HybridRetriever, GraphRAGQueryService, validate_context
from trace_gc.retrieval.planner import RetrievalPlanner, UpstreamGraphRAG
from trace_gc.retrieval.reranker import JevReranker
from trace_gc.retrieval.integration import validate_record
from trace_gc.validation import validate_bundle
from trace_gc.replay import replay_retrieval

class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.f = build_fixture(Path(self.temp.name), candidate_count=1)
        self.c = self.f.catalog
        self.r = HybridRetriever(SQLiteGraphAdapter(self.f.backend, self.c), catalog=self.c,
                                 access_policy=demo_access(self.c, self.f.snapshot_id, scope=SCOPE))
    def tearDown(self):
        self.f.backend.close()
        self.f.budget.close()
        self.temp.cleanup()

    def request(self, *, downstream=False, candidate=None, **changes):
        ref = candidate or self.f.candidate_ids[0]
        return query(requesting_component="downstream-search" if downstream else "upstream-synthesis", security_scope=SCOPE,
                     focus_entities=["document-demo", self.f.claim_id], candidate_id=None if downstream else ref,
                     text="Aster joined Meridian in 2024", budget=changes.pop("budget", RetrievalBudget(maximum_tokens=60000, maximum_latency_ms=10000)),
                     strategies=changes.pop("strategies", ["ENTITY", "SOURCE", "NEIGHBORHOOD", "PROVENANCE"]), **changes)

    def retrieved_pack(self):
        ref = self.r.retrieve(self.request())
        result = self.c.get(ref, "retrieval-result")
        ctx = self.c.get(result["graph_context_id"], "graph-context")
        pack = compile_pack(self.c, id_="retrieval-test-pack", run_id=RUN, candidate_ids=self.f.candidate_ids,
                            questions=[question(self.f.candidate_ids[0], id_="bounded")], snapshot_id=ctx["snapshot_id"], security_scope=SCOPE,
                            graph_context_ids=[result["graph_context_id"]], source_retrieval_ids=[ref])
        return pack, ref

    def publish_graph(self):
        commit = self.f.publish()
        snapshot = self.f.backend.snapshot(self.c)
        self.r.set_access_policy(demo_access(self.c, snapshot, scope=SCOPE))
        return commit, snapshot

    def new_candidate(self, name="new-assertion"):
        old = self.c.get(self.f.candidate_ids[0], "candidate")
        return self.c.candidate(id_=name, run_id=RUN, assertion=old["assertion"], claim_id=old["claim_id"], evidence_ids=old["evidence_ids"])

    def test_minimum_closure_materialization(self):
        pack, _ = self.retrieved_pack()
        p = self.c.get(pack, "pack")
        validate_pack(self.c, p, source_status=self.f.backend.statuses())
        self.assertFalse(p["state"]["graph_snapshot"]["full_snapshot_in_model_context"])
        self.assertNotIn("assertions", p["state"]["graph_snapshot"])
        self.assertTrue(p["state"]["graph_context"])
        self.assertEqual(p["evidence_closure_id"], "closure:"+p["closure"]["hash"])

    def test_legacy_pack_unchanged(self):
        p = self.c.get(self.f.pack_id, "pack")
        self.assertEqual(p["materializer_version"], "materializer-v1")
        self.assertNotIn("graph_context_ids", p)
        self.assertIn("assertions", p["state"]["graph_snapshot"])

    def test_no_graph_ablation_is_explicit_empty_selection(self):
        p = compile_pack(self.c, id_="no-graph", run_id=RUN, candidate_ids=self.f.candidate_ids,
            questions=[question(self.f.candidate_ids[0], id_="without")], snapshot_id=self.f.snapshot_id,
            security_scope=SCOPE, graph_context_ids=[], source_retrieval_ids=[])
        self.assertEqual(self.c.get(p, "pack")["state"]["graph_context"], [])
        validate_pack(self.c, self.c.get(p, "pack"))

    def test_observation_lineage_is_derived(self):
        pack, result = self.retrieved_pack()
        ids = record_response(self.c, pack, fixture_response(self.c.get(pack, "pack")))
        o = self.c.get(ids[0], "observation")
        self.assertEqual(o["source_retrieval_ids"], [result])
        self.assertEqual(o["graph_context_ids"], self.c.get(pack, "pack")["graph_context_ids"])
        validate_observation(self.c, ids[0])

    def test_forged_observation_lineage_fails(self):
        pack, _ = self.retrieved_pack()
        obs = record_response(self.c, pack, fixture_response(self.c.get(pack, "pack")))[0]
        changed = self.c.get(obs, "observation")
        changed["source_retrieval_ids"] = []
        ref = self.c.put("observation", changed)
        with self.assertRaisesRegex(ContractError, "RETRIEVAL_LINEAGE"):
            validate_observation(self.c, ref)

    def test_bounded_policy_changes_qualification_scope(self):
        pack, _ = self.retrieved_pack()
        p = self.c.get(pack, "pack")
        self.assertNotEqual(p["packing_version"], self.c.get(self.f.pack_id, "pack")["packing_version"])
        self.assertIn(p["retrieval_fingerprint"], p["packing_version"])

    def test_retrieval_graph_version_must_match_pack(self):
        _, result_id = self.retrieved_pack()
        result = self.c.get(result_id, "retrieval-result")
        self.publish_graph()
        snap = self.f.backend.snapshot(self.c)
        with self.assertRaisesRegex(ContractError, "STALE_GRAPH_CONTEXT"):
            compile_pack(self.c, id_="mismatched", run_id=RUN, candidate_ids=self.f.candidate_ids,
                         questions=[question(self.f.candidate_ids[0], id_="q")], snapshot_id=snap, security_scope=SCOPE,
                         graph_context_ids=[result["graph_context_id"]], source_retrieval_ids=[result_id])

    def test_context_is_not_mutation_authority(self):
        before = self.f.backend.state()
        self.retrieved_pack()
        self.assertEqual(self.f.backend.state(), before)

    def test_transaction_to_retrieval_visibility(self):
        before = self.r.retrieve(self.request(downstream=True))
        first = self.c.get(self.c.get(before, "retrieval-result")["graph_context_id"], "graph-context")
        self.assertFalse(first["retrieved_edges"])
        self.publish_graph()
        answer = GraphRAGQueryService(self.r).query(self.request(downstream=True))
        self.assertIn(self.f.candidate_ids[0], {edge for i in answer["context"]["items"] for edge in i["assertion_ids"]})
        self.assertGreater(answer["context"]["graph_version"], first["graph_version"])

    def test_complete_committed_provenance(self):
        self.publish_graph()
        answer = GraphRAGQueryService(self.r).query(self.request(downstream=True))
        edge = next(i for i in answer["context"]["items"] if i["kind"] == "EDGE")
        self.assertTrue(edge["transaction_ids"])
        self.assertTrue(edge["decision_ids"])
        self.assertTrue(edge["observation_ids"])
        self.assertTrue(edge["provenance_complete"])
        self.assertEqual(edge["trust_class"], "PROVISIONAL_GRAPH_FACT")  # Fabricated inference is not verified truth.

    def test_provenance_depth_cap(self):
        self.publish_graph()
        q = self.request(downstream=True, budget=RetrievalBudget(maximum_provenance_depth=1, maximum_tokens=60000))
        answer = GraphRAGQueryService(self.r).query(q)
        edge = next(i for i in answer["context"]["items"] if i["kind"] == "EDGE")
        self.assertTrue(edge["transaction_ids"])
        self.assertFalse(edge["observation_ids"])
        self.assertFalse(edge["provenance_complete"])

    def test_historical_snapshot_after_withdrawal(self):
        commit, _ = self.publish_graph()
        old_version = commit["receipt"]["version"]
        self.f.status_change(self.f.source_ids[0])
        current = GraphRAGQueryService(self.r).query(self.request(downstream=True))
        self.assertFalse(any(i["assertion_ids"] for i in current["context"]["items"]))
        historical = GraphRAGQueryService(self.r).query(self.request(downstream=True, graph_version=old_version, include_historical=True, mode="HISTORICAL"))
        # Historical facts remain in their immutable snapshot, but present-time
        # source withdrawal is a use revocation, not just a "latest" filter.
        self.assertFalse(any(i["assertion_ids"] for i in historical["context"]["items"]))
        self.assertEqual(historical["context"]["graph_version"], old_version)

    def test_historical_does_not_restore_denied_permissions(self):
        commit, _ = self.publish_graph()
        self.f.status_change(self.f.source_ids[0], permission="DENIED")
        result = GraphRAGQueryService(self.r).query(self.request(downstream=True,
            graph_version=commit["receipt"]["version"], include_historical=True, mode="HISTORICAL"))
        self.assertFalse(any(i["evidence_ids"] for i in result["context"]["items"]))

    def test_knowledge_before_source_arrival(self):
        q = self.request(downstream=True, temporal_scope={"as_of": None, "valid_at": None, "before_source": self.f.source_ids[0]})
        result = GraphRAGQueryService(self.r).query(q)
        self.assertEqual(result["context"]["graph_version"], 0)
        self.assertFalse(result["context"]["citations"])

    def test_as_of_snapshot_and_conflicting_selectors(self):
        commit, _ = self.publish_graph()
        request = self.request(downstream=True, temporal_scope={"as_of": commit["receipt"]["committed_at"], "valid_at": None, "before_source": None})
        result = GraphRAGQueryService(self.r).query(request)
        self.assertEqual(result["context"]["graph_version"], commit["receipt"]["version"])
        request["graph_version"] = 0
        with self.assertRaisesRegex(ContractError, "TEMPORAL_SCOPE_CONFLICT"):
            self.r.retrieve(request)

    def test_failed_transaction_not_visible(self):
        before = self.f.backend.state()
        def crash(point):
            if point == "after_state_write":
                raise RuntimeError("injected")
        with self.assertRaises(RuntimeError):
            self.f.publish(fault=crash)
        self.assertEqual(self.f.backend.state(), before)
        result = GraphRAGQueryService(self.r).query(self.request(downstream=True))
        self.assertFalse(any(i["assertion_ids"] for i in result["context"]["items"]))

    def test_expansion_on_insufficient_then_resolution(self):
        self.publish_graph()
        candidate = self.new_candidate()
        calls = []
        def execute(pack):
            p = self.c.get(pack, "pack")
            calls.append(pack)
            has_edge = any(i["kind"] == "EDGE" for ctx in p["state"]["graph_context"] for i in ctx["items"])
            return record_response(self.c, pack, fixture_response(p, [.95 if has_edge else .2]))
        run = UpstreamGraphRAG(self.r).run(candidate_id=candidate, execute=execute, run_budget=self.f.budget,
            policy_version=POLICY, population=POPULATION, budget=RetrievalBudget(maximum_tokens=16000, maximum_latency_ms=10000))
        self.assertGreaterEqual(len(run.result_ids), 2)
        self.assertIn(candidate, self.c.get(run.batch_id, "resolution-batch")["selected_ids"])
        self.assertEqual(run.stop_reason, "HUMAN_REVIEW_REQUIRED")
        self.assertTrue(self.c.get(run.resolution_ids[0], "resolution")["graph_context_ids"])
        self.assertEqual(self.c.get(run.expansion_ids[0], "retrieval-expansion")["decision_after"], "RETRIEVE_MORE_EVIDENCE")

    def test_saturation_stops(self):
        candidate = self.new_candidate()
        planner = RetrievalPlanner({"ASSERTION": [["ENTITY", "SOURCE"]]*5})
        run = UpstreamGraphRAG(self.r, planner).run(candidate_id=candidate,
            execute=lambda pack: record_response(self.c, pack, fixture_response(self.c.get(pack, "pack"), [.2])),
            run_budget=self.f.budget, policy_version=POLICY, population=POPULATION,
            budget=RetrievalBudget(maximum_latency_ms=10000))
        self.assertEqual(run.stop_reason, "RETRIEVAL_SATURATED")
        self.assertEqual(len(run.result_ids), 2)

    def test_round_cap(self):
        candidate = self.new_candidate()
        run = UpstreamGraphRAG(self.r).run(candidate_id=candidate,
            execute=lambda p: record_response(self.c, p, fixture_response(self.c.get(p, "pack"), [.2])),
            run_budget=self.f.budget, policy_version=POLICY, population=POPULATION,
            budget=RetrievalBudget(maximum_rounds=1, maximum_latency_ms=10000))
        self.assertEqual(run.stop_reason, "MAXIMUM_ROUNDS")
        self.assertEqual(len(run.pack_ids), 1)

    def test_budget_zero_no_model_call(self):
        candidate = self.new_candidate()
        called = []
        run = UpstreamGraphRAG(self.r).run(candidate_id=candidate, execute=lambda p: called.append(p),
            run_budget=self.f.budget, policy_version=POLICY, population=POPULATION,
            budget=RetrievalBudget(maximum_cost_units=0))
        self.assertFalse(called)
        self.assertEqual(run.stop_reason, "RETRIEVAL_BUDGET_EXHAUSTED")

    def test_semantic_reranking_uses_existing_adapter(self):
        result_id = self.r.retrieve(self.request())
        reranker = JevReranker(lambda p: record_response(self.c, p, fixture_response(self.c.get(p, "pack"))))
        new_id = reranker.rerank(self.r, result_id, candidate_id=self.f.candidate_ids[0])
        ctx = self.c.get(self.c.get(new_id, "retrieval-result")["graph_context_id"], "graph-context")
        self.assertTrue(ctx["reranking_observation_ids"])
        validate_context(self.c, self.c.get(new_id, "retrieval-result")["graph_context_id"])
        for obs in ctx["reranking_observation_ids"]:
            self.assertEqual(self.c.get(obs, "observation")["semantic_outcome"], "RELEVANT")

    def test_retrieval_records_join_existing_causal_ledger(self):
        self.retrieved_pack()
        events = build_ledger(self.c, run_id=RUN, execution_mode="SYNTHETIC")
        self.assertTrue(any(e["stage"] == "RETRIEVAL" for e in events))
        bundle = make_bundle(self.c, run_id=RUN, execution_mode="SYNTHETIC", security_scope=SCOPE,
            graph_version=self.f.backend.state()["graph_version"], schema_hash=self.c.hash(self.f.schema_id),
            source_status=self.f.backend.statuses(), policy_version=POLICY)
        report = validate_bundle(bundle)
        self.assertTrue(report["lineage_complete"])

    def test_replay_preserves_original_model_receipts(self):
        pack, ref = self.retrieved_pack()
        obs = record_response(self.c, pack, fixture_response(self.c.get(pack, "pack")))[0]
        before = self.c.hash(obs)
        replay = replay_retrieval(self.r, ref, {"retrieval_strategy": ["SOURCE"]})
        self.assertEqual(self.c.hash(obs), before)
        self.assertEqual(self.c.get(replay, "retrieval-replay")["observation_hashes_preserved"][obs], before)

    def test_summary_cannot_be_substituted_for_source_evidence(self):
        _, ref = self.retrieved_pack()
        result = self.c.get(ref, "retrieval-result")
        with self.assertRaisesRegex(ContractError, "REFERENCE_TYPE"):
            self.c.candidate(id_="summary-as-evidence", run_id=RUN, assertion=self.c.get(self.f.candidate_ids[0], "candidate")["assertion"],
                claim_id=self.f.claim_id, evidence_ids=[result["graph_context_id"]])

    def test_source_firewall_preserves_exact_quotes(self):
        pack, _ = self.retrieved_pack()
        p = self.c.get(pack, "pack")
        for evidence in p["state"]["evidence"]:
            self.assertEqual(evidence["text"], self.c.get(evidence["id"], "evidence")["quote"])
        self.assertIn("untrusted data", p["questions"][0]["instructions"])

    def test_planner_task_specific_policy(self):
        planner = RetrievalPlanner()
        a = planner.plan(self.c, candidate_id=self.f.candidate_ids[0], question_type="IDENTITY", risk_class="R4",
            known_entities=["person-a"], known_relations=["same_as"], budget=RetrievalBudget(), tier=1)
        b = planner.plan(self.c, candidate_id=self.f.candidate_ids[0], question_type="ONTOLOGY", risk_class="R2",
            known_entities=["person-a"], known_relations=["same_as"], budget=RetrievalBudget(), tier=1)
        self.assertNotEqual(self.c.get(a, "retrieval-plan")["steps"], self.c.get(b, "retrieval-plan")["steps"])

if __name__ == "__main__":
    unittest.main()
