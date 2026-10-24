from __future__ import annotations
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from trace_gc.compiler import compile_pack, validate_pack
from trace_gc.demo import build_fixture, fixture_response, RUN, POLICY, SCOPE as PIPELINE_SCOPE
from trace_gc.adapter import record_response
from trace_gc.programs import question
from trace_gc.errors import ContractError
from trace_gc.retrieval.budget import BudgetMeter
from trace_gc.retrieval.contracts import query, RetrievalBudget
from trace_gc.retrieval.fixtures import corpus, demo_access, SCOPE
from trace_gc.retrieval.service import HybridRetriever, GraphRAGQueryService, validate_context
from trace_gc.retrieval.store import SQLiteGraphAdapter
from trace_gc.retrieval.reranker import JevReranker
from trace_gc.retrieval.integration import validate_record

class RetrievalSecurityTests(unittest.TestCase):
    def setUp(self):
        self.f = corpus()
        self.c, self.r = self.f["catalog"], self.f["retriever"]
    def request(self, **changes):
        return query(requesting_component="downstream-search", security_scope=SCOPE,
            focus_entities=changes.pop("focus_entities", [self.f["claim_id"]]),
            strategies=changes.pop("strategies", ["NEIGHBORHOOD", "CONFLICT"]), **changes)
    def ctx(self, request=None):
        ref = self.r.retrieve(request or self.request())
        result = self.c.get(ref, "retrieval-result")
        return ref, result, self.c.get(result["graph_context_id"], "graph-context")
    def test_conflict_pair_budget_never_becomes_one_sided(self):
        _, result, context = self.ctx(self.request(budget=RetrievalBudget(maximum_edges=1)))
        self.assertFalse({"e-support", "e-refute"} & set(context["retrieved_edges"]))
        self.assertIn("CONFLICT_PAIR_EXCLUDED_BY_BUDGET", result["warnings"])
    def test_retrieval_fingerprint_is_reconstructed(self):
        _, _, body = self.ctx()
        body["retrieval_fingerprint"] = "0"*64
        with self.assertRaisesRegex(ContractError, "RETRIEVAL_CONFIGURATION"):
            validate_context(self.c, self.c.put("graph-context", body))
    def test_strategy_versions_are_bound(self):
        _, _, body = self.ctx()
        body["strategy_versions"]["CONFLICT"] = "unreviewed-change"
        with self.assertRaisesRegex(ContractError, "RETRIEVAL_CONFIGURATION"):
            validate_context(self.c, self.c.put("graph-context", body))
    def test_forged_path_projection_rejected(self):
        _, _, body = self.ctx()
        body["retrieved_paths"] = ["unretrieved-path"]
        with self.assertRaisesRegex(ContractError, "CONTEXT_PROJECTION"):
            validate_context(self.c, self.c.put("graph-context", body))
    def test_forged_conflict_projection_rejected(self):
        _, _, body = self.ctx()
        body["conflict_refs"] = []
        with self.assertRaisesRegex(ContractError, "CONTEXT_PROJECTION"):
            validate_context(self.c, self.c.put("graph-context", body))
    def test_custom_counter_cannot_underreport_context(self):
        self.r.token_counter = lambda item: 0
        _, result, body = self.ctx(self.request(budget=RetrievalBudget(maximum_tokens=1)))
        self.assertFalse(body["items"])
        self.assertEqual(result["usage"]["tokens"], 0)
    def test_explicit_empty_strategies_stays_empty(self):
        _, result, body = self.ctx(self.request(strategies=[]))
        self.assertEqual(body["retrieval_methods"], [])
        self.assertEqual(result["status"], "EMPTY")
    def test_latest_state_filters_expired_relationship(self):
        _, _, body = self.ctx(self.request(focus_entities=["Acme"], strategies=["TEMPORAL", "NEIGHBORHOOD"], mode="LATEST_VALID_STATE"))
        self.assertNotIn("e-partner", body["retrieved_edges"])
    def test_historical_mode_marks_historical_context(self):
        _, _, body = self.ctx(self.request(focus_entities=["Acme"], strategies=["NEIGHBORHOOD"], mode="HISTORICAL"))
        self.assertTrue(any(i["trust_class"] == "HISTORICAL_GRAPH_FACT" for i in body["items"]))
    def test_ontology_strategy_traverses_type_graph(self):
        _, _, body = self.ctx(self.request(focus_entities=["Organization"], strategies=["ONTOLOGY"], ontology_scope=["Organization", "Entity"]))
        self.assertIn("e-ontology", body["retrieved_edges"])
    def candidate(self):
        ref = self.c.candidate(id_="undecided", run_id="fixture-run", claim_id=self.f["claim_id"], evidence_ids=[self.f["evidence"]["e-support"]],
            assertion={"subject": "Paper-A", "predicate": "supports", "object": self.f["claim_id"], "qualifiers": {}})
        self.r.set_access_policy(demo_access(self.c, self.f["snapshot_id"]))
        return ref
    def test_unresolved_hypothesis_is_separate_from_graph(self):
        self.candidate()
        _, _, body = self.ctx(self.request(strategies=["DECISION"], include_historical=True))
        hypotheses = [i for i in body["items"] if i["kind"] == "HYPOTHESIS"]
        self.assertTrue(hypotheses)
        self.assertFalse(hypotheses[0]["assertion_ids"])
        self.assertEqual(hypotheses[0]["current_status"], "PROPOSED_NOT_GRAPH_TRUTH")
    def test_default_hides_unresolved_hypotheses(self):
        self.candidate()
        _, _, body = self.ctx(self.request(strategies=["DECISION"]))
        self.assertFalse(any(i["kind"] == "HYPOTHESIS" for i in body["items"]))
    def test_candidate_cannot_retrieve_itself_as_support(self):
        ref = self.candidate()
        request = self.request(strategies=["DECISION"], include_historical=True, candidate_id=ref)
        request["requesting_component"] = "upstream-synthesis"
        _, _, body = self.ctx(request)
        self.assertFalse(any(i["canonical_ref"] == ref for i in body["items"]))
    def test_hypothesis_endpoint_acl_is_checked(self):
        self.candidate()
        policy = deepcopy(self.r.access_policy)
        policy["grants"].pop("node:Paper-A")
        self.r.set_access_policy(policy)
        _, _, body = self.ctx(self.request(strategies=["DECISION"], include_historical=True))
        self.assertFalse(any(i["kind"] == "HYPOTHESIS" for i in body["items"]))
    def nonempty_answer(self):
        # BudgetMeter binds its default clock when the class is defined, so the
        # keyword default itself is replaced. A frozen clock removes host load
        # from the original selection without changing any production limit.
        calls = []
        def frozen():
            calls.append(1)
            return 0.0
        patcher = mock.patch.dict(BudgetMeter.__init__.__kwdefaults__, {"clock": frozen})
        patcher.start()
        self.addCleanup(patcher.stop)
        answer = GraphRAGQueryService(self.r).query(self.request())
        body = answer["context"]
        result = self.c.get(body["result_id"], "retrieval-result")
        context = self.c.get(body["graph_context_id"], "graph-context")
        lineage = self.c.get(result["lineage_id"], "retrieval-lineage")
        detail = {"status": result["status"], "warnings": body["warnings"], "stop_reason": lineage["stop_reason"],
                  "usage": result["usage"], "latency_ms": lineage["latency_ms"], "clock_calls": len(calls)}
        self.assertTrue(calls, detail)
        self.assertTrue(context["selected_evidence_ids"], detail)
        self.assertEqual(sorted(x["evidence_id"] for x in body["citations"]), context["selected_evidence_ids"], detail)
        self.assertNotIn("RETRIEVAL_BUDGET_EXHAUSTED", body["warnings"], detail)
        return body
    def test_answer_citations_cannot_be_silently_removed(self):
        body = self.nonempty_answer()
        body["citations"] = []
        with self.assertRaisesRegex(ContractError, "PROVENANCE_MISMATCH"):
            validate_record(self.c, self.c.record(self.c.put("graphrag-answer", body)))
    def test_answer_source_identity_cannot_be_changed(self):
        body = self.nonempty_answer()
        body["citations"][0]["source_id"] = "different-paper"
        with self.assertRaisesRegex(ContractError, "PROVENANCE_MISMATCH"):
            validate_record(self.c, self.c.record(self.c.put("graphrag-answer", body)))
    def test_lineage_ranking_cannot_disagree_with_context(self):
        _, result, _ = self.ctx()
        body = self.c.get(result["lineage_id"], "retrieval-lineage")
        body["candidates"][0]["score"] += 100
        with self.assertRaisesRegex(ContractError, "RETRIEVAL_LINEAGE"):
            validate_record(self.c, self.c.record(self.c.put("retrieval-lineage", body)))

class ModelBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.f = build_fixture(Path(self.t.name), candidate_count=1)
        self.c = self.f.catalog
        self.r = HybridRetriever(SQLiteGraphAdapter(self.f.backend, self.c), catalog=self.c,
            access_policy=demo_access(self.c, self.f.snapshot_id, scope=PIPELINE_SCOPE))
        self.result = self.r.retrieve(query(requesting_component="upstream-synthesis", security_scope=PIPELINE_SCOPE,
            candidate_id=self.f.candidate_ids[0], focus_entities=["document-demo"], strategies=["ENTITY", "SOURCE"]))
    def tearDown(self):
        self.f.close()
        self.t.cleanup()
    def test_candidate_source_acl_rechecked_before_model_context(self):
        result = self.c.get(self.result, "retrieval-result")
        pack = compile_pack(self.c, id_="acl-bound-pack", run_id=RUN, candidate_ids=self.f.candidate_ids,
            questions=[question(self.f.candidate_ids[0], id_="q")], snapshot_id=self.f.snapshot_id, security_scope=PIPELINE_SCOPE,
            graph_context_ids=[result["graph_context_id"]], source_retrieval_ids=[self.result])
        policy = deepcopy(self.r.access_policy)
        policy["grants"].pop("source:"+self.f.source_ids[0])
        with self.assertRaises(ContractError):
            validate_pack(self.c, self.c.get(pack, "pack"), current_graph_access=policy, source_status=self.f.backend.statuses())
    def reranked(self):
        return JevReranker(lambda p: record_response(self.c, p, fixture_response(self.c.get(p, "pack")))).rerank(
            self.r, self.result, candidate_id=self.f.candidate_ids[0])
    def test_reranking_can_only_change_receipt_derived_order(self):
        result = self.c.get(self.reranked(), "retrieval-result")
        body = self.c.get(result["graph_context_id"], "graph-context")
        body["ranking_scores"][body["items"][0]["id"]] += 99
        with self.assertRaisesRegex(ContractError, "RERANK_OBSERVATION"):
            validate_context(self.c, self.c.put("graph-context", body))
    def test_rerank_observation_coverage_required(self):
        result = self.c.get(self.reranked(), "retrieval-result")
        body = self.c.get(result["graph_context_id"], "graph-context")
        body["reranking_observation_ids"] = []
        with self.assertRaisesRegex(ContractError, "RERANK_OBSERVATION"):
            validate_context(self.c, self.c.put("graph-context", body))
    def test_rerank_no_recursive_self_reinforcement(self):
        ref = self.reranked()
        with self.assertRaisesRegex(ContractError, "RERANK_OBSERVATION"):
            JevReranker(lambda p: []).rerank(self.r, ref, candidate_id=self.f.candidate_ids[0])

if __name__ == "__main__":
    unittest.main()
