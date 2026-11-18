"""Semantic reranking keeps the exact domain view and rechecks current authority.

All labels and model responses are synthetic fixtures. The reranker is called
through the existing pack/observation adapter; no live model is used.
"""
from __future__ import annotations

from copy import deepcopy
import unittest

from trace_gc.adapter import record_response
from trace_gc.compiler import compile_pack
from trace_gc.demo import fixture_response
from trace_gc.errors import ContractError
from trace_gc.programs import question
from trace_gc.replay import replay_retrieval
from trace_gc.retrieval.contracts import query, RetrievalBudget
from trace_gc.retrieval.domains import research_domain_scope
from trace_gc.retrieval.fixtures import demo_access, domain_corpus, SCOPE
from trace_gc.retrieval.reranker import JevReranker, validate_reranked_context
from trace_gc.retrieval.service import validate_context


class DomainSemanticBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.f = domain_corpus()
        self.c, self.r = self.f["catalog"], self.f["retriever"]
        self.scope = research_domain_scope(self.c, self.f["taxonomy_id"], ["research:biology"])
        fact = self.c.get(self.f["snapshot_id"])["assertions"]["e-support"]
        self.candidate = self.c.candidate(id_="candidate:domain-rerank", run_id="domain-rerank-fixture",
            assertion=fact["assertion"], claim_id=self.f["claim_id"], evidence_ids=fact["evidence_ids"])
        request = query(requesting_component="upstream-synthesis", candidate_id=self.candidate,
            security_scope=SCOPE, strategies=["LEXICAL"], text="improves", include_conflicts=False,
            research_domain_scope=self.scope,
            budget=RetrievalBudget(maximum_tokens=150000, maximum_latency_ms=20000, maximum_edges=100,
                                   maximum_nodes=100, maximum_source_spans=100))
        self.result_id = self.r.retrieve(request)
        self.calls = []

        def execute(pack_id):
            self.calls.append(pack_id)
            return record_response(self.c, pack_id, fixture_response(self.c.get(pack_id, "pack")))
        self.reranker = JevReranker(execute)

    def rerank(self):
        return self.reranker.rerank(self.r, self.result_id, candidate_id=self.candidate)

    def test_rerank_preserves_scope_revision_items_and_cross_domain_closure(self):
        before = self.c.get(self.c.get(self.result_id)["graph_context_id"])
        reranked_id = self.rerank()
        after_id = self.c.get(reranked_id)["graph_context_id"]
        after = self.c.get(after_id)
        validate_context(self.c, after_id, current_access=self.r.access_policy,
                         current_status=self.f["adapter"].source_status)
        validate_reranked_context(self.c, after)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(after["research_domain_scope"], self.scope)
        self.assertEqual(after["classification_identity"], before["classification_identity"])
        self.assertEqual({item["id"] for item in after["items"]}, {item["id"] for item in before["items"]})
        # The refuting evidence outside the requested label stays selected: ranking is not membership.
        self.assertIn(self.f["evidence"]["e-refute"], after["selected_evidence_ids"])

    def test_reranked_context_cannot_swap_the_domain_scope(self):
        after = deepcopy(self.c.get(self.c.get(self.rerank())["graph_context_id"]))
        after["research_domain_scope"] = {**self.scope, "domain_ids": ["research:physics"]}
        with self.assertRaisesRegex(ContractError, "RERANK_OBSERVATION"):
            validate_reranked_context(self.c, after)

    def test_source_revocation_after_retrieval_prevents_the_semantic_call(self):
        self.f["adapter"].source_status[self.f["sources"]["e-support"]].update(active=False, epoch=2)
        with self.assertRaisesRegex(ContractError, "RESEARCH_DOMAIN_SCOPE|ACCESS_DENIED"):
            self.rerank()
        self.assertEqual(self.calls, [])

    def test_revocation_during_rerank_prevents_returning_a_stale_context(self):
        execute = self.reranker.execute
        before = len(self.c.all("graph-context"))

        def execute_then_withdraw(pack_id):
            observations = execute(pack_id)
            self.f["adapter"].source_status[self.f["sources"]["e-refute"]].update(active=False, epoch=2)
            return observations

        self.reranker.execute = execute_then_withdraw
        with self.assertRaisesRegex(ContractError, "ACCESS_DENIED"):
            self.rerank()
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(len(self.c.all("graph-context")), before)

    def test_current_acl_revocation_prevents_the_semantic_call(self):
        policy = deepcopy(self.r.access_policy)
        del policy["grants"]["source:" + self.f["sources"]["e-support"]]
        self.r.set_access_policy(policy)
        with self.assertRaisesRegex(ContractError, "RESEARCH_DOMAIN_SCOPE|ACCESS_DENIED"):
            self.rerank()
        self.assertEqual(self.calls, [])

    def result_with_prerequisite(self):
        fact = self.c.get(self.f["snapshot_id"])["assertions"]["e-owns"]
        prerequisite = self.c.candidate(id_="candidate:prerequisite", run_id="domain-rerank-fixture",
            assertion=fact["assertion"], claim_id=self.f["claim_id"], evidence_ids=fact["evidence_ids"])
        root = self.c.get(self.candidate, "candidate")
        candidate = self.c.candidate(id_="candidate:with-prerequisite", run_id=root["run_id"],
            assertion=root["assertion"], claim_id=root["claim_id"], evidence_ids=root["evidence_ids"],
            prerequisites=[prerequisite])
        result = self.c.get(self.result_id, "retrieval-result")
        request = self.c.get(result["query_id"], "retrieval-query")
        return candidate, self.r.retrieve({**request, "candidate_id": candidate})

    def test_prerequisite_endpoints_are_authorized_before_token_counting(self):
        candidate, result_id = self.result_with_prerequisite()
        policy = deepcopy(self.r.access_policy)
        del policy["grants"]["node:Acme"]
        self.r.set_access_policy(policy)
        counted = []
        self.reranker.token_counter = lambda value: counted.append(value) or 0
        with self.assertRaisesRegex(ContractError, "ACCESS_DENIED"):
            self.reranker.rerank(self.r, result_id, candidate_id=candidate)
        self.assertEqual(counted, [])
        self.assertEqual(self.calls, [])

    def test_authorization_is_rechecked_after_token_counting(self):
        counted = []

        def count(value):
            counted.append(value)
            self.f["adapter"].source_status[self.f["sources"]["e-support"]].update(active=False, epoch=2)
            return 0

        self.reranker.token_counter = count
        with self.assertRaisesRegex(ContractError, "ACCESS_DENIED"):
            self.rerank()
        self.assertTrue(counted)
        self.assertEqual(self.calls, [])

    def test_candidate_sources_are_authorized_before_upstream_embedding(self):
        calls = []
        self.r.embedding.embed = lambda texts: calls.append(texts) or []
        result = self.c.get(self.result_id, "retrieval-result")
        request = self.c.get(result["query_id"], "retrieval-query")
        self.f["adapter"].source_status[self.f["sources"]["e-support"]].update(active=False, epoch=2)
        with self.assertRaisesRegex(ContractError, "ACCESS_DENIED"):
            self.r.retrieve({**request, "retrieval_strategy": ["VECTOR"]})
        self.assertEqual(calls, [])

    def test_replay_requires_current_access_to_original_context(self):
        self.f["adapter"].source_status[self.f["sources"]["e-refute"]].update(active=False, epoch=2)
        with self.assertRaisesRegex(ContractError, "ACCESS_DENIED"):
            replay_retrieval(self.r, self.result_id, {}, synthesize=self.reranker.execute)
        self.assertEqual(self.calls, [])

    def test_replay_omits_linked_receipt_when_its_full_pack_access_is_revoked(self):
        candidate, result_id = self.result_with_prerequisite()
        context_id = self.c.get(result_id, "retrieval-result")["graph_context_id"]
        pack_id = compile_pack(self.c, id_="pack:replay-prerequisite",
            run_id="domain-rerank-fixture", candidate_ids=[candidate], questions=[question(candidate, id_="support")],
            snapshot_id=self.f["snapshot_id"], security_scope=SCOPE,
            graph_context_ids=[context_id], source_retrieval_ids=[result_id])
        observation = record_response(self.c, pack_id, fixture_response(self.c.get(pack_id, "pack")))[0]
        before = self.c.hash(observation)
        no_grant = self.c.get(replay_retrieval(self.r, result_id, {}), "retrieval-replay")
        self.assertEqual(no_grant["observation_hashes_preserved"], {})
        self.r.set_access_policy(demo_access(self.c, self.f["snapshot_id"]))
        permitted = self.c.get(replay_retrieval(self.r, result_id, {}), "retrieval-replay")
        self.assertEqual(permitted["observation_hashes_preserved"], {observation: before})
        policy = deepcopy(self.r.access_policy)
        del policy["grants"]["node:Acme"]
        self.r.set_access_policy(policy)
        denied = self.c.get(replay_retrieval(self.r, result_id, {}), "retrieval-replay")
        self.assertEqual(denied["observation_hashes_preserved"], {})
        self.assertEqual(self.c.hash(observation), before)


if __name__ == "__main__":
    unittest.main()
