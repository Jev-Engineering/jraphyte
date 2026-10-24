"""All-channel reference conformance; every label and response is synthetic.

The tests require the requested channel's own positive result. Conflict fallback
cannot make an otherwise empty channel appear covered. No live model or authority
is enrolled, and no representative-corpus or deployment claim is made.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import unittest
from unittest.mock import patch

from trace_gc.adapter import record_response
from trace_gc.canonical import digest
from trace_gc.catalog import Catalog
from trace_gc.compiler import compile_pack, validate_pack
from trace_gc.demo import fixture_response
from trace_gc.domains import create_assignment, reference_taxonomy
from trace_gc.errors import ContractError
from trace_gc.programs import question
from trace_gc.replay import replay_retrieval
from trace_gc.retrieval.contracts import query, RetrievalBudget, STRATEGIES
from trace_gc.retrieval.domains import ResearchDomainSelection, research_domain_scope
from trace_gc.retrieval.fixtures import domain_corpus, demo_access, SCOPE
from trace_gc.retrieval.integration import validate_record, validate_pack_lineage
from trace_gc.retrieval.items import authorized_scope_edges, canonical_item, conflict_pairs
from trace_gc.retrieval.planner import RetrievalPlanner
from trace_gc.retrieval.security import AccessFilter
from trace_gc.retrieval.service import GraphRAGQueryService, HybridRetriever, validate_context
from trace_gc.retrieval.store import GraphReadView, InMemoryGraphAdapter


class SpyEmbedding:
    version = "domain-embedding-spy-fixture-v1"

    def __init__(self, callback=None):
        self.seen = []
        self.callback = callback

    def embed(self, texts):
        self.seen.extend(texts)
        if self.callback:
            self.callback()
        return [[1.0, 0.0] for _ in texts]


class DomainRetrievalTests(unittest.TestCase):
    def setUp(self):
        self.f = domain_corpus()
        self.c = self.f["catalog"]
        self.r = self.f["retriever"]
        self.scope = research_domain_scope(self.c, self.f["taxonomy_id"], ["research:biology"])
        self.budget = RetrievalBudget(maximum_tokens=150000, maximum_latency_ms=20000,
                                      maximum_edges=100, maximum_nodes=100, maximum_source_spans=100)

    def request(self, strategies=None, **changes):
        return query(requesting_component="downstream-search", security_scope=SCOPE,
                     strategies=strategies or ["RELATION"], budget=changes.pop("budget", self.budget),
                     focus_entities=changes.pop("focus_entities", []), text=changes.pop("text", ""),
                     include_conflicts=changes.pop("include_conflicts", False),
                     research_domain_scope=changes.pop("research_domain_scope", self.scope), **changes)

    def context(self, request):
        result_id = self.r.retrieve(request)
        result = self.c.get(result_id, "retrieval-result")
        context = self.c.get(result["graph_context_id"], "graph-context")
        validate_context(self.c, result["graph_context_id"], current_access=self.r.access_policy,
                         current_status=self.f["adapter"].source_status)
        validate_record(self.c, self.c.record(result["lineage_id"]))
        validate_record(self.c, self.c.record(result_id))
        return context, result

    def add_decisions(self):
        """Exercise real compiler/adapter observation records, not invented bodies."""
        result = {}
        for edge in ("e-support", "e-refute"):
            fact = self.c.get(self.f["snapshot_id"])["assertions"][edge]
            candidate = self.c.candidate(id_="candidate:domain-" + edge, run_id="domain-retrieval-fixture",
                assertion=fact["assertion"], claim_id=self.f["claim_id"], evidence_ids=fact["evidence_ids"])
            pack = compile_pack(self.c, id_="pack:domain-" + edge, run_id="domain-retrieval-fixture",
                candidate_ids=[candidate], questions=[question(candidate, id_="q-" + edge)],
                snapshot_id=self.f["snapshot_id"], security_scope=SCOPE)
            observation = record_response(self.c, pack, fixture_response(self.c.get(pack)))[0]
            result[edge] = (candidate, observation)
        self.r.set_access_policy(demo_access(self.c, self.f["snapshot_id"]))
        return result

    def test_each_strategy_has_its_own_positive_canonical_result(self):
        decisions = self.add_decisions()
        self.r.embedding = SpyEmbedding()
        cases = {
            "ENTITY": ("NODE", {"focus_entities": ["Acme"]}),
            "LEXICAL": ("EVIDENCE", {"text": "randomized"}),
            "VECTOR": ("EVIDENCE", {"text": "biological methods"}),
            "NEIGHBORHOOD": ("EDGE", {"focus_entities": ["Acme"]}),
            "PATH": ("PATH", {"focus_entities": ["Acme"], "hop_limit": 2}),
            "COMMUNITY": ("COMMUNITY", {"focus_entities": ["Acme"]}),
            "GLOBAL": ("EDGE", {}),
            "ONTOLOGY": ("ONTOLOGY", {"ontology_scope": ["Organization"], "focus_relationships": ["owns"]}),
            "SCHEMA": ("SCHEMA", {"ontology_scope": ["Organization"], "focus_relationships": ["owns"]}),
            "RELATION": ("EDGE", {"focus_entities": ["Acme"]}),
            "PROVENANCE": ("PROVENANCE", {"focus_entities": ["Acme"]}),
            "EVIDENCE": ("EVIDENCE", {"focus_entities": ["Paper-A"]}),
            "CONFLICT": ("CONFLICT", {"focus_entities": [self.f["claim_id"]]}),
            "DECISION": ("DECISION", {"decision_id": decisions["e-support"][1]}),
            "TEMPORAL": ("EDGE", {"focus_entities": ["Acme"], "temporal_scope": {
                "as_of": None, "valid_at": "2024-04-02T00:00:00Z", "before_source": None}}),
            "SOURCE": ("EVIDENCE", {"source_scope": [self.f["sources"]["e-method"]]}),
            "SIMILAR_CASE": ("DECISION", {"text": "Paper-A"}),
            "CLAIM": ("CLAIM", {"focus_entities": [self.f["claim_id"]]}),
        }
        self.assertEqual(set(cases), set(STRATEGIES))
        for strategy, (kind, changes) in cases.items():
            with self.subTest(strategy=strategy):
                ctx, result = self.context(self.request([strategy], **changes))
                own = [item for item in ctx["items"] if item["kind"] == kind]
                self.assertTrue(own, (strategy, ctx["items"], result["warnings"]))
                lineage = self.c.get(result["lineage_id"])
                selected_ids = {item["id"] for item in own}
                self.assertTrue(any(row["item_id"] in selected_ids and strategy in row["methods"]
                                    for row in lineage["candidates"]))
                self.assertTrue(all(not item["instruction_authority"] for item in ctx["items"]))
                self.assertEqual(ctx["research_domain_scope"], self.scope)

    def test_every_strategy_excludes_unrelated_domain_even_with_positive_text(self):
        decisions = self.add_decisions()
        self.r.embedding = SpyEmbedding()
        absent = research_domain_scope(self.c, self.f["taxonomy_id"], ["research:mathematics"])
        for strategy in STRATEGIES:
            with self.subTest(strategy=strategy):
                ctx, _ = self.context(self.request([strategy], text="Paper-A Acme randomized Intervention",
                    focus_entities=["Acme", "Paper-A", self.f["claim_id"]], focus_relationships=["owns"],
                    ontology_scope=["Organization"], decision_id=decisions["e-support"][1],
                    include_historical=True, research_domain_scope=absent, hop_limit=2))
                self.assertEqual(ctx["items"], [])
        self.assertEqual(self.r.embedding.seen, [])

    def test_cross_domain_refutation_is_atomic_with_lexical_anchor(self):
        ctx, _ = self.context(self.request(["LEXICAL"], text="improves"))
        self.assertEqual(len(ctx["items"]), 1)
        item = ctx["items"][0]
        self.assertEqual(item["canonical_ref"], self.f["evidence"]["e-support"])
        self.assertEqual(set(item["assertion_ids"]), {"e-support", "e-refute"})
        self.assertEqual(item["trust_class"], "CONFLICTED_GRAPH_FACT")
        self.assertEqual(set(item["evidence_ids"]), {self.f["evidence"]["e-support"], self.f["evidence"]["e-refute"]})
        self.assertEqual(item["research_domain"]["anchor_assertion_ids"], ["e-support"])
        self.assertIn("e-refute", item["research_domain"]["closure_assertion_ids"])
        self.assertIn("did not improve", self.c.get(self.f["evidence"]["e-refute"])["quote"])

    def test_anchor_relation_source_filters_do_not_hide_required_refutation(self):
        for filters in ({"allowed_relation_types": ["supports"]}, {"excluded_relation_types": ["refutes"]},
                        {"source_scope": [self.f["sources"]["e-support"]]},
                        {"allowed_relation_types": ["supports"], "source_scope": [self.f["sources"]["e-support"]]}):
            with self.subTest(filters=filters):
                ctx, _ = self.context(self.request(["LEXICAL"], text="improves", **filters))
                self.assertEqual(set(ctx["retrieved_edges"]), {"e-support", "e-refute"})

    def test_refutation_outside_domain_is_not_an_independent_vector_input(self):
        spy = SpyEmbedding()
        self.r.embedding = spy
        ctx, _ = self.context(self.request(["VECTOR"], text="Intervention"))
        for edge in ("e-refute", "e-dataset", "e-partner", "e-replicate"):
            self.assertNotIn(self.c.get(self.f["evidence"][edge])["quote"], spy.seen)
        self.assertIn(self.c.get(self.f["evidence"]["e-support"])["quote"], spy.seen)
        self.assertIn("e-refute", ctx["retrieved_edges"])

    def test_refutation_is_not_an_independent_lexical_candidate(self):
        ctx, _ = self.context(self.request(["LEXICAL"], text="did not"))
        self.assertEqual(ctx["items"], [])

    def test_multi_domain_any_and_all(self):
        both = research_domain_scope(self.c, self.f["taxonomy_id"], ["research:biology", "research:chemistry"], match="ALL")
        ctx, _ = self.context(self.request(["LEXICAL"], text="owns improves randomized", research_domain_scope=both))
        anchors = {item["canonical_ref"] for item in ctx["items"]}
        self.assertEqual(anchors, {self.f["evidence"]["e-path"], self.f["evidence"]["e-support"]})
        any_scope = {**both, "match": "ANY"}
        ctx, _ = self.context(self.request(["LEXICAL"], text="owns improves randomized", research_domain_scope=any_scope))
        self.assertTrue({self.f["evidence"]["e-owns"], self.f["evidence"]["e-method"]} <=
                        {item["canonical_ref"] for item in ctx["items"]})

    def test_unclassified_is_explicit_not_a_domain_id(self):
        ctx, _ = self.context(self.request(["LEXICAL"], text="replicates"))
        self.assertEqual(ctx["items"], [])
        unknown = research_domain_scope(self.c, self.f["taxonomy_id"], [], include_unclassified=True)
        ctx, _ = self.context(self.request(["LEXICAL"], text="replicates", research_domain_scope=unknown))
        self.assertEqual([item["canonical_ref"] for item in ctx["items"]], [self.f["evidence"]["e-replicate"]])
        self.assertEqual(ctx["items"][0]["research_domain"]["source_assignments"], {self.f["sources"]["e-replicate"]: None})

    def test_unclassified_refutation_is_still_required_explanatory_evidence(self):
        snap = self.c.get(self.f["snapshot_id"])
        del snap["classifications"]["assignments"][self.f["sources"]["e-refute"]]
        self.replace_snapshot(snap)
        ctx, _ = self.context(self.request(["LEXICAL"], text="improves"))
        self.assertIn("e-refute", ctx["retrieved_edges"])
        self.assertIsNone(ctx["items"][0]["research_domain"]["source_assignments"][self.f["sources"]["e-refute"]])

    def test_assertion_membership_comes_from_evidence_not_entity_name(self):
        ctx, _ = self.context(self.request(["RELATION"], focus_entities=["Acme"]))
        anchors = {item["canonical_ref"] for item in ctx["items"]}
        self.assertIn("e-owns", anchors)
        self.assertNotIn("e-partner", anchors)
        self.assertNotIn("e-new", anchors)
        self.assertIn("e-alias", ctx["retrieved_edges"])

    def test_alias_node_uses_authorized_cross_domain_identity_proof(self):
        ctx, _ = self.context(self.request(["ENTITY"], focus_entities=["Acme-Holdings"]))
        self.assertEqual(len(ctx["items"]), 1)
        self.assertEqual(ctx["items"][0]["canonical_ref"], "Acme-Holdings")
        self.assertTrue({"e-alias", "e-owns"} <= set(ctx["retrieved_edges"]))
        policy = deepcopy(self.r.access_policy)
        del policy["grants"]["source:" + self.f["sources"]["e-alias"]]
        self.r.set_access_policy(policy)
        ctx, _ = self.context(self.request(["ENTITY"], focus_entities=["Acme-Holdings"]))
        self.assertEqual(ctx["items"], [])

    def test_path_members_remain_search_hops_not_identity_closure(self):
        ctx, _ = self.context(self.request(["PATH"], focus_entities=["Acme"], hop_limit=2))
        item = next(item for item in ctx["items"] if set(item["member_assertion_ids"]) == {"e-owns", "e-path"})
        self.assertEqual(len(item["member_assertion_ids"]), 2)
        self.assertIn("e-alias", item["assertion_ids"])
        self.assertNotIn("e-alias", item["member_assertion_ids"])
        self.assertIn("not additional search-path hops", item["text"])

    def test_community_scope_remains_topology_not_taxonomy(self):
        ctx, _ = self.context(self.request(["COMMUNITY"], focus_entities=["Acme"]))
        item = next(item for item in ctx["items"] if item["kind"] == "COMMUNITY")
        ctx2, _ = self.context(self.request(["COMMUNITY"], focus_entities=["Acme"], community_scope=[item["canonical_ref"]]))
        self.assertTrue(ctx2["items"])
        ctx3, _ = self.context(self.request(["COMMUNITY"], focus_entities=["Acme"], community_scope=["research:biology"]))
        self.assertEqual(ctx3["items"], [])
        self.assertTrue(item["generated_summary"])
        self.assertFalse(item["instruction_authority"])

    def test_schema_requires_acl_and_authorized_topical_basis(self):
        ctx, _ = self.context(self.request(["SCHEMA"], focus_relationships=["uses_dataset"]))
        # A schema rule may be relevant to an authorized selected endpoint type
        # even when its only existing instance is outside the topical anchors.
        self.assertTrue(ctx["schema_fragments"])
        self.assertNotIn("e-dataset", ctx["retrieved_edges"])
        ctx, _ = self.context(self.request(["SCHEMA"], focus_relationships=["owns"], ontology_scope=["Organization"]))
        self.assertTrue(ctx["schema_fragments"])
        policy = deepcopy(self.r.access_policy)
        del policy["grants"]["schema:" + self.f["schema_id"]]
        self.r.set_access_policy(policy)
        ctx, _ = self.context(self.request(["SCHEMA", "ONTOLOGY"], focus_relationships=["owns"], ontology_scope=["Organization"]))
        self.assertEqual(ctx["items"], [])

    def test_decision_and_hypothesis_require_own_authorized_membership(self):
        decisions = self.add_decisions()
        for strategy in ("DECISION", "SIMILAR_CASE"):
            with self.subTest(strategy=strategy):
                ctx, _ = self.context(self.request([strategy], text="Intervention Paper", focus_entities=[self.f["claim_id"]],
                                                     include_historical=True))
                refs = {item["canonical_ref"] for item in ctx["items"]}
                self.assertTrue(set(decisions["e-support"]) <= refs)
                self.assertFalse(set(decisions["e-refute"]) & refs)
                self.assertIn("e-refute", ctx["retrieved_edges"])
        policy = deepcopy(self.r.access_policy)
        for record in decisions["e-support"]:
            del policy["grants"]["decision:" + record]
        self.r.set_access_policy(policy)
        ctx, _ = self.context(self.request(["DECISION"], focus_entities=[self.f["claim_id"]], include_historical=True))
        self.assertEqual(ctx["items"], [])

    def test_no_self_candidate_or_inflight_vote_as_corroboration(self):
        decisions = self.add_decisions()
        ctx, _ = self.context(self.request(["DECISION", "SIMILAR_CASE"], text="Intervention Paper",
            focus_entities=[self.f["claim_id"]], candidate_id=decisions["e-support"][0], include_historical=True))
        self.assertFalse(set(decisions["e-support"]) & {item["canonical_ref"] for item in ctx["items"]})

    def test_domain_match_never_overrides_source_acl_before_embedding(self):
        denied = self.f["sources"]["e-method"]
        policy = deepcopy(self.r.access_policy)
        del policy["grants"]["source:" + denied]
        self.r.set_access_policy(policy)
        spy = SpyEmbedding()
        self.r.embedding = spy
        original = GraphReadView.source_classification
        examined = []
        def guarded(view, source_id, access):
            result = original(view, source_id, access)
            if source_id == denied:
                examined.append(result)
            return result
        with patch.object(GraphReadView, "source_classification", guarded):
            ctx, _ = self.context(self.request(["VECTOR"], text="randomized"))
        self.assertTrue(examined)
        self.assertTrue(all(row is None for row in examined))
        self.assertNotIn(self.c.get(denied)["text"], spy.seen)
        self.assertNotIn(self.f["evidence"]["e-method"], ctx["selected_evidence_ids"])

    def test_current_status_blocks_embedding_in_historical_mode(self):
        for status in ({"active": False}, {"permission": "DENIED"}, {"tombstone": True, "active": False, "permission": "DENIED"}):
            with self.subTest(status=status):
                source = self.f["sources"]["e-method"]
                self.f["adapter"].source_status[source].update(status)
                spy = SpyEmbedding()
                self.r.embedding = spy
                ctx, _ = self.context(self.request(["VECTOR"], text="randomized", include_historical=True, mode="HISTORICAL"))
                self.assertNotIn(self.c.get(source)["text"], spy.seen)
                self.assertNotIn(self.f["evidence"]["e-method"], ctx["selected_evidence_ids"])
                self.f["adapter"].source_status[source].update(active=True, permission="READ", tombstone=False)

    def test_denied_cross_domain_refutation_does_not_leak_through_closure(self):
        policy = deepcopy(self.r.access_policy)
        del policy["grants"]["source:" + self.f["sources"]["e-refute"]]
        self.r.set_access_policy(policy)
        ctx, _ = self.context(self.request(["LEXICAL"], text="improves"))
        self.assertEqual(ctx["retrieved_edges"], ["e-support"])
        self.assertNotIn(self.f["evidence"]["e-refute"], ctx["selected_evidence_ids"])
        self.assertNotIn(self.f["sources"]["e-refute"], ctx["items"][0]["research_domain"]["source_assignments"])

    def test_revocation_during_embedding_fails_before_context_publication(self):
        source = self.f["sources"]["e-method"]
        before = len(self.c.all("graph-context"))
        def revoke():
            self.f["adapter"].source_status[source].update(active=False, epoch=2)
        self.r.embedding = SpyEmbedding(revoke)
        with self.assertRaisesRegex(ContractError, "ACCESS_DENIED"):
            self.r.retrieve(self.request(["VECTOR"], text="randomized"))
        self.assertEqual(len(self.c.all("graph-context")), before)
        # It was allowed at entry to this synchronous call; no cancellation of
        # an already delivered model request or production SLO is asserted.

    def test_source_epoch_change_during_embedding_requires_fresh_read(self):
        source = self.f["sources"]["e-method"]
        self.r.embedding = SpyEmbedding(lambda: self.f["adapter"].source_status[source].update(epoch=2))
        with self.assertRaisesRegex(ContractError, "STALE_SOURCE_EPOCH"):
            self.r.retrieve(self.request(["VECTOR"], text="randomized"))

    def test_withdrawal_invalidates_retrieval_cache(self):
        q = self.request(["LEXICAL"], text="randomized")
        _, first = self.context(q)
        _, second = self.context(q)
        self.assertFalse(self.c.get(first["lineage_id"])["cache_hit"])
        self.assertTrue(self.c.get(second["lineage_id"])["cache_hit"])
        self.f["adapter"].source_status[self.f["sources"]["e-method"]].update(active=False, epoch=2)
        ctx, third = self.context(q)
        self.assertFalse(self.c.get(third["lineage_id"])["cache_hit"])
        self.assertEqual(ctx["items"], [])

    def test_tampered_cached_domain_proof_is_reconstructed_and_rejected(self):
        q = self.request(["LEXICAL"], text="improves")
        self.context(q)
        rows = next(iter(self.r.cache._entries.values()))
        rows[0]["item"]["research_domain"]["classification_hash"] = "0" * 64
        with self.assertRaisesRegex(ContractError, "CONTEXT_MATERIALIZATION"):
            self.r.retrieve(q)

    def test_budget_never_keeps_support_without_required_refutation(self):
        for budget in (replace(self.budget, maximum_edges=1), replace(self.budget, maximum_source_spans=1),
                       replace(self.budget, maximum_tokens=1)):
            with self.subTest(budget=budget):
                ctx, result = self.context(self.request(["LEXICAL"], text="improves", budget=budget))
                self.assertEqual(ctx["items"], [])
                self.assertEqual(result["status"], "PARTIAL")
                self.assertEqual(ctx["selected_evidence_ids"], [])

    def test_plugin_cannot_inject_out_of_domain_lexical_candidate(self):
        target = self.f["evidence"]["e-dataset"]
        class Malicious:
            version = "malicious-domain-fixture-v1"
            def retrieve(plugin, space):
                # Even an individually ACL-authorized raw legacy candidate must
                # pass canonical domain admission at the shared service boundary.
                old_query = {**space.query, "research_domain_scope": None}
                yield canonical_item(space.view, space.access, old_query, kind="EVIDENCE", ref=target)
        self.r.strategies["LEXICAL"] = Malicious()
        with self.assertRaisesRegex(ContractError, "RESEARCH_DOMAIN_SCOPE"):
            self.r.retrieve(self.request(["LEXICAL"], text="Dataset"))

    def test_context_scope_and_revision_forgery_fail_closed(self):
        ctx, _ = self.context(self.request(["LEXICAL"], text="improves"))
        for update in ({"classification_identity": {**ctx["classification_identity"], "revision": 999}},
                       {"research_domain_scope": {**self.scope, "domain_ids": ["research:physics"]}}):
            with self.subTest(update=update):
                forged = self.c.put("graph-context", {**ctx, **update})
                with self.assertRaisesRegex(ContractError, "DOMAIN_REVISION"):
                    validate_context(self.c, forged)

    def test_stripped_cross_domain_refutation_fails_canonical_validation(self):
        ctx, _ = self.context(self.request(["LEXICAL"], text="improves"))
        ctx["items"][0]["assertion_ids"].remove("e-refute")
        forged = self.c.put("graph-context", ctx)
        with self.assertRaisesRegex(ContractError, "CONTEXT_MATERIALIZATION"):
            validate_context(self.c, forged)

    def test_scope_rejects_unknown_taxonomy_hash_and_domain(self):
        for fields in ({"taxonomy_hash": "0" * 64}, {"domain_ids": ["research:invented"]},
                       {"domain_ids": []}, {"domain_ids": ["research:physics", "research:biology"]}):
            with self.subTest(fields=fields), self.assertRaises(ContractError):
                self.r.retrieve(self.request(research_domain_scope={**self.scope, **fields}))

    def test_packaged_taxonomy_proposal_cannot_be_used_as_reviewed_scope(self):
        proposal = self.c.add(reference_taxonomy())
        # Catalog.add does not return an ID; use the immutable envelope ID.
        proposal_id = reference_taxonomy()["id"]
        with self.assertRaisesRegex(ContractError, "RESEARCH_DOMAIN_SCOPE"):
            research_domain_scope(self.c, proposal_id, ["research:biology"])

    def test_classification_does_not_grant_unknown_nodes_a_domain(self):
        snap = self.c.get(self.f["snapshot_id"])
        snap["nodes"]["research:biology"] = "Type"
        self.replace_snapshot(snap)
        policy = demo_access(self.c, self.f["snapshot_id"])
        self.r.set_access_policy(policy)
        ctx, _ = self.context(self.request(["ENTITY"], focus_entities=["research:biology"], text="research biology"))
        self.assertEqual(ctx["items"], [])

    def test_scope_is_preserved_in_downstream_answer_and_lineage(self):
        answer_id = GraphRAGQueryService(self.r).query(self.request(["LEXICAL"], text="improves"))["answer_context_id"]
        answer = self.c.get(answer_id, "graphrag-answer")
        validate_record(self.c, self.c.record(answer_id))
        context = self.c.get(answer["graph_context_id"])
        self.assertEqual(answer["research_domain_scope"], self.scope)
        self.assertEqual(answer["classification_identity"], context["classification_identity"])
        self.assertEqual({row["evidence_id"] for row in answer["citations"]}, {self.f["evidence"]["e-support"], self.f["evidence"]["e-refute"]})

    def test_planner_carries_scope_and_rejects_override(self):
        planner = RetrievalPlanner()
        plan_id = planner.plan(self.c, candidate_id=None, question_type="ASSERTION", risk_class="R1",
            known_entities=["Acme"], known_relations=["owns"], budget=self.budget, research_domain_scope=self.scope)
        plan = self.c.get(plan_id)
        self.assertEqual(plan["research_domain_scope"], self.scope)
        q = planner.request(self.c, plan_id, security_scope=SCOPE, text="Acme", retrieval_round=0)
        self.assertEqual(q["research_domain_scope"], self.scope)
        other = {**self.scope, "domain_ids": ["research:physics"]}
        with self.assertRaisesRegex(ContractError, "RETRIEVAL_PLAN_BINDING"):
            self.r.retrieve({**q, "research_domain_scope": other}, plan_id=plan_id)

    def test_upstream_minimum_closure_and_replay_pin_the_same_domain_revision(self):
        fact = self.c.get(self.f["snapshot_id"])["assertions"]["e-support"]
        candidate = self.c.candidate(id_="candidate:new-domain", run_id="upstream-domain-test", assertion=fact["assertion"],
                                    claim_id=self.f["claim_id"], evidence_ids=fact["evidence_ids"])
        request = self.request(["LEXICAL"], text="improves", candidate_id=candidate)
        request["requesting_component"] = "upstream-synthesis"
        ctx, result = self.context(request)
        pack_id = compile_pack(self.c, id_="pack:new-domain", run_id="upstream-domain-test", candidate_ids=[candidate],
            questions=[question(candidate, id_="new-support")], snapshot_id=self.f["snapshot_id"], security_scope=SCOPE,
            graph_context_ids=[result["graph_context_id"]], source_retrieval_ids=[], request_cap=1000000, state_longest_cap=1000000)
        pack = self.c.get(pack_id)
        validate_pack(self.c, pack, source_status=self.f["adapter"].source_status, current_graph_access=self.r.access_policy)
        validate_pack_lineage(self.c, pack, current_status=self.f["adapter"].source_status, current_access=self.r.access_policy)
        self.assertTrue({self.f["evidence"]["e-support"], self.f["evidence"]["e-refute"]} <= set(pack["closure"]["evidence_ids"]))
        graph = pack["state"]["graph_context"][0]
        self.assertEqual(graph["classification_identity"], ctx["classification_identity"])
        self.assertEqual(graph["research_domain_scope"], self.scope)
        replay_id = replay_retrieval(self.r, self.c.put("retrieval-result", result), {"retrieval_strategy": ["RELATION"]})
        replay = self.c.get(replay_id)
        validate_record(self.c, self.c.record(replay_id))
        self.assertEqual(replay["original_classification_identity"], replay["replayed_classification_identity"])
        self.assertEqual(replay["replayed_research_domain_scope"], self.scope)

    def test_old_context_revalidation_respects_now_revoked_source(self):
        _, result = self.context(self.request(["LEXICAL"], text="improves"))
        self.f["adapter"].source_status[self.f["sources"]["e-refute"]].update(active=False, epoch=2)
        with self.assertRaises(ContractError):
            self.r.validate_live_context(result["graph_context_id"])

    def test_scoped_unmigrated_adapter_needs_current_status_capability(self):
        snap = self.c.get(self.f["snapshot_id"])
        del snap["classifications"]
        self.replace_snapshot(snap)
        adapter = self.f["adapter"]
        class NoCurrentStatus:
            version = "no-current-status-fixture-v1"
            def read(self, q):
                return adapter.read(q)
        self.r.adapter = NoCurrentStatus()
        unknown = research_domain_scope(self.c, self.f["taxonomy_id"], [], include_unclassified=True)
        with self.assertRaisesRegex(ContractError, "SOURCE_STATUS_CAPABILITY"):
            self.r.retrieve(self.request(["LEXICAL"], text="randomized", research_domain_scope=unknown))

    def test_unscoped_materialization_remains_legacy_shaped(self):
        ctx, _ = self.context(self.request(["LEXICAL"], text="randomized", research_domain_scope=None))
        self.assertNotIn("research_domain", ctx["items"][0])
        self.assertEqual(ctx["retrieved_edges"], [])
        self.assertEqual(ctx["items"][0]["text"], self.c.get(self.f["evidence"]["e-method"])["quote"])

    def test_descendant_selection_and_all_branch_semantics_are_explicit(self):
        old_taxonomy = self.c.get(self.f["taxonomy_id"])
        taxonomy = deepcopy(old_taxonomy)
        taxonomy.update(version=2, supersedes=self.f["taxonomy_id"], supersedes_hash=self.c.hash(self.f["taxonomy_id"]))
        taxonomy["domains"].append({"id": "research:cell-biology", "label": "Cell biology",
            "definition": "Synthetic hierarchy fixture for biological cells.", "parent_ids": ["research:biology"], "status": "ACTIVE"})
        taxonomy["domains"].sort(key=lambda row: row["id"])
        tax_id = self.c.put("research-domain-taxonomy", taxonomy)
        source = self.f["sources"]["e-method"]
        assignment = create_assignment(self.c, source_snapshot_id=source, taxonomy_id=tax_id,
            domain_ids=["research:cell-biology", "research:chemistry"], review=taxonomy["review"],
            classifier_id="synthetic-hierarchy", classifier_version="fixture-v1", supersedes=self.f["assignments"][source])
        snap = self.c.get(self.f["snapshot_id"])
        snap["classifications"]["assignments"][source] = assignment
        snap["classifications"]["revision"] += 1
        self.replace_snapshot(snap)
        parent = research_domain_scope(self.c, tax_id, ["research:biology"])
        ctx, _ = self.context(self.request(["LEXICAL"], text="randomized", research_domain_scope=parent))
        self.assertEqual(ctx["items"], [])
        for selection in ({**parent, "include_descendants": True},
                          {**parent, "include_descendants": True, "match": "ALL", "domain_ids": ["research:biology", "research:chemistry"]}):
            with self.subTest(selection=selection):
                ctx, _ = self.context(self.request(["LEXICAL"], text="randomized", research_domain_scope=selection))
                self.assertEqual([item["canonical_ref"] for item in ctx["items"]], [self.f["evidence"]["e-method"]])
        # The old pin does not silently reinterpret assignments in a new version.
        ctx, _ = self.context(self.request(["LEXICAL"], text="randomized"))
        self.assertEqual(ctx["items"], [])

    def test_direct_different_from_and_alias_proof_not_transitive_distinctions(self):
        snap = self.c.get(self.f["snapshot_id"])
        statuses = self.f["adapter"].source_status
        for edge, subject, predicate, object_ in (
                ("e-distinct", "Acme", "different_from", "Other"),
                ("e-other-alias", "Other", "same_as", "Other-Alias"),
                ("e-unrelated-distinction", "Other-Alias", "different_from", "Third")):
            for node in (subject, object_):
                snap["nodes"][node] = "Organization"
            source = self.c.source("synthetic-" + edge, "1", "Synthetic identity proof: " + edge, scope=SCOPE)
            evidence = self.c.evidence(source)
            snap["source_epochs"][source] = 1
            statuses[source] = {"active": True, "permission": "READ", "epoch": 1,
                                "updated_at": "2026-09-27T00:00:00Z", "tombstone": False}
            snap["assertions"][edge] = {"assertion": {"subject": subject, "predicate": predicate, "object": object_, "qualifiers": {}},
                "evidence_ids": [evidence], "prerequisites": [], "active": True, "revision": 1}
        self.replace_snapshot(snap)
        self.r.set_access_policy(demo_access(self.c, self.f["snapshot_id"]))
        ctx, _ = self.context(self.request(["RELATION"], focus_entities=["Acme"], allowed_relation_types=["owns"]))
        self.assertTrue({"e-owns", "e-distinct", "e-other-alias"} <= set(ctx["retrieved_edges"]))
        self.assertNotIn("e-unrelated-distinction", ctx["retrieved_edges"])
        self.assertNotIn("Third", ctx["retrieved_nodes"])
        # Direct distinction closure does not grant the other entity membership.
        ctx, _ = self.context(self.request(["ENTITY"], focus_entities=["Other"]))
        self.assertEqual(ctx["items"], [])

    def replace_snapshot(self, body):
        ref = self.c.put("graph-snapshot", body)
        statuses = self.f["adapter"].source_status
        adapter = InMemoryGraphAdapter(self.c, [ref], statuses)
        self.f.update(adapter=adapter, snapshot_id=ref)
        self.r.adapter = adapter


if __name__ == "__main__":
    unittest.main()
