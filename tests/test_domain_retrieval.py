"""Normal-module, fabricated multi-domain retrieval and security regressions."""
from copy import deepcopy
import json
from pathlib import Path
import unittest

from domain_retrieval_fixture import Fixture, SpyEmbedding
from trace_gc.canonical import digest
from trace_gc.errors import ContractError
from trace_gc.retrieval.contracts import query, validate_query, RetrievalBudget, STRATEGIES, VERSION as LEGACY_VERSION
from trace_gc.retrieval.domain_scope import scope, VERSION
from trace_gc.retrieval.integration import validate_record
from trace_gc.retrieval.items import canonical_item, visible_edges, conflict_pairs
from trace_gc.retrieval.security import AccessFilter
from trace_gc.retrieval.service import HybridRetriever, GraphRAGQueryService, validate_context


class DomainRetrieval(unittest.TestCase):
    def setUp(self):
        self.f = Fixture()
        self.addCleanup(self.f.close)

    def request(self, strategy="LEXICAL", **changes):
        values = dict(requesting_component="downstream-test", security_scope="tenant-a", text="Biology",
            strategies=[strategy], research_domain_scope=self.f.scope, focus_entities=["paper", self.f.claim, "entity-a"],
            focus_relationships=["supports", "related"], include_historical=True, hop_limit=2,
            budget=RetrievalBudget(maximum_tokens=1_000_000, maximum_latency_ms=20_000, maximum_cost_units=100_000))
        values.update(changes)
        return query(**values)

    def retrieve(self, request=None):
        r = self.f.retriever.retrieve(request or self.request())
        c = self.f.retriever.catalog
        result = c.get(r, "retrieval-result")
        context = c.get(result["graph_context_id"], "graph-context")
        lineage = c.get(result["lineage_id"], "retrieval-lineage")
        validate_context(c, result["graph_context_id"], current_access=self.f.retriever.access_policy,
                         current_status=self.f.f.backend.statuses())
        validate_record(c, c.record(result["lineage_id"]))
        return result, context, lineage

    def assert_code(self, code, action):
        with self.assertRaises(ContractError) as cm:
            action()
        self.assertEqual(cm.exception.code, code)

    def test_all_18_channels_have_their_own_scoped_positive_and_no_denied_sources(self):
        for strategy in STRATEGIES:
            with self.subTest(strategy=strategy):
                _, context, lineage = self.retrieve(self.request(strategy, include_conflicts=False))
                self.assertTrue(context["items"], strategy)
                self.assertTrue(any(strategy in row["methods"] for row in lineage["candidates"]), strategy)
                self.assertNotIn(self.f.sources["secret"], {s for i in context["items"] for s in i["source_ids"]})
                self.assertNotIn("secret-edge", context["retrieved_edges"])
                self.assertNotIn("unrelated-comp", context["retrieved_edges"])
                for item in context["items"]:
                    self.assertEqual(item["research_domain_context"]["scope"], self.f.scope)
                    self.assertFalse(item["research_domain_context"]["authorization_granted"])

    def test_vector_embeds_only_authorized_domain_anchor_spans(self):
        self.retrieve(self.request("VECTOR"))
        calls = self.f.embedding.calls
        self.assertTrue(calls)
        embedded = [t for call in calls for t in call[1:]]
        c = self.f.f.c
        self.assertIn(c.get(self.f.evidence["bio"], "evidence")["quote"], embedded)
        for tag in ("comp", "unknown", "secret"):
            self.assertNotIn(c.get(self.f.evidence[tag], "evidence")["quote"], embedded)

    def test_cross_domain_refutation_survives_lexical_scope(self):
        _, context, _ = self.retrieve()
        self.assertIn("comp-refute", context["retrieved_edges"])
        self.assertIn(self.f.evidence["comp"], context["selected_evidence_ids"])
        self.assertTrue(context["conflict_refs"])
        member = next(i for i in context["items"] if "comp-refute" in i["assertion_ids"])
        membership = member["research_domain_context"]["source_memberships"][self.f.sources["comp"]]
        self.assertEqual(membership["domain_ids"], ["computing"])
        self.assertEqual(membership["assignment_id"], self.f.assignments["comp"])

    def test_cross_domain_identity_and_unclassified_cannot_link_remain_explainable(self):
        _, context, _ = self.retrieve(self.request("NEIGHBORHOOD"))
        self.assertTrue({"cross-identity", "unclassified-identity"} <= set(context["retrieved_edges"]))
        item = next(i for i in context["items"] if "unclassified-identity" in i["assertion_ids"])
        self.assertEqual(item["research_domain_context"]["source_memberships"][self.f.sources["unknown"]]["state"], "UNCLASSIFIED")
        facts = {r["assertion_id"]: r for r in item["research_domain_context"]["closure_assertions"]}
        self.assertEqual(facts["cross-identity"]["predicate"], "same_as")
        self.assertEqual(facts["unclassified-identity"]["predicate"], "different_from")

    def test_explicit_unclassified_anchor_opt_in(self):
        before = self.retrieve(self.request("VECTOR"))[1]
        self.assertFalse(any(i["kind"] == "EVIDENCE" and i["canonical_ref"] == self.f.evidence["unknown"] for i in before["items"]))
        request = self.request("VECTOR", research_domain_scope={**self.f.scope, "include_unclassified": True})
        after = self.retrieve(request)[1]
        self.assertTrue(any(i["kind"] == "EVIDENCE" and i["canonical_ref"] == self.f.evidence["unknown"] for i in after["items"]))

    def test_multi_label_source_is_one_immutable_source_in_two_scopes(self):
        original = {s: self.f.f.c.hash(s) for s in self.f.sources.values()}
        self.f.classify("bio", ["biology", "computing"])
        self.f.adapter.rebuild_domain_index()
        for label in ("biology", "computing"):
            _, context, _ = self.retrieve(self.request("VECTOR", research_domain_scope={**self.f.scope, "domain_ids": [label]}))
            self.assertTrue(any(i["kind"] == "EVIDENCE" and i["canonical_ref"] == self.f.evidence["bio"] for i in context["items"]))
        self.assertEqual(original, {s: self.f.f.c.hash(s) for s in self.f.sources.values()})

    def test_real_cache_hit_then_classification_invalidation(self):
        q = self.request()
        first = self.retrieve(q)
        second = self.retrieve(q)
        self.assertFalse(first[2]["cache_hit"])
        self.assertTrue(second[2]["cache_hit"])
        old_snapshot = deepcopy(first[1])
        self.f.classify("bio", ["computing"])
        self.f.adapter.rebuild_domain_index()
        third = self.retrieve(q)
        self.assertFalse(third[2]["cache_hit"])
        self.assertGreater(self.f.retriever.cache.invalidations, 0)
        self.assertNotEqual(first[1]["research_domain_binding"], third[1]["research_domain_binding"])
        self.assertEqual(first[1], old_snapshot)

    def test_historical_exact_assignment_and_current_revocation(self):
        v = self.f.f.backend.state()["graph_version"]
        first = self.retrieve(self.request(graph_version=v))[1]
        self.f.classify("bio", ["computing"])
        self.f.adapter.rebuild_domain_index()
        history = self.retrieve(self.request(graph_version=v))[1]
        self.assertEqual(first["research_domain_binding"], history["research_domain_binding"])
        self.f.f.revoke_source()
        self.f.adapter.rebuild_domain_index()
        revoked = self.retrieve(self.request(graph_version=v))[1]
        self.assertNotIn(self.f.sources["bio"], {s for i in revoked["items"] for s in i["source_ids"]})
        self.assertFalse(revoked["items"])

    def test_revocation_during_embedding_fails_before_returning_context(self):
        def revoke():
            self.f.f.revoke_source()
            self.f.adapter.rebuild_domain_index()
        self.f.retriever.embedding = SpyEmbedding(callback=revoke)
        self.assert_code("STALE_GRAPH_CONTEXT", lambda: self.f.retriever.retrieve(self.request("VECTOR")))
        self.assertFalse(self.f.retriever.catalog.all("graph-context"))

    def test_policy_refresh_during_embedding_fails_closed(self):
        def revoke():
            p = deepcopy(self.f.policy)
            p["grants"].pop("source:"+self.f.sources["bio"])
            self.f.retriever.set_access_policy(p)
        self.f.retriever.embedding = SpyEmbedding(callback=revoke)
        self.assert_code("STALE_GRAPH_CONTEXT", lambda: self.f.retriever.retrieve(self.request("VECTOR")))

    def test_denied_source_is_not_recovered_by_any_matching_label(self):
        policy = deepcopy(self.f.policy)
        policy["grants"].pop("source:"+self.f.sources["bio"])
        self.f.retriever.set_access_policy(policy)
        _, context, _ = self.retrieve()
        self.assertEqual(context["items"], [])
        self.assertEqual(self.f.embedding.calls, [])

    def test_unknown_taxonomy_label_and_hash_fail_before_embedding(self):
        for changes, code in [({"domain_ids": ["invented"]}, "DOMAIN_UNKNOWN"), ({"taxonomy_hash": "f"*64}, "DOMAIN_TAXONOMY_BINDING")]:
            with self.subTest(changes=changes):
                self.assert_code(code, lambda: self.f.retriever.retrieve(self.request("VECTOR", research_domain_scope={**self.f.scope, **changes})))
        self.assertEqual(self.f.embedding.calls, [])

    def test_legacy_query_bytes_remain_legacy_and_reject_smuggled_scope(self):
        legacy = query(requesting_component="downstream-test", security_scope="tenant-a", text="Biology")
        self.assertEqual(legacy["version"], LEGACY_VERSION)
        self.assertNotIn("research_domain_scope", legacy)
        validate_query(legacy)
        self.assert_code("SCHEMA_ERROR", lambda: validate_query({**legacy, "research_domain_scope": self.f.scope}))
        self.assertEqual(self.request()["version"], VERSION)
        self.assert_code("SCHEMA_ERROR", lambda: validate_query({**legacy, "version": VERSION}))

    def test_context_binding_and_closure_cannot_be_rehashed_into_acceptance(self):
        result, context, _ = self.retrieve()
        c = self.f.retriever.catalog
        for mutate in (lambda b: b["research_domain_binding"].update(projection_hash="f"*64),
                       lambda b: b["items"][0]["research_domain_context"].update(closure_assertions=[])):
            bad = deepcopy(context); mutate(bad)
            ref = c.put("graph-context", bad)
            with self.assertRaises(ContractError):
                validate_context(c, ref, current_access=self.f.policy, current_status=self.f.f.backend.statuses())

    def test_lineage_cannot_change_assignment_revision(self):
        _, _, lineage = self.retrieve()
        lineage["research_domain_binding"]["projection_revision"] += 1
        c = self.f.retriever.catalog
        ref = c.put("retrieval-lineage", lineage)
        self.assert_code("DOMAIN_CONTEXT_BINDING", lambda: validate_record(c, c.record(ref)))

    def test_canonical_materialization_rejects_out_of_scope_plugin_candidate(self):
        q = self.request(include_conflicts=False)
        view = self.f.adapter.read(q)
        acl = AccessFilter(self.f.policy, view.catalog, view.source_status)
        self.assert_code("DOMAIN_OUTSIDE_SCOPE", lambda: canonical_item(view, acl, q, kind="EVIDENCE", ref=self.f.evidence["comp"]))

    def test_small_budget_does_not_return_one_side_of_conflict(self):
        request = self.request("LEXICAL", budget=RetrievalBudget(maximum_edges=1, maximum_tokens=100000,
            maximum_latency_ms=20000, maximum_cost_units=100000))
        result, context, _ = self.retrieve(request)
        self.assertEqual(result["status"], "PARTIAL")
        self.assertFalse({"bio-support", "comp-refute"} & set(context["retrieved_edges"]))
        self.assertIn("CONFLICT_PAIR_EXCLUDED_BY_BUDGET", result["warnings"])

    def test_downstream_answer_cites_every_selected_cross_domain_span(self):
        out = GraphRAGQueryService(self.f.retriever).query(self.request())
        c = self.f.retriever.catalog
        validate_record(c, c.record(out["answer_context_id"]))
        answer = out["context"]
        self.assertFalse(answer["can_mutate_graph"])
        self.assertIn(self.f.evidence["comp"], {r["evidence_id"] for r in answer["citations"]})
        self.assertNotIn(self.f.sources["secret"], {r["source_snapshot_id"] for r in answer["citations"]})

    def test_generated_schema_trees_are_exact_and_check_new_fields(self):
        root = Path(__file__).resolve().parents[1]
        files = list((root/"schemas/runtime").glob("*.schema.json"))
        self.assertEqual(len(files), 32)
        for path in files:
            self.assertEqual(path.read_bytes(), (root/"trace_gc/data/schemas"/path.name).read_bytes(), path.name)
        schema = json.loads((root/"schemas/runtime/retrieval-query.schema.json").read_text())
        self.assertIn("research_domain_scope", schema["properties"])

    def test_shared_evidence_closure_links_are_unique_without_source_rewrites(self):
        from trace_gc.compiler import validate_pack
        c = self.f.f.c
        for record in c.all("pack"):
            edges = record["body"]["closure"]["edges"]
            self.assertEqual(len(edges), len({tuple(edge) for edge in edges}))
            validate_pack(c, record["body"])
        for source in self.f.sources.values():
            self.assertEqual(c.hash(source), self.f.f.backend.load_catalog().hash(source))

    def test_replay_preserves_original_observations_and_exact_historical_scope(self):
        from trace_gc.replay import replay_retrieval
        result, context, _ = self.retrieve()
        c = self.f.retriever.catalog
        result_id = next(r["id"] for r in c.all("retrieval-result") if r["body"] == result)
        before = {r["id"]: r["hash"] for r in c.all("observation")}
        ref = replay_retrieval(self.f.retriever, result_id, {"research_domain_scope": {**self.f.scope, "domain_ids": ["computing"]}})
        report = c.get(ref, "retrieval-replay")
        replayed = c.get(report["replayed_result_id"], "retrieval-result")
        selected = c.get(replayed["graph_context_id"], "graph-context")
        validate_context(c, replayed["graph_context_id"], current_status=self.f.f.backend.statuses())
        self.assertEqual(selected["research_domain_binding"]["scope"]["domain_ids"], ["computing"])
        self.assertEqual(selected["graph_version"], context["graph_version"])
        self.assertEqual(report["observation_hashes_preserved"], before)
        self.assertEqual(report["new_observation_ids"], [])
        self.assertFalse(report["authorization_granted"])
        self.assert_code("REPLAY_SCOPE", lambda: replay_retrieval(self.f.retriever, result_id, {"security_scope": "other"}))

    def test_planner_pins_scope_and_rejects_query_replacement(self):
        from trace_gc.retrieval.planner import RetrievalPlanner
        p = RetrievalPlanner()
        c = self.f.f.c
        plan = p.plan(c, candidate_id=self.f.candidates["bio"], question_type="ASSERTION", risk_class="R2",
            known_entities=["paper", self.f.claim], known_relations=["supports"], budget=RetrievalBudget(),
            research_domain_scope=self.f.scope)
        q = p.request(c, plan, security_scope="tenant-a", text="Biology", retrieval_round=0)
        self.assertEqual(q["research_domain_scope"], self.f.scope)
        self.assert_code("DOMAIN_PLAN_BINDING", lambda: p.request(c, plan, security_scope="tenant-a",
            text="Biology", retrieval_round=0, research_domain_scope={**self.f.scope, "domain_ids": ["computing"]}))

    def test_upstream_compilation_carries_selected_assignment_closure(self):
        from trace_gc.compiler import compile_pack, validate_pack
        from trace_gc.programs import question
        q = self.request(requesting_component="upstream-synthesis", candidate_id=self.f.candidates["bio"])
        result, context, _ = self.retrieve(q)
        c = self.f.retriever.catalog
        result_id = next(r["id"] for r in c.all("retrieval-result") if r["body"] == result)
        pack_id = compile_pack(c, id_="scoped-upstream-compiled", run_id="fixture-run",
            candidate_ids=[self.f.candidates["bio"]], questions=[question(self.f.candidates["bio"], id_="new-q")],
            snapshot_id=context["snapshot_id"], security_scope="tenant-a", execution_mode="SYNTHETIC",
            graph_context_ids=[result["graph_context_id"]], source_retrieval_ids=[result_id],
            request_cap=1_000_000, state_longest_cap=1_000_000)
        pack = c.get(pack_id, "pack")
        validate_pack(c, pack, source_status=self.f.f.backend.statuses(), current_graph_access=self.f.policy)
        self.assertIn(self.f.assignments["bio"], pack["closure"]["record_ids"])
        self.assertIn(self.f.assignments["comp"], pack["closure"]["record_ids"])
        self.assertNotIn(self.f.assignments["secret"], pack["closure"]["record_ids"])
        self.assertNotIn(self.f.sources["secret"], pack["closure"]["source_snapshot_ids"])
        self.assertFalse(pack["state"]["graph_snapshot"]["full_snapshot_in_model_context"])

    def test_full_upstream_loop_uses_scoped_context_without_graph_publication(self):
        from trace_gc.retrieval.planner import UpstreamGraphRAG
        from trace_gc.policy import create_policy
        from trace_gc.budget import RunBudget
        from trace_gc.adapter import record_response
        from trace_gc.demo import fixture_response, limits
        c = self.f.retriever.catalog
        for record in self.f.f.c.all():
            c.add(record)
        create_policy(c, version="scoped-analysis-only", scope="tenant-a", population="synthetic-only")
        budget = RunBudget(self.f.f.path.parent/"retrieval-budget.sqlite", "fixture-run", limits())
        self.addCleanup(budget.close)
        before = self.f.f.backend.audit()["head_hash"]
        def execute(pack_id):
            return record_response(c, pack_id, fixture_response(c.get(pack_id, "pack")))
        result = UpstreamGraphRAG(self.f.retriever).run(candidate_id=self.f.candidates["bio"], execute=execute,
            run_budget=budget, policy_version="scoped-analysis-only", population="synthetic-only",
            budget=RetrievalBudget(maximum_rounds=1, maximum_latency_ms=20000, maximum_cost_units=100000),
            query_overrides={"research_domain_scope": self.f.scope})
        self.assertTrue(result.pack_ids)
        self.assertEqual(result.stop_reason, "HUMAN_REVIEW_REQUIRED")
        for ref in result.pack_ids:
            pack = c.get(ref, "pack")
            self.assertNotIn(self.f.sources["secret"], pack["closure"]["source_snapshot_ids"])
            self.assertIn(self.f.assignments["bio"], pack["closure"]["record_ids"])
        self.assertEqual(before, self.f.f.backend.audit()["head_hash"])

    def test_semantic_reranker_preserves_domain_membership_and_conflicts(self):
        from trace_gc.retrieval.reranker import JevReranker
        from trace_gc.adapter import record_response
        from trace_gc.demo import fixture_response
        q = self.request(requesting_component="upstream-synthesis", candidate_id=self.f.candidates["bio"],
            budget=RetrievalBudget(maximum_tokens=14000, maximum_latency_ms=20000, maximum_cost_units=100000))
        result, context, _ = self.retrieve(q)
        c = self.f.retriever.catalog
        rid = next(r["id"] for r in c.all("retrieval-result") if r["body"] == result)
        def execute(pack_id):
            return record_response(c, pack_id, fixture_response(c.get(pack_id, "pack")))
        out = JevReranker(execute).rerank(self.f.retriever, rid, candidate_id=self.f.candidates["bio"])
        new = c.get(c.get(out)["graph_context_id"], "graph-context")
        validate_context(c, c.get(out)["graph_context_id"], current_status=self.f.f.backend.statuses())
        self.assertEqual(new["research_domain_binding"], context["research_domain_binding"])
        self.assertEqual(new["conflict_refs"], context["conflict_refs"])
        self.assertEqual({i["id"] for i in new["items"]}, {i["id"] for i in context["items"]})

    def test_revocation_before_semantic_callback_prevents_execution(self):
        from trace_gc.retrieval.reranker import JevReranker
        q = self.request(requesting_component="upstream-synthesis", candidate_id=self.f.candidates["bio"],
            budget=RetrievalBudget(maximum_tokens=14000, maximum_latency_ms=20000, maximum_cost_units=100000))
        result, _, _ = self.retrieve(q)
        c = self.f.retriever.catalog
        rid = next(r["id"] for r in c.all("retrieval-result") if r["body"] == result)
        self.f.f.revoke_source()
        self.f.adapter.rebuild_domain_index()
        calls = []
        with self.assertRaises(ContractError):
            JevReranker(lambda pack: calls.append(pack)).rerank(self.f.retriever, rid, candidate_id=self.f.candidates["bio"])
        self.assertEqual(calls, [])
