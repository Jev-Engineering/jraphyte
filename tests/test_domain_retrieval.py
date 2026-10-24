"""Synthetic all-channel domain retrieval through real runtime modules.

The graph seed uses the privileged test transaction primitive, not a model or
production write. Classifications use the signed publisher and indexed adapter.
No provider, deployment, independent labels, or distributed acceptance is claimed.
"""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import unittest

from trace_gc.backend import SQLiteReferenceBackend
from trace_gc.canonical import digest, loads
from trace_gc.catalog import Catalog
from trace_gc.errors import ContractError
from trace_gc.retrieval.contracts import query, RetrievalBudget, STRATEGIES, VERSION, DOMAIN_VERSION
from trace_gc.retrieval.security import access_policy, grant
from trace_gc.retrieval.store import SQLiteGraphAdapter, InMemoryGraphAdapter
from trace_gc.retrieval.service import HybridRetriever, GraphRAGQueryService, validate_context
from trace_gc.retrieval.integration import validate_record
from trace_gc.retrieval.planner import RetrievalPlanner
from trace_gc.replay import replay_retrieval
import test_domain_publication as publication_fixture


def fixture(test):
    f = publication_fixture.DomainPublication(); f.setUp(); test.addCleanup(f.doCleanups)
    c, backend = f.c, f.backend
    claim = c.claim("Biology improves research outcomes.")
    b = c.source("paper-b", "1", "Biology did not improve research outcomes.", scope="tenant-a")
    unrelated = c.source("computing-only", "1", "Biology lookup unrelated computing notes.", scope="tenant-a")
    unknown = c.source("identity", "1", "The research entities are aliases.", scope="tenant-a")
    eb, eu, ei = [c.evidence(s) for s in (b, unrelated, unknown)]
    action = {"action": "ADMIT", "source_hashes": {s: c.hash(s) for s in sorted([b, unrelated, unknown])},
        "security_scope": "tenant-a", "execution_mode": "SYNTHETIC", "expected_version": 1}
    at = f.time()
    backend.admit_sources(c, [b, unrelated, unknown], trust=f.trust,
        authorization=f.source_signer.issue("SOURCE_STATUS", action, issued_at=at),
        security_scope="tenant-a", execution_mode="SYNTHETIC", expected_version=1, key="other-sources", at=at)
    def rel(**kw):
        return {"domain": "*", "range": "*", "symmetric": False, "inverse_of": None,
            "incompatible": [], "transitive": False, "allow_self": False, **kw}
    relations = {"supports": rel(incompatible=["refutes"]), "refutes": rel(incompatible=["supports"]),
        "related": rel(), "same_as": rel(symmetric=True), "different_from": rel(symmetric=True), "subclass_of": rel()}
    schema = c.put("schema", {"version": "retrieval-test-v1", "relations": relations})
    nodes = {"paper": "Document", "paper-b": "Document", claim: "Claim", "A": "Entity", "B": "Entity", "C": "Entity",
        "Alias": "Entity", "Other": "Entity", "D": "Entity", "E": "Entity", "Type": "Type", "Supertype": "Type"}
    facts = {}
    for ref,s,p,o,ev,prereqs in [
        ("support", "paper", "supports", claim, f.evidence, []),
        ("refute", "paper-b", "refutes", claim, eb, []),
        ("related", "A", "related", "B", f.evidence, []),
        ("path", "B", "related", "C", f.evidence, []),
        ("alias", "A", "same_as", "Alias", ei, []),
        ("cannot", "A", "different_from", "Other", ei, []),
        ("off-topic", "D", "related", "E", eu, []),
        ("ontology", "Type", "subclass_of", "Supertype", f.evidence, []),
        ("prereq", "B", "related", "Alias", ei, []),
        ("dependent", "C", "related", "Other", f.evidence, ["prereq"])]:
        facts[ref] = {"assertion": {"subject":s,"predicate":p,"object":o,"qualifiers":{}},
            "evidence_ids":[ev],"prerequisites":prereqs,"active":True,"revision":1}
    def seed(state,statuses):
        state.update(nodes=nodes, assertions=facts, schema_id=schema, schema_hash=c.hash(schema))
        return state
    operation={"action":"SYNTHETIC_TEST_GRAPH_SEED", "fixture_hash":digest([nodes, facts])}
    backend._transaction(key="seed", fingerprint=digest(operation), expected_version=2, operation=operation,
        catalog=c, apply=seed, authorization_hash=digest("test-only"), preflight_hash=digest("test-only"), at=f.time())
    f.schema=schema; f.migrate()
    assignments={}
    for source, labels in [(f.source,["biology", "computing"]),(b,["computing"]),(unrelated,["computing"])]:
        a=f.assignment(source=source, labels=labels);f.publish(f.plan(a));assignments[source]=a
    snap=backend.snapshot(c)
    # A real candidate observation/resolver/evaluation supplies decision-channel data.
    from trace_gc.compiler import compile_pack
    from trace_gc.programs import question
    from trace_gc.adapter import record_response
    from trace_gc.budget import RunBudget
    from trace_gc.resolver import solve, project_resolutions
    from trace_gc.policy import create_policy
    from trace_gc.qualification import evaluate_policy
    policy=create_policy(c,version="retrieval-analysis",scope="tenant-a",population="synthetic-tests")
    candidate=c.candidate(id_="hypothesis",run_id="fixture-run",claim_id=claim,evidence_ids=[f.evidence],
        assertion={"subject":"paper","predicate":"supports","object":claim,"qualifiers":{}})
    pack=compile_pack(c,id_="test-pack",run_id="fixture-run",candidate_ids=[candidate],questions=[question(candidate,id_="q")],
        snapshot_id=snap,security_scope="tenant-a",created_at=f.time())
    response={"model":"jev-1.13.0","answers":{"q":{"type":"choice","choice":"SUPPORTS", "probabilities":{"SUPPORTS":.95,"CONTRADICTS":.02,"INSUFFICIENT":.03},"confidence":.5}},"usage":{"input_tokens":10,"output_tokens":1}}
    obs=record_response(c,pack,json.dumps(response).encode(),completed_at=f.time())
    limits={key:10000 for key in ("retrieval_requests","model_calls","retries","solver_expansions","review_actions","request_bytes")}
    budget=RunBudget(f.path.parent/'budget.sqlite',"fixture-run",limits);test.addCleanup(budget.close)
    batch=solve(c,run_id="fixture-run",candidate_ids=[candidate],observation_ids=obs,snapshot_id=snap,budget=budget,created_at=f.time())
    resolutions=project_resolutions(c,batch)
    evaluation=evaluate_policy(c,candidate_id=candidate,batch_id=batch,policy_version="retrieval-analysis",population="synthetic-tests",at=f.time())
    grants={"node:"+n:grant("tenant-a","test") for n in nodes}
    grants.update({"edge:"+n:grant("tenant-a","test") for n in facts})
    grants.update({"source:"+s:grant("tenant-a","test") for s in backend.statuses()})
    grants.update({"decision:"+s:grant("tenant-a","test") for s in [candidate,*obs,*resolutions,evaluation]})
    grants["schema:"+schema]=grant("tenant-a","test")
    acl=access_policy(tenant="tenant-a",workspace="test",user="researcher",grants=grants)
    adapter=SQLiteGraphAdapter(backend,c,trust=f.trust);adapter.rebuild_domain_index()
    retriever=HybridRetriever(adapter,access_policy=acl,catalog=c)
    return dict(f=f,c=c,claim=claim,b=b,unrelated=unrelated,unknown=unknown,eb=eb,eu=eu,ei=ei,
        facts=facts,nodes=nodes,assignments=assignments,acl=acl,adapter=adapter,r=retriever,
        candidate=candidate,evaluation=evaluation,pack=pack,obs=obs,budget=budget)


class DomainRetrievalTests(unittest.TestCase):
    def setUp(self):
        self.x=fixture(self); self.f=self.x['f'];self.c=self.x['c']; self.r=self.x['r']
    def request(self, **kw):
        defaults=dict(requesting_component="downstream-search",security_scope="tenant-a",text="Biology research",
            focus_entities=list(self.x['nodes']),strategies=["NEIGHBORHOOD"],research_domain_scope=["fixture/biology"],
            budget=RetrievalBudget(maximum_tokens=1000000,maximum_edges=100,maximum_nodes=100,maximum_source_spans=100,
                maximum_cost_units=1000000, maximum_latency_ms=30000),hop_limit=2,include_historical=True,
            focus_relationships=list(self.c.get(self.f.schema)['relations']))
        defaults.update(kw); return query(**defaults)
    def run_query(self, request=None):
        rid=self.r.retrieve(request or self.request()); result=self.c.get(rid)
        validate_context(self.c,result['graph_context_id'],current_access=self.r.access_policy,current_status=self.f.backend.statuses())
        validate_record(self.c,self.c.record(rid));validate_record(self.c,self.c.record(result['lineage_id']))
        return rid,result,self.c.get(result['graph_context_id'])
    def test_old_query_bytes_unchanged(self):
        q=query(requesting_component="downstream-search",security_scope="tenant-a")
        self.assertEqual(q['version'],VERSION);self.assertNotIn('research_domain_scope',q)
    def test_new_query_version_required(self):
        q=self.request();self.assertEqual(q['version'],DOMAIN_VERSION);q['version']=VERSION
        with self.assertRaises(ContractError):self.r.retrieve(q)
    def test_v2_cannot_omit_scope(self):
        q=self.request();q.pop('research_domain_scope')
        with self.assertRaises(ContractError):self.r.retrieve(q)
    def test_duplicate_or_unsorted_or_ambiguous_keys_fail(self):
        for keys in [['fixture/biology','fixture/biology'],['z/a','a/b'],['biology'],['*']]:
            with self.subTest(keys=keys),self.assertRaises(ContractError): self.request(research_domain_scope=keys)
    def test_unknown_scope_empty_no_invented_membership(self):
        _,_,ctx=self.run_query(self.request(strategies=list(STRATEGIES),research_domain_scope=['unknown/biology']))
        self.assertEqual(ctx['items'],[])
    def test_multilabel_source_searches_both_topics(self):
        for label in ['fixture/biology','fixture/computing']:
            _,_,ctx=self.run_query(self.request(strategies=['LEXICAL'],research_domain_scope=[label],include_conflicts=False))
            self.assertIn(self.f.evidence,ctx['selected_evidence_ids'])
    def test_off_topic_evidence_not_candidate_but_refutation_closure_retained(self):
        _,_,ctx=self.run_query(self.request(strategies=['LEXICAL']))
        self.assertIn(self.x['eb'],ctx['selected_evidence_ids']);self.assertNotIn(self.x['eu'],ctx['selected_evidence_ids'])
    def test_vector_filters_before_embedding(self):
        seen=[]
        class Spy:
            version='spy-test-v1'
            def embed(self,texts):seen.extend(texts);return [[1.,0.] for _ in texts]
        self.r.embedding=Spy()
        _,_,ctx=self.run_query(self.request(strategies=['VECTOR']))
        self.assertIn(self.c.get(self.f.evidence)['quote'],seen)
        for ev in [self.x['eb'],self.x['eu'],self.x['ei']]:self.assertNotIn(self.c.get(ev)['quote'],seen)
        self.assertIn(self.x['eb'],ctx['selected_evidence_ids'])
    def test_source_acl_before_domain_and_embedding(self):
        acl=deepcopy(self.r.access_policy);acl['grants'].pop('source:'+self.f.source);self.r.set_access_policy(acl)
        class NoCalls:
            version='no-call-v1'
            def embed(self,texts):raise AssertionError('denied sources reached embedding')
        self.r.embedding=NoCalls();_,_,ctx=self.run_query(self.request(strategies=['VECTOR']))
        self.assertEqual(ctx['items'],[])
    def test_withdrawn_source_not_restored_by_historical_mode(self):
        self.run_query();self.f.revoke_source()
        _,_,ctx=self.run_query(self.request(graph_version=7,mode='HISTORICAL',strategies=list(STRATEGIES)))
        self.assertEqual(ctx['items'],[])
    def test_tombstone_not_restored_by_historical_mode(self):
        self.f.revoke_source(tombstone=True)
        _,_,ctx=self.run_query(self.request(graph_version=7,mode='HISTORICAL'))
        self.assertEqual(ctx['items'],[])
    def test_source_scope_meaning_preserved(self):
        _,_,ctx=self.run_query(self.request(strategies=['LEXICAL'],source_scope=[self.x['unrelated']]))
        self.assertEqual(ctx['items'],[])
    def test_identity_and_prerequisite_closure(self):
        _,_,ctx=self.run_query(self.request(include_conflicts=False))
        for key in ['alias','cannot','prereq']:self.assertIn(key,ctx['retrieved_edges'])
        self.assertTrue(any('PREREQUISITE' in i['research_domain_closure'].get('prereq',[]) for i in ctx['items']))
    def test_closure_never_grants_cross_source_acl(self):
        acl=deepcopy(self.r.access_policy);acl['grants'].pop('source:'+self.x['b']);self.r.set_access_policy(acl)
        _,_,ctx=self.run_query(self.request(strategies=['LEXICAL']))
        self.assertNotIn(self.x['eb'],ctx['selected_evidence_ids'])
    def test_indivisible_closure_budget_never_one_sided(self):
        _,result,ctx=self.run_query(self.request(strategies=['LEXICAL'],focus_entities=[self.x['claim']],budget=RetrievalBudget(maximum_edges=1,maximum_tokens=100000)))
        self.assertNotIn(self.f.evidence,ctx['selected_evidence_ids']);self.assertEqual(result['status'],'PARTIAL')
    def test_unclassified_explicit_scope(self):
        _,_,ctx=self.run_query(self.request(strategies=['SOURCE'],research_domain_scope=['@unclassified'],source_scope=[self.x['unknown']]))
        self.assertIn(self.x['ei'],ctx['selected_evidence_ids']);self.assertNotIn(self.x['eu'],ctx['selected_evidence_ids'])
    def test_missing_label_explainable_in_required_closure(self):
        _,_,ctx=self.run_query(self.request())
        rows=[i['research_domain_assignments'].get(self.x['unknown']) for i in ctx['items']]
        self.assertTrue(any(row and row['state']=='UNCLASSIFIED' and row['assignment_id'] is None for row in rows))
    def test_revision_bound_in_context_and_lineage(self):
        _,result,ctx=self.run_query()
        self.assertEqual(ctx['research_domain_binding'],self.c.get(result['lineage_id'])['research_domain_binding'])
        self.assertEqual(ctx['research_domain_binding']['classification_revision'],4)
    def test_tampered_binding_rejected(self):
        _,result,ctx=self.run_query();ctx['research_domain_binding']['projection_hash']='f'*64
        bad=self.c.put('graph-context',ctx)
        with self.assertRaisesRegex(ContractError,'DOMAIN_CONTEXT_BINDING'):validate_context(self.c,bad)
    def test_tampered_item_assignment_rejected(self):
        _,_,ctx=self.run_query();ctx['items'][0]['research_domain_assignments']={}
        with self.assertRaisesRegex(ContractError,'CONTEXT_MATERIALIZATION'):validate_context(self.c,self.c.put('graph-context',ctx))
    def test_tampered_lineage_rejected(self):
        _,result,_=self.run_query();b=self.c.get(result['lineage_id']);b['research_domain_scope']=['fixture/computing']
        with self.assertRaisesRegex(ContractError,'DOMAIN_CONTEXT_BINDING'):validate_record(self.c,self.c.record(self.c.put('retrieval-lineage',b)))
    def test_real_retrieval_cache_hit(self):
        q=self.request();self.run_query(q);_,result,_=self.run_query(q)
        self.assertTrue(self.c.get(result['lineage_id'])['cache_hit'])
    def test_reclassification_invalidates_retrieval_cache(self):
        q=self.request();self.run_query(q);prior=self.x['assignments'][self.f.source]
        a=self.f.assignment(labels=['computing'],supersedes=prior);self.f.publish(self.f.plan(a))
        _,result,ctx=self.run_query(q)
        self.assertFalse(self.c.get(result['lineage_id'])['cache_hit']);self.assertEqual(ctx['items'],[]);self.assertGreater(self.r.cache.invalidations,0)
    def test_historical_exact_assignment(self):
        prior=self.x['assignments'][self.f.source];a=self.f.assignment(labels=['computing'],supersedes=prior);self.f.publish(self.f.plan(a))
        _,_,ctx=self.run_query(self.request(graph_version=7))
        self.assertTrue(ctx['items'])
        self.assertEqual(ctx['research_domain_binding']['classification_revision'],4)
    def test_downstream_answer_binding_and_no_authority(self):
        answer=GraphRAGQueryService(self.r).query(self.request())
        body=answer['context'];self.assertFalse(body['can_mutate_graph']);self.assertEqual(body['research_domain_scope'],['fixture/biology'])
        validate_record(self.c,self.c.record(answer['answer_context_id']))
    def test_planner_scope_preserved_and_cannot_change_after_plan(self):
        planner=RetrievalPlanner();pid=planner.plan(self.c,candidate_id=self.x['candidate'],question_type='ASSERTION',risk_class='R2',
            known_entities=['paper'],known_relations=['supports'],budget=RetrievalBudget(),research_domain_scope=['fixture/biology'])
        q=planner.request(self.c,pid,security_scope='tenant-a',text='Biology',retrieval_round=0)
        self.assertEqual(q['research_domain_scope'],['fixture/biology'])
        with self.assertRaises(ContractError):planner.request(self.c,pid,security_scope='tenant-a',text='Biology',retrieval_round=0,research_domain_scope=['fixture/computing'])
    def test_replay_new_scope_preserves_original_observations(self):
        rid,_,ctx=self.run_query();before={r['id']:r['hash'] for r in self.c.all('observation')}
        replay=self.c.get(replay_retrieval(self.r,rid,{'research_domain_scope':['fixture/computing']}))
        self.assertEqual(replay['observation_hashes_preserved'],before);self.assertFalse(replay['authorization_granted'])
        self.assertEqual({r['id']:r['hash'] for r in self.c.all('observation')},before)
    def test_replay_legacy_query_to_v2(self):
        q=self.request(research_domain_scope=None);rid,_,_=self.run_query(q)
        replay=replay_retrieval(self.r,rid,{'research_domain_scope':['fixture/biology']})
        self.assertFalse(self.c.get(replay)['authorization_granted'])
    def test_schema_rule_scope_distinct_from_ontology_scope(self):
        _,_,ctx=self.run_query(self.request(strategies=['SCHEMA'],include_conflicts=False,ontology_scope=['related']))
        self.assertTrue(ctx['schema_fragments']);self.assertEqual(ctx['research_domain_scope'],['fixture/biology'])
    def test_full_graph_authority_unchanged_by_queries(self):
        before=self.f.dump()
        self.run_query(self.request(strategies=list(STRATEGIES)))
        self.assertEqual(self.f.dump(),before)
    def test_no_labels_or_membership_leak_from_denied_sources(self):
        acl=deepcopy(self.r.access_policy);acl['grants'].pop('source:'+self.x['b']);self.r.set_access_policy(acl)
        answer=GraphRAGQueryService(self.r).query(self.request())['context']
        self.assertNotIn(self.x['b'],json.dumps(answer['items']))


def strategy_test(name):
    def test(self):
        _,result,ctx=self.run_query(self.request(strategies=[name],include_conflicts=name=='CONFLICT'))
        rows=self.c.get(result['lineage_id'])['candidates']
        self.assertTrue(any(name in row['methods'] for row in rows),f'{name} produced no candidate')
        self.assertTrue(ctx['items']);self.assertNotIn('off-topic',ctx['retrieved_edges'])
        self.assertTrue(all(i['research_domain_scope']==['fixture/biology'] for i in ctx['items']))
    return test
for name in STRATEGIES:
    setattr(DomainRetrievalTests,'test_channel_'+name.lower(),strategy_test(name))
