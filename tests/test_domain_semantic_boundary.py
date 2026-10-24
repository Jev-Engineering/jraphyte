"""Current ACL/source checks and immutable domain binding at semantic execution."""
from copy import deepcopy
import unittest
from trace_gc.adapter import record_response
from trace_gc.demo import fixture_response
from trace_gc.errors import ContractError
from trace_gc.retrieval.reranker import JevReranker
from trace_gc.retrieval.service import validate_context
import test_domain_retrieval as fixtures


class DomainSemanticBoundary(unittest.TestCase):
    def setUp(self):
        self.x=fixtures.fixture(self)
        self.f,self.c,self.r=self.x['f'],self.x['c'],self.x['r']
        self.query=fixtures.DomainRetrievalTests.request(self,
            requesting_component='upstream-synthesis',candidate_id=self.x['candidate'],
            strategies=['LEXICAL'],focus_entities=[self.x['claim']],focus_relationships=[])
        self.result=self.r.retrieve(self.query)
        self.calls=[]
        def execute(pack):
            self.calls.append(pack)
            return record_response(self.c,pack,fixture_response(self.c.get(pack)))
        self.reranker=JevReranker(execute)

    def test_reranking_preserves_membership_and_cross_domain_closure(self):
        before=self.c.get(self.c.get(self.result)['graph_context_id'])
        result=self.reranker.rerank(self.r,self.result,candidate_id=self.x['candidate'])
        rid=self.c.get(result)['graph_context_id'];after=self.c.get(rid)
        validate_context(self.c,rid,current_access=self.r.access_policy,current_status=self.f.backend.statuses())
        self.assertEqual(before['research_domain_binding'],after['research_domain_binding'])
        self.assertEqual({i['id'] for i in before['items']},{i['id'] for i in after['items']})
        self.assertIn(self.x['eb'],after['selected_evidence_ids'])
        self.assertEqual(len(self.calls),1)

    def test_source_revocation_after_retrieval_prevents_semantic_call(self):
        self.f.revoke_source()
        with self.assertRaises(ContractError):
            self.reranker.rerank(self.r,self.result,candidate_id=self.x['candidate'])
        self.assertEqual(self.calls,[])

    def test_current_acl_revocation_prevents_semantic_call(self):
        acl=deepcopy(self.r.access_policy);acl['grants'].pop('source:'+self.f.source)
        self.r.set_access_policy(acl)
        with self.assertRaises(ContractError):
            self.reranker.rerank(self.r,self.result,candidate_id=self.x['candidate'])
        self.assertEqual(self.calls,[])
