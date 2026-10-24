"""Protocol and metric rejection tests; not representative-workload evidence."""
from copy import deepcopy
import unittest
from trace_gc.canonical import digest
from trace_gc.errors import ContractError
from trace_gc.retrieval.contracts import query
from trace_gc.retrieval.domain_workload import VERSION, percentile, validate_protocol, run_workload

class WorkloadProtocol(unittest.TestCase):
    def setUp(self):
        self.cases=[{'id':'example','query':query(requesting_component='downstream-search',security_scope='sandbox',
            research_domain_scope=['fixture/biology']), 'expected_edges':['edge'],
            'required_conflict_pairs':[['support','refute']],'forbidden_source_ids':[]}]
        self.p={'version':VERSION,'cohort':'SYNTHETIC','label_origin':'SYNTHETIC','corpus_hash':digest('synthetic'),
            'case_hash':digest(self.cases),'seed':0,'repeats':1,'concurrency':1,'write_count':0,
            'isolation_requirements':{},'slos':{},'decision_owner':None,'memory_profile':False}
    def test_nearest_rank_percentiles(self):
        self.assertEqual(percentile(list(range(1,101)),.95),95)
        self.assertEqual(percentile([10,20,30],.99),30)
    def test_empty_percentile_is_unknown_not_zero(self):self.assertIsNone(percentile([],.95))
    def test_explicit_synthetic_population(self):validate_protocol(self.p,self.cases)
    def test_representative_requires_external_inputs(self):
        self.p['cohort']='REPRESENTATIVE_REVIEWED';self.p['label_origin']='HUMAN'
        with self.assertRaisesRegex(ContractError,'WORKLOAD_EXTERNAL_INPUTS'):validate_protocol(self.p,self.cases)
    def test_synthetic_cannot_claim_independent_labels(self):
        self.p['label_origin']='HUMAN'
        with self.assertRaisesRegex(ContractError,'WORKLOAD_LABELS'):validate_protocol(self.p,self.cases)
    def test_changed_cases_rejected_before_session_creation(self):
        self.cases[0]['expected_edges']=[]
        with self.assertRaisesRegex(ContractError,'WORKLOAD_PROTOCOL'):
            run_workload(lambda:self.fail('session created before input verification'),self.p,self.cases,corpus_hash=self.p['corpus_hash'])
    def test_changed_corpus_rejected(self):
        with self.assertRaisesRegex(ContractError,'WORKLOAD_CORPUS'):
            run_workload(lambda:self.fail('session created'),self.p,self.cases,corpus_hash=digest('other'))
    def test_unbounded_and_boolean_concurrency_rejected(self):
        for v in [True,0,65]:
            self.p['concurrency']=v
            with self.assertRaisesRegex(ContractError,'WORKLOAD_BOUNDS'):validate_protocol(self.p,self.cases)
    def test_duplicate_case_ids_rejected(self):
        self.cases+=deepcopy(self.cases);self.p['case_hash']=digest(self.cases)
        with self.assertRaisesRegex(ContractError,'WORKLOAD_PROTOCOL'):validate_protocol(self.p,self.cases)
    def test_no_implicit_write_authority(self):
        self.p['write_count']=1
        with self.assertRaisesRegex(ContractError,'WORKLOAD_WRITE_AUTHORITY'):
            run_workload(lambda:self.fail('session created'),self.p,self.cases,corpus_hash=self.p['corpus_hash'])
    def test_bad_conflict_pair_rejected(self):
        self.cases[0]['required_conflict_pairs']=[['same','same']];self.p['case_hash']=digest(self.cases)
        with self.assertRaisesRegex(ContractError,'WORKLOAD_CASE'):validate_protocol(self.p,self.cases)
