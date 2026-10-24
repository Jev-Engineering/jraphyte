#!/usr/bin/env python3
"""Run explicitly synthetic domain workloads. This never qualifies a deployment.

A representative application integrates trace_gc.retrieval.domain_workload with
its own authenticated session factory and frozen reviewed protocol. This CLI
only creates isolated temporary reference databases and ephemeral test keys.
"""
from __future__ import annotations
import argparse
from collections import Counter
from contextlib import ExitStack
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests')]

from trace_gc.backend import SQLiteReferenceBackend
from trace_gc.canonical import digest, dumps
from trace_gc.retrieval.domain_workload import VERSION, run_workload
from trace_gc.retrieval.store import SQLiteGraphAdapter
from trace_gc.retrieval.service import HybridRetriever


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--synthetic',action='store_true',required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--repeats',type=int,default=4)
    p.add_argument('--concurrency',type=int,default=4)
    p.add_argument('--writes',type=int,default=2)
    args=p.parse_args()
    import test_domain_retrieval as fixtures
    fixture_test=unittest.TestCase()
    try:
        x=fixtures.fixture(fixture_test);f=x['f'];backend=f.backend
        initial=backend.state();frozen_version=initial['graph_version']
        sources={r['id']:r['hash'] for r in f.c.all('source')}
        corpus_hash=digest({'snapshot':initial,'source_hashes':sources})
        cases=[]
        for id_,strategies,focus in [('claim',['NEIGHBORHOOD'],[x['claim']]),
            ('lexical',['LEXICAL'],[x['claim']]),('identity',['NEIGHBORHOOD','PATH'],['A'])]:
            q=fixtures.DomainRetrievalTests.request(type('Config',(),{'x':x,'c':f.c,'f':f})(),
                strategies=strategies,focus_entities=focus,focus_relationships=[])
            cases.append({'id':id_,'query':q,'expected_edges':['support','refute'] if id_!='identity' else
                ['related','path','alias','cannot','prereq'],
                'required_conflict_pairs':[['support','refute']] if id_!='identity' else [],'forbidden_source_ids':[]})
        protocol={'version':VERSION,'cohort':'SYNTHETIC','label_origin':'SYNTHETIC','corpus_hash':corpus_hash,
            'case_hash':digest(cases),'seed':24,'repeats':args.repeats,'concurrency':args.concurrency,'write_count':args.writes,
            'isolation_requirements':{'single_temporary_sandbox':True,'deployment_requirements':'NOT_SUPPLIED'},
            'slos':{},'decision_owner':None,'memory_profile':False}
        args.output.mkdir(parents=True,exist_ok=True)
        # Inputs are frozen and recorded before measurement, not reconstructed
        # from favorable output. Synthetic source text contains no private data.
        (args.output/'protocol.json').write_text(json.dumps(protocol,indent=2)+'\n')
        (args.output/'cases.json').write_text(json.dumps(cases,indent=2)+'\n')
        (args.output/'corpus.json').write_text(json.dumps({'snapshot':initial,'source_hashes':sources,
            'fixture_sha256':hashlib.sha256(Path(fixtures.__file__).read_bytes()).hexdigest()},indent=2)+'\n')
        class Session:
            def __init__(self):
                self.backend=SQLiteReferenceBackend(f.path,catalog=f.c,schema_id=f.schema,nodes={},sandbox=True)
                self.retriever=HybridRetriever(SQLiteGraphAdapter(self.backend,trust=f.trust),access_policy=x['acl'])
            def close(self):self.backend.close()
        previous=[x['assignments'][f.source]]
        def write_action(index):
            assignment=f.assignment(labels=['biology','computing'],supersedes=previous[0])
            receipt=f.publish(f.plan(assignment,key=f'benchmark-write-{index}'))['receipt']
            previous[0]=assignment
            return {'version':receipt['version'],'event_hash':receipt['event_hash']}
        report=run_workload(Session,protocol,cases,corpus_hash=corpus_hash,write_action=write_action)
        degrees=Counter(n for fact in initial['assertions'].values() for n in
            (fact['assertion']['subject'],fact['assertion']['object']))
        report['structure']={'nodes':len(initial['nodes']),'assertions':len(initial['assertions']),
            'source_snapshots':len(sources),'degree_histogram':dict(Counter(degrees.values())),
            'maximum_degree':max(degrees.values()),'largest_hub_degree_share':max(degrees.values())/sum(degrees.values())}
        db=backend.db
        report['storage']={'sqlite_page_bytes':db.execute('PRAGMA page_count').fetchone()[0]*db.execute('PRAGMA page_size').fetchone()[0],
            'index_rows':db.execute('SELECT count(*) FROM trace_domain_index').fetchone()[0]}
        try:report['storage']['domain_index_bytes']=db.execute("SELECT sum(pgsize) FROM dbstat WHERE name IN ('trace_domain_index','trace_domain_index_heads','trace_domain_lookup')").fetchone()[0]
        except Exception:report['storage']['domain_index_bytes']=None
        f.revoke_source()
        revoke_cases=deepcopy(cases)
        for case in revoke_cases:
            case['query']['graph_version']=frozen_version
            case['forbidden_source_ids']=[f.source]
            case['expected_edges']=[];case['required_conflict_pairs']=[]
        rev_protocol={**protocol,'case_hash':digest(revoke_cases),'repeats':1,'write_count':0}
        revocation=run_workload(Session,rev_protocol,revoke_cases,corpus_hash=corpus_hash)
        report['historical_revocation']={'status':'PASS' if not any(s['source_revocation_leaks'] for s in revocation['summary'].values()) else 'FAIL',
            'graph_version':frozen_version,'current_source_epoch':backend.statuses()[f.source]['epoch'],
            'summary':revocation['summary']}
        report['provider_calls']=0;report['production_graph_writes']=0
        report['method_sha256']={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in (Path(__file__), ROOT/'trace_gc/retrieval/domain_workload.py')}
        report['placement']='NOT_DECIDED: representative workload, deployment SLOs/isolation requirements and owner approval absent'
        from trace_gc.canonical import loads
        import base64
        # Public fixture keys enable read-only replay of the recorded synthetic
        # journal. They are not trusted deployment enrollment or signing keys.
        recorded={'scope':'SYNTHETIC_REPLAY_ONLY','authorization_granted':False,
            'records':backend.load_catalog().all(),
            'genesis':loads(backend.db.execute('SELECT body FROM trace_meta').fetchone()[0])['genesis_state'],
            'events':f.journal(),'current_source_status':backend.statuses(),'access_policy':x['acl'],
            'public_test_issuers':[{ 'issuer':name,'public_key_base64':base64.b64encode(policy.public_key).decode(),
                'principal':policy.principal,'purposes':sorted(policy.purposes),'operations':sorted(policy.operations),
                'scopes':sorted(policy.scopes),'modes':sorted(policy.modes),'maximum_risk':policy.maximum_risk,
                'can_review':policy.can_review} for name,policy in sorted(f.trust._issuers.items())]}
        (args.output/'recorded-synthetic-run.json').write_text(json.dumps(recorded,indent=2)+'\n')
        report['recorded_run_sha256']=hashlib.sha256((args.output/'recorded-synthetic-run.json').read_bytes()).hexdigest()
        report['limitations'].append('Synthetic reruns mint new ephemeral fixture keys; source/evidence identities and query semantics remain stable, while signed assignment identities differ. The retained recorded run allows exact journal replay with public test keys only.')
        (args.output/'results.json').write_text(json.dumps(report,indent=2)+'\n')
        (args.output/'revocation-results.json').write_text(json.dumps(revocation,indent=2)+'\n')
        print(json.dumps({k:report[k] for k in ('status','summary','committed_writes','historical_revocation','placement')},indent=2))
        return int(report['historical_revocation']['status']!='PASS' or any(s['missed_contradictions'] or s['source_revocation_leaks'] for s in report['summary'].values()))
    finally:fixture_test.doCleanups()

if __name__=='__main__':raise SystemExit(main())
