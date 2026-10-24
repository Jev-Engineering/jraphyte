#!/usr/bin/env python3
"""Run named domain acceptance tests and retain exact results and source hashes.

This supplements, not replaces, tools/run_validation.py and genuine distribution
validation. It never marks a missing legacy source or deployment gate passed.
"""
from __future__ import annotations
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import runpy
import sys
import time
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tools'),str(ROOT/'tests')]

class EvidenceResult(unittest.TextTestResult):
    def __init__(self,*args,**kwargs):super().__init__(*args,**kwargs);self.records=[];self.started={}
    def startTest(self,test):self.started[test.id()]=time.perf_counter();super().startTest(test)
    def record(self,test,status,**extra):
        self.records.append({'test':test.id(),'status':status,'seconds':time.perf_counter()-self.started[test.id()],**extra})
    def addSuccess(self,test):super().addSuccess(test);self.record(test,'PASS')
    def addFailure(self,test,err):super().addFailure(test,err);self.record(test,'FAIL')
    def addError(self,test,err):super().addError(test,err);self.record(test,'ERROR')
    def addSkip(self,test,reason):super().addSkip(test,reason);self.record(test,'SKIPPED',reason=reason)


def verify_schemas():
    from jsonschema import Draft202012Validator
    generated=runpy.run_path(str(ROOT/'tools/build_schemas.py'))['SCHEMAS']
    expected={f'{name}.schema.json' for name in generated}
    for root in [ROOT/'schemas/runtime',ROOT/'trace_gc/data/schemas']:
        if {p.name for p in root.glob('*.schema.json')}!=expected:raise AssertionError('Schema inventory mismatch')
    hashes={}
    for name,body in generated.items():
        obj={'$schema':'https://json-schema.org/draft/2020-12/schema','$id':f'urn:trace-gc:0.3.0:{name}',
             'title':f'TRACE-GC {name} v0.3.0',**body}
        Draft202012Validator.check_schema(obj)
        data=(json.dumps(obj,indent=2)+'\n').encode()
        filename=f'{name}.schema.json'
        for root in [ROOT/'schemas/runtime',ROOT/'trace_gc/data/schemas']:
            if (root/filename).read_bytes()!=data:raise AssertionError('Generator/emitted bytes differ: '+filename)
        hashes[filename]=hashlib.sha256(data).hexdigest()
    return {'status':'PASS','count_per_tree':len(expected),'sha256':hashes}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--legacy-core',type=Path)
    parser.add_argument('--include-upstream-regressions',action='store_true')
    args=parser.parse_args();args.output.mkdir(parents=True,exist_ok=True)
    if args.legacy_core:os.environ['TRACE_GC_LEGACY_CORE']=str(args.legacy_core.resolve())
    loader=unittest.TestLoader();suite=loader.discover(str(ROOT/'tests'),pattern='test_domain_*.py')
    if args.include_upstream_regressions:
        for name in ['test_graphrag_retrieval','test_graphrag_security']:
            suite.addTests(loader.loadTestsFromName(name))
    with (args.output/'tests.log').open('w',encoding='utf-8') as stream:
        result=unittest.TextTestRunner(stream=stream,verbosity=2,resultclass=EvidenceResult).run(suite)
    ok=result.wasSuccessful();gates={}
    try:gates['schemas']=verify_schemas()
    except Exception as exc:gates['schemas']={'status':'FAIL','error':str(exc)};ok=False
    core=os.environ.get('TRACE_GC_LEGACY_CORE')
    if core:
        try:
            from trace_gc.conformance import check_legacy
            gates['pinned_legacy_original_gate']=check_legacy(core)
        except Exception as exc:gates['pinned_legacy_original_gate']={'status':'FAIL','error':str(exc)};ok=False
    else:gates['pinned_legacy_original_gate']={'status':'NOT_RUN','reason':'Exact reviewed source not supplied'}
    try:
        from trace_gc.demo import run_demo
        gates['reference_demo']=run_demo()
    except Exception as exc:gates['reference_demo']={'status':'FAIL','error':str(exc)};ok=False
    groups={}
    for record in result.records:
        group=record['test'].split('.')[0]
        groups.setdefault(group,Counter())[record['status']]+=1
    manifest={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(ROOT.rglob('*')) if p.is_file() and '.git' not in p.parts and '__pycache__' not in p.parts
        and p.suffix in {'.py','.json','.toml','.yml','.md'}}
    report={'recorded_at':datetime.now(timezone.utc).isoformat(),'status':'TARGETED_PASS' if ok else 'FAIL',
        'scope':'Named domain tests plus explicitly selected upstream regressions; not the normal whole-repository release suite.',
        'tests_run':result.testsRun,'tests_passed':sum(r['status']=='PASS' for r in result.records),
        'failures':len(result.failures),'errors':len(result.errors),'skipped':len(result.skipped),
        'groups':{k:dict(v) for k,v in groups.items()},'tests':result.records,'gates':gates,
        'environment':{'python':platform.python_version(),'platform':platform.platform(),
            'dependencies':{p:importlib.metadata.version(p) for p in ('jsonschema','cryptography')}},
        'source_sha256':manifest,'provider_calls':0,'production_graph_writes':0,
        'unrun_gates':{'normal_full_release':'NOT_RUN_BY_THIS_RUNNER','sdist_wheel':'NOT_RUN_BY_THIS_RUNNER',
            'representative_workload':'NOT_RUN_BY_THIS_RUNNER','native_deployment':'NOT_RUN',
            'required_hosted_ci_review_merge':'NOT_RUN_BY_THIS_RUNNER'},'production_qualified':False}
    (args.output/'validation.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:report[k] for k in ['status','tests_run','tests_passed','failures','errors','skipped','groups']},indent=2))
    return 0 if ok else 1

if __name__=='__main__':raise SystemExit(main())
