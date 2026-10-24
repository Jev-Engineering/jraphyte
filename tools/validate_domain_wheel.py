#!/usr/bin/env python3
"""Validate an actual installed project wheel; never substitute checkout imports."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tempfile
import zipfile

SMOKE = r'''
import contextlib, io, json, pathlib, sys
root=pathlib.Path(sys.argv[1]).resolve()
sys.path.insert(0,str(root))
import trace_gc.catalog, trace_gc.domains, trace_gc.schema, trace_gc.cli
import trace_gc.backend, trace_gc.domain_publication, trace_gc.trust
from jsonschema import Draft202012Validator
for module in (trace_gc.catalog,trace_gc.domains,trace_gc.schema,trace_gc.cli,trace_gc.backend,trace_gc.domain_publication):
    assert pathlib.Path(module.__file__).resolve().is_relative_to(root), module.__file__
package=pathlib.Path(trace_gc.domains.__file__).parent
schemas=package/'data'/'schemas'
found=sorted(schemas.glob('*.schema.json'))
assert len(found)>=32, 'new schemas missing'
for path in found:
    Draft202012Validator.check_schema(json.loads(path.read_text(encoding='utf-8')))
for kind in trace_gc.domains.KINDS | trace_gc.domain_publication.KINDS:
    assert (schemas/(kind+'.schema.json')).is_file(), kind
record=json.loads((package/'data/domains/taxonomy-v1.example.json').read_text(encoding='utf-8'))
catalog=trace_gc.catalog.Catalog([record])
assert catalog.record(record['id'])==record

# Exercise the actual installed backend/module, not an extracted class or checkout.
import tempfile
from trace_gc.canonical import digest
from trace_gc.trust import Signer, TrustStore, IssuerPolicy
from trace_gc.domains import propose, assign, review_payload, REVIEW_PURPOSE, REVIEW_OPERATION
from trace_gc.domain_publication import ClassificationPublisher, AUTHORIZATION, PREFLIGHT, PUBLISH, MIGRATE, VALIDATE_CAPABILITY, authorization_payload
signer=Signer.ephemeral('installed-wheel-fixture')
trust=TrustStore()
trust.enroll(signer.issuer,IssuerPolicy(public_key=signer.public_key(),principal='fixture',
    purposes=frozenset({REVIEW_PURPOSE,AUTHORIZATION,PREFLIGHT,'SOURCE_STATUS'}),
    operations=frozenset({REVIEW_OPERATION,PUBLISH,MIGRATE,VALIDATE_CAPABILITY,'SOURCE_ADMIT'}),
    scopes=frozenset({'wheel-fixture'}),modes=frozenset({'SYNTHETIC'}),maximum_risk=2,can_review=True))
schema_id=catalog.put('schema',{'version':'fixture-1','relations':{'related':{
    'domain':'*','range':'*','symmetric':True,'inverse_of':None,'incompatible':[],
    'transitive':False,'allow_self':False}}})
source_id=catalog.source('wheel-fixture','1','Installed publication fixture.',scope='wheel-fixture')
def stamp(second): return '2026-01-01T00:00:%02dZ'%second
with tempfile.TemporaryDirectory(prefix='trace-domain-wheel-') as directory:
    with trace_gc.backend.SQLiteReferenceBackend(pathlib.Path(directory)/'graph.sqlite',catalog=catalog,
             schema_id=schema_id,nodes={},sandbox=True) as backend:
        service=ClassificationPublisher(backend,trust,signer,security_scope='wheel-fixture',
                                       execution_mode='SYNTHETIC',publication_enabled=True)
        action={'action':'ADMIT','source_hashes':{source_id:catalog.hash(source_id)},
                'security_scope':'wheel-fixture','execution_mode':'SYNTHETIC','expected_version':0}
        backend.admit_sources(catalog,[source_id],trust=trust,
            authorization=signer.issue('SOURCE_STATUS',action,issued_at=stamp(1)),
            security_scope='wheel-fixture',execution_mode='SYNTHETIC',expected_version=0,key='admit',at=stamp(1))
        migration=service.plan(catalog,assignment_id=None,key='migration',run_id='wheel',created_at=stamp(2))
        preflight=service.preflight(catalog,migration,at=stamp(3))
        service.publish(catalog,migration,preflight=preflight,
            authorization=signer.issue(AUTHORIZATION,authorization_payload(catalog,migration),issued_at=stamp(4)),at=stamp(5))
        proposal=propose(catalog,source_snapshot_id=source_id,taxonomy_id=record['id'],
            domain_ids=[record['body']['domains'][0]['id']],source_epoch=0,effective_graph_version=3,
            method={'kind':'RULE','name':'wheel-fixture','version':'1','artifact_hash':digest('fixture')},
            basis_ids=[source_id],execution_mode='SYNTHETIC',created_at=stamp(6))
        review=catalog.put('receipt',signer.issue(REVIEW_PURPOSE,review_payload(catalog,proposal,'fixture'),issued_at=stamp(7)))
        assignment=assign(catalog,proposal_id=proposal,review_receipt_id=review,reviewed_by='fixture',trust=trust,at=stamp(8))
        plan=service.plan(catalog,assignment_id=assignment,key='publication',run_id='wheel',created_at=stamp(9))
        preflight=service.preflight(catalog,plan,at=stamp(10))
        service.publish(catalog,plan,preflight=preflight,
            authorization=signer.issue(AUTHORIZATION,authorization_payload(catalog,plan),issued_at=stamp(11)),at=stamp(12))
        assert service.audit()['classification_events']==2
        snapshot=trace_gc.catalog.Catalog()
        snap=backend.snapshot(snapshot)
        assert snapshot.get(snap)['research_domains']['assignments'][source_id]['assignment_id']==assignment

sys.argv=['trace-gc','--version']
out=io.StringIO()
with contextlib.redirect_stdout(out):
    try:
        trace_gc.cli.main()
    except SystemExit as exc:
        assert exc.code in (None,0), exc.code
assert out.getvalue().strip(), 'CLI did not report a version'
print(json.dumps({'status':'PASS','schema_count':len(found),'installed_imports':True,
                  'checkout_imports':False,'cli':out.getvalue().strip(),
                  'example_taxonomy_loaded':True,'classification_publication_smoke':True,'production_qualified':False}))
'''


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wheel',type=Path,required=True)
    parser.add_argument('--report',type=Path,required=True)
    args=parser.parse_args()
    report={'status':'NOT_RUN','production_qualified':False,'scope':'installed-wheel-contracts-only'}
    try:
        wheel=args.wheel.resolve(strict=True)
        if wheel.suffix != '.whl': raise ValueError('Expected an actual .whl file')
        report['wheel_sha256']=hashlib.sha256(wheel.read_bytes()).hexdigest()
        with zipfile.ZipFile(wheel) as archive:
            for name in archive.namelist():
                parts=PurePosixPath(name).parts
                if name.startswith('/') or '..' in parts or '\\' in name:
                    raise ValueError('Unsafe archive path')
        with tempfile.TemporaryDirectory(prefix='trace-gc-wheel-contracts-') as temporary:
            temp=Path(temporary); target=temp/'installed'; outside=temp/'outside'; outside.mkdir()
            install=subprocess.run([sys.executable,'-I','-m','pip','install','--no-index','--no-deps',
                                    '--target',str(target),str(wheel)],cwd=outside,text=True,
                                   capture_output=True,timeout=180,check=True)
            report['pip_returncode']=install.returncode
            smoke=subprocess.run([sys.executable,'-I','-c',SMOKE,str(target)],cwd=outside,
                                 text=True,capture_output=True,timeout=120,check=True)
            result=json.loads(smoke.stdout)
            if result.get('status')!='PASS': raise ValueError('Installed smoke did not pass')
            report.update(result)
    except FileNotFoundError as exc:
        report['reason']=str(exc)
    except (ValueError,zipfile.BadZipFile,subprocess.CalledProcessError,subprocess.TimeoutExpired,OSError) as exc:
        report['status']='FAIL';report['reason']=str(exc)
        if getattr(exc,'stderr',None): report['stderr']=str(exc.stderr)[-12000:]
    args.report.parent.mkdir(parents=True,exist_ok=True)
    args.report.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,indent=2))
    return 0 if report['status']=='PASS' else 2


if __name__=='__main__': raise SystemExit(main())
