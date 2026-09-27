#!/usr/bin/env python3
"""Validate an actual installed project wheel; never substitute checkout imports."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
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
from jsonschema import Draft202012Validator
for module in (trace_gc.catalog,trace_gc.domains,trace_gc.schema,trace_gc.cli):
    assert pathlib.Path(module.__file__).resolve().is_relative_to(root), module.__file__
package=pathlib.Path(trace_gc.domains.__file__).parent
schemas=package/'data'/'schemas'
found=sorted(schemas.glob('*.schema.json'))
assert len(found)>=31, 'new schemas missing'
for path in found:
    Draft202012Validator.check_schema(json.loads(path.read_text(encoding='utf-8')))
for kind in trace_gc.domains.KINDS:
    assert (schemas/(kind+'.schema.json')).is_file(), kind
record=json.loads((package/'data/domains/taxonomy-v1.example.json').read_text(encoding='utf-8'))
catalog=trace_gc.catalog.Catalog([record])
assert catalog.record(record['id'])==record
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
                  'example_taxonomy_loaded':True,'production_qualified':False}))
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
            # The wheel's code must come from target; pinned dependencies may be
            # installed in the invoking interpreter's user site on Windows.
            smoke_env=os.environ.copy()
            smoke_env.pop('PYTHONPATH',None)
            smoke_env.pop('PYTHONHOME',None)
            smoke=subprocess.run([sys.executable,'-c',SMOKE,str(target)],cwd=outside,
                                 env=smoke_env,text=True,capture_output=True,timeout=120,check=True)
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
