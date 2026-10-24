#!/usr/bin/env python3
"""Inspect declared deployment prerequisites without executing a backend.

This is an input-readiness check, not a native adapter or an operational test.
Connection secrets, private keys and tokens must not be placed in this manifest.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

FIELDS=('backend_name','backend_version','deployment_owner','connection_reference',
    'source_authority_reference','trust_enrollment_reference','deployment_authorization_reference',
    'representative_workload_report_reference','isolation_requirements_reference','slo_reference',
    'backup_restore_runbook_reference','retention_policy_reference','pilot_approval_reference')
CHECKS=('commit_rollback_visibility','historical_snapshot_availability','current_source_revocation',
    'row_edge_acl_pushdown','domain_scope_shadow_parity','bounded_io_timeout_cancellation',
    'concurrent_reads_writes','backup_restore','migration_rollback','observability','retention',
    'workload_slos','independent_labels','controlled_pilot')


def check_inputs(document: dict) -> dict:
    if not isinstance(document,dict) or set(document)!={'version','inputs'} or document['version']!='domain-deployment-inputs-v1':
        raise ValueError('Expected the exact versioned deployment-input manifest')
    inputs=document['inputs']
    if not isinstance(inputs,dict) or set(inputs)!=set(FIELDS):
        raise ValueError('Only named references are allowed; do not include secrets or authority flags')
    if any(v is not None and (not isinstance(v,str) or not v.strip()) for v in inputs.values()):
        raise ValueError('Inputs must be a nonempty reference string or explicit null')
    missing=sorted(k for k in FIELDS if inputs[k] is None)
    return {'version':'domain-deployment-readiness-v1',
        'status':'BLOCKED' if missing else 'INPUTS_DECLARED_NOT_VERIFIED',
        'missing_inputs':missing,'declared_inputs':sorted(set(FIELDS)-set(missing)),
        'checks':{name:'NOT_RUN' for name in CHECKS},'production_qualified':False,
        'authorization_granted':False,'backend_executed':False,
        'scope':'Prerequisite declaration only. No deployment adapter, network call, write, SLO verification or trust enrollment was performed.'}


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    try:
        raw=args.manifest.read_bytes()
        if len(raw)>1024*1024:raise ValueError('Manifest exceeds 1 MiB')
        def exact_pairs(pairs):
            result={}
            for key,value in pairs:
                if key in result:raise ValueError('Duplicate JSON field')
                result[key]=value
            return result
        doc=json.loads(raw,object_pairs_hook=exact_pairs)
        report=check_inputs(doc);report['manifest_sha256']=hashlib.sha256(raw).hexdigest()
        code=2 if report['status']=='BLOCKED' else 0
    except (ValueError,OSError,UnicodeError) as exc:
        report={'status':'INVALID_INPUT','error':str(exc),'production_qualified':False,
                'authorization_granted':False,'backend_executed':False};code=1
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,indent=2));return code

if __name__=='__main__':raise SystemExit(main())
