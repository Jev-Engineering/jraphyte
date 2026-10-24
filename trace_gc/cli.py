"""Offline-first command line. There is deliberately no automatic publish command."""
from __future__ import annotations
import argparse
import base64
import json
import sys
from pathlib import Path
from typing import Any
from .canonical import canonical_bytes,digest,load,write
from .errors import ContractError,require
from .trust import TrustStore,IssuerPolicy


def read_trust(path: Path) -> TrustStore:
    """An administrator-selected trust file, never inferred from bundle contents."""
    value=load(path)
    require(isinstance(value,dict) and set(value)=={"issuers","revoked_issuers"},"TRUST_CONFIG","explicit issuer configuration required")
    trust=TrustStore()
    fields={"issuer","public_key_base64","principal","purposes","operations","scopes","modes","maximum_risk","can_review"}
    require(isinstance(value["issuers"],list) and isinstance(value["revoked_issuers"],list),"TRUST_CONFIG","issuer arrays required")
    for row in value["issuers"]:
        require(isinstance(row,dict) and set(row)==fields,"TRUST_CONFIG","incomplete issuer configuration")
        require(type(row["maximum_risk"]) is int and type(row["can_review"]) is bool,"TRUST_CONFIG","risk/review types")
        for field in ("purposes","operations","scopes","modes"):
            require(isinstance(row[field],list) and all(isinstance(x,str) and bool(x) for x in row[field]),"TRUST_CONFIG",field)
        try:key=base64.b64decode(row["public_key_base64"],validate=True)
        except (ValueError,TypeError) as exc:raise ContractError("TRUST_CONFIG","invalid public key encoding") from exc
        trust.enroll(row["issuer"],IssuerPolicy(key,row["principal"],frozenset(row["purposes"]),frozenset(row["operations"]),
            frozenset(row["scopes"]),frozenset(row["modes"]),row["maximum_risk"],row["can_review"]))
    for issuer in value["revoked_issuers"]:trust.revoke(issuer)
    return trust


def parser() -> argparse.ArgumentParser:
    p=argparse.ArgumentParser(prog="trace-gc",description=__doc__)
    p.add_argument("--version",action="version",version="TRACE-GC 0.4.0")
    sub=p.add_subparsers(dest="command",required=True)
    v=sub.add_parser("validate",help="Verify a runtime bundle; does not grant write authority")
    v.add_argument("bundle",type=Path);v.add_argument("--trust",type=Path);v.add_argument("--at")
    d=sub.add_parser("demo",help="Run the complete isolated synthetic lifecycle")
    d.add_argument("--output",type=Path,default=Path("trace-gc-demo"))
    gd=sub.add_parser("graphrag-demo",help="Run four isolated synthetic GraphRAG compilation/retrieval scenarios")
    gd.add_argument("--output",type=Path,default=Path("trace-gc-graphrag-demo"))
    gb=sub.add_parser("graphrag-benchmark",help="Run the synthetic retrieval/pipeline ablations; not a real-model accuracy evaluation")
    gb.add_argument("--output",type=Path,default=Path("trace-gc-graphrag-benchmark"))
    dw=sub.add_parser("domain-workload",help="Measure fabricated domain workloads in disposable reference stores; not a placement qualification")
    dw.add_argument("--output",type=Path,required=True)
    dw.add_argument("--repetitions",type=int,default=3)
    dw.add_argument("--workers",type=int,default=2)
    dc=sub.add_parser("domain-conformance",help="Run isolated signed reference classification conformance; not production qualification")
    dc.add_argument("--output",type=Path)
    c=sub.add_parser("canonical",help="Generate a TRACE-C14N-1 hash and byte vector")
    c.add_argument("input",type=Path)
    e=sub.add_parser("evaluate-labels",help="Calculate an UNSIGNED qualification artifact from independent labels")
    e.add_argument("labels",type=Path);e.add_argument("--scope",type=Path,required=True);e.add_argument("--protocol",type=Path,required=True)
    for arg in ("threshold","risk-limit","minimum-coverage","confidence"):e.add_argument("--"+arg,type=float,required=True)
    e.add_argument("--expires-at",required=True);e.add_argument("--output",type=Path,required=True)
    a=sub.add_parser("audit-sample",help="Select accepted actions for an independent random audit")
    a.add_argument("actions",type=Path);a.add_argument("--size",type=int,required=True);a.add_argument("--seed",type=int,required=True);a.add_argument("--output",type=Path,required=True)
    l=sub.add_parser("check-legacy",help="Test only an exact-pinned upstream core.py in temporary databases")
    l.add_argument("--core",type=Path,required=True);l.add_argument("--output",type=Path)
    r=sub.add_parser("replay-policy",help="Append an unsigned analysis-only policy branch without inference")
    r.add_argument("bundle",type=Path);r.add_argument("--policy",type=Path,required=True);r.add_argument("--output",type=Path,required=True)
    r.add_argument("--trust",type=Path);r.add_argument("--at")
    return p


def main(argv: list[str] | None=None) -> int:
    args=parser().parse_args(argv)
    try:
        if args.command=="validate":
            from .validation import validate_bundle
            result=validate_bundle(load(args.bundle),trust=read_trust(args.trust) if args.trust else None,at=args.at)
        elif args.command=="demo":
            from .demo import run_demo
            result=run_demo(args.output)
        elif args.command=="graphrag-demo":
            from .retrieval.scenarios import run_scenarios
            result=run_scenarios(args.output)
        elif args.command=="graphrag-benchmark":
            from .retrieval.benchmark import run_benchmark
            report=run_benchmark(args.output)
            result={k:report[k] for k in ("status","cases","runs","provider_calls","production_graph_writes","interpretation")}
            result["output"]=str(args.output)
        elif args.command=="domain-workload":
            from .retrieval.workloads import run_reference_domain_workload
            report=run_reference_domain_workload(args.output,repetitions=args.repetitions,workers=args.workers)
            result={k:report[k] for k in ("status","sample_count","query_latency_ms","publication_latency_ms","writes","placement_decision")}
            result["output"]=str(args.output)
        elif args.command=="domain-conformance":
            from .domain_conformance import run_domain_conformance
            result=run_domain_conformance(args.output)
        elif args.command=="canonical":
            value=load(args.input);result={"profile":"TRACE-C14N-1","sha256":digest(value),"bytes_hex":canonical_bytes(value).hex()}
        elif args.command=="evaluate-labels":
            from .qualification import evaluate_labels
            from .schema import validate
            artifact=evaluate_labels(load(args.labels),scope=load(args.scope),protocol=load(args.protocol),threshold=args.threshold,
                risk_limit=args.risk_limit,minimum_coverage=args.minimum_coverage,confidence=args.confidence,expires_at=args.expires_at)
            validate("qualification",artifact);write(args.output,artifact)
            result={"status":"UNSIGNED_REVIEW_REQUIRED","output":str(args.output),"authorization_granted":False,
                    "upper_risk_bound":artifact["upper_risk_bound"],"measured_coverage":artifact["measured_coverage"]}
        elif args.command=="audit-sample":
            from .qualification import audit_sample
            selected=audit_sample(load(args.actions),args.size,seed=args.seed);write(args.output,selected)
            result={"status":"PASS","sample_size":len(selected),"output":str(args.output)}
        elif args.command=="check-legacy":
            from .conformance import check_legacy
            result=check_legacy(args.core)
            if args.output:write(args.output,result)
        else:
            from .replay import replay_analysis_policy
            bundle=replay_analysis_policy(load(args.bundle),load(args.policy),trust=read_trust(args.trust) if args.trust else None,at=args.at);write(args.output,bundle)
            result={"status":"PASS","output":str(args.output),"profile":bundle["manifest"]["profile"],"model_calls":0,"authorization_granted":False}
        print(json.dumps(result,indent=2));return 0
    except ContractError as exc:
        print(json.dumps({"status":"FAIL",**exc.as_dict()}),file=sys.stderr);return 1
    except (OSError,ValueError,TypeError,KeyError) as exc:
        print(json.dumps({"status":"FAIL","code":"INPUT_ERROR","detail":str(exc)}),file=sys.stderr);return 1

if __name__=="__main__":raise SystemExit(main())
