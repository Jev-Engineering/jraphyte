#!/usr/bin/env python3
"""Execute and record offline tests/probes/demo. Never claim unexecuted gates passed."""
from __future__ import annotations
from pathlib import Path
from datetime import datetime,timezone
import importlib.metadata
import io
import json
import os
import platform
import subprocess
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/"tools"))
from trace_gc.canonical import canonical_bytes,digest,load,loads
from trace_gc.errors import ContractError
from trace_gc.demo import run_demo
from trace_gc.legacy import PINNED_CORE_BLOB
from validate_package import load_json,validate_bundle

class RecordedResult(unittest.TextTestResult):
    def __init__(self,*args,**kwargs):super().__init__(*args,**kwargs);self.records=[]
    def addSuccess(self,test):super().addSuccess(test);self.records.append({"test":test.id(),"status":"PASS"})
    def addFailure(self,test,err):super().addFailure(test,err);self.records.append({"test":test.id(),"status":"FAIL"})
    def addError(self,test,err):super().addError(test,err);self.records.append({"test":test.id(),"status":"ERROR"})
    def addSkip(self,test,reason):super().addSkip(test,reason);self.records.append({"test":test.id(),"status":"SKIPPED","reason":reason})

def vectors():
    payload=load(ROOT/"examples/runtime/canonical_vectors.json")
    for item in payload["valid"]:
        if digest(item["value"])!=item["sha256"] or canonical_bytes(item["value"]).hex()!=item["canonical_hex"]:
            raise AssertionError("canonical vector differs: "+item["name"])
    for item in payload["invalid_json"]:
        try:loads(item["text"])
        except ContractError as exc:
            if exc.code!=item["expected_code"]:raise
        else:raise AssertionError("invalid canonical input accepted")
    return {"status":"PASS","valid_vectors":len(payload["valid"]),"invalid_vectors":len(payload["invalid_json"])}

def main():
    stream=io.StringIO();checks={};overall=True
    suite=unittest.defaultTestLoader.discover(str(ROOT/"tests"))
    result=unittest.TextTestRunner(stream=stream,verbosity=2,resultclass=RecordedResult).run(suite)
    overall=result.wasSuccessful()
    try:checks["legacy_fixture"]=validate_bundle(load_json(ROOT/"examples/bundle.json"))
    except Exception as exc:checks["legacy_fixture"]={"status":"FAIL","error":str(exc)};overall=False
    try:checks["canonical_vectors"]=vectors()
    except Exception as exc:checks["canonical_vectors"]={"status":"FAIL","error":str(exc)};overall=False
    try:
        checks["schema_resource_copies"]={"status":"PASS","count":0}
        for file in (ROOT/"schemas/runtime").glob("*.schema.json"):
            if file.read_bytes()!=(ROOT/"trace_gc/data/schemas"/file.name).read_bytes():raise AssertionError(file.name)
            checks["schema_resource_copies"]["count"]+=1
    except Exception as exc:checks["schema_resource_copies"]={"status":"FAIL","error":str(exc)};overall=False
    probe=subprocess.run([sys.executable,str(ROOT/"review/reproduce_findings.py"),str(ROOT),"--output",str(ROOT/"review/probe_results_after.json")],capture_output=True,text=True,cwd=ROOT)
    stream.write("\n=== Original design-review probes ===\n"+probe.stdout+probe.stderr)
    try:
        if probe.returncode:raise AssertionError("probe harness exited nonzero")
        raw=json.loads((ROOT/"review/probe_results_after.json").read_text())
        rejected=sum(x["outcome"]=="REJECTED_BY_VALIDATOR" for x in raw["results"])
        checks["review_probes"]={"status":"PASS" if rejected==18 else "FAIL","total":len(raw["results"]),"rejected":rejected,
                               "accepted":sum(x["outcome"]=="ACCEPTED_BY_VALIDATOR" for x in raw["results"])}
        overall=overall and rejected==18
    except Exception as exc:checks["review_probes"]={"status":"FAIL","error":str(exc)};overall=False
    try:checks["isolated_demo"]=run_demo(ROOT/"examples/runtime")
    except Exception as exc:checks["isolated_demo"]={"status":"FAIL","error":str(exc)};overall=False
    try:
        from trace_gc.retrieval.scenarios import run_scenarios
        checks["graphrag_scenarios"]=run_scenarios(ROOT/"examples/graphrag/scenarios")
    except Exception as exc:checks["graphrag_scenarios"]={"status":"FAIL","error":str(exc)};overall=False
    try:
        from trace_gc.retrieval.benchmark import run_benchmark
        benchmark=run_benchmark(ROOT/"benchmarks/graphrag")
        checks["graphrag_benchmark"]={k:benchmark[k] for k in ("status","cases","runs","upstream_configurations","downstream_configurations","provider_calls","production_graph_writes","real_model_accuracy","heldout_production_results","interpretation")}
    except Exception as exc:checks["graphrag_benchmark"]={"status":"FAIL","error":str(exc)};overall=False
    try:
        from trace_gc.domain_conformance import run_domain_conformance
        checks["domain_classification_conformance"]=run_domain_conformance()
    except Exception as exc:checks["domain_classification_conformance"]={"status":"FAIL","error":str(exc)};overall=False
    external=bool(os.environ.get("TRACE_GC_LEGACY_CORE"))
    legacy_test=next((r for r in result.records if r["test"].endswith("test_pinned_upstream_conformance")),None)
    gates={"pinned_legacy":{"status":legacy_test["status"] if legacy_test else "NOT_RUN","expected_git_blob":PINNED_CORE_BLOB,
            "source_supplied":external,"command":"python tools/check_legacy.py --core /path/to/core.py --output legacy-conformance.json"},
           "live_provider":"NOT_RUN; mock transport only","production_calibration":"NOT_QUALIFIED; independent deployment labels absent",
           "controlled_pilot":"NOT_RUN","deployed_backend":"NOT_RUN",
           "trained_embedding_provider":"NOT_RUN; pinned offline hashing and supplied-vector adapters tested",
           "remote_graph_database_adapters":"NOT_RUN; SQLite and in-memory reference adapters tested",
           "real_graph_rag_accuracy":"NOT_ESTABLISHED; synthetic retrieval and controlled-oracle pipeline experiments only"}
    report={"created_at":datetime.now(timezone.utc).isoformat(),"release":"0.4.0","status":"PASS_WITH_EXTERNAL_GATES" if overall else "FAIL",
            "environment":{"python":platform.python_version(),"platform":platform.platform(),"jsonschema":importlib.metadata.version("jsonschema"),"cryptography":importlib.metadata.version("cryptography")},
            "tests_run":result.testsRun,"tests_passed":sum(x["status"]=="PASS" for x in result.records),"failures":len(result.failures),"errors":len(result.errors),
            "skipped":len(result.skipped),"tests":result.records,"checks":checks,"external_gates":gates,
            "test_groups":{"original_baseline":sum("test_graphrag_" not in x["test"] and "test_research_domain" not in x["test"] for x in result.records),"graphrag":sum("test_graphrag_" in x["test"] for x in result.records),"research_domain":sum("test_research_domain" in x["test"] for x in result.records)},
            "provider_calls":0,"production_graph_writes":0,"isolated_database_transactions":"Executed in temporary test databases; demo count is reported separately.",
            "claims_not_established":["production semantic accuracy","empirical production calibration","completed controlled pilot","live API acceptance","distributed deployment safety","paper novelty or measured performance improvement"]}
    (ROOT/"VALIDATION_REPORT.json").write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    (ROOT/"VALIDATION_LOG.txt").write_text(stream.getvalue()+"\n=== External gates ===\n"+json.dumps(gates,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({k:report[k] for k in ("status","tests_run","tests_passed","failures","errors","skipped","provider_calls","production_graph_writes")},indent=2))
    return 0 if overall else 1

if __name__=="__main__":raise SystemExit(main())
