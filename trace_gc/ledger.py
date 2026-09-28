"""Complete-run lineage and optional externally authenticated checkpoints.

A hash chain detects inconsistency, not origin authenticity. The checkpoint
lives outside the hashed manifest/ledger to avoid recursive self-hashing.
"""
from __future__ import annotations
from copy import deepcopy
from typing import Any
from .canonical import digest
from .catalog import Catalog
from .compiler import now,timestamp
from .errors import require
from .trust import Signer,TrustStore

STAGES={"source":"SOURCE","claim":"CLAIM","evidence":"EVIDENCE","candidate":"CANDIDATE","pack":"PACK",
        "observation":"OBSERVATION","evaluation":"EVALUATION","resolution-batch":"RESOLUTION","resolution":"RESOLUTION",
        "plan":"PLAN","qualification":"QUALIFICATION","receipt":"RECEIPT","transaction":"TRANSACTION","schema":"SCHEMA","graph-snapshot":"SNAPSHOT","policy":"POLICY"}

from .retrieval.contracts import KINDS as RETRIEVAL_KINDS
STAGES.update({kind: "RETRIEVAL" for kind in RETRIEVAL_KINDS})
STAGES["image-evidence-v1"] = "SOURCE"

def references(record: dict[str,Any]) -> list[tuple[str,str]]:
    """Every record-ID-bearing field is enumerated; hashes are validated separately."""
    b=record["body"];kind=record["kind"];refs=[]
    def add(values,expected):refs.extend((v,expected) for v in values)
    if kind=="source" and "image_evidence_id" in b:add([b["image_evidence_id"]],"image-evidence-v1")
    elif kind=="evidence":add([b["source_snapshot_id"]],"source")
    elif kind=="candidate":
        add([b["claim_id"]],"claim");add(b["evidence_ids"],"evidence")
        add(b["prerequisites"]+b["alternatives"],"candidate")
    elif kind=="graph-snapshot":
        add([b["schema_id"]],"schema");add(b["source_epochs"],"source")
        for fact in b["assertions"].values():add(fact["evidence_ids"],"evidence")
    elif kind=="pack":
        add([b["snapshot_id"]],"graph-snapshot");add(b["candidate_ids"],"candidate");add(b["prior_observation_ids"],"observation")
        for q in b["questions"]:
            add([q["candidate_id"]],"candidate")
            add([dep["pack_id"] for dep in q["depends_on"]],"pack")
        for ref in b["materialization"]:add([ref["record_id"]],"*")
        add(b["closure"]["record_ids"],"*")
    elif kind=="observation":
        add([b["pack_id"]],"pack");add([b["candidate_id"]],"candidate");add(b["evidence_ids"],"evidence")
        add(b["prior_observation_ids"],"observation")
        if b["supersedes"] is not None:add([b["supersedes"]],"observation")
    elif kind=="evaluation":
        add([b["policy_id"]],"policy")
        add([b["candidate_id"]],"candidate");add(b["observation_ids"],"observation");add([b["resolution_batch_id"]],"resolution-batch")
        if b["qualification_id"] is not None:add([b["qualification_id"]],"qualification")
    elif kind=="resolution-batch":add([b["snapshot_id"]],"graph-snapshot");add(b["candidate_ids"],"candidate");add(b["observation_ids"],"observation")
    elif kind=="resolution":
        add([b["candidate_id"]],"candidate");add([b["batch_id"]],"resolution-batch");add(b["evidence_ids"],"evidence");add(b["observation_ids"],"observation")
    elif kind=="plan":
        add([b["policy_id"]],"policy")
        add([b["snapshot_id"]],"graph-snapshot");add(b["source_hashes"],"source");add(b["qualification_ids"],"qualification")
        for op in b["operations"]:
            for field,expected in (("candidate_id","candidate"),("resolution_id","resolution"),("evaluation_id","evaluation"),
                                   ("component_certificate_id","resolution-batch"),("target_schema_id","schema")):
                if field in op:add([op[field]],expected)
            if "evidence_ids" in op:add(op["evidence_ids"],"evidence")
    from .retrieval.integration import references as retrieval_references
    refs.extend(retrieval_references(kind, b))
    return list(dict.fromkeys(refs))

def causal_references(record: dict[str,Any], catalog: Catalog | None=None) -> set[str]:
    refs={ref for ref,_ in references(record)}
    kind,b=record["kind"],record["body"]
    if kind=="candidate":refs-=set(b["alternatives"])
    if catalog is not None:
        hashes={r["hash"]:r["id"] for r in catalog.all()}
        receipts={digest(r["body"]):r["id"] for r in catalog.all("receipt")}
        if kind=="receipt":
            p=b["payload"]
            field={"AUTHORIZATION":"plan_hash","PREFLIGHT":"plan_hash","QUALIFICATION":"qualification_hash","OBSERVATION":"observation_hash"}.get(b["purpose"])
            if field:
                require(field in p and p[field] in hashes,"MISSING_REFERENCE","receipt's bound record is absent")
                refs.add(hashes[p[field]])
            if b["purpose"]=="SOURCE_STATUS":
                refs.update(p.get("source_hashes",{}))
                if "source_id" in p:refs.add(p["source_id"])
        elif kind=="transaction":
            if b["plan_hash"] in hashes:refs.add(hashes[b["plan_hash"]])
            for h in (b["authorization_hash"],b["preflight_hash"]):
                if h in receipts:refs.add(receipts[h])
            earlier=[r["id"] for r in catalog.all("transaction") if r["body"]["event_hash"]==b["previous_hash"]]
            if b["previous_hash"] is not None:
                require(len(earlier)==1,"TRANSACTION_CHAIN","prior atomic transaction receipt missing")
                refs.update(earlier)
    return refs

def build_ledger(catalog: Catalog, *, run_id: str, execution_mode: str, created_at: str | None = None,
                 prefix: list[dict[str,Any]] | None = None) -> list[dict[str,Any]]:
    from .references import topological_order
    records={r["id"]:r for r in catalog.all()}
    dependencies={ref:causal_references(record,catalog) for ref,record in records.items()}
    events=deepcopy(prefix or []);record_events={};previous=None;seen=set()
    for i,e in enumerate(events,1):
        require(e["sequence"]==i and e["previous_hash"]==previous and e["id"] not in seen,"LEDGER_CHAIN","invalid append prefix")
        require(e["run_id"]==run_id and e["execution_mode"]==execution_mode,"MODE_MISMATCH","prefix scope differs")
        require(e["hash"]==digest({k:v for k,v in e.items() if k!="hash"}),"LEDGER_HASH","prefix hash differs")
        require(e["payload_hash"]==digest([records[x] for x in e["record_ids"]]),"LEDGER_PAYLOAD","prefix record bytes changed")
        for ref in e["record_ids"]:
            require(ref not in record_events and dependencies[ref]<=record_events.keys(),"LEDGER_CAUSAL_ORDER","prefix prerequisite missing")
            require({record_events[x] for x in dependencies[ref]}<=set(e["parent_ids"]),"LEDGER_CAUSAL_ORDER","prefix parent missing")
            record_events[ref]=e["id"]
        seen.add(e["id"]);previous=e["hash"]
    remaining={ref:deps-record_events.keys() for ref,deps in dependencies.items() if ref not in record_events}
    order=topological_order(remaining)
    for ref in order:
        record=records[ref];body=record["body"]
        stamp=body.get("completed_at",body.get("created_at",body.get("committed_at",body.get("issued_at",created_at or now()))))
        event={"id":f"{run_id}:event:{len(events)+1}","run_id":run_id,"execution_mode":execution_mode,"sequence":len(events)+1,
               "stage":STAGES[record["kind"]],"created_at":stamp,"parent_ids":sorted(record_events[x] for x in dependencies[ref]),
               "previous_hash":previous,"record_ids":[ref],"payload_hash":digest([record])}
        event["hash"]=digest(event);events.append(event);previous=event["hash"];record_events[ref]=event["id"]
    return events

def manifest_hash(manifest: dict[str,Any]) -> str:
    return digest({k:v for k,v in manifest.items() if k!="checkpoint_id"})

def make_bundle(catalog: Catalog, *, run_id: str,execution_mode: str,security_scope: str,graph_version: int,schema_hash: str,
                source_status: dict[str,Any],policy_version: str,profile: str="FINALIZED_ANALYSIS",
                transaction_id: str | None=None,signer: Signer | None=None,created_at: str | None=None,
                ledger_prefix: list[dict[str,Any]] | None=None) -> dict[str,Any]:
    from .policy import find_policy
    events=[] if profile=="PARTIAL_ANALYSIS" else build_ledger(catalog,run_id=run_id,execution_mode=execution_mode,created_at=created_at,prefix=ledger_prefix)
    manifest={"run_id":run_id,"execution_mode":execution_mode,"security_scope":security_scope,"profile":profile,
              "graph_version":graph_version,"schema_hash":schema_hash,"record_hashes":{r["id"]:r["hash"] for r in catalog.all()},
              "source_status":deepcopy(source_status),"record_events":{ref:e["id"] for e in events for ref in e["record_ids"]},
              "policy_version":policy_version,"policy_id":find_policy(catalog,policy_version),"source_status_as_of":created_at or now(),"ledger_head":events[-1]["hash"] if events else None,
              "checkpoint_id":None,"transaction_id":transaction_id}
    bundle={"format_version":"0.3.0","canonicalization":"TRACE-C14N-1","manifest":manifest,"records":catalog.all(),"ledger":events,"checkpoint":None}
    if signer:
        checkpoint=signer.issue("RUN_CHECKPOINT",{"manifest_hash":manifest_hash(manifest),"ledger_head":manifest["ledger_head"],
                                 "run_id":run_id,"security_scope":security_scope,"execution_mode":execution_mode},issued_at=created_at)
        manifest["checkpoint_id"]=digest(checkpoint);bundle["checkpoint"]=checkpoint
    return bundle

def validate_ledger(bundle: dict[str,Any],catalog: Catalog, *, trust: TrustStore | None=None,at: str | None=None) -> dict[str,Any]:
    m=bundle["manifest"];events=bundle["ledger"];seen=set();covered={};previous=None
    records={r["id"]:r for r in catalog.all()}
    for i,e in enumerate(events,1):
        require(e["sequence"]==i and e["previous_hash"]==previous and e["id"] not in seen,"LEDGER_CHAIN","sequence/head/identity mismatch")
        require(e["run_id"]==m["run_id"] and e["execution_mode"]==m["execution_mode"],"MODE_MISMATCH","ledger run or mode differs")
        require(set(e["parent_ids"])<=seen,"LEDGER_CAUSAL_ORDER","parent must precede event")
        require(all(ref in records for ref in e["record_ids"]),"MISSING_REFERENCE","ledger payload missing")
        for ref in e["record_ids"]:
            require(ref not in covered,"LEDGER_DUPLICATE_PAYLOAD",ref)
            require(e["stage"]==STAGES[records[ref]["kind"]],"LEDGER_STAGE",ref)
            required=causal_references(records[ref],catalog)
            require(required<=covered.keys(),"LEDGER_CAUSAL_ORDER",ref)
            require({covered[x] for x in required}<=set(e["parent_ids"]),"LEDGER_CAUSAL_ORDER","required parent omitted")
        require(e["payload_hash"]==digest([records[ref] for ref in e["record_ids"]]),"LEDGER_PAYLOAD","payload differs")
        require(e["hash"]==digest({k:v for k,v in e.items() if k!="hash"}),"LEDGER_HASH","event content differs")
        seen.add(e["id"]);previous=e["hash"]
        covered.update({ref:e["id"] for ref in e["record_ids"]})
    require(m["ledger_head"]==previous and m["record_events"]==covered,"LEDGER_MANIFEST","head/coverage projection differs")
    finalized=m["profile"]!="PARTIAL_ANALYSIS"
    if finalized:require(bool(events) and set(covered)==set(records),"LEDGER_COVERAGE","finalized run must cover all records, including sources and qualification inputs")
    checkpoint=bundle["checkpoint"];authenticated=False
    if checkpoint is not None:
        require(m["checkpoint_id"]==digest(checkpoint),"CHECKPOINT_BINDING","checkpoint ID differs")
        expected={"manifest_hash":manifest_hash(m),"ledger_head":m["ledger_head"],"run_id":m["run_id"],
                  "security_scope":m["security_scope"],"execution_mode":m["execution_mode"]}
        require(checkpoint["payload"]==expected,"CHECKPOINT_BINDING","manifest/checkpoint differs")
        if trust is not None:trust.verify(checkpoint,"RUN_CHECKPOINT",at=at);authenticated=True
    else:require(m["checkpoint_id"] is None,"CHECKPOINT_BINDING","missing checkpoint")
    if m["profile"]=="FINALIZED_PUBLISHED":require(authenticated,"CHECKPOINT_UNTRUSTED","published replay requires an external enrolled trust store")
    return {"lineage_complete":finalized,"checkpoint_authenticated":authenticated,"events":len(events)}
