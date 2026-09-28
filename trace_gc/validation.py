"""Versioned bundle validation: partial, complete analysis, publication and history."""
from __future__ import annotations
from typing import Any
from .canonical import digest,text_digest
from .catalog import Catalog
from .compiler import validate_pack,timestamp
from .adapter import validate_observation
from .constraints import validate_schema_contract,validate_graph
from .errors import boundary,require
from .ledger import references,validate_ledger
from .plans import validate_plan
from .references import topological_order,check_question_dependencies
from .resolver import verify_certificate,effective_risk
from .schema import validate
from .trust import TrustStore

@boundary
def validate_bundle(bundle: dict[str,Any], *, trust: TrustStore | None=None,at: str | None=None) -> dict[str,Any]:
    validate("bundle",bundle)
    m=bundle["manifest"];raw=bundle["records"]
    require(len(raw)==len({r["id"] for r in raw}),"DUPLICATE_ID","record IDs must be unique across all kinds")
    catalog=Catalog(raw)
    require(m["record_hashes"]=={r["id"]:r["hash"] for r in raw},"GRAPH_MANIFEST","manifest must enumerate exact record hashes")
    sources={r["id"] for r in catalog.all("source")}
    require(set(m["source_status"])==sources,"SOURCE_STATUS_MISSING","source status must enumerate all included snapshots")
    policy=catalog.get(m["policy_id"],"policy")
    require(policy["version"]==m["policy_version"] and policy["security_scope"]==m["security_scope"],"POLICY_BINDING","manifest policy differs")
    historical=m["profile"]=="HISTORICAL_REPLAY"
    packs=[];observations=[];obs_dependencies={};candidate_dependencies={}
    for r in raw:
        b=r["body"];kind=r["kind"]
        from .retrieval.integration import validate_record as validate_retrieval_record
        validate_retrieval_record(catalog, r)
        for ref,expected in references(r):catalog.record(ref,None if expected=="*" else expected)
        if "run_id" in b:require(b["run_id"]==m["run_id"],"MODE_MISMATCH","record from another run")
        if "execution_mode" in b:require(b["execution_mode"]==m["execution_mode"],"MODE_MISMATCH","record execution mode differs")
        if "security_scope" in b:require(b["security_scope"]==m["security_scope"],"SECURITY_SCOPE",r["id"])
        if kind=="source":
            require(text_digest(b["text"])==b["text_hash"],"PROVENANCE_MISMATCH","source text hash changed")
            from .pdf_image_evidence import verify_image_source
            verify_image_source(catalog, b)
        elif kind=="image-evidence-v1":
            from .pdf_image_evidence import validate_image_record
            validate_image_record(b)
        elif kind=="evidence":catalog.verify_evidence(r["id"])
        elif kind=="schema":validate_schema_contract(b["relations"])
        elif kind=="graph-snapshot":
            require(catalog.hash(b["schema_id"])==b["schema_hash"],"SCHEMA_HASH",r["id"])
            validate_graph(b["nodes"],b["assertions"],catalog.get(b["schema_id"],"schema")["relations"])
        elif kind=="candidate":
            require(catalog.hash(b["claim_id"])==b["claim_hash"],"CLAIM_BINDING",r["id"])
            if b["assertion"]["predicate"] in {"supports","refutes"}:
                require(b["assertion"]["object"]==b["claim_id"],"CLAIM_BINDING","support/refute object must be the immutable claim ID")
                require(all(catalog.get(catalog.get(ev,"evidence")["source_snapshot_id"],"source")["source_id"]==b["assertion"]["subject"] for ev in b["evidence_ids"]),"EVIDENCE_SUBJECT_BINDING","fixed document-to-claim task must cite that document's snapshots")
            if b["candidate_kind"]=="IDENTITY":require(b["assertion"]["predicate"]=="same_as","OPERATION_CANDIDATE_KIND",r["id"])
            candidate_dependencies[r["id"]]=b["prerequisites"]
        elif kind=="pack":packs.append({"id":r["id"],**b})
        elif kind=="observation":
            validate_observation(catalog,r["id"]);observations.append({"id":r["id"],**b})
            obs_dependencies[r["id"]]=b["prior_observation_ids"]+([b["supersedes"]] if b["supersedes"] else [])
        elif kind=="resolution-batch":
            verify_certificate(catalog,r["id"],b["snapshot_id"])
        elif kind=="resolution":
            batch=catalog.get(b["batch_id"],"resolution-batch");candidate=catalog.get(b["candidate_id"],"candidate")
            expected="UNRESOLVED" if batch["status"]!="OPTIMAL" else "SELECTED" if b["candidate_id"] in batch["selected_ids"] else "NOT_SELECTED"
            require(b["candidate_id"] in batch["candidate_ids"] and b["outcome"]==expected and b["evidence_ids"]==candidate["evidence_ids"],"RESOLUTION_BINDING",r["id"])
            operation="ADD_IDENTITY_ASSERTION" if candidate["candidate_kind"]=="IDENTITY" else "ADD_ASSERTION"
            require(b["risk_class"]==effective_risk(operation,batch),"RISK_UNDERCLASSIFIED",r["id"])
        elif kind=="evaluation":
            from .qualification import context_for
            evaluation_policy=catalog.get(b["policy_id"],"policy")
            require(b["policy_version"]==evaluation_policy["version"] and b["context"]["population"]==evaluation_policy["population"] and
                    evaluation_policy["security_scope"]==m["security_scope"],"POLICY_BINDING",r["id"])
            expected=context_for(catalog,b["candidate_id"],b["observation_ids"],b["resolution_batch_id"],population=b["context"]["population"],policy_version=b["policy_version"])
            require(b["context"]==expected,"POLICY_BINDING","evaluation context not derived from observations")
            if m["execution_mode"]=="SYNTHETIC":require(b["outcome"]!="ACCEPT","SYNTHETIC_PUBLICATION_FORBIDDEN","synthetic observations never auto-accept")
        elif kind=="plan":validate_plan(catalog,b,source_status=m["source_status"],historical=historical)
    topological_order(candidate_dependencies);topological_order(obs_dependencies)
    check_question_dependencies(packs,observations)
    for pack in packs:validate_pack(catalog,{k:v for k,v in pack.items() if k!="id"},source_status=m["source_status"],historical=historical)
    if m["profile"]=="FINALIZED_PUBLISHED":
        require(m["execution_mode"]!="SYNTHETIC","SYNTHETIC_PUBLICATION_FORBIDDEN","sandbox results are not published-run qualifications")
        require(m["transaction_id"] is not None,"TRANSACTION_RECEIPT_MISSING","published run needs the atomic journal receipt")
        tx=catalog.get(m["transaction_id"],"transaction")
        plans=[r for r in catalog.all("plan") if r["hash"]==tx["plan_hash"]]
        require(len(plans)==1,"TRANSACTION_PLAN_BINDING","transaction does not bind an included plan")
        receipts={digest(r["body"]):r["body"] for r in catalog.all("receipt")}
        require(tx["authorization_hash"] in receipts and tx["preflight_hash"] in receipts,"TRANSACTION_RECEIPT_MISSING","authorization/preflight lineage missing")
        require(tx["version"]==plans[0]["body"]["graph_version"]+1,"TRANSACTION_VERSION","transaction version differs")
        require(m["graph_version"]==tx["version"],"TRANSACTION_VERSION","published manifest is not the committed version")
        require(trust is not None,"CHECKPOINT_UNTRUSTED","published verification requires application trust")
        from .trust import verify_authorization
        from .plans import REQUIRED_CHECKS
        plan=plans[0]["body"]
        verify_authorization(trust,receipts[tx["authorization_hash"]],plan,plans[0]["hash"],at=tx["committed_at"])
        trusted_preflight=receipts[tx["preflight_hash"]]
        trust.verify(trusted_preflight,"PREFLIGHT",at=tx["committed_at"])
        require(trusted_preflight["payload"]["plan_hash"]==plans[0]["hash"] and
                trusted_preflight["payload"]["checks"]=={x:True for x in sorted(REQUIRED_CHECKS)},"PREFLIGHT_FAILED","published check receipt differs")
        require(tx["upstream_head"] is not None and tx["upstream_head"] in {e["hash"] for e in bundle["ledger"]},"LEDGER_BINDING","atomic journal's provenance anchor is absent")
        anchor_index=next(i for i,e in enumerate(bundle["ledger"]) if e["hash"]==tx["upstream_head"])
        transaction_index=next((i for i,e in enumerate(bundle["ledger"]) if m["transaction_id"] in e["record_ids"]),-1)
        require(transaction_index>anchor_index,"LEDGER_BINDING","commit must follow its bound provenance prefix")
    elif m["transaction_id"] is not None:catalog.get(m["transaction_id"],"transaction")
    lineage=validate_ledger(bundle,catalog,trust=trust,at=at)
    return {"status":"PASS","format_version":"0.3.0","profile":m["profile"],"record_count":len(raw),**lineage,
            "authorization_granted":False,"model_calls":0,"graph_commits":0,
            "scope":"Structural/provenance verification; publication requires the trusted service and current-state transaction rechecks."}
