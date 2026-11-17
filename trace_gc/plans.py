"""Typed immutable mutation plans and guarded append-only lifecycle transitions."""
from __future__ import annotations
from copy import deepcopy
from typing import Any
from .canonical import digest
from .catalog import Catalog
from .compiler import closure,now,validate_pack
from .adapter import validate_observation
from .constraints import validate_graph,add_candidates_to_facts,validate_schema_contract
from .errors import boundary,require
from .qualification import context_for
from .resolver import verify_certificate,effective_risk
from .schema import validate

REQUIRED_CHECKS=frozenset({"TYPED_RECORDS","EXACT_MATERIALIZATION","COMPLETE_CLOSURE","CAUSAL_DEPENDENCIES",
                         "GLOBAL_FEASIBILITY","CURRENT_SOURCE_STATUS","GRAPH_AND_SCHEMA_VERSION","EFFECTIVE_RISK",
                         "POLICY_APPLICABILITY","OBSERVATION_PROVENANCE"})
TRANSITIONS={
    "DRAFT":{"RESOLVED","ABSTAINED","REJECTED"},
    "RESOLVED":{"PREFLIGHT_VALIDATED","ABSTAINED","REJECTED"},
    "PREFLIGHT_VALIDATED":{"AUTHORIZED","REJECTED"},
    "AUTHORIZED":{"COMMIT_RECHECK","REJECTED"},
    "COMMIT_RECHECK":{"COMMITTED","REJECTED"},
    "COMMITTED":set(),"REJECTED":set(),"ABSTAINED":set(),
}

class Lifecycle:
    """Local projection only; the backend transaction receipt is publication authority."""
    def __init__(self, plan_hash: str):
        self.plan_hash=plan_hash;self.events:list[dict[str,Any]]=[]
    @property
    def state(self) -> str:return self.events[-1]["to"] if self.events else "DRAFT"
    def advance(self, target: str, *, receipt_hash: str | None = None, checks: dict[str,bool] | None = None,
                at: str | None = None) -> dict[str,Any]:
        require(target in TRANSITIONS.get(self.state,set()),"LIFECYCLE_TRANSITION",f"{self.state} -> {target}")
        if target=="PREFLIGHT_VALIDATED":
            require(checks is not None and set(checks)==REQUIRED_CHECKS and all(v is True for v in checks.values()),"PREFLIGHT_FAILED","all required implemented checks must pass")
        if target in {"PREFLIGHT_VALIDATED","AUTHORIZED","COMMITTED"}:
            require(isinstance(receipt_hash,str) and len(receipt_hash)==64,"LIFECYCLE_RECEIPT","trusted receipt reference required")
        event={"sequence":len(self.events)+1,"plan_hash":self.plan_hash,"from":self.state,"to":target,
               "receipt_hash":receipt_hash,"checks":deepcopy(checks),"created_at":at or now(),
               "previous_hash":self.events[-1]["hash"] if self.events else None}
        event["hash"]=digest(event);self.events.append(event);return deepcopy(event)

def required_sources(catalog: Catalog, operations: list[dict[str,Any]], snapshot_id: str) -> list[str]:
    candidates=[];prior=[];retrieved_sources=set()
    classification_sources={op["source_snapshot_id"] for op in operations if op["operation"]=="SET_SOURCE_CLASSIFICATION"}
    for op in operations:
        if op["operation"] in {"ADD_ASSERTION","ADD_IDENTITY_ASSERTION"}:
            candidates.append(op["candidate_id"])
            evaluation=catalog.get(op["evaluation_id"],"evaluation")
            for obs_id in evaluation["observation_ids"]:
                observation = catalog.get(obs_id,"observation")
                prior += observation["prior_observation_ids"]
                pack = catalog.get(observation["pack_id"], "pack")
                if "graph_context_ids" in pack:
                    retrieved_sources.update(pack["closure"]["source_snapshot_ids"])
    if not candidates:return sorted(classification_sources)
    return sorted(set(closure(catalog,sorted(set(candidates)),sorted(set(prior)),snapshot_id)["source_snapshot_ids"]) | retrieved_sources | classification_sources)

@boundary
def create_plan(catalog: Catalog, *, run_id: str, snapshot_id: str, operations: list[dict[str,Any]],
                security_scope: str, execution_mode: str, idempotency_key: str, policy_version: str,
                source_status: dict[str,Any], created_at: str | None = None) -> str:
    snapshot=catalog.get(snapshot_id,"graph-snapshot")
    refs=required_sources(catalog,operations,snapshot_id)
    require(set(refs)<=set(source_status),"SOURCE_STATUS_MISSING","plan required evidence")
    contexts={op["id"]:catalog.get(op["evaluation_id"],"evaluation")["context"] for op in operations if "evaluation_id" in op}
    qualifications=sorted({catalog.get(op["evaluation_id"],"evaluation")["qualification_id"] for op in operations
                           if "evaluation_id" in op and catalog.get(op["evaluation_id"],"evaluation")["qualification_id"] is not None})
    from .policy import find_policy
    body={"policy_id":find_policy(catalog,policy_version),"snapshot_id":snapshot_id,"run_id":run_id,"execution_mode":execution_mode,"security_scope":security_scope,
          "graph_version":snapshot["graph_version"],"schema_hash":snapshot["schema_hash"],"idempotency_key":idempotency_key,
          "operations":deepcopy(operations),"source_epochs":{ref:source_status[ref]["epoch"] for ref in refs},
          "source_hashes":{ref:catalog.hash(ref) for ref in refs},"contexts":contexts,"policy_version":policy_version,
          "qualification_ids":qualifications,"required_checks":sorted(REQUIRED_CHECKS),"created_at":created_at or now()}
    if "classifications" in snapshot:body["classification_revision"]=snapshot["classifications"]["revision"]
    validate_plan(catalog,body,source_status=source_status)
    return catalog.put("plan",body)

@boundary
def validate_plan(catalog: Catalog, plan: dict[str,Any], *, source_status: dict[str,Any] | None = None,
                  historical: bool = False) -> dict[str,Any]:
    validate("plan",plan)
    require(set(plan["required_checks"])==REQUIRED_CHECKS,"UNSUPPORTED_CAPABILITY","required check set cannot be weakened or silently extended")
    policy=catalog.get(plan["policy_id"],"policy")
    require(policy["version"]==plan["policy_version"] and policy["security_scope"]==plan["security_scope"] and
            plan["execution_mode"] in policy["allowed_modes"],"POLICY_BINDING","plan policy scope/version differs")
    require(set(policy["required_checks"])==REQUIRED_CHECKS,"UNSUPPORTED_CAPABILITY","policy cannot omit required checks")
    require(all(int(op["risk_class"][1:])<=int(policy["maximum_risk"][1:]) for op in plan["operations"]),"POLICY_RISK","policy risk ceiling")
    snapshot=catalog.get(plan["snapshot_id"],"graph-snapshot")
    require(plan["graph_version"]==snapshot["graph_version"] and plan["schema_hash"]==snapshot["schema_hash"],"STALE_GRAPH_VERSION","plan snapshot")
    require(plan.get("classification_revision")==snapshot.get("classifications",{}).get("revision"),"DOMAIN_REVISION","plan classification revision differs")
    require(catalog.hash(snapshot["schema_id"])==snapshot["schema_hash"],"SCHEMA_HASH","snapshot schema binding")
    ids=[op["id"] for op in plan["operations"]]
    require(len(ids)==len(set(ids)),"DUPLICATE_OPERATION_ID","operation IDs must be unique")
    expected_sources=required_sources(catalog,plan["operations"],plan["snapshot_id"])
    require(set(plan["source_epochs"])==set(expected_sources) and plan["source_hashes"]=={ref:catalog.hash(ref) for ref in expected_sources},"SOURCE_PRECONDITION","source closure differs")
    if source_status is not None and not historical:
        for ref in expected_sources:
            require(ref in source_status,"SOURCE_STATUS_MISSING",ref)
            status=source_status[ref]
            require(status["epoch"]==plan["source_epochs"][ref],"STALE_SOURCE_EPOCH",ref)
            require(status["active"] and status["permission"]=="READ" and not status["tombstone"],"STALE_EVIDENCE",ref)
    facts=deepcopy(snapshot["assertions"]);nodes=deepcopy(snapshot["nodes"])
    relations=deepcopy(catalog.get(snapshot["schema_id"],"schema")["relations"])
    from .domain_publication import apply_operations as apply_domain_operations, OPERATIONS as DOMAIN_OPERATIONS
    classification_projection=apply_domain_operations(catalog,snapshot,plan["operations"],security_scope=plan["security_scope"])
    expected_contexts={};qualifications=set();selected_by_batch:dict[str,set[str]]={};actual_by_batch:dict[str,set[str]]={}
    for op in plan["operations"]:
        operation=op["operation"]
        if operation in DOMAIN_OPERATIONS:
            continue
        if operation in {"ADD_ASSERTION","ADD_IDENTITY_ASSERTION"}:
            c=catalog.get(op["candidate_id"],"candidate")
            r=catalog.get(op["resolution_id"],"resolution");e=catalog.get(op["evaluation_id"],"evaluation")
            batch=catalog.get(r["batch_id"],"resolution-batch")
            require(c["run_id"]==plan["run_id"] and c["execution_mode"]==plan["execution_mode"],"MODE_MISMATCH",op["id"])
            require(catalog.hash(c["claim_id"])==c["claim_hash"],"CLAIM_BINDING",op["id"])
            if c["assertion"]["predicate"] in {"supports","refutes"}:
                require(c["assertion"]["object"]==c["claim_id"],"CLAIM_BINDING",op["id"])
                require(all(catalog.get(catalog.get(ev,"evidence")["source_snapshot_id"],"source")["source_id"]==c["assertion"]["subject"] for ev in c["evidence_ids"]),"EVIDENCE_SUBJECT_BINDING",op["id"])
            require(e["policy_id"]==plan["policy_id"],"POLICY_BINDING","evaluation policy differs")
            required_kind="IDENTITY" if operation=="ADD_IDENTITY_ASSERTION" else "ASSERTION"
            require(c["candidate_kind"]==required_kind,"OPERATION_CANDIDATE_KIND",op["id"])
            require((c["assertion"]["predicate"]=="same_as")== (operation=="ADD_IDENTITY_ASSERTION"),"OPERATION_PREDICATE",op["id"])
            require(op["assertion"]==c["assertion"] and op["assertion_id"]==op["candidate_id"] and
                    op["evidence_ids"]==c["evidence_ids"] and op["prerequisite_ids"]==c["prerequisites"],"CANDIDATE_BINDING",op["id"])
            require(r["candidate_id"]==e["candidate_id"]==op["candidate_id"] and e["resolution_batch_id"]==r["batch_id"],"RESOLUTION_BINDING",op["id"])
            require(r["outcome"]=="SELECTED" and batch["status"]=="OPTIMAL" and c is not None and op["candidate_id"] in batch["selected_ids"],"UNRESOLVED_PLAN",op["id"])
            verify_certificate(catalog,r["batch_id"],plan["snapshot_id"])
            require(r["evidence_ids"]==c["evidence_ids"] and r["observation_ids"]==[x for x in batch["observation_ids"] if catalog.get(x,"observation")["candidate_id"]==op["candidate_id"]],"RESOLUTION_BINDING","projection input mismatch")
            require(e["observation_ids"]==r["observation_ids"],"EVALUATION_BINDING","policy observation branch differs")
            require(op["risk_class"]==r["risk_class"]==e["context"]["risk_class"]==effective_risk(operation,batch),"RISK_UNDERCLASSIFIED","all risk projections must agree")
            if operation=="ADD_IDENTITY_ASSERTION":require(op["component_certificate_id"]==r["batch_id"],"COMPONENT_CERTIFICATE",op["id"])
            for obs in e["observation_ids"]:
                validate_observation(catalog,obs)
                observation=catalog.get(obs,"observation")
                require(observation["status"]=="OK","PREREQUISITE_NOT_COMPLETED",obs)
                pack=catalog.get(observation["pack_id"],"pack")
                validate_pack(catalog,pack,source_status=source_status,historical=historical)
                require(pack["snapshot_id"]==plan["snapshot_id"] and observation["security_scope"]==plan["security_scope"],"PREREQUISITE_SNAPSHOT",obs)
            expected=context_for(catalog,op["candidate_id"],e["observation_ids"],r["batch_id"],population=e["context"]["population"],policy_version=plan["policy_version"])
            require(e["context"]==expected and e["policy_version"]==plan["policy_version"],"POLICY_BINDING",op["id"])
            expected_contexts[op["id"]]=expected
            if e["qualification_id"] is not None:qualifications.add(e["qualification_id"])
            selected_by_batch[r["batch_id"]]=set(batch["selected_ids"])
            actual_by_batch.setdefault(r["batch_id"],set()).add(op["candidate_id"])
            require(op["assertion_id"] not in facts,"IMMUTABLE_ASSERTION",op["assertion_id"])
            facts[op["assertion_id"]]={"assertion":c["assertion"],"evidence_ids":c["evidence_ids"],"prerequisites":c["prerequisites"],"active":True,"revision":1}
        elif operation=="RETRACT_ASSERTION":
            require(op["risk_class"]=="R3","RISK_UNDERCLASSIFIED",op["id"])
            require(op["assertion_id"] in facts and facts[op["assertion_id"]]["revision"]==op["expected_revision"],"ASSERTION_REVISION",op["assertion_id"])
            deactivate(facts,{op["assertion_id"]})
        elif operation=="ATTACH_CANDIDATE_METADATA":
            c=catalog.get(op["candidate_id"],"candidate")
            require(c["run_id"]==plan["run_id"] and c["execution_mode"]==plan["execution_mode"],"MODE_MISMATCH",op["id"])
            require(op["risk_class"]=="R1","RISK_UNDERCLASSIFIED",op["id"])
        else:
            require(op["risk_class"]=="R5","RISK_UNDERCLASSIFIED",op["id"])
            target=catalog.get(op["target_schema_id"],"schema")
            validate_schema_contract(target["relations"])
            require(set(op["mapping"])<=set(nodes),"SCHEMA_MAPPING","only explicit existing-node type changes allowed")
            affected=sorted(ref for ref,fact in facts.items() if fact["active"] and
                            (fact["assertion"]["subject"] in op["mapping"] or fact["assertion"]["object"] in op["mapping"] or
                             relations.get(fact["assertion"]["predicate"])!=target["relations"].get(fact["assertion"]["predicate"])))
            expected={"before_schema_hash":plan["schema_hash"],"target_schema_hash":catalog.hash(op["target_schema_id"]),
                      "affected_assertion_ids":affected,"affected_node_ids":sorted(op["mapping"])}
            require(op["impact"]==expected,"SCHEMA_IMPACT","reviewed impact must enumerate affected content")
            if operation=="APPLY_SCHEMA_MIGRATION":nodes.update(op["mapping"]);relations=deepcopy(target["relations"])
    # Publish a joint result atomically, never a cherry-picked partial identity component.
    for batch_id,selected in selected_by_batch.items():
        require(actual_by_batch[batch_id]==selected,"PARTIAL_RESOLUTION_PUBLICATION","plan must contain the complete selected batch")
    require(plan["contexts"]==expected_contexts and set(plan["qualification_ids"])==qualifications,"POLICY_BINDING","plan qualification/context projection differs")
    validate_graph(nodes,facts,relations)
    result={"nodes":nodes,"assertions":facts,"relations":relations}
    if classification_projection is not None:result["classifications"]=classification_projection
    return result

def deactivate(facts: dict[str,Any], roots: set[str]) -> set[str]:
    from collections import deque
    children={ref:set() for ref in facts}
    for ref,fact in facts.items():
        for parent in fact["prerequisites"]:
            if parent in children:children[parent].add(ref)
    queue=deque(roots);removed=set(roots)
    while queue:
        for child in children[queue.popleft()]:
            if child not in removed:removed.add(child);queue.append(child)
    for ref in removed:
        if facts[ref]["active"]:facts[ref]["active"]=False;facts[ref]["revision"]+=1
    return removed

def add_operation(catalog: Catalog, resolution_id: str, evaluation_id: str, *, operation_id: str) -> dict[str,Any]:
    r=catalog.get(resolution_id,"resolution");c=catalog.get(r["candidate_id"],"candidate")
    op={"id":operation_id,"operation":"ADD_IDENTITY_ASSERTION" if c["candidate_kind"]=="IDENTITY" else "ADD_ASSERTION",
        "candidate_id":r["candidate_id"],"resolution_id":resolution_id,"evaluation_id":evaluation_id,
        "evidence_ids":c["evidence_ids"],"prerequisite_ids":c["prerequisites"],"risk_class":r["risk_class"],
        "assertion":c["assertion"],"assertion_id":r["candidate_id"]}
    if c["candidate_kind"]=="IDENTITY":op["component_certificate_id"]=r["batch_id"]
    return op
