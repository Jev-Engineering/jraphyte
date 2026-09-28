#!/usr/bin/env python3
"""Generate the checked-in standalone 2020-12 runtime schemas; no remote refs."""
from __future__ import annotations
import json
from copy import deepcopy
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
S = {"type":"string", "minLength":1}
H = {"type":"string", "pattern":"^[0-9a-f]{64}$"}
N = {"type":"integer", "minimum":0}
B = {"type":"boolean"}
P = {"type":"number", "minimum":0, "maximum":1}
T = {"type":"string", "format":"date-time"}
MODE = {"enum":["SYNTHETIC","RECORDED","LIVE"]}
RISK = {"enum":[f"R{i}" for i in range(6)]}

def nullable(s): return {"anyOf":[s,{"type":"null"}]}
def arr(s=S, *, minimum=0, unique=False):
    x={"type":"array","items":deepcopy(s),"minItems":minimum}
    if unique: x["uniqueItems"]=True
    return x
IDS=arr(S,unique=True)
def mapping(s): return {"type":"object","additionalProperties":deepcopy(s)}
def obj(properties, optional=()):
    return {"type":"object","properties":deepcopy(properties),"required":[x for x in properties if x not in optional],"additionalProperties":False}
ASSERTION=obj({"subject":S,"predicate":S,"object":S,"qualifiers":mapping({"type":"string"})})
DEP=obj({"run_id":S,"pack_id":S,"question_id":S})
CRITERION=obj({"label":S,"description":{"type":"string"}})
QUESTION=obj({"id":S,"candidate_id":S,"task":{"enum":["SUPPORT","IDENTITY","EVIDENCE_QUALITY"]},
              "primitive":{"enum":["CHOICE","NOUL","SCORE"]},"instructions":S,
              "criteria":arr(CRITERION,minimum=2),"depends_on":arr(DEP,unique=True)})
SNAP=obj({"graph_version":N,"schema_hash":H})
SCOPE=obj({"task":S,"predicate":S,"population":S,"candidate_generator":S,"model_version":S,
           "question_program":S,"materializer_version":S,"packing_policy":S,"tokenizer_version":S,
           "resolver_version":S,"policy_version":S,"risk_class":RISK,"security_scope":S,
           "execution_mode":MODE})
RAW={"type":["object","null"]}
STATUS=obj({"active":B,"permission":{"enum":["READ","DENIED"]},"epoch":N,
            "updated_at":T,"tombstone":B})
RELATION=obj({"domain":S,"range":S,"symmetric":B,"inverse_of":nullable(S),
              "incompatible":IDS,"transitive":B,"allow_self":B})
SCHEMAS={}
SCHEMAS["record"]=obj({"id":S,"kind":{"enum":["source","claim","evidence","candidate","pack","observation","evaluation","resolution-batch","resolution","plan","qualification","receipt","transaction","schema","graph-snapshot","policy"]},"hash":H,"body":{"type":"object"}})
SCHEMAS["source"]=obj({"source_id":S,"version":S,"representation":S,"text":S,"text_hash":H,
                       "security_scope":S,"parser_version":S,"raw_document_hash":nullable(H)})
SCHEMAS["graph-snapshot"]=obj({"graph_version":N,"schema_id":S,"schema_hash":H,"nodes":mapping(S),
    "assertions":mapping(obj({"assertion":ASSERTION,"evidence_ids":IDS,"prerequisites":IDS,"active":B,"revision":N})),"source_epochs":mapping(N)})
SCHEMAS["claim"]=obj({"text":S,"language":S,"revision":{"type":"integer","minimum":1}})
SCHEMAS["evidence"]=obj({"source_snapshot_id":S,"source_hash":H,"start":N,"end":{"type":"integer","minimum":1},
                         "quote":S,"offset_unit":{"const":"UNICODE_CODEPOINT"},"transformation":{"const":"identity-v1"}})
SCHEMAS["candidate"]=obj({"run_id":S,"candidate_kind":{"enum":["ASSERTION","IDENTITY","RETRACTION","SCHEMA","METADATA"]},
                          "assertion":ASSERTION,"claim_id":S,"claim_hash":H,"evidence_ids":IDS,
                          "prerequisites":IDS,"alternatives":IDS,"generator_version":S,
                          "execution_mode":MODE,"revision":{"type":"integer","minimum":1}})
TRACE=obj({"path":S,"record_id":S,"record_hash":H,"locator":S,"transformation":{"enum":["identity-v1","collapse-whitespace-v1"]}})
CLOSURE=obj({"roots":IDS,"record_ids":IDS,"edges":arr(arr(S,minimum=2),unique=True),"evidence_ids":IDS,
             "source_snapshot_ids":IDS,"prior_observation_ids":IDS,"snapshot":SNAP,"omissions":arr(S),"hash":H})
SCHEMAS["pack"]=obj({"snapshot_id":S,"run_id":S,"execution_mode":MODE,"security_scope":S,"graph_version":N,"schema_hash":H,
                     "model_version":S,"program_version":S,"materializer_version":{"const":"materializer-v1"},
                     "packing_version":{"const":"complete-closure-v1"},"tokenizer_version":S,
                     "candidate_ids":arr(S,minimum=1,unique=True),"prior_observation_ids":IDS,"questions":arr(QUESTION,minimum=1),
                     "state":{"type":"object"},"closure":CLOSURE,"materialization":arr(TRACE,minimum=1),
                     "transformation":{"enum":["identity-v1","collapse-whitespace-v1"]},
                     "semantic_hash":H,"wire_request_hash":H,"cache_key":H,"request_base64":S,"created_at":T,
                     "budget":obj({"state_tokens":N,"question_tokens":mapping(N),"request_cap":{"type":"integer","minimum":1},
                                   "state_longest_cap":{"type":"integer","minimum":1},"measured":B})})
SCHEMAS["observation"]=obj({"run_id":S,"execution_mode":MODE,"security_scope":S,"pack_id":S,"pack_hash":H,
                            "question_id":S,"question_hash":H,"candidate_id":S,"candidate_hash":H,
                            "semantic_hash":H,"wire_request_hash":H,"wire_response_hash":H,"cache_key":H,
                            "adapter_version":{"const":"typesafe-http-v1"},"model_requested":S,"model_returned":nullable(S),
                            "status":{"enum":["OK","ERROR"]},"raw_answer":RAW,"probabilities":nullable(mapping(P)),
                            "raw_confidence":nullable(P),"semantic_outcome":nullable(S),"error":nullable(S),
                            "evidence_ids":IDS,"prior_observation_ids":IDS,"supersedes":nullable(S),
                            "created_at":T,"completed_at":T,
                            "wire":obj({"request_base64":S,"response_base64":{"type":"string"},"http_status":N,
                                        "response_headers":mapping({"type":"string"})})})
SCHEMAS["evaluation"]=obj({"candidate_id":S,"observation_ids":arr(S,minimum=1,unique=True),"resolution_batch_id":S,
                           "policy_version":S,"policy_id":S,"qualification_id":nullable(S),"context":SCOPE,
                           "outcome":{"enum":["ACCEPT","REJECT","ABSTAIN","HUMAN_REVIEW","RETRIEVE_MORE_EVIDENCE"]},
                           "score":nullable(P),"reason":S,"created_at":T})
PROBLEM=obj({"nodes":mapping(S),"existing_identity_pairs":arr(arr(S,minimum=2)),"cannot_links":arr(arr(S,minimum=2)),
             "exclusive_groups":arr(IDS),"weights":mapping({"type":"integer"}),"dependent_assertions":mapping(IDS)})
SCHEMAS["resolution-batch"]=obj({"run_id":S,"candidate_ids":IDS,"candidate_hashes":mapping(H),"observation_ids":IDS,
                                 "observation_hashes":mapping(H),"snapshot_id":S,"snapshot":SNAP,"problem":PROBLEM,
                                 "problem_hash":H,"solver_version":{"const":"exact-subset-v1"},
                                 "objective":{"const":"MAX_INTEGER_UTILITY_THEN_LEXICOGRAPHIC"},"status":{"enum":["OPTIMAL","INFEASIBLE","BUDGET_EXHAUSTED"]},
                                 "selected_ids":IDS,"expansions":N,"objective_value":nullable({"type":"integer"}),
                                 "impact":obj({"implied_equivalences":N,"affected_nodes":N,"dependent_assertions":N}),
                                 "created_at":T})
SCHEMAS["resolution"]=obj({"candidate_id":S,"batch_id":S,"outcome":{"enum":["SELECTED","NOT_SELECTED","UNRESOLVED"]},
                           "evidence_ids":IDS,"observation_ids":IDS,"risk_class":RISK})
SCHEMAS["schema"]=obj({"version":S,"relations":mapping(RELATION)})
SCHEMAS["policy"]=obj({"version":S,"mode":{"enum":["ANALYSIS_ONLY","REVIEWED","QUALIFIED"]},
    "security_scope":S,"population":S,"allowed_modes":arr(MODE,minimum=1,unique=True),
    "maximum_risk":RISK,"qualification_metric":{"const":"ERRORS_PER_ACCEPTED_ACTION"},
    "required_checks":arr(S,minimum=1,unique=True)})
COMMON={"id":S,"risk_class":RISK}
ADD={**COMMON,"candidate_id":S,"resolution_id":S,"evaluation_id":S,"evidence_ids":arr(S,minimum=1,unique=True),
     "prerequisite_ids":IDS,"assertion":ASSERTION,"assertion_id":S}
OP=[]
OP.append(obj({**ADD,"operation":{"const":"ADD_ASSERTION"}}))
OP.append(obj({**ADD,"operation":{"const":"ADD_IDENTITY_ASSERTION"},"component_certificate_id":S}))
OP.append(obj({**COMMON,"operation":{"const":"RETRACT_ASSERTION"},"assertion_id":S,"expected_revision":N,"reason":S}))
OP.append(obj({**COMMON,"operation":{"const":"ATTACH_CANDIDATE_METADATA"},"candidate_id":S,"metadata":{"type":"object"}}))
MIG={**COMMON,"target_schema_id":S,"mapping":mapping(S),"impact":obj({"before_schema_hash":H,"target_schema_hash":H,
     "affected_assertion_ids":IDS,"affected_node_ids":IDS}),"reason":S}
OP.append(obj({**MIG,"operation":{"const":"PROPOSE_SCHEMA_MIGRATION"}}))
OP.append(obj({**MIG,"operation":{"const":"APPLY_SCHEMA_MIGRATION"}}))
SCHEMAS["plan"]=obj({"snapshot_id":S,"run_id":S,"execution_mode":MODE,"security_scope":S,"graph_version":N,"schema_hash":H,
                     "idempotency_key":S,"operations":arr({"oneOf":OP},minimum=1),"source_epochs":mapping(N),
                     "source_hashes":mapping(H),"contexts":mapping(SCOPE),"policy_version":S,"policy_id":S,
                     "qualification_ids":IDS,"required_checks":arr(S,minimum=1,unique=True),"created_at":T})
SCHEMAS["qualification"]=obj({"scope":SCOPE,"metric":{"const":"ERRORS_PER_ACCEPTED_ACTION"},"threshold":P,
                              "risk_limit":P,"upper_risk_bound":P,"confidence":P,"minimum_coverage":P,
                              "measured_coverage":P,"n_eligible":N,"n_accepted":{"type":"integer","minimum":1},
                              "n_errors":N,"dataset_hash":H,"protocol_hash":H,"pipeline_hash":H,
                              "evaluation_unit":{"const":"INDEPENDENT_ACTION_GROUP"},"split":{"const":"LOCKED_HOLDOUT"},
                              "independent_labels":{"const":True},"created_at":T,"expires_at":T,
                              "drift_status":{"enum":["CLEAR","DETECTED","UNKNOWN"]}})
SCHEMAS["receipt"]=obj({"purpose":{"enum":["AUTHORIZATION","PREFLIGHT","QUALIFICATION","RUN_CHECKPOINT","SOURCE_STATUS","OBSERVATION"]},
                        "issuer":S,"issued_at":T,"expires_at":T,"payload":{"type":"object"},"signature":S})
SCHEMAS["transaction"]=obj({"backend":S,"version":N,"idempotency_key":S,"plan_hash":H,"before_hash":H,"after_hash":H,
                            "previous_hash":nullable(H),"event_hash":H,"operation_hash":H,"authorization_hash":H,
                            "preflight_hash":H,"upstream_head":nullable(H),"committed_at":T})
from retrieval_schemas import extend
extend(SCHEMAS)
from image_evidence_schemas import extend as extend_image_evidence
extend_image_evidence(SCHEMAS)
from paper_ingestion_schemas import extend as extend_paper_ingestion
extend_paper_ingestion(SCHEMAS)
from local_semantic_schemas import extend as extend_local_semantic
extend_local_semantic(SCHEMAS)

EVENT=obj({"id":S,"run_id":S,"execution_mode":MODE,"sequence":{"type":"integer","minimum":1},
           "stage":{"enum":["SOURCE","CLAIM","EVIDENCE","CANDIDATE","PACK","OBSERVATION","RESOLUTION","EVALUATION","QUALIFICATION","PLAN","RECEIPT","TRANSACTION","SCHEMA","SNAPSHOT","POLICY","RETRIEVAL"]},
           "created_at":T,"parent_ids":IDS,"previous_hash":nullable(H),"record_ids":arr(S,minimum=1,unique=True),
           "payload_hash":H,"hash":H})
MANIFEST=obj({"run_id":S,"execution_mode":MODE,"security_scope":S,"profile":{"enum":["PARTIAL_ANALYSIS","FINALIZED_ANALYSIS","FINALIZED_PUBLISHED","HISTORICAL_REPLAY"]},
              "graph_version":N,"schema_hash":H,"record_hashes":mapping(H),"source_status":mapping(STATUS),
              "record_events":mapping(S),"policy_version":S,"policy_id":S,"source_status_as_of":T,
              "ledger_head":nullable(H),"checkpoint_id":nullable(S),"transaction_id":nullable(S)})
SCHEMAS["bundle"]=obj({"format_version":{"const":"0.3.0"},"canonicalization":{"const":"TRACE-C14N-1"},
                       "manifest":MANIFEST,"records":arr(SCHEMAS["record"]),"ledger":arr(EVENT),"checkpoint":nullable(SCHEMAS["receipt"])})

def main():
    dest=ROOT/"schemas"/"runtime"; dest.mkdir(parents=True,exist_ok=True)
    for name,body in SCHEMAS.items():
        schema={"$schema":"https://json-schema.org/draft/2020-12/schema","$id":f"urn:trace-gc:0.3.0:{name}","title":f"TRACE-GC {name} v0.3.0",**body}
        (dest/f"{name}.schema.json").write_text(json.dumps(schema,indent=2)+"\n",encoding="utf-8",newline="\n")
    package=ROOT/"trace_gc"/"data"/"schemas";package.mkdir(parents=True,exist_ok=True)
    for path in dest.glob("*.schema.json"):(package/path.name).write_bytes(path.read_bytes())
    print(f"Wrote {len(SCHEMAS)} standalone runtime schemas and wheel resources")
if __name__=="__main__":main()
