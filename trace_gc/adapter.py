"""TypeSafe HTTP lowering, exact wire receipts, and error-preserving observations.

No network activity at import. Live calls require an explicit capability flag,
an API key supplied by the embedding application, current source status, a
shared run budget, a pinned model, and a measured tokenizer-bound pack.
"""
from __future__ import annotations
import base64
import math
import time
import urllib.error
import urllib.request
from copy import deepcopy
from typing import Any, Callable
from .canonical import bytes_digest, digest, loads
from .catalog import Catalog
from .compiler import now, timestamp, validate_pack
from .errors import ContractError, boundary, require
from .budget import RunBudget

ENDPOINT = "https://api.typesafe.ai/v1/systemone"
ADAPTER = "typesafe-http-v1"
MAX_RESPONSE = 16*1024*1024

def probability(value: Any) -> None:
    require(type(value) in (int,float) and math.isfinite(value) and 0 <= value <= 1,
            "MALFORMED_DISTRIBUTION","finite nonboolean probability required")

def parse_answer(question: dict[str,Any], answer: Any) -> tuple[dict[str,float],float|None,str|None]:
    require(isinstance(answer,dict),"MALFORMED_ANSWER","object required")
    primitive=question["primitive"]
    require(answer.get("type") == primitive.lower(),"PRIMITIVE_MISMATCH",question["id"])
    labels = [x["label"] for x in question["criteria"]]
    if primitive == "NOUL":
        require(set(answer)=={"type","noul"},"NOUL_CONTRACT","Noul has no separate raw confidence")
        probability(answer["noul"])
        return {"YES":answer["noul"],"NO":1-answer["noul"]},None,None
    expected={"type","probabilities","confidence","choice"} if primitive=="CHOICE" else {"type","probabilities","confidence","score","legend"}
    require(set(answer)==expected,"MALFORMED_ANSWER","missing or unknown response fields")
    values=answer["probabilities"]
    require(isinstance(values,dict) and set(values)==set(labels),"DISTRIBUTION_LABELS",question["id"])
    for p in values.values():probability(p)
    total=sum(values.values())
    # The live Choice endpoint sometimes returns each option rounded to two
    # decimal places. Three independently rounded options can sum to 0.99 or
    # 1.01. Accept only that quantization envelope; preserve the raw values.
    two_decimal_choice=(primitive=="CHOICE" and
                        all(math.isclose(p,round(p,2),abs_tol=1e-9,rel_tol=0)
                            for p in values.values()))
    tolerance=min(0.005*len(values)+1e-9,0.02) if two_decimal_choice else 1e-6
    require(math.isclose(total,1,abs_tol=tolerance,rel_tol=0),
            "MALFORMED_DISTRIBUTION","probabilities outside reported precision; no renormalization")
    probability(answer["confidence"])
    if primitive=="CHOICE":
        selected=answer["choice"]
        # Independently rounded displayed options can invert a near tie by
        # one hundredth even when the service chose from unrounded values.
        displayed_gap=(max(values.values())-values[selected]
                       if selected in values else math.inf)
        require(selected in values and (displayed_gap<=1e-9 or
                (two_decimal_choice and displayed_gap<=0.01+1e-9)),
                "CHOICE_OUTCOME_MISMATCH","chosen label outside reported precision of maximum")
        return deepcopy(values),answer["confidence"],selected
    expected_legend={x["label"]:x["description"] for x in question["criteria"]}
    require(answer["legend"]==expected_legend,"RUBRIC_MISMATCH","returned level meanings differ")
    require(type(answer["score"]) in (int,float) and math.isfinite(answer["score"]),"SCORE_MEAN_MISMATCH","finite expected value required")
    mean=sum(int(label)*value for label,value in values.items())
    require(math.isclose(answer["score"],mean,abs_tol=1e-6,rel_tol=0),"SCORE_MEAN_MISMATCH","expected value differs")
    return deepcopy(values),answer["confidence"],None

@boundary
def record_response(catalog: Catalog, pack_id: str, response: bytes, *, http_status: int = 200,
                    response_headers: dict[str,str] | None = None, completed_at: str | None = None,
                    supersedes: dict[str,str] | None = None, transport_error: str | None = None,
                    local_execution: dict | None = None) -> list[str]:
    pack=catalog.get(pack_id,"pack"); validate_pack(catalog,pack)
    if "model_profile" in pack:
        require(local_execution is not None and http_status == 200 and not response_headers and
                supersedes is None and transport_error is None and
                (completed_at is None or completed_at == local_execution["completed_at"]),
                "LOCAL_SEMANTIC_TRANSPORT", "local execution evidence required; HTTP/retry metadata forbidden")
        from .local_semantics import record_local_response
        return record_local_response(catalog, pack_id, response, execution=local_execution)
    require(local_execution is None, "LOCAL_SEMANTIC_TRANSPORT", "local execution cannot be imported as TypeSafe HTTP")
    require(len(response) <= MAX_RESPONSE,"RESPONSE_TOO_LARGE","receipt byte limit exceeded")
    when=completed_at or now()
    require(timestamp(when)>=timestamp(pack["created_at"]),"TEMPORAL_ORDER","response before request")
    parsed,error=None,transport_error
    if error is None:
        try:
            parsed=loads(response)
            require(http_status==200,"HTTP_ERROR",str(http_status))
            require(isinstance(parsed,dict) and set(parsed)=={"model","answers","usage"},"MALFORMED_RESPONSE","unexpected envelope")
            require(parsed["model"]==pack["model_version"],"MODEL_VERSION_MISMATCH","returned model differs")
            require(isinstance(parsed["answers"],dict) and set(parsed["answers"])=={q["id"] for q in pack["questions"]},
                    "ANSWER_COVERAGE","response question IDs differ")
            usage=parsed["usage"]
            require(isinstance(usage,dict) and set(usage)=={"input_tokens","output_tokens"} and
                    all(type(x) is int and x>=0 for x in usage.values()),"MALFORMED_USAGE","invalid token usage")
        except ContractError as exc:error=str(exc)
    ids=[]
    for question in pack["questions"]:
        candidate=catalog.get(question["candidate_id"],"candidate")
        raw=None
        if isinstance(parsed,dict) and isinstance(parsed.get("answers"),dict):raw=parsed["answers"].get(question["id"])
        issue=error; values=confidence=outcome=None
        if issue is None:
            try:values,confidence,outcome=parse_answer(question,raw)
            except (ContractError,TypeError,KeyError) as exc:issue=str(exc)
        # Raw observations are never rewritten to match the desired rubric.
        safe_headers={k.lower():v for k,v in (response_headers or {}).items()
                      if k.lower() in {"x-request-id","request-id","retry-after","content-type"}}
        obs={"run_id":pack["run_id"],"execution_mode":pack["execution_mode"],"security_scope":pack["security_scope"],
             "pack_id":pack_id,"pack_hash":catalog.hash(pack_id),"question_id":question["id"],"question_hash":digest(question),
             "candidate_id":question["candidate_id"],"candidate_hash":catalog.hash(question["candidate_id"]),
             "semantic_hash":pack["semantic_hash"],"wire_request_hash":pack["wire_request_hash"],
             "wire_response_hash":bytes_digest(response),"cache_key":pack["cache_key"],"adapter_version":ADAPTER,
             "model_requested":pack["model_version"],"model_returned":parsed.get("model") if isinstance(parsed,dict) and isinstance(parsed.get("model"),str) else None,
             "status":"ERROR" if issue else "OK","raw_answer":raw if isinstance(raw,dict) else None,
             "probabilities":values,"raw_confidence":confidence,"semantic_outcome":outcome,"error":issue,
             "evidence_ids":candidate["evidence_ids"],"prior_observation_ids":pack["prior_observation_ids"],
             "supersedes":(supersedes or {}).get(question["id"]),"created_at":pack["created_at"],"completed_at":when,
             "wire":{"request_base64":pack["request_base64"],"response_base64":base64.b64encode(response).decode(),
                     "http_status":http_status,"response_headers":safe_headers}}
        from .retrieval.integration import LINEAGE_FIELDS
        obs.update({field: deepcopy(pack[field]) for field in LINEAGE_FIELDS if field in pack})
        ids.append(catalog.put("observation",obs))
    return ids

@boundary
def validate_observation(catalog: Catalog, observation_id: str) -> None:
    o=catalog.get(observation_id,"observation"); p=catalog.get(o["pack_id"],"pack")
    if o["adapter_version"] == "local-qwen-semantic-v1":
        from .local_semantics import validate_local_observation
        return validate_local_observation(catalog, observation_id)
    require("model_profile" not in p and o["adapter_version"] == ADAPTER,
            "LOCAL_SEMANTIC_TRANSPORT", "adapter identity differs from compiled profile")
    from .retrieval.integration import validate_observation_lineage
    validate_observation_lineage(o, p)
    q=next((q for q in p["questions"] if q["id"]==o["question_id"]),None)
    require(q is not None,"MISSING_REFERENCE","observation question")
    require(o["candidate_id"]==q["candidate_id"] and o["candidate_hash"]==catalog.hash(o["candidate_id"]),"CANDIDATE_BINDING",observation_id)
    require(o["pack_hash"]==catalog.hash(o["pack_id"]) and o["question_hash"]==digest(q),"REQUEST_BINDING",observation_id)
    require(o["evidence_ids"]==catalog.get(o["candidate_id"],"candidate")["evidence_ids"],"MISSING_EVIDENCE","observation evidence contract differs")
    require(o["prior_observation_ids"]==p["prior_observation_ids"],"PREREQUISITE_BINDING",observation_id)
    for field in ("execution_mode","run_id","security_scope","semantic_hash","wire_request_hash","cache_key"):
        require(o[field]==p[field],"MODE_MISMATCH" if field in {"execution_mode","run_id","security_scope"} else "REQUEST_BINDING",field)
    require(o["model_requested"]==p["model_version"],"MODEL_VERSION_MISMATCH",observation_id)
    require(o["wire"]["request_base64"]==p["request_base64"],"WIRE_REQUEST_HASH",observation_id)
    try:raw=base64.b64decode(o["wire"]["response_base64"],validate=True)
    except Exception as exc:raise ContractError("WIRE_ENCODING",str(exc)) from exc
    require(bytes_digest(raw)==o["wire_response_hash"],"WIRE_RESPONSE_HASH",observation_id)
    require(timestamp(o["completed_at"])>=timestamp(o["created_at"]) and o["created_at"]==p["created_at"],"TEMPORAL_ORDER",observation_id)
    if o["supersedes"] is not None:
        previous=catalog.get(o["supersedes"],"observation")
        require(o["supersedes"]!=observation_id and previous["candidate_id"]==o["candidate_id"] and
                timestamp(previous["completed_at"])<=timestamp(o["created_at"]),"SUPERSESSION_ORDER",observation_id)
    if o["status"]=="ERROR":
        require(o["error"] is not None and o["probabilities"] is None and o["raw_confidence"] is None and o["semantic_outcome"] is None,
                "ERROR_AS_SEMANTICS","operational errors have no semantic result")
        return
    parsed=loads(raw)
    require(isinstance(parsed,dict) and set(parsed)=={"model","answers","usage"} and
            isinstance(parsed["answers"],dict) and set(parsed["answers"])=={q["id"] for q in p["questions"]},"MALFORMED_RESPONSE","response envelope/coverage differs")
    require(isinstance(parsed["usage"],dict) and set(parsed["usage"])=={"input_tokens","output_tokens"} and
            all(type(x) is int and x>=0 for x in parsed["usage"].values()),"MALFORMED_USAGE","invalid usage")
    require(o["error"] is None and o["wire"]["http_status"]==200 and parsed["model"]==o["model_returned"]==o["model_requested"],
            "MODEL_VERSION_MISMATCH",observation_id)
    require(parsed["answers"][o["question_id"]]==o["raw_answer"],"RAW_OBSERVATION_CHANGED",observation_id)
    values,confidence,outcome=parse_answer(q,o["raw_answer"])
    require(values==o["probabilities"] and confidence==o["raw_confidence"] and outcome==o["semantic_outcome"],
            "DISTRIBUTION_MISMATCH","raw interpretation differs")

class TypeSafeAdapter:
    def __init__(self, *, enabled: bool = False, api_key: str | None = None,
                 transport: Callable[[bytes,str,float],tuple[int,dict[str,str],bytes]] | None = None,
                 timeout: float = 30, sleeper: Callable[[float],None] = time.sleep,
                 token_counter: Callable[[Any],int] | None = None,
                 tokenizer_version: str | None = None, observation_signer: Any = None):
        self.enabled,self.api_key,self.transport,self.timeout,self.sleeper=enabled,api_key,transport or self._http,timeout,sleeper
        self.token_counter,self.tokenizer_version,self.observation_signer=token_counter,tokenizer_version,observation_signer
    @staticmethod
    def _http(body: bytes, key: str, timeout: float) -> tuple[int,dict[str,str],bytes]:
        request=urllib.request.Request(ENDPOINT,data=body,headers={"Content-Type":"application/json","Authorization":f"Bearer {key}"},method="POST")
        # Do not follow redirects carrying credentials to another origin.
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self,*args,**kwargs):return None
        opener=urllib.request.build_opener(NoRedirect())
        try:
            with opener.open(request,timeout=timeout) as response:
                return response.status,dict(response.headers),response.read(MAX_RESPONSE+1)
        except urllib.error.HTTPError as exc:
            return exc.code,dict(exc.headers),exc.read(MAX_RESPONSE+1)
    def evaluate(self, catalog: Catalog, pack_id: str, *, source_status: dict[str,Any], budget: RunBudget,
                 max_retries: int = 2, current_graph_access: dict[str, Any] | None = None) -> list[str]:
        require(self.enabled and bool(self.api_key),"LIVE_DISABLED","explicit capability and externally supplied credentials required")
        pack=catalog.get(pack_id,"pack")
        require("model_profile" not in pack, "LOCAL_SEMANTIC_TRANSPORT", "local profile cannot be sent to TypeSafe HTTP")
        require(pack["execution_mode"]=="LIVE","MODE_MISMATCH","live adapter cannot label calls synthetic or recorded")
        require(pack["budget"]["measured"] and pack["tokenizer_version"]!="utf8-byte-estimate-v1","TOKENIZER_UNQUALIFIED","live cap checks need a measured tokenizer")
        require(budget.run_id==pack["run_id"],"BUDGET_SCOPE","another run's budget")
        require(type(max_retries) is int and 0<=max_retries<=10,"RETRY_CONFIG","bounded retries required")
        if "graph_context_ids" in pack:
            require(current_graph_access is not None, "GRAPH_ACCESS_REQUIRED", "live graph context requires current application ACLs")
        validate_pack(catalog,pack,source_status=source_status,current_graph_access=current_graph_access)
        body=base64.b64decode(pack["request_base64"],validate=True)
        require(self.token_counter is not None and self.tokenizer_version==pack["tokenizer_version"],"TOKENIZER_UNQUALIFIED","trusted tokenizer implementation must be injected")
        from .canonical import loads
        actual=self.token_counter(loads(body))
        require(type(actual) is int and 0<=actual<=pack["budget"]["request_cap"],"PACK_BUDGET_EXCEEDED","actual emitted request exceeds cap")
        require(self.token_counter(pack["state"])==pack["budget"]["state_tokens"] and
                all(self.token_counter(q)==pack["budget"]["question_tokens"][q["id"]] for q in pack["questions"]),"PACK_BUDGET_ACCOUNTING","caller token accounting differs from trusted tokenizer")
        require(self.observation_signer is not None,"OBSERVATION_UNATTESTED","adapter signer must be injected")
        receipts=[]
        def attest(ids):
            from .trust import attest_observation
            for ref in ids:catalog.put("receipt",attest_observation(self.observation_signer,catalog.record(ref,"observation")))
        for attempt in range(max_retries+1):
            request={"model_calls":1,"request_bytes":len(body)}
            if attempt:request["retries"]=1
            budget.consume_many(request)
            try:
                status,headers,response=self.transport(body,self.api_key,self.timeout)
                current=record_response(catalog,pack_id,response,http_status=status,response_headers=headers)
                attest(current);receipts.extend(current)
                if status not in {429,529} or attempt==max_retries:return receipts
                retry=headers.get("Retry-After",headers.get("retry-after",""))
                try:delay=min(60,max(0,float(retry))) if retry else min(60,2**attempt)
                except ValueError:delay=min(60,2**attempt)
                self.sleeper(delay)
            except (OSError,TimeoutError) as exc:
                current=record_response(catalog,pack_id,b"",http_status=0,transport_error=f"TRANSPORT_ERROR: {type(exc).__name__}")
                attest(current);receipts.extend(current)
                if attempt==max_retries:return receipts
                self.sleeper(min(60,2**attempt))
        return receipts
