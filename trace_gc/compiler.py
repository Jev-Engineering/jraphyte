"""Deterministic materialization and complete provenance/dependency closure.

Only source and record fields are rendered; no caller-supplied model state is
trusted. Materialization remains verifiable after transport hashes are recomputed.
"""
from __future__ import annotations
import base64
import re
from collections import deque
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Callable
from .canonical import digest, dumps, bytes_digest
from .catalog import Catalog
from .errors import boundary, require
from .references import topological_order

MATERIALIZER = "materializer-v1"
PACKING = "complete-closure-v1"
MODEL_PATTERN = re.compile(r"^jev-[0-9]+\.[0-9]+\.[0-9]+$")

def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def timestamp(value: str) -> datetime:
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(result.tzinfo is not None, "TIMESTAMP_ZONE", "UTC offset required")
    return result.astimezone(timezone.utc)

def transform(text: str, version: str) -> str:
    require(version in {"identity-v1", "collapse-whitespace-v1"}, "TRANSFORM_VERSION", version)
    return text if version == "identity-v1" else " ".join(text.split())

def _references(catalog: Catalog, id_: str, *, bounded_graph: bool = False) -> list[tuple[str, str, str]]:
    r = catalog.record(id_); b = r["body"]; kind = r["kind"]
    links: list[tuple[str, str, str]] = []
    if kind == "candidate":
        require(catalog.hash(b["claim_id"]) == b["claim_hash"], "CLAIM_BINDING", id_)
        links = [(b["claim_id"], "claim", "claim")]
        links += [(x,"evidence","evidence") for x in b["evidence_ids"]]
        links += [(x,"candidate","prerequisite") for x in b["prerequisites"]]
        links += [(x,"candidate","alternative-context") for x in b["alternatives"]]
    elif kind == "evidence":
        catalog.verify_evidence(id_)
        links = [(b["source_snapshot_id"], "source", "source-span")]
    elif kind == "source" and "image_evidence_id" in b:
        from .pdf_image_evidence import verify_image_source
        verify_image_source(catalog, b)
        links = [(b["image_evidence_id"], "image-evidence-v1", "reviewed-image-lineage")]
    elif kind == "observation":
        require(b["status"] == "OK", "PREREQUISITE_NOT_COMPLETED", id_)
        links = [(b["pack_id"],"pack","observed-input"), (b["candidate_id"],"candidate","target")]
        links += [(x,"evidence","support") for x in b["evidence_ids"]]
        links += [(x,"observation","prior-observation") for x in b["prior_observation_ids"]]
    elif kind == "pack":
        links = [(b["snapshot_id"],"graph-snapshot","snapshot")]
        links += [(x,"candidate","target") for x in b["candidate_ids"]]
        links += [(x,"observation","prior-observation") for x in b["prior_observation_ids"]]
    elif kind == "graph-snapshot":
        links = [(b["schema_id"],"schema","schema")]
        if not bounded_graph:
            links += [(ev,"evidence","active-graph-support") for fact in b["assertions"].values()
                      if fact["active"] for ev in fact["evidence_ids"]]
    elif kind == "graph-context":
        from .retrieval.service import validate_context
        validate_context(catalog, id_)
        links = [(b["snapshot_id"], "graph-snapshot", "retrieved-snapshot")]
        links += [(x, "evidence", "retrieved-canonical-evidence") for x in b["selected_evidence_ids"]]
        links += [(x["canonical_ref"], "claim", "retrieved-claim") for x in b["items"] if x["kind"] == "CLAIM"]
    elif kind == "retrieval-result":
        links = [(b["graph_context_id"], "graph-context", "retrieval-context")]

    for target, expected, _ in links:
        catalog.record(target, expected)
    return links

@boundary
def closure(catalog: Catalog, candidate_ids: list[str], prior_observation_ids: list[str], snapshot_id: str,
            graph_context_ids: list[str] | None = None, source_retrieval_ids: list[str] | None = None) -> dict[str, Any]:
    snap = catalog.get(snapshot_id, "graph-snapshot")
    roots = sorted(set(candidate_ids + prior_observation_ids + [snapshot_id] + (graph_context_ids or []) + (source_retrieval_ids or [])))
    bounded_graph = graph_context_ids is not None or source_retrieval_ids is not None
    queue, seen, edges = deque(roots), set(), []
    while queue:
        ref = queue.popleft()
        if ref in seen:
            continue
        seen.add(ref)
        for target, _, relationship in _references(catalog, ref, bounded_graph=bounded_graph):
            edges.append([ref, target, relationship])
            if target not in seen:
                queue.append(target)
    # All alternative/context links may be cyclic; only prerequisites are causal.
    candidates = {ref:catalog.get(ref,"candidate") for ref in seen if catalog.record(ref)["kind"] == "candidate"}
    topological_order({ref:b["prerequisites"] for ref,b in candidates.items()})
    body = {"roots":roots,"record_ids":sorted(seen),"edges":sorted(edges),
            "evidence_ids":sorted(ref for ref in seen if catalog.record(ref)["kind"] == "evidence"),
            "source_snapshot_ids":sorted(ref for ref in seen if catalog.record(ref)["kind"] == "source"),
            "prior_observation_ids":sorted(prior_observation_ids),
            "snapshot":{"graph_version":snap["graph_version"],"schema_hash":snap["schema_hash"]},"omissions":[]}
    return {**body,"hash":digest(body)}

@boundary
def materialize(catalog: Catalog, candidate_ids: list[str], prior_ids: list[str], snapshot_id: str,
                transformation: str = "identity-v1", graph_context_ids: list[str] | None = None,
                source_retrieval_ids: list[str] | None = None) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, str]]]:
    closed = closure(catalog, candidate_ids, prior_ids, snapshot_id, graph_context_ids, source_retrieval_ids)
    state: dict[str, Any] = {"candidates":[],"claims":[],"evidence":[],"prior_observations":[]}
    traces: list[dict[str, str]] = []
    def trace(path: str, ref: str, locator: str, version: str = "identity-v1") -> None:
        traces.append({"path":path,"record_id":ref,"record_hash":catalog.hash(ref),"locator":locator,"transformation":version})
    for ref in closed["record_ids"]:
        record = catalog.record(ref); b = record["body"]
        if record["kind"] == "candidate":
            i = len(state["candidates"])
            state["candidates"].append({"id":ref,"assertion":b["assertion"],"claim_id":b["claim_id"],
                                        "evidence_ids":b["evidence_ids"],"prerequisites":b["prerequisites"]})
            trace(f"/candidates/{i}/id",ref,"$id")
            for field in ("assertion","claim_id","evidence_ids","prerequisites"):
                trace(f"/candidates/{i}/{field}",ref,f"/{field}")
        elif record["kind"] == "claim":
            i = len(state["claims"])
            state["claims"].append({"id":ref,"text":transform(b["text"], transformation)})
            trace(f"/claims/{i}/id",ref,"$id")
            trace(f"/claims/{i}/text",ref,"/text",transformation)
        elif record["kind"] == "evidence":
            i = len(state["evidence"])
            source = catalog.get(b["source_snapshot_id"],"source")
            text = source["text"][b["start"]:b["end"]]
            state["evidence"].append({"id":ref,"source_snapshot_id":b["source_snapshot_id"],"text":transform(text,transformation)})
            trace(f"/evidence/{i}/id",ref,"$id")
            trace(f"/evidence/{i}/source_snapshot_id",ref,"/source_snapshot_id")
            trace(f"/evidence/{i}/text",b["source_snapshot_id"],f"/text[{b['start']}:{b['end']}]",transformation)
    for ref in sorted(prior_ids):
        obs = catalog.get(ref,"observation"); i = len(state["prior_observations"])
        state["prior_observations"].append({"id":ref,"question_id":obs["question_id"],"answer":obs["raw_answer"]})
        trace(f"/prior_observations/{i}/id",ref,"$id")
        trace(f"/prior_observations/{i}/question_id",ref,"/question_id")
        trace(f"/prior_observations/{i}/answer",ref,"/raw_answer")
    snap = catalog.get(snapshot_id,"graph-snapshot")
    if graph_context_ids is None and source_retrieval_ids is None:
        state["graph_snapshot"] = deepcopy(snap)
        trace("/graph_snapshot",snapshot_id,"/")
    else:
        # Complete snapshot stays available to deterministic compilation, not to
        # the model. Only selected, independently reconstructed context is rendered.
        state["graph_snapshot"] = {"snapshot_id": snapshot_id, "graph_version": snap["graph_version"],
                                   "schema_hash": snap["schema_hash"], "full_snapshot_in_model_context": False}
        trace("/graph_snapshot/graph_version", snapshot_id, "/graph_version")
        trace("/graph_snapshot/schema_hash", snapshot_id, "/schema_hash")
        state["graph_context"] = []
        for ref in sorted(graph_context_ids or []):
            context = catalog.get(ref, "graph-context")
            require(context["snapshot_id"] == snapshot_id, "STALE_GRAPH_CONTEXT", "retrieval/compile snapshot mismatch")
            i = len(state["graph_context"])
            state["graph_context"].append({"context_id": ref, "items": deepcopy(context["items"]),
                                           "instruction_authority": False})
            trace(f"/graph_context/{i}/items", ref, "/items")
    return state,closed,traces

def wire_request(pack: dict[str, Any]) -> bytes:
    questions = {}
    for q in pack["questions"]:
        primitive = q["primitive"]
        criteria = q["criteria"]
        if primitive == "SCORE":
            value = [x["description"] for x in criteria]
        elif primitive == "NOUL":
            mapped = {x["label"]:x["description"] for x in criteria}
            value = {"true":mapped["YES"],"false":mapped["NO"]}
        else:
            value = {x["label"]:x["description"] for x in criteria}
        questions[q["id"]] = {"type":primitive.lower(),"instructions":q["instructions"],"criteria":value}
    # Preserve criterion insertion order on the wire. Canonical hash is separate.
    import json
    return json.dumps({"model":pack["model_version"],"state":pack["state"],"questions":questions},
                      ensure_ascii=False, separators=(",",":"),allow_nan=False).encode("utf-8")

def semantic_input(pack: dict[str, Any]) -> dict[str, Any]:
    fields = ("run_id","execution_mode","security_scope","snapshot_id","graph_version","schema_hash",
              "model_version","program_version","materializer_version","packing_version","tokenizer_version",
              "candidate_ids","prior_observation_ids","questions","state","closure","materialization","transformation")
    result = {k:deepcopy(pack[k]) for k in fields}
    from .retrieval.integration import LINEAGE_FIELDS
    result.update({k:deepcopy(pack[k]) for k in LINEAGE_FIELDS if k in pack})
    return result

def byte_estimate(value: Any) -> int:
    """Transparent offline estimate, NOT a qualified provider tokenizer."""
    return len(dumps(value).encode("utf-8"))

@boundary
def compile_pack(catalog: Catalog, *, id_: str, run_id: str, candidate_ids: list[str], questions: list[dict[str, Any]],
                 snapshot_id: str, security_scope: str, execution_mode: str = "SYNTHETIC",
                 prior_observation_ids: list[str] | None = None, model_version: str = "jev-1.13.0",
                 program_version: str = "fixed-questions-v1", created_at: str | None = None,
                 transformation: str = "identity-v1", token_counter: Callable[[Any],int] | None = None,
                 tokenizer_version: str = "utf8-byte-estimate-v1", request_cap: int = 64000,
                 state_longest_cap: int = 32000, graph_context_ids: list[str] | None = None,
                 source_retrieval_ids: list[str] | None = None) -> str:
    require(bool(MODEL_PATTERN.fullmatch(model_version)), "MODEL_VERSION_UNPINNED", model_version)
    require(len(candidate_ids) == len(set(candidate_ids)) and bool(candidate_ids),"DUPLICATE_ID","candidate roots")
    prior = sorted(prior_observation_ids or [])
    require(len(prior) == len(set(prior)),"DUPLICATE_ID","prior observations")
    state,closed,traces = materialize(catalog, candidate_ids, prior, snapshot_id, transformation,
                                      graph_context_ids, source_retrieval_ids)
    snap = catalog.get(snapshot_id,"graph-snapshot")
    pack = {"snapshot_id":snapshot_id,"run_id":run_id,"execution_mode":execution_mode,"security_scope":security_scope,
            "graph_version":snap["graph_version"],"schema_hash":snap["schema_hash"],"model_version":model_version,
            "program_version":program_version,"materializer_version":MATERIALIZER,"packing_version":PACKING,
            "tokenizer_version":tokenizer_version,"candidate_ids":sorted(candidate_ids),"prior_observation_ids":prior,
            "questions":deepcopy(questions),"state":state,"closure":closed,"materialization":traces,
            "transformation":transformation,"created_at":created_at or now()}
    if graph_context_ids is not None or source_retrieval_ids is not None:
        from .retrieval.integration import lineage_fields
        pack.update(lineage_fields(catalog, graph_context_ids or [], source_retrieval_ids or [], closed["hash"]))
        pack["materializer_version"] = "materializer-v1+graph-v1"
        pack["packing_version"] = "minimum-source-graph-v1:" + pack["retrieval_fingerprint"]
    counter = token_counter or byte_estimate
    pack["budget"]={"state_tokens":counter(state),"question_tokens":{q["id"]:counter(q) for q in questions},
                    "request_cap":request_cap,"state_longest_cap":state_longest_cap,"measured":token_counter is not None}
    pack["semantic_hash"] = digest(semantic_input(pack))
    wire = wire_request(pack)
    pack["request_base64"] = base64.b64encode(wire).decode("ascii")
    pack["wire_request_hash"] = bytes_digest(wire)
    pack["cache_key"] = digest({"semantic_hash":pack["semantic_hash"],"wire_request_hash":pack["wire_request_hash"],
                                "tenant":security_scope,"mode":execution_mode,"adapter":"typesafe-http-v1"})
    # Validate before adding; never bless a caller-constructed "complete" flag.
    validate_pack(catalog,pack)
    return catalog.put("pack",pack,id_)

@boundary
def validate_pack(catalog: Catalog, pack: dict[str, Any], *, source_status: dict[str, Any] | None = None,
                  historical: bool = False, current_graph_access: dict[str, Any] | None = None) -> None:
    from .schema import validate
    validate("pack",pack)
    require(bool(MODEL_PATTERN.fullmatch(pack["model_version"])),"MODEL_VERSION_UNPINNED",pack["model_version"])
    expected_state,expected_closure,expected_trace = materialize(catalog, pack["candidate_ids"],
                                                pack["prior_observation_ids"],pack["snapshot_id"],pack["transformation"],
                                                pack.get("graph_context_ids"),pack.get("source_retrieval_ids"))
    require(pack["closure"] == expected_closure, "CLOSURE_INCOMPLETE", "closure must be derived from records")
    require(pack["state"] == expected_state and pack["materialization"] == expected_trace,
            "MATERIALIZATION_MISMATCH", "state/field provenance differs from immutable input")
    from .retrieval.integration import validate_pack_lineage
    validate_pack_lineage(catalog, pack, current_access=current_graph_access, current_status=source_status)
    snap = catalog.get(pack["snapshot_id"],"graph-snapshot")
    require(pack["graph_version"] == snap["graph_version"] and pack["schema_hash"] == snap["schema_hash"],
            "STALE_GRAPH_VERSION", "snapshot binding changed")
    require(catalog.hash(snap["schema_id"]) == snap["schema_hash"], "SCHEMA_HASH", "schema snapshot mismatch")
    for ref in expected_closure["source_snapshot_ids"]:
        source = catalog.get(ref,"source")
        require(source["security_scope"] == pack["security_scope"],"SECURITY_SCOPE",ref)
        if source_status is not None and not historical:
            require(ref in source_status, "SOURCE_STATUS_MISSING",ref)
            status = source_status[ref]
            require(status["active"] and not status["tombstone"] and status["permission"] == "READ",
                    "STALE_EVIDENCE",ref)
    for ref in expected_closure["record_ids"]:
        record = catalog.record(ref)
        if record["kind"] == "candidate":
            require(record["body"]["run_id"] == pack["run_id"] and record["body"]["execution_mode"] == pack["execution_mode"],
                    "MODE_MISMATCH",ref)
    ids = [q["id"] for q in pack["questions"]]
    require(len(ids) == len(set(ids)),"DUPLICATE_ID","question ID")
    from .programs import verify_question
    for q in pack["questions"]:
        verify_question(q,pack["program_version"])
        require(q["candidate_id"] in pack["candidate_ids"],"CANDIDATE_BINDING",q["id"])
        require(q["candidate_id"] in q["instructions"],"QUESTION_TARGET_AMBIGUOUS",q["id"])
        labels = [v["label"] for v in q["criteria"]]
        require(len(labels) == len(set(labels)),"DISTRIBUTION_LABELS",q["id"])
        if q["primitive"] == "NOUL":
            require(set(labels)=={"YES","NO"},"DISTRIBUTION_LABELS","Noul labels")
        elif q["primitive"] == "SCORE":
            require(labels == [str(i) for i in range(len(labels))] and 2 <= len(labels) <= 10,"DISTRIBUTION_LABELS","Score levels")
        else:
            require(2 <= len(labels) <= 255,"DISTRIBUTION_LABELS","Choice options")
        for dep in q["depends_on"]:
            parent = catalog.get(dep["pack_id"],"pack")
            require(parent["run_id"] == pack["run_id"] == dep["run_id"],"MODE_MISMATCH",dep["pack_id"])
            require(any(x["id"] == dep["question_id"] for x in parent["questions"]),"MISSING_REFERENCE",dep["question_id"])
            matching = [catalog.get(ref,"observation") for ref in pack["prior_observation_ids"]
                        if catalog.get(ref,"observation")["pack_id"] == dep["pack_id"]
                        and catalog.get(ref,"observation")["question_id"] == dep["question_id"]]
            require(bool(matching) and all(x["status"] == "OK" for x in matching),"PREREQUISITE_NOT_COMPLETED",dep["question_id"])
    for ref in pack["prior_observation_ids"]:
        obs = catalog.get(ref,"observation")
        require(timestamp(obs["completed_at"]) <= timestamp(pack["created_at"]),"TEMPORAL_ORDER",ref)
        parent = catalog.get(obs["pack_id"],"pack")
        require(parent["graph_version"] == pack["graph_version"] and parent["schema_hash"] == pack["schema_hash"] and
                obs["execution_mode"] == pack["execution_mode"] and obs["security_scope"] == pack["security_scope"],
                "PREREQUISITE_SNAPSHOT",ref)
    require(pack["semantic_hash"] == digest(semantic_input(pack)),"SEMANTIC_HASH","semantic input changed")
    request = wire_request(pack)
    require(pack["request_base64"] == base64.b64encode(request).decode() and pack["wire_request_hash"] == bytes_digest(request),
            "WIRE_REQUEST_HASH","actual adapter bytes differ")
    require(pack["cache_key"] == digest({"semantic_hash":pack["semantic_hash"],"wire_request_hash":pack["wire_request_hash"],
             "tenant":pack["security_scope"],"mode":pack["execution_mode"],"adapter":"typesafe-http-v1"}),"CACHE_SCOPE","cache identity differs")
    b = pack["budget"]
    require(set(b["question_tokens"]) == set(ids),"PACK_BUDGET_ACCOUNTING","question estimates incomplete")
    require(b["state_tokens"] + sum(b["question_tokens"].values()) <= b["request_cap"] and
            b["state_tokens"] + max(b["question_tokens"].values()) <= b["state_longest_cap"],"PACK_BUDGET_EXCEEDED","cannot truncate closure")
