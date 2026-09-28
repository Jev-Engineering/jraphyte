"""CHOICE-only local Qwen observations with explicit, uncalibrated provenance.

Loading and inference are opt-in application actions. No network client, signer,
graph backend or automatic retry is owned by this module.
"""
from __future__ import annotations

import base64
from copy import deepcopy
import importlib.metadata
import math
from pathlib import Path
import sys

from .canonical import bytes_digest, digest, dumps, loads
from .compiler import now, timestamp, validate_pack
from .errors import ContractError, boundary, require
from .local_generation import LocalQwenAdapter, verify_model_snapshot
from .schema import validate
from .semantic_profile import ADAPTER, MODEL_ID, PROMPT_VERSION, SCORING, SYSTEM, model_version, prompt_bytes, validate_profile


def implementation_sha256():
    root = Path(__file__).resolve().parent
    paths = sorted(list(root.rglob("*.py")) + list((root / "data/schemas").glob("*.json")))
    return digest({p.relative_to(root).as_posix(): bytes_digest(p.read_bytes())
                   for p in paths})


def runtime_identity():
    return {"python": sys.version, **{name: importlib.metadata.version(name) for name in ("torch", "transformers")}}


@boundary
def validate_execution(pack, response, execution):
    validate("local-semantic-execution", execution)
    profile = pack["model_profile"]
    request = base64.b64decode(pack["request_base64"], validate=True)
    expected_prompt = prompt_bytes(request)
    require(execution["profile_sha256"] == digest(profile) and execution["request_sha256"] == bytes_digest(request) and
            execution["response_sha256"] == bytes_digest(response) and
            execution["prompt_sha256"] == bytes_digest(expected_prompt) and
            base64.b64decode(execution["prompt_base64"], validate=True) == expected_prompt,
            "LOCAL_SEMANTIC_BINDING", "execution profile, request, prompt or response differs")
    require(execution["input_tokens"] == len(execution["input_token_ids"]) and
            execution["output_tokens"] == len(execution["output_token_ids"]) and
            execution["input_tokens"] <= profile["generation"]["maximum_input_tokens"] and
            execution["output_tokens"] <= profile["generation"]["maximum_new_tokens"],
            "LOCAL_SEMANTIC_BUDGET", "token lineage or generation cap differs")
    require(timestamp(pack["created_at"]) <= timestamp(execution["started_at"]) <= timestamp(execution["completed_at"]),
            "LOCAL_SEMANTIC_TIME", "generation precedes compiled request")
    require(execution["response_source"] == "ACTUAL_MODEL_EXECUTION" or pack["execution_mode"] == "SYNTHETIC",
            "LOCAL_SEMANTIC_MODE", "authored bytes cannot be relabeled as actual execution")


def _bodies(catalog, pack_id, response, execution):
    pack = catalog.get(pack_id, "pack")
    validate_pack(catalog, pack)
    require("model_profile" in pack and type(response) is bytes and len(response) <= 16 * 1024 * 1024,
            "LOCAL_SEMANTIC_INPUT", "bounded original local response and profile required")
    validate_execution(pack, response, execution)
    error, parsed = None, None
    try:
        require(execution["finish_reason"] == "eos", "LOCAL_SEMANTIC_INCOMPLETE", "truncated or failed generation")
        parsed = loads(response)
        require(type(parsed) is dict and set(parsed) == {"answers"} and type(parsed["answers"]) is dict and
                set(parsed["answers"]) == {q["id"] for q in pack["questions"]},
                "LOCAL_SEMANTIC_FORMAT", "exact question coverage and answers-only envelope required")
    except ContractError as exc:
        error = exc.code
    result = []
    for question in pack["questions"]:
        candidate = catalog.get(question["candidate_id"], "candidate")
        raw = parsed.get("answers", {}).get(question["id"]) if isinstance(parsed, dict) and isinstance(parsed.get("answers"), dict) else None
        issue, values, confidence, outcome = error, None, None, None
        if issue is None:
            try:
                from .adapter import parse_answer
                values, confidence, outcome = parse_answer(question, raw)
                # The TypeSafe HTTP display-rounding exception is not applied to Qwen.
                require(math.isclose(sum(values.values()), 1, rel_tol=0, abs_tol=1e-6) and
                        values[outcome] == max(values.values()), "LOCAL_SEMANTIC_DISTRIBUTION", "invalid local distribution or choice")
            except (ContractError, TypeError, KeyError, IndexError) as exc:
                issue, values, confidence, outcome = getattr(exc, "code", "MALFORMED_ANSWER"), None, None, None
        body = {"run_id": pack["run_id"], "execution_mode": pack["execution_mode"], "security_scope": pack["security_scope"],
            "pack_id": pack_id, "pack_hash": catalog.hash(pack_id), "question_id": question["id"], "question_hash": digest(question),
            "candidate_id": question["candidate_id"], "candidate_hash": catalog.hash(question["candidate_id"]),
            "semantic_hash": pack["semantic_hash"], "wire_request_hash": pack["wire_request_hash"],
            "wire_response_hash": bytes_digest(response), "cache_key": pack["cache_key"], "adapter_version": ADAPTER,
            "model_profile": deepcopy(pack["model_profile"]), "score_origin": SCORING,
            "model_requested": pack["model_version"], "model_returned": pack["model_version"],
            "status": "ERROR" if issue else "OK", "raw_answer": raw if isinstance(raw, dict) else None,
            "probabilities": values, "raw_confidence": confidence, "semantic_outcome": outcome, "error": issue,
            "evidence_ids": candidate["evidence_ids"], "prior_observation_ids": pack["prior_observation_ids"], "supersedes": None,
            "created_at": pack["created_at"], "completed_at": execution["completed_at"],
            "wire": {"transport": "LOCAL_TRANSFORMERS", "request_base64": pack["request_base64"],
                     "response_base64": base64.b64encode(response).decode(), "execution": deepcopy(execution)}}
        from .retrieval.integration import LINEAGE_FIELDS
        body.update({field: deepcopy(pack[field]) for field in LINEAGE_FIELDS if field in pack})
        result.append(body)
    return result


@boundary
def record_local_response(catalog, pack_id, response, *, execution):
    """Portable import, not execution attestation; trusted signatures remain separate."""
    return [catalog.put("observation", body) for body in _bodies(catalog, pack_id, response, execution)]


@boundary
def validate_local_observation(catalog, observation_id):
    observation = catalog.get(observation_id, "observation")
    raw = base64.b64decode(observation["wire"]["response_base64"], validate=True)
    expected = _bodies(catalog, observation["pack_id"], raw, observation["wire"]["execution"])
    require(any(body == observation for body in expected), "LOCAL_SEMANTIC_OBSERVATION", "local observation differs from original exchange")


class LocalQwenSemanticAdapter(LocalQwenAdapter):
    """Explicit local load and a single genuine inference; no publication capability.

    Reuses verified snapshot loading only. The answer-only SYSTEM/generate path
    is not called. ``generate_pack`` returns raw output plus execution evidence;
    application review/import/observation signatures remain separate actions.
    """

    def __init__(self, root, manifest_path, *, device="cpu", threads=4, maximum_input_tokens=4096, maximum_new_tokens=512):
        require(type(maximum_input_tokens) is int and 1 <= maximum_input_tokens <= 8192 and
                type(maximum_new_tokens) is int and 1 <= maximum_new_tokens <= 2048,
                "LOCAL_SEMANTIC_CONFIG", "bounded token limits required")
        # Base adapter has a smaller answer cap; reuse loading without its generation path.
        super().__init__(root, manifest_path, device=device, threads=threads, maximum_new_tokens=min(maximum_new_tokens, 512))
        self.root, self.manifest_path = Path(root).resolve(strict=True), Path(manifest_path).resolve(strict=True)
        manifest_bytes = self.manifest_path.read_bytes()
        require(bytes_digest(manifest_bytes) == self.identity["model_manifest_sha256"], "LOCAL_MODEL_CHANGED", "manifest changed after loading")
        manifest = loads(manifest_bytes)
        require("tokenizer_config.json" in manifest["files"], "LOCAL_MODEL_MANIFEST", "pinned chat template required")
        self.profile = {"version": "local-qwen-choice-profile-v1", "provider": "local-transformers", "model_id": MODEL_ID,
            "revision": self.identity["revision"], "model_manifest_sha256": self.identity["model_manifest_sha256"],
            "snapshot_files_sha256": self.identity["snapshot_files_sha256"], "tokenizer_sha256": manifest["files"]["tokenizer.json"],
            "tokenizer_config_sha256": manifest["files"]["tokenizer_config.json"], "adapter_version": ADAPTER,
            "prompt_version": PROMPT_VERSION, "prompt_sha256": bytes_digest(SYSTEM.encode()), "scoring": SCORING,
            "generation": {"do_sample": False, "dtype": "bfloat16", "device": device, "threads": threads,
                           "maximum_input_tokens": maximum_input_tokens, "maximum_new_tokens": maximum_new_tokens},
            "runtime": runtime_identity(), "implementation_sha256": implementation_sha256()}
        validate_profile(self.profile)
        self._profile_sha256 = digest(self.profile)
        self.last_execution = None

    def token_counter(self, value):
        """The compiler also measures state/question objects; whole prompt checked at call."""
        return len(self.tokenizer.encode(dumps(value), add_special_tokens=False))

    def _unchanged(self):
        require(digest(self.profile) == self._profile_sha256 and
                verify_model_snapshot(self.root, self.manifest_path) == self.identity and
                runtime_identity() == self.profile["runtime"] and
                implementation_sha256() == self.profile["implementation_sha256"],
                "LOCAL_SEMANTIC_CHANGED", "model, runtime, profile or implementation changed")

    @boundary
    def generate_pack(self, catalog, pack_id, *, execution_authorized=False, current_context=None):
        """Caller reserves durable budget and records intent BEFORE opting in.

        No retry is attempted, even after failure with unknown external outcome.
        An explicitly synthetic pack may still be used for an actual smoke, but
        its observations remain SYNTHETIC and cannot qualify a real pilot.
        """
        self.last_execution = None
        self.last_usage = None
        self.last_attempt = {"pack_id": pack_id, "status": "held", "paid_api_calls": 0, "graph_writes": 0}
        require(execution_authorized is True, "LOCAL_SEMANTIC_DISABLED", "explicit execution authorization required")
        pack = catalog.get(pack_id, "pack")
        require(callable(current_context), "LOCAL_SEMANTIC_FRESHNESS", "current application source/graph/access callback required")
        def freshness():
            context = current_context()
            require(type(context) is dict and set(context) == {"pack_sha256", "graph_version", "schema_hash", "source_status", "graph_access"} and
                    context["pack_sha256"] == catalog.hash(pack_id) and
                    context["graph_version"] == pack["graph_version"] and context["schema_hash"] == pack["schema_hash"],
                    "LOCAL_SEMANTIC_FRESHNESS", "current application context differs from compiled graph")
            validate_pack(catalog, pack, source_status=context["source_status"], current_graph_access=context["graph_access"])
            from .retrieval.security import AccessFilter
            acl = AccessFilter(context["graph_access"], catalog, context["source_status"])
            require(all(acl.allows("source", ref) for ref in pack["closure"]["source_snapshot_ids"]),
                    "LOCAL_SEMANTIC_FRESHNESS", "source access denied")
            for ref in pack["candidate_ids"]:
                assertion = catalog.get(ref, "candidate")["assertion"]
                require(acl.allows("node", assertion["subject"]) and acl.allows("node", assertion["object"]),
                        "LOCAL_SEMANTIC_FRESHNESS", "candidate endpoint access denied")
            return digest(context)
        initial_context = freshness()
        require(pack.get("model_profile") == self.profile and pack["model_version"] == model_version(self.profile) and
                pack["execution_mode"] in {"LIVE", "SYNTHETIC"} and pack["budget"]["measured"],
                "LOCAL_SEMANTIC_PROFILE", "execution profile, mode or measured tokenizer differs")
        self._unchanged()
        request = base64.b64decode(pack["request_base64"], validate=True)
        expected_prompt = prompt_bytes(request)
        messages = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": request.decode("utf-8")}]
        rendered = self.tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        require(rendered.encode("utf-8") == expected_prompt, "LOCAL_SEMANTIC_TEMPLATE", "tokenizer chat template differs from frozen lowering")
        inputs = self.tokenizer(rendered, return_tensors="pt", add_special_tokens=False).to(self.device)
        input_ids = inputs["input_ids"][0].tolist()
        generation = self.profile["generation"]
        require(len(input_ids) <= generation["maximum_input_tokens"] and len(input_ids) <= pack["budget"]["request_cap"] and
                self.token_counter(pack["state"]) == pack["budget"]["state_tokens"] and
                all(self.token_counter(q) == pack["budget"]["question_tokens"][q["id"]] for q in pack["questions"]),
                "LOCAL_SEMANTIC_BUDGET", "actual prompt or compiler token accounting differs")
        require(freshness() == initial_context, "LOCAL_SEMANTIC_FRESHNESS", "source/access changed before generation")
        started = now()
        self.last_attempt = {"pack_id": pack_id, "request_sha256": bytes_digest(request), "status": "started",
                             "started_at": started, "paid_api_calls": 0, "graph_writes": 0}
        # Exceptions leave last_attempt started/unknown; no fabricated error response.
        with self.torch.inference_mode():
            outputs = self.model.generate(**inputs, max_new_tokens=generation["maximum_new_tokens"],
                do_sample=False, pad_token_id=self.tokenizer.eos_token_id)
        output_ids = outputs[0][len(input_ids):].tolist()
        response = self.tokenizer.decode(output_ids, skip_special_tokens=True).encode("utf-8")
        eos = self.model.generation_config.eos_token_id
        eos_ids = {eos} if type(eos) is int else set(eos or [])
        finish = "eos" if output_ids and output_ids[-1] in eos_ids else "length" if len(output_ids) >= generation["maximum_new_tokens"] else "error"
        execution = {"version": "local-semantic-execution-v1", "profile_sha256": digest(self.profile),
            "request_sha256": bytes_digest(request), "prompt_sha256": bytes_digest(expected_prompt),
            "response_sha256": bytes_digest(response), "prompt_base64": base64.b64encode(expected_prompt).decode(),
            "execution_preflight_sha256": initial_context,
            "input_token_ids": input_ids, "output_token_ids": output_ids, "input_tokens": len(input_ids), "output_tokens": len(output_ids),
            "started_at": started, "completed_at": now(), "finish_reason": finish,
            "response_source": "ACTUAL_MODEL_EXECUTION",
            "paid_api_calls": 0, "cost_usd": 0, "graph_writes": 0, "publication_authorized": False}
        self._unchanged()
        require(freshness() == initial_context, "LOCAL_SEMANTIC_FRESHNESS", "source/access changed during generation; result held")
        validate_execution(pack, response, execution)
        self.last_execution = deepcopy(execution)
        self.last_usage = {"input_tokens": len(input_ids), "output_tokens": len(output_ids)}
        self.last_attempt = {"pack_id": pack_id, "status": "generated", "request_sha256": bytes_digest(request),
                             "response_sha256": bytes_digest(response), "paid_api_calls": 0, "graph_writes": 0}
        return response, execution
