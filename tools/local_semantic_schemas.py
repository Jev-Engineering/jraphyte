"""Additive local semantic profile/wire schemas; no legacy record rehashing."""
from copy import deepcopy


def extend(schemas):
    S = {"type": "string", "minLength": 1}
    H = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    N = {"type": "integer", "minimum": 0}
    T = {"type": "string", "format": "date-time"}
    def obj(properties):
        return {"type": "object", "properties": deepcopy(properties), "required": list(properties), "additionalProperties": False}
    def arr(items, minimum=0):
        return {"type": "array", "items": deepcopy(items), "minItems": minimum}
    profile = obj({
        "version": {"const": "local-qwen-choice-profile-v1"},
        "provider": {"const": "local-transformers"},
        "model_id": {"const": "Qwen/Qwen3-4B-Instruct-2507"},
        "revision": {"type": "string", "pattern": "^[0-9a-f]{40}$"},
        "model_manifest_sha256": H, "snapshot_files_sha256": H,
        "tokenizer_sha256": H, "tokenizer_config_sha256": H,
        "adapter_version": {"const": "local-qwen-semantic-v1"},
        "prompt_version": {"const": "qwen-choice-json-v1"}, "prompt_sha256": H,
        "scoring": {"const": "MODEL_GENERATED_UNCALIBRATED"},
        "generation": obj({"do_sample": {"const": False}, "dtype": {"const": "bfloat16"},
            "device": {"enum": ["cpu", "cuda:0"]}, "threads": {"type": "integer", "minimum": 1, "maximum": 8},
            "maximum_input_tokens": {"type": "integer", "minimum": 1, "maximum": 8192},
            "maximum_new_tokens": {"type": "integer", "minimum": 1, "maximum": 2048}}),
        "runtime": obj({"python": S, "torch": S, "transformers": S}),
        "implementation_sha256": H,
    })
    schemas["local-semantic-profile"] = profile
    schemas["pack"]["properties"]["model_profile"] = deepcopy(profile)
    schemas["observation"]["properties"]["adapter_version"] = {"enum": ["typesafe-http-v1", "local-qwen-semantic-v1"]}
    schemas["observation"]["properties"]["model_profile"] = deepcopy(profile)
    schemas["observation"]["properties"]["score_origin"] = {"const": "MODEL_GENERATED_UNCALIBRATED"}
    execution = obj({"version": {"const": "local-semantic-execution-v1"},
        "profile_sha256": H, "request_sha256": H, "prompt_sha256": H,
        "response_sha256": H, "prompt_base64": S,
        "execution_preflight_sha256": H,
        "input_token_ids": arr(N, minimum=1), "output_token_ids": arr(N),
        "input_tokens": N, "output_tokens": N,
        "started_at": T, "completed_at": T,
        "finish_reason": {"enum": ["eos", "length", "error"]},
        "response_source": {"enum": ["ACTUAL_MODEL_EXECUTION", "AUTHORED_SYNTHETIC"]},
        "paid_api_calls": {"const": 0}, "cost_usd": {"const": 0},
        "graph_writes": {"const": 0}, "publication_authorized": {"const": False}})
    schemas["local-semantic-execution"] = execution
    legacy_wire = deepcopy(schemas["observation"]["properties"]["wire"])
    local_wire = obj({"transport": {"const": "LOCAL_TRANSFORMERS"}, "request_base64": S,
                      "response_base64": {"type": "string"}, "execution": execution})
    schemas["observation"]["properties"]["wire"] = {"oneOf": [legacy_wire, local_wire]}
    schemas["observation"]["allOf"] = [{"if": {"properties": {"adapter_version": {"const": "local-qwen-semantic-v1"}}},
        "then": {"required": ["model_profile", "score_origin"], "properties": {"wire": local_wire}},
        "else": {"not": {"anyOf": [{"required": ["model_profile"]}, {"required": ["score_origin"]}]},
                 "properties": {"wire": legacy_wire}}}]
