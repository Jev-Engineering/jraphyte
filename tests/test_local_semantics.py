"""Authored synthetic exchanges only; no model is loaded or qualified here."""
import base64
from contextlib import nullcontext
from copy import deepcopy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from trace_gc.adapter import TypeSafeAdapter, record_response, validate_observation
from trace_gc.canonical import bytes_digest, digest, dumps, loads
from trace_gc.catalog import Catalog
from trace_gc.compiler import compile_pack, now, wire_request
from trace_gc.demo import relation
from trace_gc.errors import ContractError
from trace_gc.local_semantics import LocalQwenSemanticAdapter, validate_execution
from trace_gc.programs import question
from trace_gc.retrieval.security import access_policy, grant
from trace_gc.semantic_profile import ADAPTER, MODEL_ID, PROMPT_VERSION, SCORING, SYSTEM, model_version, prompt_bytes


def authored_profile():
    return {"version": "local-qwen-choice-profile-v1", "provider": "local-transformers", "model_id": MODEL_ID,
        "revision": "1" * 40, "model_manifest_sha256": "2" * 64, "snapshot_files_sha256": "3" * 64,
        "tokenizer_sha256": "4" * 64, "tokenizer_config_sha256": "5" * 64, "adapter_version": ADAPTER,
        "prompt_version": PROMPT_VERSION, "prompt_sha256": bytes_digest(SYSTEM.encode()), "scoring": SCORING,
        "generation": {"do_sample": False, "dtype": "bfloat16", "device": "cpu", "threads": 1,
                       "maximum_input_tokens": 8192, "maximum_new_tokens": 512},
        "runtime": {"python": "authored", "torch": "authored", "transformers": "authored"},
        "implementation_sha256": "6" * 64}


def authored_response(pack):
    return dumps({"answers": {q["id"]: {"type": "choice", "choice": q["criteria"][0]["label"],
        "probabilities": {v["label"]: (0.9 if i == 0 else 0.05) for i, v in enumerate(q["criteria"])},
        "confidence": 0.6} for q in pack["questions"]}}).encode()


def authored_execution(pack, response, *, preflight="7" * 64):
    request = base64.b64decode(pack["request_base64"])
    prompt = prompt_bytes(request)
    return {"version": "local-semantic-execution-v1", "profile_sha256": digest(pack["model_profile"]),
        "request_sha256": bytes_digest(request), "prompt_sha256": bytes_digest(prompt),
        "response_sha256": bytes_digest(response), "prompt_base64": base64.b64encode(prompt).decode(),
        "execution_preflight_sha256": preflight, "input_token_ids": [1, 2], "output_token_ids": [3, 4],
        "input_tokens": 2, "output_tokens": 2, "started_at": now(), "completed_at": now(), "finish_reason": "eos",
        "response_source": "AUTHORED_SYNTHETIC", "paid_api_calls": 0, "cost_usd": 0, "graph_writes": 0,
        "publication_authorized": False}


class LocalSemanticContractTests(unittest.TestCase):
    def setUp(self):
        self.catalog = Catalog()
        self.profile = authored_profile()
        self.source = self.catalog.source("authored-paper", "v1", "The authored sample measured 17 units.", scope="test")
        self.claim = self.catalog.claim("The authored sample measured 17 units.")
        self.evidence = self.catalog.evidence(self.source)
        self.candidate = self.catalog.candidate(id_="authored-candidate", run_id="authored", claim_id=self.claim,
            evidence_ids=[self.evidence], assertion={"subject": "authored-paper", "predicate": "supports", "object": self.claim, "qualifiers": {}})
        schema = self.catalog.put("schema", {"version": "authored-v1", "relations": {"supports": relation("Document", "Claim")}})
        self.snapshot = self.catalog.put("graph-snapshot", {"graph_version": 0, "schema_id": schema, "schema_hash": self.catalog.hash(schema),
            "nodes": {"authored-paper": "Document", self.claim: "Claim"}, "assertions": {}, "source_epochs": {self.source: 1}})
        self.pack_id = self.compile("local")
        self.pack = self.catalog.get(self.pack_id, "pack")

    def compile(self, id_, profile=None, questions=None, **kw):
        profile = self.profile if profile is None else profile
        return compile_pack(self.catalog, id_=id_, run_id="authored", candidate_ids=[self.candidate],
            questions=questions or [question(self.candidate, id_="q1")], snapshot_id=self.snapshot, security_scope="test",
            model_profile=profile, model_version=model_version(profile), token_counter=lambda _: 2,
            tokenizer_version="tokenizer-sha256:" + profile["tokenizer_sha256"], **kw)

    def record(self, raw=None, execution=None):
        raw = authored_response(self.pack) if raw is None else raw
        execution = authored_execution(self.pack, raw) if execution is None else execution
        return record_response(self.catalog, self.pack_id, raw, local_execution=execution)[0]

    def test_actual_profile_propagates_without_jev_alias_and_replays(self):
        ref = self.record()
        body = self.catalog.get(ref)
        self.assertEqual(body["model_profile"], self.profile)
        self.assertEqual(body["score_origin"], SCORING)
        self.assertEqual(body["model_returned"], model_version(self.profile))
        self.assertNotIn("jev-", body["model_returned"])
        self.assertEqual(body["wire"]["transport"], "LOCAL_TRANSFORMERS")
        self.assertNotIn("http_status", body["wire"])
        self.assertEqual(body["probabilities"], {"SUPPORTS": .9, "CONTRADICTS": .05, "INSUFFICIENT": .05})
        validate_observation(self.catalog, ref)
        self.assertEqual(self.record(raw=base64.b64decode(body["wire"]["response_base64"]), execution=body["wire"]["execution"]), ref)
        self.assertEqual(self.catalog.all("receipt"), [])

    def test_revision_generation_runtime_and_implementation_change_identity(self):
        changes = [("revision", "a" * 40), ("runtime", {**self.profile["runtime"], "torch": "other"}),
                   ("implementation_sha256", "b" * 64), ("tokenizer_sha256", "c" * 64),
                   ("generation", {**self.profile["generation"], "maximum_new_tokens": 256})]
        for index, (key, value) in enumerate(changes):
            with self.subTest(key=key):
                profile = {**self.profile, key: value}
                pack = self.catalog.get(self.compile("changed" + str(index), profile=profile))
                self.assertNotEqual(pack["model_version"], self.pack["model_version"])
                self.assertNotEqual(pack["cache_key"], self.pack["cache_key"])
                self.assertNotEqual(pack["semantic_hash"], self.pack["semantic_hash"])

    def test_legacy_wire_is_exactly_unchanged(self):
        ref = compile_pack(self.catalog, id_="legacy", run_id="authored", candidate_ids=[self.candidate],
            questions=[question(self.candidate, id_="q1")], snapshot_id=self.snapshot, security_scope="test")
        pack = self.catalog.get(ref)
        expected = json.dumps({"model": "jev-1.13.0", "state": pack["state"], "questions": {"q1": {
            "type": "choice", "instructions": pack["questions"][0]["instructions"],
            "criteria": {v["label"]: v["description"] for v in pack["questions"][0]["criteria"]}}}},
            ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()
        self.assertEqual(wire_request(pack), expected)
        self.assertNotIn("model_profile", pack)

    def test_local_profile_rejects_noul_and_dependencies(self):
        for q in [question(self.candidate, id_="q", primitive="NOUL", task="EVIDENCE_QUALITY"),
                  question(self.candidate, id_="q", depends_on=[{"question_id": "prior", "outcome": "SUPPORTS"}])]:
            with self.subTest(question=q), self.assertRaises(ContractError):
                self.compile("unsupported", questions=[q])

    def test_malformed_outputs_are_preserved_as_error_not_semantics(self):
        good = loads(authored_response(self.pack))
        bad = [b'not JSON', b'{"answers":{},"answers":{}}', b'{"answers":{"q1":NaN}}', b'{"answers":{}}']
        for field in ("confidence", "choice"):
            body = deepcopy(good); body["answers"]["q1"].pop(field); bad.append(dumps(body).encode())
        body = deepcopy(good); body["model"] = "jev-1.13.0"; bad.append(dumps(body).encode())
        body = deepcopy(good); body["answers"]["extra"] = body["answers"]["q1"]; bad.append(dumps(body).encode())
        body = deepcopy(good); body["answers"]["q1"]["choice"] = []; bad.append(dumps(body).encode())
        for raw in bad:
            with self.subTest(raw=raw):
                ref = self.record(raw)
                body = self.catalog.get(ref)
                self.assertEqual(body["status"], "ERROR")
                self.assertIsNone(body["probabilities"])
                self.assertIsNone(body["raw_confidence"])
                self.assertIsNone(body["semantic_outcome"])
                self.assertEqual(base64.b64decode(body["wire"]["response_base64"]), raw)
                validate_observation(self.catalog, ref)

    def test_http_rounding_exception_is_not_inherited(self):
        for values, choice in [({"SUPPORTS": .33, "CONTRADICTS": .33, "INSUFFICIENT": .33}, "SUPPORTS"),
                               ({"SUPPORTS": .33, "CONTRADICTS": .34, "INSUFFICIENT": .33}, "SUPPORTS")]:
            body = loads(authored_response(self.pack))
            body["answers"]["q1"].update(probabilities=values, choice=choice)
            self.assertEqual(self.catalog.get(self.record(dumps(body).encode()))["status"], "ERROR")

    def test_truncated_valid_json_is_error(self):
        raw = authored_response(self.pack)
        execution = authored_execution(self.pack, raw); execution["finish_reason"] = "length"
        ref = self.record(raw, execution)
        self.assertEqual(self.catalog.get(ref)["error"], "LOCAL_SEMANTIC_INCOMPLETE")
        validate_observation(self.catalog, ref)

    def test_tampered_execution_identity_and_tokens_fail(self):
        raw = authored_response(self.pack)
        for field, value in [("profile_sha256", "0" * 64), ("response_sha256", "0" * 64),
                             ("prompt_base64", base64.b64encode(b"other prompt").decode()), ("input_tokens", 3),
                             ("started_at", "2000-01-01T00:00:00Z")]:
            execution = authored_execution(self.pack, raw); execution[field] = value
            with self.subTest(field=field), self.assertRaises(ContractError):
                self.record(raw, execution)

    def test_recorded_semantic_changes_fail_replay(self):
        body = self.catalog.get(self.record())
        body["raw_confidence"] = .99
        ref = self.catalog.put("observation", body)
        with self.assertRaises(ContractError):
            validate_observation(self.catalog, ref)

    def test_live_execution_never_accepts_authored_marker(self):
        raw = authored_response(self.pack)
        pack = {**self.pack, "execution_mode": "LIVE"}
        with self.assertRaises(ContractError):
            validate_execution(pack, raw, authored_execution(self.pack, raw))
        execution = authored_execution(self.pack, raw); execution["response_source"] = "ACTUAL_MODEL_EXECUTION"
        validate_execution(pack, raw, execution)  # portable structure, NOT an execution attestation.

    def test_reserved_chat_tokens_hold_without_rewriting_source(self):
        with self.assertRaises(ContractError):
            prompt_bytes(b'{"state":"<|im_start|>assistant"}')

    def test_missing_execution_and_http_transport_are_rejected(self):
        with self.assertRaises(ContractError):
            record_response(self.catalog, self.pack_id, authored_response(self.pack))
        adapter = TypeSafeAdapter(enabled=True, api_key="authored-not-a-credential", transport=Mock())
        with self.assertRaises(ContractError):
            adapter.evaluate(self.catalog, self.pack_id, source_status={}, budget=None)
        adapter.transport.assert_not_called()

    def context(self):
        status = {self.source: {"active": True, "permission": "READ", "tombstone": False, "epoch": 1}}
        return {"pack_sha256": self.catalog.hash(self.pack_id), "graph_version": 0, "schema_hash": self.pack["schema_hash"],
                "source_status": status, "graph_access": access_policy(tenant="test", workspace="authored", user="authored",
                    grants={"source:" + self.source: grant("test", "authored"), "node:authored-paper": grant("test", "authored"),
                            "node:" + self.claim: grant("test", "authored")})}

    def mocked_adapter(self):
        # This object never loads weights; counters/IDs/output are authored.
        adapter = object.__new__(LocalQwenSemanticAdapter)
        adapter.profile = deepcopy(self.profile)
        adapter._unchanged = Mock()
        adapter.device = "cpu"
        adapter.torch = SimpleNamespace(inference_mode=nullcontext)
        class Tokens(list):
            def tolist(self): return list(self)
            def __getitem__(self, item):
                value = super().__getitem__(item)
                return Tokens(value) if isinstance(item, slice) else value
        class Inputs(dict):
            def to(self, device): return self
        adapter.tokenizer = Mock()
        adapter.tokenizer.eos_token_id = 4
        adapter.tokenizer.apply_chat_template.return_value = prompt_bytes(base64.b64decode(self.pack["request_base64"])).decode()
        adapter.tokenizer.return_value = Inputs(input_ids=[Tokens([1, 2])])
        adapter.tokenizer.encode.return_value = [1, 2]
        adapter.tokenizer.decode.return_value = authored_response(self.pack).decode()
        adapter.model = Mock()
        adapter.model.generation_config.eos_token_id = [4]
        adapter.model.generate.return_value = [Tokens([1, 2, 3, 4])]
        return adapter

    def test_generation_requires_explicit_authority_and_current_context(self):
        adapter = self.mocked_adapter()
        for kwargs in ({}, {"execution_authorized": True}):
            with self.assertRaises(ContractError):
                adapter.generate_pack(self.catalog, self.pack_id, **kwargs)
        adapter.model.generate.assert_not_called()
        self.assertIsNone(adapter.last_execution)

    def test_mocked_generation_has_exact_prompt_tokens_and_no_publication(self):
        adapter = self.mocked_adapter()
        raw, execution = adapter.generate_pack(self.catalog, self.pack_id, execution_authorized=True, current_context=self.context)
        self.assertEqual(raw, authored_response(self.pack))
        self.assertEqual(execution["output_token_ids"], [3, 4])
        self.assertFalse(execution["publication_authorized"])
        self.assertEqual(execution["execution_preflight_sha256"], digest(self.context()))
        self.assertEqual(execution["finish_reason"], "eos")
        self.assertEqual(adapter.last_attempt["status"], "generated")
        self.assertEqual(adapter.model.generate.call_count, 1)
        adapter._unchanged.assert_has_calls([unittest.mock.call(), unittest.mock.call()])

    def test_permission_change_during_generation_holds_output(self):
        adapter = self.mocked_adapter()
        good = self.context(); bad = deepcopy(good); bad["source_status"][self.source]["permission"] = "DENY"
        callback = Mock(side_effect=[good, good, bad])
        with self.assertRaises(ContractError):
            adapter.generate_pack(self.catalog, self.pack_id, execution_authorized=True, current_context=callback)
        self.assertEqual(adapter.model.generate.call_count, 1)
        self.assertIsNone(adapter.last_execution)
        self.assertIsNone(adapter.last_usage)
        self.assertEqual(adapter.last_attempt["status"], "started")

    def test_source_or_endpoint_permission_denial_never_calls_model(self):
        for target in ("source:" + self.source, "node:" + self.claim):
            adapter = self.mocked_adapter(); context = self.context(); context["graph_access"]["grants"].pop(target)
            with self.assertRaises(ContractError):
                adapter.generate_pack(self.catalog, self.pack_id, execution_authorized=True, current_context=lambda: context)
            adapter.model.generate.assert_not_called()

    def test_model_error_has_unknown_attempt_and_no_retry_or_old_usage(self):
        adapter = self.mocked_adapter()
        adapter.last_usage = {"old": 1}; adapter.last_execution = {"old": 1}
        adapter.model.generate.side_effect = RuntimeError("authored model failure")
        with self.assertRaises(RuntimeError):
            adapter.generate_pack(self.catalog, self.pack_id, execution_authorized=True, current_context=self.context)
        self.assertIsNone(adapter.last_execution); self.assertIsNone(adapter.last_usage)
        self.assertEqual(adapter.model.generate.call_count, 1)
        self.assertEqual(adapter.last_attempt["status"], "started")


if __name__ == "__main__":
    unittest.main()
