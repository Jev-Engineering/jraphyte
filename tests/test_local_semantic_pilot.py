"""Durable local profile integration with authored synthetic PDFs and responses."""
import copy
import unittest

from tests import test_paper_pilot as pilot_fixture
from tests.test_local_semantics import authored_profile, authored_response, authored_execution
from trace_gc.backend import CompilerService, SQLiteReferenceBackend
from trace_gc.budget import RunBudget
from trace_gc.canonical import bytes_digest, digest
from trace_gc.demo import limits
from trace_gc.errors import ContractError
from trace_gc.paper_pilot import PaperPilot
from trace_gc.trust import Signer, attest_observation, authorize_plan


@unittest.skipIf(pilot_fixture.fitz is None, "optional PyMuPDF fixture dependency unavailable")
class LocalSemanticPilotTests(unittest.TestCase):
    setUp = pilot_fixture.PaperPilotTests.setUp
    tearDown = pilot_fixture.PaperPilotTests.tearDown
    access = pilot_fixture.PaperPilotTests.access
    source = pilot_fixture.PaperPilotTests.source
    admit = pilot_fixture.PaperPilotTests.admit
    compiled = pilot_fixture.PaperPilotTests.compiled
    reopen = pilot_fixture.PaperPilotTests.reopen

    def open(self):
        self.profile = authored_profile()
        self.config["semantic_model"] = {"provider": self.profile["provider"], "model_id": self.profile["model_id"],
            "model_revision": self.profile["revision"], "tokenizer_id": "tokenizer-sha256:" + self.profile["tokenizer_sha256"]}
        self.backend = SQLiteReferenceBackend(self.root / "graph.sqlite3", catalog=self.catalog,
                                             schema_id=self.schema, nodes=self.nodes, sandbox=True)
        self.budget = RunBudget(self.root / "budget.sqlite3", self.config["run_id"], limits(model_calls=10))
        self.service = CompilerService(self.backend, self.trust, self.validator, policy_version="pilot-reviewed-v1",
            population="authored-synthetic-only", security_scope="pilot-test", policy_hash=self.catalog.hash(self.policy),
            publication_mode="REVIEWED")
        self.pilot = PaperPilot(self.root, config=self.config, catalog=self.catalog, backend=self.backend,
            service=self.service, budget=self.budget, current_access=self.access, token_counter=lambda _: 2,
            semantic_profile=self.profile)

    def exchange(self, compiled):
        raw = authored_response(self.catalog.get(compiled["pack_id"]))
        execution = authored_execution(self.catalog.get(compiled["pack_id"]), raw,
            preflight=digest(self.pilot.semantic_execution_context("compile")))
        receipt = self.receipt(raw, execution)
        return raw, execution, receipt

    def receipt(self, raw, execution, signer=None):
        payload = self.pilot.execution_payload("compile", kind="SEMANTIC", response_sha256=bytes_digest(raw),
            generated_at=execution["completed_at"], usage={"input_tokens": execution["input_tokens"], "output_tokens": execution["output_tokens"]},
            cost={"amount": 0, "currency": "USD"}, response_source="AUTHORED_SYNTHETIC", provider_request_id="authored-local-1",
            local_execution_sha256=digest(execution))
        return (signer or self.signer).issue("OBSERVATION", payload)

    def test_resume_local_profile_through_core_solver_and_explicit_reviewed_publish(self):
        compiled, _ = self.compiled()
        raw, execution, receipt = self.exchange(compiled)
        self.reopen()
        observed = self.pilot.record_semantic_response("response", compile_id="compile", response=raw,
            local_execution=execution, execution_receipt=receipt)
        self.assertEqual(self.backend.state()["graph_version"], 1)
        self.assertEqual(self.backend.view(self.catalog)["edges"], [])
        self.reopen()
        attestations = {ref: attest_observation(self.signer, self.catalog.record(ref)) for ref in observed["observation_ids"]}
        resolved = self.pilot.resolve_plan("resolve", response_id="response", attestations=attestations)
        self.assertEqual(resolved["state"], "WAIT_PLAN_REVIEW")
        self.assertEqual(self.catalog.get(resolved["evaluation_ids"][0])["outcome"], "ABSTAIN")
        self.assertEqual(self.backend.view(self.catalog)["edges"], [])
        self.reopen()
        self.pilot.preflight_plan("preflight", resolve_id="resolve")
        authorization = authorize_plan(self.signer, self.catalog.get(resolved["plan_id"]),
            self.catalog.hash(resolved["plan_id"]), reviewed_by="authored-test-reviewer")
        result = self.pilot.publish_plan("publish", preflight_id="preflight", authorization=authorization)
        self.reopen()
        self.assertEqual(self.pilot.publish_plan("publish", preflight_id="preflight", authorization=authorization), result)
        self.assertEqual(self.backend.state()["graph_version"], 2)
        self.assertEqual(len(self.backend.view(self.catalog)["edges"]), 1)

    def test_wrong_signature_or_execution_hash_cannot_import(self):
        compiled, _ = self.compiled()
        raw, execution, receipt = self.exchange(compiled)
        with self.assertRaises(ContractError):
            self.pilot.record_semantic_response("unknown", compile_id="compile", response=raw, local_execution=execution,
                execution_receipt=self.receipt(raw, execution, Signer.ephemeral("unenrolled")))
        changed = copy.deepcopy(execution); changed["output_token_ids"] = [5, 6]
        with self.assertRaises(ContractError):
            self.pilot.record_semantic_response("changed", compile_id="compile", response=raw,
                local_execution=changed, execution_receipt=receipt)
        self.assertEqual(self.catalog.all("observation"), [])

    def test_freshness_digest_and_signed_usage_must_match(self):
        compiled, _ = self.compiled()
        raw, execution, receipt = self.exchange(compiled)
        bad = copy.deepcopy(execution); bad["execution_preflight_sha256"] = "0" * 64
        with self.assertRaises(ContractError):
            self.pilot.record_semantic_response("bad-context", compile_id="compile", response=raw,
                local_execution=bad, execution_receipt=self.receipt(raw, bad))
        bad_receipt = copy.deepcopy(receipt)
        bad_payload = bad_receipt["payload"]; bad_payload["usage"]["input_tokens"] += 1
        bad_receipt = self.signer.issue("OBSERVATION", bad_payload)
        with self.assertRaises(ContractError):
            self.pilot.record_semantic_response("bad-usage", compile_id="compile", response=raw,
                local_execution=execution, execution_receipt=bad_receipt)

    def test_revoked_access_blocks_fresh_execution_context(self):
        self.compiled()
        self.grants.pop("node:" + self.claim)
        with self.assertRaises(ContractError):
            self.pilot.semantic_execution_context("compile")


if __name__ == "__main__":
    unittest.main()
