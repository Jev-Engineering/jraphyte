"""Authored synthetic PDFs/responses exercise mechanics; no real pilot evidence."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

try:
    import fitz
except ImportError:
    fitz = None

from trace_gc.backend import CompilerService, SQLiteReferenceBackend
from trace_gc.budget import RunBudget
from trace_gc.canonical import bytes_digest, digest
from trace_gc.catalog import Catalog
from trace_gc.compiler import now
from trace_gc.demo import fixture_response, limits, relation
from trace_gc.errors import ContractError
from trace_gc.paper_ingestion import CHECKS
from trace_gc.paper_pilot import PaperPilot
from trace_gc.policy import create_policy
from trace_gc.retrieval.contracts import query
from trace_gc.retrieval.security import access_policy, grant
from trace_gc.trust import IssuerPolicy, Signer, TrustStore, attest_observation, authorize_plan


@unittest.skipIf(fitz is None, "optional PyMuPDF fixture dependency unavailable")
class PaperPilotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        pdf = fitz.open()
        pdf.new_page().insert_text((70, 70), "Authored synthetic title page.")
        pdf.new_page().insert_text((70, 70), "The authored experiment measured 17 units.")
        self.pdf = pdf.tobytes()
        self.native = pdf[1].get_text("text")
        pdf.close()
        self.catalog = Catalog()
        self.claim = self.catalog.claim("The authored experiment measured 17 units.")
        self.schema = self.catalog.put("schema", {"version": "pilot-test-schema-v1",
            "relations": {"supports": relation("Document", "Claim", incompatible=["refutes"]),
                          "refutes": relation("Document", "Claim", incompatible=["supports"])}})
        self.policy = create_policy(self.catalog, version="pilot-reviewed-v1", scope="pilot-test",
            population="authored-synthetic-only", mode="REVIEWED", allowed_modes=["SYNTHETIC", "LIVE"])
        self.signer, self.validator = Signer.ephemeral("test-reviewer"), Signer.ephemeral("test-validator")
        self.trust = TrustStore()
        operations = frozenset({"SOURCE_ADMIT", "SOURCE_WITHDRAW", "SOURCE_PERMISSION", "ADD_ASSERTION",
                               "PAPER_SOURCE_REVIEW", "PAPER_ANSWER_REVIEW", "SEMANTIC_IMPORT", "ANSWER_IMPORT"})
        self.trust.enroll(self.signer.issuer, IssuerPolicy(self.signer.public_key(), "authored-test-reviewer",
            frozenset({"SOURCE_STATUS", "AUTHORIZATION", "OBSERVATION"}), operations,
            frozenset({"pilot-test"}), frozenset({"SYNTHETIC", "LIVE"}), can_review=True))
        self.trust.enroll(self.validator.issuer, IssuerPolicy(self.validator.public_key(), "test-validator",
            frozenset({"PREFLIGHT"}), frozenset(), frozenset({"pilot-test"}), frozenset({"SYNTHETIC", "LIVE"})))
        self.nodes = {"authored-paper": "Document", self.claim: "Claim"}
        model = {"provider": "AUTHORED_TEST_FIXTURE", "model_id": "jev-1.13.0",
                 "model_revision": "authored-test-revision", "tokenizer_id": "utf8-byte-estimate-v1"}
        self.config = {"run_id": "authored-pilot", "security_scope": "pilot-test", "execution_mode": "SYNTHETIC",
            "documents": [{"source_id": "authored-paper", "version": "v1", "document_sha256": bytes_digest(self.pdf), "physical_pages": [2]}],
            "questions": ["What did the authored experiment measure?"], "cohort_manifest_sha256": "1" * 64,
            "semantic_model": model, "answer_model": {**model, "model_id": "authored-answer"}}
        self.grants = {"node:" + ref: grant("pilot-test", "private-test") for ref in self.nodes}
        self.acl_revision = "test-acl-v1"
        self.open()

    def access(self):
        return access_policy(tenant="pilot-test", workspace="private-test", user="test-user",
                             grants=self.grants, revision=self.acl_revision)

    def open(self):
        self.backend = SQLiteReferenceBackend(self.root / "graph.sqlite3", catalog=self.catalog,
                                             schema_id=self.schema, nodes=self.nodes, sandbox=True)
        self.budget = RunBudget(self.root / "budget.sqlite3", self.config["run_id"], limits(model_calls=10))
        self.service = CompilerService(self.backend, self.trust, self.validator, policy_version="pilot-reviewed-v1",
            population="authored-synthetic-only", security_scope="pilot-test", policy_hash=self.catalog.hash(self.policy),
            publication_mode="REVIEWED")
        self.pilot = PaperPilot(self.root, config=self.config, catalog=self.catalog, backend=self.backend,
                               service=self.service, budget=self.budget, current_access=self.access,
                               token_counter=lambda x: len(json.dumps(x)))

    def reopen(self):
        self.pilot.close(); self.backend.close(); self.budget.close()
        initial = [self.catalog.record(ref) for ref in (self.schema, self.policy, self.claim)]
        self.catalog = Catalog(initial)
        self.open()

    def tearDown(self):
        self.pilot.close(); self.backend.close(); self.budget.close()
        self.temp.cleanup()

    def source(self):
        prepared = self.pilot.prepare_native_page("prepare", pdf_bytes=self.pdf, source_id="authored-paper", version="v1",
            physical_page=2, start=0, end=len(self.native.strip()))
        at = now()
        payload = self.pilot.source_review_payload("prepare", reviewer="authored-test-reviewer", reviewer_kind="assistant",
            reviewed_at=at, checks={key: True for key in CHECKS})
        receipt = self.signer.issue("SOURCE_STATUS", payload, issued_at=at)
        result = self.pilot.accept_source_review("review", prepared_id="prepare", receipt=receipt)
        self.grants["source:" + result["source_id"]] = grant("pilot-test", "private-test")
        return prepared, result

    def admit(self):
        _, reviewed = self.source()
        authorization = self.signer.issue("SOURCE_STATUS", self.pilot.admission_payload(["review"], expected_version=0))
        self.pilot.admit_sources("admit", review_ids=["review"], expected_version=0, authorization=authorization)
        return reviewed

    def compiled(self):
        reviewed = self.admit()
        candidate = {"assertion": {"subject": "authored-paper", "predicate": "supports", "object": self.claim, "qualifiers": {}},
                     "claim_id": self.claim, "evidence_ids": [reviewed["evidence_id"]]}
        result = self.pilot.compile_candidates("compile", candidates=[candidate])
        return result, reviewed

    def execution(self, stage, kind, response, *, source="AUTHORED_SYNTHETIC", usage=None):
        at = now()
        payload = self.pilot.execution_payload(stage, kind=kind, response_sha256=bytes_digest(response), generated_at=at,
            usage=usage or {"input_tokens": 100, "output_tokens": 20}, cost={"amount": 0, "currency": "USD"},
            response_source=source, provider_request_id="authored-test-only:" + stage)
        return self.signer.issue("OBSERVATION", payload, issued_at=at)

    def resolved(self):
        compiled, reviewed = self.compiled()
        response = fixture_response(self.catalog.get(compiled["pack_id"], "pack"))
        result = self.pilot.record_semantic_response("response", compile_id="compile", response=response,
            execution_receipt=self.execution("compile", "SEMANTIC", response))
        attestations = {ref: attest_observation(self.signer, self.catalog.record(ref, "observation")) for ref in result["observation_ids"]}
        resolved = self.pilot.resolve_plan("resolve", response_id="response", attestations=attestations)
        return resolved, reviewed

    def published(self):
        resolved, reviewed = self.resolved()
        self.assertEqual(resolved["state"], "WAIT_PLAN_REVIEW")
        self.pilot.preflight_plan("preflight", resolve_id="resolve")
        authorization = authorize_plan(self.signer, self.catalog.get(resolved["plan_id"], "plan"),
            self.catalog.hash(resolved["plan_id"]), reviewed_by="authored-test-reviewer")
        result = self.pilot.publish_plan("publish", preflight_id="preflight", authorization=authorization)
        for ref in self.backend.state()["assertions"]:
            self.grants["edge:" + ref] = grant("pilot-test", "private-test")
        return result, reviewed

    def answer_request(self):
        _, reviewed = self.published()
        request = query(requesting_component="downstream-pilot-test", security_scope="pilot-test",
            text=self.config["questions"][0], focus_entities=[self.claim])
        context = self.pilot.retrieve("retrieve", request=request)
        prepared = self.pilot.prepare_answer("prepare-answer", retrieval_id="retrieve", question_text=self.config["questions"][0])
        return context, prepared, reviewed

    def test_complete_synthetic_mechanics_reopen_at_every_external_pause(self):
        compiled, reviewed = self.compiled()
        self.assertEqual(compiled["state"], "WAIT_SEMANTIC_RESPONSE")
        self.assertEqual(self.backend.view(self.catalog)["edges"], [])
        self.reopen()
        response = fixture_response(self.catalog.get(compiled["pack_id"], "pack"))
        execution = self.execution("compile", "SEMANTIC", response)
        observed = self.pilot.record_semantic_response("response", compile_id="compile", response=response, execution_receipt=execution)
        self.reopen()
        attestations = {ref: attest_observation(self.signer, self.catalog.record(ref, "observation")) for ref in observed["observation_ids"]}
        resolved = self.pilot.resolve_plan("resolve", response_id="response", attestations=attestations)
        self.assertEqual(self.catalog.get(resolved["evaluation_ids"][0], "evaluation")["outcome"], "ABSTAIN")
        self.reopen()
        self.pilot.preflight_plan("preflight", resolve_id="resolve")
        self.reopen()
        authorization = authorize_plan(self.signer, self.catalog.get(resolved["plan_id"], "plan"), self.catalog.hash(resolved["plan_id"]),
                                       reviewed_by="authored-test-reviewer")
        published = self.pilot.publish_plan("publish", preflight_id="preflight", authorization=authorization)
        self.reopen()
        self.assertEqual(self.pilot.publish_plan("publish", preflight_id="preflight", authorization=authorization), published)
        self.assertEqual(self.backend.state()["graph_version"], 2)
        for ref in self.backend.state()["assertions"]:
            self.grants["edge:" + ref] = grant("pilot-test", "private-test")
        request = query(requesting_component="downstream-pilot-test", security_scope="pilot-test",
                        text=self.config["questions"][0], focus_entities=[self.claim])
        self.pilot.retrieve("retrieve", request=request)
        prepared = self.pilot.prepare_answer("prepare-answer", retrieval_id="retrieve", question_text=self.config["questions"][0])
        self.assertEqual(prepared["state"], "WAIT_ANSWER_RESPONSE")
        self.reopen()
        response = json.dumps({"abstain": False, "claims": [{"text": "The authored result is 17 units.",
                                "evidence_ids": [reviewed["evidence_id"]]}]}).encode()
        drafted = self.pilot.record_answer_response("answer", prepared_id="prepare-answer", response=response,
            execution_receipt=self.execution("prepare-answer", "ANSWER", response))
        self.assertEqual(drafted["state"], "WAIT_ANSWER_REVIEW")
        self.reopen()
        at = now()
        payload = self.pilot.answer_review_payload("answer", reviewer="authored-test-reviewer", reviewer_kind="assistant",
                                                   reviewed_at=at, claim_support=[True])
        reviewed_answer = self.pilot.review_answer("answer-review", response_id="answer", receipt=self.signer.issue("SOURCE_STATUS", payload, issued_at=at))
        self.assertEqual(reviewed_answer["state"], "SUPPORTED")
        self.assertFalse(reviewed_answer["review"]["independent_review"])
        self.assertFalse(reviewed_answer["issue_23_complete"])
        self.assertEqual(self.pilot.status()["provider_calls_by_service"], 0)
        self.reopen()
        self.assertEqual(self.pilot.status()["requests"][-1]["state"], "SUPPORTED")

    def test_admission_recovers_commit_before_checkpoint_without_second_write(self):
        self.source()
        authorization = self.signer.issue("SOURCE_STATUS", self.pilot.admission_payload(["review"], expected_version=0))
        def crash():
            raise RuntimeError("authored simulated controller loss")
        with self.assertRaises(RuntimeError):
            self.pilot.admit_sources("admit", review_ids=["review"], expected_version=0, authorization=authorization, after_commit=crash)
        self.assertEqual(self.backend.state()["graph_version"], 1)
        self.reopen()
        receipt = self.pilot.admit_sources("admit", review_ids=["review"], expected_version=0, authorization=authorization)
        self.assertEqual(receipt["receipt"]["version"], 1)
        self.assertTrue(receipt["historical_receipt_only"])
        self.assertEqual(self.backend.state()["graph_version"], 1)

    def test_publication_recovers_commit_before_checkpoint(self):
        resolved, _ = self.resolved()
        self.pilot.preflight_plan("preflight", resolve_id="resolve")
        authorization = authorize_plan(self.signer, self.catalog.get(resolved["plan_id"], "plan"), self.catalog.hash(resolved["plan_id"]),
                                       reviewed_by="authored-test-reviewer")
        def crash():
            raise RuntimeError("simulated process loss after graph commit")
        with self.assertRaises(RuntimeError):
            self.pilot.publish_plan("publish", preflight_id="preflight", authorization=authorization, after_commit=crash)
        self.reopen()
        result = self.pilot.publish_plan("publish", preflight_id="preflight", authorization=authorization)
        self.assertEqual(result["receipt"]["version"], 2)
        self.assertEqual(self.backend.state()["graph_version"], 2)

    def test_changed_request_and_cohort_are_rejected(self):
        self.source()
        with self.assertRaises(ContractError):
            self.pilot.prepare_native_page("prepare", pdf_bytes=self.pdf, source_id="authored-paper", version="v1",
                                          physical_page=2, start=1, end=len(self.native.strip()))
        with self.assertRaises(ContractError):
            self.pilot.prepare_native_page("other", pdf_bytes=self.pdf, source_id="authored-paper", version="v1",
                                          physical_page=1, start=0, end=10)
        self.assertEqual(self.backend.state()["graph_version"], 0)

    def test_lock_and_checkpoint_blob_tampering_fail_closed(self):
        with self.assertRaises(OSError):
            PaperPilot(self.root, config=self.config, catalog=self.catalog, backend=self.backend,
                       service=self.service, budget=self.budget, current_access=self.access)
        self.source()
        self.pilot.db.execute("UPDATE blobs SET body=? WHERE hash=?", (b"corrupt", bytes_digest(self.pdf)))
        with self.assertRaises(ContractError):
            self.pilot._source(self.pilot.requests["review"]["result"]["source_id"], admitted=False)

    def test_unsigned_review_or_execution_receipt_cannot_advance(self):
        self.source()
        args = copy.deepcopy(self.pilot.requests["review"]["args"])
        args["receipt"]["payload"]["reviewer"] = "forged reviewer"
        with self.assertRaises(ContractError):
            self.pilot.accept_source_review("forged", **args)
        # Source stage has no graph side effect.
        self.assertEqual(self.backend.state()["graph_version"], 0)

    def test_permission_revision_and_source_withdrawal_block_resume(self):
        compiled, reviewed = self.compiled()
        response = fixture_response(self.catalog.get(compiled["pack_id"], "pack"))
        receipt = self.execution("compile", "SEMANTIC", response)
        self.acl_revision = "revoked-revision"
        with self.assertRaises(ContractError):
            self.pilot.record_semantic_response("response", compile_id="compile", response=response, execution_receipt=receipt)
        self.acl_revision = "test-acl-v1"
        source_id = reviewed["source_id"]
        action = {"action": "STATUS_CHANGE", "source_id": source_id, "source_hash": self.catalog.hash(source_id),
            "active": False, "permission": "READ", "expected_epoch": 0, "expected_version": 1,
            "security_scope": "pilot-test", "reason": "authored withdrawal test", "tombstone": False}
        self.backend.change_source_status(self.catalog, source_id, active=False, permission="READ", expected_epoch=0,
            expected_version=1, key="withdraw", reason=action["reason"], authorization=self.signer.issue("SOURCE_STATUS", action), trust=self.trust)
        with self.assertRaises(ContractError):
            self.pilot.record_semantic_response("response", compile_id="compile", response=response, execution_receipt=receipt)
        self.assertEqual(self.catalog.all("observation"), [])

    def test_real_mode_rejects_authored_response_source_before_recording(self):
        # A LIVE config is only exercised negatively; no fabricated real observation is made.
        self.pilot.close(); self.backend.close(); self.budget.close()
        self.config["execution_mode"] = "LIVE"
        self.root = self.root / "negative-live"
        self.root.mkdir()
        self.open()
        compiled, _ = self.compiled()
        response = fixture_response(self.catalog.get(compiled["pack_id"], "pack"))
        with self.assertRaises(ContractError):
            self.pilot.record_semantic_response("response", compile_id="compile", response=response,
                execution_receipt=self.execution("compile", "SEMANTIC", response))
        self.assertEqual(self.catalog.all("observation"), [])

    def test_missing_attestation_and_authored_unknown_response_remain_held(self):
        compiled, _ = self.compiled()
        response = b'{"invalid":"authored transport-like error"}'
        observed = self.pilot.record_semantic_response("response", compile_id="compile", response=response,
            execution_receipt=self.execution("compile", "SEMANTIC", response))
        self.assertTrue(all(self.catalog.get(ref, "observation")["status"] == "ERROR" for ref in observed["observation_ids"]))
        with self.assertRaises(ContractError):
            self.pilot.resolve_plan("resolve", response_id="response", attestations={})
        self.assertEqual(self.backend.view(self.catalog)["edges"], [])
        used = self.budget.snapshot()["used"]
        self.reopen()
        self.assertEqual(self.budget.snapshot()["used"], used)
        self.assertFalse(compiled["automatic_retry"])

    def test_cached_source_cannot_replace_signed_review_span(self):
        _, reviewed = self.source()
        source = self.catalog.get(reviewed["source_id"], "source")
        forged = copy.deepcopy(source)
        forged["version"] = "not-reviewed-version"
        forged_id = self.catalog.put("source", forged)
        result = self.pilot.requests["review"]["result"]
        result["source_id"], result["evidence_id"] = forged_id, self.catalog.evidence(forged_id)
        with self.assertRaises(ContractError):
            self.pilot._source(forged_id, admitted=False)

    def test_execution_hash_model_usage_and_duplicate_outcome_rejected(self):
        compiled, _ = self.compiled()
        response = fixture_response(self.catalog.get(compiled["pack_id"], "pack"))
        original = self.execution("compile", "SEMANTIC", response)
        for field, value in (("response_sha256", "f" * 64), ("model", {**original["payload"]["model"], "model_revision": "wrong"})):
            p = copy.deepcopy(original["payload"]); p[field] = value
            with self.assertRaises(ContractError):
                self.pilot.record_semantic_response("bad-" + field, compile_id="compile", response=response,
                    execution_receipt=self.signer.issue("OBSERVATION", p, issued_at=original["issued_at"]))
        self.pilot.record_semantic_response("response", compile_id="compile", response=response, execution_receipt=original)
        with self.assertRaises(ContractError):
            self.pilot.record_semantic_response("duplicate", compile_id="compile", response=response, execution_receipt=original)
        bad = copy.deepcopy(self.pilot.requests["response"]["result"])
        self.pilot.requests["response"]["result"]["observation_ids"] = []
        with self.assertRaises(ContractError):
            self.pilot.resolve_plan("resolve", response_id="response", attestations={})
        self.pilot.requests["response"]["result"] = bad

    def test_export_reserves_budget_and_reopen_does_not_repeat_unknown_call(self):
        compiled, _ = self.compiled()
        before = self.budget.snapshot()["used"]
        self.assertEqual(before["model_calls"], 1)
        self.reopen()
        again = self.pilot.compile_candidates("compile", **self.pilot.requests["compile"]["args"])
        self.assertEqual(again, compiled)
        self.assertEqual(self.budget.snapshot()["used"], before)
        self.assertEqual(self.catalog.all("observation"), [])
        self.assertEqual(self.pilot.status()["requests"][-1]["state"], "WAIT_SEMANTIC_RESPONSE")

    def test_trusted_reviewer_identity_and_revocation_rechecked(self):
        self.source()
        args = self.pilot.requests["review"]["args"]
        p = copy.deepcopy(args["receipt"]["payload"])
        p["reviewer"] = "a different untrusted reviewer"
        with self.assertRaises(ContractError):
            self.pilot.accept_source_review("bad-reviewer", prepared_id="prepare",
                receipt=self.signer.issue("SOURCE_STATUS", p, issued_at=args["receipt"]["issued_at"]))
        self.trust.revoke(self.signer.issuer)
        with self.assertRaises(ContractError):
            self.pilot.accept_source_review("review", **args)

    def test_model_importer_revocation_blocks_new_publication(self):
        # Distinct app identities prove importer revocation is checked separately
        # from source-review and plan-authorization trust.
        compiled, _ = self.compiled()
        importer = Signer.ephemeral("test-importer")
        self.trust.enroll(importer.issuer, IssuerPolicy(importer.public_key(), "test-importer",
            frozenset({"OBSERVATION"}), frozenset({"SEMANTIC_IMPORT"}), frozenset({"pilot-test"}), frozenset({"SYNTHETIC"})))
        response = fixture_response(self.catalog.get(compiled["pack_id"], "pack"))
        receipt = self.execution("compile", "SEMANTIC", response)
        receipt = importer.issue("OBSERVATION", receipt["payload"], issued_at=receipt["issued_at"])
        observed = self.pilot.record_semantic_response("response", compile_id="compile", response=response, execution_receipt=receipt)
        attestations = {ref: attest_observation(self.signer, self.catalog.record(ref, "observation")) for ref in observed["observation_ids"]}
        resolved = self.pilot.resolve_plan("resolve", response_id="response", attestations=attestations)
        self.pilot.preflight_plan("preflight", resolve_id="resolve")
        authorization = authorize_plan(self.signer, self.catalog.get(resolved["plan_id"], "plan"), self.catalog.hash(resolved["plan_id"]),
                                       reviewed_by="authored-test-reviewer")
        self.trust.revoke(importer.issuer)
        with self.assertRaises(ContractError):
            self.pilot.publish_plan("publish", preflight_id="preflight", authorization=authorization)
        self.assertEqual(self.backend.view(self.catalog)["edges"], [])

    def test_answer_cannot_resume_after_access_revision_or_cite_unknown_evidence(self):
        _, _, reviewed = self.answer_request()
        response = json.dumps({"abstain": False, "claims": [{"text": "Authored unsupported statement",
                                "evidence_ids": ["unknown-evidence"]}]}).encode()
        with self.assertRaises(ContractError):
            self.pilot.record_answer_response("bad-answer", prepared_id="prepare-answer", response=response,
                execution_receipt=self.execution("prepare-answer", "ANSWER", response))
        self.acl_revision = "changed-while-model-external"
        response = json.dumps({"abstain": False, "claims": [{"text": "The authored result is 17 units.",
                                "evidence_ids": [reviewed["evidence_id"]]}]}).encode()
        with self.assertRaises(ContractError):
            self.pilot.record_answer_response("answer", prepared_id="prepare-answer", response=response,
                execution_receipt=self.execution("prepare-answer", "ANSWER", response))

    def test_checkpoint_edit_rejects_reopen(self):
        self.source()
        self.pilot.db.execute("UPDATE events SET body=? WHERE seq=2", ('{}',))
        with self.assertRaises(ContractError):
            self.reopen()

    def test_source_review_budget_is_durable_and_not_recharged_on_resume(self):
        self.source()
        self.assertEqual(self.budget.snapshot()["used"]["review_actions"], 1)
        self.reopen()
        self.pilot.accept_source_review("review", **self.pilot.requests["review"]["args"])
        self.assertEqual(self.budget.snapshot()["used"]["review_actions"], 1)

    def test_live_application_config_drift_is_rejected(self):
        self.source()
        self.pilot.config["questions"].append("A new unfrozen question")
        with self.assertRaises(ContractError) as caught:
            self.pilot.accept_source_review("review", **self.pilot.requests["review"]["args"])
        self.assertEqual(caught.exception.code, "PILOT_CONFIG_CHANGED")

    def test_cached_transaction_receipt_requires_authoritative_readback(self):
        self.admit()
        self.pilot.requests["admit"]["result"]["receipt"]["version"] = 900
        with self.assertRaises(ContractError) as caught:
            self.pilot.admit_sources("admit", **self.pilot.requests["admit"]["args"])
        self.assertEqual(caught.exception.code, "PILOT_TRANSACTION")
        self.assertEqual(self.backend.state()["graph_version"], 1)

    def test_source_review_material_has_exact_second_page_and_private_original(self):
        prepared, _ = self.source()
        material = self.pilot.source_review_material("prepare")
        self.assertEqual(material["pdf_bytes"], self.pdf)
        self.assertEqual(material["native_text"], self.native)
        self.assertEqual(bytes_digest(material["page_png_bytes"]), prepared["packet"]["render"]["page_png_sha256"])
        self.assertEqual(material["packet"]["physical_page"], 2)


if __name__ == "__main__":
    unittest.main()
