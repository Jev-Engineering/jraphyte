"""Postpublication withdrawal/denial over an authored synthetic PaperPilot run.

Mechanics only: authored PDFs, responses and reviews; no real paper, model call
or qualification evidence. Each scenario publishes an assertion, obtains a
reviewed cited answer, then changes source status through the lifecycle
service and checks the effect from fresh connections.
"""
import json
import unittest

from trace_gc.canonical import digest
from trace_gc.compiler import now
from trace_gc.errors import ContractError
from trace_gc.paper_pilot_evaluator import PROTOCOL_VERSION, evaluate, export_receipts, question_sha256
from trace_gc.paper_pilot_lifecycle import reconcile_status, status_change_once
from trace_gc.retrieval.contracts import query
from tests import test_paper_pilot as base

CLAIM_TEXT = "The authored result is 17 units."


@unittest.skipIf(base.fitz is None, "optional PyMuPDF fixture dependency unavailable")
class PostpublicationScenarioTests(unittest.TestCase):
    def setUp(self):
        self.f = base.PaperPilotTests("test_checkpoint_edit_rejects_reopen")
        self.f.setUp()
        self.question = self.f.config["questions"][0]

    def tearDown(self):
        self.f.tearDown()

    def supported(self):
        f = self.f
        _, _, reviewed = f.answer_request(grant_decisions=True)
        response = json.dumps({"abstain": False, "claims": [{"text": CLAIM_TEXT,
                               "evidence_ids": [reviewed["evidence_id"]]}]}).encode()
        f.pilot.record_answer_response("answer", prepared_id="prepare-answer", response=response,
                                       execution_receipt=f.execution("prepare-answer", "ANSWER", response))
        self.review_receipt = self.answer_review()
        result = f.pilot.review_answer("answer-review", response_id="answer", receipt=self.review_receipt)
        self.assertEqual(result["state"], "SUPPORTED")
        return reviewed

    def answer_review(self):
        at = now()
        payload = self.f.pilot.answer_review_payload("answer", reviewer="authored-test-reviewer",
            reviewer_kind="assistant", reviewed_at=at, claim_support=[True])
        return self.f.signer.issue("SOURCE_STATUS", payload, issued_at=at)

    def protocol(self, expectation, recovery=()):
        return {"version": PROTOCOL_VERSION, "protocol_id": "authored-postpublication-" + expectation.lower(),
                "questions": [{"question_sha256": question_sha256(self.question), "expectation": expectation,
                               "required_source_ids": ["authored-paper"] if expectation == "SUPPORTED" else []}],
                "expected_assertions": sorted(self.f.backend.state()["assertions"]),
                "required_recovery": list(recovery)}

    def change_status(self, source_id, *, active, permission, key):
        f = self.f
        status = f.backend.statuses()[source_id]
        version = f.backend.state()["graph_version"]
        action = {"action": "STATUS_CHANGE", "source_id": source_id, "source_hash": f.catalog.hash(source_id),
                  "active": active, "permission": permission, "expected_epoch": status["epoch"],
                  "expected_version": version, "security_scope": "pilot-test",
                  "reason": "authored postpublication scenario", "tombstone": False}
        authorization = f.signer.issue("SOURCE_STATUS", action)
        journal = f.root / "status-journal"
        journal.mkdir(exist_ok=True)
        intent = journal / (key + ".intent.json")
        kwargs = dict(source_id=source_id, active=active, permission=permission, expected_epoch=status["epoch"],
                      expected_version=version, key=key, reason=action["reason"], authorization=authorization,
                      intent_path=intent)
        first = status_change_once(f.backend, f.catalog, f.trust, **kwargs)
        return first, authorization, intent, kwargs

    def scenario(self, *, active, permission, name):
        f = self.f
        reviewed = self.supported()
        parent_receipts = export_receipts(f.pilot)
        parent = evaluate(self.protocol("SUPPORTED"), parent_receipts, [])
        self.assertEqual(parent["verdict"], "PASS", parent["rows"])
        published_version = f.backend.state()["graph_version"]
        used = f.budget.snapshot()["used"]

        first, authorization, intent, kwargs = self.change_status(reviewed["source_id"], active=active,
                                                                  permission=permission, key=name)
        f.reopen()  # fresh graph, budget and checkpoint connections
        self.assertEqual(f.backend.state()["graph_version"], published_version + 1)
        self.assertEqual(reconcile_status(f.backend, intent_path=intent, authorization=authorization)["receipt"],
                         first["receipt"])
        self.assertTrue(status_change_once(f.backend, f.catalog, f.trust, **kwargs)["replayed"])
        self.assertEqual(f.backend.state()["graph_version"], published_version + 1)
        self.assertTrue(all(not row["active"] for row in f.backend.state()["assertions"].values()))
        self.assertEqual(f.backend.view(f.catalog)["edges"], [])

        # The cached supported answer cannot be re-reviewed or re-attested under the changed status.
        for review_id in ("answer-review", "answer-review-after-" + name):
            with self.assertRaises(ContractError) as caught:
                f.pilot.review_answer(review_id, response_id="answer", receipt=self.review_receipt)
            self.assertEqual(caught.exception.code, "PILOT_STALE")

        # The private journal retains lineage. The evaluator marks rows invalidated and withholds it.
        stale = export_receipts(f.pilot)
        stale_report = evaluate(self.protocol("SUPPORTED"), stale, [])
        self.assertEqual(stale_report["verdict"], "HOLD")
        self.assertEqual(stale_report["rows"]["questions"][0]["status"], "INVALIDATED")
        self.assertEqual({r["status"] for r in stale_report["rows"]["assertions"]}, {"INVALIDATED"})
        self.assertEqual(stale_report["metrics"]["citation_chains"]["invalidated"], 1)
        self.assertTrue(all("transaction_event_hash" not in a for a in stale["assertions"]))
        original_events = {row["transaction_event_hash"] for row in parent_receipts["assertions"]}
        journal_events = {row["body"]["event_hash"] for row in f.backend.load_catalog().all("transaction")}
        self.assertTrue(original_events)
        self.assertNotIn(None, original_events)
        self.assertLessEqual(original_events, journal_events)

        # A fresh default retrieval excludes the evidence and abstains without exporting a model request.
        request = query(requesting_component="downstream-pilot-test", security_scope="pilot-test",
                        text=self.question, focus_entities=[f.claim])
        f.pilot.retrieve("retrieve-after-" + name, request=request)
        fresh = f.pilot.prepare_answer("prepare-after-" + name, retrieval_id="retrieve-after-" + name,
                                       question_text=self.question)
        self.assertEqual(fresh["state"], "ABSTAIN_NO_AUTHORIZED_EVIDENCE")
        self.assertEqual(fresh["draft"]["provider_calls"], 0)
        self.assertEqual(f.budget.snapshot()["used"]["model_calls"], used["model_calls"])

        scenario_report = evaluate(self.protocol("ABSTAIN"), export_receipts(f.pilot), [])
        row = scenario_report["rows"]["questions"][0]
        self.assertEqual((row["status"], row["reason"]), ("PASS", "NO_AUTHORIZED_EVIDENCE"))
        self.assertEqual(scenario_report["evidence_class"], "AUTHORED_SYNTHETIC_MECHANICS_ONLY")
        for text in (CLAIM_TEXT, self.question, f.native.strip()):
            self.assertNotIn(text, json.dumps(scenario_report))

        # The scenario outcome feeds the parent's recovery row; it stays mechanics-only.
        recovery = [{"scenario": name, "status": "PASS", "receipt_sha256": digest(scenario_report),
                     "evidence_class": "AUTHORED_SYNTHETIC"}]
        combined = evaluate(self.protocol("SUPPORTED", recovery=[name, "interrupted_publication"]),
                            parent_receipts, recovery)
        self.assertEqual(combined["metrics"]["recovery"]["pass"], 1)
        self.assertEqual(combined["metrics"]["recovery"]["not_run"], 1)
        self.assertEqual(combined["verdict"], "HOLD")
        self.assertFalse(combined["qualifies_issue_23"])

    def test_withdrawal_after_publication_invalidates_assertion_and_answer(self):
        self.scenario(active=False, permission="READ", name="source_withdrawal")
        self.assertFalse(next(iter(self.f.backend.statuses().values()))["active"])

    def test_permission_denial_after_publication_invalidates_assertion_and_answer(self):
        self.scenario(active=True, permission="DENIED", name="permission_denial")
        self.assertEqual(next(iter(self.f.backend.statuses().values()))["permission"], "DENIED")


if __name__ == "__main__":
    unittest.main()
