"""Aggregate pilot evaluator over authored synthetic receipts; mechanics only, no real pilot evidence."""
import copy
import io
import json
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
import tempfile
import unittest

from trace_gc.canonical import text_digest
from trace_gc.cli import main
from trace_gc.compiler import now
from trace_gc.errors import ContractError
from trace_gc.paper_pilot_evaluator import (
    PROTOCOL_VERSION, RECEIPTS_VERSION, _evaluate_sections, evaluate, export_receipts, question_sha256,
)
from trace_gc.pdf_image_evidence import REPRESENTATION as IMAGE
from trace_gc.trust import IssuerPolicy, Signer
from tests import test_paper_pilot as base

H = "a" * 64
QUESTION = question_sha256("What did the authored experiment measure?")
UNSUPPORTED = question_sha256("What did the authored experiment cost?")


def protocol(*, questions=None, assertions=("cand-1",), recovery=()):
    return {"version": PROTOCOL_VERSION, "protocol_id": "authored-synthetic-protocol-v1",
            "questions": questions if questions is not None else [
                {"question_sha256": QUESTION, "expectation": "SUPPORTED", "required_source_ids": ["paper-a"]},
                {"question_sha256": UNSUPPORTED, "expectation": "ABSTAIN", "required_source_ids": []}],
            "expected_assertions": list(assertions), "required_recovery": list(recovery)}


def receipts():
    """Hand-authored receipt rows: one supported answer, one abstention, one published assertion."""
    evidence = {"evidence_id": "evidence:" + "1" * 64, "evidence_sha256": "1" * 64,
                "source_snapshot_id": "source:" + "2" * 64, "source_id_sha256": text_digest("paper-a"), "source_hash": "2" * 64,
                "representation": "reviewed-native-pdf-page-v1", "raw_document_sha256": "3" * 64,
                "physical_page": 2, "page_png_sha256": "4" * 64, "crop_png_sha256": None, "currently_readable": True}
    answer = {"retrieval_id_sha256": text_digest("retrieve-q1"), "prepare_id_sha256": text_digest("prepare-q1"), "response_id_sha256": text_digest("answer-q1"),
              "review_id_sha256": text_digest("review-q1"), "question_sha256": QUESTION, "state": "SUPPORTED", "abstention_reason": None,
              "claims": [{"evidence_ids": [evidence["evidence_id"]], "support": True}],
              "reviewer_kind": "assistant", "answer_graph_version": 2, "graph_version_current": True, "retrieval_context_current": True}
    abstain = {"retrieval_id_sha256": text_digest("retrieve-q2"), "prepare_id_sha256": text_digest("prepare-q2"), "response_id_sha256": None, "review_id_sha256": None,
               "question_sha256": UNSUPPORTED, "state": "ABSTAIN_NO_AUTHORIZED_EVIDENCE",
               "abstention_reason": "NO_AUTHORIZED_EVIDENCE", "claims": [], "reviewer_kind": None,
               "answer_graph_version": 2, "graph_version_current": True, "retrieval_context_current": True}
    assertion = {"assertion_id_sha256": text_digest("cand-1"), "currently_readable": True, "active": True,
                 "evidence_ids": [evidence["evidence_id"]], "transaction_event_hash": "7" * 64,
                 "transaction_version": 2, "plan_id_sha256": "8" * 64, "resolution_id_sha256": "9" * 64,
                 "resolution_outcome": "SELECTED", "observation_ids_sha256": ["b" * 64],
                 "observations_ok": True}
    return {"version": RECEIPTS_VERSION, "run_id_sha256": text_digest("authored-pilot"), "execution_mode": "SYNTHETIC",
            "checkpoint_head": H, "graph": {"graph_version": 2, "journal_head": "7" * 64, "state_sha256": H},
            "source_reviews": [{"request_id_sha256": text_digest("review"), "source_snapshot_id": evidence["source_snapshot_id"],
                                "source_id_sha256": text_digest("paper-a"), "representation": "reviewed-native-pdf-page-v1",
                                "reviewer_kind": "assistant", "all_checks_passed": True, "independent_review": False}],
            "assertions": [assertion], "evidence": [evidence], "answers": [answer, abstain],
            "provider_calls_by_exporter": 0}


def scored_rows(value, section):
    rows = _evaluate_sections(protocol(), value, [])[section]
    return {row.get("question_sha256") or row.get("assertion_id_sha256"): row for row in rows}


class AggregateEvaluatorTests(unittest.TestCase):
    def test_complete_authored_rows_pass_but_remain_mechanics_only(self):
        report = evaluate(protocol(), receipts(), [])
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["evidence_class"], "AUTHORED_SYNTHETIC_MECHANICS_ONLY")
        self.assertFalse(report["qualifies_issue_23"])
        self.assertEqual(report["metrics"]["questions"]["pass"], 2)
        self.assertEqual(report["metrics"]["abstention"], {"denominator": 1, "pass": 1, "fail": 0, "hold": 0,
                                                            "not_run": 0, "invalidated": 0})
        self.assertEqual(report["metrics"]["source_reviews"]["independent"], 0)
        encoded = json.dumps(report)
        for fingerprint in (QUESTION, UNSUPPORTED, text_digest("cand-1"), text_digest("paper-a"),
                            text_digest("retrieve-q1"), text_digest("authored-pilot")):
            self.assertNotIn(fingerprint, encoded)
        self.assertEqual(report["rows"]["citation_chains"], [
            {"count": 1, "reason": "CITATION_EVIDENCE_SOURCE_PAGE", "status": "PASS", "evidence_class": None}])

    def test_missing_outputs_are_not_run_with_honest_denominators(self):
        empty = receipts()
        empty["answers"], empty["assertions"] = [], []
        report = evaluate(protocol(recovery=["withdrawal", "permission_denial"]), empty,
                          [{"scenario": "withdrawal", "status": "PASS", "receipt_sha256": H, "evidence_class": "REAL_RUN"}])
        self.assertEqual(report["verdict"], "HOLD")
        self.assertEqual(report["metrics"]["questions"]["not_run"], 2)
        self.assertEqual(report["metrics"]["questions"]["denominator"], 2)
        self.assertEqual(report["metrics"]["assertions"]["not_run"], 1)
        self.assertEqual(report["metrics"]["recovery"], {"denominator": 2, "pass": 1, "fail": 0, "hold": 0,
                                                          "not_run": 1, "invalidated": 0})

    def test_adversarial_answers_fail_not_pass(self):
        cases = {
            "REVIEW_REJECTED_CLAIM": lambda r: r["answers"][0].update(state="REJECTED_UNSUPPORTED_CLAIM"),
            "ABSTAINED_ON_SUPPORTED_QUESTION:MODEL_ABSTAINED": lambda r: r["answers"][0].update(
                state="ABSTAIN_MODEL", abstention_reason="MODEL_ABSTAINED", claims=[], review_id_sha256=None, reviewer_kind=None),
            "SUPPORT_JUDGMENT_INCOMPLETE": lambda r: r["answers"][0]["claims"][0].update(support=None),
            "REQUIRED_SOURCE_NOT_CITED": lambda r: r["evidence"][0].update(source_id_sha256=text_digest("paper-b")),
            "INCOMPLETE_CITATION_CHAIN:MISSING_PAGE_LINEAGE": lambda r: r["evidence"][0].update(page_png_sha256=None),
            "INCOMPLETE_CITATION_CHAIN:MISSING_CROP_LINEAGE": lambda r: r["evidence"][0].update(representation=IMAGE),
            "INCOMPLETE_ANSWER_REVIEW_CHAIN": lambda r: r["answers"][0].update(review_id_sha256=None),
            "INCOMPLETE_CITATION_CHAIN:MISSING_EVIDENCE": lambda r: r["answers"][0]["claims"][0].update(
                evidence_ids=["evidence:unknown"]),
        }
        for reason, mutate in cases.items():
            with self.subTest(reason=reason):
                value = receipts(); mutate(value)
                report = evaluate(protocol(), value, [])
                self.assertEqual(report["verdict"], "FAIL")
                self.assertEqual(scored_rows(value, "questions")[QUESTION]["reason"], reason)

    def test_answered_unsupported_question_and_graph_gaps_fail(self):
        value = receipts()
        value["answers"][1].update(state="SUPPORTED", abstention_reason=None)
        self.assertEqual(scored_rows(value, "questions")[UNSUPPORTED]["reason"],
                         "ANSWERED_UNSUPPORTED_QUESTION")
        for field, bad in (("transaction_event_hash", None), ("transaction_event_hash", "e" * 64), ("resolution_outcome", "REJECTED"),
                           ("observations_ok", False), ("resolution_id_sha256", None),
                           ("transaction_version", None), ("transaction_version", 3), ("observation_ids_sha256", [])):
            with self.subTest(field=field):
                value = receipts(); value["assertions"][0][field] = bad
                self.assertEqual(scored_rows(value, "assertions")[question_sha256("cand-1")]["reason"],
                                 "INCOMPLETE_GRAPH_CHAIN")
        value = receipts()
        value["assertions"].append({**value["assertions"][0], "assertion_id_sha256": text_digest("cand-unexpected")})
        report = evaluate(protocol(), value, [])
        self.assertEqual(scored_rows(value, "assertions")[question_sha256("cand-unexpected")]["reason"], "UNEXPECTED_ASSERTION")

    def test_answer_version_is_compared_with_receipt_graph_version(self):
        value = receipts()
        value["answers"][0].update(answer_graph_version=1, graph_version_current=False)
        question = scored_rows(value, "questions")[QUESTION]
        self.assertEqual(question["reason"], "GRAPH_CHANGED_AFTER_ANSWER_REFRESH_REQUIRED")

    def test_supported_answer_without_context_readback_is_held(self):
        value = receipts()
        del value["answers"][0]["retrieval_context_current"]
        question = scored_rows(value, "questions")[QUESTION]
        self.assertEqual(question["status"], "HOLD")

    def test_abstention_requires_current_context_and_completed_stage(self):
        for changes, status, reason in (
            ({"answer_graph_version": 1, "graph_version_current": False}, "HOLD", "ABSTENTION_CONTEXT_REFRESH_REQUIRED"),
            ({"retrieval_context_current": False}, "HOLD", "ABSTENTION_CONTEXT_REFRESH_REQUIRED"),
            ({"prepare_id_sha256": None}, "FAIL", "INCOMPLETE_ABSTENTION_STAGE"),
            ({"response_id_sha256": text_digest("unexpected-response")}, "FAIL", "INCOMPLETE_ABSTENTION_STAGE"),
            ({"state": "ABSTAIN_MODEL", "abstention_reason": "MODEL_ABSTAINED"},
             "FAIL", "INCOMPLETE_ABSTENTION_STAGE"),
            ({"state": "ABSTAIN_MODEL", "abstention_reason": "MODEL_ABSTAINED", "response_id_sha256": text_digest("model-response")},
             "PASS", "MODEL_ABSTAINED"),
        ):
            with self.subTest(changes=changes):
                value = receipts()
                value["answers"][1].update(changes)
                question = scored_rows(value, "questions")[UNSUPPORTED]
                self.assertEqual((question["status"], question["reason"]), (status, reason))

    def test_withdrawn_source_invalidates_supported_answer_and_assertion(self):
        value = receipts()
        value["evidence"][0] = {"evidence_id": value["evidence"][0]["evidence_id"], "currently_readable": False}
        value["assertions"][0]["active"] = False
        report = evaluate(protocol(), value, [])
        self.assertEqual(report["verdict"], "HOLD")
        self.assertEqual(scored_rows(value, "questions")[QUESTION]["status"], "INVALIDATED")
        self.assertEqual(scored_rows(value, "assertions")[question_sha256("cand-1")]["status"], "INVALIDATED")
        self.assertEqual(report["metrics"]["citation_chains"]["invalidated"], 1)

    def test_latest_attempt_per_question_is_scored(self):
        value = receipts()
        later = copy.deepcopy(value["answers"][0])
        later.update(retrieval_id_sha256=text_digest("retrieve-q1-again"), prepare_id_sha256=text_digest("prepare-q1-again"), state="ABSTAIN_NO_AUTHORIZED_EVIDENCE",
                     abstention_reason="NO_AUTHORIZED_EVIDENCE", claims=[], response_id_sha256=None, review_id_sha256=None, reviewer_kind=None)
        value["answers"].append(later)
        self.assertEqual(scored_rows(value, "questions")[QUESTION]["retrieval_id_sha256"], question_sha256("retrieve-q1-again"))

    def test_text_fields_undeclared_inputs_and_duplicates_are_rejected(self):
        mutations = [
            lambda r: r["evidence"][0].update(quote="The authored experiment measured 17 units."),
            lambda r: r["answers"][0]["claims"][0].update(claim_sha256="The authored result is 17 units."),
            lambda r: r["source_reviews"][0].update(source_id_sha256="a free text sentence with spaces"),
            lambda r: r["source_reviews"][0].update(independent_review=True),
            lambda r: r["evidence"].append(copy.deepcopy(r["evidence"][0])),
            lambda r: r["evidence"][0].update(representation="unknown-representation"),
            lambda r: r["answers"].append(copy.deepcopy(r["answers"][0])),
            lambda r: r["graph"].update(journal_head=None),
            lambda r: r.update(source_reviews={}),
            lambda r: r.update(execution_mode="PRODUCTION"),
            lambda r: r.update(provider_calls_by_exporter=False),
            lambda r: r["answers"][0].update(state="synthetic-private-state"),
            lambda r: r["answers"][1].update(abstention_reason="synthetic-private-reason"),
            lambda r: r["answers"][1].update(state="SUPPORTED"),
            lambda r: r["answers"][1].update(claims=r["answers"][0]["claims"]),
            lambda r: r["answers"][0].update(answer_graph_version=1),
        ]
        for i, mutate in enumerate(mutations):
            with self.subTest(case=i):
                value = receipts(); mutate(value)
                with self.assertRaises(ContractError) as caught:
                    evaluate(protocol(), value, [])
                self.assertEqual(caught.exception.code, "EVALUATOR_INPUT")
        with self.assertRaises(ContractError):
            evaluate(protocol(), receipts(), [{"scenario": "undeclared", "status": "PASS", "receipt_sha256": H,
                                               "evidence_class": "REAL_RUN"}])
        with self.assertRaises(ContractError):
            evaluate(protocol(questions=[]), receipts(), [])

    def test_shipped_example_protocol_is_valid_and_unrun_rows_hold(self):
        example = json.loads((Path(__file__).resolve().parents[1] / "examples/paper_pilot/evaluation_protocol.synthetic.json").read_text())
        empty = receipts()
        empty["answers"], empty["assertions"] = [], []
        report = evaluate(example, empty, [])
        self.assertEqual(report["verdict"], "HOLD")
        self.assertEqual(report["metrics"]["recovery"]["not_run"], len(example["required_recovery"]))

    def test_cli_writes_report_and_reports_structured_errors(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "protocol.json").write_text(json.dumps(protocol()))
            (root / "receipts.json").write_text(json.dumps(receipts()))
            out = io.StringIO()
            with redirect_stdout(out):
                code = main(["paper-pilot", "evaluate", str(root / "receipts.json"), "--protocol",
                             str(root / "protocol.json"), "--output", str(root / "report.json")])
            self.assertEqual(code, 0)
            summary = json.loads(out.getvalue())
            self.assertEqual(summary["verdict"], "PASS")
            self.assertFalse(summary["qualifies_issue_23"])
            self.assertNotIn("output", summary)
            self.assertEqual(json.loads((root / "report.json").read_text())["verdict"], "PASS")
            bad = receipts(); bad["evidence"][0]["quote"] = "smuggled"
            (root / "receipts.json").write_text(json.dumps(bad))
            err = io.StringIO()
            with redirect_stderr(err):
                code = main(["paper-pilot", "evaluate", str(root / "receipts.json"), "--protocol",
                             str(root / "protocol.json"), "--output", str(root / "report2.json")])
            self.assertEqual(code, 1)
            self.assertEqual(json.loads(err.getvalue())["code"], "EVALUATOR_INPUT")

            (root / "receipts.json").write_text('{"fixture-private-key": 1, "fixture-private-key": 2}')
            err = io.StringIO()
            with redirect_stderr(err):
                code = main(["paper-pilot", "evaluate", str(root / "receipts.json"), "--protocol",
                             str(root / "protocol.json"), "--output", str(root / "report2.json")])
            self.assertEqual(code, 1)
            self.assertEqual(json.loads(err.getvalue())["code"], "EVALUATOR_INPUT")
            self.assertNotIn("fixture-private-key", err.getvalue())

            (root / "receipts.json").write_text(json.dumps(receipts()))
            for field, malformed in (("required_source_ids", [[]]), ("expectation", [])):
                with self.subTest(field=field):
                    bad_protocol = protocol()
                    bad_protocol["questions"][0][field] = malformed
                    (root / "protocol.json").write_text(json.dumps(bad_protocol))
                    err = io.StringIO()
                    with redirect_stderr(err):
                        code = main(["paper-pilot", "evaluate", str(root / "receipts.json"), "--protocol",
                                     str(root / "protocol.json"), "--output", str(root / "report2.json")])
                    self.assertEqual(code, 1)
                    self.assertEqual(json.loads(err.getvalue())["code"], "EVALUATOR_INPUT")
            self.assertFalse((root / "report2.json").exists())


@unittest.skipIf(base.fitz is None, "optional PyMuPDF fixture dependency unavailable")
class PilotExportTests(unittest.TestCase):
    """Exports rows from an actual authored-synthetic PaperPilot run, then evaluates them."""

    def setUp(self):
        self.f = base.PaperPilotTests("test_checkpoint_edit_rejects_reopen")
        self.f.setUp()

    def tearDown(self):
        self.f.tearDown()

    def supported(self, reviewer_signer=None):
        f = self.f
        reviewer_signer = reviewer_signer or f.signer
        _, _, reviewed = f.answer_request(grant_decisions=True)
        response = json.dumps({"abstain": False, "claims": [{"text": "The authored result is 17 units.",
                               "evidence_ids": [reviewed["evidence_id"]]}]}).encode()
        f.pilot.record_answer_response("answer", prepared_id="prepare-answer", response=response,
                                       execution_receipt=f.execution("prepare-answer", "ANSWER", response))
        at = now()
        payload = f.pilot.answer_review_payload("answer", reviewer="authored-test-reviewer", reviewer_kind="assistant",
                                                reviewed_at=at, claim_support=[True])
        f.pilot.review_answer("answer-review", response_id="answer",
                              receipt=reviewer_signer.issue("SOURCE_STATUS", payload, issued_at=at))
        return reviewed

    def frozen(self):
        assertions = sorted(self.f.backend.state()["assertions"])
        return protocol(questions=[{"question_sha256": question_sha256(self.f.config["questions"][0]),
                                    "expectation": "SUPPORTED", "required_source_ids": ["authored-paper"]}],
                        assertions=assertions)

    def test_export_from_supported_run_is_sanitized_and_complete(self):
        self.supported()
        exported = export_receipts(self.f.pilot)
        encoded = json.dumps(exported)
        for text in (self.f.native.strip(), "The authored result is 17 units.", self.f.config["questions"][0]):
            self.assertNotIn(text, encoded)
        self.assertEqual(exported["answers"][0]["state"], "SUPPORTED")
        self.assertNotIn(text_digest("The authored result is 17 units."), encoded)
        self.assertEqual(exported["evidence"][0]["physical_page"], 2)
        report = evaluate(self.frozen(), exported, [])
        self.assertEqual(report["verdict"], "PASS", report["rows"])
        self.assertEqual(report["evidence_class"], "AUTHORED_SYNTHETIC_MECHANICS_ONLY")
        self.assertNotIn(self.f.native.strip(), json.dumps(report))
        self.f.reopen()
        self.assertEqual(export_receipts(self.f.pilot), exported)
        source_ref = exported["evidence"][0]["source_snapshot_id"]
        self.f.grants.pop("source:" + source_ref)
        self.assertEqual(self.f.pilot.backend.statuses()[source_ref]["permission"], "READ")
        denied_receipts = export_receipts(self.f.pilot)
        denied = evaluate(self.frozen(), denied_receipts, [])
        self.assertEqual(denied["metrics"]["questions"]["invalidated"], 1)
        self.assertEqual(denied["metrics"]["citation_chains"]["invalidated"], 1)
        self.assertEqual(denied["metrics"]["assertions"]["invalidated"], 1)
        self.assertEqual(denied_receipts["evidence"], [])
        self.assertEqual(denied_receipts["answers"][0]["claims"], [
            {"evidence_ids": [], "support": None, "withheld_reason": "SOURCE_NOT_CURRENTLY_READABLE"}])
        for secret in (source_ref, exported["evidence"][0]["raw_document_sha256"],
                       text_digest("The authored result is 17 units.")):
            self.assertNotIn(secret, json.dumps(denied_receipts))
            self.assertNotIn(secret, json.dumps(denied))

    def test_export_requires_durable_review_to_match_signed_judgments(self):
        self.supported()
        review = self.f.pilot.requests["answer-review"]["result"]["review"]
        original = review["claim_support"]
        try:
            review["claim_support"] = []
            with self.assertRaisesRegex(ContractError, "durable answer review differs"):
                export_receipts(self.f.pilot)
        finally:
            review["claim_support"] = original
        self.assertEqual(export_receipts(self.f.pilot)["answers"][0]["claims"][0]["support"], True)

    def test_export_applies_current_answer_reviewer_revocation(self):
        signer = Signer.ephemeral("authored-answer-review-only")
        self.f.trust.enroll(signer.issuer, IssuerPolicy(signer.public_key(), "authored-test-reviewer",
            frozenset({"SOURCE_STATUS"}), frozenset({"PAPER_ANSWER_REVIEW"}),
            frozenset({"pilot-test"}), frozenset({"SYNTHETIC"}), can_review=True))
        self.supported(signer)
        stamp = self.f.pilot._stamp()
        self.assertEqual(evaluate(self.frozen(), export_receipts(self.f.pilot), [])["verdict"], "PASS")
        self.f.trust.revoke(signer.issuer)
        self.assertEqual(self.f.pilot._stamp(), stamp)
        with self.assertRaisesRegex(ContractError, "UNTRUSTED_ISSUER"):
            export_receipts(self.f.pilot)

    def test_edge_grant_removal_holds_citation_even_with_readable_source(self):
        self.supported()
        before = export_receipts(self.f.pilot)
        edge = next(iter(self.f.backend.state()["assertions"]))
        self.assertEqual(before["assertions"][0]["assertion_id_sha256"], text_digest(edge))
        self.f.grants.pop("edge:" + edge)
        after = export_receipts(self.f.pilot)
        source = before["evidence"][0]["source_snapshot_id"]
        self.assertEqual(self.f.backend.statuses()[source]["permission"], "READ")
        self.assertEqual(after["evidence"], [])
        self.assertEqual(after["answers"][0]["claims"], [
            {"evidence_ids": [], "support": None, "withheld_reason": "CITATION_CONTEXT_REFRESH_REQUIRED"}])
        self.assertEqual(after["assertions"][0],
                         {"assertion_id_sha256": text_digest(edge), "currently_readable": False})
        report = evaluate(self.frozen(), after, [])
        self.assertEqual(report["metrics"]["questions"]["hold"], 1)
        self.assertEqual(report["metrics"]["citation_chains"]["hold"], 1)
        self.assertEqual(report["metrics"]["assertions"]["invalidated"], 1)

    def test_denied_decision_withholds_lineage_even_with_edge_and_source_access(self):
        self.supported()
        before = export_receipts(self.f.pilot)
        self.assertIsNotNone(before["assertions"][0]["transaction_event_hash"])
        observation = self.f.pilot.requests["response"]["result"]["observation_ids"][0]
        self.f.grants.pop("decision:" + observation)
        after = export_receipts(self.f.pilot)
        self.assertEqual(after["assertions"], [
            {"assertion_id_sha256": before["assertions"][0]["assertion_id_sha256"], "currently_readable": False}])
        self.assertEqual(after["evidence"], [])
        public = evaluate(self.frozen(), after, [])
        self.assertEqual(public["metrics"]["assertions"]["invalidated"], 1)
        self.assertNotIn(before["assertions"][0]["assertion_id_sha256"], json.dumps(public))

    def test_denied_assertion_does_not_export_its_only_evidence(self):
        self.f.answer_request(grant_decisions=True)
        edge = next(iter(self.f.backend.state()["assertions"]))
        self.assertTrue(export_receipts(self.f.pilot)["evidence"])
        self.f.grants.pop("edge:" + edge)
        exported = export_receipts(self.f.pilot)
        self.assertEqual(exported["evidence"], [])
        self.assertEqual(exported["assertions"],
                         [{"assertion_id_sha256": text_digest(edge), "currently_readable": False}])

    def test_export_abstention_binds_retrieval_graph_and_access(self):
        f = self.f
        text = f.config["questions"][0]
        request = base.query(requesting_component="downstream-pilot-test", security_scope="pilot-test",
                             text=text, focus_entities=[f.claim])
        retrieval_id = "récupération question"
        f.pilot.retrieve(retrieval_id, request=request)
        empty = export_receipts(f.pilot)["answers"][0]
        self.assertEqual(empty["state"], "CONTEXT_ONLY")
        self.assertEqual(empty["retrieval_id_sha256"], text_digest(retrieval_id))
        self.assertEqual(empty["answer_graph_version"], 0)

        f.pilot.prepare_answer("prepare-answer", retrieval_id=retrieval_id, question_text=text)
        frozen = protocol(questions=[{"question_sha256": question_sha256(text), "expectation": "ABSTAIN",
                                      "required_source_ids": []}], assertions=[])
        self.assertEqual(evaluate(frozen, export_receipts(f.pilot), [])["verdict"], "PASS")
        f.acl_revision = "synthetic-changed-access"
        exported = export_receipts(f.pilot)
        self.assertTrue(exported["answers"][0]["graph_version_current"])
        self.assertFalse(exported["answers"][0]["retrieval_context_current"])
        self.assertEqual(evaluate(frozen, exported, [])["verdict"], "HOLD")

    def test_export_before_answers_holds_with_not_run_rows(self):
        self.f.compiled()
        report = evaluate(protocol(questions=[{"question_sha256": question_sha256(self.f.config["questions"][0]),
                                               "expectation": "SUPPORTED", "required_source_ids": ["authored-paper"]}],
                                   assertions=["authored-pilot:compile:candidate:0"]),
                          export_receipts(self.f.pilot), [])
        self.assertEqual(report["verdict"], "HOLD")
        self.assertEqual(report["metrics"]["questions"]["not_run"], 1)
        self.assertEqual(report["metrics"]["assertions"]["not_run"], 1)


if __name__ == "__main__":
    unittest.main()
