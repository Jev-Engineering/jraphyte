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
from trace_gc.paper_pilot_evaluator import PROTOCOL_VERSION, RECEIPTS_VERSION, evaluate, export_receipts, question_sha256
from trace_gc.pdf_image_evidence import REPRESENTATION as IMAGE
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
                "source_snapshot_id": "source:" + "2" * 64, "source_id": "paper-a", "source_hash": "2" * 64,
                "representation": "reviewed-native-pdf-page-v1", "raw_document_sha256": "3" * 64,
                "physical_page": 2, "page_png_sha256": "4" * 64, "crop_png_sha256": None, "currently_readable": True}
    answer = {"retrieval_id": "retrieve-q1", "prepare_id": "prepare-q1", "response_id": "answer-q1",
              "review_id": "review-q1", "question_sha256": QUESTION, "state": "SUPPORTED", "abstention_reason": None,
              "claims": [{"claim_sha256": "5" * 64, "evidence_ids": [evidence["evidence_id"]], "support": True}],
              "reviewer_kind": "assistant", "answer_graph_version": 2, "graph_version_current": True}
    abstain = {"retrieval_id": "retrieve-q2", "prepare_id": "prepare-q2", "response_id": None, "review_id": None,
               "question_sha256": UNSUPPORTED, "state": "ABSTAIN_NO_AUTHORIZED_EVIDENCE",
               "abstention_reason": "NO_AUTHORIZED_EVIDENCE", "claims": [], "reviewer_kind": None,
               "answer_graph_version": 2, "graph_version_current": True}
    assertion = {"assertion_id": "cand-1", "claim_id": "claim:" + "6" * 64, "active": True,
                 "evidence_ids": [evidence["evidence_id"]], "transaction_event_hash": "7" * 64,
                 "transaction_version": 2, "plan_id": "plan:" + "8" * 64, "resolution_id": "resolution:" + "9" * 64,
                 "resolution_outcome": "SELECTED", "observation_ids": ["observation:" + "b" * 64],
                 "observations_ok": True}
    return {"version": RECEIPTS_VERSION, "run_id": "authored-pilot", "execution_mode": "SYNTHETIC",
            "checkpoint_head": H, "graph": {"graph_version": 2, "journal_head": H, "state_sha256": H},
            "source_reviews": [{"request_id": "review", "source_snapshot_id": evidence["source_snapshot_id"],
                                "source_id": "paper-a", "representation": "reviewed-native-pdf-page-v1",
                                "reviewer_kind": "assistant", "all_checks_passed": True, "independent_review": False}],
            "assertions": [assertion], "evidence": [evidence], "answers": [answer, abstain],
            "provider_calls_by_exporter": 0}


def rows(report, section):
    return {r.get("question_sha256") or r.get("assertion_id") or r.get("scenario"): r for r in report["rows"][section]}


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
                state="ABSTAIN_MODEL", abstention_reason="MODEL_ABSTAINED", claims=[]),
            "SUPPORT_JUDGMENT_INCOMPLETE": lambda r: r["answers"][0]["claims"][0].update(support=None),
            "REQUIRED_SOURCE_NOT_CITED": lambda r: r["evidence"][0].update(source_id="paper-b"),
            "INCOMPLETE_CITATION_CHAIN:MISSING_PAGE_LINEAGE": lambda r: r["evidence"][0].update(page_png_sha256=None),
            "INCOMPLETE_CITATION_CHAIN:MISSING_CROP_LINEAGE": lambda r: r["evidence"][0].update(representation=IMAGE),
            "INCOMPLETE_ANSWER_REVIEW_CHAIN": lambda r: r["answers"][0].update(review_id=None),
            "INCOMPLETE_CITATION_CHAIN:MISSING_EVIDENCE": lambda r: r["answers"][0]["claims"][0].update(
                evidence_ids=["evidence:unknown"]),
        }
        for reason, mutate in cases.items():
            with self.subTest(reason=reason):
                value = receipts(); mutate(value)
                report = evaluate(protocol(), value, [])
                self.assertEqual(report["verdict"], "FAIL")
                self.assertEqual(rows(report, "questions")[QUESTION]["reason"], reason)

    def test_answered_unsupported_question_and_graph_gaps_fail(self):
        value = receipts()
        value["answers"][1].update(state="SUPPORTED", abstention_reason=None)
        self.assertEqual(rows(evaluate(protocol(), value, []), "questions")[UNSUPPORTED]["reason"],
                         "ANSWERED_UNSUPPORTED_QUESTION")
        for field, bad in (("transaction_event_hash", None), ("resolution_outcome", "REJECTED"),
                           ("observations_ok", False), ("resolution_id", None),
                           ("transaction_version", None), ("transaction_version", 3), ("observation_ids", [])):
            with self.subTest(field=field):
                value = receipts(); value["assertions"][0][field] = bad
                self.assertEqual(rows(evaluate(protocol(), value, []), "assertions")["cand-1"]["reason"],
                                 "INCOMPLETE_GRAPH_CHAIN")
        value = receipts()
        value["assertions"].append({**value["assertions"][0], "assertion_id": "cand-unexpected"})
        report = evaluate(protocol(), value, [])
        self.assertEqual(rows(report, "assertions")["cand-unexpected"]["reason"], "UNEXPECTED_ASSERTION")

    def test_answer_version_is_compared_with_receipt_graph_version(self):
        value = receipts()
        value["answers"][0].update(answer_graph_version=1, graph_version_current=False)
        question = rows(evaluate(protocol(), value, []), "questions")[QUESTION]
        self.assertEqual(question["reason"], "GRAPH_CHANGED_AFTER_ANSWER_REFRESH_REQUIRED")

    def test_withdrawn_source_invalidates_supported_answer_and_assertion(self):
        value = receipts()
        value["evidence"][0]["currently_readable"] = False
        value["assertions"][0]["active"] = False
        report = evaluate(protocol(), value, [])
        self.assertEqual(report["verdict"], "HOLD")
        self.assertEqual(rows(report, "questions")[QUESTION]["status"], "INVALIDATED")
        self.assertEqual(rows(report, "assertions")["cand-1"]["status"], "INVALIDATED")
        self.assertEqual(report["metrics"]["citation_chains"]["invalidated"], 1)

    def test_latest_attempt_per_question_is_scored(self):
        value = receipts()
        later = copy.deepcopy(value["answers"][0])
        later.update(retrieval_id="retrieve-q1-again", state="ABSTAIN_NO_AUTHORIZED_EVIDENCE",
                     abstention_reason="NO_AUTHORIZED_EVIDENCE", claims=[], response_id=None, review_id=None)
        value["answers"].append(later)
        self.assertEqual(rows(evaluate(protocol(), value, []), "questions")[QUESTION]["retrieval_id"], "retrieve-q1-again")

    def test_text_fields_undeclared_inputs_and_duplicates_are_rejected(self):
        mutations = [
            lambda r: r["evidence"][0].update(quote="The authored experiment measured 17 units."),
            lambda r: r["answers"][0]["claims"][0].update(claim_sha256="The authored result is 17 units."),
            lambda r: r["source_reviews"][0].update(source_id="a free text sentence with spaces"),
            lambda r: r["source_reviews"][0].update(independent_review=True),
            lambda r: r["evidence"].append(copy.deepcopy(r["evidence"][0])),
            lambda r: r.update(execution_mode="PRODUCTION"),
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
            self.assertEqual(json.loads((root / "report.json").read_text())["verdict"], "PASS")
            bad = receipts(); bad["evidence"][0]["quote"] = "smuggled"
            (root / "receipts.json").write_text(json.dumps(bad))
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

    def supported(self):
        f = self.f
        _, _, reviewed = f.answer_request()
        response = json.dumps({"abstain": False, "claims": [{"text": "The authored result is 17 units.",
                               "evidence_ids": [reviewed["evidence_id"]]}]}).encode()
        f.pilot.record_answer_response("answer", prepared_id="prepare-answer", response=response,
                                       execution_receipt=f.execution("prepare-answer", "ANSWER", response))
        at = now()
        payload = f.pilot.answer_review_payload("answer", reviewer="authored-test-reviewer", reviewer_kind="assistant",
                                                reviewed_at=at, claim_support=[True])
        f.pilot.review_answer("answer-review", response_id="answer",
                              receipt=f.signer.issue("SOURCE_STATUS", payload, issued_at=at))
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
        self.assertEqual(exported["answers"][0]["claims"][0]["claim_sha256"], text_digest("The authored result is 17 units."))
        self.assertEqual(exported["evidence"][0]["physical_page"], 2)
        report = evaluate(self.frozen(), exported, [])
        self.assertEqual(report["verdict"], "PASS", report["rows"])
        self.assertEqual(report["evidence_class"], "AUTHORED_SYNTHETIC_MECHANICS_ONLY")
        self.assertNotIn(self.f.native.strip(), json.dumps(report))
        self.f.reopen()
        self.assertEqual(export_receipts(self.f.pilot), exported)

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
