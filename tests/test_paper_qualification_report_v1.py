"""Synthetic aggregate mechanics, never empirical qualification evidence."""
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from src.paper_qualification_v1 import (EvidenceError, METHODS, QUOTAS, REVIEW_POLICY,
    VERSION, lower_bound, statistical_gates, summarize)
from src.paper_qualification_report_v1 import (STAGES, aggregate_metrics, assert_redacted,
    build_report, preflight, write_report)

REPO = Path(__file__).resolve().parents[1]


def rows(n=400, offset=0):
    return [{"work_id": f"arxiv:2501.{offset+i:05}", "reference_status": "complete",
        "accepted": True, "strict_correct": True, "route": "image_review",
        "text": "CANARY SOURCE TEXT"} for i in range(n)]


def evaluation():
    primary, challenge = rows(), rows(80, 1000)
    strata = {k: [r["work_id"] for r in challenge] for k in QUOTAS}
    value = statistical_gates(primary, challenge, strata)
    value.update(version=VERSION, qualification_pass=True, independent_human_qualification=False,
        graph_writes=0, paid_calls=0, review_policy=REVIEW_POLICY, screened_exposure_count=1200,
        all_sampled_case_count=480, cases={r["work_id"]: r for r in primary+challenge},
        image_counts={k: 0 for k in ("image_proposals", "corrected_image_proposals", "raw_image_matches_final")},
        study_id="CANARY STUDY", invocation={"CANARY": "/private/CANARY"},
        input_hashes={"/private/CANARY": "CANARY"}, runtime="CANARY", code_sha256="CANARY")
    value["measured_arms"] = {method: {"selection": "diagnostic_only",
        "primary": summarize(primary), "challenge": {k: summarize(challenge) for k in QUOTAS},
        "cases": value["cases"]} for method in METHODS}
    return value


def execution():
    return {"version": "paper-four-arm-execution-v1", "costs": {"paid_calls": 0,
        "paid_spend_usd": 0.0, "graph_writes": 0}, "stage_reports": [
        {"stage": name, "elapsed_seconds": None, "cpu_seconds": 1.0,
         "review_active_seconds": 0, "calls": 0, "failures": 1, "retries": 2, "review_count": 0}
        for name in reversed(STAGES)]}


def save(root, name, value):
    raw = json.dumps(value).encode()
    (root/name).parent.mkdir(parents=True, exist_ok=True)
    (root/name).write_bytes(raw)
    return {"relative": name, "sha256": hashlib.sha256(raw).hexdigest()}


def published(root, value, folder="pub"):
    """Authored stand-in for a completed publish() directory; not a verified publication."""
    descriptor = save(root, folder+"/evaluation.json", value)
    save(root, folder+"/publication-complete.json", {"version": "paper-evaluation-publication-v1",
        "evaluation_sha256": descriptor["sha256"], "public_summary_sha256": "0"*64,
        "status": value["status"], "qualification_pass": value["qualification_pass"],
        "graph_qualification_registered": False})
    return descriptor


class AggregateTests(unittest.TestCase):
    def test_metrics(self):
        primary, challenge = rows(10), rows(3, 100)
        challenge[0].update(reference_status="partial_on_page_one", strict_correct=False)
        challenge[1].update(reference_status="uncertain", strict_correct=False, accepted=False)
        strata = {k: [r["work_id"] for r in challenge] for k in QUOTAS}
        report = aggregate_metrics(primary, challenge, strata)
        for actual, expected in ((report["overall"], summarize(primary)),
                (report["strata"]["partial"], summarize(challenge))):
            for key in actual:
                if key == "rejected_partial_or_absent_accepts_count":
                    self.assertEqual(actual[key], len(expected["rejected_partial_or_absent_accepts"]))
                else:
                    self.assertEqual(actual[key], expected[key])
        self.assertEqual(report["overall"]["precision_lower_97_5"], lower_bound(10, 10))
        self.assertEqual(report["strata"]["partial"]["false_accepts"], 1)
        self.assertEqual(report["strata"]["partial"]["unresolved"], 1)

    def test_membership(self):
        p, c = rows(2), rows(2, 100)
        strata = {k: [] for k in QUOTAS}
        for bad in ({}, {**strata, "partial": ["outside"]}):
            with self.assertRaises(EvidenceError): aggregate_metrics(p, c, bad)
        with self.assertRaises(EvidenceError): aggregate_metrics(p, p, strata)

    def test_redaction(self):
        value = evaluation()
        report = build_report(value)
        raw = json.dumps(report)
        for forbidden in ("CANARY", "arxiv:", "/", *value["cases"]):
            self.assertNotIn(forbidden, raw)
        self.assertEqual(report["reference_status_counts"]["complete"], 480)
        self.assertEqual(report["route_counts"]["image_review"], 480)
        self.assertFalse(report["execution_bound"])
        self.assertEqual(report["sample_counts"]["challenge_case_count"], 80)
        value["primary"]["text"] = "x"
        with self.assertRaises(EvidenceError): build_report(value)
        value = evaluation()
        value["checks"]["arxiv_2501_00001"] = True
        with self.assertRaises(EvidenceError): build_report(value)

    def test_summary_types(self):
        for key, invalid in (("n", True), ("coverage", float("nan")),
                ("precision_interval_95", [0]), ("coverage", 2)):
            value = evaluation()
            value["primary"][key] = invalid
            with self.assertRaises(EvidenceError): build_report(value)

    def test_walker(self):
        report = build_report(evaluation())
        for invalid in ("CANARY SOURCE TEXT", float("nan"), "a"*64):
            changed = deepcopy(report)
            changed["stages"] = [{"elapsed_seconds": invalid}]
            with self.assertRaises(EvidenceError): assert_redacted(changed)
        with self.assertRaises(EvidenceError): assert_redacted({"CANARY": 1})
        with self.assertRaises(EvidenceError): assert_redacted({"overall": {"arbitrary_check": True}})
        with self.assertRaises(EvidenceError): assert_redacted({"checks": {"arbitrary_check": True}})
        assert_redacted({"checks": {"challenge_notation_safety": True}})

    def test_status(self):
        for status in ("FAIL", "AUTHORED_CONTRACT_PASS_NOT_QUALIFICATION"):
            value = evaluation()
            value.update(status=status, qualification_pass=False)
            report = build_report(value)
            self.assertEqual(report["status"], status)
            self.assertFalse(report["qualification_pass"])
        value.update(status="FAIL", qualification_pass=True)
        with self.assertRaises(EvidenceError): build_report(value)

    def test_blocked(self):
        value = dict(version=VERSION, status="BLOCKED", qualification_pass=False,
            independent_human_qualification=False, graph_writes=0, paid_calls=0)
        for reason, expected in (("missing_evidence:partial", "missing_evidence:partial"),
                ("arxiv:2501.00001 /private/path", "unrecognized_reason_redacted")):
            value["reason"] = reason
            report = build_report(value)
            self.assertEqual(report["reason_code"], expected)
            self.assertNotIn("overall", report)

    def test_execution(self):
        e = execution()
        report = build_report(evaluation(), execution=e)
        self.assertTrue(report["execution_bound"])
        self.assertEqual([r["stage"] for r in report["stages"]], sorted(STAGES))
        self.assertEqual(report["failure_totals"], {"failures": 6, "retries": 12})
        self.assertIsNone(report["stages"][0]["elapsed_seconds"])
        for mutate in (lambda e: e["costs"].update(paid_spend_usd=1),
                lambda e: e["stage_reports"].pop(),
                lambda e: e["stage_reports"][0].update(calls=True)):
            bad = execution()
            mutate(bad)
            with self.assertRaises(EvidenceError): build_report(evaluation(), execution=bad)

    def test_write(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ex = save(root, "execution.json", execution())
            value = evaluation()
            ev = published(root, value)
            with self.assertRaisesRegex(EvidenceError, "execution_not_bound"):
                write_report(root, "report.json", ev, execution_descriptor=ex)
            value["input_hashes"][ex["relative"]] = ex["sha256"]
            bare = save(root, "bare/evaluation.json", value)
            with self.assertRaises(OSError): write_report(root, "report.json", bare)
            ev = published(root, value)
            result = write_report(root, "report.json", ev, execution_descriptor=ex)
            self.assertEqual(result["sha256"], hashlib.sha256((root/"report.json").read_bytes()).hexdigest())
            report = json.loads((root/"report.json").read_text())
            self.assertEqual(report["source_evaluation_sha256"], ev["sha256"])
            self.assertNotIn("CANARY", json.dumps(report))
            with self.assertRaises(EvidenceError): write_report(root, "report.json", ev)
            with self.assertRaises(EvidenceError):
                write_report(root, "other.json", {**ev, "sha256": "0"*64})
            (root/"pub/publication-invalidated.json").write_text("{}")
            with self.assertRaisesRegex(EvidenceError, "publication_invalidated"):
                write_report(root, "other.json", ev)
            stale = published(root, {**value, "status": "FAIL", "qualification_pass": False}, "stale")
            (root/"stale/evaluation.json").write_text(json.dumps(value))
            with self.assertRaises(EvidenceError):
                write_report(root, "other.json", {**stale, "sha256": hashlib.sha256(
                    (root/"stale/evaluation.json").read_bytes()).hexdigest()})
            self.assertFalse((root/"other.json").exists())

    def cli(self, *args):
        result = subprocess.run([sys.executable, "-m", "src.paper_qualification_report_v1", *args],
            cwd=REPO, text=True, capture_output=True)
        return result.returncode, json.loads(result.stdout)

    def test_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ev = published(root, evaluation())
            code, result = self.cli("report", "--data-root", directory, "--evaluation", ev["relative"],
                "--evaluation-sha256", ev["sha256"], "--output", "report.json")
            self.assertEqual(code, 0)
            self.assertNotIn("CANARY", json.dumps(result))
            self.assertNotIn("CANARY", (root/"report.json").read_text())
            for bundle, output in (("missing.json", "new.json"), (ev["relative"], "report.json")):
                code, result = self.cli("preflight", "--data-root", directory, "--bundle", bundle,
                    "--bundle-sha256", ev["sha256"], "--preregistration-sha256", "0"*64, "--output", output)
                self.assertEqual(code, 2)
                self.assertEqual(result["status"], "NOT_READY")
                self.assertFalse(result["checks"]["bundle" if bundle == "missing.json" else "output_available"])
            code, result = self.cli("preflight", "--data-root", directory, "--bundle", ev["relative"],
                "--bundle-sha256", ev["sha256"], "--preregistration-sha256", "0"*64, "--output", "new.json")
            available = all(result["checks"].values())
            self.assertEqual(code, 0 if available else 2)
            self.assertEqual(result["status"], "READY" if available else "NOT_READY")
            if not (importlib.util.find_spec("fitz") and importlib.util.find_spec("PIL")):
                self.assertEqual(result["status"], "NOT_READY")

    def test_ready_mechanics_without_opening_sources(self):
        from argparse import Namespace
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            descriptor = save(root, "bundle.json", {"selected_source": "/never/open/CANARY"})
            args = Namespace(data_root=directory, bundle=descriptor["relative"],
                bundle_sha256=descriptor["sha256"], preregistration_sha256="0"*64, output="new.json",
                runtime_lock=None)
            with patch("src.paper_qualification_report_v1.runtime_receipt", return_value={}), \
                    patch("src.paper_qualification_report_v1.evaluator_identity", return_value={}), \
                    patch("src.paper_qualification_report_v1.importlib.util.find_spec", return_value=object()):
                self.assertEqual(preflight(args)["status"], "READY")
            self.assertFalse((root/"new.json").exists())


if __name__ == "__main__":
    unittest.main()
