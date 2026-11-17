"""Synthetic aggregate mechanics, never empirical qualification evidence."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from src.paper_qualification_v1 import (CLARIFICATION, REFERENCE_REVIEW, SAMPLING, SEED, TARGETS,
    EvidenceError, METHODS, QUOTAS, REVIEW_POLICY, VERSION, _public_summary, lower_bound, publish,
    statistical_gates, summarize)
from src.paper_qualification_report_v1 import (STAGES, aggregate_metrics, assert_redacted,
    build_report, preflight, write_report)

from trace_gc.trust import TrustStore

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
        input_hashes={"/private/CANARY": "CANARY"}, runtime="CANARY", code_sha256="CANARY", image_code_sha256="CANARY")
    value["measured_arms"] = {method: {"selection": "diagnostic_only",
        "primary": summarize(primary), "challenge": {k: summarize(challenge) for k in QUOTAS},
        "cases": {key: {**row, "status": "error" if index == 0 else "truncated" if index == 1 else "ok"}
            for index, (key, row) in enumerate(value["cases"].items())}} for method in METHODS}
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
    """Authored publication shape. Replay independently checks this fixture."""
    descriptor = save(root, folder+"/evaluation.json", value)
    summary = save(root, folder+"/public-summary.json", _public_summary(value, descriptor["sha256"]))
    save(root, folder+"/publication-complete.json", {"version": "paper-evaluation-publication-v1",
        "evaluation_sha256": descriptor["sha256"], "public_summary_sha256": summary["sha256"],
        "status": value["status"], "qualification_pass": value["qualification_pass"],
        "graph_qualification_registered": False})
    return descriptor


def bundle(root, *, selected=None):
    protocol = {"schema_version": "source-first-qualification-preregistration-v1",
        "seed": SEED, "targets": TARGETS, "sampling": SAMPLING, "reference_review": REFERENCE_REVIEW,
        "registered_utc": "2026-01-01T00:00:00Z", "configuration": {
            "measured_arms": list(METHODS), "image_evidence_required": True,
            "native_only_receipt_sufficient": False}}
    documents = {"protocol.json": save(root, "prereg/protocol.json", protocol)["sha256"],
        "amendment-04/evaluator-clarification.json": save(root,
            "prereg/amendment-04/evaluator-clarification.json", CLARIFICATION)["sha256"]}
    for name in ("protocol.md", "amendment-02/protocol-amendment.md", "amendment-03/protocol-amendment.md",
            "metadata-inventory/exposure-registry.jsonl"):
        raw = b"" if name.endswith(".jsonl") else b"Authored fixture for preflight."
        path = root/"prereg"/name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        documents[name] = hashlib.sha256(raw).hexdigest()
    frames = {}
    for role, month in (("recent", "2501"), ("historical", "1801")):
        ids = [f"arxiv:{month}.{index:05}" for index in range(1, 2001)]
        projection = save(root, "prereg/"+role+".json", [
            {"work_id": work_id, "version_id": work_id+"v1", "doi": None} for work_id in ids])
        frames[role] = {"identity_projection_relative": role+".json", "sha256": projection["sha256"]}
    prereg = save(root, "prereg/current.json", {"schema_version": "qualification-preregistration-current-v1",
        "numeric_targets_unchanged": True, "reference_review_occurred": False,
        "base_protocol_and_additive_amendments": documents, "frames": frames})
    missing = {"relative": "unseen-must-not-open.pdf", "sha256": "f"*64}
    data = {"version": VERSION, "study_id": "authored", "execution_mode": "AUTHORED_CONTRACT_TEST",
        "roles": {role: {} for role in ("custodian", "source_reviewer", "adjudicator",
            "candidate_reviewer", "operator")}, "phases": [{}, {}, {}, {}], "preregistration": prereg,
        **{k: missing for k in ("configuration", "regression", "source_map", "access", "sampling",
            "screening", "sources", "references", "execution")}}
    if selected:
        data["execution"] = selected
    return save(root, "bundle.json", data), prereg


def early_block():
    return {"version": VERSION, "status": "BLOCKED", "qualification_pass": False,
        "graph_qualification_registered": False, "independent_human_qualification": False,
        "graph_writes": 0, "paid_calls": 0, "reason": "missing_or_invalid_bound_study_evidence"}


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
        for reason, expected in (("missing_or_invalid_bound_study_evidence", "missing_or_invalid_bound_study_evidence"),
                ("private_identifier:source", "unrecognized_reason_redacted"),
                ("arxiv:2501.00001 /private/path", "unrecognized_reason_redacted")):
            value["reason"] = reason
            report = build_report(value)
            self.assertEqual(report["reason_code"], expected)
            self.assertNotIn("overall", report)
        with self.assertRaises(EvidenceError):
            assert_redacted({"reason_code": "private_identifier:source"})

    def test_statistical_blocked_keeps_aggregates(self):
        value = evaluation()
        value.update(status="BLOCKED", qualification_pass=False,
            missing_representation=["image_only:complete"])
        report = build_report(value, execution=execution())
        self.assertEqual(report["status"], "BLOCKED")
        self.assertFalse(report["qualification_pass"])
        self.assertEqual(report["missing_representation"], ["image_only:complete"])
        self.assertEqual(report["overall"]["n"], 400)
        self.assertEqual(report["failure_totals"], {"failures": 6, "retries": 12})

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

    def test_write_requires_replay_and_uses_only_the_bundle_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ex = save(root, "execution.json", execution())
            wrong_ex = save(root, "other-execution.json", execution())
            bundle_descriptor, prereg = bundle(root, selected=ex)
            value = evaluation()
            value.update(graph_qualification_registered=False, evaluated_at="2026-01-02T00:00:00Z",
                invocation={"bundle_descriptor": bundle_descriptor, "expected_preregistration_sha256": prereg["sha256"]},
                input_hashes={item["relative"]: item["sha256"] for item in (ex, wrong_ex, bundle_descriptor)})
            ev = published(root, value)
            anchors = {"expected_preregistration_sha256": prereg["sha256"], "trust": TrustStore()}
            with self.assertRaisesRegex(EvidenceError, "external_publication_trust"):
                write_report(root, "report.json", ev)
            with self.assertRaisesRegex(EvidenceError, "qualification_evidence_changed"):
                write_report(root, "report.json", ev, **anchors)
            self.assertFalse((root/"report.json").exists())
            for status in ("PASS", "FAIL", "BLOCKED", "AUTHORED_CONTRACT_PASS_NOT_QUALIFICATION"):
                current = {**value, "status": status, "qualification_pass": status == "PASS"}
                ev = published(root, current, status)
                output = status+".json"
                with patch("src.paper_qualification_v1.evaluate", return_value=current), \
                        patch("src.paper_qualification_report_v1.evaluator_identity", return_value="CANARY"), \
                        patch("src.parallel_source_v4.image_ocr.code_identity", return_value="CANARY"), \
                        patch("src.paper_qualification_report_v1.runtime_receipt", return_value="CANARY"):
                    with self.assertRaisesRegex(EvidenceError, "execution_not_bound"):
                        write_report(root, output, ev, execution_descriptor=wrong_ex, **anchors)
                    result = write_report(root, output, ev, **anchors)
                    self.assertEqual(result["sha256"], hashlib.sha256((root/output).read_bytes()).hexdigest())
                    report = json.loads((root/output).read_text())
                    self.assertEqual(report["source_evaluation_sha256"], ev["sha256"])
                    self.assertEqual(report["status"], status)
                    self.assertEqual(report["execution_mode"], "AUTHORED_CONTRACT_TEST")
                    self.assertEqual(report["reviewer_kind"], "assistant")
                    for arm in report["measured_arms"].values():
                        self.assertEqual(arm["conversion_error_count"], 1)
                        self.assertEqual(arm["truncated_case_count"], 1)
                    self.assertTrue(report["execution_bound"])
                    self.assertEqual(report["failure_totals"], {"failures": 6, "retries": 12})
                    self.assertNotIn("CANARY", json.dumps(report))
                    with self.assertRaises(EvidenceError): write_report(root, output, ev, **anchors)
                    with self.assertRaisesRegex(EvidenceError, "artifact_bytes_changed"):
                        write_report(root, "new.json", {**ev, "sha256": "0"*64}, **anchors)
                (root/status/"publication-invalidated.json").write_text("{}")
                with self.assertRaisesRegex(EvidenceError, "publication_invalidated"):
                    write_report(root, "new.json", ev, **anchors)
            current = {**value, "status": "FAIL", "qualification_pass": False}
            ev = published(root, current, "replayed")
            with patch("src.paper_qualification_v1.evaluate", return_value=current), \
                    patch("src.paper_qualification_report_v1.evaluator_identity", return_value="changed"):
                with self.assertRaisesRegex(EvidenceError, "evaluation_environment_changed_during_reporting"):
                    write_report(root, "drifted.json", ev, **anchors)
            self.assertFalse((root / "drifted.json").exists())
            def bound_input_changed(*args, **kwargs):
                (root / wrong_ex["relative"]).write_text("{}")
                return build_report(*args, **kwargs)
            with patch("src.paper_qualification_v1.evaluate", return_value=current), \
                    patch("src.paper_qualification_report_v1.build_report", side_effect=bound_input_changed):
                with self.assertRaisesRegex(EvidenceError, "artifact_changed_during_evaluation"):
                    write_report(root, "changed.json", ev, **anchors)
            self.assertFalse((root / "changed.json").exists())
            bare = save(root, "bare/evaluation.json", early_block())
            with self.assertRaisesRegex(EvidenceError, "publication_completion_required"):
                write_report(root, "new.json", bare)
            self.assertFalse((root/"new.json").exists())

    def test_report_rejects_reserved_output_and_changed_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ev = published(root, early_block(), "pub")
            with self.assertRaisesRegex(EvidenceError, "publication_invalidated"):
                write_report(root, "pub/publication-invalidated.json", ev)
            self.assertFalse((root / "pub" / "publication-invalidated.json").exists())
            def public_summary_changed(*args, **kwargs):
                (root / "pub" / "public-summary.json").write_text("{}")
            with patch("src.paper_qualification_report_v1.verify_published", side_effect=public_summary_changed):
                with self.assertRaisesRegex(EvidenceError, "artifact_changed_during_evaluation"):
                    write_report(root, "report.json", ev)
            self.assertFalse((root / "report.json").exists())

    def cli(self, *args):
        result = subprocess.run([sys.executable, "-m", "src.paper_qualification_report_v1", *args],
            cwd=REPO, text=True, capture_output=True)
        return result.returncode, json.loads(result.stdout)

    def test_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipt = publish(root, "pub", early_block())
            code, result = self.cli("report", "--data-root", directory, "--evaluation", "pub/evaluation.json",
                "--evaluation-sha256", receipt["private_evaluation_sha256"], "--output", "canary-output.json")
            self.assertEqual(code, 0)
            self.assertEqual(set(result), {"sha256"})
            report = json.loads((root/"canary-output.json").read_bytes())
            self.assertEqual(report["status"], "BLOCKED")
            self.assertNotIn("overall", report)
            descriptor, prereg = bundle(root)
            for filename, output in (("missing.json", "new.json"), (descriptor["relative"], "canary-output.json")):
                code, result = self.cli("preflight", "--data-root", directory, "--bundle", filename,
                    "--bundle-sha256", descriptor["sha256"], "--preregistration-sha256", prereg["sha256"], "--output", output)
                self.assertEqual(code, 2)
                self.assertEqual(result["status"], "NOT_READY")
                self.assertFalse(result["checks"]["bundle" if filename == "missing.json" else "output_available"])

    def test_ready_checks_bound_preregistration_without_opening_sources(self):
        from argparse import Namespace
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            descriptor, prereg = bundle(root)
            args = Namespace(data_root=directory, bundle=descriptor["relative"],
                bundle_sha256=descriptor["sha256"], preregistration_sha256=prereg["sha256"], output="new.json",
                runtime_lock=None)
            pointer = json.loads((root/prereg["relative"]).read_bytes())
            body = json.loads((root/descriptor["relative"]).read_bytes())
            original = Path.read_bytes
            def guarded(path):
                self.assertIn(path.name, ("bundle.json", "current.json", "unrelated.json"))
                return original(path)
            with patch("src.paper_qualification_report_v1.runtime_receipt", return_value={}), \
                    patch("src.paper_qualification_report_v1.evaluator_identity", return_value={}), \
                    patch("src.paper_qualification_report_v1.importlib.util.find_spec", return_value=object()), \
                    patch.object(Path, "read_bytes", guarded):
                self.assertEqual(preflight(args)["status"], "READY")
                protocol_file = root / "prereg" / "protocol.md"
                protocol_bytes = b"Authored fixture for preflight."
                protocol_file.write_bytes(b"Changed protocol.")
                self.assertFalse(preflight(args)["checks"]["preregistration"])
                protocol_file.write_bytes(protocol_bytes)
                args.output = "missing/directory/new.json"
                self.assertEqual(preflight(args)["status"], "READY")
                (root/"ancestor").write_bytes(b"not a directory")
                args.output = "ancestor/nested/new.json"
                self.assertFalse(preflight(args)["checks"]["output_available"])
                args.output = "new.json"
                args.preregistration_sha256 = "0"*64
                self.assertFalse(preflight(args)["checks"]["preregistration"])
                args.preregistration_sha256 = prereg["sha256"]
                (root/prereg["relative"]).write_text("{}")
                self.assertFalse(preflight(args)["checks"]["preregistration"])
                for alter in (
                    lambda value: value.update(base_protocol_and_additive_amendments={}),
                    lambda value: value["base_protocol_and_additive_amendments"].update({"protocol.json": "bad"}),
                    lambda value: value["frames"].update(recent={}),
                    lambda value: value["frames"]["historical"].update(sha256=None),
                    lambda value: value["frames"]["historical"].update(identity_projection_relative="../escape.json"),
                ):
                    invalid = deepcopy(pointer)
                    alter(invalid)
                    updated = save(root, prereg["relative"], invalid)
                    updated_bundle = save(root, descriptor["relative"], {**body, "preregistration": updated})
                    args.preregistration_sha256 = updated["sha256"]
                    args.bundle_sha256 = updated_bundle["sha256"]
                    result = preflight(args)
                    self.assertTrue(result["checks"]["bundle"])
                    self.assertFalse(result["checks"]["preregistration"])
                    self.assertEqual(result["status"], "NOT_READY")
                (root/"unseen-must-not-open.pdf").write_bytes(b"%PDF synthetic canary")
                args.bundle, args.bundle_sha256 = "unseen-must-not-open.pdf", "0"*64
                self.assertFalse(preflight(args)["checks"]["bundle"])
                unrelated = save(root, "unrelated.json", {"selected_source": "/never/open/CANARY"})
                args.bundle, args.bundle_sha256 = unrelated["relative"], unrelated["sha256"]
                self.assertFalse(preflight(args)["checks"]["bundle"])
            self.assertFalse((root/"new.json").exists())


if __name__ == "__main__":
    unittest.main()
