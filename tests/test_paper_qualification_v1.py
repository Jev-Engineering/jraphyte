"""Authored protocol and integrity fixtures, never empirical qualification."""
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from contextlib import ExitStack

from src.paper_qualification_v1 import (Artifacts, EvidenceError, PHASES, QUOTAS,
    REVIEW_POLICY, SAMPLING, SEED, TARGETS, REFERENCE_REVIEW, VERSION, METHODS,
    evaluate, lower_bound, interval, rank, statistical_gates, summarize,
    validate_protocol, validate_selection, verify_phases, verify_review_order)
from src.paper_qualification_v1 import (_image_candidate, replay_converters, CACHE_OUTPUTS, evaluator_identity,
    publish, verify_published, reconcile_exposure, native_failure)
from src.paper_qualification_v1 import CLARIFICATION, normalize_work_id, _source
from trace_gc.canonical import digest
from trace_gc.trust import Signer, TrustStore, IssuerPolicy

PDF_STACK_AVAILABLE = bool(importlib.util.find_spec("fitz") and importlib.util.find_spec("PIL"))


def sid(n):
    return f"arxiv:2501.{n:05}"


def rows(n=400, offset=0):
    return [{"work_id": sid(offset+i), "reference_status": "complete", "accepted": True,
        "strict_correct": True, "route": "image_review"} for i in range(n)]


def roles():
    return {name: {"principal": "authored-custodian", "context_id": "authored-"+name,
        "reviewer_kind": "assistant", "model_version": None}
        for name in ("custodian", "source_reviewer", "adjudicator", "candidate_reviewer", "operator")}


def signed_phases():
    signer = Signer.ephemeral("authored-test-only")
    trust = TrustStore()
    trust.enroll(signer.issuer, IssuerPolicy(public_key=signer.public_key(), principal="authored-custodian",
        purposes=frozenset({"RUN_CHECKPOINT"}), operations=frozenset(), scopes=frozenset(), modes=frozenset({"AUTHORED_CONTRACT_TEST"}), can_review=True))
    assigned = roles()
    hashes = {p: {"bound_artifact": hashlib.sha256(p.encode()).hexdigest()} for p in PHASES}
    receipts, previous = [], None
    for index, phase in enumerate(PHASES):
        role = "operator" if phase == "predictions_frozen" else "custodian"
        receipt = signer.issue("RUN_CHECKPOINT", {"contract": VERSION, "study_id": "authored-study", "execution_mode": "AUTHORED_CONTRACT_TEST",
            "phase": phase, "artifact_hashes": hashes[phase], "previous_receipt_sha256": previous,
            "review_policy": REVIEW_POLICY, "independent_human_review": False,
            "context_id": assigned[role]["context_id"]},
            issued_at=f"2026-01-01T0{index}:00:00Z", expires_at="2027-01-01T00:00:00Z")
        receipts.append(receipt); previous = digest(receipt)
    kwargs = dict(trust=trust, study_id="authored-study", execution_mode="AUTHORED_CONTRACT_TEST", artifact_hashes=hashes, roles=assigned, at="2026-01-02T00:00:00Z")
    return signer, receipts, kwargs


class StatisticalTests(unittest.TestCase):
    def test_exact_bound_and_zero_acceptance(self):
        self.assertAlmostEqual(lower_bound(200, 200), .025**(1/200), places=12)
        self.assertGreater(lower_bound(200, 200), .98)
        self.assertIsNone(lower_bound(0, 0))
        self.assertEqual(interval(0, 0), [None, None])
        self.assertEqual(lower_bound(0, 10), 0)
        with self.assertRaises(EvidenceError): lower_bound(True, 10)

    def test_binomial_interval_inversion(self):
        low, high = interval(4, 10)
        cdf = lambda p: sum(math.comb(10,k)*p**k*(1-p)**(10-k) for k in range(5))
        tail = lambda p: sum(math.comb(10,k)*p**k*(1-p)**(10-k) for k in range(4,11))
        self.assertAlmostEqual(cdf(high), .025, places=12)
        self.assertAlmostEqual(tail(low), .025, places=12)

    def test_unresolved_is_miss_and_accepted_unresolved_is_false(self):
        value = rows(400)
        value[0].update(reference_status="uncertain", strict_correct=False)
        value[1].update(reference_status="uncertain", strict_correct=False, accepted=False)
        result = summarize(value)
        self.assertEqual(result["resolved_complete"],398)
        self.assertEqual(result["conservative_recall_denominator"],400)
        self.assertEqual(result["false_accepts"],1)
        self.assertEqual(result["strict_correct"],398)

    def test_primary_challenge_never_pooled(self):
        primary, challenge = rows(), rows(40,1000)
        strata = {name:[r["work_id"] for r in challenge] for name in QUOTAS}
        primary[0]["strict_correct"] = False
        result = statistical_gates(primary,challenge,strata)
        self.assertEqual(result["status"],"FAIL")
        self.assertEqual(result["primary"]["n"],400)
        self.assertEqual(result["primary"]["false_accepts"],1)
        self.assertFalse(result["checks"]["zero_false_accepts"])

    def test_authored_counts_can_meet_numbers_without_empirical_claim(self):
        primary, challenge = rows(), rows(40,1000)
        strata = {name:[r["work_id"] for r in challenge] for name in QUOTAS}
        result = statistical_gates(primary,challenge,strata)
        self.assertEqual(result["status"],"PASS")
        self.assertNotIn("qualification_pass",result)
        self.assertEqual(result["primary"]["strict_correct"],400)

    def test_missing_challenge_representation_blocks(self):
        primary, challenge = rows(), rows(19,1000)
        strata = {name:[r["work_id"] for r in challenge] for name in QUOTAS}
        self.assertEqual(statistical_gates(primary,challenge,strata)["status"],"BLOCKED")

    def test_image_utility_requires_real_image_route(self):
        primary, challenge = rows(), rows(40,1000)
        strata = {name:[r["work_id"] for r in challenge] for name in QUOTAS}
        challenge[0]["route"]="native_or_hold"
        result=statistical_gates(primary,challenge,strata)
        self.assertEqual(result["status"],"FAIL")
        self.assertFalse(result["checks"]["challenge_image_only_actual_image_route"])

    def test_sparse_complete_image_group_blocks(self):
        primary, challenge = rows(), rows(40,1000)
        for row in challenge[9:]:row.update(reference_status="no_abstract_text",accepted=False,strict_correct=False)
        strata = {name:[r["work_id"] for r in challenge] for name in QUOTAS}
        result=statistical_gates(primary,challenge,strata)
        self.assertEqual(result["status"],"BLOCKED")
        self.assertIn("image_only:complete",result["missing_representation"])

    def test_low_acceptance_and_excess_unresolved_fail(self):
        primary, challenge = rows(), rows(40,1000)
        for row in primary[199:]:row.update(accepted=False,strict_correct=False)
        for row in primary[200:221]:row.update(reference_status="uncertain")
        strata = {name:[r["work_id"] for r in challenge] for name in QUOTAS}
        result=statistical_gates(primary,challenge,strata)
        self.assertEqual(result["status"],"FAIL")
        self.assertFalse(result["checks"]["minimum_accepted"])
        self.assertFalse(result["checks"]["reference_resolution"])


class ProtocolTests(unittest.TestCase):
    def protocol(self):
        return {"schema_version":"source-first-qualification-preregistration-v1","seed":SEED,
            "targets":deepcopy(TARGETS),"sampling":deepcopy(SAMPLING),"reference_review":deepcopy(REFERENCE_REVIEW),
            "configuration":{"measured_arms":list(METHODS),"image_evidence_required":True,"native_only_receipt_sufficient":False}}

    def test_every_threshold_sampling_and_review_field_is_frozen(self):
        original=self.protocol();validate_protocol(original)
        for section in ("targets","sampling","reference_review"):
            for field in original[section]:
                with self.subTest(section=section,field=field):
                    changed=deepcopy(original);changed[section][field]="authored-invalid-change"
                    with self.assertRaises(EvidenceError):validate_protocol(changed)

    def selection(self):
        recent=[sid(i) for i in range(2000)]
        historical=[f"arxiv:hep-th/{i:07}" for i in range(2000)]
        rr=rank(recent,"primary");hr=rank(historical,"historical-screen")
        screens=rr[400:1000]+hr[:600]
        screen={x:{"strata":[k for k in QUOTAS if k != ("partial" if i % 2 else "absent")],"image_first":True,"prediction_access":False,
            "reviewed_at":"2026-01-01T01:30:00Z","context_id":"authored-source_reviewer"} for i,x in enumerate(screens)}
        challenge=set()
        for name,quota in QUOTAS.items():challenge.update(rank([x for x in screens if name in screen[x]["strata"]],"challenge:"+name)[:quota])
        return {"recent_frame":recent,"historical_frame":historical,"exposed_work_ids":[],"identity_exclusions":[],
            "primary":rr[:400],"recent_screen":rr[400:1000],"historical_screen":hr[:600],"screen":screen,
            "challenge":sorted(challenge),"reconciled_at":"2026-01-01T00:30:00Z",
            "exposure_snapshot":{"relative":"authored-exposure.json","sha256":"a"*64}}

    def test_current_exposure_preserves_prior_bytes_and_new_doi_aliases(self):
        selection={"exposed_work_ids":[sid(1)],"reconciled_at":"2026-01-01T00:30:00Z"}
        prior=[{"work_id":sid(1),"source_sha256":["a"*64],"page_sha256":["b"*64]}]
        snapshot={"version":"paper-exposure-snapshot-v1","reconciled_at":selection["reconciled_at"],"entries":[
            {**prior[0],"source_sha256":["a"*64,"c"*64],"dois":["10.1000/authored"]}]}
        result=reconcile_exposure(snapshot,prior,selection)
        self.assertEqual(result["source_sha256"],{"a"*64,"c"*64})
        self.assertEqual(result["dois"],{"10.1000/authored"})
        snapshot["entries"][0]["source_sha256"].remove("a"*64)
        with self.assertRaisesRegex(EvidenceError,"registry_not_preserved"):
            reconcile_exposure(snapshot,prior,selection)

    def test_rank_and_screen_selection(self):
        selection=self.selection();ids,screened,strata=validate_selection(selection)
        self.assertEqual(len(screened),1200)
        self.assertEqual(len(ids),400+len(selection["challenge"]))
        self.assertEqual(rank(selection["recent_frame"],"primary"),rank(list(reversed(selection["recent_frame"])),"primary"))
        selection["primary"][0],selection["primary"][1]=selection["primary"][1],selection["primary"][0]
        with self.assertRaisesRegex(EvidenceError,"rank_selection"):validate_selection(selection)

    def test_unavailable_is_not_replacement_eligibility(self):
        selection=self.selection()
        selection["identity_exclusions"]=[{"work_id":sid(1999),"reason":"corrupt","evidence_sha256":"a"*64}]
        with self.assertRaisesRegex(EvidenceError,"cannot_be_replaced"):validate_selection(selection)

    def test_no_prediction_screen_and_no_versioned_alias(self):
        selection=self.selection();selection["screen"][next(iter(selection["screen"]))]["prediction_access"]=True
        with self.assertRaisesRegex(EvidenceError,"source_only"):validate_selection(selection)
        with self.assertRaises(EvidenceError):rank(["arxiv:2501.00001v2"],"primary")

    def test_case_and_version_normalization_collisions_are_one_work(self):
        values=[normalize_work_id(v) for v in ("arXiv:2501.00001v1","ARXIV:2501.00001v2")]
        self.assertEqual(values,[sid(1),sid(1)])
        with self.assertRaisesRegex(EvidenceError,"duplicate_work"):
            rank(values,"primary")


class SignedReviewTests(unittest.TestCase):
    def test_authored_mode_cannot_be_relabelled_real(self):
        _, receipts, kwargs = signed_phases()
        kwargs["execution_mode"] = "REAL_LOCAL"
        with self.assertRaisesRegex(EvidenceError,"artifact_or_order"):
            verify_phases(receipts,**kwargs)

    def test_four_signed_phase_chain_and_role_attribution(self):
        signer,receipts,kwargs=signed_phases()
        result=verify_phases(receipts,**kwargs)
        self.assertLess(result["references_frozen"],result["predictions_frozen"])
        bad=deepcopy(receipts);bad[2]["payload"]["artifact_hashes"]["bound_artifact"]="f"*64
        with self.assertRaises(Exception):verify_phases(bad,**kwargs)

    def test_even_resigned_wrong_artifact_or_reordered_chain_rejects(self):
        signer,receipts,kwargs=signed_phases()
        bad=deepcopy(receipts);payload=deepcopy(bad[2]["payload"]);payload["previous_receipt_sha256"]="e"*64
        bad[2]=signer.issue("RUN_CHECKPOINT",payload,issued_at=bad[2]["issued_at"],expires_at=bad[2]["expires_at"])
        with self.assertRaisesRegex(EvidenceError,"artifact_or_order"):verify_phases(bad,**kwargs)

    def test_shared_reference_candidate_context_rejects(self):
        _,receipts,kwargs=signed_phases()
        kwargs["roles"]["candidate_reviewer"]["context_id"]=kwargs["roles"]["source_reviewer"]["context_id"]
        with self.assertRaisesRegex(EvidenceError,"context_leakage"):verify_phases(receipts,**kwargs)

    def reference(self):
        ref={"status":"complete","text":"Authored source reference.","fidelity_review":{
            "notation":{"status":"pass"},"boundary":{"status":"pass"}}}
        record={"reference":ref,"initial_reference":ref,"history":[ref],"events":[
            {"kind":"image_inspection","context_id":"authored-source_reviewer","at":"2026-01-01T01:10:00Z",
             "input_sha256":["a"*64],"decision_sha256":digest(ref)},
            {"kind":"audit","context_id":"authored-adjudicator","at":"2026-01-01T01:20:00Z",
             "input_sha256":["a"*64],"decision_sha256":digest(ref)}],"unresolved_disagreement":False,
            "requires_adjudication":False,"audit_completed":True,"audit_material_error":False,"full_dimension_audit_completed":False}
        times={p:datetime(2026,1,1,i,tzinfo=timezone.utc) for i,p in enumerate(PHASES)}
        return {sid(1):record},dict(evaluated_ids={sid(1)},roles=roles(),source_hashes={sid(1):{"image":"a"*64,"native":"b"*64}},times=times)

    def test_source_image_precedes_native_and_prediction_inputs(self):
        records,kwargs=self.reference();verify_review_order(records,**kwargs)
        records[sid(1)]["events"][0]["input_sha256"]=["b"*64]
        with self.assertRaisesRegex(EvidenceError,"image_must_precede"):verify_review_order(records,**kwargs)

    def test_late_reference_and_missing_fixed_audit_reject(self):
        records,kwargs=self.reference();records[sid(1)]["events"][0]["at"]="2026-01-01T02:00:01Z"
        with self.assertRaisesRegex(EvidenceError,"blinded_window"):verify_review_order(records,**kwargs)
        records,kwargs=self.reference();records[sid(1)]["audit_completed"]=False
        with self.assertRaisesRegex(EvidenceError,"ten_percent"):verify_review_order(records,**kwargs)

    def test_disagreement_and_image_transcription_require_adjudication(self):
        records,kwargs=self.reference();records[sid(1)]["unresolved_disagreement"]=True
        with self.assertRaisesRegex(EvidenceError,"cannot_certify"):verify_review_order(records,**kwargs)
        records,kwargs=self.reference();records[sid(1)]["requires_adjudication"]=True
        with self.assertRaisesRegex(EvidenceError,"requires_adjudication"):verify_review_order(records,**kwargs)

    def test_adjudicator_and_audit_must_endorse_final_decision(self):
        records,kwargs=self.reference();record=records[sid(1)]
        final=record["reference"];initial={**deepcopy(final),"status":"uncertain"}
        record.update(initial_reference=initial,history=[initial,final],requires_adjudication=True)
        first=record["events"][0];first["decision_sha256"]=digest(initial)
        record["events"]=[first,{**first,"kind":"adjudication","context_id":"authored-adjudicator","at":"2026-01-01T01:15:00Z"},
            {**first,"kind":"native_readback","at":"2026-01-01T01:20:00Z","decision_sha256":digest(final)},
            {**first,"kind":"audit","context_id":"authored-adjudicator","at":"2026-01-01T01:25:00Z"}]
        with self.assertRaisesRegex(EvidenceError,"history_out_of_order"):
            verify_review_order(records,**kwargs)
        record["events"][-1]["decision_sha256"]=digest(final)
        with self.assertRaisesRegex(EvidenceError,"final_notation_or_image"):
            verify_review_order(records,**kwargs)
        record["events"].append({**record["events"][-1],"kind":"adjudication","at":"2026-01-01T01:30:00Z"})
        self.assertEqual(verify_review_order(records,**kwargs),[])

    def test_audit_pool_excludes_mandatory_adjudication_and_rounds_up(self):
        records,kwargs=self.reference();base=records[sid(1)]
        records={sid(i):deepcopy(base) for i in range(12)}
        kwargs["evaluated_ids"]=set(records)
        kwargs["source_hashes"]={work:{"image":"a"*64,"native":"b"*64} for work in records}
        records[sid(0)]["requires_adjudication"]=True
        records[sid(0)]["events"].append({**records[sid(0)]["events"][-1],"kind":"adjudication","at":"2026-01-01T01:30:00Z"})
        expected=rank([sid(i) for i in range(1,12)],"reference-audit")[:2]
        self.assertEqual(verify_review_order(records,**kwargs),expected)

    def test_unavailable_source_can_remain_unresolved_after_technical_adjudication(self):
        records,kwargs=self.reference();record=records[sid(1)]
        ref={"status":"uncertain","text":""}
        record.update(reference=ref,initial_reference=ref,history=[ref],audit_completed=False)
        record["events"]=[{"kind":kind,"context_id":"authored-"+role,"at":stamp,"input_sha256":[],"decision_sha256":digest(ref)}
            for kind,role,stamp in (("source_unavailable","source_reviewer","2026-01-01T01:10:00Z"),
                ("adjudication","adjudicator","2026-01-01T01:20:00Z"))]
        kwargs["source_hashes"][sid(1)]={}
        self.assertEqual(verify_review_order(records,**kwargs),[])
        record["reference"]["status"]="complete"
        with self.assertRaises((EvidenceError,KeyError)):
            verify_review_order(records,**kwargs)


class ArtifactTests(unittest.TestCase):
    def test_negative_native_observation_binds_bytes_source_and_image(self):
        with tempfile.TemporaryDirectory() as d:
            image=ComposedContractTests.write(d,"image.json",{"authored_image_identity":True})
            original={k:hashlib.sha256(k.encode()).hexdigest() for k in
                ("assessment_sha256","text_sha256","source_sha256","page_sha256","native_sha256")}
            original["proposal"]=True
            failure={k:v for k,v in original.items() if k != "proposal"}
            failure.update(version="paper-candidate-failure-v1",image_sha256=image["sha256"],dimension="notation",status="fail",
                reviewer="authored-custodian",context_id="authored-candidate_reviewer",reviewed_at="2026-01-01T02:10:00Z",
                observed_mismatch="Authored fixture: superscript relation absent.",source_image_inspected=True)
            descriptor=ComposedContractTests.write(d,"failure.json",failure)
            kwargs=dict(original=original,source={"image":image},roles=roles(),times={
                "references_frozen":datetime(2026,1,1,2,tzinfo=timezone.utc),
                "predictions_frozen":datetime(2026,1,1,3,tzinfo=timezone.utc)})
            native_failure(Artifacts(d),descriptor,**kwargs)
            failure["image_sha256"]="f"*64
            descriptor=ComposedContractTests.write(d,"failure.json",failure)
            with self.assertRaisesRegex(EvidenceError,"healthy_or_stale"):
                native_failure(Artifacts(d),descriptor,**kwargs)
            failure["image_sha256"]=image["sha256"]
            descriptor=ComposedContractTests.write(d,"failure.json",failure)
            original["proposal"]=False
            with self.assertRaisesRegex(EvidenceError,"healthy_or_stale"):
                native_failure(Artifacts(d),descriptor,**kwargs)

    def test_statistics_implementation_is_bound(self):
        code=evaluator_identity()
        self.assertIn("trace_gc/qualification.py",code)
        self.assertIn("src/paper_qualification_v1.py",code)

    def test_strict_json_byte_binding_and_final_recheck(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/"artifact.json";raw=b'{"v":1}';path.write_bytes(raw)
            store=Artifacts(d);descriptor={"relative":"artifact.json","sha256":hashlib.sha256(raw).hexdigest()}
            self.assertEqual(store.json(descriptor),{"v":1})
            path.write_bytes(b'{"v":2}')
            with self.assertRaisesRegex(EvidenceError,"during_evaluation"):store.recheck()
            raw=b'{"v":1,"v":2}';path.write_bytes(raw);descriptor["sha256"]=hashlib.sha256(raw).hexdigest()
            with self.assertRaisesRegex(EvidenceError,"duplicate_json"):Artifacts(d).json(descriptor)

    def test_containment_before_read(self):
        with tempfile.TemporaryDirectory() as d:
            with patch.object(Path,"read_bytes",side_effect=AssertionError("must not read")):
                with self.assertRaises(ValueError):Artifacts(d).bytes({"relative":"../outside.json","sha256":"a"*64})

    def test_missing_real_bundle_is_blocked_without_qualification(self):
        with tempfile.TemporaryDirectory() as d:
            result=evaluate(d,{"relative":"missing.json","sha256":"a"*64},expected_preregistration_sha256="b"*64,trust=TrustStore())
            self.assertEqual(result["status"],"BLOCKED")
            self.assertFalse(result["qualification_pass"])
            self.assertFalse(result["independent_human_qualification"])

    def test_failed_regression_does_not_open_unseen_source(self):
        from src.parallel_source_v4.promotion import IMAGE_CONFIGURATION
        with tempfile.TemporaryDirectory() as d:
            def write(name,value,raw=False):
                data=value if raw else json.dumps(value).encode()
                path=Path(d)/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
                return {"relative":name,"sha256":hashlib.sha256(data).hexdigest()}
            protocol=ProtocolTests().protocol();protocol["registered_utc"]="2026-01-01T00:00:00Z"
            documents={"protocol.json":write("prereg/protocol.json",protocol)}
            name="amendment-04/evaluator-clarification.json";documents[name]=write("prereg/"+name,CLARIFICATION)
            for name in ("protocol.md","amendment-02/protocol-amendment.md","amendment-03/protocol-amendment.md"):
                documents[name]=write("prereg/"+name,b"Authored protocol document.",True)
            name="metadata-inventory/exposure-registry.jsonl";documents[name]=write("prereg/"+name,b"",True)
            prereg=write("prereg/current.json",{"schema_version":"qualification-preregistration-current-v1",
                "numeric_targets_unchanged":True,"reference_review_occurred":False,
                "base_protocol_and_additive_amendments":{k:v["sha256"] for k,v in documents.items()}})
            unseen={"relative":"unseen-must-not-open.pdf","sha256":"f"*64}
            bundle={"version":VERSION,"study_id":"authored-boundary-test","execution_mode":"AUTHORED_CONTRACT_TEST",
                "preregistration":prereg,"configuration":write("config.json",IMAGE_CONFIGURATION),
                "regression":write("regression.json",{"status":"FAIL"}),"source_map":write("source-map.json",{}),
                **{k:unseen for k in ("access","sampling","screening","sources","references","execution")},
                "roles":roles(),"phases":[]}
            descriptor=write("bundle.json",bundle)
            original=Path.read_bytes
            def guarded(path):
                if path.name=="unseen-must-not-open.pdf":raise AssertionError("unseen source was opened")
                return original(path)
            with patch.object(Path,"read_bytes",guarded):
                result=evaluate(d,descriptor,expected_preregistration_sha256=prereg["sha256"],trust=TrustStore())
            self.assertEqual(result["status"],"BLOCKED")
            self.assertFalse(result["qualification_pass"])

    def test_blocked_publication_is_immutable_and_redacted(self):
        with tempfile.TemporaryDirectory() as d:
            result={"version":VERSION,"status":"BLOCKED","qualification_pass":False,"graph_qualification_registered":False,
                "reason":"missing_evidence","independent_human_qualification":False,"graph_writes":0,"paid_calls":0}
            receipt=publish(d,"result",result)
            public=(Path(d)/"result/public-summary.json").read_text()
            self.assertNotIn("private-source-text",public)
            self.assertNotIn("private-study",public)
            with self.assertRaisesRegex(EvidenceError,"fresh_evaluation"):publish(d,"result",result)
            descriptor={"relative":"result/evaluation.json","sha256":receipt["private_evaluation_sha256"]}
            with self.assertRaisesRegex(EvidenceError,"nonpassing_or_authored"):
                verify_published(d,descriptor,expected_preregistration_sha256="a"*64,trust=TrustStore())

    def test_forged_pass_dictionary_cannot_be_published(self):
        with tempfile.TemporaryDirectory() as d:
            result={"version":VERSION,"status":"PASS","qualification_pass":True,"graph_qualification_registered":False,
                "independent_human_qualification":False}
            with self.assertRaisesRegex(EvidenceError,"unverified_publication"):
                publish(d,"forged",result)
            self.assertFalse((Path(d)/"forged").exists())


@unittest.skipUnless(PDF_STACK_AVAILABLE, "optional PDF/image fixture dependencies unavailable")
class ImageLineageTests(unittest.TestCase):
    def fixture(self, root, correction=False):
        from tests.test_selector_promotion_image import fixture
        from src.parallel_source_v4.promotion_image import apply_image_route
        from trace_gc.pdf_image_evidence import candidate_hash
        original,entry,args,blobs=fixture(correction=correction)
        selected,_=apply_image_route(original,original,entry,**args)
        for name,raw in blobs.items():(Path(root)/name).write_bytes(raw)
        def descriptor(name):return {"relative":name,"sha256":hashlib.sha256(blobs[name]).hexdigest()}
        value={key:descriptor(name) for key,name in {"preparation":"preparation","execution":"execution",
            "candidate":"reviewed_candidate","raw_ocr":"raw_ocr","crop":"crop_image","catalog":"catalog_records","handoff":"handoff"}.items()}
        value["review_context_id"]="authored-candidate_reviewer"
        value["access_events"]=[{"context_id":"authored-candidate_reviewer","at":"2026-09-28T09:30:00Z",
            "input_sha256":[descriptor("page_image")["sha256"],descriptor("raw_ocr")["sha256"]]}]
        assigned=roles();assigned["candidate_reviewer"]["principal"]="authored-test"
        reference=deepcopy(args["fidelity_reference"])
        closure={k:v for k,v in entry["scope_review"]["closure"].items() if k != "next_page"}
        scope={"version":"paper-image-scope-review-v1","candidate_sha256":candidate_hash(json.loads(blobs["reviewed_candidate"])),
            "source_sha256":descriptor("source.pdf")["sha256"],"image_sha256":descriptor("page_image")["sha256"],
            "decision":"complete","reviewer":"authored-test","context_id":"authored-candidate_reviewer",
            "reviewed_at":"2026-09-28T10:30:00Z","native_image_disagreement_examined":True,"no_page_continuation":True,
            "closure":closure}
        raw=json.dumps(scope).encode();(Path(root)/"scope.json").write_bytes(raw)
        value["scope_review"]={"relative":"scope.json","sha256":hashlib.sha256(raw).hexdigest()}
        from trace_gc.pdf_structure_parallel_v4 import seal
        from trace_gc.pdf_source_parallel_v4 import digest_value
        selected=seal({**selected,"closing_boundary":{"kind":closure["kind"],"review_sha256":digest_value(scope)}})
        reference["source_extent_proof"]={"version":"paper-image-reference-extent-v1",
            "image_sha256":descriptor("page_image")["sha256"],"closure":deepcopy(closure)}
        text=reference["text"]
        reference["typed_transcription"]={"version":"source-first-image-reference-v1",
            "text_sha256":hashlib.sha256(text.encode()).hexdigest(),"image_sha256":descriptor("page_image")["sha256"],
            "spans":[{"start":0,"end":len(text),"text":text,"page_no":1}]}
        kwargs=dict(source={"source":descriptor("source.pdf"),"image":descriptor("page_image")},selected=selected,original=original,
            reference=reference,code=json.loads(blobs["execution"])["code_sha256"],roles=assigned,
            image_access={"engine":json.loads(blobs["raw_ocr"])["engine"],"revision":json.loads(blobs["raw_ocr"])["revision"],
                "decoding":deepcopy(json.loads(blobs["raw_ocr"])["configuration"])},
            times={"references_frozen":datetime(2026,9,28,9,tzinfo=timezone.utc),
                   "predictions_frozen":datetime(2026,9,28,11,tzinfo=timezone.utc)},at="2026-09-28T12:00:00Z")
        return value,kwargs

    def test_actual_artifact_readback_with_authored_ocr_and_unicode_reference(self):
        for correction in (False,True):
            with self.subTest(correction=correction),tempfile.TemporaryDirectory() as d:
                value,kwargs=self.fixture(d,correction)
                result=_image_candidate(Artifacts(d),value,**kwargs)
                self.assertEqual(result["corrected"],correction)

    def test_image_reference_offset_boolean_and_wrong_length_reject(self):
        for key,new in (("start",False),("page_no",True),("end",999)):
            with self.subTest(key=key),tempfile.TemporaryDirectory() as d:
                value,kwargs=self.fixture(d)
                kwargs["reference"]["typed_transcription"]["spans"][0][key]=new
                with self.assertRaisesRegex(EvidenceError,"offset_readback"):_image_candidate(Artifacts(d),value,**kwargs)

    def test_candidate_context_cannot_receive_reference(self):
        with tempfile.TemporaryDirectory() as d:
            value,kwargs=self.fixture(d)
            value["access_events"][0]["input_sha256"].append("f"*64)
            with self.assertRaisesRegex(EvidenceError,"received_reference"):_image_candidate(Artifacts(d),value,**kwargs)

    def test_frozen_image_reference_requires_actual_following_witness(self):
        with tempfile.TemporaryDirectory() as d:
            value,kwargs=self.fixture(d)
            kwargs["reference"]["source_extent_proof"]["closure"]["excluded_regions"]=[[0,0,10,10]]
            with self.assertRaisesRegex(EvidenceError,"region_is_blank"):_image_candidate(Artifacts(d),value,**kwargs)

    def test_selected_closure_cannot_keep_unrelated_scope_hash(self):
        with tempfile.TemporaryDirectory() as d:
            value,kwargs=self.fixture(d)
            kwargs["selected"]["closing_boundary"]["review_sha256"]="f"*64
            with self.assertRaisesRegex(EvidenceError,"closure_not_bound"):_image_candidate(Artifacts(d),value,**kwargs)

    def test_rehashed_preparation_link_forgery_rejects(self):
        with tempfile.TemporaryDirectory() as d:
            value,kwargs=self.fixture(d)
            p=Path(d)/"execution";execution=json.loads(p.read_bytes());execution["preparation_sha256"]="a"*64
            raw=json.dumps(execution).encode();p.write_bytes(raw);value["execution"]["sha256"]=hashlib.sha256(raw).hexdigest()
            with self.assertRaisesRegex(EvidenceError,"preparation_lineage"):_image_candidate(Artifacts(d),value,**kwargs)

    def test_image_ocr_revision_and_configuration_match_frozen_access(self):
        for field in ("revision","decoding"):
            with self.subTest(field=field),tempfile.TemporaryDirectory() as d:
                value,kwargs=self.fixture(d)
                kwargs["image_access"][field]="wrong-revision" if field=="revision" else {"language":"wrong-language"}
                with self.assertRaisesRegex(EvidenceError,"frozen_access_configuration"):
                    _image_candidate(Artifacts(d),value,**kwargs)

    def test_source_validation_uses_hash_bound_buffers_during_image_swap(self):
        import fitz
        from io import BytesIO
        from PIL import Image
        from tests.test_selector_promotion import closure_fixture
        _,_,args,assets=closure_fixture()
        with tempfile.TemporaryDirectory() as d:
            blobs={"source":args["pdf_bytes"],"page":args["pdf_bytes"],"native":json.dumps(args["native"]).encode(),
                "image":assets["page1.png"]}
            value={"available":True,"unavailable_reason":None,"doi":None}
            for key,raw in blobs.items():
                (Path(d)/key).write_bytes(raw);value[key]={"relative":key,"sha256":hashlib.sha256(raw).hexdigest()}
            self.assertEqual(_source(Artifacts(d),value)[0],args["native"])
            invalid_native=deepcopy(args["native"]);invalid_native[0]["id"]=False
            invalid=json.dumps(invalid_native).encode();(Path(d)/"native").write_bytes(invalid)
            value["native"]["sha256"]=hashlib.sha256(invalid).hexdigest()
            with self.assertRaisesRegex(EvidenceError,"native_review_spans"):
                _source(Artifacts(d),value)
            (Path(d)/"native").write_bytes(blobs["native"]);value["native"]["sha256"]=hashlib.sha256(blobs["native"]).hexdigest()
            with Image.open(BytesIO(blobs["image"])) as image:
                buffer=BytesIO();Image.new("RGB",image.size,"white").save(buffer,format="PNG")
            bad=buffer.getvalue();(Path(d)/"image").write_bytes(bad);value["image"]["sha256"]=hashlib.sha256(bad).hexdigest()
            original_open=fitz.open
            def swap(*args,**kwargs):
                (Path(d)/"image").write_bytes(blobs["image"])
                return original_open(*args,**kwargs)
            try:
                with patch("fitz.open",side_effect=swap),self.assertRaisesRegex(EvidenceError,"review_image_not_original"):
                    _source(Artifacts(d),value)
            finally:
                (Path(d)/"image").write_bytes(bad)


@unittest.skipUnless(PDF_STACK_AVAILABLE, "optional PDF/image fixture dependencies unavailable")
class ConverterReplayTests(unittest.TestCase):
    def fixture(self, root):
        from tests.test_selector_promotion import closure_fixture
        from src.parallel_source_v4.extraction import native_document,predict
        original,_,args,_=closure_fixture()
        native=args["native"];identity={"source":original["source_sha256"],"page":original["page_sha256"]}
        payloads={"docling":{"status":"success"},"docling_document":native_document(native),
            "grobid":{"status":"success","text":original["text"]},
            "mineru":{"status":"success","blocks":[]},"olmocr":{"status":"success","raw_text":original["text"]}}
        def write(name,value):
            raw=json.dumps(value,sort_keys=True).encode();(Path(root)/name).write_bytes(raw)
            return {"relative":name,"sha256":hashlib.sha256(raw).hexdigest()}
        inputs={name:write(name+".json",value) for name,value in payloads.items()}
        access={"methods":{method:{"engine":"authored-"+method,"revision":"authored-no-converter-call"} for method in METHODS}}
        execution={"configuration_sha256":"a"*64,"runtime":{"fixture":True},"code_sha256":{"fixture":"b"*64},
            "limits":{"fixture":True},"completed_at":"2026-09-28T11:00:00Z"}
        producers={}
        for method in METHODS:
            engine=access["methods"][method]
            producers[method]=write(method+".json",{"version":"paper-converter-execution-v1","method":method,
                "engine":engine["engine"],"revision":engine["revision"],"access_sha256":digest(engine),
                "source_sha256":identity["source"],"page_sha256":identity["page"],
                "configuration_sha256":execution["configuration_sha256"],"runtime_sha256":digest(execution["runtime"]),
                "code_sha256":execution["code_sha256"],"limits_sha256":digest(execution["limits"]),
                "started_at":"2026-09-28T10:00:00Z","completed_at":"2026-09-28T10:01:00Z",
                "execution_kind":"LOCAL_CONVERTER","status":"success","output_sha256":{name:inputs[name]["sha256"] for name in CACHE_OUTPUTS[method]},
                "raw_response":write(method+"-raw.json",{"authored_fixture_not_execution":True}),"new_paid_api_calls":0,"production_graph_writes":0})
        kwargs={"source_sha256":identity["source"],"page_sha256":identity["page"],"native_lines":native,"page_size":[500,500]}
        paths={name:Path(root)/d["relative"] for name,d in inputs.items()}
        predictions={method:predict(method,paths,kwargs,expected_input_hashes={name:d["sha256"] for name,d in inputs.items()}) for method in METHODS}
        arguments=dict(predictions=predictions,source_identity=identity,native=native,page_size=[500,500],access=access,execution=execution,
            times={"references_frozen":datetime(2026,9,28,9,tzinfo=timezone.utc)})
        return {"converter_inputs":inputs,"producer_receipts":producers},arguments

    def test_all_arms_replay_exact_and_copied_primary_rejects(self):
        with tempfile.TemporaryDirectory() as d:
            case,kwargs=self.fixture(d);replay_converters(Artifacts(d),case,**kwargs)
            kwargs["predictions"]["parallel_grobid_v4"]=kwargs["predictions"]["parallel_structure_v4"]
            with self.assertRaisesRegex(EvidenceError,"not_derived"):
                replay_converters(Artifacts(d),case,**kwargs)

    def test_rehashed_converter_receipt_cannot_target_another_source(self):
        with tempfile.TemporaryDirectory() as d:
            case,kwargs=self.fixture(d)
            descriptor=case["producer_receipts"]["parallel_structure_v4"];path=Path(d)/descriptor["relative"]
            receipt=json.loads(path.read_bytes());receipt["source_sha256"]="f"*64
            raw=json.dumps(receipt).encode();path.write_bytes(raw);descriptor["sha256"]=hashlib.sha256(raw).hexdigest()
            with self.assertRaisesRegex(EvidenceError,"source_access"):
                replay_converters(Artifacts(d),case,**kwargs)


@unittest.skipUnless(PDF_STACK_AVAILABLE, "optional PDF/image fixture dependencies unavailable")
class ComposedContractTests(unittest.TestCase):
    """Compose the entire driver with explicitly substituted external ports.

    No real regression PASS, converter execution, study source, or reviewer is
    fabricated as empirical evidence. Separate tests exercise the real source,
    converter replay and image lineage adapters. These fixtures only establish
    that the composed signed contract and all fixed denominators are reachable.
    """
    def fixture(self, root):
        from tests.test_selector_promotion import closure_fixture
        from trace_gc.pdf_structure_parallel_v4 import seal
        from trace_gc.pdf_source_parallel_v4 import digest_value
        from src.parallel_source_v4.promotion import IMAGE_CONFIGURATION
        template,_,args,_=closure_fixture()
        native=args["native"]
        write=lambda name,value:self.write(root,name,value)
        code={"authored-port":"a"*64};image_code={"authored-port":"b"*64};runtime={"authored-port":True}
        config=deepcopy(IMAGE_CONFIGURATION)
        selection=ProtocolTests().selection()
        screens=selection["recent_screen"]+selection["historical_screen"]
        for i,work in enumerate(screens):
            selection["screen"][work]["strata"]=["partial"] if i<20 else ["absent"] if i<40 else (
                [k for k in QUOTAS if k not in {"partial","absent"}] if i<80 else [])
        selection["challenge"]=sorted(screens[:80])
        selection["exposure_snapshot"]=write("exposure.json",{"version":"paper-exposure-snapshot-v1",
            "reconciled_at":selection["reconciled_at"],"entries":[]})
        sampled=set(selection["primary"]+selection["challenge"])
        protocol=ProtocolTests().protocol();protocol["registered_utc"]="2025-12-31T00:00:00Z"
        docs={"protocol.json":write("prereg/protocol.json",protocol)}
        name="amendment-04/evaluator-clarification.json";docs[name]=write("prereg/"+name,CLARIFICATION)
        for name in ("protocol.md","amendment-02/protocol-amendment.md","amendment-03/protocol-amendment.md"):
            docs[name]=write("prereg/"+name,"Authored protocol fixture; no empirical claim.")
        name="metadata-inventory/exposure-registry.jsonl"
        path=Path(root)/"prereg"/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b"")
        docs[name]={"relative":"prereg/"+name,"sha256":hashlib.sha256(b"").hexdigest()}
        frames={}
        for role in ("recent","historical"):
            name=role+".json";desc=write("prereg/"+name,[{"work_id":w,"version_id":w+"v1","doi":None} for w in selection[role+"_frame"]])
            frames[role]={"identity_projection_relative":name,"sha256":desc["sha256"]}
        prereg=write("prereg/current.json",{"schema_version":"qualification-preregistration-current-v1",
            "numeric_targets_unchanged":True,"reference_review_occurred":False,"frames":frames,
            "base_protocol_and_additive_amendments":{k:v["sha256"] for k,v in docs.items()}})
        engines={"parallel_structure_v4":"docling","parallel_grobid_v4":"grobid",
            "parallel_mineru_v4":"mineru","parallel_olmocr_v4":"olmocr","image":"Windows.Media.Ocr"}
        access_methods={}
        for method,engine in engines.items():
            asset=write(method+"-asset.json",{"authored_not_a_model":True})
            stdout=write(method+"-stdout.json",{"authored_not_a_probe":True})
            probe=write(method+"-probe.json",{"version":"paper-local-readiness-v1","engine":engine,
                "revision":"authored-port","asset_sha256":[asset["sha256"]],"exit_code":0,
                "local_only":True,"stdout":stdout,"completed_at":"2025-12-31T23:30:00Z"})
            access_methods[method]={"status":"AVAILABLE_VERIFIED_LOCAL","engine":engine,"revision":"authored-port",
                "assets":[asset],"probe":probe,"license":"authored-port","device":"CPU","prompt_sha256":None,"decoding":{}}
        access={"version":"paper-local-access-v1","methods":{m:access_methods[m] for m in METHODS},
            "image_ocr":access_methods["image"],"code_sha256":code,"image_code_sha256":image_code,"runtime":runtime,
            "configuration_sha256":digest_value(config),"limits":{"request_characters":10000,"request_tokens":10000,
                "retries":0,"timeout_seconds":60,"device_concurrency":1,"crop_policy":"authored-port"},
            "new_paid_api_calls":0,"production_graph_writes":0}
        sources,references,cases={},{},{}
        for work in sorted(set(selection["primary"]+screens)):
            # Distinct declared source identities, consumed only by the mocked
            # source port. These are not PDFs and cannot pass the real adapter.
            assets={key:{"relative":"authored-not-a-pdf", "sha256":hashlib.sha256((key+work).encode()).hexdigest()}
                for key in ("source","page","image","native")}
            assets.update(available=True,unavailable_reason=None,doi=None)
            sources[work]={"version_id":work+"v1","assets":assets}
            if work not in sampled:continue
            tags=selection["screen"].get(work,{}).get("strata",[])
            status="partial_on_page_one" if "partial" in tags else "no_abstract_text" if "absent" in tags else "complete"
            image_route="image_only" in tags
            original=seal({**template,"source_sha256":assets["source"]["sha256"],"page_sha256":assets["page"]["sha256"],
                "image_sha256":assets["image"]["sha256"],"status":status if not image_route else "uncertain",
                "proposal":status=="complete" and not image_route,"complete_candidate":status=="complete" and not image_route,
                "section_owner":"abstract" if status=="complete" and not image_route else None})
            selected=original
            reference=deepcopy(args["fidelity_reference"]);reference["status"]=status
            review=reference["fidelity_review"]
            review.update(reviewer="authored-custodian",reviewer_kind="assistant",reviewed_at="2026-01-01T01:10:00Z",
                independent_review=False,source_before_predictions=True,
                source_sha256=assets["source"]["sha256"],page_sha256=assets["page"]["sha256"])
            if image_route:
                region={"page_no":1,"coord_origin":"TOPLEFT","bbox":[1,1,30,30]}
                selected=seal({**original,"proposal":True,"complete_candidate":True,"status":"complete","section_owner":"abstract",
                    "representation":"reviewed-image-transcription-v1","spans":[],"image_regions":[region]})
                review["boundary"].update(representation="image_regions",image_sha256=assets["image"]["sha256"],
                    reference_regions=[region],page_size=[500,500])
            events=[{"kind":"image_inspection","context_id":"authored-source_reviewer","at":"2026-01-01T01:10:00Z",
                "input_sha256":[assets["image"]["sha256"]],"decision_sha256":digest(reference)}]
            events.extend({"kind":kind,"context_id":"authored-adjudicator","at":stamp,
                "input_sha256":[assets["image"]["sha256"]],"decision_sha256":digest(reference)} for kind,stamp in (
                    ("adjudication","2026-01-01T01:20:00Z"),("audit","2026-01-01T01:30:00Z")))
            references[work]={"reference":reference,"initial_reference":reference,"history":[reference],"events":events,
                "unresolved_disagreement":False,"requires_adjudication":image_route,"audit_completed":True,
                "audit_material_error":False,"full_dimension_audit_completed":False}
            key=hashlib.sha256(work.encode()).hexdigest()
            prediction=write("predictions/"+key+".json",original)
            selected_descriptor=write("selected/"+key+".json",selected) if image_route else prediction
            cases[work]={"assessments":{m:prediction for m in METHODS},"selected":selected_descriptor,
                "route":"image_review" if image_route else "native_or_hold","image_evidence":{} if image_route else None,
                "native_failure":None,"converter_inputs":{},"producer_receipts":{},"failure_history":[]}
        execution={"version":"paper-four-arm-execution-v1","started_at":"2026-01-01T02:10:00Z",
            "completed_at":"2026-01-01T02:50:00Z","code_sha256":code,"image_code_sha256":image_code,"runtime":runtime,
            "configuration_sha256":digest_value(config),"limits":access["limits"],"cases":cases,
            "costs":{"paid_calls":0,"paid_spend_usd":0,"graph_writes":0},"stage_reports":[
                {"stage":stage,"elapsed_seconds":None,"cpu_seconds":None,"failures":0,"retries":0,"calls":0,
                 "review_count":0,"review_active_seconds":None} for stage in
                ("converters","ocr","source_review","adjudication","candidate_review","evaluation")]}
        bundle={"version":VERSION,"study_id":"composed-authored-contract","execution_mode":"AUTHORED_CONTRACT_TEST",
            "preregistration":prereg,"configuration":write("config.json",config),
            "regression":write("regression.json",{"input_file_hashes":{},"derived_assessment_files_sha256":{}}),
            "source_map":write("source-map.json",{}),"access":write("access.json",access),
            "sampling":write("sampling.json",{k:v for k,v in selection.items() if k not in {"screen","challenge"}}),
            "screening":write("screening.json",{k:selection[k] for k in ("screen","challenge")}),
            "sources":write("sources.json",sources),"references":write("references.json",references),
            "execution":write("execution.json",execution),"roles":roles(),"phases":[]}
        signer,_,kwargs=signed_phases();trust=kwargs["trust"]
        hashes={k:bundle[k]["sha256"] for k in ("preregistration","configuration","regression","source_map","access")}
        hashes["roles"]=digest(bundle["roles"]);previous=None
        for i,(phase,additions) in enumerate(zip(PHASES,((),("sampling","sources"),("screening","references"),("execution",)))):
            hashes.update({k:bundle[k]["sha256"] for k in additions})
            receipt=signer.issue("RUN_CHECKPOINT",{"contract":VERSION,"study_id":bundle["study_id"],
                "execution_mode":bundle["execution_mode"],"phase":phase,"artifact_hashes":deepcopy(hashes),
                "previous_receipt_sha256":previous,"review_policy":REVIEW_POLICY,"independent_human_review":False,
                "context_id":"authored-"+("operator" if i==3 else "custodian")},
                issued_at=f"2026-01-01T0{i}:00:00Z",expires_at="2027-01-01T00:00:00Z")
            bundle["phases"].append(receipt);previous=digest(receipt)
        descriptor=write("bundle.json",bundle)
        stack=ExitStack();self.addCleanup(stack.close)
        module="src.paper_qualification_v1."
        stack.enter_context(patch(module+"verify_regression",return_value={"status":"PASS"}))
        stack.enter_context(patch(module+"evaluator_identity",return_value=code))
        stack.enter_context(patch(module+"runtime_receipt",return_value=runtime))
        stack.enter_context(patch("src.parallel_source_v4.image_ocr.code_identity",return_value=image_code))
        stack.enter_context(patch(module+"_source",side_effect=lambda store,value:(native,{k:value[k]["sha256"] for k in ("source","page","image","native")})))
        stack.enter_context(patch(module+"replay_converters"))
        stack.enter_context(patch(module+"_image_candidate",return_value={"corrected":False,"raw_transcription_matches_final":True}))
        page=stack.enter_context(patch("fitz.open"))
        original_artifact_bytes=Artifacts.bytes
        stack.enter_context(patch.object(Artifacts,"bytes",autospec=True,side_effect=lambda store,descriptor:
            b"authored-not-a-pdf" if descriptor.get("relative")=="authored-not-a-pdf" else original_artifact_bytes(store,descriptor)))
        page.return_value.__enter__.return_value.__getitem__.return_value.rect.width=500
        page.return_value.__enter__.return_value.__getitem__.return_value.rect.height=500
        return descriptor,bundle,dict(expected_preregistration_sha256=prereg["sha256"],trust=trust,at="2026-01-02T00:00:00Z")

    @staticmethod
    def write(root,name,value):
        raw=json.dumps(value,sort_keys=True).encode();path=Path(root)/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
        return {"relative":name,"sha256":hashlib.sha256(raw).hexdigest()}

    def test_composed_authored_pass_cannot_qualify_or_relabel_real(self):
        with tempfile.TemporaryDirectory() as d:
            descriptor,bundle,kwargs=self.fixture(d)
            result=evaluate(d,descriptor,**kwargs)
            self.assertEqual(result["status"],"AUTHORED_CONTRACT_PASS_NOT_QUALIFICATION",result)
            self.assertFalse(result["qualification_pass"])
            self.assertEqual(result["primary"]["n"],400)
            self.assertEqual(result["all_sampled_case_count"],480)
            self.assertEqual(result["screened_exposure_count"],1200)
            self.assertEqual(result["image_counts"]["image_proposals"],40)
            self.assertEqual(set(result["measured_arms"]),set(METHODS))
            self.assertEqual(result["measured_arms"]["parallel_grobid_v4"]["selection"],"diagnostic_only")
            anchors={k:kwargs[k] for k in ("expected_preregistration_sha256","trust")}
            receipt=publish(d,"verified-authored",result,**anchors)
            self.assertFalse(receipt["qualification_pass"])
            changed=deepcopy(result);changed["primary"]["strict_correct"]=0
            with self.assertRaisesRegex(EvidenceError,"result_changed_before_publication"):
                publish(d,"mutated-result",changed,**anchors)
            self.assertFalse((Path(d)/"mutated-result").exists())
            bundle["execution_mode"]="REAL_LOCAL"
            result=evaluate(d,self.write(d,"relabelled.json",bundle),**kwargs)
            self.assertEqual(result["status"],"BLOCKED")
            self.assertFalse(result["qualification_pass"])


if __name__=="__main__":unittest.main()
