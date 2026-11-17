"""Mixed prefix plus sealed pending conversion; no converter or corpus access."""
from __future__ import annotations

import json
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.parallel_source_v4 import assessment_migration_v3 as migration
from src.parallel_source_v4 import assessment_producer as producer
from src.parallel_source_v4.common import digest, write_once

try:
    import fitz
    from trace_gc.pdf_source_parallel_v4 import source_lines
except ImportError:
    fitz = None


class PendingInventoryTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.origin = self.root / "old"
        self.checkout = self.root / "checkout"
        source = self.checkout / "src/parallel_source_v4/assessment_producer.py"
        source.parent.mkdir(parents=True)
        source.write_text("frozen", encoding="utf-8")
        self.protocol = {"ids": ["a", "b", "c"], "code_sha256": {
            "src/parallel_source_v4/assessment_producer.py": digest(source)},
            "manifest_relative": "manifest.json", "manifest_sha256": "0" * 64,
            "profile_relative": "profile.json", "profile_sha256": "1" * 64,
            "source_root": None, "query_independent": True, "scope": "FULL_CORPUS"}
        self.protocol_sha = write_once(self.origin / "protocol.json", self.protocol)
        self.protocol["stopped_execution_checkout"] = str(self.checkout)
        for sid in ("a", "b"):
            write_once(self.origin / "rows" / (sid + ".json"), {
                "sample_id": sid, "protocol_sha256": self.protocol_sha,
                "eligibility": "ineligible", "state": "ineligible",
                "assessment_relative": None, "assessment_sha256": None})
        self.pending = self.origin / "attempts" / "c"
        write_once(self.pending / "intent.json", {"sample_id": "c",
            "protocol_sha256": self.protocol_sha})
        document_sha = write_once(self.pending / "document.json", {"texts": [], "body": {"children": []}})
        write_once(self.pending / "conversion.json", {"status": "success",
            "docling_status": "ConversionStatus.SUCCESS", "model_called": True,
            "error_class": None, "document_sha256": document_sha})

    def test_exact_mixed_prefix_and_one_sealed_pending(self):
        records, pending = migration._prefix(self.root, self.origin, self.protocol, 2)
        self.assertEqual([r["sample_id"] for r in records], ["a", "b"])
        self.assertEqual(pending["sample_id"], "c")
        self.assertEqual(pending["origin_document_sha256"], digest(self.pending / "document.json"))
        self.assertIsNone(pending["origin_receipt_sha256"])

    def test_partial_or_extra_pending_holds(self):
        (self.pending / "document.json").unlink()
        with self.assertRaisesRegex(ValueError, "next_attempt_not_exact"):
            migration._prefix(self.root, self.origin, self.protocol, 2)
        write_once(self.pending / "document.json", {"texts": []})
        (self.pending / "worker-failure.json").write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "next_attempt_not_exact"):
            migration._prefix(self.root, self.origin, self.protocol, 2)

    def test_changed_pending_document_holds(self):
        (self.pending / "document.json").write_text('{"texts":[{"text":"forged"}]}', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "expected|hash"):
            migration._prefix(self.root, self.origin, self.protocol, 2)

    def test_later_attempt_holds(self):
        (self.origin / "attempts" / "later").mkdir()
        with self.assertRaisesRegex(ValueError, "later_or_unknown_attempt"):
            migration._prefix(self.root, self.origin, self.protocol, 2)

    def test_origin_producer_code_drift_holds(self):
        (self.checkout / "src/parallel_source_v4/assessment_producer.py").write_text("changed", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "call_order_code_unverified"):
            migration._prefix(self.root, self.origin, self.protocol, 2)

    def test_nested_checkout_cannot_substitute_stopped_execution_checkout(self):
        nested = self.root / "historical-nested-origin"
        source = nested / "src/parallel_source_v4/assessment_producer.py"
        source.parent.mkdir(parents=True)
        source.write_text("historical different producer", encoding="utf-8")
        self.protocol["stopped_execution_checkout"] = str(nested)
        with self.assertRaisesRegex(ValueError, "call_order_code_unverified"):
            migration._prefix(self.root, self.origin, self.protocol, 2)


class StageGuardTests(unittest.TestCase):
    def test_nested_v2_prefix_resolves_authenticated_converter_leaf(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan_sha = write_once(root / "old-v2-plan.json", {
                "schema_version": migration.migration_v2.VERSION,
                "imports": [{"sample_id": "a", "origin_row_sha256": "1" * 64}]})
            imported = {"schema_version": migration.migration_v2.ROW_VERSION,
                "sample_id": "a", "eligibility": "eligible"}
            protocol = {"migration": {"relative": "old-v2-plan.json", "sha256": plan_sha}}
            leaf = {"sample_id": "a", "eligibility": "eligible",
                "conversion_relative": "origin/attempts/a/conversion.json",
                "conversion_sha256": "2" * 64, "document_sha256": "3" * 64}
            with patch.object(migration.migration_v2, "_origin_receipt", return_value=(leaf, {})):
                self.assertEqual(migration._leaf_conversion_receipt(root, imported, protocol,
                    {"sample_id": "a"}), leaf)
            with patch.object(migration.migration_v2, "_origin_receipt", return_value=(imported, protocol)):
                with self.assertRaisesRegex(ValueError, "cycle"):
                    migration._leaf_conversion_receipt(root, imported, protocol, {"sample_id": "a"})

    def test_prepare_cannot_call_converter(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = {"new_code_sha256": migration.method_hashes(migration.REPO),
                    "new_evaluator_runtime": {"fixture": "runtime"}}
            plan_path = root / "plan.json"
            plan_path.write_text(json.dumps(plan), encoding="utf-8")
            with patch.object(migration, "prepare_plan", return_value=(plan_path, plan)), \
                 patch.object(migration, "runtime_receipt", return_value=plan["new_evaluator_runtime"]), \
                 patch.object(producer, "_run", side_effect=AssertionError("converter_called")):
                result = migration.run(root, root / "origin", root / "new", root / "old",
                    root / "python.exe", "a" * 40, "0" * 64, 2, 64)
            self.assertEqual(result["status"], "PLAN_PREPARED_NO_MODEL_CALL")

    def test_pending_import_cannot_claim_new_model_call(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "new"
            record = {"sample_id": "c", "origin_receipt_sha256": None,
                "origin_intent_sha256": "1" * 64, "origin_conversion_sha256": "2" * 64,
                "origin_document_sha256": "3" * 64}
            plan = {"schema_version": migration.VERSION, "pending_sealed_conversion": record,
                "new_code_sha256": {"code": "new"}, "manifest_sha256": "4" * 64,
                "profile_sha256": "5" * 64, "source_root": None,
                "new_max_documents_per_session": 64, "origin_protocol_sha256": "6" * 64}
            plan_sha = write_once(root / "plan.json", plan)
            protocol = {"code_sha256": plan["new_code_sha256"], "manifest_sha256": plan["manifest_sha256"],
                "profile_sha256": plan["profile_sha256"], "source_root": None,
                "converter_session": {"max_documents": 64},
                "migration": {"relative": "plan.json", "sha256": plan_sha}}
            write_once(output / "protocol.json", protocol)
            row = {"sample_id": "c", **{key + "_sha256": "0" * 64
                for key in ("source", "page", "image", "native")}}
            receipt = {"schema_version": migration.PENDING_ROW_VERSION, "sample_id": "c",
                "new_model_call": True}
            # Use a benign mocked origin conversion to reach exact receipt
            # comparison without any real converter or source access.
            with patch.object(migration, "_pending_origin", return_value=(
                    {"status": "success"}, {"texts": []})):
                with self.assertRaisesRegex(ValueError, "pending_import_row_lineage_changed"):
                    migration.verify_pending_receipt(root, row, receipt, output, None,
                        protocol, [], [100, 100])


@unittest.skipUnless(fitz, "PyMuPDF required for actual source geometry")
class ReassessmentTests(unittest.TestCase):
    def test_import_pending_cached_document_crash_resume_no_converter(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            origin, output = root / "origin", root / "new"
            with fitz.open() as pdf:
                page = pdf.new_page(width=595, height=842)
                page.insert_text((40, 60), "Abstract", fontsize=12)
                payload = pdf.tobytes()
            source = root / "source.pdf"
            source.write_bytes(payload)
            with fitz.open(stream=payload, filetype="pdf") as pdf:
                native = source_lines(pdf[0])
            rows = [{"sample_id": sid, "physical_page": 1, "source_relative": "source.pdf",
                "source_root_id": "data_root", "source_sha256": hashlib.sha256(payload).hexdigest(),
                **{key + "_sha256": "0" * 64 for key in ("page", "image", "native")}}
                for sid in ("a", "b")]
            original = {"sample_id": "a", "eligibility": "ineligible", "state": "ineligible",
                "assessment_relative": None, "assessment_sha256": None}
            record = {"sample_id": "b", "origin_receipt_sha256": None,
                "origin_intent_sha256": "1" * 64, "origin_conversion_sha256": "2" * 64,
                "origin_document_sha256": "3" * 64}
            plan = {"schema_version": migration.VERSION, "ids": ["a", "b"],
                "imports": [{"sample_id": "a", "origin_row_sha256": "4" * 64,
                    "eligibility": "ineligible", "state": "ineligible",
                    "assessment_relative": None, "assessment_sha256": None}],
                "pending_sealed_conversion": record,
                "origin_run_relative": "origin", "origin_protocol_sha256": "5" * 64,
                "new_code_sha256": {"code": "new"},
                "new_evaluator_runtime": {"runtime": "new"},
                "manifest_sha256": "6" * 64, "profile_sha256": "7" * 64,
                "source_root": None, "new_max_documents_per_session": 64}
            plan_sha = write_once(root / "plan.json", plan)
            protocol = {"ids": ["a", "b"], "code_sha256": plan["new_code_sha256"],
                "evaluator_runtime": plan["new_evaluator_runtime"],
                "manifest_sha256": plan["manifest_sha256"],
                "profile_sha256": plan["profile_sha256"], "source_root": None,
                "converter_session": {"max_documents": 64}, "scope": "FULL_CORPUS",
                "migration": {"relative": "plan.json", "sha256": plan_sha}}
            write_once(output / "protocol.json", protocol)
            conversion = {"status": "success", "session_start": {"relative": "origin/session.json",
                "sha256": "8" * 64}, "wall_seconds": 0.2}
            document = {"texts": [], "body": {"children": []}}
            real_write = migration.write_once
            tripped = False

            def crash_after_assessment(path, value):
                nonlocal tripped
                if path == output / "rows/b.json" and not tripped:
                    tripped = True
                    raise RuntimeError("interrupted_before_pending_row")
                return real_write(path, value)

            def verified(_root, row, _source_root):
                return native, [595, 842], "ineligible" if row["sample_id"] == "a" else "eligible"

            patches = (patch.object(migration, "_origin_receipt", return_value=(original, {})),
                patch.object(migration, "_pending_origin", return_value=(conversion, document)),
                patch.object(producer, "_verified_row", side_effect=verified),
                patch.object(producer, "_check_code"))
            with patches[0], patches[1], patches[2], patches[3], \
                 patch.object(migration, "write_once", side_effect=crash_after_assessment):
                with self.assertRaisesRegex(RuntimeError, "interrupted_before_pending_row"):
                    migration._initialize(root, output, {"pdfs": rows}, protocol, None)
            pending_assessment = output / "assessments" / producer.METHOD / "b.json"
            prior_sha = digest(pending_assessment)
            with patches[0], patches[1], patches[2], patches[3], \
                 patch.object(producer, "ConverterSession", side_effect=AssertionError("converter_constructed")):
                migration._initialize(root, output, {"pdfs": rows}, protocol, None)
                migration._initialize(root, output, {"pdfs": rows}, protocol, None)
            self.assertEqual(digest(pending_assessment), prior_sha)
            pending_row = migration._read(output / "rows/b.json")
            self.assertEqual(pending_row["schema_version"], migration.PENDING_ROW_VERSION)
            self.assertIs(pending_row["new_model_call"], False)
            self.assertFalse((output / "attempts").exists())

class ResumeGuardTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.origin, self.output = self.root/'origin', self.root/'new'
        self.checkout, self.interpreter = self.root/'checkout', self.root/'python'
        self.old_sha = write_once(self.origin/'protocol.json', {})
        self.record = {'sample_id':'a','origin_row_sha256':'1'*64}
        self.pending = {'sample_id':'b'}
        self.plan = dict(schema_version=migration.VERSION, origin_run_relative='origin',
            origin_protocol_sha256=self.old_sha, origin_head='a'*40,
            origin_checkout=str(self.checkout.resolve()), origin_interpreter=str(self.interpreter.resolve()),
            imported_prefix_count=1, new_max_documents_per_session=64, imports=[self.record],
            pending_sealed_conversion=self.pending, new_code_sha256={'code':'new'},
            new_evaluator_runtime={'runtime':'new'}, manifest_relative='manifest.json',
            profile_relative='profile.json', source_root=None)
        self.path = self.root/'new.mixed-pending-migration-v3.json'
        self.audit = {'completed_rows':1,'row_hashes':[['a','1'*64]]}
        self.gate = dict(receipt='gate.json',receipt_sha256=write_once(self.root/'gate.json',
            {'base_method_hashes':self.plan['new_code_sha256']}), policy='policy.json',
            policy_sha256='0'*64, configuration='config.json',source_map='map.json')

    def run_plan(self, gate=None):
        return migration.run(self.root,self.origin,self.output,self.checkout,self.interpreter,
                             'a'*40,self.old_sha,1,64,gate=gate)

    def patches(self):
        from contextlib import ExitStack
        stack = ExitStack()
        stack.enter_context(patch.object(migration.migration_v1,'_origin_audit',return_value=self.audit))
        stack.enter_context(patch.object(migration,'_prefix',return_value=([self.record],self.pending)))
        stack.enter_context(patch.object(migration,'method_hashes',return_value={'code':'new'}))
        stack.enter_context(patch.object(migration,'runtime_receipt',return_value={'runtime':'new'}))
        return stack

    def test_existing_plan_changed(self):
        for key in ('origin_run_relative','origin_protocol_sha256','origin_head','origin_checkout',
                    'origin_interpreter','imported_prefix_count','new_max_documents_per_session','schema_version'):
            self.path.write_text(json.dumps(dict(self.plan, **{key:'changed'})))
            with self.subTest(key=key), patch.object(migration,'prepare_plan',side_effect=AssertionError), \
                    patch.object(producer,'_run',side_effect=AssertionError):
                with self.assertRaisesRegex(ValueError,'existing_sealed_prefix_plan_changed'):
                    self.run_plan()

    def test_resumed_origin_changed(self):
        write_once(self.path,self.plan)
        for change in ('completed_rows','row_hashes','imports','pending'):
            with self.subTest(change=change), self.patches(), patch.object(producer,'_run',side_effect=AssertionError):
                if change in self.audit:
                    context = patch.object(migration.migration_v1,'_origin_audit',return_value=dict(self.audit,**{change:None}))
                else:
                    context = patch.object(migration,'_prefix',return_value=([],self.pending) if change=='imports' else ([self.record],{}))
                with context, self.assertRaisesRegex(ValueError,'resumed_sealed_prefix_origin_changed'):
                    self.run_plan()

    def test_code_runtime_drift_resumed_and_fresh(self):
        for fresh, key in ((False,'new_code_sha256'),(False,'new_evaluator_runtime'),(True,'new_code_sha256')):
            plan = dict(self.plan, **{key:{'stale':True}})
            if self.path.exists(): self.path.unlink()
            if not fresh: write_once(self.path,plan)
            with self.subTest(fresh=fresh,key=key), self.patches(), \
                    patch.object(migration,'prepare_plan',return_value=(self.path,plan)), \
                    patch.object(producer,'_run',side_effect=AssertionError):
                with self.assertRaisesRegex(ValueError,'sealed_prefix_new_code_or_runtime_changed'):
                    self.run_plan()

    def test_gate_refusals_and_positive_control(self):
        write_once(self.path,self.plan)
        from src import paper_selector_acceptance_v2 as acceptance
        for status, included in (('FAIL',True),('PASS',False),('PASS',True)):
            with self.subTest(status=status,included=included), self.patches(), \
                    patch.object(acceptance,'verify',return_value={'status':status,'source_verified_original_91_included':included}), \
                    patch.object(producer,'_run',return_value={'status':'fixture'}) as run:
                if status=='PASS' and included:
                    self.run_plan(self.gate)
                    run.assert_called_once()
                    self.assertEqual(run.call_args.kwargs['migration'],
                        {'relative':self.path.name,'sha256':digest(self.path)})
                    self.assertIs(run.call_args.kwargs['migration_initializer'],migration._initialize)
                else:
                    with self.assertRaisesRegex(ValueError,'current_source_verified_gate_required_before_model_run'):
                        self.run_plan(self.gate)
                    run.assert_not_called()
        (self.root/'gate.json').unlink()
        self.gate['receipt_sha256'] = write_once(self.root/'gate.json',{'base_method_hashes':{'stale':True}})
        with self.patches(), patch.object(acceptance,'verify',return_value={'status':'PASS','source_verified_original_91_included':True}), \
                patch.object(producer,'_run',side_effect=AssertionError) as run:
            with self.assertRaisesRegex(ValueError,'current_source_gate_method_closure_required_before_model_run'):
                self.run_plan(self.gate)
            run.assert_not_called()

    def test_pending_origin_native_identity(self):
        runtime = {'python':'3.12','executable_sha256':'0'*64,'packages':{}}
        write_once(self.root/'profile.json',{'runtime':runtime})
        row = {'sample_id':'b',**{k+'_sha256':'0'*64 for k in ('source','page','image','native')}}
        intent = dict(row, protocol_sha256=self.old_sha, native_sha256='f'*64)
        document_sha = write_once(self.origin/'attempts/b/document.json', {'texts':[]})
        record = dict(sample_id='b', origin_receipt_sha256=None, origin_document_sha256=document_sha,
            origin_intent_sha256=write_once(self.origin/'attempts/b/intent.json',intent),
            origin_conversion_sha256=write_once(self.origin/'attempts/b/conversion.json',
                {'model_called':True,'status':'success','document_sha256':document_sha,
                 'docling_status':'ConversionStatus.SUCCESS','error_class':None,'runtime':runtime}))
        self.plan['pending_sealed_conversion'] = record
        with self.assertRaisesRegex(ValueError,'migration_origin_attempt_identity_mismatch:b'):
            migration._pending_origin(self.root,self.plan,row)


@unittest.skipUnless(fitz, 'PyMuPDF required for actual source geometry')
class SourceChangeTests(unittest.TestCase):
    def test_import_and_pending_source_changes(self):
        for mode in ('import', 'after', 'native_hash'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                output = root/'new'
                with fitz.open() as pdf:
                    pdf.new_page(width=100,height=100)
                    payload = pdf.tobytes()
                (root/'source.pdf').write_bytes(payload)
                row = {'sample_id':'b','source_relative':'source.pdf','source_root_id':'data_root',
                       **{k+'_sha256':hashlib.sha256(payload).hexdigest() for k in ('source','page','image','native')}}
                record = {'sample_id':'b','eligibility':'ineligible','state':'ineligible',
                    'origin_row_sha256':'0'*64,'assessment_relative':None,'assessment_sha256':None,
                    'origin_intent_sha256':'1'*64,'origin_conversion_sha256':'2'*64,
                    'origin_document_sha256':'3'*64}
                plan = dict(schema_version=migration.VERSION,ids=['b'],new_evaluator_runtime={'runtime':'new'},
                    imports=[record] if mode=='import' else [],
                    pending_sealed_conversion=record,new_code_sha256={'code':'new'},manifest_sha256='4'*64,
                    profile_sha256='5'*64,source_root=None,new_max_documents_per_session=64,
                    origin_protocol_sha256='6'*64)
                plan_sha = write_once(root/'plan.json',plan)
                protocol = dict(ids=['b'],evaluator_runtime=plan['new_evaluator_runtime'],
                    code_sha256=plan['new_code_sha256'],manifest_sha256=plan['manifest_sha256'],
                    profile_sha256=plan['profile_sha256'],source_root=None,converter_session={'max_documents':64},
                    migration={'relative':'plan.json','sha256':plan_sha})
                write_once(output/'protocol.json',protocol)
                values = [([], [100,100], 'eligible'), ([{'text':'changed'}],[100,100],'eligible')]
                effect = values
                # The native-hash case uses the real verifier on bound files, not an error mock.
                if mode=='native_hash':
                    for key in ('page','image','native'):
                        (root/(key+'.json')).write_bytes(payload)
                        row[key+'_relative'] = key+'.json'
                    row['physical_page'] = 1
                    row['native_sha256'] = 'f'*64
                with patch.object(producer,'_check_code'), \
                        patch.object(migration,'_origin_receipt',return_value=({'eligibility':'ineligible'},{})), \
                        patch.object(migration,'_pending_origin',return_value=(
                            {'status':'success','session_start':{},'wall_seconds':.1},{'texts':[]})):
                    from contextlib import nullcontext
                    verifier = nullcontext() if mode=='native_hash' else patch.object(producer,'_verified_row',side_effect=effect)
                    code = {'import':'sealed_prefix_current_source_eligibility_changed:b',
                            'after':'pending_conversion_source_changed_during_reassessment',
                            'native_hash':'field_source_hash_mismatch:native'}[mode]
                    with verifier, self.assertRaisesRegex(ValueError,code):
                        migration._initialize(root,output,{'pdfs':[row]},protocol,None)
                self.assertFalse((output/'rows/b.json').exists())
                self.assertFalse((output/'assessments').exists())


if __name__ == "__main__":
    unittest.main()
