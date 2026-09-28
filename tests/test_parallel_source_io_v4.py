"""Offline input, freeze, replay, and archive contracts; temporary files only."""
import copy
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from src.parallel_source_v4.common import child, data_root, digest, write_once, read, verify_first_page_bundle
from src.parallel_source_v4.freeze import freeze_cohort, verify_freeze
from src.parallel_source_v4.extraction import preflight, predict, native_document, regression
from src.parallel_source_v4.prepare import prepare
from src.parallel_source_v4.fields import build_fields
from src.parallel_source_v4.retrieval_prepare import prepare_retrieval
from src.parallel_source_v4.extraction import native_document
from trace_gc.pdf_structure_parallel_v4 import assess_document, seal
from trace_gc.pdf_source_parallel_v4 import digest_value
from test_parallel_source_v4 import ABSTRACT, PARAMS, line, doc

from tools import package_project as package


class IOTests(unittest.TestCase):
    def test_private_root_env_override(self):
        with tempfile.TemporaryDirectory() as d,patch.dict(os.environ,{'TRACE_GC_TEST_DATA_ROOT':d}):
            self.assertEqual(data_root(),Path(d).resolve())

    def test_private_root_inside_repo_rejected(self):
        with self.assertRaises(ValueError):data_root(Path(__file__).resolve().parents[1]/'private')

    def test_path_escape_and_windows_absolute_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            for value in ('../outside','/outside','C:\\private\\source.pdf'):
                with self.subTest(value=value):
                    with self.assertRaises(ValueError):child(Path(d),value)

    def test_immutable_receipt_idempotent_but_not_overwritable(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'receipt.json'
            first=write_once(path,{'value':1});self.assertEqual(write_once(path,{'value':1}),first)
            with self.assertRaises(ValueError):write_once(path,{'value':2})
            self.assertEqual(read(path),{'value':1})
            self.assertEqual(len(list(Path(d).glob('*.tmp'))),0)

    def test_missing_regression_is_blocked_not_passed(self):
        with tempfile.TemporaryDirectory() as d:
            result=preflight(Path(d))
            self.assertEqual(result['status'],'BLOCKED')
            self.assertEqual(result['reason'],'authorized_private_regression_data_unavailable')

    def test_parallel_v4_never_writes_into_frozen_regression_caches(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):regression(Path(d),Path(d)/'validation_expanded200/v3')

    def test_independent_olmocr_fallback_survives_missing_docling(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);path=root/'olmocr.json'
            write_once(path,{'status':'success','raw_text':'Abstract '+ABSTRACT+'\n\n# Introduction','page_sha256':'b'*64})
            result=predict('parallel_olmocr_v4',{'olmocr':path},{**PARAMS,'native_lines':[line(0,'Abstract '+ABSTRACT),line(1,'Introduction',200)]})
            self.assertTrue(result['proposal'],result)
            self.assertFalse(result['eligible_for_jev'])

    def test_converter_wrong_page_hash_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'olmocr.json';write_once(path,{'status':'success','raw_text':ABSTRACT,'page_sha256':'c'*64})
            result=predict('parallel_olmocr_v4',{'olmocr':path},{**PARAMS,'native_lines':[]})
            self.assertEqual(result['status'],'error');self.assertFalse(result['proposal'])


@unittest.skipUnless(importlib.util.find_spec('fitz') and importlib.util.find_spec('PIL'),
                     'optional PyMuPDF and Pillow unavailable')
class FreezeTests(unittest.TestCase):
    def inputs(self,root):
        import fitz
        from trace_gc.pdf_source_parallel_v4 import source_lines
        with fitz.open() as pdf:
            page=pdf.new_page(width=600,height=800)
            page.insert_textbox(fitz.Rect(40,70,560,200),ABSTRACT,fontsize=10)
            page.insert_text((40,250),'1 Introduction',fontsize=12)
            pdf.save(root/'source.pdf')
        prepared=prepare(root,[{'sample_id':'unseen','work_id':'work:new','source_relative':'source.pdf'}],root/'prepared')
        row=prepared['pdfs'][0]
        native=read(child(root,row['native_relative']))
        spans=[{'line_id':x['id'],'start':0,'end':len(x['text']),'text':x['text'],'bbox':x['bbox'],'page_no':1} for x in native[:-1]]
        labels={'unseen':{'status':'complete','text':ABSTRACT,'source_review':{
            'reviewer_kind':'assistant','reviewer':'fixture reviewer','source_before_predictions':True,
            'reviewed_at':'2026-01-01T00:00:00Z','image_sha256':row['image_sha256'],'native_sha256':row['native_sha256'],
            'reference_spans':spans,'closing_boundary':{'kind':'body_section','line_id':native[-1]['id']}}}}
        exposure=[{'work_id':'work:old','source_sha256':'a'*64,'page_sha256':'b'*64}]
        return {'pdfs':[row]},labels,exposure

    def test_source_first_freeze_is_bound_and_assistant_is_not_human(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);manifest,labels,exposure=self.inputs(root)
            result=freeze_cohort(root,manifest,labels,exposure,root/'freeze.json')
            verify_freeze(root,result)
            self.assertEqual(result['review_attribution'],{'assistant':1})
            self.assertIn('not inferred',result['independence'])

    def test_seen_work_cannot_be_unseen(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);manifest,labels,exposure=self.inputs(root)
            manifest['pdfs'][0]['work_id']='work:old'
            with self.assertRaises(ValueError):freeze_cohort(root,manifest,labels,exposure,root/'freeze.json')

    def test_seen_source_hash_cannot_be_unseen(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);manifest,labels,exposure=self.inputs(root)
            exposure[0]['source_sha256']=manifest['pdfs'][0]['source_sha256']
            with self.assertRaises(ValueError):freeze_cohort(root,manifest,labels,exposure,root/'freeze.json')

    def test_source_changed_since_review_cannot_freeze(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);manifest,labels,exposure=self.inputs(root);child(root,manifest['pdfs'][0]['image_relative']).write_bytes(b'changed')
            with self.assertRaises(ValueError):freeze_cohort(root,manifest,labels,exposure,root/'freeze.json')

    def test_review_after_prediction_cannot_be_unseen(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);manifest,labels,exposure=self.inputs(root);manifest['pdfs'][0]['predictions_examined']=True
            with self.assertRaises(ValueError):freeze_cohort(root,manifest,labels,exposure,root/'freeze.json')

    def test_existing_conversion_output_cannot_be_new_frozen_cohort(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);manifest,labels,exposure=self.inputs(root);(root/'prediction.json').write_text('{}')
            manifest['pdfs'][0]['conversion_outputs']={'docling':'prediction.json'}
            with self.assertRaises(ValueError):freeze_cohort(root,manifest,labels,exposure,root/'freeze.json')

    def test_no_exposure_registry_is_not_unseen(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);manifest,labels,_=self.inputs(root)
            with self.assertRaises(ValueError):freeze_cohort(root,manifest,labels,[],root/'freeze.json')

    def test_frozen_reference_edit_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);manifest,labels,exposure=self.inputs(root)
            result=freeze_cohort(root,manifest,labels,exposure,root/'freeze.json')
            result['labels']['unseen']['text']='changed'
            with self.assertRaises(ValueError):verify_freeze(root,result)

    def test_changed_methods_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);manifest,labels,exposure=self.inputs(root)
            result=freeze_cohort(root,manifest,labels,exposure,root/'freeze.json')
            with patch('src.parallel_source_v4.freeze.method_hashes',return_value={'changed':'hash'}):
                with self.assertRaises(ValueError):verify_freeze(root,result)

    def test_unsafe_case_id_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);manifest,labels,exposure=self.inputs(root)
            manifest['pdfs'][0]['sample_id']='../escape';labels={'../escape':labels['unseen']}
            with self.assertRaises(ValueError):freeze_cohort(root,manifest,labels,exposure,root/'freeze.json')


class PackageTests(unittest.TestCase):
    def test_env_variants_except_exact_example_excluded(self):
        for name in ('.env','.env.local','sub/.env.production','.env.example.backup'):
            self.assertFalse(package.safe_name(name))
        self.assertTrue(package.safe_name('.env.example'))

    def test_private_and_model_and_temporary_material_excluded(self):
        for name in ('paper.pdf','weights/model.safetensors','cache.pt','x.pyc','temp/run.json','pages/page.png',
                     'mineru/f001.json','docling/f001.document.json','private/source.json','font.ttf','bundle.zip','model.bin'):
            with self.subTest(name=name):self.assertFalse(package.safe_name(name))

    def test_renamed_pdf_or_key_rejected(self):
        self.assertFalse(package.safe_bytes('safe.txt',b'%PDF-1.7 fake'))
        self.assertFalse(package.safe_bytes('safe.txt',b'-----BEGIN '+b'PRIVATE KEY-----\nfixture'))

    def test_traversal_and_absolute_member_names_rejected(self):
        for name in ('../escape.py','/source.py','C:/source.py','..\\source.py'):
            self.assertFalse(package.safe_name(name))

    def test_zip_manifest_and_secret_exclusion(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'source';root.mkdir();(root/'hello.py').write_text('value = 1\n');(root/'.env').write_text('placeholder-secret')
            (root/'.env.example').write_text('KEY=replace-me\n');(root/'paper.pdf').write_bytes(b'%PDF-fixture')
            result=package.package(root,Path(d)/'source.zip',tracked_only=False)
            self.assertEqual(result['status'],'PASS');self.assertEqual(result['private_pdfs'],0)
            self.assertEqual(package.audit_archive(Path(d)/'source.zip')['sha256'],result['sha256'])

    def test_symlink_excluded_without_reading_target(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'source';root.mkdir();target=Path(d)/'outside.txt';target.write_text('private')
            try:
                (root/'link.txt').symlink_to(target)
            except OSError as exc:
                if getattr(exc, 'winerror', None) == 1314:
                    self.skipTest('Windows symlink privilege unavailable')
                raise
            self.assertFalse(package.included(root/'link.txt',root))

    def test_default_package_requires_real_git_index(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'x.py').write_text('x=1')
            with self.assertRaises(ValueError):package.archive_bytes(root)


@unittest.skipUnless(importlib.util.find_spec('fitz') and importlib.util.find_spec('PIL'),
                     'optional PyMuPDF and Pillow unavailable')
class PreparationTests(unittest.TestCase):
    def test_reject_changed_cached_first_page_content(self):
        import fitz
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            with fitz.open() as pdf:
                page=pdf.new_page(width=600,height=800)
                page.insert_text((40,70),'Abstract',fontsize=15)
                page.insert_text((40,100),'A complete source paragraph.',fontsize=12)
                pdf.save(root/'source.pdf')
            manifest=prepare(root,[{'sample_id':'new','work_id':'new:fixture','source_relative':'source.pdf'}],root/'prepared')
            row=manifest['pdfs'][0]
            self.assertTrue(verify_first_page_bundle(root,row))
            cached=child(root,row['page_relative'])
            with fitz.open(cached) as pdf:
                pdf[0].insert_text((40,150),'VISIBLE TAMPER',fontsize=15)
                pdf.save(root/'tampered.pdf')
            (root/'tampered.pdf').replace(cached)
            with self.assertRaisesRegex(ValueError,'cached_page_does_not_match_first_physical_page'):
                verify_first_page_bundle(root,row)

    def test_prepare_source_first_and_build_query_independent_fields(self):
        import fitz
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);source=root/'source.pdf'
            with fitz.open() as pdf:
                page=pdf.new_page(width=600,height=800)
                page.insert_text((40,70),'Graphical Abstract',fontsize=24)
                page.insert_text((40,450),'Quantum transport in disordered materials',fontsize=15)
                pdf.new_page().insert_text((40,70),'Abstract on the second page is excluded.')
                pdf.save(source)
            manifest=prepare(root,[{'sample_id':'new','work_id':'new:fixture','source_relative':'source.pdf'}],root/'prepared')
            row=manifest['pdfs'][0]
            self.assertFalse(row['predictions_examined'])
            with fitz.open(child(root,row['page_relative'])) as pagepdf:self.assertEqual(len(pagepdf),1)
            result=build_fields(root,manifest,root/'fields.json')
            self.assertEqual(result['fields'][0]['title'],'Quantum transport in disordered materials')
            self.assertNotIn('second page',result['fields'][0]['body'])
            self.assertTrue(result['query_independent'])

    def test_retrieval_fields_hold_divergent_cached_page_without_using_its_text(self):
        import fitz
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            with fitz.open() as pdf:
                pdf.new_page(width=600,height=800).insert_text((40,70),'Original paper title',fontsize=16)
                pdf.save(root/'source.pdf')
            manifest=prepare(root,[{'sample_id':'new','work_id':'new:fixture',
                                    'source_relative':'source.pdf'}],root/'prepared')
            row=manifest['pdfs'][0]
            cached=child(root,row['page_relative'])
            with fitz.open(cached) as pdf:
                pdf[0].insert_text((40,130),'CACHED PAGE ONLY',fontsize=16)
                pdf.save(root/'changed.pdf')
            (root/'changed.pdf').replace(cached)
            row['page_sha256']=digest(cached)
            fields=build_fields(root,manifest,root/'fields.json')
            field=fields['fields'][0]
            self.assertEqual(field['cached_page_render']['state'],'render_mismatch_review_required')
            self.assertEqual(fields['cached_page_render_mismatch_ids'],['new'])
            self.assertGreater(field['cached_page_render']['max_channel_delta'],2)
            self.assertIn('Original paper title',field['body'])
            self.assertNotIn('CACHED PAGE ONLY',field['body'])
            self.assertTrue(field['retrieval_only'])
            self.assertFalse(field['eligible_for_jev'])
            with self.assertRaisesRegex(ValueError,'derived_fields_require_matching_cached_page'):
                build_fields(root,manifest,root/'derived-fields.json',ocr_caches={'new':{}})

    def test_field_builder_rechecks_original_after_field_extraction(self):
        import fitz
        import src.parallel_source_v4.fields as field_module
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);source=root/'source.pdf'
            with fitz.open() as pdf:
                pdf.new_page(width=600,height=800).insert_text((40,70),'Original paper title')
                pdf.save(source)
            manifest=prepare(root,[{'sample_id':'new','work_id':'new:fixture',
                                    'source_relative':'source.pdf'}],root/'prepared')
            original_extract=field_module.extract_fields
            def mutate_after_initial_verification(*args,**kwargs):
                source.write_bytes(source.read_bytes()+b'\n% altered after initial verification')
                return original_extract(*args,**kwargs)
            with patch('src.parallel_source_v4.fields.extract_fields',side_effect=mutate_after_initial_verification):
                with self.assertRaisesRegex(ValueError,'field_input_changed_before_publication:new:source'):
                    build_fields(root,manifest,root/'fields.json')
            self.assertFalse((root/'fields.json').exists())

    def test_field_builder_cli_uses_pinned_sealed_abstract_and_rejects_stale_evidence(self):
        import fitz
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            with fitz.open() as pdf:
                page=pdf.new_page(width=600,height=800)
                page.insert_text((40,70),'Abstract',fontsize=12)
                page.insert_textbox(fitz.Rect(40,90,560,180),ABSTRACT,fontsize=10)
                page.insert_text((40,220),'1 Introduction',fontsize=12)
                pdf.save(root/'source.pdf')
            manifest=prepare(root,[{'sample_id':'paper','work_id':'work:paper','source_relative':'source.pdf'}],root/'prepared')
            row=manifest['pdfs'][0]
            native=read(child(root,row['native_relative']))
            assessment=assess_document(native_document(native),native_lines=native,page_size=[600,800],
                                       source_sha256=row['source_sha256'],page_sha256=row['page_sha256'])
            self.assertTrue(assessment['proposal'])
            assessment_path=root/'runs/assessments/parallel_structure_v4/paper.json'
            write_once(assessment_path,assessment)
            entry={'sample_id':'paper','assessment_relative':'runs/assessments/parallel_structure_v4/paper.json',
                   'assessment_sha256':digest(assessment_path),'native_sha256':row['native_sha256']}
            mapping={'schema_version':'retrieval-assessment-map-v1','method':'parallel_structure_v4',
                     'extractor_version':assessment['extractor_version'],'entries':[entry]}
            write_once(root/'assessment-map.json',mapping)
            command=[sys.executable,'-m','src.parallel_source_v4.fields','--data-root',str(root),
                     '--manifest','prepared/manifest.json','--abstract-assessments','assessment-map.json',
                     '--output','fields.json']
            cli=subprocess.run(command,cwd=Path(__file__).resolve().parents[1],capture_output=True,text=True)
            self.assertEqual(cli.returncode,0,cli.stderr)
            duplicate_map=root/'duplicate-map.json'
            duplicate_map.write_text('{"schema_version":"retrieval-assessment-map-v1","method":"parallel_structure_v4",'
                                     '"method":"parallel_grobid_v4","extractor_version":"page-one-parallel-structure-v4",'
                                     '"entries":[]}',encoding='utf-8')
            duplicate_cli=subprocess.run([*command[:-4],'--abstract-assessments','duplicate-map.json',
                                          '--output','duplicate-cli-fields.json'],
                                         cwd=Path(__file__).resolve().parents[1],capture_output=True,text=True)
            self.assertNotEqual(duplicate_cli.returncode,0)
            self.assertIn('duplicate_key_in_bound_json',duplicate_cli.stderr)
            actual=read(root/'fields.json')
            field=actual['fields'][0]
            self.assertEqual(field['abstract'],assessment['text'])
            self.assertEqual(field['abstract_assessment_state'],'complete')
            self.assertEqual(field['native_sha256'],row['native_sha256'])
            self.assertEqual(field['field_provenance']['abstract_assessment']['declared_method'],'parallel_structure_v4')
            self.assertFalse(field['eligible_for_jev'])
            self.assertTrue(field['retrieval_only'])
            self.assertEqual(build_fields(root,manifest,root/'fields-copy.json',abstract_assessments=mapping)['fields_sha256'],actual['fields_sha256'])

            import src.parallel_source_v4.fields as field_module
            mutable_path=root/'runs/assessments/parallel_structure_v4/mutable.json'
            mutable_path.write_bytes(assessment_path.read_bytes())
            mutable_entry={**entry,'assessment_relative':'runs/assessments/parallel_structure_v4/mutable.json',
                           'assessment_sha256':digest(mutable_path)}
            mutable_map={**mapping,'entries':[mutable_entry]}
            original_extract=field_module.extract_fields
            def mutate_assessment_after_read(*args,**kwargs):
                mutable_path.write_bytes(mutable_path.read_bytes()+b'\n')
                return original_extract(*args,**kwargs)
            with patch('src.parallel_source_v4.fields.extract_fields',side_effect=mutate_assessment_after_read):
                with self.assertRaisesRegex(ValueError,'assessment_changed_before_field_publication:paper'):
                    build_fields(root,manifest,root/'mutable-fields.json',abstract_assessments=mutable_map)
            self.assertFalse((root/'mutable-fields.json').exists())

            bad={**mapping,'entries':[entry,entry]}
            with self.assertRaisesRegex(ValueError,'duplicate_or_unknown_assessment_sample_id'):
                build_fields(root,manifest,root/'duplicate.json',abstract_assessments=bad)
            bad={**mapping,'entries':[{**entry,'native_sha256':'0'*64}]}
            with self.assertRaisesRegex(ValueError,'assessment_native_representation_mismatch'):
                build_fields(root,manifest,root/'stale.json',abstract_assessments=bad)
            wrong_page={**assessment,'page_sha256':'f'*64}
            seal(wrong_page)
            write_once(root/'runs/assessments/parallel_structure_v4/wrong-page.json',wrong_page)
            bad={**mapping,'entries':[{**entry,'assessment_relative':'runs/assessments/parallel_structure_v4/wrong-page.json',
                                      'assessment_sha256':digest(root/'runs/assessments/parallel_structure_v4/wrong-page.json')}]}
            with self.assertRaisesRegex(ValueError,'abstract_field_source_mismatch'):
                build_fields(root,manifest,root/'wrong-page-fields.json',abstract_assessments=bad)
            altered={**assessment,'spans':[{**assessment['spans'][0],'text':'altered'},*assessment['spans'][1:]]}
            seal(altered)
            write_once(root/'runs/assessments/parallel_structure_v4/altered.json',altered)
            bad={**mapping,'entries':[{**entry,'assessment_relative':'runs/assessments/parallel_structure_v4/altered.json',
                                      'assessment_sha256':digest(root/'runs/assessments/parallel_structure_v4/altered.json')}]}
            with self.assertRaisesRegex(ValueError,'abstract_field_native_spans_mismatch'):
                build_fields(root,manifest,root/'altered-fields.json',abstract_assessments=bad)
            held=assess_document(native_document([]),native_lines=native,page_size=[600,800],
                                 source_sha256=row['source_sha256'],page_sha256=row['page_sha256'])
            self.assertFalse(held['proposal'])
            write_once(root/'runs/assessments/parallel_structure_v4/held.json',held)
            held_map={**mapping,'entries':[{**entry,'assessment_relative':'runs/assessments/parallel_structure_v4/held.json',
                                           'assessment_sha256':digest(root/'runs/assessments/parallel_structure_v4/held.json')}]}
            held_field=build_fields(root,manifest,root/'held-fields.json',abstract_assessments=held_map)['fields'][0]
            self.assertEqual(held_field['abstract'],'')
            self.assertEqual(held_field['abstract_assessment_state'],held['status'])

    def test_external_retrieval_preparation_binds_original_page_and_native(self):
        import fitz
        with tempfile.TemporaryDirectory() as d:
            base=Path(d);data=base/'data';data.mkdir();external=base/'originals';external.mkdir()
            source=external/'paper.pdf'
            with fitz.open() as pdf:
                page=pdf.new_page(width=600,height=800)
                page.insert_text((40,70),'Graphical Abstract',fontsize=24)
                page.insert_text((40,450),'Quantum transport in disordered materials',fontsize=15)
                pdf.save(source)
            original={'pdfs':[{'sample_id':'p01','work_id':'work:one','source_path':str(source)}]}
            index={'document_ids':['p01']}
            write_once(data/'retrieval-manifest.json',original)
            write_once(data/'index-manifest.json',index)
            prep_cli=subprocess.run([sys.executable,'-m','src.parallel_source_v4.retrieval_prepare',
                                     '--data-root',str(data),'--source-root',str(external),
                                     '--retrieval-manifest','retrieval-manifest.json','--index-manifest','index-manifest.json',
                                     '--output','cli-prepared'],
                                    cwd=Path(__file__).resolve().parents[1],capture_output=True,text=True)
            self.assertEqual(prep_cli.returncode,0,prep_cli.stderr)
            self.assertEqual(read(data/'cli-prepared/manifest.json')['pdfs'][0]['sample_id'],'p01')
            manifest=prepare_retrieval(data,external,original,index,data/'prepared')
            self.assertEqual(prepare_retrieval(data,external,original,index,data/'prepared'),manifest)
            self.assertEqual(manifest['pdfs'][0]['source_root_id'],'external')
            fields=build_fields(data,manifest,data/'fields.json',source_root=external)
            self.assertEqual(fields['fields'][0]['id'],'p01')
            self.assertEqual(fields['fields'][0]['title'],'Quantum transport in disordered materials')
            self.assertEqual(fields['fields'][0]['image_sha256'],manifest['pdfs'][0]['image_sha256'])
            self.assertEqual(fields['fields'][0]['source_root_id'],'external')
            self.assertEqual(fields['fields'][0]['native_preparation_sha256'],
                             digest_value(manifest['native_extractor']))
            with self.assertRaisesRegex(ValueError,'explicit_authorized_source_root_required'):
                build_fields(data,manifest,data/'missing-source-root.json')
            native_path=child(data,manifest['pdfs'][0]['native_relative'])
            native=read(native_path)
            native[0]['text']='T'+native[0]['text'][1:]
            native[0]['spans'][0]['text']='T'+native[0]['spans'][0]['text'][1:]
            native_path.write_text(json.dumps(native),encoding='utf-8')
            manifest['pdfs'][0]['native_sha256']=digest(native_path)
            with self.assertRaisesRegex(ValueError,'pinned_native_differs_from_original_under_current_runtime'):
                build_fields(data,manifest,data/'self-consistent-wrong-native.json',source_root=external)
            with self.assertRaisesRegex(ValueError,'retrieval_source_index_identity_mismatch'):
                prepare_retrieval(data,external,original,{'document_ids':['other']},data/'wrong-index')

    def test_retrieval_preparation_resume_rejects_changed_or_corrupt_inputs(self):
        import fitz
        with tempfile.TemporaryDirectory() as d:
            base=Path(d);data=base/'data';data.mkdir();external=base/'originals';external.mkdir()
            source=external/'paper.pdf'
            with fitz.open() as pdf:
                pdf.new_page().insert_text((40,70),'Abstract: first version')
                pdf.save(source)
            original={'pdfs':[{'sample_id':'p01','work_id':'work:one','source_path':str(source)}]}
            index={'document_ids':['p01']}
            output=data/'prepared'
            prepare_retrieval(data,external,original,index,output)
            receipt=output/'pages/p01/receipt.json'
            clean=receipt.read_bytes()
            receipt.write_bytes(b'{broken')
            with self.assertRaises((ValueError,json.JSONDecodeError)):
                prepare_retrieval(data,external,original,index,output)
            receipt.write_bytes(clean)
            altered=json.loads(clean)
            altered['physical_page']=2
            altered['page_relative']='missing/page.pdf'
            receipt.write_text(json.dumps(altered),encoding='utf-8')
            with self.assertRaisesRegex(ValueError,'retrieval_page_receipt_identity_mismatch'):
                prepare_retrieval(data,external,original,index,output)
            receipt.write_bytes(clean)
            native=output/'pages/p01/native.json'
            native.write_bytes(native.read_bytes()+b' ')
            with self.assertRaisesRegex(ValueError,'retrieval_page_receipt_hash_mismatch'):
                prepare_retrieval(data,external,original,index,output)
            # A fresh owned output must still reject a source that changed after
            # its recorded preparation receipt was created.
            source.write_bytes(source.read_bytes()+b' ')
            with self.assertRaisesRegex(ValueError,'retrieval_page_receipt_hash_mismatch'):
                prepare_retrieval(data,external,original,index,output)

    def test_retrieval_preparation_resume_rejects_incomplete_or_redirected_output(self):
        import fitz
        with tempfile.TemporaryDirectory() as d:
            base=Path(d);data=base/'data';data.mkdir();external=base/'originals';external.mkdir()
            source=external/'paper.pdf'
            with fitz.open() as pdf:
                pdf.new_page().insert_text((40,70),'Abstract: first version')
                pdf.save(source)
            original={'pdfs':[{'sample_id':'p01','work_id':'work:one','source_path':str(source)}]}
            index={'document_ids':['p01']}
            output=data/'prepared'
            prepare_retrieval(data,external,original,index,output)
            folder=output/'pages/p01';receipt=folder/'receipt.json'
            receipt.unlink()
            with self.assertRaisesRegex(ValueError,'incomplete_retrieval_page_receipt'):
                prepare_retrieval(data,external,original,index,output)
            folder.rename(output/'pages/p01-unpublished')
            (output/'manifest.json').unlink()  # Interrupted runs have no final manifest.
            # An unpublished directory from an interruption does not certify a
            # sample; the normal publication path can finish on resume.
            resumed=prepare_retrieval(data,external,original,index,output)
            self.assertEqual(resumed['field_count'],1)
            redirected=base/'redirected';redirected.mkdir()
            folder.rename(output/'pages/p01-complete')
            try:
                folder.symlink_to(redirected,target_is_directory=True)
            except (OSError,NotImplementedError):
                self.skipTest('Windows symlink privilege unavailable')
            with self.assertRaisesRegex(ValueError,'retrieval_preparation_linked_output_not_owned'):
                prepare_retrieval(data,external,original,index,output)

    def test_retrieval_preparation_keeps_page_with_outside_native_glyph_box(self):
        import fitz
        with tempfile.TemporaryDirectory() as d:
            base=Path(d);data=base/'data';data.mkdir();external=base/'originals';external.mkdir()
            source=external/'paper.pdf'
            with fitz.open() as pdf:
                page=pdf.new_page(width=612,height=792)
                page.insert_text((40,0),'Header crossing page edge',fontsize=12)
                page.insert_text((40,70),'Usable text elsewhere on page',fontsize=12)
                pdf.save(source)
            original={'pdfs':[{'sample_id':'p01','work_id':'work:one','source_path':str(source)}]}
            index={'document_ids':['p01']}
            manifest=prepare_retrieval(data,external,original,index,data/'prepared')
            row=manifest['pdfs'][0]
            self.assertEqual(row['native_extraction_state'],'error')
            self.assertEqual(row['native_extraction_error'],'source_box_outside_first_page')
            self.assertEqual(read(child(data,row['native_relative'])),[])
            fields=build_fields(data,manifest,data/'fields.json',source_root=external)
            self.assertEqual(fields['field_count'],1)
            self.assertEqual(fields['native_extraction_counts'],{'error':1})
            self.assertEqual(fields['unsearchable_ids'],['p01'])
            self.assertFalse(fields['fields'][0]['eligible_for_jev'])


if __name__=='__main__':unittest.main()
