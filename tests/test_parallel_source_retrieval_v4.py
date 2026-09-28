"""Query-independent field and candidate coverage tests with no model downloads."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from trace_gc.pdf_source_parallel_v4 import digest_value
from trace_gc.pdf_structure_parallel_v4 import seal
from src.parallel_source_v4.retrieval import (extract_fields, candidate_pool, rerank_pool,
    evaluate, local_cross_encoder, BM25, normalize_queries)
from src.parallel_source_v4.metrics import ranking_metrics, score_case, summary, fallback_increment
from src.parallel_source_v4.common import digest
from test_parallel_source_v4 import line, assess, ABSTRACT, PARAMS


class RetrievalTests(unittest.TestCase):
    def test_graphical_heading_not_title_even_when_largest(self):
        lines=[line(0,'Graphical Abstract',50,size=24),
               line(1,'Quantum transport in disordered materials',450,size=15),
               line(2,'We describe experimental measurements of local transport.',500,size=10)]
        fields=extract_fields('cover',lines,**{k:v for k,v in PARAMS.items() if k!='native_lines'})
        self.assertEqual(fields['title'],'Quantum transport in disordered materials')
        self.assertEqual(fields['abstract'],'')
        self.assertTrue(fields['retrieval_only'])
        self.assertFalse(fields['eligible_for_jev'])

    def test_empty_image_page_is_not_invented(self):
        fields=extract_fields('image',[],**PARAMS)
        self.assertFalse(fields['searchable'])
        self.assertEqual(fields['field_state'],'needs_local_ocr_or_source_review')
        self.assertEqual(fields['title'],'')

    def test_bound_local_ocr_cover_enters_lexical_search(self):
        cache={'status':'success','source_sha256':'a'*64,'page_sha256':'b'*64,
               'raw_text':'A treatise on algebraic topology','title':'A treatise on algebraic topology'}
        fields=extract_fields('cover',[],**PARAMS,ocr_cache=cache)
        result=evaluate([fields],[{'id':'q','query':'algebraic topology','target_id':'cover'}])
        self.assertEqual(result['candidate_coverage'],1)
        self.assertEqual(result['stage'],'candidate_order_only_not_reranked')
        self.assertFalse(fields['field_provenance']['body']['source_reviewed'])

    def test_unbound_ocr_rejected(self):
        with self.assertRaises(ValueError):extract_fields('image',[],**PARAMS,ocr_cache={'status':'success','raw_text':'invented'})

    def test_truncated_ocr_is_not_successful_field_conversion(self):
        cache={'status':'success','source_sha256':'a'*64,'page_sha256':'b'*64,'generated_tokens':4096,
               'raw_text':'A treatise on algebraic topology'}
        self.assertFalse(extract_fields('cover',[],**PARAMS,ocr_cache=cache)['searchable'])

    def test_reviewed_image_title_requires_image_binding(self):
        title={'text':'A treatise on algebraic topology','source_sha256':'a'*64,'page_sha256':'b'*64,
               'image_sha256':'c'*64,'reviewer_kind':'assistant','reviewer':'fixture-reviewer','source_reviewed':True}
        result=extract_fields('cover',[],**PARAMS,reviewed_title=title,image_sha256='c'*64)
        self.assertEqual(result['title'],title['text'])
        with self.assertRaises(ValueError):extract_fields('cover',[],**PARAMS,reviewed_title=title,image_sha256='d'*64)

    def test_abstract_field_requires_sealed_source_assessment(self):
        lines=[line(0,'Abstract '+ABSTRACT),line(1,'Introduction',200)]
        assessment=assess(lines)
        self.assertEqual(extract_fields('paper',lines,**PARAMS,abstract_assessment=assessment)['abstract'],ABSTRACT)
        assessment['text']='tampered'
        with self.assertRaises(ValueError):extract_fields('paper',lines,**PARAMS,abstract_assessment=assessment)

    def test_abstract_field_rejects_duplicate_native_occurrence_and_held_wrong_source(self):
        lines=[line(0,'Abstract '+ABSTRACT),line(1,'Introduction',200)]
        assessment=assess(lines)
        duplicated=[*lines,line(2,'Abstract '+ABSTRACT,350)]
        with self.assertRaisesRegex(ValueError,'abstract_field_spans_not_unique_or_current'):
            extract_fields('paper',duplicated,**PARAMS,abstract_assessment=assessment)
        held=assess(lines,conversion_status='error')
        held['page_sha256']='e'*64
        seal(held)
        with self.assertRaisesRegex(ValueError,'abstract_field_source_mismatch'):
            extract_fields('paper',lines,**PARAMS,abstract_assessment=held)
        unsupported={**held,'page_sha256':PARAMS['page_sha256'],'schema_version':99}
        seal(unsupported)
        with self.assertRaisesRegex(ValueError,'unsupported_abstract_assessment_version_or_state'):
            extract_fields('paper',lines,**PARAMS,abstract_assessment=unsupported)
        unknown={**held,'page_sha256':PARAMS['page_sha256'],'status':'mystery'}
        seal(unknown)
        with self.assertRaisesRegex(ValueError,'unsupported_abstract_assessment_version_or_state'):
            extract_fields('paper',lines,**PARAMS,abstract_assessment=unknown)

    def test_full_page_rank_44_enters_candidate_pool(self):
        field=[f'field-{i}' for i in range(50)];dense=[f'dense-{i}' for i in range(50)]
        body=[f'body-{i}' for i in range(50)];body[43]='title-field-miss'
        old_pool=set(field+dense)
        new_pool=candidate_pool(field,dense,body)
        self.assertNotIn('title-field-miss',old_pool)
        self.assertIn('title-field-miss',new_pool)
        self.assertLessEqual(len(new_pool),150)

    def test_target_label_does_not_change_candidate_pool(self):
        fields=[{'id':'a','title':'transport network','body':'','abstract':''},
                {'id':'b','title':'algebraic topology','body':'','abstract':''}]
        q={'id':'q','query':'transport','target_id':'a'}
        first=evaluate(fields,[q]);second=evaluate(fields,[{**q,'target_id':'b'}])
        self.assertEqual(first['candidates'],second['candidates'])
        self.assertEqual(second['mrr'],0)
        self.assertEqual(second['candidate_coverage'],0)

    def test_reranker_scores_exact_pool_not_known_target(self):
        seen=[]
        fields={'a':{'title':'a'},'b':{'title':'b'},'target':{'title':'target'}}
        def scorer(pairs):seen.extend(pairs);return [1,2]
        order=rerank_pool('query',fields,['a','b'],scorer)
        self.assertEqual(order,['b','a'])
        self.assertEqual(len(seen),2)
        self.assertFalse(any('target' in p[1] for p in seen))

    def test_reranker_missing_or_nan_scores_rejected(self):
        for values in ([],[float('nan')],[1,2]):
            with self.subTest(values=values):
                with self.assertRaises(ValueError):rerank_pool('query',{'a':{}},['a'],lambda _:values)

    def test_target_second_does_not_judge_first_irrelevant(self):
        result=ranking_metrics({'q':['rival','target']},{'q':['rival','target']},[{'id':'q','target_id':'target'}])
        self.assertEqual(result['mrr'],.5)
        self.assertEqual(result['details'][0]['competing_results_relevance'],'unjudged')

    def test_no_target_insertion_at_scoring(self):
        with self.assertRaises(ValueError):ranking_metrics({'q':['target']},{'q':['other']},[{'id':'q','target_id':'target'}])

    def test_dense_cache_requires_new_fields_queries_model_binding(self):
        fields=[{'id':'a','title':'Transport networks','body':'','abstract':''}]
        queries=[{'id':'q','query':'transport','target_id':'a'}]
        cache={'fields_sha256':digest_value(fields),'queries_sha256':digest_value(queries),'model_revision':'c'*40,'channel':'specter2','rankings':{'q':['a']}}
        self.assertEqual(evaluate(fields,queries,dense_cache=cache)['dense_stage'],'supplied_bound_cache')
        with self.assertRaises(ValueError):evaluate([{**fields[0],'title':'Repaired title'}],queries,dense_cache=cache)
        with self.assertRaises(ValueError):evaluate(fields,[{**queries[0],'query':'new query'}],dense_cache=cache)

    def test_frozen_query_id_text_schema_supported(self):
        result=normalize_queries({'queries':[{'query_id':'q1','text':'transport','target_id':'paper'}]})
        self.assertEqual(result,[{'id':'q1','query':'transport','target_id':'paper'}])

    def test_public_target_text_query_map_supported(self):
        result=normalize_queries({'paper':'transport'})
        self.assertEqual(result[0]['target_id'],'paper');self.assertEqual(result[0]['query'],'transport')

    def test_ambiguous_query_aliases_rejected(self):
        with self.assertRaises(ValueError):normalize_queries([{'id':'q1','query':'transport','text':'different','target_id':'paper'}])

    def test_empty_documents_do_not_receive_zero_score_padding(self):
        self.assertEqual(BM25({'a':'','b':'network'}).rank('network'),['b'])
        self.assertEqual(BM25({'a':''}).rank('network'),[])


class ModelSnapshotTests(unittest.TestCase):
    def setup_snapshot(self, root):
        for name,value in {'config.json':'{"num_labels":1}','tokenizer.json':'{}','model.safetensors':'test-fixture-not-weights'}.items():
            (root/name).write_text(value)
        return {p.name:digest(p) for p in root.iterdir()}

    def test_missing_snapshot_fails_before_import(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):local_cross_encoder(Path(directory),{})

    def test_unmanifested_file_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);manifest=self.setup_snapshot(root);(root/'extra.txt').write_text('extra')
            with self.assertRaises(ValueError):local_cross_encoder(root,manifest)

    def test_changed_weights_fail_before_model_load(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);manifest=self.setup_snapshot(root);(root/'model.safetensors').write_text('changed')
            with self.assertRaises(ValueError):local_cross_encoder(root,manifest)

    def test_pickle_weights_not_permitted(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);self.setup_snapshot(root);(root/'pytorch_model.bin').write_text('unsafe-fixture')
            manifest={p.name:digest(p) for p in root.iterdir()}
            with self.assertRaises(ValueError):local_cross_encoder(root,manifest)

    def test_remote_code_config_not_permitted(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);self.setup_snapshot(root);(root/'config.json').write_text('{"num_labels":1,"auto_map":{"x":"remote"}}')
            with self.assertRaises(ValueError):local_cross_encoder(root,{p.name:digest(p) for p in root.iterdir()})

    def test_model_constructed_with_local_flags(self):
        import types,sys
        calls=[]
        class Model:
            def __init__(self,*a,**kw):calls.append(kw)
            def predict(self,pairs,**kw):return [0.25]*len(pairs)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);manifest=self.setup_snapshot(root)
            with patch.dict(sys.modules,{'sentence_transformers':types.SimpleNamespace(CrossEncoder=Model)}):
                scorer=local_cross_encoder(root,manifest)
                self.assertEqual(scorer([('q','d')]),[.25])
        self.assertTrue(calls[0]['local_files_only']);self.assertFalse(calls[0]['trust_remote_code'])
        self.assertFalse(calls[0]['token'])


class MetricTests(unittest.TestCase):
    def test_matching_hold_is_not_counted_as_correct_proposal(self):
        details=[score_case('hold',{'text':ABSTRACT,'status':'uncertain','proposal':False},{'text':ABSTRACT,'status':'complete'})]
        result=summary(details)
        self.assertEqual(result['matching_complete_abstracts_withheld'],1)
        self.assertEqual(result['correct_proposals_98'],0)
        self.assertEqual(result['complete_abstracts_withheld'],1)
        self.assertEqual(result['correct_proposal_recall_98'],0)
        self.assertIsNone(result['proposal_precision_98'])

    def test_false_proposals_and_withheld_complete_are_disjoint(self):
        details=[score_case('wrong',{'text':ABSTRACT,'status':'complete','proposal':True},{'text':'','status':'no_abstract_text'}),
                 score_case('hold',{'text':ABSTRACT,'status':'uncertain','proposal':False},{'text':ABSTRACT,'status':'complete'}),
                 score_case('good',{'text':ABSTRACT,'status':'complete','proposal':True},{'text':ABSTRACT,'status':'complete'})]
        result=summary(details)
        self.assertEqual(result['false_proposals'],1);self.assertEqual(result['complete_abstracts_withheld'],1)
        self.assertEqual(result['proposal_precision_98'],.5);self.assertEqual(result['correct_proposal_recall_98'],.5)
        self.assertEqual(result['verified_admissions'],0)

    def test_fallback_counts_do_not_enable_automatic_admission(self):
        primary=[{'id':'case','proposed':False,'gold':'complete','text_match_98':True}]
        fallback=[{**primary[0],'proposed':True}]
        result=fallback_increment(primary,fallback)
        self.assertEqual(result['additional_correct'],1)
        self.assertFalse(result['automatic_fallback_enabled'])


if __name__=='__main__':unittest.main()
