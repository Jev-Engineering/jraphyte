"""Causal source/layout counterexamples, not empirical paper-cohort scores."""
from __future__ import annotations
import copy
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from trace_gc.pdf_source_parallel_v4 import (compare, locate, source_lines, validate_lines,
                                   validate_source_spans, digest_value)
from trace_gc.pdf_structure_parallel_v4 import assess_document, verify_assessment
from src.parallel_source_v4.adapters import document, item, olmocr_assess, grobid_assess, mineru_document

# Expected prose is authored separately from selector rules and native projection.
ABSTRACT = ('We investigate how transport changes in sparse networks under controlled perturbations. '
            'Our measurements establish a stable relationship between connectivity and response. '
            'The resulting estimates agree with independently generated observations.')
BODY = ('The rest of this article develops the background and describes earlier experiments. '
        'We compare several unrelated descriptions before introducing the detailed protocol.')
PARAMS = dict(page_size=[600, 800], source_sha256='a'*64, page_sha256='b'*64)


def line(i, text, y=100, x=40, right=280, *, bold=False, color=0, size=10, block=None):
    return {'id': i, 'text': text, 'bbox': [x, y, right, y+12], 'page_no': 1,
            'block_id': i if block is None else block,
            'spans': [{'start': 0, 'end': len(text), 'text': text,
                       'font': 'Test-Bold' if bold else 'Test-Regular',
                       'flags': 16 if bold else 0, 'color': color, 'size': size}]}


def doc(lines, labels=None, order=None):
    labels = labels or {}
    items = [item(i, x['text'], labels.get(i, 'text'), [x['bbox']]) for i, x in enumerate(lines)]
    result = document(items)
    if order is not None:
        result['body']['children'] = [{'cref': items[i]['self_ref']} for i in order]
    return result


def assess(lines, source_doc=None, **kwargs):
    return assess_document(source_doc or doc(lines), native_lines=lines, **{**PARAMS, **kwargs})


class BoundaryTests(unittest.TestCase):
    def assert_prose(self, result, expected=ABSTRACT):
        self.assertEqual(result['status'], 'complete', result)
        self.assertTrue(result['proposal'], result)
        self.assertTrue(compare(result['text'], expected)['boundary_and_98_match'], result)
        self.assertFalse(result['eligible_for_jev'])
        self.assertFalse(result['verified_admission'])
        self.assertTrue(result['closing_boundary'])
        verify_assessment(result)

    def test_explicit_bounded_abstract_retained(self):
        self.assert_prose(assess([line(0, 'Abstract '+ABSTRACT), line(1, '1 Introduction', 180)]))

    def test_separate_heading_retained(self):
        self.assert_prose(assess([line(0, 'Abstract', 70), line(1, ABSTRACT, 100), line(2, 'Keywords: networks', 180)]))

    def test_overview_spill_in_one_region(self):
        result = assess([line(0, 'Abstract '+ABSTRACT+' Overview: '+BODY)])
        self.assert_prose(result)
        self.assertNotIn(BODY, result['text'])
        self.assertEqual(result['closing_boundary']['kind'], 'embedded_body_section')

    def test_overview_word_inside_sentence_is_not_boundary(self):
        text = 'We provide an overview of measurements in sparse networks. '+ABSTRACT
        self.assert_prose(assess([line(0, 'Abstract '+text), line(1, '1 Introduction', 200)]), text)

    def test_embedded_methods_may_continue_structured_abstract(self):
        lines = [line(0, 'Abstract Context: We investigate transport in sparse networks under controlled perturbations.', 80),
                 line(1, 'Methods: We measure network response with repeated observations across all conditions.', 110),
                 line(2, 'Results: The observed response is consistent across repeated trials.', 140),
                 line(3, 'Conclusions: The method improves the reliability of transport analysis.', 170),
                 line(4, 'Keywords: transport; networks', 200)]
        result = assess(lines)
        self.assert_prose(result, '\n'.join([lines[0]['text'][len('Abstract '):]]+[x['text'] for x in lines[1:4]]))
        self.assertTrue(result['structured'])
        self.assertEqual(result['closing_boundary']['kind'], 'metadata_or_nonabstract_region')
        self.assertEqual(result['subsection_scope']['labels'], ['context', 'methods', 'results', 'conclusions'])

    def test_bold_inline_section_without_separator(self):
        text = 'Abstract '+ABSTRACT+' Overview '+BODY
        value = line(0, text)
        start = len('Abstract '+ABSTRACT+' ')
        value['spans'] = [
            {'start': 0, 'end': start, 'text': text[:start], 'font': 'Regular', 'flags': 0},
            {'start': start, 'end': start+8, 'text': 'Overview', 'font': 'Bold', 'flags': 16},
            {'start': start+8, 'end': len(text), 'text': text[start+8:], 'font': 'Regular', 'flags': 0}]
        self.assert_prose(assess([value]))

    def test_dedication_same_region(self):
        result = assess([line(0, 'Abstract '+ABSTRACT+' Dedicated to our colleagues.')])
        self.assert_prose(result)
        self.assertNotIn('Dedicated', result['text'])

    def test_dedication_separate_region(self):
        self.assert_prose(assess([line(0, 'Abstract '+ABSTRACT), line(1, 'In memory of our mentor.', 180)]))

    def test_same_region_keywords(self):
        self.assert_prose(assess([line(0, 'Abstract '+ABSTRACT+' Keywords: transport; networks')]))

    def test_color_only_boundary_is_review_hold(self):
        lines = [line(0, 'Abstract', 70), line(1, ABSTRACT, 100, bold=True),
                 line(2, 'The accompanying description gives a separate account for a general audience.', 150, color=255),
                 line(3, 'Introduction', 200)]
        result = assess(lines)
        self.assertEqual(result['status'], 'uncertain')
        self.assertFalse(result['proposal'])
        self.assertTrue(compare(result['text'], ABSTRACT)['text_match_98'])
        self.assertIn('style_transition_requires_source_review', result['reasons'])

    def test_merged_color_region_is_review_hold(self):
        lines = [line(0, 'Abstract '+ABSTRACT, 80, bold=True),
                 line(1, 'The accompanying description gives a separate account for a general audience.', 150, color=255)]
        merged = document([item(0, '\n'.join(x['text'] for x in lines), 'text', [[40,80,280,170]])])
        result = assess(lines, merged)
        self.assertFalse(result['proposal'])
        self.assertTrue(compare(result['text'], ABSTRACT)['text_match_98'], result)

    def test_wrong_tree_column_does_not_replace_left_bold_abstract(self):
        lines = [line(0, ABSTRACT, 100, bold=True), line(1, BODY, 100, 330, 570), line(2, 'Introduction', 200)]
        source_doc = doc(lines, order=[1,0,2])
        self.assert_prose(assess(lines, source_doc))

    def test_two_bold_narrative_regions_are_ambiguous(self):
        result = assess([line(0, ABSTRACT, 100, bold=True), line(1, BODY, 100, 330,570,bold=True)])
        self.assertEqual(result['status'], 'uncertain')
        self.assertFalse(result['proposal'])

    def test_authors_not_an_unlabelled_abstract(self):
        authors = 'Alice Smith, Brian Jones, Carol White, David Green, Emily Black, Frank Brown. '
        result = assess([line(0, authors*3+'Author contributions: we designed the study.', bold=True)])
        self.assertFalse(result['proposal'])
        self.assertEqual(result['status'], 'absent')

    def test_author_list_inside_merged_region_is_not_appended(self):
        names='Alice Smith, Brian Jones, Carol White, David Green, Emily Black, Frank Brown.'
        lines=[line(0,'Abstract '+ABSTRACT,100),line(1,names,160),line(2,'Introduction',220)]
        merged=document([item(0,lines[0]['text']+'\n'+names,'text',[[40,100,280,172]]),
                         item(1,'Introduction','section_header',[lines[2]['bbox']])])
        self.assert_prose(assess(lines,merged))

    def test_affiliation_not_an_abstract(self):
        for prefix in ('Department of Physics,', 'University of Example,', 'Institute for Transport,'):
            with self.subTest(prefix=prefix):
                result = assess([line(0, prefix+' '+ABSTRACT, bold=True)], scholarly_abstract=prefix+' '+ABSTRACT)
                self.assertFalse(result['proposal'])

    def test_author_note_not_an_abstract(self):
        note = 'Author note: '+ABSTRACT
        result = assess([line(0, note)], scholarly_abstract=note)
        self.assertFalse(result['proposal'])

    def test_excluded_page_roles_are_not_complete_abstracts(self):
        for role in ('Graphical Abstract', 'Highlights', 'Key points', 'Executive Summary', 'Contents', 'Dedication'):
            with self.subTest(role=role):
                text = role+': '+ABSTRACT
                result = assess([line(0,text,bold=True)], scholarly_abstract=text)
                self.assertFalse(result['proposal'])
                self.assertEqual(result['status'], 'absent')

    def test_body_prose_without_abstract_evidence_is_absent(self):
        self.assertEqual(assess([line(0,BODY)])['status'], 'absent')

    def test_source_verified_scholarly_unlabelled_candidate(self):
        lines = [line(0, ABSTRACT), line(1, 'Introduction',200)]
        self.assert_prose(assess(lines, scholarly_abstract=ABSTRACT))

    def test_scholarly_field_does_not_supply_missing_source(self):
        result = assess([line(0, BODY)], scholarly_abstract=ABSTRACT)
        self.assertEqual(result['status'], 'uncertain')
        self.assertFalse(result['proposal'])

    def test_no_closure_above_bottom_is_held_even_with_period(self):
        result = assess([line(0,'Abstract '+ABSTRACT)])
        self.assertEqual(result['status'], 'uncertain')
        self.assertFalse(result['proposal'])

    def test_page_break_partial_is_not_absent_or_complete(self):
        result = assess([line(0,'Abstract We investigate how changing the physical process affects the',760)])
        self.assertEqual(result['status'], 'partial', result)
        self.assertFalse(result['proposal'])

    def test_terminal_formula_is_not_mislabeled_as_page_break(self):
        result = assess([line(0,'Abstract '+ABSTRACT+' We obtain x = √2'),line(1,'Introduction',200)])
        self.assertEqual(result['status'], 'uncertain')
        self.assertTrue(result['math_review_required'])
        self.assertNotEqual(result['status'], 'partial')

    def test_structured_internal_sections_preserved(self):
        text = 'Background: '+ABSTRACT+'\nMethods: We measure network responses.\nResults: We observe stable transport.\nConclusion: Our analysis supports the hypothesis.'
        self.assert_prose(assess([line(0, 'Abstract '+text),line(1,'1 Introduction',300)]),text)

    def test_character_budget_not_generation_truncation(self):
        text = ABSTRACT+' '+('We measure stable transport and report every observation. '*85)
        result = assess([line(0,'Abstract '+text),line(1,'1 Introduction',300)])
        self.assertEqual(result['status'],'complete')
        self.assertTrue(result['complete_candidate'])
        self.assertFalse(result['proposal'])
        self.assertEqual(result['request_budget']['status'],'exceeded')
        self.assertEqual(result['conversion_status'],'success')
        self.assertGreater(len(result['text']),4000)
        self.assertFalse(result['request_budget']['text_truncated'])

    def test_page_two_text_never_enters_selection(self):
        lines = [line(0,'Abstract '+ABSTRACT)]
        source_doc = doc(lines)
        source_doc['texts'][0]['prov'][0]['page_no']=2
        self.assertEqual(assess(lines,source_doc)['status'],'error')

    def test_invalid_evidence_receipt_is_sealed(self):
        for kwargs in ({'page_size':[float('inf'),800]}, {'source_sha256':'fake'}, {'max_input_chars':0}):
            with self.subTest(kwargs=kwargs):
                result=assess([],**kwargs)
                self.assertEqual(result['status'],'error')
                verify_assessment(result)

    def test_footnote_cannot_certify_a_complete_page_one_abstract(self):
        lines=[line(0,'Abstract '+ABSTRACT,680),line(1,'Corresponding author: example',760)]
        result=assess(lines,doc(lines,labels={1:'footnote'}))
        self.assertEqual(result['status'],'uncertain')
        self.assertFalse(result['proposal'])

    def test_figure_caption_is_not_unlabelled_abstract(self):
        text='Figure 1: '+ABSTRACT
        result=assess([line(0,text,bold=True)],scholarly_abstract=text)
        self.assertFalse(result['proposal'])

    def test_later_methods_results_do_not_expand_structured_abstract(self):
        lines=[line(0,'Abstract '+ABSTRACT),line(1,'Methods:',190),line(2,BODY,220),
               line(3,'Results:',290),line(4,BODY,320),line(5,'Keywords: unrelated',410)]
        result=assess(lines,doc(lines,labels={1:'section_header',3:'section_header'}))
        self.assertFalse(result['proposal'])
        self.assertEqual(result['status'],'uncertain')
        self.assertNotIn(BODY,result['text'])

    def test_invalid_native_style_is_isolated_error(self):
        value=line(0,'Abstract '+ABSTRACT);value['spans'][0]['size']=float('nan')
        result=assess([value])
        self.assertEqual(result['status'],'error');verify_assessment(result)

    def test_receipt_span_tampering_detected(self):
        result=assess([line(0,'Abstract '+ABSTRACT),line(1,'Introduction',200)])
        result['spans'][0]['start']+=1
        with self.assertRaises(ValueError):verify_assessment(result)


class AlignmentTests(unittest.TestCase):
    def test_line_break_hyphenation_and_paragraph_split(self):
        native=[line(0,'We establish a source-',100),line(1,'bound transcription. We preserve notation.',120)]
        result=locate('We establish a sourcebound transcription. We preserve notation.',native)
        self.assertEqual(result['status'],'located')
        self.assertEqual(len(result['spans']),2)
        validate_source_spans(result['spans'],native)

    def test_duplicate_text_location_is_held(self):
        result=locate(ABSTRACT,[line(0,ABSTRACT),line(1,ABSTRACT,200)])
        self.assertEqual(result['status'],'ambiguous')

    def test_near_duplicate_location_is_held(self):
        changed=ABSTRACT.replace('stable','staple')
        result=locate(ABSTRACT,[line(0,ABSTRACT),line(1,changed,200)])
        self.assertEqual(result['status'],'ambiguous')

    def test_wrong_column_cannot_be_projected(self):
        native=[line(0,ABSTRACT),line(1,BODY,100,330,570)]
        result=locate(ABSTRACT,native,region_boxes=[[330,90,570,130]])
        self.assertEqual(result['status'],'unlocated')

    def test_source_offsets_exclude_same_line_metadata(self):
        source='Abstract '+ABSTRACT+' Keywords: transport'
        result=locate(ABSTRACT,[line(0,source)])
        self.assertEqual(result['text'],ABSTRACT)
        self.assertEqual(result['spans'][0]['start'],9)
        self.assertEqual(result['spans'][0]['end'],9+len(ABSTRACT))
        self.assertEqual(result['spans'][0]['box_scope'],'native_line_not_character_box')

    def test_threshold_cannot_be_lowered(self):
        with self.assertRaises(ValueError):locate(ABSTRACT,[],threshold=.90)

    def test_more_than_two_percent_invention_is_unlocated(self):
        result=locate(ABSTRACT+' We invented an extra scientific result.',[line(0,ABSTRACT)])
        self.assertEqual(result['status'],'unlocated')

    def test_native_duplicate_ids_rejected(self):
        with self.assertRaises(ValueError):validate_lines([line(0,'a'),line(0,'b',140)],[600,800])

    def test_source_page_two_rejected(self):
        value=line(0,ABSTRACT);value['page_no']=2
        with self.assertRaises(ValueError):validate_lines([value],[600,800])


class AdapterTests(unittest.TestCase):
    def test_olmocr_merged_native_line_split_into_paragraphs(self):
        first,second=ABSTRACT.split(' Our ',1)
        lines=[line(0,'Abstract '+first+' Our '+second),line(1,'Introduction',200)]
        raw={'status':'success','raw_text':'# Abstract\n\n'+first+'\n\nOur '+second+'\n\n# Introduction'}
        result=olmocr_assess(raw,**PARAMS,native_lines=lines)
        self.assertEqual(result['status'],'complete',result)
        self.assertTrue(compare(result['text'],ABSTRACT)['text_match_98'])
        self.assertIn('no predicted coordinates',result['coordinate_source'])

    def test_olmocr_no_coordinates_is_review_only_not_full_page_box(self):
        raw={'status':'success','raw_text':'# Abstract\n\n'+ABSTRACT+'\n\n# Introduction'}
        result=olmocr_assess(raw,**PARAMS,native_lines=[])
        self.assertFalse(result['proposal'])
        self.assertFalse(result['spans'])
        self.assertTrue(result['unlocated_paragraphs'])

    def test_unlocated_ocr_continuation_cannot_disappear(self):
        lines=[line(0,'Abstract '+ABSTRACT),line(1,'Introduction',200)]
        raw={'status':'success','raw_text':'Abstract '+ABSTRACT+'\n\nWe invented an additional experimental result not found on the page.\n\n# Introduction'}
        result=olmocr_assess(raw,**PARAMS,native_lines=lines)
        self.assertEqual(result['status'],'uncertain')
        self.assertIn('unlocated_ocr_paragraph_inside_candidate_boundary',result['reasons'])

    def test_ocr_token_limit_is_truncated_not_error(self):
        lines=[line(0,'Abstract '+ABSTRACT),line(1,'Introduction',200)]
        for extra in ({'status':'truncated'}, {'status':'success','generated_tokens':4096}, {'status':'success','finish_reason':'length'}):
            with self.subTest(extra=extra):
                result=olmocr_assess({'raw_text':'Abstract '+ABSTRACT,**extra},**PARAMS,native_lines=lines)
                self.assertEqual(result['status'],'truncated')
                self.assertFalse(result['proposal'])

    def test_eos_at_token_limit_is_not_assumed_truncated(self):
        lines=[line(0,'Abstract '+ABSTRACT),line(1,'Introduction',200)]
        raw={'status':'success','raw_text':'Abstract '+ABSTRACT+'\n\n# Introduction','generated_tokens':4096,'finish_reason':'eos'}
        result=olmocr_assess(raw,**PARAMS,native_lines=lines)
        self.assertNotEqual(result['status'],'truncated')

    def test_grobid_highlights_and_partial_are_not_complete_fields(self):
        for text,y in [('Highlights: '+ABSTRACT,100),('Abstract We investigate transport and obtain',760)]:
            lines=[line(0,text,y)]
            result=grobid_assess({'status':'success','text':text.removeprefix('Abstract ')},doc(lines),**PARAMS,native_lines=lines)
            self.assertFalse(result['proposal'])
            self.assertFalse(result['field_source_verified'])

    def test_grobid_header_stripped_highlights_remain_nonabstract(self):
        for heading in ('Highlights','Key points','Executive Summary','Graphical Abstract'):
            with self.subTest(heading=heading):
                lines=[line(0,heading,60),line(1,ABSTRACT,100),line(2,'Introduction',200)]
                result=grobid_assess({'status':'success','text':ABSTRACT},doc(lines),**PARAMS,native_lines=lines)
                self.assertFalse(result['proposal'],result)
                self.assertFalse(result['field_source_verified'])
                self.assertEqual(result['rejected_candidate_contexts'][0]['source_location'],'located')

    def test_scholarly_field_matching_body_prose_is_not_an_abstract(self):
        lines=[line(0,'Introduction',60),line(1,ABSTRACT,100),line(2,'2 Methods',200)]
        result=grobid_assess({'status':'success','text':ABSTRACT},doc(lines),**PARAMS,native_lines=lines)
        self.assertFalse(result['proposal'])
        self.assertFalse(result['field_source_verified'])

    def test_grobid_corroboration_remains_useful(self):
        lines=[line(0,ABSTRACT),line(1,'Introduction',200)]
        result=grobid_assess({'status':'success','text':ABSTRACT},doc(lines),**PARAMS,native_lines=lines)
        self.assertTrue(result['field_source_verified'],result)
        self.assertTrue(result['proposal'])
        self.assertFalse(result['eligible_for_jev'])

    def test_grobid_500_is_isolated_error(self):
        result=grobid_assess({'status':'error','http_status':500,'text':''},document([]),**PARAMS,native_lines=[])
        self.assertEqual(result['status'],'error')
        self.assertEqual(result['text'],'')

    def test_mineru_coordinates_outside_page_rejected(self):
        with self.assertRaises(ValueError):mineru_document({'blocks':[{'content':ABSTRACT,'bbox':[0,0,1,1.2]}]},[600,800])


@unittest.skipUnless(importlib.util.find_spec('fitz'), 'optional PyMuPDF unavailable')
class NativePDFTests(unittest.TestCase):
    def test_actual_pdf_native_spans_and_page_scope(self):
        import fitz
        with fitz.open() as pdf:
            page=pdf.new_page(width=600,height=800)
            page.insert_text((40,70),'Abstract',fontname='hebo',fontsize=11)
            page.insert_textbox(fitz.Rect(40,90,560,180),ABSTRACT,fontsize=10)
            page.insert_text((40,220),'1 Introduction',fontname='hebo',fontsize=11)
            data=pdf.tobytes()
        with fitz.open(stream=data,filetype='pdf') as pdf:
            native=source_lines(pdf[0])
            result=assess(native)
            self.assertTrue(result['proposal'],result)
            self.assertTrue(compare(result['text'],ABSTRACT)['text_match_98'])
            self.assertTrue(all('spans' in n for n in native))
            pdf.new_page()
            with self.assertRaises(ValueError):source_lines(pdf[1])


if __name__=='__main__':unittest.main()
