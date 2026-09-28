"""Authored counterexamples for section ownership, independent of paper labels."""
import unittest

from test_parallel_source_v4 import ABSTRACT, BODY, assess, doc, line
from trace_gc.pdf_source_parallel_v4 import compare, validate_source_spans
from trace_gc.pdf_structure_parallel_v4 import verify_assessment
from src.parallel_source_v4.adapters import document, item


class SectionOwnershipTests(unittest.TestCase):
    def assert_text(self, result, expected=ABSTRACT):
        self.assertTrue(compare(result['text'], expected)['boundary_and_98_match'], result)
        self.assertFalse(result['eligible_for_jev'])
        self.assertFalse(result['verified_admission'])
        verify_assessment(result)

    def test_narrow_centered_heading_does_not_hide_left_closing_heading(self):
        native = [line(0, 'Abstract', 70, 145, 195), line(1, ABSTRACT, 100, 70, 280),
                  line(2, '1 Introduction', 160, 50, 135), line(3, BODY, 185, 50, 290)]
        result = assess(native)
        self.assert_text(result)
        self.assertTrue(result['proposal'])
        self.assertEqual(result['closing_boundary']['ref'], '#/texts/2')
        self.assertEqual(result['closing_boundary']['source_location'], 'located')
        validate_source_spans(result['closing_boundary']['source_spans'], native)

    def test_staggered_two_column_body_cannot_precede_closing_heading(self):
        native = [line(0, 'Abstract '+ABSTRACT, 100, 100, 500),
                  line(1, '1 Introduction', 160, 55, 210),
                  line(2, BODY, 180, 55, 295), line(3, BODY+' Another explanation.', 159, 315, 565)]
        for order in ([0,1,2,3], [3,0,2,1]):
            with self.subTest(order=order):
                result = assess(native, doc(native, order=order))
                self.assert_text(result)
                self.assertTrue(result['proposal'])

    def test_full_width_abstract_before_two_unheaded_columns_is_preserved_and_held(self):
        native = [line(0, 'Abstract '+ABSTRACT, 100, 100, 500),
                  line(1, BODY, 160, 50, 290), line(2, BODY+' Another account.', 160, 320, 560)]
        result = assess(native)
        self.assert_text(result)
        self.assertFalse(result['proposal'])
        self.assertEqual(result['closing_boundary']['reason'], 'multiple_body_lanes')

    def test_large_gap_does_not_append_unknown_section_or_certify_closure(self):
        native = [line(0, 'Abstract '+ABSTRACT, 100), line(1, BODY, 350)]
        result = assess(native)
        self.assert_text(result)
        self.assertFalse(result['proposal'])
        self.assertEqual(result['reasons'], ['section_ownership_requires_source_review'])

    def test_tree_boundary_precedes_converter_region_spanning_both_columns(self):
        native = [line(0, 'Abstract '+ABSTRACT, 100, 50, 290),
                  line(1, 'Index Terms: networks', 150, 50, 290),
                  line(2, BODY, 175, 50, 290), line(3, BODY+' Other.', 100, 320, 560)]
        source_doc = document([item(0, native[0]['text'], 'text', [native[0]['bbox']]),
                               item(1, native[1]['text'], 'text', [native[1]['bbox']]),
                               item(2, BODY+'\n'+native[3]['text'], 'text', [[50,105,560,190]])])
        result = assess(native, source_doc)
        self.assert_text(result)
        self.assertTrue(result['proposal'])
        self.assertEqual(result['closing_boundary']['kind'], 'metadata_or_nonabstract_region')

    def test_unresolved_overlapping_model_regions_are_held(self):
        native = [line(0, 'Abstract '+ABSTRACT, 100, 50, 290), line(1, BODY, 110, 320, 560)]
        source_doc = document([item(0, native[0]['text'], 'text', [[50,100,290,125]]),
                               item(1, BODY, 'text', [[50,110,560,180]])])
        result = assess(native, source_doc)
        self.assert_text(result)
        self.assertFalse(result['proposal'])

    def test_keyword_like_style_transition_is_preserved_as_hold(self):
        native = [line(0, 'Abstract '+ABSTRACT, 100, bold=True, size=10),
                  line(1, 'transport | connectivity | response', 135, size=9.5),
                  line(2, BODY, 180, size=11)]
        result = assess(native)
        self.assert_text(result)
        self.assertFalse(result['proposal'])
        validate_source_spans(result['closing_boundary']['source_spans'], native)

    def test_unlocated_model_heading_cannot_certify_closure(self):
        native = [line(0, 'Abstract '+ABSTRACT, 100), line(1, BODY, 180)]
        source_doc = doc(native)
        source_doc['texts'][1]['text'] = '1 Introduction'
        result = assess(native, source_doc)
        self.assert_text(result)
        self.assertFalse(result['proposal'])
        self.assertEqual(result['reasons'], ['unverified_section_boundary'])

    def test_embedded_source_heading_precedes_layout_transition_hold(self):
        native = [line(0, 'Abstract '+ABSTRACT, 100, 100, 500),
                  line(1, '1 Introduction: '+BODY, 160, 50, 290),
                  line(2, BODY+' Another account.', 160, 320, 560)]
        result = assess(native)
        self.assert_text(result)
        self.assertTrue(result['proposal'])
        validate_source_spans(result['closing_boundary']['source_spans'], native)

    def test_inline_source_heading_behind_earlier_figure_label_closes_abstract(self):
        native = [line(0, 'Abstract '+ABSTRACT, 100, 100, 500),
                  line(1, 'Introduction – '+BODY, 160, 50, 290),
                  line(2, 'Bulk-like', 155, 339, 368),
                  line(3, BODY, 180, 50, 290), line(4, BODY, 180, 320, 560)]
        for order in ([0, 1, 2, 3, 4], [4, 2, 0, 3, 1]):
            with self.subTest(order=order):
                result = assess(native, doc(native, order=order))
                self.assert_text(result)
                self.assertTrue(result['proposal'], result)
                self.assertEqual(result['closing_boundary']['ref'], '#/texts/1')
                self.assertEqual(result['closing_boundary']['source_text_scope'],
                                 'source_leading_inline_heading_prefix')
                validate_source_spans(result['closing_boundary']['source_spans'], native)

    def test_unverified_inline_heading_cannot_override_layout_hold(self):
        native = [line(0, 'Abstract '+ABSTRACT, 100, 100, 500),
                  line(1, 'Our introduction to the measurements '+BODY, 160, 50, 290),
                  line(2, 'Bulk-like', 155, 339, 368),
                  line(3, BODY, 180, 50, 290), line(4, BODY, 180, 320, 560)]
        source_doc = doc(native)
        source_doc['texts'][1]['text'] = 'Introduction – '+BODY
        result = assess(native, source_doc)
        self.assert_text(result)
        self.assertFalse(result['proposal'])
        self.assertEqual(result['closing_boundary']['reason'], 'multiple_body_lanes')

    def test_converter_stripped_native_prose_before_inline_heading_stays_held(self):
        native = [line(0, 'Abstract '+ABSTRACT, 100, 100, 500),
                  line(1, 'An omitted final abstract sentence. Introduction – '+BODY, 160, 50, 290),
                  line(2, 'Bulk-like', 155, 339, 368),
                  line(3, BODY, 180, 50, 290), line(4, BODY, 180, 320, 560)]
        source_doc = doc(native)
        source_doc['texts'][1]['text'] = 'Introduction – '+BODY
        result = assess(native, source_doc)
        self.assert_text(result)
        self.assertFalse(result['proposal'])
        self.assertEqual(result['closing_boundary']['reason'], 'multiple_body_lanes')

    def test_earlier_other_lane_abstract_prose_is_not_a_figure_label(self):
        for continuation in (
            'A final abstract sentence adds a material limitation to our result.',
            'Our result is limited.',
        ):
            with self.subTest(continuation=continuation):
                native = [line(0, 'Abstract '+ABSTRACT, 100, 100, 500),
                          line(1, 'Introduction – '+BODY, 160, 320, 560),
                          line(2, continuation, 155, 50, 290),
                          line(3, BODY, 180, 320, 560)]
                result = assess(native)
                self.assert_text(result)
                self.assertFalse(result['proposal'])
                self.assertEqual(result['closing_boundary']['reason'], 'multiple_body_lanes')

    def test_source_prose_excluded_by_lane_geometry_blocks_later_heading(self):
        native = [line(0, 'Abstract '+ABSTRACT, 100, 100, 500),
                  line(1, 'Introduction – '+BODY, 160, 320, 560),
                  line(2, 'Our result is limited.', 155, 50, 105),
                  line(3, BODY, 180, 320, 560)]
        result = assess(native)
        self.assert_text(result)
        self.assertFalse(result['proposal'])
        self.assertEqual(result['reasons'], ['unowned_source_prose_requires_review'])
        self.assertTrue(any(entry.get('reason') == 'source_prose_between_abstract_and_boundary'
                            for entry in result['region_ownership']))

    def test_metadata_label_remains_source_evidence_when_converter_body_drifts(self):
        native = [line(0, 'Abstract '+ABSTRACT, 100),
                  line(1, 'Keywords: networks and transport', 160)]
        source_doc = doc(native)
        source_doc['texts'][1]['text'] = 'Keywords: invented converter transcription with formula commands'
        result = assess(native, source_doc)
        self.assert_text(result)
        self.assertTrue(result['proposal'])
        self.assertEqual(result['closing_boundary']['source_text_scope'], 'metadata_label')
        validate_source_spans(result['closing_boundary']['source_spans'], native)

    def test_metadata_label_inside_source_sentence_is_not_a_verified_boundary(self):
        native = [line(0, 'Abstract '+ABSTRACT, 100),
                  line(1, 'Keywords describe the vocabulary in this continuing abstract sentence.', 160)]
        source_doc = doc(native)
        source_doc['texts'][1]['text'] = 'Keywords: invented converter metadata'
        result = assess(native, source_doc)
        self.assertFalse(result['proposal'])

    def test_located_metadata_word_inside_sentence_is_not_a_boundary(self):
        native = [line(0, 'Abstract '+ABSTRACT, 100),
                  line(1, 'We evaluate keywords in further experiments that complete this abstract.', 140),
                  line(2, '1 Introduction', 200)]
        source_doc = doc(native)
        source_doc['texts'][1]['text'] = 'Keywords'
        result = assess(native, source_doc)
        self.assertFalse(result['proposal'])
        self.assertEqual(result['reasons'], ['unverified_section_boundary'])

    def test_copyright_notation_drift_still_excludes_the_source_legal_footer(self):
        native = [line(0, 'Abstract '+ABSTRACT, 100),
                  line(1, '\u00a9 2026 Example Publisher. All rights reserved.', 160)]
        source_doc = doc(native)
        source_doc['texts'][1]['text'] = r'\(\odot\) 2026 Example Publisher. All rights reserved.'
        result = assess(native, source_doc)
        self.assert_text(result)
        self.assertTrue(result['proposal'])
        self.assertEqual(result['closing_boundary']['source_text_scope'], 'legal_footer_statement')

    def test_copyright_phrase_in_running_prose_does_not_close_the_abstract(self):
        continuation = 'We discuss how the statement all rights reserved affects reuse.'
        native = [line(0, 'Abstract '+ABSTRACT, 100), line(1, continuation, 135),
                  line(2, '1 Introduction', 170)]
        result = assess(native)
        self.assert_text(result, ABSTRACT+'\n'+continuation)

    def test_cropped_legal_phrase_inside_native_prose_is_not_a_footer(self):
        native = [line(0, 'Abstract '+ABSTRACT, 100),
                  line(1, 'We review 2026 notices containing all rights reserved in this continuing paragraph.', 140),
                  line(2, '1 Introduction', 200)]
        source_doc = doc(native)
        source_doc['texts'][1]['text'] = r'\(\odot\) 2026 Example Publisher. All rights reserved.'
        result = assess(native, source_doc)
        self.assertFalse(result['proposal'])
        self.assertEqual(result['reasons'], ['unverified_section_boundary'])

    def test_unverified_abstract_heading_cannot_relabel_real_body_text(self):
        native = [line(0, 'Overview', 70), line(1, ABSTRACT, 100), line(2, '1 Introduction', 160)]
        source_doc = doc(native)
        source_doc['texts'][0]['text'] = 'Abstract'
        result = assess(native, source_doc)
        self.assertFalse(result['proposal'])
        self.assertIn('unverified_abstract_start_heading', result['reasons'])

    def test_located_interior_introduction_word_is_not_a_heading(self):
        continuation = ('Further experiments establish reliability. A brief introduction to the second '
                        'comparison completes our abstract with additional independently measured results.')
        native = [line(0, 'Abstract '+ABSTRACT, 100), line(1, continuation, 140),
                  line(2, 'Keywords: measurements', 200)]
        source_doc = doc(native, labels={1: 'section_header'})
        source_doc['texts'][1]['text'] = 'Introduction'
        result = assess(native, source_doc)
        self.assertFalse(result['proposal'])
        self.assertEqual(result['reasons'], ['unverified_section_boundary'])

    def test_model_header_label_does_not_turn_whole_continuation_into_heading(self):
        continuation = ('Further experiments establish reliability. Additional independently measured '
                        'results complete our abstract.')
        native = [line(0, 'Abstract '+ABSTRACT, 100), line(1, continuation, 140),
                  line(2, 'Keywords: measurements', 200)]
        result = assess(native, doc(native, labels={1: 'section_header'}))
        self.assertFalse(result['proposal'])
        self.assertEqual(result['closing_boundary']['source_location'], 'unverified_heading_role')

    def test_unknown_section_title_needs_distinct_native_heading_typography(self):
        native = [line(0, 'Abstract '+ABSTRACT, 100),
                  line(1, 'Experimental apparatus', 140, bold=True, size=14), line(2, BODY, 175)]
        result = assess(native, doc(native, labels={1: 'section_header'}))
        self.assert_text(result)
        self.assertTrue(result['proposal'])

    def test_converter_cannot_erase_graphical_prefix_of_abstract(self):
        native = [line(0, 'Graphical Abstract '+ABSTRACT, 100), line(1, 'Keywords: networks', 180)]
        source_doc = doc(native)
        source_doc['texts'][0]['text'] = 'Abstract '+ABSTRACT
        result = assess(native, source_doc)
        self.assertFalse(result['proposal'])
        self.assertIn('unverified_abstract_start_heading', result['reasons'])

    def test_repeated_source_abstract_remains_ambiguous(self):
        native = [line(0, 'Abstract '+ABSTRACT, 100), line(1, '1 Introduction', 150),
                  line(2, ABSTRACT, 350)]
        self.assertFalse(assess(native)['proposal'])

    def test_superscript_marker_requires_matching_source_footnote(self):
        text = 'Abstract '+ABSTRACT+'1'
        first = line(0, text, 100)
        first['spans'] = [dict(first['spans'][0], end=len(text)-1, text=text[:-1]),
                          dict(first['spans'][0], start=len(text)-1, flags=1, size=7, text='1')]
        native = [first, line(1, '1 Introduction', 170), line(2, '1 Additional author information.', 700)]
        result = assess(native, doc(native, labels={2: 'footnote'}))
        self.assert_text(result)
        self.assertTrue(result['proposal'])
        excluded = [x for x in result['region_ownership'] if x.get('kind') == 'linked_terminal_footnote']
        self.assertEqual(len(excluded), 1)
        validate_source_spans([excluded[0]['marker_span']], native)
        self.assertEqual(result['spans'][-1]['end'], len(text)-1)
        for region in result['region_ownership']:
            if region['decision'] == 'included':
                self.assertEqual(region['source_spans'][-1]['end'], len(text)-1)

    def test_unlinked_or_unstyled_terminal_digit_is_not_deleted(self):
        for superscript in (False, True):
            with self.subTest(superscript=superscript):
                text = 'Abstract '+ABSTRACT+'1'
                first = line(0, text, 100)
                if superscript:
                    first['spans'] = [dict(first['spans'][0], end=len(text)-1, text=text[:-1]),
                                      dict(first['spans'][0], start=len(text)-1, flags=1, size=7, text='1')]
                result = assess([first, line(1, '1 Introduction', 160)])
                self.assertTrue(result['text'].endswith('1'))
                self.assertFalse(compare(result['text'], ABSTRACT)['boundary_and_98_match'])
                if superscript:
                    self.assertFalse(result['proposal'])

    def test_converter_cannot_crop_different_native_footnote_marker_into_match(self):
        text = 'Abstract '+ABSTRACT+'1'
        first = line(0, text, 100)
        first['spans'] = [dict(first['spans'][0], end=len(text)-1, text=text[:-1]),
                          dict(first['spans'][0], start=len(text)-1, flags=1, size=7, text='1')]
        native = [first, line(1, 'Keywords: measurements', 180),
                  line(2, '21 Supplementary observations.', 300)]
        source_doc = doc(native, labels={2: 'footnote'})
        source_doc['texts'][2]['text'] = '1 Supplementary observations.'
        result = assess(native, source_doc)
        self.assertFalse(result['proposal'])
        self.assertTrue(result['text'].endswith('1'))
        self.assertIn('terminal_footnote_marker_requires_source_review', result['reasons'])

    def test_footnote_without_outer_boundary_cannot_certify_completion(self):
        native = [line(0, 'Abstract '+ABSTRACT, 100), line(1, '1 Author information.', 700)]
        result = assess(native, doc(native, labels={1: 'footnote'}))
        self.assertFalse(result['proposal'])

    def test_first_page_continuation_remains_partial(self):
        result = assess([line(0, 'Abstract We investigate how the measurements continue into', 760)])
        self.assertEqual(result['status'], 'partial')

    def test_heading_word_in_sentence_does_not_truncate(self):
        text = 'We discuss introduction and methods in the following analysis. '+ABSTRACT
        result = assess([line(0, 'Abstract '+text), line(1, '1 Introduction', 170)])
        self.assert_text(result, text)


if __name__ == '__main__':
    unittest.main()
