"""Authored section-scope counterexamples; not replacements for original papers."""
import unittest

from test_parallel_source_v4 import ABSTRACT, BODY, assess, doc, line
from trace_gc.pdf_source_parallel_v4 import compare, validate_source_spans, digest_value
from trace_gc.pdf_structure_parallel_v4 import verify_assessment, _compose_section_spans


CONTEXT = 'Context. Sparse transport networks change under controlled external perturbations.'
METHODS = 'Methods: Repeated measurements quantify the response across several network configurations.'
RESULTS = 'Results. The observed relationships remain stable across all measured conditions.'
CONCLUSIONS = 'Conclusions: The estimates support reliable comparisons of transport systems.'


class AbstractStructureTests(unittest.TestCase):
    def assert_complete(self, result, expected):
        self.assertTrue(result['proposal'], result)
        self.assertTrue(compare(result['text'], expected)['boundary_and_98_match'], result)
        self.assertFalse(result['verified_admission'])
        self.assertFalse(result['eligible_for_jev'])
        verify_assessment(result)

    def test_native_inline_subsections_across_regions_are_retained(self):
        content = [CONTEXT, METHODS, RESULTS, CONCLUSIONS]
        native = [line(0, 'Abstract', 70)] + [line(i+1, t, 100+i*24) for i,t in enumerate(content)]
        native.append(line(5, 'Keywords: networks', 210))
        result = assess(native)
        self.assert_complete(result, '\n'.join(content))
        self.assertEqual(len(result['subsection_scope']['labels']), 4)
        for entry in result['subsection_scope']['evidence']:
            validate_source_spans(entry['source_spans'], native)

    def test_structured_scope_cannot_start_in_later_body(self):
        native = [line(0, 'Abstract '+ABSTRACT, 100), line(1, '1 Introduction', 140),
                  line(2, CONTEXT, 180), line(3, METHODS, 204), line(4, RESULTS, 228),
                  line(5, 'Keywords: unrelated', 260)]
        result = assess(native)
        self.assert_complete(result, ABSTRACT)
        self.assertFalse(result['structured'])

    def test_narrow_structured_abstract_ends_above_wider_numbered_body(self):
        content = [CONTEXT, METHODS, RESULTS, CONCLUSIONS]
        native = [line(0, 'Abstract', 70, 200, 300, size=8)]
        native += [line(i+1, text, 100+i*24, 200, 540, size=8) for i,text in enumerate(content)]
        native += [line(5, '1 Introduction', 221, 40, 180, size=11),
                   line(6, BODY, 220, 320, 560, size=10)]
        result = assess(native)
        self.assert_complete(result, '\n'.join(content))
        self.assertEqual(result['closing_boundary']['scope_evidence'],
                         'numbered_outer_heading_after_subsections_and_native_size_change')
        validate_source_spans(result['closing_boundary']['source_spans'], native)

    def test_structured_size_transition_without_heading_is_held(self):
        content = [CONTEXT, METHODS, RESULTS, CONCLUSIONS]
        native = [line(0, 'Abstract', 70, 200, 300, size=8)]
        native += [line(i+1, text, 100+i*24, 200, 540, size=8) for i,text in enumerate(content)]
        native.append(line(5, BODY, 220, 320, 560, size=10))
        result = assess(native)
        self.assertFalse(result['proposal'])
        self.assertTrue(compare(result['text'], '\n'.join(content))['boundary_and_98_match'])
        self.assertEqual(result['closing_boundary']['reason'], 'larger_source_region_after_subsections')

    def test_internal_words_in_running_sentences_are_not_subheadings(self):
        continuation = 'The results describe several methods for additional observations.'
        native = [line(0, 'Abstract '+ABSTRACT, 100), line(1, continuation, 124),
                  line(2, 'Keywords: networks', 160)]
        result = assess(native)
        self.assert_complete(result, ABSTRACT+'\n'+continuation)
        self.assertFalse(result['structured'])

    def test_repeated_label_does_not_establish_subsection_hierarchy(self):
        native = [line(0, 'Abstract '+CONTEXT, 100), line(1, CONTEXT, 124),
                  line(2, 'Methods', 150), line(3, BODY, 180)]
        result = assess(native)
        self.assertFalse(result['proposal'])
        self.assertFalse(result['structured'])

    def test_context_labels_without_abstract_ownership_are_not_abstracts(self):
        native = [line(0, '1 Background', 70), line(1, CONTEXT, 100),
                  line(2, METHODS, 124), line(3, RESULTS, 148), line(4, 'Keywords: networks', 180)]
        result = assess(native, scholarly_abstract='\n'.join([CONTEXT, METHODS, RESULTS]))
        self.assertFalse(result['proposal'])

    def test_custom_source_styled_labels_need_no_fixed_name_list(self):
        content = [
            ('Approach', 'Repeated sampling estimates the response of transport systems under perturbation.'),
            ('Observations', 'The response remains stable across multiple independently measured configurations.'),
            ('Implications', 'The estimates support reliable comparisons across experimental conditions.')]
        native = [line(0, 'Abstract', 70)]
        for i,(label,body) in enumerate(content, 1):
            text = label+': '+body
            row = line(i, text, 100+(i-1)*24)
            end = len(label)+1
            row['spans'] = [{**row['spans'][0], 'end': end, 'text': text[:end], 'font': 'Test-Italic', 'flags': 2},
                            {**row['spans'][0], 'start': end, 'text': text[end:]}]
            native.append(row)
        native.append(line(4, 'Keywords: transport', 180))
        result = assess(native)
        self.assert_complete(result, '\n'.join(label+': '+body for label,body in content))
        self.assertEqual(result['subsection_scope']['labels'], ['approach', 'observations', 'implications'])

    def test_two_unlabelled_paragraphs_match_one_scholarly_field(self):
        first = 'Transport across sparse networks responds strongly to connectivity changes and external perturbations. '
        first += 'Reliable measurements are essential for comparison across experimental systems.'
        second = 'Repeated observations yield stable estimates of the response in all sampled configurations. '
        second += 'The estimates are consistent with observations from separate experiments.'
        native = [line(0, first, 100), line(1, second, 124), line(2, 'Keywords: transport', 160)]
        result = assess(native, scholarly_abstract=first+' '+second)
        self.assert_complete(result, first+'\n'+second)
        self.assertEqual(result['region_refs'], ['#/texts/0', '#/texts/1'])

    def test_adjacent_bold_abstract_paragraphs_are_one_candidate(self):
        native = [line(0, ABSTRACT, 100, bold=True), line(1, BODY, 124, bold=True),
                  line(2, 'Keywords: transport', 160)]
        self.assert_complete(assess(native), ABSTRACT+'\n'+BODY)

    def test_separate_bold_sections_still_compete(self):
        native = [line(0, ABSTRACT, 100, bold=True), line(1, 'Keywords: transport', 140),
                  line(2, BODY, 260, bold=True), line(3, 'Keywords: comparison', 300)]
        result = assess(native)
        self.assertFalse(result['proposal'])
        self.assertEqual(result['reasons'], ['multiple_plausible_abstract_regions'])

    def test_group_excludes_unlabelled_synopsis_at_typography_transition(self):
        native = [line(0, ABSTRACT, 100, bold=True), line(1, BODY, 124, bold=True),
                  line(2, 'A separate plain-language account summarizes the associated experimental work.', 160, size=11),
                  line(3, '1 Introduction', 200)]
        result = assess(native)
        self.assertFalse(result['proposal'])
        self.assertTrue(compare(result['text'], ABSTRACT+'\n'+BODY)['boundary_and_98_match'])
        self.assertEqual(result['closing_boundary']['reason'], 'unlabelled_group_typography_transition')

    def test_field_agreement_without_narrative_verbs_can_qualify(self):
        text = ('Sparse transport networks exhibit stable response relationships across perturbations. '
                'Repeated measurements are consistent across configurations and experimental conditions.')
        native = [line(0, text, 100), line(1, 'Keywords: networks', 150)]
        self.assert_complete(assess(native, scholarly_abstract=text), text)

    def test_field_agreement_under_highlights_stays_excluded(self):
        native = [line(0, 'Highlights', 70), line(1, ABSTRACT, 100), line(2, 'Keywords: networks', 150)]
        self.assertFalse(assess(native, scholarly_abstract=ABSTRACT)['proposal'])

    def test_title_matching_scholarly_field_is_not_abstract(self):
        text = ('A comprehensive comparative analysis of sparse transport networks under controlled '
                'external perturbations across diverse experimental systems.')
        for label in ('title', 'text'):
            for following in ('Author information: Alice Smith, Bob Jones.', 'Keywords: networks', '1 Introduction'):
                with self.subTest(label=label, following=following):
                    native = [line(0, text, 50, size=18), line(1, following, 90, size=11)]
                    result = assess(native, doc(native, labels={0:label}), scholarly_abstract=text)
                    self.assertFalse(result['proposal'])

    def test_stripped_native_nonabstract_prefix_cannot_supply_field_candidate(self):
        for prefix in ('Graphical Abstract ', '1 Introduction ', 'Highlights ', 'Continuing source prose. '):
            with self.subTest(prefix=prefix):
                native = [line(0, prefix+ABSTRACT, 100), line(1, 'Keywords: networks', 150)]
                source_doc = doc(native)
                source_doc['texts'][0]['text'] = ABSTRACT
                result = assess(native, source_doc, scholarly_abstract=ABSTRACT)
                self.assertFalse(result['proposal'])

    def test_stripped_real_abstract_label_can_corroborate_field_candidate(self):
        native = [line(0, 'Abstract '+ABSTRACT, 100), line(1, 'Keywords: networks', 150)]
        source_doc = doc(native)
        source_doc['texts'][0]['text'] = ABSTRACT
        self.assert_complete(assess(native, source_doc, scholarly_abstract=ABSTRACT), ABSTRACT)

    def test_composition_cannot_omit_same_lane_native_sentence(self):
        native = [line(0, ABSTRACT, 100), line(1, 'A necessary middle sentence completes the result.', 125),
                  line(2, BODY, 150)]
        from trace_gc.pdf_source_parallel_v4 import locate
        first, last = locate(ABSTRACT, native), locate(BODY, native)
        selected = {'alignment_failure': None, 'refs': ['a', 'b'], 'text': ABSTRACT+'\n'+BODY,
                    'ownership': [{'ref': ref, 'decision': 'included', 'source_spans': proof['spans'],
                                   'source_alignment': {'status': 'located', 'column_change': False}}
                                  for ref,proof in [('a', first), ('b', last)]]}
        self.assertIsNone(_compose_section_spans(selected, native))

    def test_composition_retains_exact_paragraphs_around_other_lane_objects(self):
        native = [line(0, 'Abstract', 70, 330, 400), line(1, ABSTRACT, 100, 320, 560),
                  line(2, 'Other-column metadata.', 125, 40, 280), line(3, BODY, 150, 320, 560),
                  line(4, 'Keywords: transport', 180, 320, 560)]
        result = assess(native)
        self.assert_complete(result, ABSTRACT+'\n'+BODY)
        validate_source_spans(result['spans'], native)

    def test_classification_is_excluded_and_source_bound(self):
        for label in ('Mathematics Subject Classification (2020): 17B22, 17B25',
                      '2020 Mathematics Subject Classification: 17B22', 'MSC2020: 17B22'):
            with self.subTest(label=label):
                native = [line(0, 'Abstract '+ABSTRACT, 100), line(1, label, 150)]
                result = assess(native)
                self.assert_complete(result, ABSTRACT)
                validate_source_spans(result['closing_boundary']['source_spans'], native)

    def test_classification_words_in_prose_do_not_close_section(self):
        extra = 'Mathematics Subject Classification describes the indexing used for this analysis.'
        native = [line(0, 'Abstract '+ABSTRACT, 100), line(1, extra, 124), line(2, 'Keywords: networks', 160)]
        self.assert_complete(assess(native), ABSTRACT+'\n'+extra)

    def test_publication_event_footer_needs_date_and_source_legal_context(self):
        event = 'Proceedings of the Annual Conference on Experimental Transport Systems'
        native = [line(0, ABSTRACT, 100), line(1, event, 500),
                  line(2, '21 - 26 September, 2025', 524),
                  line(3, 'Copyright owned by the authors under a publication license.', 700)]
        result = assess(native, scholarly_abstract=ABSTRACT)
        self.assert_complete(result, ABSTRACT)
        self.assertEqual(result['closing_boundary']['kind'], 'publication_event_metadata')
        for key in ('source_spans', 'date_source_spans', 'legal_source_spans'):
            validate_source_spans(result['closing_boundary'][key], native)
        for missing in (2, 3):
            with self.subTest(missing=missing):
                self.assertFalse(assess([n for i,n in enumerate(native) if i != missing], scholarly_abstract=ABSTRACT)['proposal'])

    def test_selector_owner_claim_and_native_digest_require_complete_scope(self):
        native = [line(0, 'Abstract '+ABSTRACT, 100), line(1, 'Keywords: networks', 150)]
        result = assess(native)
        self.assertEqual(result['section_owner'], 'abstract')
        self.assertEqual(result['native_sha256'], digest_value(native))
        held = assess(native[:1])
        self.assertIsNone(held['section_owner'])
        self.assertEqual(held['native_sha256'], digest_value(native[:1]))

    def test_inline_abstract_heading_uses_its_paragraph_location(self):
        text = ABSTRACT+' These abstractions support an abstract representation of the measured process.'
        native = [line(0, 'Abstract '+text, 100), line(1, 'Keywords: networks', 150)]
        self.assert_complete(assess(native), text)

    def test_title_page_with_only_whitespace_and_footer_remains_held(self):
        native = [line(0, 'Abstract '+ABSTRACT, 100), line(1, '1', 760)]
        result = assess(native, doc(native, labels={1:'page_footer'}), scholarly_abstract=ABSTRACT)
        self.assertFalse(result['proposal'])
        self.assertEqual(result['reasons'], ['no_explainable_closing_boundary'])


if __name__ == '__main__':
    unittest.main()
