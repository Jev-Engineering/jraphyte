"""Synthetic private receipts; no models or corpus."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from src.retrieval_trial_report import aggregate, CHANNELS, _canonical_hash


class TrialReportTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.result = dict(queries=4, fields_count=15, top1=1, top10=2, mrr=0.3958333333333333,
            candidate_coverage=0.75, candidate_depth=50, stage='local_cross_encoder',
            details=[dict(id='SECRETQUERY'+str(i), target_id='SECRETDOC'+str(i),
                query='secret query alpha', rank=r, candidate_present=r is not None)
                for i, r in enumerate((1, 2, 12, None))],
            candidate_stage_metrics={c: dict(status='MEASURED', hits=3, queries=4, recall=.75)
                                     for c in CHANNELS}, index_seconds=1, candidate_seconds=2,
            rerank_seconds=3, wall_seconds=6, process_cpu_seconds=5,
            rankings={}, candidates={}, fields_sha256='c'*64,
            page_channel_enabled=True, dense_stage='supplied_bound_cache', dense_cache_binding='ranking_inputs_only_v2',
            dense_cache_sha256='b'*64, reranker_model_manifest_sha256='a'*64,
            private_path='secret/model/path')
        for detail in self.result['details']:
            order = ['DISTRACTOR' + str(i) for i in range(11)]
            if detail['rank'] is not None:
                order.insert(detail['rank'] - 1, detail['target_id'])
            self.result['rankings'][detail['id']] = order
            self.result['candidates'][detail['id']] = {
                'pool': order, **{channel + '_topk': order for channel in CHANNELS[:-1]}}
        checks = {'status': 'PASS', 'checks': {key: True for key in
            ('ranking_inputs_sha256', 'ranking_outputs_sha256', 'candidates', 'dense_cache_sha256', 'labels_changed')}}
        self.receipt = dict(status='COMPLETE', protocol_sha256='a'*64, document_count=15,
            query_count=4, full_10000_by_60=False, ablations={'without_dense': 'MEASURED',
                'without_page_channel': 'NOT_RUN', 'historical_field_policy': 'NOT_RUN'},
            relevance_judgments='NOT_PERFORMED', memory={'peak_rss_bytes': 123, 'secret': 'SECRETDOC', 'scope': 'SECRETDOC',
                'child_processes_included': False},
            new_paid_api_calls=0, production_graph_writes=0,
            target_permutation=checks,
            all_arm_target_permutations={arm: checks for arm in ('primary', 'without_dense')},
            result_file_sha256={})
        self.result['dense_cache_sha256'] = self.write_dense_cache(self.result)
        queries = [{k: d[k] for k in ('id', 'query', 'target_id')} for d in self.result['details']]
        targets = [q['target_id'] for q in queries]
        for query, target in zip(queries, targets[1:] + targets[:1]):
            query['target_id'] = target
        for name in ('primary', 'target_permutation', 'without_dense', 'without_dense_target_permutation'):
            result = json.loads(json.dumps(self.result))
            if name.startswith('without_dense'):
                result['candidate_stage_metrics']['specter2'] = {'status': 'NOT_RUN'}
                result.update(dense_stage='not_run', dense_cache_sha256=None, dense_cache_binding='not_run')
                for candidates in result['candidates'].values():
                    candidates['specter2_topk'] = []
            if name.endswith('target_permutation'):
                for detail, query in zip(result['details'], queries):
                    detail.update(target_id=query['target_id'], rank=None, candidate_present=False)
                result.update(top1=0, top10=0, mrr=0., candidate_coverage=0.)
                for channel in result['candidate_stage_metrics'].values():
                    if channel['status'] == 'MEASURED':
                        channel.update(hits=0, recall=0.)
            self.write_arm(name, result)
        raw = json.dumps({'queries': queries}).encode()
        (self.root/'queries-permuted.json').write_bytes(raw)
        self.receipt['result_file_sha256']['queries-permuted.json'] = hashlib.sha256(raw).hexdigest()
        self.write_receipt()

    def write_receipt(self):
        (self.root/'receipt.json').write_text(json.dumps(self.receipt), encoding='utf-8')

    def write_dense_cache(self, result):
        queries = [{'id': detail['id'], 'query': detail['query']} for detail in result['details']]
        rankings = {qid: candidate['specter2_topk'] for qid, candidate in result['candidates'].items()}
        cache = dict(binding_version='ranking-inputs-v2', channel='specter2', target_ids_used_for_ranking=False,
                     rankings=rankings, ranking_sha256=_canonical_hash(rankings), fields_sha256=result['fields_sha256'],
                     ranking_inputs_sha256=_canonical_hash(queries), query_ids_sha256=_canonical_hash([q['id'] for q in queries]),
                     document_ids_sha256='f'*64, top_k=result['candidate_depth'])
        raw = json.dumps(cache).encode()
        path = self.root/'specter2'/'dense_cache.json'
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(raw)
        sha = hashlib.sha256(raw).hexdigest()
        files = {path.name: sha}
        self.receipt.update(dense_cache_file_sha256=sha, dense_artifact_sha256=files,
                            dense_conditions={'current': {'cache_sha256': sha, 'artifact_sha256': files}})
        return _canonical_hash(cache)

    def write_arm(self, name, result):
        result = json.loads(json.dumps(result))
        rank_calls = []
        for detail in result['details']:
            qid, rank = detail['id'], detail['rank']
            order = result['rankings'][qid]
            detail.setdefault('reciprocal_rank', 1 / rank if rank else 0.0)
            detail.setdefault('top10', order[:10])
            candidate = result['candidates'][qid]
            pool = candidate['pool']
            candidate.setdefault('pool_sha256', _canonical_hash(pool))
            if result['stage'] == 'local_cross_encoder' and pool:
                score_by_doc = {doc: len(order)-i for i, doc in enumerate(order)}
                scores = [score_by_doc[doc] for doc in pool]
                rank_calls.append({'query_id': qid, 'pair_count': len(pool), 'pairs_sha256': 'e'*64,
                                   'scores': scores, 'scores_sha256': _canonical_hash(scores)})
        result.setdefault('scored_calls', rank_calls)
        result = {'field_condition': 'historical' if name.startswith('historical_fields') else 'current', **result,
                  'ranking_outputs_sha256': _canonical_hash(result['rankings']),
                  'ranking_inputs_sha256': _canonical_hash([{k: d[k] for k in ('id', 'query')} for d in result['details']]),
                  'evaluation_labels_sha256': _canonical_hash([{k: d[k] for k in ('id', 'target_id')} for d in result['details']])}
        raw = json.dumps(dict(status='MEASURED_PENDING_FINAL_INTEGRITY', result=result)).encode()
        (self.root/(name+'.json')).write_bytes(raw)
        self.receipt['result_file_sha256'][name+'.json'] = hashlib.sha256(raw).hexdigest()

    def test_metrics_separation_and_sanitization(self):
        report = aggregate(self.root)
        arm = report['arms']['primary']
        self.assertEqual(arm['final_stage'], dict(stage='local_cross_encoder', reranked=True,
            queries=4, top1=1, top10=2, mrr=self.result['mrr'], top1_rate=.25,
            top10_rate=.5, misses_outside_candidate_pool=1, in_pool_ranked_below_10=1))
        self.assertEqual(arm['candidate_stage']['union']['recall'], .75)
        self.assertEqual(arm['timing']['wall_seconds'], 6)
        self.assertEqual(report['memory'], {'peak_rss_bytes': 123, 'scope': 'UNKNOWN',
                                            'child_processes_included': False})
        self.assertEqual(report['arms']['without_dense']['candidate_stage']['specter2'], {'status':'NOT_RUN'})
        self.assertNotIn('target_permutation', report['arms'])
        self.assertFalse(report['issue_acceptance_complete'])
        for secret in ('SECRETDOC', 'SECRETQUERY', 'secret query alpha', 'secret/model/path',
                       'details', 'rankings', 'scored_calls', 'target_id'):
            self.assertNotIn(secret, json.dumps(report))

    def test_tampered_file(self):
        (self.root/'primary.json').write_text('{}', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'trial_result_hash_mismatch:primary.json'):
            aggregate(self.root)

    def test_metrics_and_union_mismatch(self):
        for key in ('mrr', 'union', 'queries'):
            with self.subTest(key=key):
                value = json.loads(json.dumps(self.result))
                if key == 'union':
                    value['candidate_stage_metrics']['union']['hits'] = 2
                else:
                    value[key] = 0
                self.write_arm('primary', value)
                self.write_receipt()
                with self.assertRaisesRegex(ValueError, 'trial_metrics_readback_mismatch:primary'):
                    aggregate(self.root)

    def test_incomplete_manifest_and_false_full_dimensions(self):
        original = self.receipt['result_file_sha256'].copy()
        for manifest in ({}, {key: value for key, value in original.items()
                              if key != 'without_dense_target_permutation.json'}):
            with self.subTest(manifest=manifest):
                self.receipt['result_file_sha256'] = manifest
                self.write_receipt()
                with self.assertRaisesRegex(ValueError, 'trial_result_manifest_incomplete'):
                    aggregate(self.root)
        self.receipt['result_file_sha256'] = original
        self.receipt['full_10000_by_60'] = True
        self.write_receipt()
        with self.assertRaisesRegex(ValueError, 'trial_receipt_invalid_counts'):
            aggregate(self.root)

    def test_receipt_count_matches_every_measured_and_permuted_result(self):
        self.receipt['document_count'] = 10_000
        self.write_receipt()
        with self.assertRaisesRegex(ValueError, '^trial_document_count_mismatch$'):
            aggregate(self.root)
        self.receipt['document_count'] = 15
        result = json.loads((self.root/'without_dense_target_permutation.json').read_bytes())['result']
        for count in (14, 15.0):
            with self.subTest(count=count):
                result['fields_count'] = count
                self.write_arm('without_dense_target_permutation', result)
                self.write_receipt()
                with self.assertRaisesRegex(ValueError, '^trial_document_count_mismatch$'):
                    aggregate(self.root)

    def test_report_rejects_more_observed_documents_than_declared(self):
        self.receipt['document_count'] = 14
        for name in ('primary', 'without_dense', 'target_permutation', 'without_dense_target_permutation'):
            result = json.loads((self.root/(name+'.json')).read_bytes())['result']
            self.write_arm(name, {**result, 'fields_count': 14})
        self.write_receipt()
        with self.assertRaisesRegex(ValueError, '^trial_document_count_mismatch$'):
            aggregate(self.root)

    def test_report_accepts_producer_normalized_empty_query_id(self):
        cache_sha = None
        for name in ('primary', 'without_dense', 'target_permutation', 'without_dense_target_permutation'):
            result = json.loads((self.root/(name+'.json')).read_bytes())['result']
            first = result['details'][0]
            previous_id, first['id'] = first['id'], ''
            for collection in ('rankings', 'candidates'):
                result[collection][''] = result[collection].pop(previous_id)
            result['scored_calls'][0]['query_id'] = ''
            if name == 'primary':
                cache_sha = self.write_dense_cache(result)
            if result['dense_stage'] == 'supplied_bound_cache':
                result['dense_cache_sha256'] = cache_sha
            self.write_arm(name, result)
        path = self.root/'queries-permuted.json'
        queries = json.loads(path.read_bytes())
        queries['queries'][0]['id'] = ''
        raw = json.dumps(queries).encode()
        path.write_bytes(raw)
        self.receipt['result_file_sha256'][path.name] = hashlib.sha256(raw).hexdigest()
        self.write_receipt()
        self.assertEqual(aggregate(self.root)['query_count'], 4)

    def test_rank_pool_and_candidate_stage_contradictions(self):
        for mutate in (
            lambda result: result['details'][0].update(candidate_present=False),
            lambda result: result['details'][0].update(reciprocal_rank=0.0),
            lambda result: result['details'][-1].update(candidate_present=True),
            lambda result: result['candidate_stage_metrics']['union'].update(status='NOT_RUN'),
            lambda result: result['candidate_stage_metrics']['bm25_page'].update(hits=2.5, recall=.625),
        ):
            with self.subTest(mutate=mutate):
                value = json.loads(json.dumps(self.result))
                mutate(value)
                self.write_arm('primary', value)
                self.write_receipt()
                with self.assertRaisesRegex(ValueError, 'trial_metrics_readback_mismatch:primary'):
                    aggregate(self.root)

    def test_symlink_and_private_filename_errors_are_sanitized(self):
        private = self.root/'SYNTHETIC_PRIVATE_FILENAME.json'
        primary = self.root/'primary.json'
        primary.rename(private)
        primary.symlink_to(private)
        with self.assertRaisesRegex(ValueError, '^trial_result_hash_mismatch:primary.json$'):
            aggregate(self.root)
        primary.unlink()
        private.rename(primary)
        self.receipt['result_file_sha256'][private.name] = 'a'*64
        self.write_receipt()
        with self.assertRaisesRegex(ValueError, '^trial_result_hash_mismatch$'):
            aggregate(self.root)
        command = [sys.executable, '-m', 'src.retrieval_trial_report', '--trial-dir',
                   str(self.root), '--output', str(self.root/'report.json')]
        result = subprocess.run(command, cwd=Path(__file__).resolve().parents[1], capture_output=True)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, b'trial_result_hash_mismatch\n')
        self.assertFalse((self.root/'report.json').exists())

    def test_permutation_receipts_must_match_measured_contents_and_arithmetic(self):
        for name in ('target_permutation', 'without_dense_target_permutation'):
            with self.subTest(name=name):
                path = self.root/(name+'.json')
                original = path.read_bytes()
                result = json.loads(original)['result']
                result['top1'] = 1
                self.write_arm(name, result)
                self.write_receipt()
                with self.assertRaisesRegex(ValueError, '^trial_target_permutation_mismatch:'):
                    aggregate(self.root)
                path.write_bytes(original)
                self.receipt['result_file_sha256'][path.name] = hashlib.sha256(original).hexdigest()
        self.write_arm('target_permutation', self.result)
        self.write_receipt()
        with self.assertRaisesRegex(ValueError, '^trial_target_permutation_mismatch:primary$'):
            aggregate(self.root)

    def test_ablation_requires_the_declared_intervention(self):
        self.write_arm('without_dense', self.result)
        self.write_receipt()
        with self.assertRaisesRegex(ValueError, '^trial_metrics_readback_mismatch:without_dense$'):
            aggregate(self.root)

    def test_invalid_historical_field_encoding_has_a_fixed_error(self):
        self.receipt['ablations']['historical_field_policy'] = 'ARCHIVED_FIELDS_MEASURED'
        self.receipt['all_arm_target_permutations']['historical_fields'] = self.receipt['target_permutation']
        for baseline, name in (('primary', 'historical_fields'),
                               ('target_permutation', 'historical_fields_target_permutation')):
            result = json.loads((self.root/(baseline+'.json')).read_bytes())['result']
            result['field_condition'] = 'historical'
            self.write_arm(name, result)
        ids = ['DISTRACTOR' + str(i) for i in range(11)] + ['SECRETDOC' + str(i) for i in range(4)]
        rows = [{'id': doc, 'title': 'authored'} for doc in ids]
        rows[0]['title'] = '\ud800'
        raw = json.dumps({'fields': rows}).encode()
        (self.root/'historical-fields.json').write_bytes(raw)
        self.receipt['result_file_sha256']['historical-fields.json'] = hashlib.sha256(raw).hexdigest()
        self.write_receipt()
        with self.assertRaisesRegex(ValueError, '^trial_historical_fields_mismatch$'):
            aggregate(self.root)

    def test_deep_receipt_returns_a_fixed_input_error(self):
        with patch('src.retrieval_trial_report.json.loads', side_effect=RecursionError('fixture')):
            with self.assertRaisesRegex(ValueError, '^trial_receipt_invalid$'):
                aggregate(self.root)

    def test_blocked_receipt(self):
        self.receipt['status'] = 'BLOCKED'
        self.write_receipt()
        with self.assertRaisesRegex(ValueError, 'trial_receipt_not_complete'):
            aggregate(self.root)

    def test_permutation_and_ablation_require_bound_fields(self):
        name = 'target_permutation'
        path = self.root/(name+'.json')
        original = json.loads(path.read_bytes())['result']
        self.write_arm(name, {**original, 'fields_sha256': 'e'*64})
        self.write_receipt()
        with self.assertRaisesRegex(ValueError, '^trial_target_permutation_mismatch:primary$'):
            aggregate(self.root)
        self.write_arm(name, original)
        for name in ('without_dense', 'without_dense_target_permutation'):
            result = json.loads((self.root/(name+'.json')).read_bytes())['result']
            self.write_arm(name, {**result, 'fields_sha256': 'e'*64})
        self.write_receipt()
        with self.assertRaisesRegex(ValueError, '^trial_ablation_channel_mismatch$'):
            aggregate(self.root)

    def test_candidate_order_only(self):
        for name in ('primary', 'target_permutation', 'without_dense', 'without_dense_target_permutation'):
            result = json.loads((self.root/(name+'.json')).read_bytes())['result']
            result['stage'] = 'candidate_order_only_not_reranked'
            del result['scored_calls']
            self.write_arm(name, result)
        self.write_receipt()
        final = aggregate(self.root)['arms']['primary']['final_stage']
        self.assertFalse(final['reranked'])
        self.assertEqual(final['stage'], 'candidate_order_only_not_reranked')

    def test_measured_arms_share_a_single_stage_and_depth(self):
        for name in ('without_dense', 'without_dense_target_permutation'):
            result = json.loads((self.root/(name+'.json')).read_bytes())['result']
            result['candidate_depth'] += 1
            self.write_arm(name, result)
        self.write_receipt()
        with self.assertRaisesRegex(ValueError, '^trial_arm_configuration_mismatch$'):
            aggregate(self.root)

    def test_specter2_candidates_must_match_the_producer_cache(self):
        base = json.loads((self.root/'primary.json').read_bytes())['result']
        next(iter(base['candidates'].values()))['specter2_topk'].reverse()
        cache_sha = self.write_dense_cache(base)
        for name in ('primary', 'target_permutation'):
            result = json.loads((self.root/(name+'.json')).read_bytes())['result']
            result['dense_cache_sha256'] = cache_sha
            self.write_arm(name, result)
        self.write_receipt()
        with self.assertRaisesRegex(ValueError, '^trial_dense_cache_readback_mismatch$'):
            aggregate(self.root)

    def test_rejects_ranking_that_disagrees_with_bound_scores_or_pool(self):
        original = json.loads((self.root/'primary.json').read_bytes())['result']
        altered = json.loads(json.dumps(original))
        call = altered['scored_calls'][0]
        call['scores'].reverse()
        call['scores_sha256'] = _canonical_hash(call['scores'])
        self.write_arm('primary', altered)
        self.write_receipt()
        with self.assertRaisesRegex(ValueError, '^trial_target_permutation_mismatch:primary$'):
            aggregate(self.root)
        next(iter(original['candidates'].values()))['pool_sha256'] = '0'*64
        self.write_arm('primary', original)
        self.write_receipt()
        with self.assertRaisesRegex(ValueError, '^trial_target_permutation_mismatch:primary$'):
            aggregate(self.root)

    def test_arms_bind_the_producer_field_dense_and_reranker_conditions(self):
        name = 'without_dense_target_permutation'
        original = json.loads((self.root/(name+'.json')).read_bytes())['result']
        for field, value, expected in (
            ('field_condition', 'historical', 'trial_target_permutation_mismatch:without_dense'),
            ('dense_cache_binding', 'legacy_target_bound_v1', 'trial_target_permutation_mismatch:without_dense'),
            ('reranker_model_manifest_sha256', 'd'*64, 'trial_arm_configuration_mismatch'),
        ):
            with self.subTest(field=field):
                self.write_arm(name, {**original, field: value})
                self.write_receipt()
                with self.assertRaisesRegex(ValueError, expected):
                    aggregate(self.root)

    def test_cli_exclusive_output(self):
        output = self.root/'report.json'
        command = [sys.executable, '-m', 'src.retrieval_trial_report', '--trial-dir',
                   str(self.root), '--output', str(output)]
        cwd = Path(__file__).resolve().parents[1]
        subprocess.run(command, cwd=cwd, check=True, capture_output=True)
        original = output.read_bytes()
        self.assertTrue(original.endswith(b'\n'))
        result = subprocess.run(command, cwd=cwd, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stderr, b'trial_report_output_exists\n')
        self.assertEqual(output.read_bytes(), original)
