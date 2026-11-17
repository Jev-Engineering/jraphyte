"""Synthetic private receipts; no models or corpus."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from src.retrieval_trial_report import aggregate, CHANNELS, _canonical_hash


class TrialReportTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.result = dict(queries=4, top1=1, top10=2, mrr=0.3958333333333333,
            candidate_coverage=0.75, candidate_depth=50, stage='local_cross_encoder',
            details=[dict(id='SECRETQUERY'+str(i), target_id='SECRETDOC'+str(i),
                query='secret query alpha', rank=r, candidate_present=r is not None,
                top10=['SECRETDOC'+str(j) for j in range(6)])
                for i, r in enumerate((1, 2, 12, None))],
            candidate_stage_metrics={c: dict(status='MEASURED', hits=3, queries=4, recall=.75)
                                     for c in CHANNELS}, index_seconds=1, candidate_seconds=2,
            rerank_seconds=3, wall_seconds=6, process_cpu_seconds=5,
            rankings={}, candidates={},
            page_channel_enabled=True, dense_stage='supplied_bound_cache', dense_cache_sha256='b'*64,
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
        queries = [{k: d[k] for k in ('id', 'query', 'target_id')} for d in self.result['details']]
        targets = [q['target_id'] for q in queries]
        for query, target in zip(queries, targets[1:] + targets[:1]):
            query['target_id'] = target
        for name in ('primary', 'target_permutation', 'without_dense', 'without_dense_target_permutation'):
            result = json.loads(json.dumps(self.result))
            if name.startswith('without_dense'):
                result['candidate_stage_metrics']['specter2'] = {'status': 'NOT_RUN'}
                result.update(dense_stage='not_run', dense_cache_sha256=None)
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

    def write_arm(self, name, result):
        result = {**result,
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

    def test_rank_pool_and_candidate_stage_contradictions(self):
        for mutate in (
            lambda result: result['details'][0].update(candidate_present=False),
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

    def test_blocked_receipt(self):
        self.receipt['status'] = 'BLOCKED'
        self.write_receipt()
        with self.assertRaisesRegex(ValueError, 'trial_receipt_not_complete'):
            aggregate(self.root)

    def test_candidate_order_only(self):
        self.result['stage'] = 'candidate_order_only_not_reranked'
        self.write_arm('primary', self.result)
        permutation = json.loads((self.root/'target_permutation.json').read_bytes())['result']
        permutation['stage'] = self.result['stage']
        self.write_arm('target_permutation', permutation)
        self.write_receipt()
        final = aggregate(self.root)['arms']['primary']['final_stage']
        self.assertFalse(final['reranked'])
        self.assertEqual(final['stage'], 'candidate_order_only_not_reranked')

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
        self.assertEqual(output.read_bytes(), original)
