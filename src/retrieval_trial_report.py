"""Allowlisted arithmetic summary of a private retrieval trial; no provenance claim."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path

ARMS = ('primary', 'without_page', 'without_dense', 'historical_fields',
        'historical_fields_without_page')
CHANNELS = ('field_weighted_bm25_parallel_v4', 'specter2', 'bm25_page', 'union')


def number(value):
    return type(value) in (int, float) and math.isfinite(value)


def numeric(values):
    # Key names are allowlisted too: an input key could itself contain private text.
    return {k: v for k, v in values.items() if number(v)}


def status(value, allowed):
    return value if isinstance(value, str) and value in allowed else 'UNKNOWN'


def sha(value):
    if not isinstance(value, str) or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
        raise ValueError('trial_invalid_hash')
    return value


def arm_report(name, result):
    error = 'trial_metrics_readback_mismatch:' + name
    try:
        details, n = result['details'], result['queries']
        if type(n) is not int or n != len(details):
            raise ValueError(error)
        for d in details:
            if type(d['candidate_present']) is not bool or (d['rank'] is not None and
                    (type(d['rank']) is not int or d['rank'] < 1)):
                raise ValueError(error)
        top1 = sum(d['rank'] == 1 for d in details)
        top10 = sum(d['rank'] is not None and d['rank'] <= 10 for d in details)
        present = sum(d['candidate_present'] for d in details)
        mrr = sum(1 / d['rank'] if d['rank'] else 0 for d in details) / n if n else None
        expected = dict(top1=top1, top10=top10, mrr=mrr,
                        candidate_coverage=present / n if n else None)
        for key, value in expected.items():
            actual = result[key]
            if value is None:
                if actual is not None:
                    raise ValueError(error)
            elif not number(actual) or not math.isclose(actual, value, rel_tol=1e-12, abs_tol=1e-12):
                raise ValueError(error)
        stages = result['candidate_stage_metrics']
        if stages['union']['hits'] != present:
            raise ValueError(error)
        candidate = {}
        for channel in CHANNELS:
            item = stages[channel]
            if item['status'] == 'NOT_RUN':
                candidate[channel] = {'status': 'NOT_RUN'}
            else:
                if item['status'] != 'MEASURED' or not all(number(item[k]) for k in ('hits', 'queries')):
                    raise ValueError(error)
                if item['queries'] != n or not 0 <= item['hits'] <= n:
                    raise ValueError(error)
                recall = item['hits'] / n if n else None
                if item['recall'] != recall:
                    raise ValueError(error)
                candidate[channel] = dict(status='MEASURED', hits=item['hits'], queries=n, recall=recall)
        if not number(result['candidate_depth']):
            raise ValueError(error)
        candidate['candidate_depth'] = result['candidate_depth']
    except (KeyError, TypeError, ZeroDivisionError) as exc:
        raise ValueError(error) from exc
    stage = status(result.get('stage'), ('local_cross_encoder', 'supplied_scorer',
                                         'candidate_order_only_not_reranked'))
    if stage == 'UNKNOWN':
        raise ValueError(error)
    return {'candidate_stage': candidate,
            'final_stage': dict(stage=stage, reranked=stage != 'candidate_order_only_not_reranked',
                queries=n, top1=top1, top10=top10, mrr=mrr,
                top1_rate=top1/n if n else None, top10_rate=top10/n if n else None,
                misses_outside_candidate_pool=n-present,
                in_pool_ranked_below_10=sum(d['candidate_present'] and d['rank'] is not None
                                          and d['rank'] > 10 for d in details)),
            'timing': numeric({k: result.get(k) for k in ('index_seconds', 'candidate_seconds',
                'rerank_seconds', 'wall_seconds', 'process_cpu_seconds')})}


def memory_report(memory) -> dict:
    """Copy the trial's own high-water receipt (`retrieval_trial.memory_receipt`)."""
    memory = memory if isinstance(memory, dict) else {}
    report = numeric({'peak_rss_bytes': memory.get('peak_rss_bytes')})
    report['scope'] = status(memory.get('scope'), ('current_process_lifetime_including_model_threads',))
    for key in ('child_processes_included', 'system_memory_measured'):
        if type(memory.get(key)) is bool:
            report[key] = memory[key]
    return report


def aggregate(trial_dir: Path) -> dict:
    trial_dir = Path(trial_dir)
    raw = (trial_dir / 'receipt.json').read_bytes()
    receipt = json.loads(raw)
    if receipt.get('status') != 'COMPLETE':
        raise ValueError('trial_receipt_not_complete')
    arms = {}
    for name, expected in receipt['result_file_sha256'].items():
        # Never traverse outside the private trial directory.
        path = trial_dir / name
        if Path(name).name != name or '/' in name or '\\' in name or not path.is_file():
            raise ValueError('trial_result_hash_mismatch:' + name)
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError('trial_result_hash_mismatch:' + name)
        if name in {a + '.json' for a in ARMS}:
            payload = json.loads(data)
            if payload.get('status') != 'MEASURED_PENDING_FINAL_INTEGRITY':
                raise ValueError('trial_metrics_readback_mismatch:' + name[:-5])
            arms[name[:-5]] = arm_report(name[:-5], payload['result'])
    checks = receipt.get('all_arm_target_permutations', {})
    return dict(schema_version='retrieval-trial-sanitized-metrics-v1',
        trial_receipt_sha256=hashlib.sha256(raw).hexdigest(), protocol_sha256=sha(receipt['protocol_sha256']),
        **numeric({k: receipt.get(k) for k in ('document_count', 'query_count',
                                             'new_paid_api_calls', 'production_graph_writes')}),
        full_10000_by_60=receipt.get('full_10000_by_60') is True,
        ablations={k: status(receipt.get('ablations', {}).get(k),
            ('MEASURED', 'NOT_RUN', 'ARCHIVED_FIELDS_MEASURED')) for k in
            ('without_dense', 'without_page_channel', 'historical_field_policy')},
        relevance_judgments=status(receipt.get('relevance_judgments'), ('NOT_PERFORMED',)),
        memory=memory_report(receipt.get('memory')),
        target_permutation=status(receipt.get('target_permutation', {}).get('status'), ('PASS', 'FAIL')),
        all_arm_target_permutations={a: status(checks[a].get('status'), ('PASS', 'FAIL'))
                                     for a in ARMS if a in checks},
        arms=arms, issue_acceptance_complete=False,
        evidence_note='Certifies arithmetic consistency of a private receipt, not the provenance of its inputs.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trial-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = aggregate(args.trial_dir)
    with args.output.open('x', encoding='utf-8') as handle:
        handle.write(json.dumps(report, sort_keys=True, allow_nan=False) + '\n')


if __name__ == '__main__':
    main()
