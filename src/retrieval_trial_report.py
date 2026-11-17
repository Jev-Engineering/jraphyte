"""Allowlisted arithmetic summary of a private retrieval trial; no provenance claim."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import stat
from pathlib import Path

ARMS = ('primary', 'without_page', 'without_dense', 'historical_fields',
        'historical_fields_without_page')
CHANNELS = ('field_weighted_bm25_parallel_v4', 'specter2', 'bm25_page', 'union')


def number(value):
    try:
        return type(value) in (int, float) and math.isfinite(value)
    except OverflowError:
        return False


def numeric(values):
    # Key names are allowlisted too: an input key could itself contain private text.
    return {k: v for k, v in values.items() if number(v)}


def status(value, allowed):
    return value if isinstance(value, str) and value in allowed else 'UNKNOWN'


def sha(value):
    if not isinstance(value, str) or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
        raise ValueError('trial_invalid_hash')
    return value


def arm_report(name, result, query_count):
    error = 'trial_metrics_readback_mismatch:' + name
    try:
        details, n = result['details'], result['queries']
        if type(n) is not int or n != query_count or type(details) is not list or n != len(details):
            raise ValueError(error)
        for d in details:
            rank, present = d['rank'], d['candidate_present']
            if (type(present) is not bool or present != (rank is not None) or
                    (present and (type(rank) is not int or rank < 1))):
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
            elif type(value) is int:
                if type(actual) is not int or actual != value:
                    raise ValueError(error)
            elif not number(actual) or not math.isclose(actual, value, rel_tol=1e-12, abs_tol=1e-12):
                raise ValueError(error)
        stages = result['candidate_stage_metrics']
        if stages['union']['status'] != 'MEASURED' or stages['union']['hits'] != present:
            raise ValueError(error)
        candidate = {}
        for channel in CHANNELS:
            item = stages[channel]
            if item['status'] == 'NOT_RUN':
                candidate[channel] = {'status': 'NOT_RUN'}
            else:
                if item['status'] != 'MEASURED' or not all(type(item[k]) is int for k in ('hits', 'queries')):
                    raise ValueError(error)
                if item['queries'] != n or not 0 <= item['hits'] <= present:
                    raise ValueError(error)
                recall = item['hits'] / n if n else None
                if item['recall'] != recall or (recall is not None and not number(item['recall'])):
                    raise ValueError(error)
                candidate[channel] = dict(status='MEASURED', hits=item['hits'], queries=n, recall=recall)
        if type(result['candidate_depth']) is not int or result['candidate_depth'] <= 0:
            raise ValueError(error)
        candidate['candidate_depth'] = result['candidate_depth']
    except (KeyError, TypeError, OverflowError):
        raise ValueError(error) from None
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


def _read_regular(path, error):
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(error)
        flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
        fd = os.open(path, flags | getattr(os, 'O_BINARY', 0))
        with os.fdopen(fd, 'rb') as handle:
            opened = os.fstat(handle.fileno())
            if not stat.S_ISREG(opened.st_mode) or not os.path.samestat(before, opened):
                raise ValueError(error)
            return handle.read()
    except (OSError, UnicodeError):
        raise ValueError(error) from None


def _json_object(raw, error):
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError):
        raise ValueError(error) from None
    if type(value) is not dict:
        raise ValueError(error)
    return value


def _manifest(receipt):
    error = 'trial_result_manifest_incomplete'
    manifest, ablations = receipt.get('result_file_sha256'), receipt.get('ablations')
    if type(manifest) is not dict or type(ablations) is not dict:
        raise ValueError(error)
    measured = {'primary'}
    for key, arm, active in (
        ('without_dense', 'without_dense', 'MEASURED'),
        ('without_page_channel', 'without_page', 'MEASURED'),
        ('historical_field_policy', 'historical_fields', 'ARCHIVED_FIELDS_MEASURED'),
    ):
        if ablations.get(key) == active:
            measured.add(arm)
        elif ablations.get(key) != 'NOT_RUN':
            raise ValueError(error)
    required = {'queries-permuted.json'}
    if 'historical_fields' in measured:
        required.add('historical-fields.json')
        if 'without_page' in measured:
            measured.add('historical_fields_without_page')
    for arm in measured:
        required.add(arm + '.json')
        required.add('target_permutation.json' if arm == 'primary' else arm + '_target_permutation.json')
    listed_arms = {arm for arm in ARMS if arm + '.json' in manifest}
    if not required.issubset(manifest) or listed_arms != measured:
        raise ValueError(error)
    return manifest


def aggregate(trial_dir: Path) -> dict:
    trial_dir = Path(trial_dir)
    raw = _read_regular(trial_dir / 'receipt.json', 'trial_receipt_unreadable')
    receipt = _json_object(raw, 'trial_receipt_invalid')
    if receipt.get('status') != 'COMPLETE':
        raise ValueError('trial_receipt_not_complete')
    document_count, query_count = receipt.get('document_count'), receipt.get('query_count')
    if (type(document_count) is not int or document_count <= 0 or
            type(query_count) is not int or query_count <= 0):
        raise ValueError('trial_receipt_invalid_counts')
    full = document_count == 10_000 and query_count == 60
    if receipt.get('full_10000_by_60') is not full:
        raise ValueError('trial_receipt_invalid_counts')
    arms = {}
    known_arms = {a + '.json': a for a in ARMS}
    for name, expected in _manifest(receipt).items():
        arm = known_arms.get(name)
        error = 'trial_result_hash_mismatch:' + arm + '.json' if arm else 'trial_result_hash_mismatch'
        if (Path(name).name != name or name in ('', '.', '..') or
                any(char in name for char in ('/', '\\', ':', '\0'))):
            raise ValueError(error)
        data = _read_regular(trial_dir / name, error)
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError(error)
        if arm:
            metric_error = 'trial_metrics_readback_mismatch:' + arm
            payload = _json_object(data, metric_error)
            if payload.get('status') != 'MEASURED_PENDING_FINAL_INTEGRITY':
                raise ValueError(metric_error)
            arms[arm] = arm_report(arm, payload.get('result'), query_count)
    checks, permutation = receipt.get('all_arm_target_permutations'), receipt.get('target_permutation')
    if (type(checks) is not dict or type(permutation) is not dict or
            any(type(checks.get(arm)) is not dict for arm in arms)):
        raise ValueError('trial_target_permutation_missing')
    return dict(schema_version='retrieval-trial-sanitized-metrics-v1',
        trial_receipt_sha256=hashlib.sha256(raw).hexdigest(), protocol_sha256=sha(receipt['protocol_sha256']),
        **numeric({k: receipt.get(k) for k in ('document_count', 'query_count',
                                             'new_paid_api_calls', 'production_graph_writes')}),
        full_10000_by_60=full,
        ablations={k: status(receipt.get('ablations', {}).get(k),
            ('MEASURED', 'NOT_RUN', 'ARCHIVED_FIELDS_MEASURED')) for k in
            ('without_dense', 'without_page_channel', 'historical_field_policy')},
        relevance_judgments=status(receipt.get('relevance_judgments'), ('NOT_PERFORMED',)),
        memory=memory_report(receipt.get('memory')),
        target_permutation=status(permutation.get('status'), ('PASS', 'FAIL')),
        all_arm_target_permutations={a: status(checks[a].get('status'), ('PASS', 'FAIL'))
                                     for a in ARMS if a in checks},
        arms=arms, issue_acceptance_complete=False,
        evidence_note='Certifies arithmetic consistency of a private receipt, not the provenance of its inputs.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trial-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        report = aggregate(args.trial_dir)
    except ValueError as exc:
        parser.exit(1, str(exc) + '\n')
    with args.output.open('x', encoding='utf-8') as handle:
        handle.write(json.dumps(report, sort_keys=True, allow_nan=False) + '\n')


if __name__ == '__main__':
    main()
