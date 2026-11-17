"""Allowlisted arithmetic summary of a private retrieval trial; no provenance claim."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import stat
import tempfile
from pathlib import Path

ARMS = ('primary', 'without_page', 'without_dense', 'historical_fields',
        'historical_fields_without_page')
CHANNELS = ('field_weighted_bm25_parallel_v4', 'specter2', 'bm25_page', 'union')


def number(value):
    try:
        return type(value) in (int, float) and math.isfinite(value)
    except OverflowError:
        return False


def numeric(values, *, integers=False):
    # Key names are allowlisted too: an input key could itself contain private text.
    return {k: v for k, v in values.items() if number(v) and v >= 0 and (not integers or type(v) is int)}


def status(value, allowed):
    return value if isinstance(value, str) and value in allowed else 'UNKNOWN'


def sha(value):
    if not isinstance(value, str) or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
        raise ValueError('trial_invalid_hash')
    return value


def arm_report(name, result, query_count):
    error = 'trial_metrics_readback_mismatch:' + name
    dense = name != 'without_dense'
    page = name not in ('without_page', 'historical_fields_without_page')
    if (type(result) is not dict or result.get('page_channel_enabled') is not page or
            result.get('dense_stage') != ('supplied_bound_cache' if dense else 'not_run') or
            result.get('dense_cache_binding') != ('ranking_inputs_only_v2' if dense else 'not_run') or
            result.get('field_condition') != ('historical' if name.startswith('historical_fields') else 'current') or
            (result.get('dense_cache_sha256') is not None) != dense):
        raise ValueError(error)
    disabled = {channel for channel, enabled in (('specter2', dense), ('bm25_page', page)) if not enabled}
    try:
        details, n = result['details'], result['queries']
        if type(n) is not int or n != query_count or type(details) is not list or n != len(details):
            raise ValueError(error)
        for d in details:
            rank, present = d['rank'], d['candidate_present']
            if (type(present) is not bool or present != (rank is not None) or
                    (present and (type(rank) is not int or rank < 1))):
                raise ValueError(error)
            reciprocal_rank = d['reciprocal_rank']
            if not number(reciprocal_rank) or reciprocal_rank != (1 / rank if present else 0.0):
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
            if channel in disabled:
                if item != {'status': 'NOT_RUN'}:
                    raise ValueError(error)
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
    stage = status(result.get('stage'), ('local_cross_encoder', 'candidate_order_only_not_reranked'))
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
    report = numeric({'peak_rss_bytes': memory.get('peak_rss_bytes')}, integers=True)
    report['scope'] = status(memory.get('scope'), ('current_process_lifetime_including_model_threads',))
    for key in ('child_processes_included', 'system_memory_measured'):
        if type(memory.get(key)) is bool:
            report[key] = memory[key]
    return report


def _read_regular(path, error, *, hash_only=False):
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
            return hashlib.file_digest(handle, "sha256").hexdigest() if hash_only else handle.read()
    except (OSError, UnicodeError):
        raise ValueError(error) from None


def _json_object(raw, error):
    def unique_object(pairs):
        fields = {}
        for key, value in pairs:
            if key in fields:
                raise ValueError(error)
            fields[key] = value
        return fields

    def nonfinite(_):
        raise ValueError(error)

    try:
        value = json.loads(raw, object_pairs_hook=unique_object, parse_constant=nonfinite)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError(error) from None
    if type(value) is not dict:
        raise ValueError(error)
    return value


def _permutation_file(arm):
    return 'target_permutation.json' if arm == 'primary' else arm + '_target_permutation.json'


def _canonical_hash(value):
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()


def _permuted_queries(data, query_count):
    error = 'trial_target_permutation_invalid'
    queries = _json_object(data, error).get('queries')
    fields = ('id', 'query', 'target_id')
    if (type(queries) is not list or len(queries) != query_count or
            any(type(row) is not dict or any(type(row.get(key)) is not str for key in fields)
                or not row['query'].strip() or not row['target_id'] for row in queries) or len({row['id'] for row in queries}) != query_count):
        raise ValueError(error)
    return queries


def _scored_order(call, qid, pool, error):
    scores = call['scores']
    if (call['query_id'] != qid or type(call['pair_count']) is not int or call['pair_count'] != len(pool) or
            type(scores) is not list or len(scores) != len(pool) or not all(number(score) for score in scores) or
            call['scores_sha256'] != _canonical_hash(scores)):
        raise ValueError(error)
    sha(call['pairs_sha256'])
    return [pool[i] for i in sorted(range(len(pool)), key=lambda i: (-scores[i], i))]


def _permutation_check(arm, base, rotated, queries, recorded, *, historical_fields=None):
    error = 'trial_target_permutation_mismatch:' + arm
    try:
        input_hash = _canonical_hash([{'id': row['id'], 'query': row['query']} for row in queries])
        labels, score_inputs = [], []
        query_text = {row['id']: row['query'] for row in queries}
        for result in (base, rotated):
            sha(result.get('fields_sha256'))
            if result['dense_cache_sha256'] is not None:
                sha(result['dense_cache_sha256'])
            rows = [{'id': row['id'], 'target_id': row['target_id']} for row in result['details']]
            rankings, candidates = result['rankings'], result['candidates']
            if ([row['id'] for row in rows] != [row['id'] for row in queries] or
                    any(type(row['target_id']) is not str or not row['target_id'] for row in rows) or
                    type(rankings) is not dict or type(candidates) is not dict or
                    set(rankings) != {row['id'] for row in rows} or set(rankings) != set(candidates) or
                    result['evaluation_labels_sha256'] != _canonical_hash(rows) or
                    result['ranking_outputs_sha256'] != _canonical_hash(rankings) or
                    result['ranking_inputs_sha256'] != input_hash):
                raise ValueError(error)
            measured_hits = dict.fromkeys(CHANNELS[:-1], 0)
            use_scores = result['stage'] == 'local_cross_encoder'
            calls = result.get('scored_calls', [])
            if type(calls) is not list or (not use_scores and calls):
                raise ValueError(error)
            consumed = 0
            input_hashes = []
            for detail in result['details']:
                qid, target = detail['id'], detail['target_id']
                order, candidate = rankings[qid], candidates[qid]
                pool = candidate['pool']
                union = {}
                for channel in measured_hits:
                    topk = candidate[channel + '_topk']
                    stage = result['candidate_stage_metrics'][channel]
                    if (type(topk) is not list or len(topk) > result['candidate_depth'] or
                            any(type(doc) is not str or not doc for doc in topk) or len(topk) != len(set(topk)) or
                            (stage['status'] == 'NOT_RUN' and topk)):
                        raise ValueError(error)
                    measured_hits[channel] += target in topk
                    union.update(dict.fromkeys(topk))
                candidate_order = result['stage'] == 'candidate_order_only_not_reranked'
                if (pool != list(union) or candidate['pool_sha256'] != _canonical_hash(pool) or
                        type(order) is not list or len(order) != len(pool) or set(order) != set(pool) or
                        (candidate_order and order != pool)):
                    raise ValueError(error)
                if use_scores and pool:
                    if consumed >= len(calls) or _scored_order(calls[consumed], qid, pool, error) != order:
                        raise ValueError(error)
                    pair_hash = calls[consumed]['pairs_sha256']
                    if historical_fields is not None:
                        pairs = [(query_text[qid], "\n".join(historical_fields[ref].get(field, "")
                                  for field in ("title", "abstract", "body"))) for ref in pool]
                        if pair_hash != _canonical_hash(pairs):
                            raise ValueError(error)
                    input_hashes.append(pair_hash)
                    consumed += 1
                rank = order.index(target) + 1 if target in pool else None
                if detail['rank'] != rank or detail['top10'] != order[:10]:
                    raise ValueError(error)
            if consumed != len(calls):
                raise ValueError(error)
            score_inputs.append(input_hashes)
            for channel, hits in measured_hits.items():
                if result['candidate_stage_metrics'][channel].get('hits', 0) != hits:
                    raise ValueError(error)
            labels.append([row['target_id'] for row in rows])
        before, after = labels
        if before == after or before[1:] + before[:1] != after or after != [row['target_id'] for row in queries]:
            raise ValueError(error)
        checks = {key: base[key] == rotated[key] for key in
                  ('ranking_inputs_sha256', 'ranking_outputs_sha256', 'candidates', 'dense_cache_sha256')}
        checks['labels_changed'] = True
        same_configuration = all(base[key] == rotated[key] for key in ('candidate_depth', 'stage', 'fields_sha256'))
        if (not same_configuration or score_inputs[0] != score_inputs[1] or
                not all(checks.values()) or type(recorded) is not dict or
                recorded != {'status': 'PASS', 'checks': checks} or
                any(value is not True for value in recorded['checks'].values())):
            raise ValueError(error)
    except (KeyError, TypeError, UnicodeError, ValueError, RecursionError):
        raise ValueError(error) from None
    return 'PASS'


def _check_ablation(base, variant, removed):
    error = 'trial_ablation_channel_mismatch'
    if (base['ranking_inputs_sha256'] != variant['ranking_inputs_sha256'] or
            base['fields_sha256'] != variant['fields_sha256'] or
            (removed != 'specter2' and base['dense_cache_sha256'] != variant['dense_cache_sha256'])):
        raise ValueError(error)
    retained = [channel + '_topk' for channel in CHANNELS[:-1] if channel != removed]
    original, ablated = base['candidates'], variant['candidates']
    if (set(original) != set(ablated) or any(
            original[qid][key] != ablated[qid][key] for qid in original for key in retained)):
        raise ValueError(error)


def _check_dense_batches(directory, cache, artifacts, counts, query_texts, historical_file_sha, error):
    raw = _read_regular(directory / 'protocol.json', error)
    protocol = _json_object(raw, error)
    protocol_sha = sha(cache['protocol_sha256'])
    batch_size = protocol['batch_size']
    fields_file_sha = sha(protocol['fields_file_sha256'])
    bindings = ('fields_sha256', 'ranking_inputs_sha256', 'document_ids_sha256', 'query_ids_sha256',
                'model_manifest_sha256', 'model_revisions', 'top_k', 'target_ids_used_for_ranking')
    if (_canonical_hash(protocol) != protocol_sha or artifacts['protocol.json'] != hashlib.sha256(raw).hexdigest() or
            protocol['schema_version'] != 'specter2-vector-protocol-v1' or
            type(batch_size) is not int or batch_size <= 0 or
            (historical_file_sha is not None and fields_file_sha != historical_file_sha) or
            any(_canonical_hash(protocol[key]) != _canonical_hash(cache[key]) for key in bindings)):
        raise ValueError(error)
    batches = cache['vector_batches']
    if type(batches) is not dict or set(batches) != set(counts):
        raise ValueError(error)
    expected_files = {'dense_cache.json', 'protocol.json'}
    for group, total in counts.items():
        starts = range(0, total, batch_size)
        if type(batches[group]) is not list or len(batches[group]) != len(starts):
            raise ValueError(error)
        for start, batch in zip(starts, batches[group], strict=True):
            count = min(batch_size, total - start)
            expected = {'schema_version': 'specter2-batch-v1', 'start': start, 'count': count,
                        'input_sha256': sha(batch['input_sha256']), 'protocol_sha256': protocol_sha,
                        'checkpoint_sha256': sha(batch['checkpoint_sha256']), 'truncated': batch['truncated']}
            if (type(batch['start']) is not int or batch['start'] != start or
                    type(batch['count']) is not int or batch['count'] != count or
                    type(batch['truncated']) is not int or not 0 <= batch['truncated'] <= count or
                    (group == 'queries' and expected['input_sha256'] != _canonical_hash(query_texts[start:start + count]))):
                raise ValueError(error)
            name = f'{group}/{start:05d}'
            expected_files.update((name + '.npz', name + '.receipt.json'))
            raw = _read_regular(directory / (name + '.receipt.json'), error)
            receipt_sha = hashlib.sha256(raw).hexdigest()
            if (artifacts[name + '.npz'] != expected['checkpoint_sha256'] or
                    artifacts[name + '.receipt.json'] != sha(batch['receipt_sha256']) or
                    receipt_sha != batch['receipt_sha256'] or
                    _canonical_hash(_json_object(raw, error)) != _canonical_hash(expected)):
                raise ValueError(error)
    if set(artifacts) != expected_files:
        raise ValueError(error)


def _check_dense_caches(trial_dir, receipt, results, queries, historical_ids):
    error = 'trial_dense_cache_readback_mismatch'
    measured = [result for result in results.values() if result['dense_stage'] == 'supplied_bound_cache']
    conditions = receipt.get('dense_conditions')
    if type(conditions) is not dict or set(conditions) != {result['field_condition'] for result in measured}:
        raise ValueError(error)
    query_ids = [row['id'] for row in queries]
    query_texts = [row['query'] for row in queries]
    historical_id_set = set(historical_ids) if historical_ids is not None else None
    try:
        model_identity = None
        corpus_hash = _canonical_hash(historical_ids) if historical_ids is not None else None
        for condition, binding in conditions.items():
            directory = trial_dir / ('specter2' if condition == 'current' else 'specter2-historical')
            if directory.is_symlink() or not directory.is_dir():
                raise ValueError(error)
            raw = _read_regular(directory / 'dense_cache.json', error)
            file_sha = hashlib.sha256(raw).hexdigest()
            if (file_sha != binding['cache_sha256'] or
                    file_sha != binding['artifact_sha256']['dense_cache.json'] or
                    (condition == 'current' and (receipt['dense_cache_file_sha256'] != file_sha or
                     receipt['dense_artifact_sha256'] != binding['artifact_sha256']))):
                raise ValueError(error)
            artifacts = binding['artifact_sha256']
            actual = set()
            for item in directory.rglob('*'):
                if item.is_symlink() or (not item.is_dir() and not item.is_file()):
                    raise ValueError(error)
                if item.is_file():
                    actual.add(item.relative_to(directory).as_posix())
            if actual != set(artifacts):
                raise ValueError(error)
            for name, expected in artifacts.items():
                relative = Path(name)
                if (not name or relative.is_absolute() or '..' in relative.parts or
                        any(char in name for char in ('\\', ':', '\0'))):
                    raise ValueError(error)
                asset = directory / relative
                if not asset.resolve().is_relative_to(directory.resolve()):
                    raise ValueError(error)
                if name != 'dense_cache.json' and _read_regular(asset, error, hash_only=True) != sha(expected):
                    raise ValueError(error)
            cache = _json_object(raw, error)
            rankings = cache['rankings']
            document_count, query_count = receipt['document_count'], len(query_ids)
            historical_file_sha = receipt['result_file_sha256']['historical-fields.json'] if condition == 'historical' else None
            _check_dense_batches(directory, cache, artifacts, {'papers': document_count, 'queries': query_count},
                                 query_texts, historical_file_sha, error)
            versions = cache['model_revisions']
            model_sha = sha(cache['model_manifest_sha256'])
            if (type(versions) is not dict or set(versions) != {'base', 'paper', 'query'} or
                    any(type(value) is not str or re.fullmatch('[a-f0-9]{40}', value) is None
                        for value in versions.values()) or cache['model_revision'] != versions['base']):
                raise ValueError(error)
            current_model = (model_sha, versions)
            if model_identity is not None and model_identity != current_model:
                raise ValueError(error)
            model_identity = current_model
            current_corpus = sha(cache['document_ids_sha256'])
            if corpus_hash is not None and corpus_hash != current_corpus:
                raise ValueError(error)
            corpus_hash = current_corpus
            masked, masked_count = cache['dense_input_absent_ids'], cache['dense_input_absent_count']
            if type(masked) is not list or any(type(value) is not str for value in masked):
                raise ValueError(error)
            masked_ids = set(masked)
            if (type(masked_count) is not int or masked_count != len(masked_ids) or
                    masked_count != len(masked) or not 0 <= masked_count < document_count or
                    (historical_id_set is not None and not masked_ids <= historical_id_set)):
                raise ValueError(error)
            if (cache['binding_version'] != 'ranking-inputs-v2' or cache['channel'] != 'specter2' or
                    cache['target_ids_used_for_ranking'] is not False or
                    cache['query_ids_sha256'] != _canonical_hash(query_ids) or
                    type(cache['document_count']) is not int or cache['document_count'] != document_count or
                    type(cache['query_count']) is not int or cache['query_count'] != query_count or
                    type(rankings) is not dict or set(rankings) != set(query_ids) or
                    cache['ranking_sha256'] != _canonical_hash(rankings) or
                    type(cache['top_k']) is not int):
                raise ValueError(error)
            cache_sha = _canonical_hash(cache)
            for result in measured:
                if result['field_condition'] != condition:
                    continue
                depth = result['candidate_depth']
                if (result['dense_cache_sha256'] != cache_sha or depth != cache['top_k'] or
                        result['fields_sha256'] != cache['fields_sha256'] or
                        result['ranking_inputs_sha256'] != cache['ranking_inputs_sha256']):
                    raise ValueError(error)
                for qid, ranking in rankings.items():
                    if (type(ranking) is not list or len(ranking) != min(depth, document_count - masked_count) or
                            set(ranking) & masked_ids or (historical_id_set is not None and not set(ranking) <= historical_id_set) or
                            result['candidates'][qid]['specter2_topk'] != ranking):
                        raise ValueError(error)
    except (KeyError, OSError, RuntimeError, TypeError, UnicodeError, ValueError):
        raise ValueError(error) from None


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
        required.add(_permutation_file(arm))
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
    arms, results = {}, {}
    known_arms = {arm + '.json': arm for arm in ARMS}
    permutations = {_permutation_file(arm): arm for arm in ARMS}
    manifest = _manifest(receipt)
    measured = {arm for name, arm in known_arms.items() if name in manifest}
    if {arm for name, arm in permutations.items() if name in manifest} != measured:
        raise ValueError('trial_result_manifest_incomplete')
    queries = None
    historical = None
    for name, expected in manifest.items():
        arm = known_arms.get(name) or permutations.get(name)
        error = 'trial_result_hash_mismatch:' + name if arm else 'trial_result_hash_mismatch'
        if (Path(name).name != name or name in ('', '.', '..') or
                any(char in name for char in ('/', '\\', ':', '\0'))):
            raise ValueError(error)
        data = _read_regular(trial_dir / name, error)
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError(error)
        if arm:
            metric_error = ('trial_metrics_readback_mismatch:' if name in known_arms else
                            'trial_target_permutation_mismatch:') + arm
            payload = _json_object(data, metric_error)
            if payload.get('status') != 'MEASURED_PENDING_FINAL_INTEGRITY':
                raise ValueError(metric_error)
            result = payload.get('result')
            try:
                metrics = arm_report(arm, result, query_count)
            except ValueError:
                raise ValueError(metric_error) from None
            results[name] = result
            if name in known_arms:
                arms[arm] = metrics
        elif name == 'queries-permuted.json':
            queries = _permuted_queries(data, query_count)
        elif name == 'historical-fields.json':
            artifact = _json_object(data, 'trial_historical_fields_mismatch')
            historical = artifact.get('fields')
            if (set(artifact) != {'fields'} or type(historical) is not list or
                    len(historical) != document_count or any(
                        type(row) is not dict or type(row.get('id')) is not str or not row['id']
                        for row in historical)):
                raise ValueError('trial_historical_fields_mismatch')
    if any(type(result.get('fields_count')) is not int or result['fields_count'] != document_count
           for result in results.values()):
        raise ValueError('trial_document_count_mismatch')
    primary = results['primary.json']
    config_keys = ('candidate_depth', 'stage')
    if primary['stage'] == 'local_cross_encoder':
        config_keys += ('reranker_model_manifest_sha256',)
        try:
            sha(primary.get('reranker_model_manifest_sha256'))
        except ValueError:
            raise ValueError('trial_arm_configuration_mismatch') from None
    if any(result.get(key) != primary.get(key) for result in results.values() for key in config_keys):
        raise ValueError('trial_arm_configuration_mismatch')
    checks, permutation = receipt.get('all_arm_target_permutations'), receipt.get('target_permutation')
    if type(checks) is not dict or set(checks) != set(arms) or permutation != checks['primary']:
        raise ValueError('trial_target_permutation_missing')
    historical_by_id = None
    if historical is not None:
        try:
            expected_fields = _canonical_hash(historical)
        except (TypeError, ValueError, OverflowError, RecursionError):
            raise ValueError('trial_historical_fields_mismatch') from None
        if any(result.get('fields_sha256') != expected_fields for name, result in results.items()
               if name.startswith('historical_fields')):
            raise ValueError('trial_historical_fields_mismatch')
        historical_by_id = {row['id']: row for row in historical}
    verified_checks = {
        arm: _permutation_check(arm, results[arm + '.json'], results[_permutation_file(arm)], queries, checks[arm],
                                historical_fields=historical_by_id if arm.startswith('historical_fields') else None)
        for arm in arms
    }
    observed_ids = {row['target_id'] for result in results.values() for row in result['details']}
    observed_ids.update(doc for result in results.values()
                        for candidate in result['candidates'].values() for doc in candidate['pool'])
    if len(observed_ids) > document_count:
        raise ValueError('trial_document_count_mismatch')
    if historical_by_id is not None and (
            len(historical_by_id) != document_count or not observed_ids.issubset(historical_by_id)):
        raise ValueError('trial_historical_fields_mismatch')
    for base, variant, removed in (
        ('primary', 'without_page', 'bm25_page'),
        ('primary', 'without_dense', 'specter2'),
        ('historical_fields', 'historical_fields_without_page', 'bm25_page'),
    ):
        if variant in arms:
            _check_ablation(results[base + '.json'], results[variant + '.json'], removed)
    _check_dense_caches(trial_dir, receipt, results, queries, list(historical_by_id) if historical_by_id is not None else None)
    return dict(schema_version='retrieval-trial-sanitized-metrics-v1',
        trial_receipt_sha256=hashlib.sha256(raw).hexdigest(), protocol_sha256=sha(receipt.get('protocol_sha256')),
        **numeric({k: receipt.get(k) for k in ('document_count', 'query_count',
                                             'new_paid_api_calls', 'production_graph_writes')}, integers=True),
        full_10000_by_60=full,
        ablations={k: status(receipt.get('ablations', {}).get(k),
            ('MEASURED', 'NOT_RUN', 'ARCHIVED_FIELDS_MEASURED')) for k in
            ('without_dense', 'without_page_channel', 'historical_field_policy')},
        relevance_judgments=status(receipt.get('relevance_judgments'), ('NOT_PERFORMED',)),
        memory=memory_report(receipt.get('memory')),
        target_permutation=verified_checks['primary'], all_arm_target_permutations=verified_checks,
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
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=args.output.parent,
                                         prefix='.trial-report-', delete=False) as handle:
            temporary = Path(handle.name)
            try:
                handle.write(json.dumps(report, sort_keys=True, allow_nan=False) + '\n')
                handle.flush()
                os.fsync(handle.fileno())
                handle.close()
                os.link(temporary, args.output)
            finally:
                temporary.unlink(missing_ok=True)
    except FileExistsError:
        parser.exit(1, 'trial_report_output_exists\n')
    except (OSError, ValueError):
        parser.exit(1, 'trial_report_output_write_failed\n')


if __name__ == '__main__':
    main()
