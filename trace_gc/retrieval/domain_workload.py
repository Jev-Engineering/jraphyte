"""Reproducible workload measurements; never a deployment qualification.

The application supplies session factories, authenticated adapters and any
explicit write callback. Data/queries cannot instantiate a backend or signer.
Latency includes actual retrieval; ACL cost is a separately timed snapshot scan.
"""
from __future__ import annotations

from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import math
import threading
import time
import tracemalloc
from typing import Any, Callable

from ..canonical import digest
from ..errors import require
from .contracts import validate_query
from .security import AccessFilter
from .service import validate_context

VERSION = 'trace-domain-workload-v2'


def percentile(values: list[float], fraction: float) -> float | None:
    """Nearest-rank percentile. Empty data is unknown, not zero latency."""
    require(0 < fraction <= 1, 'WORKLOAD_PERCENTILE', 'fraction outside (0,1]')
    if not values:
        return None
    ordered=sorted(values)
    return ordered[max(0, math.ceil(fraction*len(ordered))-1)]


def validate_protocol(protocol: dict[str, Any], cases: list[dict[str, Any]]) -> None:
    require(set(protocol)=={'version','cohort','label_origin','corpus_hash','case_hash','seed',
        'repeats','concurrency','write_count','isolation_requirements','slos','decision_owner','memory_profile'},
        'WORKLOAD_PROTOCOL','exact frozen protocol fields required')
    require(protocol['version']==VERSION and protocol['cohort'] in {'SYNTHETIC','REPRESENTATIVE_REVIEWED'},
        'WORKLOAD_PROTOCOL','explicit benchmark population required')
    require(type(protocol['repeats']) is int and 1<=protocol['repeats']<=10000 and
        type(protocol['concurrency']) is int and 1<=protocol['concurrency']<=64 and
        type(protocol['write_count']) is int and 0<=protocol['write_count']<=1000 and
        type(protocol['seed']) is int,'WORKLOAD_BOUNDS','bounded repetitions, workers and writes required')
    require(bool(cases) and len(cases)<=1000 and protocol['case_hash']==digest(cases),
        'WORKLOAD_PROTOCOL','cases differ from frozen protocol')
    import re
    require(type(protocol['memory_profile']) is bool,'WORKLOAD_PROTOCOL','explicit memory profiling switch required')
    require(isinstance(protocol['corpus_hash'],str) and bool(re.fullmatch(r'[0-9a-f]{64}',protocol['corpus_hash'])),
        'WORKLOAD_PROTOCOL','exact source/graph corpus hash required')
    require(len({c['id'] for c in cases})==len(cases),'WORKLOAD_PROTOCOL','duplicate case IDs')
    if protocol['cohort']=='SYNTHETIC':
        require(protocol['label_origin']=='SYNTHETIC','WORKLOAD_LABELS','synthetic inputs cannot claim external labels')
    else:
        require(protocol['label_origin'] in {'HUMAN','INDEPENDENT_EXTERNAL'} and
            bool(protocol['decision_owner']) and bool(protocol['isolation_requirements']) and bool(protocol['slos']),
            'WORKLOAD_EXTERNAL_INPUTS','representative run requires reviewed inputs, owner, isolation requirements and SLOs')
    for case in cases:
        require(set(case)=={'id','query','expected_edges','required_conflict_pairs','forbidden_source_ids'},
            'WORKLOAD_CASE','explicit query/quality labels required')
        validate_query(case['query'])
        require(all(isinstance(case[k],list) and all(isinstance(x,str) and x for x in case[k]) for k in ('expected_edges','forbidden_source_ids')), 'WORKLOAD_CASE','ID lists required')
        require(len(case['expected_edges'])==len(set(case['expected_edges'])),'WORKLOAD_CASE','duplicate edge labels')
        require(all(len(p)==2 and len(set(p))==2 for p in case['required_conflict_pairs']),
            'WORKLOAD_CASE','contradiction labels must be pairs')


def run_workload(session_factory: Callable[[], Any], protocol: dict[str, Any], cases: list[dict[str, Any]],
                 *, corpus_hash: str, write_action: Callable[[int], Any] | None=None) -> dict[str, Any]:
    """A session provides retriever and close(); each worker owns its connection.

    `write_action` is an explicit trusted callback, never sourced from JSON. It
    must return only a receipt summary and implement real publication semantics.
    The caller retains responsibility for authorization and safe environments.
    """
    validate_protocol(protocol,cases)
    require(protocol['corpus_hash']==corpus_hash,'WORKLOAD_CORPUS','input corpus changed after protocol freeze')
    require(not protocol['write_count'] or write_action is not None,'WORKLOAD_WRITE_AUTHORITY','explicit writer required')
    protocol,cases=deepcopy(protocol),deepcopy(cases)
    import random
    jobs=[(case,mode) for _ in range(protocol['repeats']) for case in cases for mode in ('unscoped','scoped')]
    random.Random(protocol['seed']).shuffle(jobs)
    workers=min(protocol['concurrency'],len(jobs))
    barrier=threading.Barrier(workers + bool(protocol['write_count']))

    def worker(index):
        session=session_factory(); r=session.retriever; rows=[]
        try:
            barrier.wait(timeout=30)
            for case,mode in jobs[index::workers]:
                q=deepcopy(case['query'])
                if mode=='unscoped':q['research_domain_scope']=[]
                # Profile ACL work separately. This scan is not added to the
                # measured retrieval latency or misrepresented as all ACL cost.
                v=r.adapter.read(q);acl=AccessFilter(r.access_policy,v.catalog,v.source_status)
                acl_started=time.perf_counter()
                visible=sum(acl.edge(ref,fact) for ref,fact in v.snapshot['assertions'].items())
                acl_ms=(time.perf_counter()-acl_started)*1000
                started=time.perf_counter()
                rid=r.retrieve(q)
                elapsed=(time.perf_counter()-started)*1000
                result=r.catalog.get(rid);ctx=r.catalog.get(result['graph_context_id'])
                validate_context(r.catalog,result['graph_context_id'],current_access=r.access_policy)
                edges=set(ctx['retrieved_edges']);expected=set(case['expected_edges'])
                evidence=ctx['selected_evidence_ids']
                actual_snapshot=r.catalog.get(ctx['snapshot_id'],'graph-snapshot')
                result_acl=AccessFilter(r.access_policy,r.catalog,ctx['source_status'])
                covered=edges | {ref for ref,fact in actual_snapshot['assertions'].items()
                    if fact['evidence_ids'] and set(fact['evidence_ids'])<=set(evidence) and result_acl.edge(ref,fact)}
                sources={r.catalog.get(ev,'evidence')['source_snapshot_id'] for ev in evidence}
                lineage=r.catalog.get(result['lineage_id'])
                closure_reasons={reason for item in ctx['items'] for why in item.get('research_domain_closure',{}).values() for reason in why}
                closure_edges={ref for item in ctx['items'] for ref,why in item.get('research_domain_closure',{}).items() if 'ANCHOR' not in why}
                rows.append({'case':case['id'],'mode':mode,'graph_version':ctx['graph_version'],
                    'classification_binding':ctx.get('research_domain_binding'),
                    'latency_ms':elapsed,'acl_scan_ms':acl_ms,'acl_scan_edges':len(v.snapshot['assertions']),
                    'acl_visible_edges':visible,'selected_edges':len(edges),'expected_edges':len(expected),
                    'true_positive_edges':len(edges&expected),
                    'missed_contradictions':sum(not set(pair)<=covered for pair in case['required_conflict_pairs']),
                    'missing_structured_conflict_edges':sum(not set(pair)<=edges for pair in case['required_conflict_pairs']),
                    'required_contradictions':len(case['required_conflict_pairs']),
                    'source_revocation_leaks':len(sources&set(case['forbidden_source_ids'])),
                    'cross_domain_closure_edges':len(closure_edges),'closure_reasons':sorted(closure_reasons),
                    'cache_hit':lineage['cache_hit'],'partial':result['status']=='PARTIAL',
                    'usage':result['usage']})
            return rows, {'hits':r.cache.hits,'misses':r.cache.misses,'invalidations':r.cache.invalidations}
        finally:
            session.close()

    def writer():
        barrier.wait(timeout=30);receipts=[]
        observer=session_factory()
        try:
            for index in range(protocol['write_count']):
                t=time.perf_counter();receipt=write_action(index)
                require(isinstance(receipt,dict) and type(receipt.get('version')) is int and
                    receipt['version']>0 and isinstance(receipt.get('event_hash'),str),
                    'WORKLOAD_WRITE_RECEIPT','real version/event receipt required')
                q=deepcopy(cases[0]['query']);q['graph_version']=None
                q['temporal_scope']={'as_of':None,'valid_at':None,'before_source':None}
                view=observer.retriever.adapter.read(q)
                require(any(e['version']==receipt['version'] and e['hash']==receipt['event_hash'] for e in view.events),
                    'WORKLOAD_WRITE_RECEIPT','write receipt not visible in the authoritative journal')
                receipts.append({'latency_ms':(time.perf_counter()-t)*1000,'receipt':receipt})
            return receipts
        finally:observer.close()

    started=time.perf_counter();owned_trace=protocol['memory_profile'] and not tracemalloc.is_tracing()
    if owned_trace:tracemalloc.start()
    try:
        with ThreadPoolExecutor(max_workers=workers+bool(protocol['write_count'])) as pool:
            futures=[pool.submit(worker,i) for i in range(workers)]
            future_write=pool.submit(writer) if protocol['write_count'] else None
            completed=[f.result() for f in futures]
            writes=future_write.result() if future_write else []
        peak=tracemalloc.get_traced_memory()[1] if protocol['memory_profile'] else None
    finally:
        if owned_trace:tracemalloc.stop()
    seconds=time.perf_counter()-started
    rows=[row for block,_ in completed for row in block]
    summaries={}
    for mode in ('unscoped','scoped'):
        selected=[r for r in rows if r['mode']==mode];latency=[r['latency_ms'] for r in selected]
        tp=sum(r['true_positive_edges'] for r in selected)
        actual=sum(r['selected_edges'] for r in selected);expected=sum(r['expected_edges'] for r in selected)
        summaries[mode]={'queries':len(selected),'p50_ms':percentile(latency,.5),'p95_ms':percentile(latency,.95),'p99_ms':percentile(latency,.99),
            'acl_scan_p95_ms':percentile([r['acl_scan_ms'] for r in selected],.95),
            'edge_precision':tp/actual if actual else None,'edge_recall':tp/expected if expected else None,
            'required_contradictions':sum(r['required_contradictions'] for r in selected),
            'missed_contradictions':sum(r['missed_contradictions'] for r in selected),
            'missing_structured_conflict_edges':sum(r['missing_structured_conflict_edges'] for r in selected),
            'source_revocation_leaks':sum(r['source_revocation_leaks'] for r in selected),
            'cross_domain_closure_edges':sum(r['cross_domain_closure_edges'] for r in selected),
            'cache_hit_rate':sum(r['cache_hit'] for r in selected)/len(selected),
            'partial_results':sum(r['partial'] for r in selected)}
    try:
        import resource, sys
        peak_rss=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*(1 if sys.platform=='darwin' else 1024)
    except ImportError:peak_rss=None
    return {'version':VERSION,'status':'MEASURED_NOT_QUALIFIED','protocol':protocol,'protocol_hash':digest(protocol),
        'corpus_hash':corpus_hash,'query_mix':dict(Counter(r['case'] for r in rows)),
        'scope':'Reference/runtime engineering measurements; no placement or production approval is issued.',
        'production_qualified':False,'storage_decision_authorized':False,'seconds':seconds,
        'queries_per_second':len(rows)/seconds,'committed_writes':len(writes),'writes_per_second':len(writes)/seconds,
        'peak_traced_python_bytes':peak,'peak_process_rss_bytes':peak_rss,
        'rss_scope':'Process high-water RSS including fixture construction; not isolated request working set.','peak_scope':'Process-wide traced Python allocations, not complete RSS or per-request working set.',
        'summary':summaries,'worker_caches':[c for _,c in completed],'write_receipts':writes,'rows':rows,
        'limitations':['Nearest-rank tails are descriptive; small cohorts do not establish production tail SLOs.',
            'Contradiction recall checks either structured edges or all their authorized bound evidence; structured edge coverage is reported separately.',
            'ACL scan is a separate micro-measurement; instrumentation and tracing add overhead.',
            'Independent labels, representative sampling, operational isolation and decision ownership require external review.']}
