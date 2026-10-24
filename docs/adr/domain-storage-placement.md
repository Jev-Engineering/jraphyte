# ADR: Research domains are logical views; deployment placement remains gated

Status: **proposed; production decision pending owner evidence and review**.
Issue: CompleteDotTech/jraphyte#10; parent #4; deployment acceptance #11.
Decision owner: deployment owner **not supplied or appointed by this execution**.
The synthetic benchmark's protocol author is not the deployment decision owner.

## Requirements before a production choice

No reviewed residency/trust isolation requirements, representative labeled corpus,
production query/write mix, native-backend version, operating SLOs or deployment
concurrency target were supplied. Their absence is not evidence that isolation
is unnecessary. The bundled diagnostic declares disposable single-host isolation,
two concurrent connections and p95/p99 thresholds of 20/30 seconds **before** its
run. Those thresholds are diagnostic limits, not proposed production SLOs.

## Current candidate direction

Keep the existing single graph authority with logical multi-label domain views
for reference development. Do not create databases per research domain. **Defer
the actual production placement decision** until the deployment owner supplies
and reviews the missing requirements and a representative measured workload.
This is not acceptance of shared storage for an unidentified production system.

## Options and implications

| Option | Present disposition | Required evidence and implications |
|---|---|---|
| Shared logical graph within one trust/transaction boundary | Retained for reference development; production suitability undecided | Measure representative locality, cross-domain traversal, writes, working set, ACL overhead and contention against operator SLOs. Keep stable IDs, original provenance and one authoritative journal. |
| Dedicated authority/database per hard trust or residency boundary | Not selected; no reviewed boundary requirement supplied | Define exact boundary and owner, allowed cross-boundary references, current revocation propagation, retention/residency controls, snapshot identity, and the limit of transaction atomicity. A topical label is not such a boundary. |
| Workload-driven physical sharding | Not justified by the diagnostic | Require measured bottleneck and partition/routing design, stable global IDs, cross-shard provenance and identity explanation, consistent reads, revocation and failure behavior. Track and finish concrete implementation before closing #4. |

A logical evidence graph is not synonymous with a physical database. Multiple
topics may share one database; one graph may span storage partitions only after
its actual consistency and authority contracts are implemented and validated.
The reference implementation is single-host SQLite, not a distributed database.

## Reproduction and measured limitations

`python tools/benchmark_domain_synthetic.py --output synthetic-domain-workload.json`
records a sealed protocol, exact synthetic corpus hashes, query cases and labels,
per-query work, cache outcomes, nearest-rank p50/p95/p99, evidence misses,
concurrent-connection throughput, degree skew, database/index bytes, a separate
ACL probe, classification write/rebuild time and current-revocation behavior.
It also exercises online backup, native reopen and corrupt-derived-index recovery
on a disposable copy. Exact results and source fingerprints are in the execution
bundle. No raw source papers or production keys are included.

The run has four fabricated sources, eleven nodes, seven active assertions and
sixteen queries. Small-sample p95/p99 are dominated by the maximum sample. It
cannot establish tail performance, representative high-degree behavior,
steady-state concurrent writes, production working set or distributed scaling.
All required-evidence labels are synthetic; no empirical semantic quality or
independent-label qualification follows from them.

## Revisit and closure trigger

Revisit when the named deployment owner supplies a source-reviewed corpus and
labels, isolation/retention requirements, predeclared operating SLOs, workload mix,
backend/version and authorized disposable deployment target. Re-run with relevant
hubs, multi-domain identities, contradictions and revocation under read/write
concurrency. Review both quality and resource measurements, not an arbitrary
node/edge threshold. If that evidence justifies a physical split, create and link
its concrete implementation and operational conformance issue, and complete it
before epic closure. Until then #10 and #11 remain open; no sharding follow-up is
created merely to ratify an unmeasured design.
