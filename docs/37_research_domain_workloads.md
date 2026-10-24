# Domain workload measurement protocol

Refs #10. This is instrumentation and a reproducible **synthetic reference smoke**, not representative data, an independent-label experiment, a deployment SLO result, or a sharding justification.

## Reproduce the reference run

```sh
python -m trace_gc domain-workload --output domain-workload.json --repetitions 3 --workers 2
python -m unittest discover -s tests -p 'test_research_domain_workloads.py' -v
```

The command runs eight paired in-memory query cases per worker/repetition, then a separate disposable SQLite-reference publication/read phase. Query cases cover lexical/vector contradiction retrieval, paths and communities in scoped and unscoped forms. The SQLite phase measures append-only migration, multi-label assignment/reclassification, idempotent retries, read-index validation, cache reuse/churn, current withdrawal on historical reads, and two competing connections at the same graph version. Exactly one concurrent writer must commit; the stale rejection is not counted as a graph write.

The in-memory workers are same-process threads over copies of one immutable reference snapshot. They are not deployment-like clients, distributed replicas, or independent accepted graph authorities. No private corpus, trained model, provider credential, application deployment trust root, or production database is used.

## Metrics and limitations

`WorkloadRecorder`, `QueryCase`, `run_query_workload`, `measure_query` and `measure_publication` are reusable with an application's representative inputs and existing trusted services. The recorder does **not** create ACL grants or approve a publication. The publication wrapper requires ordinary signed preflight/authorization receipts. It reserves bounded telemetry capacity before execution, so capacity exhaustion cannot happen only after a successful write.

Latency uses `perf_counter_ns`; percentiles use nearest rank and always carry sample counts. Queries include consistent authority reads, ACL checks, candidate generation, canonical revalidation and cache handling. Write latency measures the trusted publish/commit call, excluding caller plan preparation/signing. Committed, replayed and rejected publication samples remain distinguishable.

ACL calls are counted by guard; only outermost nested guard wall time is timed, preventing double accounting. Measurement contexts are isolated across threads and reset on exceptions. These are opt-in, process-local observations, not changes to scientific records, snapshot identity or permissions. Instrumentation itself has overhead; no measured production-speed claim is made.

Domain transitions count executed path/community/required-closure hops. A transition may change membership while retaining an overlapping domain; disjoint domain hops and unclassified hops are separate counters. Revalidation may repeat a transition. These are not unique graph edges, network messages, remote transactions, or cross-shard RPCs. A cross-domain write means the union of exact pre/post source assignments touched by a signed plan has multiple taxonomy/domain pairs; it is a metadata-workload observation, not proof that storage crossed a partition.

Topology reports incident active original-assertion degrees, quantiles, Gini, and top-one-percent degree share. A test compares equal-sized star and chain graphs to ensure node count alone does not erase high-degree skew. Those test graphs are not a representative performance workload. The default small corpus does not exercise a deployment's high-degree tail.

Index observations include logical row bytes, rebuild/validation time, source/membership counts, full authority-audit cost, and actual SQLite `dbstat` B-tree bytes when available. Database/WAL byte counts are not working-set measurements. Linux RSS observations are process-wide snapshots including the harness and imported modules, not an isolated query's allocation or a deployment memory requirement.

Cache hits/misses, invalidated entries and capacity evictions are distinct. A deliberately small cache exercises churn, not a recommended production cache size. Paired quality compares only the same case ID with/without scope; unlabeled path/community quality is reported as unavailable, not perfect. The lexical/vector fixture contains an explicitly authored cross-domain refutation: preserving it is a conformance check, not evidence of real scientific retrieval accuracy. Current withdrawal is tested separately with forbidden-source expectations.

## Representative-input gate

Before running a placement study, the actual owner must preregister corpus/snapshot hashes, reviewed taxonomy and assignments, independently produced evidence/contradiction labels, query/write mixture, tenant/ACL distribution, source churn, high-degree tail, cache working set, expected concurrency, hardware/backend version, isolation/residency requirements, and latency/availability/recovery SLOs. Use the same authority snapshots, current revocation rules and labeled cases for every candidate storage option. Report misses, timeouts and rejected writes; do not report only successes. Freeze the protocol and train/tune/test split before inspecting outcomes.

An input manifest may identify `REPRESENTATIVE_CANDIDATE`, but that string or an owner name cannot mint representativeness, independent labels, or an acceptance receipt. The harness deliberately reports `MEASURED_NOT_QUALIFIED` and leaves qualification to explicit external review and the deployment gates. Store operational telemetry behind administrator access controls: even aggregate graph cardinality, query categories and hashes can be sensitive. Do not publish a representative corpus or telemetry without its owner's authorization.

The execution evidence contains a 65-sample synthetic run: 55 query observations and 10 publication attempts (five committed, four replayed, one stale-version rejection). It is sufficient to verify measurement plumbing, not to select production storage or close #10. See ADR 0001 for the provisional reference choice and external decision gate.

## Integrated-candidate execution — 2026-09-27

The installed integrated wheel executed the workload with three repetitions and two workers, producing 66 samples: 56 query records and 10 publication attempts. Five writes committed, four were idempotent replays and one was rejected; three committed batches crossed domain labels. Raw records and percentiles are retained as `evidence/domain-workload-final.json` in the delivery packet, not asserted as representative data. This differs from the earlier one-repetition reference summary and is not evidence of a performance trend. The result remains `MEASURED_NOT_QUALIFIED`, with placement deferred pending representative data, owner, isolation requirements and SLOs. No new production graph or provider was used.
