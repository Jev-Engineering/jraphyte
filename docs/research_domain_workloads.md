# Domain workload measurement protocol

Refs #10. This is instrumentation and a reproducible **synthetic reference smoke**, not representative data, an independent-label experiment, a deployment SLO result, or a sharding justification.

## Reproduce the reference run

```sh
python -m trace_gc domain-workload --output domain-workload.json --repetitions 3 --workers 2
python -m unittest discover -s tests -p 'test_research_domain_workloads.py' -v
```

The command runs eight paired in-memory query cases per worker/repetition, then an authored scope denial and a separate disposable SQLite-reference publication/read phase. Query cases cover lexical/vector contradiction retrieval, paths and communities in scoped and unscoped forms. The SQLite phase measures append-only migration, multi-label assignment/reclassification, idempotent retries, read-index validation, cache reuse/churn, current withdrawal on historical reads, and two competing connections at the same graph version. Exactly one concurrent writer must commit; the stale rejection is not counted as a graph write.

The in-memory workers are same-process threads over copies of one immutable reference snapshot. They are not deployment-like clients, distributed replicas, or independent accepted graph authorities. No private corpus, trained model, provider credential, application deployment trust root, or production database is used.

## Metrics and limitations

`WorkloadRecorder`, `QueryCase`, `run_query_workload`, `measure_query` and `measure_publication` are reusable with an application's representative inputs and existing trusted services. The recorder does **not** create ACL grants or approve a publication. The publication wrapper requires ordinary signed preflight/authorization receipts. It reserves bounded telemetry capacity before execution, so capacity exhaustion cannot happen only after a successful write.

The reusable scheduler continues through recorded retrieval exceptions. Factory and measurement failures, including recorder capacity exhaustion, still fail the schedule. The standalone query measurement records retrieval exceptions and raises them to the caller.

Latency uses `perf_counter_ns`; percentiles use nearest rank and always carry sample counts. Queries include consistent authority reads, ACL checks, candidate generation, canonical revalidation and cache handling. Write latency measures the trusted publish/commit call, excluding caller plan preparation/signing. Committed, replayed and rejected publication samples remain distinguishable. Wall-clock rates cover in-memory query attempts and completions during the worker schedule, including worker setup and excluding the separate denial. The SQLite mixed-phase rate counts signed committed plans from initialization plan preparation through closure of the second writer connection. Its elapsed time includes index work, queries, retries and withdrawal. The numerator excludes the source-status transaction, replayed plans and rejected attempts.

ACL calls are counted by guard; only outermost nested guard wall time is timed, preventing double accounting. Measurement contexts are isolated across threads and reset on exceptions. These are opt-in, process-local observations, not changes to scientific records, snapshot identity or permissions. Instrumentation itself has overhead; no measured production-speed claim is made.

Domain transitions count executed path/community/required-closure hops. A transition may change membership while retaining an overlapping domain; disjoint domain hops and unclassified hops are separate counters. Revalidation may repeat a transition. These are not unique graph edges, network messages, remote transactions, or cross-shard RPCs. A cross-domain write means the union of exact pre/post source assignments touched by a signed plan has multiple taxonomy/domain pairs; it is a metadata-workload observation, not proof that storage crossed a partition.

Topology reports incident active original-assertion degrees, quantiles, Gini, and top-one-percent degree share. A test compares equal-sized star and chain graphs to ensure node count alone does not erase high-degree skew. Those test graphs are not a representative performance workload. The default small corpus does not exercise a deployment's high-degree tail.

Index observations include serialized source-row bytes, elapsed time and counts of source and membership rows. The harness measures explicit index materialization and rebuild separately through the phase-owned adapter operations. Retrieval remains read-only and distinguishes projection-only reads from verification of a persisted index. Full authority-audit time and SQLite `dbstat` B-tree bytes are also recorded when available. Database/WAL byte counts are not working-set measurements. Linux RSS observations are process-wide snapshots including the harness and imported modules, not an isolated query's allocation or a deployment memory requirement.

Cache hits/misses, invalidated entries and capacity evictions are distinct. A deliberately small cache exercises churn, not a recommended production cache size. Paired quality compares only the same case ID with/without scope; unlabeled path/community quality is reported as unavailable, not perfect. The lexical/vector fixture contains an explicitly authored cross-domain refutation: preserving it is a conformance check, not evidence of real scientific retrieval accuracy. The report tracks whether a structured conflict item carries both assertion IDs separately from whether both evidence IDs were returned. The withdrawal check pins the most recent classification that matches the biology query, even when the final classification does not. The same historical query must return the source and evidence before withdrawal and exclude the source afterward. The positive control is reported separately from the measured query count.

## Representative-input gate

Before running a placement study, the actual owner must preregister corpus/snapshot hashes, reviewed taxonomy and assignments, independently produced evidence/contradiction labels, query/write mixture, tenant/ACL distribution, source churn, high-degree tail, cache working set, expected concurrency, hardware/backend version, isolation/residency requirements, and latency/availability/recovery SLOs. Use the same authority snapshots, current revocation rules and labeled cases for every candidate storage option. Report misses, timeouts and rejected writes; do not report only successes. Freeze the protocol and train/tune/test split before inspecting outcomes.

An input manifest may identify `REPRESENTATIVE_CANDIDATE`, but that string or an owner name cannot mint representativeness, independent labels, or an acceptance receipt. The harness deliberately reports `MEASURED_NOT_QUALIFIED` and leaves qualification to explicit external review and the deployment gates. Store operational telemetry behind administrator access controls: even aggregate graph cardinality, query categories and hashes can be sensitive. Do not publish a representative corpus or telemetry without its owner's authorization.

The command stores individual per-operation measurements in the requested path. Keep detailed receipts in approved operational storage and publish only authorized aggregates. The default run is expected to record 56 query observations and 10 publication attempts, including four idempotent replays and one stale-version rejection. The fixed timestamp for authored queries pins the reference protocol. Timings and ephemeral receipt hashes can differ between runs. The September synthetic diagnostic recorded on [#10](https://github.com/Jev-Engineering/jraphyte/issues/10) used a separate protocol. See [ADR 0001](adr/0001_research_domain_storage.md) for the proposed reference choice and external decision gate.
