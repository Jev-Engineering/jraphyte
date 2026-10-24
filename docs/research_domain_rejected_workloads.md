# Rejection-aware research-domain workload measurements

Refs #8, #9 and #10. The recorder protocol is
`research-domain-workloads-v1.1`.
This is instrumentation and synthetic reference validation, not representative
performance evidence, an approved storage decision, or deployment qualification.

## Why costs changed

The earlier recorder retained only latency and an error code for a rejected
query, and did not retain operational exceptions at all. Report aggregation
therefore omitted rejected-query ACL work, cache churn and already-authorized
traversals. A failed read could also inherit the preceding request's adapter
metrics. This produced success-only cost statistics, not whole-workload costs.

Per-attempt adapter diagnostics are now cleared before query validation.
Successful and rejected/error attempts both retain measured ACL calls/time,
cache deltas, and executed authorized transitions. The original exception is
re-raised. Only its class and contract code are recorded, never its message,
stack, query text, source text, credentials or provider response.

Completion is explicit rather than inferred from an error-code string. Failed
attempts have no returned graph/classification identity and `quality: null`;
they are not treated as empty successes or perfect zero-error quality results.
Reports give completed versus rejected/error counts and telemetry coverage.
Imported legacy rows without measurements remain unmeasured, not zero-cost.
Noncanonical rejected requests cannot supply a trustworthy request hash; their
hash is explicitly unavailable and invalid content is not copied into receipts.
Hashing telemetry must not replace the original retrieval exception.

## Reproducible negative case

The reference driver includes one explicitly declared unauthorized-tenant case,
whose expected rejection is bound in the input manifest alongside the complete
query protocol hash. It must reject with `SECURITY_SCOPE`; another outcome fails
the harness. Its measured cost counts, but it has no quality score or returned
source evidence. It does not grant access or modify the graph authority.

```sh
python -m unittest discover -s tests -p test_research_domain_rejected_workloads.py -v
python -m trace_gc domain-workload --output reference-v1.1.json --repetitions 3 --workers 2
```

The eleven regression methods cover ACL time, cache churn, transitions before a
later rejection, unexpected errors, telemetry redaction, misleading error-code
names, missing measurements, mixed outcomes, stale adapter diagnostics and
noncanonical requests. The existing workload integration test now also checks
the negative case and its contribution to observed costs.

The harness uses fabricated labels, in-memory readers and disposable SQLite
reference transactions. Threads, percentile observations and a high-degree
fixture do not establish deployment concurrency, representative quality, SLO
compliance or a need to shard. ADR 0001 remains provisional until an authorized
owner supplies representative inputs, isolation requirements and SLOs. No shard
implementation issue is justified by these measurements alone.
