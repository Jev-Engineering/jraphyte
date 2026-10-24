# ADR 0001 — Logical domains and physical storage placement

**Status:** Proposed. Reference implementation remains shared; production placement
is not decided or approved. Issue #10 remains open until representative inputs and
decision ownership are supplied. No physical split is implemented or justified here.

**Decision owner:** Application storage/security owners must be designated and approve
the deployment decision. Generating this record does not appoint or impersonate them.

## Requirements known before measurement

Research domains are multi-label topical metadata. They are not tenancy, residency,
ACL or transaction boundaries. Source, evidence, entity and assertion IDs stay stable;
identity, provenance, prerequisites and contradictions can cross domain labels.
Publication is one audited transaction under one graph authority. Current source
revocation applies to historical reads. No distributed performance claim follows
from a single-host SQLite reference test.

The measured local environment is an isolated synthetic sandbox with no production
data or provider calls. Actual tenant/trust/residency boundaries, representative
source/query distributions, independent labels, deployment concurrency and accepted
p50/p95/p99/availability/recovery SLOs have not been supplied. No numerical production
SLO or arbitrary graph-size threshold is invented to make this ADR appear approved.

## Available workload evidence

`tools/benchmark_domain_workload.py --synthetic --output DIR` freezes corpus identity,
case labels and protocol before running. It measures unscoped/scoped query latency,
a separate ACL scan, query mix, cross-domain closure, structured edge coverage and
bound-evidence contradiction coverage, cache churn, concurrent reviewed writes,
index rows/bytes, graph degree/skew and historical source revocation. Each reported
write is checked against the authoritative journal through a separate read session.

The shipped diagnostic uses the explicitly synthetic four-source, ten-assertion
fixture, not a representative deployment corpus or a high-degree scale benchmark.
Small-cohort percentiles and whole-process RSS/tracing are not production tail-latency
or working-set guarantees. The initial instrumented run and corrected metric version
are retained separately in execution evidence; returned evidence and returned graph
edges must not be counted as the same output. Nothing here establishes distributed
throughput, semantic accuracy or independent-label qualification.

## Options

| Option | Current disposition | Consequences and required evidence |
|---|---|---|
| Shared logical graph per trust/transaction boundary | Retain for the reference implementation | Preserves atomic publication and cross-domain explanations. Optimize measured read/audit/index costs before attributing overhead to domain count. Production SLO acceptance is still pending. |
| Dedicated database per hard trust/residency boundary | Conditional; not selected | Requires approved isolation requirements, boundary routing, external revocation propagation, cross-boundary permitted links, consistency and operational ownership. A topical label alone is not a hard boundary. |
| Workload-driven physical shards | Deferred; not justified by this diagnostic | Requires representative skew/concurrency/working-set measurements and a design for global identity/provenance, snapshot tokens, retries, coordination and fail-closed distributed transaction behavior. |
| Database per research domain by default | Rejected | Multi-label sources duplicate ownership and turn topical reclassification into storage movement, weakening one-authority consistency and complicating required cross-domain evidence. |

## Any future split

Preserve globally stable source/evidence/assertion/entity IDs and original hashes.
Routing must be based on an explicitly approved physical boundary, versioned
independently of topical assignment. Cross-partition links must preserve provenance
and explain denied or unavailable closure rather than hiding contradictions. Define
consistent multi-partition snapshot selection, current revocation/epoch propagation,
atomic publication or explicit fail-closed failure semantics, idempotency, restore,
retention and audit reconciliation before implementation.

A split requires a concrete linked implementation issue derived from the approved
measurements/design. Complete that issue before closing epic #4. No such split is
justified or claimed complete by the current synthetic diagnostic.

## Revisit and completion triggers

Revisit when owners provide actual isolation/residency requirements, a frozen
representative labeled corpus and workload, deployment-like concurrency, accepted
SLOs, or measured evidence that shared placement cannot meet them after targeted
optimization. Run the supplied generic workload API with the actual authenticated
adapter and retain protocol, raw metrics, limitations and independent review.
Then record an accepted option and owner, or a scoped remediation/split issue.
Issue #11 must separately qualify that selected backend and its operational gates.
