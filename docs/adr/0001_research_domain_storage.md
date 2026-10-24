# ADR 0001 — Shared logical domain views; deployment placement decision pending

**Status:** provisional reference-design decision; deployment placement **BLOCKED**. Refs #10 and #11; does not close either issue or epic #4.

**Decision owner:** not selected in the live initiative record. An authorized deployment/data owner must accept or replace this decision after the representative-input gate. The implementation author is not claiming that authority.

## Context

A research domain is mutable, multi-label search metadata. It is neither a tenant grant, a relation endpoint type, an ontology, nor a graph community. Identity, full graph constraints, accepted publication, immutable source/evidence provenance and historical audit remain graph-wide within one trust/transaction boundary. A source can change domains, belong to several domains, or remain unclassified. Required identity and refutation closure crosses topical labels.

The reference work provides versioned classification operations inside the existing publication transaction and rebuildable indexes over its accepted snapshots. The live initiative has not supplied a selected deployment backend/owner, representative independently labeled data, isolation requirements, or agreed workload/SLOs. The measured fixture run is explicitly synthetic, small and single-host. It is not evidence of a production capacity limit or of a distribution benefit.

## Provisional choice

**Retain one accepted graph authority per trust/transaction boundary and shared logical research-domain views in the reference implementation.** Keep the domain index disposable and derived; use stable source, evidence, entity, assertion, assignment and taxonomy identities independent of topical routing. Do not split databases by research-domain label. This choice preserves the specified semantics without presupposing a production database product or deployment readiness.

The deployment owner must later choose the physical implementation from the preregistered workload and hard isolation needs. This ADR does not convert SQLite-reference into the deployment backend.

## Alternatives and decision triggers

| Option | Current disposition | Evidence needed / consequence |
|---|---|---|
| Shared logical graph in one authority | Reference choice | Qualify the selected backend's consistent reads, ACL enforcement, journal, restore and source epochs on representative workloads. Measure full graph validation and index/audit costs, not just lookup latency. |
| Dedicated storage for a hard trust/residency boundary | Conditional; not selected | An actual legal, tenancy, administrative or residency requirement with an owner. Dedicated storage is keyed to that boundary, not topical labels. Explicitly govern any authorized cross-boundary references and evidence transfer. |
| Measured physical sharding | Deferred; no implementation issue justified | A reproducible representative bottleneck after reasonable query/index/cache work, a measured benefit, and explicit routing/consistency/transaction costs. Synthetic fixtures and arbitrary node/edge thresholds cannot satisfy this trigger. |

Revisit when the backend and owner are selected; hard isolation requirements change; measured SLO or resource-pressure failures occur on representative peak/high-degree/churn workloads; or the accepted workload materially changes. A numeric node-count threshold is intentionally absent.

## Requirements before any physical split

The separately scoped implementation issue must define stable globally resolvable IDs and unchanged immutable source/evidence hashes; authenticated provenance and cross-partition identity/refutation links; a versioned routing map and routing epoch; a consistent graph/classification snapshot identity; present source-epoch and revocation propagation before every returned result; fail-closed timeouts, cancellation and unavailable-history behavior; idempotent publication through one authority; atomic visibility of graph-wide constraints, journal and projections; and consistent backup/restore including journal, trust-enrollment and revocation state.

A participant-local success cannot be a graph-wide commit. A search index cannot become another authority. Do not weaken publication constraints to avoid cross-partition validation, silently drop contradictory evidence, reinterpret current ACLs on historical reads, or rewrite identities when moving labels. Specify the actual commit/recovery protocol and test partial failures, not just the desired behavior. Any proposed dedicated or sharded layout requires its own security and operational evidence.

## Evidence and limitations

`trace_gc.retrieval.workloads` and `docs/research_domain_workloads.md` define reproducible measurements: latency p50/p95/p99, cross-domain transitions and writes, degree skew, ACL/audit/index cost, cache churn, source withdrawal and paired retrieval quality. The recorded reference sample exercises measurement plumbing and concurrent compare-and-swap, not a representative workload. Low sample counts and fixture-authored labels prohibit production-performance or accuracy conclusions. No sharding implementation issue was created because the required justification is absent.

#10 remains open until benchmark inputs, representative results, owner/SLOs and an accepted ADR are available. #11 and #4 remain open until actual deployment acceptance passes independently of these reference tests.
