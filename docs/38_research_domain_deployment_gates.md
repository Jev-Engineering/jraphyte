# Deployment-native research-domain adapter: blocked acceptance protocol

Refs #11; native dependency #10 and epic #4 remain open. **No deployment-native adapter is implemented or qualified by this change.** The actual backend and owner must be selected first. SQLite-reference and in-memory adapters are reference implementations, not substitutes for that choice.

## Current reference boundary

Issue #11 requires a selected backend and deployment owner, authorized infrastructure, representative independently labeled data, workload and isolation requirements, SLOs, enrolled trust inputs, and pilot authority. The reference implementation does not supply these inputs. Exact legacy conformance requires the reviewed source with Git blob `68217feec539d37e4a524432c93df035f9a0fe39`; it remains NOT RUN. Application signatures in temporary conformance databases do not establish deployment trust enrollment.

## Required selection inputs

Record the named backend/product/version, deployment and data owners, authorized endpoint/connection, topology and tenant/residency boundaries, source authority and epoch rules, trust-enrollment/revocation configuration, representative data and independent label hashes, accepted workload/SLO ADR, maintenance windows, retention and backup/recovery objectives, observability owner, and explicit pilot authorization. Credentials must arrive through approved secret handling, never a committed template or generated report.

## Qualification matrix after selection

| Gate | Required operational evidence | Current state |
|---|---|---|
| Consistent reads | One graph version, taxonomy/assignment revision and source-status cut across every query channel; unavailable history fails closed | NOT RUN |
| ACL pushdown | Backend-side row/edge/source denial before domain selection, embedding, expansion or summary; compare denied populations and revocation races | NOT RUN |
| Source epochs | Current revocation on historical reads, epoch propagation lag, stale-replica denial and cache invalidation under load | NOT RUN |
| Single authority / atomic visibility | Signed plan, CAS, idempotency, full graph validation, record/status/journal commit or rollback visible together across concurrent clients | NOT RUN |
| Bounded I/O | Real driver/server deadlines, cancellation, connection loss, resource limits and retry behavior; no implicit unbounded fetch | NOT RUN |
| Journal-equivalent history | Immutable original records, authenticated provenance, reproducible snapshots, append-only migration/compensation and explicit retention loss | NOT RUN |
| Backup and restore | Consistent graph/journal/index/trust/source-status backup, isolated restore and hash/epoch comparison, tested recovery objectives | NOT RUN |
| Concurrency and failure recovery | Representative simultaneous reads/writes, CAS contention, deadlocks, failover/partial failure and no split authority | NOT RUN |
| Shadow comparison | Matched authorized reference and native results, including multi-domain/unclassified sources, identity and cross-domain refutations | NOT RUN |
| SLO / operational acceptance | Owner-approved workload, latency/error/availability/resource budgets, alerts, on-call and remediation issues for unmet objectives | NOT RUN |
| External semantic/pilot gates | Independent labels, current provider/tokenizer acceptance where used, enrolled authorities and approved pilot | NOT RUN |

A selected sharded/dedicated layout additionally needs the stable-ID, routing, provenance, revocation, consistency and transaction design specified in ADR 0001, plus a separately scoped implementation issue before qualification. No such sharding issue is justified by the available synthetic measurements.

The reference unit/conformance results are useful preconditions, not evidence that any row above passed. Do not remove native blockers, check these boxes, close #11/#4, or use `PASS_WITH_EXTERNAL_GATES` as a production-ready claim.
