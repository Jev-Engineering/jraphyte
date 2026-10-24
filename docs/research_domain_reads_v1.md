# Journal-bound domain reads, v1

Status: unmerged reference implementation candidate for issue #7. Not a remote
adapter, deployment acceptance, or distributed-performance result.

## Identity and authority

`GraphReadView.research_domains` selects assignments from the requested graph
snapshot, never the newest Catalog record. It records graph and classification
revisions, the complete committed projection hash, taxonomy IDs/hashes/versions,
assignment IDs/hashes/revisions, and explicit UNCLASSIFIED or RETIRED states.
Source, evidence, assertion and entity IDs are unchanged. Classification proposals
in a working catalog do not affect the committed selection.

SQLite reads audit the graph and replay domain transactions using application-
enrolled trust at each commit instant. Current key revocation still fails closed.
In-memory domain snapshots require the corresponding original genesis and complete
journal; alternate or downgraded snapshots for a version are rejected. Pre-domain
fixtures retain the prior contract. These are privileged adapter APIs, not user
responses: authorization must still precede materialization or embedding.

Current source permission, active status, tombstones and ACLs apply even when the
requested graph is historical. The old `active or historical` source exception is
removed. A historical assertion is not permission to read withdrawn evidence.

## Derived SQLite index

`SQLiteGraphAdapter(..., trust=application_trust).rebuild_domain_index()` explicitly
builds or repairs `trace_domain_index` and `trace_domain_index_heads`. The index is
in the existing backend database, keyed by graph version/source/domain, with a
composite version/domain/source lookup index. It is not a second write authority.
Missing classifications have an explicit unclassified row. Multiple domains have
separate rows with the same source and assignment identities.

Repair holds a write transaction, verifies authority first, and changes derived
tables only. Once installed, every graph transaction writes its new version's index
rows in the same transaction as state, source status, records and journal. Old
version rows are never updated. Faults roll back both graph and derived rows.

Reads compare selected rows and hashes with journal-derived expectations. Missing,
forged or stale indexes fail closed with `DOMAIN_INDEX_UNAVAILABLE` or
`DOMAIN_INDEX_STALE`. Repair is administrative, never silently authorized by a query.
Source erasure can make exact reconstruction unavailable; the implementation does
not fabricate missing source or assignment bytes.

## Adapter requirements and limitations

Deployment adapters must provide a single consistent selected-version snapshot,
current authoritative source status/epochs, ACL and domain pushdown before private
content reaches embeddings, stable IDs, and explicit unavailable-history errors.
They must enforce database/network deadlines and cancellation, including during
history/index verification, not merely after returning. Failures must not fall back
to unrestricted or latest-version results. Native commit/rollback visibility and
revocation propagation need backend-specific concurrent tests.

This reference implementation verifies full history and selected index rows on
reads. The composite index is implemented, but this full audit still has workload-
dependent costs. No sublinear end-to-end query, remote timeout/cancellation, horizontal
scaling, independent-label accuracy, or production SLO claim follows from these tests.
Index retention is not whole-system erasure: journal, exports, backups and catalogs
retain provenance and require deployment-owned retention policy.

## Validation

Normal imports, not an extracted-class harness: the recovered 101 contract and
publication tests plus 32 new read/index/authorization tests pass in this execution.
The new tests cover parity, exact history, reclassification, retirement, proposals,
source withdrawal, key revocation, tampering, explicit repair, query-plan index use,
and atomic rollback of the installed index at four publication fault points.
Full-repository release, wheel, legacy and deployed-backend gates remain separate.
