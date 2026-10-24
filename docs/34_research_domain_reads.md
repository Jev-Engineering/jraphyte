# Version-consistent research-domain reads

Refs #7. This extends the in-memory and SQLite reference read adapters; it does
not select or qualify a deployment-native backend under #11.

`GraphReadView.classification_identity` binds contract version, graph-wide
classification revision, exact projection hash and explicit migration state.
The read identity additionally includes the immutable graph snapshot hash,
present source statuses/epochs, available record IDs and adapter version. A
reclassification invalidates retrieval caches without changing any older graph
snapshot. In-memory snapshots supplied with a journal must match their selected
authoritative event, rather than asserting a different assignment projection.

## Derived index, not authority

The SQLite adapter obtains state, journal, immutable records and **current** source
statuses in one consistent database transaction. It audits authority before
index use. Supplying an application trust registry also authenticates the
classification history; an integrity-only audit does not claim origin proof.
Caller working catalogs can contribute proposals but cannot add assignments to
the accepted source-to-domain projection.

`trace_domain_index_meta`, `trace_domain_index_sources` and
`trace_domain_index_membership` are expendable derivative tables. They index
exact immutable snapshot hashes and source snapshots; domain and source lookup
keys never replace global entity/assertion/evidence IDs. New versions build new
index entries. On each reference read, the entries and membership rows are
compared against the authority, including self-consistent forged index hashes.
Corruption fails closed with `DOMAIN_INDEX_CORRUPT`.
`SQLiteGraphAdapter.rebuild_classification_index(query)` explicitly regenerates
the selected entry from the authority without touching state, status, source,
evidence or journal bytes. New tables are additive schema objects, not an
implicit classification migration or backfill.

The reference audit/index verification scans authority. Its logical row/byte
counts, build status and validation time are exposed in `read_metrics`. This is
a correctness-first reference index, **not** a measured production-performance
optimization. Representative workload evidence belongs to #10.

## Current authorization is always first

`AccessFilter.source` requires an exact source grant, matching tenant, present
READ permission, active status and no tombstone. `source_classification` invokes
that check before selecting domain metadata. Evidence uses the same current
source check even in historical mode. The old historical-withdrawal exception
has been removed: old snapshot facts are preserved, but withdrawn evidence is
not usable simply because a query requests history. Denied or erased content
is never restored by selecting an earlier version. Missing replay content
fails explicitly rather than being replaced by current assignments.

Sources lacking reviewed assignments remain explicitly unclassified. Explicit
unclassified and retired assignments retain their distinct status and immutable
review/provenance records. The internal read view contains authority metadata,
not a caller-facing access grant; only authorized, canonically materialized
context may leave the retrieval boundary.

## Requirements for another adapter

A deployment adapter must provide one consistent graph/classification snapshot,
current source epochs and revocation checks, ACL and domain pushdown without
changing semantics, stable global IDs, explicit unavailable-history errors,
bounded timeouts/cancellation, and journal-equivalent history. It must report
read/write visibility, backup/restore, concurrency and operational evidence.
The reference SQLite connection has its existing bounded connection timeout;
this document is not a claim of remote cancellation or native production
qualification. No deployment owner, endpoint or operating SLO has been inferred.
