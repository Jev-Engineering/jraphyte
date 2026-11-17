# Version-consistent research-domain reads

The in-memory and SQLite adapters expose the classification projection from the
same graph snapshot as the selected facts. The projection contains the graph-wide
assignment revision. Each source row identifies the taxonomy by ID and hash and
carries the assignment's effective revision. `classification_identity` binds the
contract version, graph-wide revision, projection hash, and migration state.
The retrieval cache keys include this identity, the snapshot hash, and current
source statuses and epochs. A new classification can invalidate a cache entry
while leaving the bytes and IDs of every older snapshot intact.

`source_classification` and `sources_in_domain` use the current statuses captured
by the view and the application's source grants. Both require a grant for the
exact source, a matching tenant, active READ permission, and no tombstone.
Historical evidence must pass those same checks. A source without a reviewed
assignment has an explicit unclassified row. Reviewed unclassified and retired
assignments retain separate statuses and their original provenance. The view's
raw records and projection are internal adapter data. Use the ACL-filtered
methods for application-facing membership and export only authorized context.

## SQLite authority and index

SQLite captures selected graph state, journal, catalog, and current source
statuses in one transaction. A classified snapshot requires the
application-enrolled trust registry passed to `SQLiteGraphAdapter` as
`audit_trust`. The adapter runs the backend's complete audit in the same
transaction and requires authenticated classification replay. Missing replay
content fails with `REPLAY_CONTENT_UNAVAILABLE`. Working catalog records can
support current proposals. The index takes its assignments exclusively from
the audited persisted catalog. The memory adapter consumes application-supplied
snapshots and statuses and checks the selected event when a journal is supplied.
Only the persisted SQLite boundary authenticates journal provenance.

The three `trace_domain_index_*` tables hold disposable metadata, source rows,
and taxonomy-qualified membership keyed by the immutable snapshot hash.
Existing entries are checked against the audited classification before use.
A missing entry is derived from authority, while inconsistent entries fail
with `DOMAIN_INDEX_CORRUPT`. `materialize_classification_index(query)` stores a
verified entry and `rebuild_classification_index(query)` replaces the selected
entry. These operations leave source, entity, assertion, and evidence IDs
unchanged. Their transaction order is phase write authority, backend lock, then
`BEGIN IMMEDIATE`. Construction and ordinary reads are read-only. Index writes
and reads both reject a caller-owned SQL transaction.

After a committed source tombstone, `erase_cached_content` discards all stored
classification index entries in the same transaction as the cached record
deletions. This includes entries for historical snapshots. Exact replay still
reports `REPLAY_CONTENT_UNAVAILABLE` after erasure.

## Adapter requirements

An adapter must expose a consistent graph and classification snapshot, apply
present-time source ACLs and epochs, and report unavailable history explicitly.
ACL and domain pushdown must preserve the same authorization and membership
semantics. IDs are global across domain selections. Adapters must document
their consistency, latency bounds, and cancellation behavior.

The local adapters accept a monotonic `deadline` and a `cancelled` callback.
They check before work and before publishing a result. SQLite also checks after
acquiring the lock and after auditing authority. These checks are cooperative.
SQLite retains the backend's connection timeout, and a single audit stage or
lock wait can delay cancellation. SQLite validates authority and index contents
on each read, so the index provides no production latency guarantee. The
implemented adapters are local and in-memory or SQLite-backed, including the
pinned bridge. Native Windows phase behavior requires separate qualification.
