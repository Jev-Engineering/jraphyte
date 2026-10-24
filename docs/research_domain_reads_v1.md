# Journal-bound domain reads and rebuildable index

Implementation candidate for issue #7. The journal remains authoritative; the
index is disposable. This is a single-host reference implementation and does not
establish deployed performance, remote storage support, or production acceptance.

## Two clocks and one authority

The selected graph version determines the assignment projection, taxonomy record,
assignment revision and immutable source identity. Current source permissions,
active state and tombstones determine whether any of that source's material may
be returned. Historical selection never restores revoked access. The caller's
application-owned ACL is applied before reading membership or source text.

`GraphReadView.classification_identity` hashes the exact selected projection;
`classification_revision` is zero for a pre-migration snapshot. The existing read
identity includes the immutable snapshot hash and current source status, so a
classification change or source revocation changes cache identity without
rewriting old snapshots. Unclassified, inaccessible and not-yet-admitted are
separate outcomes. A missing approved assignment is not a missing source.

## SQLite and in-memory adapters

Configure `SQLiteGraphAdapter(backend, classification_trust=trust)` with the same
application-enrolled trust used to audit classification publication. The adapter
reads the graph state, immutable records, full journal, current statuses and
index in one SQLite read transaction. It checks both the backend audit and signed
classification transitions before using any index row. A working catalog can
supply hypotheses; it cannot promote an uncommitted assignment to membership.

`InMemoryGraphAdapter` accepts `classification_trust`, `genesis_state` and explicit
`sandbox` mode when domain history is supplied. It verifies the full event chain,
selected projection and current statuses. A query cannot supply these authority
inputs. Legacy snapshots without classification remain readable without silently
claiming a committed domain history. The application must supply an atomically
captured catalog/events/status snapshot; this adapter is not a remote store.

These adapters expose privileged internal read views, not unrestricted end-user
exports. `source_membership(view, source_id, acl)` performs current ACL/status
checks before exposing exact topical metadata. Query-service access checks remain
required for edges, nodes, schema names, decisions, evidence and model inputs.

## Derived index and operational recovery

`adapter.rebuild_domain_index()` is an explicit administrative operation. It
replays committed assignments, then atomically replaces rows and their head/hash
anchor inside the existing database. It creates no graph event and no second
graph-state table. No source/evidence ID, genesis or old journal row changes.

Rows bind source ID, effective graph version, assignment ID/hash/revision, taxonomy
ID/hash and label. An empty internal label represents an explicitly unclassified
or retired assignment, never a wildcard. Indexed SQL selects the latest applicable
assignment per source at the requested graph version. All labels of a multi-label
assignment remain present.

A missing, stale, deleted, forged or independently rehashed index fails closed
with `DOMAIN_INDEX_STALE`. A source-status write or any newer graph event also
invalidates the head anchor. Rebuild explicitly after such an event, then retry
the read. Rebuild failures roll back. Queries do not repair or mutate storage.
Concurrent rebuild/read/writes follow SQLite transactions and the owning backend
lock. Existing caller transactions are never implicitly committed by schema DDL.

Full replay and row comparison are intentionally conservative and cost O(history
plus index size) before the selected-version SQL read. This is not a scalability
claim. A future optimized adapter must preserve equivalent authenticated
checkpoints, revocation semantics and tamper detection rather than dropping audit.

## Adapter conformance required beyond the reference implementation

A deployment-native adapter must bind graph version, classification revision/hash,
source epochs and current ACL/status to a consistent snapshot. It must push down
ACLs and domain candidate predicates before embedding or semantic expansion while
preserving authorized evidence and contradiction closure. The current reference
membership checks are application-side; no remote/federated pushdown is claimed.

Unavailable history fails explicitly; it must not fall back to current membership.
Timeout, cancellation and resource exhaustion must return a typed failure or
explicit partial result, never silently omit required contradictions. Native I/O
must enforce deadlines at the driver/service boundary. The reference SQLite
connection timeout and retrieval budget are not equivalent to native cancellation
or a production latency SLO. These operational checks require the actual selected
backend and remain part of issue #11 acceptance.

Taxonomy IDs never grant access, allocate databases or merge identities. Shared
entities and assertions retain stable IDs; assertion membership is derived from
supporting source evidence, not the entity name or a query-supplied tag.
