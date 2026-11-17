# Reviewed classification publication

`INITIALIZE_RESEARCH_DOMAINS` and `SET_SOURCE_CLASSIFICATION` are mutation plan
operations submitted through `CompilerService.preflight` and `publish`. The
application enables publication with `classification_enabled=True` and pins
approved taxonomy hashes in `classification_taxonomy_hashes`. The authorization
issuer needs the exact operation in its capabilities and `can_review=True`.
For assignment publication, the issuer principal must match the assignment's
recorded reviewer, and the assignment review must exist before approval issuance.

Plans bind the graph version, source epoch and hash, taxonomy and assignment
hashes, and the current assignment predecessor. The graph-wide classification
revision advances once per classification transaction. The backend rechecks
credentials and application policy after acquiring its write transaction and
before consulting the idempotency key. A valid retry returns the original receipt.
Classification shares the state, source status, record and journal transaction
with the existing graph authority.

## Migration and historical snapshots

Opening an older database preserves its serialized genesis and journal. An
absent classification projection represents revision zero, with all sources
unclassified. A reviewed initialization plan appends the empty revision-one
projection. Backfill then proceeds source by source through reviewed assignment
plans. Source and evidence record bytes and hashes remain intact.

Reclassification and retirement append a successor. To restore a prior
assignment, `trace_gc.domain_publication.restore_assignment` constructs a new
successor from an earlier revision of the same assignment lineage. Submit it
with fresh review and authorization. Historical graph snapshots keep the
classification projection at their recorded graph version.

## Audit and the pinned bridge

`backend.audit(trust=...)` replays classification plans and checks snapshots,
source epochs, prospective graph state, review attribution and receipt bindings.
Supply the trust registry to authenticate the approval and validator signatures.
When source-derived records have been erased, the audit reports classification
replay as `UNAVAILABLE_ERASED_CONTENT`. Further plan publication requires
replayable classification history after initialization.

The bridge commits classification through its upstream audit-only transaction.
Its sidecar and receipt bind the upstream journal event. Run
`python tools/check_legacy.py --core <reviewed-core.py>` against the externally
supplied Git blob `68217feec539d37e4a524432c93df035f9a0fe39`. The command verifies
bytes before import and runs both the original graph lifecycle and the
classification lifecycle against the same pinned implementation. If the
reviewed source is unavailable, the gate remains pending. The fixtures use
fabricated labels and disposable Ed25519 application keys in temporary databases.
