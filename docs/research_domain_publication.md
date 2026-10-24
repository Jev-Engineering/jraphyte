# Reviewed classification publication and append-only migration

Refs #6; dependent contract: #5. This is reference implementation work, not a
production qualification or a claim that the GitHub delivery gates have passed.

## One write authority

`INITIALIZE_RESEARCH_DOMAINS` and `SET_SOURCE_CLASSIFICATION` are typed mutation
plan operations. They go through `CompilerService.preflight` and `publish`, the
existing signed reviewer/validator capabilities, full graph constraint checks,
and the backend's existing state/status/records/journal transaction. The
application must explicitly enable classification and pin reviewed taxonomy
hashes. Neither model-origin proposals nor claimed review fields confer authority.
The authenticated reviewer must match the assignment's immutable review receipt.
Even an idempotent retry must present valid, correctly bound signatures.
Request authorization, preflight validity and the application's classification
and taxonomy policy are verified again **inside the backend owner lock**
(after the phase guard and backend lock, after `BEGIN IMMEDIATE`), before the
journal idempotency shortcut returns a stored receipt. A credential that expires,
an issuer that is revoked or loses review authority, or an application that
disables classification or unpins the taxonomy while a request waits for the lock
is rejected with the database unchanged; a still-valid retry returns the original
receipt. This applies to both the reference and the pinned-legacy backend.

Plans bind the complete snapshot, graph version, current source epoch, source
hash and scope, taxonomy hash, assignment hash and predecessor. A transaction may
publish at most one successor for each source. Its graph-wide classification
revision advances once, not once per label. Publication does not edit source or
evidence records, their IDs, or any existing journal entry.

## Old databases and rollback

Opening an old database does not modify its serialized genesis or state. Before
migration, readers interpret the absent projection as revision zero and sources
as unclassified. A separately reviewed initialization plan appends revision one
with no assignments. The existing journal, source records and evidence remain
byte-identical. No automatic classification/backfill is authorized by opening a
database. Explicit reviewed successor plans provide backfill.

Reclassification and retirement append an immutable successor. A compensating
rollback is another reviewed successor with a higher revision and the desired
historical labels; `restore_assignment` constructs such a proposal but does not
approve or publish it. It does not overwrite prior assignments or decrement the
graph version. Historical graph snapshots retain their original classifications.

## Audit and pinned legacy bridge

`backend.audit(trust=...)` additionally replays classification plans, verifies
source epochs, exact prospective graph state, review attribution and signed
preflight/authorization bindings. Omitting the trusted key registry runs an
integrity/replay audit, not cryptographic origin authentication. Erased source
content is reported as unavailable for exact classification replay, never as a
successful authenticated replay.

The pinned legacy bridge uses its existing upstream audit-only operation and
pre-COMMIT integration hook. Its classification sidecar stays bound to the
upstream journal and transaction. The exact reviewed upstream source blob
`68217feec539d37e4a524432c93df035f9a0fe39` is supplied externally (never
vendored). `python tools/check_legacy.py --core <reviewed core.py>` verifies the
blob before import and then runs the original 11 checks plus the classification
lifecycle; without that file the gate is **NOT RUN**, and local SQLite or
synthetic fixtures cannot satisfy it. A native deployment adapter,
operator, trust enrollment, operational SLOs and pilot approval remain external
gates under #11.

## Validation scope

The local domain suite exercises migration and reopen, immutable old hashes,
commit/retry, invalid signatures including retries, model-origin rejection,
application pins, graph/source CAS, predecessor checks, competing connections,
faults before/after state and journal writes, append-only restore, and replay.
Application test keys are disposable Ed25519 fixtures; they are not the user's
SSH Git commit-signing identity. Hosted CI, signature, review and merge status are
tracked separately on the pull request.
