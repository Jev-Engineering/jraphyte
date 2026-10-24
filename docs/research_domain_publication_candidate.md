# Reference classification publication candidate — issue #6

**Status: partial, unmerged, not deployment qualified.** This change depends on
the unmerged issue #5 contract candidate. It does not resolve #6 by itself.
The main commit used for source verification is
`d5ca636a48e963619f4c89e2958d0bb1a3e72f80`.

## Authority and migration

`ClassificationPublisher` is an application-owned, disabled-by-default service
for `SQLiteReferenceBackend`. It uses that backend's existing atomic transaction,
records, state, source-status and graph-journal tables. It does not create another
graph authority, a database per domain, or a native deployment adapter.

A `classification-plan` is immutable and content addressed. Publication binds
the exact reviewed assignment, source and taxonomy hashes, source epoch, complete
base-state hash, graph version and idempotency key. A model suggestion or catalog
import cannot select the current assignment. The initial migration adds an empty
`research_domains` projection in a new journal event. Missing assignments mean
unclassified; migration does not infer or backfill topical labels automatically.
Reclassification and retirement append new reviewed assignments and new events.
Genesis, old journal rows and source/evidence record bodies are not rewritten.

The application must enroll separate capabilities before enabling publication:
`CLASSIFY_SOURCE` for reviewed assignments, `VALIDATE_CLASSIFICATION` for signed
preflight, `PUBLISH_CLASSIFICATION` for publication, and
`MIGRATE_CLASSIFICATION_STATE` for the privileged whole-graph migration. Migration
permission must not be handed to ordinary source reviewers or query callers.
Receipt purposes distinguish review, preflight and publication. Scope, execution
mode, capability, signature, risk limit and expiry are checked explicitly.
Synthetic input requires the existing sandbox backend. Private keys are injected;
only test fixtures generate ephemeral keys, and they never auto-enroll a model key.

Every commit rechecks the exact plan, current source status/epoch, committed
predecessor, graph state and semantic journal history under the transaction lock.
With the default clock, publication re-reads the time after waiting for that lock.
The underlying transaction's recorded time is also sampled after acquisition.
An explicit `at` is for trusted recorded/test execution, not user/model input.

An idempotent retry is authenticated before lookup. It returns only the immutable
transaction receipt, never historical graph assertions or source-status bodies.
A retry does not republish a withdrawn source or grant access to its old content.

## Snapshots and audit

Old snapshot bodies remain valid and unchanged. New administrative snapshots have
an optional, versioned projection with exact assignment IDs/hashes and a monotonic
projection revision. Snapshot construction hydrates the selected assignments'
immutable dependency closure from persisted records, not caller-supplied aliases.

`ClassificationPublisher.audit()` checks the existing backend's structural audit,
then semantically replays classification operations using the original base-state
hashes and signed receipts at their commit instants. It rejects projection changes
through unrelated transaction types. The caller must supply its enrolled trust
store; ledger consistency alone is not origin authentication. Erased dependency
content makes exact semantic audit unavailable rather than fabricated.

These are privileged catalog/audit APIs, NOT downstream retrieval responses.
They do not replace `GraphReadView` ACL checks or authorize historical content.
Issue #7 still needs the indexed read projection and current-status historical
reads, and #8 still needs domain filtering across every retrieval channel.

## Validation and package integration

The generator updates both schema trees, adds a typed classification plan and
receipt purposes, and preserves optional backward-compatible snapshot fields.
Catalog, ledger causal references and bundle validation hooks recognize the new
plan and projection. The installed-wheel smoke imports the actual installed
backend and runs a synthetic migration/publication/snapshot/audit scenario outside
the checkout. CI is extended to build a real project wheel and invoke that smoke.
These CI and installed-wheel changes have NOT been executed on a complete wheel
in this execution environment.

New tests cover migration, publication, reclassification, retirement, unclassified
assignments, unchanged prior hashes, all four transaction fault points, idempotency,
independent and concurrent connections, stale versions/epochs, source withdrawal,
tombstones, erasure, forged/expired/revoked capabilities, fresh clock checks,
semantic-history tampering and snapshot/causal bindings.

The recorded local publication run executed the selected, complete backend class
AST from verified source, not a normal import of the full backend module. The
surrounding plan/compiler/qualification modules were not assembled. Do not label
that extracted-class run as full-module, complete-repository, installed-wheel,
pinned-legacy or deployment acceptance. The standard tests import the full actual
backend when run in a complete repository; they do not use that extraction helper.

## Remaining work before issue #6 can close

Full-repository integration and the normal release suite remain required. Review
integration with the generic mutation-plan lifecycle, replay entry points and
pinned legacy bridge; this reference service does not implement the legacy bridge.
Run the actual sdist/wheel and installed-wheel checks, and obtain maintainer review.
The exact reviewed legacy core, blob
`68217feec539d37e4a524432c93df035f9a0fe39`, was not available here.

Semantic audit currently scans complete retained journal/catalog history. This is
a conservative reference implementation, not the indexed read path or a measured
production SLO. Current issuer revocation can make historical signature audit fail
closed; key-history and recovery policy need deployment review. Retention erasure
can block subsequent complete-history checks. There is no repair-by-rehash path.

Signed commits, PR, required checks/review, allowed-method merge and hosted
post-merge verification are still outstanding. Do not close #5, #6 or epic #4
because these local reference tests pass. Issues #7–#11 are not implemented by
this patch, and no measured physical-storage ADR has been accepted.
