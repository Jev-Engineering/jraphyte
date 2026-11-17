# PaperPilot successor and postpublication workflow

`trace_gc.paper_pilot_lifecycle` is an application service for creating an
isolated successor from a completed PaperPilot run and reconciling a signed
source-status change. It operates on the existing `PaperPilot`,
`SQLiteReferenceBackend`, `RunBudget`, `Catalog`, trust, and retrieval APIs.
The application owns signers, source reviews, access grants, model execution,
and every release decision. This service does not run a model, sign a receipt,
grant access, or change a source without a supplied authorization.

## Parent qualification and identity

The application first reopens the parent with **the exact implementation and
runtime identity recorded in its OPEN checkpoint**, original config, trust
store, source catalog, budget, and access callback. A later package version
can change `implementation_identity()`; it cannot relabel or rewrite the old
OPEN event. Existing runs created before this service was shipped therefore
require their pinned parent runtime for reopen and a separately reviewed
compatibility handoff. A new run created with this service available can use
the service directly. Do not silently import old checkpoint events into a
successor with a modified config.

The operator supplies exact expected assertion IDs, source IDs, completed
request IDs, original imported response bytes, and original semantic execution
contexts. `parent_proof()` calls `backend.audit()`, checks the checkpoint and
budget represented by the reopened `PaperPilot`, and revalidates every
semantic/answer import against the original signed execution receipt. For a
completed local semantic call, it uses the saved original execution context;
recomputing a context after publication would refer to a later graph version.
The application must obtain an approved **signed** qualification receipt from
a separately enrolled review authority with a signer key distinct from all
parent action keys, including aliases that reuse the same Ed25519 public key.
The signed decision records an attributed reviewer; key
separation alone makes no claim about independent human review. Its typed
`PARENT_READY_FOR_POSTPUBLICATION_SCENARIOS` decision requires exactly four
PASS gates (`extraction`, `graph`, `retrieval`, `answers`), while recovery is
`NOT_RUN` or `HOLD` until successor scenarios finish. The decision pins an
externally hashed evaluator report and evaluator code, with the same explicit
evaluator version in the report and signed decision, parent run/config, checkpoint head,
graph journal head, all imported response hashes, original local execution
contexts, and archived application artifact hashes. The service verifies the
signature and authority; it does not itself decide scientific sufficiency. A
mere `response_source` string or a synthetic fixture is insufficient.

## Fork under application quiescence

The application passes a context manager that owns all parent writers,
including source/reviewer controllers, for the full fork. `prepare_successor`
rejects a destination inside or containing the parent root. It validates the
new run ID, protected scope/questions/model settings, exact document frame,
and declared changed-document IDs **before** creating anything. A revision
changes the document version/hash in the new cohort; withdrawal or permission
denial can preserve original document bytes.

Under quiescence the service uses SQLite's backup API for parent graph,
checkpoint, budget, and any application-owned journal databases supplied by
the caller. It archives exact raw model outputs, the qualification receipt,
parent config, original execution contexts, and an externally hash-pinned
artifact inventory such as signed reviews, answers, plan, ACL, and protocol.
The copied graph is the successor's only live database. The successor opens a
**new** checkpoint and `RunBudget` under its own run ID. Its limits are the
parent's original limits minus parent usage; a cumulative cap cannot be reset.
The original checkpoint, reviews, answers, graph journal, and budget remain
archived under their original identity. A partial fork remains held for
explicit reconciliation rather than being deleted or automatically retried.

The application then constructs its ordinary `Catalog`,
`SQLiteReferenceBackend`, `CompilerService`, `RunBudget`, and `PaperPilot`
with its own trust store and current access callback. It prepares and reviews
the new PDF with the existing `PaperPilot.prepare_*`, source-review, and
admission APIs. An application-authored modified PDF used for a recovery test
must be labelled as such; it is not an author-issued scholarly revision or
scientific acceptance evidence. Source withdrawal and permission changes use
the original source bytes and need no content revision.

## One signed status transaction and recovery

For a source withdrawal or denial, the application constructs the exact
`STATUS_CHANGE` payload using the current source hash, epoch, graph version,
scope, reason, and desired permission. Its authorized signer issues the
`SOURCE_STATUS` receipt. `status_change_once()` writes and fsyncs a stable
intent before calling `SQLiteReferenceBackend.change_source_status()`. The
backend verifies the caller's trust policy and commits one journal event under
the supplied idempotency key. The service writes an immutable committed
receipt projection without using the volatile `replayed` flag.

If the caller loses the result after commit, it calls `reconcile_status()`.
That method audits the graph journal and checks the exact action,
authorization hash, and fingerprint. It returns the existing receipt without
issuing another transaction. If the journal has no matching key, it returns
`UNKNOWN_NOT_COMMITTED_HOLD`; it does not retry a possibly unknown call. A
freshly reopened application must recheck source status, assertion activity,
current and historical retrieval, stale plans, cached answers, and ACL before
claiming a postpublication scenario complete.

## Evidence boundary

The package tests use authored synthetic PDFs and responses to check backup,
fresh successor identity, signed status change, normal replay, tampered
response rejection, parent-path rejection, and a graph version 2 historical
local semantic witness with a changed-context rejection. They do not establish a real
paper, scientific notation, model-output, or end-to-end acceptance result.
`tests/test_paper_pilot_postpublication.py` additionally publishes an authored
assertion, records a reviewed supported answer, then withdraws or denies its
source through `status_change_once`. From fresh connections it checks one
status transaction under replay and reconciliation, the inactive assertion,
`PILOT_STALE` for the cached answer review, an abstaining fresh retrieval with
no exported model request, and the aggregate evaluator's `INVALIDATED` rows.
That is authored mechanics evidence only.
Each real scenario still needs its own source-first review, signed stage
releases, immutable run receipts, current/historical access probes, and the
numeric gate evaluator specified by its protocol.
