# Durable paper pilot service

`trace_gc.paper_pilot.PaperPilot` supports a bounded native-page workflow for
[issue #23](https://github.com/Jev-Engineering/jraphyte/issues/23). It is an
application service, with no provider client, credential loader, automatic
reviewer, or production graph connection. **This implementation does not close
#23. No real-paper numerical or answer-quality result is claimed.** The tests
use authored synthetic PDFs and responses, explicitly marked `SYNTHETIC`.

## Supported path and durable pauses

| Service method | Completed work | Durable state |
|---|---|---|
| `prepare_native_page` | Original PDF hash, physical page, render and exact native span | `WAIT_SOURCE_REVIEW` |
| `accept_source_review` | Enrolled reviewer attests all source checks; creates native source/evidence | `WAIT_SOURCE_ADMISSION` |
| `admit_sources` | Existing trusted source-admission transaction | `TRANSACTION_RECORDED` |
| `compile_candidates` | Explicit application proposals → candidate → question → compiled pack | `WAIT_SEMANTIC_RESPONSE` |
| `record_semantic_response` | Authenticated actual execution receipt → existing response parser | `WAIT_OBSERVATION_ATTESTATION` |
| `resolve_plan` | Attestations → solve → project resolutions → evaluate policy → plan | `WAIT_PLAN_REVIEW`, or `HELD_NO_SELECTED_OPERATION` |
| `preflight_plan` | Existing compiler checks, with review required | `WAIT_AUTHORIZATION` |
| `publish_plan` | Existing signed authorization/preflight → compiler publication | `TRANSACTION_RECORDED` |
| `retrieve` | Current application ACL → existing graph retrieval | `CONTEXT_ONLY` |
| `prepare_answer` | Exact pinned-model prompt, without calling a model | `WAIT_ANSWER_RESPONSE`, or no-evidence abstention |
| `record_answer_response` | Actual external bytes and authenticated execution receipt | `WAIT_ANSWER_REVIEW`, or model abstention |
| `review_answer` | Authenticated source-first per-claim judgments and current evidence checks | `SUPPORTED` or `REJECTED_UNSUPPORTED_CLAIM` |

These states describe individual requests, not a claim that the entire cohort or
issue passed. `status()` is historical progress plus the current backend audit;
it does not authorize reusing an old answer. Use the review/answer methods again
to recheck current permissions. A recorded graph receipt is explicitly marked
`historical_receipt_only=True` and cannot authorize a new transaction.

## Application prerequisites

The embedding application must supply all of the following before a real run:

- A frozen authorized cohort manifest, exact original PDF SHA-256 values,
  permitted physical pages, fixed questions, and source-first review protocol.
  The real cohort must satisfy the issue's qualification and retrieval gates.
  Later pages are supported independently of the first-page abstract benchmark.
- A private run directory with access controls appropriate for source text,
  model exchanges and review receipts. `checkpoint.sqlite3` contains PDF/image
  bytes and text; keep the directory, SQLite WAL files and backups private.
- A `Catalog` with an explicit schema, `REVIEWED` policy, immutable claims, and
  graph endpoint nodes. Proposal authorship is the application's responsibility;
  the pilot does not invent claims or infer accepted graph edges from prose.
- A `SQLiteReferenceBackend` at `run_dir / "graph.sqlite3"`, a persistent
  `RunBudget` at `run_dir / "budget.sqlite3"`, an enrolled `TrustStore`, and a
  `CompilerService` bound to that same backend and trust store. Non-synthetic
  real runs should use `sandbox=False`. This remains an isolated reference
  backend, not production deployment qualification.
- Application-owned source-admission, source-review, model-import, semantic
  observation-attestation, publication-authorization, and answer-review
  identities. Private signing keys stay outside the checkpoint and repository.
  The service does not enroll issuers or manufacture signatures.
- A callable returning the **current authenticated** `graph-access` policy.
  Missing source/node/edge grants deny access. This callback must not derive
  permissions from a query or model response. It is invoked again on resume.
- Pinned semantic and answer provider/model/revision/tokenizer identities and
  an application tokenizer callable for a `LIVE` semantic pack. The current
  semantic compiler accepts the existing `jev-x.y.z` TypeSafe contract only.
  A local free-text answer model is not a substitute for its semantic response
  probabilities. A compatible genuine semantic execution is a missing input
  until the application can supply one; do not fabricate or relabel one.

`PyMuPDF`, `Pillow`, `jsonschema` and `cryptography` must be installed in the
application environment. Python/package versions, all runtime Python files and
embedded schemas are frozen in the checkpoint. A code/runtime/config change
requires a new run or a separately reviewed migration; this service does not
silently migrate an active run.

## Application trust receipts

The service uses the existing receipt signature envelope. Its custom execution
receipts remain **private checkpoint records**, because the Catalog's
`OBSERVATION` receipt has a distinct `observation_hash` contract used by the
ledger and compiler. The existing `attest_observation` receipt is still required
for every imported observation, including in an isolated synthetic test.

| Receipt | Purpose | Required issuer operation |
|---|---|---|
| `source_review_payload(...)` | `SOURCE_STATUS` | `PAPER_SOURCE_REVIEW`, `can_review=True` |
| `admission_payload(...)` | `SOURCE_STATUS` | Existing `SOURCE_ADMIT` |
| `execution_payload(..., kind="SEMANTIC")` | `OBSERVATION` | `SEMANTIC_IMPORT` |
| Existing `attest_observation(...)` | `OBSERVATION` | Existing observation-attestation trust contract |
| Existing `authorize_plan(...)` | `AUTHORIZATION` | Existing operation/risk/reviewer policy |
| `execution_payload(..., kind="ANSWER")` | `OBSERVATION` | `ANSWER_IMPORT` |
| `answer_review_payload(...)` | `SOURCE_STATUS` | `PAPER_ANSWER_REVIEW`, `can_review=True` |

Every custom payload binds version, run, scope and execution mode. Source review
binds the exact page packet, reviewer identity/kind/time and all four checks
(`source_identity`, `reading_order`, `boundaries`, `notation`). The reviewer must
match the enrolled principal. Answer review binds the durable draft hash and one
actual support judgment per claim. Assistant reviews are explicitly attributed;
they are never described as independent human reviews.

An execution payload binds exact compiled-pack hash (semantic only), request
SHA-256, response SHA-256, provider/model/revision/tokenizer, generation time,
provider request identity, actual input/output tokens, USD cost (including an
explicit zero for a local model), and response source. `LIVE` requires
`ACTUAL_MODEL_EXECUTION`; tests require `AUTHORED_SYNTHETIC`. The trusted importer
is responsible for attesting an authentic execution, not signing arbitrary
caller claims. A signature proves attribution and byte binding, not factual
correctness or model quality. Receipt checks honor current issuer revocation.

## Supported embedding sequence

The following is a service integration template, not a credential bootstrap or
an executable synthetic answer oracle. Names prefixed `app_` are application
inputs/actions with the responsibilities above. Keep their actual receipts and
source-first judgments in the private run. No default reviewer or allow-all ACL
is supplied by the pilot.

```python
from trace_gc.paper_pilot import PaperPilot
from trace_gc.trust import attest_observation, authorize_plan

config = {
    "run_id": app_run_id,
    "security_scope": app_scope,
    "execution_mode": "LIVE",
    "documents": app_frozen_documents,  # source_id, version, document_sha256, physical_pages
    "questions": app_frozen_questions,
    "cohort_manifest_sha256": app_manifest_sha256,
    "semantic_model": app_semantic_identity,  # provider, model_id, model_revision, tokenizer_id
    "answer_model": app_answer_identity,      # same four explicit identity fields
}
pilot = PaperPilot(
    app_private_run_dir, config=config, catalog=app_catalog,
    backend=app_sqlite_backend, service=app_compiler_service,
    budget=app_persistent_budget, current_access=app_current_access,
    token_counter=app_pinned_semantic_token_counter,
)

prepared = pilot.prepare_native_page(
    "page-prepare-001", pdf_bytes=app_original_pdf_bytes,
    source_id=app_document_id, version=app_document_version,
    physical_page=app_physical_page, start=app_native_start, end=app_native_end,
)
material = pilot.source_review_material("page-prepare-001")
# STOP: authorized reviewer inspects original PDF/page/native text and exact span.
review_payload = pilot.source_review_payload("page-prepare-001", **app_actual_source_judgment)
review_receipt = app_source_reviewer.issue(
    "SOURCE_STATUS", review_payload, issued_at=review_payload["reviewed_at"])
reviewed = pilot.accept_source_review("page-review-001", prepared_id="page-prepare-001", receipt=review_receipt)

expected_version = app_sqlite_backend.state()["graph_version"]
admission = pilot.admission_payload(["page-review-001"], expected_version=expected_version)
# STOP: source authority reviews this exact admission action.
admission_receipt = app_source_authority.issue("SOURCE_STATUS", admission)
pilot.admit_sources("admit-001", review_ids=["page-review-001"],
                    expected_version=expected_version, authorization=admission_receipt)
# The application grants authorized source/node access through its own ACL.

compiled = pilot.compile_candidates("compile-001", candidates=app_reviewable_candidates)
# Each candidate has assertion, claim_id, evidence_ids. No accepted facts yet.
# STOP: application executes the exported exact request once using its pinned
# compatible model. Persist/reconcile its provider request ID outside the pilot.
# `app_actual_semantic_exchange` contains original response bytes, generated_at,
# usage, cost, response_source and provider_request_id from that execution.
response_bytes = app_actual_semantic_exchange["response_bytes"]
execution_payload = pilot.execution_payload(
    "compile-001", kind="SEMANTIC", **app_actual_semantic_execution_metadata)
execution_receipt = app_semantic_importer.issue("OBSERVATION", execution_payload)
observed = pilot.record_semantic_response("semantic-001", compile_id="compile-001",
    response=response_bytes, execution_receipt=execution_receipt)
# STOP: the trusted importer validates and attests the resulting observations.
attestations = {ref: attest_observation(app_observation_attestor,
                    app_catalog.record(ref, "observation"))
                for ref in observed["observation_ids"]}
resolved = pilot.resolve_plan("resolve-001", response_id="semantic-001", attestations=attestations)
# If HELD_NO_SELECTED_OPERATION: stop here; no plan can be published.
preflight = pilot.preflight_plan("preflight-001", resolve_id="resolve-001")
# STOP: actual authorized reviewer reviews the complete plan and source support.
# REVIEWED policy may retain ABSTAIN; preflight does not grant review authority.
plan_id = resolved["plan_id"]
authorization = authorize_plan(app_plan_reviewer, app_catalog.get(plan_id, "plan"),
    app_catalog.hash(plan_id), reviewed_by=app_plan_reviewer_principal)
pilot.publish_plan("publish-001", preflight_id="preflight-001", authorization=authorization)

# Application supplies an existing retrieval.contracts.query request with a
# frozen question as text and requesting_component beginning 'downstream'.
context = pilot.retrieve("retrieve-001", request=app_current_graph_query)
answer_request = pilot.prepare_answer("answer-prepare-001", retrieval_id="retrieve-001",
                                     question_text=app_current_graph_query["text"])
# No authorized evidence yields an abstention and no model slot/request.
# Otherwise STOP: execute exact exported prompt once via approved pinned model.
answer_execution = pilot.execution_payload("answer-prepare-001", kind="ANSWER",
                                           **app_actual_answer_execution_metadata)
draft = pilot.record_answer_response("answer-001", prepared_id="answer-prepare-001",
    response=app_actual_answer_bytes,
    execution_receipt=app_answer_importer.issue("OBSERVATION", answer_execution))
# STOP if WAIT_ANSWER_REVIEW: read original cited evidence, judge each claim.
answer_review = pilot.answer_review_payload("answer-001", **app_actual_answer_judgment)
final = pilot.review_answer("answer-review-001", response_id="answer-001",
    receipt=app_answer_reviewer.issue("SOURCE_STATUS", answer_review,
                                      issued_at=answer_review["reviewed_at"]))
pilot.close()
```

Execution metadata passed to `execution_payload` must contain
`response_sha256`, `generated_at`, `usage={input_tokens, output_tokens}`,
`cost={amount, currency:"USD"}`, `response_source`, and `provider_request_id`.
The hashes refer to original bytes, not a JSON reserialization. The semantic
pack export is `request_base64`; the answer export uses the same field. The
answer response format remains exactly `{abstain: bool, claims: [{text,
evidence_ids}]}` from `paper_answer.py`. A malformed semantic response is stored
as error observations; it is never repaired into a successful response.

## Resume, reconciliation and budgets

Close/reopen the same backend and budget, reconstruct the same application trust
store, callbacks and frozen config, then create `PaperPilot` on the same directory.
The checkpoint restores immutable Catalog records and every completed request.
Call a method with the **same request ID and exact original arguments** to resume;
changing them raises `PILOT_IDEMPOTENCY_CONFLICT`. Keep signed original arguments
in the application journal, not newly generated replacement receipts.

Before a graph mutation, the service durably records intent. If the controller
dies after the backend commits but before checkpoint completion, resume matches
the authoritative backend journal receipt, action/plan and authorization hashes,
and preflight hash where applicable. The graph version does not increment again.
Receipt recovery remains historical even if a source was later withdrawn.
New semantic, publication and answer work revalidates source review, original
PDF/page bytes, graph/source status, issuer trust and current application access.
Permission or graph changes cause a hold; create a freshly reviewed request.

An OS file lock admits one controller for the run directory and releases on
process termination. The embedding application must still use one controller
thread and serialize its own capability changes. No process is killed to steal
a lock. The sidecar's hash chain detects accidental edits; it is not a security
boundary against a principal who can rewrite the private directory. Trust keys,
current ACL and backend authorization remain outside that sidecar's authority.

The persistent budget reserves one `model_calls` slot and exact `request_bytes`
before exporting each request. Here `model_calls` means authorized execution
slots, not a count of provider calls made by this service (always zero). Reopening
a completed export consumes no second slot. A crash before export checkpoint may
conservatively consume an additional slot; the service never refunds an uncertain
attempt. Accepted source reviews, plan publication review and answer review all
consume `review_actions`; cached resumes do not charge again. Solver/retrieval
limits use the existing shared budget. Actual
usage/cost come from the signed execution receipts. The application must enforce
its provider spending limit and delivery idempotency before executing a request.

There is no automatic provider retry. A pending exported request after a crash
has an unknown external outcome until the application reconciles its execution
journal/provider request ID. A second imported outcome for the same export is
rejected; a new request requires explicit new intent and budget. The service
never calls an external model while reopening or polling status.

## Verification and remaining issue gates

```powershell
python -m unittest discover -s tests -p 'test_paper_pilot.py' -v
```

The authored tests exercise original second-page lineage, strict review/model
receipt binding, current permission/withdrawal/revocation holds, durable budget,
all workflow pauses, one-outcome import, unknown citations, immutable request
IDs, checkpoint/blob tampering, and admission/publication recovery after commit.
They demonstrate mechanics only. The service has not run a real cohort, supplied
a real semantic observation, measured answer quality, or qualified production.

Missing for #23 completion: approved final cohort and source-first judgments;
genuine compatible semantic execution and exact receipts; actual reviewed
publication of its resolved plans; current approved answer-model exchanges;
supported/unsupported/conflict query outcomes; real fresh-process replay and
permission-change evidence; resource/cost results; applicable #20 and #22 gates.
Image transcription routing is not implemented by this native-page service.
An image-enabled final pilot needs a separately integrated reviewed image route;
do not convert image transcription into fictitious native PDF offsets.
