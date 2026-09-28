# Local Qwen semantic pilot profile

Status: implementation and authored offline tests. **No real semantic inference
or real-paper pilot is claimed by this change. Issue #23 remains open.** Review
the protocol below before the first real call. This profile supports independent
CHOICE questions in `fixed-questions-v1`; SCORE, NOUL, question dependencies and
retrieval relevance programs are held.

## Model and observation identity

The supported model is `Qwen/Qwen3-4B-Instruct-2507`, loaded from a complete local
snapshot with `local_files_only=True`, `trust_remote_code=False` and bfloat16.
The prepared local snapshot has revision
`cdbee75f17c01a7cc42f958dc650907174af0554` and these byte identities:

| Artifact | SHA256 |
|---|---|
| Snapshot manifest | `1a9ad5bed19d89752f5b0cb712e93da215af49439a28a505bde56a381e895150` |
| Canonical files map | `80f3cba8395947bf39a1b714151d9dfa49bab2339ba52610e52196cff36f74fc` |
| tokenizer.json | `aeb13307a71acd8fe81861d94ad54ab689df773318809eed3cbe794b4492dae4` |
| tokenizer_config.json | `a62ff0a2472a0fa1b8eaabcb57c59b58afa42a22831dc141400b6e0cf2b65ce3` |

The loader verifies the exact file set, manifest bytes, every file and indexed
weight shard before and after loading. The semantic adapter verifies these
identities and the current runtime/code before and after each call. It never
downloads missing files. Credentials and a production graph client are absent.

`local-semantic-profile` freezes provider/model/revision, model/tokenizer hashes,
system prompt/version, generation limits/device/thread count, Python/Torch/
Transformers versions, and every installed `trace_gc` Python/schema file. Its
canonical digest is part of the composite model identity:

```text
local-transformers:Qwen/Qwen3-4B-Instruct-2507@REVISION#profile:PROFILE_SHA256
```

That identity and the full profile participate in pack, wire, semantic, cache and
observation hashes. Existing qualification scopes inherit the composite identity;
a different profile cannot reuse another model's qualification. Legacy `jev-*`
requests retain their existing wire bytes. A local profile cannot use the
TypeSafe HTTP adapter. Qwen is never labeled `jev-*`.

The model returns **only** an `answers` object. Exact question/criterion coverage,
types, finite probabilities summing to one, explicit confidence, and a selected
maximum are checked. There is no HTTP rounding exemption, renormalization,
confidence default, JSON repair, retry or invented answer. Invalid or truncated
output remains an ERROR observation with the original response bytes preserved.
Its probabilities/confidence/outcome are null. Valid output is explicitly
`MODEL_GENERATED_UNCALIBRATED`. A high reported value is not calibrated accuracy.

Each local execution contains exact request/prompt/response hashes, rendered
prompt bytes, input/output token IDs and counts, timestamps, finish reason,
current application preflight digest, actual/authored origin and zero paid API
cost. `publication_authorized` is always false. The tokenizer's rendered chat
template must equal the versioned prompt bytes; reserved chat-control tokens in
source text cause a hold. The full prompt token count is enforced at execution.

Portable receipts establish consistency, not proof that a model ran. An
application-enrolled signer must attest an actual observed execution and its
exact `local_execution_sha256`. Authored fixture receipts are allowed only in
SYNTHETIC mode. The separate observation attestation is still required. No key,
issuer enrollment, semantic review or source review is supplied by this module.

## Protocol for the first real call (review before execution)

1. Use only an already exposed, authorized real paper, chosen and source-reviewed
   before seeing a model response. Record document/version/page/raw PDF/image/
   Unicode source/evidence hashes, the exact proposed claim and its qualifiers,
   and the actual internally attributed source-first review. Do not use the #20
   unseen frame. Preserve ambiguous or unsupported claims as holds.
2. Freeze a fresh private pilot directory, Git commit and code/schema digest,
   installed runtime, profile and prompt hashes, exact local model manifest,
   source/claim/candidate IDs, ACL, trust roles, budget and input packet. Record
   reviewer identities and review order. Internal assistant review is permitted;
   external independent human review is not claimed.
3. Initial resource budget: CPU, at most four Torch threads, one pack containing
   one SUPPORT CHOICE question, at most 8192 input and 512 generated tokens, one
   attempt, zero automatic retries, zero paid calls and no graph publication.
   Coordinate CPU/RAM with other runs; changing device/limits creates a new
   profile before execution. Do not disturb WSL or other model processes.
4. Use `PaperPilot` with the exact semantic profile and `adapter.token_counter`.
   Complete actual source review and explicit source admission into the isolated
   SQLite reference graph. `compile_candidates` records the durable intent and
   reserves its model-call/request-byte budget before exporting the pack. It
   returns `WAIT_SEMANTIC_RESPONSE`; it does not execute the model.
5. Record controller intent before invoking `generate_pack`. Pass explicit
   authorization and the current `PaperPilot.semantic_execution_context`
   callback. The adapter validates graph version/schema, source statuses and
   source/endpoint ACLs before and after execution. Changed state holds the
   result. An exception leaves `last_attempt` started/unknown; preserve it and
   reconcile rather than retry. A crash without saved output is not a completed
   model response and does not authorize another attempt.
6. Save original response bytes, original local execution JSON, exact profile,
   pack and logs atomically in the private pilot evidence area. The trusted
   application may sign an execution receipt only from this observed run, with
   model/provider/revision, request/response/pack/profile/execution hashes,
   generation time, token usage and zero paid cost. Do not edit rejected output.
7. Import with `record_semantic_response(..., local_execution=execution)` and
   supply separately trusted observation attestations. Resume through
   `resolve_plan`, preserving the solver/evaluation/plan records. Without valid
   qualification the automatic evaluation remains ABSTAIN. Stop at the held
   plan review state for this first-call protocol; no graph publication follows
   automatically from the response or its signature.
8. Report actual format status, selected label and raw uncalibrated values,
   source-review agreement/disagreement, all failures, duration/usage/resource
   observations and hashes. One successful call demonstrates mechanics only.
   Expanding to real reviewed publication, retrieval and cited answer review
   requires an explicitly frozen follow-on pilot using the existing
   [durable service](paper_pilot.md), genuine responses and actual review.

The source review and claim verdict should be sealed before opening the semantic
response. The reviewer of a generated cited answer remains an attributed internal
reviewer. A signed timestamp attests the application's recorded review sequence;
it does not prove independent human review or semantic truth.

## Supported application call sequence

The application supplies the private paths, owned services, enrolled issuer and
actual source review described in [paper_pilot.md](paper_pilot.md). Imports do
not load a model. Constructing the adapter explicitly loads the verified local
snapshot; call it only within the approved resource window.

```python
from trace_gc.canonical import bytes_digest, digest
from trace_gc.local_semantics import LocalQwenSemanticAdapter

adapter = LocalQwenSemanticAdapter(
    model_root, manifest_path, device="cpu", threads=4,
    maximum_input_tokens=8192, maximum_new_tokens=512,
)
# Freeze adapter.profile and its digest before creating/opening PaperPilot.
# config.semantic_model must exactly identify this profile's provider, model,
# revision and tokenizer. Supply semantic_profile=adapter.profile and
# token_counter=adapter.token_counter to the application-owned PaperPilot.

compiled = pilot.compile_candidates("compile-1", candidates=reviewed_candidates)
# Persist external intent; confirm the reviewed protocol and source-first record.
raw, execution = adapter.generate_pack(
    pilot.catalog, compiled["pack_id"], execution_authorized=True,
    current_context=lambda: pilot.semantic_execution_context("compile-1"),
)
# Persist raw, execution and adapter.last_attempt before proceeding.
payload = pilot.execution_payload(
    "compile-1", kind="SEMANTIC", response_sha256=bytes_digest(raw),
    generated_at=execution["completed_at"],
    usage={"input_tokens": execution["input_tokens"],
           "output_tokens": execution["output_tokens"]},
    cost={"amount": 0, "currency": "USD"},
    response_source=execution["response_source"],
    provider_request_id=application_execution_id,
    local_execution_sha256=digest(execution),
)
# Signing is an explicit application action after checking genuine execution.
receipt = enrolled_execution_signer.issue("OBSERVATION", payload)
observed = pilot.record_semantic_response(
    "response-1", compile_id="compile-1", response=raw,
    execution_receipt=receipt, local_execution=execution,
)
# Separate actual observation attestation/review is required to resolve a plan.
# This example does not authorize or perform publication.
```

`semantic_execution_context` checks current graph/source/access state without
consuming another model-call slot. `record_semantic_response` binds its current
digest to the signed local execution, and resume rechecks it. The private
checkpoint is not graph authority. A code, schema, model or profile change
invalidates the frozen run; preserve it and create a deliberate new run/version.

## Verification and limits

```powershell
python -m unittest tests.test_local_semantics tests.test_local_semantic_pilot tests.test_paper_pilot -q
python tools/run_validation.py
python tools/validate_package.py
```

Authored tests exercise provider/profile cache isolation, exact legacy wire
compatibility, malformed/truncated response preservation, strict replay, no
unauthorized inference, current permission races, unknown-outcome handling,
durable resume, signing boundaries and explicit reviewed publication on synthetic
fixtures. They do not demonstrate real Qwen structured-output success, accuracy,
calibration, real paper utility, image semantic ingestion or completion of #23.

The official [model card](https://huggingface.co/Qwen/Qwen3-4B-Instruct-2507)
identifies this non-thinking instruction model. Transformers
[generation scores](https://huggingface.co/docs/transformers/en/main_classes/text_generation)
describe token generation; they are not substituted for calibrated claim
correctness. Constrained JSON generation could be a separately frozen future
profile, using supported [structured output APIs](https://docs.vllm.ai/en/latest/features/structured_outputs/).
It is not installed, invoked or emulated by this change.
