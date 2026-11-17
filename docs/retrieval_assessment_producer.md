# Query-independent Docling assessment producer

`python -m src.parallel_source_v4.assessment_producer run` builds the private
`retrieval-assessment-map-v1` consumed by `src.parallel_source_v4.fields`. It
reads a completed `retrieval_source_first_no_predictions` preparation manifest,
never reads queries or target labels, and writes one immutable row per selected
document. The default selection is every manifest ID in manifest order. `--id`
selects already-exposed pages for a resource smoke; its receipt is explicitly
`EXPOSED_SMOKE`, never a full-corpus result.

The controller must run under the pinned V4 evaluator runtime recorded by
`src/parallel_source_v4/runtime-windows-py312.lock.json`. It re-extracts the
original physical first page and verifies the saved page, review image and
native JSON through the same source check used by the retrieval field builder.
The Docling worker is launched under a separate pinned converter interpreter.
It uses the offline Heron/RapidOCR CPU configuration from
`src.paper_converter_worker._docling` with network connections denied. The
converter and evaluator runtimes are separate identities.
One owned CPU worker converts at most 64 pages by default. The
`--max-documents-per-session` option pins a limit from 1 to 256 in the immutable
run protocol. After each completed conversion has a verified row receipt, the
controller asks its owned child to drain, verifies the child's exit and hashed
drain receipt, then starts a fresh session for the next eligible page. This is
an operational residence bound, not a measured memory cap or a proven fix for
the underlying native thread growth. A timeout or an unknown child exit holds
the run without retrying that page.
The new protocol and changed code identity require a new versioned run or an
explicit migration; an older frozen run cannot be silently resumed with this
controller. Existing intents, conversions and receipts retain their original
protocol and provenance.

An external supervisor may write one immutable
`control/drain-requests/<request_id>.json` with `version` set to
`assessment-graceful-drain-v1`, a fresh 32-digit lowercase hexadecimal
`request_id`, the exact `protocol_sha256`, and `requested_at`. The owner checks
it only at a verified row boundary, drains its child, writes
`control/drain-ack-<request_id>.json`, and returns `STOPPED_DRAINED` without a
completed corpus map. Both the direct producer and migration commands exit 4
for this controlled stop; exit 0 remains reserved for a completed assessment.
The same request and acknowledgement are recognized on
resume; a changed request or unknown child outcome holds. Later requests use
new IDs and keep earlier request and acknowledgement files intact. More than
one pending request holds. The supervisor must not signal or terminate the
converter child directly.
The request folder is a trusted local owner control channel. The request ID
and protocol hash bind its identity; they are not a cryptographic signature.
On Windows the controller records the actual worker PID and creation time
before conversion, retains a kernel handle to that exact process, and verifies
its exit before ending a timed-out attempt. A child whose ownership cannot be
verified remains an unknown outcome and cannot be silently retried.

The private profile JSON has exactly these keys:

```json
{
  "engine": {
    "name": "docling", "revision": "2.130.0", "device": "cpu",
    "decoding": {
      "layout_directory": "private-assets/docling-project--docling-layout-heron",
      "det_model": "private-assets/rapidocr/PP-OCRv6_det_small.pth",
      "cls_model": "private-assets/rapidocr/ch_ptocr_mobile_v2.0_cls_mobile.pth",
      "rec_model": "private-assets/rapidocr/PP-OCRv6_rec_small.pth",
      "rec_keys": "private-assets/rapidocr/ppocrv6_dict.txt",
      "cpu_threads": 4
    },
    "assets": [
      {"relative": "private-assets/docling-project--docling-layout-heron/model.safetensors", "sha256": "<real file SHA-256>"}
    ]
  },
  "runtime": {
    "python": "<exact converter Python version>",
    "executable": "sample_comparison/.venv/Scripts/python.exe",
    "executable_sha256": "<real executable SHA-256>",
    "packages": {
      "docling": "2.130.0", "docling-core": "<installed version>",
      "docling-ibm-models": "4.0.3", "rapidocr": "3.9.2",
      "torch": "<installed version>"
    }
  },
  "limits": {"timeout_seconds": 180, "max_document_bytes": 16777216, "max_attempts": 1}
}
```

The `assets` list must contain **every regular file** in the local Heron
directory, plus the four RapidOCR files named by `decoding`. All paths are
relative to the authorized private data root and all hashes must be measured
from the actual bytes. Stage a private, plain directory with the pinned Heron
snapshot; the existing Hugging Face snapshot path is outside the data root and
contains links, so it cannot be passed directly. The profile file itself must
also reside under the data root. Do not publish private model paths or corpus
outputs.

Example, using real private paths and the pinned evaluator interpreter:

```powershell
& $evaluatorPython -B -s -m src.parallel_source_v4.assessment_producer run `
  --data-root $dataRoot --source-root $sourceRoot `
  --manifest validation_v3_private/retrieval-preparation/manifest.json `
  --profile validation_v3_private/docling-profile.json `
  --output validation_v3_private/retrieval-assessments-exposed-01 --id $exposedCorpusId
```

Before a full run, measure elapsed time and peak worker memory on an exposed
page, declare a bounded resource budget, and use a new output path with no
`--id`. The controller holds an OS lock, freezes the manifest/profile/code and
evaluator runtime, and checks every row before and after conversion. Each
eligible row has an intent, converter status, genuine raw Docling document on
success, sealed V4 assessment and receipt. The worker records an immutable
session-start receipt; every conversion record binds its hash, worker PID,
runtime, pinned profile and exact document hash. An exception during the
converter call becomes a sealed error assessment. A worker exit or timeout
without a conversion receipt is an unknown attempt that blocks completion;
it cannot be relabeled as a converter error. Native errors, page-copy
mismatches and empty-native rows are `ineligible` ledger rows and stay out of
the consumer map. A Docling error that returns a partial document retains that
document with its error status; the partial text is never promoted.
Assessments remain unreviewed retrieval candidates; they do
not authorize graph evidence.

Reissuing the identical command verifies completed rows and continues. If a
controller stops after a worker sealed `conversion.json`, it can finish that
assessment without another converter call. An intent without a converter
receipt is an unknown attempt and fails closed for investigation; do not delete
it or start another controller. `ledger.json` and `assessment-map.json` seal
only after the complete selected ID set passes independent source, converter,
assessment and hash readback. A smoke ledger is not the 10,000-row acceptance
gate. After the complete full-corpus map, rebuild all fields and dense vectors
under the frozen corpus policy, then run the separate retrieval protocol.

## Exposed resource smoke, 2026-09-29

A private, already-exposed original-corpus smoke exercised three then ten
eligible documents under the pinned local CPU profile. The ten-document run
took 66.02 seconds from protocol creation through final ledger readback. Its
converter time summed to 21.01 seconds; after startup, the median document
conversion was 1.38 seconds. All ten genuine Docling calls succeeded. Peak
worker working set rose to 1,475 MiB on the third document and stayed there
through the tenth. A separate three-row smoke verified one each of native
error, page-copy mismatch and empty-native states; all were ledgered as
ineligible, with zero converter attempts and zero assessment-map entries.

The ten-document end-to-end rate extrapolates to about 18.3 hours for 10,000
documents. This is a planning estimate, not a measured full-corpus runtime;
long-tail pages, I/O variation, interruptions and final field/ranking work
need additional time. Reserve at least a 24-hour execution window and memory
headroom above the observed 1.5 GiB worker working set, plus evaluator and OS
cache. Run only after the final #19 selector tree and profile are frozen.

## Full-run resource budget derivation

Measure an exposed smoke from protocol creation through final ledger readback
for N exposed documents. Retain that end-to-end wall time, each converter's
`wall_seconds`, peak `peak_process_memory_bytes`, and the converter session
count. Compute `projected_hours = wall_seconds_total / N * eligible_count / 3600`.
Declare a window comprising that projection plus explicit margins for long-tail
pages, session restarts (one session per `max_documents_per_session` eligible
rows), interruptions, and downstream field, dense and ranking stages. Declare
memory as the observed peak worker working set plus evaluator and OS cache
headroom; the worker peak alone is not a host memory budget.

The 2026-09-29 example used 10 documents and 66.02 seconds end to end, giving
about 18.3 hours projected for 10,000 documents. Peak worker memory was
1,475 MiB. The 24-hour planning window and memory headroom described above
belong to that example. Derive the actual budget from a fresh smoke on the
final frozen #19 tree and profile for the verified eligible count.

## Aggregate public receipt schema

The redacted `retrieval-assessment-aggregate-public-v1` receipt summarizes a
completed private `ledger.json` after independent readback from the bound
protocol, manifest, profile, row receipts and assessment map. Use
`FULL_CORPUS` only after verifying coverage of the whole frozen manifest and
`EXPOSED_SMOKE` for the verified exposed subset. For a migrated run, verify
the origin protocols, imported rows and pending-conversion lineage, including
nested imports, and bind their evidence by digest. Distinguish inherited work
from new attempts and measurements when reporting totals.

The receipt contains the following fields.

- `scope`: `FULL_CORPUS` or `EXPOSED_SMOKE`; `status`.
- `private_evidence_sha256`: protocol, ledger, assessment map, manifest and
  profile hashes; `code_tree`: git head and method-hash digest.
- `document_count`, `eligible_count`, `eligibility_counts`, `state_counts`,
  and assessment status counts.
- Converter totals: attempts, success, error and unknown/held.
- Resource measurements: total wall seconds, median and maximum converter
  seconds, and peak worker bytes.
- Operational claims with verified evidence for the declared scope.
  Assert `query_independent` from the bound selection inputs and execution
  records. Assert `new_paid_api_calls` and `production_graph_writes` from
  verified accounting across the run and its workers. Assert
  `graph_admission_enabled` from the effective admission policy and execution
  evidence. Bind the supporting private evidence by digest. For imported
  work, verify the same claims against its origin evidence and distinguish
  its accounting from activity new to the resumed run. Omit unsupported
  claims or mark them unverified, including when an origin has missing
  evidence. A completed ledger alone does not establish these values.

Never include sample IDs, source paths, converter text, native text, proposals,
labels, per-paper rankings or private model paths. This schema is a
documentation contract: no producer for it exists yet and no full-corpus
instance has been published.
