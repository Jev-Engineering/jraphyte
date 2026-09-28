# Reviewed image evidence (issue #18)

`pdf-image-evidence-v1` supplies an explicit image review route when native PDF
text is absent, corrupt, or insufficient. OCR output is a candidate. An attributed
visual review can create immutable derived text evidence; neither step admits a
source, creates a graph assertion, or calls JEV. Existing native evidence and its
historical extraction metrics are unchanged.

## Contract and trust boundary

The new `image-evidence-v1` catalog record binds:

- Original PDF SHA-256 and one-based physical page. `page_identity_sha256` is the
  canonical digest of the original PDF hash, page number, rotation and unrotated
  page rectangle; it is **not** the hash of an independently saved one-page PDF.
- Renderer/PyMuPDF/MuPDF/Pillow versions, DPI, rotation, RGB image dimensions,
  forward/inverse transforms, page PNG hash and decoded RGB pixel hash.
- An observed crop rectangle, its dimensions and PNG/pixel hashes. Coordinates
  are integer pixel edges measured from the rendered image's top left; right and
  bottom are exclusive. PDF coordinates are MuPDF unrotated page points relative
  to the page crop. Re-rendering derives the crop from the original page.
- OCR engine revision, configuration and its hash, exact input crop hash, raw
  output hash/byte count, completion state and exact candidate transcription.
- A review of that exact candidate: named assistant/human, zoned timestamp,
  disposition, and separate transcription, reading-order, boundary and notation
  checks. `independent_review` is always false in this contract.

The review is an attestation, not an authenticated signature or proof that the
reviewer was correct. Hashes detect inconsistent artifacts, not hallucination.
The reviewer must inspect the source image and perform the four accuracy checks.
The software never infers those checks from OCR confidence or a hash match.
Unknown original OCR input or revision stays held even if the text looks right.
Edited text creates a new candidate, retains raw OCR and the previous candidate
hash, records its editor, and invalidates the old review.

`handoff()` re-renders the original byte snapshot and verifies raw OCR before
creating three catalog records: image evidence, a source with representation
`reviewed-image-transcription-v1`, and ordinary Unicode text evidence. The source
contains `image_evidence_id`, the original document hash, and an image-record
hash as its version. Evidence offsets count Unicode code points in this immutable
**derived text**. They are never reported as offsets or spans in native PDF text.
`Catalog.verify_evidence`, compiler closure, ledger references and bundle
validation all retain and validate image lineage. Original PDF/crop/raw OCR bytes
remain external and must be available for an artifact audit. Portable bundle
validation checks the recorded bindings and review; it does not reopen external
files or authenticate the reviewer.

An image record that is unreviewed, partial, absent, ambiguous, uncertain about
equations, erroneous, truncated, over the unchanged 4,000-character/16,000-UTF-8-
byte text budget, or missing OCR provenance is held. Text is never silently
truncated. Existing compiler request/token budgets still apply after handoff.
Native extraction state `available` only means nonempty text with no detected
replacement/control characters; a valid-but-wrong character mapping still needs
source review. `fallback_route` preserves an existing native proposal and routes
other cases to image review, without changing its native assessment or admitting
anything. Image results must be reported separately from native success counts.

## Run with authorized local inputs

Use the pinned extraction environment documented in [reproduction](31_first_page_parallel_reproduction.md).
PyMuPDF and Pillow are required. All CLI paths below except the data root are
safe relative paths beneath that explicitly authorized external root. Use a new
output directory for each changed crop, OCR attempt, correction or review. The
CLI refuses conflicting output bytes and rechecks source, images, raw output,
review inputs and implementation hashes before publishing its completion receipt.
Keep private PDFs, images, transcripts and review notes outside Git.

```powershell
python -m src.parallel_source_v4.image_ocr prepare --data-root <AUTHORIZED_DATA_ROOT> --source sources/paper.pdf --source-id paper-id --physical-page 1 --dpi 144 --crop 200 250 1040 310 --output image-run/prepared
```

Inspect `page.png` for the complete abstract and its surrounding boundaries, then
inspect `crop.png`. Record the intended region before opening candidate OCR.
The crop must contain every glyph of the intended evidence. A small clean crop
does not establish that it contains a complete abstract. Do not infer an abstract
from cover text (the known f076 page is an image-only cover).

On Windows, this invokes only the **already installed** Windows.Media.Ocr engine:

```powershell
python -m src.parallel_source_v4.image_ocr ocr --data-root <AUTHORIZED_DATA_ROOT> --preparation image-run/prepared --output image-run/ocr
```

The adapter performs no installation, download, paid API call or service change.
It records the engine DLL hash/version, installed OCR resource hashes, OS build,
language, helper hash and exact crop hash before/after recognition. Windows exposes
a component revision, not a separate model revision; that limit is recorded in
the configuration. Word boxes in raw output are explicitly model estimates and
never enter the source-image geometry contract. Missing local language support,
oversized images or OCR failure produces `BLOCKED`, not an empty successful run.

To inspect an existing olmOCR cache without a new OCR call:

```powershell
python -m src.parallel_source_v4.image_ocr ocr --data-root <AUTHORIZED_DATA_ROOT> --preparation image-run/prepared --cached-output cached/olmocr.json --output image-run/cached
```

Legacy caches have no reliable input-crop/revision binding. This command preserves
their bytes and explicitly marks the provenance unverified; they cannot complete
the verified handoff. Do not manufacture missing model/input metadata.

Create an external UTF-8 review JSON after comparing candidate text to both images:

```json
{
  "candidate_sha256": "COPY_THE_EXACT_CANDIDATE_HASH_FROM_EXECUTION_JSON",
  "reviewer": "actual reviewer identity",
  "reviewer_kind": "assistant",
  "reviewed_at": "2026-09-28T12:00:00Z",
  "disposition": "complete",
  "checks": {"transcription": true, "reading_order": true, "boundaries": true, "notation": true},
  "notes": "Describe the actual source review and any representation choices."
}
```

Only set a check true after performing it. Use a held disposition otherwise.
The timestamp/example checks above are placeholders, not a review. For a needed
correction, write another external JSON with `candidate_sha256`, `transcription`,
`editor`, `editor_kind`, `edited_at`, and `reason`, then create a new candidate:

```powershell
python -m src.parallel_source_v4.image_ocr correct --data-root <AUTHORIZED_DATA_ROOT> --ocr-output image-run/ocr --correction image-run/correction-spec.json --output image-run/corrected
python -m src.parallel_source_v4.image_ocr handoff --data-root <AUTHORIZED_DATA_ROOT> --preparation image-run/prepared --ocr-output image-run/corrected --review image-run/corrected-review.json --scope private-research --output image-run/handoff
```

Without a correction, pass `image-run/ocr` as `--ocr-output`. Review must reference
the current candidate hash. UTF-8 is required; platform-default text decoding can
change mathematical characters and correctly fail the hash check.
`REVIEWED_TEXT_EVIDENCE` means the immutable catalog handoff succeeded.
`admitted: false` remains explicit: existing source-admission authority, JEV
qualification and publication gates still apply separately.

## Migration and validation

The source schema gains an optional `image_evidence_id`, required exclusively for
`reviewed-image-transcription-v1`. Existing source/evidence records and hashes do
not change. Readers of new image bundles must upgrade their record-kind registry,
source schema, catalog verifier, closure traversal and ledger validation together;
older readers fail closed on the new kind. Do not remove the image record during
export. Both `schemas/runtime` and packaged `trace_gc/data/schemas` are generated
from `tools/build_schemas.py` plus `tools/image_evidence_schemas.py`.

```powershell
python tools/build_schemas.py
python -m unittest discover -s tests -p 'test*image*v*.py' -q
python -m unittest discover -s tests -p 'test_parallel_source*v4.py' -q
python -m unittest discover -s tests -p 'test_pdf*.py' -q
python tools/run_validation.py
python tools/validate_package.py
```

`tools/image_evidence_fixtures.py` authors public synthetic image-only,
valid-but-wrong Unicode mapping, rotated and repeated-text PDFs at runtime. They
are not new research-paper observations. Negative tests cover changed PDF/image/
crop/raw output/transform, hallucinated words, equation and boundary review
failure, stale reviews, missing lineage, out-of-bounds coordinates, budget holds,
immutable files and source mutation before publication. Tests also transport the
image lineage through materialization and a finalized analysis bundle. Synthetic
review attestations test enforcement; they do not measure OCR accuracy.

## Recorded local experiment

The [sanitized experiment receipt](../examples/image_evidence/experiment_20260928.json)
binds 88 implementation/schema files and hashes of the tested artifacts. Its
SHA-256 is `7ac10816e849361210a0420d65dd2c383145877b386a2248ea4ec8c2c736146c`.
This is a diagnostic subset of four already exposed frozen200 pages, selected
for absent/suspect native encoding. It is not an unseen cohort or a population
accuracy estimate. The implementation agent performed the source review and the
correction; no independent reviewer is claimed for these labels.

| Case | Raw local OCR review | Final disposition |
| --- | --- | --- |
| f033 | Incorrect inequalities/fractions/floor notation | Held: uncertain equation |
| f059 | One-half fraction became a letter | Explicit Unicode correction, then fresh review and text-evidence handoff |
| f076 | Readable image-only cover, no abstract | Held: abstract absent |
| f111 | Incorrect mathematical notation and included inline label | Held: uncertain equation |

Raw acceptance was **0/4** (notation errors on **3/3** abstract-present pages).
After one attributed correction, **1/4** pages completed the image text-evidence
handoff and **3/4** remained held. The final experiment made six local OCR calls:
four real pages and two authored synthetic pages. Both synthetic image-only and
broken-mapping PDFs completed reviewed handoff. These counts are separate from
the historical native metric; there were zero paid API calls, graph writes or
new unseen papers. Review workload was four real pages, five candidate reviews
and one correction. Wall-clock review duration was not instrumented.

The private audit receipt SHA-256 is
`61affbab198db98446775c66fb6f442b086e9ec00440f69e645aaccb43d3af5f`.
It enumerates 75 exact input/artifact hashes. Reproduction requires authorized
access to the frozen200 source map, original PDF bytes, page/crop images, raw OCR,
review/correction specifications and handoff catalog files under
`<AUTHORIZED_DATA_ROOT>/validation_v3_private/issue18-image-20260928/`.
Final real artifacts are `real03/<case-id>/`; authored artifacts are
`synthetic-final02/<case-id>/`. The two final-tree experiment JSON files bind the
private and sanitized views. Earlier pilot/intermediate folders are preserved
and are not substituted for the final experiment. The public repository contains
hashes and authored fixture code, not private paper text or images.

Upstream integration must rerun the normal tests and promotion gate on its merged
tree. This diagnostic receipt does not enable image OCR in a native-only promoted
configuration, establish automatic mathematical OCR accuracy, or qualify graph
admission.

## Research basis

- [PyMuPDF OCR documentation](https://pymupdf.readthedocs.io/en/latest/recipes-ocr.html): OCR text does not preserve native PDF font/style information; this path does not invent it.
- [PyMuPDF page coordinate reference](https://pymupdf.readthedocs.io/en/latest/page.html): rotation and derotation matrices motivate the explicit two-way transform checks.
- [Microsoft OcrEngine reference](https://learn.microsoft.com/en-us/uwp/api/windows.media.ocr.ocrengine): the installed engine recognizes a bitmap in a supported language; review remains necessary for mathematical notation and boundaries.
