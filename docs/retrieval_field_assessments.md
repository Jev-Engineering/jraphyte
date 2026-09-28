# Source-bound abstract fields for retrieval

`python -m src.parallel_source_v4.fields` builds discovery fields from an authorized first-page preparation manifest. Abstract selector assessments are optional. When supplied, the builder reads an explicit method and file map; it never selects a method from query text, target IDs or ranking results. The method is caller declared and checked against the assessment path; a separate producer receipt is needed to attest which executable created it.

For the original 10,000-paper retrieval corpus, the PDFs are outside the test-data root. Prepare them with a separate, explicit read-only source root. The preparation command first validates that the index IDs and source manifest IDs match exactly and that every source path is inside the authorized source root. It writes a new page/image/native manifest under the data root; it does not apply the unseen-cohort freeze protocol to these exposed retrieval documents:

```sh
python -m src.parallel_source_v4.retrieval_prepare \
  --data-root /authorized/TRACE-GC_RealPaper_Test \
  --source-root /authorized/original-pdfs \
  --retrieval-manifest validation_200_10k/retrieval_manifest.json \
  --index-manifest validation_200_10k/index/manifest.json \
  --output validation_v3_private/retrieval-preparation-UNIQUE
```

Use a never-used output directory and allow for 10,000 page PDFs, images and native JSON files to be written. The original source PDFs are read from the external root and are not copied. The command preserves recorded historical source hashes where available, computes missing hashes and records the current extractor/runtime identity. If preparation is interrupted, rerun the same command against the same output directory. It verifies the frozen input protocol, each completed page receipt and its source/page/image/native hashes before continuing. Incomplete or corrupt published sample directories fail closed and require investigation; unpublished temporary directories are retained as interruption evidence. Start a new owned output directory when inputs, runtime, or configuration change. A truncated preparation is not a full-corpus result.

Place a private `assessment-map.json` under the authorized `--data-root`:

```json
{
  "schema_version": "retrieval-assessment-map-v1",
  "method": "parallel_structure_v4",
  "extractor_version": "page-one-parallel-structure-v4",
  "entries": [
    {
      "sample_id": "paper-001",
      "assessment_relative": "runs/extraction/assessments/parallel_structure_v4/paper-001.json",
      "assessment_sha256": "<64 lowercase hex characters for the assessment file>",
      "native_sha256": "<64 lowercase hex characters for the saved native JSON file>"
    }
  ]
}
```

Allowed methods are `parallel_structure_v4`, `parallel_grobid_v4`, `parallel_mineru_v4` and `parallel_olmocr_v4`. Every mapped sample ID must appear once in the input manifest. An omitted sample has state `missing`; a sealed hold, error, partial or absent assessment retains that state and contributes no abstract field. Proposals must have a complete first-page state, a located native transcription, a closing boundary and source spans that exactly read back from the pinned saved native JSON. The builder rejects mismatched source, page, native, geometry, assessment file and seal identities. It does not re-extract native text with whichever PyMuPDF happens to be installed.

Example after the path and hashes above are replaced with authorized values:

```sh
python -m src.parallel_source_v4.fields \
  --data-root /authorized/TRACE-GC_RealPaper_Test \
  --source-root /authorized/original-pdfs \
  --manifest validation_v3_private/retrieval-preparation-UNIQUE/manifest.json \
  --abstract-assessments runs/assessment-map.json \
  --output runs/fields-with-abstracts.json
```

The output records the manifest and map hashes, declared method, assessment extractor version, saved native file and semantic hashes, per-sample assessment state, assessment file/seal hashes, source/image identity and counts. It re-extracts native text from the original page under the pinned runtime to verify the saved native representation; it never silently replaces that representation. Before publication it rechecks every original PDF and saved page/image/native file hash, the complete V4 Python module hash set, and renderer/runtime identity. Any changed input or code blocks the output. `fields_sha256` binds the entire field list; downstream dense caches made from earlier fields must be rebuilt. Field outputs retain `retrieval_only=true` and `eligible_for_jev=false`. A selector proposal aids discovery and remains unreviewed evidence; the application must not use it as authority for Jev calls or graph writes.

The original first-page image must match the original PDF rendering byte for byte. A saved one-page PDF can render differently after `insert_pdf`, so the builder records its pixel comparison separately. It retains the existing two-channel tolerance; a larger difference is `render_mismatch_review_required` with exact sample IDs, maximum channel delta and changed-channel count. The field still comes from the original PDF and verified native JSON, and remains retrieval-only. On such a row, optional abstract assessments, reviewed titles and OCR caches are rejected until the page-copy discrepancy is resolved; a cached-page review cannot silently qualify an original-page field. These rows remain in the corpus denominator.

If a PDF renders but its native text has a bounding box outside the physical page, preparation retains that document with `native_extraction_state=error`, the exact diagnostic and empty native evidence. The field manifest reports native extraction counts and unsearchable IDs; such a document remains in the 10,000-paper denominator. It needs a separate source-bound OCR or reviewed-image route to become searchable. No native span is clipped or invented by this fallback.

Source PDFs, preparation manifests, assessments, reviewed titles and OCR outputs remain outside the public repository. For a full-corpus run, every original document and its bound first-page source/page/image/native representation must be available; missing or invalid files are errors, not silently skipped rows. Retrieval quality is measured separately by the 10,000-paper trial.
