# Reviewed notation fragments

`reviewed-notation-fragment-v1` adds a small derived representation to the
[native notation sidecar](native_notation_sidecar.md). It preserves the original
PDF, native bytes, character IDs, offsets, boxes, glyph/font witnesses and image
identity. It changes no extraction result, source-fidelity threshold, section
boundary, promotion gate or graph record.

The supported unit is **one reviewed expression**: one base with a subscript,
superscript, or both; or one base with a supported, correctly mapped diacritic.
Its status can become `REVIEWED_FRAGMENT_DERIVATIVE`. This does not certify a
whole abstract. `proposal` and `graph_admission_enabled` remain false,
`section_owner` remains null, and `promotion_effect` remains `none`.

## Evidence and review contract

1. Pin the raw hashes of the authorized original PDF, saved native JSON and
   sidecar. Read each once; the direct API snapshots mutable byte buffers.
   Rebuild the sidecar core from the same PDF/native bytes and require exact
   projection and core identity. Historical sidecar producer metadata is not
   relabeled as a current run.
2. Render physical page one and an observed pixel crop. Bind full-page and crop
   PNG/pixel hashes, renderer versions, page identity and coordinate transforms.
   Nonzero CropBox origins and page rotation use the existing image transform.
3. Inventory **every native glyph box intersecting the crop**, including spaces,
   clipped context and unresolved mappings. Retain the complement of glyph IDs
   outside it. This inventories text glyphs; it does not claim that a PDF's
   arbitrary vector artwork has been interpreted as text.
4. An actual source-image reviewer inspects the full page and crop, identifies
   the expression's semantic role, and partitions the crop inventory into
   expression glyphs and explicitly described exclusions. Included glyphs must
   be entirely within the crop. Every glyph is used once or excluded once.
   Review checks cover mapping, reading order, semantic role, occlusion,
   complete-fragment extent and exclusions.
5. Pin the exact review bytes and reviewer identity separately at the call site.
   The review records attribution, UTC time, actual execution mode, prior
   exposure and `source_image_before_derivative_acceptance`. These development
   papers were seen previously; review is **not** claimed to precede their
   original extraction predictions. Authored fixtures use `SYNTHETIC_AUTHORED`.
6. Replay the source again when deriving. Script relations require exact PR40
   witnesses. Page-wide neighboring-glyph checks prevent omitting an unmodeled
   script/accent by cropping or declaring it context. Mapped diacritics require
   an explicit versioned mapping and unique measured base/mark geometry.
   Unmodeled painted horizontal rules crossing the expression also hold.
7. Emit deterministic presentation MathML and a separately versioned Unicode
   derivative only when the supported table has a faithful mapping. For example,
   a `q` subscript has no mapping here: MathML can represent it while the Unicode
   text is null. Diacritic output is decomposed base + combining mark, without
   NFC/NFKC rewriting. The raw native characters never change.
8. Recheck all source/review files, the repository import closure, complete
   pinned runtime and output hashes around immutable publication. Conflicting
   existing outputs fail. Repeating identical inputs is idempotent.

The attribution is **unsigned** and pinned by the caller's expected hash. These
checks establish artifact consistency, not the truth or identity of a reviewer.
No file, reviewer string or check box confers application trust or graph
authority. There is no Catalog, compiler, admission or selector integration.
Consumers must replay the pinned inputs; a detached status string is not evidence.

## Deliberate holds

- Uncertain RAWDICT/texttrace/font mappings, controls, replacement characters,
  rotated text, hidden paint, clipped included glyphs or competing relations.
- Missing or ambiguous script counterparts, extra overhead marks, unmodeled
  rules, incomplete/overlapping crop glyph coverage or an unsupported expression.
- Fractions, radicals, multiple-character bases/scripts, and composed
  accent-plus-script expressions. They need additional typed contracts.
- Mapped-glyph cases such as the exposed f122/f153 and the f149 footnote scope
  remain unresolved; the implementation has no paper-ID exceptions.

An intact but unsupported expression returns `HELD` with a specific reason and
no MathML/Unicode. Hash/replay/review-contract failures raise an error; the CLI
prints a redacted `BLOCKED` result and exits 2. A review packet by itself remains
`WAIT_SOURCE_IMAGE_REVIEW`. Partial files after an interrupted/blocked write are
not a completion receipt; rerun and validate all pinned inputs before using them.

## Supported service API

```python
from trace_gc.canonical import bytes_digest
from trace_gc.reviewed_notation import prepare_evidence, derive_reviewed

# Authorized immutable input bytes; keep all paper content outside the repo.
evidence, page_png, crop_png = prepare_evidence(pdf_bytes, native_bytes,
                                              sidecar_bytes, crop_pixels)
# A real review occurs here. Store its exact JSON bytes separately.
result = derive_reviewed(pdf_bytes, native_bytes, sidecar_bytes, review_bytes,
                        expected_review_sha256=review_sha256_from_review_handoff,
                        expected_reviewer=reviewer_from_review_handoff)
```

The review object uses `notation-fragment-review-v1`, `evidence_sha256` from
`trace_gc.canonical.digest(evidence)`, the exact crop, and one expression:

```json
{"kind":"scripts","base":132,"sub":134,"sup":133}
```

The integers are glyph IDs from that exact sidecar, not native offsets.
For a diacritic the fields are `kind`, `base`, `mark` and `combining`; the last
must match the versioned raw-mark mapping in `trace_gc/reviewed_notation.py`.
Each exclusion has `glyph_ids`, `role` (`context`, `whitespace`,
`other_expression`, or `unresolved_source_glyph`) and a concrete `reason`.
The authored test helper documents a complete review object. Copying its
synthetic attestation is not an actual paper review.

## Private CLI

Use the pinned interpreter and authorized external data root described in
[parallel reproduction](31_first_page_parallel_reproduction.md). Prepare a packet:

```powershell
& $PinnedPython -m src.parallel_source_v4.reviewed_notation `
  --data-root $env:TRACE_GC_TEST_DATA_ROOT `
  --source 'authorized/source.pdf' --source-sha256 $PdfSha `
  --native 'authorized/native.json' --native-sha256 $NativeSha `
  --sidecar 'authorized/notation.json' --sidecar-sha256 $SidecarSha `
  --crop 850 346 910 391 --output 'private-notation/new-review-packet'
```

After actually reviewing its `page.png`, `crop.png` and `result.json`, save the
attributed review outside the repository. Produce a fresh derivative output:

```powershell
& $PinnedPython -m src.parallel_source_v4.reviewed_notation `
  --data-root $env:TRACE_GC_TEST_DATA_ROOT `
  --source 'authorized/source.pdf' --source-sha256 $PdfSha `
  --native 'authorized/native.json' --native-sha256 $NativeSha `
  --sidecar 'authorized/notation.json' --sidecar-sha256 $SidecarSha `
  --review 'private-notation/actual-review.json' --review-sha256 $ReviewSha `
  --reviewer $ActualReviewer --output 'private-notation/new-derivative'
```

The crop is owned by the pinned review in the second command. Output contains
`page.png`, `crop.png`, `result.json` and `receipt.json`. It includes private paper
text/images; publish only a scrubbed count/hash receipt. The receipt binds all
inputs, outputs, code and runtime, and records zero paid calls and graph writes.

## Verification

```powershell
& $PinnedPython -m unittest tests.test_reviewed_notation tests.test_native_notation_v4 -q
```

Authored PDFs exercise scripts, combined scripts, diacritics, exclusions,
unmapped letters, extra accents/scripts, vector overlines, partial crops, image
rotation/CropBox origin, immutable replay, review attribution/pinning and
post-derivation input mutation. These are authored tests, not a 200-paper run or
unseen qualification. Real exposed examples are recorded separately in
`review/reviewed_notation_v1/diagnostic_receipt.json` when that receipt is present.
