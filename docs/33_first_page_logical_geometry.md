# Native logical rows for first-page alignment

The bounded [math row geometry extension](native_math_row_geometry.md) versions
the current derived view as `native-logical-rows-v2`. The v1 measurements below
remain the original historical evidence.

Issue [#15](https://github.com/CompleteDotTech/jraphyte/issues/15) separates
PDF extraction units from visual rows. A PyMuPDF native line can be one fragment
of a sentence, split at a font change or an inline formula. The previous
`locate()` compared consecutive fragment rectangles and marked horizontal
non-overlap as a column transition. Its `_chains()` could also omit a short
fragment while assembling a column from similarly sized native rectangles.

## Representation and source identity

`trace_gc/pdf_geometry_parallel_v4.py` adds the derived
`native-logical-rows-v1` view. It reads the existing native lines and span sizes.
`source_lines()`, native JSON, line IDs, text, offsets, boxes, historical
canonicalization and the 98% alignment floor are unchanged. No source text is
normalized into a replacement native artifact. Returned alignment spans still
round-trip to the original line and exact character interval.

The view joins close horizontal fragments using continuous-row evidence from
their native blocks. Ordinary fragments need paragraph-width support above and
below, or a native block-start anchor followed by two corroborating rows.
A compact displaced formula run needs flanking baseline text with comparable
typography and an owned supporting row; a small raised word alone is insufficient.
Already corroborated fragments can explain overlapping font runs across native
block splits, with that context recorded explicitly.

Compatible vertical geometry remains required. Large gaps, overprints, tall or
explicitly rotated lines, and even one neighboring paired gutter retain their
separation. A wide anchor prevents a script from joining successive rows
transitively. Preceding full-width text alone cannot bridge body columns, even
when their native block IDs are identical. Unsupported isolated fragments remain
separate.

Column-local chains now operate on those logical rows and retain every native
fragment in physical x order inside a supported row. The original native order
remains an alternative search chain. Full-width lines cannot transitively link
two narrow columns through the column-chain width constraint. Unique occurrence
checking and wrong-region source projection remain active.

`locate()` adds `logical_geometry` to located results, containing its version,
derived row rectangles, original line IDs, join reasons, supporting source
IDs/boxes, ownership cues and unsupported transitions. The selector preserves
this evidence in `source_alignment` and its
existing seal binds it. These derived rectangles describe complete visual rows;
they are not character boxes or replacement source boxes. Section ownership and
closing-boundary decisions remain separately evaluated by the selector.

The geometry is conservative, heuristic evidence. Current native caches do not
contain direction, baseline origins or RAWDICT characters. The height/font-size
guard rejects observed tall rotated fragments, but does not recover direction
or establish a general rotation guarantee. The [PyMuPDF extraction documentation](https://pymupdf.readthedocs.io/en/latest/app1.html)
describes the distinction between blocks, lines, spans and characters; that
documentation does not validate this grouping method on unseen papers.

## Reproduction

Use the authorized original external dataset described in
[the reproduction guide](31_first_page_parallel_reproduction.md). Authored tests
are counterexamples, never substitutes for the private 200-paper corpus.
From the repository root, in PowerShell:

```powershell
python -m unittest discover -s tests -p 'test_parallel_source*v4.py' -q
python -m src.parallel_source_v4.geometry_probe `
  --data-root $env:TRACE_GC_TEST_DATA_ROOT `
  --output validation_v3_private/geometry-diagnostic-new/results.json
```

Use a fresh output path. `geometry_probe` replays all 200 cases through four
cached converter methods using saved native lines. It binds the parsed input
bytes and implementation files by SHA-256 and checks them again before writing
an immutable result. It records scores, states, changed IDs/reasons and source
identities, and emits no paper text. It makes no model calls or graph writes.
Its explicit status is `CACHED_NATIVE_GEOMETRY_DIAGNOSTIC_NOT_VALIDATION`.

This probe does not re-extract native lines or independently verify PDF bytes,
converter execution, notation fidelity or reference boundaries. Its historical
alphanumeric scores are descriptive diagnostics; see issue
[#14](https://github.com/CompleteDotTech/jraphyte/issues/14) for the separate
versioned fidelity evaluation. Already examined regression cases cannot establish
unseen-paper accuracy.

After integrating the bounded runtime from
[#13](https://github.com/CompleteDotTech/jraphyte/issues/13), run the source-bound
native replay with a fresh output directory:

```powershell
python -m src.parallel_source_v4.extraction regression `
  --data-root $env:TRACE_GC_TEST_DATA_ROOT `
  --source-map validation_v3_private/parallel-v4-source-map.json `
  --output validation_v3_private/geometry-integrated-new
python tools/run_validation.py
python tools/validate_package.py
```

Native geometry bounds remain strict. In particular, a negative top coordinate
such as the observed h149 header remains a native extraction error; this change
does not introduce a clipping or tolerance policy.

## Evidence and remaining gates

The [public receipt](../review/first_page_geometry_v1/evaluation_receipt.json)
binds the completed 200-case, 800-assessment cached diagnostic, 1,402 input
artifacts and final implementation hashes. Observed historical boundary-and-98
agreement was:

| Method | Correct proposals before → after | False proposals after |
| --- | ---: | ---: |
| Primary structure | 38 → 51 | 0 |
| GROBID candidate | 33 → 46 | 0 |
| MinerU candidate | 38 → 49 | 1 |
| olmOCR candidate | 39 → 50 | 0 |

The MinerU false proposal is the existing f039 boundary failure. All four methods
had zero absent/partial false proposals. The primary recovered all 12 diagnosed
cases plus f058, lost none of its previously correct proposals, and reduced
complete abstracts withheld from 73 to 60. Its observed proposal precision was
1.0 and complete-abstract recall rose from 0.3423 to 0.4595. There are still 42
preexisting losses against the frozen v2 preservation target, so that gate fails.

These scores do not certify scientific notation. Frozen manual math-review-hold
accounting is not recomputed by this diagnostic. The receipt lists all 29 prior
primary column-hold cases and changed states/reasons for all four methods.
The final offline gate ran 549 tests: 545 passed and four were skipped. Package
validation passed. A separate agent completed code review; this was not human or unseen-paper
qualification.

All raw
papers, cached native lines and labels remain external. The focused fixtures
cover fragmented rows, scripts, wrap continuation, full-width abstracts,
neighboring columns, duplicate occurrences, narrow repeated gutters, rotated
sidebars (including authored PDFs) and immutable native identity.

The parent recovery gate still requires the integrated native replay, independent
review, preservation accounting and source-reviewed unseen evaluation. Known
case f026 must retain its separate missing-closure hold until
[#16](https://github.com/CompleteDotTech/jraphyte/issues/16) supplies valid boundary
evidence. Proposals remain review candidates with graph admission disabled.
