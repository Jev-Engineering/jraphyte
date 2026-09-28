# Exact native leading-prefix binding

This bounded follow-up to [issue #17](https://github.com/CompleteDotTech/jraphyte/issues/17)
repairs source slicing and preserves uncertain review candidates. It does not
resolve the remaining scientific transcription or promotion gates.

## Cause and repair

The locator searches canonical alphanumeric characters. Its original slice
started at the first mapped alphanumeric character, dropping a requested leading
symbol even when that symbol was present in the same native line. Authored
examples include `∂t`, `√x`, `(x + y)` and `|x| = y`.

The `native-requested-leading-prefix-v1` rule runs **after** the existing source
occurrence ambiguity decision. It extends the first selected raw offset only
when the complete requested prefix occurs immediately before the selected
character on the same native line. The canonical anchor must also agree. The
prefix may contain visible punctuation, symbols and horizontal spaces; controls,
combining marks and line breaks require separate representation evidence.

The returned text is sliced directly from the original native string. Native
strings, line IDs, boxes, offset coordinates, extraction schema, geometry rules
and alignment thresholds are preserved. A query without a prefix does not absorb
a preceding heading separator or opening punctuation. Missing, mismatched or cross-line
prefixes remain unlocated with an explicit reason. Operator prefixes cannot
silently select among multiple canonical occurrences.

This rule covers the leading prefix of each actual locator query. It does not
infer arbitrary internal operators, attach standalone glyph lines, or change
the historical trailing-punctuation rule. It is not notation certification.

## Retaining uncertain candidate text

The first targeted replay exposed a separate integration effect: the collector
stopped at the first newly unlocated mathematical region, hiding later candidate
prose in `f079` and `f122`. That diagnostic is preserved.

The `source-prefix-hold-retention-v1` path can retain attempted text and continue
only when it has a verified explicit Abstract start, a source-located closing
boundary, and native continuity between previously located content, the
provisional extent and the next located region. Source lane, width, order and
gap checks apply; missing source evidence, intervening headings and unrelated
columns stop continuation. Existing collection boundary and style gates remain.

The provisional `candidate_native_extent` is marked `canonical_extent_only` and
`accepted: false`. It is diagnostic provenance, never accepted transcription.
The missing-prefix failure remains sticky. The assessment stays uncertain with
empty accepted spans, no abstract section owner, no complete proposal and no
graph admission. A later review cannot treat this provisional extent as proof
that the missing symbols were repaired.

## Measured diagnostic and remaining gates

The [receipt](../review/native_leading_prefix_v1/evaluation_receipt.json) binds
the source, tests and cached-native results on base
`7300a3345b0a6af44d12cddcd7729819c75af16d`.

The final targeted diagnostic covers 16 previously examined papers and all four
methods, for 64 assessments in 91.893 seconds. Historical correct proposal counts
are unchanged: primary 7, GROBID 7, MinerU 6 and olmOCR 4. There are no new or lost
correct proposals and no historical false proposals in this diagnostic.

All 24 authored tests passed, including the negative continuation cases. A peer
assistant independently ran those tests and reviewed the bounded source and
case evidence. Repository validation ran 796 tests: 789 passed, seven skipped,
zero failures or errors. Package validation passed. Generated tracked validation
artifacts were preserved externally and the historical files restored.

| Case | Observed result | Remaining issue |
| --- | --- | --- |
| `f079` | Full candidate retained; historical recall restored from the first diagnostic's 0.165 to 1; still uncertain | The converter requests both numerator and denominator symbols from separate native lines. Their fraction structure is unresolved. |
| `f122` | Candidate retained; historical recall restored from 0.283 to its previous 0.998908; still uncertain | The requested combining hat differs from a native alphanumeric glyph mapping. No hat is synthesized or inferred. |
| `f131` | Existing hold retained | The radical is a standalone native line and closure remains unproven. |

Broken native control glyphs in `f153`, scientific scripts, diacritics and overbars
remain outside this repair. They need an explicitly versioned derived
transcription with source evidence. Historical text98 agreement cannot certify
those relationships.

This diagnostic reuses hash-bound native files and converter caches. It does not
re-extract or reverify original PDF bytes, qualify an unseen cohort, or replace
the pending fresh full200/four-method replay on the final integrated tree. There
were no new paid API calls or production graph writes. The original preservation
and source-reviewed notation gates remain open.

## Reproduce

Use the pinned runtime and authorized external dataset from the
[reproduction guide](31_first_page_parallel_reproduction.md). Output paths must
be new; authored fixtures are not substitutes for the original papers.

```sh
python -m unittest tests.test_parallel_source_native_prefix_v4 -v
python -m unittest discover -s tests -p 'test_parallel_source*v4.py' -q
python -m src.parallel_source_v4.geometry_probe \
  --data-root "${TRACE_GC_TEST_DATA_ROOT}" \
  --run validation_v3_private/issue17-followup-full200-20260928-02 \
  --output validation_v3_private/native-prefix-new-diagnostic/results.json \
  --cases f026 f079 f081 f111 f122 f131 f142 f153 f030 f192 f195 f039 f017 f186 f022 f106
```

The authorized fresh integrated replay uses the separate `extraction regression`
command from the reproduction guide, with `--native-mode fresh` and the exact
runtime lock. Its result must retain its own integrated code identity.
