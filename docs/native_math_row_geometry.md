# Source-bound math row geometry

`native-logical-rows-v2` adds two bounded raw-order rules for issues
[#15](https://github.com/CompleteDotTech/jraphyte/issues/15) and
[#16](https://github.com/CompleteDotTech/jraphyte/issues/16). This supplements the
[original logical-row contract](33_first_page_logical_geometry.md); its historical
v1 receipt remains historical.

## Causes and supported rules

A radical can be extracted in its own native block before the paragraph that
contains it. The prior block-sharing condition prevented its placement between
two otherwise corroborated baseline fragments. A second case splits a paragraph
at an overlapping upper/lower script column: both native blocks begin on that
first visual row, leaving no preceding paragraph row for the prior rule.

The new rules require:

- **Separate math operator:** one visible Unicode `Sm` glyph with an exact native
  font-run partition; two unique, comparable baseline flanks; near-exact edge
  contact; and paragraph-width rows above and below in the flank owners' blocks.
- **Overlapping script column:** two native block starts, an exact and complete
  font-run partition, a one-character italic base followed by a smaller raised
  glyph and an aligned smaller lowered glyph in the next block, matching resumed
  baseline typography, and two distinct following paragraph rows in that block.

The existing horizontal-orientation, gap, occurrence-ambiguity and wide-anchor
guards remain active. A nearby paired gutter, missing flank or support row,
unowned support, malformed runs, duplicate competing flanks or overprinting
keeps the fragments separate. An isolated row-start radical and a fraction with
only one following paragraph row are outside these rules.

## Evidence and trust limits

The implementation changes only the derived logical view. Native bytes, line
IDs, offsets, boxes and font runs are unchanged. Selected spans still round-trip
to the original source. The view records the precise support IDs/boxes and script
run offsets; every new math join carries `notation_review_required: true`.
`transition_evidence()` propagates this flag to `logical_geometry`.

This flag must feed the selector's `math_review_required` field when integrating
the coordinated structure consumer patch. Geometry alone does not establish a
typed script, radical scope, fraction, corrected Unicode or scientific fidelity.
The raw sequence `lambda, 2, q` remains that sequence: no subscript/superscript
transcription is invented. Source-reviewed typed notation remains a separate
artifact with its own coverage and review requirements. Neither a located span
nor a bounded extraction proposal enables graph admission or promotion.

Current native caches lack direction and character origins. The existing
height/font-size check is conservative rotation evidence, not a general direction
guarantee. This change does not rewrite their schema or silently substitute a
RAWDICT projection. The previously exposed development papers are not an unseen
qualification sample.

## Reproduction

Use the frozen runtime described in the
[reproduction guide](31_first_page_parallel_reproduction.md):

```powershell
python -m unittest tests.test_parallel_source_math_rows_v4 tests.test_parallel_source_geometry_v4 -v
python -m unittest discover -s tests -p 'test_parallel_source*v4.py' -q
python tools/run_validation.py
python tools/validate_package.py
```

The new tests are authored fixtures. They cover raw order, immutable offsets,
duplicate occurrences, competing gutters, exact font-run provenance and the
unsupported isolated/fraction-like layouts. Real-paper results and their limits
are recorded separately in the public evidence receipt; source PDFs, images,
native text and full assessments remain in the authorized external evidence root.

## Observed bounded replay

The [public receipt](../review/native_math_rows_v2/evaluation_receipt.json)
binds a fresh-native diagnostic of 27 previously exposed papers across all four
cached conversion arms (108 assessments). Native identities were unchanged;
every selected span round-tripped to the source. Only f026, f111 and f142 changed
text, state or reason. The other 24 cases, including f059 and f131, retained those
outputs. There were no new historical boundary-and-98 false proposals or lost
previously correct proposals in this subset.

- f026 joins native lines `[14, 11, 15]` in visual order and remains held for a
  missing closing boundary.
- f111 joins `[3, 4]`; primary and GROBID now return bounded raw extraction
  proposals. Its flattened scripts still require typed notation review.
- f142 joins `[9, 6, 10]`; the primary remains held for section ownership, pending
  the separate structure patch. MinerU already supplies a located closing
  boundary and now returns a bounded raw proposal.

The recorded scientific-fidelity states remain unresolved: no old source-review
seal was transferred to a changed assessment. These are geometry observations,
not three newly certified abstracts. Focused V4 validation ran 355 tests
(353 passed, two skipped); full offline validation ran 971 (964 passed, seven
skipped). Package validation passed. The tests made no provider calls or
production graph writes.

After integrating both geometry and structure changes, the exact final tree
requires a new full 200-paper, four-arm replay and the separate source-fidelity
and promotion gates. A subset diagnostic cannot close those gates.
