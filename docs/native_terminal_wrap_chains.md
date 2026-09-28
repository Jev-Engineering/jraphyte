# Source-owned short final wrap lines

The source locator preserves the existing column-width constraint and adds one
versioned exception: `native-terminal-wrap-chain-v1`. It extends a logical
paragraph chain with a short final line only when native ownership and nearby
paragraph geometry corroborate that line.

## Observed cause

In the exposed development case f142, the logical row correctly orders native
lines `[9, 6, 10]`, placing the original radical between its baseline flanks.
However, the abstract's final native line 16 is much shorter than the paragraph.
The prior width-ratio constraint excludes it from every wide logical chain.
Only the original extraction-order chain can then match the whole paragraph;
the radical at earlier native line 6 falls outside that selected interval.
The earlier geometry repair therefore did not restore the radical in emitted
text. Its notation review flag correctly remained set.

## Bounded extension

The new chain is an additional search candidate. All original width-local and
native-order candidates, occurrence ambiguity checks, and the 98% alignment
floor remain available. No native JSON, font run, text, ID, offset or box changes.

An added line must satisfy all of these conditions:

- It is the actual last native line of its block, with unique native block
  indices and two immediate predecessors. Each belongs to a single native-line
  logical row.
- Both predecessors already belong to the original wide chain. They have
  matching full paragraph widths; the final line is distinctly narrower.
- Dominant native font, point size, bold/italic flags and color agree. All three
  lines pass the existing horizontal geometry check, share a left edge, and have
  consistent normal line spacing.
- The final line contains a sentence ending. It is eligible under the caller's
  source region constraints.
- No intervening source row or simultaneous neighboring lane contradicts that
  final continuation. Full-page native context is used even when a converter's
  region boxes exclude later lines.

Located results record `chain_evidence` with the version, original block and line
indices, supporting native IDs/boxes, font identity and raw-order-only scope.
Selected offsets still round-trip to their original native lines. Input duplicate
line IDs are rejected by `validate_lines()` before production assessment.

This rule deliberately holds unfamiliar typography, missing metadata, multiple
short terminal lines, duplicate block indices, unowned rows, large vertical gaps,
rotated fragments, and competing columns. It does not infer a new semantic
section boundary or a general reading direction.

## Validation and remaining gates

Authored tests cover exact raw operator retention, unchanged source objects,
hidden later owner lines, an excluded terminal region, duplicate native IDs and
block indices, typography/spacing mismatches, neighboring columns, and duplicate
paragraph occurrences. Run them with the pinned PDF runtime:

```powershell
python -m unittest tests.test_parallel_source_final_wrap_v4 tests.test_parallel_source_math_rows_v4 tests.test_parallel_source_geometry_v4 -q
python -m unittest discover -s tests -p 'test_parallel_source*v4.py' -q
python tools/run_validation.py
python tools/validate_package.py
```

The [paired diagnostic receipt](../review/native_terminal_wrap_v1/evaluation_receipt.json)
compares the same 27 exposed cases and all four cached converter arms before and
after this change. The only text/span change is f142: all four arms gain exactly
native position `(6, 0)`, the radical, with no removed positions or reordered
existing positions. Proposal, status, reason and math-review states are unchanged.
The final local gate ran 1,004 tests: 997 passed and seven skipped; package
validation passed. Forty focused geometry/wrap tests passed.

The comparison binds source/page/image/native, cache, code and runtime identities
and rechecks them before publishing a result. This is cached-native replay, not a
new converter or native extraction run.

The [full 200-paper comparison](../review/native_terminal_wrap_v1/full200_cached_comparison.json)
then replays all 800 assessments from the exact sealed fresh-native input of the
integrated geometry/structure tree. It includes all 91 historical correct IDs.
The primary/GROBID/MinerU/olmOCR correct counts remain 79/73/67/64, with zero
false proposals and no newly lost correct IDs. Historical preservation still
fails for the same 16 cases (75 of the historical 91 retained).

Only f142 and f102 have text/span changes. In addition to f142's raw radical
recovery, the held f102 olmOCR candidate no longer appends the separate ARTICLE
INFO column. Its hold reason changes to an unverified abstract start heading;
it gains no proposal or accepted source spans. Four existing converter
error/truncated results are byte-identical and remain unassessed. This empirical
comparison used existing native/converter outputs and made no model calls.

Raw radical recovery is not scientific-fidelity certification. The existing
`math_review_required` flag remains set; full-region source review and any typed
notation requirements remain separate. No graph admission or promotion policy
changes. The integrated final tree still requires its preservation and
source-fidelity gates; this bounded comparison does not turn the existing
preservation failure into a pass.
