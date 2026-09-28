# Source-linked interior footnotes

`source-linked-interior-footnote-exclusion-v1` is a bounded transformation of an
already complete native proposal. It removes an interior prose footnote marker
only when native typography, source positions and a unique source-owned footer
note corroborate that role. It does not repair notation, alignment or closure.

## Cause and rule

The prior selector could retain a superscript footnote numeral between two
abstract sentences. A native font run preserves that numeral as an ordinary
character, and the earlier terminal-marker rule handles only paragraph endings.
In the exposed development case f149, the linked note is labelled `page_footer`
by the cached converter. A label alone is insufficient evidence.

The new rule requires all of the following:

- An existing complete native proposal with a source-located closing boundary.
- A separate, smaller native superscript run after ordinary sentence punctuation
  and before another prose sentence, with nonitalic baseline flanks.
- Bounded horizontal attachment and vertical displacement on the same native
  line. Disconnected annotations, mathematical bases and baseline numbers cannot
  supply this evidence.
- Exactly one corresponding converter footer/footnote region and exactly one
  matching full native marker token in the footer area. The entire native note
  line must be located, including its smaller raised marker and following prose.
  Cropped tokens, duplicate native notes and numbered body headings fail closed.

All questions about candidate markers are resolved together. One ambiguous
marker holds the entire result and retains its original text. An ordinary
scientific script without the required prose-footnote context remains untouched.

## Evidence and consumers

Raw native JSON, IDs, boxes, font runs and character offsets are unchanged. The
assessment retains a sealed unsplit parent, note inputs bound to that parent,
source-owned decisions, exact excluded spans and ordered remaining spans.
`span_joiners` distinguishes an empty join within a split native span from the
original newline between native spans. No replacement glyph is inserted.

`verify_interior_footnote_exclusion` independently checks the parent seal,
source/page/native identities, exact native readback and unique relocation. It
then replays the exclusion rule and compares the full proof, text, ordered spans
and joins. Retrieval and promotion ingestion use this same verifier; a caller
cannot provide arbitrary rewritten text or unchecked joiners. The closure-only
review adapter cannot settle an unresolved interior marker.

Fields remain retrieval candidates with `source_reviewed=false`. Assessments
retain `eligible_for_jev=false` and `verified_admission=false`. A correct footnote
exclusion does not certify the rest of a scientific transcription.

## Verification and reproduction

Public tests use authored source geometry and prose:

```powershell
python -m unittest discover -s tests -p test_parallel_source_interior_footnotes_v4.py -v
python tools/run_validation.py
```

The private replay uses only the authorized data root documented in
[the parallel reproduction guide](31_first_page_parallel_reproduction.md). The recorded
targeted runner is an external diagnostic script, not a substitute corpus:

```powershell
& $TRACE_GC_LOCKED_PYTHON "$env:TRACE_GC_TEST_DATA_ROOT/validation_v3_private/issue17-interior-footnote-20260928-01/targeted_runner.py"
```

The runner requires a new output directory, the pinned runtime lock, all 200
original/source/cache preflight checks, the saved native manifest, and the
unchanged frozen labels before measuring its 16 cases across four methods. It
also runs the actual field builder against f149's original PDF, page image,
saved native representation and corrected/held assessments. The public receipt
records the immutable result path and hashes without publishing paper text.

These cases were previously exposed development data. Legacy boundary/text98
scores are not notation certification, and this targeted replay does not replace
the required integrated full-200 preservation and source-fidelity gates.

The frozen targeted04 diagnostic completed 64 assessments. Only f149 changed:
the primary and GROBID arms exclude one linked marker and expose the exact
remaining 1,510 characters through `build_fields`; MinerU and olmOCR retain an
uncertain state and expose no abstract field. All other 15 cases, including
f195, are unchanged across all four arms. Original PDF, saved page/image/native
bytes, assessment seals and final code identity were rechecked. The nine
historical math/geometry holds remain held. Full-200 integrated acceptance and
source-reviewed scientific fidelity remain outstanding.

See [the diagnostic receipt](../review/interior_footnote_exclusion_v1/diagnostic_receipt.json)
for exact hashes, the preserved earlier attempts, test evidence and scope limits.
