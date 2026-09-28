# Native notation evidence sidecar

`native-notation-sidecar-v1` records character and drawing evidence without
changing the native extraction or approving a scientific transcription. Every
relation is an **unreviewed geometry candidate** with `accepted: false`.
The sidecar has no section owner, no transcription, no proposal, and no graph or
promotion integration. Existing source, selector, historical scores and receipts
remain unchanged.

## Why a separate representation is needed

Native text can preserve a mathematical character while losing its relation to
other characters: superscripts become ordinary digits, a numerator becomes a
separate line, or a radical occurs before its operand in a different native
block. Some PDFs also have incorrect Unicode mappings. Replacing a control
character or a misleading ordinary letter from its surrounding formula would
invent source text.

PyMuPDF RAWDICT exposes character positions and font metadata, while texttrace
exposes glyph identifiers and paint metadata. Their character sequences differ,
including synthetic spaces and ligatures. The sidecar retains disagreements and
multiple matches; it never treats them as an automatic replacement mapping.
[RAWDICT documentation](https://pymupdf.readthedocs.io/en/latest/textpage.html#structure-of-dictionary-outputs),
[texttrace documentation](https://pymupdf.readthedocs.io/en/latest/functions.html#Page.get_texttrace).

## Contract

1. Hash and open the same immutable original PDF bytes. The direct API snapshots
   mutable byte buffers and the supplied native list.
2. Re-extract physical page one under the pinned runtime. Its complete typed
   native representation must match the supplied native identity. A mismatch
   produces a typed hold with no projected characters or relations.
3. Project RAWDICT only when line count, exact codepoints, order, line boxes and
   block coordinates match. Each character keeps the original native line ID and
   half-open offset. No normalization, sorting into a new native line, or guessed
   mapping is allowed.
4. Record raw character, origin, character box, writing direction, size, font
   flags, font-resource references and embedded-font hashes. Retain texttrace
   origin matches with glyph ID, Unicode, opacity and sequence number.
   Unmatched/ambiguous traces, synthetic characters, control codes, U+FFFD and
   Unicode disagreements remain explicit uncertainties. Missing font-resource
   matches and conflicting matching font-program hashes also block relation
   seeding. A matched standard PDF font without embedded bytes is explicitly
   `not_embedded`; its geometric candidates retain all review requirements.
5. Bind PDF crop/MediaBox, rotation and coordinate transforms, plus a 144-DPI
   full-page image hash. Text evidence uses PyMuPDF unrotated page coordinates;
   the render descriptor retains rotation and pixel dimensions.
6. Record only measured candidate arrangements: smaller characters above/below
   a possible mathematical base; characters above/below a painted horizontal
   rule; or a native radical with an adjoining rule and possible operand.
   Each relation includes source character IDs and rule witnesses. Competing
   interpretations of one rule are explicitly linked.
7. Recheck input file hashes, the repository import closure and the complete
   pinned runtime receipt before and after immutable output publication.

`native-notation-geometry-candidates-v1` is not a formula parser. It can miss
relations or propose competing arrangements, including an italic footnote or
table border. Paint metadata does not prove that later content has not covered
the glyph. Semantic role, ownership and occlusion remain unreviewed on every
relation. Whole-page counts include body text and cannot measure abstract quality.

## Reproduction

Use the interpreter installed from the pinned runtime requirements in
[parallel source reproduction](31_first_page_parallel_reproduction.md). The source
and saved native files must be authorized external data; synthetic replacements
cannot stand in for the real diagnostic cases.

```powershell
& $PinnedPython -m src.parallel_source_v4.notation `
  --data-root $env:TRACE_GC_TEST_DATA_ROOT `
  --source 'authorized/source.pdf' --source-sha256 $OriginalPdfSha256 `
  --native 'authorized/native.json' --native-sha256 $NativeFileSha256 `
  --runtime-lock src/parallel_source_v4/runtime-windows-py312.lock.json `
  --output 'private-diagnostics/never-used-case-output'
```

The output contains `page.png` and `notation.json`. Keep them private: they contain
source paper content. A successful command means diagnostic capture completed,
not notation qualification. A source/projection mismatch returns a typed hold;
  input/runtime/code mismatches block publication. Repeating identical output is
idempotent; conflicting existing output is rejected.

The new module participates in the measured import closure. Earlier extraction
receipts retain their recorded code identity; they cannot be relabeled as runs
of this tree even though the source and selector implementations are unchanged.

```powershell
& $PinnedPython -m unittest tests.test_native_notation_v4 tests.test_parallel_source_native_prefix_v4 -q
```

## Nine exposed cases: remaining work

The companion [diagnostic receipt](../review/native_notation_sidecar_v1/diagnostic_receipt.json)
records input and code hashes, exact native projection and unaccepted output.
This is previously exposed development evidence with assistant source-image
inspection, not independent human qualification or a fresh 200-paper replay.

| Case | Observable evidence | Required next step and separate blocker |
| --- | --- | --- |
| f026 | Native radical, fraction rule and script positions exist. | Derive and review typed relationships; first-page closure is still unproven. |
| f059 | Native numerator/denominator and fraction rule are present. | A separately bound image correction already exists in the final-main audit; the native sidecar does not inherit its approval. Native section/geometry remains held. |
| f079 | Numerator and denominator are distinct native extents with a rule; the exact same-line bar repair is separate. | A typed fraction preserves both extents; full formula order and source ownership still require review. Never splice the numerator into a raw native line. |
| f081 | Fractions/scripts have source geometry; a vertical margin line interrupts native order. | An explicit derived order must account for the excluded margin with source evidence; no generic skip of unmatched text. |
| f111 | One base has separately positioned upper and lower scripts. | Preserve both relations in a derived expression and verify the complete source text. Ordinary digit concatenation is insufficient. |
| f122 | Hat and arrow components have native/trace Unicode disagreement and U+FFFD witnesses. | Source-image or verified font-glyph mapping review is required. Geometry cannot replace the raw ordinary characters. |
| f131 | Native row-start radical and an actual rule support an operand candidate. | Resolve the competing geometric interpretation and prove closure separately. |
| f142 | Abstract radical and rule exist; additional body radicals are separate. | Review notation within the abstract scope; unresolved body-lane ownership is a separate gate. |
| f153 | Native control codes correspond to unresolved trace glyphs; fraction rules remain observable. | Review font-glyph/image corrections for all delimiters and typed fractions. Never normalize away U+0000/U+0001. |

## Subsequent representation and acceptance gates

A future reviewed derivative can use typed base/script/fraction/radical nodes and
serialize them to a format such as MathML. That format represents relationships;
it does not establish PDF source fidelity.
[MathML Core](https://www.w3.org/TR/mathml-core/).

Before such a derivative is eligible for a promotion adapter it needs: exact
source/image/native/sidecar/reviewer binding; glyph-by-glyph coverage including
punctuation and unresolved mappings; independently checked reading order;
explicit source-bound exclusions; and the existing boundary/closure checks.
Image corrections must use their separate reviewed lineage. The original native
bytes and historical candidate observations remain immutable. This patch adds
none of those admission permissions.
