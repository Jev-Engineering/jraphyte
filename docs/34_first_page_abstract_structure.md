# Source-owned abstract paragraphs and subsections

The experimental selector records `abstract_structure_version` as
`source-abstract-sections-v1`. Its inputs remain the first physical page's
verified native lines and authentic cached converter output. It does not change
native line IDs, offsets, text, boxes, historical comparison scores or graph
admission rules.

## Why the section model changed

The earlier selector inferred structured scope from the first converter region,
required a small English verb vocabulary for unlabelled abstracts, and compared
each paragraph against the entire scholarly abstract. Internal Methods/Results
sections and neighbouring abstract paragraphs consequently became boundaries or
competing candidates. Matching a short `Abstract` query could also be ambiguous
inside a paragraph containing words such as “abstractions.”

[NLM describes several structured-abstract formats](https://www.nlm.nih.gov/bsd/policy/structured_abstracts.html),
including variation between journals. [JATS permits paragraphs and sections
inside an abstract, and distinguishes multiple abstract uses](https://jats.nlm.nih.gov/publishing/tag-library/1.3/element/abstract.html).
These support a section representation. They do not establish ownership or
closure for an individual PDF; those decisions need its source evidence.

## Evidence and conservative decisions

- **Start:** an inline Abstract label is bound to its uniquely located full
  paragraph and the beginning of its original native line. A converter cannot
  erase a Graphical prefix or turn an interior occurrence into a heading.
- **Subsections:** the opening abstract prose must itself begin with a native
  inline label. At least three distinct labels must occur within a consistent
  source text size and section lane. Conventional subsection names may be plain;
  custom labels need distinct inline typography. A later body Methods/Results
  pair cannot retroactively establish a structured abstract. Numbered outer
  sections retain their boundary role.
- **Paragraphs:** matching scholarly fields can corroborate a contiguous source
  paragraph group without particular English verbs. Source title typography,
  title labels, authors, Highlights, dedications and other section contexts
  remain rejection or review evidence. Adjacent candidates collapse only within
  the same located, closely spaced source style and lane. Parallel columns and
  distinct sections remain competing candidates.
- **Native order:** when another column's objects interleave the source order,
  separately located paragraphs may be composed with whitespace separators.
  This requires exact source text, monotone paragraph extents, consistent lane
  widths, no duplicate positions and no omitted same-lane native characters.
  A global ambiguous match or an individual column/alignment failure stays held.
- **Closure:** classification labels are source metadata. A proceedings footer
  requires a located event block, its adjacent source date and a native copyright
  footer. A narrower structured abstract may close before a wider body only
  with its completed subsection sequence, native size transition and a located
  numbered outer heading. Typography changes alone remain review holds.
- **Title pages:** punctuation, whitespace and page numbers do not certify that
  an abstract ends on page one. Cases with no located closure retain their text
  and explicit hold until attributed source review supplies the missing evidence.

`subsection_scope` and `region_ownership` retain the source spans supporting the
decisions. `native_sha256` is the canonical native representation hash used by
the extraction harness. `section_owner="abstract"` is emitted only for a
source-bounded complete candidate. This is a selector claim to compare against
separate attributed review; it does not create reviewed labels or notation
certification. `eligible_for_jev` and `verified_admission` remain false.

The selector accepts no manual-closure override. A separate attributed review
may resolve a held case only in a new derived artifact bound to the original
assessment seal, text/source/page/native/image hashes, exact accepted spans and
source-referenced excluded spans. Its closure description must identify actual
evidence, such as the distinct following synopsis or a separately hashed image
of page two beginning the body. It must not invent a heading or append later-page
text. Review of these already examined development cases must disclose prior
exposure; it is neither blinded nor independent human qualification. Automatic
and manually resolved results must be reported separately.

## Reproduce

Use the pinned runtime and authorized original data described in
[the reproduction guide](31_first_page_parallel_reproduction.md). Authored
fixtures cannot replace the original 200-paper gate. Keep private paper text,
labels, full assessments and source maps outside the repository.

```sh
python -m unittest discover -s tests -p 'test_parallel_source*v4.py' -q
python -m src.parallel_source_v4.extraction regression \
  --data-root "${TRACE_GC_TEST_DATA_ROOT}" \
  --source-map validation_v3_private/parallel-v4-source-map.json \
  --native-mode fresh \
  --output validation_v3_private/abstract-structure-next
python tools/run_validation.py
python tools/validate_package.py
```

The full replay measures all 200 originals and all four authentic converter
arms. A preservation failure is exit 1; blocked input/runtime checks are exit 2.
Neither authored tests nor selected cached-native diagnostics establish unseen
paper precision. Report the historical boundary/text score separately from the
attributed fidelity metric and its unresolved review dimensions.

## Measurement status

The frozen full replay completed all 800 assessments in 824.808 seconds. Source
preflight and the historical saved-assessment replay passed. All 200 native
representations remained byte-identical to the combined prerequisite baseline.
The [public receipt](../review/first_page_abstract_structure_v1/evaluation_receipt.json)
records the runtime, source hashes, external evidence hashes and per-ID changes.

| Converter arm | Correct proposals before | Correct proposals after | False proposals after |
| --- | ---: | ---: | ---: |
| Primary structure | 68 | 74 | 0 |
| GROBID | 63 | 68 | 0 |
| MinerU | 65 | 68 | 0 |
| olmOCR | 60 | 64 | 0 |

These counts use the historical boundary plus text98 metric. No arm lost a
correct proposal relative to the combined prerequisite baseline. Primary gains
were `f017`, `f080`, `f084`, `f113`, `f178` and `f186`; `f195` remained correct.

The original-91 preservation gate still **fails**, with 20 losses instead of
26. That historical contract uses text98; its exact IDs and the stricter boundary
score are recorded separately. Primary has 37 withheld complete cases overall.
`f007`, `f085` and `f131` retain matching text without source-located closure;
`f119` and `f150` retain matching text with unresolved section ownership.
The held set also includes candidate, reading-order and notation mismatches;
manual closure alone cannot resolve those defects. Every attributed fidelity
dimension remains unresolved because this run supplied no reviewed references.
It establishes development regression results, not promotion or unseen-paper
qualification.

The focused suite ran 245 tests (244 passed, one skipped), including 25 new
authored tests. Repository validation ran 664 tests (658 passed, six skipped),
with no failures; package validation passed. No paid API calls or production
graph writes occurred. Post-integration promotion and source-review gates remain
required.
