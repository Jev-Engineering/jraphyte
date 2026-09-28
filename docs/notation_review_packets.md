# Full-region notation repair preparation

`python -m src.paper_review_packets` prepares private review packets for an entire
frozen cohort of failed native proposals. It writes no transcription, review,
acceptance, or graph record. Every existing notation failure remains a failure.

## Why a separate packet is needed

Character-for-character native text can flatten scientific roles: subscripts,
superscripts, overbars, diacritics, and fractions. A correct abstract boundary and
high alphanumeric overlap do not establish notation fidelity. Reviewing one
symbol also does not establish fidelity of the full abstract.

The existing `trace_gc.reviewed_notation` contract produces a reviewed **fragment**
derivative. There is no supported whole-abstract composer. Its MathML and Unicode
results cannot be concatenated into a promotion candidate through this tool.

## Frozen inputs

The protocol is a JSON object with exactly these keys:

| Key | Value |
| --- | --- |
| `version` | `notation-repair-cohort-v1` |
| `scope` | `previously_examined_development` or `authored_fixture` |
| `results` | Descriptor of the prior extraction result |
| `native_manifest` | Descriptor of its fresh native manifest |
| `reviews` | Descriptor of the attributed `promotion-fidelity-review-v1` supplement |
| `cases` | Case ID to the five asset descriptors below |

Each descriptor is exactly `{"relative": "path/under/data/root", "sha256": "..."}`.
Each case supplies `source`, `page`, `image`, `native`, and `assessment`.
The assessment must be the complete native primary proposal recorded in the
result's assessment manifest. The cohort must contain every notation-failed
case in the supplied frozen supplement. The caller is responsible for pinning
the intended supplement; a content hash is an identity, not reviewer authority.

The tool reads and hashes the same bytes it verifies. It rerenders the original
PDF first page, checks the saved page and review image, regenerates the immutable
native representation, validates each selected offset, and checks the existing
negative observation's source, page, image, native, text, and assessment identities.
Invalid ranges are rejected before iteration; selected extents are capped at
100,000 native characters.
It retains the prior execution method map and separately pins current code and
runtime. This is **not** a new extraction run or permission to rebind a review to
a changed assessment.

## Commands

Use the pinned PDF interpreter and runtime lock. Both output and input paths are
relative to the authorized private data root. Use a fresh output directory.

```powershell
python -B -m src.paper_review_packets prepare `
  --data-root PRIVATE_ROOT --input cohort/protocol.json `
  --input-sha256 PROTOCOL_SHA256 --output cohort/packets `
  --evaluated-at 2026-09-28T20:00:00+00:00

python -B -m src.paper_review_packets verify `
  --data-root PRIVATE_ROOT --input cohort/packets/receipt.json `
  --input-sha256 RECEIPT_SHA256
```

An explicit `--runtime-lock PATH` is supported. Verification reconstructs all
packets and compares every output. Source, code, runtime, or output drift blocks
readback. A publication integrity failure leaves an `INVALIDATED.json` marker;
restoring inputs does not authorize that output directory.

## Packet contents and review sequence

Each case contains the original-source full page at 144 DPI, a navigation crop,
the native notation sidecar, and `packet.json`. The crop bounds cover selected
native lines plus a margin. They are navigation context and do not establish
section ownership or complete symbol coverage. The full page is always retained.
The packet partitions selected versus surrounding glyphs and lists uncertainty;
it retains raw offsets and existing negative evidence. Review and transcription
fields remain null.

1. Inspect the original full page and all abstract paragraphs/subsections. Check
   the title, metadata, adjacent columns, and closing section transition.
2. Inventory every visible scientific role across the whole abstract, including
   glyphs outside selected native spans and painted accents/rules. Ambiguous
   source mappings remain unresolved.
3. Select a representation only after inspection. A faithful Unicode image
   transcription may use the existing image route. The fidelity comparator also
   recognizes explicit braced script text such as `x^{2}` and `T_{S}`; a separately
   reviewed image transcription and reference can preserve those roles without
   inventing unavailable Unicode characters. This is no automatic conversion or
   algebraic-equivalence claim. Unsupported fractions, radicals, accents, or
   combinations remain held unless a faithful representation passes the existing
   whole-region source review. Fragment output alone is insufficient.
4. For the image route, obtain fresh exact-code OCR execution evidence, retain
   raw errors, and review any corrected text against the original. Supply all
   existing image preparation/candidate/execution/raw/output/review assets plus
   full-abstract scope and fidelity evidence. Do not manufacture native offsets.
5. Recheck text, reading order, all notation, boundary, and exclusions across the
   final full region. Preserve attributed development exposure and the original
   failure. This tool records no new certification.
6. After the final extraction tree is frozen, use a fresh complete regression and
   the existing explicit failed-native image replacement policy. The exact
   candidate, source, review, configuration, preservation, and fidelity gates
   remain required. Healthy native proposals cannot be replaced through this path.

Packets are private because they contain paper text and source renders. Public
handoffs should include only safe case IDs, hashes, counts, and unresolved reasons.
Authored tests exercise integrity, never real-paper quality or independent human
qualification. No OCR, provider, model, graph, or retrieval call is made by this
command. The module lives outside the extraction method-map seed directory and
pins its own bytes separately.
