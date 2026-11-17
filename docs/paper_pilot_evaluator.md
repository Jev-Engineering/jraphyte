# PaperPilot aggregate evaluator

`trace_gc.paper_pilot_evaluator` is a public, offline aggregate evaluator for
[issue #23](https://github.com/Jev-Engineering/jraphyte/issues/23). It reads
sanitized receipt rows exported from a `PaperPilot` run and compares them with
a frozen evaluation protocol. **It does not run a model, sign anything, grant
authority, judge entailment or qualify #23.** Its output never contains source
text, quotes, question text or answer text. A run with `execution_mode:
SYNTHETIC`, or any recovery row labelled `AUTHORED_SYNTHETIC`, is reported as
`AUTHORED_SYNTHETIC_MECHANICS_ONLY` whatever the verdict.

The real-paper pilot still needs the private cohort, attributed reviews, actual
model execution and the #20/#22 receipts. This evaluator only gives that run a
public, reproducible way to count its rows.

## Workflow

1. Inside the private application, reopen the run as usual (same config, trust,
   callbacks and backend) and call `export_receipts(pilot)`. The exporter reads
   the verified checkpoint, the backend journal and the **current** source and
   assertion status. It emits identifiers, hashes, page numbers, review kinds and
   states. Application-assigned references use SHA-256 of their exact UTF-8
   identifiers. Claims are identified by position within their answer. Questions
   use the frozen protocol's SHA-256 references. A denied assertion contributes
   its fingerprint and access status. It contributes no evidence links or
   provenance, and a denied source contributes a local marker.
2. Freeze the evaluation protocol before inspecting answers. See
   [`examples/paper_pilot/evaluation_protocol.synthetic.json`](../examples/paper_pilot/evaluation_protocol.synthetic.json).
   `question_sha256(text)` gives the question identifier.
3. Record each required recovery scenario as a row produced by the application's
   own scenario run: `{scenario, status: PASS|FAIL|HOLD, receipt_sha256,
   evidence_class: AUTHORED_SYNTHETIC|REAL_RUN}`. A required scenario without a
   row is `NOT_RUN`. The evaluator checks the row's shape, not the receipt the
   hash refers to.
4. Run the command:

```bash
trace-gc paper-pilot evaluate receipts.json --protocol protocol.json \
    --recovery recovery.json --output report.json
```

It exits 1 with a structured `EVALUATOR_INPUT` error for any extra field,
free-text value, duplicate row, undeclared scenario or malformed hash. The public report emits SHA-256 references for caller-supplied identifiers. Keep the receipt inputs and identifier mapping private. No
report is written in that case.

## Row rules

| Section | PASS | Not PASS |
|---|---|---|
| `questions` (SUPPORTED) | Latest attempt has a complete preparation, response and attributed review chain with state `SUPPORTED`; every claim judged `true`; every citation resolves to evidence → source → original PDF hash → physical page (and crop for image sources); every cited source currently readable; each `required_source_ids` entry cited; graph version unchanged since the answer | `FAIL`: rejected claim, abstention, missing judgment, missing evidence, page or crop lineage, required source not cited. `INVALIDATED`: cited source withdrawn or denied. `HOLD`: pending stage or graph changed. `NOT_RUN`: no attempt |
| `questions` (ABSTAIN) | Latest attempt abstained at its completed preparation or model-response stage with a current retrieval context and graph version | `FAIL`: an answer was drafted or reviewed. `HOLD`/`NOT_RUN` as above |
| `assertions` | Expected assertion active and currently authorized, with a journal transaction at a recorded version whose plan hash matches, an identified `SELECTED` resolution and one or more identified `OK` observations | `FAIL`: incomplete chain or unexpected assertion. `INVALIDATED`: inactive or currently denied. `NOT_RUN`: not published |
| `citation_chains` | Each claim of each latest answer has complete, currently readable chains and a current retrieval context | `FAIL` / `INVALIDATED` as above. `HOLD`: context refresh required |
| `recovery` | Supplied row says `PASS` | Supplied `FAIL`/`HOLD`, or `NOT_RUN` |

`abstention` summarizes the ABSTAIN questions on their own. Each section reports
its denominator and counts for every status. The verdict is `FAIL` if any row
fails, `PASS` only if every row passes, and `HOLD` otherwise.

Question and citation rows score the latest attempt in checkpoint order. If
that attempt cites a withdrawn or denied source, its citation rows are
`INVALIDATED`. A fresh attempt replaces those rows in the evaluation. Use the
exported attempt history and predeclared recovery rows to review the withdrawal
sequence. Older exports without a retrieval-context check yield `HOLD` for
abstention until a current receipt is exported.

## Boundaries

- Claim support is the attributed answer review recorded by `PaperPilot`.
  Matching citations mechanically does not establish entailment.
- Extraction completeness, evidence quality and graph correctness still need
  their own predeclared attributed reviews. The evaluator counts source reviews
  and their kinds; it reports `independent: 0`.
- The receipt file is unsigned. The report pins `protocol_sha256`,
  `receipts_sha256`, `recovery_sha256`, the evaluator code SHA-256, and the
  run's checkpoint and journal heads. Bind those values in the private run's
  signed records.
- `qualifies_issue_23` and `authorization_granted` are always `false`.
