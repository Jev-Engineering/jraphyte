# Preregistered paper qualification evaluator

`src.paper_qualification_v1` evaluates the frozen issue #20 study. It does not
download papers, run converters, issue review signatures, enroll trusted keys,
or register a graph qualification. `trace_gc.qualification.evaluate_labels` and
`QualificationRegistry` retain their existing contracts.

No real qualification is supplied by this change. The current development #19
receipts fail preservation and source fidelity. No prospective paper, image or
prediction was opened to implement or test this evaluator. Its tests use authored
protocol records, ephemeral test keys and source-rendered fixtures; fabricated
converter/OCR outputs are clearly identified as test data.

## Frozen study and statistical unit

The evaluator consumes the externally pinned current preregistration pointer,
its base JSON/Markdown, both metadata-frame amendments and the approved amendment
04 on normalization and audit selection. It verifies all listed
artifact hashes. The recent returned OAI frame supports primary estimates; the
historical hep-th frame supplies separate challenge screening. Neither represents
all arXiv or all scholarly papers.

The exact seed, numeric targets, sampling contract and review policy match the
frozen protocol. Different thresholds or sampling require a new protocol and
implementation version before source access.

| Primary requirement | Gate |
| --- | --- |
| Fixed primary size | 400 distinct works |
| Accepted outputs | At least 200 |
| Resolved complete references | At least 200 |
| Strict accepted precision | Zero false accepts and one-sided 97.5% exact lower bound at least 0.98 |
| Strict complete recall | One-sided 97.5% exact lower bound at least 0.80 |
| Unresolved references | At most 20; all enter recall denominator as misses |
| Accepted unresolved reference | A precision failure |

Strict success requires a complete accepted output and passing transcription,
notation, extent, order and source-location evidence. Legacy alphanumeric scores
cannot override these checks. The two primary bounds have at least 95% joint
coverage under the preregistered binomial model. The existing exact binomial
implementation is reused and its file is included in the evaluator identity.

Primary selection takes the first 400 eligible recent work IDs by the frozen
`primary` rank. The next 600 form the recent screen; 600 historical works use
`historical-screen`. All 1,200 screen outcomes must exist. Source-only tags select
the first eligible works under `challenge:<stratum>`; overlapping strata share a
single case. Quotas are 20 each for partial, absent, structured, multicolumn,
title-page, image-only and broken-mapping pages, plus 40 notation cases. The union
is at most 180 and never enters primary estimates.

Every challenge stratum has zero false accepts. A stratum with at least ten
resolved complete references needs conservative complete-recall point estimate
at least 0.80. Image-only and broken-mapping strata each require at least ten
resolved complete references and successful use of the actual image route.
Two-sided 95% exact intervals are reported per stratum; these do not certify 98%
precision in each rare stratum. Missing representation is `BLOCKED`.

## Trust and chronology

Reference review is `internal-attributed-blinded-source-first-v1`.
`independent_human_qualification` is always false. Named assistant roles include
custodian, source reviewer, adjudicator, candidate reviewer and execution operator.
Their context IDs, principals and known model versions are recorded; an unknown
model version is null. Reference, candidate and adjudication contexts are separate.

The caller supplies an application-owned `TrustStore`; this evaluator cannot
enroll keys. Four existing `RUN_CHECKPOINT` receipts form a signed hash chain:

1. `configuration_frozen` binds preregistration, policy, exact image-enabled #19
   acceptance, its source map, genuine converter access and assigned roles.
2. `cohort_frozen` additionally binds the fixed sampling and all source assets.
3. `references_frozen` additionally binds all screening and reference decisions.
4. `predictions_frozen` additionally binds the complete execution artifact.

Every payload also binds study ID, execution mode, review policy, custodian or
operator context, and the previous receipt digest. An authored bundle cannot
be relabeled `REAL_LOCAL` by editing and rehashing its outer manifest. Issuer
enrollment must authorize the declared mode. A test signature grants no real
execution or qualification authority.

Phase timestamps are strictly ordered. Reference access events fall between
cohort and reference freezes. The first source event receives only the original
image; later source events can receive its immutable native representation.
Their input-hash allowlist excludes metadata abstracts, converter outputs,
predictions and candidate corrections. Candidate image review has a separate
source/candidate input manifest and occurs after reference sealing. Converter
generation starts after reference sealing. Initial decisions and every amendment
remain in the signed reference history.

Uncertain reference history and every image transcription require adjudication.
The fixed `reference-audit` rank selects 10% of otherwise resolved references,
excluding mandatory uncertainty/image adjudications, rounded up. Required audit
and adjudication events must endorse the exact final frozen decision. Decision
events follow the preserved history in order; an old uncertain decision cannot
authorize a later complete label. A material audit error requires a full-dimension audit
and adjudication records across the cohort before predictions. Unresolved
disagreement cannot certify a complete reference. Unavailable sources can receive
an explicitly source-free technical adjudication while remaining unresolved.

Signatures authenticate the enrolled issuer's statements and artifact chain.
They are not an external time service and cannot prove that a reviewer told the
truth or that an unlogged access never happened. Review access control and the
custodian's actual record keeping remain required operational controls. No human
independence or external accuracy claim is inferred from multiple assistants.

## Artifact contract

All artifact descriptors are exactly `{relative, sha256}` beneath an explicit
authorized external root. JSON parsing rejects duplicate keys and nonfinite
values; parsing and identity use the same bytes. Large model assets are hashed
as streams. All consumed bytes, code, runtime and the regression prerequisite are
rechecked before evaluation completes and before publication.

The bundle has the exact fields checked by `evaluate`:

- `version`, `study_id`, `execution_mode` (`REAL_LOCAL` or
  `AUTHORED_CONTRACT_TEST`), `roles`, and the four `phases`.
- Descriptors for `preregistration`, `configuration`, `regression`, `source_map`,
  `access`, `sampling`, `screening`, `sources`, `references`, and `execution`.

The `regression` descriptor must identify a privately pinned **PASS** receipt
verified by the existing #19 verifier under this exact policy/code/runtime. A
native-only receipt is insufficient. This check precedes opening any selected
prospective source artifact. Its nested input and derived-output hashes are also
retained for final readback.

`access` pins all four genuine local converters, Windows image OCR, executable
and model assets, licenses, revisions, device, prompts, decoding, request limits,
retries, timeout, concurrency and crop policy. Each engine requires a typed local
readiness receipt linked to its assets and raw probe stdout, completed before
configuration freeze. Model presence or an arbitrary successful exit does not
prove an authentic conversion: the custodian must verify the actual recorded
engine and execution.
For Windows OCR, `image_ocr.decoding` is the complete raw producer configuration,
including component and resource hashes, language, pixel/alpha settings and
helper identity. The actual OCR revision and this entire configuration must match
the frozen access record; internal candidate consistency alone is insufficient.

`sampling` contains both exact 2,000-work metadata frames, the reconciled exposed
work IDs, eligibility records and the fixed 400+600+600 membership. Work IDs are
lowercase, normalized and versionless; original selected version IDs are bound
separately. Its `exposure_snapshot` descriptor binds a current
`paper-exposure-snapshot-v1` inventory with work IDs, source/page hashes and DOI
aliases. The inventory preserves every baseline exposure and byte alias, binds
the reconciliation time and includes newly exposed work and alias identities.
`screening` supplies all 1,200 source-only outcomes and the deterministically
selected challenge union. Source/page byte duplicates, known exposed bytes and
duplicate DOIs block the study. Corrupt, encrypted and unavailable assigned
sources stay unresolved in their original denominators.

`sources` records all 1,600 assigned outcomes. Available cases have original PDF,
first-page PDF, original-render PNG and native-line JSON descriptors. The existing
source verification renders and parses the exact hash-checked in-memory buffers,
checks the page copy, image and native extraction, and preserves raw native
offsets. Native equality uses canonical digests so booleans cannot impersonate
integer IDs. A transient file swap between initial/final hashes cannot substitute
an unbound render. Unavailable
cases have explicit reasons and no fabricated source assets.

`references` records every evaluated work's initial/final reference, preserved
history, attributed input events, disagreements, adjudication and audit evidence.
Complete references carry the existing #14 fidelity contract. Image references
add `source-first-image-reference-v1` transcription identity and contiguous
Python Unicode code-point spans; these never claim native offsets. Their separate
`source_extent_proof` binds the original image and a nonblank following section
transition witness before predictions exist.

Each execution case records all four assessment descriptors, five converter
input-cache descriptors, typed per-method producer receipts, original failures,
the selected assessment and its route. Producer receipts bind source/page,
engine/model access, policy, code/runtime/limits, execution timestamps and exact
cache outputs. Every assessment is deterministically replayed through the
existing extraction adapter and compared in full, including its seal. Copying a
primary assessment into another arm is rejected.
All four arms retain per-case fidelity and separate primary/challenge summaries;
the three diagnostic arms cannot silently replace the selected primary policy.

An image selection additionally supplies current preparation, raw OCR,
execution, crop, reviewed candidate, catalog, handoff and `scope_review` artifacts. Source
rendering, single-correction lineage, reviewer context/time, catalog reconstruction
and typed image evidence are checked. The attributed scope review binds candidate
identity, complete extent, native/image disagreement review, no page continuation
and an actual disjoint following source region. The selected assessment seals
that scope review. Blank or solely preceding boxes cannot establish closure.
An originally proposed native candidate needs the explicit failed-native policy
and a parsed, hash-bound `paper-candidate-failure-v1` observation of the exact
assessment, text, source, page, native and image identities. It retains the
observed mismatch, attribution and time; candidate access includes the failed
assessment itself. A free-standing evidence hash is insufficient;
identical bad notation cannot count as repaired. Final source-fidelity comparison
uses the separately frozen reference. Raw OCR errors, corrections and final image
proposals have separate counts.

Stage reports cover converters, OCR, source review, adjudication, candidate review
and evaluation, including calls, failures/retries and review counts. Unavailable
timings are null. Paid calls/spend and graph writes must remain zero.

## API and immutable results

The API accepts a previously configured trust store and externally reviewed raw
hashes. It creates no review records or inference jobs:

```python
from src.paper_qualification_v1 import evaluate, publish, verify_published

result = evaluate(
    data_root, bundle_descriptor,
    expected_preregistration_sha256=preregistration_sha256,
    trust=review_trust_store,
)
receipt = publish(
    data_root, fresh_output_relative, result,
    expected_preregistration_sha256=preregistration_sha256,
    trust=review_trust_store,
)
```

The variables above are real authorized inputs, not defaults supplied by an
untrusted bundle. Before publishing any evidence-bearing result, `publish`
recomputes the complete evaluation under those external trust anchors and
requires exact result equality, then rechecks all inputs. A fabricated PASS dict
or modified metric fails before any output directory is created. Only a strictly
shaped nonqualifying BLOCKED error can be published without study evidence.
It writes immutable `evaluation.json` and a redacted
`public-summary.json`. Private paths, per-work rows, study identity and review
audit membership are omitted from the public summary. `verify_published` takes
the private receipt's externally pinned descriptor, original preregistration
trust anchor and trust store, then recomputes the complete evaluation. A copied
`PASS` field or a public summary cannot qualify a study.

`AUTHORED_CONTRACT_TEST` can return
`AUTHORED_CONTRACT_PASS_NOT_QUALIFICATION`; `qualification_pass` remains false.
`BLOCKED` preserves missing/invalid evidence; `FAIL` preserves observed numerical
failures. Even a real internally attributed study PASS never enrolls a generic
graph qualification, changes extraction defaults or admits evidence to a graph.

## Present limits and required integration

No prospective signed review records, selected cohort, genuine four-converter
execution package or passing #19 prerequisite exists in this implementation.
The study therefore remains blocked. The new producer/access contracts must be
emitted by the genuine local execution controller; authored fixtures cannot fill
that role. Native manual-closure reseals are currently rejected by this evaluator
unless a separately reviewed prospective adapter is implemented and frozen;
only exact native selection or the checked typed image route is supported.
Prospective image title-page closure is likewise blocked until a page-two witness
adapter is implemented; the supported image closure has an actual following
section transition. This limitation cannot be recast as a successful title-page
candidate or omitted from the challenge denominator.

Identity replacement is also deliberately blocked until its actual alias proof
adapter is implemented. The frozen protocol permits verified identity-only
replacements before review; this evaluator does not accept an arbitrary exclusion
reason as proof. A duplicate or unavailable source cannot trigger a silent cohort
change. These remaining adapters require a new implementation freeze before any
prospective source access; no current code or unit test closes issue #20.

Run authored checks with:

```powershell
python -m unittest tests.test_paper_qualification_v1 -v
python tools/run_validation.py
```

The PDF/image tests skip when their optional dependencies are absent. The locked
research interpreter runs those fixture tests locally. No test reads the private
paper corpus, contacts providers or claims native model performance. A composed
authored driver fixture exercises 400 primary cases, 80 challenge cases, all
1,200 screening outcomes and the four signed phases with explicitly substituted
external source/regression/converter/image ports. It can meet the numerical
contract without qualifying, and mode-only relabeling is rejected. Separate
tests exercise actual fixture source/image readback and converter-assessment replay.
