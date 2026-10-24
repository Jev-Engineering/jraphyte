# Research-domain conformance and gate accounting

Refs #9; dependencies #5–#8 remain completion gates. This document does not authorize a merge, close an issue, or qualify a deployment.

## Executable checks

`python -m trace_gc domain-conformance --output domain-conformance.json` executes a real, temporary SQLite-reference lifecycle. It injects four write-boundary failures, verifies signed migration/retry, preserves genesis and journal prefixes, publishes multi-label assignments, reclassifies, reads historical assignments with current withdrawal, appends a compensating assignment, and reopens/audits the database. Every label is fabricated. The command supplies no production identity and performs no provider calls or production graph writes.

`python tools/check_legacy.py --core ../external/pinned-legacy-core.py --output legacy-conformance.json` includes the same classification lifecycle against the pinned bridge, **after** verifying Git blob `68217feec539d37e4a524432c93df035f9a0fe39`. Wrong bytes fail before import. The reviewed core is supplied externally and is never vendored or reconstructed in this repository; supply the exact file with `--core` or `TRACE_GC_LEGACY_CORE`. A hash match does not constitute maintainer review, a signature, or deployment approval.

Targeted suites are `test_research_domain_*.py` (contracts, transactions, authority boundary, review order, reads, retrieval, identity conflicts, semantic boundary, workloads, conformance, packaging and the wheel-validator gate) plus `test_historical_source_revocation_regression.py`. Their checks are behavioral, not counts of enum names: each retrieval strategy must produce its own expected positive candidate and exclude an unrelated domain, and embedding spies inspect the actual input text. Historical withdrawal, cross-domain refutation, identity closure, index forgery, approval forgery, and packaged schema generation are exercised.

## Additional fail-closed behavior

Two different snapshots claiming the selected graph version are rejected, including for a current read; repeating the identical snapshot is harmless. Candidate plugins cannot promote a mutated membership cache into canonical context: final verification reconstructs membership from the immutable records captured before candidate generation. Cache insertion occurs only after that verification. Python plugins still execute trusted application code, not a security sandbox.

`SQLiteGraphAdapter` requires administrator-supplied `audit_trust` for non-sandbox classified or domain-scoped reads. Hash-only audit is explicitly not origin authentication. The adversarial tests rewrite an approval or preflight signature and recompute the record, event and receipt hashes: structural audit can report an intact hash chain, but authenticated audit/read/rebuild rejects the forged signature. Presently revoked issuers fail closed on historical verification too; deployment trust rotation and retention remain operational requirements, not demonstrated deployment readiness.

## Provenance negatives and the retrieval clock

A negative test that deletes or alters citations is meaningful only when the original answer has nonempty `selected_evidence_ids` and citations; with both empty, `[] == []` satisfies the exact-citation check and the mutation is a no-op. `BudgetMeter` binds `time.monotonic` as a keyword default when it is defined, so patching `time.monotonic` or a module attribute later does not reach it. `tests/test_graphrag_budget_clock.py` therefore replaces `BudgetMeter.__init__.__kwdefaults__["clock"]`, asserts the controlled clock was called, asserts nonempty original selection/citations before every tamper case, and separately asserts the budget-exhausted and empty-request boundaries (including that a fabricated citation on an empty answer is still rejected). The production default `maximum_latency_ms=2000` is unchanged and asserted. These are deterministic functional tests; they do not diagnose why the preserved affected-suite run saw an empty selection and are not a latency SLO (issue 10).

## Image-derived sources in domain-scoped retrieval

`tests/test_research_domain_image_evidence.py` renders the authored `tools/image_evidence_fixtures.py` PDF, runs the delivered `render_source`/`image_candidate`/`review_image`/`handoff` path with real PyMuPDF and Pillow, and places the resulting source and evidence in the synthetic `domain_corpus` through the existing classification assignment, snapshot, ACL and retrieval contracts. It checks that released, authorized, classified image text is selected by the LEXICAL, VECTOR, SOURCE, EVIDENCE and NEIGHBORHOOD channels and cited with exact hashes and identity; that a wrong domain, a missing grant, a wrong principal, and an inactive, denied or tombstoned source (current and historical reads) exclude it before any embedding; and that image-lineage binding, held validation and review staleness stay authoritative: an authorized reader of a forged or held image source fails closed with `IMAGE_SOURCE_BINDING`, `IMAGE_REVIEW_REQUIRED` or `IMAGE_REVIEW_STALE`. Two phases are distinguished. (1) Authority/projection integrity validation (`GraphReadView` construction, `verify_projection`, `verify_assignment`) runs for every reader before any ACL filter exists; when an accepted classification assignment uses an evidence-span basis, it calls `Catalog.verify_evidence` and therefore verifies the image lineage of that span, whatever the reader may read. An invalid authoritative image fails the whole query for every reader with the same error (the suite asserts `MISSING_REFERENCE` for a removed image record, identically for an authorized and an unauthorized reader); there is no per-edge skipping and no reader-dependent signal. This phase does not evaluate a source-record basis, which carries no span. (2) Candidate evaluation is ACL-gated per reader: `access.evidence` and the source grant, scope, READ, tombstone and active checks precede `Catalog.verify_evidence` of a candidate and precede the domain-selection test, so an unauthorized reader has the candidate excluded from results, selected evidence, context text and embedding input. The suite asserts both controls: a source-record-basis fixture never has the invalid evidence verified for an unauthorized reader, and an evidence-basis fixture has its span verified at the authority phase while the same reader still receives no image item and no image text in embeddings. This documents the implemented boundary; it is not a claim that unauthorized readers avoid all image-lineage evaluation. The review is the authored fixture attestation, not an independent human review, no OCR engine runs, and the module is skipped when PyMuPDF or Pillow is missing, so a hosted run must report zero skips for it. Retrieval re-checks only the portable image record (`validate_image_record`); artifact re-rendering stays a separate gate. This is a functional regression, not the empirical acceptance of issues 10 or 11.

## Reference validation

Run, from a complete checkout with `requirements.txt` installed:

```sh
python -m unittest discover -s tests -p "test_research_domain*.py" -v   # domain suites
python -m unittest discover -s tests -p "test_historical_source_revocation_regression.py" -v
python tools/build_schemas.py            # regenerates both schema trees; the diff must be empty
python tools/run_validation.py           # release validation incl. classification conformance
TRACE_GC_LEGACY_CORE=../external/pinned-legacy-core.py python tools/run_validation.py   # also runs the exact pinned bridge
python -m build --sdist --wheel --outdir scratch/dist
cd <outside-checkout directory under the same project root>   # the validator must not run from the source tree
python <checkout>/tools/validate_domain_wheel.py --wheel <checkout>/scratch/dist/trace_gc-*.whl --report <project-local scratch>/wheel.json [--legacy-core <checkout>/../external/pinned-legacy-core.py]
```

`../external/pinned-legacy-core.py` is the project-local, non-vendored copy of the reviewed core (Git blob `68217feec539d37e4a524432c93df035f9a0fe39`); `scratch/` is a project-local, untracked directory. Do not write outputs to a root-level `/external` path.

`tools/validate_domain_wheel.py` installs the wheel into a fresh target outside the
source tree and runs the domain conformance lifecycle from that installed copy; it
checks that every domain module and schema resource is imported from the wheel and
reports the pinned-legacy gate as `NOT_RUN` unless the exact reviewed core is
supplied. Actual test counts, skips and failures for a given revision belong to that
run's report, not to this document. The inherited paper-pilot suites contain tests
with workstation-specific absolute paths; a failure there is not evidence about
research-domain behavior and is reported separately.

The skips on a typical run are unavailable optional experiment dependencies and
Windows symlink/FIFO privilege limits. `PASS_WITH_EXTERNAL_GATES` does not establish
production qualification, representative performance, independent labels, a
deployment backend, hosted checks, or a pilot.
