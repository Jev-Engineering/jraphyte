# Research-domain conformance and gate accounting

Refs #9; dependencies #5–#8 remain completion gates. This document does not authorize a merge, close an issue, or qualify a deployment.

## Executable checks

`python -m trace_gc domain-conformance --output domain-conformance.json` executes a real, temporary SQLite-reference lifecycle. It injects four write-boundary failures, verifies signed migration/retry, preserves genesis and journal prefixes, publishes multi-label assignments, reclassifies, reads historical assignments with current withdrawal, appends a compensating assignment, and reopens/audits the database. Every label is fabricated. The command supplies no production identity and performs no provider calls or production graph writes.

`python tools/check_legacy.py --core /reviewed/path/core.py --output legacy-conformance.json` includes the same classification lifecycle against the pinned bridge, **after** verifying Git blob `68217feec539d37e4a524432c93df035f9a0fe39`. Wrong bytes fail before import. Exact legacy conformance remains **NOT RUN** until that reviewed source is supplied.

Targeted suites are `test_research_domain_contracts.py`, `test_research_domain_transactions.py`, `test_research_domain_reads.py`, `test_research_domain_retrieval.py`, `test_research_domain_conformance.py`, and `test_research_domain_packaging.py`. Their checks are behavioral, not counts of enum names: each retrieval strategy must produce its own expected positive candidate and exclude an unrelated domain, and embedding spies inspect the actual input text. Historical withdrawal, cross-domain refutation, identity closure, index forgery, approval forgery, and packaged schema generation are exercised.

## Additional fail-closed behavior

Two different snapshots claiming the selected graph version are rejected, including for a current read; repeating the identical snapshot is harmless. Candidate plugins cannot promote a mutated membership cache into canonical context: final verification reconstructs membership from the immutable records captured before candidate generation. Cache insertion occurs only after that verification. Python plugins still execute trusted application code, not a security sandbox.

`SQLiteGraphAdapter` requires administrator-supplied `audit_trust` for non-sandbox classified or domain-scoped reads. Hash-only audit is explicitly not origin authentication. The adversarial tests rewrite an approval or preflight signature and recompute the record, event and receipt hashes: structural audit can report an intact hash chain, but authenticated audit/read/rebuild rejects the forged signature. Presently revoked issuers fail closed on historical verification too; deployment trust rotation and retention remain operational requirements, not demonstrated deployment readiness.

## Reference validation

On the complete base checkout with this patch series applied, `tools/run_validation.py` passed on Python 3.13.12: **695 tests run, 671 passed, 24 skipped, zero failures/errors**. The command also passed the canonical vectors, design probes, 33 schema-resource comparisons, isolated demo, GraphRAG scenarios/benchmark, and temporary domain lifecycle. The clean schema-regeneration test verifies byte-identical LF output on Windows without an inherited `PYTHONPATH`. This run includes 22 review-order and rejected-workload regression tests plus 14 authority-boundary regressions.

The skipped gates must be read from `VALIDATION_REPORT.json`; a successful reference run does not pass exact legacy conformance, hosted Python-version checks, representative workload and independent-label studies, a native backend, production SLOs, or a deployment pilot. GitHub delivery and review have separate evidence requirements.
