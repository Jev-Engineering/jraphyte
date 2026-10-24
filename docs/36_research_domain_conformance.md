# Research-domain conformance and gate accounting

Refs #9; dependencies #5–#8 remain completion gates. This document does not authorize a merge, close an issue, or qualify a deployment.

## Executable checks

`python -m trace_gc domain-conformance --output domain-conformance.json` executes a real, temporary SQLite-reference lifecycle. It injects four write-boundary failures, verifies signed migration/retry, preserves genesis and journal prefixes, publishes multi-label assignments, reclassifies, reads historical assignments with current withdrawal, appends a compensating assignment, and reopens/audits the database. Every label is fabricated. The command supplies no production identity and performs no provider calls or production graph writes.

`python tools/check_legacy.py --core /reviewed/path/core.py --output legacy-conformance.json` includes the same classification lifecycle against the pinned bridge, **after** verifying Git blob `68217feec539d37e4a524432c93df035f9a0fe39`. Wrong bytes fail before import. The pinned-source recovery protocol is in `41_research_domain_release_recovery.md`. A hash match does not constitute maintainer review, a signature, or deployment approval.

Targeted suites are `test_research_domain_contracts.py`, `test_research_domain_transactions.py`, `test_research_domain_reads.py`, `test_research_domain_retrieval.py`, `test_research_domain_conformance.py`, and `test_research_domain_packaging.py`. Their checks are behavioral, not counts of enum names: each retrieval strategy must produce its own expected positive candidate and exclude an unrelated domain, and embedding spies inspect the actual input text. Historical withdrawal, cross-domain refutation, identity closure, index forgery, approval forgery, and packaged schema generation are exercised.

## Additional fail-closed behavior

Two different snapshots claiming the selected graph version are rejected, including for a current read; repeating the identical snapshot is harmless. Candidate plugins cannot promote a mutated membership cache into canonical context: final verification reconstructs membership from the immutable records captured before candidate generation. Cache insertion occurs only after that verification. Python plugins still execute trusted application code, not a security sandbox.

`SQLiteGraphAdapter` requires administrator-supplied `audit_trust` for non-sandbox classified or domain-scoped reads. Hash-only audit is explicitly not origin authentication. The adversarial tests rewrite an approval or preflight signature and recompute the record, event and receipt hashes: structural audit can report an intact hash chain, but authenticated audit/read/rebuild rejects the forged signature. Presently revoked issuers fail closed on historical verification too; deployment trust rotation and retention remain operational requirements, not demonstrated deployment readiness.

## Reference validation

On a complete base checkout with the integrated and authority corrections applied, `python tools/run_validation.py` passed on Python 3.13.12: **746 tests run, 716 passed, 30 skipped, zero failures or errors**. Origin accounting records 527 baseline and 219 initiative tests; 108 GraphRAG tests are a subset of the baseline. The 35-module inventory rejects missing, unexpected, nonregular and symlinked test inputs before discovery.

The release command also passed bundle validation, canonical vectors, 33 schema-resource comparisons, 18 original design probes, the isolated demo, GraphRAG scenarios and synthetic benchmark, and the 13-check classification lifecycle. Clean schema regeneration produces byte-identical LF files on Windows. The source/evidence schema blobs remain unchanged.

The skips include unavailable optional experiment dependencies, Windows symlink privilege and FIFO limitations, and the exact pinned legacy source, which was not supplied to this checkout. The archived reference execution records 24 legacy checks, but that is separate evidence, not a rerun in this environment. `PASS_WITH_EXTERNAL_GATES` does not establish production qualification, representative performance, independent labels, a deployment backend, hosted candidate checks, or a pilot.
