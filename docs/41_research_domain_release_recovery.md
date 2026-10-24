# Exact-pinned source recovery and complete-suite release verification

Refs #6 and #9; informs #10, #11 and #4 without closing them.

## Recovery without changing authority

`tools/recover_legacy_core.py` accepts an explicitly supplied local ZIP and verifies the one selected `graph_synthesis/core.py` against the loader's exact Git blob pin. It never downloads a source, imports archive code, extracts arbitrary members or changes the pin. It takes one bounded immutable archive-byte snapshot, rejects oversized/nonregular inputs, traversal, ambiguous/duplicate members, symlinks, encryption and mismatched bytes, and creates only an explicitly requested new output using an atomic no-overwrite operation. Unsupported filesystems fail closed. Use `--verify-only` for a write-free check; `--member` can disambiguate a member but cannot change the accepted hash.

The actual saved input was `TRACE-GC_Implemented_Project_v0.3.1.zip`, archive SHA-256 `be1608f8ad5a5621c09514b8a18710aa6853ca4db31d9f3a24288a35c048bc85`. Its member `TRACE-GC_Implemented_Project/trace_gc/data/upstream/graph_synthesis/core.py` contains 25,168 bytes, Git blob `68217feec539d37e4a524432c93df035f9a0fe39`, SHA-256 `ad12193fc729907279a1da332d5a92f189949604934bc5ad686d1da3f86e5f14`. The extracted input stayed external to the repository. No source, evidence or journal hash was rewritten, and no new legacy source is vendored by these patches.

A hash match identifies bytes; it does not supply a reviewer signature, a new license/provenance approval, deployment trust, a scientific claim, or publication authority. The loader still verifies the pin immediately before executing its captured bytes. Maintainer acceptance of this recovered source provenance remains separate from the executed conformance result.

## Reproduce on an authorized clean checkout

```sh
python tools/recover_legacy_core.py /authorized/archive.zip --output /external/new-core.py
python tools/check_legacy.py --core /external/new-core.py --output /external/legacy.json
python -m pip install -r requirements.txt
python tools/build_schemas.py
TRACE_GC_LEGACY_CORE=/external/new-core.py python -m unittest discover -s tests -v
TRACE_GC_LEGACY_CORE=/external/new-core.py python tools/run_validation.py
```

The destination's parent must already exist and the output must not. Environment-setting syntax differs on PowerShell; do not replace the workstation's configured SSH signing wrapper with these Linux validation examples. The recovery command's receipt explicitly says it has not run conformance; only the subsequent conformance command can report that result.

## Prevent partial-suite and origin-count overclaims

`tools/release_suite.py` maintains an explicit reviewed inventory of 22 current-main modules plus 12 initiative modules. The release runner checks it before importing/discovering tests. Missing or unexpected modules and nonregular/symlinked entries stop the release with zero executed tests and an explicit incomplete-source failure. This guard does not establish test coverage or cryptographic origin; baseline Git hashes were checked separately during source reconstruction.

The runner also separates baseline and initiative test executions. The inherited two-way non-GraphRAG/GraphRAG counter mislabeled new initiative tests as original baseline. The corrected report has 527 current-main baseline tests, 205 initiative tests, zero other tests; its 108 GraphRAG tests are explicitly a baseline subset. A repeated run is not a new independent test. Failed imports and unknown test origins are not credited to the baseline.

The recovery utility has 20 boundary tests; the inventory/accounting utility has 13. These 33 tests are included in the final total, not added again. All 34 modules execute: **732 passed, zero failures/errors/skips**. Release probes, canonical vectors, bundle validation, both schema trees, isolated demo, synthetic GraphRAG scenarios/benchmark and classification conformance pass. The exact-pinned legacy gate passes 24 checks, including 13 classification checks. Source and installed-wheel conformance agree.

## Delivery and operational boundaries

The local report is `PASS_WITH_EXTERNAL_GATES`. It is not hosted Python 3.11/3.12/3.13 CI, independent PR review, a Git signature, a merged PR, synchronized main, or production qualification. The original workstation checkout was never accessed. GitHub reads worked but a requested issue write returned HTTP 403 and the connection reports no push/triage permission. No Git commit was created or published. The configured SSH/WSL signer is unavailable in this runtime, not diagnosed broken.

The saved hardened series and identity-closure work were reconciled locally. The distinct issue-5 contract candidate identified by SHA-256 `f075d71ba5b1af0052f8451d44b48a971c4b9e9f0321102adc4ec44733714907` was not recovered or reconciled; maintainer ownership/contract review is still required. Preserve existing branches and apply only after refreshing current main and concurrent work.

The newly executed 66-sample workload is synthetic instrumentation evidence, not representative capacity or retrieval-quality qualification. ADR 0001 keeps shared logical storage only as the reference choice. Representative labeled corpus/workloads, hard isolation requirements, accepted SLOs and an authorized decision owner remain missing. No physical sharding issue is justified. The real backend/version/owner/endpoint, operational trust, backup/restore/concurrency evidence and pilot authority for #11 remain missing. All native completion gates and issue states remain open.
