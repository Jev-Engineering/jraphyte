<p align="center"><img src="assets/banner.jpg" alt="Violet and cyan diagram of evidence streams passing a hexagonal gate and compiling into a connected knowledge graph." width="100%"></p>

# TRACE-GC 0.4.0 — bidirectional GraphRAG integration

Evidence-bound graph compilation with immutable observations, explicit policy branches, typed mutation plans, and an authenticated transaction boundary.

This release preserves the implemented 0.3 design-review improvements and extends the same installable Python runtime with upstream graph-aware evidence acquisition and downstream provenance-aware GraphRAG. It is an **isolated reference implementation with explicit deployment gates**, not an empirically qualified production service.

> **The graph is both an output of compilation and an input to future compilation.**

`UpstreamGraphRAG` feeds bounded hybrid context into the existing closure, question, Jev, resolver and mutation workflow. `GraphRAGQueryService` returns source-cited contexts over the compiled graph for search, QA and agents. Both share 18 retrieval channels, strict records, access controls, version-aware caches and budgets; neither grants publication authority.

```sh
python -m trace_gc graphrag-demo --output examples/graphrag/scenarios
python -m trace_gc graphrag-benchmark --output benchmarks/graphrag
python examples/graphrag/query_example.py
```

Read the [canonical architecture](docs/01_architecture.md), [material change matrix](docs/20_graphrag_deltas.md), [retrieval and downstream API](docs/17_hybrid_and_downstream_graphrag.md), [security boundary](docs/18_graphrag_security.md) and [all-requirements/deliverables index](docs/22_graphrag_traceability.md). Editable diagrams are in `diagrams/`; four executable scenarios and their immutable bundles are in `examples/graphrag/`.

Research-domain classification is topical metadata over the single authoritative evidence graph, distinct from ACLs, ontology types and graph communities: see the [contracts](docs/research_domain_contracts.md), [publication and migration](docs/research_domain_publication.md), [indexed reads](docs/research_domain_reads.md), [all-channel scoped retrieval](docs/research_domain_retrieval.md), [conformance](docs/research_domain_conformance.md), [storage ADR](docs/adr/0001_research_domain_storage.md) and [deployment gates](docs/research_domain_deployment_gates.md). The reference adapters are not a deployment-native backend.

Explore the [end-to-end workflow atlas](docs/workflow/README.md): 12 source-reviewed Mermaid chapters with high-resolution light/dark PNGs, code links, failure paths and reproducible rendering.

The implementation is graph-database agnostic, with tested SQLite and in-memory adapters. Other database adapters are specified interfaces, not installed integrations. The offline vector baseline uses token hashing; trained embeddings are injectable. Community summaries are bounded connected components, not a full Microsoft GraphRAG global pipeline. The existing fixed semantic synthesis tasks remain support/refutation and identity. Live providers, real-data accuracy, deployment calibration, distributed scale and new semantic programs are not claimed as completed gates.

## Run it

Python 3.11 or later is required. The attached validation report records the exact Python and dependency versions actually exercised; the CI matrix is configured separately and is not a claim that all versions were tested here.

```sh
python -m pip install -r requirements.txt
python tools/run_validation.py
python -m trace_gc demo --output examples/runtime
python -m trace_gc validate examples/runtime/bundle.json
```

Install the CLI, including its offline JSON schemas:

```sh
python -m pip install .
trace-gc --version
trace-gc demo --output trace-gc-demo
```

`demo` creates temporary **sandbox-only** SQLite databases and ephemeral in-memory signing keys. It uses fabricated observations, performs no provider request, does not connect to a deployed graph, and exports no private key. It demonstrates compilation, recorded observation, joint resolution, abstention under unqualified policy, separate human-review authorization, atomic publication to the test store, idempotent retry, two alternative proofs, progressive source withdrawal, and historical replay.

`validate` never grants write authority. An analysis bundle can be structurally valid without an authenticated checkpoint; the output distinguishes those properties. Signed published verification requires an independently enrolled administrator trust file. Do not trust public keys merely because the same bundle or demo supplies them.

## Existing design-review implementation retained

| Area | Executable implementation |
|---|---|
| Evidence and claim binding | Immutable logical-source snapshots and claim content; exact Unicode spans; deterministic state compiler; per-field record/locator/transform trace; reproducible permitted normalization. |
| Closure and execution | Recursive closure with typed edges and required graph evidence; shared linear DAG checks; fully scoped questions; completed, temporally prior, snapshot-compatible prerequisites. |
| Model observations | Immutable exact request/response byte receipts; full Choice/Noul/Score checks; Score legend meanings checked; malformed responses retained as errors; separate semantic, wire, and tenant/mode cache hashes. |
| Resolution | Bounded joint exact search with explicit alternatives, cannot-links, identity component constraints, input certificates, impact, deterministic ties, and fail-closed incomplete solves. |
| Plans and policy | Six discriminated operation types, exact assertion/revision/schema targets, risk consistency, immutable plan hashes, one lifecycle, multiple policy branches without rewriting observations. |
| Trust and qualification | Service-owned Ed25519 issuer enrollment; scoped, expiring approvals; observation attestations; exact 14-dimensional qualification applicability; final-pipeline independent-label risk/coverage calculation and accepted-action audit sampling. |
| Transactions and history | CAS and source epochs rechecked under SQLite transaction; graph/status/records/journal atomic; persistent idempotency; OR proofs and AND dependency withdrawal; causal complete-run ledger and signed root; explicit erasure/replay loss. |
| Engineering | Cached schemas, typed root/source contracts, structured errors, monotonic shared run budgets, state-sequence/fault/concurrency tests, CLI, wheel resources, and upstream pin/conformance tooling. |

See [the recommendation traceability matrix](docs/13_recommendation_traceability.md), [runtime specification](docs/12_implementation.md), [deployment and trust guide](docs/14_deployment.md), and [API examples](docs/15_api_examples.md).

## Validation and evidence

`VALIDATION_REPORT.json` and `VALIDATION_LOG.txt` are retained generated evidence for the v0.4 release: the unchanged original 197-test baseline plus 108 retrieval tests (305 total), all 18 original adversarial probes, canonicalization vectors, the original isolated lifecycle, four GraphRAG scenarios and 91 synthetic retrieval/pipeline comparisons. The current runner also discovers the added first-page validation tests; rerun it for a current result. A skipped external backend test remains explicitly marked skipped. External gates are reported separately.

The prior 18 probes are unchanged in their malicious mutations; the compatibility harness only learns the new claims-manifest entry. Original versions remain in `review/reproduce_findings_original.py` and `archive/v0.2`. Run them against the hardened compatibility API with:

```sh
python review/reproduce_findings.py . --output review/probe_results_after.json
```

No report in this release establishes model semantic accuracy, empirical production calibration, a completed controlled pilot, live TypeSafe interoperability, distributed-backend behavior, or deployed security certification. Tests that exercise a `RECORDED` or `LIVE` mode flag use fabricated receipts or a mock transport, with isolated test keys. They are boundary tests, not real inference evidence.

## Pinned legacy GraphStore

`trace_gc.legacy.PinnedLegacyBackend` wraps the original store instead of creating a second accepted-graph authority. The upstream graph state and journal remain authoritative; compiler sidecars and source status participate in the same SQLite transaction.

The exact original `graph_synthesis/core.py` Git blob must be:

```text
68217feec539d37e4a524432c93df035f9a0fe39
```

The release did **not** obtain matching executable bytes for that pin. Therefore the real pinned-upstream conformance gate is **NOT RUN**. A nonmatching source is rejected before import. The upstream source is not vendored or silently replaced with a reconstructed copy.

Run the provided gate with an actual matching checkout:

```sh
python tools/check_legacy.py --core /path/to/paper-package/graph_synthesis/core.py --output legacy-conformance.json
```

The optional integration test reads `TRACE_GC_LEGACY_CORE`. Without it, that test is explicitly skipped. Passing the reference-backend tests does not pass the upstream gate. The bridge supports atomic homogeneous additions, retractions, audit-only metadata/proposals, and relation-schema migrations; it rejects mixed add/retract batches and node-type migrations the upstream API cannot represent. See the deployment guide for additional limitations.

## Command reference

```text
trace-gc validate BUNDLE [--trust ADMIN_TRUST.json] [--at UTC_TIMESTAMP]
trace-gc demo --output DIRECTORY
trace-gc graphrag-demo --output DIRECTORY
trace-gc graphrag-benchmark --output DIRECTORY
trace-gc canonical INPUT.json
trace-gc replay-policy BUNDLE --policy ANALYSIS_POLICY.json --output BRANCH.json [--trust ADMIN_TRUST.json] [--at UTC_TIMESTAMP]
trace-gc evaluate-labels LABELS.json --scope SCOPE.json --protocol PROTOCOL.json
    --threshold NUMBER --risk-limit NUMBER --minimum-coverage NUMBER
    --confidence NUMBER --expires-at UTC_TIMESTAMP --output QUALIFICATION.json
trace-gc audit-sample ACCEPTED_ACTION_IDS.json --size INTEGER --seed INTEGER --output SAMPLE.json
trace-gc check-legacy --core CORE.py [--output REPORT.json]
```

A label evaluation produces an **unsigned review-required artifact**, not an authorization. The replay CLI only creates analysis-only branches. There is intentionally no “publish this untrusted JSON” CLI command.

## Repository layout and compatibility

The optional [first-page evidence validation](docs/23_first_page_validation.md)
adds a frozen experimental PDF selector, explicit source-review receipts and a
10,000-paper retrieval trial. Automatic selector promotion is disabled; this
experiment does not change the active corpus worker or publish graph claims.
The [follow-up comparison](docs/24_first_page_validation_followup.md) tests a
reading-order selector, local vision parsers, BM25F, SPECTER2, and reranking on
regression cases and newly reviewed source pages.
The [expanded local comparison](docs/25_first_page_expanded200.md) evaluates all
six extraction pipelines on 200 papers and local retrieval on 60 queries, with
no new paid API calls. The [failure audit](docs/26_first_page_failure_root_causes.md)
traces missed and incorrect proposals to their source-page and parser causes.
The [parallel source experiment](docs/30_first_page_parallel_experiment.md)
compares a separate review-only selector on the known 200 papers and a small
source-first sample; its preservation gate still fails.
The [implementation prompt](NEXT_AGENT_PROMPT.md) defines the follow-up work and
its GitHub delivery and verification steps.

`trace_gc/` is the v0.4 runtime. `schemas/runtime/` contains 28 standalone schemas, also embedded as package resources. The existing 0.3.0 record envelope stays compatible; retrieval payloads use `trace-retrieval-v1`. `tools/validate_package.py` is the separately hardened legacy fixture checker; it still denies publication. `examples/bundle.json` exercises that compatibility checker. `examples/runtime/` contains the retained runtime lifecycle examples and canonical vectors. Do not pass one format to the other's validator or rehash old live observations into the new format.

`archive/v0.2/` preserves the original design, tests, schemas and provenance. `archive/v0.3/` preserves the supplied implementation documentation and release reports. `review/graphrag_baseline_audit.json` records byte-level preservation of the original test files and unchanged authority modules. Current contracts in `docs/03_ir_contracts.md`, `docs/05_provenance_replay.md`, and `docs/12_implementation.md` supersede the old record and lifecycle definitions. Future research modules in the old design are not represented as completed experimental findings.

The release manifest lists file sizes and SHA-256 hashes; its own bytes are deliberately excluded to avoid recursive self-hashing. No private keys, credentials, live source documents, persistent test databases, or third-party font files are included.
