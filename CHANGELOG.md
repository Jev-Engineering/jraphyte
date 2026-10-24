# Changelog

## Unreleased — research-domain classification and scoped retrieval

Added reviewed, immutable multi-label `research-domain-taxonomy` and `classification-assignment` records; append-only, signed, atomic classification publication and migration through the existing reference and pinned-legacy transaction boundaries; journal-verified, rebuildable indexed domain reads with current source status/ACL checks on historical reads; a `research_domain_scope` query field enforced by one authorized predicate across all 18 retrieval strategies before embedding or semantic reranking, with authorized cross-domain identity/contradiction closure and planner/cache/lineage/replay/compiler propagation; classification conformance (`trace-gc domain-conformance`, extended `check-legacy`); and a synthetic workload recorder (`trace-gc domain-workload`). Historical retrieval no longer treats a withdrawn source as readable. Existing source/evidence records and hashes are unchanged.

Review repairs: required fact prerequisites are now recursive, authorized, atomically budgeted closure; request authorization, preflight and application policy are revalidated under the owner lock even on an idempotent retry (both backends); every classification-index DDL/rebuild/write runs under `PhaseAuthority.write` with phase-then-backend-lock-then-`BEGIN IMMEDIATE` ordering and phase-bound reads never write; a hosted wheel/sdist job validates the installed wheel from outside the checkout. Native Windows phase qualification of the index is authored but NOT_RUN on Linux.

No deployment-native adapter, representative workload evidence or accepted production storage decision is included; those remain open gates (#10, #11).

## 0.4.0 — bidirectional GraphRAG integration

Extended the existing evidence-gated runtime with hybrid source/graph retrieval, task/risk planning, strict retrieval IRs, canonical graph-context reconstruction, ACL filtering, bounded source-plus-graph closure, uncertainty expansion, scoped caches, provenance/contradiction/temporal/decision-aware downstream contexts, optional bounded Jev relevance packs, retrieval-aware replay, metrics and held-out research gates. Preserved the original semantic programs and transaction authority. Added 108 tests, four executable synthetic lifecycle scenarios, a 91-run synthetic benchmark, updated diagrams/specifications and material delta/requirement matrices.

The 0.3 documents/reports are archived; original test files remain unchanged. Bundle envelope compatibility stays 0.3.0 while the distribution is 0.4.0 and retrieval payloads are trace-retrieval-v1. No trained embedding quality, live provider conformance, production calibration, remote adapter deployment or research novelty is inferred from fixture results.

## 0.3.0 — implemented design-review revision

Added the installable compiler runtime, 18 standalone runtime schemas, deterministic materialization/recursive closure, immutable observations and replay branches, typed operations, joint component resolution, scoped qualification and Ed25519 authority, transactional SQLite reference backend, pinned upstream bridge/conformance command, complete provenance profiles, source maintenance/erasure semantics, shared budgets, CLI, CI configuration and expanded regression/state-sequence tests.

Hardened the original synthetic fixture checker against all 18 reviewed probes without replacing the original 42 tests. Original v0.2 documents, contracts and tests are preserved under `archive/v0.2`. Changed lifecycle and IR definitions are explicitly versioned rather than silently reinterpreting old observations.

Release evidence is restricted to the locally executed suites and isolated demo. Exact pinned-upstream conformance, live provider operation, independent empirical calibration and a real controlled pilot remain external acceptance gates. The software does not manufacture successful evidence for them.
