# Domain-scoped retrieval v1 — candidate implementation

Status: unmerged source candidate. This document describes implemented reference
behavior, not signed delivery, independent review, or production acceptance.

## Query and authority boundary

Unscoped `trace-retrieval-v1` queries retain their original body and hash. A query
with `research_domain_scope` uses `trace-retrieval-domain-v1` and identifies an
exact taxonomy ID/hash, sorted domain IDs, explicit ANY_EXPLICIT_LABEL matching,
and whether explicitly unclassified sources may anchor retrieval. Unknown IDs,
a forged taxonomy hash, or the new field on an old-version query are rejected.
Hierarchy membership is not silently inferred. Retirement is not an anchor.

The trusted application supplies ACLs and the journal-verification trust store.
`DomainFilter` derives membership from the selected committed projection; a
working catalog cannot publish its own assignment. Source READ, active state,
tombstone, tenant, and ACL checks precede topical membership and embedding.
Historical graph selection does not restore withdrawn content. Raw administrative
snapshots and catalogs remain privileged APIs; only filtered contexts are suitable
for downstream delivery.

## Shared candidate predicate and required closure

All 18 built-in strategies use the same domain predicate. Source/lexical/vector
paths test it before token matching or embedding. Graph adjacency is restricted
to anchored assertions and authorized explanation closure before expansion.
Node/claim, decision/hypothesis, and schema/ontology producers apply the same
anchor semantics. Third-party candidate materialization is checked again.

For an anchored result, preserve authorized prerequisite assertions, explicit
same-as/different-from links and directly detected refutations across domain
labels, including unclassified evidence. Domain scope chooses anchors; it does
not erase evidence needed to explain them. The canonical item has a separate
`research_domain_context` with exact closure assertions, source membership
revision/hash, taxonomy identity and projection binding. Original source/evidence
records and IDs are not rewritten. Retrieved context never grants authorization.

The closure shares the existing work, token, source-span, edge and node budgets.
An oversized item is rejected as a unit rather than silently truncating its
explanation. Known conflict pairs are kept atomic. An explicit caller request to
disable conflict search retains the existing warning semantics. This does not
claim that every semantic contradiction is detectable by the installed graph's
explicit incompatibility rules.

## History, caching, replay and model calls

The selected projection identity participates in graph-read identity, cache keys,
retrieval fingerprints, context and lineage. Current source epochs and ACLs also
invalidate cached results. Context validation reconstructs the exact selected
assignment and checks the canonical material, not caller-written membership.

Plans carry the scope and cannot be silently overridden. Counterfactual replay
may explicitly change or remove scope while preserving original observations.
Upstream compilation includes only the selected authorized classification
references in its evidence closure. Unrelated denied-source assignments are not
added to model input. A source/reclassification/ACL change during retrieval fails
closed before returning a scoped context. The upstream executor and semantic
reranker recheck current context before and after their callback.

## Validation limits

Targeted tests use normal imports, real Ed25519 validation, reference SQLite and
an exact byte-pinned legacy core. Synthetic observations, hashing embeddings and
fabricated corpus labels do not establish live-provider quality. The synthetic
all-channel test disables fallback conflict insertion and requires output from
each requested channel itself. Separate negative tests exercise leakage before
embedding, current revocation, forged context, cache changes, replay, scope-bound
planning and semantic execution. See the execution evidence for actual results.

This candidate has not passed the complete repository release runner, a complete
project sdist/wheel installation, hosted CI, or independent security review. It
implements no unnamed remote/federated backend or deployment-native I/O deadline.
