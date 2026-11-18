# ACL-safe research-domain retrieval

Reference implementation for issue #8 in the domain-aware evidence graph initiative.

## Query contract and distinct scopes

`research_domain_scope` is an optional, explicitly named field of the versioned
query and retrieval plan. It pins `contract_version: 1`, the immutable taxonomy
ID and hash, canonical domain IDs, `match: ANY | ALL`, `include_unclassified`,
and `include_descendants`. Live scoped queries require the constructor's default
`authorized-identity-v1` conflict-resolution pin. Archived `literal-v1` contexts
and older contexts that omit the pin retain their historical materialization.
Replay can compare one of those contexts with an explicit identity-aware scope.
`research_domain_scope(catalog, taxonomy_id, ids, ...)`
constructs and validates the value. An empty domain list is only meaningful with
`include_unclassified: true`. Unknown or retired IDs and proposed taxonomies
fail closed. Taxonomy review attribution is not a publication signature.

```python
from trace_gc.retrieval import query
from trace_gc.retrieval.domains import research_domain_scope

scope = research_domain_scope(catalog, reviewed_taxonomy_id, ["research:biology"])
request = query(requesting_component="downstream-search", security_scope=tenant,
                text="cell culture", strategies=["LEXICAL"], research_domain_scope=scope)
answer = service.query(request)
```

Research domains are topical search metadata. They are neither endpoint
`domain`/`range` types, `ontology_scope`, topology-derived `community_scope`,
`source_scope`, nor `security_scope`. No domain assignment creates a source,
node, edge, schema or decision ACL grant. Unscoped old queries and canonical item
bodies retain their previous materialization semantics; adding metadata does
not rewrite any old query, source, evidence or graph-snapshot record.

The taxonomy pin is exact. Labels in a different taxonomy or version do not
silently share membership, even when strings are equal. A reviewed successor
assignment or a query for the previous version is required. Descendant expansion
is opt-in. `ALL` with descendants means that each requested hierarchy branch has
a matching label, not that a source must have every descendant simultaneously.
An explicit unclassified inclusion also admits missing/retired assignments.

## Shared admission, not post-filtering graph edges

`ResearchDomainSelection` is built from a version-consistent read view and its
accepted assignment projection. The application ACL and **present** source
active/READ/non-tombstone state are checked before any assignment is examined
for candidate selection. Missing source authority does not imply unclassified
access. The same predicate is used by canonical materialization and all 18
strategies, including lexical/vector/source spans, entities, claims, decisions,
hypotheses, schema/ontology rules, graph edges, temporal/provenance channels,
paths, global retrieval and communities. Embedding input consists only of
individually authorized, domain-admitted original evidence spans.

Assertion membership derives from supporting evidence's exact source snapshots.
Nodes and claims derive membership from authorized incident assertions; shared
identities can participate in several topical views. Only authorized `same_as`
links propagate identity basis. Decisions and hypotheses require their own
source-evidence membership and decision/node ACLs; current in-flight candidates
and their votes are not retrieved as corroboration. Schema rules require a
schema ACL and an authorized selected predicate or endpoint-type basis. A rule
relevant to a selected `Document` type can therefore be retrieved even when its
only existing instance is not a topical anchor; this does not import that
instance as a fact.

## Atomic explanatory closure

Topical, relation and source filters constrain **anchors**, not necessary
explanation. An anchor carries its authorized source spans, endpoints,
`same_as` proof, direct `different_from` distinctions and canonical conflicting
or refuting assertions, including sources labeled in another domain or left
unclassified. Relation/source anchor filters and disabling the separate
`CONFLICT` strategy do not silently remove this required closure. Current ACLs
and withdrawal still apply to every closure member. A denied contradiction is
not disclosed; topical scope is not an access override.

A fact's `prerequisites` are required closure too. The selection follows them
recursively (cycle-safe, depth-unbounded) from every anchor, through sources in
other or no domains, and charges each prerequisite assertion, endpoint and source
span to the same atomic item budget. If any transitive prerequisite is denied,
withdrawn, outside the requested validity window or otherwise unavailable, the
dependent anchor is excluded rather than returned without its proof, and nothing
about the unavailable prerequisite is disclosed. A prerequisite is never an
independent topical hit. Cached closures are keyed by the pinned scope and are
revalidated against current ACL and source status. Tampered closure IDs fail
canonical context validation (`CONTEXT_MATERIALIZATION`).

Each item's exact `research_domain` metadata distinguishes anchor assertion IDs
from closure assertion IDs, pins scope and classification hashes, and records
source-to-assignment IDs (null for missing assignments). Identity equivalence
proof can be transitive, but `different_from` is only a direct distinction. The
other endpoint's equivalence proof is included without expanding unrelated
`A != B != C` chains. Path hops and community membership use topical assertions.
With `ALL` matching, their combined topical labels can satisfy the scope.
An explicit conflict can carry both sides of the pair while its anchor metadata
identifies the topical members.

The whole anchor and closure must fit the existing unique-edge, unique-node,
source-span, token, work and time budgets. Otherwise the entire item is dropped
and the result reports partial/budget-limited retrieval. A one-span budget cannot
keep a supporting span while dropping its required refutation. Generated
community summaries remain noncanonical and have no instruction authority.
`community_scope` selects topology-derived component IDs for the queried view.
Changing the edges eligible for traversal can change the component ID.

## Version binding, current revocation and model contexts

Snapshot identity and cache keys include the accepted classification revision
and hash, current source status and application ACL. Cached canonical items are
reconstructed against authority on reuse. The planner carries the exact scope
into each query. The read determines the classification identity. Context,
lineage, downstream answers, and replay bind both values. Scoped upstream model
packs carry both values in their traced graph context. Replay validates both
graph versions and their classification revisions against the referenced
contexts. A replay on the same
graph version must resolve to the same immutable snapshot. The replay allowlist
permits an explicit alternative domain scope and preserves the original tenant,
requesting role and candidate. Original observations and evidence hashes remain
immutable. Replay checks current access to both contexts before producing the
receipt. New receipts expose only linked observations whose originating packs
still pass current authorization and whose own decision grants allow access.
The receipt pins the replaying application's authorization record. Validation
checks each preserved hash and binds new observations to authorized receipts
from the replayed result. The comparison is derived from those new observations.

The reference adapters check live source status before selecting a domain view,
before embeddings, and before returning context. An application-supplied
retrieval token counter also receives only candidates whose sources and access
are still current, including cached candidates and candidates later dropped by
the budget. A changed source epoch requires a new consistent read, and
revocation denies use. Upstream synthesis, reranking and downstream
materialization revalidate context against current ACL/status at their model/use
boundary. Upstream embedding also checks the input candidate's endpoints and
evidence sources. The full candidate and source closure of a retrieval pack is
authorized before token counting and checked before execution and before using
the returned observations. Scoped reads require the present-status hook.
Unscoped adapters that implement the original read-only protocol use their
consistent read status when the hook is absent.
The reference check runs synchronously at each boundary. Deployment-native
revocation propagation, I/O deadlines and cancellation remain #11 acceptance
work. Historical replay of standalone evidence or decisions needs a journal
that records when those records became available. An in-memory fixture without
history can replay snapshot assertions and their evidence closure.

Pre-scope queries and contexts retain their original fingerprint calculation
when they omit the fields. New contexts pin the classification identity even
when the scope is null, and use a new strategy version. Candidate search,
selection and scoped canonical reconstruction share the discovery work meter.
If verification exhausts it, the service returns a partial result with no
unverified selections. An empty result needs no graph reconstruction. Separate
live use checks have their own bounded verification. Adapter I/O and archival
verification have separate operational timing from candidate search.

Only canonical selected graph context reaches the model. Its classification
identity and scope have exact field traces. Classification review basis is not
silently promoted into scientific evidence or the Minimum Evidence Closure.
The full accepted graph remains available to deterministic compilation,
identity/constraint validation, publication and audit independently of this
search view.

## Local conformance

`tests/test_research_domain_retrieval.py` includes a strategy matrix that
requires each of the 18 strategies to produce its own correctly typed positive
result and checks an unrelated-domain negative for every strategy; automatic
conflict fallback cannot satisfy an otherwise empty channel. Additional cases
inspect actual embedding inputs, real compiler/adapter observation records,
current ACL/withdrawal, reclassification identity, atomic refutation budgets,
cache/plugin tampering, source/relation-filter closure, explicit unclassified
material, taxonomy hierarchy/version pins, planner, upstream and replay bindings.

The corpus and all classification/reviewer/response labels in these tests are
explicitly fabricated reference fixtures. They are not independent research
labels, representative query quality, authenticated deployment publication or
operational qualification. Run the full release and packaged-wheel gates before
claiming issue completion, and retain #6's exact pinned-legacy external gate.
