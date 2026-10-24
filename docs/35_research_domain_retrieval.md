# ACL-safe research-domain retrieval

Refs #8; part of #4. Reference implementation, not deployment qualification.

## Query contract and distinct scopes

`research_domain_scope` is an optional, explicitly named field of the versioned
query and retrieval plan. It pins `contract_version: 1`, the immutable taxonomy
ID and hash, canonical domain IDs, `match: ANY | ALL`, `include_unclassified`,
and `include_descendants`. `research_domain_scope(catalog, taxonomy_id, ids, ...)`
constructs and validates the value. An empty domain list is only meaningful with
`include_unclassified: true`. Unknown or retired IDs and proposed taxonomies
fail closed. Taxonomy review attribution is not a publication signature.

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

Each item's exact `research_domain` metadata distinguishes anchor assertion IDs
from closure assertion IDs, pins scope and classification hashes, and records
source-to-assignment IDs (null for missing assignments). Identity equivalence
proof can be transitive, but `different_from` is only a direct distinction. The
other endpoint's equivalence proof is included without expanding unrelated
`A != B != C` chains. Search paths keep their ordered member IDs and hop budget;
extra explanatory assertions are explicitly not represented as additional
search-path hops.

The whole anchor and closure must fit the existing unique-edge, unique-node,
source-span, token, work and time budgets. Otherwise the entire item is dropped
and the result reports partial/budget-limited retrieval. A one-span budget cannot
keep a supporting span while dropping its required refutation. Generated
community summaries remain noncanonical and have no instruction authority.

## Version binding, current revocation and model contexts

Snapshot identity and cache keys include the accepted classification revision
and hash, current source status and application ACL. Cached canonical items are
reconstructed against authority on reuse. Context, lineage, downstream answers,
planner requests, upstream materialization and replay carry the exact scope and
classification identity. The replay allowlist permits an explicit alternative
domain scope but never a tenant/role/candidate change. Original observations and
source/evidence hashes are not edited by counterfactual retrieval.

Before embeddings and before returning context, the reference adapters' live
source-status hook is checked. A changed source epoch requires a new consistent
read; revocation denies use. Upstream synthesis, reranking and downstream
materialization revalidate context against current ACL/status at their model/use
boundary. Both migrated and explicitly scoped old snapshots require this hook.
This is a bounded synchronous reference check, **not** cancellation of a request
already delivered to a remote model. Deployment-native revocation propagation,
I/O deadlines and cancellation remain #11 acceptance work.

Only canonical selected graph context reaches the model. Its classification
identity and scope have exact field traces. Classification review basis is not
silently promoted into scientific evidence or the Minimum Evidence Closure.
The full accepted graph remains available to deterministic compilation,
identity/constraint validation, publication and audit independently of this
search view.

## Local conformance

`tests/test_research_domain_retrieval.py` has 38 tests. Its strategy matrix
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
