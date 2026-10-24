# Domain-aware retrieval v2

## Contract and authority

`research_domain_scope` is a sorted unique list of namespace-qualified topical IDs,
for example `fixture/biology`, or the explicit `@unclassified` selector. Supplying
it selects `trace-retrieval-domain-v2`. Omitting it preserves the original v1 query
shape and unscoped behavior. An empty v2 list is explicitly unscoped. A v1 request
cannot smuggle in the new field, and a v2 request cannot omit it.

Labels never grant access. The application's existing tenant, workspace, node,
edge, source and decision grants are enforced independently. Present source
READ, active and tombstone status applies even when the graph version is historical.
Taxonomy hierarchy is metadata, not an implicit grant or automatic ancestor match.
Unknown query labels return no invented members. Taxonomy/assignment records remain
content-addressed and refer to unchanged original source/evidence records.

## One predicate, all channels

`DomainMembership` is shared by candidate producers and canonical reconstruction.
It covers ENTITY, CLAIM, NEIGHBORHOOD, PATH, LEXICAL, VECTOR, SOURCE, EVIDENCE,
ONTOLOGY, SCHEMA, CONFLICT, DECISION, SIMILAR_CASE, RELATION, TEMPORAL, PROVENANCE,
GLOBAL and COMMUNITY. An authorized source must be admitted in the selected graph
version before its committed assignment is consulted. Nodes and schema fragments
derive their topical relevance from source-backed anchors, not caller-supplied tags.

Lexical and vector candidate spans are filtered before embedding or semantic
expansion. A cross-domain refutation can enter the required evidence closure without
being sent to the scoped candidate embedding batch. Plugin output is reconstructed
and checked against the same predicate; a plugin cannot invent membership or text.

## Anchor scope versus required evidence

Topical scope selects candidate anchors. Their authorized prerequisites, identity
and cannot-link assertions, conflicting/refuting assertions, endpoints and evidence
are retained across domains, including explicitly unclassified sources. This
closure is an indivisible budget unit. Exhaustion withholds the candidate rather
than silently keeping only the favorable side of a contradiction. Work is charged
to the existing meter, and all underlying edges, nodes and spans count toward caps.
Explicit pre-existing relation, source and temporal filters keep their meanings.

Returned items explain closure reasons and only the selected authorized source
assignment rows. They carry the exact classification revision/projection hash and
taxonomy/assignment identities. Extra closure does not promote an anchor into a
fully proven or calibrated scientific assertion. Source text remains data, not
instructions. Full graph constraints and write authority are never domain-pruned.

## Lineage, cache and replay

The scope and classification binding are included in the retrieval fingerprint,
cache identity, canonical context, lineage, downstream answer and replay branch.
Planner requests cannot silently change scope after planning. Reclassification
changes current retrieval identity without changing older snapshots; current ACL
and source revocation still invalidates historical use. Reranking rechecks current
source status and application ACL immediately before semantic execution and can
change only receipt-derived ordering, not the selected closure or domain binding.

`tests/test_domain_retrieval.py` includes a candidate-producing test for all 18
channels and targeted forgery, revocation, historical, cache, budget and replay
checks. `tests/test_domain_semantic_boundary.py` exercises the reranker boundary.
These are synthetic software tests, not independent-label or deployment qualification.
