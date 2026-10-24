# Research-domain identity-aware conflict closure

Refs #8, #9, #10. This is reference implementation behavior, not a production
adapter or deployment receipt.

## Defects reproduced

An earlier draft compared the literal object IDs of assertions when
looking for contradictions. Consequently, a support for claim A can omit a
refutation of claim B even when authorized active `same_as` evidence identifies A
and B. A second regression permits an inactive identity assertion in historical
retrieval to act as a current equivalence proof. Inverse relation spellings also
need their original proof records preserved, not merely normalized endpoints.

The regression suite first reproduced the missing cross-domain refutation and
inactive-identity defects. A further inverse-identity regression failed before
its proof-closure correction. These are fixture-based software findings; they do
not establish real scientific equivalence or deployment performance.

## Versioned behavior and compatibility

New `research_domain_scope(...)` calls explicitly emit
`conflict_resolution: "authorized-identity-v1"`. The field is optional in the
versioned scope schema. A missing field, or the explicit value `literal-v1`, uses
the previous literal comparison and selection behavior. Unknown values fail
validation. Old serialized query and context bodies are not amended or rehashed.

For newly pinned identity-aware queries, conflict detection first normalizes the
ontology's inverse and symmetric relation forms, then resolves only active,
authorized `same_as` links. Retrieval, cache validation and canonical context
verification use the same pinned algorithm. A scoped literal-mode request emits
`LEGACY_LITERAL_CONFLICT_RESOLUTION_MAY_OMIT_ALIASED_REFUTATIONS`; compatibility
is not a claim that literal mode is complete. An unscoped request keeps its
existing behavior.

An application migrates a query by constructing a new explicitly pinned scope.
It must not rewrite a stored query or substitute the new algorithm while claiming
to replay the old one. The query-body difference naturally changes query/cache
identity. This supplement does not change a source, evidence record, assignment,
publication journal, graph version, source epoch or authoritative graph ID.

## Authorization and closure

`query_conflicts` receives the already ACL/current-source-status-filtered universe
from `authorized_scope_edges`. Its identity graph is not built from the raw
catalog or an untrusted summary. Revoked proof and refutation sources cannot
participate. Inactive `same_as`/`different_from` links cannot establish identity or
expand topical membership in the new mode, including historical queries that
otherwise admit inactive facts. Authorized identity proofs and cross-domain
refutations remain closure, not independent out-of-domain embedding candidates.

Normalization never replaces the original assertion or provenance record IDs.
Canonical materialization includes the selected anchor, required identity links,
conflicts and evidence atomically within edge and source-span budgets. A bundle
that cannot fit is omitted rather than returning a misleading support without its
required contradiction. Existing disjoint-validity-interval behavior is retained.
The additional identity passes are charged to the existing work meter.

## Workload provenance

The workload implementation manifest now hashes `retrieval/items.py` and
`constraints.py` as well as the existing files: changing conflict or relation
normalization code must invalidate the implementation receipt. Synthetic runs
remain `MEASURED_NOT_QUALIFIED`. This change neither selects a production storage
backend nor supplies representative corpus, SLO, isolation, owner or pilot inputs.

## Tests and validation boundary

`tests/test_research_domain_identity_conflicts.py` contains 18 regressions covering
aliased and transitive contradictions; inverse identity and refutation forms;
unclassified proof; denied and revoked sources; inactive proofs; symmetric
normalization; disjoint intervals; current-revocation cache/context rejection;
atomic budgets; forged closure; pre-embedding filtering; work accounting; replay;
and explicit legacy compatibility. The workload test checks the two new code pins.

Both generated schema trees are regenerated from the generator. Hosted CI,
required review, signed delivery and deployment gates are separate from these
reference tests, and issues and native dependencies remain open until those gates
are genuinely met.
