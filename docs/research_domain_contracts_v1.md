# Research-domain record contracts v1

Implementation candidate for issue #5 of CompleteDotTech/jraphyte, based on
`d5ca636a48e963619f4c89e2958d0bb1a3e72f80`. This contract does not implement
publication, a graph read projection, retrieval filtering, or a deployment
adapter. Those remain the responsibilities of issues #6–#11. A passing contract
test is not a completed initiative, an approved taxonomy, or production acceptance.

## Distinct concepts

Research-domain labels are topical metadata. They are not relation endpoint
`domain`/`range` types, `ontology_scope`, topology-derived `community_scope`,
security clearance/classification, tenant/workspace membership, or `security_scope`.
A label never grants access. Present-time source READ/active/tombstone checks and
application-owned ACLs remain mandatory even for historical graph reads.

A taxonomy record has an immutable namespace/version, deterministic content hash,
stable lower-case domain IDs, labels and an optional acyclic multi-parent hierarchy.
A namespace/version cannot be rebound to different contents in one catalog.
Hierarchy is descriptive: membership does not silently expand to parent domains.
Changing definitions requires a new taxonomy version and reviewed assignments.
The installed example taxonomy is synthetic demonstration data, not an approved
classification policy, default source assignment, or externally validated taxonomy.

## Immutable records and review

`research-domain-taxonomy`, `classification-proposal`, and
`classification-assignment` use the existing TRACE-C14N-1 record envelope. Their
IDs must equal `<kind>:<record hash>`; arbitrary aliases remain allowed for older
record kinds. Existing source and evidence records are not extended or rehashed.

A proposal binds an exact source snapshot ID/hash/security scope and source epoch;
the taxonomy record ID/hash/version; sorted explicit domain IDs; pinned classifier
method/name/version/artifact hash; hash-bound source text or evidence-span basis;
revision, proposed effective graph version, predecessor ID/hash, mode and time.
Methods are HUMAN, RULE, or MODEL. No method, including HUMAN, implies authority.
External unbound prose, unrelated evidence and unsupported transformations cannot
serve as classification basis.

`CLASSIFIED` requires at least one valid label. `UNCLASSIFIED` has no labels and is
explicitly distinct from an unknown taxonomy ID. `RETIRED` also has no labels and
must supersede an existing assignment. Unreviewed or absent assignments must remain
explicitly unclassified in the future graph projection, not disappear from required
evidence closure. A revision starts at 1; subsequent revisions must bind the
predecessor and advance graph version without moving epoch/time backward. Competing
proposals are permissible; competing reviewed assignments for the same source
revision/effective version are rejected as ambiguous.

A separate Ed25519 `CLASSIFICATION_REVIEW` receipt signs the exact proposal hash,
source security scope, execution mode, reviewer principal and classification
operation/risk. The assignment binds both proposal and receipt IDs/hashes and
records the reviewer and review timestamp. The application-owned TrustStore must
enroll the issuer for that purpose, scope, mode and `CLASSIFY_SOURCE` capability,
with review permission and a risk ceiling of at least R2. No key is auto-enrolled
from a bundle; no deployment signer or private key is supplied.

Catalog and schema validation establish record consistency. Importing an assignment
into a privileged catalog is **not** publication and does not assert its review is
authentic without external trust. `assign(..., trust=...)` verifies review authority;
`validate_catalog(..., trust=..., at=...)` authenticates imported reviews at the
explicit verification instant (or the trust store's current instant). Source
admission and graph publication require separate application authority.

## Ledger and bundle compatibility

New ledger stages are DOMAIN_TAXONOMY, CLASSIFICATION_PROPOSAL and
CLASSIFICATION_ASSIGNMENT. Causal references require the exact source/taxonomy/basis
and predecessor before a proposal, the proposal before its review receipt, and the
receipt before the assignment. Assignment events use the review timestamp, not the
earlier proposal timestamp. Appending these events preserves a supplied valid old
ledger prefix and its hashes.

Catalog construction uses two-phase loading for new-kind references, so a serialized
record list need not be in topological order. Incremental insertion checks new
records before mutation. Bundle verification calls the classification validator;
existing source/evidence and old record-envelope version remain unchanged. Catalog
order is not a current-assignment selection mechanism.

## Rules required of the next stages

Only the assignment map selected by an authoritative committed graph version may
provide membership. Never choose membership from the newest record in a catalog.
The publication operation must recheck expected graph version, exact source epoch,
source permissions/status, current predecessor, taxonomy/assignment hashes and
scoped authority under the existing transaction lock. Persist the projection,
records, source state and journal atomically. Migration is a new journal event,
never a rewrite of genesis or old source/evidence/journal hashes.

Assertion topical membership is the union of the assignments of its supporting
evidence sources at the selected graph version. It does not change assertion IDs.
Shared entities can occur in multiple domain views without being cloned. A scoped
candidate anchor must retain authorized supporting/refuting evidence, endpoint and
identity links, and contradictions across labels within budgets. Missing labels do
not justify removing required evidence. These are downstream requirements, not
claims that this contract patch implements retrieval or publication.

## Validation and delivery gates

Run `python -m unittest discover -s tests -p test_domain_contracts.py -v`.
Run `python tools/build_schemas.py` and check both schema trees for drift.
The normal release runner remains `python tools/run_validation.py` in a complete
checkout. Build the real project wheel and run
`python tools/validate_domain_wheel.py --wheel /path/to/trace_gc.whl --report wheel-domain-validation.json`.
That command installs the supplied wheel offline into a fresh target and checks
package-origin imports, CLI availability, every packaged schema and the example
taxonomy. It does not pass unless that installed wheel actually runs.

The current delivery's execution report distinguishes performed focused tests from
unrun full release, installed-wheel, pinned-legacy and live-deployment gates. No
synthetic/reference result qualifies a legacy source or deployed backend. No
physical database-per-domain or storage-placement decision is made here.
