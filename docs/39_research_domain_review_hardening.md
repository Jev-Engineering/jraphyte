# Research-domain review chronology hardening

Refs #5, #6 and #9; no issue closure or publication approval is implied.
This hardens the seven-patch reference candidate based on main
`d5ca636a48e963619f4c89e2958d0bb1a3e72f80`. It is not the separate
`jraphyte-issue-5-contracts.patch` candidate recorded on issue #5.

## Defect and correction

The earlier reference candidate accepted inconsistent recorded review histories.
An assignment could claim approval before its exact taxonomy had been approved;
a successor could backdate the predecessor's approval; a signed authorization
could be issued before the review it claimed to attest. A valid Ed25519 signature
proved who signed those bytes, not that their chronology was internally valid.
Seven of ten initial regression methods failed against the recovered candidate.

Approved taxonomy and assignment successors now have nondecreasing review
instants. Approved assignments cannot predate their exact approved taxonomy.
Validation walks the full predecessor chain, so a later valid-looking revision
cannot hide an invalid ancestor. Equivalent timezone offsets and equal instants
are accepted; proposals continue to have no reviewer or approval timestamp.

The publication service checks that the assignment's review existed by both the
signed authorization's issuance and the transaction's publication instant. The
same issuance check is made during authenticated journal replay and published
bundle verification. Cryptographic verification, current source epochs, scope,
CAS, full-graph constraints and atomic publication remain separate requirements.
No recorded timestamp or model-produced field is a publication capability.

## Compatibility and migration

This is stricter semantic validation, not a new record format. No source,
evidence, taxonomy, assignment, snapshot, genesis or journal bytes are rewritten;
neither generated schema tree changes. Existing databases without classification
metadata retain their original representation. Valid monotone classification
history continues to replay against its recorded instants rather than the
current wall clock, under the existing current revocation checks.

A chronology-invalid history produced by the older, unpublished candidate fails
closed. It is not silently repaired by changing hashes or rebuilding the index.
The added test constructs such a history using the old missing-check behavior
and actual test-authority signatures; audit and index rebuild reject it without
changing the journal or authoritative state. Compensating rollback must be a
new reviewed successor, not a backdated alteration of its predecessor.

## Validation boundary

`python -m unittest discover -s tests -p test_research_domain_review_order.py -v`
executes eleven regression methods, including full signed publication rejection,
authenticated historical rejection, offset equivalence, and immutable hash
preservation. These are isolated fabricated fixtures. Test Ed25519 authorities
are not the user's Git signer, scientific taxonomy review, legacy conformance,
independent PR review, or deployment qualification.

Required delivery still includes reconciliation on complete current main,
normal release validation, configured SSH-signed commits, PR checks/review and
protected merge. The exact pinned legacy blob remains a separate external gate.
