# Domain authority: authenticate before publication, expose committed reads only

Refs #6, #7, #9. Reference implementation correction; not native deployment
qualification or evidence of completed GitHub review and delivery.

## Failure and correction

A valid authorization for a new operation does not authenticate the history it
extends. An earlier draft checked current approvals but could
append to a rehashed journal containing an invalid older authorization or
preflight. Its idempotency path could return that corrupted recorded result.
An unlogged change to state metadata could likewise become the next event's
preimage. The existing authenticated audit detected these conditions, but the
publication boundary did not invoke it.

`CompilerService.publish` now supplies an internal authority check to the backend
transaction whenever the action contains a domain operation or the accepted state
already has a classification projection. The backend acquires `BEGIN IMMEDIATE`,
authenticates classification history with application-enrolled trust, verifies the
journal/state/record bindings, and requires complete classification replay **before**
idempotency lookup or apply. A competing writer cannot enter between verification
and use. The callback is application code, not a query, model proposal, plan field,
or caller-supplied attestation. It does not create a second graph authority.

No genesis, old event, source, evidence, or assignment bytes are rewritten. A
corrupt or unavailable history is rejected and must be handled through the owner's
recovery process; this change does not silently repair it. Existing signatures,
source epoch checks, compare-and-swap, global constraints, and transaction rollback
continue to apply. An unmigrated database with no domain operation retains its
previous publication path. Source withdrawal/revocation remains available through
the separate source-administration boundary even if classification history is
invalid: preventing new publication must not prevent reducing access. Such a
revocation does not certify or repair the invalid history.

The pinned-legacy transaction proxy runs the same callback immediately after the
actual upstream transaction begins, before upstream retry lookup. A reentrancy
guard prevents the audit's state reads from triggering apply. An audit failure
rolls back the newly opened transaction; a failed nested BEGIN does not roll back
the caller's pre-existing transaction. Proxy tests use real disposable SQLite,
not the missing reviewed pinned GraphStore. The exact legacy conformance gate
remains pending for Git blob `68217feec539d37e4a524432c93df035f9a0fe39`.

## Read visibility

A reference adapter sharing a writer connection previously reused an existing SQL
transaction. Called from a publication fault hook after the journal write but
before commit, it could return an assignment that was later rolled back. That
result could outlive its transaction in a retrieved context or cache.

`SQLiteGraphAdapter` version `sqlite-trace-domain-read-v1.1` rejects reads,
current-source-status queries, and index writes (construction DDL, rebuilds, materialization) when its connection already has
a caller-owned transaction (`GRAPH_READ_UNCOMMITTED`). It neither commits nor
rolls back that caller's work. Normal reads own a consistent snapshot; current
revocation checks continue to apply to historical results. For concurrent reads,
use a **separate backend/adapter connection**. The regression demonstrates that
such a reader sees the old committed assignment while the writer is at
`before_commit`, then the new assignment only after commit. The adapter-version
change also partitions retrieval cache keys from the previous visibility contract.

This is a single-host reference guarantee, not remote ACL pushdown, backup/restore,
deployment SLO acceptance, distributed transaction evidence, or a production claim.

## Regression evidence and execution

`tests/test_research_domain_authority_boundary.py` covers corrupted older
AUTHORIZATION and PREFLIGHT signatures with recomputed hashes, corrupted retry
receipts, unjournaled metadata, rollback visibility, caller-transaction preservation,
write-lock ordering including retry, separate-reader commit visibility, source
revocation with invalid history, and the legacy proxy's failure/reentrancy paths.

Run with the repository requirements installed:

```sh
python -m unittest discover -s tests -p 'test_research_domain_authority_boundary.py' -v
python -m unittest discover -s tests -p 'test_research_domain*.py' -v
python tools/build_schemas.py
python tools/run_validation.py
```

Seven initial negative regressions failed against the earlier draft and passed
after the correction. Actual complete-run receipts, packaging scope, and outstanding
external gates belong in the execution report; this document does not mark an
unrun release, required review, hosted CI, pinned legacy or deployment gate passed.
