# Pinned legacy domain publication and conformance

The bridge supports reviewed classification and append-only migration through the
actual upstream SQLite transaction. It does not create `trace_state`. The upstream
state and journal remain the graph authority; classification metadata, records,
source status, lineage, and an installed derived index participate in that same
transaction. An empty upstream audit commit supplies a graph revision for topical
metadata, and the sidecar event binds its exact upstream journal hash and core pin.

The original genesis, source/evidence bodies, old snapshots and earlier journal
hashes are not rewritten. Reopening an old database does not silently migrate it.
Migration requires its own enrolled capability. Classification requires separately
reviewed immutable assignment bytes and exact source/taxonomy/version/epoch binding.
Publisher and preflight capabilities are rechecked under the actual upstream lock,
including idempotent retry. A failed begin-guard explicitly releases the upstream
transaction because its BEGIN precedes the upstream exception handler.

The supported pin remains Git blob
`68217feec539d37e4a524432c93df035f9a0fe39`. The pin is checked before execution;
no replacement implementation or reconstructed source passes that check. The source
is external and is not bundled or added to this repository. A deployment must retain
its own authorized reviewed checkout and trust enrollment.

Run the original gate, then the domain suite, with that exact file:

```sh
TRACE_GC_LEGACY_CORE=/authorized/paper-package/graph_synthesis/core.py \
  python tools/run_domain_validation.py --output validation/domain \
  --include-upstream-regressions
```

The supplemental runner invokes the unchanged original 11-check legacy gate and
reports it separately from `test_domain_legacy` tests. Missing source is NOT_RUN
or explicitly skipped, never passed. Tests use temporary stores, synthetic inputs
and ephemeral test keys. Their success is not deployed-backend, independent-label,
live-provider, or controlled-pilot acceptance.

Remaining inherited restrictions include homogeneous upstream mutation shapes,
no implicit existing-graph adoption, permanent upstream evidence withdrawal, and
one upstream SQLite connection per owning thread. A new deployment-native adapter
needs its own conformance and operational evidence; its name must not be inferred
from the reference implementation.
