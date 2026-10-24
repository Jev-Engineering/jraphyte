# Deployment-native domain graph acceptance — blocked pending selection

No deployment-native adapter is implemented or qualified by the input-readiness
checker. The actual backend/version/endpoint, owner, authorized connection, source
authority and application trust enrollment must be selected and supplied outside
model-visible secrets. Reference SQLite and the pinned legacy bridge remain separate
software-conformance targets, not substitutes for this deployment decision.

The example manifest contains explicit nulls. Checking it returns BLOCKED, exit 2,
and NOT_RUN for every operational gate:

```sh
python tools/check_domain_deployment.py \
  --manifest examples/domain_graph/deployment-inputs.example.json \
  --output deployment-inputs.json
```

Filling the manifest returns only INPUTS_DECLARED_NOT_VERIFIED. JSON declarations
never enroll keys, grant authority, execute a backend, or pass operational checks.
Keep credentials/private keys in the application's secret manager; the manifest
contains references only, and the report exports field names rather than values.

The selected native adapter must implement consistent journal-equivalent versioned
reads, indexed source/domain lookup, row/edge ACL pushdown before semantic work,
present-time source epochs/status on historical versions, stable cross-domain IDs,
unavailable-history failures and bounded I/O deadlines/cancellation. Preserve the
single write authority and exact publication semantics. Any approved physical split
first needs linked routing/provenance/consistency/revocation/atomicity implementation.

Required actual-environment evidence includes commit/rollback visibility, concurrent
reads/writes, domain-scope shadow parity, current revocation, ACL pushdown, backup and
restore, migration/rollback, telemetry, retention, workload SLOs, independent-label
qualification, live provider/tokenizer gates when applicable, and a reviewed pilot.
Record limitations with concrete remediation issues rather than marking unrun gates
passed. Keep issue #11 and epic #4 open while these inputs or results are absent.
