# Domain graph operational acceptance — unmerged candidate

`check_sandbox_backup_recovery` in `trace_gc/retrieval/domain_operations.py`
accepts an actual sandbox backend and an application-owned factory that reopens
that same backend. It refuses non-sandbox stores. It uses SQLite online backup,
reopens an isolated copy, checks journal/snapshot/current-source-status equality,
corrupts only the backup's derived index, confirms fail-closed reads, rebuilds
explicitly from authority and verifies the original authority is unchanged.
This is executable reference/pinned-core evidence, not an invented deployment.

Run the synthetic driver documented in the storage ADR. The exact legacy core
must be supplied separately and pass its Git-blob pin before any import. Do not
vendor private inputs, credentials, signing keys or a reconstructed substitute
for the pinned core. Source labels, graph assignments and successful backups do
not grant deployment or publication authority.

## Gates still requiring the actual deployment

Issue #11 still requires a named backend/version/owner, authorized disposable
endpoint, enrolled operator/source authority, representative inputs and the
workload ADR's real SLOs. Its native adapter must implement ACL/domain pushdown,
consistent journal-equivalent snapshots, current revocation propagation, stable
cross-boundary identity/provenance and native timeout/cancellation. Complete
concurrent read/write, backup/restore, rollback/migration, observability, retention
and shadow-result acceptance there. Reference tests cannot certify these missing
interfaces or set an operating SLO for the operator.

Keep live-provider/tokenizer verification, independently labeled qualification,
trusted key enrollment, independent security/operational review and approved
pilot acceptance as separate gates. No provider credentials are needed for the
synthetic diagnostic; no paid API or production graph operation is run by it.

The current read index fails closed on stale rows until the trusted application
explicitly rebuilds. Rebuilding on every journal change and authenticating full
history is deliberately conservative and not a production performance claim.
A deployed incremental index and pushdown path must preserve the same authority
checks rather than suppress them for performance.
