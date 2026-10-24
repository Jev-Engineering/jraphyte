# Deployment acceptance and external trust

## Explicit gates

1. Run the full local release runner; retain its report and file manifest.
2. Obtain the exact reviewed upstream checkout when using the legacy bridge and run `check-legacy`. A missing or wrong source fails/skips visibly; no source is imported on hash mismatch.
3. Test live provider behavior with an approved account, pinned model and the actual tokenizer. All release transports are synthetic or mocked. Measure request costs/limits in that environment.
4. Enroll issuer public keys and capabilities independently, hold private keys outside model-visible execution, select an exact policy hash and publication mode in the service, and connect the service to the intended single graph authority.
5. Obtain representative independent labels and a genuine locked evaluation protocol. Review the risk bound, coverage, statistical assumptions and drift controls; approve an exact matching artifact. No included fixture is a production qualification.
6. Run a bounded reviewed pilot and independent audit before automatic consequential publication. Validate operational concurrency, failure recovery, access controls, retention and backups in the actual deployment.

These are acceptance requirements, not a claim that this release performed external operations. The reference backend is single-host SQLite; this project does not certify distributed storage.

## Trust ownership

`TrustStore` is application-owned. Enroll Ed25519 public keys with principal, receipt purposes, operations, scopes, execution modes, maximum risk and review capability. Signers hold private keys injected by the application. Bundles and model output cannot enroll issuers. Rotate by introducing a new key ID; revocation immediately blocks its receipts. A previously valid historical receipt may be inspectable at its recorded time, but that does not restore revoked present-time authority.

`CompilerService` defaults to ANALYSIS_ONLY. Publication needs an explicitly selected service mode and exact trusted policy hash, separately enrolled validators/reviewers, source authority and an operation-scoped authorization binding every plan byte. Non-sandbox synthetic publication is denied. Reviewed approval is distinct from automatic empirical acceptance. A model can propose a plan; it cannot sign one into authorization.

The CLI `--trust` path is an explicit administrative choice. Its format is `{ "issuers": [...], "revoked_issuers": [...] }`. Each issuer entry must contain `issuer`, `public_key_base64`, `principal`, `purposes`, `operations`, `scopes`, `modes`, `maximum_risk`, and `can_review`. Do not populate this from untrusted included public keys. No deployment private key or permissive production trust configuration is shipped.

## Legacy bridge contract and limits

Provide `core_path`, the runtime catalog/current schema/nodes, an explicit upstream Policy configuration, database path and durable sandbox mode to `PinnedLegacyBackend`. Source bytes must have Git blob `68217feec539d37e4a524432c93df035f9a0fe39`; this is Git-object SHA-1 with its blob header, not a raw file SHA-256. The source code is not vendored. Importing a different file or changing the pin requires a new source review and conformance process.

The bridge targets a fresh upstream database or one already initialized by the same bridge. An existing unrelated graph requires a separately reviewed provenance import; it is not silently adopted. The upstream state and journal remain the accepted-graph authority. Sidecar records, source epochs, aliases and lineage participate in the upstream SQLite transaction; no second `trace_state` is created. Writes outside the bridge cause audit/version disagreement rather than being silently trusted.

The provided conformance command tests idempotency, single authority, OR/AND withdrawal, durable reopen, upstream/sidecar audit and rollback/retry at four commit fault points. **The exact pinned source was unavailable in this release, so that gate is NOT RUN.** Pin-rejection tests did run. The bridge implementation and conformance harness are delivered for execution against the real checkout, not labeled as proven compatible without it.

Supported upstream atomic shapes are homogeneous assertion additions, homogeneous retractions, audit-only metadata/proposals and a single relation-schema migration. Mixed addition/retraction batches and node-type remapping are rejected before writes; split them into separately reviewed versioned plans only when non-atomic application is appropriate. Upstream withdrawal is permanent for that evidence; restoring read permission requires a new immutable source snapshot rather than silent reactivation. Use one upstream connection per owning thread/process and run real backend concurrency acceptance for the deployed integration.

The original upstream retains evidence text in its own records/journal. Compiler-cache erasure is **not** whole-upstream erasure and cannot guarantee deletion of backups/external copies. A deployment requiring total retention deletion needs a separately reviewed upstream retention implementation. Do not suppress audit failures or claim exact replay after deleting necessary bytes.

## Failure and recovery

Persist the database and budget store, use a stable idempotency key only for one immutable plan, and never refresh a receipt by changing input hashes. On source/schema/version drift, rebuild the pack/plan and obtain new approval rather than retrying a stale action under a new key. Identical successful retries return the original receipt even if later maintenance changed graph state; they do not restore old support.

Bounded solver exhaustion, malformed provider answers, unavailable source bytes, unsupported operations, unqualified thresholds, or invalid signatures fail closed. Observations can remain in analysis history without becoming eligible for mutation. Logs and exported bundles may contain source text; apply deployment access and retention controls accordingly.

## GraphRAG deployment gates

Read `18_graphrag_security.md` before exposing the query service. Provide authenticated application-owned ACLs, a consistent graph adapter, source status/epoch propagation, provider deadlines and exact-version embedding/tokenizer/model implementations. The included allow-all fixture grant helper is only for isolated synthetic examples. GraphRAG does not grant production write authority; the existing policy, reviewer, signature, CAS and qualification requirements remain unchanged.

Research-domain views are logical metadata over one authority; see `research_domain_deployment_gates.md` and ADR 0001 before selecting a deployment backend or physical placement. The shipped adapters are the in-memory and single-host SQLite references only.
