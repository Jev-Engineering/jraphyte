"""Executable classification lifecycle conformance against a selected factory.

Only isolated synthetic databases and ephemeral application-signing keys are
used. These are not Git commit signatures or production trust enrollment.
The pinned-legacy caller must verify its exact source bytes before invoking us.
"""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Callable

from .backend import CompilerService, SQLiteReferenceBackend
from .canonical import digest, loads, write
from .demo import build_fixture, POLICY, POPULATION, RUN, SCOPE
from .domain_publication import OPERATIONS, classification_operation, migration_operation, restore_assignment
from .domains import create_assignment, reference_taxonomy
from .errors import ContractError, require
from .plans import create_plan
from .retrieval.store import SQLiteGraphAdapter
from .trust import IssuerPolicy, Signer, authorize_plan


def run_domain_conformance(output: str | Path | None = None, *,
                           backend_factory: Callable[..., Any] = SQLiteReferenceBackend,
                           backend_label: str = "sqlite-reference-v1") -> dict[str, Any]:
    checks: list[str] = []
    with TemporaryDirectory(prefix="trace-domain-conformance-") as temporary:
        f = build_fixture(Path(temporary), backend_factory=backend_factory)
        try:
            f.publish()
            c, b = f.catalog, f.backend
            original = {record["id"]: deepcopy(record) for kind in ("source", "evidence") for record in c.all(kind)}
            genesis = b.db.execute("SELECT body FROM trace_meta WHERE id=1").fetchone()[0]
            genesis_record = loads(genesis)
            before_journal = list(b.db.execute("SELECT * FROM trace_journal ORDER BY version"))
            before_snapshot_id = b.snapshot(c)
            domain_signer = Signer.ephemeral("conformance-domain-reviewer")
            f.trust.enroll(domain_signer.issuer, IssuerPolicy(domain_signer.public_key(), "isolated-domain-reviewer",
                frozenset({"AUTHORIZATION"}), OPERATIONS, frozenset({SCOPE}), frozenset({"SYNTHETIC"}), can_review=True))
            taxonomy = reference_taxonomy()["body"]
            review = {"status": "APPROVED", "reviewer_id": "isolated-domain-reviewer",
                      "reviewed_at": "2026-09-27T00:00:00Z", "rationale": "Synthetic conformance labels, not independent research review."}
            taxonomy["review"] = review
            taxonomy["provenance"]["basis"] = "Fabricated labels for isolated lifecycle conformance only."
            taxonomy_id = c.put("research-domain-taxonomy", taxonomy)
            service = CompilerService(b, f.trust, f.validator, policy_version=POLICY, population=POPULATION,
                security_scope=SCOPE, publication_mode="REVIEWED", policy_hash=c.hash(f.policy_id), classification_enabled=True,
                classification_taxonomy_hashes=frozenset({c.hash(taxonomy_id)}))

            def plan(operations, key, *, source_status=None):
                return create_plan(c, run_id=RUN, snapshot_id=b.snapshot(c), operations=operations,
                    security_scope=SCOPE, execution_mode="SYNTHETIC", idempotency_key=key, policy_version=POLICY,
                    source_status=b.statuses() if source_status is None else source_status)

            def approvals(plan_id):
                return {"preflight": service.preflight(c, plan_id, reviewed=True),
                        "authorization": authorize_plan(domain_signer, c.get(plan_id), c.hash(plan_id),
                                                        reviewed_by="isolated-domain-reviewer")}

            def publish(plan_id, **changes):
                return service.publish(c, plan_id, **approvals(plan_id), **changes)

            initialize = plan([migration_operation(operation_id="initialize-domains", reason="Synthetic append-only conformance migration")], "domain-initialize")
            initialize_approvals = approvals(initialize)
            for point in ("before_state_write", "after_state_write", "after_journal_write", "before_commit"):
                before_state = b.state()
                before_records = list(b.db.execute("SELECT * FROM trace_records ORDER BY id"))
                def interrupt(name):
                    if name == point:
                        raise RuntimeError("domain-conformance-fault")
                try:
                    service.publish(c, initialize, **initialize_approvals, fault=interrupt)
                except RuntimeError as exc:
                    require(str(exc) == "domain-conformance-fault", "DOMAIN_CONFORMANCE", "unexpected injected error")
                else:
                    raise AssertionError("classification fault did not interrupt commit")
                require(b.state() == before_state and list(b.db.execute("SELECT * FROM trace_records ORDER BY id")) == before_records,
                        "DOMAIN_CONFORMANCE", "classification state and immutable records did not roll back atomically")
                require(list(b.db.execute("SELECT * FROM trace_journal ORDER BY version")) == before_journal,
                        "DOMAIN_CONFORMANCE", "failed classification migration changed the journal")
                b.audit(trust=f.trust)
                checks.append("classification_rollback:" + point)
            first = service.publish(c, initialize, **initialize_approvals)
            retry = service.publish(c, initialize, **initialize_approvals)
            require(not first["replayed"] and retry["replayed"] and first["receipt"] == retry["receipt"],
                    "DOMAIN_CONFORMANCE", "signed idempotent migration retry differs")
            require("classifications" not in c.get(before_snapshot_id) and
                    list(b.db.execute("SELECT * FROM trace_journal WHERE version<=? ORDER BY version", (len(before_journal),))) == before_journal,
                    "DOMAIN_CONFORMANCE", "old snapshots or journal prefix changed")
            current_meta = loads(b.db.execute("SELECT body FROM trace_meta WHERE id=1").fetchone()[0])
            require(all(current_meta[key] == genesis_record[key] for key in ("genesis_state", "genesis_hash")),
                    "DOMAIN_CONFORMANCE", "migration rewrote genesis")
            checks.extend(["signed_migration_idempotency", "append_only_genesis_and_journal"])

            assignments = []
            for source_id, labels in zip(f.source_ids, (["research:biology", "research:chemistry"], ["research:chemistry"])):
                assignments.append(create_assignment(c, source_snapshot_id=source_id, taxonomy_id=taxonomy_id,
                    domain_ids=labels, review=review, classifier_id="isolated-domain-reviewer", classifier_version="conformance-v1"))
            operations = [classification_operation(c, ref, operation_id="classify:" + str(i))
                          for i, ref in enumerate(assignments)]
            assign_plan = plan(operations, "domain-assign")
            stale_plan = plan(operations, "domain-stale-graph")
            stale_approvals = approvals(stale_plan)
            publish(assign_plan)
            accepted_state = b.state()
            accepted_journal = list(b.db.execute("SELECT * FROM trace_journal ORDER BY version"))
            try:
                service.publish(c, stale_plan, **stale_approvals)
            except ContractError as exc:
                require(exc.code == "STALE_GRAPH_VERSION", "DOMAIN_CONFORMANCE", "wrong stale graph rejection")
            else:
                raise AssertionError("a preflighted classification plan committed against a stale graph")
            require(b.state() == accepted_state and
                    list(b.db.execute("SELECT * FROM trace_journal ORDER BY version")) == accepted_journal,
                    "DOMAIN_CONFORMANCE", "stale graph rejection changed committed rows")
            checks.append("signed_classification_stale_graph_cas")
            try:
                plan(operations, "domain-stale-predecessor")
            except ContractError as exc:
                require(exc.code == "DOMAIN_REVISION", "DOMAIN_CONFORMANCE", "wrong stale predecessor rejection")
            else:
                raise AssertionError("classification planning accepted a stale predecessor")
            checks.append("classification_planning_rejects_stale_predecessor")
            classified_snapshot_id = b.snapshot(c)
            classified_snapshot = c.get(classified_snapshot_id, "graph-snapshot")
            classified = classified_snapshot["classifications"]["assignments"]
            require(classified == dict(zip(f.source_ids, assignments, strict=True)),
                    "DOMAIN_CONFORMANCE", "classification projection did not bind each exact assignment")
            checks.append("multi_source_assignment_publication")
            second = create_assignment(c, source_snapshot_id=f.source_ids[0], taxonomy_id=taxonomy_id,
                domain_ids=["research:physics"], review=review, classifier_id="isolated-domain-reviewer",
                classifier_version="conformance-v1", supersedes=assignments[0])
            publish(plan([classification_operation(c, second, operation_id="reclassify")], "domain-reclassify"))
            current = c.get(b.snapshot(c), "graph-snapshot")
            require(current["classifications"]["assignments"][f.source_ids[0]] == second,
                    "DOMAIN_CONFORMANCE", "current projection does not show the reviewed successor")
            historical_request = {"graph_version": classified_snapshot["graph_version"],
                                  "temporal_scope": {"as_of": None, "before_source": None}}
            historical = SQLiteGraphAdapter(b, audit_trust=f.trust).read(historical_request)
            require(historical.snapshot_id == classified_snapshot_id and historical.snapshot == classified_snapshot,
                    "DOMAIN_CONFORMANCE", "reclassification changed the historical snapshot")
            checks.extend(["reclassification_updates_current_projection", "historical_assignment_replay"])

            restored = restore_assignment(c, current_assignment_id=second, restore_assignment_id=assignments[0], review=review,
                                          classifier_id="isolated-domain-reviewer", classifier_version="conformance-v1")
            publish(plan([classification_operation(c, restored, operation_id="restore")], "domain-compensation"))
            require(c.get(restored)["effective_revision"] == 3 and c.get(second)["domain_ids"] == ["research:physics"],
                    "DOMAIN_CONFORMANCE", "compensation changed history or reused a revision")
            require(b.state()["classifications"]["assignments"][f.source_ids[0]] == restored and
                    c.get(restored)["domain_ids"] == c.get(assignments[0])["domain_ids"],
                    "DOMAIN_CONFORMANCE", "compensation did not restore selected labels")
            checks.append("append_only_compensating_rollback")
            previous_status = b.statuses()
            f.status_change(f.source_ids[0])
            candidate = create_assignment(c, source_snapshot_id=f.source_ids[0], taxonomy_id=taxonomy_id,
                domain_ids=["research:physics"], review=review, classifier_id="isolated-domain-reviewer",
                classifier_version="conformance-v1", supersedes=restored)
            outdated_source = plan([classification_operation(c, candidate, operation_id="outdated-source")],
                                   "domain-stale-source", source_status=previous_status)
            try:
                approvals(outdated_source)
            except ContractError as exc:
                require(exc.code == "STALE_SOURCE_EPOCH", "DOMAIN_CONFORMANCE", "wrong stale source rejection")
            else:
                raise AssertionError("classification preflight accepted an outdated source epoch")
            checks.append("classification_preflight_rejects_stale_source_epoch")
            require(not b.statuses()[f.source_ids[0]]["active"] and len(b.view(c)["edges"]) == 1,
                    "DOMAIN_CONFORMANCE", "withdrawal lost the independent alternative graph proof")
            checks.append("source_withdrawal_preserves_independent_proof")

            accepted = b.state()
            persisted = b.load_catalog()
            require(all(persisted.record(ref) == record for ref, record in original.items()),
                    "DOMAIN_CONFORMANCE", "source or evidence body/hash changed")
            b.close()
            f.backend = b = backend_factory(Path(temporary) / "graph.sqlite3", catalog=c,
                schema_id=f.schema_id, nodes=accepted["nodes"], sandbox=True)
            require(b.state() == accepted, "DOMAIN_CONFORMANCE", "classification state changed on old database reopen")
            audit = b.audit(trust=f.trust)
            require(audit["classification_authority_verified"], "DOMAIN_CONFORMANCE", "classification signatures were not verified")
            checks.extend(["immutable_source_evidence_hashes", "classified_database_reopen_authenticated_audit"])
            report = {"status": "PASS", "backend": backend_label, "checks": checks, "checks_run": len(checks),
                "classification_events": audit["classification_events"], "journal_events": audit["events"],
                "final_graph_version": accepted["graph_version"], "final_state_hash": digest(accepted),
                "execution_mode": "SYNTHETIC", "label_origin": "FABRICATED_CONFORMANCE_ONLY", "provider_calls": 0,
                "production_graph_writes": 0, "production_qualification": "NOT_ESTABLISHED",
                "scope": "Isolated classification lifecycle, atomicity, historical snapshots and authenticated journal conformance; not representative workload or operational qualification."}
        finally:
            f.close()
    if output is not None:
        write(Path(output), report)
    return report
