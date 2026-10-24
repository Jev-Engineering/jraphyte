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
from .domain_publication import OPERATIONS, classification_operation, migration_operation
from .domains import create_assignment, reference_taxonomy, restore_assignment
from .errors import require
from .plans import create_plan
from .trust import IssuerPolicy, Signer, authorize_plan
from .retrieval.contracts import query, RetrievalBudget
from .retrieval.domains import research_domain_scope
from .retrieval.fixtures import demo_access
from .retrieval.service import HybridRetriever, validate_context
from .retrieval.store import SQLiteGraphAdapter


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

            def plan(operations, key):
                return create_plan(c, run_id=RUN, snapshot_id=b.snapshot(c), operations=operations,
                    security_scope=SCOPE, execution_mode="SYNTHETIC", idempotency_key=key,
                    policy_version=POLICY, source_status=b.statuses())

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
                    list(b.db.execute("SELECT * FROM trace_journal WHERE version<=2 ORDER BY version")) == before_journal,
                    "DOMAIN_CONFORMANCE", "old snapshots or journal prefix changed")
            current_meta = loads(b.db.execute("SELECT body FROM trace_meta WHERE id=1").fetchone()[0])
            require(all(current_meta[key] == genesis_record[key] for key in ("genesis_state", "genesis_hash")),
                    "DOMAIN_CONFORMANCE", "migration rewrote genesis")
            checks.extend(["signed_migration_idempotency", "append_only_genesis_and_journal"])

            assignments = []
            for source_id, labels in zip(f.source_ids, (["research:biology", "research:chemistry"], ["research:chemistry"])):
                assignments.append(create_assignment(c, source_snapshot_id=source_id, taxonomy_id=taxonomy_id,
                    domain_ids=labels, review=review, classifier_id="isolated-domain-reviewer", classifier_version="conformance-v1"))
            assign_plan = plan([classification_operation(c, ref, operation_id="classify:" + str(i))
                                for i, ref in enumerate(assignments)], "domain-assign")
            publish(assign_plan)
            classified_version = b.state()["graph_version"]
            adapter = SQLiteGraphAdapter(b, c, audit_trust=f.trust)
            access = demo_access(c, b.snapshot(c), scope=SCOPE)
            retriever = HybridRetriever(adapter, catalog=c, access_policy=access)
            scope = research_domain_scope(c, taxonomy_id, ["research:biology"])
            request = query(requesting_component="downstream-search", security_scope=SCOPE, strategies=["LEXICAL"],
                text=c.get(f.evidence_ids[0])["quote"], research_domain_scope=scope, include_conflicts=False,
                budget=RetrievalBudget(maximum_tokens=100000, maximum_latency_ms=20000))

            def retrieve(q):
                result_id = retriever.retrieve(q)
                result = c.get(result_id)
                validate_context(c, result["graph_context_id"], current_access=access, current_status=b.statuses())
                return c.get(result["graph_context_id"]), c.get(result["lineage_id"])

            selected, _ = retrieve(request)
            require(f.evidence_ids[0] in selected["selected_evidence_ids"] and f.evidence_ids[1] not in selected["selected_evidence_ids"],
                    "DOMAIN_CONFORMANCE", "multi-domain lexical membership differs")
            _, cached = retrieve(request)
            require(cached["cache_hit"], "DOMAIN_CONFORMANCE", "unchanged reference read did not reuse cache")
            second = create_assignment(c, source_snapshot_id=f.source_ids[0], taxonomy_id=taxonomy_id,
                domain_ids=["research:physics"], review=review, classifier_id="isolated-domain-reviewer",
                classifier_version="conformance-v1", supersedes=assignments[0])
            publish(plan([classification_operation(c, second, operation_id="reclassify")], "domain-reclassify"))
            current, changed = retrieve(request)
            require(not current["items"] and not changed["cache_hit"], "DOMAIN_CONFORMANCE", "reclassification did not invalidate selection/cache")
            historical, _ = retrieve({**request, "graph_version": classified_version, "include_historical": True})
            require(historical["selected_evidence_ids"] == selected["selected_evidence_ids"] and
                    historical["classification_identity"] == selected["classification_identity"],
                    "DOMAIN_CONFORMANCE", "historical classification identity changed")
            checks.extend(["multi_domain_reference_reads", "reclassification_cache_invalidation", "historical_assignment_replay"])

            restored = restore_assignment(c, current_assignment_id=second, restore_assignment_id=assignments[0], review=review,
                                          classifier_id="isolated-domain-reviewer", classifier_version="conformance-v1")
            publish(plan([classification_operation(c, restored, operation_id="restore")], "domain-compensation"))
            require(c.get(restored)["effective_revision"] == 3 and c.get(second)["domain_ids"] == ["research:physics"],
                    "DOMAIN_CONFORMANCE", "compensation changed history or reused a revision")
            current, _ = retrieve(request)
            require(current["selected_evidence_ids"] == selected["selected_evidence_ids"], "DOMAIN_CONFORMANCE", "compensation did not restore selected labels")
            checks.append("append_only_compensating_rollback")
            f.status_change(f.source_ids[0])
            historical, _ = retrieve({**request, "graph_version": classified_version, "include_historical": True})
            require(not historical["items"], "DOMAIN_CONFORMANCE", "current withdrawal leaked through historical classification")
            require(len(b.view(c)["edges"]) == 1, "DOMAIN_CONFORMANCE", "classification or withdrawal lost the independent alternative graph proof")
            checks.append("current_withdrawal_on_historical_read")

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
                "scope": "Isolated classification lifecycle, atomicity, read and authenticated journal conformance; not representative workload or operational qualification."}
        finally:
            f.close()
    if output is not None:
        write(Path(output), report)
    return report
