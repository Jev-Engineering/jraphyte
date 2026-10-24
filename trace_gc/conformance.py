"""Explicit conformance gate for a user-supplied, byte-pinned legacy checkout.

This command never downloads or imports nonmatching source, never touches a
production database, and uses synthetic observations in temporary test stores.
"""
from __future__ import annotations
import tempfile
from pathlib import Path
from typing import Any
from .canonical import digest
from .demo import build_fixture
from .errors import require
from .legacy import PinnedLegacyBackend, PINNED_CORE_BLOB, load_pinned_core


def legacy_test_policy() -> dict[str,Any]:
    """Test-only upstream configuration, not an empirically qualified policy."""
    return {"version":"isolated-legacy-conformance-only","thresholds":{"supports":.9,"refutes":.9,"same_as":.9},
            "contracts":{"supports":["SUPPORTS","CONTRADICTS","INSUFFICIENT"],
                         "refutes":["CONTRADICTS","SUPPORTS","INSUFFICIENT"],
                         "same_as":["MATCH","DIFFERENT","INSUFFICIENT"]},"allowed_modes":["synthetic"]}


def check_legacy(core_path: str | Path) -> dict[str,Any]:
    load_pinned_core(core_path)  # Must complete before any upstream execution.
    checks=[]
    def backend_factory(path,**kwargs):
        return PinnedLegacyBackend(path,core_path=core_path,legacy_policy=legacy_test_policy(),**kwargs)
    with tempfile.TemporaryDirectory(prefix="trace-gc-legacy-conformance-") as temp:
        root=Path(temp)
        fixture=build_fixture(root/"lifecycle",backend_factory=backend_factory)
        try:
            approvals=fixture.approvals()
            first=fixture.publish(approvals=approvals);second=fixture.publish(approvals=approvals)
            require(not first["replayed"] and second["replayed"],"CONFORMANCE_FAILURE","idempotency")
            checks.append("exact_plan_idempotency")
            require(fixture.backend.db.execute("SELECT name FROM sqlite_master WHERE name='trace_state'").fetchone() is None,
                    "CONFORMANCE_FAILURE","must not create a second accepted-graph state")
            checks.append("upstream_is_single_graph_authority")
            require(len(fixture.backend.view(fixture.catalog)["edges"][0]["assertion_ids"])==2,"CONFORMANCE_FAILURE","OR proofs")
            fixture.status_change(fixture.source_ids[0])
            require(len(fixture.backend.view(fixture.catalog)["edges"][0]["assertion_ids"])==1,"CONFORMANCE_FAILURE","alternate proof survival")
            fixture.status_change(fixture.source_ids[1])
            require(not fixture.backend.view(fixture.catalog)["edges"],"CONFORMANCE_FAILURE","complete withdrawal")
            checks.extend(["alternative_proof_survival","all_proofs_withdrawn","atomic_upstream_and_lineage_audit"])
            fixture.backend.audit()
            state=fixture.backend.state();fixture.backend.close()
            fixture.backend=backend_factory(root/"lifecycle"/"graph.sqlite3",catalog=fixture.catalog,
                schema_id=fixture.schema_id,nodes=state["nodes"],sandbox=True)
            require(fixture.backend.state()==state,"CONFORMANCE_FAILURE","durable restart")
            fixture.backend.audit();checks.append("durable_reopen")
        finally:fixture.close()
        for stage in ("before_state_write","after_state_write","after_journal_write","before_commit"):
            fixture=build_fixture(root/stage,backend_factory=backend_factory)
            try:
                before=digest(fixture.backend.state());version=fixture.backend.state()["graph_version"]
                def fault(point):
                    if point==stage:raise RuntimeError("injected-conformance-fault")
                try:fixture.publish(fault=fault)
                except RuntimeError as exc:
                    require(str(exc)=="injected-conformance-fault","CONFORMANCE_FAILURE","unexpected fault")
                else:raise AssertionError("fault did not interrupt upstream commit")
                require(digest(fixture.backend.state())==before and fixture.backend.state()["graph_version"]==version,
                        "CONFORMANCE_FAILURE","interrupted commit not atomic")
                fixture.backend.audit();fixture.publish();fixture.backend.audit()
                checks.append("rollback_and_retry:"+stage)
            finally:fixture.close()
        fixture=build_fixture(root/"and-chain",prerequisite_chain=True,backend_factory=backend_factory)
        try:
            fixture.publish();fixture.status_change(fixture.source_ids[0])
            require(not fixture.backend.view(fixture.catalog)["edges"],"CONFORMANCE_FAILURE","AND dependency withdrawal")
            fixture.backend.audit();checks.append("and_dependency_withdrawal")
        finally:fixture.close()
    from .domain_conformance import run_domain_conformance
    classification = run_domain_conformance(backend_factory=backend_factory, backend_label="pinned-legacy-v1")
    checks.extend("domain:" + check for check in classification["checks"])
    return {"status":"PASS","core_blob":PINNED_CORE_BLOB,"checks":checks,"checks_run":len(checks),
            "classification_conformance": classification,
            "execution_mode":"SYNTHETIC","provider_calls":0,"production_graph_writes":0,
            "scope":"Pinned single-host legacy adapter lifecycle and atomicity tests; not empirical semantic qualification."}
