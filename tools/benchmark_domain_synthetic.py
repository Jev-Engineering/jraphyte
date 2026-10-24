#!/usr/bin/env python3
"""Fabricated single-host workload diagnostic, never representative acceptance."""
import argparse
from copy import deepcopy
from pathlib import Path
import sqlite3
import sys
import time
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "tests")]
from domain_retrieval_fixture import Fixture
from trace_gc.backend import SQLiteReferenceBackend
from trace_gc.canonical import digest, dumps, write
from trace_gc.retrieval.contracts import query, RetrievalBudget
from trace_gc.retrieval.domain_benchmark import WorkloadRequirements, run_workload, graph_shape
from trace_gc.retrieval.domain_operations import check_sandbox_backup_recovery
from trace_gc.retrieval.security import AccessFilter
from trace_gc.retrieval.service import HybridRetriever
from trace_gc.retrieval.store import SQLiteGraphAdapter


def run(concurrency, repeats):
    fixture = Fixture()
    f = fixture.f
    c = f.c
    try:
        snapshot = f.backend.state()
        corpus = {"origin": "FABRICATED_FIXTURE", "source_hashes": {s: c.hash(s) for s in sorted(fixture.sources.values())},
                  "graph_hash": digest(snapshot), "classification_hash": digest(snapshot["research_domains"])}
        requirements = WorkloadRequirements("synthetic-protocol-author-not-deployment-owner", "SYNTHETIC", digest(corpus),
            ("Disposable SQLite test authority on one host; no deployment isolation requirement supplied.",),
            False, 20000, 30000, concurrency, repeats)
        def request(strategy, scoped):
            q = query(requesting_component="downstream-synthetic-benchmark", security_scope="tenant-a", text="Biology",
                      strategies=[strategy], focus_entities=[fixture.claim, "paper", "entity-a"],
                      budget=RetrievalBudget(maximum_latency_ms=20000, maximum_cost_units=100000, maximum_tokens=100000))
            if scoped:
                q = query(requesting_component=q["requesting_component"], security_scope="tenant-a", text=q["text"],
                          strategies=[strategy], focus_entities=q["focus_entities"], budget=RetrievalBudget(**q["budget"]),
                          research_domain_scope=fixture.scope)
            return q
        cases = [{"id": f"{strategy.lower()}-{'scoped' if scoped else 'unscoped'}", "query": request(strategy, scoped),
                  "expected_evidence_ids": [fixture.evidence["bio"], fixture.evidence["comp"]]}
                 for strategy in ("LEXICAL", "VECTOR") for scoped in (False, True)]
        def reopen(path):
            return SQLiteReferenceBackend(path, catalog=c, schema_id=snapshot["schema_id"], nodes=snapshot["nodes"], sandbox=True)
        class Worker:
            def __init__(self):
                self.backend = reopen(f.path)
                self.adapter = SQLiteGraphAdapter(self.backend, classification_trust=f.trust)
                self.retriever = HybridRetriever(self.adapter, access_policy=fixture.policy)
            def execute(self, q):
                result_id = self.retriever.retrieve(q)
                catalog = self.retriever.catalog
                result = catalog.get(result_id, "retrieval-result")
                context = catalog.get(result["graph_context_id"], "graph-context")
                lineage = catalog.get(result["lineage_id"], "retrieval-lineage")
                memberships = {s: m for i in context["items"] for s, m in i.get("research_domain_context", {}).get("source_memberships", {}).items()}
                return {"selected_evidence_ids": context["selected_evidence_ids"], "cache_hit": lineage["cache_hit"],
                        "cache_invalidations": self.retriever.cache.invalidations, "response_status": result["status"],
                        "cross_domain_selected_sources": sum(bool(m["domain_ids"]) and "biology" not in m["domain_ids"] for m in memberships.values()) if "research_domain_scope" in q else None,
                        "unclassified_selected_sources": sum(m["state"] == "UNCLASSIFIED" for m in memberships.values()) if "research_domain_scope" in q else None,
                        "cost_units": result["usage"]["cost_units"], "vector_queries": result["usage"]["vector_queries"]}
            def close(self):
                self.backend.close()
        result = run_workload(Worker, cases, requirements)
        view = fixture.adapter.read(cases[0]["query"])
        acl = AccessFilter(fixture.policy, view.catalog, view.source_status)
        start = time.perf_counter()
        for _ in range(100):
            for evidence in fixture.evidence.values():
                acl.evidence(evidence)
        result["acl_probe"] = {"checks": 400, "milliseconds": (time.perf_counter()-start)*1000,
                               "scope": "separate warm in-process ACL+evidence-validation probe"}
        result["corpus_manifest"] = corpus
        result["graph_shape"] = graph_shape(view.snapshot)
        result["reference_working_set_json_bytes"] = len(dumps(snapshot).encode())
        result["database_bytes"] = f.backend.db.execute("PRAGMA page_count").fetchone()[0] * f.backend.db.execute("PRAGMA page_size").fetchone()[0]
        result["domain_index_rows"] = f.backend.db.execute("SELECT COUNT(*) FROM trace_domain_index").fetchone()[0]
        try:
            result["domain_index_pages_bytes"] = f.backend.db.execute("SELECT SUM(pgsize) FROM dbstat WHERE name IN ('trace_domain_index','trace_domain_lookup','trace_domain_index_meta')").fetchone()[0]
        except sqlite3.OperationalError:
            result["domain_index_pages_bytes"] = None
        result["sandbox_operations"] = check_sandbox_backup_recovery(f.backend, reopen=reopen,
            classification_trust=f.trust, query=cases[1]["query"])
        # A measured write/rebuild pair, not an inferred deployment write rate.
        start = time.perf_counter()
        fixture.classify("bio", ["biology", "computing"])
        result["classification_write_ms"] = (time.perf_counter()-start)*1000
        start = time.perf_counter()
        fixture.adapter.rebuild_domain_index()
        result["index_rebuild_after_write_ms"] = (time.perf_counter()-start)*1000
        fixture.retriever.retrieve(cases[1]["query"])
        invalidations = fixture.retriever.cache.invalidations
        f.revoke_source()
        fixture.adapter.rebuild_domain_index()
        revoked = fixture.retriever.retrieve(cases[1]["query"])
        body = fixture.retriever.catalog.get(revoked, "retrieval-result")
        result["revocation_probe"] = {"revoked_evidence_returned": fixture.evidence["bio"] in body["source_evidence_ids"],
                                      "cache_invalidations_delta": fixture.retriever.cache.invalidations - invalidations,
                                      "scope": "actual synthetic reference source-status transaction"}
        result["concurrency_scope"] = "independent connections and retrievers sharing one disposable SQLite authority"
        result["not_measured"] = ["representative high-degree corpus", "steady-state concurrent write rate", "deployment I/O cancellation",
                                  "distributed or cross-partition performance", "production memory working set"]
        return result
    finally:
        fixture.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--concurrency", type=int, default=2)
    parser.add_argument("--repeats", type=int, default=2)
    args = parser.parse_args()
    write(args.output, run(args.concurrency, args.repeats))
