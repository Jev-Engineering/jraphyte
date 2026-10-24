"""Adversarial authority and deployment-gate conformance; fabricated test data only."""
from __future__ import annotations

from copy import deepcopy
import os
from pathlib import Path
import tempfile
import unittest

from trace_gc.backend import SQLiteReferenceBackend
from trace_gc.canonical import digest, dumps, loads
from trace_gc.catalog import Catalog
from trace_gc.domain_conformance import run_domain_conformance
from trace_gc.errors import ContractError
from trace_gc.retrieval.contracts import query, RetrievalBudget
from trace_gc.retrieval.domains import research_domain_scope
from trace_gc.retrieval.fixtures import domain_corpus, SCOPE
from trace_gc.retrieval.items import canonical_item
from trace_gc.retrieval.store import InMemoryGraphAdapter, SQLiteGraphAdapter
from test_research_domain_transactions import DomainFixture


class DomainAdversarialAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.f = DomainFixture(self.directory.name)

    def tearDown(self):
        self.f.close()
        self.directory.cleanup()

    def request(self, **updates):
        return query(requesting_component="downstream-search", security_scope="test", strategies=["LEXICAL"],
                     text="biology", **updates)

    def rewrite_latest_signature_with_consistent_hashes(self, purpose):
        """An attacker controls local DB bytes, not an enrolled private signing key.

        Rehash the forged record, enclosing event, and transaction receipt. A
        hash-consistent journal MUST NOT be confused with authenticated authority.
        """
        b = self.f.backend
        version, text = b.db.execute("SELECT version,body FROM trace_journal ORDER BY version DESC LIMIT 1").fetchone()
        event = loads(text)
        field = "authorization_hash" if purpose == "AUTHORIZATION" else "preflight_hash"
        records = b.load_catalog()
        original = next(row for row in records.all("receipt") if digest(row["body"]) == event[field])
        forged = deepcopy(original["body"])
        # Keep valid signature encoding and all semantic payload bindings, but
        # alter one base64 byte so cryptographic verification must be exercised.
        forged["signature"] = ("A" if forged["signature"][0] != "A" else "B") + forged["signature"][1:]
        ref = records.put("receipt", forged)
        row = records.record(ref)
        b.db.execute("INSERT INTO trace_records VALUES(?,?,?,?)", (ref, row["hash"], "receipt", dumps(forged)))
        event["record_hashes"][ref] = row["hash"]
        event[field] = digest(forged)
        event["hash"] = digest({k: v for k, v in event.items() if k not in {"hash", "transaction_receipt"}})
        event["transaction_receipt"][field] = event[field]
        event["transaction_receipt"]["event_hash"] = event["hash"]
        receipt = event["transaction_receipt"]
        rh = digest({"kind": "transaction", "body": receipt})
        b.db.execute("INSERT INTO trace_records VALUES(?,?,?,?)", ("transaction:" + rh, rh, "transaction", dumps(receipt)))
        b.db.execute("UPDATE trace_journal SET body=?,hash=? WHERE version=?", (dumps(event), event["hash"], version))

    def test_rehashed_approval_fails_authenticated_read(self):
        self.f.migrate()
        self.rewrite_latest_signature_with_consistent_hashes("AUTHORIZATION")
        audit = self.f.backend.audit()
        self.assertFalse(audit["classification_authority_verified"])
        with self.assertRaises(ContractError) as caught:
            SQLiteGraphAdapter(self.f.backend, audit_trust=self.f.trust).read(self.request())
        self.assertEqual(caught.exception.code, "SIGNATURE_INVALID")

    def test_rehashed_preflight_fails_authenticated_audit(self):
        self.f.migrate()
        self.rewrite_latest_signature_with_consistent_hashes("PREFLIGHT")
        self.assertFalse(self.f.backend.audit()["classification_authority_verified"])
        with self.assertRaises(ContractError) as caught:
            self.f.backend.audit(trust=self.f.trust)
        self.assertEqual(caught.exception.code, "SIGNATURE_INVALID")

    def test_revoked_reviewer_does_not_pass_historical_read_authentication(self):
        self.f.migrate()
        self.f.trust.revoke(self.f.reviewer.issuer)
        with self.assertRaises(ContractError) as caught:
            SQLiteGraphAdapter(self.f.backend, audit_trust=self.f.trust).read(self.request(graph_version=2))
        self.assertEqual(caught.exception.code, "UNTRUSTED_ISSUER")

    def test_non_sandbox_scoped_read_requires_explicit_application_trust(self):
        # Deliberately exercise the non-sandbox configuration in a TEMPORARY,
        # empty reference database. This is not a real deployment or data set.
        with SQLiteReferenceBackend(Path(self.directory.name) / "untrusted-read.db", catalog=self.f.catalog,
                    schema_id=self.f.schema, nodes={"a": "Entity", "b": "Entity"}, sandbox=False) as backend:
            scope = research_domain_scope(self.f.catalog, self.f.taxonomy, ["research:biology"])
            with self.assertRaises(ContractError) as caught:
                SQLiteGraphAdapter(backend).read(self.request(research_domain_scope=scope))
            self.assertEqual(caught.exception.code, "CLASSIFICATION_TRUST_REQUIRED")
            self.assertEqual(backend.state()["graph_version"], 0)
            self.assertEqual(backend.audit()["events"], 0)

    def test_index_rebuild_cannot_override_failed_signature_gate(self):
        self.f.migrate()
        adapter = SQLiteGraphAdapter(self.f.backend, audit_trust=self.f.trust)
        before = adapter.read(self.request())
        rows = list(self.f.backend.db.execute("SELECT * FROM trace_domain_index_meta"))
        self.rewrite_latest_signature_with_consistent_hashes("AUTHORIZATION")
        with self.assertRaises(ContractError):
            adapter.rebuild_classification_index(self.request())
        self.assertEqual(rows, list(self.f.backend.db.execute("SELECT * FROM trace_domain_index_meta")))
        self.assertEqual(before.snapshot["graph_version"], 2)


class DomainCandidateIsolationTests(unittest.TestCase):
    def setUp(self):
        self.f = domain_corpus()

    def request(self, **changes):
        return query(requesting_component="downstream-search", security_scope=SCOPE, strategies=["LEXICAL"],
            text="dataset", include_conflicts=False,
            research_domain_scope=research_domain_scope(self.f["catalog"], self.f["taxonomy_id"], ["research:biology"]),
            budget=RetrievalBudget(maximum_tokens=150000, maximum_latency_ms=20000), **changes)

    def test_ambiguous_graph_version_is_rejected(self):
        c = self.f["catalog"]
        adapter = self.f["retriever"].adapter
        selected = adapter.read(self.request())
        wrong = deepcopy(selected.snapshot)
        wrong["classifications"]["assignments"] = {}
        competing = c.put("graph-snapshot", wrong)
        mixed = InMemoryGraphAdapter(c, [selected.snapshot_id, competing], selected.source_status)
        for request in (self.request(), self.request(graph_version=selected.snapshot["graph_version"])):
            with self.subTest(version=request["graph_version"]), self.assertRaises(ContractError) as caught:
                mixed.read(request)
            self.assertEqual(caught.exception.code, "GRAPH_VERSION_AMBIGUOUS")

    def test_repeated_identical_snapshot_is_not_an_ambiguity(self):
        c = self.f["catalog"]
        view = self.f["retriever"].adapter.read(self.request())
        adapter = InMemoryGraphAdapter(c, [view.snapshot_id, view.snapshot_id], view.source_status)
        self.assertEqual(adapter.read(self.request()).snapshot_id, view.snapshot_id)

    def test_plugin_cannot_promote_mutated_selection_into_canonical_context_or_cache(self):
        f = self.f
        evidence = f["evidence"]["e-dataset"]
        source = f["sources"]["e-dataset"]
        class MutatingStrategy:
            version = "malicious-mutable-selection-test-v1"
            def retrieve(self, space):
                # A custom Python plugin is trusted code, not a process sandbox.
                # Even so, mutating its candidate membership cache must never
                # become authoritative materialization or a reusable cache entry.
                space.domain_selection._source_rows[source]["domain_ids"] = ["research:biology"]
                space.domain_selection._candidate_cache.clear()
                yield canonical_item(space.view, space.access, space.query, kind="EVIDENCE", ref=evidence,
                    members=[], edges=space.edges, conflicts=space.conflicts, domain_selection=space.domain_selection)
        r = f["retriever"]
        r.strategies["LEXICAL"] = MutatingStrategy()
        with self.assertRaises(ContractError) as caught:
            r.retrieve(self.request())
        self.assertIn(caught.exception.code, {"RESEARCH_DOMAIN_SCOPE", "DOMAIN_SCOPE", "CONTEXT_MATERIALIZATION"})
        self.assertEqual(len(r.cache._entries), 0)
        self.assertEqual(r.catalog.all("retrieval-result"), [])


class DomainExecutableConformanceTests(unittest.TestCase):
    def test_reference_driver_executes_recorded_lifecycle(self):
        report = run_domain_conformance()
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["checks_run"], 13)
        self.assertEqual(report["classification_events"], 4)
        self.assertEqual(report["production_qualification"], "NOT_ESTABLISHED")
        self.assertEqual(report["production_graph_writes"], 0)
        self.assertEqual(report["label_origin"], "FABRICATED_CONFORMANCE_ONLY")

    def test_legacy_gate_rejects_nonmatching_source_before_execution(self):
        from trace_gc.conformance import check_legacy
        with tempfile.TemporaryDirectory() as directory:
            wrong = Path(directory) / "core.py"
            wrong.write_text("raise AssertionError('must not execute unreviewed legacy source')\n")
            with self.assertRaises(ContractError) as caught:
                check_legacy(wrong)
            self.assertEqual(caught.exception.code, "UPSTREAM_PIN_MISMATCH")


if __name__ == "__main__":
    unittest.main()
