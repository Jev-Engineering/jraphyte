"""Fabricated reference workload; not a representative corpus or production input.

Graph fixture seeds use the low-level sandbox transaction boundary explicitly.
Domain assignments themselves use normal signed review/preflight/publication.
"""
from copy import deepcopy
import test_domain_publication as fixtures
from trace_gc.canonical import digest
from trace_gc.constraints import validate_graph
from trace_gc.domains import propose, review_payload, assign, REVIEW_PURPOSE
from trace_gc.retrieval.security import access_policy, grant
from trace_gc.retrieval.store import SQLiteGraphAdapter
from trace_gc.retrieval.service import HybridRetriever
from trace_gc.retrieval.domain_scope import scope
from trace_gc.retrieval.vector import HashingEmbedding


class SpyEmbedding(HashingEmbedding):
    version = "test-spy-token-hash-v1"
    def __init__(self, callback=None):
        self.calls, self.callback = [], callback
    def embed(self, texts):
        self.calls.append(list(texts))
        if self.callback:
            self.callback()
        return super().embed(texts)


class Fixture:
    def __init__(self):
        f = self.f = fixtures.DomainPublication()
        f.setUp()
        c = f.c
        self.sources = {"bio": f.source}
        for tag, doc, text in [
            ("comp", "computing-paper", "Computing contradicts the Biology claim."),
            ("unknown", "unclassified-paper", "Unclassified Biology identity evidence."),
            ("secret", "secret-paper", "Secret Biology material must never be embedded.")]:
            self.sources[tag] = c.source(doc, "1", text, scope="tenant-a")
        self.evidence = {tag: c.evidence(s) for tag, s in self.sources.items()}
        at = f.time()
        version = f.backend.state()["graph_version"]
        source_ids = sorted(set(self.sources.values()) - {f.source})
        action = {"action": "ADMIT", "source_hashes": {s: c.hash(s) for s in source_ids},
                  "security_scope": "tenant-a", "execution_mode": "SYNTHETIC", "expected_version": version}
        f.backend.admit_sources(c, source_ids, trust=f.trust,
            authorization=f.source_signer.issue("SOURCE_STATUS", action, issued_at=at),
            security_scope="tenant-a", execution_mode="SYNTHETIC", expected_version=version, key="fixture-admit-more", at=at)
        self.claim = c.claim("Biology claim and computing hypothesis")
        def relation(symmetric=False, incompatible=()):
            return {"domain": "*", "range": "*", "symmetric": symmetric, "inverse_of": None,
                    "incompatible": list(incompatible), "transitive": False, "allow_self": False}
        relations = {"related": relation(), "supports": relation(incompatible=["refutes"]),
                     "refutes": relation(incompatible=["supports"]), "same_as": relation(True),
                     "different_from": relation(True)}
        schema = c.put("schema", {"version": "domain-query-fixture-v1", "relations": relations})
        nodes = {"paper": "Document", "computing-paper": "Document", "unclassified-paper": "Document",
                 "secret-paper": "Document", self.claim: "Claim", "entity-a": "Person", "entity-b": "Person",
                 "entity-c": "Person", "outside-1": "Person", "outside-2": "Person", "secret-node": "Person"}
        def fact(s, p, o, tag, dependencies=()):
            return {"assertion": {"subject": s, "predicate": p, "object": o, "qualifiers": {}},
                    "evidence_ids": [self.evidence[tag]], "prerequisites": list(dependencies), "active": True, "revision": 1}
        self.facts = {
            "bio-support": fact("paper", "supports", self.claim, "bio"),
            "comp-refute": fact("computing-paper", "refutes", self.claim, "comp"),
            "bio-link": fact("paper", "related", "entity-a", "bio"),
            "cross-identity": fact("entity-a", "same_as", "entity-b", "comp"),
            "unclassified-identity": fact("entity-a", "different_from", "entity-c", "unknown"),
            "unrelated-comp": fact("outside-1", "related", "outside-2", "comp"),
            "secret-edge": fact("secret-paper", "related", "secret-node", "secret"),
        }
        validate_graph(nodes, self.facts, relations)
        self.seed(lambda state: {**state, "schema_id": schema, "schema_hash": c.hash(schema),
                                "nodes": nodes, "assertions": deepcopy(self.facts)}, "fabricated-graph")
        # Normal immutable candidate, pack and observation records, with a mock
        # response body explicitly produced by the existing synthetic fixture.
        from trace_gc.compiler import compile_pack
        from trace_gc.programs import question
        from trace_gc.adapter import record_response
        from trace_gc.demo import fixture_response
        snapshot = f.backend.snapshot(c)
        self.candidates, self.observations = {}, {}
        for tag in self.sources:
            source = c.get(self.sources[tag], "source")
            candidate = c.candidate(id_="past-" + tag, run_id="fixture-run", claim_id=self.claim,
                assertion={"subject": source["source_id"], "predicate": "supports", "object": self.claim, "qualifiers": {}},
                evidence_ids=[self.evidence[tag]], mode="SYNTHETIC")
            self.candidates[tag] = candidate
            pack = compile_pack(c, id_="pack-"+tag, run_id="fixture-run", candidate_ids=[candidate],
                questions=[question(candidate, id_="q")], snapshot_id=snapshot, security_scope="tenant-a",
                execution_mode="SYNTHETIC", created_at=f.time(), request_cap=1_000_000, state_longest_cap=1_000_000)
            self.observations[tag] = record_response(c, pack, fixture_response(c.get(pack, "pack")), completed_at=f.time())[0]
        self.seed(lambda state: state, "fabricated-observations")
        f.migrate()
        self.assignments = {}
        self.classify("bio", ["biology"])
        self.classify("comp", ["computing"])
        self.classify("secret", ["biology"])
        self.adapter = SQLiteGraphAdapter(f.backend, classification_trust=f.trust)
        self.adapter.rebuild_domain_index()
        grants = {"node:"+n: grant("tenant-a", "test") for n in nodes}
        grants.update({"source:"+s: grant("tenant-a", "test") for tag, s in self.sources.items() if tag != "secret"})
        grants.update({"edge:"+r: grant("tenant-a", "test") for r in self.facts})
        grants.update({"decision:"+r: grant("tenant-a", "test") for r in list(self.candidates.values())+list(self.observations.values())})
        grants["schema:"+schema] = grant("tenant-a", "test")
        self.policy = access_policy(tenant="tenant-a", workspace="test", user="reader", grants=grants)
        self.embedding = SpyEmbedding()
        self.retriever = HybridRetriever(self.adapter, access_policy=self.policy, embedding=self.embedding)
        self.scope = scope(taxonomy_id=f.tax, taxonomy_hash=c.hash(f.tax), domain_ids=["biology"])

    def seed(self, apply, key):
        f = self.f
        action = {"action": "SYNTHETIC_FIXTURE_SEED", "fixture_key": key}
        f.backend._transaction(key=key, fingerprint=digest(action), expected_version=f.backend.state()["graph_version"],
            operation=action, catalog=f.c, apply=lambda state, statuses: apply(state),
            authorization_hash=digest("NOT_PRODUCTION_FIXTURE"), preflight_hash=digest("NOT_PRODUCTION_FIXTURE"), at=f.time())

    def classify(self, tag, labels, *, state="CLASSIFIED"):
        f, c = self.f, self.f.c
        proposal = propose(c, source_snapshot_id=self.sources[tag], taxonomy_id=f.tax, domain_ids=labels,
            source_epoch=f.backend.statuses()[self.sources[tag]]["epoch"], state=state, method=f.method,
            basis_ids=[self.evidence[tag]],
            effective_graph_version=f.backend.state()["graph_version"]+1, execution_mode="SYNTHETIC",
            supersedes=self.assignments.get(tag), created_at=f.time())
        review = f.review.issue(REVIEW_PURPOSE, review_payload(c, proposal, "reviewer"), issued_at=f.time())
        rid = c.put("receipt", review)
        assignment = assign(c, proposal_id=proposal, review_receipt_id=rid, reviewed_by="reviewer", trust=f.trust, at=f.time())
        f.publish(f.plan(assignment))
        self.assignments[tag] = assignment
        return assignment

    def close(self):
        self.f.doCleanups()
