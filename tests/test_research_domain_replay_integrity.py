"""A retrieval replay of a domain-aware context must state, and keep, its classification pin.

Synthetic fixtures only. The replay record is produced by `replay_retrieval`; each
negative case edits a copy of that record and re-stores it, so schema-valid forgeries
reach `validate_record`.
"""
from copy import deepcopy
import unittest

from trace_gc.errors import ContractError
from trace_gc.replay import replay_retrieval
from trace_gc.retrieval.contracts import RetrievalBudget, query
from trace_gc.retrieval.domains import research_domain_scope
from trace_gc.retrieval.fixtures import domain_corpus, SCOPE
from trace_gc.retrieval.integration import validate_record

PIN_KEYS = ("original_classification_identity", "replayed_classification_identity",
            "original_research_domain_scope", "replayed_research_domain_scope")


class ReplayClassificationPinTests(unittest.TestCase):
    def setUp(self):
        self.f = domain_corpus()
        self.c = self.f["catalog"]
        self.r = self.f["retriever"]
        self.scope = research_domain_scope(self.c, self.f["taxonomy_id"], ["research:biology"])
        budget = RetrievalBudget(maximum_tokens=150000, maximum_latency_ms=20000,
                                 maximum_edges=100, maximum_nodes=100, maximum_source_spans=100)
        request = query(requesting_component="replay-integrity", security_scope=SCOPE, text="improves",
                        strategies=["LEXICAL"], include_conflicts=False, research_domain_scope=self.scope, budget=budget)
        self.result_id = self.r.retrieve(request)
        self.replay_id = replay_retrieval(self.r, self.result_id, {"retrieval_strategy": ["LEXICAL"]})
        self.replay = self.c.get(self.replay_id, "retrieval-replay")

    def forge(self, mutate):
        body = deepcopy(self.replay)
        mutate(body)
        forged = self.c.put("retrieval-replay", body)
        return self.c.record(forged)

    def test_replay_of_a_scoped_context_records_and_validates_its_pins(self):
        context = self.c.get(self.c.get(self.result_id, "retrieval-result")["graph_context_id"], "graph-context")
        self.assertIn("classification_identity", context)
        for key in PIN_KEYS:
            self.assertIn(key, self.replay)
        self.assertEqual(self.replay["original_research_domain_scope"], self.scope)
        self.assertEqual(self.replay["replayed_research_domain_scope"], self.scope)
        validate_record(self.c, self.c.record(self.replay_id))

    def test_a_replay_that_omits_any_pin_is_rejected(self):
        for key in PIN_KEYS:
            with self.subTest(omitted=key), self.assertRaises(ContractError) as caught:
                validate_record(self.c, self.forge(lambda body, key=key: body.pop(key)))
            self.assertEqual(caught.exception.code, "DOMAIN_REVISION")

    def test_a_replay_with_a_changed_classification_revision_is_rejected(self):
        for prefix in ("original", "replayed"):
            with self.subTest(side=prefix), self.assertRaises(ContractError) as caught:
                validate_record(self.c, self.forge(
                    lambda body, prefix=prefix: body[prefix + "_classification_identity"].update(
                        revision=body[prefix + "_classification_identity"]["revision"] + 1)))
            self.assertEqual(caught.exception.code, "DOMAIN_REVISION")

    def test_a_replay_with_a_changed_scope_is_rejected(self):
        other = research_domain_scope(self.c, self.f["taxonomy_id"], ["research:chemistry"])
        for prefix in ("original", "replayed"):
            with self.subTest(side=prefix), self.assertRaises(ContractError) as caught:
                validate_record(self.c, self.forge(
                    lambda body, prefix=prefix: body.__setitem__(prefix + "_research_domain_scope", other)))
            self.assertEqual(caught.exception.code, "DOMAIN_REVISION")


if __name__ == "__main__":
    unittest.main()
