"""Deterministic, non-vacuous provenance tampering and retrieval-budget boundary tests.

BudgetMeter binds ``time.monotonic`` as a keyword default when the class is
defined. Replacing ``time.monotonic`` later (or a module attribute) does not
reach it; the keyword default itself must be replaced. These tests prove that
the controlled clock reaches every meter, assert that the original selection and
citations are nonempty before any mutation, and keep the empty / budget-exhausted
boundary as a separate, explicitly asserted case. No production limit changes.
"""
from __future__ import annotations
from contextlib import contextmanager
from copy import deepcopy
import types
import unittest
from unittest import mock
from trace_gc.errors import ContractError
from trace_gc.retrieval import budget as budget_module
from trace_gc.retrieval.budget import BudgetMeter
from trace_gc.retrieval.contracts import RetrievalBudget, query
from trace_gc.retrieval.fixtures import SCOPE, corpus
from trace_gc.retrieval.integration import validate_record
from trace_gc.retrieval.service import GraphRAGQueryService, HybridRetriever
from trace_gc.retrieval.strategies import BuiltinStrategy


class StepClock:
    """Returns the current reading, then advances it by ``step`` seconds."""
    def __init__(self, *, start: float = 0.0, step: float = 0.0):
        self.now, self.step, self.calls = float(start), float(step), 0

    def __call__(self) -> float:
        self.calls += 1
        value = self.now
        self.now += self.step
        return value

    def advance(self, seconds: float) -> None:
        self.now += seconds


@contextmanager
def meter_clock(clock):
    with mock.patch.dict(BudgetMeter.__init__.__kwdefaults__, {"clock": clock}):
        yield clock


class AdvancingStrategy:
    """Delegates to a built-in strategy, then moves the controlled clock forward."""
    def __init__(self, inner: BuiltinStrategy, clock: StepClock, seconds: float):
        self.inner, self.clock, self.seconds = inner, clock, seconds
        self.name, self.version = inner.name, inner.version

    def retrieve(self, space):
        yield from self.inner.retrieve(space)
        self.clock.advance(self.seconds)


class BudgetClockReachTests(unittest.TestCase):
    def test_production_default_latency_is_unchanged(self):
        self.assertEqual(RetrievalBudget().maximum_latency_ms, 2000)

    def test_patched_keyword_default_reaches_every_meter_and_is_restored(self):
        original = BudgetMeter.__init__.__kwdefaults__["clock"]
        clock = StepClock()
        with meter_clock(clock):
            meter = BudgetMeter(RetrievalBudget())
            self.assertIs(meter.clock, clock)
            self.assertEqual(clock.calls, 1)
        self.assertIs(BudgetMeter.__init__.__kwdefaults__["clock"], original)
        self.assertIsNot(BudgetMeter(RetrievalBudget()).clock, clock)

    def test_replacing_the_module_time_attribute_does_not_reach_the_default(self):
        original = BudgetMeter.__init__.__kwdefaults__["clock"]
        fake = lambda: 10_000.0
        with mock.patch.object(budget_module, "time", types.SimpleNamespace(monotonic=fake)):
            meter = BudgetMeter(RetrievalBudget())
        self.assertIs(meter.clock, original)
        self.assertIsNot(meter.clock, fake)

    def test_latency_boundary_is_inclusive_at_the_limit(self):
        clock = StepClock()
        meter = BudgetMeter(RetrievalBudget(maximum_latency_ms=2000), clock=clock)
        clock.now = 2047 / 1024  # 1999.0234375 ms, exact in binary floating point
        meter.check()
        meter.work()
        self.assertIsNone(meter.exhausted)
        clock.now = 2.0
        with self.assertRaisesRegex(ContractError, "RETRIEVAL_BUDGET_EXHAUSTED"):
            meter.check()
        self.assertEqual(meter.exhausted, "latency")
        with self.assertRaisesRegex(ContractError, "RETRIEVAL_BUDGET_EXHAUSTED"):
            meter.work()

    def test_clock_running_backwards_never_reports_negative_elapsed_time(self):
        clock = StepClock(start=5.0)
        meter = BudgetMeter(RetrievalBudget(maximum_latency_ms=1), clock=clock)
        clock.now = 1.0
        self.assertEqual(meter.elapsed_ms, 0.0)
        meter.check()


class RetrievalDiagnosticsMixin:
    def setUp(self):
        self.f = corpus()
        self.c = self.f["catalog"]

    def request(self, **changes):
        return query(requesting_component="downstream-search", security_scope=SCOPE,
                     focus_entities=changes.pop("focus_entities", [self.f["claim_id"]]),
                     strategies=changes.pop("strategies", ["NEIGHBORHOOD", "CONFLICT"]), **changes)

    def answer(self, retriever=None, **changes):
        answer = GraphRAGQueryService(retriever or self.f["retriever"]).query(self.request(**changes))
        body = answer["context"]
        result = self.c.get(body["result_id"], "retrieval-result")
        context = self.c.get(body["graph_context_id"], "graph-context")
        lineage = self.c.get(result["lineage_id"], "retrieval-lineage")
        detail = {"status": result["status"], "warnings": body["warnings"], "stop_reason": lineage["stop_reason"],
                  "usage": result["usage"], "latency_ms": lineage["latency_ms"],
                  "selected_evidence_ids": context["selected_evidence_ids"]}
        return body, result, context, lineage, detail

    def reject(self, body, detail=None):
        with self.assertRaisesRegex(ContractError, "PROVENANCE_MISMATCH", msg=str(detail)):
            validate_record(self.c, self.c.record(self.c.put("graphrag-answer", body)))


class CitationTamperTests(RetrievalDiagnosticsMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.clock = StepClock()
        patcher = meter_clock(self.clock)
        patcher.__enter__()
        self.addCleanup(patcher.__exit__, None, None, None)
        self.body, self.result, self.context, self.lineage, self.detail = self.answer()

    def test_original_answer_is_nonempty_attributed_and_valid(self):
        self.assertGreater(self.clock.calls, 0, "controlled clock did not reach BudgetMeter")
        self.assertNotIn("RETRIEVAL_BUDGET_EXHAUSTED", self.body["warnings"], self.detail)
        selected = self.context["selected_evidence_ids"]
        self.assertTrue(selected, self.detail)
        self.assertEqual(sorted(x["evidence_id"] for x in self.body["citations"]), selected, self.detail)
        expected = {self.f["evidence"]["e-support"], self.f["evidence"]["e-refute"]}
        self.assertLessEqual(expected, set(selected), self.detail)
        validate_record(self.c, self.c.record(self.c.put("graphrag-answer", deepcopy(self.body))))

    def test_removing_all_citations_is_rejected(self):
        body = deepcopy(self.body)
        self.assertTrue(body["citations"], self.detail)
        body["citations"] = []
        self.reject(body, self.detail)

    def test_removing_any_single_citation_is_rejected(self):
        self.assertGreaterEqual(len(self.body["citations"]), 2, self.detail)
        for index in range(len(self.body["citations"])):
            with self.subTest(removed=self.body["citations"][index]["evidence_id"]):
                body = deepcopy(self.body)
                del body["citations"][index]
                self.reject(body, self.detail)

    def test_duplicating_a_citation_is_rejected(self):
        body = deepcopy(self.body)
        body["citations"].append(deepcopy(body["citations"][0]))
        self.reject(body, self.detail)

    def test_substituting_an_unselected_evidence_span_is_rejected(self):
        unselected = self.f["evidence"]["e-owns"]
        self.assertNotIn(unselected, self.context["selected_evidence_ids"], self.detail)
        evidence = self.c.get(unselected, "evidence")
        source = self.c.get(evidence["source_snapshot_id"], "source")
        body = deepcopy(self.body)
        body["citations"][0] = {"evidence_id": unselected, "source_snapshot_id": evidence["source_snapshot_id"],
                                "source_id": source["source_id"], "source_hash": evidence["source_hash"],
                                "start": evidence["start"], "end": evidence["end"], "quote": evidence["quote"]}
        self.reject(body, self.detail)

    def test_changing_any_attributed_field_is_rejected(self):
        other = self.c.get(self.f["sources"]["e-owns"], "source")
        changes = {"quote": "a quotation the source does not contain", "source_hash": "0" * 64,
                   "start": self.body["citations"][0]["start"] + 1, "end": self.body["citations"][0]["end"] + 1,
                   "source_snapshot_id": self.f["sources"]["e-owns"], "source_id": other["source_id"]}
        for field, value in changes.items():
            with self.subTest(field=field):
                body = deepcopy(self.body)
                body["citations"][0][field] = value
                self.reject(body, self.detail)


class EmptyAndExhaustedBoundaryTests(RetrievalDiagnosticsMixin, unittest.TestCase):
    def fabricated_citation(self, body):
        evidence_id = self.f["evidence"]["e-support"]
        evidence = self.c.get(evidence_id, "evidence")
        source = self.c.get(evidence["source_snapshot_id"], "source")
        forged = deepcopy(body)
        forged["citations"] = [{"evidence_id": evidence_id, "source_snapshot_id": evidence["source_snapshot_id"],
                                "source_id": source["source_id"], "source_hash": evidence["source_hash"],
                                "start": evidence["start"], "end": evidence["end"], "quote": evidence["quote"]}]
        return forged

    def test_first_check_exhaustion_is_partial_with_no_context_and_still_validates(self):
        clock = StepClock(step=5.0)
        with meter_clock(clock):
            body, result, context, lineage, detail = self.answer()
        self.assertGreater(clock.calls, 0, "controlled clock did not reach BudgetMeter")
        self.assertEqual(result["status"], "PARTIAL", detail)
        self.assertEqual(lineage["stop_reason"], "RETRIEVAL_BUDGET_EXHAUSTED", detail)
        self.assertGreaterEqual(lineage["latency_ms"], 2000, detail)
        self.assertEqual((body["items"], body["citations"], context["selected_evidence_ids"]), ([], [], []), detail)
        self.assertIn("RETRIEVAL_BUDGET_EXHAUSTED", body["warnings"], detail)
        self.assertIn("NO_AUTHORIZED_CONTEXT", body["warnings"], detail)
        validate_record(self.c, self.c.record(self.c.put("graphrag-answer", deepcopy(body))))
        self.reject(self.fabricated_citation(body), detail)

    def test_latency_expiry_rejects_the_conflict_and_blocks_its_member_edges_for_a_separate_reason(self):
        clock = StepClock()
        strategies = {"NEIGHBORHOOD": AdvancingStrategy(BuiltinStrategy("NEIGHBORHOOD"), clock, 10.0)}
        retriever = HybridRetriever(self.f["adapter"], catalog=self.c, access_policy=self.f["access"], strategies=strategies)
        with meter_clock(clock):
            body, result, context, lineage, detail = self.answer(retriever)
        self.assertGreater(clock.calls, 0, "controlled clock did not reach BudgetMeter")
        self.assertEqual(result["status"], "PARTIAL", detail)
        self.assertEqual(lineage["stop_reason"], "CONTEXT_BUDGET_REACHED", detail)
        self.assertTrue(lineage["discarded"], detail)
        kinds = {row["item_id"]: row["kind"] for row in lineage["candidates"]}
        self.assertIn("CONFLICT", kinds.values(), detail)
        reasons = {}
        for row in lineage["discarded"]:
            reasons.setdefault(kinds[row["item_id"]], set()).add(row["reason"])
        # Ranking puts the conflict first: it is rejected for latency. Its constituent
        # edges are then deliberately blocked so that half a pair is never selected.
        self.assertEqual(kinds[lineage["discarded"][0]["item_id"]], "CONFLICT", detail)
        self.assertEqual(reasons["CONFLICT"], {"latency_budget"}, detail)
        self.assertIn("EDGE", reasons, detail)
        self.assertEqual(reasons["EDGE"], {"incomplete_conflict_pair_blocked"}, detail)
        self.assertLessEqual(set(reasons), {"CONFLICT", "EDGE"}, detail)
        self.assertIn("CONFLICT_PAIR_EXCLUDED_BY_BUDGET", body["warnings"], detail)
        self.assertEqual((body["items"], body["citations"], context["selected_evidence_ids"]), ([], [], []), detail)
        validate_record(self.c, self.c.record(self.c.put("graphrag-answer", deepcopy(body))))
        self.reject(self.fabricated_citation(body), detail)

    def test_same_wrapper_without_clock_advance_selects_cited_context(self):
        clock = StepClock()
        strategies = {"NEIGHBORHOOD": AdvancingStrategy(BuiltinStrategy("NEIGHBORHOOD"), clock, 0.0)}
        retriever = HybridRetriever(self.f["adapter"], catalog=self.c, access_policy=self.f["access"], strategies=strategies)
        with meter_clock(clock):
            body, result, context, lineage, detail = self.answer(retriever)
        self.assertTrue(context["selected_evidence_ids"], detail)
        self.assertEqual(sorted(x["evidence_id"] for x in body["citations"]), context["selected_evidence_ids"], detail)
        self.assertNotIn("latency_budget", {x["reason"] for x in lineage["discarded"]}, detail)
        self.assertNotEqual(lineage["stop_reason"], "RETRIEVAL_BUDGET_EXHAUSTED", detail)

    def test_empty_request_is_empty_not_budget_exhausted(self):
        with meter_clock(StepClock()):
            body, result, context, lineage, detail = self.answer(strategies=[])
        self.assertEqual(result["status"], "EMPTY", detail)
        self.assertNotIn("RETRIEVAL_BUDGET_EXHAUSTED", body["warnings"], detail)
        self.assertIn("NO_AUTHORIZED_CONTEXT", body["warnings"], detail)
        self.assertEqual((body["citations"], context["selected_evidence_ids"]), ([], []), detail)
        validate_record(self.c, self.c.record(self.c.put("graphrag-answer", deepcopy(body))))
        self.reject(self.fabricated_citation(body), detail)


if __name__ == "__main__":
    unittest.main()
