"""Synthetic regressions: required fact prerequisites travel with an in-domain anchor.

The fixture classifies only the anchor's own sources; the prerequisite chain comes
from unclassified sources, so it can only enter a result as authorized required
closure, never as an independent topical hit.
"""
from copy import deepcopy
from dataclasses import replace
import unittest

from trace_gc.constraints import validate_graph
from trace_gc.errors import ContractError
from trace_gc.retrieval.contracts import RetrievalBudget, query
from trace_gc.retrieval.domains import research_domain_scope
from trace_gc.retrieval.fixtures import domain_corpus, demo_access, SCOPE
from trace_gc.retrieval.service import HybridRetriever, validate_context
from trace_gc.retrieval.store import InMemoryGraphAdapter


class PrerequisiteClosureTests(unittest.TestCase):
    def setUp(self):
        self.f = domain_corpus()
        self.c = self.f['catalog']
        self.snapshot = self.c.get(self.f['snapshot_id'], 'graph-snapshot')
        self.statuses = deepcopy(self.f['statuses'])
        self.sources, self.evidence = {}, {}
        # e-support -> e-prereq-1 -> e-prereq-2 (both outside the selected domain)
        for ref, subject, obj in (('e-prereq-1', 'Paper-D', 'Method-S1'), ('e-prereq-2', 'Paper-E', 'Method-S2')):
            self.snapshot['nodes'].update({subject: 'Document', obj: 'Method'})
            source = self.c.source('source-' + ref, '1', 'Synthetic prerequisite fact ' + ref + '.', scope=SCOPE)
            evidence = self.c.evidence(source)
            self.sources[ref], self.evidence[ref] = source, evidence
            self.statuses[source] = {'active': True, 'permission': 'READ', 'epoch': 1,
                                     'updated_at': '2026-09-27T00:00:00Z', 'tombstone': False}
            self.snapshot['source_epochs'][source] = 1
            self.snapshot['assertions'][ref] = {
                'assertion': {'subject': subject, 'predicate': 'uses_method', 'object': obj, 'qualifiers': {}},
                'evidence_ids': [evidence], 'prerequisites': [], 'active': True, 'revision': 1}
        self.snapshot['assertions']['e-prereq-1']['prerequisites'] = ['e-prereq-2']
        self.snapshot['assertions']['e-support']['prerequisites'] = ['e-prereq-1']
        self.scope = research_domain_scope(self.c, self.f['taxonomy_id'], ['research:biology'])
        self.budget = RetrievalBudget(maximum_tokens=150000, maximum_latency_ms=20000,
                                      maximum_edges=100, maximum_nodes=100, maximum_source_spans=100)
        self.refresh()

    def refresh(self):
        validate_graph(self.snapshot['nodes'], self.snapshot['assertions'],
                       self.c.get(self.snapshot['schema_id'], 'schema')['relations'])
        self.snapshot_id = self.c.put('graph-snapshot', self.snapshot)
        self.adapter = InMemoryGraphAdapter(self.c, [self.snapshot_id], self.statuses)
        self.retriever = HybridRetriever(self.adapter, catalog=self.c,
                                         access_policy=demo_access(self.c, self.snapshot_id))

    def request(self, **changes):
        return query(requesting_component='prerequisite-closure-regression', security_scope=SCOPE,
                     text=changes.pop('text', 'improves'), strategies=changes.pop('strategies', ['LEXICAL']),
                     include_conflicts=False, research_domain_scope=changes.pop('research_domain_scope', self.scope),
                     budget=changes.pop('budget', self.budget), **changes)

    def retrieve(self, **changes):
        result = self.c.get(self.retriever.retrieve(self.request(**changes)), 'retrieval-result')
        context = self.c.get(result['graph_context_id'], 'graph-context')
        validate_context(self.c, result['graph_context_id'], current_access=self.retriever.access_policy,
                         current_status=self.adapter.current_source_status())
        return result, context

    def assertNoGraphState(self, context):
        # A bare source span may remain an in-domain evidence hit; no graph fact may.
        self.assertEqual([i['kind'] for i in context['items'] if i['kind'] != 'EVIDENCE'], [])
        self.assertTrue(all(not i['assertion_ids'] for i in context['items']))
        self.assertNotIn('e-support', context['retrieved_edges'])
        for ref in ('e-prereq-1', 'e-prereq-2'):
            self.assertNotIn(self.evidence[ref], context['selected_evidence_ids'])

    def deny(self, ref):
        policy = deepcopy(self.retriever.access_policy)
        del policy['grants']['source:' + self.sources[ref]]
        self.retriever.set_access_policy(policy)

    def test_complete_prerequisite_chain_travels_with_the_anchor(self):
        _, context = self.retrieve()
        self.assertEqual(len(context['items']), 1)
        item = context['items'][0]
        self.assertTrue({'e-support', 'e-prereq-1', 'e-prereq-2'} <= set(item['assertion_ids']))
        for ref in ('e-prereq-1', 'e-prereq-2'):
            self.assertIn(self.evidence[ref], item['evidence_ids'])
            self.assertIn(self.sources[ref], item['source_ids'])
            self.assertIn(ref, item['research_domain']['closure_assertion_ids'])
        self.assertIn('e-support', item['research_domain']['anchor_assertion_ids'])
        self.assertTrue({'e-prereq-1', 'e-prereq-2'} <= set(context['retrieved_edges']))

    def test_prerequisite_is_never_an_independent_topical_hit(self):
        _, context = self.retrieve(text='Synthetic prerequisite fact e-prereq-2')
        self.assertEqual(context['items'], [])
        self.assertNotIn('e-prereq-2', context['retrieved_edges'])

    def test_denied_first_level_prerequisite_excludes_the_dependent_without_leakage(self):
        self.deny('e-prereq-1')
        _, context = self.retrieve()
        self.assertNoGraphState(context)

    def test_denied_transitive_prerequisite_excludes_the_dependent_without_leakage(self):
        self.deny('e-prereq-2')
        _, context = self.retrieve()
        self.assertNoGraphState(context)

    def test_revoked_prerequisite_source_invalidates_cached_closure_and_old_context(self):
        original, context = self.retrieve()
        self.assertIn('e-prereq-2', context['retrieved_edges'])
        self.retrieve()
        self.assertEqual(self.retriever.cache.hits, 1)
        self.adapter.source_status[self.sources['e-prereq-2']].update(active=False, epoch=2)
        _, revoked = self.retrieve()
        self.assertNoGraphState(revoked)
        with self.assertRaises(ContractError):
            validate_context(self.c, original['graph_context_id'], current_access=self.retriever.access_policy,
                             current_status=self.adapter.current_source_status())

    def test_prerequisite_outside_the_requested_validity_window_excludes_the_dependent(self):
        self.snapshot['assertions']['e-prereq-2']['assertion']['qualifiers']['valid_until'] = '2020-01-01T00:00:00Z'
        self.refresh()
        _, unscoped = self.retrieve()
        self.assertIn('e-prereq-2', unscoped['items'][0]['assertion_ids'])
        _, context = self.retrieve(temporal_scope={'as_of': None, 'valid_at': '2026-01-01T00:00:00Z', 'before_source': None})
        self.assertNoGraphState(context)

    def test_unrelated_anchor_is_unaffected_by_a_denied_prerequisite(self):
        self.deny('e-prereq-2')
        _, context = self.retrieve(text='Acme owns Bar')
        self.assertIn('e-owns', context['retrieved_edges'])

    def test_budget_rejects_the_entire_anchor_not_the_prerequisite_proof(self):
        accepted, context = self.retrieve()
        needed = len(context['items'][0]['assertion_ids'])
        spans = len(context['items'][0]['evidence_ids'])
        self.assertGreaterEqual(needed, 3)
        for budget in (replace(self.budget, maximum_edges=needed - 1),
                       replace(self.budget, maximum_source_spans=spans - 1)):
            with self.subTest(budget=budget):
                result, rejected = self.retrieve(budget=budget)
                self.assertEqual(result['status'], 'PARTIAL')
                self.assertEqual(rejected['items'], [])
                self.assertEqual(rejected['selected_evidence_ids'], [])
        exact, fitted = self.retrieve(budget=replace(self.budget, maximum_edges=needed, maximum_source_spans=spans))
        self.assertEqual(len(fitted['items']), 1)

    def test_budget_sized_for_the_unproven_anchor_alone_is_rejected(self):
        _, full = self.retrieve()
        full_edges = len(full['items'][0]['assertion_ids'])
        bare = deepcopy(self.snapshot)
        for ref in ('e-prereq-1', 'e-prereq-2'):
            del bare['assertions'][ref]
        bare['assertions']['e-support']['prerequisites'] = []
        saved, self.snapshot = self.snapshot, bare
        self.refresh()
        _, context = self.retrieve()
        bare_edges = len(context['items'][0]['assertion_ids'])
        self.snapshot = saved
        self.refresh()
        self.assertEqual(full_edges - bare_edges, 2)
        result, rejected = self.retrieve(budget=replace(self.budget, maximum_edges=bare_edges))
        self.assertEqual(result['status'], 'PARTIAL')
        self.assertEqual(rejected['items'], [])

    def test_tampering_with_a_required_prerequisite_fails_canonical_validation(self):
        _, context = self.retrieve()
        context['items'][0]['assertion_ids'].remove('e-prereq-2')
        forged = self.c.put('graph-context', context)
        with self.assertRaises(ContractError) as caught:
            validate_context(self.c, forged, current_access=self.retriever.access_policy,
                             current_status=self.adapter.current_source_status())
        self.assertEqual(caught.exception.code, 'CONTEXT_MATERIALIZATION')

    def test_literal_pin_also_carries_prerequisites(self):
        legacy = deepcopy(self.scope)
        legacy['conflict_resolution'] = 'literal-v1'
        _, context = self.retrieve(research_domain_scope=legacy)
        self.assertTrue({'e-support', 'e-prereq-1', 'e-prereq-2'} <= set(context['items'][0]['assertion_ids']))
        self.deny('e-prereq-1')
        _, denied = self.retrieve(research_domain_scope=legacy)
        self.assertNoGraphState(denied)


if __name__ == '__main__':
    unittest.main()
