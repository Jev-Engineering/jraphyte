"""Synthetic, authority-bound identity/refutation regressions (not corpus quality)."""
from copy import deepcopy
import unittest

from trace_gc.constraints import validate_graph
from trace_gc.errors import ContractError
from trace_gc.replay import replay_retrieval
from trace_gc.retrieval.contracts import RetrievalBudget, query
from trace_gc.retrieval.domains import research_domain_scope
from trace_gc.retrieval.fixtures import domain_corpus, demo_access, SCOPE
from trace_gc.retrieval.items import conflict_pairs
from trace_gc.retrieval.service import HybridRetriever, validate_context
from trace_gc.retrieval.store import InMemoryGraphAdapter


class IdentityConflictTests(unittest.TestCase):
    def setUp(self):
        self.f = domain_corpus()
        self.c = self.f['catalog']
        self.original = self.f['claim_id']
        self.alias = self.c.claim('Alternative identifier for the synthetic intervention claim.')
        self.snapshot = self.c.get(self.f['snapshot_id'], 'graph-snapshot')
        self.snapshot['nodes'][self.alias] = 'Claim'
        self.snapshot['assertions']['e-refute']['assertion']['object'] = self.alias
        self.statuses = deepcopy(self.f['statuses'])
        self.identity_source = self.c.source('synthetic-claim-identity', '1',
            'Synthetic fixture: the two claim IDs denote the same research question.', scope=SCOPE)
        evidence = self.c.evidence(self.identity_source)
        self.identity_evidence = evidence
        self.statuses[self.identity_source] = {'active': True, 'permission': 'READ', 'epoch': 1,
            'updated_at': '2026-09-27T00:00:00Z', 'tombstone': False}
        self.snapshot['source_epochs'][self.identity_source] = 1
        self.snapshot['assertions']['e-claim-identity'] = {
            'assertion': {'subject': self.original, 'predicate': 'same_as', 'object': self.alias, 'qualifiers': {}},
            'evidence_ids': [evidence], 'prerequisites': [], 'active': True, 'revision': 1}
        self.scope = research_domain_scope(self.c, self.f['taxonomy_id'], ['research:biology'])
        self.budget = RetrievalBudget(maximum_tokens=150000, maximum_latency_ms=20000,
            maximum_edges=100, maximum_nodes=100, maximum_source_spans=100)
        self.refresh()

    def refresh(self):
        # Distinct paper subjects allow contradictory evidence without violating
        # the authority's graph-wide incompatible-relation constraint.
        validate_graph(self.snapshot['nodes'], self.snapshot['assertions'],
                       self.c.get(self.snapshot['schema_id'], 'schema')['relations'])
        self.snapshot_id = self.c.put('graph-snapshot', self.snapshot)
        self.adapter = InMemoryGraphAdapter(self.c, [self.snapshot_id], self.statuses)
        self.retriever = HybridRetriever(self.adapter, catalog=self.c,
            access_policy=demo_access(self.c, self.snapshot_id))

    def request(self, **changes):
        return query(requesting_component='downstream-identity-regression', security_scope=SCOPE,
            text=changes.pop('text', 'improves'), strategies=changes.pop('strategies', ['LEXICAL']),
            include_conflicts=False, research_domain_scope=changes.pop('research_domain_scope', self.scope),
            budget=changes.pop('budget', self.budget), **changes)

    def retrieve(self, **changes):
        result = self.c.get(self.retriever.retrieve(self.request(**changes)), 'retrieval-result')
        context = self.c.get(result['graph_context_id'], 'graph-context')
        validate_context(self.c, result['graph_context_id'], current_access=self.retriever.access_policy,
                         current_status=self.adapter.current_source_status())
        return result, context

    def test_aliased_refutation_and_its_identity_proof_are_atomic_closure(self):
        _, context = self.retrieve()
        self.assertEqual(len(context['items']), 1)
        item = context['items'][0]
        self.assertTrue({'e-support', 'e-refute', 'e-claim-identity'} <= set(item['assertion_ids']))
        self.assertEqual(item['trust_class'], 'CONFLICTED_GRAPH_FACT')
        self.assertIn(self.f['evidence']['e-refute'], item['evidence_ids'])
        self.assertIn(self.identity_evidence, item['evidence_ids'])
        # The identity source is explicitly unclassified, not granted a label.
        self.assertIsNone(item['research_domain']['source_assignments'][self.identity_source])

    def test_denied_identity_does_not_invent_a_conflict_or_leak_evidence(self):
        policy = deepcopy(self.retriever.access_policy)
        del policy['grants']['source:' + self.identity_source]
        self.retriever.set_access_policy(policy)
        _, context = self.retrieve()
        self.assertEqual(set(context['retrieved_edges']), {'e-support'})
        self.assertNotIn(self.identity_evidence, context['selected_evidence_ids'])
        self.assertNotIn(self.f['evidence']['e-refute'], context['selected_evidence_ids'])

    def test_inactive_identity_is_not_a_current_equivalence_or_membership_grant(self):
        self.snapshot['assertions']['e-claim-identity']['active'] = False
        self.refresh()
        _, context = self.retrieve(include_historical=True)
        self.assertEqual(set(context['retrieved_edges']), {'e-support'})

    def test_transitive_identity_proofs_retain_cross_domain_refutation(self):
        middle = self.c.claim('Intermediate identifier for the synthetic intervention claim.')
        self.snapshot['nodes'][middle] = 'Claim'
        self.snapshot['assertions']['e-claim-identity']['assertion']['object'] = middle
        second = deepcopy(self.snapshot['assertions']['e-claim-identity'])
        second['assertion'].update(subject=middle, object=self.alias)
        self.snapshot['assertions']['e-claim-identity-2'] = second
        self.refresh()
        _, context = self.retrieve()
        self.assertTrue({'e-support', 'e-refute', 'e-claim-identity', 'e-claim-identity-2'} <=
                        set(context['items'][0]['assertion_ids']))

    def test_current_identity_revocation_invalidates_cache_and_old_context(self):
        original, context = self.retrieve()
        self.assertIn('e-refute', context['retrieved_edges'])
        self.retrieve()
        self.assertEqual(self.retriever.cache.hits, 1)
        self.adapter.source_status[self.identity_source].update(active=False, epoch=2)
        _, revoked = self.retrieve()
        self.assertEqual(set(revoked['retrieved_edges']), {'e-support'})
        self.assertGreater(self.retriever.cache.invalidations, 0)
        with self.assertRaises(ContractError):
            validate_context(self.c, original['graph_context_id'], current_access=self.retriever.access_policy,
                             current_status=self.adapter.current_source_status())

    def test_denied_refutation_does_not_leak_via_an_authorized_alias(self):
        policy = deepcopy(self.retriever.access_policy)
        del policy['grants']['source:' + self.f['sources']['e-refute']]
        self.retriever.set_access_policy(policy)
        _, context = self.retrieve()
        self.assertEqual(set(context['retrieved_edges']), {'e-support', 'e-claim-identity'})
        self.assertNotIn(self.f['evidence']['e-refute'], context['selected_evidence_ids'])
        self.assertNotEqual(context['items'][0]['trust_class'], 'CONFLICTED_GRAPH_FACT')

    def test_inactive_identity_cannot_give_an_alias_node_topical_membership(self):
        self.snapshot['assertions']['e-claim-identity']['active'] = False
        self.refresh()
        _, context = self.retrieve(strategies=['ENTITY'], text='', focus_entities=[self.alias], include_historical=True)
        self.assertEqual(context['items'], [])

    def test_budget_rejects_entire_anchor_rather_than_dropping_alias_refutation(self):
        from dataclasses import replace
        for budget in (replace(self.budget, maximum_edges=2), replace(self.budget, maximum_source_spans=2)):
            with self.subTest(budget=budget):
                result, context = self.retrieve(budget=budget)
                self.assertEqual(result['status'], 'PARTIAL')
                self.assertEqual(context['items'], [])
                self.assertEqual(context['selected_evidence_ids'], [])

    def test_tampering_with_required_aliased_refutation_fails_canonical_validation(self):
        result, context = self.retrieve()
        context['items'][0]['assertion_ids'].remove('e-refute')
        forged = self.c.put('graph-context', context)
        with self.assertRaises(ContractError) as caught:
            validate_context(self.c, forged, current_access=self.retriever.access_policy,
                             current_status=self.adapter.current_source_status())
        self.assertEqual(caught.exception.code, 'CONTEXT_MATERIALIZATION')

    def test_schema_inverse_form_of_refutation_is_not_hidden(self):
        from trace_gc.demo import relation
        schema = self.c.get(self.snapshot['schema_id'], 'schema')
        schema['relations']['is_refuted_by'] = relation('Claim', 'Document', inverse_of='refutes')
        schema['version'] = 'synthetic-inverse-refutation-v1'
        schema_id = self.c.put('schema', schema)
        self.snapshot.update(schema_id=schema_id, schema_hash=self.c.hash(schema_id))
        a = self.snapshot['assertions']['e-refute']['assertion']
        a.update(subject=self.alias, predicate='is_refuted_by', object='Paper-B')
        self.refresh()
        _, context = self.retrieve()
        self.assertIn('e-refute', context['retrieved_edges'])
        self.assertEqual(context['items'][0]['trust_class'], 'CONFLICTED_GRAPH_FACT')
        # The original inverse assertion and source span are kept, not rewritten.
        self.assertEqual(self.c.get(self.snapshot_id)['assertions']['e-refute']['assertion'], a)

    def test_inverse_identity_keeps_the_actual_proof_record(self):
        from trace_gc.demo import relation
        schema = self.c.get(self.snapshot['schema_id'], 'schema')
        schema['relations']['alias_of'] = relation('*', '*', inverse_of='same_as')
        schema['version'] = 'synthetic-inverse-identity-v1'
        schema_id = self.c.put('schema', schema)
        self.snapshot.update(schema_id=schema_id, schema_hash=self.c.hash(schema_id))
        a = self.snapshot['assertions']['e-claim-identity']['assertion']
        a.update(subject=self.alias, predicate='alias_of', object=self.original)
        self.refresh()
        _, context = self.retrieve()
        self.assertTrue({'e-support', 'e-refute', 'e-claim-identity'} <= set(context['retrieved_edges']))
        self.assertIn(self.identity_evidence, context['selected_evidence_ids'])

    def test_disjoint_intervals_do_not_create_alias_conflicts(self):
        self.snapshot['assertions']['e-support']['assertion']['qualifiers']['valid_until'] = '2024-01-01T00:00:00Z'
        self.snapshot['assertions']['e-refute']['assertion']['qualifiers']['valid_from'] = '2024-01-01T00:00:00Z'
        self.refresh()
        _, context = self.retrieve()
        self.assertNotIn('e-refute', context['retrieved_edges'])
        self.assertNotEqual(context['items'][0]['trust_class'], 'CONFLICTED_GRAPH_FACT')

    def test_vector_inputs_remain_scoped_but_output_retains_alias_conflict(self):
        class Spy:
            version = 'synthetic-identity-embedding-spy-v1'
            def __init__(self):
                self.seen = []
            def embed(self, texts):
                self.seen.extend(texts)
                return [[1.0, 0.0] for text in texts]
        spy = Spy()
        self.retriever.embedding = spy
        _, context = self.retrieve(strategies=['VECTOR'])
        self.assertNotIn(self.c.get(self.f['evidence']['e-refute'])['quote'], spy.seen)
        self.assertNotIn(self.c.get(self.identity_evidence)['quote'], spy.seen)
        self.assertIn('e-refute', context['retrieved_edges'])
        self.assertIn(self.identity_evidence, context['selected_evidence_ids'])

    def test_missing_legacy_pin_preserves_old_materialization_and_can_be_compared(self):
        legacy = deepcopy(self.scope)
        legacy.pop('conflict_resolution')
        old, old_context = self.retrieve(research_domain_scope=legacy)
        self.assertEqual(set(old_context['retrieved_edges']), {'e-support', 'e-claim-identity'})
        self.assertIn('LEGACY_LITERAL_CONFLICT_RESOLUTION_MAY_OMIT_ALIASED_REFUTATIONS', old['warnings'])
        before = self.c.hash(old['graph_context_id'])
        new, new_context = self.retrieve()
        self.assertIn('e-refute', new_context['retrieved_edges'])
        self.assertNotEqual(old_context['retrieval_fingerprint'], new_context['retrieval_fingerprint'])
        validate_context(self.c, old['graph_context_id'], current_access=self.retriever.access_policy,
                         current_status=self.adapter.current_source_status())
        self.assertEqual(self.c.hash(old['graph_context_id']), before)
        explicit = research_domain_scope(self.c, self.f['taxonomy_id'], ['research:biology'], conflict_resolution='literal-v1')
        _, explicit_context = self.retrieve(research_domain_scope=explicit)
        self.assertEqual(explicit_context['retrieved_edges'], old_context['retrieved_edges'])

    def test_unknown_algorithm_pin_is_rejected(self):
        with self.assertRaises(ContractError):
            research_domain_scope(self.c, self.f['taxonomy_id'], ['research:biology'], conflict_resolution='latest')

    def test_counterfactual_replay_keeps_original_literal_scope_immutable(self):
        legacy = deepcopy(self.scope)
        legacy.pop('conflict_resolution')
        original_id = self.retriever.retrieve(self.request(research_domain_scope=legacy))
        original_hash = self.c.hash(original_id)
        # Explicit synthetic availability journal for this exact read snapshot.
        self.adapter.events = [{'version': self.snapshot['graph_version'], 'state_after': self.snapshot,
            'committed_at': '2026-09-27T00:00:00Z', 'record_hashes': {r['id']: r['hash'] for r in self.c.all()}}]
        replay_id = replay_retrieval(self.retriever, original_id, {'research_domain_scope': self.scope})
        replay = self.c.get(replay_id, 'retrieval-replay')
        self.assertEqual(replay['original_research_domain_scope'], legacy)
        self.assertEqual(replay['replayed_research_domain_scope'], self.scope)
        self.assertEqual(replay['original_classification_identity'], replay['replayed_classification_identity'])
        self.assertFalse(replay['authorization_granted'])
        self.assertEqual(self.c.hash(original_id), original_hash)
        result = self.c.get(replay['replayed_result_id'], 'retrieval-result')
        context = self.c.get(result['graph_context_id'], 'graph-context')
        self.assertIn('e-refute', context['retrieved_edges'])


class ConflictNormalizationTests(unittest.TestCase):
    def test_symmetric_pairs_use_schema_normal_form_only_when_pinned(self):
        from trace_gc.demo import relation
        schema = {'related': relation('Entity', 'Entity', symmetric=True, incompatible=['unrelated']),
                  'unrelated': relation('Entity', 'Entity', symmetric=True, incompatible=['related'])}
        def fact(s, p, o):
            return {'assertion': {'subject': s, 'predicate': p, 'object': o, 'qualifiers': {}}, 'active': True}
        edges = {'left': fact('a', 'related', 'b'), 'right': fact('b', 'unrelated', 'a')}
        self.assertEqual(conflict_pairs(edges, schema), [])
        self.assertEqual(conflict_pairs(edges, schema, resolve_identities=True), [['left', 'right']])

    def test_identity_normalization_is_charged_to_work_budget(self):
        from trace_gc.demo import relation
        from trace_gc.retrieval.budget import BudgetMeter
        schema = {'same_as': relation('Entity', 'Entity', symmetric=True, transitive=True)}
        edges = {'identity-' + str(i): {'assertion': {'subject': str(i), 'predicate': 'same_as',
            'object': str(i+1), 'qualifiers': {}}, 'active': True} for i in range(20)}
        meter = BudgetMeter(RetrievalBudget(maximum_cost_units=10))
        with self.assertRaises(ContractError) as caught:
            conflict_pairs(edges, schema, meter, resolve_identities=True)
        self.assertEqual(caught.exception.code, 'RETRIEVAL_BUDGET_EXHAUSTED')
