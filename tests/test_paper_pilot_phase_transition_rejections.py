"""Authored synthetic rejection mechanics; no real transition/private-run evidence."""
import copy
import os
import sqlite3
import unittest

from tests.test_paper_pilot_phase_transition_e2e import PhaseFixture, files, fitz
from trace_gc.canonical import bytes_digest, dumps, loads
from trace_gc.errors import ContractError
from trace_gc.trust import Signer
from trace_gc import phase_transition as transition


@unittest.skipIf(fitz is None, 'optional PyMuPDF fixture dependency unavailable')
class PhaseRejections(PhaseFixture, unittest.TestCase):
    def test_export_matrix(self):
        for changes in ({'expected_historical_identity_sha256': '0' * 64},
                        {'external_semantic_intent_sha256': '0' * 64},
                        {'attempt_manifest_sha256': '0' * 64},
                        {'destination': self.old_root / 'redirected'}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.export(**changes)
        path = self.export_args['attempt_manifest_path']
        raw = path.read_bytes()
        manifest = loads(raw)
        manifest['expected_budget_used']['model_calls'] = 0
        path.write_text(dumps(manifest))
        with self.assertRaises(ValueError):
            self.export(attempt_manifest_sha256=bytes_digest(path.read_bytes()))
        path.write_bytes(raw)
        self.export()
        capsule = self.capsule_dir / 'capsule.json'
        capsule.write_bytes(b'conflicting capsule')
        before = files(self.capsule_dir)
        with self.assertRaises(ValueError):
            self.export()
        self.assertEqual(files(self.capsule_dir), before)
        self.assertEqual({n: (self.old_root / n).read_bytes() for n in self.export_old_bytes},
                         self.export_old_bytes)

    def test_capsule_matrix(self):
        self.cutover()
        mutations = [lambda c: c.update(checkpoint_head='0' * 64),
            lambda c: c['checkpoint_events'][1].__setitem__(1,
                dumps({**loads(c['checkpoint_events'][1][1]), 'kind': 'TAMPERED'})),
            lambda c: c.update(catalog_records=[]),
            lambda c: c['budget_snapshot']['used'].update(model_calls=0),
            lambda c: c['config'].update(questions=['changed']),
            lambda c: c['old_implementation'].update(python='changed'),
            lambda c: c.pop('blobs')]
        for mutate in mutations:
            capsule = copy.deepcopy(self.capsule)
            mutate(capsule)
            with self.subTest(mutation=mutate), self.assertRaises(ContractError):
                transition.verify_capsule(capsule)
            self.preserved()

    def test_restore_matrix(self):
        self.cutover()
        self.restore()
        before = files(self.target)
        payload = self.auth['payload']
        stale = self.phase_signer.issue('AUTHORIZATION', payload,
            issued_at='2020-01-01T00:00:00Z', expires_at='2020-01-01T00:01:00Z')
        untrusted = Signer.ephemeral('unenrolled').issue('AUTHORIZATION', payload)
        wrong_operation = self.phase_signer.issue('AUTHORIZATION', {**payload, 'operation': 'PHASE_ACTIVATE'})
        for changes in ({'capsule_sha256': '0' * 64},
                        {'target_implementation_sha256': '0' * 64},
                        {'authorization': stale}, {'authorization': untrusted},
                        {'authorization': wrong_operation},
                        {'target_root': self.capsule_dir / 'redirected'}):
            with self.subTest(changes=changes), self.assertRaises(ContractError):
                self.restore(**changes)
            self.assertEqual(files(self.target), before)
            self.preserved()
        self.old_root.mkdir()
        with self.assertRaises(ContractError) as caught:
            self.restore()
        self.assertEqual(caught.exception.code, 'PHASE_FENCE')
        self.old_root.rmdir()
        archive_file = self.archive / 'graph.sqlite3'
        raw = archive_file.read_bytes()
        archive_file.write_bytes(raw + b'changed')
        with self.assertRaises(ContractError) as caught:
            self.restore()
        self.assertEqual(caught.exception.code, 'PHASE_FENCE')
        archive_file.write_bytes(raw)
        self.pointer.write_bytes(b'conflicting pointer')
        with self.assertRaises(ContractError):
            self.restore()
        self.assertEqual(self.pointer.read_bytes(), b'conflicting pointer')
        self.assertEqual(files(self.target), before)
        self.preserved()

    def test_target_identity_and_config(self):
        self.cutover(); self.restore()
        wrong = {**self.binding, 'implementation_sha256': '0' * 64}
        with self.assertRaises(ContractError) as caught:
            self.open_target(binding=wrong)
        self.assertEqual(caught.exception.code, 'PHASE_CONFIG')
        self.close_all()
        self.authority = self.make_authority()
        self.open_target(config={**self.config, 'questions': ['changed question']})
        with self.assertRaises(ContractError):
            self.import_phase()
        self.assertEqual(self.pilot.db.execute('SELECT count(*) FROM events').fetchone()[0], 1)
        self.preserved()

    def test_target_budget_mismatch(self):
        self.cutover(); self.restore()
        db = sqlite3.connect(self.target / 'budget.sqlite3')
        used = copy.deepcopy(self.capsule['budget_snapshot']['used'])
        used['model_calls'] = 0
        db.execute('UPDATE trace_budgets SET used=?', (dumps(used),))
        db.commit(); db.close()
        self.open_target()
        with self.assertRaises(ContractError):
            self.import_phase()
        self.assertEqual(self.pilot.db.execute('SELECT count(*) FROM events').fetchone()[0], 1)
        self.assertEqual(self.budget.snapshot()['used'], used)
        self.assertEqual(files(self.archive), self.old_bytes)
        self.assertEqual(files(self.capsule_dir), self.capsule_bytes)

    def test_target_graph_mismatch(self):
        self.cutover(); self.restore()
        db = sqlite3.connect(self.target / 'graph.sqlite3')
        state = loads(db.execute('SELECT body FROM trace_state WHERE id=1').fetchone()[0])
        state['metadata'] = {'authored-injected': True}
        db.execute('UPDATE trace_state SET body=? WHERE id=1', (dumps(state),))
        db.commit(); db.close()
        with self.assertRaises(ContractError):
            self.open_target()
            self.import_phase()
        checkpoint = self.target / 'checkpoint.sqlite3'
        if checkpoint.exists():
            db = sqlite3.connect(checkpoint)
            kinds = [loads(r[0])['kind'] for r in db.execute('SELECT body FROM events')]
            db.close()
            self.assertNotIn('IMPORT_PHASE', kinds)
        self.assertEqual(files(self.archive), self.old_bytes)
        self.assertEqual(files(self.capsule_dir), self.capsule_bytes)

    def test_import_arguments_and_inactive_guards(self):
        self.cutover(); self.restore(); self.open_target()
        for changes, code in (({'capsule_path': self.phase / 'authorization.json'}, 'PHASE_IMPORT'),
                              ({'capsule_sha256': '0' * 64}, 'PHASE_IMPORT'),
                              ({'authorization': {}}, 'PHASE_AUTHORITY')):
            with self.subTest(code=code), self.assertRaises(ContractError) as caught:
                self.import_phase(**changes)
            self.assertEqual(caught.exception.code, code)
        self.inactive()
        self.preserved()

    def test_live_archived_owner(self):
        self.cutover(); self.restore()
        with (self.archive / 'controller.lock').open('r+b') as held:
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(held.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                with self.assertRaises(OSError):
                    self.open_target()
            finally:
                if os.name == 'nt':
                    held.seek(0)
                    msvcrt.locking(held.fileno(), msvcrt.LK_UNLCK, 1)
        self.preserved()

    def test_activation_matrix(self):
        self.cutover(); self.restore(); self.open_target(); self.controller_open()
        with self.assertRaises(ContractError) as caught:
            self.activate()
        self.assertEqual(caught.exception.code, 'PHASE_ACTIVATION')
        self.controller.close(); self.controller = None
        self.import_phase(); self.controller_open()
        payload = {**self.authority.activation_payload(), 'activation_epoch': 2}
        with self.assertRaises(ContractError) as caught:
            self.activate(activation_receipt=self.phase_signer.issue('AUTHORIZATION', payload))
        self.assertEqual(caught.exception.code, 'PHASE_ACTIVATION')
        self.pointer.write_bytes(b'conflicting pointer')
        with self.assertRaises(ContractError):
            self.activate()
        self.assertEqual(self.pointer.read_bytes(), b'conflicting pointer')
        self.preserved()
