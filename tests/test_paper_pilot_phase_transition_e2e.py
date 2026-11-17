"""Authored synthetic mechanics only; no real transition or private-run evidence."""
import copy
from contextlib import contextmanager
import json
import os
from pathlib import Path
import shutil
import tempfile
import threading
import unittest
from unittest.mock import patch

from tests import test_paper_pilot as fixtures
from trace_gc.backend import CompilerService, SQLiteReferenceBackend
from trace_gc.budget import RunBudget
from trace_gc.canonical import bytes_digest, digest, dumps, loads
from trace_gc.catalog import Catalog
from trace_gc.compiler import now
from trace_gc.demo import limits
from trace_gc.errors import ContractError, require
from trace_gc.paper_ingestion import CHECKS
from trace_gc.paper_pilot import PaperPilot, implementation_identity
from trace_gc.paper_pilot_controller import PaperPilotController
from trace_gc.phase_authority import PhaseAuthority
from trace_gc import phase_transition as transition
from trace_gc.retrieval.security import grant
from trace_gc.trust import IssuerPolicy, Signer
from src import paper_pilot_phase_export as exporter

fitz = fixtures.fitz
NAMES = {'checkpoint.sqlite3', 'graph.sqlite3', 'budget.sqlite3',
         'application-journal.sqlite3', 'controller.lock'}


def files(root):
    return {p.name: p.read_bytes() for p in root.iterdir() if p.is_file()}


class PhaseFixture:
    access = fixtures.PaperPilotTests.access

    def open(self):
        # Called by the reused authored PDF/catalog setup, before any old steps.
        self.base = self.root
        self.root = self.base / 'state' / 'run'
        self.root.mkdir(parents=True)
        fixtures.PaperPilotTests.open(self)

    def setUp(self):
        self.old_identity = copy.deepcopy(implementation_identity())
        self.old_identity['files']['synthetic-old-runtime-marker.py'] = '0' * 64
        self.patches = [patch('trace_gc.paper_pilot.implementation_identity', return_value=self.old_identity),
                        patch.object(exporter, 'implementation_identity', return_value=self.old_identity)]
        for p in self.patches:
            p.start()
        self.addCleanup(self.stop_old)
        temporary = tempfile.TemporaryDirectory
        with patch.object(fixtures.tempfile, 'TemporaryDirectory',
                          side_effect=lambda: temporary(dir=os.environ.get('ISSUE90_TEST_TMPDIR'))):
            fixtures.PaperPilotTests.setUp(self)
        self.addCleanup(self.temp.cleanup)
        self.controller = None
        self.authority = None
        self.addCleanup(self.close_all)
        self.initial = [self.catalog.record(ref) for ref in (self.schema, self.policy, self.claim)]
        self.old_root = self.root
        self.archive = self.base / 'archive' / 'run'
        self.target = self.base / 'target' / 'run'
        self.capsule_dir = self.base / 'capsule'
        self.phase = self.base / 'phase'
        self.phase.mkdir()
        (self.phase / 'phase.lock').touch()
        self.active = self.base / 'active'
        self.active.mkdir()
        self.pointer = self.active / 'phase.json'
        self.manifest = {'version': 'real-paper-pilot-controller-v1', 'pilot_config': self.config,
            'questions': self.config['questions'], 'acceptance': {
                'phase': 'source_preparation_only', 'source_review_checks': sorted(CHECKS)},
            'pages': [{'id': 'paper-page-2', 'source_id': 'authored-paper', 'version': 'v1',
                       'pdf_sha256': bytes_digest(self.pdf), 'physical_page': 2,
                       'start': 0, 'end': len(self.native.strip())}]}
        self.controller = PaperPilotController(self.pilot, manifest=self.manifest, private_dir=self.root)
        self.controller.preflight({'paper-page-2': self.pdf})
        self.controller.prepare('paper-page-2', self.pdf)
        prepared = 'source-prepare:paper-page-2'
        at = now()
        payload = self.pilot.source_review_payload(prepared, reviewer='authored-test-reviewer',
            reviewer_kind='assistant', reviewed_at=at, checks={k: True for k in CHECKS})
        reviewed = self.pilot.accept_source_review('review', prepared_id=prepared,
            receipt=self.signer.issue('SOURCE_STATUS', payload, issued_at=at))
        self.grants['source:' + reviewed['source_id']] = grant('pilot-test', 'private-test')
        self.pilot.admit_sources('admit', review_ids=['review'], expected_version=0,
            authorization=self.signer.issue('SOURCE_STATUS',
                self.pilot.admission_payload(['review'], expected_version=0)))
        self.candidates = [{'assertion': {'subject': 'authored-paper', 'predicate': 'supports',
            'object': self.claim, 'qualifiers': {}}, 'claim_id': self.claim,
            'evidence_ids': [reviewed['evidence_id']]}]
        result = self.pilot.compile_candidates('compile', candidates=self.candidates)
        self.assertEqual(result['state'], 'WAIT_SEMANTIC_RESPONSE')
        self.old_requests = copy.deepcopy(self.pilot.requests)
        attempt = self.base / 'attempt'
        attempt.mkdir()
        intent = {'version': 'issue23-semantic-intent-v1', 'compile_id': 'compile',
            'pack_sha256': result['pack_sha256'], 'request_sha256': result['request_sha256'],
            'automatic_retry': False, 'attempts_authorized': 1, 'graph_writes': 0}
        intent_path = attempt / 'semantic-intent.json'
        intent_path.write_text(dumps(intent) + '\n')
        inventory = {'version': 'paper-pilot-phase-attempt-manifest-v1',
            'run_id': self.config['run_id'], 'intent_sha256': bytes_digest(intent_path.read_bytes()),
            'artifacts': {name: None for name in exporter.ATTEMPT_NAMES},
            'source_receipts': {k: digest(v['args']['receipt']) for k, v in self.pilot.requests.items()
                                if v['kind'] == 'REVIEW_SOURCE'},
            'source_open_sha256': 'a' * 64, 'expected_budget_used': self.budget.snapshot()['used']}
        manifest_path = attempt / 'attempt-manifest.json'
        manifest_path.write_text(dumps(inventory) + '\n')
        self.export_args = dict(expected_historical_identity_sha256=digest(self.old_identity),
            external_semantic_intent_path=intent_path,
            external_semantic_intent_sha256=bytes_digest(intent_path.read_bytes()),
            attempt_manifest_path=manifest_path, attempt_manifest_sha256=bytes_digest(manifest_path.read_bytes()),
            source_open_sha256='a' * 64)
        # Establish main-file byte pins at the quiescent export boundary.
        for db in (self.pilot.db, self.backend.db, self.budget.db, self.controller.db):
            db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        self.export_old_bytes = {n: (self.old_root / n).read_bytes() for n in NAMES}

    def stop_old(self):
        for p in self.patches:
            p.stop()
        self.patches = []

    def close_all(self):
        for name in ('controller', 'pilot', 'backend', 'budget', 'authority'):
            obj = getattr(self, name, None)
            if obj is not None:
                obj.close()
                setattr(self, name, None)

    def export(self, **changes):
        args = {**self.export_args, **changes}
        return exporter.export_phase(self.pilot, self.controller.db,
                                     args.pop('destination', self.capsule_dir), **args)

    def cutover(self):
        self.export()
        self.capsule_path = self.capsule_dir / 'capsule.json'
        self.capsule = loads(self.capsule_path.read_bytes())
        self.capsule_sha = bytes_digest(self.capsule_path.read_bytes())
        self.capsule_bytes = files(self.capsule_dir)
        self.close_all()
        self.old_bytes = files(self.old_root)
        self.assertEqual(set(self.old_bytes), NAMES)
        self.assertEqual(self.old_bytes, self.export_old_bytes)
        self.archive.parent.mkdir()
        os.replace(self.old_root, self.archive)
        self.stop_old()
        fence = {'version': 'paper-pilot-phase-namespace-fence-v1',
            'old_root_path': str(self.old_root), 'archived_root_path': str(self.archive),
            'old_parent_dacl_sha256': 'b' * 64, 'deny_sid': 'S-1-5-21-authored',
            'archived_files_sha256': {k: bytes_digest(v) for k, v in self.old_bytes.items()},
            'status': 'OLD_PATH_FENCED_NEW_PHASE_ALLOWED'}
        fence_path = self.phase / 'fence.json'
        fence_path.write_text(dumps(fence) + '\n')
        self.phase_signer = Signer.ephemeral('authored-phase-reviewer')
        self.trust.enroll(self.phase_signer.issuer, IssuerPolicy(self.phase_signer.public_key(),
            'authored phase reviewer', frozenset({'AUTHORIZATION'}),
            frozenset({'PHASE_IMPORT', 'PHASE_ACTIVATE'}), frozenset({'pilot-test'}),
            frozenset({'SYNTHETIC', 'LIVE'}), can_review=True))
        self.identity = digest(implementation_identity())
        self.auth = self.phase_signer.issue('AUTHORIZATION', {'version': transition.AUTH_VERSION,
            'operation': 'PHASE_IMPORT', 'capsule_sha256': self.capsule_sha,
            'target_implementation_sha256': self.identity, 'run_id': self.config['run_id']})
        auth_path = self.phase / 'authorization.json'
        auth_path.write_text(dumps(self.auth))
        self.binding = dict(phase_id='authored-phase', run_id=self.config['run_id'],
            capsule_sha256=self.capsule_sha, implementation_sha256=self.identity,
            activation_path=str(self.pointer), activation_sha256='', activation_epoch=1,
            phase_lock_path=str(self.phase / 'phase.lock'), fence_receipt_path=str(fence_path),
            fence_receipt_sha256=bytes_digest(fence_path.read_bytes()), old_root_path=str(self.old_root),
            archived_old_root_path=str(self.archive), capsule_path=str(self.capsule_path.resolve()),
            authorization_path=str(auth_path), authorization_sha256=bytes_digest(auth_path.read_bytes()))
        self.authority = self.make_authority()
        self.receipt = self.phase_signer.issue('AUTHORIZATION', self.authority.activation_payload())
        self.binding['activation_sha256'] = bytes_digest((dumps(self.receipt) + '\n').encode())
        self.authority.binding = copy.deepcopy(self.binding)

    def make_authority(self):
        # Portable stand-in ONLY: Windows fence tests cover the real DACL fence.
        # Keep real staging/write/current/signature/archive-handle implementations.
        a = object.__new__(PhaseAuthority)
        a.binding, a.trust = copy.deepcopy(self.binding), self.trust
        a._mutex, a._depth, a._archived_lock_file = threading.RLock(), 0, None
        a._lock_path = Path(a.binding['phase_lock_path'])
        a._lock_file = a._lock_path.open('r+b')
        stat = os.fstat(a._lock_file.fileno())
        a._lock_identity = (stat.st_dev, stat.st_ino)

        def fence():
            b = a.binding
            raw = Path(b['fence_receipt_path']).read_bytes()
            require(bytes_digest(raw) == b['fence_receipt_sha256'], 'PHASE_FENCE', 'fence bytes')
            f = loads(raw)
            old, archived = Path(b['old_root_path']), Path(b['archived_old_root_path'])
            require(set(f) == {'version', 'old_root_path', 'archived_root_path',
                'old_parent_dacl_sha256', 'archived_files_sha256', 'deny_sid', 'status'} and
                f['version'] == 'paper-pilot-phase-namespace-fence-v1' and
                f['status'] == 'OLD_PATH_FENCED_NEW_PHASE_ALLOWED' and
                f['old_root_path'] == str(old) and f['archived_root_path'] == str(archived) and
                type(f['deny_sid']) is str and not old.exists() and archived.is_dir() and
                set(f['archived_files_sha256']) == NAMES and
                {p.name for p in archived.iterdir()} == NAMES and
                all(not (getattr((archived / n).lstat(), 'st_file_attributes', 0) & 0x400)
                    for n in NAMES) and
                all(bytes_digest(a._archive_bytes(archived, n)) == sha
                    for n, sha in f['archived_files_sha256'].items()), 'PHASE_FENCE', 'archive changed')

        @contextmanager
        def locked(*, active):
            with a._mutex:
                stat = a._lock_path.stat()
                require((stat.st_dev, stat.st_ino) == a._lock_identity, 'PHASE_LOCK', 'lock replaced')
                a._depth += 1
                try:
                    a._current() if active else a.verify_fence()
                    yield
                finally:
                    a._depth -= 1
        a.verify_fence, a._locked = fence, locked
        return a

    def restore(self, **changes):
        return transition.restore_target(**{**dict(capsule_path=self.capsule_path,
            capsule_sha256=self.capsule_sha, target_root=self.target, authorization=self.auth,
            trust=self.trust, target_implementation_sha256=self.identity,
            phase_authority=self.authority), **changes})

    def open_target(self, config=None, binding=None):
        self.root = self.target
        self.catalog = Catalog(self.initial)
        self.backend = SQLiteReferenceBackend(self.root / 'graph.sqlite3', catalog=self.catalog,
            schema_id=self.schema, nodes=self.nodes, sandbox=True, phase_authority=self.authority)
        self.budget = RunBudget(self.root / 'budget.sqlite3', self.config['run_id'],
                               limits(model_calls=10), phase_authority=self.authority)
        self.service = CompilerService(self.backend, self.trust, self.validator,
            policy_version='pilot-reviewed-v1', population='authored-synthetic-only',
            security_scope='pilot-test', policy_hash=self.catalog.hash(self.policy), publication_mode='REVIEWED')
        self.pilot = PaperPilot(self.root, config=config or self.config, catalog=self.catalog,
            backend=self.backend, service=self.service, budget=self.budget, current_access=self.access,
            token_counter=lambda x: len(json.dumps(x)), phase_import=binding or self.binding,
            phase_authority=self.authority)

    def import_phase(self, **changes):
        return self.pilot.import_phase(**{**dict(capsule_path=self.capsule_path,
            capsule_sha256=self.capsule_sha, authorization=self.auth), **changes})

    def controller_open(self):
        self.controller = PaperPilotController(self.pilot, manifest=self.manifest, private_dir=self.target)

    def activate(self, **changes):
        return transition.activate_imported_phase(**{**dict(pilot=self.pilot,
            controller=self.controller, phase_authority=self.authority,
            activation_receipt=self.receipt), **changes})

    def reopen_target(self, controller=True):
        self.close_all()
        self.authority = self.make_authority()
        self.open_target()
        if controller:
            self.controller_open()

    def preserved(self):
        self.assertEqual(files(self.archive), self.old_bytes)
        self.assertEqual(files(self.capsule_dir), self.capsule_bytes)
        if self.budget is not None:
            self.assertEqual(self.budget.snapshot(), self.capsule['budget_snapshot'])
            self.assertEqual(self.backend.state(), self.capsule['graph_state'])
            self.assertEqual(self.backend.statuses(), self.capsule['source_statuses'])

    def inactive(self):
        before = self.budget.snapshot()
        with self.assertRaises(ContractError) as caught:
            self.pilot.compile_candidates('compile2', candidates=self.candidates)
        self.assertEqual(caught.exception.code, 'PHASE_INACTIVE')
        with self.assertRaises(ContractError):
            self.budget.consume_many({'model_calls': 1})
        self.assertEqual(self.budget.snapshot(), before)


@unittest.skipIf(fitz is None, 'optional PyMuPDF fixture dependency unavailable')
class PhaseTransitionTests(PhaseFixture, unittest.TestCase):
    def test_full_transition_and_reopen(self):
        self.cutover()
        restored = self.restore()
        self.assertEqual(self.restore(), restored)
        self.open_target()
        self.import_phase()
        self.controller_open()
        result = self.activate()
        self.assertEqual(result['status'], 'ACTIVE_IMPORTED_PHASE_EXACT')
        self.assertEqual((result['model_calls'], result['graph_writes']), (0, 0))
        pointer = self.pointer.read_bytes()
        self.assertEqual(self.activate(), result)
        self.assertEqual(self.pointer.read_bytes(), pointer)
        with self.assertRaises(ContractError) as caught:
            self.import_phase()
        self.assertEqual(caught.exception.code, 'PHASE_INACTIVE')
        self.reopen_target()
        self.preserved()
        events = [loads(r[0]) for r in self.pilot.db.execute('SELECT body FROM events ORDER BY seq')]
        self.assertEqual([e['kind'] for e in events], ['OPEN', 'IMPORT_PHASE'])
        self.assertNotEqual(events[0]['value']['implementation'], self.old_identity)
        journal = [loads(r[0]) for r in self.controller.db.execute('SELECT body FROM events ORDER BY seq')]
        self.assertEqual([e['kind'] for e in journal], ['FREEZE', 'APPLICATION_PHASE_IMPORT'])
        self.assertEqual(journal[1]['old_journal_head'], self.capsule['application_journal_head'])
        self.assertEqual(journal[1]['old_pilot_head'], self.capsule['checkpoint_head'])
        self.assertEqual(self.pilot.requests, self.old_requests)
        for record in self.capsule['catalog_records']:
            self.assertEqual(self.catalog.record(record['id']), record)
        self.assertFalse(any(r['kind'] == 'SEMANTIC_RESPONSE' for r in self.pilot.requests.values()))
        self.pilot.semantic_execution_context('compile')
        # An identical replay of the pending COMPILE runs through the phased
        # _step guard and returns the durable result without a second charge.
        self.assertEqual(self.pilot.compile_candidates('compile', candidates=self.candidates),
                         self.old_requests['compile']['result'])
        self.preserved()
        # Guard check uses disposable copies, never the immutable archive.
        saved = (self.root, self.pilot, self.backend, self.budget, self.catalog)
        self.root = self.base / 'scratch'
        shutil.copytree(self.archive, self.root)
        self.catalog = Catalog(self.initial)
        try:
            with self.assertRaises(ContractError) as caught:
                fixtures.PaperPilotTests.open(self)
            self.assertEqual(caught.exception.code, 'PILOT_CONFIG_CHANGED')
        finally:
            self.backend.close()
            self.budget.close()
            self.root, self.pilot, self.backend, self.budget, self.catalog = saved
        self.preserved()

    def test_export_interruptions_resume(self):
        original = exporter._backup
        calls = 0
        def interrupted(*args):
            nonlocal calls
            calls += 1
            if calls == 3:
                raise RuntimeError('third backup')
            return original(*args)
        before = [exporter._logical(db) for db in
                  (self.pilot.db, self.backend.db, self.budget.db, self.controller.db)]
        with patch.object(exporter, '_backup', side_effect=interrupted):
            with self.assertRaises(RuntimeError):
                self.export()
        path_open = Path.open
        def no_capsule(path, *args, **kwargs):
            if path.name == 'capsule.json':
                raise RuntimeError('before capsule')
            return path_open(path, *args, **kwargs)
        with patch.object(Path, 'open', no_capsule):
            with self.assertRaises(RuntimeError):
                self.export()
        self.assertEqual(before, [exporter._logical(db) for db in
            (self.pilot.db, self.backend.db, self.budget.db, self.controller.db)])
        self.assertEqual({n: (self.old_root / n).read_bytes() for n in NAMES}, self.export_old_bytes)
        self.cutover()
        transition.verify_capsule(self.capsule)
        self.assertEqual(set(files(self.capsule_dir)), {'capsule.json'} |
                         {n + '.sqlite3' for n in self.capsule['database_backup_sha256']})
        self.restore()
        self.open_target()
        self.preserved()

    def test_import_interrupted_before_event(self):
        self.cutover(); self.restore(); self.open_target()
        append = self.pilot._append
        def fail(kind, value):
            if kind == 'IMPORT_PHASE':
                raise RuntimeError('before import event')
            return append(kind, value)
        with patch.object(self.pilot, '_append', side_effect=fail):
            with self.assertRaises(RuntimeError):
                self.import_phase()
        self.assertGreater(self.pilot.db.execute('SELECT count(*) FROM blobs').fetchone()[0], 0)
        self.reopen_target(controller=False)
        self.assertEqual(self.pilot.requests, {})
        self.assertFalse(self.pilot._phase_imported)
        self.import_phase()
        self.assertEqual(self.pilot.db.execute('SELECT count(*) FROM events').fetchone()[0], 2)
        self.preserved()

    def test_import_lost_return_is_idempotent(self):
        self.cutover(); self.restore(); self.open_target()
        append = self.pilot._append
        def lost_return(kind, value):
            append(kind, value)
            if kind == 'IMPORT_PHASE':
                raise RuntimeError('durable import, lost return')
        with patch.object(self.pilot, '_append', side_effect=lost_return):
            with self.assertRaises(RuntimeError):
                self.import_phase()
        result = {'status': 'PHASE_IMPORTED_HELD', 'capsule_sha256': self.capsule_sha,
                  'checkpoint_head': self.pilot._head, 'model_calls': 0}
        self.reopen_target(controller=False)
        self.assertTrue(self.pilot._phase_imported)
        before = files(self.target)
        self.assertEqual(self.import_phase(), result)
        self.assertEqual(files(self.target), before)
        for changes in ({'capsule_sha256': '0' * 64}, {'authorization': {}},
                        {'capsule_path': self.phase / 'authorization.json'}):
            with self.assertRaises(ContractError):
                self.import_phase(**changes)
        self.assertEqual(self.pilot.db.execute('SELECT count(*) FROM events').fetchone()[0], 2)
        self.preserved()

    def test_controller_interruption_resumes(self):
        self.cutover(); self.restore(); self.open_target(); self.import_phase()
        append = PaperPilotController._append
        def fail(controller, body):
            if body['kind'] == 'APPLICATION_PHASE_IMPORT':
                raise RuntimeError('after freeze')
            return append(controller, body)
        with patch.object(PaperPilotController, '_append', fail):
            with self.assertRaises(RuntimeError):
                self.controller_open()
        self.reopen_target()
        rows = self.controller.db.execute('SELECT body FROM events').fetchall()
        self.assertEqual([loads(r[0])['kind'] for r in rows], ['FREEZE', 'APPLICATION_PHASE_IMPORT'])
        self.preserved()

    def test_activation_interruptions_resume(self):
        self.cutover(); self.restore(); self.open_target(); self.import_phase(); self.controller_open()
        with patch.object(transition.os, 'link', side_effect=RuntimeError('before publish')):
            with self.assertRaises(RuntimeError):
                self.activate()
        self.assertEqual(list(self.active.iterdir()), [])
        self.inactive()
        self.preserved()
        with patch.object(self.authority, '_current', side_effect=RuntimeError('lost return')):
            with self.assertRaises(RuntimeError):
                self.activate()
        pointer = self.pointer.read_bytes()
        result = self.activate()
        self.assertEqual(result, self.activate())
        self.assertEqual(self.pointer.read_bytes(), pointer)
        self.reopen_target()
        self.preserved()
