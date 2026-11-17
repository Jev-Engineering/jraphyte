"""Closure-pinned verifier loader regressions for issue #97.

All verifiers here are authored synthetic fixtures. The "legacy" runner below is
an authored model of a top-level-only pin with ordinary imports; it is not the
private V6 evaluator. No result here is a real gate or qualification outcome.
"""
import hashlib
import json
import os
from pathlib import Path
import py_compile
import shutil
import subprocess
import sys
import tempfile
import unittest

from src import verifier_closure_loader as loader
from src.verifier_closure_loader import VerifierClosureError

FIXTURE = Path(__file__).resolve().parent / "fixtures/verifier_closure/authored_verifier"
ENTRY = "authored_verifier.entry"
BELOW, ABOVE = {"observed": 0.5}, {"observed": 0.99}

LEGACY_RUNNER = r"""
import hashlib, importlib, json, sys
root, entry, pinned, inputs = sys.argv[1:5]
sys.path.insert(0, root)
path = root + "/" + entry.replace(".", "/") + ".py"
if hashlib.sha256(open(path, "rb").read()).hexdigest() != pinned:
    print("HOLD"); raise SystemExit
print(importlib.import_module(entry).evaluate(json.loads(inputs)))
"""


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class Release:
    """A temporary approved verifier root holding a copy of the fixture."""

    def __init__(self, testcase, **contract_options):
        self.temporary = tempfile.TemporaryDirectory()
        testcase.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve() / "release"
        shutil.copytree(FIXTURE, self.root / "authored_verifier")
        self.options = contract_options

    def path(self, relative):
        return self.root / "authored_verifier" / relative

    def write(self, relative, text):
        self.path(relative).write_text(text, encoding="utf-8")

    def contract(self):
        options = {"approved_external": ("json",), **self.options}
        return loader.build_release_contract(self.root, ENTRY, verifier_id="authored-fixture",
                                             approved_roots=[self.root], **options)

    def run(self, contract, inputs=BELOW):
        return loader.run_verifier(self.root, contract, inputs, approved_roots=[self.root])

    def legacy(self, pinned, inputs=BELOW, flags=("-B",)):
        completed = subprocess.run(
            [sys.executable, "-I", *flags, "-c", LEGACY_RUNNER, str(self.root), ENTRY, pinned, json.dumps(inputs)],
            capture_output=True, text=True, check=True)
        return completed.stdout.strip()


def make_pass_helper(release):
    text = release.path("helper.py").read_text(encoding="utf-8")
    release.write("helper.py", text.replace('observed >= THRESHOLD else "HOLD"', 'observed >= 0 else "HOLD"'))


class HoldToPassReproductionTests(unittest.TestCase):
    def test_legacy_top_level_pin_turns_hold_into_pass_when_only_helper_changes(self):
        release = Release(self)
        pinned = sha(release.path("entry.py"))
        self.assertEqual(release.legacy(pinned), "HOLD")
        make_pass_helper(release)
        self.assertEqual(sha(release.path("entry.py")), pinned)
        self.assertEqual(release.legacy(pinned), "PASS")

    def test_closure_loader_rejects_the_same_helper_only_change(self):
        release = Release(self)
        contract = release.contract()
        entry = sha(release.path("entry.py"))
        self.assertEqual(release.run(contract)["status"], "HOLD")
        make_pass_helper(release)
        self.assertEqual(sha(release.path("entry.py")), entry)
        with self.assertRaises(VerifierClosureError) as caught:
            release.run(contract)
        self.assertEqual(caught.exception.code, "closure_mismatch")
        self.assertIn("authored_verifier/helper.py", str(caught.exception))
        gate = loader.evaluate_closure_gate(release.root, contract, BELOW, approved_roots=[release.root])
        self.assertEqual((gate["status"], gate["rejected"]), ("HOLD", "closure_mismatch"))


class AcceptedClosureTests(unittest.TestCase):
    def test_contract_pins_entry_helpers_and_package(self):
        release = Release(self)
        contract = release.contract()
        self.assertEqual(set(contract["closure"]), {
            "authored_verifier/__init__.py", "authored_verifier/entry.py",
            "authored_verifier/helper.py", "authored_verifier/criteria.py"})
        self.assertEqual(contract["runtime"], loader.runtime_identity())

    def test_unchanged_closure_passes_and_genuine_failure_stays_hold(self):
        release = Release(self)
        contract = release.contract()
        passed = release.run(contract, ABOVE)
        self.assertEqual(passed["status"], "PASS")
        self.assertEqual(passed["release_contract_sha256"], loader.contract_sha256(contract))
        self.assertEqual(passed["evidence"], "mechanical_closure_check_not_qualification")
        self.assertEqual(release.run(contract, BELOW)["status"], "HOLD")

    def test_verifier_exception_and_unknown_result_are_hold(self):
        release = Release(self)
        release.write("helper.py", "def decide(inputs):\n    return inputs['absent']\n")
        held = release.run(release.contract())
        self.assertEqual((held["status"], held["hold_reason"]), ("HOLD", "KeyError"))
        release.write("helper.py", "def decide(inputs):\n    return 'pass'\n")
        held = release.run(release.contract())
        self.assertEqual((held["status"], held["hold_reason"]), ("HOLD", "unrecognized_verifier_result"))

    def test_loading_does_not_populate_sys_modules_or_sys_path(self):
        release = Release(self)
        before_path = list(sys.path)
        release.run(release.contract(), ABOVE)
        self.assertEqual(sys.path, before_path)
        self.assertFalse([name for name in sys.modules if name.startswith("authored_verifier")])

    def test_approved_dynamic_dependency_is_pinned(self):
        release = Release(self, approved_dynamic=("authored_verifier.plugin",))
        release.write("plugin.py", "RESULT = 'PASS'\n")
        release.write("entry.py", "def evaluate(inputs):\n"
                                  "    return __import__('authored_verifier.plugin').plugin.RESULT\n")
        contract = release.contract()
        self.assertIn("authored_verifier/plugin.py", contract["closure"])
        self.assertEqual(release.run(contract)["status"], "PASS")
        release.write("plugin.py", "RESULT = 'HOLD'\n")
        with self.assertRaises(VerifierClosureError) as caught:
            release.run(contract)
        self.assertEqual(caught.exception.code, "closure_mismatch")


class RejectionTests(unittest.TestCase):
    def assert_rejected(self, code, action):
        with self.assertRaises(VerifierClosureError) as caught:
            action()
        self.assertEqual(caught.exception.code, code)

    def test_helper_replacement_by_new_transitive_file(self):
        release = Release(self)
        contract = release.contract()
        release.write("criteria.py", "from .override import THRESHOLD\n")
        release.write("override.py", "THRESHOLD = 0\n")
        self.assert_rejected("closure_mismatch", lambda: release.run(contract))

    def test_missing_dependency(self):
        release = Release(self)
        contract = release.contract()
        release.path("criteria.py").unlink()
        self.assert_rejected("missing_dependency", lambda: release.run(contract))
        release.write("criteria.py", "THRESHOLD = 0.95\n")
        release.write("entry.py", "from . import absent\n\ndef evaluate(inputs):\n    return 'PASS'\n")
        self.assert_rejected("missing_dependency", release.contract)

    def test_sys_path_ambiguity(self):
        release = Release(self)
        contract = release.contract()
        shadow = Path(release.temporary.name) / "shadow"
        shutil.copytree(release.root / "authored_verifier", shadow / "authored_verifier")
        sys.path.insert(0, str(shadow))
        try:
            self.assert_rejected("import_path_ambiguity", lambda: release.run(contract))
        finally:
            sys.path.remove(str(shadow))
        self.assertEqual(release.run(contract)["status"], "HOLD")

    def test_cached_sys_modules_entry_is_rejected(self):
        release = Release(self)
        contract = release.contract()
        sys.modules["authored_verifier.helper"] = type(sys)("authored_verifier.helper")
        try:
            self.assert_rejected("module_cached_outside_closure", lambda: release.run(contract))
        finally:
            del sys.modules["authored_verifier.helper"]

    def test_unapproved_root(self):
        release = Release(self)
        contract = release.contract()
        copy = Path(release.temporary.name) / "copy"
        shutil.copytree(release.root, copy)
        self.assert_rejected("unapproved_verifier_root",
                             lambda: loader.run_verifier(copy, contract, BELOW, approved_roots=[release.root]))
        self.assert_rejected("dynamic_dependency_outside_verifier_package", lambda: loader.build_release_contract(
            release.root, ENTRY, verifier_id="x", approved_roots=[release.root], approved_dynamic=("other.module",)))

    def test_unapproved_dynamic_imports_and_execution(self):
        bodies = {
            "unapproved_dynamic_import": "__import__('authored_verifier.criteria')",
            "import_machinery_denied": "import importlib",
            "unapproved_dynamic_execution": "exec('RESULT = 1')",
        }
        for code, body in bodies.items():
            with self.subTest(code=code):
                release = Release(self)
                release.write("entry.py", body + "\n\ndef evaluate(inputs):\n    return 'PASS'\n")
                self.assert_rejected(code, release.contract)
        release = Release(self)
        release.write("entry.py", "import urllib.request\n\ndef evaluate(inputs):\n    return 'PASS'\n")
        self.assert_rejected("unpinned_import", release.contract)

    def test_local_stdlib_shadow_is_rejected_by_method_hashes_cross_check(self):
        release = Release(self)
        (release.root / "json.py").write_text("def loads(value):\n    return {'observed': 1}\n", encoding="utf-8")
        self.assert_rejected("closure_scan_disagreement", release.contract)

    def test_closure_scan_disagreement_with_method_hashes_fails_closed(self):
        release = Release(self)
        extra = release.root / "src/parallel_source_v4/unreviewed.py"
        extra.parent.mkdir(parents=True)
        extra.write_text("VALUE = 1\n", encoding="utf-8")
        self.assert_rejected("closure_scan_disagreement", release.contract)

    def test_symlinked_helper(self):
        release = Release(self)
        target = Path(release.temporary.name) / "outside_helper.py"
        shutil.copy(release.path("helper.py"), target)
        release.path("helper.py").unlink()
        try:
            os.symlink(target, release.path("helper.py"))
        except (OSError, NotImplementedError) as exc:
            self.skipTest("symlink creation unavailable: " + type(exc).__name__)
        self.assert_rejected("symlink_in_closure", release.contract)

    def test_ambiguous_module_file_and_package(self):
        release = Release(self)
        (release.path("helper")).mkdir()
        release.write("helper/__init__.py", "def decide(inputs):\n    return 'PASS'\n")
        self.assert_rejected("ambiguous_module_resolution", release.contract)

    def test_runtime_and_contract_shape(self):
        release = Release(self)
        contract = release.contract()
        changed = dict(contract, runtime={"implementation": "cpython", "version": "2.7"})
        self.assert_rejected("unsupported_runtime", lambda: release.run(changed))
        extra = dict(contract, accepted=True)
        self.assert_rejected("unsupported_release_contract", lambda: release.run(extra))

    def test_import_time_side_effects_never_run_on_rejection(self):
        release = Release(self)
        marker = Path(release.temporary.name) / "side_effect"
        release.write("entry.py", "from . import helper\n"
                                  f"open({str(marker)!r}, 'w').close()\n\n"
                                  "def evaluate(inputs):\n    return helper.decide(inputs)\n")
        contract = release.contract()
        self.assertFalse(marker.exists())
        make_pass_helper(release)
        self.assert_rejected("closure_mismatch", lambda: release.run(contract))
        self.assertFalse(marker.exists())
        release.write("helper.py", FIXTURE.joinpath("helper.py").read_text(encoding="utf-8"))
        self.assertEqual(release.run(contract)["status"], "HOLD")
        self.assertTrue(marker.exists())

    def test_change_during_execution_is_rejected(self):
        release = Release(self, approved_external=("json", "pathlib"))
        helper = release.path("criteria.py")
        release.write("entry.py", "from pathlib import Path\n\nfrom . import helper\n\n"
                                  "def evaluate(inputs):\n"
                                  f"    Path({str(helper)!r}).write_text('THRESHOLD = 0\\n')\n"
                                  "    return 'PASS'\n")
        contract = release.contract()
        self.assert_rejected("closure_changed_during_execution", lambda: release.run(contract))


class StaleBytecodeTests(unittest.TestCase):
    def test_stale_pycache_reaches_legacy_import_but_not_closure_loader(self):
        release = Release(self)
        helper = release.path("helper.py")
        genuine = helper.read_bytes()
        make_pass_helper(release)
        stale = helper.read_bytes()
        helper.write_bytes(stale.replace(b'>= 0 else', b'>= 0 else' + b' ' * (len(genuine) - len(stale))))
        self.assertEqual(len(helper.read_bytes()), len(genuine))
        os.utime(helper, (1_700_000_000, 1_700_000_000))
        # Default cache location as seen by the isolated child (-I ignores PYTHONPYCACHEPREFIX).
        cached = helper.parent / "__pycache__" / f"helper.{sys.implementation.cache_tag}.pyc"
        py_compile.compile(str(helper), cfile=str(cached),
                           doraise=True, invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP)
        helper.write_bytes(genuine)
        os.utime(helper, (1_700_000_000, 1_700_000_000))
        contract = release.contract()
        self.assertEqual(contract["closure"]["authored_verifier/helper.py"], hashlib.sha256(genuine).hexdigest())
        pinned = sha(release.path("entry.py"))
        self.assertEqual(release.legacy(pinned, flags=()), "PASS")  # executes the stale bytecode
        self.assertEqual(release.run(contract)["status"], "HOLD")  # executes the verified source bytes


if __name__ == "__main__":
    unittest.main()
