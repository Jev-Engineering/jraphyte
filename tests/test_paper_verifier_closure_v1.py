"""Behavioural tests for the #97 executable dependency closure (``paper-verifier-closure-v1``).

Every execution test starts a fresh interpreter through the public API; the subprocess boundary is never mocked.
Fixtures are disposable authored verifiers under a temporary directory: no private corpus, label, prediction,
model, key or credential is read.  The first class reproduces the defects of the previous pin-only pattern so the
later tests demonstrably close them.
"""
from __future__ import annotations

import contextlib
import copy
import errno
import hashlib
import importlib.util
import inspect
import io
import json
import os
import py_compile
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from pathlib import Path
from unittest import mock

from trace_gc import verifier_closure as pv

WINDOWS = sys.platform == "win32"
REPO = Path(__file__).resolve().parents[1]
_OBSERVATION = None
_BUILT: dict = {}


def observation():
    """One runtime observation per test process (the census is the expensive part)."""
    global _OBSERVATION
    if _OBSERVATION is None:
        _OBSERVATION = pv.observe_runtime(sys.executable)
    return _OBSERVATION


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def alive(pid: int) -> bool:
    if WINDOWS:
        import ctypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.restype = ctypes.c_void_p
        handle = kernel.OpenProcess(0x00100000, False, pid)  # SYNCHRONIZE
        if not handle:
            return False
        try:
            return kernel.WaitForSingleObject(ctypes.c_void_p(handle), 0) == 0x102  # WAIT_TIMEOUT
        finally:
            kernel.CloseHandle(ctypes.c_void_p(handle))
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    try:                                                              # a reaped-pending zombie is not alive
        with open("/proc/%d/stat" % pid, "rb") as stream:
            return stream.read().rsplit(b")", 1)[1].split()[0] != b"Z"
    except OSError:
        return True


def evaluator_privilege():
    """The trusted-writer principal this very process runs as (``uid:0``, or an enabled ``sid:`` of SYSTEM, Administrators or
    TrustedInstaller), else ``None``: asked of the SAME inspector the enforcement gate uses.  An enforced run by such an
    evaluator is refused with ``runtime_evaluator_privileged`` BEFORE any writable path is reported, so every negative
    that expects ``runtime_writable_by_others`` from a real run must expect this instead when this is not ``None``."""
    view = pv.default_protection_view(pv.ProtectionPolicy.build())
    return None if view is None else view.privileged_evaluator()


def expected_exposure_reason():
    """``(reason prefix, detail)`` an enforced real run over a tree this process can write must report."""
    held = evaluator_privilege()
    return ("runtime_evaluator_privileged", held) if held else ("runtime_writable_by_others", None)


MAIN = '''import hashlib
import json
from . import helper


def verify(inputs, params):
    return {"status": helper.decide(inputs), "doc_sha256": hashlib.sha256(inputs["doc"]).hexdigest(),
            "names": json.dumps(sorted(inputs))}
'''
HELPER_HOLD = 'def decide(inputs):\n    return "HOLD"\n'
HELPER_PASS = 'def decide(inputs):\n    return "PASS"\n'
# ``vars()`` at module level is the module namespace; neither it nor a non-constant ``getattr`` name is something the
# static scan can see, so these fixtures reach the run-time mediation through the supported language itself.
MAIN_IMPORTLIB_LITERAL = ('import importlib\n\nPROXY = vars()["importlib"]\n\n\ndef verify(inputs, params):\n'
                          '    importlib.import_module("json")\n'
                          '    return {"status": "PASS", "proxy": type(PROXY).__name__, "util": getattr(PROXY, "util", None) is not None}\n')
REACH_IMPORT = 'builtins = print.__self__\nIMPORT = getattr(builtins, "__imp" + "ort__")\n'
REACH_MODULES = 'import sys\n\nMODULES = getattr(sys, "mod" + "ules")\n'


class Fixture:
    """A disposable authored verifier closure plus one input document."""

    def __init__(self, test: unittest.TestCase, helper: str = HELPER_PASS, main: str = MAIN, extra: dict | None = None):
        self.test = test
        self.tmp = Path(tempfile.mkdtemp(prefix="pvc-test-"))
        test.addCleanup(shutil.rmtree, self.tmp, True)
        self.root = self.tmp / "closure"
        self.data = self.tmp / "data"
        self.work = self.tmp / "work"
        for directory in (self.root / "vc", self.data, self.work):
            directory.mkdir(parents=True)
        self.files = {"vc/__init__.py": "", "vc/main.py": main, "vc/helper.py": helper, **(extra or {})}
        for relative, text in self.files.items():
            self.write(relative, text)
        (self.data / "doc.txt").write_bytes(b"good")
        self.manifest = self.digest = self.release = None

    def write(self, relative: str, text: str, root: Path | None = None):
        path = (root or self.root) / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode("utf-8"))
        return path

    @property
    def roots(self):
        return {"vc": self.root}

    def build(self, **kwargs):
        roots = kwargs.pop("roots", self.roots)
        entry = kwargs.pop("entry", "vc.main")
        key = None
        if roots == self.roots and not kwargs:                        # the manifest is location independent: share builds
            key = (tuple(sorted(self.files.items())), entry)
        if key is not None and key in _BUILT:
            self.manifest = copy.deepcopy(_BUILT[key])
        else:
            self.manifest = pv.build_manifest(name="authored", roots=roots, entry_module=entry, observation=observation(),
                                              **kwargs)
            if key is not None:
                _BUILT[key] = copy.deepcopy(self.manifest)
        self.digest = pv.manifest_digest(self.manifest)
        self.release = pv.release_digest(self.manifest)
        return self

    def inputs(self):
        return {"doc": pv.InputSpec(self.data, "doc.txt", sha(b"good"))}

    def run(self, manifest=None, digest=None, release=None, **kwargs):
        manifest = manifest or self.manifest
        kwargs.setdefault("inputs", self.inputs())
        kwargs.setdefault("roots", self.roots)
        kwargs.setdefault("work_dir", self.work)
        kwargs.setdefault("allow_unprotected_runtime", True)          # protection itself is tested in RuntimeProtection
        return pv.run_verifier(manifest, digest or self.digest,
                               expected_release_sha256=release or (self.release if manifest is self.manifest else pv.release_digest(manifest)),
                               **kwargs)

    def verify(self, manifest=None, digest=None, release=None, **kwargs):
        manifest = manifest or self.manifest
        kwargs.setdefault("roots", self.roots)
        kwargs.setdefault("allow_unprotected_runtime", True)
        return pv.verify_closure(manifest, digest or self.digest,
                                 expected_release_sha256=release or (self.release if manifest is self.manifest else pv.release_digest(manifest)),
                                 **kwargs)

    def table(self, **kwargs):
        """The complete module map an independent reviewer holds: reviewer-side census of this closure and interpreter."""
        return self.verify(**kwargs).table


def retarget(manifest, mutate):
    """Return a mutated manifest copy with a *recomputed* digest, so only the content checks can reject it."""
    changed = copy.deepcopy(manifest)
    mutate(changed)
    return changed, pv.manifest_digest(changed)


def add_module(manifest, name, data: bytes, root="vc", package=False, edges=()):
    entry = {"name": name, "root": root, "path": pv._derived_path(name, package), "sha256": sha(data),
             "bytes": len(data), "package": package}
    manifest["modules"] = sorted([*manifest["modules"], entry], key=lambda m: m["name"])
    manifest["edges"][name] = sorted(edges)
    manifest["edges"] = dict(sorted(manifest["edges"].items()))


def reseal(receipt):
    """Recompute the unkeyed binding after an edit: what a forger with no key can always do."""
    pv._seal(receipt)
    return receipt


class RejectionMixin:
    def assertRejected(self, run, code, failure=None):
        self.assertEqual(run.status, "REJECTED", run.reason)
        self.assertTrue(run.reason.startswith(code), run.reason)
        self.assertIsNotNone(run.receipt["failure_class"])
        if failure:
            self.assertEqual(run.receipt["failure_class"], failure, run.reason)

    def assertRaisesCode(self, code, function, *args, **kwargs):
        with self.assertRaises(pv.ClosureRejected) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.code, code, str(caught.exception))
        return caught.exception


# ---------------------------------------------------------------------------------------------------
# 1. Reproduce the pre-closure behaviour (these tests describe the *old* pattern, not the new API).

LEGACY_HARNESS = r'''
import hashlib, sys
top, expected, helper_dir = sys.argv[1:4]
raw = open(top, "rb").read()
assert hashlib.sha256(raw).hexdigest() == expected, "top-level source changed"
sys.path.insert(0, helper_dir)           # ordinary import resolution, as in the old captured-module pattern
namespace = {"__name__": "legacy_verifier"}
exec(compile(raw, top, "exec"), namespace)
print(namespace["verify"]({"doc": b"good"}, {})["status"])
'''


class OldPatternReproduction(unittest.TestCase):
    """The old top-level-only pin: helper-only change, import-order ambiguity, stale pyc."""

    def legacy(self, top: Path, helper_dir: Path, expected: str | None = None) -> str:
        done = subprocess.run([sys.executable, "-I", "-B", "-c", LEGACY_HARNESS, str(top), expected or sha(top.read_bytes()),
                               str(helper_dir)], capture_output=True, text=True, timeout=60)
        self.assertEqual(done.returncode, 0, done.stderr)
        return done.stdout.strip()

    def test_helper_only_change_flips_hold_to_pass_under_unchanged_top_level_pin(self):
        tmp = Path(tempfile.mkdtemp(prefix="pvc-legacy-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        top = tmp / "verifier_top.py"
        top.write_text('import legacy_helper\n\n\ndef verify(inputs, params):\n    return {"status": legacy_helper.decide(inputs)}\n')
        pinned = sha(top.read_bytes())
        (tmp / "legacy_helper.py").write_text(HELPER_HOLD)
        self.assertEqual(self.legacy(top, tmp, pinned), "HOLD")
        (tmp / "legacy_helper.py").write_text(HELPER_PASS)             # only the helper changes
        self.assertEqual(sha(top.read_bytes()), pinned)                 # the pinned top-level is byte-identical
        self.assertEqual(self.legacy(top, tmp, pinned), "PASS")        # old pattern: verdict flips undetected

    def test_old_method_hashes_prefers_module_file_where_import_system_prefers_package(self):
        try:
            from src.parallel_source_v4.common import method_hashes
        except ImportError as exc:                                      # pragma: no cover - explicit environment skip
            self.skipTest("public method_hashes primitive unavailable: %s" % exc)
        repo = Path(tempfile.mkdtemp(prefix="pvc-ambiguity-"))
        self.addCleanup(shutil.rmtree, repo, True)
        (repo / "src/parallel_source_v4").mkdir(parents=True)
        (repo / "src/parallel_source_v4/seed.py").write_text("import ambig\n")
        (repo / "ambig.py").write_text("WHO = 'module_file'\n")
        (repo / "ambig").mkdir()
        (repo / "ambig/__init__.py").write_text("WHO = 'package_init'\n")
        hashes = method_hashes(repo)
        self.assertIn("ambig.py", hashes)
        self.assertNotIn("ambig/__init__.py", hashes)                   # the file the import system will execute is unbound
        done = subprocess.run([sys.executable, "-I", "-c", "import sys; sys.path.insert(0, sys.argv[1]); import ambig; print(ambig.WHO)",
                               str(repo)], capture_output=True, text=True, timeout=60)
        self.assertEqual(done.stdout.strip(), "package_init")
        self.assertRaisesRegex(pv.ClosureRejected, "ambiguous_resolution",
                               pv.build_manifest, name="x", roots={"r": repo}, entry_module="ambig", observation=observation())

    def test_unchecked_hash_pyc_executes_stale_code_under_dont_write_bytecode_but_not_with_fresh_prefix(self):
        tmp = Path(tempfile.mkdtemp(prefix="pvc-pyc-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        module = tmp / "stale_helper.py"
        module.write_text("VALUE = 'old'\n")
        py_compile.compile(str(module), invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH)
        module.write_text("VALUE = 'new'\n")
        program = "import sys; sys.path.insert(0, sys.argv[1]); import stale_helper; print(stale_helper.VALUE)"

        def run(*flags):
            return subprocess.run([sys.executable, "-I", "-B", *flags, "-c", program, str(tmp)], capture_output=True, text=True,
                                  timeout=60).stdout.strip()
        self.assertEqual(run(), "old")                                  # -B only stops *writing* bytecode
        empty = tmp / "empty-prefix"
        empty.mkdir()
        self.assertEqual(run("-X", "pycache_prefix=" + str(empty)), "new")


# ---------------------------------------------------------------------------------------------------
# 2. The new contract: helper replacement and friends under the same scenario.

class ClosureExecution(RejectionMixin, unittest.TestCase):
    def test_helper_only_replacement_is_rejected_while_top_level_stays_identical(self):
        fx = Fixture(self, helper=HELPER_HOLD).build()
        top = fx.root / "vc/main.py"
        before = sha(top.read_bytes())
        self.assertEqual(fx.run().status, "HOLD")
        fx.write("vc/helper.py", HELPER_PASS)
        self.assertEqual(sha(top.read_bytes()), before)
        run = fx.run()
        self.assertRejected(run, "closure_module_changed:vc.helper", "closure")
        self.assertIsNone(run.receipt["verifier"])                      # nothing executed
        self.assertIsNone(run.receipt["process"])

    def test_same_size_and_mtime_replacement_is_still_rejected(self):
        fx = Fixture(self, helper=HELPER_HOLD).build()
        path = fx.root / "vc/helper.py"
        stamp = path.stat()
        path.write_bytes(HELPER_PASS.encode().ljust(len(HELPER_HOLD))[:len(HELPER_HOLD)])
        self.assertEqual(path.stat().st_size, stamp.st_size)
        os.utime(path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
        self.assertRejected(fx.run(), "closure_module_changed:vc.helper")

    def test_unchanged_complete_closure_passes_and_binds_everything(self):
        fx = Fixture(self).build()
        run = fx.run()
        self.assertEqual((run.status, run.reason), ("PASS", "ok"), run.receipt)
        receipt = run.receipt
        self.assertEqual(pv.verify_receipt(receipt, expected_manifest_sha256=fx.digest, expected_release_sha256=fx.release,
                                           expected_inputs={"doc": sha(b"good")}, require_acceptance=False), "PASS")
        self.assertEqual(receipt["implementation_source"], "disk_reread")   # not started through the launcher
        self.assertFalse(receipt["runtime_protection"]["enforced"])         # explicit opt-out: not acceptance grade
        self.assertIsNone(receipt["failure_class"])
        self.assertEqual(receipt["verifier"]["result"]["doc_sha256"], sha(b"good"))
        self.assertEqual(receipt["verifier"]["result_sha256"], pv.canonical_digest(receipt["verifier"]["result"]))
        self.assertEqual(set(receipt["loaded"]["closure"]), {"vc", "vc.main", "vc.helper"})
        self.assertEqual(receipt["loaded"]["closure"]["vc.helper"], sha(HELPER_PASS.encode()))
        self.assertEqual(receipt["violations"], [])
        self.assertTrue(all(receipt["post_checks"].values()))
        self.assertEqual(receipt["runtime"]["census_sha256"], observation()["pins"]["census_sha256"])
        self.assertEqual({row["path"] for row in receipt["implementation"]},
                         {"trace_gc/" + name for name in pv.IMPLEMENTATION_FILES})
        self.assertEqual(receipt["process"]["exit_code"], 0)
        self.assertEqual(receipt["request"].keys(), {"nonce", "header_sha256"})

    def test_genuine_verifier_failure_remains_hold_and_distinct_from_closure_errors(self):
        fx = Fixture(self, helper=HELPER_HOLD).build()
        run = fx.run()
        self.assertEqual((run.status, run.reason), ("HOLD", "verifier_hold"))
        self.assertIsNone(run.receipt["failure_class"])
        self.assertEqual(pv.verify_receipt(run.receipt, expected_manifest_sha256=fx.digest, expected_release_sha256=fx.release,
                                           require_acceptance=False), "HOLD")
        changed = fx.run(release="0" * 64)
        self.assertEqual(changed.status, "REJECTED")                    # a closure error never reads as HOLD

    def test_verifier_exception_and_invalid_result_are_rejected_not_pass_or_hold(self):
        raising = MAIN.replace('return {"status": helper.decide(inputs),', 'raise ValueError("private detail must not leak")\n    return {"status": helper.decide(inputs),')
        run = Fixture(self, main=raising).build().run()
        self.assertRejected(run, "execution_verifier_exception:ValueError", "execution")
        self.assertNotIn("private detail", json.dumps(run.receipt))
        for body in ('return "PASS"', 'return {"status": "MAYBE"}', 'return {"verdict": "PASS"}'):
            main = "from . import helper\n\n\ndef verify(inputs, params):\n    " + body + "\n"
            run = Fixture(self, main=main).build().run()
            self.assertRejected(run, "execution_result_invalid", "execution")

    def test_standard_library_use_is_reproducible_and_reported(self):
        main = ('import dataclasses\nimport hashlib\nimport re\nimport typing\nfrom . import helper\n\n\n'
                '@dataclasses.dataclass\nclass Row:\n    key: str\n\n\ndef verify(inputs, params):\n'
                '    row = Row(re.sub("o", "0", "good"))\n    return {"status": helper.decide(inputs), "row": row.key,\n'
                '            "digest": hashlib.md5(b"x", usedforsecurity=False).hexdigest()[:4]}\n')
        fx = Fixture(self, main=main).build()
        first, second = fx.run(), fx.run()
        self.assertEqual(first.status, "PASS", first.receipt)
        self.assertEqual(first.receipt["verifier"]["result_sha256"], second.receipt["verifier"]["result_sha256"])
        self.assertEqual(first.receipt["runtime"], second.receipt["runtime"])
        self.assertEqual(first.receipt["verifier"]["result"]["row"], "g00d")
        self.assertGreater(first.receipt["loaded"]["stdlib"] + first.receipt["loaded"]["frozen"], 0)

    def test_manifest_digest_is_location_independent_and_deterministic(self):
        one, two = Fixture(self).build(), Fixture(self).build()
        self.assertNotEqual(one.root, two.root)
        self.assertEqual((one.digest, one.release), (two.digest, two.release))
        self.assertEqual(pv.manifest_digest(json.loads(json.dumps(one.manifest))), one.digest)
        self.assertEqual(one.run().status, "PASS")

    def test_approved_literal_dynamic_import_is_part_of_the_closure(self):
        main = ('import importlib\nfrom . import helper\n\n\ndef verify(inputs, params):\n'
                '    plugin = importlib.import_module("vc.plugin")\n    return {"status": plugin.VERDICT, "h": helper.decide(inputs)}\n')
        fx = Fixture(self, main=main, extra={"vc/plugin.py": 'VERDICT = "PASS"\n'})
        self.assertRaisesCode("unapproved_dynamic_import", pv.build_manifest, name="x", roots=fx.roots, entry_module="vc.main",
                              observation=observation())
        fx.build(dynamic=[{"module": "vc.main", "target": "vc.plugin"}])
        self.assertIn("vc.plugin", fx.manifest["edges"]["vc.main"])
        self.assertEqual(fx.run().status, "PASS")
        fx.write("vc/plugin.py", 'VERDICT = "HOLD"\n')
        self.assertRejected(fx.run(), "closure_module_changed:vc.plugin")

    def test_unapproved_dynamic_target_is_refused_by_the_child_before_it_loads(self):
        main = ('import importlib\nfrom . import helper\n\n\ndef verify(inputs, params):\n'
                '    plugin = importlib.import_module("vc.plugin")\n    return {"status": plugin.VERDICT}\n')
        fx = Fixture(self, main=main, extra={"vc/plugin.py": 'VERDICT = "PASS"\n'})
        fx.build(dynamic=[{"module": "vc.main", "target": "vc.plugin"}])
        verified = fx.verify(work=str(fx.work))
        self.assertTrue(any("vc.plugin" in site[4] for site in verified.sites["vc.main"]))
        self.assertTrue(all(len(site) == 5 and all(type(v) is int for v in site[:4]) for site in verified.sites["vc.main"]))
        verified.sites["vc.main"] = [[*site[:4], [n for n in site[4] if n != "vc.plugin"]]
                                     for site in verified.sites["vc.main"]]   # approval withdrawn
        execution, nonce, header, _ = pv._launch(verified, {}, None, "run", 120.0, str(fx.work))
        report = pv._accept_report(execution, nonce, header, verified, "run")
        self.assertIn("undeclared_import:vc.plugin", report["violations"])
        self.assertNotIn("vc.plugin", report["loaded"]["closure"])

    def test_unused_or_unlisted_dynamic_approval_is_rejected(self):
        fx = Fixture(self)
        self.assertRaisesCode("dynamic_approval_mismatch", pv.build_manifest, name="x", roots=fx.roots, entry_module="vc.main",
                              dynamic=[{"module": "vc.main", "target": "vc.helper"}], observation=observation())

    def test_declared_third_party_distribution_is_census_bound(self):
        fx = Fixture(self, main=MAIN.replace("from . import helper", "import authdep\nfrom . import helper").replace(
            'helper.decide(inputs)', 'authdep.VERDICT if helper.decide(inputs) else "HOLD"'))
        site = fx.tmp / "site"
        (site / "authdep").mkdir(parents=True)
        (site / "authdep/__init__.py").write_text('VERDICT = "PASS"\n')
        (site / "authdep-1.0.dist-info").mkdir()
        (site / "authdep-1.0.dist-info/METADATA").write_text("Metadata-Version: 2.1\nName: authdep\nVersion: 1.0\n")
        roots = {"vc": fx.root, "site": site}
        self.assertRaisesCode("unpinned_import", pv.build_manifest, name="x", roots=fx.roots, entry_module="vc.main",
                              observation=observation())               # not resolvable in any closure root and not declared
        fx.build(roots=roots, packages=[{"distribution": "authdep", "version": "1.0", "root": "site", "top_level": ["authdep"]}])
        self.assertEqual(fx.manifest["packages"][0]["census_files"], 2)
        run = fx.run(roots=roots)
        self.assertEqual(run.status, "PASS", run.receipt)
        self.assertEqual(run.receipt["loaded"]["package"], {"authdep": 1})
        (site / "authdep/__init__.py").write_text('VERDICT = "HOLD"\n')
        self.assertRejected(fx.run(roots=roots), "package_changed:authdep")
        (site / "authdep/__init__.py").write_text('VERDICT = "PASS"\n')
        (site / "authdep-1.0.dist-info/METADATA").write_text("Metadata-Version: 2.1\nName: authdep\nVersion: 2.0\n")
        self.assertRejected(fx.run(roots=roots), "package_")

    def test_package_resolution_ambiguity_and_native_top_level(self):
        tmp = Path(tempfile.mkdtemp(prefix="pvc-pkg-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        suffixes = observation()["probe"]["extension_suffixes"]
        (tmp / ("nativetop" + suffixes[0])).write_bytes(b"not a real extension module; only its bytes are censused")
        (tmp / "nativetop-3.1.dist-info").mkdir()
        (tmp / "nativetop-3.1.dist-info/METADATA").write_text("Name: nativetop\nVersion: 3.1\n")
        entry = {"distribution": "nativetop", "version": "3.1", "root": "site", "top_level": ["nativetop"]}
        digest, count = pv.package_census(str(tmp), entry, suffixes)
        self.assertEqual(count, 2)
        (tmp / "nativetop.py").write_text("X = 1\n")                    # module file next to the extension: ambiguous
        self.assertRaisesCode("package_resolution_ambiguous_or_missing", pv.package_census, str(tmp), entry, suffixes)


# ---------------------------------------------------------------------------------------------------
# 3. Graph, resolution and dynamic-construct rejections (before any verifier code runs).

class ClosureRejections(RejectionMixin, unittest.TestCase):
    def test_missing_dependency_file(self):
        fx = Fixture(self).build()
        (fx.root / "vc/helper.py").unlink()
        run = fx.run()
        self.assertRejected(run, "path_missing_or_case_mismatch", "closure")
        self.assertIsNone(run.receipt["process"])

    def test_manifest_that_omits_an_imported_helper_is_rejected(self):
        fx = Fixture(self).build()

        def drop(manifest):
            manifest["modules"] = [m for m in manifest["modules"] if m["name"] != "vc.helper"]
            del manifest["edges"]["vc.helper"]
            manifest["edges"]["vc.main"] = ["vc"]
        manifest, digest = retarget(fx.manifest, drop)
        self.assertRaisesCode("unlisted_module", fx.verify, manifest, digest)

    def test_manifest_that_omits_an_edge_or_adds_an_unreachable_module_is_rejected(self):
        fx = Fixture(self).build()
        manifest, digest = retarget(fx.manifest, lambda m: m["edges"].__setitem__("vc.main", ["vc"]))
        self.assertRaisesCode("import_graph_mismatch", fx.verify, manifest, digest)
        fx.write("vc/unused.py", "X = 1\n")
        manifest, digest = retarget(fx.manifest, lambda m: add_module(m, "vc.unused", b"X = 1\n", edges=["vc"]))
        self.assertRaisesCode("unreachable_module", fx.verify, manifest, digest)

    def test_entry_callable_must_exist_and_be_synchronous(self):
        fx = Fixture(self)
        self.assertRaisesCode("entry_callable_missing", pv.build_manifest, name="x", roots=fx.roots, entry_module="vc.main",
                              entry_callable="absent", observation=observation())
        fx.write("vc/main.py", "async def verify(inputs, params):\n    return {'status': 'PASS'}\n")
        self.assertRaisesCode("entry_callable_missing", pv.build_manifest, name="x", roots=fx.roots, entry_module="vc.main",
                              observation=observation())

    def test_manifest_and_release_digests_must_match_the_external_values_before_anything_runs(self):
        fx = Fixture(self).build()
        self.assertRaisesCode("manifest_digest_mismatch", fx.verify, digest="0" * 64)
        self.assertRaisesCode("expected_digest_required", fx.verify, digest="not-a-digest")
        self.assertRaisesCode("release_digest_mismatch", fx.verify, release="0" * 64)
        self.assertRaisesCode("expected_release_required", fx.verify, release="short")
        changed = copy.deepcopy(fx.manifest)
        changed["name"] = "renamed"
        self.assertRaisesCode("manifest_digest_mismatch", fx.verify, changed, fx.digest)
        run = fx.run(changed, fx.digest)
        self.assertRejected(run, "manifest_digest_mismatch", "release")
        run = fx.run(release="0" * 64)
        self.assertRejected(run, "release_digest_mismatch", "release")
        self.assertIsNone(run.receipt["process"])
        self.assertIsNone(run.receipt["verifier"])

    def test_release_digest_covers_every_shipped_implementation_file(self):
        fx = Fixture(self).build()
        files = pv.implementation_files()
        self.assertEqual(set(files), {"trace_gc/" + name for name in pv.IMPLEMENTATION_FILES})
        self.assertIn("trace_gc/verifier_closure_bootstrap.py", files)
        self.assertIn("trace_gc/verifier_closure_launcher.py", files)
        self.assertIn("trace_gc/canonical.py", files)
        for path in files:
            changed = dict(files)
            changed[path] = files[path] + b"\n# one trailing byte\n"
            self.assertNotEqual(pv.release_digest(fx.manifest, changed), fx.release, path)
        with mock.patch.object(pv, "implementation_files", lambda: {**files, "trace_gc/verifier_closure_bootstrap.py":
                                                                   files["trace_gc/verifier_closure_bootstrap.py"] + b"\n#\n"}):
            run = fx.run()
        self.assertRejected(run, "release_digest_mismatch", "release")
        self.assertIsNone(run.receipt["process"])                       # a modified bootstrap is never executed

    def test_manifest_shape_is_exact(self):
        fx = Fixture(self).build()
        for mutate, code in ((lambda m: m.__setitem__("extra", 1), "manifest_shape"),
                             (lambda m: m["modules"][0].__setitem__("path", "vc/other.py"), "manifest_module_path"),
                             (lambda m: m["modules"].reverse(), "manifest_modules_unsorted_or_duplicate"),
                             (lambda m: m["runtime"].pop("census_sha256"), "manifest_runtime_shape"),
                             (lambda m: m["modules"][0].__setitem__("name", "vc.é"), "manifest_module_name"),
                             (lambda m: m.__setitem__("version", "paper-verifier-closure-v0"), "manifest_version")):
            changed = copy.deepcopy(fx.manifest)
            mutate(changed)
            with self.assertRaises(pv.ClosureRejected) as caught:
                pv.validate_manifest(changed)
            self.assertEqual(caught.exception.code, code)

    def test_package_vs_module_sourceless_and_case_ambiguity(self):
        fx = Fixture(self).build()
        (fx.root / "vc/helper").mkdir()                                  # package directory beside module file
        self.assertRaisesCode("ambiguous_resolution", fx.verify)
        shutil.rmtree(fx.root / "vc/helper")
        (fx.root / "vc/helper.pyc").write_bytes(b"\0\0\0\0")             # sourceless sibling
        self.assertRaisesCode("ambiguous_resolution", fx.verify)
        (fx.root / "vc/helper.pyc").unlink()
        suffix = observation()["probe"]["extension_suffixes"][0]
        (fx.root / ("vc/helper" + suffix)).write_bytes(b"x")             # extension-module sibling
        self.assertRaisesCode("ambiguous_resolution", fx.verify)
        (fx.root / ("vc/helper" + suffix)).unlink()
        fx.verify()                                                      # all ambiguity removed: verifies again

    def test_same_module_in_two_roots_is_ambiguous(self):
        fx = Fixture(self).build()
        shadow = fx.tmp / "shadow"
        fx.write("vc/helper.py", HELPER_PASS, root=shadow)
        roots = {"vc": fx.root, "shadow": shadow}
        self.assertRaisesCode("ambiguous_multiple_roots", fx.verify, roots=roots)
        self.assertRaisesCode("ambiguous_multiple_roots", pv.build_manifest, name="x", roots=roots, entry_module="vc.main",
                              observation=observation())

    def test_module_file_beside_package_of_same_name_at_build_time(self):
        fx = Fixture(self)
        fx.write("vc.py", "X = 1\n")                                      # the old method_hashes picks this; the importer picks the package
        self.assertRaisesCode("ambiguous_resolution", pv.build_manifest, name="x", roots=fx.roots, entry_module="vc.main",
                              observation=observation())

    def test_case_substitute_is_rejected(self):
        fx = Fixture(self).build()
        os.replace(fx.root / "vc/helper.py", fx.root / "vc/Helper.py")
        self.assertRejected(fx.run(), "path_missing_or_case_mismatch")

    def test_namespace_package_and_sourceless_only_module_are_unsupported(self):
        fx = Fixture(self, main='from ns import leaf\n\n\ndef verify(inputs, params):\n    return {"status": "PASS"}\n',
                     extra={"ns/leaf.py": "X = 1\n"})
        self.assertRaisesCode("unresolved_import", pv.build_manifest, name="x", roots=fx.roots, entry_module="vc.main",
                              observation=observation())               # a directory without __init__ is a namespace package
        fx.write("vc/helper.py", "from vc import ghost\n\n\ndef decide(inputs):\n    return 'PASS'\n")
        (fx.root / "vc/ghost.pyc").write_bytes(b"\0\0\0\0")             # importable sourceless module the manifest cannot bind
        fx.write("vc/main.py", MAIN)
        self.assertRaisesCode("unlisted_module", pv.build_manifest, name="x", roots=fx.roots, entry_module="vc.main",
                              observation=observation())

    def test_unsupported_dynamic_loading_constructs_are_rejected_at_authoring(self):
        cases = {
            "unapproved_dynamic_import": 'import importlib\n\n\ndef verify(i, p):\n    importlib.import_module("vc.helper")\n',
            "dynamic_import_not_literal": 'import importlib\n\n\ndef verify(i, p):\n    importlib.import_module(p["name"])\n',
            "dynamic_execution": 'def verify(i, p):\n    exec(p["code"])\n',
            "dynamic_execution:eval": 'def verify(i, p):\n    return eval(p["code"])\n',
            "forbidden_import": 'import subprocess\n\n\ndef verify(i, p):\n    return {}\n',
            "forbidden_import:ctypes": 'import ctypes\n\n\ndef verify(i, p):\n    return {}\n',
            "forbidden_sys_attribute": 'import sys\n\n\ndef verify(i, p):\n    sys.path.insert(0, p["dir"])\n',
            "forbidden_sys_attribute:alias": 'import sys as s\n\n\ndef verify(i, p):\n    return s.modules\n',
            "forbidden_os_call": 'import os\n\n\ndef verify(i, p):\n    os.system("x")\n',
            "forbidden_import:runpy": 'import runpy\n\n\ndef verify(i, p):\n    return runpy.run_path("x")\n',
            "forbidden_import:builtins": 'import builtins\n\n\ndef verify(i, p):\n    return {}\n',
            "forbidden_import:from-builtins": 'from builtins import open\n\n\ndef verify(i, p):\n    return {}\n',
            "forbidden_import:msvcrt": 'import msvcrt\n\n\ndef verify(i, p):\n    return {}\n',
            "importlib_without_approved_dynamic_import": 'import importlib\n\n\ndef verify(i, p):\n    return {}\n',
            "dynamic_import_layout": ('import importlib\n\n\ndef verify(i, p):\n    importlib.\\\n        import_module("json")\n'
                                      '    return {}\n'),
            "forbidden_import:importlib.util": 'import importlib.util\n\n\ndef verify(i, p):\n    return {}\n',
            "invalid_relative_import": 'from .. import x\n\n\ndef verify(i, p):\n    return {}\n',
            "syntax_error": "def verify(:\n",
        }
        for label, source in cases.items():
            fx = Fixture(self, main=source)
            with self.assertRaises(pv.ClosureRejected, msg=label) as caught:
                pv.build_manifest(name="x", roots=fx.roots, entry_module="vc.main", observation=observation())
            self.assertEqual(caught.exception.code, label.partition(":")[0], label)

    def test_tampered_manifest_with_dynamic_construct_is_rejected_at_verification(self):
        """The manifest is not trusted: even hash-consistent bytes are re-scanned."""
        fx = Fixture(self).build()
        evil = 'from . import helper\n\n\ndef verify(inputs, params):\n    exec(params["code"])\n    return {"status": "PASS"}\n'
        fx.write("vc/main.py", evil)

        def retarget_main(manifest):
            for item in manifest["modules"]:
                if item["name"] == "vc.main":
                    item.update(sha256=sha(evil.encode()), bytes=len(evil.encode()))
        manifest, digest = retarget(fx.manifest, retarget_main)
        self.assertRaisesCode("dynamic_execution", fx.verify, manifest, digest)

    def test_unpinned_and_shadowing_imports(self):
        fx = Fixture(self, helper="import jsonschema\n\n\ndef decide(i):\n    return 'PASS'\n")
        self.assertRaisesCode("unpinned_import", pv.build_manifest, name="x", roots=fx.roots, entry_module="vc.main",
                              observation=observation())             # installed in the test env, but not pinned
        shadow = Fixture(self, extra={"json/__init__.py": "X = 1\n"}, main="import json\n\n\ndef verify(i, p):\n    return {}\n")
        shadow.write("vc/helper.py", "X = 1\n")
        with self.assertRaises(pv.ClosureRejected) as caught:
            pv.build_manifest(name="x", roots=shadow.roots, entry_module="json", observation=observation())
        self.assertEqual(caught.exception.code, "closure_name_shadows_runtime")

    def test_relative_paths_reject_windows_aliases_and_traversal(self):
        for bad in ("vc/con.py", "vc/nul.txt", "vc/a:b.py", "vc/../x.py", "vc\\x.py", "/abs.py", "vc/x.py.", "vc/x .py", "vc//x.py",
                    "vc/~1.py", "vc/a b.py", ""):
            with self.assertRaises(pv.ClosureRejected, msg=bad):
                pv._check_relative(bad)
        self.assertEqual(pv._check_relative("vc/ok-1.0+x/__init__.py"), ["vc", "ok-1.0+x", "__init__.py"])


# ---------------------------------------------------------------------------------------------------
# 4. Runtime contract.

class RuntimeContract(RejectionMixin, unittest.TestCase):
    def test_pinned_runtime_is_authenticated_before_any_interpreter_process_exists(self):
        """Executable, base executable, venv config, start-up configuration/files, census and natives are hashed from the
        file system before the first interpreter starts: neither the probe nor any child process may be created."""
        fx = Fixture(self).build()
        pins = observation()["pins"]

        def startup_files(runtime):
            runtime["startup_files"][0][1] = "9" * 64
            runtime["startup_files_sha256"] = pv.canonical_digest(runtime["startup_files"])

        def startup_config(runtime):
            row = runtime["startup_config"][0]
            row[1] = "9" * 64 if row[1] == "absent" else "absent"
        cases = [("invoked_executable", lambda r: r.__setitem__("invoked_executable", r["invoked_executable"] + ".missing")),
                 ("executable_sha256", lambda r: r.__setitem__("executable_sha256", "2" * 64)),
                 ("base_executable_sha256", lambda r: r.__setitem__("base_executable_sha256", "4" * 64)),
                 ("pyvenv_cfg_sha256", lambda r: r.__setitem__("pyvenv_cfg_sha256", "7" * 64)),
                 ("census_sha256", lambda r: r.__setitem__("census_sha256", "1" * 64)),
                 ("startup_config", startup_config)]
        if pins["startup_files"]:
            cases.append(("startup_files", startup_files))
        if pins["natives"]:
            cases.append(("native_changed", lambda r: r["natives"][0].__setitem__("sha256", "8" * 64)))
        for label, mutate in cases:
            manifest, digest = retarget(fx.manifest, lambda m, f=mutate: f(m["runtime"]))
            with mock.patch.object(pv, "probe_runtime", side_effect=AssertionError("interpreter probe started")) as probe, \
                    mock.patch.object(pv.subprocess, "Popen", side_effect=AssertionError("process started")):
                run = fx.run(manifest, digest)
            probe.assert_not_called()
            self.assertRejected(run, "runtime_mismatch:" + label, "runtime")
            self.assertIsNone(run.receipt["process"], label)

    def test_live_probe_facts_are_compared_after_authentication(self):
        fx = Fixture(self).build()
        for key, value in (("cache_tag", "bogus-00"), ("startup_modules_sha256", "3" * 64), ("preload_modules_sha256", "5" * 64)):
            manifest, digest = retarget(fx.manifest, lambda m, k=key, v=value: m["runtime"].__setitem__(k, v))
            run = fx.run(manifest, digest)
            self.assertRejected(run, "runtime_mismatch:" + key, "runtime")
            self.assertIsNone(run.receipt["process"], key)
        manifest, digest = retarget(fx.manifest, lambda m: m["runtime"].__setitem__("version", "0.0.0"))
        run = fx.run(manifest, digest)
        self.assertRegex(run.reason, r"^runtime_mismatch:(version|startup_config)$")
        manifest, digest = retarget(fx.manifest, lambda m: m["runtime"].__setitem__("startup_files_sha256", "6" * 64))
        self.assertRejected(fx.run(manifest, digest), "manifest_runtime_rows")

    def test_runtime_protection_is_required_by_default_and_enforced_before_any_interpreter(self):
        fx = Fixture(self).build()
        exposure = fx.run().receipt["runtime_protection"]
        self.assertEqual(set(exposure), {"inspected", "enforced", "paths_checked", "exposed", "policy", "trusted"})
        self.assertFalse(exposure["enforced"])                           # the explicit opt-out is recorded, never silent
        self.assertEqual(exposure["policy"], pv.WINDOWS_POLICY if WINDOWS else pv.POSIX_POLICY)
        if not WINDOWS:
            self.assertTrue(exposure["inspected"], exposure)
            self.assertEqual(exposure["trusted"], ["uid:0"])
        with mock.patch.object(pv, "authenticate_runtime", side_effect=AssertionError("runtime hashed first")), \
                mock.patch.object(pv, "probe_runtime", side_effect=AssertionError("interpreter probe started")), \
                mock.patch.object(pv.subprocess, "Popen", side_effect=AssertionError("process started")):
            if WINDOWS:
                self.skipTest("native Windows enforcement is exercised by RuntimeProtection.test_windows_view_*")
            os.chmod(fx.root, 0o777)
            exposed = pv.runtime_write_exposure(observation()["pins"], [str(fx.root)])["exposed"]
            self.assertTrue(any(e.startswith(os.path.abspath(fx.root) + " [") for e in exposed), exposed)   # owner:<uid> or other_write
            # a privileged evaluator (uid 0) is refused FIRST; the writable tree is still reported in the evidence
            reason, held = expected_exposure_reason()
            if held:
                self.assertTrue(exposed[0].startswith("evaluator [privileged_evaluator:"), exposed)
            else:
                self.assertFalse(any(e.startswith("evaluator [") for e in exposed), exposed)
            error = self.assertRaisesCode(reason, fx.verify, allow_unprotected_runtime=False)
            self.assertEqual(error.detail, held or error.detail)
            refused = fx.run(allow_unprotected_runtime=False)
            self.assertRejected(refused, reason, "runtime")
            self.assertIsNone(refused.receipt["process"])
            self.assertIsNone(refused.receipt["verifier"])

    def test_a_privileged_evaluator_precedes_a_writable_tree_in_the_gate_on_either_platform(self):
        """Independent of who runs the suite: the gate's order is fixed by the inspector's evidence, tested with facts
        injected into the inspector's OWN view (the production decision code, not a copy of it)."""
        fx = Fixture(self).build()
        pins = observation()["pins"]
        manifest = fx.manifest
        parsed = pv._parse_roots(fx.roots)
        for kind, held, labels in (("posix", "uid:0", {"uid:0"}), ("windows", "sid:" + ADMINS_SID, {"sid:" + ADMINS_SID})):
            with self.subTest(kind):
                class Privileged(pv.ProtectionView):
                    def __init__(self, policy):
                        super().__init__(policy)
                        self.kind = kind

                    def evaluators(self):
                        return labels

                    def assess(self, path, st, strict):
                        return "other_write"                                   # every inspected path is also writable by others
                policy = pv.ProtectionPolicy.build()
                view = Privileged(policy)
                exposure = pv.runtime_write_exposure(pins, [*parsed.values()], policy=policy, view=view)
                self.assertEqual(exposure["exposed"][0], "evaluator [privileged_evaluator:%s]" % held)
                self.assertTrue(any("[other_write]" in entry for entry in exposure["exposed"][1:]))
                error = self.assertRaisesCode("runtime_evaluator_privileged", pv._protection_gate, pins, parsed, manifest, True,
                                              policy, view)
                self.assertEqual(error.detail, held)                           # privileged precedes runtime_writable_by_others

    def test_unprotected_runs_are_labelled_and_never_acceptance_grade(self):
        fx = Fixture(self).build()
        run = fx.run()                                                   # explicit opt-out
        self.assertEqual(run.status, "PASS", run.receipt)
        base = dict(expected_manifest_sha256=fx.digest, expected_release_sha256=fx.release)
        self.assertEqual(pv.verify_receipt(run.receipt, require_acceptance=False, **base), "PASS")
        self.assertRaisesCode("receipt_context_required", pv.verify_receipt, run.receipt, **base)
        context = dict(manifest=fx.manifest, expected_inputs={"doc": sha(b"good")},
                       expected_params_sha256=pv.canonical_digest(None), expected_module_table=fx.table(), **base)
        self.assertRaisesCode("receipt_not_acceptance_grade", pv.verify_receipt, run.receipt, **context)
        forged = copy.deepcopy(run.receipt)
        forged["implementation_source"] = "launcher_capture"
        forged["runtime_protection"].update(inspected=True, enforced=True)
        self.assertRaisesCode("receipt_binding_mismatch", pv.verify_receipt, forged, **context)   # honest label, not editable

    def test_pinned_native_file_changes_are_detected_before_execution(self):
        if not observation()["pins"]["natives"]:
            self.skipTest("no native mappings recorded on this platform")
        fx = Fixture(self).build()
        manifest, digest = retarget(fx.manifest, lambda m: m["runtime"]["natives"][0].__setitem__("sha256", "8" * 64))
        run = fx.run(manifest, digest)
        self.assertRejected(run, "runtime_mismatch:native_changed", "runtime")
        self.assertIsNone(run.receipt["process"])

    @unittest.skipUnless(sys.platform.startswith("linux"), "the start-up mapped-library check reads /proc/self/maps")
    def test_child_refuses_a_native_mapping_that_is_not_pinned_before_any_closure_code_is_loaded(self):
        fx = Fixture(self).build()
        verified = fx.verify(work=str(fx.work))
        if not verified.pins["natives"]:
            self.skipTest("no native mappings recorded")
        verified.pins = dict(verified.pins, natives=[])               # every library mapped at start is now unlisted
        execution, nonce, header, _ = pv._launch(verified, {}, None, "run", 120.0, str(fx.work))
        with self.assertRaises(pv.ClosureRejected) as caught:
            pv._accept_report(execution, nonce, header, verified, "run")
        self.assertTrue(caught.exception.code.startswith("runtime_bootstrap_reject"), caught.exception)
        self.assertIn("native_mapping_unlisted_at_start", caught.exception.detail)

    def test_missing_interpreter_is_a_rejection(self):
        fx = Fixture(self).build()
        self.assertRejected(fx.run(python=fx.tmp / "no-python.exe"), "runtime_", "runtime")

    def test_a_different_interpreter_is_not_accepted(self):
        names = [shutil.which("python3.11"), shutil.which("python3.12"), shutil.which("python3.13"),
                 *os.environ.get("PVC_OTHER_PYTHONS", "").split(os.pathsep)]
        other = [Path(p) for p in names if p and Path(p).is_file()
                 and Path(p).resolve() != Path(sys.executable).resolve()
                 and sha(Path(p).resolve().read_bytes()) != observation()["pins"]["executable_sha256"]]
        if not other:
            self.skipTest("no second interpreter available on this machine")
        fx = Fixture(self).build()
        run = fx.run(python=other[0])
        self.assertRejected(run, "runtime_", "runtime")
        self.assertIsNone(run.receipt["process"])

    def test_unsupported_old_interpreter_is_rejected_honestly(self):
        old = Path(shutil.which("python3.10") or "")
        if not old.is_file():
            self.skipTest("no Python 3.10 available")
        self.assertRaisesCode("unsupported_runtime", pv.probe_runtime, old)

    def test_runtime_census_binds_files_additions_and_absent_paths(self):
        tmp = Path(tempfile.mkdtemp(prefix="pvc-census-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        (tmp / "Lib/pkg").mkdir(parents=True)
        (tmp / "Lib/os.py").write_text("A = 1\n")
        (tmp / "Lib/pkg/mod.py").write_text("B = 2\n")
        probe = {"base_prefix": str(tmp), "sys_path": [str(tmp / "Lib"), str(tmp / "python3.zip")], "core_files": []}
        census = pv.runtime_census(probe)
        base = census.sha256
        self.assertEqual(census.files, 3)                                # two files plus the absent archive entry
        self.assertEqual(pv.runtime_census(probe).sha256, base)
        self.assertEqual(set(census.hashes), {str(tmp / "Lib/os.py"), str(tmp / "Lib/pkg/mod.py")})
        (tmp / "Lib/pkg/mod.py").write_text("B = 3\n")
        self.assertNotEqual(pv.runtime_census(probe).sha256, base)
        (tmp / "Lib/pkg/mod.py").write_text("B = 2\n")
        self.assertEqual(pv.runtime_census(probe).sha256, base)
        (tmp / "Lib/pkg/new.py").write_text("C = 1\n")                  # an added file is a changed runtime
        self.assertNotEqual(pv.runtime_census(probe).sha256, base)
        (tmp / "Lib/pkg/new.py").unlink()
        (tmp / "python3.zip").write_bytes(b"PK")                         # a previously absent sys.path entry appeared
        self.assertNotEqual(pv.runtime_census(probe).sha256, base)
        (tmp / "python3.zip").unlink()
        (tmp / "Lib/__pycache__").mkdir()
        (tmp / "Lib/__pycache__/os.cpython-0.pyc").write_bytes(b"cache")  # bytecode caches are not part of the contract
        self.assertEqual(pv.runtime_census(probe).sha256, base)

    def test_probe_runs_isolated_without_site_and_reports_the_startup_set(self):
        probe = observation()["probe"]
        self.assertEqual(probe["flags"], {"isolated": 1, "no_site": 1, "dont_write_bytecode": 1})
        self.assertNotIn("site", probe["startup_modules"])
        self.assertTrue(all("site-packages" not in p for p in probe["sys_path"]))
        self.assertGreaterEqual(tuple(int(x) for x in probe["version"].split(".")[:2]), (3, 11))

    def test_runtime_pins_include_the_invoked_and_resolved_interpreter_separately(self):
        pins = observation()["pins"]
        self.assertEqual(pins["invoked_executable"], os.path.abspath(sys.executable))
        self.assertEqual(pins["executable_resolved"], os.path.realpath(sys.executable))
        self.assertEqual(len(pins["executable_sha256"]), 64)

    @unittest.skipUnless(sys.platform.startswith("linux"), "native census via /proc/self/maps is Linux-only here")
    def test_native_and_startup_dependencies_are_part_of_the_pinned_runtime(self):
        natives = {os.path.basename(n["path"]) for n in observation()["pins"]["natives"]}
        self.assertTrue(any(name.startswith("libc") or name.startswith("ld-") for name in natives), natives)
        self.assertTrue(observation()["pins"]["natives"])
        self.assertTrue(all(len(n["sha256"]) == 64 for n in observation()["pins"]["natives"]))


# ---------------------------------------------------------------------------------------------------
# 4b. Runtime write protection (authored for first execution; every test drives the real inspector over a real tree).

SYSTEM_SID, ADMINS_SID = "S-1-5-18", "S-1-5-32-544"
USER_SID, OTHER_SID = "S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002"
FULL_CONTROL, READ_EXECUTE = 0x1F01FF, 0x1200A9


class SyntheticView(pv.ProtectionView):
    """The production POSIX inspector over a REAL tree, with the owner/mode/ACL/evaluator facts replaced.

    The default is a root-owned tree without group/other write, so a clean result is deterministic for any user that
    runs the test suite; every negative changes exactly one fact of exactly one path.
    """

    def __init__(self, policy=None, facts=None, acl=(), unreadable=(), writable=(), evaluator="uid:4242", trusted_gids=(0,)):
        super().__init__(policy or pv.ProtectionPolicy())
        self.facts = {os.path.abspath(str(k)): v for k, v in (facts or {}).items()}
        self.acl = {os.path.abspath(str(p)) for p in acl}
        self.unreadable = {os.path.abspath(str(p)) for p in unreadable}
        self.writable = {os.path.abspath(str(p)) for p in writable}
        self.evaluator, self.trusted_gids = evaluator, set(trusted_gids)

    def evaluators(self):
        return {self.evaluator}

    def lstat(self, path):
        if path in self.unreadable:
            raise PermissionError(errno.EACCES, "denied", path)
        real = os.lstat(path)
        fact = self.facts.get(path, {})
        permissions = fact.get("mode", stat.S_IMODE(real.st_mode) & ~0o022)
        return os.stat_result((stat.S_IFMT(real.st_mode) | permissions, real.st_ino, real.st_dev, real.st_nlink,
                               fact.get("uid", 0), fact.get("gid", 0), real.st_size, 0, 0, 0))

    def acl_present(self, path):
        return path in self.acl

    def writable_by_evaluator(self, path):
        return path in self.writable

    def trusted_group(self, gid):
        return gid in self.trusted_gids


class ProtectionTree(RejectionMixin):
    """A real runtime/closure tree plus the helpers every protection test class shares (runs on every platform)."""

    def setUp(self):
        self.tmp = Path(os.path.realpath(tempfile.mkdtemp(prefix="pvc-prot-")))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.rt = self.tmp / "rt"
        (self.rt / "bin").mkdir(parents=True)
        (self.rt / "lib").mkdir()
        (self.rt / "bin/python").write_bytes(b"interpreter")
        (self.rt / "lib/core.py").write_text("X = 1\n")
        self.closure = self.tmp / "closure"
        (self.closure / "vc").mkdir(parents=True)
        self.target = self.closure / "vc/main.py"
        self.target.write_text("pass\n")
        python = str(self.rt / "bin/python")
        self.pins = {"invoked_executable": python, "executable_resolved": python, "base_executable": python,
                     "core_files": [str(self.rt / "lib/core.py")], "startup_files": [], "natives": [], "startup_config": [],
                     "sys_path": [str(self.rt / "lib")]}

    def exposure(self, view=None, files=None, **kwargs):
        return pv.runtime_write_exposure(self.pins, [str(self.closure)], [], files if files is not None else [str(self.target)],
                                         view=view or SyntheticView(), **kwargs)

    def entry(self, path, reason):
        return "%s [%s]" % (path, reason)


@unittest.skipIf(WINDOWS, "the synthetic POSIX view needs POSIX stat semantics")
class RuntimeProtection(ProtectionTree, unittest.TestCase):
    def test_a_clean_tree_is_inspected_enforcement_ready_and_names_its_policy(self):
        result = self.exposure()
        self.assertEqual(set(result), {"inspected", "enforced", "paths_checked", "exposed", "policy", "trusted"})
        self.assertEqual((result["inspected"], result["exposed"], result["policy"], result["trusted"]),
                         (True, [], pv.POSIX_POLICY, ["uid:0"]))
        self.assertGreater(result["paths_checked"], 5)

    def test_each_way_an_untrusted_principal_can_write_a_path_is_named_exactly(self):
        path = str(self.target)
        cases = (("owner:1000", dict(facts={path: {"uid": 1000}})),
                 ("other_write", dict(facts={path: {"mode": 0o666}})),
                 ("group_write:100", dict(facts={path: {"mode": 0o664, "gid": 100}})),
                 ("acl", dict(acl={path})),
                 ("evaluator_writable", dict(writable={path})))
        for reason, kwargs in cases:
            with self.subTest(reason):
                result = self.exposure(SyntheticView(**kwargs))
                self.assertEqual((result["inspected"], result["exposed"]), (True, [self.entry(path, reason)]))

    def test_trusted_principals_are_accepted_and_only_by_explicit_policy(self):
        path = str(self.target)
        self.assertEqual(self.exposure(SyntheticView(facts={path: {"mode": 0o664, "gid": 0}}))["exposed"], [])   # trusted group
        owned = {path: {"uid": 1000}}
        self.assertEqual(self.exposure(SyntheticView(facts=owned))["exposed"], [self.entry(path, "owner:1000")])
        policy = pv.ProtectionPolicy.build([1000])
        result = self.exposure(SyntheticView(policy, facts=owned))
        self.assertEqual((result["exposed"], result["trusted"]), ([], ["uid:0", "uid:1000"]))

    def test_symlink_targets_and_every_ancestor_of_the_target_are_inspected(self):
        outside = self.tmp / "outside"
        (outside / "sub").mkdir(parents=True)
        destination = outside / "sub/target.py"
        destination.write_text("Y = 1\n")
        baseline = self.exposure()
        (self.rt / "lib/linked.py").symlink_to(destination)
        (self.rt / "lib/relative.py").symlink_to(os.path.relpath(destination, self.rt / "lib"))
        clean = self.exposure()
        self.assertEqual((clean["inspected"], clean["exposed"]), (True, []))
        self.assertGreater(clean["paths_checked"], baseline["paths_checked"])           # the targets really were examined
        cases = (("target_other_write", destination, {"mode": 0o666}, "other_write"),
                 ("target_owner", destination, {"uid": 1000}, "owner:1000"),
                 ("target_parent_other_write", outside / "sub", {"mode": 0o777}, "other_write"),
                 ("target_grandparent_other_write", outside, {"mode": 0o777}, "other_write"))
        for label, path, fact, reason in cases:
            with self.subTest(label):
                result = self.exposure(SyntheticView(facts={str(path): fact}))
                self.assertEqual(result["inspected"], True)
                self.assertIn(self.entry(path, reason), result["exposed"])

    def test_a_symlinked_ancestor_exposes_the_real_directory_behind_it(self):
        real = self.tmp / "realdir"
        real.mkdir()
        (real / "f.py").write_text("Z = 1\n")
        link = self.tmp / "linkdir"
        link.symlink_to(real)
        files = [str(link / "f.py")]
        clean = self.exposure(files=files)
        self.assertEqual((clean["inspected"], clean["exposed"]), (True, []))
        for label, path, fact, reason in (("real_directory", real, {"mode": 0o777}, "other_write"),
                                          ("link_owner", link, {"uid": 1000}, "owner:1000"),
                                          ("real_file", real / "f.py", {"mode": 0o666}, "other_write")):
            with self.subTest(label):
                result = self.exposure(SyntheticView(facts={str(path): fact}), files=files)
                self.assertIn(self.entry(path, reason), result["exposed"])

    def test_inspection_that_cannot_complete_is_never_reported_as_clean(self):
        def explode(*_):
            raise OSError(errno.EIO, "io_error")
        broken_listing = SyntheticView()
        broken_listing.listdir = explode
        broken_acl = SyntheticView()
        broken_acl.acl_present = explode
        broken_link = SyntheticView()
        broken_link.link_target = explode
        broken_real = SyntheticView()
        broken_real.realpath = explode
        cases = (("unreadable_root", SyntheticView(unreadable={self.closure}), str(self.closure)),
                 ("unreadable_ancestor", SyntheticView(unreadable={self.tmp}), str(self.tmp)),
                 ("unreadable_file", SyntheticView(unreadable={self.target}), str(self.target)),
                 ("unreadable_runtime_file", SyntheticView(unreadable={self.rt / "lib/core.py"}), "core.py"),
                 ("listing", broken_listing, "io_error"), ("acl", broken_acl, "io_error"),
                 ("link_target", broken_link, "io_error"), ("realpath", broken_real, "io_error"))
        for label, view, needle in cases:
            with self.subTest(label):
                result = self.exposure(view)
                self.assertFalse(result["inspected"])
                self.assertIn(needle, result["exposed"][-1])

    def test_the_entry_limit_and_a_missing_inspector_fail_closed(self):
        with mock.patch.object(pv, "MAX_EXPOSURE_ENTRIES", 3):
            limited = self.exposure()
        self.assertEqual((limited["inspected"], limited["exposed"]), (False, ["entry_limit"]))
        with mock.patch.object(pv, "default_protection_view", return_value=None):
            missing = pv.runtime_write_exposure(self.pins)
        self.assertEqual((missing["inspected"], missing["policy"], missing["trusted"], missing["paths_checked"]),
                         (False, "unavailable", [], 0))

    def test_sticky_ancestors_are_accepted_but_strict_content_directories_are_not(self):
        self.assertEqual(self.exposure(SyntheticView(facts={str(self.tmp): {"mode": 0o1777}}))["exposed"], [])
        lib = str(self.rt / "lib")
        self.assertIn(self.entry(lib, "other_write"), self.exposure(SyntheticView(facts={lib: {"mode": 0o1777}}))["exposed"])
        self.assertIn(self.entry(self.tmp, "other_write"), self.exposure(SyntheticView(facts={str(self.tmp): {"mode": 0o777}}))["exposed"])

    def test_policies_that_trust_the_evaluator_or_are_malformed_are_refused(self):
        for kwargs in (dict(trusted_uids=[-1]), dict(trusted_uids=[True]), dict(trusted_uids=[1.5]), dict(trusted_uids=[1 << 32]),
                       dict(trusted_sids=["not-a-sid"]), dict(trusted_sids=[7]), dict(trusted_sids=["S-1-5"])):
            with self.subTest(kwargs):
                self.assertRaisesCode("runtime_protection_policy_invalid", pv.ProtectionPolicy.build, **kwargs)
        policy = pv.ProtectionPolicy.build([4242])
        refused = self.assertRaisesCode("runtime_protection_policy_invalid", self.exposure, SyntheticView(policy))
        self.assertEqual(refused.detail, "trusts_evaluator:uid:4242")
        self.assertEqual(self.exposure(SyntheticView(policy, evaluator="uid:7"))["trusted"], ["uid:0", "uid:4242"])
        # the superuser is not a policy error, but it is never an acceptable evaluator: the separation failure is recorded
        privileged = self.exposure(SyntheticView(evaluator="uid:0"))
        self.assertEqual((privileged["inspected"], privileged["exposed"]), (True, ["evaluator [privileged_evaluator:uid:0]"]))

    def test_an_administrative_evaluator_is_refused_when_enforcing_and_is_never_acceptance_grade(self):
        marker = "evaluator [privileged_evaluator:uid:0]"
        writable = self.exposure(SyntheticView(evaluator="uid:0", writable={str(self.target)}))
        self.assertEqual(writable["exposed"], [marker])      # a root evaluator can write anything: only the separation failure is named
        manifest = {"packages": [], "modules": [{"root": "r", "path": "vc/main.py"}]}
        pins = dict(self.pins)
        refused = self.assertRaisesCode("runtime_evaluator_privileged", pv._protection_gate, pins, {"r": str(self.closure)}, manifest,
                                        True, None, SyntheticView(evaluator="uid:0"))
        self.assertEqual(refused.detail, "uid:0")
        diagnostic = pv._protection_gate(pins, {"r": str(self.closure)}, manifest, False, None, SyntheticView(evaluator="uid:0"))
        self.assertEqual((diagnostic["enforced"], diagnostic["exposed"]), (False, [marker]))
        accepted = pv._protection_gate(pins, {"r": str(self.closure)}, manifest, True, None, SyntheticView(evaluator="uid:4242"))
        self.assertEqual((accepted["enforced"], accepted["inspected"], accepted["exposed"]), (True, True, []))
        windows = pv.WindowsProtectionView(pv.ProtectionPolicy(), security=lambda path: (SYSTEM_SID, []),
                                           token_sids=lambda: {ADMINS_SID})
        self.assertEqual(windows.privileged_evaluator(), "sid:" + ADMINS_SID)
        self.assertIsNone(pv.WindowsProtectionView(pv.ProtectionPolicy(), security=lambda path: (SYSTEM_SID, []),
                                                   token_sids=lambda: {USER_SID}).privileged_evaluator())

class WindowsProtectionDecisions(ProtectionTree, unittest.TestCase):
    """The Windows owner/DACL decisions drive the production inspector through injected security facts, so they run
    on Windows as well as on POSIX (only the native security API calls themselves are NOT_RUN off Windows)."""

    def test_dacl_decisions_cover_owner_null_dacl_write_rights_and_inheritance(self):
        trusted = frozenset(pv.BUILTIN_SIDS)
        rows = [(0, 0, FULL_CONTROL, ADMINS_SID), (0, 0, READ_EXECUTE, USER_SID)]
        self.assertIsNone(pv._dacl_reason(SYSTEM_SID, rows, trusted, True))
        self.assertEqual(pv._dacl_reason(USER_SID, rows, trusted, True), "owner:" + USER_SID)
        self.assertEqual(pv._dacl_reason(SYSTEM_SID, None, trusted, True), "null_dacl")
        self.assertEqual(pv._dacl_reason(SYSTEM_SID, [(0, 0, 0x2, USER_SID)], trusted, True), "dacl_write:%s:0x2" % USER_SID)
        self.assertEqual(pv._dacl_reason(SYSTEM_SID, [(9, 0, 0x2, USER_SID)], trusted, True), "dacl_write:%s:0x2" % USER_SID)
        self.assertEqual(pv._dacl_reason(SYSTEM_SID, [(0, 0, 0x10000000, USER_SID)], trusted, True),
                         "dacl_write:%s:0x10000000" % USER_SID)
        self.assertIsNone(pv._dacl_reason(SYSTEM_SID, [(0, 0, 0x2, ADMINS_SID)], trusted, True))        # trusted principal
        self.assertIsNone(pv._dacl_reason(SYSTEM_SID, [(0, 0x08, 0x2, USER_SID)], trusted, True))       # inherit-only entry
        self.assertIsNone(pv._dacl_reason(SYSTEM_SID, [(1, 0, 0x2, USER_SID)], trusted, True))          # deny entry
        self.assertIsNone(pv._dacl_reason(SYSTEM_SID, [(0, 0, 0x2, USER_SID)], trusted, False))         # may create siblings only
        self.assertEqual(pv._dacl_reason(SYSTEM_SID, [(0, 0, 0x10000, USER_SID)], trusted, False),
                         "dacl_write:%s:0x10000" % USER_SID)                                           # DELETE can replace an entry
        for ace_type in (4, 5, 11):
            with self.assertRaises(OSError) as caught:
                pv._dacl_reason(SYSTEM_SID, [(ace_type, 0, 0, "")], trusted, True)
            self.assertEqual(caught.exception.strerror, "unsupported_ace_type:%d" % ace_type)

    def windows_view(self, dacls=None, policy=None, token=(USER_SID,), fail=None):
        table = dacls or {}

        def security(path):
            if fail and path in fail:
                raise fail[path]
            return table.get(os.path.abspath(path), (SYSTEM_SID, [(0, 0, FULL_CONTROL, ADMINS_SID), (0, 0, READ_EXECUTE, USER_SID)]))
        return pv.WindowsProtectionView(policy or pv.ProtectionPolicy(), security=security, token_sids=lambda: set(token))

    def test_windows_view_decides_from_owner_and_dacl_over_the_real_tree(self):
        path = str(self.target)
        clean = self.exposure(self.windows_view())
        self.assertEqual((clean["inspected"], clean["exposed"], clean["policy"]), (True, [], pv.WINDOWS_POLICY))
        self.assertEqual(clean["trusted"], sorted("sid:" + s for s in pv.BUILTIN_SIDS))
        cases = (("owner", {path: (USER_SID, [])}, "owner:" + USER_SID),
                 ("write", {path: (SYSTEM_SID, [(0, 0, 0x2, USER_SID)])}, "dacl_write:%s:0x2" % USER_SID),
                 ("null_dacl", {path: (SYSTEM_SID, None)}, "null_dacl"))
        for label, table, reason in cases:
            with self.subTest(label):
                self.assertEqual(self.exposure(self.windows_view(table))["exposed"], [self.entry(path, reason)])
        sibling_only = {str(self.tmp): (SYSTEM_SID, [(0, 0, 0x2, USER_SID)])}               # ancestor: may add files, not replace
        self.assertEqual(self.exposure(self.windows_view(sibling_only))["exposed"], [])
        replace = {str(self.tmp): (SYSTEM_SID, [(0, 0, 0x10000, USER_SID)])}
        self.assertEqual(self.exposure(self.windows_view(replace))["exposed"], [self.entry(self.tmp, "dacl_write:%s:0x10000" % USER_SID)])

    def test_windows_view_fails_closed_on_unreadable_security_unsupported_entries_and_evaluator_trust(self):
        path = str(self.target)
        denied = self.exposure(self.windows_view(fail={path: OSError(errno.EACCES, "security_query_failed")}))
        self.assertFalse(denied["inspected"])
        self.assertIn("security_query_failed", denied["exposed"][-1])
        unsupported = self.exposure(self.windows_view({path: (SYSTEM_SID, [(4, 0, 0, "")])}))
        self.assertFalse(unsupported["inspected"])
        self.assertIn("unsupported_ace_type:4", unsupported["exposed"][-1])
        self.assertRaisesCode("runtime_protection_policy_invalid", self.exposure,
                              self.windows_view(policy=pv.ProtectionPolicy.build(trusted_sids=[USER_SID])))
        extra = self.exposure(self.windows_view({path: (OTHER_SID, [])}, policy=pv.ProtectionPolicy.build(trusted_sids=[OTHER_SID])))
        self.assertEqual(extra["exposed"], [])
        self.assertIn("sid:" + OTHER_SID, extra["trusted"])

    def test_windows_acceptance_requires_a_non_administrative_evaluator_and_a_clean_dacl(self):
        path = str(self.target)
        marker = "evaluator [privileged_evaluator:sid:%s]" % ADMINS_SID
        privileged = self.exposure(self.windows_view(token=(ADMINS_SID, USER_SID)))
        self.assertEqual((privileged["inspected"], privileged["exposed"]), (True, [marker]))
        manifest = {"packages": [], "modules": [{"root": "r", "path": "vc/main.py"}]}
        parsed = {"r": str(self.closure)}
        refused = self.assertRaisesCode("runtime_evaluator_privileged", pv._protection_gate, self.pins, parsed, manifest, True,
                                        None, self.windows_view(token=(ADMINS_SID,)))
        self.assertEqual(refused.detail, "sid:" + ADMINS_SID)
        accepted = pv._protection_gate(self.pins, parsed, manifest, True, None, self.windows_view(token=(USER_SID,)))
        self.assertEqual((accepted["enforced"], accepted["inspected"], accepted["exposed"], accepted["policy"]),
                         (True, True, [], pv.WINDOWS_POLICY))
        dirty = self.windows_view({path: (SYSTEM_SID, [(0, 0, 0x2, USER_SID)])}, token=(USER_SID,))
        self.assertRaisesCode("runtime_writable_by_others", pv._protection_gate, self.pins, parsed, manifest, True, None, dirty)


@unittest.skipIf(WINDOWS, "the synthetic POSIX view needs POSIX stat semantics")
class RuntimeProtectionGate(ProtectionTree, unittest.TestCase):
    def gate_view(self, **kwargs):
        return lambda policy: SyntheticView(policy, **kwargs)

    def test_the_gate_runs_before_any_runtime_hash_interpreter_or_process(self):
        fx = Fixture(self).build()
        helper = str(fx.root / "vc/helper.py")
        accepted = fx.verify(work=str(fx.work), allow_unprotected_runtime=False, protection_view=SyntheticView())
        exposure = accepted.exposure
        self.assertEqual((exposure["inspected"], exposure["enforced"], exposure["exposed"], exposure["policy"], exposure["trusted"]),
                         (True, True, [], pv.POSIX_POLICY, ["uid:0"]))
        refusals = (("runtime_writable_by_others", SyntheticView(facts={helper: {"mode": 0o666}})),
                    ("runtime_writable_by_others", SyntheticView(facts={str(fx.root): {"uid": 1000}})),
                    ("runtime_writable_by_others", SyntheticView(acl={observation()["pins"]["executable_resolved"]})),
                    ("runtime_protection_not_inspectable", SyntheticView(unreadable={fx.root})))
        with mock.patch.object(pv, "authenticate_runtime", side_effect=AssertionError("runtime hashed first")), \
                mock.patch.object(pv, "probe_runtime", side_effect=AssertionError("interpreter probe started")), \
                mock.patch.object(pv.subprocess, "Popen", side_effect=AssertionError("process started")):
            for code, view in refusals:
                self.assertRaisesCode(code, fx.verify, work=str(fx.work), allow_unprotected_runtime=False, protection_view=view)
        recorded = fx.verify(work=str(fx.work), allow_unprotected_runtime=True,
                             protection_view=SyntheticView(facts={helper: {"mode": 0o666}})).exposure
        self.assertEqual((recorded["enforced"], recorded["exposed"]), (False, [self.entry(helper, "other_write")]))

    def test_run_verifier_reports_a_protected_pass_and_a_refusal_with_exact_receipt_evidence(self):
        fx = Fixture(self).build()
        helper = str(fx.root / "vc/helper.py")
        with mock.patch.object(pv, "default_protection_view", self.gate_view()):
            run = fx.run(allow_unprotected_runtime=False)
        self.assertEqual((run.status, run.reason), ("PASS", "ok"), run.receipt)
        protection = run.receipt["runtime_protection"]
        self.assertEqual((protection["inspected"], protection["enforced"], protection["exposed"], protection["policy"],
                          protection["trusted"]), (True, True, [], pv.POSIX_POLICY, ["uid:0"]))
        self.assertEqual(pv.verify_receipt(run.receipt, require_acceptance=False, expected_manifest_sha256=fx.digest,
                                           expected_release_sha256=fx.release), "PASS")
        with mock.patch.object(pv, "default_protection_view", self.gate_view(facts={helper: {"mode": 0o666}})):
            refused = fx.run(allow_unprotected_runtime=False)
        self.assertRejected(refused, "runtime_writable_by_others", "runtime")
        self.assertIsNone(refused.receipt["process"])
        self.assertIsNone(refused.receipt["verifier"])
        owned = {helper: {"uid": 1000}}
        with mock.patch.object(pv, "default_protection_view", self.gate_view(facts=owned)):
            self.assertRejected(fx.run(allow_unprotected_runtime=False), "runtime_writable_by_others", "runtime")
            trusting = fx.run(allow_unprotected_runtime=False, protection_policy=pv.ProtectionPolicy.build([1000]))
        self.assertEqual((trusting.status, trusting.receipt["runtime_protection"]["trusted"]), ("PASS", ["uid:0", "uid:1000"]))


# ---------------------------------------------------------------------------------------------------
# 4c. Native dependency parsing, the transitive pre-load plan, the mapped-file inventory and exact import positions.
# The bootstrap is executed here as a module namespace (never as ``__main__``): its parsing and planning functions are
# pure over bytes and files, so they are exercised directly; the in-child enforcement is covered by the subprocess tests.

def load_bootstrap():
    source = (REPO / "trace_gc/verifier_closure_bootstrap.py").read_text(encoding="utf-8")
    namespace = {"__name__": "pvc_bootstrap_under_test", "_PVC_STARTUP": [], "_PVC_BOOTSTRAP_SHA256": "0" * 64}
    exec(compile(source, "verifier_closure_bootstrap.py", "exec"), namespace)
    return namespace


def build_elf(needed=(), soname=None, extra=(), bits=64, order="little", strtab=True, load=True):
    """A minimal ELF image whose program and dynamic headers describe ``needed``/``soname`` (not loadable code)."""
    wide = bits == 64
    word, header_size, ph_size = (8, 64, 56) if wide else (4, 52, 32)
    strings, offsets = b"\0", {}
    for text in [*needed, *([soname] if soname else [])]:
        offsets[text] = len(strings)
        strings += text.encode() + b"\0"
    str_at = header_size + 2 * ph_size
    dyn_at = (str_at + len(strings) + 7) & ~7
    entries = [(1, offsets[name]) for name in needed] + ([(14, offsets[soname])] if soname else []) + list(extra)
    if strtab:
        entries.append((5, str_at))
    entries.append((0, 0))
    dynamic = b"".join(tag.to_bytes(word, order) + value.to_bytes(word, order) for tag, value in entries)
    total = dyn_at + len(dynamic)
    header = bytearray(header_size)
    header[0:4] = b"\x7fELF"
    header[4], header[5] = (2 if wide else 1), (1 if order == "little" else 2)
    count = 2 if load else 1
    if wide:
        header[32:40] = header_size.to_bytes(8, order)
        header[54:56], header[56:58] = ph_size.to_bytes(2, order), count.to_bytes(2, order)
    else:
        header[28:32] = header_size.to_bytes(4, order)
        header[42:44], header[44:46] = ph_size.to_bytes(2, order), count.to_bytes(2, order)

    def program_header(kind, offset, size):
        def number(value, width):
            return value.to_bytes(width, order)
        if wide:
            return number(kind, 4) + number(0, 4) + number(offset, 8) + number(offset, 8) + number(offset, 8) + number(size, 8) + \
                number(size, 8) + number(8, 8)
        return number(kind, 4) + number(offset, 4) + number(offset, 4) + number(offset, 4) + number(size, 4) + number(size, 4) + \
            number(0, 4) + number(8, 4)
    headers = (program_header(1, 0, total) if load else b"") + program_header(2, dyn_at, len(dynamic))
    image = bytes(header) + headers
    image = image.ljust(str_at, b"\0") + strings
    return image.ljust(dyn_at, b"\0") + dynamic


def build_pe(imports=(), plus=True, delay=False):
    """A minimal PE image with one section holding an import directory for ``imports``."""
    optional_size = 240 if plus else 224
    count_at, directories = (108, 112) if plus else (92, 96)
    optional = bytearray(optional_size)
    optional[0:2] = (0x20B if plus else 0x10B).to_bytes(2, "little")
    optional[count_at:count_at + 4] = (16).to_bytes(4, "little")
    base_rva, data_at = 0x1000, 0x200
    names, rvas = b"", []
    for name in imports:
        rvas.append(base_rva + 20 * (len(imports) + 1) + len(names))
        names += name.encode() + b"\0"
    table = b"".join(b"\0" * 12 + rva.to_bytes(4, "little") + b"\0" * 4 for rva in rvas) + b"\0" * 20 + names
    if imports:
        optional[directories + 8:directories + 12] = base_rva.to_bytes(4, "little")
    if delay:
        optional[directories + 8 * 13:directories + 8 * 13 + 4] = base_rva.to_bytes(4, "little")
    dos = bytearray(64)
    dos[0:2], dos[0x3C:0x40] = b"MZ", (64).to_bytes(4, "little")
    coff = b"PE\0\0" + b"\x64\x86" + (1).to_bytes(2, "little") + b"\0" * 12 + optional_size.to_bytes(2, "little") + b"\0\0"
    section = b".idata\0\0" + len(table).to_bytes(4, "little") + base_rva.to_bytes(4, "little") + \
        len(table).to_bytes(4, "little") + data_at.to_bytes(4, "little") + b"\0" * 12
    return (bytes(dos) + coff + bytes(optional) + section).ljust(data_at, b"\0") + table


class NativeParsingAndPlanning(unittest.TestCase):
    def setUp(self):
        self.ns = load_bootstrap()
        self.tmp = Path(tempfile.mkdtemp(prefix="pvc-native-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def violations(self):
        return list(self.ns["_REPORT"]["violations"])

    def source(self, data):
        return self.ns["_BytesSource"](data)

    def test_elf_dynamic_reads_needed_soname_and_unsupported_entries_for_every_layout(self):
        for bits in (64, 32):
            for order in ("little", "big"):
                with self.subTest(bits=bits, order=order):
                    image = build_elf(["libb.so.1", "libc.so.6"], "liba.so.1", bits=bits, order=order)
                    self.assertEqual(self.ns["_elf_dynamic"](self.source(image)), (["libb.so.1", "libc.so.6"], "liba.so.1", []))
                    self.assertEqual(self.ns["_elf_dynamic"](self.source(build_elf([], None, bits=bits, order=order))), ([], None, []))
        tags = {15: "rpath", 29: "runpath", 0x7FFFFFFD: "filter", 0x7FFFFFFE: "auxiliary", 0x6FFFFEFC: "audit", 0x6FFFFEFB: "depaudit"}
        for tag, kind in tags.items():
            with self.subTest(kind):
                needed, soname, unsupported = self.ns["_elf_dynamic"](self.source(build_elf(["libb.so.1"], extra=[(tag, 1)])))
                self.assertEqual((needed, soname, unsupported), (["libb.so.1"], None, [kind]))

    def test_malformed_elf_images_are_refused_never_partially_read(self):
        good = build_elf(["libb.so.1", "libc.so.6"], "liba.so.1")
        bad_class = bytearray(good)
        bad_class[4] = 3
        cases = {"not_elf": b"MZ" + good[2:], "elf_class": bytes(bad_class), "elf_no_dynamic": build_elf(["x"])[:64] + b"\0" * 112,
                 "elf_no_strtab": build_elf(["libb.so.1"], strtab=False), "elf_unmapped_strtab": build_elf(["libb.so.1"], load=False),
                 "string_offset": build_elf([], extra=[(1, 10 ** 6)])}
        for expected, image in cases.items():
            with self.subTest(expected):
                with self.assertRaises(ValueError) as caught:
                    self.ns["_elf_dynamic"](self.source(image))
                self.assertEqual(str(caught.exception), expected)
        for cut in (3, 40, 70, len(good) - 9, len(good) - 1):
            with self.subTest(cut=cut):
                with self.assertRaises((ValueError, IndexError, OverflowError)):
                    self.ns["_elf_dynamic"](self.source(good[:cut]))

    def test_pe_imports_are_listed_lower_cased_and_delay_load_or_damage_is_refused(self):
        for plus in (True, False):
            with self.subTest(plus=plus):
                image = build_pe(["KERNEL32.dll", "VCRUNTIME140.dll", "python3.dll"], plus=plus)
                self.assertEqual(self.ns["_pe_imports"](self.source(image)), (["kernel32.dll", "vcruntime140.dll", "python3.dll"], []))
                self.assertEqual(self.ns["_pe_imports"](self.source(build_pe([], plus=plus))), ([], []))
        self.assertEqual(self.ns["_pe_imports"](self.source(build_pe(["a.dll"], delay=True))), (["a.dll"], ["delay_load"]))
        good = bytearray(build_pe(["a.dll"]))
        unmapped = bytearray(good)
        unmapped[0x200 + 12:0x200 + 16] = (0x9000).to_bytes(4, "little")
        bad_magic = bytearray(good)
        bad_magic[64 + 24:64 + 26] = (0x1234).to_bytes(2, "little")
        bad_signature = bytearray(good)
        bad_signature[64:68] = b"XX\0\0"
        for expected, image in {"pe_unmapped_rva": unmapped, "pe_magic": bad_magic, "pe_signature": bad_signature,
                                "not_pe": bytearray(b"ZZ" + bytes(good[2:]))}.items():
            with self.subTest(expected):
                with self.assertRaises(ValueError) as caught:
                    self.ns["_pe_imports"](self.source(bytes(image)))
                self.assertEqual(str(caught.exception), expected)
        for cut in (1, 70, 300, 0x205):
            with self.subTest(cut=cut):
                with self.assertRaises((ValueError, IndexError, OverflowError)):
                    self.ns["_pe_imports"](self.source(bytes(good[:cut])))

    @unittest.skipUnless(sys.platform.startswith("linux"), "ELF dependency lists are the Linux path")
    def test_native_needed_refuses_unparsable_unsupported_and_path_named_dependencies(self):
        needed = self.ns["_native_needed"]
        state = self.ns["_STATE"]
        state["strict"] = True
        self.assertEqual(needed("ext", build_elf(["liba.so.1"])), ["liba.so.1"])                       # a plain NEEDED list is accepted
        cases = (("native_closure_unparsable:ext", b"not an elf"),
                 ("native_dependency_unsupported:ext:rpath", build_elf(["liba.so.1"], extra=[(15, 1)])),
                 ("native_dependency_unsupported:ext:runpath", build_elf(["liba.so.1"], extra=[(29, 1)])),
                 ("native_dependency_unsupported:ext:audit", build_elf(["liba.so.1"], extra=[(0x6FFFFEFC, 1)])),
                 ("native_dependency_unsupported:ext:filter", build_elf(["liba.so.1"], extra=[(0x7FFFFFFD, 1)])),
                 ("native_dependency_unsupported:ext:path", build_elf(["dir/liba.so.1"])))
        for violation, image in cases:
            with self.subTest(violation):
                self.ns["_REPORT"]["violations"].clear()
                with self.assertRaises(ImportError):
                    needed("ext", image)
                self.assertEqual(self.violations(), [violation])
        state["strict"] = False                                                                           # discovery refuses RPATH/RUNPATH too
        for tag, value in (("rpath", 15), ("runpath", 29)):
            with self.subTest(tag):
                self.ns["_REPORT"]["violations"].clear()
                with self.assertRaises(ImportError):
                    needed("ext", build_elf(["liba.so.1"], extra=[(value, 1)]))
                self.assertEqual(self.violations(), ["native_dependency_unsupported:ext:" + tag])

    def lib(self, name, needed=(), soname=None, directory=None):
        """A pinned ELF stub.  ``soname=None`` gives it ``DT_SONAME == name`` (what real libraries carry); ``""`` omits it."""
        path = (directory or self.tmp) / name
        path.parent.mkdir(parents=True, exist_ok=True)
        data = build_elf(needed, name if soname is None else soname)
        path.write_bytes(data)
        return str(path), sha(data)

    def plan(self, needed, libs, satisfied=("libc.so.6",), strict=True):
        self.ns["_REPORT"]["violations"].clear()
        pins, index = self.ns["_native_index"](libs)
        self.ns["_STATE"].update(strict=strict, satisfied=set(satisfied), native_pins=pins, native_index=index)
        return self.ns["_native_plan"]("ext", needed)

    @unittest.skipUnless(sys.platform.startswith("linux"), "ELF dependency lists are the Linux path")
    def test_the_transitive_plan_loads_dependencies_before_dependents_from_hashed_bytes(self):
        liba = self.lib("liba.so.1", ["libb.so.1", "libc.so.6"])
        libb = self.lib("libb.so.1", ["libc.so.6"])
        plan = self.plan(["liba.so.1"], [liba, libb])
        self.assertEqual([(os.path.basename(path), digest) for path, digest, _, _ in plan],
                         [("libb.so.1", libb[1]), ("liba.so.1", liba[1])])
        self.assertTrue(all(sha(data) == digest for _, digest, data, _ in plan))
        self.assertEqual(self.violations(), [])
        self.assertEqual(self.plan(["libc.so.6"], [liba, libb]), [])                                  # already mapped: nothing to load
        diamond_top = self.lib("libtop.so.1", ["libb.so.1", "liba.so.1"])
        order = [os.path.basename(p) for p, *_ in self.plan(["libtop.so.1"], [liba, libb, diamond_top])]
        self.assertEqual(order, ["libb.so.1", "liba.so.1", "libtop.so.1"])                            # shared dependency planned once
        self.assertEqual(self.plan(["liba.so.1"], [liba, libb], strict=False), [])                    # discovery plans nothing

    @unittest.skipUnless(sys.platform.startswith("linux"), "ELF dependency lists are the Linux path")
    def test_a_dependency_is_resolved_by_soname_and_refused_when_unpinned_ambiguous_cyclic_or_changed(self):
        aliased = self.lib("alias.bin", [], "libreal.so.1")
        self.assertEqual([os.path.basename(p) for p, *_ in self.plan(["libreal.so.1"], [aliased])], ["alias.bin"])
        liba = self.lib("liba.so.1", ["libb.so.1"])
        libb = self.lib("libb.so.1")
        duplicate = [self.lib("libdup.so.1", directory=self.tmp / "one"), self.lib("libdup.so.1", directory=self.tmp / "two")]
        libx, liby = self.lib("libx.so", ["liby.so"]), self.lib("liby.so", ["libx.so"])
        nameless = self.lib("libnameless.so.1", soname="", directory=self.tmp / "n")
        cases = (("native_dependency_unpinned:ext:libmissing.so", ["libmissing.so"], [liba, libb]),
                 ("native_dependency_unpinned:ext:libnameless.so.1", ["libnameless.so.1"], [nameless]),   # basename alone never matches
                 ("native_dependency_ambiguous:ext:libdup.so.1", ["libdup.so.1"], duplicate),
                 ("native_dependency_cycle:liby.so:libx.so", ["libx.so"], [libx, liby]),
                 ("runtime_file_changed:liba.so.1", ["liba.so.1"], [(liba[0], "0" * 64), libb]))
        for violation, needed, libs in cases:
            with self.subTest(violation):
                with self.assertRaises(ImportError):
                    self.plan(needed, libs)
                self.assertEqual(self.violations(), [violation])

    @unittest.skipUnless(sys.platform.startswith("linux"), "ELF dependency lists are the Linux path")
    def test_the_plan_size_and_depth_are_bounded(self):
        chain = [self.lib("lib%d.so" % n, ["lib%d.so" % (n + 1)] if n < 20 else []) for n in range(21)]
        with self.assertRaises(ImportError):
            self.plan(["lib0.so"], chain)
        self.assertTrue(all(v.startswith("native_dependency_plan_too_large:") for v in self.violations()), self.violations())
        self.assertEqual(len(self.violations()), 1)
        short = [self.lib("lib%d.so" % n, ["lib%d.so" % (n + 1)] if n < 4 else [], directory=self.tmp / "s") for n in range(5)]
        self.assertEqual(len(self.plan(["lib0.so"], short)), 5)                                       # a short chain is a working positive
        with mock.patch.dict(self.ns, {"MAX_NATIVE_PLAN": 2}):
            wide = [self.lib("w%d.so" % n, directory=self.tmp / "w") for n in range(4)]
            top = self.lib("wtop.so", ["w%d.so" % n for n in range(4)], directory=self.tmp / "w")
            with self.assertRaises(ImportError):
                self.plan(["wtop.so"], [*wide, top])
        self.assertTrue(self.violations()[0].startswith("native_dependency_plan_too_large:"))

    def test_loader_names_are_sonames_on_linux_and_lower_cased_file_names_on_windows(self):
        names = self.ns["_names_of"]
        with mock.patch.dict(self.ns, {"sys": types.SimpleNamespace(platform="linux")}):
            self.assertEqual(names("/proc/self/fd/9", "libz.so.1"), {"libz.so.1"})      # a staged object is matched by DT_SONAME only
            self.assertEqual(names("/lib/libz.so.1", None), set())                        # no DT_SONAME: no name, never the basename
        with mock.patch.dict(self.ns, {"sys": types.SimpleNamespace(platform="win32")}):
            self.assertEqual(names("/py/VCRUNTIME140.dll", None), {"vcruntime140.dll"})

    @unittest.skipUnless(sys.platform.startswith("linux") and hasattr(os, "memfd_create"), "memfd identities are the Linux path")
    def test_memfd_identity_keys_follow_proc_maps_and_ignore_other_memfd_mappings(self):
        fd = os.memfd_create("pvc-ext")
        self.addCleanup(os.close, fd)
        key = self.ns["_memfd_key"](fd)
        device, inode = key.split(" ")
        self.assertRegex(device, r"^[0-9a-f]{2,}:[0-9a-f]{2,}$")
        self.assertEqual(int(inode), os.fstat(fd).st_ino)
        maps = ("7f0000000000-7f0000021000 rw-s 00000000 %s %s /memfd:pvc-ext (deleted)\n"
                "7f0000100000-7f0000200000 rw-s 00000000 00:01 77 /memfd:pvc-dep (deleted)\n"
                "7f0000300000-7f0000400000 rw-s 00000000 00:01 88 /memfd:libffi (deleted)\n"
                "7f0000500000-7f0000600000 r-xp 00000000 08:01 99 /usr/lib/libc.so.6\n") % (device, inode)
        with mock.patch.dict(self.ns, {"_read_path": lambda path, limit: maps.encode()}):
            self.assertEqual(self.ns["_mapped_memfds"](), {key, "00:01 77"})

        def unreadable(path, limit):
            raise OSError("no /proc")
        with mock.patch.dict(self.ns, {"_read_path": unreadable}):
            self.assertIsNone(self.ns["_mapped_memfds"]())

    @unittest.skipUnless(sys.platform.startswith("linux") and hasattr(os, "memfd_create"), "memfd identities are the Linux path")
    def test_retained_backing_objects_are_unique_and_a_load_must_map_exactly_that_object(self):
        loader = self.ns["_NativeLoader"]()
        first, second = os.memfd_create("pvc-ext"), os.memfd_create("pvc-dep")
        alias = os.dup(first)
        for fd in (first, second, alias):
            self.addCleanup(os.close, fd)
        self.assertEqual(loader.retain(first, "a"), first)
        self.assertEqual(loader.retain(second, "b"), second)
        self.assertEqual(self.violations(), [])
        for duplicate in (first, alias):                       # the same descriptor, and a second descriptor of the same object
            with self.subTest(fd=duplicate):
                self.ns["_REPORT"]["violations"].clear()
                with self.assertRaises(ImportError):
                    loader.retain(duplicate, "c")
                self.assertEqual(self.violations(), ["native_identity_duplicate:c"])
        key = self.ns["_memfd_key"](first)
        with mock.patch.dict(self.ns, {"_mapped_memfds": lambda: {key}}):
            loader.confirm(first, "a")
            self.assertEqual(self.violations(), ["native_identity_duplicate:c"])
            self.ns["_REPORT"]["violations"].clear()
            with self.assertRaises(ImportError):               # the maps show a different memfd than the one just opened
                loader.confirm(second, "b")
            self.assertEqual(self.violations(), ["native_identity_unconfirmed:b"])
        for mapped in (None, set()):
            with self.subTest(mapped=mapped), mock.patch.dict(self.ns, {"_mapped_memfds": lambda mapped=mapped: mapped}):
                self.ns["_REPORT"]["violations"].clear()
                with self.assertRaises(ImportError):
                    loader.confirm(first, "a")
                self.assertEqual(self.violations(), ["native_identity_unconfirmed:a"])

        def unreadable(fd):
            raise OSError("closed")
        self.ns["_REPORT"]["violations"].clear()
        with mock.patch.dict(self.ns, {"_memfd_key": unreadable}), self.assertRaises(ImportError):
            loader.retain(first, "d")
        self.assertEqual(self.violations(), ["native_identity_unreadable:d"])

    @unittest.skipUnless(sys.platform.startswith("linux") and hasattr(os, "memfd_create"), "memfd staging is the Linux path")
    def test_staging_loads_dependencies_from_retained_verified_bytes_before_the_extension_and_refuses_before_any_dependent_load(self):
        events = []

        def recorder(fail=None):
            def dlopen(path, flags):
                fd = int(path.rsplit("/", 1)[1])
                events.append(("dlopen", os.readlink("/proc/self/fd/%d" % fd).startswith("/memfd:pvc-"), tuple(sorted(self.ns["_STATE"]["satisfied"]))))
                if fail is not None and len(events) == fail:
                    raise OSError("load refused")
                mapped.add(self.ns["_memfd_key"](fd))
            return dlopen
        liba = self.lib("libdep.so.1", ["libc.so.6"], directory=self.tmp / "deps")
        extension_data = build_elf(["libdep.so.1", "libc.so.6"])
        extension = self.tmp / "ext.so"
        extension.write_bytes(extension_data)
        row = ("ext", "ext", str(extension), sha(extension_data), False)

        def stage(fail=None, forget=False):
            mapped.clear()
            events.clear()
            self.ns["_REPORT"]["violations"].clear()
            loader = self.ns["_NATIVE"] = self.ns["_NativeLoader"]()
            loaders.append(loader)
            pins, index = self.ns["_native_index"]([liba])
            self.ns["_STATE"].update(strict=True, satisfied={"libc.so.6"}, native_pins=pins, native_index=index, table={"ext": row})
            self.ns["_STATE"]["native_paths"].clear()
            patch = {"_dlopen": recorder(fail), "_mapped_memfds": (lambda: set()) if forget else (lambda: set(mapped))}
            with mock.patch.dict(self.ns, patch):
                return loader, loader.stage("ext")
        mapped, loaders = set(), []
        self.addCleanup(lambda: [os.close(held) for each in loaders for held in each.retained.values()])
        loader, (fd, path) = stage()
        self.assertEqual(path, "/proc/self/fd/%d" % fd)
        self.assertEqual([(kind, memfd) for kind, memfd, _ in events], [("dlopen", True), ("dlopen", True)])
        self.assertNotIn("libdep.so.1", events[0][2])                    # the dependency is loaded while the name is still unresolved
        self.assertIn("libdep.so.1", events[1][2])                       # the extension loads only after its name resolves to the loaded object
        self.assertEqual(loader.plan, [[liba[0], liba[1]]])
        self.assertEqual(len(loader.retained), 2)
        self.assertIn(path, self.ns["_STATE"]["native_paths"])
        self.assertEqual(self.violations(), [])
        for fail, expected, loads in ((1, "native_preload_failed:libdep.so.1", 1), (2, "native_preload_failed:ext", 2)):
            with self.subTest(expected):
                with self.assertRaises(ImportError):
                    stage(fail=fail)
                self.assertEqual(self.violations(), [expected])
                self.assertEqual(len(events), loads)                   # a failed dependency load stops everything after it
        with self.assertRaises(ImportError):
            stage(forget=True)                                          # loaded, but no mapping of the retained dependency object
        self.assertEqual(self.violations(), ["native_identity_unconfirmed:libdep.so.1"])
        self.assertEqual(len(events), 1)

    @unittest.skipUnless(sys.platform.startswith("linux") and hasattr(os, "memfd_create"), "memfd staging is the Linux path")
    def test_a_pinned_dependency_without_a_soname_is_refused_before_it_is_loaded(self):
        nameless = self.lib("libnameless.so.1", soname="")
        calls = []
        self.ns["_STATE"].update(satisfied=set())
        with mock.patch.dict(self.ns, {"_dlopen": lambda path, flags: calls.append(path)}):
            with self.assertRaises(ImportError):
                self.ns["_preload_native"](nameless[0], nameless[1], Path(nameless[0]).read_bytes(), nameless[0])
        self.assertEqual(self.violations(), ["native_dependency_unnamed:libnameless.so.1"])
        self.assertEqual((calls, self.ns["_NATIVE"].retained, self.ns["_NATIVE"].plan), ([], {}, []))

    def test_windows_api_set_imports_resolve_through_the_loaders_own_host_or_are_refused_before_loading(self):
        import ctypes
        host = self.tmp / "ucrtbase.dll"
        host.write_bytes(build_pe(["kernel32.dll"]))
        other = self.tmp / "elsewhere.dll"
        other.write_bytes(build_pe([]))
        dep_data = build_pe(["kernel32.dll"])
        dep = self.tmp / "dep.dll"
        dep.write_bytes(dep_data)

        class Kernel:
            def __init__(self, hosts):
                self.hosts = hosts

            def GetModuleHandleW(self, name):
                return self.hosts.get(name, (0, ""))[0]

            def GetCurrentProcess(self):
                return 1

            def K32GetModuleFileNameExW(self, process, module, buffer, length):
                for handle, path in self.hosts.values():
                    if handle == module and path:
                        buffer.value = path
                        return len(path)
                return 0
        api = "api-ms-win-crt-runtime-l1-1-0.dll"
        array = ctypes.c_wchar * 32768                                         # what the bootstrap builds before the audit hook is armed
        patched = {"ctypes": ctypes, "sys": types.SimpleNamespace(platform="win32"), "_APISET_PATH": array}
        with mock.patch.dict(self.ns, {"ctypes": ctypes, "_APISET_PATH": array,
                                       "_K32": Kernel({api: (7, "\\\\?\\" + str(host))})}):
            self.assertEqual(self.ns["_apiset_host"](api), os.path.normcase(os.path.realpath(str(host))))
            self.assertIsNone(self.ns["_apiset_host"]("api-ms-win-core-missing-l1-1-0.dll"))
        with mock.patch.dict(self.ns, {"ctypes": ctypes, "_APISET_PATH": array, "_K32": Kernel({api: (7, "")})}):
            self.assertIsNone(self.ns["_apiset_host"](api))                  # the host's file name cannot be read: unresolved
        with mock.patch.dict(self.ns, {"ctypes": ctypes, "_APISET_PATH": array, "_K32": None}):
            self.assertIsNone(self.ns["_apiset_host"](api))

        def denied_open(path):
            return os.open(path, os.O_RDONLY)

        def plan(needed, kernel):
            self.ns["_REPORT"]["violations"].clear()
            with mock.patch.dict(self.ns, {**patched, "_K32": kernel, "_open_write_denied": denied_open}):
                libs = [(str(host), sha(host.read_bytes())), (str(dep), sha(dep_data))]
                pins, index = self.ns["_native_index"](libs)
                self.ns["_STATE"].update(strict=True, satisfied={"kernel32.dll"}, native_pins=pins, native_index=index)
                try:
                    return self.ns["_native_plan"]("ext", needed)
                finally:
                    for descriptor in self.ns["_NATIVE"].locks:
                        os.close(descriptor)
                    self.ns["_NATIVE"].locks.clear()
        hosted = Kernel({api: (7, str(host))})
        self.assertEqual(plan([api], hosted), [])                                           # hosted by a loaded pinned native: nothing to load
        self.assertEqual(self.violations(), [])
        self.assertEqual([os.path.basename(p) for p, *_ in plan(["dep.dll"], hosted)], ["dep.dll"])
        for label, kernel in (("not resolved", Kernel({})), ("hosted outside the pins", Kernel({api: (7, str(other))}))):
            with self.subTest(label):
                with self.assertRaises(ImportError):
                    plan([api], kernel)
                self.assertEqual(self.violations(), ["native_apiset_unresolved:ext:" + api])

    def test_the_mapped_file_inventory_is_complete_or_unavailable_never_partial(self):
        maps = ("00400000-00452000 r-xp 00000000 08:01 1 /usr/bin/python3\n"
                "7f0000000000-7f0000021000 rw-p 00000000 00:00 0 \n"
                "7f0000100000-7f0000200000 r--p 00000000 08:01 2 /usr/lib/libc.so.6\n"
                "7f0000300000-7f0000400000 r-xp 00000000 08:01 2 /usr/lib/libc.so.6\n"
                "7f0000500000-7f0000600000 rw-s 00000000 00:01 3 /memfd:pvc-ext (deleted)\n"
                "7ffd00000000-7ffd00021000 rw-p 00000000 00:00 0 [stack]\n")
        namespace = self.ns
        with mock.patch.dict(namespace, {"sys": types.SimpleNamespace(platform="linux"), "_read_path": lambda path, limit: maps.encode()}):
            self.assertEqual(namespace["_mapped_files"](), ["/memfd:pvc-ext (deleted)", "/usr/bin/python3", "/usr/lib/libc.so.6"])

        def unreadable(path, limit):
            raise OSError("no /proc")
        with mock.patch.dict(namespace, {"sys": types.SimpleNamespace(platform="linux"), "_read_path": unreadable}):
            self.assertIsNone(namespace["_mapped_files"]())
        with mock.patch.dict(namespace, {"sys": types.SimpleNamespace(platform="freebsd")}):
            self.assertIsNone(namespace["_mapped_files"]())                                              # no inventory: refusal, not []

    def test_windows_module_enumeration_is_all_or_nothing(self):
        import ctypes
        from ctypes import wintypes
        size = ctypes.sizeof(wintypes.HMODULE)

        class Kernel:
            def __init__(self, names, fail_name=None, fail_enum=False, announce=None, always_grow=False):
                self.names, self.fail_name, self.fail_enum, self.announce = names, fail_name, fail_enum, announce
                self.always_grow = always_grow
                self.calls = 0
                self.paths = {}

            def GetCurrentProcess(self):
                return 1

            def K32EnumProcessModules(self, process, array, length, needed):
                self.calls += 1
                if self.fail_enum:
                    return 0
                total = self.announce if self.announce else len(self.names)
                if self.always_grow:
                    total = length // size + 100
                needed._obj.value = total * size
                if total * size <= length:
                    for index in range(len(self.names)):
                        array[index] = index + 1
                        self.paths[index + 1] = self.names[index]
                return 1

            def K32GetModuleFileNameExW(self, process, module, buffer, length):
                if self.paths[module] == self.fail_name:
                    return 0
                buffer.value = self.paths[module]
                return len(self.paths[module])

        namespace = self.ns
        names = ["\\\\?\\C:\\py\\python313.dll", "C:\\py\\python.exe", "C:\\Windows\\System32\\kernel32.dll"]

        def run(kernel):
            with mock.patch.dict(namespace, {"_K32": kernel, "ctypes": ctypes, "_wt": wintypes}):
                return namespace["_windows_modules"]()
        self.assertEqual(run(Kernel(names)), sorted(["C:\\py\\python313.dll", "C:\\py\\python.exe", "C:\\Windows\\System32\\kernel32.dll"]))
        self.assertIsNone(run(Kernel(names, fail_name="C:\\py\\python.exe")))                           # one unresolved name: no partial list
        self.assertIsNone(run(Kernel(names, fail_enum=True)))
        grown = Kernel(["C:\\m%d.dll" % n for n in range(1500)], announce=1500)
        self.assertEqual(len(run(grown) or []), 1500)
        self.assertEqual(grown.calls, 2)                                                                 # buffer grown, then complete
        self.assertIsNone(run(Kernel(names, always_grow=True)))                                         # never converges: unavailable
        self.assertIsNone(run(None))                                                                     # no kernel binding at all


# A fresh interpreter executes the real bootstrap as a namespace, arms ITS audit policy (``_audit``, the function main()
# installs) and performs allocation and calls from boot frames and from a non-boot frame.  A recording hook installed
# first sees every ``ctypes.*`` event the interpreter really raises, so nothing here is modeled.
ARMED_AUDIT_DRIVER = r'''
import ctypes, json, sys
events = []
sys.addaudithook(lambda event, args: events.append(event) if event.startswith("ctypes.") else None)
namespace = {"__name__": "pvc_armed_under_test", "_PVC_STARTUP": [], "_PVC_BOOTSTRAP_SHA256": "0" * 64}
exec(compile(open(sys.argv[1], encoding="utf-8").read(), "verifier_closure_bootstrap.py", "exec"), namespace)
windows = sys.platform == "win32"
library = ctypes.WinDLL("kernel32") if windows else ctypes.CDLL(None)
call = library.GetCurrentProcess if windows else library.getpid
array = ctypes.c_wchar * 32768
exec("def _boot_call(function):\n    return function()\n", namespace)
state = namespace["_STATE"]
state["meta"] = list(sys.meta_path)
state["armed"] = True
sys.addaudithook(namespace["_audit"])
report = {}
mark = len(events)
buffer = array()
buffer.value = "abc"
report["array_events"], report["array_value"] = list(events[mark:]), buffer.value
report["boot_call_returned"] = namespace["_boot_call"](call) is not None


def attempt(label, function):
    try:
        function()
        report[label] = "allowed"
    except RuntimeError as exc:
        report[label] = str(exc)


attempt("dependency_function_pointer", call)
attempt("dependency_buffer_helper", lambda: ctypes.create_unicode_buffer(8))
attempt("dependency_array", lambda: array())
report["violations"] = list(namespace["_REPORT"]["violations"])
state["armed"] = False
print(json.dumps(report))
'''

# Windows only: the REAL trusted resolver (the bootstrap's own prebuilt kernel32 binding) under the armed audit policy.
WINDOWS_RESOLVER_DRIVER = r'''
import hashlib, json, sys
events = []
sys.addaudithook(lambda event, args: events.append(event) if event.startswith("ctypes.") else None)
namespace = {"__name__": "pvc_armed_under_test", "_PVC_STARTUP": [], "_PVC_BOOTSTRAP_SHA256": "0" * 64}
exec(compile(open(sys.argv[1], encoding="utf-8").read(), "verifier_closure_bootstrap.py", "exec"), namespace)
real, missing = sys.argv[2], sys.argv[3]
state, report = namespace["_STATE"], {}
host = namespace["_apiset_host"](real)                                           # unarmed: only to learn the host for the pins
pins, index = namespace["_native_index"]([(host, hashlib.sha256(open(host, "rb").read()).hexdigest())]) if host else ({}, {})
state["meta"] = list(sys.meta_path)
state["armed"] = True
sys.addaudithook(namespace["_audit"])
mark = len(events)
report["resolved"] = namespace["_apiset_host"](real)
report["unresolved"] = namespace["_apiset_host"](missing)
report["resolver_events"] = sorted(set(events[mark:]))
state.update(strict=True, satisfied=set(), native_pins=pins, native_index=index)


def plan(names):
    try:
        return namespace["_native_plan"]("ext", names)
    except ImportError as exc:
        return "ImportError"


report["plan_hosted"] = plan([real])
report["violations_after_hosted"] = list(namespace["_REPORT"]["violations"])
report["plan_unresolved"] = plan([missing])
state.update(native_pins={}, native_index={})
report["plan_unpinned_host"] = plan([real])
report["violations"] = list(namespace["_REPORT"]["violations"])
state["armed"] = False
report["host"] = host
print(json.dumps(report))
'''


BOOTSTRAP_FILE = REPO / "trace_gc" / "verifier_closure_bootstrap.py"


def run_armed_driver(test, driver, *arguments):
    """Run ``driver`` in a fresh isolated interpreter against the real bootstrap file; its last stdout line is JSON."""
    done = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", driver, str(BOOTSTRAP_FILE), *arguments],
                          capture_output=True, text=True, timeout=300, cwd=tempfile.gettempdir())
    test.assertEqual(done.returncode, 0, done.stdout + done.stderr)
    return json.loads(done.stdout.strip().splitlines()[-1])


class ArmedCtypesAuditPolicy(unittest.TestCase):
    """The trusted resolver allocates its output buffer without any ctypes event, and no dependency gains a ctypes waiver."""

    BOOTSTRAP = BOOTSTRAP_FILE

    def drive(self, driver, *arguments):
        return run_armed_driver(self, driver, *arguments)

    def test_the_resolver_source_issues_no_ctypes_helper_call_and_its_buffer_type_is_built_before_arming(self):
        import ast
        tree = ast.parse(self.BOOTSTRAP.read_text(encoding="utf-8"))
        resolver = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_apiset_host")
        helpers = {"create_unicode_buffer", "create_string_buffer", "cast", "addressof", "byref", "string_at", "wstring_at",
                   "WinDLL", "CDLL", "POINTER", "sizeof"}
        called = {c.func.attr for c in ast.walk(resolver) if isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute)}
        called |= {c.func.id for c in ast.walk(resolver) if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)}
        self.assertFalse(called & helpers, called & helpers)
        self.assertTrue({"GetModuleHandleW", "GetCurrentProcess", "K32GetModuleFileNameExW"} <= called, called)
        source = self.BOOTSTRAP.read_text(encoding="utf-8")
        built = source.index("_APISET_PATH = ctypes.c_wchar * 32768")
        self.assertLess(built, source.index("_BOOT_GLOBALS = globals()"))          # before the audit hook can exist
        self.assertLess(built, source.index("sys.addaudithook(_audit)"))

    def test_array_allocation_raises_no_ctypes_event_while_the_helper_and_a_dependency_call_are_refused(self):
        report = self.drive(ARMED_AUDIT_DRIVER)
        self.assertEqual(report["array_events"], [])                              # the premise of the fix, observed, not assumed
        self.assertEqual(report["array_value"], "abc")
        self.assertTrue(report["boot_call_returned"])                             # the boot frame's foreign call is permitted ...
        self.assertEqual(report["dependency_function_pointer"], "audit refused: ctypes.call_function")   # ... the same call elsewhere is not
        self.assertEqual(report["dependency_buffer_helper"], "audit refused: ctypes.create_unicode_buffer")
        self.assertEqual(report["dependency_array"], "allowed")                   # allocation grants no capability
        self.assertEqual(report["violations"], ["denied_event:ctypes.call_function", "denied_event:ctypes.create_unicode_buffer"])

    def test_the_audit_policy_still_denies_every_other_ctypes_event_to_boot_frames_as_well(self):
        source = self.BOOTSTRAP.read_text(encoding="utf-8")
        audit = source[source.index("def _audit(event, args):"):source.index("# ---", source.index("def _audit(event, args):"))]
        self.assertEqual(audit.count('startswith(("ctypes.call_function", "ctypes.dlopen"))'), 1)   # the one narrow allowance
        self.assertNotIn("create_unicode_buffer", audit)                           # and no allowance was added for the buffer helper
        self.assertNotIn("ctypes.dlsym", audit)


class WindowsArmedNativePath(unittest.TestCase):
    """The supported Windows native path with REAL processes, the real kernel32 binding and the armed audit policy.

    There is no class-level platform skip: ``setUpClass`` asks ``windows_protected_gate``, so a host without native Windows
    is a skip only while ``PVC_REQUIRE_WINDOWS_PROTECTED`` is unset and a failure when it is set."""

    API_SET = "api-ms-win-crt-runtime-l1-1-0.dll"
    MISSING = "api-ms-win-core-nonexistent-fixture-l1-1-0.dll"
    EXTENSION_CANDIDATES = ("unicodedata", "_socket", "select", "_hashlib", "_bz2", "_lzma")

    @classmethod
    def setUpClass(cls):
        decision, reason = windows_protected_gate(os.environ, WINDOWS, True, [])
        if decision == "skip":
            raise unittest.SkipTest(reason)
        if decision == "fail":
            raise AssertionError(reason)

    def test_the_real_resolver_resolves_a_real_api_set_to_its_loaded_host_under_the_armed_policy(self):
        report = run_armed_driver(self, WINDOWS_RESOLVER_DRIVER, self.API_SET, self.MISSING)
        self.assertEqual(os.path.basename(report["resolved"]).lower(), "ucrtbase.dll", report)
        self.assertIsNone(report["unresolved"])                                   # the unresolved-host negative, armed
        self.assertEqual(report["resolver_events"], ["ctypes.call_function"])     # only the permitted foreign calls, no helper event
        self.assertEqual(report["plan_hosted"], [])                               # hosted by a pinned loaded native: nothing to load
        self.assertEqual(report["violations_after_hosted"], [])
        self.assertEqual(report["plan_unresolved"], "ImportError")
        self.assertEqual(report["plan_unpinned_host"], "ImportError")             # resolved, but its host is not a pinned native
        self.assertEqual(report["violations"], ["native_apiset_unresolved:ext:" + self.MISSING,
                                                "native_apiset_unresolved:ext:" + self.API_SET])
        self.assertFalse([v for v in report["violations"] if v.startswith("denied_event")])

    def test_a_dependency_cannot_use_the_resolvers_binding_from_its_own_frame(self):
        report = run_armed_driver(self, ARMED_AUDIT_DRIVER)
        self.assertEqual(report["dependency_function_pointer"], "audit refused: ctypes.call_function")
        self.assertEqual(report["violations"][0], "denied_event:ctypes.call_function")

    def extension(self):
        """``(name, path)`` of a real extension file of this interpreter that imports an API set, from known host facts."""
        base = Path(sys.base_prefix) / "DLLs"
        for name in self.EXTENSION_CANDIDATES:
            for path in base.glob(name + "*.pyd"):
                if b"api-ms-win-" in path.read_bytes():
                    return name, path
        self.fail("no extension file under %s imports an API set (candidates %s): the fixture fact is missing"
                  % (base, ", ".join(self.EXTENSION_CANDIDATES)))

    def test_a_closure_importing_a_real_extension_with_api_set_imports_runs_to_a_pass_through_the_armed_native_path(self):
        name, path = self.extension()
        main = ("import %s\n\n\ndef verify(inputs, params):\n    return {'status': 'PASS', 'module': %s.__name__}\n" % (name, name))
        fx = Fixture(self, main=main).build()
        run = fx.run()
        self.assertEqual((run.status, run.reason), ("PASS", "ok"), run.receipt)
        self.assertEqual(run.receipt["violations"], [])
        self.assertIn(name, run.receipt["loaded"]["native"])                      # loaded as a pinned native, not from the filesystem search
        self.assertIn(name, {row[0] for row in run.receipt["evidence"]["native_files"]})
        self.assertEqual(pv.verify_receipt(run.receipt, manifest=fx.manifest, expected_manifest_sha256=fx.digest,
                                           expected_release_sha256=fx.release, expected_inputs={"doc": sha(b"good")},
                                           expected_params_sha256=pv.canonical_digest(None), expected_module_table=fx.table(),
                                           require_acceptance=False), "PASS")


class ExactImportPositions(unittest.TestCase):
    def test_recorded_sites_are_the_exact_ast_positions_of_statements_and_literal_calls(self):
        source = (b"import os\nfrom . import helper\nimport importlib\n\n\ndef verify(i, p):\n    import json\n"
                  b"    importlib.import_module(\n        \"zlib\")\n    return json\n")
        scan = pv.scan_source(source, "vc.main", False)
        self.assertEqual(scan.rejections, [])
        self.assertEqual(scan.sites, [(1, 1, 0, 9, ("os",)), (2, 2, 0, 20, ("vc", "vc.helper")), (3, 3, 0, 16, ("importlib",)),
                                      (7, 7, 4, 15, ("json",)), (8, 9, 4, 15, ("zlib",))])

    def test_multi_line_from_import_and_star_import_record_one_span_each(self):
        scan = pv.scan_source(b"from os import (\n    path,\n    sep,\n)\nfrom json import *\n", "vc.main", False)
        self.assertEqual(scan.rejections, [])
        self.assertEqual(scan.sites, [(1, 4, 0, 1, ("os", "os.path", "os.sep")), (5, 5, 0, 18, ("json",))])

    def test_two_calls_with_one_name_are_two_distinct_sites(self):
        scan = pv.scan_source(b"import importlib\nimportlib.import_module('json'); importlib.import_module('json')\n", "vc.main", False)
        calls = [site for site in scan.sites if site[4] == ("json",)]
        self.assertEqual(len(calls), 2)
        self.assertEqual(len({(site[0], site[2]) for site in calls}), 2)


# ---------------------------------------------------------------------------------------------------
# 5. Import cache, ambient environment and in-process state.

class CacheAndAmbientState(RejectionMixin, unittest.TestCase):
    def test_poisoned_unchecked_hash_pyc_cannot_substitute_the_pinned_source(self):
        fx = Fixture(self, helper=HELPER_HOLD).build()
        poison = fx.tmp / "poison_helper.py"
        poison.write_text(HELPER_PASS)
        cache = Path(importlib.util.cache_from_source(str(fx.root / "vc/helper.py")))
        cache.parent.mkdir(parents=True, exist_ok=True)
        py_compile.compile(str(poison), cfile=str(cache), invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH)
        # The old ambient-import pattern executes the poisoned bytecode...
        done = subprocess.run([sys.executable, "-I", "-B", "-c", "import sys; sys.path.insert(0, sys.argv[1]); import vc.helper as h; "
                               "print(h.decide({}))", str(fx.root)], capture_output=True, text=True, timeout=60)
        self.assertEqual(done.stdout.strip(), "PASS")
        # ...the closure runner executes only the pinned source bytes.
        run = fx.run()
        self.assertEqual((run.status, run.reason), ("HOLD", "verifier_hold"))
        self.assertTrue(run.receipt["post_checks"]["bytecode_dir_empty"])

    def test_stale_cache_of_replaced_source_cannot_make_the_replacement_pass(self):
        fx = Fixture(self, helper=HELPER_HOLD).build()
        cache = Path(importlib.util.cache_from_source(str(fx.root / "vc/helper.py")))
        cache.parent.mkdir(parents=True, exist_ok=True)
        py_compile.compile(str(fx.root / "vc/helper.py"), cfile=str(cache), invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH)
        fx.write("vc/helper.py", HELPER_PASS)
        self.assertRejected(fx.run(), "closure_module_changed:vc.helper")

    def test_cached_modules_in_the_parent_process_cannot_poison_the_child(self):
        fx = Fixture(self, helper=HELPER_HOLD).build()
        fake_helper = types.ModuleType("vc.helper")
        fake_helper.decide = lambda inputs: "PASS"
        with mock.patch.dict(sys.modules, {"vc": types.ModuleType("vc"), "vc.helper": fake_helper}):
            run = fx.run()
        self.assertEqual((run.status, run.reason), ("HOLD", "verifier_hold"))
        self.assertEqual(run.receipt["parent_sys_modules_collisions"], ["vc", "vc.helper"])

    def test_closure_module_named_like_a_preloaded_or_stdlib_module_is_rejected(self):
        for name in ("os", "json", "_imp"):
            fx = Fixture(self, main="def verify(i, p):\n    return {'status': 'PASS'}\n", extra={name + "/__init__.py": "X = 1\n"})
            roots = {"vc": fx.root}
            with self.assertRaises(pv.ClosureRejected, msg=name) as caught:
                pv.build_manifest(name="x", roots=roots, entry_module=name, observation=observation())
            self.assertEqual(caught.exception.code, "closure_name_shadows_runtime", name)

    def test_child_refuses_a_closure_whose_module_is_already_preloaded(self):
        fx = Fixture(self).build()
        verified = fx.verify(work=str(fx.work))
        data = b"def verify(i, p):\n    return {'status': 'PASS'}\n"
        verified.modules["os"] = data
        verified.manifest = copy.deepcopy(verified.manifest)
        verified.manifest["modules"].append({"name": "os", "root": "vc", "path": "vc/os.py", "sha256": sha(data), "bytes": len(data),
                                             "package": False})
        verified.sites["os"] = []
        execution, nonce, header, _ = pv._launch(verified, {}, None, "run", 120.0, str(fx.work))
        self.assertNotEqual(execution.returncode, 0)
        with self.assertRaises(pv.ClosureRejected) as caught:
            pv._accept_report(execution, nonce, header, verified, "run")
        self.assertTrue(caught.exception.code.startswith("runtime_bootstrap_reject"), caught.exception)
        self.assertRegex(caught.exception.detail, "closure_module_preloaded|closure_name_shadows_runtime")

    def test_environment_search_path_startup_and_site_poison_is_ignored(self):
        fx = Fixture(self).build()
        poison = fx.tmp / "poison"
        poison.mkdir()
        for name in ("json.py", "hashlib.py", "sitecustomize.py", "usercustomize.py", "startup.py"):
            (poison / name).write_text("raise RuntimeError('ambient poison executed')\n")
        env = {"PYTHONPATH": str(poison), "PYTHONSTARTUP": str(poison / "startup.py"), "PYTHONUSERBASE": str(poison),
               "PYTHONDONTWRITEBYTECODE": "", "PYTHONPYCACHEPREFIX": str(poison), "PYTHONHASHSEED": "random"}
        with mock.patch.dict(os.environ, env):
            run = fx.run()
        self.assertEqual((run.status, run.reason), ("PASS", "ok"), run.receipt)
        self.assertEqual(list(poison.glob("__pycache__")), [])

    def test_import_and_swallow_of_a_module_the_importer_is_not_approved_for_is_caught_at_load_time(self):
        """Every fixture below is accepted by the static scan (it compares constant strings only): the real ``builtins``
        module comes from ``print.__self__`` and the dunder name is assembled at run time.  The mediated ``__import__``
        judges the exact calling instruction before anything loads, so swallowing the refusal and scrubbing
        ``sys.modules`` afterwards cannot hide the attempt."""
        main = ('from . import helper\n' + REACH_IMPORT + REACH_MODULES + '\n\ndef verify(inputs, params):\n'
                '    try:\n        IMPORT("vc.hidden")\n    except ImportError:\n        pass\n'
                '    MODULES.pop("vc.hidden", None)\n'
                '    return {"status": "PASS"}\n')
        helper = 'def decide(inputs):\n    from . import hidden\n    return hidden.VALUE\n'
        fx = Fixture(self, main=main, helper=helper, extra={"vc/hidden.py": 'VALUE = "PASS"\n'}).build()
        run = fx.run()
        self.assertRejected(run, "closure_runtime_violation:undeclared_import:vc.hidden", "closure")
        self.assertEqual(run.receipt["violations"], ["undeclared_import:vc.hidden"])
        self.assertIsNone(run.receipt["verifier"])

    def test_import_and_remove_of_a_loaded_closure_module_is_caught(self):
        main = ('from . import helper\n' + REACH_MODULES + '\n\ndef verify(inputs, params):\n'
                '    del MODULES["vc.hidden"]\n    return {"status": "PASS"}\n')
        helper = 'from . import hidden\n\n\ndef decide(inputs):\n    return hidden.VALUE\n'
        fx = Fixture(self, main=main, helper=helper, extra={"vc/hidden.py": 'VALUE = "PASS"\n'}).build()
        run = fx.run()
        self.assertRejected(run, "closure_runtime_violation:closure_module_removed:vc.hidden", "closure")
        self.assertEqual(run.receipt["violations"], ["closure_module_removed:vc.hidden"])
        self.assertIsNone(run.receipt["verifier"])

    def test_runtime_import_guard_catches_undetectable_ambient_imports(self):
        main = (REACH_IMPORT + '\n\ndef verify(inputs, params):\n    try:\n        IMPORT(params["name"])\n'
                '    except ImportError:\n        pass\n    return {"status": "PASS"}\n')
        fx = Fixture(self, main=main).build()
        for name in ("yaml_unavailable_pkg", "jsonschema", "json", "os"):       # absent, absent, cached stdlib, preloaded
            run = fx.run(params={"name": name})
            self.assertRejected(run, "closure_runtime_violation:undeclared_import:" + name, "closure")
            self.assertEqual(run.receipt["violations"], ["undeclared_import:" + name])

    def test_replacing_a_loaded_closure_module_or_mutating_sys_path_is_detected(self):
        replace = ('import types\nfrom . import helper\n' + REACH_MODULES + '\n\ndef verify(inputs, params):\n'
                   '    MODULES["vc.helper"] = types.ModuleType("vc.helper")\n    return {"status": "PASS"}\n')
        run = Fixture(self, main=replace).build().run()
        self.assertRejected(run, "closure_runtime_violation:module_from_unlisted_location:vc.helper", "closure")
        self.assertEqual(run.receipt["violations"], ["module_from_unlisted_location:vc.helper"])
        mutate = ('import sys\nfrom . import helper\n\nPATH = getattr(sys, "pa" + "th")\n\n\ndef verify(inputs, params):\n'
                  '    PATH.insert(0, params["dir"])\n    return {"status": "PASS"}\n')
        fx = Fixture(self, main=mutate).build()
        changed = fx.run(params={"dir": str(fx.tmp)})
        self.assertRejected(changed, "closure_runtime_violation:import_state_mutated", "closure")
        self.assertEqual(changed.receipt["violations"], ["import_state_mutated"])

    def test_dynamic_code_and_denied_native_apis_are_refused_at_runtime(self):
        """What the static scan cannot see (attribute access through ``builtins`` or a computed name) is blocked by the
        audit hook, not trusted; a plain read of an allowed file stays a PASS and no sandbox is claimed."""
        cases = (("exec", 'builtins.exec("x = 1")', "dynamic_compile:vc.main.verify"),
                 ("eval", 'builtins.eval("1")', "dynamic_compile:vc.main.verify"),
                 ("compile", 'builtins.compile("1", "s", "eval")', "dynamic_compile:vc.main.verify"),
                 ("system", 'getattr(os, "sys" + "tem")("true")', "denied_event:os.system"),
                 ("read", 'builtins.open(params["path"], "rb").read()', None))
        for label, body, violation in cases:
            main = ('import os\n\nbuiltins = print.__self__\n\n\ndef verify(inputs, params):\n    try:\n        %s\n    except BaseException:\n'
                    '        pass\n    return {"status": "PASS"}\n') % body
            fx = Fixture(self, main=main).build()
            run = fx.run(params={"path": str(fx.data / "doc.txt")})
            if violation is None:
                self.assertEqual((run.status, run.reason), ("PASS", "ok"), (label, run.reason))
                self.assertEqual(run.receipt["violations"], [])
            else:
                self.assertRejected(run, "closure_runtime_violation:" + violation, "closure")
                self.assertEqual(run.receipt["violations"], [violation], label)

    TRIGGER_MAIN = ('import authdep\nfrom . import helper\n\n\ndef verify(inputs, params):\n    authdep.trigger()\n'
                    '    return {"status": "PASS", "value": authdep.VALUE}\n')

    def dependency_fixture(self, package, extra=None, main=None):
        """``(fixture, roots, packages)`` for a closure whose entry imports the pinned distribution ``authdep`` (source
        ``package``, extra files ``extra``); nothing is built or run yet.  ``main`` replaces the closure entry (the
        ``TRIGGER_MAIN`` entry calls ``authdep.trigger()``, so an operation placed in that function happens at RUN time
        only: the discovery pass that imports the entry never performs it)."""
        main = main or 'import authdep\nfrom . import helper\n\n\ndef verify(inputs, params):\n    return {"status": "PASS", "value": authdep.VALUE}\n'
        fx = Fixture(self, main=main)
        site = fx.tmp / "site"
        (site / "authdep").mkdir(parents=True)
        (site / "authdep/__init__.py").write_text(package)
        for name, text in (extra or {}).items():
            (site / "authdep" / name).write_text(text)
        (site / "authdep-1.0.dist-info").mkdir()
        (site / "authdep-1.0.dist-info/METADATA").write_text("Metadata-Version: 2.1\nName: authdep\nVersion: 1.0\n")
        roots = {"vc": fx.root, "site": site}
        return fx, roots, [{"distribution": "authdep", "version": "1.0", "root": "site", "top_level": ["authdep"]}]

    def dependency_run(self, package, extra=None, operations=()):
        fx, roots, packages = self.dependency_fixture(package, extra)
        fx.build(roots=roots, packages=packages, dependency_operations=list(operations))
        return fx.run(roots=roots)

    APPROVED_PACKAGE = ("import builtins\nimport importlib\nimport json\nfrom os import path\nfrom . import sub\n\n"
                        "VALUE = [builtins.__import__ is not None, json.dumps([]), path.sep == __import__('os').sep, sub.VALUE,\n"
                        "         importlib.import_module('.sub', __package__).VALUE, importlib.import_module('json') is json]\n")
    APPROVED_OPERATIONS = ({"importer": "authdep", "form": "import", "module": "os"},
                           {"importer": "authdep", "form": "import_module", "module": "authdep.sub"},
                           {"importer": "authdep", "form": "import_module", "module": "json"})

    def test_dependency_code_may_perform_only_the_approved_operations_and_ordinary_imports(self):
        """The reviewed dependency import operation (``builtins`` import statement), ordinary static imports (absolute or
        relative, no declaration) and the three DYNAMIC operations on pinned targets that the manifest declares (an
        explicit ``__import__`` call, ``import_module`` of a pinned submodule through a relative name, ``import_module``
        of a cached module) work end to end without any recorded violation."""
        run = self.dependency_run(self.APPROVED_PACKAGE, {"sub.py": "VALUE = 3\n"}, operations=self.APPROVED_OPERATIONS)
        self.assertEqual((run.status, run.reason), ("PASS", "ok"), run.receipt)
        self.assertEqual(run.receipt["verifier"]["result"]["value"], [True, "[]", True, 3, 3, True])
        self.assertEqual(run.receipt["violations"], [])
        self.assertEqual(run.receipt["refused"], ["dependency_operation:authdep:import:os",
                                                  "dependency_operation:authdep:import_module:authdep.sub",
                                                  "dependency_operation:authdep:import_module:json"])

    def test_the_same_dynamic_operations_on_pinned_targets_without_a_declaration_are_refused_at_authoring_and_at_run_time(self):
        fx, roots, packages = self.dependency_fixture(self.APPROVED_PACKAGE, {"sub.py": "VALUE = 3\n"})
        refused = self.assertRaisesCode("dependency_operation_undeclared", fx.build, roots=roots, packages=packages)
        self.assertEqual(refused.detail, "authdep:import:os")                       # the first undeclared operation, named exactly
        fx.build(roots=roots, packages=packages, dependency_operations=list(self.APPROVED_OPERATIONS))
        manifest, digest = retarget(fx.manifest, lambda m: m.__setitem__("dependency_operations", []))
        run = fx.run(manifest, digest, roots=roots)
        self.assertRejected(run, "closure_runtime_violation:undeclared_dependency_operation:authdep:import:os", "closure")
        self.assertIsNone(run.receipt["verifier"])

    def test_a_denied_dependency_import_is_refused_at_authoring_when_it_runs_at_import_time(self):
        """The discovery pass imports the entry, so a denylisted import in the dependency's top-level code is rejected
        while building (``closure_import_failed``) and no manifest comes into existence."""
        for label, statement, name in self.DENIED_FORMS:
            with self.subTest(label):
                package = ("import builtins\nimport importlib\nimport importlib.util\n\nVALUE = 1\ntry:\n    %s\nexcept ImportError:\n"
                           "    pass\n" % statement)
                fx, roots, packages = self.dependency_fixture(package)
                error = self.assertRaisesCode("closure_import_failed", fx.build, roots=roots, packages=packages)
                self.assertEqual(error.detail, "forbidden_dependency_import:" + name)

    DENIED_FORMS = (("statement", "import subprocess", "subprocess"),
                    ("cached_module", "import _ctypes", "_ctypes"),
                    ("import_module", "importlib.import_module('ctypes')", "ctypes"),
                    ("import_module_builtins", "importlib.import_module('builtins')", "builtins"),
                    ("indirect", "builtins.__import__('_ctypes')", "_ctypes"),
                    ("relative_import_module", "importlib.import_module('.hostile', 'subprocess')", "subprocess.hostile"),
                    ("relative_through_globals", "builtins.__import__('hostile', {'__package__': 'subprocess'}, None, (), 1)",
                     "subprocess.hostile"),
                    ("find_spec_cached", "importlib.util.find_spec('_ctypes')", "_ctypes"),
                    ("find_spec_relative", "importlib.util.find_spec('.hostile', 'subprocess')", "subprocess.hostile"),
                    ("importlib_dunder_import", "importlib.__import__('_ctypes')", "_ctypes"),
                    ("private_gcd_import", "importlib._bootstrap._gcd_import('ctypes')", "ctypes"))

    def test_a_denied_dependency_import_is_a_recorded_violation_in_every_form_even_when_the_refusal_is_swallowed(self):
        """Statement, cached-module, ``importlib.import_module`` (absolute and relative), ``builtins`` through
        ``import_module`` and indirect ``__import__`` (also relative through its ``globals`` argument) are all rejected at
        RUN time: the operation sits in a function the entry calls, so the discovery pass builds cleanly and only the
        enforced run reaches it.  A refusal that the dependency swallows still fails the run."""
        for label, statement, name in self.DENIED_FORMS:
            with self.subTest(label):
                package = ("import builtins\nimport importlib\nimport importlib.util\n\nVALUE = 1\n\n\ndef trigger():\n    try:\n        %s\n"
                           "    except ImportError:\n        pass\n" % statement)
                fx, roots, packages = self.dependency_fixture(package, main=self.TRIGGER_MAIN)
                fx.build(roots=roots, packages=packages)
                run = fx.run(roots=roots)
                self.assertRejected(run, "closure_runtime_violation:forbidden_dependency_import:" + name, "closure")
                self.assertEqual(run.receipt["violations"], ["forbidden_dependency_import:" + name])
                self.assertIsNone(run.receipt["verifier"])

    OPTIONAL_PROBES = ("try:\n    import yaml_unavailable_pkg\nexcept ImportError:\n    HAVE_YAML = False\nelse:\n    HAVE_YAML = True\n"
                       "import importlib\ntry:\n    importlib.import_module('accel_unavailable_pkg')\nexcept ImportError:\n"
                       "    HAVE_ACCEL = False\nelse:\n    HAVE_ACCEL = True\nVALUE = [HAVE_YAML, HAVE_ACCEL]\n")
    PROBE_OPERATIONS = ({"importer": "authdep", "form": "import", "module": "yaml_unavailable_pkg"},
                        {"importer": "authdep", "form": "import_module", "module": "accel_unavailable_pkg"})

    def test_a_declared_optional_probe_of_an_unpinned_module_is_absent_and_recorded_for_review(self):
        """The reviewed per-dependency operation (importer, form, module): the dependency's ``ImportError`` handling works,
        the module is reported absent rather than loaded, and the attempt is recorded exactly as declared."""
        run = self.dependency_run(self.OPTIONAL_PROBES, operations=self.PROBE_OPERATIONS)
        self.assertEqual((run.status, run.reason), ("PASS", "ok"), run.receipt)
        self.assertEqual(run.receipt["verifier"]["result"]["value"], [False, False])
        self.assertEqual(run.receipt["violations"], [])
        self.assertEqual(sorted(run.receipt["refused"]),
                         ["dependency_operation:authdep:import:yaml_unavailable_pkg",
                          "dependency_operation:authdep:import_module:accel_unavailable_pkg"])
        self.assertEqual(run.receipt["refused"], sorted(run.receipt["refused"]))

    def test_an_unpinned_dependency_operation_that_was_not_declared_fails_at_authoring(self):
        fx, roots, packages = self.dependency_fixture(self.OPTIONAL_PROBES)
        refused = self.assertRaisesCode("dependency_operation_undeclared", fx.build, roots=roots, packages=packages)
        self.assertEqual(refused.detail, "authdep:import:yaml_unavailable_pkg")
        partial = self.assertRaisesCode("dependency_operation_undeclared", fx.build, roots=roots, packages=packages,
                                        dependency_operations=list(self.PROBE_OPERATIONS[:1]))
        self.assertEqual(partial.detail, "authdep:import_module:accel_unavailable_pkg")

    def test_an_operation_that_the_manifest_does_not_declare_is_a_recorded_violation_even_when_swallowed(self):
        """Declare, build, then remove or alter the declaration: the dependency's own ``except ImportError`` swallows the
        refusal, yet the attempt is judged against the manifest's table before it is answered and fails the run."""
        fx, roots, packages = self.dependency_fixture(self.OPTIONAL_PROBES)
        fx.build(roots=roots, packages=packages, dependency_operations=list(self.PROBE_OPERATIONS))
        probe, via = self.PROBE_OPERATIONS
        cases = (("none_declared", [], "authdep:import:yaml_unavailable_pkg"),
                 ("only_the_import_declared", [probe], "authdep:import_module:accel_unavailable_pkg"),
                 ("wrong_form", [{**probe, "form": "import_module"}, via], "authdep:import:yaml_unavailable_pkg"),
                 ("wrong_module", [{**probe, "module": "other_unavailable_pkg"}, via], "authdep:import:yaml_unavailable_pkg"),
                 ("wrong_importer", [{**probe, "importer": "json"}, via], "authdep:import:yaml_unavailable_pkg"))
        for label, operations, first in cases:
            with self.subTest(label):
                manifest, digest = retarget(fx.manifest, lambda m: m.__setitem__("dependency_operations", sorted(
                    operations, key=lambda d: (d["importer"], d["form"], d["module"]))))
                run = fx.run(manifest, digest, roots=roots)
                self.assertRejected(run, "closure_runtime_violation:undeclared_dependency_operation:" + first, "closure")
                self.assertEqual(run.receipt["violations"][0], "undeclared_dependency_operation:" + first)
                self.assertIsNone(run.receipt["verifier"])

    def test_the_declared_importer_is_the_pinned_module_whose_code_issued_the_request(self):
        """A declaration for the package ``__init__`` does not cover its submodule's attempt; the submodule's own
        declaration does."""
        package = "from . import sub\n\nVALUE = sub.VALUE\n"
        sub = "try:\n    import yaml_unavailable_pkg\nexcept ImportError:\n    VALUE = 'absent'\nelse:\n    VALUE = 'present'\n"
        for importer, expected in (("authdep", "undeclared_dependency_operation:authdep.sub:import:yaml_unavailable_pkg"),
                                   ("authdep.sub", None)):
            with self.subTest(importer):
                fx, roots, packages = self.dependency_fixture(package, {"sub.py": sub})
                operation = {"importer": "authdep.sub", "form": "import", "module": "yaml_unavailable_pkg"}
                fx.build(roots=roots, packages=packages, dependency_operations=[operation])
                manifest, digest = retarget(fx.manifest, lambda m: m.__setitem__("dependency_operations", [{**operation, "importer": importer}]))
                run = fx.run(manifest, digest, roots=roots)
                if expected is None:
                    self.assertEqual((run.status, run.reason), ("PASS", "ok"), run.receipt)
                    self.assertEqual(run.receipt["verifier"]["result"]["value"], "absent")
                    self.assertEqual(run.receipt["refused"], ["dependency_operation:authdep.sub:import:yaml_unavailable_pkg"])
                else:
                    self.assertRejected(run, "closure_runtime_violation:" + expected, "closure")

    def test_a_declaration_may_name_a_pinned_module_but_not_an_unpinned_importer_a_closure_module_or_a_denylisted_one(self):
        fx, roots, packages = self.dependency_fixture(self.OPTIONAL_PROBES)
        fx.build(roots=roots, packages=packages, dependency_operations=list(self.PROBE_OPERATIONS))
        table = fx.table(roots=roots)
        pinned = {"dependency_operations": [{"importer": "authdep", "form": "import_module", "module": "json"},
                                            {"importer": "authdep", "form": "import", "module": "authdep.sub"}]}
        pv._check_dependency_operations(pinned, table)                              # pinned targets are declarable (no exception)
        unpinned = {"dependency_operations": [{"importer": "no_such_importer", "form": "import", "module": "x_unavailable"}]}
        refused = self.assertRaisesCode("dependency_operation_importer_unpinned", pv._check_dependency_operations, unpinned, table)
        self.assertEqual(refused.detail, "no_such_importer")
        for operation in ({"importer": "authdep", "form": "import", "module": "vc.helper"},
                          {"importer": "vc.main", "form": "import", "module": "x_unavailable"},
                          {"importer": "authdep", "form": "import", "module": "subprocess"},
                          {"importer": "authdep", "form": "import_module", "module": "builtins"}):
            self.assertRaisesCode("manifest_dependency_operations", fx.build, roots=roots, packages=packages,
                                  dependency_operations=[operation])
        built = fx.build(roots=roots, packages=packages, dependency_operations=[
            {"importer": "authdep", "form": "import_module", "module": "json"}, *self.PROBE_OPERATIONS]).manifest   # Fixture supplies the observation
        pv.validate_manifest(built)                                                  # a pinned declaration survives verification

    PINNED_PRELUDE = "import builtins\nimport importlib\nimport json\n\nVALUE = 1\n"
    #           label, statements run at import time, operations in EXECUTION order
    PINNED_CASES = (
        ("import_module_fresh", "importlib.import_module('authdep.sub')", (("authdep", "import_module", "authdep.sub"),)),
        ("import_module_cached", "importlib.import_module('json')", (("authdep", "import_module", "json"),)),
        ("import_module_relative", "importlib.import_module('.sub', __package__)", (("authdep", "import_module", "authdep.sub"),)),
        ("dunder_import_fresh", "__import__('authdep.sub')", (("authdep", "import", "authdep.sub"),)),
        ("dunder_import_cached", "__import__('json')", (("authdep", "import", "json"),)),
        ("dunder_import_relative", "__import__('sub', globals(), None, (), 1)", (("authdep", "import", "authdep.sub"),)),
        ("indirect_import_module_alias", "loader = importlib.import_module\nloader('json')", (("authdep", "import_module", "json"),)),
        ("indirect_dunder_import_alias", "hook = builtins.__import__\nhook('json')", (("authdep", "import", "json"),)),
        ("fromlist_names_a_pinned_submodule", "__import__('authdep', globals(), None, ['sub'])",
         (("authdep", "import", "authdep"), ("authdep", "import", "authdep.sub"))),
        ("importlib_dunder_import_cached", "importlib.__import__('json')", (("authdep", "import", "json"),)),
        ("private_gcd_import_cached", "import importlib._bootstrap as boot\nboot._gcd_import('json')",
         (("authdep", "import_module", "json"),)),
        ("private_gcd_import_relative", "import importlib._bootstrap as boot\nboot._gcd_import('sub', 'authdep', 1)",
         (("authdep", "import_module", "authdep.sub"),)),
        ("find_spec_uncached_absolute", "import importlib.util\nimportlib.util.find_spec('authdep.sub')",
         (("authdep", "find_spec", "authdep.sub"),)),
        ("find_spec_cached_absolute", "import importlib.util\nimportlib.util.find_spec('json')",
         (("authdep", "find_spec", "json"),)),
        ("find_spec_cached_builtin", "import importlib.util\nimportlib.util.find_spec('sys')",
         (("authdep", "find_spec", "sys"),)),
        ("find_spec_relative", "import importlib.util\nimportlib.util.find_spec('.sub', __package__)",
         (("authdep", "find_spec", "authdep.sub"),)),
        ("find_spec_indirect_alias", "import importlib.util\nprobe = importlib.util.find_spec\nprobe('json')",
         (("authdep", "find_spec", "json"),)),
        ("find_spec_of_a_frozen_module_when_the_build_freezes_it", "import importlib.util\nimportlib.util.find_spec('os')",
         (("authdep", "find_spec", "os"),)),
        ("private_find_and_load_cached", "import importlib._bootstrap as boot\nboot._find_and_load('json', None)",
         (("authdep", "import_module", "json"),)),
        ("private_bootstrap_dunder_import_cached", "import importlib._bootstrap as boot\nboot.__import__('json')",
         (("authdep", "import", "json"),)),
        ("builtin_importer_find_spec", "import importlib.machinery\nimportlib.machinery.BuiltinImporter.find_spec('sys')",
         (("authdep", "find_spec", "sys"),)),
        ("frozen_importer_find_spec", "import importlib.machinery\nimportlib.machinery.FrozenImporter.find_spec('os')",
         (("authdep", "find_spec", "os"),)),
        ("path_finder_find_spec", "import importlib.machinery\nimportlib.machinery.PathFinder.find_spec('json')",
         (("authdep", "find_spec", "json"),)),
        ("the_codec_exception_is_narrow", "importlib.import_module('encodings.koi8_u')",
         (("authdep", "import_module", "encodings.koi8_u"),)),
    )

    def pinned_package(self, statements):
        body = "\n".join("    " + line for line in statements.splitlines())
        return self.PINNED_PRELUDE + "try:\n" + body + "\nexcept ImportError:\n    pass\n"

    def test_every_dynamic_dependency_operation_on_a_pinned_target_needs_its_declaration_and_is_recorded_when_declared(self):
        """Uncached, cached, relative and indirect forms of ``import_module``, ``__import__`` (also through ``fromlist``) and
        ``find_spec`` against PINNED modules: the declared operation runs and is recorded exactly; the undeclared one is
        refused while authoring (the discovery pass names the first undeclared operation) and is a recorded violation at
        run time, also when the dependency swallows the ``ImportError``."""
        for label, statements, operations in self.PINNED_CASES:
            with self.subTest(label):
                fx, roots, packages = self.dependency_fixture(self.pinned_package(statements), {"sub.py": "VALUE = 3\n"})
                entries = [pv.DEPENDENCY_OPERATION_PREFIX + ":".join(item) for item in operations]
                refused = self.assertRaisesCode("dependency_operation_undeclared", fx.build, roots=roots, packages=packages)
                self.assertEqual(refused.detail, min(entries)[len(pv.DEPENDENCY_OPERATION_PREFIX):])
                declared = [{"importer": i, "form": f, "module": m} for i, f, m in operations]
                fx.build(roots=roots, packages=packages, dependency_operations=declared)
                run = fx.run(roots=roots)
                self.assertEqual((run.status, run.reason), ("PASS", "ok"), (label, run.receipt))
                self.assertEqual(run.receipt["violations"], [], label)
                self.assertEqual(run.receipt["refused"], sorted(entries), label)
                manifest, digest = retarget(fx.manifest, lambda m: m.__setitem__("dependency_operations", []))
                undeclared = fx.run(manifest, digest, roots=roots)
                first = ":".join(operations[0])
                self.assertRejected(undeclared, "closure_runtime_violation:undeclared_dependency_operation:" + first, "closure")
                self.assertIsNone(undeclared.receipt["verifier"])

    def test_a_declaration_for_another_form_importer_or_target_does_not_cover_a_pinned_operation(self):
        fx, roots, packages = self.dependency_fixture(self.pinned_package("importlib.import_module('json')"))
        right = {"importer": "authdep", "form": "import_module", "module": "json"}
        fx.build(roots=roots, packages=packages, dependency_operations=[right])
        for label, wrong in (("form", {**right, "form": "import"}), ("target", {**right, "module": "os"}),
                             ("importer", {**right, "importer": "json"})):
            with self.subTest(label):
                manifest, digest = retarget(fx.manifest, lambda m: m.__setitem__("dependency_operations", [wrong]))
                run = fx.run(manifest, digest, roots=roots)
                self.assertRejected(run, "closure_runtime_violation:undeclared_dependency_operation:authdep:import_module:json", "closure")

    def test_the_reviewed_codec_lookup_of_the_standard_library_needs_no_declaration(self):
        """``encodings.search_function`` loads a codec with an explicit ``__import__`` call: the one reviewed standard-library
        dynamic operation, so a dependency that merely encodes text with an unloaded codec runs undeclared and records
        nothing."""
        package = "VALUE = [list('\\xe9'.encode('cp437')), list('\\u0434'.encode('koi8_u'))]\n"
        fx, roots, packages = self.dependency_fixture(package)
        fx.build(roots=roots, packages=packages)
        run = fx.run(roots=roots)
        self.assertEqual((run.status, run.reason), ("PASS", "ok"), run.receipt)
        self.assertEqual(run.receipt["verifier"]["result"]["value"], [[130], [196]])
        self.assertEqual((run.receipt["violations"], run.receipt["refused"]), ([], []))

    def test_the_reviewed_standard_library_table_is_one_narrow_rule_in_both_implementations_and_in_the_contract(self):
        import ast
        tree = ast.parse((REPO / "trace_gc" / "verifier_closure_bootstrap.py").read_text(encoding="utf-8"))
        values = {t.targets[0].id: ast.literal_eval(t.value) for t in tree.body
                  if isinstance(t, ast.Assign) and isinstance(t.targets[0], ast.Name) and t.targets[0].id == "DEPENDENCY_STDLIB_OPERATIONS"}
        self.assertEqual(values["DEPENDENCY_STDLIB_OPERATIONS"], pv.DEPENDENCY_STDLIB_OPERATIONS)
        self.assertEqual(pv.CONTRACT["dependency_stdlib_operations"], [list(item) for item in pv.DEPENDENCY_STDLIB_OPERATIONS])
        self.assertEqual(pv.DEPENDENCY_STDLIB_OPERATIONS, (("encodings", "import", "encodings", True),))
        check = load_bootstrap()["_stdlib_operation"]
        self.assertTrue(check("encodings", "import", "encodings.cp437"))
        self.assertTrue(check("encodings", "import", "encodings"))
        for importer, form, module in (("encodings", "import_module", "encodings.cp437"), ("encodings", "find_spec", "encodings.cp437"),
                                       ("json", "import", "encodings.cp437"), ("authdep", "import", "encodings.cp437"),
                                       ("encodings", "import", "encodings_evil"), ("encodings", "import", "os"),
                                       ("encodings", "import", "json"), (None, "import", "encodings.cp437")):
            self.assertFalse(check(importer, form, module), (importer, form, module))
        # the exception describes the real standard library: its codec search function imports 'encodings.<codec>' by __import__
        import encodings
        source = Path(encodings.__file__).read_text(encoding="utf-8")
        calls = [c for c in ast.walk(ast.parse(source)) if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)
                 and c.func.id == "__import__" and c.args and isinstance(c.args[0], ast.BinOp)
                 and isinstance(c.args[0].left, ast.Constant) and c.args[0].left.value == "encodings."]
        self.assertEqual(len(calls), 1, "the reviewed codec lookup is not what this interpreter's encodings package does")

    def test_every_supported_entry_point_is_replaced_by_a_mediating_function_that_decides_before_any_cache_shortcut(self):
        source = (REPO / "trace_gc" / "verifier_closure_bootstrap.py").read_text(encoding="utf-8")
        for installed in ("importlib.import_module = _mediated_import_module", "importlib.__import__ = _mediated_import",
                          "._gcd_import = _mediated_gcd_import", "module.find_spec = _mediated_find_spec"):
            self.assertIn(installed, source)
        namespace = load_bootstrap()
        for name in ("_mediated_find_spec", "_mediated_gcd_import", "_install_find_spec", "_is_import_plumbing"):
            self.assertTrue(callable(namespace[name]), name)
        text = (REPO / "docs" / "paper_verifier_closure.md")
        if text.is_file():
            self.assertNotIn("so it is not an", text.read_text(encoding="utf-8"))

    def test_the_dynamic_operation_gate_decides_by_declaration_review_and_discovery_mode(self):
        namespace = load_bootstrap()
        gate, state, report = namespace["_dependency_dynamic_operation"], namespace["_STATE"], namespace["_REPORT"]
        requester = types.SimpleNamespace(f_code=types.SimpleNamespace(co_filename="/lib/imp.py"))
        state.update(file_names={"/lib/imp.py": "imp"}, dep_ops=frozenset({("imp", "import_module", "json")}), strict=True)
        gate(requester, "import_module", "json")                                    # declared: allowed and recorded
        self.assertEqual(report["refused"], ["dependency_operation:imp:import_module:json"])
        gate(requester, "import", "builtins")                                       # the reviewed dependency import operation
        namespace["_STATE"].update(file_names={"/lib/enc.py": "encodings"})
        gate(types.SimpleNamespace(f_code=types.SimpleNamespace(co_filename="/lib/enc.py")), "import", "encodings.cp437")
        self.assertEqual(report["refused"], ["dependency_operation:imp:import_module:json"])    # reviewed standard library: not recorded
        state.update(file_names={"/lib/imp.py": "imp"})
        for form, module in (("import_module", "os"), ("import", "json"), ("find_spec", "json")):
            with self.assertRaises(ImportError):
                gate(requester, form, module)
        self.assertEqual(report["violations"], ["undeclared_dependency_operation:imp:import_module:os",
                                                "undeclared_dependency_operation:imp:import:json",
                                                "undeclared_dependency_operation:imp:find_spec:json"])
        stranger = types.SimpleNamespace(f_code=types.SimpleNamespace(co_filename="/elsewhere.py"))
        with self.assertRaises(ImportError):
            gate(stranger, "import_module", "json")                                 # no pinned importer: never declarable
        self.assertEqual(report["violations"][-1], "undeclared_dependency_operation:None:import_module:json")
        report["violations"].clear()
        state.update(strict=False)                                                  # discovery records instead of refusing
        gate(requester, "import_module", "os")
        self.assertEqual((report["violations"], report["refused"][-1]), ([], "dependency_operation:imp:import_module:os"))
        state.update(strict=True, find_spec_file="/lib/imp.py")
        state["find_spec_depth"] = {namespace["_GET_IDENT"](): 1}
        gate(requester, "import", "os")                                             # the real find_spec's own request: decided with its call
        other = types.SimpleNamespace(f_code=types.SimpleNamespace(co_filename="/lib/other.py"))
        state["file_names"]["/lib/other.py"] = "other"
        with self.assertRaises(ImportError):
            gate(other, "import", "os")                                             # any other code during that call is judged on its own
        state["find_spec_depth"] = {}
        with self.assertRaises(ImportError):
            gate(requester, "import", "os")                                         # and outside the call nothing is suppressed
        self.assertIsInstance(namespace["_IMPORT_STATEMENT_OPCODE"], int)
        import dis
        self.assertEqual(namespace["_IMPORT_STATEMENT_OPCODE"], dis.opmap["IMPORT_NAME"])   # measured, and equal to the table

    def test_a_declaration_never_relaxes_the_closures_own_imports(self):
        fx = Fixture(self, helper="import yaml_unavailable_pkg\n\n\ndef decide(i):\n    return 'PASS'\n")
        self.assertRaisesCode("unpinned_import", pv.build_manifest, name="x", roots=fx.roots, entry_module="vc.main",
                              observation=observation(),
                              dependency_operations=[{"importer": "json", "form": "import", "module": "yaml_unavailable_pkg"}])
        main = (REACH_IMPORT + '\n\ndef verify(inputs, params):\n    try:\n        IMPORT("yaml_unavailable_pkg")\n'
                '    except ImportError:\n        pass\n    return {"status": "PASS"}\n')
        run = Fixture(self, main=main).build().run()
        self.assertRejected(run, "closure_runtime_violation:undeclared_import:yaml_unavailable_pkg", "closure")

    def test_dependency_operation_declarations_have_an_exact_bounded_shape(self):
        fx = Fixture(self).build()
        row = {"importer": "json", "form": "import", "module": "probe_00"}
        rows = [{**row, "module": "probe_%02d" % n} for n in range(pv.MAX_DEPENDENCY_OPERATIONS)]
        accepted = copy.deepcopy(fx.manifest)
        accepted["dependency_operations"] = rows
        pv.validate_manifest(accepted)                                         # exactly the maximum is valid
        self.assertEqual(pv.MAX_DEPENDENCY_OPERATIONS, 32)
        cases = {
            "too_many": rows + [{**row, "module": "probe_zz"}],
            "bad_form": [{**row, "form": "exec"}],
            "extra_key": [{**row, "note": "x"}],
            "missing_key": [{"importer": "json", "form": "import"}],
            "not_a_mapping": [["json", "import", "probe_00"]],
            "non_identifier": [{**row, "module": "probe-00"}],
            "non_ascii": [{**row, "module": "probé"}],
            "denylisted_module": [{**row, "module": "subprocess"}],
            "denylisted_submodule": [{**row, "module": "ctypes.util"}],
            "closure_owned_module": [{**row, "module": "vc.helper"}],
            "closure_owned_importer": [{**row, "importer": "vc.main"}],
            "unsorted": [{**row, "module": "probe_01"}, row],
            "duplicate": [row, dict(row)],
            "too_long": [{**row, "module": "m" * 120}],
            "not_a_list": {"json": "import"},
        }
        for label, value in cases.items():
            with self.subTest(label):
                changed = copy.deepcopy(fx.manifest)
                changed["dependency_operations"] = value
                with self.assertRaises(pv.ClosureRejected) as caught:
                    pv.validate_manifest(changed)
                self.assertEqual(caught.exception.code, "manifest_dependency_operations")
        missing = copy.deepcopy(fx.manifest)
        del missing["dependency_operations"]
        with self.assertRaises(pv.ClosureRejected) as caught:
            pv.validate_manifest(missing)
        self.assertEqual(caught.exception.code, "manifest_shape")

    def test_the_declared_operations_change_the_manifest_and_release_identity(self):
        fx, roots, packages = self.dependency_fixture(self.OPTIONAL_PROBES)
        fx.build(roots=roots, packages=packages, dependency_operations=list(self.PROBE_OPERATIONS))
        stripped, stripped_digest = retarget(fx.manifest, lambda m: m.__setitem__("dependency_operations", []))
        self.assertNotEqual(stripped_digest, fx.digest)
        self.assertNotEqual(pv.release_digest(stripped), fx.release)
        self.assertRaisesCode("manifest_digest_mismatch", fx.verify, stripped, fx.digest)

    def test_a_receipt_that_records_an_attempt_the_manifest_did_not_declare_is_refused(self):
        fx, roots, packages = self.dependency_fixture(self.OPTIONAL_PROBES)
        fx.build(roots=roots, packages=packages, dependency_operations=list(self.PROBE_OPERATIONS))
        run = fx.run(roots=roots)
        self.assertEqual(run.status, "PASS", run.receipt)
        forged = copy.deepcopy(run.receipt)
        forged["refused"] = sorted([*forged["refused"], "dependency_operation:authdep:import:other_unavailable_pkg"])
        reseal(forged)
        base = dict(expected_manifest_sha256=fx.digest, expected_release_sha256=fx.release, manifest=fx.manifest, require_acceptance=False)
        self.assertEqual(pv.verify_receipt(run.receipt, **base), "PASS")
        with self.assertRaises(pv.ClosureRejected) as caught:
            pv.verify_receipt(forged, **base)
        self.assertEqual((caught.exception.code, caught.exception.detail), ("receipt_manifest_mismatch", "dependency_operations"))
        informational = copy.deepcopy(run.receipt)
        informational["refused"] = ["unpinned_import:other_unavailable_pkg"]               # the retired informational form
        reseal(informational)
        with self.assertRaises(pv.ClosureRejected) as caught:
            pv.verify_receipt(informational, **base)
        self.assertEqual(caught.exception.code, "receipt_manifest_mismatch")

    def test_import_of_an_already_cached_module_still_requires_the_importers_approval(self):
        """``os`` is preloaded, so the import system never consults the finder for it: the per-module ``__import__``
        guard is what enforces the approval list for cache hits (this is the 'cached-import approval' contract)."""
        main = ('import os\nfrom . import helper\n\n\ndef verify(inputs, params):\n'
                '    return {"status": helper.decide(inputs), "sep": os.sep}\n')
        fx = Fixture(self, main=main).build()
        self.assertEqual(fx.run().status, "PASS")
        verified = fx.verify(work=str(fx.work))
        self.assertTrue(any("os" in row[4] for row in verified.sites["vc.main"]))
        verified.sites["vc.main"] = [[*row[:4], [n for n in row[4] if n != "os"]] for row in verified.sites["vc.main"]]
        execution, nonce, header, _ = pv._launch(verified, {"doc": b"good"}, None, "run", 120.0, str(fx.work))
        report = pv._accept_report(execution, nonce, header, verified, "run")
        self.assertIn("undeclared_import:os", report["violations"])
        self.assertNotIn("vc.main", report["loaded"]["closure"])

    def test_importlib_inside_a_closure_is_a_checked_literal_only_proxy(self):
        main = ('import importlib\n\nPROXY = vars()["importlib"]\n\n\ndef verify(inputs, params):\n'
                '    importlib.import_module("json")\n'
                '    try:\n        PROXY.import_module(params["name"])\n    except ImportError:\n        pass\n'
                '    return {"status": "PASS", "proxy": type(PROXY).__name__, "util": getattr(PROXY, "util", None) is not None}\n')
        fx = Fixture(self, main=main).build(dynamic=[{"module": "vc.main", "target": "json"}])
        # A non-literal dynamic call is not part of the supported language: even the approved name is refused when the
        # call is not the recorded literal site (the previous behaviour, PASS, is the contradiction this replaces).
        for name in ("json", "os"):
            refused = fx.run(params={"name": name})
            self.assertRejected(refused, "closure_runtime_violation:undeclared_import:" + name, "closure")
            self.assertEqual(refused.receipt["violations"], ["undeclared_import:" + name])
        relative = fx.run(params={"name": ".helper"})
        self.assertRejected(relative, "closure_runtime_violation:dynamic_import_not_literal:importlib", "closure")
        literal_only = MAIN_IMPORTLIB_LITERAL
        pure = Fixture(self, main=literal_only).build(dynamic=[{"module": "vc.main", "target": "json"}])
        run = pure.run()
        self.assertEqual((run.status, run.reason), ("PASS", "ok"), run.receipt)
        self.assertEqual(run.receipt["verifier"]["result"]["proxy"], "_ImportlibProxy")
        self.assertFalse(run.receipt["verifier"]["result"]["util"])           # no importlib.util / machinery / sys access
        verified = pure.verify(work=str(pure.work))
        verified.sites["vc.main"] = [[*row[:4], [n for n in row[4] if n != "json"]] for row in verified.sites["vc.main"]]  # approval withdrawn
        execution, nonce, header, _ = pv._launch(verified, {}, None, "run", 120.0, str(pure.work))
        report = pv._accept_report(execution, nonce, header, verified, "run")
        self.assertIn("undeclared_import:json", report["violations"])

    def test_a_literal_import_site_approves_only_its_exact_call_position(self):
        """Approval is per call identity (line, end line, column, end column), not per module or per line range: a second
        call to the same approved name executed anywhere else -- another line, or the same line -- is refused, while a
        multi-line approved call is a working positive."""
        head = 'import importlib\n\nPROXY = vars()["importlib"]\n\n\ndef verify(inputs, params):\n'
        tail = '    return {"status": "PASS"}\n'
        dynamic = [{"module": "vc.main", "target": "json"}]
        other_line = head + '    importlib.import_module("json")\n    PROXY.import_module("json")\n' + tail
        same_line = head + '    importlib.import_module("json"); PROXY.import_module("json")\n' + tail
        for label, main in (("other_line", other_line), ("same_line", same_line)):
            run = Fixture(self, main=main).build(dynamic=dynamic).run()
            self.assertRejected(run, "closure_runtime_violation:undeclared_import:json", "closure")
            self.assertEqual(run.receipt["violations"], ["undeclared_import:json"], label)
        multiline = head + '    importlib.import_module(\n        "json",\n    )\n' + tail
        run = Fixture(self, main=multiline).build(dynamic=dynamic).run()
        self.assertEqual((run.status, run.reason), ("PASS", "ok"), run.receipt)

    def test_a_callee_split_across_lines_is_a_static_layout_rejection(self):
        source = ('import importlib\n\n\ndef verify(inputs, params):\n'
                  '    importlib.\\\n        import_module("json")\n    return {"status": "PASS"}\n')
        scan = pv.scan_source(source.encode(), "vc.main", False)
        self.assertIn("dynamic_import_layout:importlib.import_module", scan.rejections)
        self.assertEqual(scan.dynamic, [])
        same_line = source.replace("importlib.\\\n        import_module", "importlib.import_module")
        clean = pv.scan_source(same_line.encode(), "vc.main", False)
        self.assertEqual((clean.rejections, clean.dynamic), ([], ["json"]))

    def test_static_and_runtime_denied_import_policies_are_the_same_set(self):
        import ast
        tree = ast.parse((REPO / "trace_gc/verifier_closure_bootstrap.py").read_text(encoding="utf-8"))
        denied = None
        for node in tree.body:
            if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "DENIED_IMPORTS" for t in node.targets):
                denied = ast.literal_eval(node.value)
        self.assertIsNotNone(denied)
        self.assertEqual(set(denied), set(pv.FORBIDDEN_MODULES))
        self.assertTrue({"builtins", "msvcrt", "ctypes", "subprocess"} <= set(denied))

    def test_closure_is_served_from_captured_bytes_without_file_or_cache_attributes(self):
        main = ('from . import helper\n\nMODULE = vars()\n\n\ndef verify(inputs, params):\n'
                '    spec = MODULE["__spec" + "__"]\n'
                '    return {"status": "PASS", "has_file": "__file__" in MODULE, "has_cached": "__cached__" in MODULE,\n'
                '            "origin": spec.origin, "loader": type(spec.loader).__name__}\n')
        result = Fixture(self, main=main).build().run()
        self.assertEqual(result.status, "PASS", result.receipt)
        value = result.receipt["verifier"]["result"]
        self.assertFalse(value["has_file"] or value["has_cached"])
        self.assertEqual((value["origin"], value["loader"]), ("closure:vc/vc/main.py", "_Loader"))


# ---------------------------------------------------------------------------------------------------
# 6. Mutation, input capture, timeout, process cleanup and the strict result protocol.

class MutationInputsAndProcesses(RejectionMixin, unittest.TestCase):
    def test_closure_mutated_during_execution_is_rejected_even_if_the_verifier_returns_pass(self):
        main = ('from . import helper\n\n\ndef verify(inputs, params):\n    with open(params["target"], "ab") as stream:\n'
                '        stream.write(b"\\n# changed while running\\n")\n    return {"status": "PASS"}\n')
        fx = Fixture(self, main=main).build()
        run = fx.run(params={"target": str(fx.root / "vc/helper.py")})
        self.assertRejected(run, "closure_module_changed_during_execution:vc.helper", "closure")
        self.assertEqual(run.receipt["post_checks"]["closure_unchanged"], False)

    def test_replace_execute_restore_cannot_change_what_executed(self):
        """Pre/post hashes alone cannot exclude this; execution uses captured bytes, so the restored file is irrelevant."""
        main = ('import os\nfrom . import helper\n\n\ndef verify(inputs, params):\n    target = params["target"]\n'
                '    original = open(target, "rb").read()\n    open(target, "wb").write(b"def decide(inputs):\\n    return \\"PASS\\"\\n")\n'
                '    open(target, "wb").write(original)\n    return {"status": helper.decide(inputs)}\n')
        fx = Fixture(self, main=main, helper=HELPER_HOLD).build()
        run = fx.run(params={"target": str(fx.root / "vc/helper.py")})
        self.assertEqual((run.status, run.reason), ("HOLD", "verifier_hold"), run.receipt)
        self.assertEqual(run.receipt["loaded"]["closure"]["vc.helper"], sha(HELPER_HOLD.encode()))

    def test_input_mutated_during_execution_is_rejected(self):
        main = ('from . import helper\n\n\ndef verify(inputs, params):\n    with open(params["target"], "ab") as stream:\n'
                '        stream.write(b"!")\n    return {"status": "PASS"}\n')
        fx = Fixture(self, main=main).build()
        self.assertRejected(fx.run(params={"target": str(fx.data / "doc.txt")}), "input_changed_during_execution:doc", "input")

    def test_params_are_bound_and_must_be_canonical(self):
        fx = Fixture(self).build()
        run = fx.run(params={"threshold": 3, "labels": ["a", "b"], "ratio": 0.5})
        self.assertEqual(run.receipt["params_sha256"], pv.canonical_digest({"threshold": 3, "labels": ["a", "b"], "ratio": 0.5}))
        for bad in ({"x": float("nan")}, {"x": 2 ** 60}, {"x": object()}):
            self.assertRejected(fx.run(params=bad), "params_not_canonical", "input")

    def test_input_identity_is_captured_once_and_verified(self):
        fx = Fixture(self).build()
        bad = {"doc": pv.InputSpec(fx.data, "doc.txt", sha(b"other"))}
        self.assertRejected(fx.run(inputs=bad), "input_hash_mismatch:doc", "input")
        escaping = {"doc": pv.InputSpec(fx.data, "../closure/vc/main.py", sha(b"x"))}
        escaped = fx.run(inputs=escaping)
        self.assertRejected(escaped, "input_path_invalid", "input")
        self.assertIsNone(escaped.receipt["process"])                         # refused before any interpreter or child
        self.assertRejected(fx.run(inputs={"bad name": pv.InputSpec(fx.data, "doc.txt", sha(b"good"))}), "input_name_invalid", "input")
        run = fx.run()
        self.assertEqual(run.receipt["inputs"], {"doc": {"sha256": sha(b"good"), "bytes": 4}})
        self.assertEqual(run.receipt["verifier"]["result"]["doc_sha256"], sha(b"good"))

    def test_bytecode_written_into_the_fresh_prefix_is_detected(self):
        main = ('import os\nfrom . import helper\n\n\ndef verify(inputs, params):\n'
                '    for prefix in [n for n in os.listdir(params["work"]) if n.startswith("pvc-bytecode-")]:\n'
                '        with open(os.path.join(params["work"], prefix, "x.pyc"), "wb") as stream:\n            stream.write(b"x")\n'
                '    return {"status": "PASS"}\n')
        fx = Fixture(self, main=main).build()
        self.assertRejected(fx.run(params={"work": str(fx.work)}), "bytecode_written_during_execution")

    def test_timeout_is_a_rejection_not_a_hold_and_the_process_is_gone(self):
        main = ('import os\nimport time\nfrom . import helper\n\n\ndef verify(inputs, params):\n'
                '    with open(params["pidfile"], "w") as stream:\n        stream.write(str(os.getpid()))\n    time.sleep(120)\n')
        fx = Fixture(self, main=main).build()
        pidfile = fx.tmp / "pid.txt"
        started = time.monotonic()
        run = fx.run(params={"pidfile": str(pidfile)}, timeout=15)
        self.assertRejected(run, "execution_timeout", "execution")
        self.assertTrue(run.receipt["process"]["timed_out"])
        self.assertIsNone(run.receipt["verifier"])
        self.assertLess(time.monotonic() - started, 120)
        pid = int(pidfile.read_text())
        deadline = time.monotonic() + 10
        while alive(pid) and time.monotonic() < deadline:
            time.sleep(0.2)
        self.assertFalse(alive(pid))

    def _tree_program(self, pidfile: Path, exit_first: bool) -> str:
        return ("import subprocess, sys, time\n"
                "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'])\n"
                "open(sys.argv[1], 'w').write(str(child.pid))\n"
                + ("" if exit_first else "time.sleep(120)\n"))

    def _wait_pid(self, pidfile: Path) -> int:
        deadline = time.monotonic() + 30
        while not (pidfile.exists() and pidfile.read_text()) and time.monotonic() < deadline:
            time.sleep(0.1)
        return int(pidfile.read_text())

    def test_containment_kills_the_whole_process_tree_on_timeout(self):
        tmp = Path(tempfile.mkdtemp(prefix="pvc-tree-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        pidfile = tmp / "grandchild.txt"
        result = pv._execute([sys.executable, "-c", self._tree_program(pidfile, False), str(pidfile)], str(tmp), b"", 6.0, 1 << 16, 1 << 16)
        self.assertTrue(result.timed_out)
        grandchild = self._wait_pid(pidfile)
        deadline = time.monotonic() + 15
        while alive(grandchild) and time.monotonic() < deadline:
            time.sleep(0.2)
        self.assertFalse(alive(grandchild))

    def test_descendant_that_outlives_the_child_is_reported_and_killed(self):
        tmp = Path(tempfile.mkdtemp(prefix="pvc-orphan-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        pidfile = tmp / "grandchild.txt"
        result = pv._execute([sys.executable, "-c", self._tree_program(pidfile, True), str(pidfile)], str(tmp), b"", 60.0, 1 << 16, 1 << 16)
        self.assertEqual(result.returncode, 0)
        self.assertTrue(result.descendants)
        grandchild = self._wait_pid(pidfile)
        deadline = time.monotonic() + 15
        while alive(grandchild) and time.monotonic() < deadline:
            time.sleep(0.2)
        self.assertFalse(alive(grandchild))

    def test_output_overflow_is_bounded_and_rejected(self):
        tmp = Path(tempfile.mkdtemp(prefix="pvc-flood-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        result = pv._execute([sys.executable, "-c", "import sys\nwhile True:\n    sys.stdout.write('x' * 65536)\n    sys.stdout.flush()"],
                             str(tmp), b"", 60.0, 1 << 16, 1 << 16)
        self.assertEqual(result.overflow, "stdout")
        self.assertLessEqual(len(result.stdout), 1 << 16)

    def _execution(self, stdout: bytes, **kwargs):
        return pv.Execution(returncode=kwargs.pop("returncode", 0), stdout=stdout, **kwargs)

    def test_report_must_be_one_strict_json_line_bound_to_this_request(self):
        fx = Fixture(self).build()
        verified = fx.verify(work=str(fx.work))
        execution, nonce, header, _ = pv._launch(verified, {}, None, "run", 120.0, str(fx.work))
        good = pv._accept_report(execution, nonce, header, verified, "run")
        self.assertEqual(good["result"]["status"] if good["result"] else None, "PASS" if good["result"] else None)
        line = [l for l in execution.stdout.split(b"\n") if l][0]
        body = line[len((pv.RESULT_PREFIX + nonce + " ").encode()):]

        def reject(stdout, code, **kwargs):
            with self.assertRaises(pv.ClosureRejected) as caught:
                pv._accept_report(self._execution(stdout, **kwargs), nonce, header, verified, "run")
            self.assertTrue(caught.exception.code.startswith(code), caught.exception.code)
        prefix = (pv.RESULT_PREFIX + nonce + " ").encode()
        reject(b"", "protocol_no_valid_result")
        reject(line + b"\n" + line + b"\n", "protocol_no_valid_result")          # two result lines
        reject(b"noise\n" + line + b"\n", "protocol_no_valid_result")             # unexpected extra output
        reject((pv.RESULT_PREFIX + "0" * 32 + " ").encode() + body + b"\n", "protocol_no_valid_result")   # other nonce
        reject(prefix + body[:-1] + b",\"nonce\":\"x\"}\n", "protocol_no_valid_result")                    # duplicate key
        reject(prefix + b"{" + body[1:].replace(b'"status"', b'"status"', 1)[:-1] + b",}\n", "protocol_no_valid_result")  # malformed
        reject(prefix + b'{"nonce": NaN}\n', "protocol_no_valid_result")
        reject(prefix + b"[]\n", "protocol_no_valid_result")
        reject(prefix + body + b" " * (pv.MAX_REPORT_BYTES + 1) + b"\n", "protocol_no_valid_result")
        reject(line + b"\n", "protocol_exit_status", returncode=3)
        reject(line + b"\n", "execution_timeout", timed_out=True)
        reject(line + b"\n", "protocol_output_overflow", overflow="stdout")
        reject(line + b"\n", "containment_unresolved_descendants", descendants=True)
        reject(line + b"\n", "execution_launch_failed", launch_error="child_launch_failed")
        forged = json.loads(body)
        for key, value in (("header_sha256", "0" * 64), ("manifest_sha256", "0" * 64), ("release_sha256", "0" * 64),
                           ("entry", ["vc.other", "verify"]), ("mode", "import"), ("protocol", "other")):
            changed = dict(forged, **{key: value})
            reject(prefix + json.dumps(changed).encode() + b"\n", "protocol_")
        extra = dict(forged, surplus=1)
        reject(prefix + json.dumps(extra).encode() + b"\n", "protocol_report_shape")
        with self.assertRaises(pv.ClosureRejected):
            pv._accept_report(execution, "f" * 32, header, verified, "run")              # wrong expected nonce
        with self.assertRaises(pv.ClosureRejected):
            pv._accept_report(execution, nonce, "f" * 64, verified, "run")               # wrong expected header

    def test_each_run_uses_a_fresh_nonce_and_binds_arguments_into_the_request(self):
        fx = Fixture(self).build()
        one, two = fx.run(params={"a": 1}), fx.run(params={"a": 2})
        self.assertNotEqual(one.receipt["request"]["nonce"], two.receipt["request"]["nonce"])
        self.assertNotEqual(one.receipt["request"]["header_sha256"], two.receipt["request"]["header_sha256"])
        self.assertNotEqual(one.receipt["binding_sha256"], two.receipt["binding_sha256"])

    def test_invalid_timeouts_are_rejected_before_any_interpreter_census_or_child_exists(self):
        fx = Fixture(self).build()
        for bad in (0, -1, 0.0, float("nan"), float("inf"), -float("inf"), True, False, "5", None, [5], pv.MAX_TIMEOUT + 1):
            with mock.patch.object(pv, "probe_runtime", side_effect=AssertionError("interpreter probe started")) as probe, \
                    mock.patch.object(pv, "runtime_census", side_effect=AssertionError("census started")), \
                    mock.patch.object(pv.subprocess, "Popen", side_effect=AssertionError("process started")):
                run = fx.run(timeout=bad)
            probe.assert_not_called()
            self.assertRejected(run, "invalid_arguments", "arguments")
            self.assertIsNone(run.receipt["process"], repr(bad))
            self.assertIsNone(run.receipt["runtime"], repr(bad))
            self.assertIsNone(run.receipt["verifier"], repr(bad))
            pv.validate_receipt(run.receipt)
            with mock.patch.object(pv.subprocess, "Popen", side_effect=AssertionError("process started")):
                self.assertRaisesCode("invalid_arguments", pv._execute, [sys.executable, "-c", "pass"], str(fx.tmp), b"", bad, 1024, 1024)
        self.assertEqual(pv.validate_timeout(120), 120.0)
        self.assertEqual(pv.validate_timeout(pv.MAX_TIMEOUT), pv.MAX_TIMEOUT)
        self.assertEqual(fx.run(timeout=60).status, "PASS")

    def test_timeout_validation_is_total_and_a_positive_timeout_is_never_recorded_as_zero_milliseconds(self):
        for huge in (10 ** 400, -(10 ** 400), 10 ** 309, 2 ** 2000):
            self.assertRaisesCode("invalid_arguments", pv.validate_timeout, huge)             # not OverflowError
            self.assertRaisesCode("invalid_arguments", pv.timeout_ms, huge)
        fx = Fixture(self).build()
        with mock.patch.object(pv, "probe_runtime", side_effect=AssertionError("interpreter probe started")), \
                mock.patch.object(pv.subprocess, "Popen", side_effect=AssertionError("process started")):
            run = fx.run(timeout=10 ** 400)
        self.assertRejected(run, "invalid_arguments", "arguments")
        for seconds, expected in ((1e-9, 1), (0.0004, 1), (0.001, 1), (0.0011, 2), (0.5, 500), (120, 120000),
                                  (pv.MAX_TIMEOUT, pv.MAX_TIMEOUT_MS)):
            self.assertEqual(pv.timeout_ms(seconds), expected, seconds)
        for bad in (0, -0.0):
            self.assertRaisesCode("invalid_arguments", pv.timeout_ms, bad)

    def test_the_launch_command_is_bounded_ascii_and_never_carries_the_bootstrap(self):
        bootstrap = (REPO / "trace_gc" / "verifier_closure_bootstrap.py").read_bytes()
        digest = sha(bootstrap)
        command = pv._interpreter_command(sys.executable, os.path.join(tempfile.gettempdir(), "pvc-prefix"), digest)
        self.assertLessEqual(pv._command_units(command), pv.MAX_COMMAND_UNITS)
        self.assertTrue(command[-1].isascii())
        self.assertIn(digest, command[-1])
        self.assertNotIn(bootstrap[:200].decode("utf-8"), command[-1])
        self.assertEqual(command[-2], "-c")
        self.assertEqual(pv.CONTRACT["launch"]["stub_sha256"], pv._sha_text(pv.STUB_TEMPLATE))
        self.assertRaisesCode("execution_command_too_long", pv._interpreter_command, "x" * (pv.MAX_COMMAND_UNITS + 1),
                              "prefix", digest)
        for bad in ("", "xyz", digest.upper(), digest[:-1]):
            self.assertRaisesCode("bootstrap_digest_invalid", pv._interpreter_command, sys.executable, "prefix", bad)
        self.assertEqual(pv._bootstrap_stream(b"abc", b"PVCPROBE"), (3).to_bytes(8, "big") + b"abcPVCPROBE")
        for bad in (b"", b"x" * (pv.MAX_BOOTSTRAP_BYTES + 1)):
            self.assertRaisesCode("bootstrap_size_invalid", pv._bootstrap_stream, bad, b"")

    def test_the_stub_executes_only_bootstrap_bytes_matching_the_embedded_digest(self):
        good = b"import sys\nsys.stdout.write('ran:' + _PVC_BOOTSTRAP_SHA256)\n"

        def start(digest, stream):
            command = pv._interpreter_command(sys.executable, str(self.scratch()), digest)
            return subprocess.run(command, input=stream, capture_output=True, timeout=120, cwd=str(self.scratch()))
        ran = start(sha(good), pv._bootstrap_stream(good, b""))
        self.assertEqual((ran.returncode, ran.stdout), (0, b"ran:" + sha(good).encode()), ran.stderr)
        wrong = start(sha(good), pv._bootstrap_stream(good + b"# tampered\n", b""))
        self.assertEqual((wrong.returncode, wrong.stdout), (72, b""))                              # digest mismatch: nothing ran
        oversize = start(sha(good), (pv.MAX_BOOTSTRAP_BYTES + 1).to_bytes(8, "big"))
        self.assertEqual((oversize.returncode, oversize.stdout), (71, b""))
        truncated = start(sha(good), len(good).to_bytes(8, "big") + good[:5])
        self.assertEqual((truncated.returncode, truncated.stdout), (70, b""))
        silent = start(sha(good), b"")
        self.assertEqual((silent.returncode, silent.stdout), (70, b""))

    def scratch(self) -> Path:
        directory = Path(tempfile.mkdtemp(prefix="pvc-stub-"))
        self.addCleanup(shutil.rmtree, directory, True)
        return directory

    def test_every_caller_argument_is_captured_once_before_verification_begins(self):
        """Mutating the caller's manifest, roots, inputs or params while the run is in progress changes nothing."""
        main = 'from . import helper\n\n\ndef verify(inputs, params):\n    return {"status": "PASS", "params": params}\n'
        fx = Fixture(self, main=main).build()
        original_params = {"threshold": 3, "labels": ["a"]}
        params = copy.deepcopy(original_params)
        manifest = copy.deepcopy(fx.manifest)
        roots = {"vc": fx.root}
        inputs = fx.inputs()
        original = pv.verify_closure

        def mutate_then_verify(*args, **kwargs):
            params["threshold"] = 99
            params["labels"].append("evil")
            manifest["modules"].clear()
            manifest["name"] = "changed"
            roots["vc"] = fx.tmp / "nowhere"
            roots["extra"] = fx.tmp
            inputs["doc"] = pv.InputSpec(fx.data, "doc.txt", sha(b"other"))
            inputs["more"] = pv.InputSpec(fx.data, "doc.txt", sha(b"good"))
            return original(*args, **kwargs)
        with mock.patch.object(pv, "verify_closure", side_effect=mutate_then_verify):
            # Argument capture is the subject here, not acceptance: the explicit diagnostic opt-out keeps this a
            # PASS/diagnostic run; the required protected positive is RuntimeProtectionGate.
            run = pv.run_verifier(manifest, fx.digest, expected_release_sha256=fx.release, roots=roots, inputs=inputs,
                                  params=params, work_dir=fx.work, allow_unprotected_runtime=True)
        self.assertEqual((run.status, run.reason), ("PASS", "ok"), run.receipt)
        self.assertEqual(run.receipt["params_sha256"], pv.canonical_digest(original_params))
        self.assertEqual(run.receipt["verifier"]["result"]["params"], original_params)
        self.assertEqual(set(run.receipt["inputs"]), {"doc"})
        self.assertEqual(run.receipt["inputs"]["doc"]["sha256"], sha(b"good"))

    def test_input_specs_and_roots_with_the_wrong_types_are_argument_errors(self):
        fx = Fixture(self).build()
        for label, kwargs in (("roots_type", {"roots": ["vc"]}), ("roots_empty", {"roots": {}}),
                              ("inputs_type", {"inputs": [("doc", "x")]}), ("input_spec_type", {"inputs": {"doc": "x"}}),
                              ("python_type", {"python": 5}), ("flag_type", {"embed_result": "yes"})):
            run = fx.run(**kwargs)
            self.assertEqual(run.status, "REJECTED", label)
            self.assertIsNone(run.receipt["process"], label)
            pv.validate_receipt(run.receipt)

    def _spied_execute(self, argv, tmp, frame=b"frame", timeout=20.0):
        """``_execute`` with an ordered event log: process creation, attach outcome, and every write to the child's stdin."""
        real_popen, real_write, real_attach = subprocess.Popen, os.write, pv._Containment.attach
        events, stdin_fds, commands, started = [], set(), [], []

        def spy(*args, **kwargs):
            commands.append(list(args[0]))
            process = real_popen(*args, **kwargs)
            stdin_fds.add(process.stdin.fileno())
            started.append(process)
            events.append("created")
            return process

        def record(fd, data):
            if fd in stdin_fds:
                events.append(("stdin", len(data)))
            return real_write(fd, data)

        def attach(contain, process, limit=10.0):
            try:
                return real_attach(contain, process, limit)
            finally:
                events.append("attach_returned")
        with mock.patch.object(pv._Containment, "attach", autospec=True, side_effect=attach), \
                mock.patch.object(pv.subprocess, "Popen", side_effect=spy), mock.patch.object(pv.os, "write", side_effect=record):
            result = pv._execute(argv, str(tmp), frame, timeout, 1 << 16, 1 << 16)
        return result, events, commands, started

    def test_no_request_byte_is_written_before_attach_returns_and_the_supervisor_arms_first(self):
        tmp = Path(tempfile.mkdtemp(prefix="pvc-attach-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        fine, events, commands, _ = self._spied_execute([sys.executable, "-c", "import sys; sys.stdin.buffer.read()"], tmp)
        self.assertEqual((fine.returncode, fine.launch_error, fine.cleanup_failed, fine.descendants), (0, None, False, False))
        self.assertEqual(events[:2], ["created", "attach_returned"])
        self.assertEqual(sum(e[1] for e in events if isinstance(e, tuple)), 5)
        if sys.platform.startswith("linux"):
            self.assertEqual(fine.containment, "subreaper")
            self.assertEqual(commands[0][:1], [sys.executable])
            self.assertEqual(commands[0][-2], "-c")
            self.assertIn("prctl(36,1,0,0,0)", commands[0][-1])          # the supervisor program is what the host launches
        else:
            self.assertEqual(fine.containment, "job_object")             # Windows: created suspended, assigned, then resumed

    @unittest.skipUnless(sys.platform.startswith("linux"), "the supervisor is the Linux containment")
    def test_an_unarmed_supervisor_means_no_frame_a_killed_process_and_an_exact_attach_failure(self):
        """A supervisor that never reports readiness but still answers the purge request: attach fails, the frame is never
        written, the process is reaped, cleanup is verified, and the report is the exact attach failure."""
        tmp = Path(tempfile.mkdtemp(prefix="pvc-unarmed-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        fake = ("import os,time\n_A=%(argv)s\n_R=%(ctl)d\n_W=%(st)d\n_G=%(grace)s\ntime.sleep(0.3)\n"
                "while True:\n c=os.read(_R,1)\n if c==b'K':\n  os.write(_W,b'K0 0\\n')\n else:\n  os._exit(0)\n")
        with mock.patch.object(pv, "SUPERVISOR_TEMPLATE", fake), mock.patch.object(pv, "CONTAIN_START", 1.0), \
                mock.patch.object(pv, "CLEANUP_GRACE", 2.0), mock.patch.object(pv, "SUPERVISOR_PURGE", 0.5):
            failed, events, _, started = self._spied_execute([sys.executable, "-c", "import sys; sys.stdin.buffer.read()"], tmp)
        self.assertEqual(failed.launch_error, "containment_attach_failed")
        self.assertFalse(failed.cleanup_failed)
        self.assertEqual(failed.stdout, b"")
        self.assertEqual([e for e in events if isinstance(e, tuple)], [])        # no verifier byte reached an unarmed supervisor
        self.assertIsNotNone(started[0].poll())
        self.assertFalse(alive(started[0].pid))
        report = self.assertRaisesCode("containment_attach_failed", pv._accept_report, failed, "0" * 32, "0" * 64, None, "run")
        self.assertEqual(pv.failure_class(report.code), "containment")

    @unittest.skipUnless(sys.platform.startswith("linux"), "the supervisor is the Linux containment")
    def test_an_unarmed_and_unresponsive_supervisor_is_killed_and_cleanup_is_reported_failed(self):
        tmp = Path(tempfile.mkdtemp(prefix="pvc-mute-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        fake = "import time\n_A=%(argv)s\n_R=%(ctl)d\n_W=%(st)d\n_G=%(grace)s\ntime.sleep(120)\n"
        with mock.patch.object(pv, "SUPERVISOR_TEMPLATE", fake), mock.patch.object(pv, "CONTAIN_START", 1.0), \
                mock.patch.object(pv, "CLEANUP_GRACE", 1.0), mock.patch.object(pv, "SUPERVISOR_PURGE", 0.5):
            mute, events, _, started = self._spied_execute([sys.executable, "-c", "pass"], tmp)
        self.assertEqual(mute.launch_error, "containment_attach_failed")
        self.assertTrue(mute.cleanup_failed)                                     # nothing could confirm that the run is empty
        self.assertEqual([e for e in events if isinstance(e, tuple)], [])
        deadline = time.monotonic() + 10
        while alive(started[0].pid) and time.monotonic() < deadline:
            time.sleep(0.1)
        self.assertFalse(alive(started[0].pid))                                  # the silent supervisor itself was killed
        self.assertRaisesCode("containment_cleanup_failed", pv._accept_report, mute, "0" * 32, "0" * 64, None, "run")

    @unittest.skipUnless(sys.platform.startswith("linux"), "the supervisor is the Linux containment")
    def test_a_supervisor_that_vanishes_after_arming_is_observed_and_never_accepted(self):
        tmp = Path(tempfile.mkdtemp(prefix="pvc-lost-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        fake = "import os\n_A=%(argv)s\n_R=%(ctl)d\n_W=%(st)d\n_G=%(grace)s\nos.write(_W,b'R12345\\n')\nos._exit(0)\n"
        with mock.patch.object(pv, "SUPERVISOR_TEMPLATE", fake), mock.patch.object(pv, "CLEANUP_GRACE", 2.0), \
                mock.patch.object(pv, "SUPERVISOR_PURGE", 0.5):
            lost, _, _, _ = self._spied_execute([sys.executable, "-c", "pass"], tmp)
        self.assertTrue(lost.descendants)                                        # nothing can say the run is empty: uncertain
        self.assertTrue(lost.cleanup_failed)
        self.assertIsNone(lost.returncode)
        self.assertRaisesCode("containment_cleanup_failed", pv._accept_report, lost, "0" * 32, "0" * 64, None, "run")

    @staticmethod
    def _dispose(contain, process):
        """Kill, reap and close what a test adopted: the containment owns it once ``adopt`` ran."""
        with contextlib.suppress(Exception):
            contain.reap(process, 10.0)
        contain.close(process)
        for stream in (process.stdin, process.stdout, process.stderr):
            with contextlib.suppress(OSError, ValueError):
                stream.close()

    def _adopted_supervisor(self, tmp, argv):
        """A real Linux launch attempt created synchronously (no deadline race) and adopted by a containment."""
        attempt = pv._LaunchAttempt(argv, str(tmp), windows=False)
        attempt._create()
        self.assertEqual((attempt.state, attempt.error), ("running", None))
        contain = pv._Containment(str(tmp))
        contain.adopt(attempt)
        self.addCleanup(self._dispose, contain, attempt.process)
        return attempt, contain, attempt.process

    @unittest.skipUnless(sys.platform.startswith("linux"), "the supervisor is the Linux containment")
    def test_the_supervisor_runs_isolated_with_a_private_empty_bytecode_directory_and_a_cached_file_is_a_cleanup_failure(self):
        tmp = Path(tempfile.mkdtemp(prefix="pvc-supcache-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        attempt, contain, process = self._adopted_supervisor(tmp, [sys.executable, "-c", "pass"])
        command = list(process.args)
        self.assertEqual(command[:1], [sys.executable])
        self.assertEqual(command[1:1 + len(pv.INTERPRETER_FLAGS)], list(pv.INTERPRETER_FLAGS))
        prefix = next(a for a in command if a.startswith("pycache_prefix="))[len("pycache_prefix="):]
        self.assertEqual(prefix, attempt.prefix)
        self.assertEqual(command[command.index("-X", len(pv.INTERPRETER_FLAGS)) + 1], "pycache_prefix=" + prefix)
        self.assertEqual(os.listdir(prefix), [])
        self.assertNotEqual(os.path.realpath(prefix), os.path.realpath(str(tmp)))
        self.assertEqual(contain._sup_identity, attempt.prefix_identity)         # the directory is owned by its creation identity
        self.assertTrue(contain.supervisor_cache_clean())
        Path(prefix, "ghost.cpython-3.pyc").write_bytes(b"cached")
        self.assertFalse(contain.supervisor_cache_clean())                       # an executable representation appeared
        shutil.rmtree(prefix)
        self.assertFalse(contain.supervisor_cache_clean())                       # an unreadable directory is never "clean"

    @unittest.skipUnless(sys.platform.startswith("linux"), "the supervisor is the Linux containment")
    def test_the_supervisor_owns_the_verifier_by_kernel_parenthood_and_answers_its_protocol(self):
        tmp = Path(tempfile.mkdtemp(prefix="pvc-protocol-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        _attempt, contain, process = self._adopted_supervisor(tmp, [sys.executable, "-c", "import sys; sys.stdin.buffer.read()"])
        try:
            contain.attach(process, 30.0)
            child = contain._state["child"]
            self.assertNotEqual(child, process.pid)
            fields = Path("/proc/%d/stat" % child).read_bytes().rpartition(b")")[2].split()
            self.assertEqual(int(fields[1]), process.pid)                       # the verifier is the supervisor's child
            self.assertEqual(contain.wait_exit(process), (False, None))
            self.assertTrue(contain.survivors(process))                          # the blocked verifier is a live member
            process.stdin.close()
            self.assertTrue(contain._wait(lambda s: s["exited"], 30.0))
            self.assertEqual(contain.wait_exit(process), (True, 0))
            self.assertFalse(contain.survivors(process))                         # exited and nothing left: empty and inspected
            self.assertTrue(contain.reap(process, 10.0))
            self.assertEqual(process.returncode, 0)                              # the supervisor itself ended normally
        finally:
            contain.close(process)
            for stream in (process.stdin, process.stdout, process.stderr):
                with contextlib.suppress(OSError, ValueError):
                    stream.close()

    @unittest.skipUnless(sys.platform.startswith("linux"), "the supervisor is the Linux containment")
    def test_survivor_answers_are_uncertain_unless_the_supervisor_reports_an_empty_inspected_run(self):
        contain = pv._Containment("/nonexistent-cwd")
        process = mock.Mock()
        for reply, expected in ((None, True), ((0, 1), True), ((2, 0), True), ((2, 1), True), ((0, 0), False)):
            with mock.patch.object(pv._Containment, "_ask", return_value=reply):
                self.assertEqual(contain.survivors(process), expected, reply)
        contain._ctl_w = None
        self.assertIsNone(contain._ask("S", 0.1))                               # no control channel is no answer
        contain._clean = None
        with mock.patch.object(pv._Containment, "_ask", return_value=(0, 1)):
            self.assertFalse(contain.reap(mock.Mock(returncode=0, wait=mock.Mock(return_value=0)), 1.0))

    @unittest.skipUnless(sys.platform.startswith("linux"), "the supervisor is the Linux containment")
    def test_unrelated_processes_sharing_the_cwd_or_a_string_prefix_of_it_are_never_touched(self):
        base = Path(tempfile.mkdtemp(prefix="pvc-decoy-"))
        self.addCleanup(shutil.rmtree, base, True)
        run_cwd, sibling = base / "run", base / "runner"
        run_cwd.mkdir(), sibling.mkdir()
        sleeper = [sys.executable, "-c", "import time; time.sleep(120)", str(run_cwd)]
        decoys = [subprocess.Popen(sleeper, cwd=str(run_cwd)), subprocess.Popen(sleeper, cwd=str(sibling))]
        for decoy in decoys:
            self.addCleanup(decoy.wait)
            self.addCleanup(decoy.kill)
        result = pv._execute([sys.executable, "-c", "pass"], str(run_cwd), b"", 60.0, 1 << 16, 1 << 16)
        self.assertEqual((result.returncode, result.descendants, result.cleanup_failed), (0, False, False))
        self.assertTrue(all(alive(decoy.pid) for decoy in decoys))               # ownership is parenthood, never a path prefix
        self.assertTrue(all(decoy.poll() is None for decoy in decoys))

    def test_one_operation_deadline_is_shared_by_every_phase_and_nested_scopes_restore_it(self):
        self.assertEqual(pv._Operation.remaining(7.0), 7.0)                      # outside a run the caller's cap applies
        pv._Operation.tick("anywhere")
        with pv._Operation(30.0):
            self.assertLessEqual(pv._Operation.remaining(1000.0), 30.0)
            self.assertEqual(pv._Operation.remaining(0.5), 0.5)
            with pv._Operation(0.05):
                time.sleep(0.1)
                self.assertRaisesCode("operation_deadline_exceeded", pv._Operation.tick, "census")
                self.assertRaisesCode("operation_deadline_exceeded", pv._Operation.remaining, 5.0)
            pv._Operation.tick("restored")                                       # the outer deadline is back in force
            self.assertGreater(pv._Operation.remaining(1000.0), 0)
        self.assertIsNone(pv._Operation.current())
        self.assertEqual(pv.failure_class("operation_deadline_exceeded"), "execution")
        self.assertRaisesCode("invalid_arguments", pv._Operation, 0)

    def test_an_overlong_phase_before_launch_exhausts_the_whole_operation_not_just_the_child(self):
        fx = Fixture(self).build()
        real = pv.runtime_census

        def slow_census(*args, **kwargs):
            time.sleep(3.5)
            return real(*args, **kwargs)
        with mock.patch.object(pv, "runtime_census", side_effect=slow_census), \
                mock.patch.object(pv, "_launch", side_effect=AssertionError("the verifier child was started after the deadline")):
            run = fx.run(timeout=3)
        self.assertRejected(run, "operation_deadline_exceeded", "execution")
        self.assertIsNone(run.receipt["process"])
        pv.validate_receipt(run.receipt)

    def test_a_child_that_ignores_its_stdin_cannot_block_shutdown_through_a_buffered_close(self):
        """The pipes are raw: a large frame the child never reads is abandoned at the deadline, not flushed by close()."""
        tmp = Path(tempfile.mkdtemp(prefix="pvc-stdin-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        begun = time.monotonic()
        result = pv._execute([sys.executable, "-c", "import time; time.sleep(120)"], str(tmp), b"x" * (8 << 20), 1.0, 1 << 16, 1 << 16)
        self.assertTrue(result.timed_out)
        self.assertLess(time.monotonic() - begun, 30)

    def test_a_deadline_already_in_the_past_never_yields_a_result_and_the_flags_are_consistent(self):
        """Whether the bounded launch gives up first (``child_launch_timeout``: the late child is settled by the abandoned
        attempt and ``cleanup_failed`` says whether that was confirmed; no ``timed_out``) or the child was created and the
        pre-delivery check fires (``timed_out``), the outcome is one of exactly these two and neither can be accepted."""
        tmp = Path(tempfile.mkdtemp(prefix="pvc-late-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        passed = time.monotonic() - 1.0
        late = pv._execute([sys.executable, "-c", "pass"], str(tmp), b"", 5.0, 1 << 16, 1 << 16, deadline=passed)
        if late.launch_error == "child_launch_timeout":
            self.assertEqual((late.timed_out, late.returncode), (False, None))
            expected = "containment_cleanup_failed" if late.cleanup_failed else "execution_launch_failed"
        else:
            self.assertEqual((late.launch_error, late.timed_out), (None, True))
            expected = "containment_cleanup_failed" if late.cleanup_failed else "execution_timeout"
        self.assertEqual(late.stdout, b"")
        self.assertRaisesCode(expected, pv._accept_report, late, "0" * 32, "0" * 64, None, "run")

    def test_unverifiable_cleanup_and_unlaunchable_children_are_reported_not_ignored(self):
        tmp = Path(tempfile.mkdtemp(prefix="pvc-cleanup-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        with mock.patch.object(pv._Containment, "reap", return_value=False):
            unverified = pv._execute([sys.executable, "-c", "import sys; sys.stdin.buffer.read()"], str(tmp), b"x", 20.0, 1 << 16, 1 << 16)
        self.assertTrue(unverified.cleanup_failed)
        with self.assertRaises(pv.ClosureRejected) as caught:
            pv._accept_report(unverified, "0" * 32, "0" * 64, None, "run")
        self.assertEqual(caught.exception.code, "containment_cleanup_failed")
        missing = pv._execute([str(tmp / "no-such-interpreter")], str(tmp), b"x", 20.0, 1 << 16, 1 << 16)
        self.assertEqual((missing.launch_error, missing.cleanup_failed, missing.returncode), ("child_launch_failed", False, None))
        with self.assertRaises(pv.ClosureRejected) as caught:
            pv._accept_report(missing, "0" * 32, "0" * 64, None, "run")
        self.assertEqual(caught.exception.code, "execution_launch_failed")
        self.assertEqual(pv.failure_class("containment_cleanup_failed"), "containment")
        self.assertEqual(pv.failure_class("containment_attach_failed"), "containment")
        self.assertEqual(pv.failure_class("execution_launch_failed"), "execution")

    def test_the_deadline_covers_process_launch_and_a_late_child_is_settled_before_the_caller_reports(self):
        """The Popen cannot be cancelled: it completes 0.6 s after the 0.3 s deadline.  The caller still reports at the
        shared cleanup deadline at the latest, and what it reports is the TRUTH about the late child: a child confirmed
        killed and reaped is not a cleanup failure, an unconfirmed one is; neither is ever acceptable."""
        tmp = Path(tempfile.mkdtemp(prefix="pvc-launch-deadline-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        real_popen = subprocess.Popen
        started = []

        def slow_launch(*args, **kwargs):
            time.sleep(0.6)
            process = real_popen(*args, **kwargs)
            started.append(process)
            return process
        begun = time.monotonic()
        with mock.patch.object(pv.subprocess, "Popen", side_effect=slow_launch), mock.patch.object(pv, "CLEANUP_GRACE", 15.0):
            result = pv._execute([sys.executable, "-c", "import time; time.sleep(120)"], str(tmp), b"", 0.3, 1 << 16, 1 << 16)
        self.assertLess(time.monotonic() - begun, 0.3 + 15.0 + 5.0)              # never past the one shared cleanup deadline
        self.assertEqual(result.launch_error, "child_launch_timeout")
        self.assertFalse(result.timed_out)
        self.assertIsNone(result.returncode)
        self.assertTrue(started)                                                 # the creation really completed late
        self.assertIsNotNone(started[0].poll())                                  # and the late child was killed and reaped
        self.assertFalse(alive(started[0].pid))
        if not result.cleanup_failed:                                            # a confirmed settle is reported as such ...
            self.assertIn(("child", str(started[0].pid), "reaped"), pv._LATE_OUTCOMES)
        expected = "containment_cleanup_failed" if result.cleanup_failed else "execution_launch_failed"
        self.assertRaisesCode(expected, pv._accept_report, result, "0" * 32, "0" * 64, None, "run")   # ... and never accepted

    @unittest.skipUnless(sys.platform.startswith("linux"), "the subreaper is the Linux containment")
    def test_descendant_that_left_the_process_group_and_session_is_still_owned_and_killed(self):
        tmp = Path(tempfile.mkdtemp(prefix="pvc-setsid-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        pidfile = tmp / "grandchild.txt"
        program = ("import subprocess, sys\n"
                   "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'], start_new_session=True)\n"
                   "open(sys.argv[1], 'w').write(str(child.pid))\n")
        result = pv._execute([sys.executable, "-c", program, str(pidfile)], str(tmp), b"", 60.0, 1 << 16, 1 << 16)
        self.assertEqual(result.returncode, 0)
        self.assertTrue(result.descendants)
        self.assertFalse(result.cleanup_failed)
        grandchild = self._wait_pid(pidfile)
        deadline = time.monotonic() + 15
        while alive(grandchild) and time.monotonic() < deadline:
            time.sleep(0.2)
        self.assertFalse(alive(grandchild))

    @unittest.skipUnless(sys.platform.startswith("linux"), "the subreaper is the Linux containment")
    def test_an_adopted_and_already_exited_orphan_does_not_make_the_run_unconfirmed(self):
        """A grandchild whose parent exited is adopted by the supervisor and remains its (zombie) child after it exits.
        The empty-tree confirmation must be stable despite that adoption: the run is empty and cleanup is verified."""
        tmp = Path(tempfile.mkdtemp(prefix="pvc-adopt-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        program = ("import os, time\n"
                   "r, w = os.pipe()\n"
                   "if os.fork() == 0:\n"
                   "    if os.fork() == 0:\n"
                   "        os.write(w, b'x')\n"
                   "        os._exit(0)\n"
                   "    os._exit(0)\n"
                   "os.wait()\n"
                   "os.read(r, 1)\n"
                   "time.sleep(0.5)\n")
        result = pv._execute([sys.executable, "-c", program], str(tmp), b"", 60.0, 1 << 16, 1 << 16)
        self.assertEqual((result.returncode, result.descendants, result.cleanup_failed, result.timed_out), (0, False, False, False))
        self.assertIsNone(result.launch_error)


class Stuck:
    """Stands in for one blocking inspection (a stuck stat, read, hash, directory walk or security query).

    It never returns on its own; ``release`` (set at test end) lets the abandoned helper thread finish.  With ``real``
    given, every call except number ``on_call`` is delegated to it, so a later phase can be the one that blocks."""

    def __init__(self, test, real=None, on_call=1):
        self.release, self.entered = threading.Event(), threading.Event()
        self.real, self.on_call, self.calls = real, on_call, 0
        test.addCleanup(self.release.set)

    def __call__(self, *args, **kwargs):
        self.calls += 1
        if self.real is not None and self.calls != self.on_call:
            return self.real(*args, **kwargs)
        self.entered.set()
        self.release.wait(120)
        raise RuntimeError("released after the deadline: this late outcome must be discarded")


class EnforcedDeadlines(RejectionMixin, unittest.TestCase):
    """The whole-operation and cleanup deadlines are enforced for blocking phases, not only between chunks.

    The public-run cases are timing based: ``TIMEOUT`` must be long enough that the real earlier phases (interpreter
    probe, runtime census) finish inside it, and short enough that the suite stays quick."""

    TIMEOUT = 6

    def scratch_directories(self):
        """Record every run scratch directory (``pvc-run-*``) the module creates and remove what the test leaves."""
        made, real = [], tempfile.mkdtemp

        def record(*args, **kwargs):
            path = real(*args, **kwargs)
            if os.path.basename(path).startswith("pvc-run-"):
                made.append(path)
            return path
        patcher = mock.patch.object(pv.tempfile, "mkdtemp", side_effect=record)
        patcher.start()
        self.addCleanup(lambda: [shutil.rmtree(path, True) for path in made])
        self.addCleanup(patcher.stop)
        return made

    def tree(self, name="scratch"):
        root = Path(tempfile.mkdtemp(prefix="pvc-tree-"))
        self.addCleanup(shutil.rmtree, root, True)
        top = root / name
        (top / "a" / "b").mkdir(parents=True)
        (top / "a" / "b" / "deep.bin").write_bytes(b"x" * 100)
        (top / "top.txt").write_text("top")
        outside = root / "outside"
        outside.mkdir()
        (outside / "keep.txt").write_text("keep")
        return top, outside

    def test_a_bounded_call_outside_a_run_is_direct_and_inside_a_run_returns_values_and_errors_unchanged(self):
        caller = threading.get_ident()
        self.assertEqual(pv._Operation.bounded("x", threading.get_ident), caller)
        with pv._Operation(30.0) as operation:
            seen = pv._Operation.bounded("x", lambda a, b=0: (a + b, pv._Operation.current() is operation,
                                                              threading.get_ident() != caller), 2, b=3)
            self.assertEqual(seen, (5, True, True))                              # arguments pass; the helper carries the operation
            error = self.assertRaisesCode("closure_module_changed_during_execution", pv._Operation.bounded, "x",
                                          pv._reject, "closure_module_changed_during_execution", "m")
            self.assertEqual(error.detail, "m")
            with self.assertRaises(ValueError):
                pv._Operation.bounded("x", int, "not a number")
            self.assertEqual(operation.abandoned, [])

    def test_a_blocked_call_returns_control_at_the_deadline_and_the_late_helper_is_neither_killed_nor_trusted(self):
        stuck = Stuck(self)
        with pv._Operation(0.4) as operation:
            begun = time.monotonic()
            error = self.assertRaisesCode("operation_deadline_exceeded", pv._Operation.bounded, "directory_walk", stuck)
            elapsed = time.monotonic() - begun
        self.assertEqual(error.detail, "directory_walk:blocked")
        self.assertTrue(stuck.entered.is_set())
        self.assertGreaterEqual(elapsed, 0.3)
        self.assertLess(elapsed, 3.0)                                            # the caller did not wait for the system call
        self.assertEqual(operation.abandoned, ["directory_walk"])
        stuck.release.set()
        for helper in [t for t in threading.enumerate() if t.name == "pvc-bounded-directory_walk"]:
            helper.join(10)
            self.assertFalse(helper.is_alive())                                  # it ended by itself; nothing signalled it
        self.assertEqual(pv.failure_class("operation_deadline_exceeded"), "execution")

    def test_a_phase_that_starts_after_the_deadline_never_starts(self):
        called = []
        with pv._Operation(0.05):
            time.sleep(0.15)
            error = self.assertRaisesCode("operation_deadline_exceeded", pv._Operation.bounded, "stat", called.append, 1)
        self.assertEqual((error.detail, called), ("stat:before_phase", []))

    def test_call_within_answers_inside_its_budget_whatever_the_call_does(self):
        self.assertEqual(pv._call_within(5.0, lambda a: a * 2, 21), (True, 42))
        self.assertEqual(pv._call_within(5.0, int, "x"), (False, None))           # a failing inspection is not a confirmation
        stuck = Stuck(self)
        begun = time.monotonic()
        self.assertEqual(pv._call_within(0.3, stuck), (False, None))
        self.assertLess(time.monotonic() - begun, 3.0)
        self.assertTrue(stuck.entered.is_set())

    def test_bounded_removal_deletes_the_tree_and_links_but_never_what_they_point_to(self):
        top, outside = self.tree()
        try:
            os.symlink(str(outside), str(top / "link"), target_is_directory=True)
        except (OSError, NotImplementedError):
            pass                                                                 # unprivileged Windows: the link case is not available
        self.assertTrue(pv._bounded_rmtree(str(top), 10.0))
        self.assertFalse(top.exists())
        self.assertEqual((outside / "keep.txt").read_text(), "keep")
        self.assertTrue(pv._bounded_rmtree(str(top), 10.0))                       # an absent path is verifiably absent

    def test_bounded_removal_is_false_not_silent_success_when_it_blocks_or_leaves_something(self):
        top, _ = self.tree()
        stuck, stops = Stuck(self), []

        def blocking(path, stop, identity=None):
            stops.append(stop)
            stuck(path, stop)
        with mock.patch.object(pv, "_remove_tree", side_effect=blocking):
            begun = time.monotonic()
            self.assertFalse(pv._bounded_rmtree(str(top), 0.3))
            self.assertLess(time.monotonic() - begun, 3.0)
        self.assertTrue(stops[0].is_set())                                       # the abandoned removal is told to stop at its next entry
        self.assertTrue(top.exists())
        before = len(stops)
        begun = time.monotonic()
        self.assertEqual(pv._bounded_remove(str(top), 0.3), "unconfirmed")        # a retry joins the worker in flight ...
        self.assertEqual(len(stops), before)                                      # ... and never starts a duplicate worker
        self.assertLess(time.monotonic() - begun, 3.0)
        stuck.release.set()                                                       # the blocked call ends by itself
        for helper in [t for t in threading.enumerate() if t.name == "pvc-cleanup"]:
            helper.join(10)
        with mock.patch.object(pv, "_remove_tree", side_effect=lambda path, stop, identity=None: None):
            self.assertFalse(pv._bounded_rmtree(str(top), 5.0))                   # finished, but the path is still there
        self.assertTrue(pv._bounded_rmtree(str(top), 10.0))                       # the real removal still works afterwards

    def test_an_unconfirmed_scratch_removal_turns_pass_into_rejected_and_a_rejected_receipt_records_the_leftover(self):
        fx = Fixture(self).build()
        passed = fx.run()
        self.assertEqual((passed.status, passed.reason), ("PASS", "ok"), passed.reason)
        kept = copy.deepcopy(passed.receipt)
        pv._settle_cleanup(kept, True)
        self.assertEqual((kept["status"], kept["reason"]), ("PASS", "ok"))
        settled = copy.deepcopy(passed.receipt)
        pv._settle_cleanup(settled, False)
        self.assertEqual((settled["status"], settled["reason"], settled["failure_class"], settled["verifier"]),
                         ("REJECTED", "containment_cleanup_failed:work_directory", "containment", None))
        self.assertTrue(settled["process"]["cleanup_failed"])
        pv.validate_receipt(reseal(settled))                                     # the rewritten receipt is still a consistent receipt
        wrong = {"doc": pv.InputSpec(fx.data, "doc.txt", sha(b"not the input"))}
        rejected = fx.run(inputs=wrong)
        self.assertEqual(rejected.status, "REJECTED")
        before = rejected.reason
        receipt = copy.deepcopy(rejected.receipt)
        pv._settle_cleanup(receipt, False)
        self.assertEqual(receipt["reason"], before)                              # the original reason is kept ...
        self.assertEqual(receipt["refused"][-1], "work_directory_not_removed")   # ... and the leftover is recorded
        pv.validate_receipt(reseal(receipt))

    def test_a_run_whose_own_scratch_directory_is_not_verifiably_removed_is_never_a_pass(self):
        made = self.scratch_directories()
        fx = Fixture(self).build()
        clean = fx.run(work_dir=None)
        self.assertEqual((clean.status, clean.reason), ("PASS", "ok"), clean.reason)
        self.assertEqual(len(made), 1)
        self.assertFalse(os.path.exists(made[0]))                                # the run removed its own scratch before sealing
        real = pv._bounded_remove

        def unconfirmed(path, budget, identity=None):
            if os.path.basename(path).startswith("pvc-run-"):
                return "unconfirmed"
            return real(path, budget, identity)
        with mock.patch.object(pv, "_bounded_remove", side_effect=unconfirmed):
            run = fx.run(work_dir=None)
        self.assertRejected(run, "containment_cleanup_failed:work_directory", "containment")
        self.assertTrue(run.receipt["process"]["cleanup_failed"])
        self.assertIsNone(run.receipt["verifier"])
        pv.validate_receipt(run.receipt)
        self.assertEqual(sorted(pv._ORPHANS).count(made[-1]), 1)                 # an unconfirmed removal stays owned, not forgotten
        self.assertEqual(pv.settle_orphans(30.0).count(made[-1]), 0)             # and settles later, identity-bound
        self.assertFalse(os.path.exists(made[-1]))

    def test_a_blocked_scratch_removal_is_bounded_by_the_cleanup_grace_and_reported(self):
        made = self.scratch_directories()
        stuck = Stuck(self)
        real = pv._remove_tree

        def remove(path, stop, identity=None):
            if os.path.basename(path).startswith("pvc-run-"):
                return stuck(path, stop)
            return real(path, stop, identity)
        fx = Fixture(self).build()
        with mock.patch.object(pv, "_remove_tree", side_effect=remove), mock.patch.object(pv, "CLEANUP_GRACE", 0.5):
            run = fx.run(work_dir=None)
        self.assertTrue(stuck.entered.is_set())
        self.assertRejected(run, "containment_cleanup_failed:work_directory", "containment")
        pv.validate_receipt(run.receipt)
        self.assertTrue(made)
        stuck.release.set()                                                      # the blocked removal ends by itself, ...
        for helper in [t for t in threading.enumerate() if t.name == "pvc-cleanup"]:
            helper.join(10)
        pv._ORPHANS.pop(made[-1], None)                                          # ... this test settles the orphan it created

    PRE_LAUNCH = (("protection", "_protection_gate", 1), ("census", "runtime_census", 2),
                  ("runtime_pins", "_runtime_pins", 1), ("natives", "_check_natives", 1),
                  ("closure_read", "_read_closure_modules", 1), ("graph_and_table", "module_table", 1),
                  ("inputs", "_capture_inputs", 1))
    POST_LAUNCH = (("post_closure", "_recheck_closure", 1), ("post_inputs", "_recheck_inputs", 1),
                   ("post_runtime", "authenticate_runtime", 2))

    def blocked_run(self, where, name, nth, launched):
        stuck = Stuck(self, getattr(pv, name), nth)
        fx = Fixture(self).build()
        guard = (mock.patch.object(pv, "_launch", side_effect=AssertionError("the verifier child was started after the deadline"))
                 if not launched else contextlib.nullcontext())
        with mock.patch.object(pv, name, side_effect=stuck), guard:
            begun = time.monotonic()
            run = fx.run(timeout=self.TIMEOUT)
            elapsed = time.monotonic() - begun
        self.assertTrue(stuck.entered.is_set(), where)
        self.assertRejected(run, "operation_deadline_exceeded:%s:blocked" % where, "execution")
        self.assertGreaterEqual(elapsed, self.TIMEOUT - 0.5, where)               # it really waited for the deadline, not for the call
        self.assertLess(elapsed, self.TIMEOUT + 6, where)                         # and the caller regained control right after it
        self.assertIsNone(run.receipt["verifier"])
        pv.validate_receipt(run.receipt)
        return run

    def test_every_blocking_phase_before_the_launch_ends_the_run_at_the_deadline_without_a_child(self):
        for where, name, nth in self.PRE_LAUNCH:
            with self.subTest(phase=where):
                run = self.blocked_run(where, name, nth, launched=False)
                self.assertIsNone(run.receipt["process"])

    def test_every_blocking_post_check_after_the_child_ran_is_a_rejection_not_a_pass(self):
        for where, name, nth in self.POST_LAUNCH:
            with self.subTest(phase=where):
                run = self.blocked_run(where, name, nth, launched=True)
                self.assertIsNotNone(run.receipt["process"])
                self.assertFalse(all(run.receipt["post_checks"].values()))

    def test_a_blocked_package_census_is_bounded_like_every_other_phase(self):
        fx, roots, packages = CacheAndAmbientState.dependency_fixture(self, "VALUE = 1\n")
        fx.build(roots=roots, packages=packages)
        stuck = Stuck(self)
        with mock.patch.object(pv, "package_census", side_effect=stuck), \
                mock.patch.object(pv, "_launch", side_effect=AssertionError("the verifier child was started after the deadline")):
            begun = time.monotonic()
            run = fx.run(roots=roots, timeout=self.TIMEOUT)
            elapsed = time.monotonic() - begun
        self.assertTrue(stuck.entered.is_set())
        self.assertRejected(run, "operation_deadline_exceeded:package_census:blocked", "execution")
        self.assertLess(elapsed, self.TIMEOUT + 6)
        pv.validate_receipt(run.receipt)

    def test_the_final_acceptance_check_refuses_a_verdict_that_arrives_after_the_deadline(self):
        real_tick = pv._Operation.tick

        def late(where):
            if where == "final":
                time.sleep(max(0.0, pv._Operation.current().deadline - time.monotonic()) + 0.1)
            return real_tick(where)
        fx = Fixture(self).build()
        with mock.patch.object(pv._Operation, "tick", side_effect=late):
            run = fx.run(timeout=self.TIMEOUT)
        self.assertRejected(run, "operation_deadline_exceeded:final", "execution")
        self.assertIsNone(run.receipt["verifier"])                               # no PASS/HOLD result was ever recorded
        pv.validate_receipt(run.receipt)

    @unittest.skipUnless(sys.platform.startswith("linux"), "the supervisor is the Linux containment")
    def test_a_failed_launch_leaves_no_supervisor_bytecode_directory_and_a_blocked_one_is_bounded(self):
        tmp = Path(tempfile.mkdtemp(prefix="pvc-launchfail-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        real, made = tempfile.mkdtemp, []

        def record(*args, **kwargs):
            path = real(*args, **kwargs)
            made.append(path)
            return path
        with mock.patch.object(pv.tempfile, "mkdtemp", side_effect=record):
            failed = pv._execute([str(tmp / "no-such-interpreter")], str(tmp), b"x", 20.0, 1 << 16, 1 << 16)
        supervisors = [path for path in made if "pvc-supervisor-bytecode-" in os.path.basename(path)]
        self.assertEqual((failed.launch_error, failed.cleanup_failed), ("child_launch_failed", False))
        self.assertEqual(len(supervisors), 1)
        self.assertFalse(os.path.exists(supervisors[0]))                         # its own empty directory was removed, not leaked
        stuck = Stuck(self)

        def blocking(*args, **kwargs):
            if str(kwargs.get("prefix", "")).startswith("pvc-supervisor-bytecode-"):
                return stuck(*args, **kwargs)
            return real(*args, **kwargs)
        with mock.patch.object(pv.tempfile, "mkdtemp", side_effect=blocking), mock.patch.object(pv, "CLEANUP_GRACE", 1.0):
            begun = time.monotonic()
            late = pv._execute([sys.executable, "-c", "pass"], str(tmp), b"", 0.5, 1 << 16, 1 << 16)
            elapsed = time.monotonic() - begun
        self.assertTrue(stuck.entered.is_set())
        self.assertLess(elapsed, 0.5 + 1.0 + 4.0)                                # the caller did not wait for the directory call
        # the blocked system call is still pending, so the attempt is not settled: the report says so
        self.assertEqual((late.launch_error, late.cleanup_failed, late.returncode), ("child_launch_timeout", True, None))

    def test_no_runtime_pin_or_start_up_file_work_is_called_directly_in_the_verification_path(self):
        """``_verify_core`` hands ``_runtime_pins`` (start-up file hashes, executable resolution, native rows) and every
        other filesystem phase to ``_Operation.bounded``; none of them is called by name in that function."""
        import ast
        tree = ast.parse((REPO / "trace_gc" / "verifier_closure.py").read_text(encoding="utf-8"))
        core = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "_verify_core")
        direct = {c.func.id for c in ast.walk(core) if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)}
        self.assertFalse(direct & {"_runtime_pins", "_startup_rows", "_startup_config_rows", "authenticate_runtime",
                                   "runtime_census", "_check_natives", "_read_closure_modules", "package_census",
                                   "_protection_gate", "_resolve_executable", "_native_rows", "_file_sha256"}, direct)
        handed = {a.id for c in ast.walk(core) if isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute)
                  and c.func.attr == "bounded" for a in c.args if isinstance(a, ast.Name)}
        self.assertTrue({"_runtime_pins", "authenticate_runtime", "runtime_census", "_check_natives", "_read_closure_modules",
                         "package_census", "_protection_gate"} <= handed, handed)

    def test_a_blocked_startup_file_read_inside_the_runtime_pins_ends_the_run_at_the_deadline(self):
        run = self.blocked_run("runtime_pins", "_startup_rows", 1, launched=False)
        self.assertIsNone(run.receipt["process"])

    def test_a_blocked_run_directory_creation_is_bounded_and_a_late_creation_is_removed_by_the_creating_thread(self):
        gate, made, real = threading.Event(), [], tempfile.mkdtemp
        self.addCleanup(gate.set)
        self.addCleanup(lambda: [shutil.rmtree(path, True) for path in made])

        def slow(*args, **kwargs):
            if kwargs.get("prefix") == "pvc-run-":
                gate.wait(60)
                made.append(real(*args, **kwargs))
                return made[-1]
            return real(*args, **kwargs)
        fx = Fixture(self).build()
        begun = time.monotonic()
        with mock.patch.object(pv.tempfile, "mkdtemp", side_effect=slow):
            run = fx.run(work_dir=None, timeout=2)
        self.assertLess(time.monotonic() - begun, 2 + pv.CLEANUP_GRACE + 4)
        self.assertRejected(run, "operation_deadline_exceeded:run_dir:blocked", "execution")
        self.assertIsNone(run.receipt["process"])
        pv.validate_receipt(run.receipt)
        self.assertEqual(made, [])                                               # the creation had not happened when the run reported
        gate.set()                                                               # the uncancellable creation now completes ...
        deadline = time.monotonic() + 30
        while (not made or os.path.exists(made[0])) and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertTrue(made)
        self.assertFalse(os.path.exists(made[0]))                                # ... and the creating thread removes what it made
        self.assertIn(("scratch", made[0], "removed"), pv._LATE_OUTCOMES)

    def test_a_blocked_seal_is_a_bounded_step_and_the_receipt_is_a_sealed_rejection_of_the_true_reason(self):
        stuck = Stuck(self, pv._binding, 1)
        fx = Fixture(self).build()
        with mock.patch.object(pv, "_binding", side_effect=stuck):
            begun = time.monotonic()
            run = fx.run(timeout=self.TIMEOUT)
            elapsed = time.monotonic() - begun
        self.assertTrue(stuck.entered.is_set())
        self.assertRejected(run, "operation_deadline_exceeded:seal:blocked", "execution")
        self.assertGreaterEqual(elapsed, self.TIMEOUT - 0.5)
        self.assertLess(elapsed, self.TIMEOUT + 6)
        self.assertIsNone(run.receipt["verifier"])                               # the genuine result was withdrawn, not returned
        pv.validate_receipt(run.receipt)                                         # and the receipt is sealed and valid

    def test_a_receipt_that_cannot_be_serialized_is_a_sealed_protocol_rejection_never_a_verdict(self):
        fx = Fixture(self).build()
        passing = fx.run().receipt
        broken = copy.deepcopy(passing)
        with self.assertRaises(pv.ContractError):                                 # outside the canonical data domain: unpaired surrogate
            pv.canonical_bytes({"bad": "\ud800"})
        broken["verifier"]["result"] = {"status": "PASS", "bad": "\ud800"}
        broken["binding_sha256"] = None
        pv._seal(broken)
        self.assertEqual((broken["status"], broken["reason"], broken["failure_class"], broken["verifier"]),
                         ("REJECTED", "protocol_receipt_not_canonical", "protocol", None))
        pv.validate_receipt(broken)

    def test_the_absence_check_after_a_removal_is_bounded_like_the_removal_and_a_confirmed_removal_is_inside_the_bound(self):
        top, outside = self.tree()
        identity = pv._identity(os.lstat(top))
        begun = time.monotonic()
        self.assertEqual(pv._bounded_remove(str(top), 10.0, identity), "removed")   # the positive, inside the bound
        self.assertLess(time.monotonic() - begun, 10.0)
        self.assertTrue((outside / "keep.txt").exists())
        top2, _ = self.tree("second")
        identity2 = pv._identity(os.lstat(top2))
        release, real_lstat = threading.Event(), os.lstat
        self.addCleanup(release.set)

        def lstat(path, *args, **kwargs):
            if os.fspath(path) == str(top2) and not os.path.exists(top2):
                release.wait(60)                                                  # the CONCLUDING absence check blocks
            return real_lstat(path, *args, **kwargs)
        with mock.patch.object(pv.os, "lstat", side_effect=lstat):
            begun = time.monotonic()
            outcome = pv._bounded_remove(str(top2), 0.5, identity2)
            elapsed = time.monotonic() - begun
        self.assertEqual(outcome, "unconfirmed")                                  # gone, but not CONFIRMED gone inside the bound
        self.assertLess(elapsed, 5.0)
        self.assertFalse(top2.exists())
        release.set()

    def test_every_cleanup_step_spends_from_one_shared_deadline_so_stuck_steps_cannot_stack_allowances(self):
        """Every removal blocks (the work directory, the supervisor bytecode directory and each retry): the report still
        arrives by operation deadline + cleanup grace, not after one grace period per stage."""
        self.scratch_directories()
        stuck = Stuck(self)
        grace = 1.0
        known = set(pv._ORPHANS)

        def settle_what_this_test_orphaned():
            stuck.release.set()
            for helper in [t for t in threading.enumerate() if t.name == "pvc-cleanup"]:
                helper.join(10)
            for path in set(pv._ORPHANS) - known:
                shutil.rmtree(path, True)
                pv._ORPHANS.pop(path, None)
        self.addCleanup(settle_what_this_test_orphaned)

        def remove(path, stop, identity=None):
            return stuck(path, stop)
        fx = Fixture(self).build()
        begun = time.monotonic()
        with mock.patch.object(pv, "_remove_tree", side_effect=remove), mock.patch.object(pv, "CLEANUP_GRACE", grace):
            run = fx.run(work_dir=None, timeout=self.TIMEOUT)
            elapsed = time.monotonic() - begun
        self.assertTrue(stuck.entered.is_set())
        self.assertRejected(run, "containment_cleanup_failed", "containment")
        self.assertLess(elapsed, self.TIMEOUT + grace + 4.0)
        pv.validate_receipt(run.receipt)
        self.assertTrue(set(pv._ORPHANS) - known)                                # every unconfirmed removal stays owned

    def test_the_same_run_without_a_stuck_phase_still_passes_inside_the_same_deadline(self):
        run = Fixture(self).build().run(timeout=self.TIMEOUT)
        self.assertEqual((run.status, run.reason), ("PASS", "ok"), run.reason)
        self.assertEqual(run.receipt["process"]["cleanup_failed"], False)

    def test_a_clean_run_leaves_no_scratch_directory_and_the_cleanup_inside_the_bound_is_a_pass(self):
        made = self.scratch_directories()
        run = Fixture(self).build().run(work_dir=None, timeout=self.TIMEOUT)
        self.assertEqual((run.status, run.reason), ("PASS", "ok"), run.reason)
        self.assertEqual([path for path in made if os.path.exists(path)], [])


class StubAttempt(pv._LaunchAttempt):
    """A launch attempt whose uncancellable creation is controlled by the test; the child it creates is a REAL process.

    ``before`` blocks the creation before it has begun (the liveness check then still sees the caller's decision),
    ``after`` blocks it after the liveness check passed, i.e. a system call already in flight that nothing can cancel."""

    def __init__(self, before=None, after=None, fail=False):
        super().__init__([sys.executable], os.getcwd(), windows=True)
        self.before, self.after, self.fail = before, after, fail
        self.in_flight = threading.Event()

    def _create(self):
        if self.before is not None:
            self.before.wait(60)
        if self.fail:
            raise OSError("injected creation failure")
        if not self._live():
            return
        self.in_flight.set()
        if self.after is not None:
            self.after.wait(60)
        self.process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)


class LateEffectOwnership(RejectionMixin, unittest.TestCase):
    """An abandoned operation keeps durable ownership of every effect it still produces, and cleanup is bound to the
    identity of what was created.  Each late-resumption case checks the EVENTUAL effect (process, descriptors, streams,
    directory, competing replacement), not only the prompt return.  A call blocked in the kernel cannot be cancelled:
    these tests hold it open with an event and then let it complete."""

    def scratch(self):
        root = Path(tempfile.mkdtemp(prefix="pvc-own-"))
        self.addCleanup(shutil.rmtree, root, True)
        return root

    def test_an_attempt_that_finishes_inside_its_deadline_is_adopted_and_its_thread_settles_nothing(self):
        attempt = StubAttempt()
        process, failure = pv._bounded_launch(attempt, time.monotonic() + 30)
        self.addCleanup(lambda: (process.kill(), process.wait(), [s.close() for s in (process.stdin, process.stdout, process.stderr)]))
        self.assertEqual((failure, attempt.state), (None, "adopted"))
        self.assertIs(process, attempt.process)
        self.assertFalse(attempt.settled.wait(0.3))                               # the adopted child belongs to the caller now
        self.assertIsNone(process.poll())

    def test_a_creation_that_has_not_begun_when_the_caller_gives_up_never_happens(self):
        before = threading.Event()
        self.addCleanup(before.set)
        attempt = StubAttempt(before=before)
        begun = time.monotonic()
        self.assertEqual(pv._bounded_launch(attempt, time.monotonic() + 0.3), (None, "child_launch_timeout"))
        self.assertLess(time.monotonic() - begun, 3.0)
        self.assertEqual(attempt.state, "abandoned")
        self.assertFalse(attempt.settle(0.2))                                     # still blocked: honestly NOT settled
        before.set()
        self.assertTrue(attempt.settle(30))
        self.assertIsNone(attempt.process)                                        # the later effect was prevented, not just ignored

    def test_a_creation_already_in_flight_completes_late_and_the_child_is_owned_terminated_reaped_and_closed(self):
        after = threading.Event()
        self.addCleanup(after.set)
        attempt = StubAttempt(after=after)
        self.assertEqual(pv._bounded_launch(attempt, time.monotonic() + 0.5), (None, "child_launch_timeout"))
        self.assertTrue(attempt.in_flight.wait(5))
        self.assertFalse(attempt.settled.is_set())
        after.set()                                                               # the uncancellable creation now completes
        self.assertTrue(attempt.settle(60))
        process = attempt.process
        self.assertIsNotNone(process)                                             # the effect DID happen ...
        self.assertIsNotNone(process.poll())                                      # ... and was terminated and reaped
        self.assertFalse(alive(process.pid))
        self.assertTrue(all(stream.closed for stream in (process.stdin, process.stdout, process.stderr)))
        self.assertIn(("child", str(process.pid), "reaped"), pv._LATE_OUTCOMES)

    def test_a_failed_creation_settles_and_reports_the_failure(self):
        attempt = StubAttempt(fail=True)
        self.assertEqual(pv._bounded_launch(attempt, time.monotonic() + 30), (None, "child_launch_failed"))
        self.assertEqual(attempt.state, "failed")
        self.assertTrue(attempt.settle(10))
        self.assertIsNone(attempt.process)

    def test_a_late_effect_never_touches_a_containment_that_was_already_closed(self):
        tmp = self.scratch()
        contain = pv._Containment(str(tmp))
        contain.close()
        frozen = dict(contain.__dict__)
        after = threading.Event()
        self.addCleanup(after.set)
        attempt = StubAttempt(after=after)
        self.assertEqual(pv._bounded_launch(attempt, time.monotonic() + 0.4), (None, "child_launch_timeout"))
        after.set()
        self.assertTrue(attempt.settle(60))
        self.assertEqual(contain.__dict__, frozen)                                # no late write reached the closed object
        self.assertFalse([v for v in vars(attempt).values() if isinstance(v, pv._Containment)])   # and it holds no reference to one

    @unittest.skipUnless(sys.platform.startswith("linux"), "the supervisor is the Linux containment")
    def test_a_late_supervisor_is_asked_to_kill_waited_for_and_its_directory_removed_by_identity(self):
        tmp = self.scratch()
        real_popen, gate, started = subprocess.Popen, threading.Event(), []
        self.addCleanup(gate.set)

        def slow(*args, **kwargs):
            gate.wait(60)
            started.append(real_popen(*args, **kwargs))
            return started[-1]
        attempt = pv._LaunchAttempt([sys.executable, "-c", "pass"], str(tmp), windows=False)
        with mock.patch.object(pv.subprocess, "Popen", side_effect=slow):
            self.assertEqual(pv._bounded_launch(attempt, time.monotonic() + 0.5), (None, "child_launch_timeout"))
            prefix = attempt.prefix
            self.assertTrue(prefix and os.path.isdir(prefix))                     # created before the blocked Popen
            gate.set()
            self.assertTrue(attempt.settle(60))
        self.assertTrue(attempt.clean)
        self.assertIsNotNone(started[0].poll())
        self.assertFalse(alive(started[0].pid))                                   # the late supervisor is gone (reaped)
        self.assertFalse(os.path.exists(prefix))
        self.assertEqual(attempt._fds, [])                                        # the pipe descriptors were closed
        self.assertTrue(all(stream.closed for stream in (started[0].stdin, started[0].stdout, started[0].stderr)))
        self.assertIn(("supervisor_dir", prefix, "removed"), pv._LATE_OUTCOMES)
        self.assertIn(("child", str(started[0].pid), "reaped"), pv._LATE_OUTCOMES)

    @unittest.skipUnless(sys.platform.startswith("linux"), "the supervisor is the Linux containment")
    def test_a_supervisor_directory_created_after_the_launch_was_abandoned_is_removed_and_no_process_is_started(self):
        tmp = self.scratch()
        real_mkdtemp, gate, made = tempfile.mkdtemp, threading.Event(), []
        self.addCleanup(gate.set)
        self.addCleanup(lambda: [shutil.rmtree(path, True) for path in made])

        def slow(*args, **kwargs):
            if str(kwargs.get("prefix", "")).startswith("pvc-supervisor-bytecode-"):
                gate.wait(60)
                made.append(real_mkdtemp(*args, **kwargs))
                return made[-1]
            return real_mkdtemp(*args, **kwargs)
        popen = mock.Mock(side_effect=AssertionError("a process was started for an abandoned launch"))
        attempt = pv._LaunchAttempt([sys.executable, "-c", "pass"], str(tmp), windows=False)
        with mock.patch.object(pv.tempfile, "mkdtemp", side_effect=slow), mock.patch.object(pv.subprocess, "Popen", popen):
            self.assertEqual(pv._bounded_launch(attempt, time.monotonic() + 0.4), (None, "child_launch_timeout"))
            gate.set()
            self.assertTrue(attempt.settle(30))
        popen.assert_not_called()
        self.assertEqual(len(made), 1)
        self.assertFalse(os.path.exists(made[0]))
        self.assertIn(("supervisor_dir", made[0], "removed"), pv._LATE_OUTCOMES)
        self.assertIsNone(attempt.process)
        self.assertEqual(attempt._fds, [])

    def test_removal_is_bound_to_the_created_directory_and_never_deletes_a_replacement_directory(self):
        root = self.scratch()
        owned = root / "owned"
        owned.mkdir()
        (owned / "mine.txt").write_text("mine")
        identity = pv._identity(os.lstat(owned))
        owned.rename(root / "moved")
        owned.mkdir()                                                             # a different directory now has the name
        (owned / "precious.txt").write_text("keep")
        self.assertEqual(pv._bounded_remove(str(owned), 10.0, identity), "replaced")
        self.assertEqual((owned / "precious.txt").read_text(), "keep")
        self.assertEqual((root / "moved" / "mine.txt").read_text(), "mine")
        self.assertFalse(pv._bounded_rmtree(str(owned), 10.0, identity))          # "replaced" is never reported as removed

    def test_a_link_that_replaced_the_owned_directory_is_left_alone_and_so_is_its_target(self):
        root = self.scratch()
        victim = root / "victim"
        victim.mkdir()
        (victim / "keep.txt").write_text("keep")
        owned = root / "owned"
        owned.mkdir()
        identity = pv._identity(os.lstat(owned))
        owned.rmdir()
        try:
            os.symlink(str(victim), str(owned), target_is_directory=True)
        except (OSError, NotImplementedError):
            if not (WINDOWS and make_junction(owned, victim)):
                self.skipTest("neither a symlink nor a junction can be created by this user")
        self.assertEqual(pv._bounded_remove(str(owned), 10.0, identity), "replaced")
        self.assertEqual((victim / "keep.txt").read_text(), "keep")
        self.assertTrue(os.path.lexists(owned))                                   # the link itself is not ours to remove

    def test_the_stop_signal_is_honoured_between_removals_and_a_replacement_after_the_timeout_is_untouched(self):
        root = self.scratch()
        top = root / "top"
        top.mkdir()
        for index in range(6):
            (top / ("f%d.bin" % index)).write_bytes(b"x")
        identity = pv._identity(os.lstat(top))
        entered, gate, calls, real_unlink = threading.Event(), threading.Event(), [], os.unlink
        self.addCleanup(gate.set)

        def unlink(path, *args, **kwargs):
            calls.append(path)
            if len(calls) == 1:
                entered.set()
                gate.wait(60)                                                     # the first removal blocks in the kernel
            return real_unlink(path, *args, **kwargs)
        with mock.patch.object(pv.os, "unlink", side_effect=unlink):
            self.assertEqual(pv._bounded_remove(str(top), 0.4, identity), "unconfirmed")
            self.assertTrue(entered.is_set())
            top.rename(root / "moved")                                            # the owner's directory is replaced meanwhile
            top.mkdir()
            (top / "precious.txt").write_text("keep")
            gate.set()
            for helper in [t for t in threading.enumerate() if t.name == "pvc-cleanup"]:
                helper.join(10)
        self.assertEqual((top / "precious.txt").read_text(), "keep")              # nothing was removed from the replacement
        self.assertEqual(len(calls), 1)                                           # stop honoured BETWEEN removals: no second removal began
        remaining = len(list((root / "moved").iterdir()))
        # POSIX removes by directory descriptor, so the removal already in flight hit the owned (moved) directory; Windows
        # has no descriptor-relative removal and resolves the name again (documented residual): it hit nothing here
        self.assertEqual(remaining, 5 if pv._DIR_FD_REMOVAL else 6)

    def test_an_unconfirmed_removal_stays_owned_until_it_settles_and_a_replaced_path_is_dropped_not_deleted(self):
        ledger = pv._ScratchLedger()
        path = tempfile.mkdtemp(prefix="pvc-ledger-")
        self.addCleanup(shutil.rmtree, path, True)
        self.addCleanup(pv._ORPHANS.pop, path, None)
        self.assertTrue(ledger.adopt(path))
        self.assertTrue(ledger.holds(path))
        with mock.patch.object(pv, "_remove_tree", return_value="unconfirmed"):
            self.assertFalse(ledger.release_all(2.0))
        self.assertIn(path, pv._ORPHANS)                                          # retained responsibility, not forgotten
        self.assertTrue(os.path.isdir(path))
        self.assertNotIn(path, pv.settle_orphans(30.0))
        self.assertFalse(os.path.exists(path))
        self.assertNotIn(path, pv._ORPHANS)
        other = tempfile.mkdtemp(prefix="pvc-ledger-")
        self.addCleanup(shutil.rmtree, other, True)
        self.addCleanup(shutil.rmtree, other + "-moved", True)
        self.addCleanup(pv._ORPHANS.pop, other, None)
        identity = pv._identity(os.lstat(other))
        os.rename(other, other + "-moved")
        os.mkdir(other)
        Path(other, "x").write_text("keep")
        pv._keep_orphan(other, identity)
        self.assertNotIn(other, pv.settle_orphans(10.0))                          # dropped from the registry ...
        self.assertEqual(Path(other, "x").read_text(), "keep")                    # ... and never deleted

    def test_a_scratch_directory_registered_after_the_ledger_closed_is_removed_by_the_registering_thread(self):
        ledger = pv._ScratchLedger()
        self.assertTrue(ledger.release_all(1.0))
        late = tempfile.mkdtemp(prefix="pvc-late-ledger-")
        self.addCleanup(shutil.rmtree, late, True)
        Path(late, "f").write_text("x")
        self.assertFalse(ledger.adopt(late))                                      # the run had ended: settled right here
        self.assertFalse(os.path.exists(late))
        self.assertIn(("scratch", late, "removed"), pv._LATE_OUTCOMES)
        stuck = tempfile.mkdtemp(prefix="pvc-late-ledger-")
        self.addCleanup(shutil.rmtree, stuck, True)
        self.addCleanup(pv._ORPHANS.pop, stuck, None)
        with mock.patch.object(pv, "_remove_tree", return_value="unconfirmed"):
            self.assertFalse(ledger.adopt(stuck))
        self.assertIn(stuck, pv._ORPHANS)                                         # an unconfirmed late removal stays owned

    def test_the_release_contract_and_the_document_describe_what_the_code_does(self):
        contract = pv.CONTRACT["containment"]
        for phrase in ("ONE cleanup deadline", "cleanup_grace_seconds", "settle_orphans", "identity", "descriptor-relative",
                       "serialization", "AFTER the required cleanup", "finalization window", "janitor", "NEW effect",
                       "argument capture"):
            self.assertIn(phrase, contract)
        for retired in ("only reads or hashes", "owns no process", "its result is discarded; a worker"):
            self.assertNotIn(retired, contract)                                   # the earlier, incomplete description
        self.assertEqual(pv.CONTRACT["limits"]["cleanup_grace_seconds"], pv.CLEANUP_GRACE)
        for key, value in (("finalize_grace_seconds", pv.FINALIZE_GRACE), ("finalize_floor_seconds", pv.FINALIZE_FLOOR),
                           ("janitor_interval_seconds", pv.JANITOR_INTERVAL), ("settle_floor_seconds", pv.SETTLE_FLOOR),
                           ("settle_backoff_after_passes", pv.SETTLE_BACKOFF_AFTER)):
            self.assertEqual(pv.CONTRACT["limits"][key], value, key)
        self.assertNotIn("is not an operation", pv.CONTRACT["imports"])             # no cached find_spec exemption
        self.assertNotIn("cached find_spec loads nothing", pv.CONTRACT["imports"])
        document = REPO / "docs" / "paper_verifier_closure.md"
        if not document.is_file():
            self.skipTest("docs/ is not part of this installation")
        text = document.read_text(encoding="utf-8")
        for phrase in ("_ScratchLedger", "_LaunchAttempt", "settle_orphans", "FAILURE_CLASS_PREFIXES",
                       "DEPENDENCY_STDLIB_OPERATIONS", "operation deadline + CLEANUP_GRACE", "_ExecutionOwner",
                       "FINALIZE_GRACE", "_minimal_rejection", "JANITOR_INTERVAL", "importlib._bootstrap._gcd_import"):
            self.assertIn(phrase, text)
        self.assertIn("superseded", text)                                         # the earlier no-known-gaps statement

    def test_a_caller_owned_work_directory_is_used_and_not_removed(self):
        fx = Fixture(self).build()
        run = fx.run()                                                            # work_dir=fx.work belongs to the caller
        self.assertEqual((run.status, run.reason), ("PASS", "ok"), run.reason)
        self.assertTrue(fx.work.is_dir())


class FlakyProcess:
    """A real child whose ``wait`` times out ``failures`` times first: a child that cannot be reaped YET."""

    def __init__(self, process, failures):
        self._process, self.failures = process, failures

    def __getattr__(self, name):
        return getattr(self._process, name)

    def wait(self, timeout=None):
        if self.failures > 0:
            self.failures -= 1
            raise subprocess.TimeoutExpired("flaky", timeout)
        return self._process.wait(timeout)


class FlakyAttempt(StubAttempt):
    def __init__(self, failures, **kwargs):
        super().__init__(**kwargs)
        self.failures = failures

    def _create(self):
        super()._create()
        if self.process is not None:
            self.process = FlakyProcess(self.process, self.failures)


class FakeContainment:
    """A containment whose ``reap`` fails until the ``succeed_on``-th call, then really ends the child."""
    job = None

    def __init__(self, succeed_on):
        self.calls, self.succeed_on, self.closed = 0, succeed_on, 0
        self.cleanup_end = time.monotonic() - 100.0   # long past: a retry must not be clipped by it

    def reap(self, process, grace):
        self.calls += 1
        if self.calls < self.succeed_on:
            return False
        process.kill()
        process.wait()
        return True

    def close(self, process):
        self.closed += 1
        return True


# Fake supervisor programs (substituted for ``SUPERVISOR_TEMPLATE``): each owns ONE real descendant and reports it in its
# ``R`` line, so the tests below retain real descendants.  The first answers the kill request "processes live" twice and
# only then cleans; the second never answers anything.
FAKE_LIVE_SUPERVISOR = r'''import os,subprocess,sys
_A=%(argv)s
_R=%(ctl)d
_W=%(st)d
_G=%(grace)s
g=subprocess.Popen([sys.executable,'-c','import time; time.sleep(120)'])
os.write(_W,('R'+str(g.pid)+'\n').encode())
n=0
while True:
 c=os.read(_R,1)
 if c==b'K':
  n+=1
  if n<3:
   os.write(_W,b'K1 0\n')
  else:
   g.kill(); g.wait(); os.write(_W,b'K0 0\n')
 elif c==b'S':
  os.write(_W,b'S1 0\n')
 else:
  g.kill(); g.wait(); os._exit(0)
'''
FAKE_MUTE_SUPERVISOR = r'''import os,subprocess,sys,time
_A=%(argv)s
_R=%(ctl)d
_W=%(st)d
_G=%(grace)s
g=subprocess.Popen([sys.executable,'-c','import time; time.sleep(120)'])
os.write(_W,('R'+str(g.pid)+'\n').encode())
time.sleep(120)
'''


class FinalizationAndCancellation(RejectionMixin, unittest.TestCase):
    """Argument capture and every serialization are inside the deadline model, a rejection is always finalized inside its
    one window, no helper starts a NEW effect after cancellation, and unsettled resources are retried until released."""

    TIMEOUT = 6

    def child(self):
        process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(lambda: (process.kill(), process.wait(), [s.close() for s in (process.stdin, process.stdout, process.stderr)]))
        return process

    def scratch(self):
        root = Path(tempfile.mkdtemp(prefix="pvc-cancel-"))
        self.addCleanup(shutil.rmtree, root, True)
        return root

    # ---- finding 1: capture, serialization, finalization ---------------------------------------------------------

    def test_a_blocked_argument_capture_ends_the_run_at_the_deadline_and_a_late_capture_is_dropped(self):
        fx = Fixture(self).build()
        stuck = Stuck(self)
        with mock.patch.object(pv, "_snapshot", side_effect=stuck):
            begun = time.monotonic()
            run = fx.run(timeout=2)
            elapsed = time.monotonic() - begun
        self.assertTrue(stuck.entered.is_set())
        self.assertRejected(run, "operation_deadline_exceeded:arguments:blocked", "execution")
        self.assertIsNone(run.receipt["process"])
        self.assertLess(elapsed, 2 + pv.CLEANUP_GRACE + pv.FINALIZE_GRACE + 3)
        pv.validate_receipt(run.receipt)
        stuck.release.set()
        real = pv._snapshot
        released = threading.Event()
        self.addCleanup(released.set)

        def slow(*args, **kwargs):
            released.wait(60)
            return real(*args, **kwargs)
        with mock.patch.object(pv, "_snapshot", side_effect=slow):
            late = fx.run(timeout=2)
        self.assertRejected(late, "operation_deadline_exceeded:arguments:blocked", "execution")
        released.set()                                                           # the capture now completes, successfully ...
        for helper in [t for t in threading.enumerate() if t.name == "pvc-bounded-arguments"]:
            helper.join(10)
        self.assertEqual((late.status, late.reason.split(":")[0]), ("REJECTED", "operation_deadline_exceeded"))   # ... and changes nothing
        self.assertIsNone(late.receipt["process"])

    def test_a_phase_that_succeeds_after_the_deadline_is_never_accepted(self):
        for _ in range(3):
            with pv._Operation(0.3) as operation:
                def finishes_at_the_deadline():
                    time.sleep(max(0.0, operation.deadline - time.monotonic()))
                    return "result"
                error = self.assertRaisesCode("operation_deadline_exceeded", pv._Operation.bounded, "phase", finishes_at_the_deadline)
                self.assertRegex(error.detail, r"^phase:(blocked|late)$")          # never the value
                self.assertTrue(operation.cancelled.is_set())
        with pv._Operation(5.0):
            self.assertEqual(pv._Operation.bounded("phase", lambda: "result"), "result")   # the positive inside the bound
            error = self.assertRaisesCode("closure_module_changed", pv._Operation.bounded, "phase", pv._reject, "closure_module_changed")
            self.assertEqual(error.code, "closure_module_changed")

    def rejected_run(self, fx):
        return fx.run(inputs={"doc": pv.InputSpec(fx.data, "doc.txt", sha(b"not the input"))})

    def test_an_already_rejected_receipt_whose_first_seal_blocks_is_finalized_by_the_safety_receipt_inside_its_window(self):
        fx = Fixture(self).build()
        stuck = Stuck(self)                                                      # EVERY call of the binding blocks
        with mock.patch.object(pv, "FINALIZE_GRACE", 0.8), mock.patch.object(pv, "_binding", side_effect=stuck):
            begun = time.monotonic()
            run = self.rejected_run(fx)
            elapsed = time.monotonic() - begun
        self.assertTrue(stuck.entered.is_set())
        self.assertEqual(run.status, "REJECTED")
        self.assertTrue(run.reason.startswith("input_hash_mismatch"), run.reason)  # the true reason survives
        self.assertEqual(run.receipt["refused"], ["finalization_fallback"])
        self.assertEqual(run.receipt["binding_sha256"], pv._direct_binding(run.receipt))   # sealed through the plain function
        self.assertIsNone(run.receipt["process"])
        self.assertLess(elapsed, 60)
        pv.validate_receipt(run.receipt)                                          # canonical, truthful and bound

    def test_a_pass_whose_seal_blocks_repeatedly_is_a_rejection_of_the_true_reason_sealed_by_the_safety_receipt(self):
        fx = Fixture(self).build()
        stuck = Stuck(self)
        with mock.patch.object(pv, "FINALIZE_GRACE", 0.8), mock.patch.object(pv, "_binding", side_effect=stuck):
            begun = time.monotonic()
            run = fx.run(timeout=self.TIMEOUT)
            elapsed = time.monotonic() - begun
        self.assertRejected(run, "operation_deadline_exceeded:seal:blocked", "execution")
        self.assertGreaterEqual(elapsed, self.TIMEOUT - 0.5)                      # the acceptance seal waited for the deadline ...
        self.assertLess(elapsed, self.TIMEOUT + 2.5)                              # ... and the rejection was finalized in its window
        self.assertEqual(run.receipt["refused"], ["finalization_fallback"])
        self.assertEqual(run.receipt["binding_sha256"], pv._direct_binding(run.receipt))
        self.assertIsNone(run.receipt["verifier"])
        pv.validate_receipt(run.receipt)

    def test_when_even_the_safety_receipts_binding_blocks_a_valid_sealed_v1_receipt_is_still_returned_once_not_retried(self):
        """Both bindings block: the bounded wait ends, and the last step is the constant-size inline computation, so the
        returned object is a SEALED, VALID v1 rejection (no invalid object, no versioned exception to the interface)."""
        fx = Fixture(self).build()
        first, second = Stuck(self), Stuck(self)
        with mock.patch.object(pv, "FINALIZE_GRACE", 0.8), mock.patch.object(pv, "_binding", side_effect=first), \
                mock.patch.object(pv, "_direct_binding", side_effect=second):
            begun = time.monotonic()
            run = self.rejected_run(fx)
            elapsed = time.monotonic() - begun
        self.assertEqual(run.status, "REJECTED")
        self.assertTrue(run.reason.startswith("input_hash_mismatch"), run.reason)    # the causal reason survives
        self.assertEqual(run.receipt["refused"], ["finalization_fallback"])
        self.assertEqual(second.calls, 1)                                         # one attempt in the window, no recursive retry
        self.assertEqual(run.receipt["binding_sha256"], pv._safety_binding(run.receipt))
        self.assertLess(elapsed, 60)
        pv.validate_receipt(run.receipt)                                          # the original v1 contract, with no exception
        try:
            from trace_gc.schema import validate
        except ImportError:                                                       # pragma: no cover
            return
        validate("paper-verifier-closure-receipt", run.receipt)                   # and the published schema accepts it

    def test_a_noncanonical_rejection_keeps_its_causal_reason_and_a_new_attempt_that_succeeds_is_valid(self):
        """Content outside the canonical domain is WITHHELD, not blamed: the reason and the process evidence stay, so the
        retry that succeeds seals a receipt that Python and the schema both read back."""
        fx = Fixture(self).build()
        passing = fx.run().receipt
        try:
            from trace_gc.schema import validate
        except ImportError:                                                       # pragma: no cover
            validate = None
        cases = (("containment_cleanup_failed", {"cleanup_failed": True}),
                 ("execution_timeout", {"timed_out": True}),
                 ("protocol_output_overflow", {"overflow": "stdout"}),
                 ("containment_unresolved_descendants", {"descendants": True}),
                 ("operation_deadline_exceeded:final", {"timed_out": True, "cleanup_failed": True}),
                 ("input_hash_mismatch:doc", {}))
        for reason, flags in cases:
            with self.subTest(reason):
                receipt = copy.deepcopy(passing)
                receipt.update(status="REJECTED", reason=reason, failure_class=pv.failure_class(reason.partition(":")[0]),
                               verifier=None, binding_sha256=None)
                receipt["process"].update(cleanup_failed=False, timed_out=False, overflow=None, descendants=False)
                receipt["process"].update(flags)
                receipt["violations"] = ["\ud800"]                                # the first binding fails: not canonical
                pv._seal(receipt)                                                 # the second (real) binding succeeds
                self.assertEqual(receipt["reason"], reason)                       # NOT rewritten into a protocol reason
                self.assertEqual({k: receipt["process"][k] for k in flags}, flags)   # and the process evidence is intact
                self.assertEqual(receipt["refused"], ["finalization_content_withheld"])
                self.assertEqual(receipt["violations"], [])
                self.assertEqual(receipt["binding_sha256"], pv._binding(receipt))
                pv.validate_receipt(receipt)                                      # Python readback (reason/process agree)
                if validate is not None:
                    validate("paper-verifier-closure-receipt", receipt)           # schema readback agrees

    def test_a_pass_that_cannot_be_serialized_becomes_a_consistent_protocol_rejection_and_flags_never_contradict_it(self):
        passing = Fixture(self).build().run().receipt
        receipt = copy.deepcopy(passing)
        receipt["verifier"]["result"] = {"status": "PASS", "bad": "\ud800"}
        receipt["binding_sha256"] = None
        pv._seal(receipt)
        self.assertEqual((receipt["status"], receipt["reason"]), ("REJECTED", "protocol_receipt_not_canonical"))
        pv.validate_receipt(receipt)
        # with a retained flag the protocol reason would contradict the process record: the NEUTRAL reason is chosen instead
        flagged = copy.deepcopy(passing)
        flagged["process"]["timed_out"] = True
        flagged["verifier"]["result"] = {"status": "PASS", "bad": "\ud800"}
        flagged["binding_sha256"] = None
        pv._seal(flagged)
        self.assertEqual((flagged["status"], flagged["reason"].partition(":")[0]), ("REJECTED", "execution_internal_error"))
        self.assertTrue(flagged["process"]["timed_out"])
        pv.validate_receipt(flagged)

    def test_the_safety_receipt_is_constant_size_and_independent_of_what_the_caller_or_the_child_produced(self):
        hostile = pv._receipt(status="REJECTED", reason="x" * 5000, manifest_sha256="not a digest", release_sha256=None,
                              params_sha256="0" * 64, violations=["\ud800" * 100], refused=["y" * 5000])
        minimal = pv._minimal_rejection(hostile)
        self.assertEqual(minimal["reason"], "execution_internal_error:reason_not_canonical")   # too long: neutral code
        self.assertIsNone(minimal["manifest_sha256"])                              # not a digest: dropped, never copied
        self.assertEqual((minimal["violations"], minimal["refused"], minimal["process"], minimal["evidence"]),
                         ([], ["finalization_fallback"], None, None))
        minimal["binding_sha256"] = pv._safety_binding(minimal)
        pv.validate_receipt(minimal)
        self.assertLess(len(pv.canonical_bytes(minimal)), 2048)

    def test_a_clean_run_inside_the_bound_is_sealed_by_the_full_receipt_without_the_fallback(self):
        run = Fixture(self).build().run(timeout=self.TIMEOUT)
        self.assertEqual((run.status, run.reason), ("PASS", "ok"), run.reason)
        self.assertEqual(run.receipt["refused"], [])
        self.assertEqual(run.receipt["binding_sha256"], pv._binding(run.receipt))
        pv.validate_receipt(run.receipt)

    def test_every_data_dependent_phase_of_the_verification_path_is_a_bounded_phase(self):
        import ast
        tree = ast.parse((REPO / "trace_gc" / "verifier_closure.py").read_text(encoding="utf-8"))

        def direct_calls(name):
            function = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == name)
            return {c.func.id for c in ast.walk(function) if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)}
        self.assertFalse(direct_calls("run_verifier") & {"_snapshot", "validate_manifest", "canonical_digest", "canonical_dumps"})
        self.assertFalse(direct_calls("verify_closure") & {"validate_manifest", "canonical_digest", "release_record"})
        self.assertFalse(direct_calls("_run") & {"canonical_digest", "_accept_report", "_evidence"})
        self.assertFalse(direct_calls("_verify_core") & {"canonical_digest"})

    # ---- finding 2: nothing NEW starts after cancellation --------------------------------------------------------

    @unittest.skipUnless(sys.platform.startswith("linux"), "the supervisor launch path creates the pipes")
    def test_the_second_pipe_is_never_started_when_the_launch_was_abandoned_during_the_first(self):
        tmp = self.scratch()
        real_pipe, gate, entered, fds, count = os.pipe, threading.Event(), threading.Event(), [], []
        self.addCleanup(gate.set)

        def pipe():
            count.append(1)
            if len(count) == 1:
                entered.set()
                gate.wait(60)                                                    # the first os.pipe() is blocked in the kernel
            pair = real_pipe()
            fds.extend(pair)
            return pair
        popen = mock.Mock(side_effect=AssertionError("a process was started for an abandoned launch"))
        mkdtemp = mock.Mock(side_effect=AssertionError("a directory was created for an abandoned launch"))
        attempt = pv._LaunchAttempt([sys.executable, "-c", "pass"], str(tmp), windows=False)
        with mock.patch.object(pv.os, "pipe", side_effect=pipe), mock.patch.object(pv.subprocess, "Popen", popen), \
                mock.patch.object(pv.tempfile, "mkdtemp", mkdtemp):
            self.assertEqual(pv._bounded_launch(attempt, time.monotonic() + 0.4), (None, "child_launch_timeout"))
            self.assertTrue(entered.wait(5))
            gate.set()                                                            # the first pipe now returns
            self.assertTrue(attempt.settle(30))
        self.assertEqual(len(count), 1)                                           # NO second pipe was started
        popen.assert_not_called()
        mkdtemp.assert_not_called()
        self.assertEqual((attempt._fds, attempt.process, attempt.prefix), ([], None, None))
        self.assertEqual(len(fds), 2)
        for descriptor in fds:                                                    # and the pair that was made is closed
            with self.assertRaises(OSError):
                os.fstat(descriptor)

    def test_no_removal_starts_after_the_final_inspection_blocked_past_the_callers_deadline(self):
        root = self.scratch()
        top = root / "top"
        top.mkdir()
        (top / "f.bin").write_bytes(b"x")
        identity = pv._identity(os.lstat(top))
        gate, entered, calls, removals = threading.Event(), threading.Event(), [], []
        real_lstat, real_rmdir = os.lstat, os.rmdir
        self.addCleanup(gate.set)

        def lstat(path, *args, **kwargs):
            if os.fspath(path) == str(top) and not kwargs:
                calls.append(1)
                if len(calls) == 2:                                               # the inspection right before the final rmdir
                    entered.set()
                    gate.wait(60)
            return real_lstat(path, *args, **kwargs)

        def rmdir(path, *args, **kwargs):
            removals.append(os.fspath(path))
            return real_rmdir(path, *args, **kwargs)
        with mock.patch.object(pv.os, "lstat", side_effect=lstat), mock.patch.object(pv.os, "rmdir", side_effect=rmdir):
            self.assertEqual(pv._bounded_remove(str(top), 0.5, identity), "unconfirmed")
            self.assertTrue(entered.is_set())
            gate.set()                                                            # the blocked inspection returns after cancellation
            for helper in [t for t in threading.enumerate() if t.name == "pvc-cleanup"]:
                helper.join(10)
        self.assertNotIn(str(top), removals)                                      # NO rmdir was started
        self.assertTrue(top.is_dir())
        self.assertEqual(os.listdir(top), [])

    def test_the_windows_unlink_to_rmdir_fallback_has_a_checkpoint_between_the_two_removals(self):
        root = self.scratch()
        top = root / "top"
        top.mkdir()
        entry = top / "link-like"
        entry.write_bytes(b"x")
        identity = pv._identity(os.lstat(top))
        gate, entered, removals = threading.Event(), threading.Event(), []
        real_rmdir = os.rmdir
        self.addCleanup(gate.set)

        def unlink(path, *args, **kwargs):
            entered.set()
            gate.wait(60)
            raise PermissionError("the unlink failed after it was cancelled")    # so the rmdir fallback WOULD follow

        def rmdir(path, *args, **kwargs):
            removals.append(os.fspath(path))
            return real_rmdir(path, *args, **kwargs)
        with mock.patch.object(pv, "_DIR_FD_REMOVAL", False), mock.patch.object(pv.os, "unlink", side_effect=unlink), \
                mock.patch.object(pv.os, "rmdir", side_effect=rmdir):
            self.assertEqual(pv._bounded_remove(str(top), 0.5, identity), "unconfirmed")
            self.assertTrue(entered.is_set())
            gate.set()
            for helper in [t for t in threading.enumerate() if t.name == "pvc-cleanup"]:
                helper.join(10)
        self.assertEqual(removals, [])                                            # the fallback never started
        self.assertTrue(entry.exists())

    def test_a_second_scratch_directory_is_not_created_once_the_phase_was_abandoned(self):
        root = self.scratch()
        real, gate, entered, made = tempfile.mkdtemp, threading.Event(), threading.Event(), []
        self.addCleanup(gate.set)

        def slow(*args, **kwargs):
            prefix = kwargs.get("prefix", "")
            if prefix == "pvc-bytecode-":
                entered.set()
                gate.wait(60)                                                    # the FIRST creation is blocked
            path = real(*args, **kwargs)
            made.append(os.path.basename(path))
            return path
        run_dir = root / "run"
        run_dir.mkdir()
        with mock.patch.object(pv.tempfile, "mkdtemp", side_effect=slow), pv._Operation(0.4) as operation:
            self.assertTrue(operation.scratch.adopt(str(run_dir)))                      # the run owns its work directory
            error = self.assertRaisesCode("operation_deadline_exceeded", pv._Operation.bounded, "frame", pv._fresh_dirs,
                                          str(run_dir))
            self.assertEqual(error.detail, "frame:blocked")
            gate.set()
            for helper in [t for t in threading.enumerate() if t.name == "pvc-bounded-frame"]:
                helper.join(10)
            self.assertEqual([name for name in made if name.startswith("pvc-bytecode-")], made)   # the first creation completed late
            self.assertTrue(operation.scratch.release_all(5.0))
        self.assertEqual([name for name in made if name.startswith("pvc-cwd-")], [])   # the second creation never began
        self.assertFalse(run_dir.exists())                                              # and everything owned was removed by the ledger

    # ---- finding 3: unsettled resources are owned, retried and released ---------------------------------------------

    def test_a_child_that_cannot_be_reaped_yet_stays_owned_and_a_later_retry_reaps_and_closes_it(self):
        after = threading.Event()
        self.addCleanup(after.set)
        with mock.patch.object(pv, "JANITOR_INTERVAL", 3600.0):
            attempt = FlakyAttempt(2, after=after)
            self.assertEqual(pv._bounded_launch(attempt, time.monotonic() + 0.4), (None, "child_launch_timeout"))
            after.set()
            self.assertTrue(attempt.settled.wait(60))
            child = attempt.process._process
            self.addCleanup(lambda: (child.kill(), child.wait()))
            self.assertEqual((attempt.released, attempt.clean), (False, False))   # the prompt truth
            self.assertIn(attempt._token, pv._OWNED)                              # ... and the debt is a registry record
            self.assertFalse(any(stream.closed for stream in (child.stdin, child.stdout, child.stderr)))   # nothing closed under a live child
            self.assertFalse(attempt.settle(0.3))                                 # an explicit settle RETRIES (second failure)
            self.assertNotIn(("child", str(child.pid), "reaped"), pv._LATE_OUTCOMES)
            token = attempt._token
            remaining = pv.settle_orphans(10.0)                                   # the registered settler now succeeds
        self.assertNotIn("launch#%d" % token, remaining)
        self.assertEqual((attempt.released, attempt.clean), (True, True))
        self.assertIsNotNone(child.poll())
        self.assertTrue(all(stream.closed for stream in (child.stdin, child.stdout, child.stderr)))
        self.assertNotIn(token, pv._OWNED)
        self.assertIn(("child", str(child.pid), "reaped"), pv._LATE_OUTCOMES)

    def test_the_janitor_settles_an_owned_record_without_anyone_asking(self):
        after = threading.Event()
        self.addCleanup(after.set)
        with mock.patch.object(pv, "JANITOR_INTERVAL", 0.05), mock.patch.object(pv, "SETTLE_FLOOR", 0.5):
            attempt = FlakyAttempt(1, after=after)
            self.assertEqual(pv._bounded_launch(attempt, time.monotonic() + 0.4), (None, "child_launch_timeout"))
            after.set()
            self.assertTrue(attempt.settled.wait(60))
            child = attempt.process._process
            self.addCleanup(lambda: (child.kill(), child.wait()))
            deadline = time.monotonic() + 30
            while not attempt.released and time.monotonic() < deadline:
                time.sleep(0.05)
        self.assertTrue(attempt.released)                                         # with no settle() and no settle_orphans() call
        self.assertIsNotNone(child.poll())
        self.assertTrue(all(stream.closed for stream in (child.stdin, child.stdout, child.stderr)))

    def test_an_execution_that_could_not_be_reaped_is_retried_off_the_runs_clock_until_it_is_released(self):
        process = self.child()
        stop = threading.Event()
        reader = threading.Thread(target=lambda: process.stdout.read(), daemon=True)
        reader.start()
        contain = FakeContainment(succeed_on=2)
        owner = pv._ExecutionOwner(contain, process, [reader], stop)
        self.assertFalse(owner.settle(0.2))                                       # the child is alive: nothing may be closed
        self.assertTrue(reader.is_alive())
        self.assertFalse(process.stdout.closed)
        self.assertEqual(contain.closed, 0)
        token = pv._own("execution", owner.retry)
        with mock.patch.object(pv, "JANITOR_INTERVAL", 3600.0):
            remaining = pv.settle_orphans(10.0)
        self.assertNotIn("execution#%d" % token, remaining)
        self.assertIsNone(contain.cleanup_end)                                    # the retry is not clipped by the old deadline
        self.assertIsNotNone(process.poll())
        reader.join(5)
        self.assertFalse(reader.is_alive())
        self.assertTrue(all(stream.closed for stream in (process.stdin, process.stdout, process.stderr)))   # closed after the thread
        self.assertEqual(contain.closed, 1)
        self.assertNotIn(token, pv._OWNED)

    def supervised(self, template):
        """A REAL launch attempt under a fake supervisor program, adopted by a real containment and attached: the fake
        supervisor owns one real descendant (its ``R`` line names it)."""
        tmp = self.scratch()
        with mock.patch.object(pv, "SUPERVISOR_TEMPLATE", template), mock.patch.object(pv, "SUPERVISOR_PURGE", 0.5):
            attempt = pv._LaunchAttempt([sys.executable, "-c", "pass"], str(tmp), windows=False)
            attempt._create()
        contain = pv._Containment(str(tmp), None)
        contain.adopt(attempt)
        process = attempt.process
        contain.attach(process, 10.0)
        descendant = contain._state["child"]

        def reap_everything():
            for pid in (descendant, process.pid):
                try:
                    os.kill(pid, 9)
                except OSError:
                    pass
            process.poll()
        self.addCleanup(reap_everything)
        return attempt, contain, process, descendant

    @unittest.skipUnless(sys.platform.startswith("linux"), "the supervisor protocol is the Linux containment")
    def test_a_supervisor_that_keeps_answering_that_processes_live_is_never_ended_and_its_descendant_is_reaped_on_recovery(self):
        with mock.patch.object(pv, "SETTLE_BACKOFF_AFTER", 1), mock.patch.object(pv, "JANITOR_INTERVAL", 3600.0):
            _attempt, contain, process, descendant = self.supervised(FAKE_LIVE_SUPERVISOR)
            owner = pv._ExecutionOwner(contain, process, [], threading.Event())
            for _ in range(2):                                                    # far more than any bounded retry count would allow
                self.assertFalse(owner.settle(2.0))                               # the caller-visible truth: not settled
                self.assertTrue(alive(descendant))                                # the descendant still has an owner ...
                self.assertIsNone(process.poll())                                 # ... the supervisor, which was NOT ended
                self.assertFalse(contain._closed)
            self.assertFalse(contain.tree_settled)
            token = pv._own("execution", owner.retry)
            self.assertNotIn("execution#%d" % token, pv.settle_orphans(10.0))     # the cleanup recovers: K answers 0 0
        self.assertFalse(alive(descendant))                                       # eventual reaping of the descendant
        self.assertIsNotNone(process.poll())                                      # and of the supervisor
        self.assertTrue(contain._closed and contain.tree_settled and owner.released)
        self.assertTrue(all(stream.closed for stream in (process.stdin, process.stdout, process.stderr)))
        self.assertNotIn(token, pv._OWNED)

    @unittest.skipUnless(sys.platform.startswith("linux"), "the supervisor protocol is the Linux containment")
    def test_a_supervisor_that_cannot_answer_has_its_descendants_ended_from_here_before_it_is_ended_itself(self):
        with mock.patch.object(pv, "JANITOR_INTERVAL", 3600.0):
            _attempt, contain, process, descendant = self.supervised(FAKE_MUTE_SUPERVISOR)
            owner = pv._ExecutionOwner(contain, process, [], threading.Event())
            self.assertTrue(alive(descendant))
            for _ in range(8):
                if owner.settle(1.0):
                    break
        self.assertTrue(owner.released)
        self.assertFalse(alive(descendant))                                       # ended by THIS process, by pid and start time
        self.assertIsNotNone(process.poll())
        self.assertTrue(contain.tree_settled)
        self.assertIsNot(contain._clean, True)                                    # the unanswered protocol stays a cleanup failure

    @unittest.skipUnless(sys.platform.startswith("linux"), "the supervisor protocol is the Linux containment")
    def test_a_late_launch_never_ends_a_live_supervisor_and_a_mute_one_only_after_its_descendants_are_gone(self):
        tmp = self.scratch()
        with mock.patch.object(pv, "SUPERVISOR_TEMPLATE", FAKE_LIVE_SUPERVISOR), mock.patch.object(pv, "SUPERVISOR_PURGE", 0.5):
            live = pv._LaunchAttempt([sys.executable, "-c", "pass"], str(tmp), windows=False)
            live._create()
        self.addCleanup(lambda: (live.process.kill(), live.process.wait()))
        time.sleep(0.3)
        self.assertFalse(live._reap_late_child(live.process, 1.0))               # answers "live": kept, not ended
        self.assertIsNone(live.process.poll())
        self.assertFalse(live._tree_settled)
        self.assertFalse(live._reap_late_child(live.process, 1.0))
        self.assertTrue(live._reap_late_child(live.process, 5.0))                # third answer is clean: now it is ended
        self.assertTrue(live._tree_settled and live._tree is True)
        with mock.patch.object(pv, "SUPERVISOR_TEMPLATE", FAKE_MUTE_SUPERVISOR), mock.patch.object(pv, "SUPERVISOR_PURGE", 0.5):
            mute = pv._LaunchAttempt([sys.executable, "-c", "pass"], str(tmp), windows=False)
            mute._create()
        self.addCleanup(lambda: (mute.process.kill(), mute.process.wait()))
        deadline = time.monotonic() + 15
        while not mute._reap_late_child(mute.process, 1.0) and time.monotonic() < deadline:
            pass
        self.assertIsNotNone(mute.process.poll())
        self.assertTrue(mute._tree_settled)
        self.assertIsNone(mute._tree)                                             # confirmed by this process, not by the supervisor

    def test_the_registry_spends_one_shared_budget_and_never_starts_a_record_once_it_is_spent(self):
        started, release = [], threading.Event()
        self.addCleanup(release.set)

        def slow(budget):
            started.append(("slow", budget))
            release.wait(5)                                                       # a BLOCKED settler
            return False

        def quick(budget):
            started.append(("quick", budget))
            return True
        with mock.patch.object(pv, "JANITOR_INTERVAL", 3600.0):
            tokens = [pv._own("slow", slow), pv._own("quick-1", quick), pv._own("quick-2", quick)]
            self.addCleanup(lambda: [pv._disown(token) for token in tokens])
            begun = time.monotonic()
            remaining = pv._settle_owned(0.3)
            elapsed = time.monotonic() - begun
            self.assertLess(elapsed, 2.0)                                         # the caller did not wait for the blocked settler
            self.assertEqual([name for name, _ in started], ["slow"])             # and no later record was started
            self.assertLessEqual(started[0][1], 0.3)                              # it received the caller's budget, not a floor
            self.assertEqual(len(remaining), 3)
            after = pv._settle_owned(2.0)                                         # unrelated records are not held up by it ...
            self.assertEqual([name for name, _ in started].count("slow"), 1)      # ... and the blocked one gets NO duplicate worker
            self.assertEqual(after, ["slow#%d" % tokens[0]])
            release.set()
            deadline = time.monotonic() + 10
            while tokens[0] in pv._SETTLING and time.monotonic() < deadline:
                time.sleep(0.02)
        self.assertEqual({name for name, _ in started}, {"slow", "quick"})

    def test_a_settlement_that_cannot_take_the_records_lock_inside_its_budget_starts_nothing(self):
        fresh = FlakyAttempt(1)
        pv._bounded_launch(fresh, time.monotonic() + 10)
        self.addCleanup(lambda: (fresh.process._process.kill(), fresh.process._process.wait()))
        spy = mock.Mock(side_effect=AssertionError("a second cleanup worker was started"))
        with fresh._settle_lock:                                                  # another settlement is in progress
            with mock.patch.object(fresh, "_reap_late_child", spy):
                begun = time.monotonic()
                self.assertFalse(fresh._retry(0.2))
                self.assertLess(time.monotonic() - begun, 2.0)
        spy.assert_not_called()
        self.assertFalse(fresh.released)
        owner = pv._ExecutionOwner(FakeContainment(1), self.child(), [], threading.Event())
        with owner._lock:
            begun = time.monotonic()
            self.assertFalse(owner.settle(0.2))                                   # the owner's lock honours the same budget
            self.assertLess(time.monotonic() - begun, 2.0)

    @unittest.skipUnless(sys.platform.startswith("linux"), "the request pipe exists on the Linux supervisor path only")
    def test_a_request_write_to_a_wedged_supervisor_cannot_block_past_the_budget(self):
        tmp = self.scratch()
        attempt = pv._LaunchAttempt([sys.executable, "-c", "pass"], str(tmp), windows=False)
        attempt._create()
        contain = pv._Containment(str(tmp), None)
        contain.adopt(attempt)

        def settle():
            attempt.process.kill()
            attempt.process.wait()
            contain.tree_settled = True
            contain.close(attempt.process)
        self.addCleanup(settle)
        self.assertFalse(os.get_blocking(attempt.ctl_w))                          # non-blocking by construction
        with mock.patch.object(pv.os, "write", side_effect=BlockingIOError(11, "pipe full")):
            begun = time.monotonic()
            self.assertIsNone(contain._ask("K", 5.0))                              # a full pipe is "no answer", at once
            self.assertLess(time.monotonic() - begun, 1.0)

    @unittest.skipUnless(sys.platform.startswith("linux"), "the status reader belongs to the Linux supervisor protocol")
    def test_a_status_descriptor_whose_reader_is_still_blocked_is_closed_by_the_reader_when_it_ends(self):
        contain = pv._Containment(os.getcwd())
        read_end, write_end = os.pipe()
        contain._st_r = read_end
        contain._reader = threading.Thread(target=contain._pump_status, args=(read_end,), daemon=True)
        contain._reader.start()
        self.addCleanup(lambda: [os.close(fd) for fd in (write_end,) if fd >= 0 and _fd_open(fd)])
        time.sleep(0.1)
        contain.close(None)
        self.assertEqual(contain._st_r, read_end)                                  # not closed under the blocked reader
        self.assertTrue(contain._reader.is_alive())
        os.close(write_end)                                                        # the reader sees EOF and ends ...
        contain._reader.join(10)
        self.assertFalse(contain._reader.is_alive())
        self.assertIsNone(contain._st_r)                                           # ... and closed the descriptor itself
        with self.assertRaises(OSError):
            os.fstat(read_end)

    def test_a_closed_containment_adopts_nothing_and_closing_twice_releases_nothing_twice(self):
        contain = pv._Containment(os.getcwd())
        contain.close(None)
        contain.close(None)
        self.assertRaisesCode("containment_closed", contain.adopt, StubAttempt())

    @unittest.skipUnless(sys.platform.startswith("linux"), "the supervisor protocol is the Linux containment")
    def test_a_supervisor_that_answers_that_processes_live_stays_alive_and_a_later_reap_ends_it(self):
        contain = pv._Containment(os.getcwd())
        read_end, write_end = os.pipe()
        contain._ctl_w = write_end
        self.addCleanup(lambda: [os.close(fd) for fd in (read_end, write_end)])
        os.set_blocking(read_end, False)
        replies = iter([(2, 0), (0, 0)])
        process = mock.Mock(returncode=0)
        process.wait.return_value = 0
        with mock.patch.object(pv._Containment, "_ask", side_effect=lambda tag, limit: next(replies)):
            self.assertFalse(contain.reap(process, 1.0))
            with self.assertRaises(BlockingIOError):
                os.read(read_end, 1)                                               # no quit request: the supervisor is kept
            process.kill.assert_not_called()
            self.assertTrue(contain.reap(process, 1.0))                            # the retry gets the clean answer
            self.assertEqual(os.read(read_end, 1), b"Q")
        self.assertTrue(contain._clean)

    # ---- finding 3: every remaining caller-controlled or data-dependent step is a bounded phase --------------------

    class BlockingPath:
        """A caller-supplied ``work_dir`` whose ``os.fspath`` conversion blocks (it is read only inside the capture phase)."""
        def __init__(self, test):
            self.release, self.entered = threading.Event(), threading.Event()
            test.addCleanup(self.release.set)

        def __fspath__(self):
            self.entered.set()
            self.release.wait(60)
            return "/nonexistent-blocked"

    def test_a_blocked_work_dir_conversion_ends_the_run_in_the_capture_phase(self):
        fx = Fixture(self).build()
        blocking = self.BlockingPath(self)
        begun = time.monotonic()
        run = fx.run(work_dir=blocking, timeout=2)
        self.assertTrue(blocking.entered.is_set())
        self.assertRejected(run, "operation_deadline_exceeded:arguments:blocked", "execution")
        self.assertLess(time.monotonic() - begun, 2 + pv.CLEANUP_GRACE + pv.FINALIZE_GRACE + 3)
        pv.validate_receipt(run.receipt)
        self.assertEqual(fx.run().status, "PASS")                                 # the ordinary positive counterpart

    DATA_PHASES = (("module_table", "module_table_digest", 1), ("facts", "_run_facts", 1), ("probe_parse", "_parse_probe", 1),
                   ("probe_command", "_launch_arguments", 1), ("frame", "_launch_arguments", 2),
                   ("report_rows", "_check_report_rows", 1))

    def test_every_hash_parse_and_comprehension_phase_ends_the_run_at_the_deadline_when_it_blocks(self):
        fx = Fixture(self).build()
        digest = pv.module_table_digest(fx.table())
        for where, name, nth in self.DATA_PHASES:
            with self.subTest(phase=where):
                stuck = Stuck(self, getattr(pv, name), nth)
                begun = time.monotonic()
                with mock.patch.object(pv, name, side_effect=stuck):
                    run = fx.run(timeout=EnforcedDeadlines.TIMEOUT, expected_module_table_sha256=digest)
                elapsed = time.monotonic() - begun
                self.assertTrue(stuck.entered.is_set(), where)
                self.assertRejected(run, "operation_deadline_exceeded:%s:blocked" % where, "execution")
                self.assertGreaterEqual(elapsed, EnforcedDeadlines.TIMEOUT - 0.5, where)
                self.assertLess(elapsed, EnforcedDeadlines.TIMEOUT + 6, where)
                stuck.release.set()
                pv.validate_receipt(run.receipt)
        positive = fx.run(timeout=EnforcedDeadlines.TIMEOUT, expected_module_table_sha256=digest)   # all phases inside the bound
        self.assertEqual((positive.status, positive.reason), ("PASS", "ok"), positive.reason)

    def test_a_phase_that_completes_after_the_deadline_is_rejected_for_the_data_dependent_phases_too(self):
        fx = Fixture(self).build()
        real = pv._run_facts

        def late(verified, captured):
            time.sleep(max(0.0, pv._Operation.current().deadline - time.monotonic()) + 0.2)
            return real(verified, captured)
        with mock.patch.object(pv, "_run_facts", side_effect=late):
            run = fx.run(timeout=EnforcedDeadlines.TIMEOUT)
        self.assertRejected(run, "operation_deadline_exceeded:facts:", "execution")    # blocked or late, never the value
        self.assertRegex(run.reason, r"^operation_deadline_exceeded:facts:(blocked|late)$")

    def test_the_direct_calls_of_the_run_path_contain_no_hash_parse_or_path_conversion_in_any_form(self):
        """Names and attributes, including inside comprehensions and nested functions: hashing, canonicalization and path
        conversion appear in these functions only as arguments handed to ``_Operation.bounded``."""
        import ast
        tree = ast.parse((REPO / "trace_gc" / "verifier_closure.py").read_text(encoding="utf-8"))

        def calls(name):
            function = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == name)
            found = set()
            for node in ast.walk(function):
                if isinstance(node, ast.Call):
                    found.add(node.func.id if isinstance(node.func, ast.Name) else
                              (node.func.value.id + "." + node.func.attr if isinstance(node.func, ast.Attribute)
                               and isinstance(node.func.value, ast.Name) else "?"))
            return found
        hashing = {"_sha", "canonical_digest", "canonical_dumps", "canonical_loads", "module_table_digest", "_normalise_table",
                   "release_record", "validate_manifest", "hashlib.sha256", "json.dumps", "json.loads"}
        for name in ("run_verifier", "_run", "_launch", "verify_closure", "probe_runtime"):
            self.assertFalse(calls(name) & hashing, (name, calls(name) & hashing))
        for name in ("run_verifier", "_run", "_launch"):
            self.assertFalse(calls(name) & {"os.fspath", "os.path.abspath"}, name)

    def test_a_containment_that_is_built_late_is_closed_by_the_builder_and_the_report_says_so(self):
        gate, closes = threading.Event(), []
        self.addCleanup(gate.set)

        class Slow(pv._Containment):
            def __init__(self, *args):
                gate.wait(60)
                super().__init__(*args)

            def close(self, process=None):
                closes.append(process)
                return super().close(process)
        tmp = self.scratch()
        with mock.patch.object(pv, "_Containment", Slow):
            begun = time.monotonic()
            result = pv._execute([sys.executable, "-c", "pass"], str(tmp), b"", 0.5, 1 << 16, 1 << 16)
            self.assertLess(time.monotonic() - begun, 5.0)
            self.assertEqual((result.launch_error, result.cleanup_failed, result.returncode),
                             ("containment_build_timeout", True, None))
            gate.set()                                                            # the construction now completes late ...
            deadline = time.monotonic() + 10
            while not closes and time.monotonic() < deadline:
                time.sleep(0.02)
        self.assertEqual(closes, [None])                                          # ... and its owner releases what it built
        self.assertRaisesCode("containment_cleanup_failed", pv._accept_report, result, "0" * 32, "0" * 64, None, "run")

    def test_a_containment_construction_failure_is_raised_exactly_and_a_plain_execution_still_works(self):
        def broken(*args):
            raise pv.ClosureRejected("process_containment_unavailable", "create_job")
        tmp = self.scratch()
        with mock.patch.object(pv, "_Containment", side_effect=broken):
            self.assertRaisesCode("process_containment_unavailable", pv._execute, [sys.executable, "-c", "pass"], str(tmp), b"",
                                  5.0, 1 << 16, 1 << 16)
        done = pv._execute([sys.executable, "-c", "pass"], str(tmp), b"", 30.0, 1 << 16, 1 << 16)
        self.assertEqual((done.returncode, done.launch_error, done.cleanup_failed), (0, None, False))

    # ---- finding 7: a Windows job handle has an owner from the moment it exists ----------------------------------------

    def job_kernel(self, events, set_result=1, set_raises=None, create_result=77):
        class Kernel:
            def CreateJobObjectW(self, attributes, name):
                events.append("create")
                return create_result

            def SetInformationJobObject(self, job, kind, reference, size):
                events.append("set")
                if set_raises is not None:
                    raise set_raises
                return set_result

            def CloseHandle(self, handle):
                events.append(("close", handle))
                return 1
        return Kernel()

    def test_a_job_handle_is_closed_exactly_once_when_the_setup_after_its_creation_fails_and_kept_when_it_succeeds(self):
        import ctypes

        class Basic(ctypes.Structure):
            _fields_ = [("LimitFlags", ctypes.c_uint32)]

        class Extended(ctypes.Structure):
            _fields_ = [("Basic", Basic)]

        def containment(kernel):
            contain = object.__new__(pv._Containment)
            contain.__dict__.update(job=None, _k=kernel, _ctypes=ctypes)
            return contain
        events = []
        failing = containment(self.job_kernel(events, set_result=0))
        error = self.assertRaisesCode("process_containment_unavailable", failing._open_job, Extended)
        self.assertEqual(error.detail, "limit_job")
        self.assertEqual(events, ["create", "set", ("close", 77)])                # exactly one closure of exactly that handle
        self.assertIsNone(failing.job)
        events.clear()
        raising = containment(self.job_kernel(events, set_raises=RuntimeError("setup crashed")))
        with self.assertRaises(RuntimeError):
            raising._open_job(Extended)
        self.assertEqual(events, ["create", "set", ("close", 77)])                # an exception is not a leak either
        events.clear()
        refused = containment(self.job_kernel(events, create_result=0))
        self.assertRaisesCode("process_containment_unavailable", refused._open_job, Extended)
        self.assertEqual(events, ["create"])                                      # nothing was acquired, nothing is closed
        events.clear()
        good = containment(self.job_kernel(events))
        good._open_job(Extended)
        self.assertEqual((good.job, events), (77, ["create", "set"]))             # the positive keeps the handle for its owner

    # ---- finding 6: a failed identity inspection never loses or substitutes the creation identity ----------------------

    def inspection_failing(self, target):
        """Patch ``os.lstat`` so that inspecting ``target`` fails (not with a confirmed absence) until ``healed`` is set."""
        healed, real = threading.Event(), os.lstat

        def lstat(path, *args, **kwargs):
            if os.fspath(path) == target and not kwargs and not healed.is_set():
                raise PermissionError(13, "inspection denied")
            return real(path, *args, **kwargs)
        return healed, mock.patch.object(pv.os, "lstat", side_effect=lstat)

    def test_a_directory_whose_creation_identity_could_not_be_inspected_stays_owned_and_is_never_removed_by_name(self):
        root = self.scratch()
        path = str(root / "made")
        os.mkdir(path)
        (Path(path) / "mine.txt").write_text("mine")
        healed, patch = self.inspection_failing(path)
        known = set(pv._ORPHANS)
        self.addCleanup(lambda: [pv._ORPHANS.pop(p, None) for p in set(pv._ORPHANS) - known])
        ledger = pv._ScratchLedger()
        with patch:
            self.assertTrue(ledger.adopt(path))                                   # owned, with an UNKNOWN identity
            self.assertTrue(ledger.holds(path))
            self.assertFalse(ledger.release_all(2.0))                              # uncertainty is a cleanup failure
            self.assertIn(path, pv._ORPHANS)
            self.assertIsNone(pv._ORPHANS[path])                                  # the record says: identity unknown
            self.assertEqual((Path(path) / "mine.txt").read_text(), "mine")       # nothing was removed by name
            self.assertIn(path, pv.settle_orphans(2.0))                           # still unresolved while it cannot be inspected
        # healed, but a DIFFERENT directory now occupies the pathname: it is not what was created and must not be touched
        shutil.move(path, path + "-original")
        os.mkdir(path)
        (Path(path) / "other.txt").write_text("other")
        healed.set()
        self.assertIn(path, pv.settle_orphans(2.0))                               # a readable occupant is not a confirmed absence
        self.assertEqual((Path(path) / "other.txt").read_text(), "other")
        shutil.rmtree(path)                                                       # recovery: the pathname is confirmed absent
        self.assertNotIn(path, pv.settle_orphans(2.0))
        self.assertNotIn(path, pv._ORPHANS)
        self.assertEqual((Path(path + "-original") / "mine.txt").read_text(), "mine")

    @unittest.skipUnless(sys.platform.startswith("linux"), "the supervisor directory is created on the Linux path")
    def test_a_supervisor_directory_with_an_uninspectable_creation_stays_uncertain_and_owned_until_confirmed_absent(self):
        real_mkdtemp, made = tempfile.mkdtemp, []
        tmp = self.scratch()

        def mkdtemp(*args, **kwargs):
            path = real_mkdtemp(*args, **kwargs)
            if str(kwargs.get("prefix", "")).startswith("pvc-supervisor-bytecode-"):
                made.append(path)
            return path
        known = set(pv._ORPHANS)
        self.addCleanup(lambda: [pv._ORPHANS.pop(p, None) for p in set(pv._ORPHANS) - known])
        broken = {"on": True}
        real_lstat = os.lstat

        def lstat(path, *args, **kwargs):
            if broken["on"] and made and os.fspath(path) == made[0] and not kwargs:
                raise PermissionError(13, "inspection denied")
            return real_lstat(path, *args, **kwargs)
        with mock.patch.object(pv.tempfile, "mkdtemp", side_effect=mkdtemp), mock.patch.object(pv.os, "lstat", side_effect=lstat), \
                mock.patch.object(pv.subprocess, "Popen", side_effect=OSError("stop here: only the directory matters")), \
                mock.patch.object(pv, "JANITOR_INTERVAL", 3600.0):
            attempt = pv._LaunchAttempt([sys.executable, "-c", "pass"], str(tmp), windows=False)
            self.assertEqual(pv._bounded_launch(attempt, time.monotonic() + 10), (None, "child_launch_failed"))
            self.assertFalse(attempt.settle(2.0))                                 # unresolved: the failure stays a failure
            self.assertIsNone(attempt.prefix_identity)
            prefix = made[0]
            self.assertTrue(os.path.isdir(prefix))                                # and the directory was not removed
            self.assertFalse(attempt.released or attempt.clean)
            shutil.move(prefix, prefix + "-original")                              # an intervening replacement ...
            os.mkdir(prefix)
            (Path(prefix) / "other.txt").write_text("other")
            broken["on"] = False                                                  # ... that is now readable
            self.assertFalse(attempt.settle(2.0))
            self.assertEqual((Path(prefix) / "other.txt").read_text(), "other")    # never deleted in place of the creation
            shutil.rmtree(prefix)                                                 # recovery: confirmed absent
            self.assertTrue(attempt.settle(5.0) or attempt.released)
        self.assertTrue(attempt.released)
        shutil.rmtree(prefix + "-original", True)

    # ---- finding 8: nothing reaches a cached, frozen or captured import operation unmediated --------------------------

    def test_a_captured_reference_to_a_replaced_import_function_is_found_so_the_bootstrap_can_fail_closed(self):
        namespace = load_bootstrap()

        def real():
            return None
        holder, clean = types.SimpleNamespace(find_spec=real, other=1), types.SimpleNamespace(x=2)
        found = namespace["_captured_references"]({"a": holder, "b": clean, "c": types.SimpleNamespace(alias=real)}, [real])
        self.assertEqual(found, ["a.find_spec", "c.alias"])
        self.assertEqual(namespace["_captured_references"]({"b": clean}, [real]), [])

    def test_the_utility_module_is_loaded_before_arming_so_a_frozen_build_cannot_skip_its_mediation(self):
        source = (REPO / "trace_gc" / "verifier_closure_bootstrap.py").read_text(encoding="utf-8")
        self.assertLess(source.index("import importlib.util"), source.index("# --- preload end ---"))
        self.assertIn("_install_entry_points()", source)
        for replaced in ("boot.__import__ = _mediated_import", "importlib.__import__ = _mediated_import",
                         "boot._gcd_import = _mediated_gcd_import", "_mediated_private(real, \"import_module\", name_of)",
                         "owner.find_spec = classmethod(replacement)", "_install_find_spec(util)",
                         "importlib.find_loader = _mediated_private(legacy, \"find_spec\", _first_argument)"):
            self.assertIn(replaced, source)
        self.assertIn('_fail("captured_import_reference"', source)


def _fd_open(descriptor):
    try:
        os.fstat(descriptor)
        return True
    except OSError:
        return False


class RecordingKernel:
    """Windows Job Object calls recorded in order.  Terminating the job reaches only processes assigned to it."""

    def __init__(self, events, process, assign_ok=True, active=0, query_ok=True):
        self.events, self.process, self.assign_ok, self.active, self.query_ok = events, process, assign_ok, active, query_ok
        self.assigned = False

    def AssignProcessToJobObject(self, job, handle):
        self.events.append(("assign", handle))
        self.assigned = self.assign_ok
        return 1 if self.assign_ok else 0

    def TerminateJobObject(self, job, code):
        self.events.append(("terminate_job",))
        if self.assigned and self.process.returncode is None:
            self.process.returncode = 1
        return 1

    def QueryInformationJobObject(self, job, kind, reference, size, returned):
        reference._obj.ActiveProcesses = self.active
        return 1 if self.query_ok else 0

    def CloseHandle(self, handle):
        self.events.append(("close_job",))
        return 1


class RecordingProcess:
    _handle = 4242

    def __init__(self, events):
        self.events, self.returncode = events, None

    def poll(self):
        return self.returncode

    def kill(self):
        self.events.append(("kill_process",))
        self.returncode = 9

    def wait(self, timeout=None):
        if self.returncode is None:
            raise subprocess.TimeoutExpired("recording", timeout)
        return self.returncode


class WindowsContainmentOrdering(RejectionMixin, unittest.TestCase):
    """The Windows Job Object ordering and failure cleanup against recording fakes (no Windows API is called; the
    native Windows run stays NOT_RUN until hosted CI)."""

    def contained(self, assign_ok=True, resume_code=0, active=0, query_ok=True):
        import ctypes

        class Accounting(ctypes.Structure):
            _fields_ = [("ActiveProcesses", ctypes.c_uint32)]
        events = []
        process = RecordingProcess(events)
        kernel = RecordingKernel(events, process, assign_ok, active, query_ok)

        class Resumer:
            def NtResumeProcess(self, handle):
                events.append(("resume", handle))
                return resume_code
        contain = object.__new__(pv._Containment)
        contain.__dict__.update(job="JOB", cwd=None, kind="job_object", _k=kernel, _nt=Resumer(), _ctypes=ctypes,
                                _accounting=Accounting, _assigned=False, _clean=None, _fds=None, _ctl_w=None, _st_r=None,
                                _reader=None, _sup_prefix=None, _sup_identity=None, cleanup_end=None, _closed=False,
                                _closing=False, _fd_lock=threading.Lock())
        return contain, process, events

    def test_the_child_joins_the_job_before_it_is_resumed(self):
        contain, process, events = self.contained()
        contain.attach(process)
        self.assertEqual(events, [("assign", 4242), ("resume", 4242)])
        self.assertTrue(contain._assigned)

    def test_the_windows_launch_attempt_creates_the_child_suspended_in_its_own_group_without_a_console(self):
        seen = {}

        def record(command, **kwargs):
            seen.update(kwargs)
            return RecordingProcess([])
        attempt = pv._LaunchAttempt([sys.executable, "-c", "pass"], os.getcwd(), windows=True)
        with mock.patch.object(pv.subprocess, "Popen", side_effect=record):
            attempt._create()
        self.assertEqual(seen["creationflags"], 0x00000200 | 0x08000000 | 0x00000004)   # new group, no window, SUSPENDED
        self.assertNotIn("start_new_session", seen)
        self.assertNotIn("pass_fds", seen)
        self.assertIsNone(attempt.prefix)                                                  # no supervisor directory on Windows

    def test_a_failed_job_assignment_never_resumes_and_the_unassigned_child_is_terminated_and_reaped_directly(self):
        contain, process, events = self.contained(assign_ok=False)
        self.assertRaisesCode("containment_attach_failed", contain.attach, process)
        self.assertFalse([e for e in events if e[0] == "resume"])                                # a suspended child never ran
        self.assertFalse(contain._assigned)
        self.assertTrue(contain.reap(process, 2.0))
        self.assertEqual(process.returncode, 9)                                                  # terminated directly: the job never held it
        self.assertLess(events.index(("terminate_job",)), events.index(("kill_process",)))

    def test_a_failed_resume_after_assignment_is_reached_by_the_job_without_a_direct_kill(self):
        contain, process, events = self.contained(resume_code=-1)
        self.assertRaisesCode("containment_attach_failed", contain.attach, process)
        self.assertTrue(contain._assigned)
        self.assertTrue(contain.reap(process, 2.0))
        self.assertEqual(process.returncode, 1)                                                  # the job terminated it
        self.assertNotIn(("kill_process",), events)

    def test_cleanup_is_confirmed_only_when_the_job_reports_no_active_process(self):
        for label, kwargs in (("still_active", {"active": 1}), ("query_failed", {"query_ok": False})):
            with self.subTest(label):
                contain, process, _ = self.contained(**kwargs)
                contain.attach(process)
                self.assertTrue(contain.survivors(process))                                      # uncertainty counts as a survivor
                self.assertFalse(contain.reap(process, 0.1))
        contain, process, _ = self.contained()
        contain.attach(process)
        self.assertFalse(contain.survivors(process))
        self.assertTrue(contain.reap(process, 2.0))

    def test_closing_the_containment_kills_an_unassigned_live_child_before_the_job_handle_is_closed(self):
        contain, process, events = self.contained(assign_ok=False)
        contain.close(process)
        self.assertEqual([e[0] for e in events], ["kill_process", "terminate_job", "close_job"])
        self.assertIsNone(contain.job)


# ---------------------------------------------------------------------------------------------------
# 7. Links, junctions and reparse points (native filesystem behaviour, not mocks).

def linked_ancestors(path: Path) -> list[str]:
    """Ancestors of ``path`` (and itself) that are symlinks or reparse points; closure roots may not sit below any."""
    found = []
    for candidate in (Path(os.path.abspath(path)), *Path(os.path.abspath(path)).parents):
        try:
            st = os.lstat(candidate)
        except OSError:
            continue
        if stat.S_ISLNK(st.st_mode) or getattr(st, "st_file_attributes", 0) & 0x400:
            found.append(str(candidate))
    return found


def make_junction(link: Path, target: Path) -> bool:
    if WINDOWS:
        done = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True, text=True)
        return done.returncode == 0
    try:
        os.symlink(target, link, target_is_directory=True)
        return True
    except OSError:
        return False


class LinksAndReparsePoints(RejectionMixin, unittest.TestCase):
    def test_directory_link_substituted_for_a_package_is_rejected_although_bytes_match(self):
        fx = Fixture(self).build()
        copy_dir = fx.tmp / "vc-copy"
        shutil.copytree(fx.root / "vc", copy_dir)
        shutil.rmtree(fx.root / "vc")
        if not make_junction(fx.root / "vc", copy_dir):
            self.skipTest("cannot create a directory link/junction here")
        self.assertRaisesCode("path_link_or_reparse_point", fx.verify)
        self.assertRejected(fx.run(), "path_link_or_reparse_point")

    def test_linked_root_is_rejected(self):
        fx = Fixture(self).build()
        link = fx.tmp / "linked-root"
        if not make_junction(link, fx.root):
            self.skipTest("cannot create a directory link/junction here")
        self.assertRaisesCode("root_not_plain_directory", fx.verify, roots={"vc": link})

    def test_file_symlink_module_is_rejected(self):
        fx = Fixture(self).build()
        real = fx.tmp / "real_helper.py"
        real.write_bytes((fx.root / "vc/helper.py").read_bytes())
        (fx.root / "vc/helper.py").unlink()
        try:
            os.symlink(real, fx.root / "vc/helper.py")
        except (OSError, NotImplementedError):
            self.skipTest("file symlinks need a privilege this account lacks")
        self.assertRaisesCode("path_link_or_reparse_point", fx.verify)

    def test_linked_input_is_rejected(self):
        fx = Fixture(self).build()
        link = fx.tmp / "linked-data"
        if not make_junction(link, fx.data):
            self.skipTest("cannot create a directory link/junction here")
        run = fx.run(inputs={"doc": pv.InputSpec(link, "doc.txt", sha(b"good"))})
        self.assertRejected(run, "root_not_plain_directory")

    def test_junction_inside_a_package_tree_is_rejected(self):
        tmp = Path(tempfile.mkdtemp(prefix="pvc-pkgjunction-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        (tmp / "deptop").mkdir()
        (tmp / "deptop/__init__.py").write_text("X = 1\n")
        (tmp / "elsewhere").mkdir()
        (tmp / "elsewhere/x.py").write_text("Y = 2\n")
        if not make_junction(tmp / "deptop/sub", tmp / "elsewhere"):
            self.skipTest("cannot create a directory link/junction here")
        (tmp / "deptop-1.0.dist-info").mkdir()
        (tmp / "deptop-1.0.dist-info/METADATA").write_text("Name: deptop\nVersion: 1.0\n")
        entry = {"distribution": "deptop", "version": "1.0", "root": "site", "top_level": ["deptop"]}
        self.assertRaisesCode("census_linked_directory", pv.package_census, str(tmp), entry, [])

    def test_link_inside_the_runtime_census_is_rejected(self):
        tmp = Path(tempfile.mkdtemp(prefix="pvc-censuslink-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        (tmp / "Lib").mkdir()
        (tmp / "Lib/a.py").write_text("A = 1\n")
        (tmp / "other").mkdir()
        if not make_junction(tmp / "Lib/linked", tmp / "other"):
            self.skipTest("cannot create a directory link/junction here")
        probe = {"base_prefix": str(tmp), "sys_path": [str(tmp / "Lib")], "core_files": []}
        with self.assertRaises(pv.ClosureRejected) as caught:
            pv.runtime_census(probe)
        self.assertTrue(caught.exception.code.startswith("census_"), caught.exception.code)

    def test_a_link_or_junction_anywhere_above_a_root_is_rejected(self):
        fx = Fixture(self).build()
        alias = fx.tmp / "alias"
        if not make_junction(alias, fx.tmp):
            self.skipTest("cannot create a directory link/junction here")
        through = alias / "closure"
        self.assertTrue(through.is_dir())
        self.assertRaisesCode("root_ancestor_link_or_reparse_point", fx.verify, roots={"vc": through})
        self.assertRaisesCode("root_ancestor_link_or_reparse_point", pv.build_manifest, name="x", roots={"vc": through},
                              entry_module="vc.main", observation=observation())
        run = fx.run(roots={"vc": through})
        self.assertRejected(run, "root_ancestor_link_or_reparse_point", "arguments")
        pv.validate_receipt(run.receipt)
        self.assertEqual((run.receipt["process"], run.receipt["runtime"], run.receipt["verifier"]), (None, None, None))
        self.assertEqual(fx.run().status, "PASS")                           # the unlinked spelling of the same directory is fine

    def test_equal_and_nested_roots_are_rejected_as_ambiguous_ownership(self):
        fx = Fixture(self).build()
        self.assertRaisesCode("roots_not_distinct", fx.verify, roots={"vc": fx.root, "again": fx.root})
        self.assertRaisesCode("roots_nested", fx.verify, roots={"vc": fx.root, "inner": fx.root / "vc"})
        self.assertRaisesCode("roots_nested", fx.verify, roots={"inner": fx.root / "vc", "vc": fx.root})
        self.assertRejected(fx.run(roots={"vc": fx.root, "again": fx.root}), "roots_not_distinct", "arguments")
        self.assertRaisesCode("roots_required", fx.verify, roots={})
        self.assertRaisesCode("root_alias_invalid", fx.verify, roots={"not an alias!": fx.root})
        self.assertRaisesCode("root_missing", fx.verify, roots={"vc": fx.tmp / "no-such-root"})
        sibling = fx.tmp / "closure-sibling"                                  # a shared name prefix is not nesting
        sibling.mkdir()
        self.assertEqual(fx.verify(roots={"vc": fx.root, "sib": sibling}).manifest_sha256, fx.digest)
        self.assertRaisesCode("root_not_supplied", fx.verify, roots={"other": sibling})

    def test_two_distributions_in_one_install_root_are_owned_once_and_run(self):
        main = MAIN.replace("from . import helper", "import authdep\nimport authtwo\nfrom . import helper").replace(
            'helper.decide(inputs)', 'authdep.VERDICT if authtwo.VERDICT == helper.decide(inputs) else "HOLD"')
        fx = Fixture(self, main=main)
        site = fx.tmp / "site"
        for name in ("authdep", "authtwo"):
            (site / name).mkdir(parents=True)
            (site / name / "__init__.py").write_text('VERDICT = "PASS"\n')
            (site / (name + "-1.0.dist-info")).mkdir()
            (site / (name + "-1.0.dist-info") / "METADATA").write_text("Metadata-Version: 2.1\nName: %s\nVersion: 1.0\n" % name)
        roots = {"vc": fx.root, "site": site}
        packages = [{"distribution": name, "version": "1.0", "root": "site", "top_level": [name]} for name in ("authdep", "authtwo")]
        fx.build(roots=roots, packages=packages)
        self.assertEqual([p["distribution"] for p in fx.manifest["packages"]], ["authdep", "authtwo"])
        verified = fx.verify(roots=roots)
        names = [row[0] for row in verified.table]
        self.assertEqual(len(names), len(set(names)))                         # one candidate per module: no duplicate rows
        self.assertNotIn("ambiguous", {row[1] for row in verified.table})
        self.assertTrue({"authdep", "authtwo"} <= set(names))
        owner = {row[0]: row[5] for row in verified.table}                    # per-file ownership, never a per-root label
        self.assertEqual((owner["authdep"], owner["authtwo"]), ("authdep", "authtwo"))
        self.assertNotIn("authdep+authtwo", set(owner.values()))
        run = fx.run(roots=roots)
        self.assertEqual(run.status, "PASS", run.receipt)
        self.assertEqual(run.receipt["loaded"]["package"], {"authdep": 1, "authtwo": 1})
        (site / "authtwo" / "__init__.py").write_text('VERDICT = "HOLD"\n')
        self.assertRejected(fx.run(roots=roots), "package_changed:authtwo")
        (site / "authtwo" / "__init__.py").write_text('VERDICT = "PASS"\n')
        self.assertRaisesCode("manifest_package_duplicate_top", pv.validate_manifest,
                              dict(copy.deepcopy(fx.manifest), packages=[
                                  dict(fx.manifest["packages"][0]), dict(fx.manifest["packages"][1], top_level=["authdep"])]))


# ---------------------------------------------------------------------------------------------------
# 8. Receipts, CLI, schemas, frozen-primitive invariants and the installed wheel.

class ReceiptsCliAndInvariants(RejectionMixin, unittest.TestCase):
    def test_receipt_readback_rejects_tampering(self):
        fx = Fixture(self).build()
        receipt = fx.run().receipt
        base = dict(expected_manifest_sha256=fx.digest, expected_release_sha256=fx.release, require_acceptance=False)
        self.assertRaisesCode("receipt_manifest_mismatch", pv.verify_receipt, receipt,
                              expected_manifest_sha256="0" * 64, expected_release_sha256=fx.release)
        self.assertRaisesCode("receipt_release_mismatch", pv.verify_receipt, receipt,
                              expected_manifest_sha256=fx.digest, expected_release_sha256="0" * 64)
        # Every field edit of a stored receipt is caught by the binding unless the editor also recomputes it ...
        for path, value in ((("verifier", "result", "doc_sha256"), "0" * 64), (("inputs", "doc", "sha256"), "0" * 64),
                            (("request", "nonce"), "0" * 32), (("params_sha256",), pv.canonical_digest({"other": 1})),
                            (("post_checks", "runtime_unchanged"), False), (("status",), "HOLD"),
                            (("implementation", 0, "sha256"), "0" * 64), (("runtime", "census_sha256"), "0" * 64),
                            (("evidence", "report_sha256"), "0" * 64), (("process", "exit_code"), 1)):
            forged = copy.deepcopy(receipt)
            target = forged
            for step in path[:-1]:
                target = target[step]
            target[path[-1]] = value
            self.assertRaisesCode("receipt_binding_mismatch", pv.verify_receipt, forged, **base)
        # ... and a re-sealed edit still has to satisfy every status invariant.
        forged = reseal(copy.deepcopy(receipt))
        self.assertEqual(pv.verify_receipt(forged, **base), "PASS")      # sealing an unedited receipt changes nothing
        forged = copy.deepcopy(receipt)
        forged["verifier"]["result"]["doc_sha256"] = "0" * 64
        self.assertRaisesCode("receipt_result_digest_mismatch", pv.verify_receipt, reseal(forged), **base)
        forged = copy.deepcopy(receipt)
        forged["post_checks"]["runtime_unchanged"] = False
        self.assertRaisesCode("receipt_result_unbound", pv.verify_receipt, reseal(forged), **base)
        forged = copy.deepcopy(receipt)
        forged["status"] = "HOLD"
        self.assertRaisesCode("receipt_result_unbound", pv.verify_receipt, reseal(forged), **base)
        self.assertRaisesCode("receipt_inputs_mismatch", pv.verify_receipt, receipt, expected_inputs={"doc": "0" * 64}, **base)
        self.assertRaisesCode("receipt_params_mismatch", pv.verify_receipt, receipt,
                              expected_params_sha256=pv.canonical_digest({"other": 1}), **base)
        self.assertEqual(pv.verify_receipt(receipt, expected_params_sha256=pv.canonical_digest(None), **base), "PASS")

    def test_resealed_receipt_edits_that_break_a_pass_invariant_are_all_rejected(self):
        """The binding is unkeyed, so a forger can recompute it: the cross-field invariants must still reject."""
        fx = Fixture(self).build()
        receipt = fx.run().receipt
        base = dict(expected_manifest_sha256=fx.digest, expected_release_sha256=fx.release, require_acceptance=False)
        self.assertEqual(pv.verify_receipt(receipt, **base), "PASS")

        def put(section, key, value):
            return lambda r: r[section].__setitem__(key, value)
        mutations = {
            "implementation_missing_row": lambda r: r["implementation"].pop(),
            "implementation_bad_sha": lambda r: r["implementation"][0].__setitem__("sha256", "zz"),
            "implementation_none": lambda r: r.__setitem__("implementation", None),
            "runtime_key_missing": lambda r: r["runtime"].pop("census_sha256"),
            "runtime_none": lambda r: r.__setitem__("runtime", None),
            "protection_type": put("runtime_protection", "inspected", "yes"),
            "protection_none": lambda r: r.__setitem__("runtime_protection", None),
            "closure_modules_empty": put("closure", "modules", []),
            "closure_none": lambda r: r.__setitem__("closure", None),
            "nonce_shape": put("request", "nonce", "XYZ"),
            "request_none": lambda r: r.__setitem__("request", None),
            "verifier_not_returned": put("verifier", "returned", False),
            "verifier_exception": put("verifier", "exception_type", "ValueError"),
            "verifier_none": lambda r: r.__setitem__("verifier", None),
            "process_exit": put("process", "exit_code", 1),
            "process_timed_out": put("process", "timed_out", True),
            "process_descendants": put("process", "descendants", True),
            "process_cleanup": put("process", "cleanup_failed", True),
            "process_overflow": put("process", "overflow", "stdout"),
            "process_timeout_zero": put("process", "timeout_ms", 0),
            "process_timeout_huge": put("process", "timeout_ms", 10 ** 9),
            "process_stderr_none": put("process", "stderr_sha256", None),
            "process_none": lambda r: r.__setitem__("process", None),
            "post_closure": put("post_checks", "closure_unchanged", False),
            "post_inputs": put("post_checks", "inputs_unchanged", False),
            "post_runtime": put("post_checks", "runtime_unchanged", False),
            "post_bytecode": put("post_checks", "bytecode_dir_empty", False),
            "post_empty": lambda r: r.__setitem__("post_checks", {}),
            "post_none": lambda r: r.__setitem__("post_checks", None),
            "evidence_none": lambda r: r.__setitem__("evidence", None),
            "evidence_sha": put("evidence", "report_sha256", "zz"),
            "violations": lambda r: r.__setitem__("violations", ["undeclared_import:x"]),
            "failure_class_on_pass": lambda r: r.__setitem__("failure_class", "closure"),
            "reason_not_ok": lambda r: r.__setitem__("reason", "something_else"),
            "manifest_none": lambda r: r.__setitem__("manifest_sha256", None),
            "release_none": lambda r: r.__setitem__("release_sha256", None),
            "params_none": lambda r: r.__setitem__("params_sha256", None),
            "loaded_none": lambda r: r.__setitem__("loaded", None),
            "extra_key": lambda r: r.__setitem__("surplus", 1),
            "version": lambda r: r.__setitem__("version", "paper-verifier-closure-receipt-v0"),
            "input_bytes_negative": lambda r: r["inputs"]["doc"].__setitem__("bytes", -1),
            "binding_none": lambda r: r.__setitem__("binding_sha256", None),
        }
        for label, mutate in mutations.items():
            forged = copy.deepcopy(receipt)
            mutate(forged)
            if label != "binding_none":
                reseal(forged)
            with self.assertRaises(pv.ClosureRejected, msg=label):
                pv.verify_receipt(forged, **base)

    def test_rejected_receipts_are_valid_evidence_but_cannot_carry_a_verifier_or_a_wrong_class(self):
        fx = Fixture(self).build()
        rejected = fx.run(release="0" * 64).receipt
        self.assertEqual(pv.verify_receipt(rejected, expected_manifest_sha256=fx.digest, expected_release_sha256="0" * 64), "REJECTED")
        for label, mutate in (("class", lambda r: r.__setitem__("failure_class", "execution")),
                              ("class_none", lambda r: r.__setitem__("failure_class", None)),
                              ("verifier", lambda r: r.__setitem__("verifier", {"returned": True, "exception_type": None,
                                                                              "result_sha256": "0" * 64, "result": None})),
                              ("reason_empty", lambda r: r.__setitem__("reason", ""))):
            forged = copy.deepcopy(rejected)
            mutate(forged)
            with self.assertRaises(pv.ClosureRejected, msg=label):
                pv.verify_receipt(reseal(forged), expected_manifest_sha256=fx.digest, expected_release_sha256="0" * 64)

    def test_every_present_receipt_field_is_validated_for_every_status_including_rejected(self):
        """A REJECTED receipt may omit evidence, but anything it does carry must be well formed."""
        fx = Fixture(self).build()
        passing = fx.run().receipt
        late = copy.deepcopy(passing)
        late.update(status="REJECTED", reason="execution_timeout", failure_class="execution", verifier=None)
        late["process"]["timed_out"] = True
        trusted = dict(expected_manifest_sha256=fx.digest, expected_release_sha256=fx.release)
        self.assertEqual(pv.verify_receipt(reseal(late), **trusted), "REJECTED")        # carrying evidence is allowed
        sparse = copy.deepcopy(late)
        for key in ("implementation", "implementation_source", "runtime", "runtime_protection", "closure", "request",
                    "loaded", "process", "post_checks", "evidence"):
            sparse[key] = None
        self.assertEqual(pv.verify_receipt(reseal(sparse), **trusted), "REJECTED")      # omitting it is allowed too
        mutations = {
            "implementation_short": lambda r: r["implementation"].pop(),
            "implementation_bad_path": lambda r: r["implementation"][0].__setitem__("path", "trace_gc/other.py"),
            "implementation_source": lambda r: r.__setitem__("implementation_source", "elsewhere"),
            "runtime_missing_key": lambda r: r["runtime"].pop("census_sha256"),
            "runtime_bad_bits": lambda r: r["runtime"].__setitem__("bits", "64"),
            "protection_type": lambda r: r["runtime_protection"].__setitem__("enforced", "yes"),
            "protection_exposed_type": lambda r: r["runtime_protection"].__setitem__("exposed", "all"),
            "closure_empty": lambda r: r["closure"].__setitem__("modules", []),
            "closure_duplicate": lambda r: r["closure"]["modules"].append(dict(r["closure"]["modules"][0])),
            "nonce": lambda r: r["request"].__setitem__("nonce", "short"),
            "loaded_keys": lambda r: r["loaded"].pop("native"),
            "loaded_count": lambda r: r["loaded"].__setitem__("stdlib", -1),
            "process_timeout_zero": lambda r: r["process"].__setitem__("timeout_ms", 0),
            "process_timeout_float": lambda r: r["process"].__setitem__("timeout_ms", 1.5),
            "process_overflow": lambda r: r["process"].__setitem__("overflow", "stdin"),
            "post_checks_type": lambda r: r["post_checks"].__setitem__("closure_unchanged", 1),
            "evidence_sha": lambda r: r["evidence"].__setitem__("report_sha256", "zz"),
            "input_digest": lambda r: r["inputs"]["doc"].__setitem__("sha256", "zz"),
            "violation_type": lambda r: r.__setitem__("violations", [1]),
        }
        for label, mutate in mutations.items():
            forged = copy.deepcopy(late)
            mutate(forged)
            with self.assertRaises(pv.ClosureRejected, msg=label):
                pv.verify_receipt(reseal(forged), **trusted)

    def test_acceptance_of_a_hold_needs_the_same_trusted_context_and_grade_as_a_pass(self):
        fx = Fixture(self, helper=HELPER_HOLD).build()
        receipt = fx.run().receipt
        self.assertEqual(receipt["status"], "HOLD")
        trusted = dict(expected_manifest_sha256=fx.digest, expected_release_sha256=fx.release)
        self.assertEqual(pv.verify_receipt(receipt, require_acceptance=False, **trusted), "HOLD")
        self.assertRaisesCode("receipt_context_required", pv.verify_receipt, receipt, **trusted)
        context = dict(manifest=fx.manifest, expected_inputs={"doc": sha(b"good")},
                       expected_params_sha256=pv.canonical_digest(None), expected_module_table=fx.table(), **trusted)
        self.assertRaisesCode("receipt_not_acceptance_grade", pv.verify_receipt, receipt, **context)     # disk_reread / unprotected
        for missing in ("manifest", "expected_inputs", "expected_params_sha256", "expected_module_table"):
            partial = {k: v for k, v in context.items() if k != missing}
            self.assertRaisesCode("receipt_context_required", pv.verify_receipt, receipt, **partial)

    def test_receipt_can_be_recomputed_against_the_manifest_it_claims(self):
        fx = Fixture(self).build()
        receipt = fx.run().receipt
        base = dict(expected_manifest_sha256=fx.digest, expected_release_sha256=fx.release, require_acceptance=False)
        self.assertEqual(pv.verify_receipt(receipt, manifest=fx.manifest, **base), "PASS")
        other, other_digest = retarget(fx.manifest, lambda m: m["modules"][0].__setitem__("sha256", "5" * 64))
        self.assertRaisesCode("receipt_manifest_mismatch", pv.verify_receipt, receipt, manifest=other, **base)
        forged = copy.deepcopy(receipt)                       # the loaded evidence no longer matches the claimed closure digest
        row = next(m for m in forged["closure"]["modules"] if m["name"] == "vc.main")
        row["sha256"] = "5" * 64
        self.assertRaisesCode("receipt_evidence_inconsistent", pv.verify_receipt, reseal(forged), manifest=fx.manifest, **base)
        forged = copy.deepcopy(receipt)                       # internally consistent, but not the manifest's own row
        forged["closure"]["modules"][0]["bytes"] += 1
        self.assertRaisesCode("receipt_manifest_mismatch", pv.verify_receipt, reseal(forged), manifest=fx.manifest, **base)
        forged = copy.deepcopy(receipt)
        forged["runtime"]["census_sha256"] = "5" * 64
        self.assertRaisesCode("receipt_manifest_mismatch", pv.verify_receipt, reseal(forged), manifest=fx.manifest, **base)
        forged = copy.deepcopy(receipt)
        forged["implementation"][0]["sha256"] = "5" * 64
        self.assertRaisesCode("receipt_release_mismatch", pv.verify_receipt, reseal(forged), manifest=fx.manifest, **base)

    def test_a_rejected_receipt_that_carries_evidence_is_cross_checked_exactly_like_a_pass(self):
        fx = Fixture(self).build()
        passing = fx.run().receipt
        late = copy.deepcopy(passing)
        late.update(status="REJECTED", reason="execution_timeout", failure_class="execution", verifier=None)
        late["process"]["timed_out"] = True
        trusted = dict(expected_manifest_sha256=fx.digest, expected_release_sha256=fx.release)
        self.assertEqual(pv.verify_receipt(reseal(copy.deepcopy(late)), **trusted), "REJECTED")        # positive counterpart
        mutations = {
            "rows_digest": lambda r: r["evidence"].__setitem__("runtime_modules_sha256", "0" * 64),
            "rows_count": lambda r: r["evidence"].__setitem__("runtime_modules", r["evidence"]["runtime_modules"] + 1),
            "mapped_digest": lambda r: r["evidence"].__setitem__("mapped_sha256", "0" * 64),
            "loaded_stdlib_count": lambda r: r["loaded"].__setitem__("stdlib", r["loaded"]["stdlib"] + 1),
            "loaded_closure_digest": lambda r: r["loaded"]["closure"].__setitem__("vc.main", "5" * 64),
            "loaded_native_not_in_rows": lambda r: r["loaded"]["native"].__setitem__("vc.ghost", "5" * 64),
            "plan_unsorted": lambda r: r["evidence"].__setitem__("native_plan", [["b", "1" * 64], ["a", "1" * 64]]),
            "plan_unpinned": lambda r: r["evidence"].__setitem__("native_plan", [["/nowhere/x.so", "1" * 64]]),
            "mapped_unpinned": lambda r: r["evidence"].update(mapped=["/nowhere/x.so"], mapped_sha256=pv.canonical_digest(["/nowhere/x.so"])),
        }
        for label, mutate in mutations.items():
            forged = copy.deepcopy(late)
            mutate(forged)
            error = self.assertRaisesCode("receipt_evidence_inconsistent", pv.verify_receipt, reseal(forged), **trusted)
            self.assertTrue(error.detail, label)

    REASON_PROCESS_ACCEPTED = (
        # (label, reason, failure_class, process flags set on top of an all-clear record)
        ("cleanup", "containment_cleanup_failed", "containment", dict(cleanup_failed=True)),
        ("cleanup_and_timeout", "containment_cleanup_failed", "containment", dict(cleanup_failed=True, timed_out=True)),
        ("timeout", "execution_timeout", "execution", dict(timed_out=True)),
        ("timeout_and_overflow", "execution_timeout", "execution", dict(timed_out=True, overflow="stdout")),
        ("overflow_stdout", "protocol_output_overflow", "protocol", dict(overflow="stdout")),
        ("overflow_stderr", "protocol_output_overflow", "protocol", dict(overflow="stderr", descendants=True)),
        ("descendants", "containment_unresolved_descendants", "containment", dict(descendants=True)),
        ("deadline_with_every_flag", "operation_deadline_exceeded", "execution",
         dict(cleanup_failed=True, timed_out=True, overflow="stderr", descendants=True)),
        ("deadline_clean", "operation_deadline_exceeded", "execution", {}),
        ("internal_error", "execution_internal_error:RuntimeError", "execution", dict(timed_out=True)),
        ("attach_failed", "containment_attach_failed", "containment", {}),
        ("launch_failed", "execution_launch_failed", "execution", {}),
        ("report_rejected", "closure_runtime_violation:forbidden_import:socket", "closure", {}),
    )
    REASON_PROCESS_REFUSED = (
        ("cleanup_reason_without_flag", "containment_cleanup_failed", "containment", dict(timed_out=True)),
        ("timeout_reason_without_flag", "execution_timeout", "execution", {}),
        ("timeout_reason_with_earlier_cleanup", "execution_timeout", "execution", dict(timed_out=True, cleanup_failed=True)),
        ("overflow_reason_without_flag", "protocol_output_overflow", "protocol", dict(descendants=True)),
        ("overflow_reason_with_earlier_timeout", "protocol_output_overflow", "protocol", dict(overflow="stdout", timed_out=True)),
        ("overflow_reason_with_earlier_cleanup", "protocol_output_overflow", "protocol", dict(overflow="stdout", cleanup_failed=True)),
        ("descendants_reason_without_flag", "containment_unresolved_descendants", "containment", {}),
        ("descendants_reason_with_earlier_overflow", "containment_unresolved_descendants", "containment",
         dict(descendants=True, overflow="stdout")),
        ("descendants_reason_with_earlier_timeout", "containment_unresolved_descendants", "containment",
         dict(descendants=True, timed_out=True)),
        ("attach_failure_with_timeout", "containment_attach_failed", "containment", dict(timed_out=True)),
        ("launch_failure_with_cleanup", "execution_launch_failed", "execution", dict(cleanup_failed=True)),
        ("launch_failure_with_overflow", "execution_launch_failed", "execution", dict(overflow="stdout")),
        ("report_rejection_with_descendants", "closure_runtime_violation:x", "closure", dict(descendants=True)),
    )

    def rejected_with_process(self, fx, passing, reason, failure, flags):
        forged = copy.deepcopy(passing)
        forged.update(status="REJECTED", reason=reason, failure_class=failure, verifier=None)
        forged["process"].update(cleanup_failed=False, timed_out=False, overflow=None, descendants=False)
        forged["process"].update(flags)
        return reseal(forged)

    def test_a_rejected_reason_and_the_retained_process_evidence_tell_the_same_story(self):
        fx = Fixture(self).build()
        passing = fx.run().receipt
        trusted = dict(expected_manifest_sha256=fx.digest, expected_release_sha256=fx.release)
        for label, reason, failure, flags in self.REASON_PROCESS_ACCEPTED:
            forged = self.rejected_with_process(fx, passing, reason, failure, flags)
            self.assertEqual(pv.validate_receipt(forged)["status"], "REJECTED", label)
            self.assertEqual(pv.verify_receipt(forged, **trusted), "REJECTED", label)
        for label, reason, failure, flags in self.REASON_PROCESS_REFUSED:
            forged = self.rejected_with_process(fx, passing, reason, failure, flags)
            error = self.assertRaisesCode("receipt_evidence_inconsistent", pv.validate_receipt, forged)
            self.assertEqual(error.detail, "reason_process:" + reason.partition(":")[0], label)

    def test_a_rejected_receipt_without_a_process_record_makes_no_process_claim(self):
        fx = Fixture(self).build()
        passing = fx.run().receipt
        for reason, failure in (("execution_timeout", "execution"), ("containment_cleanup_failed", "containment"),
                                ("closure_runtime_violation:x", "closure")):
            forged = self.rejected_with_process(fx, passing, reason, failure, {})
            forged = copy.deepcopy(forged)
            forged["process"] = None
            self.assertEqual(pv.validate_receipt(reseal(forged))["status"], "REJECTED", reason)

    def test_the_published_schema_and_the_validator_agree_on_every_reason_and_process_relationship(self):
        try:
            from trace_gc.schema import validate
        except ImportError as exc:                                      # pragma: no cover
            self.skipTest("jsonschema unavailable: %s" % exc)
        from trace_gc.errors import ContractError
        fx = Fixture(self).build()
        passing = fx.run().receipt
        for label, reason, failure, flags in self.REASON_PROCESS_ACCEPTED:
            validate("paper-verifier-closure-receipt", self.rejected_with_process(fx, passing, reason, failure, flags))
        for label, reason, failure, flags in self.REASON_PROCESS_REFUSED:
            with self.assertRaises(ContractError, msg=label):
                validate("paper-verifier-closure-receipt", self.rejected_with_process(fx, passing, reason, failure, flags))
        for reason, wrong in (("execution_timeout", "closure"), ("closure_runtime_violation:x", "execution"),
                              ("containment_attach_failed", "execution"), ("protocol_output_overflow", "containment")):
            forged = self.rejected_with_process(fx, passing, reason, wrong, {})
            with self.assertRaises(ContractError, msg=reason):
                validate("paper-verifier-closure-receipt", forged)
            with self.assertRaises(pv.ClosureRejected, msg=reason):
                pv.validate_receipt(forged)

    def reason_heads(self):
        """``(reason, class)`` for every class prefix (bare and with a detail), the neutral reasons and the fallback class."""
        heads = []
        for name, prefixes in pv.FAILURE_CLASS_PREFIXES:
            for prefix in prefixes:
                heads += [(prefix + "x", name), (prefix + "x:detail", name)]
        heads += [(reason, "execution") for reason in pv._PROCESS_NEUTRAL]
        heads += [(reason, pv.FAILURE_CLASS_FALLBACK) for reason in (
            "closure_runtime_violation:undeclared_import:x", "dependency_operation_undeclared:a:b", "unlisted_module:a->b",
            "manifest_shape", "receipt_shape:x", "unpinned_import", "x")]
        return heads

    def test_the_published_schema_and_the_validator_agree_on_the_full_reason_to_failure_class_matrix(self):
        """Every reason head against every one of the eight classes, with no class left out: the validator and the schema
        accept exactly the right pairing and refuse every other one, for the release, runtime, input, arguments and
        default (closure) classes as much as for containment, protocol and execution."""
        try:
            from trace_gc.schema import validate
        except ImportError as exc:                                      # pragma: no cover
            self.skipTest("jsonschema unavailable: %s" % exc)
        from trace_gc.errors import ContractError
        fx = Fixture(self).build()
        passing = fx.run().receipt
        classes = sorted(pv.CONTRACT["failure_classes"])
        self.assertEqual(len(classes), 8)
        covered = set()
        for reason, right in self.reason_heads():
            for klass in classes:
                forged = self.rejected_with_process(fx, passing, reason, klass, {})
                if klass == right:
                    covered.add(right)
                    validate("paper-verifier-closure-receipt", forged)
                    self.assertEqual(pv.validate_receipt(forged)["failure_class"], right, reason)
                else:
                    with self.assertRaises(ContractError, msg="schema accepted %s as %s" % (reason, klass)):
                        validate("paper-verifier-closure-receipt", forged)
                    with self.assertRaises(pv.ClosureRejected, msg="validator accepted %s as %s" % (reason, klass)):
                        pv.validate_receipt(forged)
        self.assertEqual(covered, set(classes))                           # no class is exempt from the matrix

    def test_the_schema_generator_reason_tables_equal_the_validator_tables(self):
        generator = REPO / "tools" / "verifier_closure_schemas.py"
        if not generator.is_file():
            self.skipTest("tools/ is not part of this installation")
        spec = importlib.util.spec_from_file_location("verifier_closure_schemas_reasons", generator)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        # EVERY class the validator derives is in the generator's table, with the same prefixes in the same order, plus the
        # same fallback; no class is left to the validator alone
        self.assertEqual([(name, list(prefixes)) for name, prefixes in module.CLASS_PREFIXES],
                         [(name, list(prefixes)) for name, prefixes in pv.FAILURE_CLASS_PREFIXES])
        self.assertEqual(module.CLASS_FALLBACK, pv.FAILURE_CLASS_FALLBACK)
        self.assertEqual({name for name, _ in module.CLASS_PREFIXES} | {module.CLASS_FALLBACK}, set(pv.CONTRACT["failure_classes"]))
        every = [(name, prefix) for name, prefixes in module.CLASS_PREFIXES for prefix in prefixes]
        for index, (name, prefix) in enumerate(every):
            self.assertEqual(pv.failure_class(prefix + "x"), name, prefix)
            self.assertEqual(pv.failure_class(prefix), name, prefix)
            for other, longer in every[index + 1:]:                                       # the prefixes are pairwise independent
                self.assertFalse(prefix.startswith(longer) or longer.startswith(prefix), (prefix, longer))
        for probe in ("closure_x", "closure_runtime_violation", "dependency_operation_undeclared", "manifest_shape",
                      "unresolved_import", "unlisted_module", "import_graph_mismatch", "receipt_shape", "x"):
            self.assertEqual(pv.failure_class(probe), module.CLASS_FALLBACK, probe)
            self.assertFalse(probe.startswith(tuple(prefix for _, prefix in every)), probe)
        self.assertEqual([code for code, _ in module.PROCESS_REASONS], [reason for reason, _, _ in pv._PROCESS_FLAGS])
        self.assertEqual(tuple(module.NEUTRAL_REASONS), tuple(pv._PROCESS_NEUTRAL))
        positive = {"cleanup_failed": {"const": True}, "timed_out": {"const": True},
                    "overflow": {"enum": ["stdout", "stderr"]}, "descendants": {"const": True}}
        keys = [key for _, key, _ in pv._PROCESS_FLAGS]
        for index, (code, flags) in enumerate(module.PROCESS_REASONS):
            self.assertEqual(set(flags), set(keys[:index + 1]), code)
            self.assertEqual(flags[keys[index]], positive[keys[index]], code)
            for earlier in keys[:index]:
                self.assertEqual(flags[earlier], module.CLEAR_FLAGS[earlier], (code, earlier))
        self.assertEqual(set(module.CLEAR_FLAGS), set(keys))

    def test_published_schema_and_validator_agree_on_status_conditionals_exact_positions_and_runtime_strings(self):
        try:
            from trace_gc.schema import validate
        except ImportError as exc:                                      # pragma: no cover
            self.skipTest("jsonschema unavailable: %s" % exc)
        from trace_gc.errors import ContractError
        passing = Fixture(self).build().run().receipt
        holding = Fixture(self, helper=HELPER_HOLD).build().run().receipt
        self.assertEqual(holding["status"], "HOLD")
        cases = (
            ("pass_embeds_hold_result", passing, lambda r: r["verifier"].__setitem__("result", {"status": "HOLD"})),
            ("hold_embeds_pass_result", holding, lambda r: r["verifier"].__setitem__("result", {"status": "PASS"})),
            ("implementation_swapped", passing, lambda r: r["implementation"].insert(0, r["implementation"].pop(1))),
            ("implementation_five_rows", passing, lambda r: r["implementation"].pop()),
            ("implementation_seven_rows", passing, lambda r: r["implementation"].append(dict(r["implementation"][0]))),
            ("implementation_unknown_path", passing, lambda r: r["implementation"][5].__setitem__("path", "trace_gc/x.py")),
            ("runtime_empty_string", passing, lambda r: r["runtime"].__setitem__("implementation", "")),
            ("runtime_overlong_string", passing, lambda r: r["runtime"].__setitem__("version", "v" * 4097)),
            ("pass_with_cleanup_failed", passing, lambda r: r["process"].__setitem__("cleanup_failed", True)),
            ("pass_with_overflow", passing, lambda r: r["process"].__setitem__("overflow", "stdout")),
            ("pass_with_exception_type", passing, lambda r: r["verifier"].__setitem__("exception_type", "ValueError")),
            ("pass_with_unconfirmed_post_check", passing, lambda r: r["post_checks"].__setitem__("runtime_unchanged", False)),
            ("collision_not_a_module", passing, lambda r: r["parent_sys_modules_collisions"].append("not a module")),
        )
        for label, base, mutate in cases:
            forged = copy.deepcopy(base)
            mutate(forged)
            forged = reseal(forged)
            with self.assertRaises(ContractError, msg=label + " (schema)"):
                validate("paper-verifier-closure-receipt", forged)
            with self.assertRaises(pv.ClosureRejected, msg=label + " (validator)"):
                pv.validate_receipt(forged)
        for receipt in (passing, holding):
            validate("paper-verifier-closure-receipt", receipt)
            pv.validate_receipt(receipt)

    NATIVE_PATH = "/opt/trusted/ext.so"

    def with_native_claim(self, passing, claim_path, claim_sha=None, pins=(), platform=None):
        forged = copy.deepcopy(passing)
        name, sha_value = forged["evidence"]["runtime_rows"][0]
        forged["evidence"].update(native_files=[[name, claim_path, claim_sha or sha_value]], native_plan=[], mapped=[],
                                  mapped_sha256=pv.canonical_digest([]))
        forged["loaded"]["native"] = {name: sha_value}
        forged["runtime"]["natives"] = [{"path": path, "sha256": digest} for path, digest in pins]
        if platform is not None:
            forged["runtime"]["platform"] = platform
        return reseal(forged)

    def test_individual_native_file_claims_are_reconciled_with_the_trusted_pins_on_every_platform(self):
        fx = Fixture(self).build()
        passing = fx.run().receipt
        trusted = dict(expected_manifest_sha256=fx.digest, expected_release_sha256=fx.release, require_acceptance=False)
        agreed = passing["evidence"]["runtime_rows"][0][1]
        other = "5" * 64
        self.assertNotEqual(agreed, other)
        accepted = (
            ("pinned_and_equal", self.with_native_claim(passing, self.NATIVE_PATH, pins=[(self.NATIVE_PATH, agreed)])),
            ("unpinned_but_absolute", self.with_native_claim(passing, self.NATIVE_PATH)),
            ("windows_pin_case_folds", self.with_native_claim(passing, "C:\\Py\\EXT.pyd", pins=[("c:\\py\\ext.pyd", agreed)],
                                                              platform="win32")),
            ("windows_unc_path", self.with_native_claim(passing, "\\\\host\\share\\ext.pyd", platform="win32")),
        )
        for label, receipt in accepted:
            self.assertEqual(pv.verify_receipt(receipt, **trusted), "PASS", label)
        refused = (
            ("pinned_with_another_digest", self.with_native_claim(passing, self.NATIVE_PATH, pins=[(self.NATIVE_PATH, other)])),
            ("relative_path", self.with_native_claim(passing, "ext.so")),
            ("dot_relative_path", self.with_native_claim(passing, "./ext.so")),
            ("windows_pin_case_folds_to_a_different_digest", self.with_native_claim(
                passing, "C:\\Py\\EXT.pyd", pins=[("c:\\py\\ext.pyd", other)], platform="win32")),
        )
        self.assertEqual(pv.verify_receipt(                      # POSIX names are case sensitive: a different file, not the pinned one
            self.with_native_claim(passing, "/opt/trusted/EXT.so", pins=[("/opt/trusted/ext.so", other)]), **trusted), "PASS")
        for label, receipt in refused:
            error = self.assertRaisesCode("receipt_evidence_inconsistent", pv.verify_receipt, receipt, **trusted)
            self.assertEqual(error.detail, "native_files_pin", label)

    def test_a_result_that_was_not_embedded_must_be_supplied_and_is_bound_by_digest_and_status(self):
        fx = Fixture(self).build()
        embedded = fx.run().receipt
        result = embedded["verifier"]["result"]
        bare = fx.run(embed_result=False).receipt
        self.assertIsNone(bare["verifier"]["result"])
        self.assertEqual(bare["verifier"]["result_sha256"], embedded["verifier"]["result_sha256"])
        trusted = dict(expected_manifest_sha256=fx.digest, expected_release_sha256=fx.release)
        context = dict(manifest=fx.manifest, expected_inputs={"doc": sha(b"good")}, expected_params_sha256=pv.canonical_digest(None),
                       expected_module_table=fx.table(), **trusted)
        self.assertEqual(pv.verify_receipt(bare, require_acceptance=False, **trusted), "PASS")          # diagnostic readback needs none
        self.assertRaisesCode("receipt_context_required", pv.verify_receipt, bare, **context)           # acceptance cannot go on a bare digest
        self.assertEqual(pv.verify_receipt(bare, require_acceptance=False, result=result, **trusted), "PASS")
        error = self.assertRaisesCode("receipt_not_acceptance_grade", pv.verify_receipt, bare, result=result, **context)
        self.assertEqual(error.detail, "implementation_source")                                          # the result binding itself held
        for label, wrong in (("content", dict(result, doc_sha256="0" * 64)), ("status", dict(result, status="HOLD")),
                             ("extra", dict(result, extra=1)), ("not_a_mapping", [result])):
            self.assertRaisesCode("receipt_result_digest_mismatch", pv.verify_receipt, bare, require_acceptance=False,
                                  result=wrong, **trusted)
        self.assertRaisesCode("receipt_result_digest_mismatch", pv.verify_receipt, embedded, require_acceptance=False,
                              result=dict(result, doc_sha256="0" * 64), **trusted)

    def accepted_candidate(self, fx, receipt):
        """An internally consistent edit of a run's receipt that satisfies every acceptance-grade condition.

        The binding is unkeyed, so any holder of the bytes can build this; it exercises the readback predicates only.
        """
        candidate = copy.deepcopy(receipt)
        windows = candidate["runtime"]["platform"] == "win32"
        candidate["implementation_source"] = "launcher_capture"
        candidate["runtime_protection"] = {
            "inspected": True, "enforced": True, "paths_checked": 12, "exposed": [],
            "policy": pv.WINDOWS_POLICY if windows else pv.POSIX_POLICY,
            "trusted": sorted("sid:" + sid for sid in pv.BUILTIN_SIDS) if windows else ["uid:0"]}
        candidate["process"]["containment"] = "job_object" if windows else "subreaper"
        return candidate

    def test_acceptance_requires_launcher_bytes_enforced_protection_and_owned_containment(self):
        fx = Fixture(self).build()
        receipt = fx.run().receipt
        context = dict(manifest=fx.manifest, expected_inputs={"doc": sha(b"good")}, expected_params_sha256=pv.canonical_digest(None),
                       expected_manifest_sha256=fx.digest, expected_release_sha256=fx.release, expected_module_table=fx.table())
        windows = receipt["runtime"]["platform"] == "win32"
        self.assertEqual(pv.verify_receipt(reseal(self.accepted_candidate(fx, receipt)), **context), "PASS")
        other_backend = "subreaper" if windows else "job_object"
        policy = pv.WINDOWS_POLICY if windows else pv.POSIX_POLICY
        cases = {
            ("implementation_source", "disk_reread"): lambda r: r.__setitem__("implementation_source", "disk_reread"),
            ("runtime_protection", "not_enforced"): lambda r: r["runtime_protection"].__setitem__("enforced", False),
            ("runtime_protection", "not_inspected"): lambda r: r["runtime_protection"].update(inspected=False),
            ("runtime_protection", "exposed"): lambda r: r["runtime_protection"].__setitem__("exposed", ["/x [other_write]"]),
            ("runtime_protection", "unavailable"): lambda r: r["runtime_protection"].update(
                policy="unavailable", inspected=False, trusted=[]),
            ("runtime_protection", "wrong_policy"): lambda r: r["runtime_protection"].__setitem__(
                "policy", pv.POSIX_POLICY if windows else pv.WINDOWS_POLICY),
            ("runtime_protection", "no_administrative_principal"): lambda r: r["runtime_protection"].__setitem__("trusted", []),
            ("runtime_protection", "nothing_checked"): lambda r: r["runtime_protection"].__setitem__("paths_checked", 0),
            ("containment", "other_backend"): lambda r: r["process"].__setitem__("containment", other_backend),
        }
        self.assertEqual(policy, self.accepted_candidate(fx, receipt)["runtime_protection"]["policy"])
        for (detail, label), mutate in cases.items():
            forged = self.accepted_candidate(fx, receipt)
            mutate(forged)
            error = self.assertRaisesCode("receipt_not_acceptance_grade", pv.verify_receipt, reseal(forged), **context)
            self.assertEqual(error.detail, detail, label)

    def test_write_receipt_is_exclusive_and_ascii(self):
        fx = Fixture(self).build()
        run = fx.run()
        target = fx.tmp / "receipt.json"
        written = pv.write_receipt(target, run.receipt)
        self.assertEqual(written, sha(target.read_bytes()))
        self.assertTrue(target.read_bytes().isascii())
        with self.assertRaises(FileExistsError):
            pv.write_receipt(target, run.receipt)
        self.assertEqual(json.loads(target.read_text(encoding="ascii")), run.receipt)

    def test_writes_are_complete_even_when_the_operating_system_writes_in_small_pieces(self):
        real_write = os.write
        calls = []

        def short_write(fd, data):
            calls.append(len(data))
            return real_write(fd, bytes(data)[:3])
        tmp = Path(tempfile.mkdtemp(prefix="pvc-short-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        payload = b"0123456789abcdef" * 8
        with mock.patch.object(pv.os, "write", side_effect=short_write):
            pv._publish_new(tmp / "out.bin", payload)
        self.assertEqual((tmp / "out.bin").read_bytes(), payload)
        self.assertGreater(len(calls), len(payload) // 3 - 1)
        self.assertEqual([p.name for p in tmp.iterdir()], ["out.bin"])

    def test_failed_or_stalled_writes_leave_no_partial_target_and_no_temporary_file(self):
        tmp = Path(tempfile.mkdtemp(prefix="pvc-failwrite-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        real_write = os.write

        def fail_second(fd, data):
            fail_second.count += 1
            if fail_second.count == 2:
                raise OSError("disk full")
            return real_write(fd, bytes(data)[:2])
        fail_second.count = 0
        with mock.patch.object(pv.os, "write", side_effect=fail_second):
            with self.assertRaises(OSError):
                pv._publish_new(tmp / "out.bin", b"abcdef")
        self.assertEqual(list(tmp.iterdir()), [])
        with mock.patch.object(pv.os, "write", return_value=0):
            self.assertRaisesCode("write_incomplete", pv._publish_new, tmp / "out.bin", b"abcdef")
        self.assertEqual(list(tmp.iterdir()), [])

    def test_publication_never_overwrites_an_existing_target(self):
        tmp = Path(tempfile.mkdtemp(prefix="pvc-exists-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        (tmp / "out.bin").write_bytes(b"original")
        with self.assertRaises(FileExistsError):
            pv._publish_new(tmp / "out.bin", b"replacement")
        self.assertEqual((tmp / "out.bin").read_bytes(), b"original")
        self.assertEqual([p.name for p in tmp.iterdir()], ["out.bin"])

    def test_publication_without_hard_links_never_exposes_an_empty_or_partial_destination(self):
        """No supported fallback may create the destination before its bytes are complete: where links are unavailable
        and the platform's rename could silently replace a file, publication is refused instead (fail closed)."""
        tmp = Path(tempfile.mkdtemp(prefix="pvc-nolink-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        seen_destination = []
        real_open, real_rename = os.open, os.rename

        def watch_open(path, *args, **kwargs):
            if os.fspath(path) == str(tmp / "out.bin"):
                seen_destination.append("opened")                         # the old fallback created the destination here
            return real_open(path, *args, **kwargs)
        with mock.patch.object(pv.os, "link", side_effect=OSError("links unsupported")), \
                mock.patch.object(pv.os, "open", side_effect=watch_open):
            if WINDOWS:
                pv._publish_new(tmp / "out.bin", b"complete payload")
                self.assertEqual((tmp / "out.bin").read_bytes(), b"complete payload")
                self.assertRaises(FileExistsError, pv._publish_new, tmp / "out.bin", b"other")
                self.assertEqual((tmp / "out.bin").read_bytes(), b"complete payload")
            else:
                with mock.patch.object(pv.os, "rename", side_effect=AssertionError("rename could replace a file")):
                    self.assertRaisesCode("publish_unsupported", pv._publish_new, tmp / "out.bin", b"complete payload")
                self.assertFalse((tmp / "out.bin").exists())
        self.assertEqual(seen_destination, [])
        self.assertEqual(sorted(p.name for p in tmp.iterdir()), ["out.bin"] if WINDOWS else [])      # no temporary file left behind
        (tmp / "existing.bin").write_bytes(b"original")
        with mock.patch.object(pv.os, "link", side_effect=OSError("links unsupported")):
            if not WINDOWS:
                self.assertRaisesCode("publish_unsupported", pv._publish_new, tmp / "existing.bin", b"replacement")
        self.assertEqual((tmp / "existing.bin").read_bytes(), b"original")

    def test_command_line_build_digest_release_and_run_round_trip(self):
        fx = Fixture(self)
        out = fx.tmp / "manifest.json"
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            self.assertEqual(pv.main(["build", "--name", "cli", "--root", "vc=" + str(fx.root), "--entry", "vc.main",
                                      "--output", str(out)]), 0)
        built = json.loads(captured.getvalue())
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            self.assertEqual(pv.main(["digest", str(out)]), 0)
        expected = captured.getvalue().strip()
        self.assertEqual(expected, built["manifest_sha256"])
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            self.assertEqual(pv.main(["release", str(out)]), 0)
        release = captured.getvalue().strip()
        self.assertEqual(release, built["release_sha256"])
        receipt = fx.tmp / "cli-receipt.json"
        base = ["run", str(out), "--root", "vc=" + str(fx.root), "--input", "doc=%s=%s" % (sha(b"good"), fx.data / "doc.txt"),
                "--timeout", "120", "--allow-unprotected-runtime"]
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(pv.main([*base, "--expected-sha256", expected, "--expected-release-sha256", release,
                                      "--receipt", str(receipt)]), 0)
            self.assertEqual(json.loads(receipt.read_text())["status"], "PASS")
            self.assertFalse(json.loads(receipt.read_text())["runtime_protection"]["enforced"])      # opted out: never acceptance grade
            self.assertEqual(pv.main([*base, "--expected-sha256", expected, "--expected-release-sha256", "0" * 64,
                                      "--receipt", str(fx.tmp / "second.json")]), 1)
        self.assertEqual(json.loads((fx.tmp / "second.json").read_text())["failure_class"], "release")
        # An existing receipt path is refused before any verification work and is never overwritten.
        before = receipt.read_bytes()
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            self.assertEqual(pv.main([*base, "--expected-sha256", expected, "--expected-release-sha256", release,
                                      "--receipt", str(receipt)]), 2)
        self.assertIn("receipt_exists", captured.getvalue())
        self.assertEqual(receipt.read_bytes(), before)
        # Duplicate --input names are an argument error, not a silent last-one-wins.
        duplicate = ["run", str(out), "--root", "vc=" + str(fx.root), "--timeout", "120",
                     "--input", "doc=%s=%s" % (sha(b"good"), fx.data / "doc.txt"),
                     "--input", "doc=%s=%s" % (sha(b"good"), fx.data / "doc.txt")]
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            self.assertEqual(pv.main([*duplicate, "--expected-sha256", expected, "--expected-release-sha256", release,
                                      "--receipt", str(fx.tmp / "dup.json")]), 2)
        self.assertIn("argument_pair_invalid", captured.getvalue())
        self.assertFalse((fx.tmp / "dup.json").exists())

    def test_command_line_timeout_must_be_finite_and_positive(self):
        for bad in ("nan", "0", "-1", "inf", "-inf", "abc", "", str(pv.MAX_TIMEOUT + 1)):
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit, msg=bad) as caught:
                pv.main(["run", "missing-manifest.json", "--expected-sha256", "0" * 64, "--expected-release-sha256", "0" * 64,
                         "--timeout", bad, "--receipt", "unused-receipt.json"])
            self.assertEqual(caught.exception.code, 2, bad)
            self.assertIn("timeout", stderr.getvalue(), bad)
        self.assertEqual(pv._cli_timeout("0.5"), 0.5)
        self.assertEqual(pv._cli_timeout(str(pv.MAX_TIMEOUT)), pv.MAX_TIMEOUT)

    def test_command_line_pairs_and_input_specs_are_bounded_duplicate_free_and_well_formed(self):
        good = sha(b"good")
        self.assertEqual(pv._pairs(["a=1", "b=2"]), {"a": "1", "b": "2"})
        for bad in (["a=1", "a=2"], ["=x"], ["a="], ["noequals"], ["k%d=v" % i for i in range(33)]):
            self.assertRaisesCode("argument_pair_invalid", pv._pairs, bad)
        specs = pv._input_specs(["doc=%s=%s" % (good, Path("/data/doc.txt"))])
        self.assertEqual((specs["doc"].relative, specs["doc"].sha256), ("doc.txt", good))
        for bad in (["doc=%s=/a" % good, "doc=%s=/b" % good], ["doc=zz=/a"], ["doc=%s=" % good], ["doc=%s" % good],
                    ["bad name=%s=/a" % good], ["n%d=%s=/a" % (i, good) for i in range(pv.MAX_INPUTS + 1)]):
            self.assertRaisesCode("argument_pair_invalid", pv._input_specs, bad)

    def test_manifest_file_reads_are_bounded_regular_and_strict(self):
        tmp = Path(tempfile.mkdtemp(prefix="pvc-json-"))
        self.addCleanup(shutil.rmtree, tmp, True)

        def make(name, data: bytes):
            path = tmp / name
            path.write_bytes(data)
            return str(path)
        self.assertEqual(pv._read_json_file(make("ok.json", b'{"a": 1}')), {"a": 1})
        self.assertRaisesCode("manifest_too_large", pv._read_json_file, make("big.json", b'{"a": 1}'), 3)
        # The transport accepts exactly what the canonical encoding can hash: a finite float is data, not an error.
        self.assertEqual(pv._read_json_file(make("float.json", b'{"a": 1.5}')), {"a": 1.5})
        for label, data in (("duplicate", b'{"a": 1, "a": 2}'), ("nan", b'{"a": NaN}'), ("infinity", b'{"a": Infinity}'),
                            ("overflowing_float", b'{"a": 1e999}'), ("integer_over_2_53", b'{"a": 9007199254740993}'),
                            ("huge_integer", b'{"a": ' + b"9" * 6000 + b"}"),
                            ("binary", b"\xff\xfe"), ("truncated", b'{"a": '), ("empty", b"")):
            self.assertRaisesCode("manifest_unparseable", pv._read_json_file, make(label + ".json", data))
        if not WINDOWS:
            self.assertRaisesCode("manifest_not_regular_file", pv._read_json_file, str(tmp))
            fifo = tmp / "pipe.json"
            os.mkfifo(fifo)
            self.assertRaisesCode("manifest_not_regular_file", pv._read_json_file, str(fifo))

    def test_manifest_and_receipt_validate_against_the_published_schemas(self):
        try:
            from trace_gc.schema import validate
        except ImportError as exc:                                      # pragma: no cover
            self.skipTest("jsonschema unavailable: %s" % exc)
        fx = Fixture(self).build()
        validate("paper-verifier-closure-manifest", fx.manifest)
        validate("paper-verifier-closure-receipt", fx.run().receipt)
        rejected = fx.run(release="0" * 64)
        self.assertEqual(rejected.status, "REJECTED")
        validate("paper-verifier-closure-receipt", rejected.receipt)
        validate("paper-verifier-closure-receipt", Fixture(self, helper=HELPER_HOLD).build().run().receipt)

    def test_published_schemas_reject_incomplete_or_unbound_receipts_and_manifests(self):
        try:
            from trace_gc.schema import validate
        except ImportError as exc:                                      # pragma: no cover
            self.skipTest("jsonschema unavailable: %s" % exc)
        from trace_gc.errors import ContractError
        fx = Fixture(self).build()
        receipt = fx.run().receipt
        validate("paper-verifier-closure-receipt", receipt)

        def invalid(name, document, label):
            with self.assertRaises(ContractError, msg=label):
                validate(name, document)
        for label, mutate in (
                ("binding_missing", lambda r: r.pop("binding_sha256")),
                ("binding_none", lambda r: r.__setitem__("binding_sha256", None)),
                ("binding_shape", lambda r: r.__setitem__("binding_sha256", "xyz")),
                ("extra_key", lambda r: r.__setitem__("surplus", 1)),
                ("evidence_missing", lambda r: r.pop("evidence")),
                ("protection_missing", lambda r: r.pop("runtime_protection")),
                ("process_cleanup_missing", lambda r: r["process"].pop("cleanup_failed")),
                ("process_timeout_missing", lambda r: r["process"].pop("timeout_ms")),
                ("process_timeout_zero", lambda r: r["process"].__setitem__("timeout_ms", 0)),
                ("implementation_source_null", lambda r: r.__setitem__("implementation_source", None)),
                ("implementation_source_unknown", lambda r: r.__setitem__("implementation_source", "other")),
                ("protection_enforced_missing", lambda r: r["runtime_protection"].pop("enforced")),
                ("pass_with_descendants", lambda r: r["process"].__setitem__("descendants", True)),
                ("pass_with_violation", lambda r: r["violations"].append("x")),
                ("pass_with_wrong_reason", lambda r: r.__setitem__("reason", "verifier_hold")),
                ("pass_with_a_failure_class", lambda r: r.__setitem__("failure_class", "closure")),
                ("implementation_bytes_missing", lambda r: r["implementation"][0].pop("bytes")),
                ("status", lambda r: r.__setitem__("status", "MAYBE")),
                ("failure_class", lambda r: r.__setitem__("failure_class", "other")),
                ("nonce", lambda r: r["request"].__setitem__("nonce", "short")),
                ("module_table_commitment_missing", lambda r: r["evidence"].pop("module_table_sha256")),
                ("module_table_commitment_shape", lambda r: r["evidence"].__setitem__("module_table_sha256", "xyz"))):
            forged = copy.deepcopy(receipt)
            mutate(forged)
            invalid("paper-verifier-closure-receipt", forged, label)
        rejected = fx.run(release="0" * 64).receipt
        validate("paper-verifier-closure-receipt", rejected)
        for label, mutate in (
                ("rejected_without_failure_class", lambda r: r.__setitem__("failure_class", None)),
                ("rejected_with_verifier_result", lambda r: r.__setitem__("verifier", {"returned": True, "exception_type": None,
                                                                                       "result_sha256": "0" * 64, "result": {}}))):
            forged = copy.deepcopy(rejected)
            mutate(forged)
            invalid("paper-verifier-closure-receipt", forged, label)
        for label, mutate in (
                ("extra_key", lambda m: m.__setitem__("surplus", 1)),
                ("dependency_operations_missing", lambda m: m.pop("dependency_operations")),
                ("dependency_operation_bad_form", lambda m: m["dependency_operations"].append(
                    {"importer": "json", "form": "exec", "module": "x_unavailable"})),
                ("dependency_operation_extra_key", lambda m: m["dependency_operations"].append(
                    {"importer": "json", "form": "import", "module": "x_unavailable", "note": "x"})),
                ("dependency_operations_over_the_bound", lambda m: m.__setitem__("dependency_operations", [
                    {"importer": "json", "form": "import", "module": "probe_%02d" % n}
                    for n in range(pv.MAX_DEPENDENCY_OPERATIONS + 1)])),
                ("runtime_startup_config_missing", lambda m: m["runtime"].pop("startup_config")),
                ("runtime_startup_files_missing", lambda m: m["runtime"].pop("startup_files")),
                ("startup_config_bad_row", lambda m: m["runtime"]["startup_config"].append(["x", "not-a-digest"])),
                ("runtime_executable_sha", lambda m: m["runtime"].__setitem__("executable_sha256", "xyz")),
                ("version", lambda m: m.__setitem__("version", "other"))):
            forged = copy.deepcopy(fx.manifest)
            mutate(forged)
            invalid("paper-verifier-closure-manifest", forged, label)

    def test_runtime_and_packaged_schema_copies_are_identical_and_match_the_generator(self):
        names = ("paper-verifier-closure-manifest", "paper-verifier-closure-receipt")
        packaged_dir = REPO / "trace_gc" / "data" / "schemas"
        runtime_dir = REPO / "schemas" / "runtime"
        generator = REPO / "tools" / "verifier_closure_schemas.py"
        for name in names:
            packaged = (packaged_dir / (name + ".schema.json")).read_bytes()
            self.assertTrue(packaged_dir.joinpath(name + ".schema.json").is_file(), name)
            if runtime_dir.is_dir():
                self.assertEqual((runtime_dir / (name + ".schema.json")).read_bytes(), packaged, name)
        if not generator.is_file():
            self.skipTest("tools/ is not part of this installation")
        spec = importlib.util.spec_from_file_location("verifier_closure_schemas_under_test", generator)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        generated: dict = {}
        module.extend(generated)
        self.assertEqual(set(generated), set(names))
        for name in names:
            stored = json.loads((packaged_dir / (name + ".schema.json")).read_text(encoding="utf-8"))
            for wrapper in ("$schema", "$id", "title"):
                stored.pop(wrapper)
            self.assertEqual(stored, generated[name], name)

    def test_schema_generator_limits_equal_the_parent_limits_so_every_expressible_bound_is_published(self):
        generator = REPO / "tools" / "verifier_closure_schemas.py"
        if not generator.is_file():
            self.skipTest("tools/ is not part of this installation")
        spec = importlib.util.spec_from_file_location("verifier_closure_schemas_limits", generator)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for name in ("MAX_MODULES", "MAX_PACKAGES", "MAX_NATIVES", "MAX_DYNAMIC", "MAX_DEPENDENCY_OPERATIONS", "MAX_INPUTS", "MAX_MODULE_BYTES",
                     "MAX_INPUT_BYTES", "MAX_TIMEOUT_MS", "MAX_RUNTIME_ROWS", "MAX_MAPPED", "MAX_LOADED"):
            self.assertEqual(getattr(module, name), getattr(pv, name), name)
        self.assertEqual(module.MODULE_PATTERN, pv.MODULE.pattern)
        self.assertEqual(module.ALIAS_PATTERN, pv.ALIAS.pattern)
        self.assertEqual(module.INPUT_NAME_PATTERN, pv.INPUT_NAME.pattern)
        self.assertEqual(module.TRUSTED_PATTERN, pv._TRUSTED_LABEL.pattern)
        self.assertEqual(tuple(module.PROTECTION_POLICIES), tuple(pv.PROTECTION_POLICIES))
        self.assertEqual(tuple(module.CONTAINMENTS), tuple(pv.CONTAINMENTS))
        self.assertEqual(tuple(module.IMPLEMENTATION_PATHS), tuple("trace_gc/" + n for n in pv.IMPLEMENTATION_FILES))

    def test_published_schemas_carry_the_numeric_and_array_limits_the_parent_enforces(self):
        packaged_dir = REPO / "trace_gc" / "data" / "schemas"
        manifest = json.loads((packaged_dir / "paper-verifier-closure-manifest.schema.json").read_text(encoding="utf-8"))
        receipt = json.loads((packaged_dir / "paper-verifier-closure-receipt.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["properties"]["modules"]["maxItems"], pv.MAX_MODULES)
        self.assertEqual(manifest["properties"]["packages"]["maxItems"], pv.MAX_PACKAGES)
        self.assertEqual(manifest["properties"]["dynamic"]["maxItems"], pv.MAX_DYNAMIC)
        operations = manifest["properties"]["dependency_operations"]
        self.assertEqual(operations["maxItems"], pv.MAX_DEPENDENCY_OPERATIONS)
        self.assertEqual(operations["items"]["properties"]["form"]["enum"], list(pv.DEPENDENCY_OPERATION_FORMS))
        self.assertEqual(operations["items"]["required"], ["importer", "form", "module"])
        self.assertIn("dependency_operations", manifest["required"])
        self.assertEqual(manifest["properties"]["runtime"]["properties"]["natives"]["maxItems"], pv.MAX_NATIVES)
        self.assertIn("module_table_sha256", json.dumps(receipt))
        self.assertEqual(manifest["properties"]["modules"]["items"]["properties"]["bytes"]["maximum"], pv.MAX_MODULE_BYTES)
        text = json.dumps(receipt)
        for bound in (pv.MAX_TIMEOUT_MS, pv.MAX_RUNTIME_ROWS, pv.MAX_MAPPED, pv.MAX_INPUTS, pv.MAX_INPUT_BYTES):
            self.assertIn(str(bound), text, bound)
        for policy in pv.PROTECTION_POLICIES:
            self.assertIn(policy, text, policy)
        for containment in pv.CONTAINMENTS:
            self.assertIn(containment, text, containment)

    def test_bootstrap_policy_constants_equal_the_parent_policy_constants(self):
        import ast
        tree = ast.parse((REPO / "trace_gc" / "verifier_closure_bootstrap.py").read_text(encoding="utf-8"))
        values = {}
        for node in tree.body:
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                try:
                    values[node.targets[0].id] = ast.literal_eval(node.value)
                except ValueError:
                    pass
        self.assertEqual(frozenset(values["DENIED_IMPORTS"]), pv.FORBIDDEN_MODULES)
        self.assertEqual(values["DEPENDENCY_IMPORT_OPERATIONS"], (("import", "builtins"),))
        self.assertEqual(values["DEPENDENCY_IMPORT_OPERATIONS"], pv.DEPENDENCY_IMPORT_OPERATIONS)
        self.assertEqual(pv.CONTRACT["dependency_import_operations"], [list(item) for item in pv.DEPENDENCY_IMPORT_OPERATIONS])
        self.assertTrue({module for _, module in values["DEPENDENCY_IMPORT_OPERATIONS"]} <= set(values["DENIED_IMPORTS"]))
        self.assertEqual(values["DEPENDENCY_OPERATION_FORMS"], pv.DEPENDENCY_OPERATION_FORMS)
        self.assertEqual(values["DEPENDENCY_OPERATION_PREFIX"], pv.DEPENDENCY_OPERATION_PREFIX)
        self.assertEqual(values["MAX_DEPENDENCY_OPERATIONS"], pv.MAX_DEPENDENCY_OPERATIONS)
        self.assertEqual(pv.CONTRACT["dependency_operation_forms"], list(pv.DEPENDENCY_OPERATION_FORMS))
        self.assertEqual(pv.CONTRACT["limits"]["dependency_operations"], pv.MAX_DEPENDENCY_OPERATIONS)
        self.assertEqual(values["SUPERVISOR_MODULES"], pv.SUPERVISOR_MODULES)
        self.assertEqual(values["PROTOCOL"], pv.PROTOCOL)
        self.assertEqual(values["RESULT_PREFIX"], pv.RESULT_PREFIX)
        self.assertEqual(values["MAX_NATIVE_PLAN"], 256)
        self.assertEqual(values["MAX_NATIVE_DEPTH"], 16)
        self.assertIn("os.system", values["DENIED_EVENT_PREFIXES"])
        self.assertIn("subprocess.", values["DENIED_EVENT_PREFIXES"])
        self.assertIn(("ast", "parse"), values["DYNAMIC_STDLIB_CALLERS"])

    def test_repository_modules_can_be_part_of_a_closure(self):
        """A realistic closure: an authored verifier plus public ``trace_gc`` modules from this checkout."""
        main = ('from trace_gc.canonical import digest\n\n\ndef verify(inputs, params):\n'
                '    return {"status": "PASS", "digest": digest({"doc": inputs["doc"].decode("ascii")})}\n')
        fx = Fixture(self, main=main)
        if linked_ancestors(REPO):
            self.skipTest("the checkout sits below a symlink or junction, which a closure root may not do")
        roots = {"vc": fx.root, "repo": REPO}
        fx.build(roots=roots)
        self.assertEqual({m["name"] for m in fx.manifest["modules"]}, {"vc", "vc.main", "trace_gc", "trace_gc.canonical", "trace_gc.errors"})
        run = fx.run(roots=roots)
        self.assertEqual(run.status, "PASS", run.receipt)
        self.assertEqual(run.receipt["verifier"]["result"]["digest"], pv.canonical_digest({"doc": "good"}))

    def test_bootstrap_imports_nothing_but_the_standard_library_and_the_primitive_ships_under_trace_gc(self):
        import ast
        boot = REPO / "trace_gc" / "verifier_closure_bootstrap.py"
        tree = ast.parse(boot.read_text(encoding="utf-8"))
        imported = {n.names[0].name.partition(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import)}
        imported |= {n.module.partition(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
        self.assertEqual(imported - {"sys", "os", "_imp", "marshal", "_sha2", "_sha256", "fcntl", "_winapi", "msvcrt", "ctypes",
                                     "_ctypes", "importlib"}, set())
        self.assertEqual(Path(pv.PACKAGE_DIR).resolve(), (REPO / "trace_gc").resolve())
        self.assertFalse((REPO / "src" / "paper_verifier_closure_v1.py").exists())

    def test_verifier_modules_are_in_the_method_map_only_when_the_reviewed_dossier_declares_them(self):
        try:
            from src.parallel_source_v4.common import method_hashes
        except ImportError as exc:                                      # pragma: no cover
            self.skipTest("public method_hashes primitive unavailable: %s" % exc)
        members = {k for k in method_hashes(REPO) if "verifier_closure" in k}
        declared = set()
        if self.DOSSIER_FILE.is_file():
            declared = {k for k in json.loads(self.DOSSIER_FILE.read_text(encoding="ascii"))["added"] if "verifier_closure" in k}
        self.assertEqual(members, declared)

    BASELINE_FILE = REPO / "tests" / "data" / "method_hashes_baseline_04acabe.json"
    BASELINE_FILE_SHA256 = "ab5f4014aeea3be429b18288f44f802e5f177a488ac1978c5bd432439f8485c4"
    DOSSIER_FILE = REPO / "tests" / "data" / "method_hashes_integration_dossier.json"

    @staticmethod
    def apply_dossier(baseline: dict, dossier: dict) -> dict:
        """The map a reviewed integration dossier predicts; every declared change must start from the recorded baseline."""
        if set(dossier) != {"schema", "baseline_sha256", "delivered_base", "changed", "added", "removed"}:
            raise ValueError("dossier keys")
        if dossier["schema"] != "method-hashes-integration-dossier-v1" or not dossier["delivered_base"]:
            raise ValueError("dossier identity")
        expected = dict(baseline)
        for path in dossier["removed"]:
            if path not in expected:
                raise ValueError("removed path not in baseline: " + path)
            del expected[path]
        for path, row in dossier["changed"].items():
            if path not in baseline or path not in expected:
                raise ValueError("changed path not in baseline: " + path)
            if set(row) != {"from", "to", "reason"} or not row["reason"].strip():
                raise ValueError("changed row needs from/to/reason: " + path)
            if row["from"] != baseline[path] or row["to"] == row["from"]:
                raise ValueError("changed row does not start from the baseline: " + path)
            expected[path] = row["to"]
        for path, digest in dossier["added"].items():
            if path in baseline:
                raise ValueError("added path already in baseline: " + path)
            expected[path] = digest
        return expected

    def test_the_original_baseline_stays_immutable_and_complete(self):
        data = self.BASELINE_FILE.read_bytes()
        self.assertEqual(hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest(), self.BASELINE_FILE_SHA256)
        baseline = json.loads(data.decode("ascii"))
        self.assertEqual(len(baseline), 87)
        self.assertTrue(all(len(v) == 64 for v in baseline.values()))

    def test_dossier_application_is_exact_and_refuses_unreviewed_or_misanchored_changes(self):
        baseline = {"a.py": "1" * 64, "b.py": "2" * 64, "c.py": "3" * 64}
        base = {"schema": "method-hashes-integration-dossier-v1", "baseline_sha256": self.BASELINE_FILE_SHA256,
                "delivered_base": "deadbeef", "changed": {}, "added": {}, "removed": []}
        self.assertEqual(self.apply_dossier(baseline, base), baseline)                       # nothing declared, nothing changed
        changed = dict(base, changed={"a.py": {"from": "1" * 64, "to": "9" * 64, "reason": "reviewed delivery"}},
                       added={"d.py": "4" * 64}, removed=["c.py"])
        self.assertEqual(self.apply_dossier(baseline, changed), {"a.py": "9" * 64, "b.py": "2" * 64, "d.py": "4" * 64})
        for label, bad in (
                ("wrong_from", dict(base, changed={"a.py": {"from": "0" * 64, "to": "9" * 64, "reason": "x"}})),
                ("no_op_change", dict(base, changed={"a.py": {"from": "1" * 64, "to": "1" * 64, "reason": "x"}})),
                ("no_reason", dict(base, changed={"a.py": {"from": "1" * 64, "to": "9" * 64, "reason": " "}})),
                ("unknown_changed_path", dict(base, changed={"z.py": {"from": "1" * 64, "to": "9" * 64, "reason": "x"}})),
                ("removed_unknown", dict(base, removed=["z.py"])),
                ("added_existing", dict(base, added={"a.py": "5" * 64})),
                ("changed_after_removal", dict(base, removed=["a.py"],
                                               changed={"a.py": {"from": "1" * 64, "to": "9" * 64, "reason": "x"}})),
                ("extra_key", dict(base, surplus=1)),
                ("no_delivered_base", dict(base, delivered_base=""))):
            with self.assertRaises(ValueError, msg=label):
                self.apply_dossier(baseline, bad)

    def test_frozen_method_hashes_complete_output_map_is_either_the_baseline_or_exactly_the_reviewed_dossier(self):
        """Never claims 'unchanged' unless the whole map equals the recorded baseline.

        After the trustee-110 delivery ``phase_authority.py`` legitimately differs; the map must then equal the
        baseline plus a reviewed dossier whose every change is declared, anchored and explained.
        """
        try:
            from src.parallel_source_v4.common import method_hashes
        except ImportError as exc:                                      # pragma: no cover
            self.skipTest("public method_hashes primitive unavailable: %s" % exc)
        current = method_hashes(REPO)
        if any(b"\r\n" in (REPO / name).read_bytes() for name in current):
            self.skipTest("working tree has CRLF line endings; the baseline records LF bytes")
        baseline = json.loads(self.BASELINE_FILE.read_text(encoding="ascii"))
        if current == baseline:
            self.assertFalse(self.DOSSIER_FILE.exists(), "a dossier must not accompany an unchanged map")
            return
        self.assertTrue(self.DOSSIER_FILE.is_file(),
                        "the method map differs from the 04acabe baseline (%s); an integration dossier is required: %s" % (
                            sorted(set(current) ^ set(baseline) | {k for k in current if k in baseline and current[k] != baseline[k]}),
                            self.DOSSIER_FILE.name))
        dossier = json.loads(self.DOSSIER_FILE.read_text(encoding="ascii"))
        self.assertEqual(dossier["baseline_sha256"], self.BASELINE_FILE_SHA256)
        self.assertEqual(current, self.apply_dossier(baseline, dossier))


def committed(receipt, table):
    """A resealed copy of ``receipt`` whose own commitment names ``table`` (what a forger or a matching reviewer holds)."""
    other = copy.deepcopy(receipt)
    other["evidence"]["module_table_sha256"] = pv.module_table_digest(table)
    return reseal(other)


class TrustedModuleIdentity(RejectionMixin, unittest.TestCase):
    """Individual runtime, package, extension and native identities are related to a trusted complete module map that the
    acceptance API requires; a digest or count recomputed from the receipt's own rows proves nothing."""

    GHOST = "zz_ghost_module"

    def prepared(self):
        fx = Fixture(self).build()
        receipt = fx.run().receipt
        self.assertEqual(receipt["status"], "PASS", receipt)
        table = fx.table()
        trusted = dict(expected_manifest_sha256=fx.digest, expected_release_sha256=fx.release, require_acceptance=False)
        name = receipt["evidence"]["runtime_rows"][0][0]
        index = next(i for i, row in enumerate(table) if row[0] == name)
        return fx, receipt, table, trusted, name, index

    def test_a_receipt_is_accepted_against_the_independently_held_complete_map_and_that_map_is_required(self):
        fx, receipt, table, trusted, name, index = self.prepared()
        self.assertEqual(receipt["evidence"]["module_table_sha256"], pv.module_table_digest(table))
        self.assertEqual(pv.module_table_digest(fx.table()), pv.module_table_digest(table))          # the census is reproducible
        self.assertEqual(pv.verify_receipt(receipt, manifest=fx.manifest, expected_module_table=table, **trusted), "PASS")
        self.assertEqual(pv.verify_receipt(receipt, expected_module_table=[list(row) for row in table], **trusted), "PASS")
        context = dict(manifest=fx.manifest, expected_inputs={"doc": sha(b"good")}, expected_params_sha256=pv.canonical_digest(None),
                       expected_manifest_sha256=fx.digest, expected_release_sha256=fx.release)
        error = self.assertRaisesCode("receipt_context_required", pv.verify_receipt, receipt, **context)
        self.assertEqual(error.detail, "module_table")                                              # acceptance needs the map itself
        self.assertRaisesCode("receipt_not_acceptance_grade", pv.verify_receipt, receipt, expected_module_table=table, **context)

    def test_a_map_that_is_not_the_one_the_receipt_committed_to_is_refused(self):
        fx, receipt, table, trusted, name, index = self.prepared()
        changed = copy.deepcopy(table)
        changed[index][3] = "5" * 64
        extra = sorted(copy.deepcopy(table) + [[self.GHOST, "py", os.path.abspath(os.sep + self.GHOST + ".py"), "5" * 64, False, None]],
                       key=lambda row: row[0])
        for label, wrong in (("row_digest", changed), ("extra_row", extra), ("missing_row", table[:index] + table[index + 1:]), ("empty", [])):
            error = self.assertRaisesCode("receipt_module_identity_mismatch", pv.verify_receipt, receipt, expected_module_table=wrong, **trusted)
            self.assertEqual(error.detail, "table_commitment", label)

    def test_a_forger_who_recomputes_every_receipt_digest_cannot_agree_with_the_trusted_map(self):
        fx, receipt, table, trusted, name, index = self.prepared()
        forged = copy.deepcopy(receipt)
        forged["evidence"]["runtime_rows"][0][1] = "5" * 64
        forged["evidence"]["runtime_modules_sha256"] = pv.canonical_digest(forged["evidence"]["runtime_rows"])
        lying = copy.deepcopy(table)
        lying[index][3] = "5" * 64
        lying_receipt = committed(forged, lying)
        error = self.assertRaisesCode("receipt_module_identity_mismatch", pv.verify_receipt, lying_receipt, expected_module_table=table, **trusted)
        self.assertEqual(error.detail, "table_commitment")                                           # its own commitment is not the trust root
        self.assertEqual(pv.verify_receipt(lying_receipt, expected_module_table=lying, **trusted), "PASS")   # the HELD map is the trust root
        copied = reseal(copy.deepcopy(forged))                                                       # commitment copied, row still forged
        error = self.assertRaisesCode("receipt_module_identity_mismatch", pv.verify_receipt, copied, expected_module_table=table, **trusted)
        self.assertEqual(error.detail, "runtime_row:" + name)
        ghost = copy.deepcopy(receipt)
        rows = sorted(ghost["evidence"]["runtime_rows"] + [[self.GHOST, "5" * 64]])
        ghost["evidence"].update(runtime_rows=rows, runtime_modules=len(rows), runtime_modules_sha256=pv.canonical_digest(rows))
        ghost["loaded"]["stdlib"] += 1
        error = self.assertRaisesCode("receipt_module_identity_mismatch", pv.verify_receipt, reseal(ghost), expected_module_table=table, **trusted)
        self.assertEqual(error.detail, "runtime_row:" + self.GHOST)
        ambiguous = copy.deepcopy(table)
        ambiguous[index] = [name, "ambiguous", "", "", False, None]
        error = self.assertRaisesCode("receipt_module_identity_mismatch", pv.verify_receipt, committed(receipt, ambiguous),
                                      expected_module_table=ambiguous, **trusted)
        self.assertEqual(error.detail, "runtime_row:" + name)

    def native_claim(self, receipt, name, path):
        forged = copy.deepcopy(receipt)
        digest = dict((n, s) for n, s in forged["evidence"]["runtime_rows"])[name]
        forged["evidence"].update(native_files=[[name, path, digest]], native_plan=[], mapped=[], mapped_sha256=pv.canonical_digest([]))
        forged["loaded"]["native"] = {name: digest}
        forged["runtime"]["natives"] = []
        return forged

    def test_an_extension_identity_must_be_the_trusted_maps_extension_row_with_the_same_path_and_digest(self):
        fx, receipt, table, trusted, name, index = self.prepared()
        path = "/opt/trusted/ext.so"
        as_extension = copy.deepcopy(table)
        as_extension[index][1:3] = ["ext", path]
        self.assertEqual(pv.verify_receipt(committed(self.native_claim(receipt, name, path), as_extension),
                                           expected_module_table=as_extension, **trusted), "PASS")
        elsewhere = self.native_claim(receipt, name, "/opt/other/ext.so")
        error = self.assertRaisesCode("receipt_module_identity_mismatch", pv.verify_receipt, committed(elsewhere, as_extension),
                                      expected_module_table=as_extension, **trusted)
        self.assertEqual(error.detail, "native_file:" + name)
        not_an_extension = self.native_claim(receipt, name, path)
        error = self.assertRaisesCode("receipt_module_identity_mismatch", pv.verify_receipt, not_an_extension, expected_module_table=table, **trusted)
        self.assertEqual(error.detail, "native_file:" + name)

    def claims(self, receipt, entries):
        """``receipt`` reporting every ``(name, path)`` of ``entries`` as an extension file AND in ``loaded.native``."""
        forged = copy.deepcopy(receipt)
        digests = dict((n, s) for n, s in forged["evidence"]["runtime_rows"])
        forged["evidence"].update(native_files=sorted([name, path, digests[name]] for name, path in entries), native_plan=[],
                                  mapped=[], mapped_sha256=pv.canonical_digest([]))
        forged["loaded"]["native"] = {name: digests[name] for name, _ in entries}
        forged["runtime"]["natives"] = []
        return forged

    @staticmethod
    def extension_map(table, entries):
        """``table`` in which each ``(name, path)`` of ``entries`` is an extension row (what a reviewer's map says)."""
        changed = copy.deepcopy(table)
        for name, path in entries:
            index = next(i for i, row in enumerate(changed) if row[0] == name)
            changed[index][1:3] = ["ext", path]
        return changed

    def test_the_extension_evidence_must_equal_exactly_what_the_trusted_map_assigns_to_the_reported_modules(self):
        fx, receipt, table, trusted, name, index = self.prepared()
        first, second, third = (row[0] for row in receipt["evidence"]["runtime_rows"][:3])
        entries = [(first, "/opt/trusted/a.so"), (second, "/opt/trusted/b.so")]
        mapped = self.extension_map(table, entries)

        def accepted(candidate):
            return pv.verify_receipt(committed(candidate, mapped), expected_module_table=mapped, **trusted)

        def refused(candidate, code, detail):
            error = self.assertRaisesCode(code, pv.verify_receipt, committed(candidate, mapped), expected_module_table=mapped, **trusted)
            self.assertEqual(error.detail, detail)
        self.assertEqual(accepted(self.claims(receipt, entries)), "PASS")                    # the trusted positive: exact equality
        refused(self.claims(receipt, entries[:1]), "receipt_module_identity_mismatch", "native_files_incomplete")   # mutual omission
        refused(self.claims(receipt, []), "receipt_module_identity_mismatch", "native_files_incomplete")           # total omission
        refused(self.claims(receipt, entries + [(third, "/opt/trusted/c.so")]), "receipt_module_identity_mismatch",
                "native_file:" + third)                                                      # an extra row the map does not know as an extension
        refused(self.claims(receipt, [entries[0], (second, "/opt/forged/b.so")]), "receipt_module_identity_mismatch",
                "native_file:" + second)                                                     # the right module at a forged path
        # the two representations are also tied to each other, before the map is consulted
        half = self.claims(receipt, entries)
        del half["loaded"]["native"][second]
        error = self.assertRaisesCode("receipt_evidence_inconsistent", pv.validate_receipt, reseal(half))
        self.assertEqual(error.detail, "native_identity")
        extra = self.claims(receipt, entries)
        extra["loaded"]["native"][third] = dict(extra["evidence"]["runtime_rows"])[third]
        error = self.assertRaisesCode("receipt_evidence_inconsistent", pv.validate_receipt, reseal(extra))
        self.assertEqual(error.detail, "native_identity")
        duplicate = self.claims(receipt, entries)
        duplicate["evidence"]["native_files"] = sorted(duplicate["evidence"]["native_files"] + [list(duplicate["evidence"]["native_files"][0])])
        error = self.assertRaisesCode("receipt_evidence_inconsistent", pv.validate_receipt, reseal(duplicate))
        self.assertEqual(error.detail, "native_files")

    def test_the_complete_external_map_stays_mandatory_for_the_exact_extension_relationship(self):
        fx, receipt, table, trusted, name, index = self.prepared()
        first = receipt["evidence"]["runtime_rows"][0][0]
        mapped = self.extension_map(table, [(first, "/opt/trusted/a.so")])
        omitted = committed(receipt, mapped)                                                 # the receipt omits an extension the map has
        context = dict(manifest=fx.manifest, expected_inputs={"doc": sha(b"good")}, expected_params_sha256=pv.canonical_digest(None),
                       expected_manifest_sha256=fx.digest, expected_release_sha256=fx.release)
        error = self.assertRaisesCode("receipt_context_required", pv.verify_receipt, omitted, **context)
        self.assertEqual(error.detail, "module_table")                                       # acceptance cannot omit the map ...
        self.assertRaisesCode("receipt_module_identity_mismatch", pv.verify_receipt, omitted, expected_module_table=mapped,
                              **trusted)                                                     # ... and the map decides, not the receipt

    def test_loaded_counts_and_distribution_labels_are_taken_from_the_trusted_map_not_from_the_receipt(self):
        fx, receipt, table, trusted, name, index = self.prepared()
        labelled = copy.deepcopy(table)
        labelled[index][5] = "reviewed-dist"
        error = self.assertRaisesCode("receipt_module_identity_mismatch", pv.verify_receipt, committed(receipt, labelled),
                                      expected_module_table=labelled, **trusted)
        self.assertEqual(error.detail, "loaded_counts")                                              # the map assigns it to a package
        error = self.assertRaisesCode("receipt_module_identity_mismatch", pv.verify_receipt, committed(receipt, labelled),
                                      manifest=fx.manifest, expected_module_table=labelled, **trusted)
        self.assertEqual(error.detail, "table_distribution")                                         # and no manifest package owns that label

    def test_a_malformed_map_is_refused_by_shape_before_it_is_compared(self):
        fx, receipt, table, trusted, name, index = self.prepared()
        path, digest = os.path.abspath(os.sep + "a.py"), "5" * 64
        row_a, row_b = ["a", "py", path, digest, False, None], ["b", "py", path, digest, False, None]
        invalid = (("not_a_list", {"a": 1}), ("short_row", [["a", "py", path, digest, False]]), ("unsorted", [row_b, row_a]),
                   ("duplicate", [row_a, row_a]), ("relative_path", [["a", "py", "a.py", digest, False, None]]),
                   ("bad_digest", [["a", "py", path, "zz", False, None]]), ("bad_kind", [["a", "dll", path, digest, False, None]]),
                   ("ambiguous_with_path", [["a", "ambiguous", path, "", False, None]]),
                   ("package_not_bool", [["a", "py", path, digest, 1, None]]), ("bad_distribution", [["a", "py", path, digest, False, "bad dist!"]]),
                   ("bad_name", [["a b", "py", path, digest, False, None]]))
        for label, bad in invalid:
            self.assertRaisesCode("module_table_invalid", pv.module_table_digest, bad)
            self.assertRaisesCode("module_table_invalid", pv.verify_receipt, receipt, expected_module_table=bad, **trusted)
        self.assertEqual(len(pv.module_table_digest([row_a, row_b, ["c", "ambiguous", "", "", False, None]])), 64)

    def test_the_expected_map_digest_is_enforced_before_the_verifier_child_exists(self):
        fx = Fixture(self).build()
        digest = pv.module_table_digest(fx.table())
        self.assertEqual(pv.module_table_digest(fx.verify(expected_module_table_sha256=digest).table), digest)
        self.assertRaisesCode("runtime_module_table_mismatch", fx.verify, expected_module_table_sha256="0" * 64)
        refused = fx.run(expected_module_table_sha256="0" * 64)
        self.assertRejected(refused, "runtime_module_table_mismatch", "runtime")
        self.assertIsNone(refused.receipt["process"])
        self.assertIsNone(refused.receipt["verifier"])
        accepted = fx.run(expected_module_table_sha256=digest)
        self.assertEqual(accepted.status, "PASS", accepted.receipt)
        self.assertEqual(accepted.receipt["evidence"]["module_table_sha256"], digest)
        self.assertRejected(fx.run(expected_module_table_sha256="not-a-digest"), "invalid_arguments", "arguments")


LAUNCHER = REPO / "trace_gc" / "verifier_closure_launcher.py"
LAUNCHER_LOAD =("__init__.py", "errors.py", "canonical.py", "verifier_closure.py")          # executed by the launcher
LAUNCHER_ALL = tuple(pv.IMPLEMENTATION_FILES)                                                 # hashed, captured and bound
ISOLATED = ("-I", "-S", "-B", "-X", "utf8")


class ExternalLauncher(RejectionMixin, unittest.TestCase):
    """The parent cannot authenticate itself; the stdlib-only launcher loads only bytes matching externally pinned digests."""

    def pins(self, directory: Path, **override):
        values = {name: sha((directory / name).read_bytes()) for name in LAUNCHER_ALL}
        values.update(override)
        return [arg for name, value in values.items() if value is not None for arg in ("--sha256", "%s=%s" % (name, value))]

    def launch(self, arguments, flags=ISOLATED, cwd=None):
        done = subprocess.run([sys.executable, *flags, str(LAUNCHER), *arguments], capture_output=True, text=True, timeout=300,
                              cwd=str(cwd or tempfile.gettempdir()))
        return done

    def rejected(self, done, reason):
        self.assertEqual(done.returncode, 2, done.stdout + done.stderr)
        payload = json.loads(done.stdout)
        self.assertEqual(payload["status"], "REJECTED")
        self.assertTrue(payload["reason"].startswith(reason), payload)

    def package_copy(self, fx):
        directory = fx.tmp / "pkgcopy"
        directory.mkdir()
        for name in LAUNCHER_ALL:
            shutil.copy(REPO / "trace_gc" / name, directory / name)
        return directory

    def test_the_launcher_has_only_standard_library_imports_and_pins_exactly_the_files_the_parent_needs(self):
        import ast
        tree = ast.parse(LAUNCHER.read_text(encoding="utf-8"))
        imported = {n.names[0].name.partition(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import)}
        imported |= {n.module.partition(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
        self.assertEqual(imported, {"hashlib", "json", "os", "stat", "sys", "types"})
        self.assertEqual(tuple(sorted(LAUNCHER_LOAD)), tuple(sorted(("__init__.py", "errors.py", "canonical.py", "verifier_closure.py"))))
        self.assertIn("verifier_closure_launcher.py", pv.IMPLEMENTATION_FILES)
        self.assertEqual(set(LAUNCHER_ALL), set(LAUNCHER_LOAD) | {"verifier_closure_bootstrap.py", "verifier_closure_launcher.py"})
        parent_imports = {n.module for n in ast.walk(ast.parse((REPO / "trace_gc" / "verifier_closure.py").read_text(encoding="utf-8")))
                          if isinstance(n, ast.ImportFrom) and n.level == 1}
        self.assertTrue(parent_imports <= {"canonical", "errors"}, parent_imports)     # nothing outside the pinned set

    def test_pinned_bytes_run_the_parent_and_it_agrees_with_the_in_process_digests(self):
        fx = Fixture(self).build()
        manifest = fx.tmp / "manifest.json"
        manifest.write_text(json.dumps(fx.manifest), encoding="utf-8")
        pins = self.pins(REPO / "trace_gc")
        done = self.launch(["--package-dir", str(REPO / "trace_gc"), *pins, "--", "digest", str(manifest)])
        self.assertEqual((done.returncode, done.stdout.strip()), (0, fx.digest), done.stderr)
        done = self.launch(["--package-dir", str(REPO / "trace_gc"), *pins, "--", "release", str(manifest)])
        self.assertEqual((done.returncode, done.stdout.strip()), (0, fx.release), done.stderr)
        receipt = fx.tmp / "receipt.json"
        done = self.launch(["--package-dir", str(REPO / "trace_gc"), *pins, "--", "run", str(manifest), "--expected-sha256", fx.digest,
                            "--expected-release-sha256", fx.release, "--root", "vc=" + str(fx.root),
                            "--input", "doc=%s=%s" % (sha(b"good"), fx.data / "doc.txt"), "--allow-unprotected-runtime",
                            "--receipt", str(receipt)])
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        data = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertEqual(data["status"], "PASS")
        pv.validate_receipt(data)
        self.assertEqual(data["process"]["containment"], "job_object" if WINDOWS else "subreaper")
        self.assertIn("trace_gc/verifier_closure_launcher.py", {row["path"] for row in data["implementation"]})
        self.assertEqual(data["implementation_source"], "launcher_capture")        # the hashed bytes, not a later disk read
        self.assertFalse(data["runtime_protection"]["enforced"])                    # the opt-out is recorded

    def strict_arguments(self, fx, manifest, receipt, package=None):
        return ["--package-dir", str(package or REPO / "trace_gc"), *self.pins(package or REPO / "trace_gc"), "--", "run",
                str(manifest), "--expected-sha256", fx.digest, "--expected-release-sha256", fx.release,
                "--root", "vc=" + str(fx.root), "--input", "doc=%s=%s" % (sha(b"good"), fx.data / "doc.txt"),
                "--receipt", str(receipt)]

    def test_the_strict_launcher_refuses_before_any_process_when_the_evaluator_is_privileged_or_does_not_own_the_tree(self):
        """Negative twin of the protected positive: whichever principal runs this suite, enforcement refuses, with the
        reason that names the actual separation failure, a REJECTED receipt and no interpreter or child ever started."""
        fx = Fixture(self).build()
        manifest = fx.tmp / "manifest.json"
        manifest.write_text(json.dumps(fx.manifest), encoding="utf-8")
        receipt = fx.tmp / "receipt.json"
        done = self.launch(self.strict_arguments(fx, manifest, receipt))
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        data = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertEqual((data["status"], data["failure_class"]), ("REJECTED", "runtime"))
        reason, held = expected_exposure_reason()                                     # uid 0, or an elevated Windows token, comes first
        if held:
            self.assertEqual(data["reason"], "runtime_evaluator_privileged:" + held)
        else:
            self.assertTrue(data["reason"].startswith(reason), data["reason"])
        self.assertIsNone(data["process"])
        self.assertIsNone(data["verifier"])

    @staticmethod
    def unavailable(test, message):
        if os.environ.get("PVC_REQUIRE_PROTECTED"):
            test.fail("PVC_REQUIRE_PROTECTED is set but the protected-acceptance prerequisites are missing: " + message)
        test.skipTest(message + " (set PVC_REQUIRE_PROTECTED=1 to make this a failure)")

    def protected_setup(self):
        """A root-owned fixture the unprivileged evaluator can read but not write, plus a receipt directory it can write."""
        if WINDOWS or os.geteuid() != 0 or not hasattr(os, "chown"):
            self.unavailable(self, "needs POSIX superuser to create a root-owned tree and drop to an unprivileged evaluator")
        uid = int(os.environ.get("PVC_PROTECTED_UID", "65534"))
        gid = int(os.environ.get("PVC_PROTECTED_GID", str(uid)))
        if uid == 0 or gid == 0:
            self.unavailable(self, "PVC_PROTECTED_UID/GID name the superuser")
        fx = Fixture(self).build()
        os.chmod(fx.tmp, 0o755)
        package = self.package_copy(fx)
        os.chmod(package, 0o755)
        out = fx.tmp / "out"
        out.mkdir()
        os.chown(out, uid, gid)
        manifest = fx.tmp / "manifest.json"
        manifest.write_text(json.dumps(fx.manifest), encoding="utf-8")
        return fx, uid, gid, package, out, manifest

    def launch_as(self, uid, gid, arguments):
        env = {k: v for k, v in os.environ.items() if not k.startswith("PYTHON")}
        return subprocess.run([sys.executable, *ISOLATED, str(Path(arguments[1]) / "verifier_closure_launcher.py"), *arguments],
                              capture_output=True, text=True, timeout=300, cwd=tempfile.gettempdir(), env=env,
                              user=uid, group=gid, extra_groups=[])

    def test_a_non_privileged_evaluator_over_a_root_owned_unexposed_tree_yields_an_acceptance_grade_pass(self):
        """The required working positive: separation of evaluator and writers is real (uid dropped, tree root-owned)."""
        fx, uid, gid, package, out, manifest = self.protected_setup()
        receipt = out / "receipt.json"
        done = self.launch_as(uid, gid, self.strict_arguments(fx, manifest, receipt, package))
        if done.returncode == 1 and receipt.exists():
            refused = json.loads(receipt.read_text(encoding="utf-8"))
            if refused["reason"].startswith(("runtime_writable_by_others", "runtime_protection_not_inspectable")):
                self.unavailable(self, "the interpreter or its libraries are not a root-owned, unexposed, readable tree: " +
                                 refused["reason"])
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        data = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertEqual(data["status"], "PASS", data)
        self.assertEqual(pv.verify_receipt(data, manifest=fx.manifest, expected_manifest_sha256=fx.digest,
                                           expected_release_sha256=fx.release, expected_inputs={"doc": sha(b"good")},
                                           expected_params_sha256=pv.canonical_digest(None), expected_module_table=fx.table()), "PASS")
        protection = data["runtime_protection"]
        self.assertEqual((protection["enforced"], protection["inspected"], protection["exposed"], protection["policy"]),
                         (True, True, [], pv.POSIX_POLICY))
        self.assertEqual(protection["trusted"], ["uid:0"])
        self.assertEqual((data["implementation_source"], data["process"]["containment"]), ("launcher_capture", "subreaper"))

    def test_the_same_protected_setup_refuses_a_closure_file_the_evaluator_owns_and_a_privileged_evaluator(self):
        fx, uid, gid, package, out, manifest = self.protected_setup()
        arguments = self.strict_arguments(fx, manifest, out / "receipt.json", package)
        os.chown(fx.root / "vc/helper.py", uid, gid)
        done = self.launch_as(uid, gid, arguments)
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        data = json.loads((out / "receipt.json").read_text(encoding="utf-8"))
        self.assertTrue(data["reason"].startswith("runtime_writable_by_others"), data["reason"])
        self.assertIsNone(data["process"])
        os.chown(fx.root / "vc/helper.py", 0, 0)
        (out / "receipt.json").unlink()
        rooted = subprocess.run([sys.executable, *ISOLATED, str(package / "verifier_closure_launcher.py"), *arguments],
                                capture_output=True, text=True, timeout=300, cwd=tempfile.gettempdir())
        self.assertEqual(rooted.returncode, 1, rooted.stdout + rooted.stderr)
        data = json.loads((out / "receipt.json").read_text(encoding="utf-8"))
        self.assertEqual((data["reason"], data["process"]), ("runtime_evaluator_privileged:uid:0", None))

    def test_the_launcher_must_be_the_file_whose_digest_was_pinned(self):
        fx = Fixture(self).build()
        directory = self.package_copy(fx)
        self.rejected(self.launch(["--package-dir", str(directory), *self.pins(directory), "--", "digest", "x"]),
                      "launcher_not_the_pinned_file")

    def test_a_modified_parent_file_is_refused_before_any_of_it_executes(self):
        fx = Fixture(self).build()
        copy_dir = self.package_copy(fx)
        pins = self.pins(copy_dir)
        marker = fx.tmp / "executed.txt"
        for name in LAUNCHER_ALL:
            original = (copy_dir / name).read_bytes()
            (copy_dir / name).write_bytes(original + ("\nopen(%r, 'w').write('ran')\n" % str(marker)).encode("ascii"))
            self.rejected(self.launch(["--package-dir", str(copy_dir), *pins, "--", "digest", str(fx.tmp / "m.json")]),
                          "launcher_hash_mismatch:" + name)
            self.assertFalse(marker.exists(), name)
            (copy_dir / name).write_bytes(original)
        wrong = self.pins(copy_dir, **{"verifier_closure.py": "0" * 64})
        self.rejected(self.launch(["--package-dir", str(copy_dir), *wrong, "--", "digest", "x"]), "launcher_hash_mismatch:verifier_closure.py")

    def test_incomplete_duplicate_or_malformed_launcher_arguments_are_refused(self):
        package = REPO / "trace_gc"
        pins = self.pins(package)
        self.rejected(self.launch(["--package-dir", str(package), *pins, "digest", "x"]), "launcher_arguments:missing_separator")
        self.rejected(self.launch(["--package-dir", "trace_gc", *pins, "--", "digest", "x"]), "launcher_arguments:package_dir")
        self.rejected(self.launch(["--package-dir", str(package), "--package-dir", str(package), *pins, "--", "digest", "x"]),
                      "launcher_arguments:package_dir")
        self.rejected(self.launch(["--package-dir", str(package), *self.pins(package, **{"errors.py": None}), "--", "digest", "x"]),
                      "launcher_arguments:incomplete")
        self.rejected(self.launch([*pins, "--", "digest", "x"]), "launcher_arguments:incomplete")
        self.rejected(self.launch(["--package-dir", str(package), *pins, *pins[:2], "--", "digest", "x"]), "launcher_arguments:sha256")
        self.rejected(self.launch(["--package-dir", str(package), *pins, "--sha256", "other.py=" + "a" * 64, "--", "digest", "x"]),
                      "launcher_arguments:sha256")
        self.rejected(self.launch(["--package-dir", str(package), *self.pins(package, **{"errors.py": "A" * 64}), "--", "digest", "x"]),
                      "launcher_arguments:sha256")
        self.rejected(self.launch(["--package-dir", str(package), *self.pins(package, **{"errors.py": "ab"}), "--", "digest", "x"]),
                      "launcher_arguments:sha256")
        self.rejected(self.launch(["--unknown", "x", "--", "digest", "x"]), "launcher_arguments:--unknown")

    def test_missing_or_irregular_package_files_are_refused(self):
        fx = Fixture(self).build()
        empty = fx.tmp / "empty"
        empty.mkdir()
        self.rejected(self.launch(["--package-dir", str(empty), *self.pins(REPO / "trace_gc"), "--", "digest", "x"]), "launcher_unreadable")
        directory = self.package_copy(fx)
        pins = self.pins(directory)
        (directory / "errors.py").unlink()
        (directory / "errors.py").mkdir()
        self.rejected(self.launch(["--package-dir", str(directory), *pins, "--", "digest", "x"]), "launcher_file_irregular:errors.py")
        (directory / "errors.py").rmdir()
        shutil.copy(REPO / "trace_gc" / "errors.py", directory / "real_errors.py")
        try:
            os.symlink(directory / "real_errors.py", directory / "errors.py")
        except (OSError, NotImplementedError):
            return
        self.rejected(self.launch(["--package-dir", str(directory), *pins, "--", "digest", "x"]), "launcher_file_irregular:errors.py")

    def test_the_launcher_refuses_to_start_outside_isolated_mode(self):
        pins = self.pins(REPO / "trace_gc")
        arguments = ["--package-dir", str(REPO / "trace_gc"), *pins, "--", "digest", "x"]
        self.rejected(self.launch(arguments, flags=("-P", "-B")), "launcher_requires_isolated_mode")
        self.rejected(self.launch(arguments, flags=("-I", "-B")), "launcher_requires_isolated_mode")        # site still enabled
        self.rejected(self.launch(arguments, flags=("-I", "-S")), "launcher_requires_isolated_mode")        # bytecode may be written


WINDOWS_ADMINISTRATORS = "S-1-5-32-544"
WINDOWS_AUTHENTICATED_USERS = "S-1-5-11"
WINDOWS_PROTECTED_ACL = ("*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-11:(OI)(CI)RX")
WINDOWS_COPY_EXCLUDED = ("site-packages", "__pycache__", "Doc", "Tools", "include", "libs", "idlelib", "turtledemo", "test")
# Self-contained probe executed INSIDE each evaluator process: its own enabled token SIDs, elevation and write ability.
WINDOWS_PROBE = inspect.getsource(pv._windows_token_sids) + '''
import ctypes, json, os, sys
try:
    open(os.path.join(sys.argv[1], "write-probe.txt"), "wb").close()
    wrote = True
except OSError:
    wrote = False
print(json.dumps({"sids": sorted(_windows_token_sids()), "admin": bool(ctypes.windll.shell32.IsUserAnAdmin()), "wrote": wrote}))
'''


def windows_protected_gate(environment, windows, elevated, missing_tooling):
    """('run' | 'fail' | 'skip', reason).  There is no skip switch: an absent prerequisite is a skip only while
    ``PVC_REQUIRE_WINDOWS_PROTECTED`` is unset, and a failure when the hosted Windows job sets it."""
    missing = []
    if not windows:
        missing.append("a native Windows host")
    elif not elevated:
        missing.append("an elevated administrator token that can own the disposable protected tree")
    missing.extend(missing_tooling)
    if not missing:
        return "run", ""
    text = ", ".join(missing)
    if environment.get("PVC_REQUIRE_WINDOWS_PROTECTED"):
        return "fail", "PVC_REQUIRE_WINDOWS_PROTECTED is set but the protected-acceptance prerequisites are missing: " + text
    return "skip", text + " (set PVC_REQUIRE_WINDOWS_PROTECTED=1 to make this a failure)"


def reviewer_module_table(manifest, digest, release, roots, python):
    """The complete module map an independent reviewer holds for the reviewed closure and interpreter."""
    return pv.verify_closure(manifest, digest, expected_release_sha256=release, roots=roots, python=python,
                             allow_unprotected_runtime=True).table


def icacls(*arguments):
    done = subprocess.run(["icacls", *arguments], capture_output=True, text=True, timeout=600)
    if done.returncode != 0:
        raise AssertionError("icacls %s failed (%d): %s" % (" ".join(arguments[:3]), done.returncode, done.stdout + done.stderr))


def remove_protected_tree(path):
    def writable(function, target, _info):
        os.chmod(target, stat.S_IWRITE)
        function(target)
    shutil.rmtree(path, onerror=writable)


class RestrictedEvaluator:
    """Runs a command under a restricted copy of the caller's OWN primary token: Administrators becomes deny-only and
    every removable privilege is disabled.  No account, group, policy or service is created or changed, and the
    token is only used for the one child process.  Native Windows only; NOT_RUN until hosted CI."""

    @staticmethod
    def run(argv, cwd, environment, timeout, stdout_path, stderr_path):
        import ctypes
        import msvcrt
        from ctypes import wintypes
        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)

        class SidAndAttributes(ctypes.Structure):
            _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]

        class StartupInfo(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR), ("lpDesktop", wintypes.LPWSTR),
                        ("lpTitle", wintypes.LPWSTR), ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
                        ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD), ("dwXCountChars", wintypes.DWORD),
                        ("dwYCountChars", wintypes.DWORD), ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
                        ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD), ("lpReserved2", ctypes.c_void_p),
                        ("hStdInput", wintypes.HANDLE), ("hStdOutput", wintypes.HANDLE), ("hStdError", wintypes.HANDLE)]

        class ProcessInformation(ctypes.Structure):
            _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE), ("dwProcessId", wintypes.DWORD),
                        ("dwThreadId", wintypes.DWORD)]

        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
        advapi.OpenProcessToken.restype = wintypes.BOOL
        advapi.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
        advapi.ConvertStringSidToSidW.restype = wintypes.BOOL
        advapi.CreateRestrictedToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(SidAndAttributes),
                                                 wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p,
                                                 ctypes.POINTER(wintypes.HANDLE)]
        advapi.CreateRestrictedToken.restype = wintypes.BOOL
        advapi.CreateProcessAsUserW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p, ctypes.c_void_p,
                                                wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR,
                                                ctypes.POINTER(StartupInfo), ctypes.POINTER(ProcessInformation)]
        advapi.CreateProcessAsUserW.restype = wintypes.BOOL
        kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel.WaitForSingleObject.restype = wintypes.DWORD
        kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel.TerminateProcess.restype = wintypes.BOOL
        kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel.GetExitCodeProcess.restype = wintypes.BOOL
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.LocalFree.argtypes = [ctypes.c_void_p]

        def check(success, what):
            if not success:
                raise OSError(ctypes.get_last_error(), what)

        opened = []
        source, restricted, administrators = wintypes.HANDLE(), wintypes.HANDLE(), ctypes.c_void_p()
        info = ProcessInformation()
        try:
            check(advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x1 | 0x2 | 0x8, ctypes.byref(source)), "OpenProcessToken")
            check(advapi.ConvertStringSidToSidW(WINDOWS_ADMINISTRATORS, ctypes.byref(administrators)), "ConvertStringSidToSidW")
            disabled = (SidAndAttributes * 1)(SidAndAttributes(administrators.value, 0))
            check(advapi.CreateRestrictedToken(source, 0x1, 1, disabled, 0, None, 0, None, ctypes.byref(restricted)),
                  "CreateRestrictedToken")
            streams = [open("NUL", "rb"), open(stdout_path, "wb"), open(stderr_path, "wb")]
            opened.extend(streams)
            handles = [msvcrt.get_osfhandle(stream.fileno()) for stream in streams]
            for handle in handles:
                os.set_handle_inheritable(handle, True)
            startup = StartupInfo()
            startup.cb = ctypes.sizeof(StartupInfo)
            startup.dwFlags = 0x100
            startup.hStdInput, startup.hStdOutput, startup.hStdError = handles
            command = ctypes.create_unicode_buffer(subprocess.list2cmdline([str(a) for a in argv]))
            block = ctypes.create_unicode_buffer("\0".join("%s=%s" % item for item in environment.items()) + "\0")
            check(advapi.CreateProcessAsUserW(restricted, None, command, None, None, True, 0x08000000 | 0x400, block,
                                              str(cwd), ctypes.byref(startup), ctypes.byref(info)), "CreateProcessAsUserW")
            finished = kernel.WaitForSingleObject(info.hProcess, int(timeout * 1000)) == 0
            if not finished:
                kernel.TerminateProcess(info.hProcess, 1)               # the one child this helper started
                kernel.WaitForSingleObject(info.hProcess, 30000)
            code = wintypes.DWORD()
            check(kernel.GetExitCodeProcess(info.hProcess, ctypes.byref(code)), "GetExitCodeProcess")
        finally:
            for handle in (info.hProcess, info.hThread, restricted, source):
                if handle:
                    kernel.CloseHandle(handle)
            if administrators.value:
                kernel.LocalFree(administrators)
            for stream in opened:
                stream.close()
        text = [Path(p).read_text(encoding="utf-8", errors="replace") for p in (stdout_path, stderr_path)]
        return (code.value if finished else None), text[0], text[1]


class WindowsProtectedGateDecisions(unittest.TestCase):
    """The required Windows protected positive cannot be skipped away, satisfied by a refusal, or satisfied by injected facts."""

    def test_the_gate_runs_when_prerequisites_exist_and_has_no_skip_switch(self):
        self.assertEqual(windows_protected_gate({}, True, True, []), ("run", ""))
        self.assertEqual(windows_protected_gate({"PVC_SKIP_WINDOWS_PROTECTED": "1", "PVC_SKIP_WHEEL": "1"}, True, True, [])[0], "run")
        self.assertEqual(windows_protected_gate({"PVC_REQUIRE_WINDOWS_PROTECTED": "1"}, True, True, [])[0], "run")

    def test_absent_prerequisites_skip_only_while_the_requirement_is_unset_and_fail_when_it_is_set(self):
        for windows, elevated, tooling, phrase in ((False, False, [], "native Windows host"),
                                                   (True, False, [], "elevated administrator"),
                                                   (True, True, ["icacls"], "icacls")):
            skipped = windows_protected_gate({}, windows, elevated, tooling)
            self.assertEqual(skipped[0], "skip", phrase)
            self.assertIn(phrase, skipped[1])
            self.assertIn("PVC_REQUIRE_WINDOWS_PROTECTED", skipped[1])
            failed = windows_protected_gate({"PVC_REQUIRE_WINDOWS_PROTECTED": "1"}, windows, elevated, tooling)
            self.assertEqual(failed[0], "fail", phrase)
            self.assertIn(phrase, failed[1])

    def test_the_positive_is_real_process_and_cannot_pass_through_injected_facts_a_refusal_or_a_skip(self):
        source = inspect.getsource(WindowsProtectedAcceptance)
        for forbidden in ("WindowsProtectionView(", "token_sids=", "security=", "mock.", "_dacl_reason(", "protection_view",
                          "allow_unprotected_runtime", "--allow-unprotected-runtime", "skipTest", "unavailable("):
            self.assertNotIn(forbidden, source, forbidden)
        for required in ("RestrictedEvaluator.run(", "verify_receipt(", "expected_module_table=", '"PASS"', "pv._windows_security(",
                         "--expected-module-table-sha256"):
            self.assertIn(required, source, required)
        positive = inspect.getsource(WindowsProtectedAcceptance.test_a_restricted_token_evaluator_over_the_administrator_owned_tree_yields_an_acceptance_grade_pass)
        self.assertIn("self.assertEqual(code, 0", positive)                    # a refusal (exit 1) is a failure here, never a pass
        self.assertNotIn("reason", positive.split("verify_receipt")[0])
        self.assertIn("startswith", inspect.getsource(WindowsProtectedAcceptance.test_the_same_tree_refuses_an_evaluator_writable_closure_file_and_a_privileged_evaluator))

    def test_the_probe_is_self_contained_and_reports_the_enabled_token_groups_elevation_and_write_ability(self):
        compile(WINDOWS_PROBE, "<probe>", "exec")
        for needed in ("GetTokenInformation", "IsUserAnAdmin", "write-probe.txt", "0x4"):
            self.assertIn(needed, WINDOWS_PROBE)
        self.assertNotIn("trace_gc", WINDOWS_PROBE.replace("_windows_token_sids", ""))

    def test_the_restricted_evaluator_helper_only_derives_from_the_callers_own_token(self):
        source = inspect.getsource(RestrictedEvaluator)
        for needed in ("CreateRestrictedToken", "OpenProcessToken(kernel.GetCurrentProcess()", "CreateProcessAsUserW", "TerminateProcess(info.hProcess"):
            self.assertIn(needed, source)
        for forbidden in ("LogonUser", "NetUserAdd", "NetLocalGroup", "AdjustTokenPrivileges", "SetSecurityInfo", "ImpersonateLoggedOnUser", "sc.exe"):
            self.assertNotIn(forbidden, source)

    def test_a_required_windows_class_fails_on_a_non_windows_host_and_no_class_level_skip_can_bypass_its_gate(self):
        """The gate lives in ``setUpClass``.  A class-level ``skipUnless(WINDOWS)`` would skip the class BEFORE it, so a
        Linux host with the requirement set would pass by skipping; neither required class may carry one."""
        for cls in (WindowsProtectedAcceptance, WindowsArmedNativePath):
            with self.subTest(cls.__name__):
                self.assertFalse(getattr(cls, "__unittest_skip__", False))
                self.assertNotIn("skipUnless", inspect.getsource(cls).split("class %s" % cls.__name__, 1)[0][-200:])
                with mock.patch.dict(globals(), {"WINDOWS": False}):
                    with mock.patch.dict(os.environ, {"PVC_REQUIRE_WINDOWS_PROTECTED": "1"}):
                        with self.assertRaises(AssertionError) as caught:
                            cls.setUpClass()
                    self.assertIn("PVC_REQUIRE_WINDOWS_PROTECTED", str(caught.exception))
                    self.assertIn("native Windows host", str(caught.exception))
                    optional = {k: v for k, v in os.environ.items() if k != "PVC_REQUIRE_WINDOWS_PROTECTED"}
                    with mock.patch.dict(os.environ, optional, clear=True):
                        with self.assertRaises(unittest.SkipTest):
                            cls.setUpClass()

    def test_the_posix_protected_positives_cannot_pass_by_refusal_the_unprotected_flag_or_injected_facts(self):
        for test in (ExternalLauncher.test_a_non_privileged_evaluator_over_a_root_owned_unexposed_tree_yields_an_acceptance_grade_pass,
                     InstalledWheel.test_the_installed_wheel_yields_an_acceptance_grade_pass_for_a_non_privileged_evaluator):
            source = inspect.getsource(test)
            for forbidden in ("allow-unprotected-runtime", "allow_unprotected_runtime", "protection_view", "mock."):
                self.assertNotIn(forbidden, source, (test.__name__, forbidden))
            for required in ('"PASS"', "verify_receipt(", "expected_module_table=", "self.assertEqual(done.returncode, 0"):
                self.assertIn(required, source, (test.__name__, required))

    def test_the_posix_protected_requirement_turns_a_missing_prerequisite_into_a_failure(self):
        probe = unittest.TestCase()
        with mock.patch.dict(os.environ, {"PVC_REQUIRE_PROTECTED": "1"}):
            with self.assertRaises(AssertionError) as caught:
                ExternalLauncher.unavailable(probe, "needs POSIX superuser")
        self.assertIn("PVC_REQUIRE_PROTECTED", str(caught.exception))
        optional = {k: v for k, v in os.environ.items() if k != "PVC_REQUIRE_PROTECTED"}
        with mock.patch.dict(os.environ, optional, clear=True):
            with self.assertRaises(unittest.SkipTest):
                ExternalLauncher.unavailable(probe, "needs POSIX superuser")


class WindowsProtectedAcceptance(RejectionMixin, unittest.TestCase):
    """The required Windows working positive, with real processes and real actual token and ACL facts.

    A disposable administrator-owned tree under the system drive holds a copy of the interpreter, the four launcher
    files, the closure and the input.  The evaluator is the same user's token restricted so that Administrators is
    deny-only: it can read and execute the tree and cannot write it, while the administrator test process can.  The
    positive requires an acceptance-grade PASS verified with the independently held module map; a refusal fails it.

    There is deliberately NO class-level ``skipUnless``: a class-level skip would bypass ``setUpClass`` and with it the
    requirement check, so a Linux host with ``PVC_REQUIRE_WINDOWS_PROTECTED=1`` would report a pass-by-skip.  The gate
    below is the only place that decides, and it fails when the requirement is set and a prerequisite is missing.
    """

    @classmethod
    def setUpClass(cls):
        elevated = False
        if WINDOWS:
            try:
                elevated = WINDOWS_ADMINISTRATORS in pv._windows_token_sids()
            except OSError:
                pass
        base = Path(sys.base_prefix) / "python.exe"
        tooling = [name for name, found in (("icacls", shutil.which("icacls")), ("the base interpreter python.exe", base.is_file())) if not found]
        decision, reason = windows_protected_gate(os.environ, WINDOWS, elevated, tooling)
        if decision == "skip":
            raise unittest.SkipTest(reason)
        if decision == "fail":
            raise AssertionError(reason)
        cls.tree = Path(tempfile.mkdtemp(prefix="pvc-protected-", dir=os.environ.get("SystemDrive", "C:") + "\\"))
        cls.addClassCleanup(remove_protected_tree, cls.tree)
        icacls(str(cls.tree), "/inheritance:r", "/grant:r", *WINDOWS_PROTECTED_ACL)
        icacls(str(cls.tree), "/setowner", "*" + WINDOWS_ADMINISTRATORS)
        cls.exe = cls.tree / "python" / "python.exe"
        shutil.copytree(sys.base_prefix, cls.tree / "python", ignore=shutil.ignore_patterns(*WINDOWS_COPY_EXCLUDED))
        cls.pkg = cls.tree / "pkg"
        cls.pkg.mkdir()
        for name in LAUNCHER_ALL:
            shutil.copy(REPO / "trace_gc" / name, cls.pkg / name)
        cls.closure = cls.tree / "closure"
        (cls.closure / "vc").mkdir(parents=True)
        cls.extension = None
        for candidate in WindowsArmedNativePath.EXTENSION_CANDIDATES:
            for path in (cls.tree / "python" / "DLLs").glob(candidate + "*.pyd"):
                if b"api-ms-win-" in path.read_bytes():
                    cls.extension = candidate
                    break
            if cls.extension:
                break
        if cls.extension is None:
            raise AssertionError("no extension file in the interpreter copy imports an API set (candidates %s): the armed "
                                 "native-path fixture fact is missing" % ", ".join(WindowsArmedNativePath.EXTENSION_CANDIDATES))
        native_main = ("import %s\n\n\ndef verify(inputs, params):\n    return {'status': 'PASS', 'module': %s.__name__}\n"
                       % (cls.extension, cls.extension))
        for relative, text in (("vc/__init__.py", ""), ("vc/main.py", MAIN), ("vc/helper.py", HELPER_PASS),
                               ("vc/native.py", native_main)):
            (cls.closure / relative).write_bytes(text.encode("utf-8"))
        cls.data = cls.tree / "data"
        cls.data.mkdir()
        (cls.data / "doc.txt").write_bytes(b"good")
        roots = {"vc": cls.closure}
        cls.manifest = pv.build_manifest(name="windows-protected", roots=roots, entry_module="vc.main", python=cls.exe)
        cls.digest, cls.release = pv.manifest_digest(cls.manifest), pv.release_digest(cls.manifest)
        cls.manifest_path = cls.tree / "manifest.json"
        cls.manifest_path.write_text(json.dumps(cls.manifest), encoding="utf-8")
        cls.table = reviewer_module_table(cls.manifest, cls.digest, cls.release, roots, cls.exe)
        native = pv.build_manifest(name="windows-protected-native", roots=roots, entry_module="vc.native", python=cls.exe)
        native_path = cls.tree / "native-manifest.json"
        native_path.write_text(json.dumps(native), encoding="utf-8")
        native_digest, native_release = pv.manifest_digest(native), pv.release_digest(native)
        cls.native = (native, native_digest, native_release, native_path,
                      reviewer_module_table(native, native_digest, native_release, roots, cls.exe))
        cls.out = Path(tempfile.mkdtemp(prefix="pvc-evaluator-out-"))
        cls.addClassCleanup(shutil.rmtree, cls.out, True)
        cls.environment = {k: v for k, v in os.environ.items() if not k.upper().startswith("PYTHON")}

    def command(self, receipt, variant=None):
        _manifest, digest, release, path, table = variant or (self.manifest, self.digest, self.release, self.manifest_path, self.table)
        pins = [arg for name in LAUNCHER_ALL for arg in ("--sha256", "%s=%s" % (name, sha((self.pkg / name).read_bytes())))]
        return [str(self.exe), *ISOLATED, str(self.pkg / "verifier_closure_launcher.py"), "--package-dir", str(self.pkg), *pins,
                "--", "run", str(path), "--expected-sha256", digest, "--expected-release-sha256", release,
                "--root", "vc=" + str(self.closure), "--input", "doc=%s=%s" % (sha(b"good"), self.data / "doc.txt"),
                "--python", str(self.exe), "--expected-module-table-sha256", pv.module_table_digest(table),
                "--receipt", str(receipt)]

    def evaluate(self, label, restricted=True, variant=None):
        receipt = self.out / (label + ".json")
        argv = self.command(receipt, variant)
        if restricted:
            code, stdout, stderr = RestrictedEvaluator.run(argv, self.out, self.environment, 900, self.out / (label + ".out"),
                                                           self.out / (label + ".err"))
        else:
            done = subprocess.run(argv, capture_output=True, text=True, timeout=900, cwd=str(self.out), env=self.environment)
            code, stdout, stderr = done.returncode, done.stdout, done.stderr
        return code, stdout + stderr, receipt

    def probe(self, label, restricted):
        argv = [str(self.exe), "-I", "-S", "-B", "-c", WINDOWS_PROBE, str(self.tree)]
        if restricted:
            code, stdout, stderr = RestrictedEvaluator.run(argv, self.out, self.environment, 300, self.out / (label + ".out"),
                                                           self.out / (label + ".err"))
        else:
            done = subprocess.run(argv, capture_output=True, text=True, timeout=300, cwd=str(self.out), env=self.environment)
            code, stdout, stderr = done.returncode, done.stdout, done.stderr
        self.assertEqual(code, 0, stdout + stderr)
        return json.loads(stdout.strip().splitlines()[-1])

    def test_the_tree_dacl_and_the_two_principals_are_what_the_separation_claims(self):
        owner, aces = pv._windows_security(str(self.tree))
        self.assertIn(owner, pv.BUILTIN_SIDS)
        self.assertIsNotNone(aces)
        writers = {sid for kind, _flags, mask, sid in aces if kind in (0, 9) and mask & pv._WINDOWS_WRITE_MASK}
        self.assertTrue(writers and writers <= set(pv.BUILTIN_SIDS), writers)
        self.assertIn(WINDOWS_AUTHENTICATED_USERS, {sid for kind, _flags, mask, sid in aces if kind in (0, 9) and mask & 0x1})
        helper_owner, helper_aces = pv._windows_security(str(self.closure / "vc" / "helper.py"))
        self.assertIn(helper_owner, pv.BUILTIN_SIDS)
        self.assertFalse({sid for kind, _f, mask, sid in helper_aces if kind in (0, 9) and mask & pv._WINDOWS_WRITE_MASK} - set(pv.BUILTIN_SIDS))
        restricted = self.probe("probe-restricted", True)
        self.assertNotIn(WINDOWS_ADMINISTRATORS, restricted["sids"])
        self.assertEqual((restricted["admin"], restricted["wrote"]), (False, False))
        privileged = self.probe("probe-privileged", False)
        try:
            self.assertIn(WINDOWS_ADMINISTRATORS, privileged["sids"])
            self.assertEqual((privileged["admin"], privileged["wrote"]), (True, True))
        finally:
            (self.tree / "write-probe.txt").unlink()

    def test_a_restricted_token_evaluator_over_the_administrator_owned_tree_yields_an_acceptance_grade_pass(self):
        code, output, receipt = self.evaluate("positive")
        self.assertEqual(code, 0, output)
        data = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertEqual(data["status"], "PASS", data)
        self.assertEqual(pv.verify_receipt(data, manifest=self.manifest, expected_manifest_sha256=self.digest,
                                           expected_release_sha256=self.release, expected_inputs={"doc": sha(b"good")},
                                           expected_params_sha256=pv.canonical_digest(None), expected_module_table=self.table), "PASS")
        protection = data["runtime_protection"]
        self.assertEqual((protection["enforced"], protection["inspected"], protection["exposed"], protection["policy"]),
                         (True, True, [], pv.WINDOWS_POLICY))
        self.assertTrue({"sid:" + sid for sid in pv.BUILTIN_SIDS} <= set(protection["trusted"]))
        self.assertGreater(protection["paths_checked"], 0)
        self.assertEqual((data["implementation_source"], data["process"]["containment"]), ("launcher_capture", "job_object"))
        self.assertEqual(data["evidence"]["module_table_sha256"], pv.module_table_digest(self.table))

    def test_a_restricted_token_evaluator_loads_a_real_api_set_extension_through_the_armed_native_path_to_an_acceptance_grade_pass(self):
        manifest, digest, release, _path, table = self.native
        code, output, receipt = self.evaluate("native", variant=self.native)
        self.assertEqual(code, 0, output)
        data = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertEqual((data["status"], data["violations"]), ("PASS", []), data)
        self.assertEqual(data["verifier"]["result"]["module"], self.extension)
        self.assertIn(self.extension, data["loaded"]["native"])                   # a pinned extension file, loaded by the native path
        self.assertIn(self.extension, {row[0] for row in data["evidence"]["native_files"]})
        self.assertEqual(pv.verify_receipt(data, manifest=manifest, expected_manifest_sha256=digest, expected_release_sha256=release,
                                           expected_inputs={"doc": sha(b"good")}, expected_params_sha256=pv.canonical_digest(None),
                                           expected_module_table=table), "PASS")

    def test_the_same_tree_refuses_an_evaluator_writable_closure_file_and_a_privileged_evaluator(self):
        helper = self.closure / "vc" / "helper.py"
        icacls(str(helper), "/grant", "*%s:M" % WINDOWS_AUTHENTICATED_USERS)
        try:
            code, output, receipt = self.evaluate("writable-helper")
        finally:
            icacls(str(helper), "/remove:g", "*" + WINDOWS_AUTHENTICATED_USERS)
        self.assertEqual(code, 1, output)
        data = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertTrue(data["reason"].startswith("runtime_writable_by_others"), data["reason"])
        self.assertIsNone(data["process"])
        code, output, receipt = self.evaluate("privileged", restricted=False)
        self.assertEqual(code, 1, output)
        data = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertTrue(data["reason"].startswith("runtime_evaluator_privileged:sid:"), data["reason"])
        self.assertIsNone(data["process"])
        self.assertIsNone(data["verifier"])

    def test_a_trusted_module_map_that_disagrees_with_the_live_runtime_is_refused_before_any_process(self):
        forged = [list(row) for row in self.table]
        forged[0][3] = "0" * 64
        receipt = self.out / "forged-map.json"
        argv = self.command(receipt)
        argv[argv.index("--expected-module-table-sha256") + 1] = pv.module_table_digest(forged)
        code, stdout, stderr = RestrictedEvaluator.run(argv, self.out, self.environment, 900, self.out / "forged.out", self.out / "forged.err")
        self.assertIn(code, (1, 2), stdout + stderr)
        reason = json.loads(receipt.read_text(encoding="utf-8"))["reason"] if receipt.exists() else json.loads(stdout.strip().splitlines()[-1])["reason"]
        self.assertTrue(reason.startswith("runtime_module_table_mismatch"), reason)


class PackageWideIdentityImpact(unittest.TestCase):
    """PaperPilot and local semantics hash every ``*.py`` and every packaged schema JSON, so these files move that identity."""

    def test_every_verifier_file_is_inside_the_package_wide_identity_enumeration(self):
        for module in ("paper_pilot.py", "local_semantics.py"):
            text = (REPO / "trace_gc" / module).read_text(encoding="utf-8")
            self.assertIn('rglob("*.py")', text, module)
            self.assertIn('(root / "data/schemas").glob("*.json")', text, module)
        package = REPO / "trace_gc"
        covered = {p.relative_to(package).as_posix() for p in [*package.rglob("*.py"), *(package / "data/schemas").glob("*.json")]}
        for name in pv.IMPLEMENTATION_FILES:
            self.assertIn(name, covered, name)
        for schema in ("paper-verifier-closure-manifest", "paper-verifier-closure-receipt"):
            self.assertIn("data/schemas/%s.schema.json" % schema, covered)

    def test_the_files_this_work_adds_enter_the_method_map_only_through_the_reviewed_dossier(self):
        added = {"trace_gc/" + name for name in pv.IMPLEMENTATION_FILES if "verifier_closure" in name}
        self.assertEqual(len(added), 3)
        try:
            from src.parallel_source_v4.common import method_hashes
        except ImportError as exc:                                      # pragma: no cover
            self.skipTest("public method_hashes primitive unavailable: %s" % exc)
        present = {k for k in method_hashes(REPO) if k in added}
        dossier_file = ReceiptsCliAndInvariants.DOSSIER_FILE
        declared = set()
        if dossier_file.is_file():
            declared = added & set(json.loads(dossier_file.read_text(encoding="ascii"))["added"])
        self.assertEqual(present, declared)


class InstalledWheel(unittest.TestCase):
    """The shipped artifact chain: a source distribution is built, pip builds the wheel FROM THAT SDIST, pip installs the
    wheel into a clean virtual environment, and the installed copy runs a closure from an external working directory.

    Nothing here extracts a wheel by hand.  The gate may be skipped only by the explicit ``PVC_SKIP_WHEEL`` switch or
    by absent build tooling (build, setuptools, pip, venv, ensurepip); ``PVC_REQUIRE_WHEEL`` overrides both and turns
    absent tooling into a failure (the artifact gate sets it).
    """

    SDIST_FILES = ("verifier_closure.py", "verifier_closure_bootstrap.py", "verifier_closure_launcher.py")
    SCHEMAS = ("paper-verifier-closure-manifest.schema.json", "paper-verifier-closure-receipt.schema.json")

    @staticmethod
    def gate_decision(environment, missing):
        """('run' | 'skip' | 'fail', reason): PVC_REQUIRE_WHEEL always wins over PVC_SKIP_WHEEL and over absent tooling."""
        required = bool(environment.get("PVC_REQUIRE_WHEEL"))
        if missing:
            return ("fail", "PVC_REQUIRE_WHEEL is set but build tooling is missing: " + ", ".join(missing)) if required else (
                "skip", "build tooling unavailable (%s); set PVC_REQUIRE_WHEEL=1 to make this a failure" % ", ".join(missing))
        if environment.get("PVC_SKIP_WHEEL") and not required:
            return "skip", "wheel gate disabled by PVC_SKIP_WHEEL"
        return "run", ""

    @staticmethod
    def missing_tooling():
        missing = []
        for module in ("build", "setuptools", "pip", "venv", "ensurepip"):
            if importlib.util.find_spec(module) is None:
                missing.append(module)
        return missing

    @classmethod
    def setUpClass(cls):
        cls.skip_reason = None
        cls.tmp = Path(tempfile.mkdtemp(prefix="pvc-wheel-"))
        decision, reason = cls.gate_decision(os.environ, cls.missing_tooling())
        if decision == "fail":
            shutil.rmtree(cls.tmp, ignore_errors=True)
            raise AssertionError(reason)
        if decision == "skip":
            cls.skip_reason = reason
            return
        source = cls.tmp / "src-copy"
        source.mkdir()
        for name in ("pyproject.toml", "README.md", "LICENSE", "MANIFEST.in"):
            if (REPO / name).exists():
                shutil.copy(REPO / name, source / name)
        shutil.copytree(REPO / "trace_gc", source / "trace_gc", ignore=shutil.ignore_patterns("__pycache__"))
        cls.source = source
        cls.dist = cls.tmp / "dist"
        cls.run_checked([sys.executable, "-m", "build", "--sdist", "--no-isolation", "--outdir", str(cls.dist), str(source)])
        cls.sdist = next(cls.dist.glob("trace_gc-*.tar.gz"))
        cls.wheels = cls.tmp / "wheels"
        cls.run_checked([sys.executable, "-m", "pip", "wheel", "--no-index", "--no-deps", "--no-build-isolation",
                         "--disable-pip-version-check", "--wheel-dir", str(cls.wheels), str(cls.sdist)])
        cls.wheel = next(cls.wheels.glob("trace_gc-*.whl"))
        env_dir = cls.tmp / "venv"
        cls.run_checked([sys.executable, "-m", "venv", str(env_dir)])
        cls.python = env_dir / ("Scripts/python.exe" if WINDOWS else "bin/python")
        cls.run_checked([str(cls.python), "-m", "pip", "install", "--no-index", "--no-deps", "--disable-pip-version-check",
                         str(cls.wheel)])
        cls.site = subprocess.run([str(cls.python), "-c", "import sysconfig; print(sysconfig.get_paths()['purelib'])"],
                                  capture_output=True, text=True, check=True).stdout.strip()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @staticmethod
    def run_checked(command):
        done = subprocess.run(command, capture_output=True, text=True, timeout=900)
        if done.returncode != 0:
            raise AssertionError("%s failed (%d): %s" % (command[:4], done.returncode, (done.stdout + done.stderr)[-2000:]))
        return done

    def setUp(self):
        if self.skip_reason:
            self.skipTest(self.skip_reason)

    def test_the_source_distribution_carries_the_primitive_and_the_wheel_is_built_from_that_sdist(self):
        import tarfile
        import zipfile
        with tarfile.open(self.sdist) as archive:
            members = archive.getnames()
        for name in self.SDIST_FILES:
            self.assertTrue(any(m.endswith("/trace_gc/" + name) for m in members), name)
        for schema in self.SCHEMAS:
            self.assertTrue(any(m.endswith("/trace_gc/data/schemas/" + schema) for m in members), schema)
        self.assertFalse([m for m in members if "/src/" in m])
        names = zipfile.ZipFile(self.wheel).namelist()
        for name in (*self.SDIST_FILES, "__init__.py", "canonical.py", "errors.py"):
            self.assertIn("trace_gc/" + name, names)
        for schema in self.SCHEMAS:
            self.assertIn("trace_gc/data/schemas/" + schema, names)
        self.assertFalse([n for n in names if n.startswith("src/")])
        # pip installed it: the environment has a dist-info record and the files are byte-identical to the sdist input
        installed = Path(self.site) / "trace_gc"
        self.assertTrue(list(Path(self.site).glob("trace_gc-*.dist-info")))
        for name in pv.IMPLEMENTATION_FILES:
            self.assertEqual(sha((installed / name).read_bytes()), sha((self.source / "trace_gc" / name).read_bytes()), name)
        for schema in self.SCHEMAS:
            self.assertEqual((installed / "data/schemas" / schema).read_bytes(),
                             (self.source / "trace_gc/data/schemas" / schema).read_bytes(), schema)

    def test_installed_wheel_runs_a_closure_from_an_external_working_directory(self):
        tmp, python, site = self.tmp, self.python, self.site
        outside = tmp / "elsewhere"
        outside.mkdir()
        project = outside / "proj"
        project.mkdir()
        (project / "helper.py").write_text("def twice(x):\n    return 2 * x\n")
        (project / "vmain.py").write_text("import helper\n\n\ndef verify(inputs, params):\n    return {'status': 'PASS', 'v': helper.twice(21)}\n")
        env = {k: v for k, v in os.environ.items() if not k.startswith("PYTHON")}
        run = lambda *args: subprocess.run([str(python), "-I", "-m", "trace_gc.verifier_closure", *args], cwd=outside, env=env,
                                           capture_output=True, text=True, timeout=600)
        probe = subprocess.run([str(python), "-I", "-c", "import trace_gc.verifier_closure as m; print(m.__file__)"], cwd=outside, env=env,
                               capture_output=True, text=True, timeout=60)
        self.assertEqual(probe.returncode, 0, probe.stderr)
        self.assertTrue(Path(probe.stdout.strip()).resolve().is_relative_to(Path(site).resolve()), probe.stdout)
        manifest = outside / "manifest.json"
        built = run("build", "--name", "wheel", "--root", "proj=" + str(project), "--entry", "vmain", "--python", str(python),
                    "--output", str(manifest))
        self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
        digests = json.loads(built.stdout.strip().splitlines()[-1])
        receipt = outside / "receipt.json"
        ran = run("run", str(manifest), "--expected-sha256", digests["manifest_sha256"], "--expected-release-sha256",
                  digests["release_sha256"], "--root", "proj=" + str(project), "--python", str(python),
                  "--allow-unprotected-runtime", "--receipt", str(receipt))
        self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)
        data = json.loads(receipt.read_text())
        self.assertEqual((data["status"], data["verifier"]["result"]["v"]), ("PASS", 42))
        self.assertEqual(data["implementation_source"], "disk_reread")             # started with -m: never acceptance grade
        implemented = {row["path"] for row in data["implementation"]}
        self.assertIn("trace_gc/verifier_closure_bootstrap.py", implemented)
        self.assertIn("trace_gc/verifier_closure_launcher.py", implemented)
        package = Path(site) / "trace_gc"
        launcher = package / "verifier_closure_launcher.py"
        pins = [arg for name in LAUNCHER_ALL
                for arg in ("--sha256", "%s=%s" % (name, sha((package / name).read_bytes())))]
        through = subprocess.run([str(python), "-I", "-S", "-B", "-X", "utf8", str(launcher), "--package-dir", str(package), *pins,
                                  "--", "digest", str(manifest)], cwd=outside, env=env, capture_output=True, text=True, timeout=120)
        self.assertEqual((through.returncode, through.stdout.strip()), (0, digests["manifest_sha256"]), through.stderr)
        launched = subprocess.run([str(python), "-I", "-S", "-B", "-X", "utf8", str(launcher), "--package-dir", str(package), *pins,
                                   "--", "run", str(manifest), "--expected-sha256", digests["manifest_sha256"],
                                   "--expected-release-sha256", digests["release_sha256"], "--root", "proj=" + str(project),
                                   "--python", str(python), "--allow-unprotected-runtime", "--receipt", str(outside / "launched.json")],
                                  cwd=outside, env=env, capture_output=True, text=True, timeout=600)
        self.assertEqual(launched.returncode, 0, launched.stdout + launched.stderr)
        again = json.loads((outside / "launched.json").read_text())
        self.assertEqual((again["status"], again["verifier"]["result"]["v"]), ("PASS", 42))
        self.assertEqual(again["implementation_source"], "launcher_capture")
        self.assertEqual(again["implementation"], data["implementation"])        # same shipped bytes whichever way it started
        self.assertFalse(again["runtime_protection"]["enforced"])
        strict = subprocess.run([str(python), "-I", "-S", "-B", "-X", "utf8", str(launcher), "--package-dir", str(package), *pins,
                                 "--", "run", str(manifest), "--expected-sha256", digests["manifest_sha256"],
                                 "--expected-release-sha256", digests["release_sha256"], "--root", "proj=" + str(project),
                                 "--python", str(python), "--receipt", str(outside / "strict.json")],
                                cwd=outside, env=env, capture_output=True, text=True, timeout=600)
        # a venv and project created by this (possibly privileged) process are not a protected deployment: enforcement
        # refuses, naming the separation failure; the protected positive is ExternalLauncher's privilege-dropped test
        self.assertEqual(strict.returncode, 1, strict.stdout + strict.stderr)
        refused = json.loads((outside / "strict.json").read_text())
        self.assertEqual((refused["status"], refused["failure_class"]), ("REJECTED", "runtime"))
        reason, held = expected_exposure_reason()
        if held:
            self.assertEqual(refused["reason"], "runtime_evaluator_privileged:" + held)
        else:
            self.assertTrue(refused["reason"].startswith(reason), refused["reason"])
        (project / "helper.py").write_text("def twice(x):\n    return 3 * x\n")
        bad = run("run", str(manifest), "--expected-sha256", digests["manifest_sha256"], "--expected-release-sha256",
                  digests["release_sha256"], "--root", "proj=" + str(project), "--python", str(python),
                  "--allow-unprotected-runtime", "--receipt", str(outside / "r2.json"))
        self.assertEqual(bad.returncode, 1)
        self.assertIn("closure_module_changed:helper", json.loads((outside / "r2.json").read_text())["reason"])

    def test_the_installed_wheel_yields_an_acceptance_grade_pass_for_a_non_privileged_evaluator(self):
        """The shipped artifact (not the source tree) is the verifier a protected, privilege-dropped evaluator runs: the
        required working positive over the genuine wheel.  A host whose interpreter is not a root-owned, unexposed tree
        is an unsupported configuration (skip, or failure under ``PVC_REQUIRE_PROTECTED``); it is never a pass."""
        if WINDOWS or os.geteuid() != 0 or not hasattr(os, "chown"):
            ExternalLauncher.unavailable(self, "needs POSIX superuser to create a root-owned tree and drop to an unprivileged evaluator")
        uid = int(os.environ.get("PVC_PROTECTED_UID", "65534"))
        gid = int(os.environ.get("PVC_PROTECTED_GID", str(uid)))
        if uid == 0 or gid == 0:
            ExternalLauncher.unavailable(self, "PVC_PROTECTED_UID/GID name the superuser")
        python, site = self.python, self.site
        os.chmod(self.tmp, 0o755)                                                 # mkdtemp is 0700: the evaluator must traverse it
        outside = self.tmp / "protected"
        project, out = outside / "proj", outside / "out"
        for directory in (outside, project, out):
            directory.mkdir(parents=True)
        os.chmod(outside, 0o755)
        os.chmod(project, 0o755)
        os.chown(out, uid, gid)
        (project / "helper.py").write_text("def twice(x):\n    return 2 * x\n")
        (project / "vmain.py").write_text("import helper\n\n\ndef verify(inputs, params):\n    return {'status': 'PASS', 'v': helper.twice(21)}\n")
        env = {k: v for k, v in os.environ.items() if not k.startswith("PYTHON")}
        manifest = outside / "manifest.json"
        built = subprocess.run([str(python), "-I", "-m", "trace_gc.verifier_closure", "build", "--name", "wheel-protected",
                                "--root", "proj=" + str(project), "--entry", "vmain", "--python", str(python),
                                "--output", str(manifest)], cwd=outside, env=env, capture_output=True, text=True, timeout=600)
        self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
        digests = json.loads(built.stdout.strip().splitlines()[-1])
        package = Path(site) / "trace_gc"
        pins = [arg for name in LAUNCHER_ALL for arg in ("--sha256", "%s=%s" % (name, sha((package / name).read_bytes())))]
        receipt = out / "receipt.json"
        done = subprocess.run([str(python), "-I", "-S", "-B", "-X", "utf8", str(package / "verifier_closure_launcher.py"),
                               "--package-dir", str(package), *pins, "--", "run", str(manifest), "--expected-sha256",
                               digests["manifest_sha256"], "--expected-release-sha256", digests["release_sha256"],
                               "--root", "proj=" + str(project), "--python", str(python), "--receipt", str(receipt)],
                              cwd=tempfile.gettempdir(), env=env, capture_output=True, text=True, timeout=600,
                              user=uid, group=gid, extra_groups=[])
        if done.returncode == 1 and receipt.exists():
            refused = json.loads(receipt.read_text(encoding="utf-8"))
            if refused["reason"].startswith(("runtime_writable_by_others", "runtime_protection_not_inspectable")):
                ExternalLauncher.unavailable(self, "the base interpreter behind the wheel's environment is not a root-owned, "
                                                   "unexposed, readable tree: " + refused["reason"])
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        data = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertEqual((data["status"], data["verifier"]["result"]["v"]), ("PASS", 42), data)
        reviewed = json.loads(manifest.read_text(encoding="utf-8"))
        table = reviewer_module_table(reviewed, digests["manifest_sha256"], digests["release_sha256"], {"proj": project}, str(python))
        self.assertEqual(pv.verify_receipt(data, manifest=reviewed, expected_manifest_sha256=digests["manifest_sha256"],
                                           expected_release_sha256=digests["release_sha256"], expected_inputs={},
                                           expected_params_sha256=pv.canonical_digest(None), expected_module_table=table), "PASS")
        protection = data["runtime_protection"]
        self.assertEqual((protection["enforced"], protection["inspected"], protection["exposed"], protection["policy"]),
                         (True, True, [], pv.POSIX_POLICY))
        self.assertEqual((data["implementation_source"], data["process"]["containment"]), ("launcher_capture", "subreaper"))
        installed = {row["path"]: row["sha256"] for row in data["implementation"]}
        for name in pv.IMPLEMENTATION_FILES:                                      # the bytes that ran are the wheel's installed bytes
            self.assertEqual(installed["trace_gc/" + name], sha((package / name).read_bytes()), name)

    def test_the_extracted_package_runs_through_the_launcher_and_matches_the_installed_bytes(self):
        import zipfile
        extracted = self.tmp / "extracted"
        with zipfile.ZipFile(self.wheel) as archive:
            archive.extractall(extracted)
        package = extracted / "trace_gc"
        installed = Path(self.site) / "trace_gc"
        for name in LAUNCHER_ALL:
            self.assertEqual((package / name).read_bytes(), (installed / name).read_bytes(), name)
        outside = self.tmp / "from-extracted"
        outside.mkdir()
        project = outside / "proj"
        project.mkdir()
        (project / "vmain.py").write_text("def verify(inputs, params):\n    return {'status': 'PASS'}\n")
        env = {k: v for k, v in os.environ.items() if not k.startswith("PYTHON")}
        built = subprocess.run([str(self.python), "-I", "-m", "trace_gc.verifier_closure", "build", "--name", "extracted",
                                "--root", "proj=" + str(project), "--entry", "vmain", "--python", str(self.python),
                                "--output", str(outside / "m.json")], cwd=outside, env=env, capture_output=True, text=True, timeout=600)
        self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
        expected = json.loads(built.stdout.strip().splitlines()[-1])["manifest_sha256"]
        pins = [arg for name in LAUNCHER_ALL for arg in ("--sha256", "%s=%s" % (name, sha((package / name).read_bytes())))]
        done = subprocess.run([str(self.python), "-I", "-S", "-B", "-X", "utf8", str(package / "verifier_closure_launcher.py"),
                               "--package-dir", str(package), *pins, "--", "digest", str(outside / "m.json")],
                              cwd=outside, env=env, capture_output=True, text=True, timeout=120)
        self.assertEqual((done.returncode, done.stdout.strip()), (0, expected), done.stderr)
        wrong = list(pins)
        wrong[wrong.index("--sha256") + 1] = "__init__.py=" + "0" * 64
        refused = subprocess.run([str(self.python), "-I", "-S", "-B", "-X", "utf8", str(package / "verifier_closure_launcher.py"),
                                  "--package-dir", str(package), *wrong, "--", "digest", str(outside / "m.json")],
                                 cwd=outside, env=env, capture_output=True, text=True, timeout=120)
        self.assertEqual(refused.returncode, 2, refused.stdout + refused.stderr)
        self.assertTrue(json.loads(refused.stdout)["reason"].startswith("launcher_hash_mismatch:"), refused.stdout)


class WheelGateDecisions(unittest.TestCase):
    """The artifact gate's own switch logic (no build is run here)."""

    decide = staticmethod(InstalledWheel.gate_decision)

    def test_the_gate_runs_unless_it_is_explicitly_skipped_and_not_required(self):
        self.assertEqual(self.decide({}, []), ("run", ""))
        self.assertEqual(self.decide({"PVC_REQUIRE_WHEEL": "1"}, []), ("run", ""))
        self.assertEqual(self.decide({"PVC_SKIP_WHEEL": "1"}, [])[0], "skip")

    def test_require_overrides_every_skip_condition(self):
        self.assertEqual(self.decide({"PVC_REQUIRE_WHEEL": "1", "PVC_SKIP_WHEEL": "1"}, []), ("run", ""))
        decision, reason = self.decide({"PVC_REQUIRE_WHEEL": "1", "PVC_SKIP_WHEEL": "1"}, ["pip"])
        self.assertEqual(decision, "fail")
        self.assertIn("pip", reason)

    def test_absent_tooling_skips_only_when_the_gate_is_not_required(self):
        self.assertEqual(self.decide({}, ["build"])[0], "skip")
        self.assertEqual(self.decide({"PVC_SKIP_WHEEL": "1"}, ["build"])[0], "skip")
        self.assertEqual(self.decide({"PVC_REQUIRE_WHEEL": "1"}, ["build", "venv"])[0], "fail")

    def test_the_build_prerequisites_the_gate_needs_are_all_checked(self):
        source = Path(__file__).read_text(encoding="utf-8")
        for module in ("build", "setuptools", "pip", "venv", "ensurepip"):
            self.assertIn('"%s"' % module, source[source.index("def missing_tooling"):][:400], module)


if __name__ == "__main__":
    unittest.main()
