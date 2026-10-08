"""A genuinely generated sdist must ship, and be able to import, what the phase-fence tests need.

The wheel installs only ``trace_gc``; ``src/``, ``tools/``, the phase and Windows test modules and
``tests/phase_trustee_harness.py`` reach an sdist only through ``MANIFEST.in`` on older build
backends. This builds a real sdist with the declared build backend (setuptools from pyproject.toml) from a copy of the tree, derives
from the source imports and by-path loads every file the affected tests need, requires each to be an
sdist member, and requires every affected test module to import from the extracted sdist. A missing
module fails; nothing is skipped. Any equivalent MANIFEST.in rule passes.
"""
from __future__ import annotations

import ast
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
ROOT_PATTERNS = ("tests/test_paper_pilot_phase_*.py", "tests/test_windows_*.py")
EXTRA_ROOTS = ("tests/phase_trustee_harness.py", "tools/installed_phase_authority_check.py",
               "tests/test_sdist_phase_distribution.py")
BY_PATH = re.compile(r"""["'](src|tools)["']\s*/\s*["'](\w+\.py)["']""")
FIRST_PARTY = {"src", "tools", "tests", "trace_gc"}
BUILD_INPUTS = ("pyproject.toml", "setup.cfg", "setup.py", "MANIFEST.in", "README.md", "LICENSE")
BUILD_TREES = ("trace_gc", "src", "tools", "tests")
IMPORT_PROBE = (
    "import json, sys, unittest\n"
    "sys.path.insert(0, '')\n"
    "broken, loaded = [], set()\n"
    "def walk(suite):\n"
    "    for item in suite:\n"
    "        if isinstance(item, unittest.TestSuite):\n"
    "            walk(item)\n"
    "        elif type(item).__name__ == '_FailedTest':\n"
    "            broken.append(item.id())\n"
    "        else:\n"
    "            loaded.add(type(item).__module__)\n"
    "for pattern in sys.argv[1:]:\n"
    "    walk(unittest.TestLoader().discover('tests', pattern))\n"
    "print(json.dumps({'broken': broken, 'loaded': sorted(loaded)}))\n"
)


def _resolve(module: str) -> Path | None:
    base = ROOT.joinpath(*module.split("."))
    for candidate in (base.with_suffix(".py"), base / "__init__.py"):
        if candidate.is_file():
            return candidate
    return None


def _imports(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            yield from (alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            yield node.module
            yield from (node.module + "." + alias.name for alias in node.names)


def affected_files() -> set[Path]:
    todo = [path for pattern in ROOT_PATTERNS for path in ROOT.glob(pattern)]
    todo += [ROOT / name for name in EXTRA_ROOTS]
    seen: set[Path] = set()
    while todo:
        path = todo.pop()
        if path in seen:
            continue
        seen.add(path)
        text = path.read_text(encoding="utf-8")
        for module in _imports(path):
            if module.split(".")[0] in FIRST_PARTY:
                found = _resolve(module)
                if found is not None:
                    todo.append(found)
        for folder, name in BY_PATH.findall(text):
            todo.append(ROOT / folder / name)
    return seen


def needed_relative_paths() -> set[str]:
    return {path.relative_to(ROOT).as_posix() for path in affected_files()
            if not path.relative_to(ROOT).as_posix().startswith("trace_gc/")}


class ClosureTests(unittest.TestCase):
    def test_the_closure_is_the_expected_non_empty_set(self):
        needed = needed_relative_paths()
        for expected in ("src/paper_pilot_phase_cutover_guarded_v4.py", "tests/phase_trustee_harness.py",
                         "tools/windows_fixture_acl.py", "tools/windows_fence_diagnostics.py",
                         "tools/installed_phase_authority_check.py"):
            self.assertIn(expected, needed)


class GeneratedSdistTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        declared = re.search(r"setuptools>=(\d+)", (ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        import setuptools
        if declared is None or int(setuptools.__version__.split(".")[0]) < int(declared.group(1)):
            raise AssertionError("pyproject.toml requires setuptools>=%s; this interpreter has %s"
                                 % (declared and declared.group(1), setuptools.__version__))
        cls.work = Path(tempfile.mkdtemp(prefix="sdist-phase-"))
        cls.addClassCleanup(shutil.rmtree, cls.work, ignore_errors=True)
        tree = cls.work / "tree"
        tree.mkdir()
        for name in BUILD_INPUTS:
            if (ROOT / name).is_file():
                shutil.copy2(ROOT / name, tree / name)
        for name in BUILD_TREES:
            shutil.copytree(ROOT / name, tree / name, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        dist = cls.work / "dist"
        dist.mkdir()
        build = subprocess.run(
            [sys.executable, "-c", "import sys, setuptools.build_meta as b; b.build_sdist(sys.argv[1])", str(dist)],
            cwd=tree, capture_output=True, text=True, timeout=300)
        if build.returncode:
            raise AssertionError("sdist build failed:\n" + build.stdout + build.stderr)
        archives = sorted(dist.glob("*.tar.gz"))
        assert len(archives) == 1, archives
        with tarfile.open(archives[0]) as archive:
            cls.members = {"/".join(member.name.split("/")[1:]) for member in archive.getmembers() if member.isfile()}
            extract = cls.work / "extracted"
            if hasattr(tarfile, "data_filter"):
                archive.extractall(extract, filter="data")
            else:
                archive.extractall(extract)
        cls.extracted = next(extract.iterdir())

    def test_every_file_the_affected_tests_need_is_a_member_of_the_generated_sdist(self):
        missing = sorted(needed_relative_paths() - self.members)
        self.assertEqual(missing, [], "the generated sdist does not ship files the affected tests need")

    def test_every_affected_test_module_imports_from_the_extracted_sdist(self):
        patterns = [Path(pattern).name for pattern in ROOT_PATTERNS]
        expected = sorted(path.stem for pattern in ROOT_PATTERNS for path in ROOT.glob(pattern))
        probe = subprocess.run([sys.executable, "-c", IMPORT_PROBE, *patterns], cwd=self.extracted,
                               capture_output=True, text=True, timeout=300)
        self.assertEqual(probe.returncode, 0, probe.stdout + probe.stderr)
        result = json.loads(probe.stdout)
        self.assertEqual(result["broken"], [])
        self.assertEqual(result["loaded"], expected)


if __name__ == "__main__":
    unittest.main()
