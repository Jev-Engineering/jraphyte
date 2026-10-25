"""Public source identity regressions; these are not empirical qualification."""
import hashlib
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from src import paper_qualification_v1 as evaluator
from src.parallel_source_v4.common import REPO, method_hashes


class AdditionalRootTests(unittest.TestCase):
    def test_default_roots_do_not_adopt_unrequested_entrypoint(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            seed = root / "src/parallel_source_v4/metric.py"
            seed.parent.mkdir(parents=True)
            seed.write_text("VALUE = 1\n", encoding="utf-8")
            extra = root / "authored_verifier.py"
            extra.write_text("VALUE = 'HOLD'\n", encoding="utf-8")
            before = method_hashes(root)
            self.assertEqual(before, method_hashes(root, additional_roots=()))
            extra.write_text("VALUE = 'PASS'\n", encoding="utf-8")
            self.assertEqual(before, method_hashes(root))
            self.assertNotIn("authored_verifier.py", before)
            selected = method_hashes(root, additional_roots=("authored_verifier",))
            self.assertEqual(set(selected) - set(before), {"authored_verifier.py"})

    def test_explicit_roots_fail_closed_when_missing_or_invalid(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for module in ("absent.verifier", "../outside", "", "os.path"):
                with self.subTest(module=module), self.assertRaises(ValueError):
                    method_hashes(root, additional_roots=(module,))

    def test_scan_includes_packages_and_local_imports_without_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sources = {
                "authored_verifier/__init__.py": "raise RuntimeError('must not import package')\n",
                "authored_verifier/entry.py": (
                    "from . import helper\n"
                    "def evaluate():\n    from .nested import result\n"
                    "raise RuntimeError('must not execute verifier')\n"),
                "authored_verifier/helper.py": "raise RuntimeError('must not import helper')\n",
                "authored_verifier/nested.py": "raise RuntimeError('must not import nested helper')\n",
            }
            for relative, source in sources.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(source, encoding="utf-8")
            hashes = method_hashes(root, additional_roots=("authored_verifier.entry",))
            self.assertEqual(set(hashes), set(sources))
            self.assertEqual(hashes, {
                name: hashlib.sha256(source.encode()).hexdigest() for name, source in sources.items()})


class EvaluatorClosureTests(unittest.TestCase):
    def test_real_qualifier_helpers_are_bound_without_entrypoint_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for directory in ("src", "trace_gc"):
                shutil.copytree(REPO / directory, root / directory,
                                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            entry = root / "src/paper_qualification_v1.py"
            with patch.object(evaluator, "__file__", str(entry)), patch.object(
                    evaluator, "method_hashes", side_effect=lambda **kwargs: method_hashes(root, **kwargs)):
                before = evaluator.evaluator_identity()
                helpers = ("trace_gc/constraints.py", "trace_gc/plans.py",
                           "trace_gc/policy.py", "trace_gc/resolver.py")
                self.assertTrue(set(helpers) <= set(before))
                self.assertIn("src/paper_qualification_v1.py", before)
                for helper in helpers:
                    path = root / helper
                    original = path.read_bytes()
                    try:
                        path.write_bytes(original + b"\nraise RuntimeError('authored unexecuted mutation')\n")
                        after = evaluator.evaluator_identity()
                        self.assertEqual(before["src/paper_qualification_v1.py"],
                                         after["src/paper_qualification_v1.py"])
                        self.assertNotEqual(before[helper], after[helper])
                        self.assertEqual({name for name in before if before[name] != after[name]}, {helper})
                    finally:
                        path.write_bytes(original)


if __name__ == "__main__":
    unittest.main()
