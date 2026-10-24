"""Resource and deterministic schema-generation gates, also usable from a wheel."""
from importlib.resources import files
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from trace_gc.domains import reference_taxonomy
from trace_gc.schema import validate


class DomainPackagingTests(unittest.TestCase):
    def test_installed_resources_cover_domain_contracts(self):
        resources = files("trace_gc").joinpath("data", "schemas")
        names = {entry.name for entry in resources.iterdir() if entry.name.endswith(".schema.json")}
        required = {name + ".schema.json" for name in ("research-domain-taxonomy", "classification-assignment",
                    "classification-projection", "classification-read-identity", "research-domain-scope")}
        self.assertTrue(required <= names)
        for name in required:
            value = json.loads(resources.joinpath(name).read_text(encoding="utf-8"))
            self.assertEqual(value["$schema"], "https://json-schema.org/draft/2020-12/schema")
            self.assertFalse(value.get("additionalProperties", True))

    def test_packaged_taxonomy_is_a_proposal_not_a_trust_root(self):
        record = reference_taxonomy()
        validate("record", record)
        validate("research-domain-taxonomy", record["body"])
        self.assertEqual(record["body"]["review"]["status"], "PROPOSED")
        self.assertIsNone(record["body"]["review"]["reviewer_id"])
        self.assertGreater(len(record["body"]["domains"]), 1)

    def test_domain_generator_leaves_source_and_evidence_schemas_untouched(self):
        """The domain extension must not edit existing source/evidence contracts.

        This compares the schema bodies immediately before and after the domain
        generator runs, so the invariant survives unrelated source-schema changes.
        """
        import copy
        import importlib.util
        root = Path(__file__).resolve().parents[1]
        if not (root / "tools/build_schemas.py").exists():
            self.skipTest("schema generator is a source-checkout gate; installed resources checked independently")
        tools = str(root / "tools")
        sys.path.insert(0, tools)
        observed = {}
        try:
            import domain_schemas
            original = domain_schemas.extend

            def recorder(schemas):
                before = {name: copy.deepcopy(schemas[name]) for name in ("source", "evidence")}
                original(schemas)
                observed["unchanged"] = all(schemas[name] == before[name] for name in before)
            domain_schemas.extend = recorder
            try:
                spec = importlib.util.spec_from_file_location("_domain_build_schemas_probe", root / "tools/build_schemas.py")
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
            finally:
                domain_schemas.extend = original
        finally:
            sys.path.remove(tools)
        self.assertTrue(observed.get("unchanged"))
        resource = files("trace_gc").joinpath("data", "schemas")
        for name in ("source", "evidence"):
            data = resource.joinpath(name + ".schema.json").read_bytes()
            visible = root / "schemas/runtime" / (name + ".schema.json")
            if visible.exists():
                self.assertEqual(data, visible.read_bytes())
            value = json.loads(data)
            self.assertNotIn("classifications", value["properties"])
            self.assertNotIn("research_domain_scope", value["properties"])

    def test_clean_regeneration_matches_both_trees(self):
        root = Path(__file__).resolve().parents[1]
        if not (root / "tools/build_schemas.py").exists():
            self.skipTest("schema generator is a source-checkout gate; installed resources checked independently")
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "tools").mkdir()
            for path in [root / "tools/build_schemas.py", *(root / "tools").glob("*_schemas.py")]:
                shutil.copy2(path, target / "tools" / path.name)
            # Copy the runtime contracts but not pre-generated schemas.  A clean
            # generation gate must not rely on an editable install/PYTHONPATH.
            shutil.copytree(root / "trace_gc", target / "trace_gc",
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "schemas"))
            environment = dict(os.environ)
            environment.pop("PYTHONPATH", None)
            environment.pop("PYTHONHOME", None)
            result = subprocess.run([sys.executable, str(target / "tools/build_schemas.py")],
                                    cwd=target, env=environment,
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            generated = {p.name: p.read_bytes() for p in (target / "schemas/runtime").glob("*.schema.json")}
            packaged = {p.name: p.read_bytes() for p in (target / "trace_gc/data/schemas").glob("*.schema.json")}
            expected = {p.name: p.read_bytes() for p in (root / "schemas/runtime").glob("*.schema.json")}
            self.assertEqual(generated, packaged)
            self.assertEqual(generated, expected)
