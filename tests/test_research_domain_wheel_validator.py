"""The installed-wheel gate refuses unsafe, partial and missing wheels."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "validate_domain_wheel.py"


@unittest.skipUnless(TOOL.exists(), "source-checkout tool; not installed in the wheel")
class DomainWheelValidatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("_validate_domain_wheel", TOOL)
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)

    def make_wheel(self, directory, members, name="trace_gc-0.0-py3-none-any.whl"):
        path = Path(directory) / name
        with zipfile.ZipFile(path, "w") as archive:
            for member in members:
                archive.writestr(member, b"{}")
        return path

    def complete(self):
        required = [f"trace_gc/data/schemas/{name}.schema.json" for name in self.tool.DOMAIN_SCHEMAS]
        return required + ["trace_gc/data/research_domains/reference_taxonomy_v1.json"]

    def test_accepts_wheel_with_every_domain_resource(self):
        with tempfile.TemporaryDirectory() as directory:
            wheel = self.make_wheel(directory, self.complete())
            self.assertEqual(len(self.tool.audit_wheel(wheel)), 64)

    def test_rejects_non_wheel_unsafe_member_and_missing_resources(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "expected an actual .whl"):
                self.tool.audit_wheel(self.make_wheel(directory, self.complete(), name="source.zip"))
            with self.assertRaisesRegex(ValueError, "unsafe wheel member"):
                self.tool.audit_wheel(self.make_wheel(directory, self.complete() + ["../escape.py"]))
            partial = self.complete()[1:]
            with self.assertRaisesRegex(ValueError, "lacks domain resources"):
                self.tool.audit_wheel(self.make_wheel(directory, partial))
            no_taxonomy = self.complete()[:-1]
            with self.assertRaisesRegex(ValueError, "lacks domain resources"):
                self.tool.audit_wheel(self.make_wheel(directory, no_taxonomy))

    def test_missing_wheel_reports_fail_never_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.json"
            with contextlib.redirect_stdout(io.StringIO()):
                code = self.tool.main(["--wheel", str(Path(directory) / "absent.whl"), "--report", str(report)])
            data = json.loads(report.read_text(encoding="utf-8"))
        self.assertEqual(code, 1)
        self.assertEqual(data["status"], "FAIL")
        self.assertFalse(data["production_qualified"])


if __name__ == "__main__":
    unittest.main()
