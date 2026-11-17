"""The installed-wheel gate refuses unsafe, partial and missing wheels."""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
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
        return required + [self.tool.TAXONOMY]

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

    def test_installed_smoke_is_valid_python(self):
        compile(self.tool.SMOKE, "<installed-wheel-smoke>", "exec")

    def test_missing_wheel_reports_fail_never_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.json"
            with contextlib.redirect_stdout(io.StringIO()):
                code = self.tool.main(["--wheel", str(Path(directory) / "absent.whl"), "--report", str(report)])
            data = json.loads(report.read_text(encoding="utf-8"))
        self.assertEqual(code, 1)
        self.assertEqual(data["status"], "FAIL")
        self.assertFalse(data["production_qualified"])

    def test_report_destination_must_be_distinct_from_input(self):
        with tempfile.TemporaryDirectory() as directory:
            wheel = self.make_wheel(directory, self.complete())
            original = wheel.read_bytes()
            hard_link = wheel.with_name("hard-link.json")
            os.link(wheel, hard_link)
            for output in (wheel, hard_link):
                with self.subTest(output=output.name), contextlib.redirect_stdout(io.StringIO()) as stdout:
                    code = self.tool.main(["--wheel", str(wheel), "--report", str(output)])
                    self.assertEqual(code, 1)
                    self.assertEqual(json.loads(stdout.getvalue())["error"]["code"], "REPORT_PATH_ALIAS")
                    self.assertEqual(wheel.read_bytes(), original)

    def run_validator(self, wheel, report):
        with contextlib.redirect_stdout(io.StringIO()) as stdout:
            code = self.tool.main(["--wheel", str(wheel), "--report", str(report)])
        data = json.loads(report.read_text(encoding="utf-8"))
        self.assertEqual(json.loads(stdout.getvalue()), data)
        return code, data

    def smoke_payload(self):
        return {
            "status": "PASS", "installed_imports": True, "checkout_imports": False,
            "schema_count": len(self.tool.DOMAIN_SCHEMAS), "domain_contract_lifecycle": "PASS",
            "reference_taxonomy_review": "PROPOSED", "cli_version": "TRACE-GC 0.4.0",
        }

    def test_audit_and_install_share_a_private_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            wheel = self.make_wheel(directory, self.complete())
            original = wheel.read_bytes()
            audit = self.tool.audit_wheel

            def audit_then_replace(staged):
                self.assertNotEqual(staged.parent, wheel.parent)
                self.assertEqual(staged.name, wheel.name)
                digest = audit(staged)
                wheel.write_bytes(b"replacement")
                return digest

            def run(command, **kwargs):
                if command[2] == "-m":
                    self.assertEqual(Path(command[-1]).read_bytes(), original)
                    return subprocess.CompletedProcess(command, 0, b"", b"")
                return subprocess.CompletedProcess(command, 0, json.dumps(self.smoke_payload()).encode(), b"")

            with patch.object(self.tool, "audit_wheel", side_effect=audit_then_replace) as audited, \
                    patch.object(self.tool.subprocess, "run", side_effect=run) as child:
                code, data = self.run_validator(wheel, Path(directory) / "report.json")
            staged = audited.call_args.args[0]
            self.assertEqual(Path(child.call_args_list[0].args[0][-1]), staged)
            self.assertFalse(staged.exists())
            self.assertEqual(code, 0)
            self.assertEqual(data["wheel_sha256"], hashlib.sha256(original).hexdigest())
            self.assertEqual(data["wheel_bytes"], len(original))
            self.assertFalse(data["production_qualified"])

    def test_rejects_malformed_or_extra_smoke_fields(self):
        base = self.smoke_payload()
        cases = [
            b"not json",
            b"null",
            b'{"status":"PASS","status":"PASS",' + json.dumps(base).encode()[1:],
            json.dumps({"status": "PASS"}).encode(),
            json.dumps(dict(base, status="FAIL")).encode(),
            json.dumps(dict(base, production_qualified=True, scope="changed", wheel_sha256="changed")).encode(),
            json.dumps(dict(base, installed_imports=1)).encode(),
            json.dumps(dict(base, checkout_imports=True)).encode(),
            json.dumps(dict(base, schema_count=True)).encode(),
            json.dumps(dict(base, cli_version="/private/tree")).encode(),
        ]
        with tempfile.TemporaryDirectory() as directory:
            wheel = self.make_wheel(directory, self.complete())
            for payload in cases:
                with self.subTest(payload=payload), patch.object(self.tool.subprocess, "run", side_effect=[
                    subprocess.CompletedProcess([], 0, b"", b""),
                    subprocess.CompletedProcess([], 0, payload, b""),
                ]):
                    code, data = self.run_validator(wheel, Path(directory) / "report.json")
                    self.assertEqual(code, 1)
                    self.assertEqual(data["status"], "FAIL")
                    self.assertEqual(data["error"]["code"], "INVALID_SMOKE_RESULT")
                    self.assertFalse(data["production_qualified"])
                    self.assertEqual(data["scope"], "installed-wheel-synthetic-reference-only")
                    self.assertEqual(data["wheel_sha256"], hashlib.sha256(wheel.read_bytes()).hexdigest())

    def test_failure_reports_omit_exception_and_subprocess_output(self):
        private = b"/private/path"
        pip_ok = subprocess.CompletedProcess([], 0, b"", b"")
        child_failed = subprocess.CompletedProcess([], 1, private, private)
        timeout = subprocess.TimeoutExpired([private], 1, output=private, stderr=private)
        with tempfile.TemporaryDirectory() as directory:
            wheel = self.make_wheel(directory, self.complete())
            for results, stage, error in (
                ([child_failed], "install", "PIP_FAILED"),
                ([pip_ok, child_failed], "smoke", "SMOKE_FAILED"),
                ([pip_ok, timeout], "smoke", "TIMEOUT"),
                ([OSError(private.decode())], "install", "IO_FAILED"),
            ):
                with self.subTest(stage=stage, error=error), \
                        patch.object(self.tool.subprocess, "run", side_effect=results):
                    code, data = self.run_validator(wheel, Path(directory) / "report.json")
                    self.assertEqual(code, 1)
                    self.assertEqual(data["error"]["stage"], stage)
                    self.assertEqual(data["error"]["code"], error)
                    self.assertNotIn(private.decode(), json.dumps(data))


if __name__ == "__main__":
    unittest.main()
