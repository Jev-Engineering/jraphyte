#!/usr/bin/env python3
"""Validate research-domain behavior of an installed wheel, never checkout imports.

The wheel is installed with --no-index --no-deps into a new target directory and
exercised by an isolated interpreter started outside the source tree. It checks
that every domain module and schema resource comes from the installed copy, then
runs the executable classification lifecycle conformance (signed migration,
multi-label publication, indexed scoped retrieval, historical revocation,
reclassification cache invalidation and authenticated reopen). An optional
reviewed legacy core runs the exact pinned bridge gate; without it that gate is
reported NOT_RUN. Synthetic fixtures only: this is not deployment qualification.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

DOMAIN_SCHEMAS = ("research-domain-taxonomy", "classification-assignment", "classification-projection",
                  "classification-read-identity", "research-domain-scope")

SMOKE = r'''
import contextlib, io, json, pathlib, sys
root = pathlib.Path(sys.argv[1]).resolve()
legacy = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] else None
sys.path.insert(0, str(root))
import trace_gc.catalog, trace_gc.domains, trace_gc.domain_publication, trace_gc.domain_conformance
import trace_gc.backend, trace_gc.cli, trace_gc.replay, trace_gc.schema
import trace_gc.retrieval.domains, trace_gc.retrieval.domain_index, trace_gc.retrieval.service
import trace_gc.retrieval.planner, trace_gc.retrieval.reranker, trace_gc.retrieval.store
from jsonschema import Draft202012Validator
modules = (trace_gc.catalog, trace_gc.domains, trace_gc.domain_publication, trace_gc.domain_conformance,
           trace_gc.backend, trace_gc.cli, trace_gc.replay, trace_gc.schema, trace_gc.retrieval.domains,
           trace_gc.retrieval.domain_index, trace_gc.retrieval.service, trace_gc.retrieval.planner,
           trace_gc.retrieval.reranker, trace_gc.retrieval.store)
for module in modules:
    assert pathlib.Path(module.__file__).resolve().is_relative_to(root), module.__file__
schemas = pathlib.Path(trace_gc.domains.__file__).parent / "data" / "schemas"
for name in json.loads(sys.argv[3]):
    path = schemas / (name + ".schema.json")
    assert path.is_file(), name
    Draft202012Validator.check_schema(json.loads(path.read_text(encoding="utf-8")))
schema_count = len(list(schemas.glob("*.schema.json")))
taxonomy = trace_gc.domains.reference_taxonomy()
trace_gc.schema.validate("record", taxonomy)
assert taxonomy["body"]["review"]["status"] == "PROPOSED"
conformance = trace_gc.domain_conformance.run_domain_conformance()
assert conformance["status"] == "PASS" and conformance["production_qualification"] == "NOT_ESTABLISHED"
result = {"status": "PASS", "installed_imports": True, "checkout_imports": False, "schema_count": schema_count,
          "domain_conformance_checks": conformance["checks_run"], "reference_taxonomy_review": "PROPOSED"}
if legacy:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = trace_gc.cli.main(["check-legacy", "--core", legacy])
    report = json.loads(out.getvalue())
    assert code == 0 and report["status"] == "PASS", report
    result["pinned_legacy"] = {"status": "PASS", "core_blob": report["core_blob"], "checks_run": report["checks_run"]}
else:
    result["pinned_legacy"] = {"status": "NOT_RUN", "reason": "reviewed core not supplied"}
out = io.StringIO()
with contextlib.redirect_stdout(out):
    try:
        trace_gc.cli.main(["--version"])
    except SystemExit as exc:
        assert exc.code in (None, 0), exc.code
result["cli_version"] = out.getvalue().strip()
assert result["cli_version"]
print(json.dumps(result))
'''


def audit_wheel(wheel: Path) -> str:
    if wheel.suffix != ".whl":
        raise ValueError("expected an actual .whl file")
    with zipfile.ZipFile(wheel) as archive:
        if archive.testzip() is not None:
            raise ValueError("wheel CRC failure")
        names = archive.namelist()
    for name in names:
        parts = PurePosixPath(name).parts
        if name.startswith("/") or ".." in parts or "\\" in name:
            raise ValueError("unsafe wheel member path")
    missing = [name for name in DOMAIN_SCHEMAS if f"trace_gc/data/schemas/{name}.schema.json" not in names]
    if missing or "trace_gc/data/research_domains/reference_taxonomy_v1.json" not in names:
        raise ValueError("wheel lacks domain resources: " + ",".join(missing))
    return hashlib.sha256(wheel.read_bytes()).hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--legacy-core", type=Path, help="exact reviewed legacy core.py; its blob is verified before import")
    args = parser.parse_args(argv)
    report: dict = {"status": "NOT_RUN", "production_qualified": False, "scope": "installed-wheel-synthetic-reference-only"}
    code = 1
    try:
        wheel = args.wheel.resolve(strict=True)
        report["wheel_sha256"] = audit_wheel(wheel)
        report["wheel_bytes"] = wheel.stat().st_size
        with tempfile.TemporaryDirectory(prefix="trace-gc-domain-wheel-") as temporary:
            target, outside = Path(temporary) / "installed", Path(temporary) / "outside"
            outside.mkdir()
            install = subprocess.run([sys.executable, "-I", "-m", "pip", "install", "--no-index", "--no-deps",
                                      "--target", str(target), str(wheel)], cwd=outside, text=True,
                                     capture_output=True, timeout=300)
            report["pip_returncode"] = install.returncode
            if install.returncode:
                raise RuntimeError("pip install failed: " + install.stderr[-400:])
            legacy = str(args.legacy_core.resolve(strict=True)) if args.legacy_core else ""
            smoke = subprocess.run([sys.executable, "-I", "-c", SMOKE, str(target), legacy, json.dumps(list(DOMAIN_SCHEMAS))],
                                   cwd=outside, text=True, capture_output=True, timeout=900)
            report["smoke_returncode"] = smoke.returncode
            if smoke.returncode:
                raise RuntimeError("installed smoke failed: " + (smoke.stderr or smoke.stdout)[-1200:])
            report.update(json.loads(smoke.stdout.strip().splitlines()[-1]))
            code = 0
    except Exception as exc:  # reported, never converted into a pass
        report.update(status="FAIL", error=f"{type(exc).__name__}: {exc}")
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(report, indent=2))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
