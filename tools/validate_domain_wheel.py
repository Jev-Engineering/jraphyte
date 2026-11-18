"""Validate research-domain contracts of an installed wheel, never checkout imports.

The wheel is installed with --no-index --no-deps into a new target directory and
exercised by an isolated interpreter started outside the source tree. It checks
that every domain contract module and schema resource comes from the installed
copy, then runs a synthetic contract lifecycle: multi-label, unclassified and
superseding assignments, a complete bundle validation, and rejection of an
approved assignment that binds the packaged PROPOSED taxonomy. The installed
SQLite lifecycle also validates authenticated domain-scoped lexical retrieval
using synthetic evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

DOMAIN_SCHEMAS = (
    "research-domain-taxonomy",
    "classification-assignment",
    "classification-read-identity",
    "research-domain-scope",
    "retrieval-query",
)
TAXONOMY = "trace_gc/data/research_domains/reference_taxonomy_v1.json"

SMOKE = r'''
import contextlib, copy, io, json, pathlib, sys
from importlib.resources import files
root = pathlib.Path(sys.argv[1]).resolve()
sys.path.insert(0, str(root))
import trace_gc.catalog, trace_gc.domains, trace_gc.ledger, trace_gc.validation, trace_gc.schema, trace_gc.cli
from jsonschema import Draft202012Validator
modules = (trace_gc.catalog, trace_gc.domains, trace_gc.ledger, trace_gc.validation, trace_gc.schema, trace_gc.cli)
def assert_installed(path):
    assert pathlib.Path(path).resolve().is_relative_to(root), path

for module in modules:
    assert_installed(module.__file__)
data = files("trace_gc").joinpath("data")
assert_installed(data.joinpath("research_domains", "reference_taxonomy_v1.json"))
schemas = data.joinpath("schemas")
for name in json.loads(sys.argv[2]):
    path = schemas / (name + ".schema.json")
    assert_installed(path)
    assert path.is_file(), name
    Draft202012Validator.check_schema(json.loads(path.read_text(encoding="utf-8")))
schema_count = len(list(schemas.glob("*.schema.json")))
from trace_gc.catalog import Catalog
from trace_gc.canonical import dumps, loads
from trace_gc.demo import relation
from trace_gc.domain_conformance import run_domain_conformance
from trace_gc.domains import create_assignment, reference_taxonomy, validate_catalog
from trace_gc.errors import ContractError
from trace_gc.ledger import make_bundle
from trace_gc.policy import create_policy
taxonomy = reference_taxonomy()
trace_gc.schema.validate("record", taxonomy)
assert taxonomy["body"]["review"]["status"] == "PROPOSED"
stamp = "2026-09-27T00:00:00Z"
review = {"status": "APPROVED", "reviewer_id": "wheel-fixture-reviewer", "reviewed_at": stamp,
          "rationale": "Synthetic installed-wheel fixture; not taxonomy-owner review."}
c = Catalog()
proposal = c.add(taxonomy)
body = copy.deepcopy(taxonomy["body"]); body["review"] = copy.deepcopy(review)
taxonomy_id = c.put("research-domain-taxonomy", body)
source = c.source("wheel-paper", "v1", "Synthetic paper about computation and biology.", scope="test")
other = c.source("wheel-unclassified", "v1", "Synthetic unclassified paper.", scope="test")
common = dict(review=copy.deepcopy(review), classifier_id="wheel-fixture-reviewer", classifier_version="wheel-v1")
first = create_assignment(c, source_snapshot_id=source, taxonomy_id=taxonomy_id,
                          domain_ids=["research:computer-science", "research:biology"], **common)
create_assignment(c, source_snapshot_id=source, taxonomy_id=taxonomy_id, domain_ids=["research:mathematics"],
                  supersedes=first, **common)
create_assignment(c, source_snapshot_id=other, taxonomy_id=taxonomy_id, domain_ids=[], **common)
try:
    create_assignment(c, source_snapshot_id=source, taxonomy_id=proposal, domain_ids=["research:biology"], **common)
    raise AssertionError("approved assignment accepted a proposed taxonomy")
except ContractError as exc:
    assert exc.code == "DOMAIN_REVIEW", exc.code
validate_catalog(c)
create_policy(c, version="p1", scope="test", population="synthetic-only")
schema = c.put("schema", {"version": "s1", "relations": {"related": relation("Entity", "Entity")}})
statuses = {r["id"]: {"active": True, "permission": "READ", "epoch": 0, "updated_at": stamp, "tombstone": False}
            for r in c.all("source")}
bundle = make_bundle(c, run_id="wheel-domain-contract", execution_mode="SYNTHETIC", security_scope="test",
                     graph_version=0, schema_hash=c.hash(schema), source_status=statuses,
                     policy_version="p1", created_at=stamp)
outcome = trace_gc.validation.validate_bundle(loads(dumps(bundle)))
assert outcome["status"] == "PASS" and not outcome["authorization_granted"], outcome
assert {"DOMAIN_TAXONOMY", "CLASSIFICATION"} <= {e["stage"] for e in bundle["ledger"]}
domain = run_domain_conformance()
assert domain["status"] == "PASS" and domain["backend"] == "sqlite-reference-v1", domain
assert domain["checks_run"] == len(domain["checks"]), domain
assert "authenticated_scoped_lexical_retrieval" in domain["checks"], domain
result = {"status": "PASS", "installed_imports": True, "checkout_imports": False, "schema_count": schema_count,
          "domain_contract_lifecycle": "PASS", "reference_taxonomy_review": "PROPOSED",
          "domain_conformance_checks": domain["checks_run"]}
out = io.StringIO()
with contextlib.redirect_stdout(out):
    try:
        trace_gc.cli.main(["--version"])
    except SystemExit as exc:
        assert exc.code in (None, 0), exc.code
result["cli_version"] = out.getvalue().strip()
assert result["cli_version"]
for name, module in tuple(sys.modules.items()):
    if name == "trace_gc" or name.startswith("trace_gc."):
        assert_installed(module.__file__)
print(json.dumps(result))
'''


class WheelValidationError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def audit_wheel(wheel: Path) -> str:
    if wheel.suffix != ".whl":
        raise WheelValidationError("INVALID_WHEEL_TYPE", "expected an actual .whl file")
    with zipfile.ZipFile(wheel) as archive:
        if archive.testzip() is not None:
            raise WheelValidationError("WHEEL_CRC_FAILURE", "wheel CRC failure")
        names = archive.namelist()
    for name in names:
        parts = PurePosixPath(name).parts
        if name.startswith("/") or ".." in parts or "\\" in name:
            raise WheelValidationError("UNSAFE_WHEEL_MEMBER", "unsafe wheel member path")
    missing = [name for name in DOMAIN_SCHEMAS if f"trace_gc/data/schemas/{name}.schema.json" not in names]
    if missing or TAXONOMY not in names:
        raise WheelValidationError("MISSING_DOMAIN_RESOURCES", "wheel lacks domain resources")
    with wheel.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def _unique_keys(pairs: list[tuple[str, object]]) -> dict:
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("duplicate JSON keys")
    return result


def _smoke_result(stdout: str) -> dict:
    invalid = WheelValidationError("INVALID_SMOKE_RESULT", "invalid installed smoke result")
    try:
        result = json.loads(stdout, object_pairs_hook=_unique_keys)
    except (ValueError, RecursionError):
        raise invalid from None
    required = {
        "status": "PASS",
        "installed_imports": True,
        "checkout_imports": False,
        "domain_contract_lifecycle": "PASS",
        "reference_taxonomy_review": "PROPOSED",
    }
    if not isinstance(result, dict) or set(result) != {*required, "schema_count", "cli_version", "domain_conformance_checks"}:
        raise invalid
    for key, expected in required.items():
        if type(result[key]) is not type(expected) or result[key] != expected:
            raise invalid
    if type(result["schema_count"]) is not int or result["schema_count"] < len(DOMAIN_SCHEMAS):
        raise invalid
    if type(result["domain_conformance_checks"]) is not int or result["domain_conformance_checks"] <= 0:
        raise invalid
    version = result["cli_version"]
    if not isinstance(version, str) or not re.fullmatch(r"TRACE-GC [0-9][0-9A-Za-z.+!-]{0,63}", version):
        raise invalid
    return result


def _check_report_path(wheel: Path, report: Path) -> None:
    if wheel.resolve() == report.resolve():
        raise WheelValidationError("REPORT_PATH_ALIAS", "report path identifies the input wheel")
    if wheel.exists() and report.exists() and wheel.samefile(report):
        raise WheelValidationError("REPORT_PATH_ALIAS", "report path identifies the input wheel")


def _write_report(wheel: Path, path: Path, report: dict) -> None:
    data = json.dumps(report, indent=2) + "\n"
    with tempfile.TemporaryDirectory(prefix=".domain-wheel-report-", dir=path.parent) as directory:
        staged = Path(directory) / "report.json"
        staged.write_text(data, encoding="utf-8", newline="\n")
        _check_report_path(wheel, path)
        staged.replace(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)
    report: dict = {"status": "NOT_RUN", "production_qualified": False, "scope": "installed-wheel-synthetic-reference-only"}
    stage = "report"
    try:
        _check_report_path(args.wheel, args.report)
        stage = "staging"
        with tempfile.TemporaryDirectory(prefix="trace-gc-domain-wheel-") as temporary:
            root = Path(temporary)
            staged = root / "wheel"
            staged.mkdir()
            wheel = staged / args.wheel.name
            shutil.copyfile(args.wheel, wheel)

            stage = "audit"
            report["wheel_sha256"] = audit_wheel(wheel)
            report["wheel_bytes"] = wheel.stat().st_size

            stage = "install"
            target, outside = root / "installed", root / "outside"
            outside.mkdir()
            install = subprocess.run([sys.executable, "-I", "-m", "pip", "install", "--no-index", "--no-deps",
                                      "--target", str(target), str(wheel)], cwd=outside, capture_output=True,
                                     timeout=300)
            report["pip_returncode"] = install.returncode
            if install.returncode:
                raise WheelValidationError("PIP_FAILED", "offline wheel installation failed")

            stage = "smoke"
            smoke = subprocess.run([sys.executable, "-I", "-c", SMOKE, str(target), json.dumps(list(DOMAIN_SCHEMAS))],
                                   cwd=outside, capture_output=True, timeout=900)
            report["smoke_returncode"] = smoke.returncode
            if smoke.returncode:
                raise WheelValidationError("SMOKE_FAILED", "installed contract smoke failed")
            try:
                result = _smoke_result(smoke.stdout.decode("utf-8"))
            except UnicodeDecodeError:
                raise WheelValidationError("INVALID_SMOKE_RESULT", "invalid installed smoke result") from None
        report.update(result)
    except WheelValidationError as exc:
        report.update(status="FAIL", error={"stage": stage, "code": exc.code, "message": str(exc)})
    except subprocess.TimeoutExpired:
        report.update(status="FAIL", error={"stage": stage, "code": "TIMEOUT", "message": "validation subprocess timed out"})
    except zipfile.BadZipFile:
        report.update(status="FAIL", error={"stage": stage, "code": "INVALID_WHEEL_ARCHIVE", "message": "invalid wheel archive"})
    except OSError:
        report.update(status="FAIL", error={"stage": stage, "code": "IO_FAILED", "message": "validation I/O failed"})
    except Exception:
        report.update(status="FAIL", error={"stage": stage, "code": "VALIDATION_FAILED", "message": "wheel validation failed"})
    if report.get("error", {}).get("code") != "REPORT_PATH_ALIAS":
        try:
            _write_report(args.wheel, args.report, report)
        except WheelValidationError as exc:
            report.update(status="FAIL", error={"stage": "report", "code": exc.code, "message": str(exc)})
        except (OSError, RuntimeError):
            report.update(status="FAIL", error={"stage": "report", "code": "REPORT_WRITE_FAILED",
                                               "message": "could not write report"})
    print(json.dumps(report, indent=2))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
