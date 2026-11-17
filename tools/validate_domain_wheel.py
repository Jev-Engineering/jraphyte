"""Validate research-domain contracts of an installed wheel, never checkout imports.

The wheel is installed with --no-index --no-deps into a new target directory and
exercised by an isolated interpreter started outside the source tree. It checks
that every domain contract module and schema resource comes from the installed
copy, then runs a synthetic contract lifecycle: multi-label, unclassified and
superseding assignments, a complete bundle validation, and rejection of an
approved assignment that binds the packaged PROPOSED taxonomy. Synthetic
fixtures only: this is not deployment qualification or publication evidence.
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

DOMAIN_SCHEMAS = ("research-domain-taxonomy", "classification-assignment")
TAXONOMY = "trace_gc/data/research_domains/reference_taxonomy_v1.json"

SMOKE = r'''
import contextlib, copy, io, json, pathlib, sys
root = pathlib.Path(sys.argv[1]).resolve()
sys.path.insert(0, str(root))
import trace_gc.catalog, trace_gc.domains, trace_gc.ledger, trace_gc.validation, trace_gc.schema, trace_gc.cli
from jsonschema import Draft202012Validator
modules = (trace_gc.catalog, trace_gc.domains, trace_gc.ledger, trace_gc.validation, trace_gc.schema, trace_gc.cli)
for module in modules:
    assert pathlib.Path(module.__file__).resolve().is_relative_to(root), module.__file__
schemas = pathlib.Path(trace_gc.domains.__file__).parent / "data" / "schemas"
for name in json.loads(sys.argv[2]):
    path = schemas / (name + ".schema.json")
    assert path.is_file(), name
    Draft202012Validator.check_schema(json.loads(path.read_text(encoding="utf-8")))
schema_count = len(list(schemas.glob("*.schema.json")))
from trace_gc.catalog import Catalog
from trace_gc.canonical import dumps, loads
from trace_gc.demo import relation
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
result = {"status": "PASS", "installed_imports": True, "checkout_imports": False, "schema_count": schema_count,
          "domain_contract_lifecycle": "PASS", "reference_taxonomy_review": "PROPOSED"}
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
    if missing or TAXONOMY not in names:
        raise ValueError("wheel lacks domain resources: " + ",".join(missing))
    return hashlib.sha256(wheel.read_bytes()).hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
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
            smoke = subprocess.run([sys.executable, "-I", "-c", SMOKE, str(target), json.dumps(list(DOMAIN_SCHEMAS))],
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
