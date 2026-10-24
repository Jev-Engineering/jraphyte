#!/usr/bin/env python3
"""Isolated-process domain test runner; NOT the complete repository release runner.

Run from an actual checkout or an explicitly identified verified source subset.
No provider call, production graph access, or Git write is performed.
"""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULES = ("test_domain_contracts", "test_domain_publication", "test_domain_bundles",
           "test_domain_legacy", "test_domain_reads", "test_domain_retrieval", "test_domain_workload")


def source_hashes():
    files = {}
    for folder in ("trace_gc", "tools", "schemas", "tests"):
        for p in sorted((ROOT / folder).rglob("*")):
            if p.is_file() and p.suffix in {".py", ".json"} and "__pycache__" not in p.parts:
                files[str(p.relative_to(ROOT))] = hashlib.sha256(p.read_bytes()).hexdigest()
    return files


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--one")
    parser.add_argument("--workers", type=int, default=3, choices=range(1, 5))
    parser.add_argument("--timeout", type=int, default=40, choices=range(1, 301))
    parser.add_argument("--batch", type=int, default=0)
    parser.add_argument("--batches", type=int, default=1)
    args = parser.parse_args()
    sys.path[:0] = [str(ROOT), str(ROOT / "tests")]
    args.output.mkdir(parents=True, exist_ok=True)
    if args.one:
        suite = unittest.defaultTestLoader.loadTestsFromName(args.one)
        started = time.perf_counter()
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        receipt = {"test_id": args.one, "tests_run": result.testsRun, "failures": len(result.failures),
                   "errors": len(result.errors), "skipped": len(result.skipped), "duration_seconds": time.perf_counter()-started,
                   "status": "PASS" if result.wasSuccessful() and not result.skipped else "SKIP" if result.wasSuccessful() else "FAIL"}
        (args.output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        return 0 if result.wasSuccessful() else 1
    if not 1 <= args.batches <= 100 or not 0 <= args.batch < args.batches:
        parser.error("batch must be in 0..batches-1")
    ids = [case.id() for mod in MODULES for case in flatten(unittest.defaultTestLoader.loadTestsFromName(mod))]
    if len(set(ids)) != len(ids):
        parser.error("duplicate test identities in the runner")
    selected = ids[args.batch::args.batches]
    before = source_hashes()
    def run(pair):
        index, test_id = pair
        directory = args.output / f"case-{index:03d}"
        directory.mkdir(exist_ok=True)
        command = [sys.executable, str(Path(__file__).resolve()), "--one", test_id, "--output", str(directory.resolve())]
        try:
            cp = subprocess.run(command, cwd=ROOT, env=os.environ.copy(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=args.timeout, check=False)
            (directory/"test.log").write_bytes(cp.stdout)
            receipt_path = directory/"receipt.json"
            receipt = json.loads(receipt_path.read_text()) if receipt_path.exists() else {"status": "INCOMPLETE"}
            return {**receipt, "test_id": test_id, "returncode": cp.returncode, "log": str(directory/"test.log")}
        except subprocess.TimeoutExpired as exc:
            (directory/"test.log").write_bytes(exc.stdout or b"")
            return {"test_id": test_id, "status": "TIMEOUT", "timeout_seconds": args.timeout}
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        receipts = list(pool.map(run, enumerate(selected)))
    after = source_hashes()
    summary = {"version": "domain-targeted-validation-v1", "at": datetime.now(timezone.utc).isoformat(),
               "python": sys.version, "batch": args.batch, "batches": args.batches, "selected_test_ids": selected,
               "inventory_count": len(ids), "receipts": receipts, "source_hashes": before, "source_unchanged": before == after,
               "tests_run": sum(r.get("tests_run", 0) for r in receipts),
               "passed_test_cases": sum(r["status"] == "PASS" for r in receipts),
               "status": "PASS" if before == after and all(r["status"] == "PASS" for r in receipts) else "INCOMPLETE_OR_FAILED",
               "scope": "TARGETED_DOMAIN_TESTS_ONLY", "complete_repository_release_validation": "NOT_RUN",
               "production_qualified": False}
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({k: summary[k] for k in ("status", "tests_run", "passed_test_cases", "source_unchanged", "inventory_count")}))
    return 0 if summary["status"] == "PASS" else 1

if __name__ == "__main__":
    raise SystemExit(main())
