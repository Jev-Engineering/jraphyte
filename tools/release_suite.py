#!/usr/bin/env python3
"""Fail closed when release discovery sees only a subset of the intended suite.

This is an explicit test-module inventory requiring review, not a Git attestation or a
coverage claim. Adding/removing a release test module requires updating this
inventory in the same reviewed change. Never regenerate it from a partial tree.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Iterable

# Existing modules were checked against the test-tree inventory of main
# d5ca636a48e963619f4c89e2958d0bb1a3e72f80; initiative modules extend that inventory.
RELEASE_TEST_FILES = (
    'tests/test_abstract_validation.py',
    'tests/test_contracts.py',
    'tests/test_expanded_retrieval.py',
    'tests/test_first_page_retrieval_v3.py',
    'tests/test_first_page_v3_differential.py',
    'tests/test_first_page_v3_io.py',
    'tests/test_first_page_v3_local_models.py',
    'tests/test_graphrag_evaluation.py',
    'tests/test_graphrag_pipeline.py',
    'tests/test_graphrag_retrieval.py',
    'tests/test_graphrag_security.py',
    'tests/test_legacy_source_recovery.py',
    'tests/test_parallel_source_io_v4.py',
    'tests/test_parallel_source_retrieval_v4.py',
    'tests/test_parallel_source_v4.py',
    'tests/test_pdf_admission.py',
    'tests/test_pdf_evidence.py',
    'tests/test_pdf_source_v3.py',
    'tests/test_pdf_structure.py',
    'tests/test_release_suite.py',
    'tests/test_research_domain_authority_boundary.py',
    'tests/test_research_domain_conformance.py',
    'tests/test_research_domain_contracts.py',
    'tests/test_research_domain_identity_conflicts.py',
    'tests/test_research_domain_packaging.py',
    'tests/test_research_domain_reads.py',
    'tests/test_research_domain_rejected_workloads.py',
    'tests/test_research_domain_retrieval.py',
    'tests/test_research_domain_review_order.py',
    'tests/test_research_domain_transactions.py',
    'tests/test_research_domain_workloads.py',
    'tests/test_runtime_contracts.py',
    'tests/test_runtime_qualification.py',
    'tests/test_runtime_transactions.py',
    'tests/test_runtime_workflows.py',
)



# Explicit origin accounting prevents new tests from inflating a baseline claim.
INITIATIVE_TEST_MODULES = frozenset({
    "test_legacy_source_recovery", "test_release_suite",
    "test_research_domain_authority_boundary",
    "test_research_domain_conformance", "test_research_domain_contracts",
    "test_research_domain_identity_conflicts", "test_research_domain_packaging",
    "test_research_domain_reads", "test_research_domain_rejected_workloads",
    "test_research_domain_retrieval", "test_research_domain_review_order",
    "test_research_domain_transactions", "test_research_domain_workloads",
})
BASELINE_TEST_MODULES = frozenset(Path(p).stem for p in RELEASE_TEST_FILES) - INITIATIVE_TEST_MODULES


def test_origin_counts(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Count recorded executions, not distinct validation runs or coverage."""
    counts = {"current_main_baseline": 0, "initiative": 0, "other": 0,
              "graphrag_subset_of_baseline": 0}
    for record in records:
        module = record["test"].split(".", 1)[0]
        group = ("current_main_baseline" if module in BASELINE_TEST_MODULES
                 else "initiative" if module in INITIATIVE_TEST_MODULES else "other")
        counts[group] += 1
        if group == "current_main_baseline" and module.startswith("test_graphrag_"):
            counts["graphrag_subset_of_baseline"] += 1
    return counts


def check_suite_inventory(root: Path, *, expected: Iterable[str] = RELEASE_TEST_FILES) -> dict[str, Any]:
    root = Path(root)
    required = set(expected)
    for relative in required:
        path = Path(relative)
        if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] != "tests":
            raise ValueError("invalid release inventory path")
    tests = root / "tests"
    discovered = {p.relative_to(root).as_posix() for p in tests.rglob("test*.py")}
    invalid = []
    for relative in sorted(required | discovered):
        path = root / relative
        if (path.exists() or path.is_symlink()) and (not path.is_file() or any(p.is_symlink() for p in (path, *path.parents)
                                                       if p != root and root in p.parents)):
            invalid.append(relative)
    missing = sorted(required - discovered)
    unexpected = sorted(discovered - required)
    return {
        "status": "PASS" if not (missing or unexpected or invalid) else "FAIL",
        "required_modules": len(required),
        "discovered_modules": len(discovered),
        "missing": missing,
        "unexpected": unexpected,
        "nonregular_or_symlinked": invalid,
        "scope": "Source test-module inventory only; does not prove current-main provenance, coverage, or production qualification.",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args(argv)
    report = check_suite_inventory(args.root)
    print(json.dumps(report, indent=2))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
