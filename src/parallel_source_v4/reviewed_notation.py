"""Immutable private source-review packets and reviewed notation derivatives."""
from __future__ import annotations

import argparse
from copy import deepcopy
import json
from pathlib import Path

from trace_gc.canonical import bytes_digest, digest as semantic_digest
from trace_gc.errors import ContractError
from trace_gc.reviewed_notation import derive_reviewed, prepare_evidence
from .common import child, data_root, digest, method_hashes, within, write_once
from .image_ocr import write_bytes_once
from .runtime import DEFAULT_RUNTIME_LOCK, runtime_receipt


def run(root: Path, inputs: dict, output: str, *, crop: list[int] | None = None,
        reviewer: str | None = None, runtime_lock: Path = DEFAULT_RUNTIME_LOCK):
    """Every input descriptor must be separately pinned before publication.

    Without a review, produce a packet only. With a review, verify that packet
    again, record its actual attributed review, and publish a non-admitting result.
    """
    inputs = deepcopy(inputs)
    if set(inputs) not in ({"source", "native", "sidecar"}, {"source", "native", "sidecar", "review"}):
        raise ValueError("notation_input_set")
    if any(type(v) is not dict or set(v) != {"relative", "sha256"} for v in inputs.values()):
        raise ValueError("notation_input_descriptor")
    paths = {key: child(root, row["relative"]) for key, row in inputs.items()}
    payloads = {key: path.read_bytes() for key, path in paths.items()}
    if any(bytes_digest(payloads[key]) != inputs[key]["sha256"] for key in paths):
        raise ValueError("notation_input_hash_mismatch")
    code, runtime = method_hashes(), runtime_receipt(runtime_lock)
    if "review" in inputs:
        if crop is not None:
            raise ValueError("notation_review_owns_crop")
        result = derive_reviewed(payloads["source"], payloads["native"], payloads["sidecar"], payloads["review"],
                                 expected_review_sha256=inputs["review"]["sha256"], expected_reviewer=reviewer)
        evidence, page_png, crop_png = prepare_evidence(payloads["source"], payloads["native"], payloads["sidecar"],
                                                       result["review"]["crop"])
        if semantic_digest(evidence) != result["evidence_sha256"]:
            raise ValueError("notation_replay_changed")
    else:
        if crop is None or reviewer is not None:
            raise ValueError("notation_packet_requires_crop_only")
        evidence, page_png, crop_png = prepare_evidence(payloads["source"], payloads["native"], payloads["sidecar"], crop)
        result = {"status": "WAIT_SOURCE_IMAGE_REVIEW", "evidence": evidence, "evidence_sha256": semantic_digest(evidence),
                  "graph_admission_enabled": False, "proposal": False}

    def recheck():
        if any(digest(path) != inputs[key]["sha256"] for key, path in paths.items()):
            raise ValueError("notation_input_changed")
        if method_hashes() != code or runtime_receipt(runtime_lock) != runtime:
            raise ValueError("notation_code_or_runtime_changed")

    recheck()
    folder = child(root, output)
    files = {name: within(root, folder / name) for name in ("page.png", "crop.png", "result.json", "receipt.json")}
    write_bytes_once(files["page.png"], page_png)
    write_bytes_once(files["crop.png"], crop_png)
    result_sha = write_once(files["result.json"], result)
    recheck()
    expected_outputs = {"page.png": bytes_digest(page_png), "crop.png": bytes_digest(crop_png), "result.json": result_sha}
    if any(digest(files[key]) != sha for key, sha in expected_outputs.items()):
        raise ValueError("notation_output_changed")
    receipt = {"version": "reviewed-notation-run-v1", "status": result["status"], "inputs": inputs,
               "outputs": expected_outputs, "code_sha256": code, "runtime": runtime,
               "paid_calls": 0, "production_graph_writes": 0, "graph_admission_enabled": False,
               "proposal": False, "promotion_effect": "none"}
    receipt_sha = write_once(files["receipt.json"], receipt)
    recheck()
    if digest(files["receipt.json"]) != receipt_sha or any(digest(files[k]) != v for k, v in expected_outputs.items()):
        raise ValueError("notation_output_changed")
    return {"status": result["status"], "receipt_sha256": receipt_sha, "result_sha256": result_sha,
            "proposal": False, "graph_admission_enabled": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", required=True)
    for name in ("source", "native", "sidecar", "review"):
        parser.add_argument("--" + name, required=name != "review")
        parser.add_argument("--" + name + "-sha256", required=name != "review")
    parser.add_argument("--crop", nargs=4, type=int)
    parser.add_argument("--reviewer")
    parser.add_argument("--output", required=True)
    parser.add_argument("--runtime-lock", type=Path, default=DEFAULT_RUNTIME_LOCK)
    args = parser.parse_args()
    try:
        if bool(args.review) != bool(args.review_sha256):
            raise ValueError("notation_review_pin_required")
        inputs = {name: {"relative": getattr(args, name), "sha256": getattr(args, name + "_sha256")}
                  for name in ("source", "native", "sidecar", "review") if getattr(args, name)}
        result = run(data_root(args.data_root), inputs, args.output, crop=args.crop,
                     reviewer=args.reviewer, runtime_lock=args.runtime_lock)
        print(json.dumps(result, sort_keys=True))
        return 0 if result["status"] in ("WAIT_SOURCE_IMAGE_REVIEW", "REVIEWED_FRAGMENT_DERIVATIVE") else 2
    except (OSError, ValueError, TypeError, KeyError, ContractError) as exc:
        print(json.dumps({"status": "BLOCKED", "reason": "notation_review_failed", "error_class": type(exc).__name__}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
