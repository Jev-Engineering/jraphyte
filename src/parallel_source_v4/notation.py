"""Capture immutable private notation sidecars; no extraction or promotion changes."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from trace_gc.canonical import bytes_digest, loads
from trace_gc.pdf_notation_parallel_v4 import capture_notation
from trace_gc.pdf_source_parallel_v4 import digest_value
from .common import child, data_root, digest, method_hashes, within, write_once
from .image_ocr import write_bytes_once
from .runtime import DEFAULT_RUNTIME_LOCK, runtime_receipt


def prepare(root: Path, source: str, native: str, output: str, *, source_sha256: str,
            native_sha256: str, runtime_lock: Path = DEFAULT_RUNTIME_LOCK):
    paths = {"source": child(root, source), "native": child(root, native)}
    payloads = {key: path.read_bytes() for key, path in paths.items()}
    expected = {"source": source_sha256, "native": native_sha256}
    if any(bytes_digest(payloads[key]) != expected[key] for key in paths):
        raise ValueError("notation_input_hash_mismatch")
    native_value = loads(payloads["native"])
    code = method_hashes()
    runtime = runtime_receipt(runtime_lock)
    sidecar, image = capture_notation(payloads["source"], native_value)
    sidecar.update({"input_files": {"source": {"relative": source, "sha256": source_sha256},
                                    "native": {"relative": native, "sha256": native_sha256}},
                    "code_sha256": code, "runtime": runtime,
                    "production_graph_writes": 0, "new_paid_api_calls": 0})
    sidecar["sidecar_sha256"] = digest_value(sidecar)

    def recheck():
        if any(digest(paths[key]) != expected[key] for key in paths):
            raise ValueError("notation_input_changed")
        if method_hashes() != code or runtime_receipt(runtime_lock) != runtime:
            raise ValueError("notation_code_or_runtime_changed")

    recheck()
    folder = child(root, output)
    image_path, sidecar_path = within(root, folder / "page.png"), within(root, folder / "notation.json")
    write_bytes_once(image_path, image)
    written_hash = write_once(sidecar_path, sidecar)
    recheck()
    if digest(image_path) != bytes_digest(image) or digest(sidecar_path) != written_hash:
        raise ValueError("notation_output_changed")
    return {"status": sidecar["status"], "claim": "diagnostic_only_no_notation_certification",
            "sidecar_sha256": sidecar["sidecar_sha256"], "sidecar_file_sha256": written_hash,
            "native_identity": sidecar.get("native_identity"), "rawdict_projection": sidecar.get("rawdict_projection"),
            "characters": len(sidecar["characters"]), "relations": len(sidecar["relations"]),
            "unresolved_characters": len(sidecar.get("unresolved_character_ids", [])), "accepted": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--source-sha256", required=True)
    parser.add_argument("--native", required=True)
    parser.add_argument("--native-sha256", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--runtime-lock", type=Path, default=DEFAULT_RUNTIME_LOCK)
    args = parser.parse_args()
    try:
        result = prepare(data_root(args.data_root), args.source, args.native, args.output,
                         source_sha256=args.source_sha256, native_sha256=args.native_sha256,
                         runtime_lock=args.runtime_lock)
        print(json.dumps(result, sort_keys=True))
        return 0 if result["status"] == "diagnostic_only" else 2
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print(json.dumps({"status": "BLOCKED", "reason": "notation_capture_failed", "error_class": type(exc).__name__}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
