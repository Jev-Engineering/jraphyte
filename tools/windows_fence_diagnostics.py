#!/usr/bin/env python3
"""Sanitized Windows trustee-serialization diagnostics for the hosted fence job.

Prints one JSON object describing how this runner's own SID is written in a real
DACL string and whether the admission barrier recognizes it. Machine and domain
sub-authorities are redacted; no account name, path or exception text is emitted.
The owned probe deny is always removed again and the removal is verified and
reported; the exit status is nonzero only when that cleanup is not verified.

It also runs the real guarded fence once on a disposable owned fixture and prints
the sanitized before/after DACL of the fence parent and of a state file around
every icacls call, so a hosted-only DACL representation difference is visible.
All fixture denies are removed and verified afterwards.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def redact(text: str) -> str:
    return re.sub(r"S-1-5-21-\d+-\d+-\d+-(\d+)", r"S-1-5-21-<machine>-\1", text)


def describe_error(exc: BaseException) -> dict:
    """Exception type and a bounded category only; never the message (it may hold paths or names)."""
    kind = type(exc).__name__
    code = getattr(exc, "code", None)
    result = {"type": kind if re.fullmatch(r"\w{1,64}", kind) else "Exception",
              "category": code if isinstance(code, str) and re.fullmatch(r"[A-Z][A-Z0-9_]{0,31}", code)
              else "unspecified"}
    exit_code = getattr(exc, "returncode", None)
    if type(exit_code) is int:
        result["exit_code"] = exit_code
    return result


_SAFE_DETAIL = re.compile(r"[A-Za-z][A-Za-z0-9 ,.'-]{0,79}")


def _outcome(exc: BaseException) -> dict:
    """Error description plus our own constant contract detail (never a path-bearing message)."""
    result = describe_error(exc)
    detail = getattr(exc, "detail", None)
    if (isinstance(detail, str) and not getattr(exc, "path", "")
            and _SAFE_DETAIL.fullmatch(detail)):
        result["detail"] = detail
    return result


def _remove_probe_deny(guarded, probe: Path, sid: str) -> dict:
    """Remove the owned probe deny and verify, independently of the checks under diagnosis."""
    outcome = {"icacls_remove_exit": None, "deny_absent_verified": False}
    try:
        removed = subprocess.run(["icacls.exe", str(probe), "/remove:d", "*" + sid],
                                 capture_output=True, text=True, timeout=30)
        outcome["icacls_remove_exit"] = removed.returncode
    except Exception as exc:
        outcome["error"] = describe_error(exc)
        return outcome
    try:
        outcome["deny_absent_verified"] = not guarded._owner_deny_present(
            guarded.directory_dacl_sddl(probe), sid)
    except Exception as exc:
        outcome["verify_error"] = describe_error(exc)
    return outcome


def trace_fence(guarded, *, temp_factory=tempfile.TemporaryDirectory) -> tuple[dict, bool]:
    """Run the real guarded fence on an owned fixture, recording sanitized DACL shapes."""
    trace = {"steps": []}
    cleanup = {"paths_checked": 0, "denies_remaining": None}
    remaining = None
    try:
        sid = guarded._current_sid()
        with temp_factory(prefix="jraphyte-fence-diag-trace-") as temp:
            base = Path(temp)
            root, old = base / "old-app", base / "old-app" / "state"
            archive = base / "archive" / "state"
            receipts = base / "receipts"
            old.mkdir(parents=True)
            archive.parent.mkdir()
            receipts.mkdir()
            content = {}
            for name in sorted(guarded.NAMES):
                body = b"0" if name == "controller.lock" else name.encode()
                (old / name).write_bytes(body)
                content[name] = hashlib.sha256(body).hexdigest()
            for name in ("source-stage.lock", "phase-stage.lock"):
                (root / name).write_bytes(b"0")
            read = guarded.directory_dacl_sddl
            try:
                trace["parent_before"] = redact(read(root))
                trace["old:controller.lock_before"] = redact(read(old / "controller.lock"))
                pins = (hashlib.sha256(read(root).encode()).hexdigest(),
                        {name: hashlib.sha256(read(old / name).encode()).hexdigest()
                         for name in guarded.NAMES})
                actual = guarded._icacls

                def recording(path, *args):
                    actual(path, *args)
                    target = Path(path)
                    # Only the constant historical file names and the location are reported.
                    label = ("parent" if target == root else
                             ("archived:" if target.parent == archive else "old:") + target.name)
                    step = {"target": label,
                            "operation": "deny" if "/deny" in args else "remove_deny"}
                    step["dacl_after"] = redact(read(path))
                    trace["steps"].append(step)
                guarded._icacls = recording
                try:
                    result = guarded.fence_closed_old_phase_guarded(
                        old_root=old, archived_root=archive, expected_file_sha256=content,
                        source_stage_lock=root / "source-stage.lock",
                        phase_stage_lock=root / "phase-stage.lock", deny_sid=sid,
                        expected_parent_dacl_sha256=pins[0], expected_file_dacl_sha256=pins[1],
                        barrier_receipt_path=receipts / "barrier.json",
                        fence_receipt_path=receipts / "fence.json")
                    trace["outcome"] = {"status": result["status"]}
                finally:
                    guarded._icacls = actual
            except Exception as exc:
                trace["outcome"] = {"error": _outcome(exc)}
            finally:
                # Always lift this fixture's own denies, then verify none remain.
                targets = [root] + [folder / name for folder in (old, archive)
                                    for name in sorted(guarded.NAMES)]
                for target in targets:
                    if target.exists():
                        subprocess.run(["icacls.exe", str(target), "/remove:d", "*" + sid],
                                       capture_output=True, text=True, timeout=30)
                remaining = 0
                for target in targets:
                    if target.exists():
                        cleanup["paths_checked"] += 1
                        try:
                            if guarded._owner_deny_present(read(target), sid):
                                remaining += 1
                        except Exception:
                            remaining += 1
                cleanup["denies_remaining"] = remaining
    except Exception as exc:  # setup or temp-directory removal failed
        trace["error"] = describe_error(exc)
    trace["cleanup"] = cleanup
    return trace, remaining == 0


def collect(guarded=None, *, temp_factory=tempfile.TemporaryDirectory) -> tuple[dict, bool]:
    """Return (sanitized report, whether the owned probe deny is verified removed)."""
    report = {"python": platform.python_version(), "os": platform.platform(),
              "os_name": os.name}
    cleanup_ok = True
    try:
        if guarded is None:
            from src import paper_pilot_phase_cutover_guarded_v2 as guarded
        sid = guarded._current_sid()
        report["runner_sid"] = redact(sid)
        report["runner_canonical_trustee"] = redact(guarded._canonical_trustee(sid))
        with temp_factory(prefix="jraphyte-fence-diag-") as temp:
            probe = Path(temp) / "probe.bin"
            probe.write_bytes(b"0")
            attempted = False
            try:
                attempted = True
                subprocess.run(["icacls.exe", str(probe), "/deny", "*" + sid + ":(WD,AD)"],
                               capture_output=True, text=True, timeout=30, check=True)
                raw = guarded.directory_dacl_sddl(probe)
                report["probe_dacl_after_runner_deny"] = redact(raw)
                report["literal_numeric_ace_present"] = guarded.DENY_FILE_ACE.format(sid=sid) in raw
                report["barrier_recognizes_deny"] = guarded._file_deny(probe, sid)
                report["owner_deny_detected"] = guarded._owner_deny_present(raw, sid)
            finally:
                # Runs even if the deny, the DACL query or the recognition failed.
                if attempted:
                    cleanup = _remove_probe_deny(guarded, probe, sid)
                    report["probe_cleanup"] = cleanup
                    cleanup_ok = (cleanup["icacls_remove_exit"] == 0
                                  and cleanup["deny_absent_verified"] is True)
    except Exception as exc:  # diagnostics must never mask the test result
        report["diagnostic_error"] = describe_error(exc)
    if guarded is not None:
        report["fence_trace"], trace_ok = trace_fence(guarded, temp_factory=temp_factory)
        cleanup_ok = cleanup_ok and trace_ok
    return report, cleanup_ok


def main() -> int:
    report, cleanup_ok = collect()
    print(json.dumps(report, indent=2))
    return 0 if cleanup_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
