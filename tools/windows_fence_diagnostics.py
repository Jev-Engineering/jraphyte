#!/usr/bin/env python3
"""Sanitized Windows trustee-serialization diagnostics for the hosted fence job.

Prints one JSON object describing how this runner's own SID is written in a real
DACL string and whether the admission barrier recognizes it. Machine and domain
sub-authorities are redacted; no account name, path or exception text is emitted.
The owned probe deny is always removed again and the removal is verified and
reported; the exit status is nonzero only when that cleanup is not verified.
"""
from __future__ import annotations

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
    return report, cleanup_ok


def main() -> int:
    report, cleanup_ok = collect()
    print(json.dumps(report, indent=2))
    return 0 if cleanup_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
