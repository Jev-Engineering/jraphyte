#!/usr/bin/env python3
"""Sanitized Windows trustee-serialization diagnostics for the hosted fence job.

Prints one JSON object describing how this runner's own SID is written in a real
DACL string and whether the admission barrier recognizes it. Machine and domain
sub-authorities are redacted; no account name, path or exception text is emitted.
The owned probe deny is always removed again and the removal is verified and
reported, as is the probe directory's own removal; the exit status is nonzero only when
a cleanup is not verified.

It also runs the real guarded fence once on a disposable owned fixture and prints
sanitized DACL descriptions (control flags P/AI, ACE counts, explicit vs. inherited
allows, and the production strict-comparison verdicts) for the fixture's temp parent,
base, fence parent, state directory and state files: as created, after the owned fixture
ACL is made explicit and protected (windows_fixture_acl), and before any pin,
immediately before and after every icacls call (including failed calls), around each
cleanup removal, at the end of the run and after cleanup. Recording is capped at
MAX_RECORDED_OPERATIONS. It only observes: it changes no production behavior and
asserts no cause. Every fixture target gets its own removal attempt; any survivor,
failed removal or failed temp-directory removal makes the run's status non-clean.
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

from tools import windows_fixture_acl  # noqa: E402


def redact(text: str) -> str:
    text = re.sub(r"S-1-5-21-\d+-\d+-\d+-(\d+)", r"S-1-5-21-<machine>-\1", text)
    return re.sub(r"S-1-12-1(?:-\d+){4}", "S-1-12-1-<directory>", text)


_ACE = re.compile(r"\([^)]*\)")
_CONTROL = re.compile(r"AI|AR|P")
_TWIN_FLAG_TOKEN = re.compile(r"..")


def _ace_fields(ace: str) -> list[str]:
    return ace[1:-1].split(";")


def _twin_key(ace: str) -> tuple:
    """Type, non-inherited flag tokens, rights and trustee of an allow ACE."""
    fields = _ace_fields(ace)
    if len(fields) != 6:
        return ()
    tokens = [t for t in _TWIN_FLAG_TOKEN.findall(fields[1]) if t != "ID"]
    return (fields[0], tuple(tokens), fields[2], fields[5])


def describe_dacl(sddl: str) -> dict:
    """Sanitized structural description of one DACL string (text only; no Windows calls)."""
    control = _CONTROL.findall(sddl.split("(", 1)[0].removeprefix("D:"))
    aces = _ACE.findall(sddl)
    allows = [ace for ace in aces if ace.startswith("(A;") and len(_ace_fields(ace)) == 6]
    inherited = [ace for ace in allows if "ID" in _TWIN_FLAG_TOKEN.findall(_ace_fields(ace)[1])]
    explicit = [ace for ace in allows if ace not in inherited]
    inherited_keys = {_twin_key(ace) for ace in inherited}
    return {"sddl": redact(sddl), "control": "".join(control),
            "protected": "P" in control, "auto_inherited": "AI" in control,
            "ace_count": len(aces),
            "deny": sum(1 for ace in aces if ace.startswith("(D;")),
            "explicit_allow": len(explicit), "inherited_allow": len(inherited),
            "explicit_copies_of_inherited": sum(1 for ace in explicit
                                                if _twin_key(ace) in inherited_keys)}


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


# Exact constant messages raised by the guarded fence, mapped to fixed diagnostic codes.
# Nothing outside this table is ever copied into the report.
_DETAIL_CODES = {
    "Windows DACL update failed": "ICACLS_UPDATE_FAILED",
    "historical five-file inventory differs": "INVENTORY_DIFFERS",
    "historical state bytes differ": "STATE_BYTES_DIFFER",
    "reviewed SID or five-file pins differ": "PINS_DIFFER",
    "reviewed ACL pins absent": "ACL_PINS_ABSENT",
    "ambiguous old/archive namespace": "AMBIGUOUS_NAMESPACE",
    "historical barrier scope differs": "BARRIER_SCOPE_DIFFERS",
    "archive lacks prior barrier": "ARCHIVE_LACKS_BARRIER",
    "existing owner deny cannot be safely merged": "OWNER_DENY_NOT_MERGEABLE",
    "original Windows DACL identity changed": "ORIGINAL_DACL_IDENTITY_CHANGED",
    "unreviewed preexisting file deny": "PREEXISTING_FILE_DENY",
    "old parent DACL changed beyond admission deny": "PARENT_CHANGED_BEYOND_DENY",
    "database changed after lock acquisition": "DATABASE_CHANGED",
    "unreviewed old file DACL drift": "FILE_DACL_DRIFT",
    "new old-state write open not denied": "WRITE_OPEN_NOT_DENIED",
    "old state recreation remains possible": "RECREATION_POSSIBLE",
    "old parent DACL broadened during fence": "PARENT_BROADENED_DURING_FENCE",
    "stage lock path replaced while held": "STAGE_LOCK_REPLACED",
    "fixed old path not closed": "OLD_PATH_NOT_CLOSED",
    "archived readback still denied": "ARCHIVED_STILL_DENIED",
    "old fixed path admission reopened": "ADMISSION_REOPENED",
    "old parent DACL changed after archive": "PARENT_CHANGED_AFTER_ARCHIVE",
    "archived effective file DACL changed": "ARCHIVED_FILE_DACL_CHANGED",
}


def _outcome(exc: BaseException) -> dict:
    """Error description plus a fixed code, only for a known constant message without a path."""
    result = describe_error(exc)
    detail = getattr(exc, "detail", None)
    if isinstance(detail, str) and not getattr(exc, "path", ""):
        code = _DETAIL_CODES.get(detail)
        if code is not None:
            result["detail_code"] = code
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


def _snapshot(guarded, read, paths: dict, sid: str | None = None, originals: dict | None = None) -> dict:
    """Describe each existing path's DACL; with originals, add the production strict verdicts."""
    result = {}
    for label, path in paths.items():
        try:
            present = path.exists()
        except Exception as exc:
            result[label] = {"error": describe_error(exc)}
            continue
        if not present:
            result[label] = {"absent": True}
            continue
        try:
            raw = read(path)
            entry = describe_dacl(raw)
        except Exception as exc:
            result[label] = {"error": describe_error(exc)}
            continue
        if originals is not None and label in originals:
            entry["strict"] = _verdicts(guarded, label, originals[label], raw, sid)
        result[label] = entry
    return result


def _verdicts(guarded, label: str, original: str, current: str, sid: str) -> dict:
    """The unchanged production comparators, applied to one observed DACL."""
    admission = (guarded._only_parent_admission_added if label == "parent"
                 else guarded._only_admission_dacl_added)
    verdict = {}
    for key, check in (("admission_only_added", lambda: admission(original, current, sid)),
                       ("same_as_original", lambda: guarded._same_effective_dacl(original, current))):
        try:
            verdict[key] = bool(check())
        except Exception as exc:
            verdict[key] = None
            verdict[key + "_error"] = describe_error(exc)
    return verdict


def _fixture_paths(guarded, base: Path, root: Path, old: Path, archive: Path) -> dict:
    state = old if old.exists() else archive
    paths = {"temp_parent": base.parent, "base": base, "parent": root, "state": state}
    for name in sorted(guarded.NAMES):
        paths["file:" + name] = state / name
    return paths


MAX_RECORDED_OPERATIONS = 64
_COMPACT = ("sddl", "protected", "auto_inherited", "ace_count", "deny",
            "explicit_copies_of_inherited", "strict", "absent", "error")


def _compact(snapshot: dict) -> dict:
    return {label: {key: entry[key] for key in _COMPACT if key in entry}
            for label, entry in snapshot.items()}


def _label(root: Path, archive: Path, target: Path) -> str:
    return ("parent" if target == root else
            ("archived:" if target.parent == archive else "old:") + target.name)


def _cleanup_targets(guarded, root: Path, old: Path, archive: Path) -> list:
    targets = [("parent", root)]
    for folder, prefix in ((old, "old:"), (archive, "archived:")):
        targets += [(prefix + name, folder / name) for name in sorted(guarded.NAMES)]
    return targets


def _exists(path: Path) -> bool:
    try:
        return path.exists()
    except Exception:
        return True   # unknown: still attempt and verify it


def _lift_and_verify(guarded, read, sid: str, targets: list, observe, record, cleanup: dict) -> None:
    """Attempt every owned target's own removal, then verify every surviving target."""
    failures = []
    for label, target in targets:
        if not _exists(target):
            continue
        step = {"target": label, "operation": "cleanup_remove_deny", "before": observe()}
        try:
            done = subprocess.run(["icacls.exe", str(target), "/remove:d", "*" + sid],
                                  capture_output=True, text=True, timeout=30)
            step["icacls_exit"] = done.returncode
            if done.returncode != 0:
                failures.append({"target": label, "exit_code": done.returncode})
        except Exception as exc:
            step["icacls"] = "failed"
            step["error"] = describe_error(exc)
            failures.append({"target": label, "error": step["error"]})
        step["after"] = observe(strict=True)
        record(cleanup["steps"], step)
    remaining = verification_errors = checked = 0
    for label, target in targets:
        if not _exists(target):
            continue
        checked += 1
        try:
            if guarded._owner_deny_present(read(target), sid):
                remaining += 1
        except Exception:
            verification_errors += 1
            remaining += 1   # an unverifiable target is not a clean one
    cleanup.update({"paths_checked": checked, "denies_remaining": remaining,
                    "verification_errors": verification_errors, "removal_failures": failures})


def trace_fence(guarded, *, temp_factory=tempfile.TemporaryDirectory) -> tuple[dict, bool]:
    """Run the real guarded fence on an owned fixture, observing sanitized DACL descriptions.

    The fixture is recorded as created, then given the verified explicit, protected
    ACL of windows_fixture_acl, then pinned. Returns (trace, clean). clean is False for
    a failed setup or fixture stabilization, a failed or unverified removal on any
    target, or a failed temp-directory removal.
    """
    trace = {"steps": [], "operations_dropped": 0}
    cleanup = {"paths_checked": 0, "denies_remaining": None, "removal_failures": [],
               "verification_errors": 0, "steps": [], "directory_removal": "not_reached"}
    recorded = {"count": 0}

    def record(bucket: list, step: dict) -> None:
        if recorded["count"] >= MAX_RECORDED_OPERATIONS:
            trace["operations_dropped"] += 1
            return
        recorded["count"] += 1
        bucket.append(step)

    body_done = False
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
            originals = None

            def observe(strict: bool = False) -> dict:
                try:
                    return _compact(_snapshot(guarded, read, _fixture_paths(guarded, base, root, old, archive),
                                              sid if strict else None, originals if strict else None))
                except Exception as exc:
                    return {"error": describe_error(exc)}
            try:
                # The fixture exactly as created: nothing yet applied, nothing yet pinned.
                trace["setup_as_created"] = _snapshot(guarded, read, _fixture_paths(guarded, base, root, old, archive))
                targets = [("parent", root), ("state", old)] + [("file:" + name, old / name)
                                                                for name in sorted(guarded.NAMES)]
                try:
                    windows_fixture_acl.stabilize_owned_fixture(base, targets, read=read, run=subprocess.run)
                    trace["fixture_acl"] = {"status": "stabilized", "targets": len(targets)}
                except windows_fixture_acl.FixtureAclError as exc:
                    trace["fixture_acl"] = {"status": "failed", "problems": [
                        {"target": label, "code": code} for label, code in exc.problems]}
                    raise
                # The fixture as it is pinned: after stabilization, before the first fence call.
                trace["setup"] = _snapshot(guarded, read, _fixture_paths(guarded, base, root, old, archive))
                originals = {"parent": read(root)}
                originals.update({"file:" + name: read(old / name) for name in guarded.NAMES})
                pins = (hashlib.sha256(originals["parent"].encode()).hexdigest(),
                        {name: hashlib.sha256(originals["file:" + name].encode()).hexdigest()
                         for name in guarded.NAMES})
                actual = guarded._icacls

                def recording(path, *args):
                    target = Path(path)
                    # Only the constant historical file names and the location are reported.
                    step = {"target": _label(root, archive, target),
                            "operation": "deny" if "/deny" in args else "remove_deny",
                            "before": observe(strict=True)}
                    try:
                        actual(path, *args)
                        step["icacls"] = "ok"
                    except BaseException as exc:
                        step["icacls"] = "failed"
                        step["error"] = describe_error(exc)
                        raise
                    finally:
                        step["after"] = observe(strict=True)
                        record(trace["steps"], step)
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
                try:
                    trace["at_end"] = _snapshot(guarded, read, _fixture_paths(guarded, base, root, old, archive),
                                                sid, originals)
                except Exception as exc:
                    trace["at_end"] = {"error": describe_error(exc)}
                _lift_and_verify(guarded, read, sid, _cleanup_targets(guarded, root, old, archive),
                                 observe, record, cleanup)
                try:
                    trace["after_remove_d"] = _snapshot(guarded, read,
                                                        _fixture_paths(guarded, base, root, old, archive),
                                                        sid, originals)
                except Exception as exc:
                    trace["after_remove_d"] = {"error": describe_error(exc)}
            body_done = True
        cleanup["directory_removal"] = "ok"
    except Exception as exc:
        if body_done:
            cleanup["directory_removal"] = "failed"
            cleanup["directory_removal_error"] = describe_error(exc)
        else:
            trace["error"] = describe_error(exc)   # setup or temp creation failed
    trace["cleanup"] = cleanup
    clean = (cleanup["denies_remaining"] == 0 and not cleanup["removal_failures"]
             and cleanup["directory_removal"] == "ok"
             and trace.get("fixture_acl", {}).get("status") == "stabilized")
    return trace, clean


def collect(guarded=None, *, temp_factory=tempfile.TemporaryDirectory) -> tuple[dict, bool]:
    """Return (sanitized report, whether every owned probe/fixture cleanup is verified)."""
    report = {"python": platform.python_version(), "os": platform.platform(),
              "os_name": os.name}
    cleanup_ok = True
    try:
        if guarded is None:
            from src import paper_pilot_phase_cutover_guarded_v2 as guarded
        sid = guarded._current_sid()
        report["runner_sid"] = redact(sid)
        report["runner_canonical_trustee"] = redact(guarded._canonical_trustee(sid))
        directory = temp_factory(prefix="jraphyte-fence-diag-")
        temp = directory.__enter__()
        try:
            probe = Path(temp) / "probe.bin"
            probe.write_bytes(b"0")
            try:
                report["probe_dacl_before_runner_deny"] = describe_dacl(guarded.directory_dacl_sddl(probe))
            except Exception as exc:
                report["probe_before_error"] = describe_error(exc)
            attempted = False
            try:
                attempted = True
                subprocess.run(["icacls.exe", str(probe), "/deny", "*" + sid + ":(WD,AD)"],
                               capture_output=True, text=True, timeout=30, check=True)
                raw = guarded.directory_dacl_sddl(probe)
                report["probe_dacl_after_runner_deny"] = redact(raw)
                report["probe_dacl_after_runner_deny_shape"] = describe_dacl(raw)
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
        finally:
            # The probe directory's own removal is part of the cleanup status, whatever the body did.
            try:
                directory.__exit__(None, None, None)
                report["probe_directory_removal"] = "ok"
            except Exception as exc:
                report["probe_directory_removal"] = "failed"
                report["probe_directory_removal_error"] = describe_error(exc)
                cleanup_ok = False
    except Exception as exc:
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
