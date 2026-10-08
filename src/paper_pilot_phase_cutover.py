"""Application-owned, Windows-only namespace fence for a closed pilot phase.

The caller must stop and close every historical owner before entry. This
helper never terminates a process, runs a provider, edits a graph, or signs a
receipt. A reviewed release must pin the exact closed file inventory.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess

from trace_gc.canonical import bytes_digest, dumps, loads
from trace_gc.errors import require
from trace_gc.phase_authority import _plain_absolute_path, dacl_has_ace, directory_dacl_sddl

NAMES = {"checkpoint.sqlite3", "graph.sqlite3", "budget.sqlite3",
         "application-journal.sqlite3", "controller.lock"}
DENY_PARENT_ACE = "(D;;LC;;;{sid})"


def _current_sid() -> str:
    result = subprocess.run(["pwsh.exe", "-NoProfile", "-NonInteractive", "-Command",
        "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value"],
        capture_output=True, text=True, timeout=15)
    require(result.returncode == 0 and result.stdout.strip().startswith("S-1-5-"),
            "PHASE_FENCE", "current Windows SID unavailable")
    return result.stdout.strip()


def _pinned_files(root: Path, expected: dict[str, str]) -> None:
    _plain_absolute_path(str(root))
    for name in NAMES:
        _plain_absolute_path(str(root / name))
    require(root.is_dir() and not root.is_symlink() and
            {p.name for p in root.iterdir()} == NAMES and set(expected) == NAMES and
            all((root / name).is_file() and not (root / name).is_symlink() and
                bytes_digest((root / name).read_bytes()) == sha
                for name, sha in expected.items()),
            "PHASE_FENCE", "closed historical five-file inventory changed")


def _write_once(path: Path, body: dict) -> str:
    raw = (dumps(body) + "\n").encode("utf-8")
    if path.exists():
        require(path.read_bytes() == raw, "PHASE_FENCE", "conflicting fence receipt")
        return bytes_digest(raw)
    with path.open("xb") as file:
        file.write(raw)
        file.flush(); os.fsync(file.fileno())
    require(path.read_bytes() == raw, "PHASE_FENCE", "fence receipt readback failed")
    return bytes_digest(raw)


def fence_closed_old_phase(*, old_root: str | Path, archived_root: str | Path,
                           expected_file_sha256: dict[str, str], deny_sid: str,
                           receipt_path: str | Path) -> dict:
    """Move one closed fixed-path state directory behind a durable deny-create.

    Repeating the same call after a crash verifies the completed namespace and
    seals the same receipt. If the deny exists but the move is pending, it
    finishes the move only when the exact five closed files still match.
    """
    require(os.name == "nt", "PHASE_PLATFORM", "NTFS namespace fence requires Windows")
    old, archived, receipt = Path(old_root), Path(archived_root), Path(receipt_path)
    # Reject existing reparse ancestors before the first DACL or namespace edit.
    # In particular, a Windows junction does not satisfy Path.is_symlink().
    for path in (old, archived, receipt):
        _plain_absolute_path(str(path))
    require(old.is_absolute() and archived.is_absolute() and receipt.is_absolute() and
            old.name == "state" and old != archived and
            old.drive.lower() == archived.drive.lower() and
            not archived.is_relative_to(old.parent) and
            not old.is_relative_to(archived.parent) and
            not old.parent.is_symlink() and not archived.parent.is_symlink() and
            archived.parent.is_dir() and receipt.parent.is_dir() and
            receipt.parent != old.parent and receipt.parent != archived.parent,
            "PHASE_PATH", "disjoint preexisting owned phase paths required")
    require(deny_sid == _current_sid(), "PHASE_FENCE", "fence SID differs from current owner")
    require(set(expected_file_sha256) == NAMES and
            all(type(v) is str and len(v) == 64 and
                all(c in "0123456789abcdef" for c in v)
                for v in expected_file_sha256.values()),
            "PHASE_FENCE", "exact reviewed closed-file hashes required")
    require(not (old.exists() and archived.exists()) and (old.exists() or archived.exists()),
            "PHASE_FENCE", "ambiguous old/archive namespace")
    if old.exists():
        _pinned_files(old, expected_file_sha256)
    else:
        _pinned_files(archived, expected_file_sha256)
    sddl = directory_dacl_sddl(old.parent)
    # Windows may spell this SID as a DACL alias (for example LA); the exact
    # deny-create ACE is recognized under either spelling.
    if not dacl_has_ace(sddl, DENY_PARENT_ACE, deny_sid):
        require(old.exists(), "PHASE_FENCE", "archive moved without durable parent deny")
        command = subprocess.run(["icacls.exe", str(old.parent), "/deny", "*" + deny_sid + ":(AD)"],
                                 capture_output=True, text=True, timeout=30)
        require(command.returncode == 0, "PHASE_FENCE", "could not deny old state recreation")
        sddl = directory_dacl_sddl(old.parent)
    require(dacl_has_ace(sddl, DENY_PARENT_ACE, deny_sid), "PHASE_FENCE",
            "old parent lacks exact deny-create ACE")
    if old.exists():
        # No COPY_ALLOWED: same-volume directory rename or HOLD. Application has
        # already closed every old database/lock handle; a leaked handle fails.
        require(not archived.exists(), "PHASE_FENCE", "archive target already exists")
        os.rename(old, archived)
    _pinned_files(archived, expected_file_sha256)
    require(not old.exists(), "PHASE_FENCE", "fixed old path still exists")
    body = {"version": "paper-pilot-phase-namespace-fence-v1",
            "old_root_path": str(old), "archived_root_path": str(archived),
            "old_parent_dacl_sha256": bytes_digest(sddl.encode("utf-8")),
            "archived_files_sha256": expected_file_sha256,
            "deny_sid": deny_sid, "status": "OLD_PATH_FENCED_NEW_PHASE_ALLOWED"}
    sha = _write_once(receipt, body)
    return {"status": body["status"], "receipt_sha256": sha,
            "old_path_absent": True, "archived_file_count": len(NAMES)}
