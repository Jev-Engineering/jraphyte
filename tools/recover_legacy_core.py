#!/usr/bin/env python3
"""Recover only the exact-pinned legacy core from an explicitly supplied ZIP.

No member is executed or imported. No arbitrary archive path is extracted. The
caller owns the destination; existing files are never replaced. A matching hash
identifies source bytes, not a signature, a new review, or production approval.
"""
from __future__ import annotations

import argparse
from hashlib import sha1, sha256
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import tempfile
import zlib
from typing import Any
from zipfile import BadZipFile, ZipFile

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from trace_gc.legacy import PINNED_CORE_BLOB

MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_MEMBERS = 4096
MAX_CORE_BYTES = 128 * 1024
CORE_SUFFIX = ("graph_synthesis", "core.py")


class RecoveryError(ValueError):
    """A fail-closed input, integrity, or destination check."""


def git_blob(data: bytes) -> str:
    """Git's blob identity, including its type/length framing."""
    return sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def _member_path(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    # ZIP paths are POSIX paths even on Windows. Refuse alternate spellings and
    # drive-qualified names rather than guessing how an extractor would use them.
    if (not name or "\\" in name or "\0" in name or path.is_absolute()
            or any(part in {".", ".."} for part in name.rstrip("/").split("/"))
            or any(":" in part for part in path.parts)):
        raise RecoveryError("UNSAFE_ARCHIVE_MEMBER")
    return path


def _publish_new_file(destination: Path, data: bytes) -> None:
    """Publish verified bytes atomically without an overwrite race.

    A hard-link of a fully written temporary file either creates a new pathname
    or fails if one already exists (including a symlink). No replace/rename over
    the caller's existing files is used. Unsupported filesystems fail closed.
    """
    parent = destination.parent
    if not parent.is_dir():
        raise RecoveryError("DESTINATION_PARENT_MISSING")
    if destination.exists() or destination.is_symlink():
        raise RecoveryError("DESTINATION_EXISTS")
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(prefix=".trace-pinned-core-", dir=parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, destination)
        except FileExistsError as exc:
            raise RecoveryError("DESTINATION_EXISTS") from exc
        except OSError as exc:
            raise RecoveryError("ATOMIC_CREATE_UNAVAILABLE") from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def recover_core(archive: Path, *, destination: Path | None = None,
                 member: str | None = None) -> dict[str, Any]:
    """Verify a bounded archive snapshot; optionally create an external core.py.

    ``member`` disambiguates an explicitly named archive member. It cannot change
    the accepted source pin. ``destination=None`` is a write-free verification.
    """
    archive = Path(archive)
    # The receipt's archive hash and extracted bytes come from one immutable,
    # bounded in-memory copy, not separate path opens vulnerable to substitution.
    # Nonblocking open lets us reject FIFOs/devices before a blocking read.
    descriptor = os.open(archive, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise RecoveryError("ARCHIVE_NOT_REGULAR")
        if os.fstat(stream.fileno()).st_size > MAX_ARCHIVE_BYTES:
            raise RecoveryError("ARCHIVE_TOO_LARGE")
        raw = stream.read(MAX_ARCHIVE_BYTES + 1)
    if len(raw) > MAX_ARCHIVE_BYTES:
        raise RecoveryError("ARCHIVE_TOO_LARGE")
    if member is not None:
        _member_path(member)
    try:
        with ZipFile(io.BytesIO(raw)) as bundle:
            entries = bundle.infolist()
            if len(entries) > MAX_MEMBERS:
                raise RecoveryError("TOO_MANY_ARCHIVE_MEMBERS")
            names: set[str] = set()
            candidates = []
            for entry in entries:
                # ZipInfo normalizes member names on Windows before exposing
                # filename. Inspect the decoded central-directory spelling too;
                # otherwise a raw backslash or NUL can disappear before our
                # portable path checks run.
                path = _member_path(entry.orig_filename)
                if entry.orig_filename != entry.filename:
                    raise RecoveryError("UNSAFE_ARCHIVE_MEMBER")
                if entry.filename in names:
                    raise RecoveryError("DUPLICATE_ARCHIVE_MEMBER")
                names.add(entry.filename)
                if tuple(path.parts[-2:]) == CORE_SUFFIX and not entry.is_dir():
                    candidates.append(entry)
            if member is not None:
                candidates = [entry for entry in candidates if entry.filename == member]
            if len(candidates) != 1:
                raise RecoveryError("PINNED_MEMBER_MISSING" if not candidates else "PINNED_MEMBER_AMBIGUOUS")
            selected = candidates[0]
            mode = selected.external_attr >> 16
            if stat.S_ISLNK(mode) or (stat.S_IFMT(mode) not in {0, stat.S_IFREG}):
                raise RecoveryError("PINNED_MEMBER_NOT_REGULAR")
            if selected.flag_bits & 1:
                raise RecoveryError("ENCRYPTED_ARCHIVE_MEMBER")
            if not 0 < selected.file_size <= MAX_CORE_BYTES:
                raise RecoveryError("CORE_SIZE_LIMIT")
            with bundle.open(selected) as stream:
                data = stream.read(MAX_CORE_BYTES + 1)
            if len(data) != selected.file_size or len(data) > MAX_CORE_BYTES:
                raise RecoveryError("CORE_SIZE_LIMIT")
    except (BadZipFile, RuntimeError, NotImplementedError, EOFError, zlib.error) as exc:
        raise RecoveryError("INVALID_ARCHIVE") from exc
    actual = git_blob(data)
    if actual != PINNED_CORE_BLOB:
        raise RecoveryError("UPSTREAM_PIN_MISMATCH")
    if destination is not None:
        _publish_new_file(Path(destination), data)
    return {
        "format_version": 1,
        "status": "EXACT_PIN_VERIFIED",
        "archive_sha256": sha256(raw).hexdigest(),
        "archive_member": selected.filename,
        "core_git_blob": actual,
        "core_sha256": sha256(data).hexdigest(),
        "core_bytes": len(data),
        "destination_created": destination is not None,
        "existing_files_overwritten": False,
        "code_executed": False,
        "git_signature_or_review_approval": "NOT_ESTABLISHED_BY_HASH_MATCH",
        "legacy_conformance": "NOT_RUN_BY_RECOVERY",
        "production_qualification": "NOT_ESTABLISHED",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path, help="Explicitly supplied local ZIP; never downloaded automatically")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--output", type=Path, help="New external core.py path; its parent must already exist")
    mode.add_argument("--verify-only", action="store_true", help="Verify without creating a file")
    parser.add_argument("--member", help="Exact member name when more than one core.py is present")
    args = parser.parse_args(argv)
    try:
        result = recover_core(args.archive, destination=args.output, member=args.member)
    except (RecoveryError, OSError) as exc:
        # Avoid copying potentially sensitive filesystem paths into public logs.
        print(json.dumps({"status": "FAIL", "code": str(exc) if isinstance(exc, RecoveryError)
                          else type(exc).__name__, "code_executed": False}), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
