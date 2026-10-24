"""Versioned continuous-lock quiescence and admission fence for an old pilot.

The reviewed caller must exclusively own all historical launch authority before
entry. This module locks the two stage files and the old pilot controller file,
then installs a durable deny for new writes to each of the five old state files.
The controller handle is released only after that deny is read back. The old
directory is renamed on the same volume while the stage locks remain held.

No provider, graph, source, or budget operation occurs here. An incomplete
deny/rename is a HOLD and is reconciled with the same pinned inputs.
"""

from __future__ import annotations

from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import subprocess

from trace_gc.canonical import bytes_digest, dumps, loads
from trace_gc.errors import require
from trace_gc.phase_authority import (_plain_absolute_path, canonical_dacl_ace,
                                      canonical_dacl_aces, dacl_has_ace,
                                      dacl_has_deny_trustee, directory_dacl_sddl)
from src.paper_pilot_phase_cutover import NAMES, _current_sid

DENY_FILE_ACE = "(D;;DCLC;;;{sid})"
DENY_PARENT_ACE = "(D;;LC;;;{sid})"


def _write_once(path: Path, body: dict) -> str:
    raw = (dumps(body) + "\n").encode("utf-8")
    expected = bytes_digest(raw)
    if path.exists():
        require(path.read_bytes() == raw, "PHASE_FENCE", "conflicting durable receipt")
        return expected
    require(path.parent.is_dir(), "PHASE_PATH", "receipt parent absent")
    pending = path.with_name(path.name + ".pending")
    if pending.exists():
        require(pending.read_bytes() == raw, "PHASE_FENCE", "conflicting pending receipt")
    else:
        with pending.open("xb") as handle:
            handle.write(raw); handle.flush(); os.fsync(handle.fileno())
    os.replace(pending, path)
    require(path.read_bytes() == raw, "PHASE_FENCE", "receipt readback differed")
    return expected


def _stage_lock(path: Path):
    import msvcrt
    require(path.is_file() and not path.is_symlink() and path.stat().st_size >= 1,
            "PHASE_FENCE", "preexisting stage lock required")
    handle = path.open("r+b")
    try:
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
    except BaseException:
        handle.close()
        raise
    return handle


def _same_held_lock(path: Path, handle) -> bool:
    held = os.fstat(handle.fileno())
    linked = os.stat(path)
    return (held.st_dev, held.st_ino) == (linked.st_dev, linked.st_ino)


def _icacls(path: Path, *args: str) -> None:
    result = subprocess.run(["icacls.exe", str(path), *args], capture_output=True,
                            text=True, timeout=30)
    require(result.returncode == 0, "PHASE_FENCE", "Windows DACL update failed")


def _file_deny(path: Path, sid: str) -> bool:
    return dacl_has_ace(directory_dacl_sddl(path), DENY_FILE_ACE, sid)


def _readable_pins(root: Path, expected: dict[str, str]) -> None:
    require(root.is_dir() and not root.is_symlink() and
            {p.name for p in root.iterdir()} == NAMES,
            "PHASE_FENCE", "historical five-file inventory differs")
    for name, value in sorted(expected.items()):
        path = root / name
        _plain_absolute_path(str(path))
        require(path.is_file() and not path.is_symlink() and
                bytes_digest(path.read_bytes()) == value,
                "PHASE_FENCE", "historical state bytes differ")


def _same_effective_dacl(before: str, after: str) -> bool:
    # icacls may add the auto-inherited control flag (AI). Explicit ACEs and
    # protection (P) must still match exactly; no broadened access is accepted.
    before_flags = before.split("(", 1)[0].removeprefix("D:").replace("AI", "")
    after_flags = after.split("(", 1)[0].removeprefix("D:").replace("AI", "")
    return (before_flags == after_flags and
            canonical_dacl_aces(before) == canonical_dacl_aces(after))


def _only_admission_dacl_added(original: str, current: str, sid: str) -> bool:
    old_aces = canonical_dacl_aces(original)
    now_aces = canonical_dacl_aces(current)
    deny = canonical_dacl_ace(DENY_FILE_ACE.format(sid=sid))
    if deny in now_aces:
        now_aces.remove(deny)
    old_flags = original.split("(", 1)[0].removeprefix("D:").replace("AI", "")
    now_flags = current.split("(", 1)[0].removeprefix("D:").replace("AI", "")
    return old_flags == now_flags and old_aces == now_aces


def _owner_deny_present(sddl: str, sid: str) -> bool:
    return dacl_has_deny_trustee(sddl, sid)


def _only_parent_admission_added(original: str, current: str, sid: str) -> bool:
    old_aces = canonical_dacl_aces(original)
    now_aces = canonical_dacl_aces(current)
    deny = canonical_dacl_ace(DENY_PARENT_ACE.format(sid=sid))
    if deny in now_aces:
        now_aces.remove(deny)
    old_flags = original.split("(", 1)[0].removeprefix("D:").replace("AI", "")
    now_flags = current.split("(", 1)[0].removeprefix("D:").replace("AI", "")
    return old_flags == now_flags and old_aces == now_aces


def fence_closed_old_phase_guarded(*, old_root: str | Path,
                                   archived_root: str | Path,
                                   expected_file_sha256: dict[str, str],
                                   source_stage_lock: str | Path,
                                   phase_stage_lock: str | Path,
                                   deny_sid: str,
                                   expected_parent_dacl_sha256: str,
                                   expected_file_dacl_sha256: dict[str, str],
                                   barrier_receipt_path: str | Path,
                                   fence_receipt_path: str | Path,
                                   _preheld_locks: tuple | None = None,
                                   _release_observer_lease=None) -> dict:
    """Fence a closed old phase, preserving a durable denial across crashes.

    Caller-owned launch exclusion is still required before this function enters:
    no file API can atomically prevent a first launch before its first DACL write.
    """
    require(os.name == "nt", "PHASE_PLATFORM", "Windows fence required")
    old, archived = Path(old_root), Path(archived_root)
    barrier, receipt = Path(barrier_receipt_path), Path(fence_receipt_path)
    source_lock, phase_lock = Path(source_stage_lock), Path(phase_stage_lock)
    for path in (old, archived, barrier, receipt, source_lock, phase_lock):
        _plain_absolute_path(str(path))
    require(old.name == "state" and old != archived and
            old.drive.lower() == archived.drive.lower() and
            old.parent != archived.parent and old.parent.is_dir() and
            archived.parent.is_dir() and barrier.parent.is_dir() and
            receipt.parent.is_dir() and
            not old.is_relative_to(archived.parent) and
            not archived.is_relative_to(old.parent),
            "PHASE_PATH", "exact disjoint same-volume layout required")
    require(source_lock.parent == old.parent and phase_lock.parent == old.parent and
            source_lock.name == "source-stage.lock" and
            phase_lock.name == "phase-stage.lock",
            "PHASE_PATH", "exact historical stage locks required")
    require(deny_sid == _current_sid() and set(expected_file_sha256) == NAMES and
            all(type(value) is str and len(value) == 64 and
                set(value) <= set("0123456789abcdef")
                for value in expected_file_sha256.values()),
            "PHASE_FENCE", "reviewed SID or five-file pins differ")
    require(set(expected_file_dacl_sha256) == NAMES and
            all(type(value) is str and len(value) == 64 for value in
                (*expected_file_dacl_sha256.values(), expected_parent_dacl_sha256)),
            "PHASE_FENCE", "reviewed ACL pins absent")
    require(not (old.exists() and archived.exists()) and
            (old.exists() or archived.exists()),
            "PHASE_FENCE", "ambiguous old/archive namespace")

    with ExitStack() as stack:
        if _preheld_locks is None:
            source_handle = stack.enter_context(_stage_lock(source_lock))
            phase_handle = stack.enter_context(_stage_lock(phase_lock))
            preheld_controller = None
        else:
            require(len(_preheld_locks) == 3, "PHASE_LOCK", "three held old locks required")
            source_handle, phase_handle, preheld_controller = _preheld_locks
            require(not source_handle.closed and not phase_handle.closed and
                    (preheld_controller is None or not preheld_controller.closed) and
                    _same_held_lock(source_lock, source_handle) and
                    _same_held_lock(phase_lock, phase_handle) and
                    ((preheld_controller is not None and
                      _same_held_lock(old / "controller.lock", preheld_controller)) or
                     (preheld_controller is None and barrier.exists() and
                      _file_deny(old / "controller.lock", deny_sid))),
                    "PHASE_LOCK", "preheld old lock identities differ")
        held_controller = preheld_controller if barrier.exists() else None
        if barrier.exists():
            recorded = loads(barrier.read_bytes())
            require(recorded.get("version") == "paper-pilot-admission-barrier-v1" and
                    recorded.get("old_root_path") == str(old) and
                    recorded.get("archive_root_path") == str(archived) and
                    recorded.get("file_sha256") == expected_file_sha256 and
                    bytes_digest(recorded["original_parent_dacl_sddl"].encode()) ==
                    expected_parent_dacl_sha256 and
                    {name: bytes_digest(value.encode()) for name, value in
                     recorded["original_file_dacl_sddl"].items()} ==
                    expected_file_dacl_sha256 and
                    recorded.get("sid") == deny_sid,
                    "PHASE_FENCE", "historical barrier scope differs")
        else:
            require(old.exists(), "PHASE_FENCE", "archive lacks prior barrier")
            if _preheld_locks is None:
                _readable_pins(old, expected_file_sha256)
            else:
                # The controller's first byte is locked on our existing
                # handle. A second read handle cannot read that byte on
                # Windows; its byte hash was checked before acquisition.
                require({p.name for p in old.iterdir()} == NAMES and
                        all(bytes_digest((old / name).read_bytes()) ==
                            expected_file_sha256[name]
                            for name in NAMES - {"controller.lock"}),
                        "PHASE_FENCE", "held old database bytes differ")
            held_controller = preheld_controller or _stage_lock(old / "controller.lock")
            stack.callback(held_controller.close)
            original = {name: directory_dacl_sddl(old / name)
                        for name in sorted(NAMES)}
            parent_original = directory_dacl_sddl(old.parent)
            require(not _owner_deny_present(parent_original, deny_sid) and
                    all(not _owner_deny_present(value, deny_sid)
                        for value in original.values()),
                    "PHASE_FENCE", "existing owner deny cannot be safely merged")
            require(bytes_digest(parent_original.encode()) == expected_parent_dacl_sha256 and
                    {name: bytes_digest(value.encode()) for name, value in
                     original.items()} == expected_file_dacl_sha256,
                    "PHASE_FENCE", "original Windows DACL identity changed")
            require(all(not dacl_has_ace(value, DENY_FILE_ACE, deny_sid)
                        for value in original.values()),
                    "PHASE_FENCE", "unreviewed preexisting file deny")
            recorded = {"version": "paper-pilot-admission-barrier-v1",
                        "old_root_path": str(old),
                        "archive_root_path": str(archived),
                        "file_sha256": expected_file_sha256,
                        "original_file_dacl_sddl": original,
                        "original_parent_dacl_sddl": parent_original,
                        "sid": deny_sid}
            _write_once(barrier, recorded)

        # On replay the first file can already be denied, so its old controller
        # handle cannot be reopened. The durable ACE is the admission barrier.
        try:
            require(_only_parent_admission_added(
                        recorded["original_parent_dacl_sddl"],
                        directory_dacl_sddl(old.parent), deny_sid),
                    "PHASE_FENCE", "old parent DACL changed beyond admission deny")
            if old.exists():
                controller_path = old / "controller.lock"
                if not _file_deny(controller_path, deny_sid) and held_controller is None:
                    # First entry owns this byte lock already. A replay with a
                    # missing deny must reacquire it or HOLD.
                    held_controller = _stage_lock(controller_path)
                    stack.callback(held_controller.close)
                # Recheck mutable database bytes after all old launch locks
                # have been acquired. The controller file's first byte is
                # byte-locked, so its pre-lock hash remains the pinned proof.
                for name in sorted(NAMES - {"controller.lock"}):
                    path = old / name
                    if not _file_deny(path, deny_sid):
                        require(bytes_digest(path.read_bytes()) ==
                                expected_file_sha256[name],
                                "PHASE_FENCE", "database changed after lock acquisition")
                for name in ("controller.lock", "checkpoint.sqlite3", "graph.sqlite3",
                             "budget.sqlite3", "application-journal.sqlite3"):
                    path = old / name
                    require(_only_admission_dacl_added(
                                recorded["original_file_dacl_sddl"][name],
                                directory_dacl_sddl(path), deny_sid),
                            "PHASE_FENCE", "unreviewed old file DACL drift")
                    if not _file_deny(path, deny_sid):
                        _icacls(path, "/deny", "*" + deny_sid + ":(WD,AD)")
                    require(_file_deny(path, deny_sid), "PHASE_FENCE",
                            "new old-state write open not denied")
                parent_sddl = directory_dacl_sddl(old.parent)
                if not dacl_has_ace(parent_sddl, DENY_PARENT_ACE, deny_sid):
                    _icacls(old.parent, "/deny", "*" + deny_sid + ":(AD)")
                require(dacl_has_ace(directory_dacl_sddl(old.parent), DENY_PARENT_ACE,
                                     deny_sid), "PHASE_FENCE",
                        "old state recreation remains possible")
                require(_only_parent_admission_added(
                            recorded["original_parent_dacl_sddl"],
                            directory_dacl_sddl(old.parent), deny_sid),
                        "PHASE_FENCE", "old parent DACL broadened during fence")
                # The observer's retained read handles kept direct database
                # writers out during the first ACL update. Once all five file
                # denies and the parent deny are read back, release them so
                # Windows permits the same-volume directory rename.
                if _release_observer_lease is not None:
                    _release_observer_lease()
                # Every new open is now denied. Existing controller handle
                # closes before parent rename; stage locks remain held.
                if held_controller is not None:
                    held_controller.close()
                    held_controller = None
                require(_same_held_lock(source_lock, source_handle) and
                        _same_held_lock(phase_lock, phase_handle),
                        "PHASE_FENCE", "stage lock path replaced while held")
                os.rename(old, archived)
        finally:
            if held_controller is not None:
                held_controller.close()
        require(not old.exists() and archived.is_dir(), "PHASE_FENCE",
                "fixed old path not closed")
        # Restore only our five explicit per-file denies at the archive path.
        # The parent deny-create remains durable. A crash before this loop is
        # reconciled with the original barrier and the same archive bytes.
        for name in sorted(NAMES):
            path = archived / name
            if _file_deny(path, deny_sid):
                _icacls(path, "/remove:d", "*" + deny_sid)
            require(not _file_deny(path, deny_sid), "PHASE_FENCE",
                    "archived readback still denied")
        _readable_pins(archived, expected_file_sha256)
        require(dacl_has_ace(directory_dacl_sddl(old.parent), DENY_PARENT_ACE, deny_sid),
                "PHASE_FENCE", "old fixed path admission reopened")
        require(_only_parent_admission_added(
                    recorded["original_parent_dacl_sddl"],
                    directory_dacl_sddl(old.parent), deny_sid),
                "PHASE_FENCE", "old parent DACL changed after archive")
        # The Windows ACL API may add the auto-inherited control flag when
        # restoring ACEs; require effective non-deny ACEs to remain equal.
        effective = {name: directory_dacl_sddl(archived / name)
                     for name in sorted(NAMES)}
        require(all(_same_effective_dacl(recorded["original_file_dacl_sddl"][name],
                                         effective[name]) for name in NAMES),
                "PHASE_FENCE", "archived effective file DACL changed")
        # Preserve the public PhaseAuthority V1 receipt contract. The separate
        # durable barrier receipt proves the guarded admission sequence and is
        # pinned by the external stage release; no phase-runtime API change is
        # needed to reopen the imported pilot.
        body = {"version": "paper-pilot-phase-namespace-fence-v1",
                "old_root_path": str(old), "archived_root_path": str(archived),
                "archived_files_sha256": expected_file_sha256,
                "old_parent_dacl_sha256": bytes_digest(
                    directory_dacl_sddl(old.parent).encode("utf-8")),
                "deny_sid": deny_sid,
                "status": "OLD_PATH_FENCED_NEW_PHASE_ALLOWED"}
        receipt_sha = _write_once(receipt, body)
        return {"status": body["status"], "receipt_sha256": receipt_sha,
                "old_path_absent": True, "archived_file_count": len(NAMES)}


def held_quiescence_receipt_body(*, old_root: str | Path,
                                 archived_root: str | Path,
                                 expected_file_sha256: dict[str, str],
                                 source_stage_lock: str | Path,
                                 phase_stage_lock: str | Path,
                                 deny_sid: str,
                                 expected_parent_dacl_sha256: str,
                                 expected_file_dacl_sha256: dict[str, str],
                                 quiescence_authorization_sha256: str) -> dict:
    """Canonical, time-free receipt contract to pin before first ACL effect."""
    return {"version": "paper-pilot-held-quiescence-v1",
            "status": "QUIESCENT_UNDER_CONTINUOUS_OLD_LOCKS",
            "old_root_path": str(old_root), "archive_root_path": str(archived_root),
            "source_stage_lock_path": str(source_stage_lock),
            "phase_stage_lock_path": str(phase_stage_lock),
            "old_file_sha256": expected_file_sha256,
            "old_parent_dacl_sha256": expected_parent_dacl_sha256,
            "old_file_dacl_sha256": expected_file_dacl_sha256,
            "deny_sid": deny_sid,
            "quiescence_authorization_sha256": quiescence_authorization_sha256}


def quiescence_then_fence_guarded(*, old_root: str | Path,
                                  archived_root: str | Path,
                                  expected_file_sha256: dict[str, str],
                                  source_stage_lock: str | Path,
                                  phase_stage_lock: str | Path,
                                  deny_sid: str,
                                  expected_parent_dacl_sha256: str,
                                  expected_file_dacl_sha256: dict[str, str],
                                  quiescence_authorization_sha256: str,
                                  fence_authorization_sha256: str,
                                  quiescence_receipt_path: str | Path,
                                  expected_quiescence_receipt_sha256: str,
                                  barrier_receipt_path: str | Path,
                                  fence_receipt_path: str | Path,
                                  observer=None) -> dict:
    """Observe and fence under one continuous three-lock ownership interval.

    The application coordinator must verify both stage authorizations before
    calling this function. A replay after the first deny uses the durable
    quiescence/barrier receipts and the ordinary guarded reconcile path.
    """
    require(os.name == "nt", "PHASE_PLATFORM", "Windows fence required")
    old, archived = Path(old_root), Path(archived_root)
    source_lock, phase_lock = Path(source_stage_lock), Path(phase_stage_lock)
    quiescence = Path(quiescence_receipt_path)
    for path in (old, archived, source_lock, phase_lock, quiescence,
                 Path(barrier_receipt_path), Path(fence_receipt_path)):
        _plain_absolute_path(str(path))
    require(old.name == "state" and old.drive.lower() == archived.drive.lower() and
            old.parent != archived.parent and old.parent.is_dir() and
            archived.parent.is_dir() and quiescence.parent.is_dir() and
            source_lock.parent == old.parent and phase_lock.parent == old.parent and
            source_lock.name == "source-stage.lock" and
            phase_lock.name == "phase-stage.lock" and
            set(expected_file_sha256) == NAMES and
            set(expected_file_dacl_sha256) == NAMES and
            deny_sid == _current_sid() and
            all(type(value) is str and len(value) == 64 and
                set(value) <= set("0123456789abcdef") for value in
                (*expected_file_sha256.values(), *expected_file_dacl_sha256.values(),
                 expected_parent_dacl_sha256, quiescence_authorization_sha256,
                 fence_authorization_sha256, expected_quiescence_receipt_sha256)),
            "PHASE_PATH", "reviewed continuous-lock inputs differ")
    body = held_quiescence_receipt_body(
        old_root=old, archived_root=archived,
        expected_file_sha256=expected_file_sha256,
        source_stage_lock=source_lock, phase_stage_lock=phase_lock,
        deny_sid=deny_sid,
        expected_parent_dacl_sha256=expected_parent_dacl_sha256,
        expected_file_dacl_sha256=expected_file_dacl_sha256,
        quiescence_authorization_sha256=quiescence_authorization_sha256)
    require(bytes_digest((dumps(body) + "\n").encode()) ==
            expected_quiescence_receipt_sha256,
            "PHASE_FENCE", "deterministic quiescence receipt pin differs")

    common = {"old_root": old, "archived_root": archived,
              "expected_file_sha256": expected_file_sha256,
              "source_stage_lock": source_lock, "phase_stage_lock": phase_lock,
              "deny_sid": deny_sid,
              "expected_parent_dacl_sha256": expected_parent_dacl_sha256,
              "expected_file_dacl_sha256": expected_file_dacl_sha256,
              "barrier_receipt_path": barrier_receipt_path,
              "fence_receipt_path": fence_receipt_path}
    if Path(barrier_receipt_path).exists():
        require(quiescence.is_file() and
                bytes_digest(quiescence.read_bytes()) ==
                expected_quiescence_receipt_sha256,
                "PHASE_FENCE", "quiescence receipt missing on fence replay")
        if not old.exists():
            result = fence_closed_old_phase_guarded(**common)
        else:
            # The barrier can precede the first ACL update. Rebuild the
            # observer lease across any still-writable database files before
            # continuing. A controller file already denied cannot be opened
            # again; that denial itself blocks unchanged old launchers.
            with ExitStack() as replay_stack:
                source_handle = replay_stack.enter_context(_stage_lock(source_lock))
                phase_handle = replay_stack.enter_context(_stage_lock(phase_lock))
                controller_handle = None
                if not _file_deny(old / "controller.lock", deny_sid):
                    controller_handle = replay_stack.enter_context(
                        _stage_lock(old / "controller.lock"))
                lease_stack = ExitStack()
                replay_stack.callback(lease_stack.close)
                require(observer is not None, "PHASE_LOCK",
                        "incomplete old fence requires renewed owner observation")
                lease = observer(old_root=old, archived_root=archived,
                                 source_handle=source_handle,
                                 phase_handle=phase_handle,
                                 controller_handle=controller_handle,
                                 writable_database_names=tuple(sorted(
                                     name for name in NAMES - {"controller.lock"}
                                     if not _file_deny(old / name, deny_sid))))
                require(hasattr(lease, "__enter__") and hasattr(lease, "__exit__"),
                        "PHASE_LOCK", "observer must return a retained context lease")
                lease_stack.enter_context(lease)
                result = fence_closed_old_phase_guarded(
                    **common,
                    _preheld_locks=(source_handle, phase_handle, controller_handle),
                    _release_observer_lease=lease_stack.close)
        return {**result, "quiescence_receipt_sha256":
                expected_quiescence_receipt_sha256, "reconciled": True}

    require(not quiescence.exists() and
            not quiescence.with_name(quiescence.name + ".pending").exists(),
            "PHASE_FENCE", "pre-barrier quiescence needs renewed owner review")

    # The two stage locks and old controller byte lock remain held until the
    # old files have received a durable deny. The fence closes only controller
    # before same-volume rename; the stage locks stay held through the result.
    with ExitStack() as stack:
        source_handle = stack.enter_context(_stage_lock(source_lock))
        phase_handle = stack.enter_context(_stage_lock(phase_lock))
        _readable_pins(old, expected_file_sha256)
        require(bytes_digest(directory_dacl_sddl(old.parent).encode()) ==
                expected_parent_dacl_sha256 and
                {name: bytes_digest(directory_dacl_sddl(old / name).encode())
                 for name in NAMES} == expected_file_dacl_sha256,
                "PHASE_FENCE", "old ACL changed before held quiescence")
        controller = stack.enter_context(_stage_lock(old / "controller.lock"))
        require(_same_held_lock(source_lock, source_handle) and
                _same_held_lock(phase_lock, phase_handle) and
                _same_held_lock(old / "controller.lock", controller) and
                all(bytes_digest((old / name).read_bytes()) == expected_file_sha256[name]
                    for name in NAMES - {"controller.lock"}),
                "PHASE_LOCK", "old state changed after all locks acquired")
        observer_lease = ExitStack()
        stack.callback(observer_lease.close)
        if observer is not None:
            lease = observer(old_root=old, archived_root=archived,
                             source_handle=source_handle,
                             phase_handle=phase_handle,
                             controller_handle=controller,
                             writable_database_names=tuple(sorted(
                                 NAMES - {"controller.lock"})))
            require(hasattr(lease, "__enter__") and hasattr(lease, "__exit__"),
                    "PHASE_LOCK", "observer must return a retained context lease")
            observer_lease.enter_context(lease)
        require(_write_once(quiescence, body) == expected_quiescence_receipt_sha256,
                "PHASE_FENCE", "held quiescence receipt changed")
        result = fence_closed_old_phase_guarded(
            **common, _preheld_locks=(source_handle, phase_handle, controller),
            _release_observer_lease=observer_lease.close)
        return {**result, "quiescence_receipt_sha256":
                expected_quiescence_receipt_sha256, "reconciled": False}
