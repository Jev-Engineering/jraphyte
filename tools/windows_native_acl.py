#!/usr/bin/env python3
"""Native Windows descriptor and directory-creation helpers for owned disposable fixtures.

``icacls`` resolves every trustee through an account lookup, so it cannot install an ACE for a
SID that no machine knows (a fabricated domain RID-500 SID). ``deny_by_descriptor`` parses a
numeric-SID SDDL string and installs it with ``SetNamedSecurityInfoW``; no lookup happens, and the
installed ACE list, owner and digest are read back from the real descriptor.

The directory-creation probe reports, from the real kernel, whether a parent deny ACE refuses
``mkdir`` for the full process token and for a copy with every privilege removed, what
``AccessCheck`` computes for each, which privileges are enabled, and the volume file system. It
changes no production behaviour, emits no path, account name or exception text, and every
directory it creates is removed again and verified.

Run as a script (``python tools/windows_native_acl.py``, from any directory) it first makes the
checkout importable, then prints one sanitized JSON report naming each stage it completed
(``bootstrap``, ``checkout_imports``, ``native_api``, ``identity``) and, on Windows, the sections
``matrix`` (candidate deny shapes), ``actual_fence_shape``, ``privilege_isolation`` (which single
privilege removals change the outcome), ``installation_observation`` (per-component facts for an
unprotected and a stabilized fixture) and ``restricted_primary_child`` (the same recreation report
from a child whose primary token has every privilege removed). Every section is an observation:
``cause_established`` is always false and nothing is accepted on it. All fixtures are owned
temporary directories; the exit status is nonzero on Windows unless every cleanup is verified.
``--stages-only`` stops after the identity stage. Loaded by path (the installed-wheel check) the
module edits neither ``sys.path`` nor ``sys.modules``.
"""
from __future__ import annotations

from collections import Counter
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]

PARENT_RIGHTS = "LC"        # FILE_ADD_SUBDIRECTORY, spelled by icacls as (AD)
FILE_ADD_FILE = 0x2
FILE_ADD_SUBDIRECTORY = 0x4
BYPASS_PRIVILEGES = ("SeBackupPrivilege", "SeRestorePrivilege")
_DACL = re.compile(r"D:([A-Z]*)((?:\([^)]*\))*)")
_NUMERIC_SID = re.compile(r"S-1-[0-9]+(?:-[0-9]+)+")


def redact(text):
    """Mask machine and directory sub-authorities; byte-identical in effect to the sanitizer of
    ``tools/windows_fence_diagnostics.py`` but local, so loading this module by path never edits
    ``sys.path`` or imports checkout code."""
    text = re.sub(r"S-1-5-21-\d+-\d+-\d+-(\d+)", r"S-1-5-21-<machine>-\1", text)
    return re.sub(r"S-1-12-1(?:-\d+){4}", "S-1-12-1-<directory>", text)


class NativeError(Exception):
    """A Win32 call failed; only the API name and the numeric error are kept."""

    def __init__(self, api: str, code: int | None):
        super().__init__("%s failed with %s" % (api, code))
        self.api, self.code = api, code


def split_dacl(sddl: str) -> tuple[str, list[str]]:
    match = _DACL.fullmatch(sddl)
    if match is None:
        raise ValueError("not a plain DACL string")
    return match.group(1), re.findall(r"\([^)]*\)", match.group(2))


def join_dacl(control: str, aces: list[str]) -> str:
    return "D:" + control + "".join(aces)


def with_ace_first(sddl: str, ace: str) -> str:
    control, aces = split_dacl(sddl)
    return join_dacl(control, [ace, *aces])


def canonical_ace(native, ace: str) -> str:
    """Spell only the trustee of one six-field ACE as this machine's Windows writes it.

    A strictly numeric SID is translated forward by the operating system (the alias for a
    well-known or machine-local SID, itself for any other), so Windows reading back ``LA`` or
    ``BU`` matches the numeric SID that was installed, while two distinct accounts that share a
    RID (a machine and a foreign domain RID-500) never collapse. Type, flags, rights and object
    fields are compared exactly.
    """
    fields = ace[1:-1].split(";")
    if len(fields) != 6:
        return ace
    if _NUMERIC_SID.fullmatch(fields[5]):
        fields[5] = native.canonical_trustee(fields[5])
    return "(" + ";".join(fields) + ")"


def canonical_aces(native, sddl: str) -> list[str]:
    return [canonical_ace(native, ace) for ace in split_dacl(sddl)[1]]


def without_ace(sddl: str, ace: str, native=None) -> str:
    """Remove the first ACE equal to ``ace``; with ``native`` the trustee is compared canonically."""
    control, aces = split_dacl(sddl)
    key = (lambda text: canonical_ace(native, text)) if native is not None else (lambda text: text)
    wanted = key(ace)
    for index, present in enumerate(aces):
        if key(present) == wanted:
            del aces[index]
            return join_dacl(control, aces)
    raise ValueError("ACE absent")


def ace_present(native, sddl: str, ace: str) -> bool:
    wanted = canonical_ace(native, ace)
    return wanted in canonical_aces(native, sddl)


def restoration(native, path, dacl: str, owner: str) -> dict:
    """Compare the live descriptor with a recorded one: control and protection flags, the ordered
    ACEs (trustees compared canonically) and the owner. Booleans only, so it is safe to report."""
    control, aces = split_dacl(dacl)
    now_control, now_aces = split_dacl(native.read_dacl(path))
    result = {"control": control == now_control,
              "aces": [canonical_ace(native, ace) for ace in aces]
                      == [canonical_ace(native, ace) for ace in now_aces],
              "owner": owner == native.read_owner(path)}
    result["verified"] = all(result.values())
    return result


def _inherited(ace: str) -> bool:
    fields = ace[1:-1].split(";")
    return len(fields) == 6 and "ID" in re.findall("..", fields[1])


def _spelled(native, sddl: str) -> list[str]:
    return canonical_aces(native, sddl)


def _shown(aces: list[str]) -> list[str]:
    return [redact(ace) for ace in aces]


def installation_components(native, before: str, after: str, ace: str,
                            owner_before: str, owner_after: str) -> dict:
    """Per-component facts of one descriptor installation, safe to print: the DACL control and
    protection flags, the ordered ACEs (trustees canonical, machine SIDs redacted) with the count,
    explicit and inherited tallies and any ACE that is unexpected or missing, and the owner.
    ``installed_exactly`` is true only if the control is unchanged, the ACEs are exactly the new
    one first and the old ones after it in their order, and the owner is unchanged."""
    control_before, control_after = split_dacl(before)[0], split_dacl(after)[0]
    old, new = _spelled(native, before), _spelled(native, after)
    expected = [canonical_ace(native, ace), *old]
    unexpected = Counter(new) - Counter(expected)
    missing = Counter(expected) - Counter(new)
    components = {
        "control": {"before": control_before, "after": control_after,
                    "unchanged": control_before == control_after},
        "aces": {"expected": _shown(expected), "before": _shown(old), "after": _shown(new),
                 "count_before": len(old), "count_expected": len(expected), "count_after": len(new),
                 "explicit_before": sum(not _inherited(item) for item in old),
                 "explicit_after": sum(not _inherited(item) for item in new),
                 "inherited_before": sum(_inherited(item) for item in old),
                 "inherited_after": sum(_inherited(item) for item in new),
                 "new_ace_first": bool(new) and new[0] == expected[0],
                 "exact": new == expected,
                 "unexpected_after": _shown(sorted(unexpected.elements())),
                 "missing_after": _shown(sorted(missing.elements()))},
        "owner": {"before": redact(owner_before), "after": redact(owner_after),
                  "unchanged": owner_before == owner_after}}
    components["installed_exactly"] = (components["control"]["unchanged"]
                                       and components["aces"]["exact"]
                                       and components["owner"]["unchanged"])
    return components


def restoration_components(native, path, dacl: str, owner: str) -> dict:
    """Per-component facts of a restoration check (see ``restoration``), safe to print."""
    control, aces = split_dacl(dacl)
    now_control, now_aces = split_dacl(native.read_dacl(path))
    expected = [canonical_ace(native, item) for item in aces]
    now = [canonical_ace(native, item) for item in now_aces]
    now_owner = native.read_owner(path)
    components = {
        "control": {"expected": control, "now": now_control, "same": control == now_control},
        "aces": {"expected": _shown(expected), "now": _shown(now),
                 "count_expected": len(expected), "count_now": len(now), "same": expected == now,
                 "unexpected_now": _shown(sorted((Counter(now) - Counter(expected)).elements())),
                 "missing_now": _shown(sorted((Counter(expected) - Counter(now)).elements()))},
        "owner": {"expected": redact(owner), "now": redact(now_owner), "same": owner == now_owner}}
    components["verified"] = (components["control"]["same"] and components["aces"]["same"]
                              and components["owner"]["same"])
    return components


def components_message(label: str, components: dict) -> str:
    return label + ": " + json.dumps(components, sort_keys=True)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


WAIT_OBJECT_0, WAIT_TIMEOUT, WAIT_FAILED = 0, 0x102, 0xFFFFFFFF
STILL_ACTIVE = 259
SE_PRIVILEGE_ENABLED = 0x2
PRIVILEGE_STATE_MASK = 0x7      # default-enabled, enabled, removed; "used for access" changes on use


class PrivilegeRestorationError(NativeError):
    """The process token's privilege inventory could not be shown unchanged after a scope."""

    def __init__(self, details: dict):
        super().__init__("privilege_restoration", None)
        self.details = details


def privilege_state(api) -> dict:
    return {name: attributes & PRIVILEGE_STATE_MASK
            for name, attributes in api.privilege_attributes().items()}


@contextmanager
def privilege_scope(api, name: str):
    """Enable ``name`` for the body and put the token back exactly as it was.

    The exact original state of every privilege is captured first; afterwards the privilege is set
    back to what it was (enabled stays enabled, disabled returns to disabled), the whole inventory
    is read back and compared, and a restoration that cannot be shown raises
    ``PrivilegeRestorationError`` even when the body failed (the body's error is its context).
    ``api`` offers ``privilege_attributes() -> {name: attributes}`` and
    ``adjust_privilege(name, attributes)``.
    """
    before = privilege_state(api)
    if name not in before:
        raise NativeError("privilege_absent", None)
    original = before[name]
    try:
        api.adjust_privilege(name, SE_PRIVILEGE_ENABLED)
        if not privilege_state(api).get(name, 0) & SE_PRIVILEGE_ENABLED:
            raise NativeError("AdjustTokenPrivileges", None)
        yield
    finally:
        problems, after = [], None
        try:
            api.adjust_privilege(name, original & SE_PRIVILEGE_ENABLED)
        except Exception:
            problems.append("restore_failed")
        try:
            after = privilege_state(api)
        except Exception:
            problems.append("readback_failed")
        if after is not None and after != before:
            problems.append("inventory_changed")
        if problems:
            raise PrivilegeRestorationError({
                "privilege": name, "problems": problems,
                "changed": sorted(key for key in (set(before) | set(after or {}))
                                  if (after or {}).get(key) != before.get(key))})


def _wait_name(status) -> str:
    return {WAIT_OBJECT_0: "signaled", WAIT_TIMEOUT: "timeout",
            WAIT_FAILED: "failed"}.get(status, "unexpected")


def run_contained(api, timeout: float, grace_ms: int = 30000):
    """Start one process inside its own kill-on-close job, wait for it, and report what is KNOWN.

    ``api`` supplies ``create_job``, ``start`` (suspended), ``assign``, ``resume``, ``wait``,
    ``terminate_job``, ``terminate_process``, ``exit_code``, ``active_processes``, ``close`` and
    ``pause`` (each failure carries its Windows error). ``completed`` is true only when the process
    was contained and resumed, exited inside the timeout with a real exit code (never the
    ``STILL_ACTIVE`` placeholder), and left no descendant behind. ``cleanup_verified`` additionally
    requires the process signaled, the job empty and every handle closed; otherwise the handles
    are returned so the caller keeps ownership of them. ``child_stopped`` is the one fact a caller
    may rely on before it restores or removes anything the child could still touch: true only when
    nothing was started, or the process was seen signaled and the job holds no process (a failed
    handle close alone does not change it). Returns ``(report, retained_handles)``.
    """
    report = {"launched": False, "completed": False, "exit_code": None, "timed_out": False,
              "wait_failed": False, "still_active": False, "terminated": False,
              "final_wait": None, "descendants_terminated": False, "job_active_processes": None,
              "cleanup_verified": False, "handles_retained": False, "winerror": None,
              "child_stopped": False, "terminate_errors": [], "errors": []}

    def note(api_name, code):
        report["errors"].append({"api": api_name, "code": code})

    def terminate(job, process, contained):
        # Ending a job ends only the processes assigned to it: a child whose assignment failed or
        # is unknown is owned but outside the job, so it is terminated directly.
        if contained:
            ok, error = api.terminate_job(job, 1)
            if not ok:
                report["terminate_errors"].append({"api": "TerminateJobObject", "code": error})
        else:
            ok = False
        if not ok:
            ok, error = api.terminate_process(process, 1)
            if not ok:
                report["terminate_errors"].append({"api": "TerminateProcess", "code": error})
        report["terminated"] = report["terminated"] or ok

    job, error = api.create_job()
    if job is None:
        report["winerror"] = error
        report["child_stopped"] = True
        note("CreateJobObject", error)
        return report, []
    held = [job]
    process, thread, error = api.start()
    if process is None:
        report["winerror"] = error
        report["child_stopped"] = True
        note("CreateProcessAsUserW", error)
        if not api.close(job):
            note("CloseHandle", None)
            report["handles_retained"] = True
            return report, held
        return report, []
    held += [thread, process]
    contained = False
    try:
        started = False
        contained, error = api.assign(job, process)
        if not contained:
            note("AssignProcessToJobObject", error)
        else:
            ok, error = api.resume(thread)
            if not ok:
                note("ResumeThread", error)
            else:
                started = True
        report["launched"] = started
        signaled = False
        if started:
            status, error = api.wait(process, int(timeout * 1000))
            if status == WAIT_OBJECT_0:
                signaled = True
            elif status == WAIT_TIMEOUT:
                report["timed_out"] = True
            else:
                report["wait_failed"] = True
                note("WaitForSingleObject", error)
        if not signaled:
            terminate(job, process, contained)
            status, error = api.wait(process, grace_ms)
            report["final_wait"] = _wait_name(status)
            signaled = status == WAIT_OBJECT_0
            if not signaled:
                note("WaitForSingleObject", error)
        if signaled:
            ok, code, error = api.exit_code(process)
            if not ok:
                note("GetExitCodeProcess", error)
            elif code == STILL_ACTIVE:
                report["still_active"] = True
            else:
                report["exit_code"] = code
        count, error = api.active_processes(job)
        if count is None:
            note("QueryInformationJobObject", error)
        elif count > 0:
            report["descendants_terminated"] = True
            terminate(job, process, contained)
            remaining = grace_ms
            while count and remaining > 0:
                api.pause(100)
                remaining -= 100
                count, error = api.active_processes(job)
                if count is None:
                    note("QueryInformationJobObject", error)
                    break
        report["job_active_processes"] = count
        report["child_stopped"] = bool(signaled and count == 0)
        report["completed"] = (started and not report["timed_out"] and not report["wait_failed"]
                               and report["exit_code"] is not None
                               and not report["descendants_terminated"])
        report["cleanup_verified"] = (signaled and not report["still_active"] and count == 0)
    except BaseException:
        try:
            terminate(job, process, contained)
        except Exception:
            pass
        api.retain(held)
        raise
    if not report["cleanup_verified"]:
        report["handles_retained"] = True
        return report, held
    left = [handle for handle in held if not api.close(handle)]
    if left:
        note("CloseHandle", None)
        report["cleanup_verified"], report["completed"] = False, False
        report["handles_retained"] = True
    return report, left


class _ProcessApi:
    """The kernel seam ``run_contained`` drives, over one restricted primary token."""

    def __init__(self, native, primary, argv, cwd):
        self.native, self.primary, self.argv, self.cwd = native, primary, argv, cwd
        self.quota_enabled, self.restoration_error = False, None
        c, w = native.c, native.w

        class StartupInfo(c.Structure):
            _fields_ = [("cb", w.DWORD), ("lpReserved", w.LPWSTR), ("lpDesktop", w.LPWSTR),
                        ("lpTitle", w.LPWSTR), ("dwX", w.DWORD), ("dwY", w.DWORD),
                        ("dwXSize", w.DWORD), ("dwYSize", w.DWORD), ("dwXCountChars", w.DWORD),
                        ("dwYCountChars", w.DWORD), ("dwFillAttribute", w.DWORD), ("dwFlags", w.DWORD),
                        ("wShowWindow", w.WORD), ("cbReserved2", w.WORD), ("lpReserved2", c.c_void_p),
                        ("hStdInput", c.c_void_p), ("hStdOutput", c.c_void_p), ("hStdError", c.c_void_p)]

        class ProcessInformation(c.Structure):
            _fields_ = [("hProcess", c.c_void_p), ("hThread", c.c_void_p),
                        ("dwProcessId", w.DWORD), ("dwThreadId", w.DWORD)]

        class BasicLimit(c.Structure):
            _fields_ = [("PerProcessUserTimeLimit", c.c_longlong), ("PerJobUserTimeLimit", c.c_longlong),
                        ("LimitFlags", w.DWORD), ("MinimumWorkingSetSize", c.c_size_t),
                        ("MaximumWorkingSetSize", c.c_size_t), ("ActiveProcessLimit", w.DWORD),
                        ("Affinity", c.c_size_t), ("PriorityClass", w.DWORD), ("SchedulingClass", w.DWORD)]

        class IoCounters(c.Structure):
            _fields_ = [(name, c.c_ulonglong) for name in (
                "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

        class ExtendedLimit(c.Structure):
            _fields_ = [("BasicLimitInformation", BasicLimit), ("IoInfo", IoCounters),
                        ("ProcessMemoryLimit", c.c_size_t), ("JobMemoryLimit", c.c_size_t),
                        ("PeakProcessMemoryUsed", c.c_size_t), ("PeakJobMemoryUsed", c.c_size_t)]

        class Accounting(c.Structure):
            _fields_ = [("TotalUserTime", c.c_longlong), ("TotalKernelTime", c.c_longlong),
                        ("ThisPeriodTotalUserTime", c.c_longlong), ("ThisPeriodTotalKernelTime", c.c_longlong),
                        ("TotalPageFaultCount", w.DWORD), ("TotalProcesses", w.DWORD),
                        ("ActiveProcesses", w.DWORD), ("TotalTerminatedProcesses", w.DWORD)]
        self._types = (StartupInfo, ProcessInformation, ExtendedLimit, Accounting)

    def _error(self):
        return self.native.c.get_last_error()

    def create_job(self):
        c, kernel = self.native.c, self.native.kernel
        extended = self._types[2]()
        extended.BasicLimitInformation.LimitFlags = 0x2000      # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        c.set_last_error(0)
        job = kernel.CreateJobObjectW(None, None)
        if not job:
            return None, self._error()
        c.set_last_error(0)
        if not kernel.SetInformationJobObject(job, 9, c.byref(extended), c.sizeof(extended)):
            error = self._error()
            kernel.CloseHandle(job)
            return None, error
        return job, None

    def _create(self):
        c, native = self.native.c, self.native
        info, created = self._types[0](), self._types[1]()
        info.cb = c.sizeof(info)
        import subprocess
        command = c.create_unicode_buffer(subprocess.list2cmdline(self.argv))
        c.set_last_error(0)
        started = native.advapi.CreateProcessAsUserW(
            self.primary, None, command, None, None, False, 0x08000004, None, str(self.cwd),
            c.byref(info), c.byref(created))
        if not started:
            return None, None, self._error()
        return created.hProcess, created.hThread, None

    def start(self):
        attempt = self._create()
        if attempt[0] is None and attempt[2] == 1314:
            try:
                with self.native.privilege_enabled("SeIncreaseQuotaPrivilege"):
                    self.quota_enabled = True
                    attempt = self._create()
            except PrivilegeRestorationError as error:
                self.restoration_error = error
            except NativeError:
                pass
        return attempt

    def assign(self, job, process):
        self.native.c.set_last_error(0)
        ok = bool(self.native.kernel.AssignProcessToJobObject(job, process))
        return ok, None if ok else self._error()

    def resume(self, thread):
        self.native.c.set_last_error(0)
        previous = self.native.kernel.ResumeThread(thread)
        ok = previous != 0xFFFFFFFF
        return ok, None if ok else self._error()

    def wait(self, handle, milliseconds):
        self.native.c.set_last_error(0)
        status = self.native.kernel.WaitForSingleObject(handle, milliseconds)
        return status, self._error() if status == WAIT_FAILED else None

    def terminate_job(self, job, code):
        self.native.c.set_last_error(0)
        ok = bool(self.native.kernel.TerminateJobObject(job, code))
        return ok, None if ok else self._error()

    def terminate_process(self, process, code):
        self.native.c.set_last_error(0)
        ok = bool(self.native.kernel.TerminateProcess(process, code))
        return ok, None if ok else self._error()

    def exit_code(self, process):
        code = self.native.w.DWORD()
        self.native.c.set_last_error(0)
        ok = bool(self.native.kernel.GetExitCodeProcess(process, self.native.c.byref(code)))
        return ok, code.value if ok else None, None if ok else self._error()

    def active_processes(self, job):
        c, kernel = self.native.c, self.native.kernel
        accounting = self._types[3]()
        c.set_last_error(0)
        if not kernel.QueryInformationJobObject(job, 1, c.byref(accounting), c.sizeof(accounting), None):
            return None, self._error()
        return accounting.ActiveProcesses, None

    def close(self, handle):
        return bool(self.native.kernel.CloseHandle(handle))

    def pause(self, milliseconds):
        time.sleep(milliseconds / 1000)

    def retain(self, handles):
        self.native.retained_handles.extend(handles)


class WindowsNative:
    """ctypes access to the descriptor, token, access-check and volume APIs (Windows only)."""

    def __init__(self):
        import ctypes
        from ctypes import wintypes
        if os.name != "nt":
            raise NativeError("platform", None)
        self.c, self.w = ctypes, wintypes
        self.retained_handles: list = []
        self.advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        v, p, d = ctypes.c_void_p, ctypes.POINTER, wintypes.DWORD
        for library, name, argtypes, restype in (
                (self.kernel, "GetCurrentProcess", (), v),
                (self.kernel, "CloseHandle", (v,), wintypes.BOOL),
                (self.kernel, "LocalFree", (v,), v),
                (self.kernel, "GetVolumePathNameW", (wintypes.LPCWSTR, wintypes.LPWSTR, d), wintypes.BOOL),
                (self.kernel, "GetVolumeInformationW",
                 (wintypes.LPCWSTR, wintypes.LPWSTR, d, p(d), p(d), p(d), wintypes.LPWSTR, d), wintypes.BOOL),
                (self.kernel, "CreateDirectoryW", (wintypes.LPCWSTR, v), wintypes.BOOL),
                (self.kernel, "WaitForSingleObject", (v, d), d),
                (self.kernel, "GetExitCodeProcess", (v, p(d)), wintypes.BOOL),
                (self.kernel, "TerminateProcess", (v, wintypes.UINT), wintypes.BOOL),
                (self.kernel, "CreateJobObjectW", (v, wintypes.LPCWSTR), v),
                (self.kernel, "SetInformationJobObject", (v, ctypes.c_int, v, d), wintypes.BOOL),
                (self.kernel, "AssignProcessToJobObject", (v, v), wintypes.BOOL),
                (self.kernel, "TerminateJobObject", (v, wintypes.UINT), wintypes.BOOL),
                (self.kernel, "QueryInformationJobObject", (v, ctypes.c_int, v, d, p(d)), wintypes.BOOL),
                (self.kernel, "ResumeThread", (v,), d),
                (self.advapi, "LookupPrivilegeValueW", (wintypes.LPCWSTR, wintypes.LPCWSTR, v), wintypes.BOOL),
                (self.advapi, "AdjustTokenPrivileges", (v, wintypes.BOOL, v, d, v, v), wintypes.BOOL),
                (self.advapi, "CreateProcessAsUserW",
                 (v, wintypes.LPCWSTR, wintypes.LPWSTR, v, v, wintypes.BOOL, d, v, wintypes.LPCWSTR, v, v),
                 wintypes.BOOL),
                (self.advapi, "OpenProcessToken", (v, d, p(v)), wintypes.BOOL),
                (self.advapi, "GetTokenInformation", (v, ctypes.c_int, v, d, p(d)), wintypes.BOOL),
                (self.advapi, "LookupPrivilegeNameW", (wintypes.LPCWSTR, v, wintypes.LPWSTR, p(d)), wintypes.BOOL),
                (self.advapi, "CreateRestrictedToken", (v, d, d, v, d, v, d, v, p(v)), wintypes.BOOL),
                (self.advapi, "DuplicateTokenEx", (v, d, v, ctypes.c_int, ctypes.c_int, p(v)), wintypes.BOOL),
                (self.advapi, "SetThreadToken", (v, v), wintypes.BOOL),
                (self.advapi, "RevertToSelf", (), wintypes.BOOL),
                (self.advapi, "AccessCheck", (v, v, d, v, v, p(d), p(d), p(wintypes.BOOL)), wintypes.BOOL),
                (self.advapi, "GetFileSecurityW", (wintypes.LPCWSTR, d, v, d, p(d)), wintypes.BOOL),
                (self.advapi, "GetNamedSecurityInfoW", (wintypes.LPCWSTR, ctypes.c_int, d, v, v, v, v, p(v)), d),
                (self.advapi, "SetNamedSecurityInfoW", (wintypes.LPWSTR, ctypes.c_int, d, v, v, v, v), d),
                (self.advapi, "GetSecurityDescriptorDacl", (v, p(wintypes.BOOL), p(v), p(wintypes.BOOL)), wintypes.BOOL),
                (self.advapi, "ConvertStringSecurityDescriptorToSecurityDescriptorW",
                 (wintypes.LPCWSTR, d, p(v), v), wintypes.BOOL),
                (self.advapi, "ConvertSecurityDescriptorToStringSecurityDescriptorW",
                 (v, d, d, p(wintypes.LPWSTR), v), wintypes.BOOL)):
            function = getattr(library, name)
            function.argtypes, function.restype = argtypes, restype

    def _fail(self, api: str):
        raise NativeError(api, self.c.get_last_error())

    def _ok(self, api: str, result) -> None:
        if not result:
            self._fail(api)

    # ---- descriptor -------------------------------------------------------------------

    def _encode(self, descriptor, information: int) -> str:
        text = self.w.LPWSTR()
        self._ok("ConvertSecurityDescriptorToStringSecurityDescriptorW",
                 self.advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                     descriptor, 1, information, self.c.byref(text), None))
        try:
            return text.value
        finally:
            self.kernel.LocalFree(self.c.cast(text, self.c.c_void_p))

    def _named_descriptor(self, path, information: int) -> str:
        descriptor = self.c.c_void_p()
        code = self.advapi.GetNamedSecurityInfoW(str(path), 1, information, None, None, None, None,
                                                 self.c.byref(descriptor))
        if code:
            raise NativeError("GetNamedSecurityInfoW", code)
        try:
            return self._encode(descriptor, information)
        finally:
            self.kernel.LocalFree(descriptor)

    def canonical_trustee(self, sid: str) -> str:
        """The spelling of one numeric SID in this machine's DACL text; no account lookup."""
        cache = self.__dict__.setdefault("_trustees", {})
        if sid not in cache:
            descriptor = self.c.c_void_p()
            self._ok("ConvertStringSecurityDescriptorToSecurityDescriptorW",
                     self.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                         "D:(D;;DCLC;;;" + sid + ")", 1, self.c.byref(descriptor), None))
            try:
                text = self._encode(descriptor, 4)
            finally:
                self.kernel.LocalFree(descriptor)
            match = re.fullmatch(r"D:\(D;;DCLC;;;([^;()]+)\)", text)
            if match is None:
                raise NativeError("trustee encoding", None)
            cache[sid] = match.group(1)
        return cache[sid]

    def read_dacl(self, path) -> str:
        return self._named_descriptor(Path(path).resolve(strict=True), 4)

    def read_owner(self, path) -> str:
        text = self._named_descriptor(Path(path).resolve(strict=True), 1)
        if not text.startswith("O:"):
            raise NativeError("owner encoding", None)
        return text

    def apply_dacl(self, path, sddl: str, protection: str = "auto") -> None:
        """Write the DACL. ``auto`` marks the DACL protected if the control says ``P`` and
        unprotected otherwise; ``none`` sends neither protection flag (observation only)."""
        control, _ = split_dacl(sddl)
        if protection not in ("auto", "none"):
            raise ValueError("protection must be 'auto' or 'none'")
        protection = (0 if protection == "none"
                      else 0x80000000 if "P" in control else 0x20000000)
        descriptor = self.c.c_void_p()
        self._ok("ConvertStringSecurityDescriptorToSecurityDescriptorW",
                 self.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                     sddl, 1, self.c.byref(descriptor), None))
        try:
            present, defaulted, dacl = self.w.BOOL(), self.w.BOOL(), self.c.c_void_p()
            self._ok("GetSecurityDescriptorDacl", self.advapi.GetSecurityDescriptorDacl(
                descriptor, self.c.byref(present), self.c.byref(dacl), self.c.byref(defaulted)))
            if not present.value:
                raise NativeError("GetSecurityDescriptorDacl", None)
            code = self.advapi.SetNamedSecurityInfoW(str(Path(path).resolve(strict=True)), 1, 4 | protection,
                                                     None, None, dacl, None)
            if code:
                raise NativeError("SetNamedSecurityInfoW", code)
        finally:
            self.kernel.LocalFree(descriptor)

    # ---- token ------------------------------------------------------------------------

    def privilege_luid(self, name: str) -> bytes:
        luid = self.c.create_string_buffer(8)
        self._ok("LookupPrivilegeValueW", self.advapi.LookupPrivilegeValueW(None, name, luid))
        return luid.raw

    def _restrict(self, process, delete):
        """A restricted copy of ``process``: ``delete=None`` removes every privilege
        (``DISABLE_MAX_PRIVILEGE``); a tuple of names removes exactly those privileges."""
        restricted = self.c.c_void_p()
        if delete is None:
            self._ok("CreateRestrictedToken", self.advapi.CreateRestrictedToken(
                process, 0x1, 0, None, 0, None, 0, None, self.c.byref(restricted)))
        else:
            names = tuple(delete)
            entries = b"".join(self.privilege_luid(name) + struct.pack("<I", 0) for name in names)
            buffer = self.c.create_string_buffer(entries, max(len(entries), 1))
            self._ok("CreateRestrictedToken", self.advapi.CreateRestrictedToken(
                process, 0, 0, None, len(names), buffer, 0, None, self.c.byref(restricted)))
        return restricted

    @contextmanager
    def impersonation_token(self, stripped: bool, delete=()):
        """An impersonation copy of the process token: unchanged, with every privilege removed
        (``stripped``), or with exactly the named privileges removed (``delete``)."""
        process = self.c.c_void_p()
        self._ok("OpenProcessToken", self.advapi.OpenProcessToken(
            self.kernel.GetCurrentProcess(), 0x1 | 0x2 | 0x4 | 0x8, self.c.byref(process)))
        opened = [process]
        try:
            source = process
            if stripped or delete:
                source = self._restrict(process, None if stripped else delete)
                opened.append(source)
            impersonation = self.c.c_void_p()
            self._ok("DuplicateTokenEx", self.advapi.DuplicateTokenEx(
                source, 0x1 | 0x2 | 0x4 | 0x8, None, 2, 2, self.c.byref(impersonation)))
            opened.append(impersonation)
            yield impersonation
        finally:
            for handle in opened:
                self.kernel.CloseHandle(handle)

    @contextmanager
    def impersonating(self, token):
        self._ok("SetThreadToken", self.advapi.SetThreadToken(None, token))
        try:
            yield
        finally:
            self._ok("RevertToSelf", self.advapi.RevertToSelf())

    def privilege_attributes(self) -> dict:
        """Every privilege of this process token with its exact attribute bits."""
        process = self.c.c_void_p()
        self._ok("OpenProcessToken", self.advapi.OpenProcessToken(
            self.kernel.GetCurrentProcess(), 0x8, self.c.byref(process)))
        try:
            size = self.w.DWORD()
            self.advapi.GetTokenInformation(process, 3, None, 0, self.c.byref(size))
            buffer = self.c.create_string_buffer(size.value)
            self._ok("GetTokenInformation", self.advapi.GetTokenInformation(
                process, 3, buffer, size, self.c.byref(size)))
            (count,) = struct.unpack_from("<I", buffer.raw, 0)
            found = {}
            for index in range(count):
                offset = 4 + 12 * index
                low, high, attributes = struct.unpack_from("<IiI", buffer.raw, offset)
                luid = self.c.create_string_buffer(buffer.raw[offset:offset + 8], 8)
                length = self.w.DWORD(128)
                name = self.c.create_unicode_buffer(128)
                self._ok("LookupPrivilegeNameW", self.advapi.LookupPrivilegeNameW(
                    None, luid, name, self.c.byref(length)))
                found[name.value] = attributes
            return found
        finally:
            self.kernel.CloseHandle(process)

    def privileges(self) -> list[tuple[str, bool]]:
        return [(name, bool(attributes & SE_PRIVILEGE_ENABLED))
                for name, attributes in self.privilege_attributes().items()]

    def adjust_privilege(self, name: str, attributes: int) -> None:
        process = self.c.c_void_p()
        self._ok("OpenProcessToken", self.advapi.OpenProcessToken(
            self.kernel.GetCurrentProcess(), 0x20 | 0x8, self.c.byref(process)))
        try:
            state = self.c.create_string_buffer(
                struct.pack("<I", 1) + self.privilege_luid(name) + struct.pack("<I", attributes))
            self.c.set_last_error(0)
            self._ok("AdjustTokenPrivileges", self.advapi.AdjustTokenPrivileges(
                process, False, state, 0, None, None))
            if self.c.get_last_error() == 1300:
                raise NativeError("AdjustTokenPrivileges", 1300)
        finally:
            self.kernel.CloseHandle(process)

    def access_mask(self, path, stripped: bool) -> int:
        """Rights ``AccessCheck`` grants this token on ``path`` under its current DACL."""
        target = str(Path(path).resolve(strict=True))
        size = self.w.DWORD()
        self.advapi.GetFileSecurityW(target, 1 | 2 | 4, None, 0, self.c.byref(size))
        descriptor = self.c.create_string_buffer(size.value)
        self._ok("GetFileSecurityW", self.advapi.GetFileSecurityW(
            target, 1 | 2 | 4, descriptor, size, self.c.byref(size)))
        mapping = (self.w.DWORD * 4)(0x120089, 0x120116, 0x1200A0, 0x1F01FF)
        privilege_set = self.c.create_string_buffer(1024)
        privilege_length, granted, status = self.w.DWORD(1024), self.w.DWORD(), self.w.BOOL()
        with self.impersonation_token(stripped) as token:
            self._ok("AccessCheck", self.advapi.AccessCheck(
                descriptor, token, 0x02000000, mapping, privilege_set, self.c.byref(privilege_length),
                self.c.byref(granted), self.c.byref(status)))
        return granted.value if status.value else 0

    def privilege_enabled(self, name: str):
        """Enable one privilege that is present in this process token, and put the token back
        exactly as it was (see ``privilege_scope``). Process-local; no host or account setting
        changes."""
        return privilege_scope(self, name)

    def run_with_restricted_primary_token(self, argv: list[str], cwd, timeout: float = 900.0) -> dict:
        """Start ``argv`` as a new process whose PRIMARY token is a copy of this process token with
        every privilege removed, inside an owned kill-on-close job, wait for it, and report what is
        known (see ``run_contained``).

        This is a supported-context launcher for tests: the child's original process token is
        the restricted token (not a thread impersonating one), so what the child does is what a
        process started without the bypass privileges does. Handles are not inherited and no
        console is shown; a child reports through files it is given. If Windows refuses the
        launch with ``ERROR_PRIVILEGE_NOT_HELD`` the disabled ``SeIncreaseQuotaPrivilege`` of this
        process is enabled for the launch only and the launch is retried once; the token's
        privilege inventory must then read back unchanged or the report says it did not.
        """
        process = self.c.c_void_p()
        self._ok("OpenProcessToken", self.advapi.OpenProcessToken(
            self.kernel.GetCurrentProcess(), 0x1 | 0x2 | 0x4 | 0x8, self.c.byref(process)))
        opened = [process]
        try:
            restricted = self._restrict(process, None)
            opened.append(restricted)
            primary = self.c.c_void_p()
            self._ok("DuplicateTokenEx", self.advapi.DuplicateTokenEx(
                restricted, 0xF01FF, None, 2, 1, self.c.byref(primary)))
            opened.append(primary)
            api = _ProcessApi(self, primary, argv, cwd)
            report, retained = run_contained(api, timeout)
        finally:
            for handle in opened:
                if handle.value:
                    self.kernel.CloseHandle(handle)
        self.retained_handles.extend(retained)
        report["increase_quota_enabled_for_launch"] = api.quota_enabled
        if api.restoration_error is not None:
            report["privilege_restoration"] = {"verified": False, **api.restoration_error.details}
            report["cleanup_verified"], report["completed"] = False, False
        elif api.quota_enabled:
            report["privilege_restoration"] = {"verified": True}
        return report

    def filesystem(self, path) -> str:
        volume = self.c.create_unicode_buffer(260)
        self._ok("GetVolumePathNameW", self.kernel.GetVolumePathNameW(
            str(Path(path).resolve(strict=True)), volume, 260))
        name = self.c.create_unicode_buffer(64)
        self._ok("GetVolumeInformationW", self.kernel.GetVolumeInformationW(
            volume.value, None, 0, None, None, None, name, 64))
        return name.value

    def try_create_directory(self, path, stripped: bool, route: str = "os.mkdir", delete=(),
                             impersonate: bool = False) -> dict:
        """Try to create ``path``; remove it again if it was created and verify the removal.
        ``stripped`` removes every privilege from an impersonation copy, ``delete`` only the named
        ones; neither changes the process token itself."""
        target = Path(path)

        def attempt() -> dict:
            if route == "CreateDirectoryW":
                if self.kernel.CreateDirectoryW(str(target), None):
                    return {"created": True}
                return {"created": False, "winerror": self.c.get_last_error()}
            try:
                os.mkdir(target)
                return {"created": True}
            except OSError as error:
                return {"created": False, "winerror": getattr(error, "winerror", None)}
        if stripped or delete or impersonate:
            with self.impersonation_token(stripped, delete) as token, self.impersonating(token):
                outcome = attempt()
        else:
            outcome = attempt()
        if outcome["created"]:
            try:
                os.rmdir(target)
            except OSError as error:
                outcome["removal_error"] = getattr(error, "winerror", None) or error.errno
            outcome["removed"] = not target.exists()
        return outcome

    def try_create_file(self, path, stripped: bool) -> dict:
        target = Path(path)

        def attempt() -> dict:
            try:
                with open(target, "xb"):
                    pass
                return {"created": True}
            except OSError as error:
                return {"created": False, "winerror": getattr(error, "winerror", None)}
        if stripped:
            with self.impersonation_token(True) as token, self.impersonating(token):
                outcome = attempt()
        else:
            outcome = attempt()
        if outcome["created"]:
            try:
                target.unlink()
            except OSError as error:
                outcome["removal_error"] = getattr(error, "winerror", None) or error.errno
            outcome["removed"] = not target.exists()
        return outcome


def deny_by_descriptor(native, path, sid: str, rights: str = PARENT_RIGHTS, protection: str = "auto") -> dict:
    """Install ``(D;;rights;;;sid)`` first in the DACL of ``path`` without any account lookup.

    ``installed_exactly`` is true only if the read-back keeps the control and protection flags,
    holds the new ACE first and the old ACEs after it in their old order (trustees compared
    canonically), and leaves the owner unchanged. ``components`` carries the sanitized
    per-component facts behind that boolean.
    """
    before_owner = native.read_owner(path)
    before = native.read_dacl(path)
    ace = "(D;;%s;;;%s)" % (rights, sid)
    if protection == "auto":
        native.apply_dacl(path, with_ace_first(before, ace))
    else:
        native.apply_dacl(path, with_ace_first(before, ace), protection)
    after = native.read_dacl(path)
    owner_after = native.read_owner(path)
    components = installation_components(native, before, after, ace, before_owner, owner_after)
    return {"ace": ace, "before": before, "after": after, "owner_before": before_owner,
            "owner_after": owner_after, "installed_exactly": components["installed_exactly"],
            "components": components}


def deny_present(native, path, sid: str, rights: str = PARENT_RIGHTS) -> bool:
    return ace_present(native, native.read_dacl(path), "(D;;%s;;;%s)" % (rights, sid))


def remove_descriptor_deny(native, path, sid: str, rights: str = PARENT_RIGHTS) -> bool:
    """Remove the one ACE ``deny_by_descriptor`` added, wherever Windows spells its trustee as an
    alias, and report whether the result is exactly the old DACL minus that ACE.

    Raises ``ValueError`` if no such ACE is present. True means the ACE is gone, every other ACE
    is still present in its order, the control and protection flags are unchanged and the owner is
    unchanged; any drift is reported as False rather than hidden.
    """
    ace = "(D;;%s;;;%s)" % (rights, sid)
    owner = native.read_owner(path)
    current = native.read_dacl(path)
    updated = without_ace(current, ace, native)
    native.apply_dacl(path, updated)
    after = native.read_dacl(path)
    return (split_dacl(after)[0] == split_dacl(current)[0]
            and canonical_aces(native, after) == canonical_aces(native, updated)
            and native.read_owner(path) == owner)


ERROR_ACCESS_DENIED = 5
CREATION_PROBES = (("os.mkdir", "mkdir"), ("CreateDirectoryW", "mkdir_CreateDirectoryW"))


def non_denial_outcomes(report: dict) -> list:
    """Failed creations whose Windows error is not ``ERROR_ACCESS_DENIED``: a missing parent, an
    existing target, an invalid path or a resource error says nothing about the fence."""
    return [{"route": route, "token": label, "winerror": report[key][label].get("winerror")}
            for route, key in CREATION_PROBES for label in ("stripped", "full")
            if not report[key][label]["created"]
            and report[key][label].get("winerror") != ERROR_ACCESS_DENIED]


def probe_cleanup_verified(report: dict) -> bool:
    """True only if everything a probe created was verifiably removed again."""
    outcomes = [report[key][label] for _, key in CREATION_PROBES for label in ("stripped", "full")]
    outcomes += [report["file_control"][label] for label in ("stripped", "full")]
    return all(outcome.get("removed") is True for outcome in outcomes if outcome["created"])


def classify(report: dict) -> str:
    """Label a recreation outcome from a probe report; a label is an observation, not a proven cause."""
    def created(label):
        return report["mkdir"][label]["created"] or report["mkdir_CreateDirectoryW"][label]["created"]
    if created("stripped"):
        return ("DACL_GRANTS_ADD_SUBDIRECTORY" if report["access_check"]["stripped"]["add_subdirectory"]
                else "KERNEL_CREATE_IGNORES_DACL")
    if not created("full"):
        return "REFUSED_WITHOUT_ACCESS_DENIED" if non_denial_outcomes(report) else "DENIED"
    enabled = set(report["enabled_privileges"])
    if enabled & set(BYPASS_PRIVILEGES) and not report["access_check"]["full"]["add_subdirectory"]:
        return "FULL_TOKEN_CREATES_WHILE_BYPASS_PRIVILEGE_ENABLED"
    return "FULL_TOKEN_CREATES_UNEXPLAINED"


# Only a refusal for the full original process token passes. Every creation verdict is a failure;
# the privilege label records a correlation, never an established cause.
ACCEPTED_VERDICTS = ("DENIED",)


def recreation_report(native, parent, target) -> dict:
    """Sanitized facts about whether ``target`` can be created in ``parent`` (stripped first)."""
    parent, target = Path(parent), Path(target)
    privileges = native.privileges()
    report = {
        "filesystem": native.filesystem(parent),
        "enabled_privileges": sorted(name for name, enabled in privileges if enabled),
        "disabled_privileges": sorted(name for name, enabled in privileges if not enabled),
        "parent_dacl": redact(native.read_dacl(parent)),
        "access_check": {},
        "mkdir": {},
        "mkdir_CreateDirectoryW": {},
        "file_control": {},
    }
    for label, stripped in (("stripped", True), ("full", False)):
        mask = native.access_mask(parent, stripped)
        report["access_check"][label] = {"mask": "0x%X" % mask,
                                         "add_subdirectory": bool(mask & FILE_ADD_SUBDIRECTORY),
                                         "add_file": bool(mask & FILE_ADD_FILE)}
    for label, stripped in (("stripped", True), ("full", False)):
        report["mkdir"][label] = native.try_create_directory(target, stripped)
        report["mkdir_CreateDirectoryW"][label] = native.try_create_directory(target, stripped, "CreateDirectoryW")
        report["file_control"][label] = native.try_create_file(parent / "recreation-control.bin", stripped)
    report["non_denial_outcomes"] = non_denial_outcomes(report)
    report["probe_cleanup_verified"] = probe_cleanup_verified(report)
    report["verdict"] = classify(report)
    report["cause_established"] = False
    return report


def require_recreation_denied(native, parent, target) -> dict:
    """Fail unless creating ``target`` is refused with ``ERROR_ACCESS_DENIED`` for the full process
    token and for the privilege-stripped copy, by both ``os.mkdir`` and ``CreateDirectoryW``, and
    everything the probe created was removed again. Creation with the full token fails even when a
    bypass privilege is enabled; the stripped result only explains it."""
    report = recreation_report(native, parent, target)
    if report["verdict"] not in ACCEPTED_VERDICTS or not report["probe_cleanup_verified"]:
        raise AssertionError("old path recreation is not denied: " + json.dumps(report, sort_keys=True))
    return report


CANDIDATE_SHAPES = {
    "control_no_deny": "",
    "current_LC": "(D;;LC;;;{sid})",
    "DCLC": "(D;;DCLC;;;{sid})",
    "DCLCDT": "(D;;DCLCDT;;;{sid})",
    "LC_container_inherit": "(D;OICI;LC;;;{sid})",
    "wide_without_dacl_rights": "(D;;CCDCLCSWWPDT;;;{sid})",
}


def candidate_matrix(native, sid: str, make_directory) -> dict:
    """Try each deny shape on its own owned parent and report the outcomes (diagnostic only)."""
    matrix, cleanup_ok = {}, True
    for label, template in CANDIDATE_SHAPES.items():
        entry = {}
        try:
            parent = make_directory(label)
            original, owner = native.read_dacl(parent), native.read_owner(parent)
            ace = template.format(sid=sid)
            try:
                if ace:
                    native.apply_dacl(parent, with_ace_first(original, ace))
                entry["installed_dacl"] = redact(native.read_dacl(parent))
                entry["add_subdirectory_granted"] = {
                    "stripped": bool(native.access_mask(parent, True) & FILE_ADD_SUBDIRECTORY),
                    "full": bool(native.access_mask(parent, False) & FILE_ADD_SUBDIRECTORY)}
                entry["mkdir"] = {name: native.try_create_directory(parent / "child", stripped)
                                  for name, stripped in (("stripped", True), ("full", False))}
                entry["mkdir_CreateDirectoryW"] = {
                    name: native.try_create_directory(parent / "child", stripped, "CreateDirectoryW")
                    for name, stripped in (("stripped", True), ("full", False))}
                entry["probe_cleanup_verified"] = all(
                    outcome.get("removed") is True
                    for key in ("mkdir", "mkdir_CreateDirectoryW") for outcome in entry[key].values()
                    if outcome["created"])
                cleanup_ok = cleanup_ok and entry["probe_cleanup_verified"]
            finally:
                native.apply_dacl(parent, original)
                entry["restored"] = restoration(native, parent, original, owner)
                cleanup_ok = cleanup_ok and entry["restored"]["verified"]
        except Exception as error:
            entry["error"] = {"type": type(error).__name__, "code": getattr(error, "code", None)}
            cleanup_ok = False
        matrix[label] = entry
    return {"shapes": matrix, "cleanup_verified": cleanup_ok}


def probe_actual_fence_shape(native, make_directory, sid: str) -> dict:
    """The recreation report for the exact production parent deny, then a verified restoration."""
    parent = make_directory("actual_fence_shape")
    original, owner = native.read_dacl(parent), native.read_owner(parent)
    native.apply_dacl(parent, with_ace_first(original, "(D;;%s;;;%s)" % (PARENT_RIGHTS, sid)))
    try:
        report = recreation_report(native, parent, parent / "state")
    finally:
        native.apply_dacl(parent, original)
        restored = restoration(native, parent, original, owner)
    return {"report": report, "restored": restored,
            "verified": restored["verified"] and report["probe_cleanup_verified"]}


def privilege_isolation(native, parent, target) -> dict:
    """Observation only: whether creating ``target`` in ``parent`` changes when exactly one
    privilege is removed from, or exactly one privilege is kept in, an impersonation copy of the
    process token. It names which single removals turn the full token's creation into an
    ``ERROR_ACCESS_DENIED`` refusal; it establishes no cause and nothing is accepted on it."""
    parent, target = Path(parent), Path(target)
    privileges = native.privileges()
    every = sorted(name for name, _ in privileges)
    enabled = sorted(name for name, on in privileges if on)
    outcomes = {"original_process_token": native.try_create_directory(target, False),
                "impersonated_copy_unchanged": native.try_create_directory(target, False, impersonate=True),
                "impersonated_copy_all_removed": native.try_create_directory(target, True),
                "remove_only": {}, "keep_only": {}}
    for name in enabled:
        outcomes["remove_only"][name] = native.try_create_directory(target, False, delete=(name,))
        outcomes["keep_only"][name] = native.try_create_directory(
            target, False, delete=tuple(other for other in every if other != name))

    def denied(outcome):
        return not outcome["created"] and outcome.get("winerror") == ERROR_ACCESS_DENIED
    everything = [outcomes[key] for key in ("original_process_token", "impersonated_copy_unchanged",
                                            "impersonated_copy_all_removed")]
    everything += list(outcomes["remove_only"].values()) + list(outcomes["keep_only"].values())
    return {"enabled": enabled, "outcomes": outcomes,
            "single_removals_that_turn_creation_into_access_denied":
                [name for name, outcome in outcomes["remove_only"].items()
                 if denied(outcome) and outcomes["original_process_token"]["created"]],
            "single_retentions_that_still_create":
                [name for name, outcome in outcomes["keep_only"].items() if outcome["created"]],
            "probe_cleanup_verified": all(item.get("removed") is True for item in everything
                                          if item["created"]),
            "cause_established": False}


def privilege_isolation_on_fence_shape(native, make_directory, sid: str) -> dict:
    """``privilege_isolation`` on the exact production parent deny, then a verified restoration."""
    parent = make_directory("privilege_isolation")
    original, owner = native.read_dacl(parent), native.read_owner(parent)
    native.apply_dacl(parent, with_ace_first(original, "(D;;%s;;;%s)" % (PARENT_RIGHTS, sid)))
    try:
        isolation = privilege_isolation(native, parent, parent / "state")
    finally:
        native.apply_dacl(parent, original)
        restored = restoration_components(native, parent, original, owner)
    return {"isolation": isolation, "restored": restored,
            "verified": restored["verified"] and isolation["probe_cleanup_verified"]}


def installation_observation(native, sid: str, make_directory, stabilize) -> dict:
    """Observation only: install ``(D;;LC;;;sid)`` first by descriptor on an unprotected fixture
    that inherits its allows, with and without the protection flag ``apply_dacl`` normally sends,
    and on a stabilized (protected, explicit) fixture, with per-component facts for each.

    Whether an installation was exact is kept apart from whether the fixture was put back: only
    the stabilized installation gates ``stabilized_install_and_restoration_exact`` (the unprotected
    shapes are diagnostics and may be inexact), while ``restoration_verified`` is false unless EVERY
    fixture whose original descriptor was captured shows a verified restoration. A restoration that
    is unverified or raised is listed in ``restoration_unverified``; a fixture that failed before
    anything was captured has nothing to restore and is not counted."""
    result, unverified = {}, []
    for label, prepared, protection in (("unprotected_inherited_auto_flag", False, "auto"),
                                        ("unprotected_inherited_no_flag", False, "none"),
                                        ("stabilized_protected_auto_flag", True, "auto")):
        entry, captured = {}, False
        try:
            parent = make_directory(label)
            if prepared:
                stabilize(parent)
            original, owner = native.read_dacl(parent), native.read_owner(parent)
            captured = True
            entry["initial_control"] = split_dacl(original)[0]
            try:
                entry["installed"] = deny_by_descriptor(native, parent, sid, protection=protection)["components"]
            finally:
                native.apply_dacl(parent, original)
                entry["restored"] = restoration_components(native, parent, original, owner)
        except Exception as error:
            entry["error"] = {"type": type(error).__name__, "code": getattr(error, "code", None)}
        if captured:
            entry["restoration_verified"] = entry.get("restored", {}).get("verified") is True
            if not entry["restoration_verified"]:
                unverified.append(label)
        result[label] = entry
    result["stabilized_install_and_restoration_exact"] = bool(
        result["stabilized_protected_auto_flag"].get("installed", {}).get("installed_exactly")
        and result["stabilized_protected_auto_flag"].get("restored", {}).get("verified"))
    result["restoration_unverified"] = unverified
    result["restoration_verified"] = not unverified
    return result


def installation_section_verified(body: dict) -> bool:
    """The standalone installation section is clean only with an exact stabilized installation AND a
    verified restoration of every fixture that was captured; a body lacking either is not clean."""
    return bool(body.get("stabilized_install_and_restoration_exact") is True
                and body.get("restoration_verified") is True)


def child_recreation_probe(parent: str, target: str, output: str) -> int:
    """Child entry: the recreation report of the process this was started as, written to a file."""
    try:
        body = recreation_report(WindowsNative(), parent, target)
    except Exception as error:
        body = {"error": {"type": type(error).__name__, "code": getattr(error, "code", None)}}
    Path(output).write_text(json.dumps(body, sort_keys=True), encoding="utf-8")
    return 0


CHILD_VERDICTS = ("DENIED", "REFUSED_WITHOUT_ACCESS_DENIED", "FULL_TOKEN_CREATES_WHILE_BYPASS_PRIVILEGE_ENABLED",
                  "FULL_TOKEN_CREATES_UNEXPLAINED", "DACL_GRANTS_ADD_SUBDIRECTORY", "KERNEL_CREATE_IGNORES_DACL")


def launch_defects(launch: dict) -> list:
    """Why a restricted-primary launch is not an accepted, completed and cleaned-up run. Every
    launcher consumer requires this to be empty; the exit code alone is never acceptance."""
    reasons = []
    if not launch.get("launched"):
        reasons.append("launch_failed")
    if launch.get("timed_out"):
        reasons.append("timed_out")
    if launch.get("wait_failed") or launch.get("still_active"):
        reasons.append("wait_incomplete")
    if launch.get("exit_code") != 0:
        reasons.append("nonzero_or_missing_exit")
    if launch.get("completed") is not True:
        reasons.append("launch_not_completed")
    if launch.get("cleanup_verified") is not True:
        reasons.append("launch_cleanup_unverified")
    if launch.get("handles_retained"):
        reasons.append("handles_retained")
    if launch.get("privilege_restoration", {}).get("verified", True) is not True:
        reasons.append("privilege_restoration_unverified")
    if launch.get("errors"):
        reasons.append("launch_errors")
    if launch.get("child_stopped") is not True:
        reasons.append("child_stop_unestablished")
    return reasons


CHILD_REPORT_FIELDS = ("filesystem", "enabled_privileges", "disabled_privileges", "parent_dacl", "access_check",
                       "mkdir", "mkdir_CreateDirectoryW", "file_control", "non_denial_outcomes",
                       "probe_cleanup_verified", "verdict", "cause_established")


def child_evidence(launch: dict, out: Path):
    """The child's report and the reasons, if any, it is not complete evidence. A missing,
    malformed, non-object, error or incomplete report or any launch defect is a reason (the probe
    was NOT_RUN or incomplete), never a pass. Whether a report was read is decided by the parse, not
    by the parsed value, so a JSON ``null`` is a non-object report like any other."""
    reasons = launch_defects(launch)
    child, parsed = None, False
    if not out.exists():
        reasons.append("child_report_missing")
    else:
        try:
            child, parsed = json.loads(out.read_text(encoding="utf-8")), True
        except (OSError, ValueError):
            reasons.append("child_report_malformed")
    if parsed:
        if not isinstance(child, dict):
            reasons.append("child_reported_error")
            child = None
        elif "error" in child:
            reasons.append("child_reported_error")
        else:
            if child.get("verdict") not in CHILD_VERDICTS:
                reasons.append("child_verdict_missing_or_unknown")
            if child.get("probe_cleanup_verified") is not True:
                reasons.append("child_cleanup_unverified")
            if any(field not in child for field in CHILD_REPORT_FIELDS):
                reasons.append("child_report_incomplete")
    return child, reasons


def restricted_primary_child_report(native, make_directory, sid: str, stabilize, hold=None) -> dict:
    """The actual-fence-shape recreation report taken by a child whose PRIMARY token has every
    privilege removed, beside the same report for this (original) process.

    ``restoration_verified`` (the fixture and this process's own probes) is kept apart from
    ``evidence_complete`` (the child launched, finished cleanly in time, left nothing behind and
    wrote a valid report); ``not_run`` lists why evidence is incomplete.

    The fixture's DACL is restored only when the child is known stopped (or was never started).
    Otherwise the fixture is left as it is, ``"child_stop_unestablished"`` is appended to ``hold``
    (the caller must then not remove the fixture root) and the restoration is reported unverified;
    this holds as well when the launcher raises."""
    parent = make_directory("restricted_primary_child")
    stabilize(parent)
    original, owner = native.read_dacl(parent), native.read_owner(parent)
    out = Path(parent).parent / "restricted_primary_child.json"
    out.unlink(missing_ok=True)
    native.apply_dacl(parent, with_ace_first(original, "(D;;%s;;;%s)" % (PARENT_RIGHTS, sid)))
    child_may_run = False
    try:
        original_report = recreation_report(native, parent, parent / "state")
        child_may_run = True
        launch = native.run_with_restricted_primary_token(
            [sys.executable, str(Path(__file__).resolve()), "--child-recreation-probe",
             str(parent), str(parent / "state"), str(out)], ROOT, timeout=300)
        child_may_run = launch.get("child_stopped") is not True
        child, reasons = child_evidence(launch, out)
    finally:
        if child_may_run:
            if hold is not None:
                hold.append("child_stop_unestablished")
            restored = {"verified": False, "skipped": "child_stop_unestablished"}
        else:
            native.apply_dacl(parent, original)
            restored = restoration_components(native, parent, original, owner)
    is_report = isinstance(child, dict)
    return {"launch": launch, "original_process_verdict": original_report["verdict"],
            "child": child if is_report else None, "child_verdict": child.get("verdict") if is_report else None,
            "restored": restored, "fixture_retained": child_may_run,
            "restoration_verified": bool(restored["verified"] and original_report["probe_cleanup_verified"]),
            "evidence_complete": not reasons and is_report, "not_run": reasons,
            "cause_established": False}


@contextmanager
def owned_fixture_root(prefix: str, hold: list):
    """An owned temporary root that is removed on exit unless ``hold`` is non-empty, which means a
    child may still be running under it: then it is left in place and its handles stay owned."""
    root = tempfile.mkdtemp(prefix=prefix)
    try:
        yield Path(root)
    finally:
        if not hold:
            shutil.rmtree(root)


class ChildStopHold:
    """Couples fixture restoration and removal to authoritative child-stop evidence for callers that
    launch through ``run_with_restricted_primary_token``: a launch whose child is not shown stopped,
    or a launcher that raised, keeps the owned fixture and its temporary root and reports failure."""

    def __init__(self):
        self.reasons = []

    @property
    def held(self) -> bool:
        return bool(self.reasons)

    def launch(self, native, argv, cwd, **kwargs) -> dict:
        try:
            launch = native.run_with_restricted_primary_token(argv, cwd, **kwargs)
        except BaseException:
            self.reasons.append("launcher_raised")
            raise
        if launch.get("child_stopped") is not True:
            self.reasons.append("child_stop_unestablished")
        return launch

    def settle(self, temp, restore) -> None:
        """Run ``restore`` then remove ``temp``, unless the hold is set: then detach the temporary
        directory's own finalizer (so garbage collection or interpreter exit cannot remove it either)
        and fail without touching the fixture; a failed ``restore`` is retained the same way."""
        finalizer = getattr(temp, "_finalizer", None)
        if self.reasons:
            if finalizer is not None:
                finalizer.detach()
            raise AssertionError("fixture retained, restoration and removal skipped (%s): %s"
                                 % (", ".join(self.reasons), temp.name))
        try:
            restore()
        except BaseException:
            if finalizer is not None:
                finalizer.detach()
            raise
        temp.cleanup()


def child_section_verified(body: dict) -> bool:
    """The restricted-primary section is clean only when the fixture was restored AND the child's
    evidence is complete; a restored fixture alone is never enough."""
    return bool(body["restoration_verified"] and body["evidence_complete"])


def bootstrap_checkout() -> None:
    """Make the checkout importable for the script entry only; never called when this file is
    loaded by path, so the installed-wheel check keeps ``sys.path`` and its imports untouched."""
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["--child-recreation-probe"] and len(argv) == 4:
        return child_recreation_probe(*argv[1:])
    report = {"os_name": os.name, "completed_stages": []}
    clean = True
    stage = "bootstrap"
    try:
        bootstrap_checkout()
        report["completed_stages"].append(stage)
        stage = "checkout_imports"
        from src.paper_pilot_phase_cutover import _current_sid
        from tools import windows_fixture_acl
        report["completed_stages"].append(stage)
        stage = "native_api"
        native = WindowsNative()
        report["completed_stages"].append(stage)
        stage = "identity"
        sid = _current_sid()
        report["runner_sid"] = redact(sid)
        report["completed_stages"].append(stage)
        if argv == ["--stages-only"]:
            report["cleanup_verified"] = True
            print(json.dumps(report, indent=2, sort_keys=True))
            return 0
        retain = []
        with owned_fixture_root("jraphyte-recreation-probe-", retain) as base:

            def make_directory(label: str) -> Path:
                path = base / label
                path.mkdir()
                return path

            def stabilize(path) -> None:
                windows_fixture_acl.stabilize_owned_fixture(
                    base, [("fixture", path)], read=native.read_dacl)

            def stable_directory(label: str) -> Path:
                path = make_directory(label)
                stabilize(path)
                return path
            sections = (
                ("matrix", lambda: candidate_matrix(native, sid, stable_directory),
                 lambda body: body["cleanup_verified"]),
                ("actual_fence_shape", lambda: probe_actual_fence_shape(native, stable_directory, sid),
                 lambda body: body["verified"]),
                ("privilege_isolation", lambda: privilege_isolation_on_fence_shape(native, stable_directory, sid),
                 lambda body: body["verified"]),
                ("installation_observation", lambda: installation_observation(native, sid, make_directory, stabilize),
                 installation_section_verified),
                ("restricted_primary_child", lambda: restricted_primary_child_report(native, make_directory, sid, stabilize, hold=retain),
                 child_section_verified))
            for section, produce, verified in sections:
                try:
                    report[section] = produce()
                    report["completed_stages"].append(section)
                    clean = bool(verified(report[section])) and clean
                except Exception as error:
                    report[section] = {"error": {"type": type(error).__name__,
                                               "code": getattr(error, "code", None)}}
                    clean = False
            if retain:
                report["fixture_retained"] = True
                clean = False
    except Exception as error:
        report["error"] = {"type": type(error).__name__, "code": getattr(error, "code", None),
                           "stage": stage}
        clean = os.name != "nt"
    report["cleanup_verified"] = clean
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if clean else 1


if __name__ == "__main__":
    raise SystemExit(main())
