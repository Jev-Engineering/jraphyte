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

Run as a script it prints one sanitized JSON report, including a matrix of candidate deny shapes
on owned temporary directories; the exit status is nonzero only if a cleanup is not verified.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]

PARENT_RIGHTS = "LC"        # FILE_ADD_SUBDIRECTORY, spelled by icacls as (AD)
FILE_ADD_FILE = 0x2
FILE_ADD_SUBDIRECTORY = 0x4
BYPASS_PRIVILEGES = ("SeBackupPrivilege", "SeRestorePrivilege")
_DACL = re.compile(r"D:([A-Z]*)((?:\([^)]*\))*)")
_NUMERIC_SID = re.compile(r"S-1-[0-9]+(?:-[0-9]+)+")


def redact(text):
    """The sanitizer of the diagnostics tool, imported on first use so that loading this module
    by path (the installed-wheel check does) never edits ``sys.path`` or imports checkout code."""
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from tools.windows_fence_diagnostics import redact as sanitize
    return sanitize(text)


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


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class WindowsNative:
    """ctypes access to the descriptor, token, access-check and volume APIs (Windows only)."""

    def __init__(self):
        import ctypes
        from ctypes import wintypes
        if os.name != "nt":
            raise NativeError("platform", None)
        self.c, self.w = ctypes, wintypes
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

    def apply_dacl(self, path, sddl: str) -> None:
        control, _ = split_dacl(sddl)
        protection = 0x80000000 if "P" in control else 0x20000000
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

    @contextmanager
    def impersonation_token(self, stripped: bool):
        """An impersonation copy of the process token, optionally with every privilege removed."""
        process = self.c.c_void_p()
        self._ok("OpenProcessToken", self.advapi.OpenProcessToken(
            self.kernel.GetCurrentProcess(), 0x1 | 0x2 | 0x4 | 0x8, self.c.byref(process)))
        opened = [process]
        try:
            source = process
            if stripped:
                restricted = self.c.c_void_p()
                self._ok("CreateRestrictedToken", self.advapi.CreateRestrictedToken(
                    process, 0x1, 0, None, 0, None, 0, None, self.c.byref(restricted)))
                opened.append(restricted)
                source = restricted
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

    def privileges(self) -> list[tuple[str, bool]]:
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
            found = []
            for index in range(count):
                offset = 4 + 12 * index
                low, high, attributes = struct.unpack_from("<IiI", buffer.raw, offset)
                luid = self.c.create_string_buffer(buffer.raw[offset:offset + 8], 8)
                length = self.w.DWORD(128)
                name = self.c.create_unicode_buffer(128)
                self._ok("LookupPrivilegeNameW", self.advapi.LookupPrivilegeNameW(
                    None, luid, name, self.c.byref(length)))
                found.append((name.value, bool(attributes & 0x2)))
            return found
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

    def filesystem(self, path) -> str:
        volume = self.c.create_unicode_buffer(260)
        self._ok("GetVolumePathNameW", self.kernel.GetVolumePathNameW(
            str(Path(path).resolve(strict=True)), volume, 260))
        name = self.c.create_unicode_buffer(64)
        self._ok("GetVolumeInformationW", self.kernel.GetVolumeInformationW(
            volume.value, None, 0, None, None, None, name, 64))
        return name.value

    def try_create_directory(self, path, stripped: bool, route: str = "os.mkdir") -> dict:
        """Try to create ``path``; remove it again if it was created and verify the removal."""
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
        if stripped:
            with self.impersonation_token(True) as token, self.impersonating(token):
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


def deny_by_descriptor(native, path, sid: str, rights: str = PARENT_RIGHTS) -> dict:
    """Install ``(D;;rights;;;sid)`` first in the DACL of ``path`` without any account lookup.

    ``installed_exactly`` is true only if the read-back keeps the control and protection flags,
    holds the new ACE first and the old ACEs after it in their old order (trustees compared
    canonically), and leaves the owner unchanged.
    """
    before_owner = native.read_owner(path)
    before = native.read_dacl(path)
    ace = "(D;;%s;;;%s)" % (rights, sid)
    native.apply_dacl(path, with_ace_first(before, ace))
    after = native.read_dacl(path)
    owner_after = native.read_owner(path)
    installed = (split_dacl(after)[0] == split_dacl(before)[0]
                 and canonical_aces(native, after) == [canonical_ace(native, ace)] + canonical_aces(native, before)
                 and owner_after == before_owner)
    return {"ace": ace, "before": before, "after": after, "owner_before": before_owner,
            "owner_after": owner_after, "installed_exactly": installed}


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


def main() -> int:
    report = {"os_name": os.name}
    clean = True
    try:
        native = WindowsNative()
        from src.paper_pilot_phase_cutover import _current_sid
        sid = _current_sid()
        with tempfile.TemporaryDirectory(prefix="jraphyte-recreation-probe-") as temp:
            base = Path(temp)

            def make_directory(label: str) -> Path:
                path = base / label
                path.mkdir()
                return path
            report["runner_sid"] = redact(sid)
            report["matrix"] = candidate_matrix(native, sid, make_directory)
            clean = report["matrix"]["cleanup_verified"]
            actual = probe_actual_fence_shape(native, make_directory, sid)
            report["actual_fence_shape"] = actual["report"]
            report["actual_fence_shape_restored"] = actual["restored"]
            clean = clean and actual["verified"]
    except Exception as error:
        report["error"] = {"type": type(error).__name__, "code": getattr(error, "code", None)}
        clean = os.name != "nt"
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if clean else 1


if __name__ == "__main__":
    raise SystemExit(main())
