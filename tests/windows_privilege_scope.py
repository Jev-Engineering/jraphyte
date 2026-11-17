"""Test-only scope that disables this process's enabled privileges, then restores them exactly.

Hosted Windows runners start Python with a token whose enabled privileges let it create a
directory beneath a ``(D;;LC;;;sid)`` parent deny that names it. The v1 fence therefore
holds there (``_require_denial_enforced``), which is the intended fail-closed result. The
positive v1 path needs a process token that the deny actually refuses, so the native tests
run it inside this scope: every enabled privilege except ``SeChangeNotifyPrivilege`` is
disabled on the process's own primary token with ``AdjustTokenPrivileges`` (no privilege is
removed, no account, group or host setting changes), and on exit the captured attributes are
put back and the whole inventory is read back; any difference fails loudly.

This changes only the token of the test process for the duration of the block. It does not
change, relax or bypass any production check, and it does not establish why the enabled
privileges allowed creation.
"""
from __future__ import annotations

from contextlib import contextmanager
import os
import struct

SE_PRIVILEGE_ENABLED = 0x2
SE_PRIVILEGE_USED_FOR_ACCESS = 0x80000000
ERROR_NOT_ALL_ASSIGNED = 1300
KEPT = frozenset({"SeChangeNotifyPrivilege"})
TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY = 0x20, 0x8


class PrivilegeScopeError(AssertionError):
    pass


class _Api:
    def __init__(self):
        import ctypes
        from ctypes import wintypes
        if os.name != "nt":
            raise PrivilegeScopeError("privilege scope requires Windows")
        self.c, self.w = ctypes, wintypes
        self.advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        v, d = ctypes.c_void_p, wintypes.DWORD
        for library, name, argtypes, restype in (
                (self.kernel, "GetCurrentProcess", (), v),
                (self.kernel, "CloseHandle", (v,), wintypes.BOOL),
                (self.advapi, "OpenProcessToken", (v, d, ctypes.POINTER(v)), wintypes.BOOL),
                (self.advapi, "GetTokenInformation", (v, ctypes.c_int, v, d, ctypes.POINTER(d)),
                 wintypes.BOOL),
                (self.advapi, "LookupPrivilegeNameW",
                 (wintypes.LPCWSTR, v, wintypes.LPWSTR, ctypes.POINTER(d)), wintypes.BOOL),
                (self.advapi, "AdjustTokenPrivileges", (v, wintypes.BOOL, v, d, v, v),
                 wintypes.BOOL)):
            function = getattr(library, name)
            function.argtypes, function.restype = argtypes, restype

    def token(self, access: int):
        handle = self.c.c_void_p()
        if not self.advapi.OpenProcessToken(self.kernel.GetCurrentProcess(), access,
                                            self.c.byref(handle)):
            raise PrivilegeScopeError("OpenProcessToken failed: %d" % self.c.get_last_error())
        return handle

    def close(self, handle) -> None:
        if not self.kernel.CloseHandle(handle):
            raise PrivilegeScopeError("CloseHandle failed: %d" % self.c.get_last_error())

    def inventory(self) -> dict[str, tuple[bytes, int]]:
        """Every privilege of the process token: name -> (LUID bytes, attributes)."""
        token = self.token(TOKEN_QUERY)
        try:
            size = self.w.DWORD()
            self.advapi.GetTokenInformation(token, 3, None, 0, self.c.byref(size))
            buffer = self.c.create_string_buffer(size.value)
            if not self.advapi.GetTokenInformation(token, 3, buffer, size, self.c.byref(size)):
                raise PrivilegeScopeError("GetTokenInformation failed: %d" % self.c.get_last_error())
        finally:
            self.close(token)
        raw = buffer.raw
        (count,) = struct.unpack_from("<I", raw, 0)
        found = {}
        for index in range(count):
            offset = 4 + 12 * index
            luid = raw[offset:offset + 8]
            (attributes,) = struct.unpack_from("<I", raw, offset + 8)
            name = self.c.create_unicode_buffer(128)
            length = self.w.DWORD(128)
            if not self.advapi.LookupPrivilegeNameW(None, self.c.create_string_buffer(luid, 8),
                                                    name, self.c.byref(length)):
                raise PrivilegeScopeError("LookupPrivilegeNameW failed: %d" % self.c.get_last_error())
            found[name.value] = (luid, attributes)
        return found

    def adjust(self, entries: list[tuple[bytes, int]]) -> None:
        body = struct.pack("<I", len(entries)) + b"".join(
            luid + struct.pack("<I", attributes) for luid, attributes in entries)
        state = self.c.create_string_buffer(body, len(body))
        token = self.token(TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY)
        try:
            self.c.set_last_error(0)
            ok = self.advapi.AdjustTokenPrivileges(token, False, state, 0, None, None)
            code = self.c.get_last_error()
        finally:
            self.close(token)
        if not ok or code == ERROR_NOT_ALL_ASSIGNED:
            raise PrivilegeScopeError("AdjustTokenPrivileges failed: %d" % code)


def _comparable(inventory: dict) -> dict[str, int]:
    return {name: attributes & ~SE_PRIVILEGE_USED_FOR_ACCESS
            for name, (_, attributes) in inventory.items()}


def enabled_privileges() -> list[str]:
    return sorted(name for name, (_, attributes) in _Api().inventory().items()
                  if attributes & SE_PRIVILEGE_ENABLED)


@contextmanager
def privileges_disabled():
    """Disable every enabled privilege except ``SeChangeNotifyPrivilege``; yield their names."""
    api = _Api()
    before = api.inventory()
    chosen = sorted(name for name, (_, attributes) in before.items()
                    if attributes & SE_PRIVILEGE_ENABLED and name not in KEPT)
    try:
        if chosen:
            api.adjust([(before[name][0], 0) for name in chosen])
        inside = _comparable(api.inventory())
        if any(inside[name] & SE_PRIVILEGE_ENABLED for name in chosen):
            raise PrivilegeScopeError("a privilege stayed enabled inside the scope")
        yield chosen
    finally:
        if chosen:
            api.adjust([(before[name][0], SE_PRIVILEGE_ENABLED) for name in chosen])
        if _comparable(api.inventory()) != _comparable(before):
            raise PrivilegeScopeError("process privilege inventory was not restored exactly")
