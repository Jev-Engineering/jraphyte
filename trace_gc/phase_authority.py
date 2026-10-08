"""Windows phase authority for a copied, isolated PaperPilot backend and budget.

The historical package does not import this module. Its fixed source directory
is fenced before activation. This authority protects supported target writers;
it does not claim protection against a privileged or hostile same-user writer.
"""
from __future__ import annotations

from contextlib import contextmanager
import ctypes
import functools
from pathlib import Path
import os
import re
import threading

from .canonical import bytes_digest, digest, dumps, loads
from .compiler import now, timestamp
from .errors import require


def _plain_absolute_path(value: str) -> Path:
    """Reject drive-relative paths and existing reparse components."""
    require(type(value) is str, "PHASE_PATH", "absolute path string required")
    path = Path(value)
    require(path.is_absolute(), "PHASE_PATH", "drive-relative phase path denied")
    for component in (path, *path.parents):
        if component.exists() or component.is_symlink():
            attributes = getattr(component.lstat(), "st_file_attributes", 0)
            require(not (attributes & 0x400) and not component.is_symlink(),
                    "PHASE_PATH", "reparse point in phase authority path")
    return path


def directory_dacl_sddl(path: str | Path) -> str:
    """Read the actual Windows DACL without invoking a command interpreter."""
    require(os.name == "nt", "PHASE_PLATFORM", "NTFS phase fencing requires Windows")
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.LocalFree.argtypes = (ctypes.c_void_p,)
    kernel.LocalFree.restype = ctypes.c_void_p
    descriptor = ctypes.c_void_p()
    get = advapi.GetNamedSecurityInfoW
    get.argtypes = (ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
                    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                    ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p))
    get.restype = ctypes.c_uint32
    code = get(str(Path(path).resolve(strict=True)), 1, 4, None, None,
               None, None, ctypes.byref(descriptor))
    require(code == 0, "PHASE_FENCE", "cannot read archived parent DACL")
    value = ctypes.c_wchar_p()
    length = ctypes.c_uint32()
    convert = advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW
    convert.argtypes = (ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32,
                        ctypes.POINTER(ctypes.c_wchar_p), ctypes.POINTER(ctypes.c_uint32))
    convert.restype = ctypes.c_int
    try:
        require(bool(convert(descriptor, 1, 4, ctypes.byref(value), ctypes.byref(length))),
                "PHASE_FENCE", "cannot encode archived parent DACL")
        try:
            return value.value
        finally:
            kernel.LocalFree(ctypes.cast(value, ctypes.c_void_p))
    finally:
        kernel.LocalFree(descriptor)


_NUMERIC_SID = re.compile(r"S-1-[0-9]+(?:-[0-9]+)+")


def _is_windows() -> bool:
    return os.name == "nt"


@functools.lru_cache(maxsize=256)
def _windows_trustee(sid: str) -> str:
    """Spell one numeric SID exactly as this machine's Windows writes it in a DACL.

    The numeric SID is parsed into an in-memory descriptor and encoded back by the
    same conversion ``directory_dacl_sddl`` uses, so the result is whatever the
    OS would have serialized (an alias such as ``BU``, or ``LA`` only when the SID
    is this machine's own RID-500 account). No account lookup, DACL or file is
    touched, and an alias is never mapped back to a numeric SID.
    """
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.LocalFree.argtypes = (ctypes.c_void_p,)
    kernel.LocalFree.restype = ctypes.c_void_p
    parse = advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
    parse.argtypes = (ctypes.c_wchar_p, ctypes.c_uint32,
                      ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p)
    parse.restype = ctypes.c_int
    encode = advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW
    encode.argtypes = (ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32,
                       ctypes.POINTER(ctypes.c_wchar_p), ctypes.c_void_p)
    encode.restype = ctypes.c_int
    descriptor = ctypes.c_void_p()
    require(bool(parse("D:(D;;DCLC;;;" + sid + ")", 1, ctypes.byref(descriptor), None)),
            "PHASE_FENCE", "cannot parse SID trustee")
    try:
        value = ctypes.c_wchar_p()
        require(bool(encode(descriptor, 1, 4, ctypes.byref(value), None)),
                "PHASE_FENCE", "cannot encode SID trustee")
        try:
            text = value.value
        finally:
            kernel.LocalFree(ctypes.cast(value, ctypes.c_void_p))
    finally:
        kernel.LocalFree(descriptor)
    match = re.fullmatch(r"D:\(D;;DCLC;;;([^;()]+)\)", text)
    require(match is not None, "PHASE_FENCE", "unexpected SID trustee encoding")
    return match.group(1)


def canonical_dacl_trustee(trustee: str) -> str:
    """Return ``trustee`` spelled as Windows serializes it in this machine's DACL text.

    Only a strictly numeric ``S-1-...`` SID is translated, forward to the OS
    spelling, so distinct account/domain SIDs that share a RID (for example two
    RID-500 administrators) stay distinct. Aliases and any other text are
    returned unchanged. Off Windows the alias relation cannot be established, so
    a numeric SID fails closed (``PHASE_PLATFORM``) instead of being compared
    literally; a receipt written on another machine is judged only by what this
    machine's DACL text and this machine's serialization say.
    """
    if _NUMERIC_SID.fullmatch(trustee) is None:
        return trustee
    require(_is_windows(), "PHASE_PLATFORM",
            "SID/SDDL trustee aliases can only be resolved on Windows")
    return _windows_trustee(trustee)


def canonical_dacl_ace(ace: str) -> str:
    """Normalize only the trustee field of one six-field ACE; all else stays exact."""
    fields = ace[1:-1].split(";")
    if len(fields) != 6:
        return ace
    fields[5] = canonical_dacl_trustee(fields[5])
    return "(" + ";".join(fields) + ")"


def canonical_dacl_aces(sddl: str) -> list[str]:
    """ACEs in DACL order with trustees spelled canonically (type, flags, rights untouched)."""
    return [canonical_dacl_ace(ace) for ace in re.findall(r"\([^)]*\)", sddl)]


def dacl_has_ace(sddl: str, template: str, sid: str) -> bool:
    """Whether the DACL holds the exact ACE ``template`` for ``sid`` under any trustee spelling."""
    return canonical_dacl_ace(template.format(sid=sid)) in canonical_dacl_aces(sddl)


def dacl_has_deny_trustee(sddl: str, sid: str) -> bool:
    """Whether any plain deny ACE in the DACL names ``sid``, in any trustee spelling."""
    trustee = canonical_dacl_trustee(sid)
    return any(ace.startswith("(D;") and ace.endswith(";;;" + trustee + ")")
               for ace in canonical_dacl_aces(sddl))


class PhaseAuthority:
    """One exact phase, one shared cross-process writer lock and current pointer."""

    def __init__(self, binding: dict, trust):
        require(os.name == "nt", "PHASE_PLATFORM", "phase import currently requires Windows")
        required = {"phase_id", "run_id", "capsule_sha256", "implementation_sha256",
                    "activation_path", "activation_sha256", "activation_epoch",
                    "phase_lock_path", "fence_receipt_path", "fence_receipt_sha256",
                    "old_root_path", "archived_old_root_path", "capsule_path",
                    "authorization_path", "authorization_sha256"}
        require(type(binding) is dict and set(binding) == required,
                "PHASE_CONFIG", "exact phase binding required")
        for key in ("activation_path", "phase_lock_path", "fence_receipt_path",
                    "old_root_path", "archived_old_root_path", "capsule_path",
                    "authorization_path"):
            _plain_absolute_path(binding[key])
        self.binding = loads(dumps(binding))
        self.trust = trust
        self._mutex = threading.RLock()
        self._depth = 0
        self._archived_lock_file = None
        lock_path = Path(binding["phase_lock_path"]).resolve(strict=True)
        require(lock_path.is_file() and not Path(binding["phase_lock_path"]).is_symlink() and
                lock_path.parent != Path(binding["old_root_path"]).parent,
                "PHASE_LOCK", "disjoint preexisting phase lock required")
        self._lock_path = lock_path
        self._lock_file = lock_path.open("r+b")
        self._lock_identity = (os.fstat(self._lock_file.fileno()).st_dev,
                               os.fstat(self._lock_file.fileno()).st_ino)

    def close(self):
        self._lock_file.close()

    def bind_archived_lock(self, handle):
        expected = Path(self.binding["archived_old_root_path"]) / "controller.lock"
        require(not handle.closed and Path(handle.name).resolve(strict=True) == expected.resolve(strict=True),
                "PHASE_LOCK", "archived historical lock handle differs")
        self._archived_lock_file = handle

    def unbind_archived_lock(self, handle):
        if self._archived_lock_file is handle:
            self._archived_lock_file = None

    def _archive_bytes(self, archived: Path, name: str) -> bytes:
        if name == "controller.lock" and self._archived_lock_file is not None:
            handle = self._archived_lock_file
            require(not handle.closed, "PHASE_LOCK", "archived historical lock was closed")
            held = os.fstat(handle.fileno())
            current = os.stat(archived / name)
            require((held.st_dev, held.st_ino) == (current.st_dev, current.st_ino),
                    "PHASE_LOCK", "archived historical lock path was replaced")
            position = handle.tell()
            try:
                handle.seek(0)
                return handle.read()
            finally:
                handle.seek(position)
        return (archived / name).read_bytes()

    def _current(self):
        b = self.binding
        pointer = Path(b["activation_path"])
        require(pointer.is_file() and not pointer.is_symlink(),
                "PHASE_INACTIVE", "active phase pointer absent")
        raw = pointer.read_bytes()
        require(bytes_digest(raw) == b["activation_sha256"],
                "PHASE_INACTIVE", "active phase pointer changed or absent")
        receipt = loads(raw)
        self.verify_activation_receipt(receipt, historical=True)
        self.verify_fence()

    def activation_payload(self):
        b = self.binding
        return {"version": "paper-pilot-phase-activation-v1", "operation": "PHASE_ACTIVATE",
                    "phase_id": b["phase_id"], "run_id": b["run_id"],
                    "capsule_sha256": b["capsule_sha256"],
                    "implementation_sha256": b["implementation_sha256"],
                    "activation_epoch": b["activation_epoch"],
                    "fence_receipt_sha256": b["fence_receipt_sha256"],
                    "layout_sha256": digest({key: value for key, value in b.items()
                                             if key != "activation_sha256"})}

    def verify_activation_receipt(self, receipt, *, historical: bool = False):
        policy = self.trust.verify(receipt, "AUTHORIZATION",
                                   at=receipt["issued_at"] if historical else None)
        require(timestamp(receipt["issued_at"]) <= timestamp(now()) and
                receipt["payload"] == self.activation_payload() and policy.can_review and
                "PHASE_ACTIVATE" in policy.operations,
                "PHASE_INACTIVE", "current signed phase pointer differs")

    def verify_fence(self):
        b = self.binding
        fence_raw = Path(b["fence_receipt_path"]).read_bytes()
        require(bytes_digest(fence_raw) == b["fence_receipt_sha256"],
                "PHASE_FENCE", "phase fence receipt changed")
        fence = loads(fence_raw)
        old = Path(b["old_root_path"])
        archived = Path(b["archived_old_root_path"])
        names = {"checkpoint.sqlite3", "graph.sqlite3", "budget.sqlite3",
                 "application-journal.sqlite3", "controller.lock"}
        sddl = directory_dacl_sddl(old.parent)
        deny_sid = fence.get("deny_sid")
        require(set(fence) == {"version", "old_root_path", "archived_root_path",
                                "old_parent_dacl_sha256", "archived_files_sha256",
                                "deny_sid", "status"} and
                fence["version"] == "paper-pilot-phase-namespace-fence-v1" and
                fence["old_root_path"] == str(old) and
                fence["archived_root_path"] == str(archived) and
                fence["status"] == "OLD_PATH_FENCED_NEW_PHASE_ALLOWED" and
                type(deny_sid) is str and
                dacl_has_ace(sddl, "(D;;LC;;;{sid})", deny_sid) and
                bytes_digest(sddl.encode("utf-8")) == fence["old_parent_dacl_sha256"] and
                set(fence["archived_files_sha256"]) == names and
                not old.exists() and archived.is_dir() and
                {name for name in (path.name for path in archived.iterdir())} == names and
                all(not (getattr((archived / name).lstat(), "st_file_attributes", 0) & 0x400)
                    for name in names) and
                all(bytes_digest(self._archive_bytes(archived, name)) == expected
                    for name, expected in fence["archived_files_sha256"].items()),
                "PHASE_FENCE", "archived old path or NTFS deny changed")

    @contextmanager
    def _locked(self, *, active: bool):
        with self._mutex:
            require((os.stat(self._lock_path).st_dev, os.stat(self._lock_path).st_ino) ==
                    self._lock_identity, "PHASE_LOCK", "phase lock path was replaced")
            first = self._depth == 0
            if first:
                import msvcrt
                self._lock_file.seek(0)
                msvcrt.locking(self._lock_file.fileno(), msvcrt.LK_LOCK, 1)
            self._depth += 1
            try:
                if active:
                    self._current()
                else:
                    self.verify_fence()
                yield
            finally:
                self._depth -= 1
                if first:
                    self._lock_file.seek(0)
                    msvcrt.locking(self._lock_file.fileno(), msvcrt.LK_UNLCK, 1)

    def write(self):
        return self._locked(active=True)

    def staging(self):
        return self._locked(active=False)

    def check(self):
        with self.write():
            pass


def binding_sha256(binding: dict) -> str:
    return digest(binding)
