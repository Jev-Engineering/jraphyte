"""Child-side bootstrap for ``paper-verifier-closure-v1`` (standard library only, no repository imports).

The parent (``trace_gc.verifier_closure``) starts a fresh interpreter as
``python -I -S -B -X utf8 -X pycache_prefix=<empty dir> -c <bounded ASCII stub>``.  The stub (a few hundred bytes, so
the command line stays far below the Windows limit) reads this file's bytes from stdin, executes them only when their
SHA-256 equals the digest the parent embedded in the stub, and passes two globals: ``_PVC_STARTUP`` (the module
names present before the stub imported anything) and ``_PVC_BOOTSTRAP_SHA256``.  The same stdin then carries one
request frame, or ``PVCPROBE`` for the runtime facts the manifest pins.

Before the frame is read this file imports only modules the interpreter ships (``os``, ``_imp``, ``marshal``,
``importlib``, the hash and, per platform, ``fcntl`` plus ``_ctypes.dlopen`` or ``_winapi``/``msvcrt``/``ctypes``); it
never imports a file from the repository, the checkout or ``sys.path`` beyond those.  Those preload modules and their
files are part of the manifest pins and are re-hashed once the frame is read.  The mapped native libraries at start
must already be a subset of the pinned natives; an unavailable or partial mapping inventory is a refusal, never an
empty or shortened set.  Once the frame is verified it

* serves closure modules from the captured bytes and standard-library or declared-package modules only from the
  parent's census table (a name-to-file table: ``sys.path`` and ``PathFinder`` are not consulted); every such
  source file is hashed when it is read and compiled from exactly those bytes, and every extension module is hashed
  and loaded from a sealed memfd (Linux) or from its file under a writer-denying handle that is re-hashed after the
  run (Windows, not run yet), so there is no unguarded verify-then-reload gap for them on Linux;
* plans the native loading of an extension module BEFORE any of its code or its dependencies' code is loaded: the
  ELF ``DT_NEEDED`` / PE import list of the hashed bytes is resolved, recursively, to files that were already mapped
  when the frame was read or to exactly one pinned native each (hashed against its pin); every pinned dependency is
  then loaded first from a sealed memfd (Linux) or under a writer-denying handle (Windows), so the dynamic loader
  satisfies the extension's own list from objects this process already holds and performs no filesystem search.
  On Linux a ``DT_NEEDED`` string is matched the way the glibc loader matches it against an object it holds: by the
  object's ``DT_SONAME`` (an object loaded from ``/proc/self/fd/N`` has no other name), never by its file basename; a
  pinned dependency that has no ``DT_SONAME`` therefore cannot satisfy a ``DT_NEEDED`` entry and the plan is refused.
  Every memfd that backs a loaded object stays open until the process exits (a reused descriptor number would be a
  reused loader name) and, after each ``dlopen``, ``/proc/self/maps`` must list a mapping with exactly that memfd's
  device and inode before the next object, and before the extension's own initialiser, is loaded.  On Windows an
  API-set import (``api-ms-*``/``ext-ms-*``) is resolved to its host module through ``GetModuleHandleW`` and must be
  hosted by an already loaded, pinned native; an unresolved host is refused.  An unparsable image, a dependency named
  by a path, an unpinned, unnamed or ambiguous dependency, a cycle, ``RPATH``/``RUNPATH``, audit/filter entries and PE
  delay-load imports are refused before the extension is loaded, in every mode;
* mediates EVERY import through one function that is installed as ``builtins.__import__`` and as
  ``importlib.import_module``: the requesting frame decides the policy.  A closure frame may import a name only when
  the executing instruction is, by exact source position (line, end line, column, end column), one of the import
  statements or literal import calls the parent recorded for that file and the name is one of its names, for fresh
  imports and ``sys.modules`` cache hits and indirect routes alike; a refusal is recorded at that moment, so
  import-and-delete cannot hide it.  A dependency frame is held to the reviewed dependency operation contract:
  every import it performs, fresh or cached, absolute or relative, through the statement, ``__import__`` or
  ``importlib.import_module``, is resolved to an absolute name first; a denylisted module is a recorded violation unless
  it is a reviewed dependency import operation (``DEPENDENCY_IMPORT_OPERATIONS``); a DYNAMIC operation (``import_module``,
  an explicit ``__import__`` call, a ``fromlist`` item naming a pinned submodule, ``find_spec``) on ANY target, pinned or
  not, is a recorded violation unless it is a reviewed standard-library operation (``DEPENDENCY_STDLIB_OPERATIONS``) or
  exactly a declared ``(importer, form, module)`` triple (``importlib.util.find_spec``, ``importlib.__import__`` and the
  private ``importlib._bootstrap._gcd_import`` are replaced by mediating functions that decide before any cache shortcut);
  a denylisted module the interpreter preloaded is removed from
  ``sys.modules`` before arming;
* installs an audit hook that rejects process creation, dynamic library loading, ``exec``/``compile`` outside an
  exact allowlist, and imports under mutated import state or from unlisted native files;
* reports through a private descriptor, never through the verifier's stdout.

It is an integrity boundary for reviewed code, not a sandbox: it does not stop hostile Python from writing to
file descriptors or editing process memory.  The final comparison of the mapped files with the pins stays as
defence in depth after the run; it is not the primary native control.
"""
import sys

try:
    _STARTUP = list(_PVC_STARTUP)
    _BOOTSTRAP_SHA256 = str(_PVC_BOOTSTRAP_SHA256)
except NameError:
    raise SystemExit(74)
_STARTUP_PATH = list(sys.path)
_STARTUP_META = list(sys.meta_path)
_STARTUP_HOOKS = list(sys.path_hooks)
# --- preload begin ---
import _imp
import gc   # built in; its referrer query backs the captured-reference audit at arming
import importlib
import importlib.util   # loaded here (it is frozen on some builds, so no loader hook would ever see it) and mediated at arming
import marshal
import os
try:
    from _sha2 import sha256 as _sha256
except ImportError:
    from _sha256 import sha256 as _sha256
_dlopen = None
if sys.platform.startswith("linux"):
    import fcntl
    try:
        from _ctypes import dlopen as _dlopen
    except ImportError:
        _dlopen = None
elif sys.platform == "win32":
    import _winapi
    import msvcrt
    import ctypes
    from ctypes import wintypes as _wt
# --- preload end ---

MAGIC = b"PVCLOS03"
PROBE_MAGIC = b"PVCPROBE"
RESULT_PREFIX = "PVCLOSURE-RESULT "
PROTOCOL = "PVCLOS03"
MODES = ("import", "confirm", "run")

MAX_HEADER = 192 << 20
MAX_RESULT = 4 << 20
MAX_LIST = 200

# Policy shared with the parent (``trace_gc.verifier_closure`` pins these in the release contract).
DYNAMIC_STDLIB_CALLERS = (("ast", "parse"), ("collections", "namedtuple"), ("dataclasses", "_create_fn"),
                          ("dataclasses", "add_fns_to_class"))
DENIED_EVENT_PREFIXES = ("ctypes.", "os.system", "os.exec", "os.spawn", "os.posix_spawn", "os.fork", "os.forkpty",
                         "os.startfile", "os.add_dll_directory", "subprocess.", "pty.spawn", "webbrowser.open",
                         "sys.setdlopenflags", "winreg.")
DENIED_IMPORTS = ("runpy", "pkgutil", "imp", "zipimport", "ctypes", "_ctypes", "cffi", "subprocess", "multiprocessing",
                  "_winapi", "_posixsubprocess", "pty", "builtins", "msvcrt")
# Reviewed dependency import operations: ``(form, module)`` pairs a census-loaded dependency may perform although the
# module is denylisted.  ``builtins`` is only ever referenced (its ``__import__`` is the mediating function below) and
# only by an import statement or ``__import__`` call; ``importlib.import_module`` has no reviewed operation.  Any other
# denylisted import by a dependency, fresh or cached, absolute or relative, is a recorded violation.
DEPENDENCY_IMPORT_OPERATIONS = (("import", "builtins"),)
# Declared (manifest) dependency operations ``(importer, form, module)``.  A census-loaded dependency that tries to load
# an unpinned or ambiguous module is refused as absent and the attempt is approved only when it is exactly a declared
# triple, otherwise it is a recorded violation.  The same declaration is required for a dependency's DYNAMIC operation on a
# PINNED (or builtin/frozen) module: ``importlib.import_module`` (absolute or relative, fresh or cached), an explicit
# ``__import__`` call (anything that is not an ``import`` statement), a ``__import__`` ``fromlist`` item that names a pinned
# submodule, and ``find_spec`` (an attempt that reaches the finder without passing through a mediated import function, for
# example ``importlib.util.find_spec``).  An ``import`` statement of a pinned, non-denylisted module is the pinned census
# graph itself and needs no declaration.  ``importer`` is the pinned census module whose code issued the request.
DEPENDENCY_OPERATION_FORMS = ("import", "import_module", "find_spec")
# Reviewed standard-library dynamic operations that need no declaration: ``(importer, form, module, submodules)``;
# ``importer`` ``None`` is any census-loaded dependency, ``submodules`` also covers ``module.<anything>``.  The codec
# search function is the one shipped-interpreter dynamic import every closure reaches (any codec that was not loaded at start-up).
DEPENDENCY_STDLIB_OPERATIONS = (("encodings", "import", "encodings", True),)
DEPENDENCY_OPERATION_PREFIX = "dependency_operation:"
MAX_DEPENDENCY_OPERATIONS = 32
SUPERVISOR_MODULES = ("ctypes", "os", "select", "signal", "subprocess", "sys", "time")
# Code names (``co_name``, which a function's ``__name__`` does not change) of every mediating function, with the operation
# form each one names.  The requesting frame is the first frame that is none of these, import plumbing or an own frame of
# the real ``find_spec``; the form is the one named by the OUTERMOST mediating frame between the finder and that requester.
_MEDIATION_FORMS = {"_mediated_import": "import", "_mediated_import_module": "import_module",
                    "_mediated_gcd_import": "import_module", "_mediated_find_spec": "find_spec",
                    "_private_import_module": "import_module", "_private_find_spec": "find_spec",
                    "_mediated_finder_method": "find_spec", "_mediated_loader_method": "import_module"}
MAX_NATIVE_PLAN = 256
MAX_NATIVE_DEPTH = 16
_REAL_IMPORT = __import__
_REAL_IMPORT_MODULE = importlib.import_module
_GET_IDENT = sys.modules["_thread"].get_ident   # the import system itself loaded _thread: no new preload module
_PLUMBING_FILES = frozenset(p for p in (getattr(importlib, "__file__", None),) if isinstance(p, str))
_FRAME_TYPE = type(sys._getframe())
_FUNCTION_TYPE = type(lambda: None)
_WRAPPERS = []   # every mediating function installed by ``_install_entry_points`` (their closure cells are our own references)

# Windows: every ctypes object is built here, before the frame is read and before the audit hook exists, so that later
# boot-side calls need no dynamic library load.  Closure code cannot import ctypes (denied) and its ctypes events are refused.
_K32 = None
if sys.platform == "win32":
    _K32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _K32.GetCurrentProcess.restype = _wt.HANDLE
    _K32.K32EnumProcessModules.argtypes = [_wt.HANDLE, ctypes.POINTER(_wt.HMODULE), _wt.DWORD, ctypes.POINTER(_wt.DWORD)]
    _K32.K32EnumProcessModules.restype = _wt.BOOL
    _K32.K32GetModuleFileNameExW.argtypes = [_wt.HANDLE, _wt.HMODULE, _wt.LPWSTR, _wt.DWORD]
    _K32.K32GetModuleFileNameExW.restype = _wt.DWORD
    _K32.CreateFileW.argtypes = [_wt.LPCWSTR, _wt.DWORD, _wt.DWORD, _wt.LPVOID, _wt.DWORD, _wt.DWORD, _wt.HANDLE]
    _K32.CreateFileW.restype = _wt.HANDLE
    _K32.LoadLibraryExW.argtypes = [_wt.LPCWSTR, _wt.HANDLE, _wt.DWORD]
    _K32.LoadLibraryExW.restype = _wt.HMODULE
    _K32.GetModuleHandleW.argtypes = [_wt.LPCWSTR]
    _K32.GetModuleHandleW.restype = _wt.HMODULE
    # The resolver's output buffer TYPE is built here: ``ctypes.create_unicode_buffer`` raises the denied
    # ``ctypes.create_unicode_buffer`` audit event, instantiating a prebuilt array type raises none.
    _APISET_PATH = ctypes.c_wchar * 32768

_BOOT_GLOBALS = globals()
_REPORT = {"violations": [], "refused": []}
_REPORT_FD = None
_STATE = {"armed": False, "finder": None, "meta": None, "native_paths": set(), "table": {}, "entries": {},
          "created": {}, "owned_tops": frozenset(), "strict": True, "by_file": {}, "runtime_files": frozenset(),
          "native_pins": {}, "native_index": {}, "satisfied": set(), "dep_ops": frozenset(), "file_names": {},
          "find_spec_depth": {}, "real_find_spec": None, "find_spec_file": None, "real_gcd_import": None}


def _sha(data):
    return _sha256(data).hexdigest()


def _violation(code):
    if len(_REPORT["violations"]) < MAX_LIST and code not in _REPORT["violations"]:
        _REPORT["violations"].append(code)


def _refused(code):
    if len(_REPORT["refused"]) < MAX_LIST and code not in _REPORT["refused"]:
        _REPORT["refused"].append(code)


def _calibrate_import_statement():
    """The opcode byte the interpreter is executing when an ``import`` statement calls ``builtins.__import__``, measured
    here with a recording stand-in instead of taken from an opcode table.  Any other call into ``__import__`` (an explicit
    call, or a C-level request) executes a different instruction, so that request is a dynamic operation.  ``None`` (not
    measurable) classifies every request as dynamic, which only ever demands more declarations."""
    seen = []
    real = _REAL_IMPORT

    def record(name, globals=None, locals=None, fromlist=(), level=0):
        frame = sys._getframe(1)
        seen.append(frame.f_code.co_code[frame.f_lasti])
        return real(name, globals, locals, fromlist, level)

    def statement():
        import sys as _calibration_probe

    builtins_module = sys.modules["builtins"]
    original = builtins_module.__import__
    builtins_module.__import__ = record
    try:
        statement()
    finally:
        builtins_module.__import__ = original
    return seen[0] if len(seen) == 1 else None


_IMPORT_STATEMENT_OPCODE = _calibrate_import_statement()


# ----------------------------------------------------------------------------------------------- report

def _quote(text):
    out = ['"']
    for ch in text:
        code = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif code < 0x20 or code > 0x7E:
            if code > 0xFFFF:
                code -= 0x10000
                out.append("\\u%04x\\u%04x" % (0xD800 + (code >> 10), 0xDC00 + (code & 0x3FF)))
            else:
                out.append("\\u%04x" % code)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _encode(value, out, depth=0):
    if depth > 64:
        raise ValueError("depth")
    kind = type(value)
    if value is None:
        out.append("null")
    elif kind is bool:
        out.append("true" if value else "false")
    elif kind is int:
        if abs(value) > (1 << 53) - 1:
            raise ValueError("integer range")
        out.append(int.__repr__(value))
    elif kind is float:
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError("nonfinite")
        out.append(float.__repr__(value))
    elif kind is str:
        out.append(_quote(value))
    elif kind is list:
        out.append("[")
        for index, item in enumerate(value):
            if index:
                out.append(",")
            _encode(item, out, depth + 1)
        out.append("]")
    elif kind is dict:
        out.append("{")
        for index, key in enumerate(sorted(value, key=lambda k: k if type(k) is str else "")):
            if type(key) is not str:
                raise ValueError("key")
            if index:
                out.append(",")
            out.append(_quote(key))
            out.append(":")
            _encode(value[key], out, depth + 1)
        out.append("}")
    else:
        raise ValueError("type")


def _dumps(value):
    out = []
    _encode(value, out)
    return "".join(out)


def _write_all(fd, data):
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        view = view[written:]


def _emit(report):
    line = "\n" + RESULT_PREFIX + report.get("nonce", "") + " " + _dumps(report) + "\n"
    _write_all(_REPORT_FD, line.encode("ascii"))


def _finish(report, code=0):
    _emit(report)
    try:
        os.close(_REPORT_FD)
    except OSError:
        pass
    os._exit(code)


def _fail(reason, **extra):
    report = {"protocol": PROTOCOL, "status": "BOOTSTRAP_REJECT", "reason": reason, "nonce": _REPORT.get("nonce", ""),
              "violations": list(_REPORT["violations"])}
    report.update(extra)
    _finish(report, 3)


# ----------------------------------------------------------------------------------------------- io helpers

def _read_exact(count):
    chunks, left = [], count
    while left:
        piece = os.read(0, min(left, 1 << 20))
        if not piece:
            _fail("frame_truncated")
        chunks.append(piece)
        left -= len(piece)
    return b"".join(chunks)


def _hash_path(path):
    digest = _sha256()
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    try:
        while True:
            piece = os.read(fd, 1 << 20)
            if not piece:
                break
            digest.update(piece)
    finally:
        os.close(fd)
    return digest.hexdigest()


def _read_path(path, limit):
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    try:
        chunks, total = [], 0
        while True:
            piece = os.read(fd, 1 << 20)
            if not piece:
                break
            total += len(piece)
            if total > limit:
                raise OSError("file too large")
            chunks.append(piece)
    finally:
        os.close(fd)
    return b"".join(chunks)


def _windows_modules():
    """Every module mapped into this process (Windows ``EnumProcessModules``), or ``None`` if the list is unavailable
    or any module's file name cannot be resolved (a partial inventory is never returned)."""
    try:
        enum, name = _K32.K32EnumProcessModules, _K32.K32GetModuleFileNameExW
        process = _K32.GetCurrentProcess()
        size = 1024
        for _ in range(4):
            array = (_wt.HMODULE * size)()
            needed = _wt.DWORD(0)
            if not enum(process, array, ctypes.sizeof(array), ctypes.byref(needed)):
                return None
            count = needed.value // ctypes.sizeof(_wt.HMODULE)
            if count <= size:
                break
            size = count + 64
        else:
            return None
        found = set()
        buffer = ctypes.create_unicode_buffer(32768)
        for module in array[:count]:
            if not name(process, module, buffer, 32768):
                return None
            text = buffer.value
            found.add(text[4:] if text.startswith("\\\\?\\") else text)
        return sorted(found)
    except (OSError, ValueError, AttributeError):
        return None


def _mapped_files():
    if sys.platform == "win32":
        return _windows_modules()
    if not sys.platform.startswith("linux"):
        return None
    try:
        text = _read_path("/proc/self/maps", 64 << 20).decode("utf-8", "replace")
    except OSError:
        return None
    found = set()
    for line in text.splitlines():
        parts = line.split(None, 5)
        if len(parts) == 6 and parts[5].startswith("/"):
            found.add(parts[5])
    return sorted(found)


def _exe_sha256():
    if sys.platform.startswith("linux"):
        try:
            return _hash_path("/proc/self/exe")
        except OSError:
            return None
    if sys.platform == "win32":
        try:
            return _hash_path(_winapi.GetModuleFileName(0))
        except OSError:
            return None
    return None


# ----------------------------------------------------------------------------------------------- loading

class _Entry:
    __slots__ = ("name", "root", "path", "package", "data", "sha256", "sites")


def _absolute_name(name, namespace, level):
    if not level:
        return name
    if type(namespace) is not dict:
        namespace = None
    package = namespace.get("__package__") if namespace else None
    if package is None and namespace:
        spec = namespace.get("__spec__")
        package = getattr(spec, "parent", None) if spec is not None else None
        if package is None and type(namespace.get("__name__")) is str:
            package = namespace["__name__"] if "__path__" in namespace else namespace["__name__"].rpartition(".")[0]
    if not package or type(package) is not str:
        raise ImportError("attempted relative import with no known parent package")
    parts = package.split(".")
    keep = len(parts) - (level - 1)
    if keep <= 0:
        raise ImportError("attempted relative import beyond top-level package")
    base = ".".join(parts[:keep])
    return base + "." + name if name else base


def _position(frame):
    """``(line, end line, column, end column)`` of the instruction ``frame`` is executing, or ``None``."""
    index = frame.f_lasti >> 1
    count = 0
    for position in frame.f_code.co_positions():
        if count == index:
            return position if None not in position else None
        count += 1
    return None


def _frame_source(frame):
    """Classify the frame that requests an import: ``("closure", entry)``, ``("dependency", None)``, ``("boot", None)``
    or ``("other", None)`` (interpreter-shipped code and code compiled from strings).  The classification uses the
    code object's file name, which closure and dependency code cannot choose, never ``__name__``."""
    if frame.f_globals is _BOOT_GLOBALS:
        return "boot", None
    filename = frame.f_code.co_filename
    entry = _STATE["by_file"].get(filename)
    if entry is not None:
        return "closure", entry
    if filename in _STATE["runtime_files"]:
        return "dependency", None
    if filename.startswith("closure/"):
        return "unknown_closure", None
    return "other", None


def _site_allows(entry, position, name):
    """True when the executing instruction is, by exact position, a recorded import site of this file naming ``name``."""
    names = entry.sites.get(position) if position is not None else None
    return names is not None and name in names


def _refuse_closure(entry, frame, name):
    """Approve ``name`` for a closure frame at its executing instruction; record the violation before refusing."""
    if not _site_allows(entry, _position(frame), name):
        _violation("undeclared_import:" + name)
        raise ModuleNotFoundError("closure import refused: undeclared_import:" + name, name=name)
    if name.partition(".")[0] in DENIED_IMPORTS:
        _violation("forbidden_import:" + name)
        raise ModuleNotFoundError("closure import refused: forbidden_import:" + name, name=name)


def _admit(frame, name, form="import"):
    """The one import policy, applied to every route (statement, literal call, cache hit, indirect call, relative
    form).  ``form`` is ``"import"`` for the statement and ``__import__`` and ``"import_module"`` for that function."""
    kind, entry = _frame_source(frame)
    if kind == "closure":
        _refuse_closure(entry, frame, name)
    elif kind == "unknown_closure":
        _violation("undeclared_import:" + name)
        raise ModuleNotFoundError("closure import refused: undeclared_import:" + name, name=name)
    elif kind == "dependency":
        if name.partition(".")[0] in DENIED_IMPORTS and (form, name) not in DEPENDENCY_IMPORT_OPERATIONS:
            _violation("forbidden_dependency_import:" + name)
            raise ModuleNotFoundError("dependency import refused: forbidden_dependency_import:" + name, name=name)
    return kind


def _resolve_relative(name, package):
    """Absolute name of a relative ``importlib.import_module`` request (the arithmetic of ``importlib._bootstrap``),
    or ``None`` when the arguments are not a resolvable relative request."""
    if type(name) is not str or type(package) is not str or not package:
        return None
    level = len(name) - len(name.lstrip("."))
    bits = package.rsplit(".", level - 1)
    if len(bits) < level:
        return None
    return bits[0] + "." + name[level:] if name[level:] else bits[0]


def _import_targets(frame, name, namespace, level):
    """Every absolute name an ``__import__`` call can resolve to: the real import resolves a relative name against the
    ``globals`` argument, so that is checked as well as the requesting frame's own globals."""
    if not level:
        return [name]
    found = []
    for candidate in (frame.f_globals, namespace):
        try:
            absolute = _absolute_name(name, candidate, level)
        except ImportError:
            continue
        if absolute not in found:
            found.append(absolute)
    return found


class _ImportlibProxy:
    """What ``import importlib`` yields inside a closure module: only the mediated ``import_module``."""

    __slots__ = ("import_module",)

    def __init__(self, function):
        self.import_module = function


def _mediated_import(name, globals=None, locals=None, fromlist=(), level=0):
    """Installed as ``builtins.__import__``: every ``import`` statement and ``__import__`` call of every frame."""
    frame = sys._getframe(1)
    if not _STATE["armed"] or frame.f_globals is _BOOT_GLOBALS:
        return _REAL_IMPORT(name, globals, locals, fromlist, level)
    kind, entry = _frame_source(frame)
    if kind in ("closure", "unknown_closure"):
        targets = _import_targets(frame, name, globals, level)
        if not targets:
            raise ImportError("attempted relative import with no known parent package")
        for absolute in targets:
            _admit(frame, absolute)
            for item in fromlist or ():
                if type(item) is str and item != "*" and (absolute + "." + item) in sys.modules:
                    _admit(frame, absolute + "." + item)
        module = _REAL_IMPORT(name, globals, locals, fromlist, level)
        return _STATE["proxy"] if targets[0] == "importlib" else module
    if kind == "dependency":
        dynamic = frame.f_code.co_code[frame.f_lasti] != _IMPORT_STATEMENT_OPCODE
        for absolute in _import_targets(frame, name, globals, level):
            _admit(frame, absolute)
            if dynamic:
                _dependency_dynamic_operation(frame, "import", absolute)
            for item in fromlist or ():
                if type(item) is str and item != "*" and (absolute + "." + item) in sys.modules:
                    _admit(frame, absolute + "." + item)
                if dynamic and type(item) is str and item != "*" and (absolute + "." + item) in _STATE["table"]:
                    _dependency_dynamic_operation(frame, "import", absolute + "." + item)
    return _REAL_IMPORT(name, globals, locals, fromlist, level)


def _mediated_import_module(name, package=None):
    """Installed as ``importlib.import_module`` and handed to closure code as the only ``importlib`` attribute."""
    frame = sys._getframe(1)
    if _STATE["armed"] and frame.f_globals is not _BOOT_GLOBALS:
        kind, _entry = _frame_source(frame)
        if kind in ("closure", "unknown_closure"):
            if type(name) is not str or package is not None or not name or name.startswith("."):
                _violation("dynamic_import_not_literal:importlib")
                raise ImportError("closure import refused: dynamic_import_not_literal")
            _admit(frame, name, "import_module")
        elif kind == "dependency" and type(name) is str:
            absolute = _resolve_relative(name, package) if name.startswith(".") else name
            if absolute is not None:
                _admit(frame, absolute, "import_module")
                _dependency_dynamic_operation(frame, "import_module", absolute)
    return _REAL_IMPORT_MODULE(name, package)


def _mediated_find_spec(name, package=None):
    """Installed as ``importlib.util.find_spec``: the supported "find a spec" operation, decided BEFORE the real function's
    cache shortcut (it returns a loaded module's spec without consulting any finder), so a cached target is an operation
    exactly like an uncached one.  The importer is the CALLER (relative names resolve against ``package`` first); the real
    function's own internal requests (its parent import, its finder call) are not declared separately: while it runs, a
    request made by its own code file is attributed to this call."""
    frame = sys._getframe(1)
    if _STATE["armed"] and frame.f_globals is not _BOOT_GLOBALS:
        kind, _entry = _frame_source(frame)
        if kind in ("closure", "unknown_closure"):
            _violation("undeclared_import:" + str(name)[:80])
            raise ImportError("closure import refused: undeclared_import:" + str(name)[:80])
        if kind == "dependency" and type(name) is str:
            absolute = _resolve_relative(name, package) if name.startswith(".") else name
            if absolute is not None:
                _admit(frame, absolute, "find_spec")
                _dependency_dynamic_operation(frame, "find_spec", absolute)
    depth, ident = _STATE["find_spec_depth"], _GET_IDENT()
    depth[ident] = depth.get(ident, 0) + 1
    try:
        return _STATE["real_find_spec"](name, package)
    finally:
        depth[ident] -= 1
        if not depth[ident]:
            del depth[ident]


def _install_find_spec(module):
    real = module.find_spec
    if real is not _mediated_find_spec:
        _STATE["real_find_spec"], _STATE["find_spec_file"] = real, real.__code__.co_filename
        module.find_spec = _mediated_find_spec


def _is_import_plumbing(frame):
    filename = frame.f_code.co_filename
    return filename.startswith("<frozen importlib") or filename in _PLUMBING_FILES


def _mediated_gcd_import(name, package=None, level=0):
    """Installed as ``importlib._bootstrap._gcd_import``, the private function behind ``importlib.import_module``: a request
    made by dependency code itself is an ``import_module`` operation like the public one, whether the module is cached or
    not; requests made by the import machinery (frozen importlib frames and ``importlib/__init__``) pass unchanged."""
    frame = sys._getframe(1)
    if _STATE["armed"] and frame.f_globals is not _BOOT_GLOBALS and not _is_import_plumbing(frame):
        kind, _entry = _frame_source(frame)
        if kind in ("closure", "unknown_closure"):
            _violation("dynamic_import_not_literal:importlib")
            raise ImportError("closure import refused: dynamic_import_not_literal")
        if kind == "dependency" and type(name) is str:
            absolute = _resolve_relative("." * level + name, package) if level else name
            if absolute is not None:
                _admit(frame, absolute, "import_module")
                _dependency_dynamic_operation(frame, "import_module", absolute)
    return _STATE["real_gcd_import"](name, package, level)


def _gate_request(frame, name, form):
    """Gate one explicit import-system request issued by non-boot code: closure code may not make it at all, dependency code
    only as a declared or reviewed operation.  Frames of the import machinery are never gated (they act for a request that
    was already decided)."""
    kind, _entry = _frame_source(frame)
    if kind in ("closure", "unknown_closure"):
        _violation("dynamic_import_not_literal:importlib")
        raise ImportError("closure import refused: dynamic_import_not_literal")
    if kind == "dependency" and type(name) is str:
        _admit(frame, name, form)
        _dependency_dynamic_operation(frame, form, name)


def _gate_private(frame, form, name_of, args, kwargs):
    """Gate the call of a replaced entry point by ITS caller ``frame`` (the machinery's own calls and the boot frame pass)."""
    if _STATE["armed"] and frame.f_globals is not _BOOT_GLOBALS and not _is_import_plumbing(frame):
        name = name_of(args, kwargs)
        if type(name) is str:
            _gate_request(frame, name, form)


def _mediated_private(real, form, name_of):
    """A replacement for one reachable private or semi-public function of the import system.  Its caller is the
    requester.  The inner functions carry the code names ``_importer`` recognises (a function's ``__name__`` does not change
    its code name), so the finder attributes the request to the frame that CALLED the replacement."""
    if form == "find_spec":
        def _private_find_spec(*args, **kwargs):
            _gate_private(sys._getframe(1), "find_spec", name_of, args, kwargs)
            return real(*args, **kwargs)
        wrapper = _private_find_spec
    else:
        def _private_import_module(*args, **kwargs):
            _gate_private(sys._getframe(1), "import_module", name_of, args, kwargs)
            return real(*args, **kwargs)
        wrapper = _private_import_module
    wrapper.__name__ = getattr(real, "__name__", wrapper.__name__)
    _WRAPPERS.append(wrapper)
    return wrapper


def _method_mediator(real_function, form, name_of, skip):
    """Replacement body of a method of a finder or loader class (``skip`` leading arguments are the instance or class).  The
    class keeps its descriptor kind (static, class or instance method), so callers and the machinery see the same shape."""
    if form == "find_spec":
        def _mediated_finder_method(*args, **kwargs):
            _gate_private(sys._getframe(1), "find_spec", name_of, args[skip:], kwargs)
            return real_function(*args, **kwargs)
        wrapper = _mediated_finder_method
    else:
        def _mediated_loader_method(*args, **kwargs):
            _gate_private(sys._getframe(1), "import_module", name_of, args[skip:], kwargs)
            return real_function(*args, **kwargs)
        wrapper = _mediated_loader_method
    wrapper.__name__ = getattr(real_function, "__name__", wrapper.__name__)
    _WRAPPERS.append(wrapper)
    return wrapper


def _first_argument(args, kwargs):
    return args[0] if args else kwargs.get("name", kwargs.get("fullname"))


def _spec_name(args, kwargs):
    spec = args[0] if args else kwargs.get("spec")
    return getattr(spec, "name", None)


def _module_name(args, kwargs):
    module = args[0] if args else kwargs.get("module")
    name = getattr(getattr(module, "__spec__", None), "name", None)
    return name if type(name) is str else getattr(module, "__name__", None)


def _holder_label(referrer, depth=0):
    """A short, deterministic description of an object that holds a reference (for the refusal detail only)."""
    if type(referrer) is _FUNCTION_TYPE:
        return "function:" + referrer.__qualname__[:60]
    if type(referrer) is type:
        return "class:" + referrer.__qualname__[:60]
    kind = type(referrer).__name__
    if depth < 2 and kind in ("tuple", "cell", "list", "set", "dict", "mappingproxy"):
        outer = sorted({_holder_label(item, depth + 1) for item in gc.get_referrers(referrer)
                        if not (type(item) is _FRAME_TYPE and item.f_globals is _BOOT_GLOBALS)})
        return kind + "<" + ",".join(outer[:3]) + ">"
    return kind


def _captured_references(reals, own, modules):
    """Sorted descriptions of every object, other than the ``own`` ones, that still holds one of the ``reals``.  The query is
    the collector's referrer relation, so it covers module namespaces, function defaults and closure cells, containers,
    class and instance attributes and suspended frames, not only the attributes of loaded modules.  ``own`` are the
    containers and cells this module itself created for the originals."""
    gc.collect()
    ours = {id(item) for item in own}
    namespaces = {}
    for name, module in list(modules.items()):
        namespace = getattr(module, "__dict__", None)
        if type(namespace) is dict:
            namespaces[id(namespace)] = name
    found = set()
    for referrer in gc.get_referrers(*reals):
        if id(referrer) in ours or (type(referrer) is _FRAME_TYPE and referrer.f_globals is _BOOT_GLOBALS):
            continue
        if type(referrer) is dict:
            keys = sorted(key if type(key) is str else type(key).__name__ for key, value in list(referrer.items())
                          if any(value is real for real in reals))
            owner = namespaces.get(id(referrer))
            label = ("module:" + owner if owner is not None else _holder_label(referrer)) + "." + ",".join(keys)
        else:
            label = _holder_label(referrer)
        found.add(label[:100])
    return sorted(found)


# (owner attribute path, attribute, form, name extractor): module-level functions of the import system that take a NAME, a
# SPEC or a MODULE and load, create, execute or look up a module.  The names, specs and modules a caller holds may have
# been taken from ``sys.modules`` or a retained spec before arming, so these are mediated by what they do with the name.
_FUNCTION_ENTRY_POINTS = (
    ("boot", "_find_and_load", "import_module", _first_argument), ("boot", "_find_and_load_unlocked", "import_module", _first_argument),
    ("boot", "_load", "import_module", _spec_name), ("boot", "_load_unlocked", "import_module", _spec_name),
    ("boot", "module_from_spec", "import_module", _spec_name), ("util", "module_from_spec", "import_module", _spec_name),
    ("boot", "_exec", "import_module", _spec_name), ("importlib", "reload", "import_module", _module_name),
    ("imp", "create_builtin", "import_module", _spec_name), ("imp", "exec_builtin", "import_module", _module_name),
    ("imp", "init_frozen", "import_module", _first_argument), ("imp", "get_frozen_object", "import_module", _first_argument),
    ("importlib", "find_loader", "find_spec", _first_argument))
# (class, attribute, form, name extractor) for the methods of the built-in/frozen/path finders and loaders.  A hand-made
# spec for a built-in or frozen module is created and executed by these methods without any lookup, so they decide too.
_METHOD_ENTRY_POINTS = (
    ("BuiltinImporter", "find_spec", "find_spec", _first_argument), ("FrozenImporter", "find_spec", "find_spec", _first_argument),
    ("PathFinder", "find_spec", "find_spec", _first_argument), ("FileFinder", "find_spec", "find_spec", _first_argument),
    ("BuiltinImporter", "create_module", "import_module", _spec_name), ("BuiltinImporter", "exec_module", "import_module", _module_name),
    ("BuiltinImporter", "load_module", "import_module", _first_argument),
    ("FrozenImporter", "create_module", "import_module", _spec_name), ("FrozenImporter", "exec_module", "import_module", _module_name),
    ("FrozenImporter", "load_module", "import_module", _first_argument))


def _install_entry_points():
    """Replace EVERY supported or reachable import-system entry point with a mediating function, then require that nothing
    else still holds an original.  Fails closed (``captured_import_reference``) if something does: a retained reference
    (a module attribute, a default argument, a closure cell, a container, a class or instance attribute) to an unmediated
    original would perform a cached, indirect or retained operation that bypasses the contract."""
    boot = sys.modules["_frozen_importlib"]
    external = sys.modules["_frozen_importlib_external"]
    namespaces = {"boot": boot, "util": sys.modules["importlib.util"], "importlib": importlib, "imp": _imp}
    classes = {"BuiltinImporter": boot.BuiltinImporter, "FrozenImporter": boot.FrozenImporter,
               "PathFinder": external.PathFinder, "FileFinder": external.FileFinder}
    reals = [_REAL_IMPORT, _REAL_IMPORT_MODULE, boot.__import__, boot._gcd_import, namespaces["util"].find_spec]
    held = []
    importlib.import_module = _mediated_import_module
    importlib.__import__ = _mediated_import
    boot.__import__ = _mediated_import
    _STATE["real_gcd_import"] = boot._gcd_import
    boot._gcd_import = _mediated_gcd_import
    _install_find_spec(namespaces["util"])
    for owner_key, attribute, form, name_of in _FUNCTION_ENTRY_POINTS:
        owner = namespaces[owner_key]
        real = getattr(owner, attribute, None)
        if real is not None:
            reals.append(real)
            setattr(owner, attribute, _mediated_private(real, form, name_of))
    for class_key, attribute, form, name_of in _METHOD_ENTRY_POINTS:
        owner = classes[class_key]
        raw = owner.__dict__.get(attribute)
        if raw is None:
            continue
        function = getattr(raw, "__func__", raw)
        reals.extend((function, raw))
        held.append(raw)
        replacement = _method_mediator(function, form, name_of, 0 if isinstance(raw, staticmethod) else 1)
        setattr(owner, attribute, raw.__class__(replacement) if isinstance(raw, (classmethod, staticmethod)) else replacement)
    own = [_BOOT_GLOBALS, _STATE, reals, held, _WRAPPERS]
    for wrapper in _WRAPPERS:
        own.extend(wrapper.__closure__ or ())
    captured = _captured_references(reals, own, sys.modules)
    if captured:
        _fail("captured_import_reference", names=captured[:20])


class _Loader:
    """Serve closure module code exclusively from the bytes captured by the parent."""

    def __init__(self):
        self.created = {}

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        entry = _STATE["entries"][module.__spec__.name]
        code = compile(entry.data, "closure/" + entry.root + "/" + entry.path, "exec", dont_inherit=True)
        exec(code, module.__dict__)
        self.created[entry.name] = module

    def get_source(self, fullname):
        entry = _STATE["entries"].get(fullname)
        return None if entry is None else entry.data.decode("utf-8", "replace")

    def is_package(self, fullname):
        return _STATE["entries"][fullname].package


class _RuntimeLoader:
    """Serve census-table source modules: hashed on read, compiled from the same bytes."""

    def __init__(self):
        self.created = {}

    def create_module(self, spec):
        return None

    def _row(self, fullname):
        return _STATE["table"][fullname]

    def _read(self, fullname):
        row = self._row(fullname)
        try:
            data = _read_path(row[2], 64 << 20)
        except OSError:
            _violation("runtime_file_unreadable:" + fullname)
            raise ImportError("runtime file unreadable: " + fullname, name=fullname)
        if _sha(data) != row[3]:
            _violation("runtime_file_changed:" + fullname)
            raise ImportError("runtime file changed: " + fullname, name=fullname)
        return data

    def exec_module(self, module):
        name = module.__spec__.name
        data = self._read(name)
        code = compile(data, self._row(name)[2], "exec", dont_inherit=True)
        exec(code, module.__dict__)
        self.created[name] = module
        if name == "importlib.util":
            _install_find_spec(module)

    def get_source(self, fullname):
        return self._read(fullname).decode("utf-8", "replace")

    def get_filename(self, fullname):
        return self._row(fullname)[2]

    def is_package(self, fullname):
        return bool(self._row(fullname)[4])

    def get_data(self, path):
        raise OSError("resource access is not part of the closure contract")


def _open_write_denied(path):
    """Open ``path`` read-only with a share mode that refuses writers while the descriptor stays open (Windows)."""
    handle = _K32.CreateFileW(path, 0x80000000, 0x00000001, None, 3, 0x80, None)  # GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING
    if handle is None or handle == _wt.HANDLE(-1).value:
        raise OSError("could not open native file with writers denied")
    return msvcrt.open_osfhandle(handle, os.O_RDONLY)


class _BytesSource:
    def __init__(self, data):
        self.data, self.size = data, len(data)

    def read(self, offset, count):
        if offset < 0 or count < 0 or offset + count > self.size:
            raise ValueError("truncated")
        return self.data[offset:offset + count]


class _FileSource:
    """Seek-based reader: parsing a large library never loads it whole."""

    def __init__(self, path):
        self.fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
        self.size = os.fstat(self.fd).st_size

    def read(self, offset, count):
        if offset < 0 or count < 0 or offset + count > self.size:
            raise ValueError("truncated")
        os.lseek(self.fd, offset, 0)
        chunks, left = [], count
        while left:
            piece = os.read(self.fd, left)
            if not piece:
                raise ValueError("truncated")
            chunks.append(piece)
            left -= len(piece)
        return b"".join(chunks)

    def close(self):
        os.close(self.fd)


def _uint(source, offset, size, order="little"):
    return int.from_bytes(source.read(offset, size), order)


def _cstring(source, offset, limit=4096):
    if offset < 0 or offset >= source.size:
        raise ValueError("string_offset")
    raw = source.read(offset, min(limit, source.size - offset))
    end = raw.find(b"\0")
    if end < 0:
        raise ValueError("unterminated_string")
    return raw[:end].decode("ascii")


_ELF_UNSUPPORTED = {15: "rpath", 29: "runpath", 0x7FFFFFFD: "filter", 0x7FFFFFFE: "auxiliary", 0x6FFFFEFC: "audit",
                    0x6FFFFEFB: "depaudit"}


def _elf_dynamic(source):
    """``(needed names, soname, unsupported kinds)`` of an ELF object, read from its program and dynamic headers."""
    if source.read(0, 4) != b"\x7fELF":
        raise ValueError("not_elf")
    ident = source.read(4, 2)
    if ident[0] not in (1, 2) or ident[1] not in (1, 2):
        raise ValueError("elf_class")
    wide = ident[0] == 2
    order = "little" if ident[1] == 1 else "big"
    word = 8 if wide else 4
    if wide:
        phoff, phentsize, phnum = _uint(source, 32, 8, order), _uint(source, 54, 2, order), _uint(source, 56, 2, order)
    else:
        phoff, phentsize, phnum = _uint(source, 28, 4, order), _uint(source, 42, 2, order), _uint(source, 44, 2, order)
    if phnum > 256 or phentsize < (56 if wide else 32):
        raise ValueError("elf_program_headers")
    loads, dynamic = [], None
    for index in range(phnum):
        base = phoff + index * phentsize
        kind = _uint(source, base, 4, order)
        if wide:
            offset, vaddr, filesz = _uint(source, base + 8, 8, order), _uint(source, base + 16, 8, order), _uint(source, base + 32, 8, order)
        else:
            offset, vaddr, filesz = _uint(source, base + 4, 4, order), _uint(source, base + 8, 4, order), _uint(source, base + 16, 4, order)
        if kind == 1:
            loads.append((vaddr, offset, filesz))
        elif kind == 2:
            dynamic = (offset, filesz)
    if dynamic is None:
        raise ValueError("elf_no_dynamic")
    offset, size = dynamic
    if size > (1 << 20):
        raise ValueError("elf_dynamic_size")
    entries = []
    for position in range(offset, offset + size, 2 * word):
        tag = _uint(source, position, word, order)
        if tag == 0:
            break
        entries.append((tag, _uint(source, position + word, word, order)))
    strtab = None
    for tag, value in entries:
        if tag == 5:
            strtab = value
    if strtab is None:
        raise ValueError("elf_no_strtab")
    table = None
    for vaddr, file_offset, filesz in loads:
        if vaddr <= strtab < vaddr + filesz:
            table = file_offset + strtab - vaddr
    if table is None:
        raise ValueError("elf_unmapped_strtab")
    needed, soname, unsupported = [], None, []
    for tag, value in entries:
        if tag == 1:
            needed.append(_cstring(source, table + value))
        elif tag == 14:
            soname = _cstring(source, table + value)
        elif tag in _ELF_UNSUPPORTED:
            unsupported.append(_ELF_UNSUPPORTED[tag])
    return needed, soname, unsupported


def _pe_imports(source):
    """``(imported DLL names lower-cased, unsupported kinds)`` of a PE image (import directory; delay-load refused)."""
    if source.read(0, 2) != b"MZ":
        raise ValueError("not_pe")
    pe = _uint(source, 0x3C, 4)
    if source.read(pe, 4) != b"PE\0\0":
        raise ValueError("pe_signature")
    section_count, optional_size, optional = _uint(source, pe + 6, 2), _uint(source, pe + 20, 2), pe + 24
    magic = _uint(source, optional, 2)
    if magic == 0x10B:
        count_at, directories = optional + 92, optional + 96
    elif magic == 0x20B:
        count_at, directories = optional + 108, optional + 112
    else:
        raise ValueError("pe_magic")
    directory_count = _uint(source, count_at, 4)
    if section_count > 96:
        raise ValueError("pe_sections")
    sections = []
    for index in range(section_count):
        base = optional + optional_size + 40 * index
        virtual_size, virtual_address = _uint(source, base + 8, 4), _uint(source, base + 12, 4)
        raw_size, raw_pointer = _uint(source, base + 16, 4), _uint(source, base + 20, 4)
        sections.append((virtual_address, max(virtual_size, raw_size), raw_pointer))

    def locate(rva):
        for virtual_address, span, raw_pointer in sections:
            if virtual_address <= rva < virtual_address + span:
                return raw_pointer + rva - virtual_address
        raise ValueError("pe_unmapped_rva")

    def directory(index):
        if index >= directory_count:
            return 0
        return _uint(source, directories + 8 * index, 4)

    imports = []
    rva = directory(1)
    if rva:
        position = locate(rva)
        for _ in range(1024):
            descriptor = source.read(position, 20)
            if descriptor == b"\0" * 20:
                break
            imports.append(_cstring(source, locate(int.from_bytes(descriptor[12:16], "little")), 256).lower())
            position += 20
        else:
            raise ValueError("pe_import_count")
    return imports, (["delay_load"] if directory(13) else [])


def _soname_of(source):
    """``DT_SONAME`` of an ELF image behind ``source`` (``None`` when absent or unreadable); Linux only."""
    if not sys.platform.startswith("linux"):
        return None
    try:
        return _elf_dynamic(source)[1]
    except (ValueError, IndexError, OverflowError, OSError):
        return None


def _names_of(path, soname):
    """Names by which the dynamic loader matches ``path`` against a dependency entry once the object is loaded.

    Windows matches the lower-cased module file name.  glibc matches a ``DT_NEEDED`` string against the name an object
    was opened with and against its ``DT_SONAME``; a native staged from ``/proc/self/fd/N`` was opened with that
    descriptor path, so on Linux only the ``DT_SONAME`` can match and an object without one has no name at all."""
    if sys.platform == "win32":
        return {os.path.basename(path).lower()}
    return {soname} if soname else set()


def _file_names(path):
    source = None
    try:
        source = _FileSource(path) if sys.platform.startswith("linux") else None
    except OSError:
        source = None
    try:
        return _names_of(path, _soname_of(source) if source is not None else None)
    finally:
        if source is not None:
            source.close()


def _native_index(natives):
    """``(pins, index)``: ``real path -> (path, sha)`` and ``name -> {real path}`` over the pinned natives."""
    pins, index = {}, {}
    for path, digest in natives:
        real = os.path.normcase(os.path.realpath(path))
        pins[real] = (path, digest)
        for name in _file_names(path):
            index.setdefault(name, set()).add(real)
    return pins, index


def _native_needed(name, data):
    """Dependency list of a native image's hashed bytes, or an ``ImportError`` recorded as a violation.

    Refused in every mode: an unparsable image, ``RPATH``/``RUNPATH``, audit/filter/auxiliary entries, PE delay-load
    imports and dependencies named by a path.
    """
    source = _BytesSource(data)
    try:
        if sys.platform == "win32":
            needed, unsupported = _pe_imports(source)
        else:
            needed, _soname, unsupported = _elf_dynamic(source)
    except (ValueError, IndexError, OverflowError):
        _violation("native_closure_unparsable:" + name)
        raise ImportError("native dependency list could not be read: " + name, name=name)
    if unsupported:
        _violation("native_dependency_unsupported:" + name + ":" + unsupported[0])
        raise ImportError("native dependency configuration unsupported: " + name, name=name)
    for dependency in needed:
        if "/" in dependency or "\\" in dependency:
            _violation("native_dependency_unsupported:" + name + ":path")
            raise ImportError("native dependency named by path: " + name, name=name)
    return needed


def _native_bytes(name, path, expected):
    """Read a pinned native (Windows: through a writer-denying handle kept until exit) and compare its hash."""
    try:
        if sys.platform == "win32":
            fd = _open_write_denied(path)
            _NATIVE.locks.append(fd)
            chunks = []
            while True:
                piece = os.read(fd, 1 << 20)
                if not piece:
                    break
                chunks.append(piece)
            data = b"".join(chunks)
        else:
            data = _read_path(path, 256 << 20)
    except OSError:
        _violation("runtime_file_unreadable:" + name)
        raise ImportError("runtime file unreadable: " + name, name=name)
    if _sha(data) != expected:
        _violation("runtime_file_changed:" + name)
        raise ImportError("runtime file changed: " + name, name=name)
    return data


def _apiset_host(dependency):
    """Normalised real path of the loaded module that hosts the Windows API-set import ``dependency`` (as the loader's
    own schema resolves it), or ``None`` when it resolves to no loaded module."""
    try:
        handle = _K32.GetModuleHandleW(dependency)
        if not handle:
            return None
        buffer = _APISET_PATH()
        if not _K32.K32GetModuleFileNameExW(_K32.GetCurrentProcess(), handle, buffer, 32768):
            return None
        text = buffer.value
    except (OSError, ValueError, AttributeError):
        return None
    return os.path.normcase(os.path.realpath(text[4:] if text.startswith("\\\\?\\") else text))


def _native_plan(name, needed):
    """Ordered ``(path, sha, bytes, real path)`` of the pinned dependencies to load first (dependencies before
    dependents), resolved from hashed bytes only; ``ImportError`` (violation recorded) when any dependency is neither
    already mapped nor exactly one pinned native.  Discovery (non-strict) plans nothing."""
    if not _STATE["strict"]:
        return []
    windows = sys.platform == "win32"
    satisfied, pins, index = _STATE["satisfied"], _STATE["native_pins"], _STATE["native_index"]
    plan, seen, active = [], set(), set()

    def visit(owner, dependencies, depth):
        for dependency in dependencies:
            if dependency in satisfied:
                continue
            if windows and dependency.startswith(("api-ms-", "ext-ms-")):
                host = _apiset_host(dependency)
                if host is None or host not in pins:
                    _violation("native_apiset_unresolved:" + owner[:60] + ":" + dependency[:60])
                    raise ImportError("API-set import is not hosted by a loaded pinned native: " + owner, name=owner)
                continue
            candidates = index.get(dependency, ())
            if len(candidates) != 1:
                _violation(("native_dependency_ambiguous:" if candidates else "native_dependency_unpinned:") +
                           owner[:60] + ":" + dependency[:60])
                raise ImportError("native dependency is not resolvable to one pinned native: " + owner, name=owner)
            real = next(iter(candidates))
            if real in active:
                _violation("native_dependency_cycle:" + owner[:60] + ":" + dependency[:60])
                raise ImportError("native dependency cycle: " + owner, name=owner)
            if real in seen:
                continue
            if depth >= MAX_NATIVE_DEPTH or len(seen) >= MAX_NATIVE_PLAN:
                _violation("native_dependency_plan_too_large:" + owner[:60])
                raise ImportError("native dependency plan too large: " + owner, name=owner)
            seen.add(real)
            active.add(real)
            path, digest = pins[real]
            data = _native_bytes(dependency, path, digest)
            visit(dependency, _native_needed(dependency, data), depth + 1)
            active.discard(real)
            plan.append((path, digest, data, real))

    visit(name, needed, 0)
    return plan


def _sealed_memfd(label, data, name):
    fd = os.memfd_create(label, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        _write_all(fd, data)
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE)
    except OSError:
        os.close(fd)
        _violation("native_seal_failed:" + name)
        raise ImportError("could not seal native module: " + name, name=name)
    return fd


def _memfd_key(fd):
    """``"major:minor inode"`` of a memfd, spelled the way ``/proc/self/maps`` spells a mapping of it."""
    info = os.fstat(fd)
    return "%02x:%02x %d" % (os.major(info.st_dev), os.minor(info.st_dev), info.st_ino)


def _mapped_memfds():
    """Device-and-inode keys of every mapping of a memfd this loader creates (``/memfd:pvc-ext``/``/memfd:pvc-dep``) in
    this process; ``None`` when the maps are unreadable.  Other memfd mappings (for example libffi's) are not keyed."""
    try:
        text = _read_path("/proc/self/maps", 64 << 20).decode("utf-8", "replace")
    except OSError:
        return None
    found = set()
    for line in text.splitlines():
        parts = line.split(None, 5)
        if len(parts) == 6 and parts[5].startswith(("/memfd:pvc-ext", "/memfd:pvc-dep")):
            found.add(parts[3] + " " + parts[4])
    return found


def _preload_native(path, digest, data, real):
    """Load one planned dependency from the verified bytes so later list entries resolve to it, not to a search."""
    label = os.path.basename(path)[:60]
    if sys.platform == "win32":
        if not _K32.LoadLibraryExW(real, None, 0x1100):
            _violation("native_preload_failed:" + label)
            raise ImportError("could not load pinned native dependency: " + label, name=label)
        names = _names_of(path, None)
    else:
        if _dlopen is None:
            _violation("native_preload_unavailable:" + label)
            raise ImportError("pinned native dependencies cannot be preloaded here: " + label, name=label)
        names = _names_of(path, _soname_of(_BytesSource(data)))
        if not names:
            _violation("native_dependency_unnamed:" + label)
            raise ImportError("pinned native dependency has no DT_SONAME the loader could match: " + label, name=label)
        fd = _NATIVE.retain(_sealed_memfd("pvc-dep", data, label), label)
        try:
            _dlopen("/proc/self/fd/%d" % fd, os.RTLD_NOW)
        except OSError:
            _violation("native_preload_failed:" + label)
            raise ImportError("could not load pinned native dependency: " + label, name=label)
        _NATIVE.confirm(fd, label)
    _STATE["satisfied"].update(names)
    _NATIVE.plan.append([path, digest])


class _NativeLoader:
    """Load an extension module from a sealed memfd holding the hash-checked bytes (Linux), or from the file while a
    writer-denying handle is held and re-hashed after the run (Windows, not run in this repository's CI yet).  The
    transitive dependency plan is resolved from hashed bytes and loaded first, so the dynamic loader finds every
    dependency of the extension already in this process (see ``_native_plan``)."""

    def __init__(self):
        self.created = {}
        self.locks = []
        self.plan = []
        self.retained = {}

    def retain(self, fd, label):
        """Keep ``fd`` open until exit and record the identity of the object behind it.  The loader names a memfd
        object ``/proc/self/fd/N``, so a closed and reused descriptor number would alias a different object; a
        second memfd with an already recorded device and inode is refused as well."""
        try:
            key = _memfd_key(fd)
        except OSError:
            _violation("native_identity_unreadable:" + label)
            raise ImportError("native object identity could not be read: " + label, name=label)
        if key in self.retained or fd in self.retained.values():
            _violation("native_identity_duplicate:" + label)
            raise ImportError("native object identity is not unique: " + label, name=label)
        self.retained[key] = fd
        return fd

    def confirm(self, fd, label):
        """After a load: ``/proc/self/maps`` must show a mapping of exactly this memfd (device and inode)."""
        mapped = _mapped_memfds()
        if mapped is None or _memfd_key(fd) not in mapped:
            _violation("native_identity_unconfirmed:" + label)
            raise ImportError("native object is not the one loaded from the verified bytes: " + label, name=label)

    def stage(self, name):
        row = _STATE["table"][name]
        windows = sys.platform == "win32"
        if not windows and not (sys.platform.startswith("linux") and hasattr(os, "memfd_create") and _dlopen is not None):
            _violation("native_load_unsupported:" + name)
            raise ImportError("native module loading needs memfd and dlopen on Linux or a Windows write-denied handle: " + name, name=name)
        data = _native_bytes(name, row[2], row[3])
        for step in _native_plan(name, _native_needed(name, data)):
            _preload_native(*step)
        if windows:
            _STATE["native_paths"].add(row[2])
            return None, row[2]
        fd = self.retain(_sealed_memfd("pvc-ext", data, name), name)
        path = "/proc/self/fd/%d" % fd
        try:
            _dlopen(path, os.RTLD_NOW)
        except OSError:
            _violation("native_preload_failed:" + name)
            raise ImportError("could not load pinned native module: " + name, name=name)
        self.confirm(fd, name)
        _STATE["native_paths"].add(path)
        return fd, path


_RUNTIME = _RuntimeLoader()
_NATIVE = _NativeLoader()
_CLOSURE = _Loader()


def _importer():
    """``(frame, form, decided)`` for the request the finder is answering.  ``frame`` is the frame that asked: the first
    frame, going outwards from the finder's caller, that is none of a mediating function (recognised by its CODE name in
    the bootstrap's own globals, which renaming a function's ``__name__`` does not change), import-system plumbing
    (identified by code file) or an own frame of the real ``importlib.util.find_spec`` while one runs on this thread.
    ``form`` is the operation named by the OUTERMOST mediating frame passed on the way (``find_spec`` when there was
    none), because that is the function the requester actually called.  ``decided`` is true when the walk passed an
    own frame of the real ``find_spec``: the call that started it was already decided by ``_mediated_find_spec``."""
    frame = sys._getframe(2)
    form, decided = "find_spec", False
    inside = _STATE["find_spec_depth"].get(_GET_IDENT()) and _STATE["find_spec_file"]
    while frame is not None:
        if frame.f_globals is _BOOT_GLOBALS:
            named = _MEDIATION_FORMS.get(frame.f_code.co_name)
            if named is None:
                return frame, form, decided
            form = named
        else:
            filename = frame.f_code.co_filename
            if inside and filename == inside:
                decided = True
            elif not filename.startswith("<frozen importlib") and filename not in _PLUMBING_FILES:
                return frame, form, decided
        frame = frame.f_back
    return None, form, decided


def _dependency_operation(requester, kind, form, name, decided=False):
    """Decide a dependency's attempt to load the unpinned or ambiguous module ``name``.  The attempt is always refused as
    absent.  It is approved only when it is a declared ``(importer, form, module)`` triple (recorded as a
    ``dependency_operation:`` entry, also while discovering so the exact operations can be reviewed); every other
    attempt is a recorded violation.  The importer is the pinned census module whose code file issued the request.
    ``decided`` means the request was made on behalf of a call that ``_mediated_find_spec`` already decided and recorded
    (the real ``find_spec``'s own parent import and finder call): it is answered as absent without a second decision."""
    if decided:
        raise ModuleNotFoundError("dependency import refused: absent module " + name, name=name)
    importer = _STATE["file_names"].get(requester.f_code.co_filename) if kind == "dependency" and requester is not None else None
    triple = (importer, form, name)
    entry = DEPENDENCY_OPERATION_PREFIX + ":".join(str(item) for item in triple)
    if importer is not None and len(entry) <= 120 and (triple in _STATE["dep_ops"] or not _STATE["strict"]):
        _refused(entry)
        raise ModuleNotFoundError("dependency import refused: absent module " + name, name=name)
    _violation("undeclared_dependency_operation:" + ":".join(str(item) for item in triple))
    raise ModuleNotFoundError("dependency import refused: undeclared_dependency_operation:" + name, name=name)


def _stdlib_operation(importer, form, name):
    for row_importer, row_form, row_module, submodules in DEPENDENCY_STDLIB_OPERATIONS:
        if form == row_form and (row_importer is None or row_importer == importer) and \
                (name == row_module or (submodules and name.startswith(row_module + "."))):
            return True
    return False


def _dependency_dynamic_operation(requester, form, name):
    """Gate a dependency's DYNAMIC import operation on ``name`` (pinned or not): approved when it is a reviewed
    dependency import operation, a reviewed standard-library operation or exactly a declared ``(importer, form, module)``
    triple (recorded as a ``dependency_operation:`` entry, also while discovering so the exact operations can be
    reviewed); every other one is a recorded violation and is refused.  ``requester`` is the frame that issued the request;
    the importer is the pinned census module whose code file it runs."""
    if (form, name) in DEPENDENCY_IMPORT_OPERATIONS:
        return
    if requester is not None and _STATE["find_spec_depth"].get(_GET_IDENT()) and \
            requester.f_code.co_filename == _STATE["find_spec_file"]:
        return   # the real find_spec's own request, made on behalf of a call that was already decided (see _mediated_find_spec)
    importer = _STATE["file_names"].get(requester.f_code.co_filename) if requester is not None else None
    if _stdlib_operation(importer, form, name):
        return
    triple = (importer, form, name)
    entry = DEPENDENCY_OPERATION_PREFIX + ":".join(str(item) for item in triple)
    if importer is not None and len(entry) <= 120 and (triple in _STATE["dep_ops"] or not _STATE["strict"]):
        _refused(entry)
        return
    _violation("undeclared_dependency_operation:" + ":".join(str(item) for item in triple))
    raise ImportError("dependency import refused: undeclared_dependency_operation:" + name, name=name)


def _prefixes(name):
    parts = name.split(".")
    return [".".join(parts[:i]) for i in range(1, len(parts) + 1)]


class _Finder:
    """First and only path-less finder: closure bytes, census table, builtin/frozen hand-off, else refusal."""

    def find_spec(self, name, path=None, target=None):
        spec_cls = sys.modules["_frozen_importlib"].ModuleSpec
        entries = _STATE["entries"]
        requester, form, decided = _importer()
        kind, source = _frame_source(requester) if requester is not None else ("boot", None)
        decided = decided and kind == "dependency"
        direct = kind in ("closure", "unknown_closure")
        top = name.partition(".")[0]
        if direct:
            if source is None or not _site_allows(source, _position(requester), name):
                _violation("undeclared_import:" + name)
                raise ModuleNotFoundError("closure import refused: undeclared_import:" + name, name=name)
            if top in DENIED_IMPORTS:
                _violation("forbidden_import:" + name)
                raise ModuleNotFoundError("closure import refused: forbidden_import:" + name, name=name)
        elif top in DENIED_IMPORTS:
            _violation("forbidden_dependency_import:" + name)
            raise ModuleNotFoundError("dependency import refused: forbidden_dependency_import:" + name, name=name)
        entry = entries.get(name)
        row = _STATE["table"].get(name)
        if not direct and not decided and kind == "dependency" and form == "find_spec" and (
                entry is not None or name in sys.builtin_module_names or _imp.is_frozen(name) or
                (row is not None and row[1] != "ambiguous")):
            _dependency_dynamic_operation(requester, form, name)
        if entry is not None:
            return spec_cls(name, _CLOSURE, origin="closure:" + entry.root + "/" + entry.path, is_package=entry.package)
        if top in _STATE["owned_tops"]:
            _violation("unlisted_closure_module:" + name)
            raise ModuleNotFoundError("closure import refused: unlisted_closure_module:" + name, name=name)
        if name in sys.builtin_module_names or _imp.is_frozen(name):
            return None
        if row is None:
            if not direct:
                _dependency_operation(requester, kind, form, name, decided)
            _violation("unpinned_import:" + name)
            raise ModuleNotFoundError("closure import refused: unpinned_import:" + name, name=name)
        if row[1] == "ambiguous":
            if not direct:
                _dependency_operation(requester, kind, form, name, decided)
            _violation("ambiguous_runtime_module:" + name)
            raise ModuleNotFoundError("closure import refused: ambiguous_runtime_module:" + name, name=name)
        if row[1] == "ext":
            fd, memory_path = _NATIVE.stage(name)
            loader = sys.modules["_frozen_importlib_external"].ExtensionFileLoader(name, memory_path)
            spec = spec_cls(name, loader, origin=memory_path)
            _NATIVE.created[name] = (fd, row)
            return spec
        spec = spec_cls(name, _RUNTIME, origin=row[2], is_package=bool(row[4]))
        spec.has_location = True
        if row[4]:
            spec.submodule_search_locations = [os.path.dirname(row[2])]
        return spec


# ----------------------------------------------------------------------------------------------- audit

def _caller_allowed(frame):
    if frame.f_globals is _BOOT_GLOBALS:
        return True
    code = frame.f_code
    if (frame.f_globals.get("__name__"), code.co_name) in DYNAMIC_STDLIB_CALLERS:
        spec = frame.f_globals.get("__spec__")
        return getattr(spec, "loader", None) is _RUNTIME and not code.co_filename.startswith("closure/")
    return False


def _audit(event, args):
    if not _STATE["armed"]:
        return
    if event == "import":
        meta = _STATE["meta"]
        if len(sys.meta_path) != len(meta) or any(a is not b for a, b in zip(sys.meta_path, meta)):
            _violation("meta_path_mutated")
            raise ImportError("import refused: import state mutated")
        if sys.path_hooks != _STARTUP_HOOKS or sys.path != _STARTUP_PATH:
            _violation("import_state_mutated")
            raise ImportError("import refused: import state mutated")
        filename = args[1] if len(args) > 1 else None
        if filename is not None and filename not in _STATE["native_paths"]:
            _violation("native_load_unlisted:" + str(filename)[:80])
            raise ImportError("import refused: native file not staged")
        return
    if event in ("exec", "compile"):
        frame = sys._getframe(1)
        if _caller_allowed(frame):
            return
        if event == "exec" and frame.f_code.co_filename.startswith("<frozen importlib") and \
                getattr(args[0], "co_filename", "").startswith("<frozen "):
            return
        _violation("dynamic_" + event + ":" + str(frame.f_globals.get("__name__"))[:40] + "." + frame.f_code.co_name[:40])
        raise RuntimeError("audit refused: " + event)
    if event == "marshal.loads":
        if sys._getframe(1).f_globals is not _BOOT_GLOBALS:
            _violation("dynamic_marshal.loads")
            raise RuntimeError("audit refused: marshal.loads")
        return
    for prefix in DENIED_EVENT_PREFIXES:
        if event.startswith(prefix):
            if event.startswith(("ctypes.call_function", "ctypes.dlopen")) and \
                    sys._getframe(1).f_globals is _BOOT_GLOBALS:
                return
            _violation("denied_event:" + event)
            raise RuntimeError("audit refused: " + event)


# ----------------------------------------------------------------------------------------------- run

class _Sink:
    def __init__(self):
        self.total = 0
        self.parts = []

    def write(self, text):
        data = str(text).encode("utf-8", "replace")
        if self.total < (1 << 20):
            self.parts.append(data)
        self.total += len(data)
        return len(text)

    def flush(self):
        pass

    def isatty(self):
        return False

    def sha256(self):
        return _sha(b"".join(self.parts))


def _classify(name, module):
    spec = getattr(module, "__spec__", None)
    if spec is None:
        return "nospec"
    loader = spec.loader
    if loader is _CLOSURE:
        return "closure"
    if loader is _RUNTIME:
        return "runtime"
    if spec.origin == "built-in":
        return "builtin"
    if spec.origin == "frozen":
        return "frozen"
    if name in _NATIVE.created:
        return "native"
    return "unlisted"


def _startup_files():
    found = []
    for name, module in list(sys.modules.items()):
        path = getattr(module, "__file__", None)
        if isinstance(path, str) and os.path.isabs(path):
            found.append(path)
    return sorted(set(found))


def _probe():
    core = []
    if sys.platform == "win32":
        core.append(_winapi.GetModuleFileName(sys.dllhandle))
    preload, startup_files = sorted(sys.modules), _startup_files()
    if sys.platform.startswith("linux"):
        for name in SUPERVISOR_MODULES:   # the containment supervisor's own extension modules and libraries join the pins
            __import__(name)
    mapped = _mapped_files()
    external = sys.modules["_frozen_importlib_external"]
    report = {
        "protocol": PROTOCOL, "implementation": sys.implementation.name, "version": sys.version.split()[0],
        "cache_tag": sys.implementation.cache_tag, "magic": external.MAGIC_NUMBER.hex(), "platform": sys.platform,
        "bits": sys.maxsize.bit_length(), "executable": sys.executable,
        "base_executable": getattr(sys, "_base_executable", sys.executable), "prefix": sys.prefix,
        "base_prefix": sys.base_prefix, "core_files": core,
        "native_mappings": sorted({os.path.realpath(p) for p in mapped}) if mapped is not None else None,
        "sys_path": list(_STARTUP_PATH),
        "meta_path": [i.__name__ if isinstance(i, type) else type(i).__name__ for i in _STARTUP_META],
        "startup_modules": _STARTUP, "preload_modules": preload, "startup_files": startup_files,
        "supervisor_modules": list(SUPERVISOR_MODULES),
        "stdlib_module_names": sorted(sys.stdlib_module_names), "extension_suffixes": list(external.EXTENSION_SUFFIXES),
        "flags": {"isolated": sys.flags.isolated, "no_site": sys.flags.no_site,
                  "dont_write_bytecode": sys.flags.dont_write_bytecode},
        "pycache_prefix": sys.pycache_prefix, "exe_sha256": _exe_sha256(), "bootstrap_sha256": _BOOTSTRAP_SHA256}
    _write_all(_REPORT_FD, _dumps(report).encode("ascii") + b"\n")
    os._exit(0)


def _name_digest(names):
    return _sha("\n".join(names).encode("utf-8"))


def _changed_files(pairs, known=None):
    changed = []
    for path, expected in pairs:
        try:
            if (known.get(path) if known else None) is None:
                if _hash_path(path) != expected:
                    changed.append(path)
            elif known[path] != expected:
                changed.append(path)
        except OSError:
            changed.append(path)
    return changed


def main():
    global _REPORT_FD
    _REPORT_FD = os.dup(1)
    devnull = os.open(os.devnull, os.O_RDWR)
    os.dup2(devnull, 1)
    os.close(devnull)
    magic = _read_exact(8)
    if magic == PROBE_MAGIC:
        _probe()
    if magic != MAGIC:
        _fail("frame_magic")
    header_length = int.from_bytes(_read_exact(8), "big")
    if header_length > MAX_HEADER:
        _fail("frame_header_too_large")
    header_bytes = _read_exact(header_length)
    header_sha256 = _sha(header_bytes)
    header = marshal.loads(header_bytes)
    _REPORT["nonce"] = nonce = header["nonce"]
    expect = header["expect"]
    mode = header["mode"]
    if mode not in MODES:
        _fail("frame_mode")
    if expect["bootstrap_sha256"] != _BOOTSTRAP_SHA256:
        _fail("bootstrap_binding")
    flags = sys.flags
    observed = {"isolated": flags.isolated, "no_site": flags.no_site, "dont_write_bytecode": flags.dont_write_bytecode}
    if not (flags.isolated and flags.no_site and flags.dont_write_bytecode):
        _fail("interpreter_flags", observed=observed)
    if sys.pycache_prefix is None or os.path.normcase(os.path.abspath(sys.pycache_prefix)) != \
            os.path.normcase(os.path.abspath(expect["pycache_prefix"])):
        _fail("pycache_prefix_mismatch")
    if sys.version.split()[0] != expect["version"] or sys.implementation.cache_tag != expect["cache_tag"] or \
            sys.executable != expect["executable"]:
        _fail("runtime_version_mismatch")
    if _name_digest(_STARTUP) != expect["startup_modules_sha256"]:
        _fail("startup_modules_mismatch")
    if _STARTUP_PATH != expect["sys_path"]:
        _fail("startup_sys_path_mismatch")
    if [i.__name__ if isinstance(i, type) else type(i).__name__ for i in _STARTUP_META] != expect["meta_path"]:
        _fail("startup_meta_path_mismatch")
    preload = sorted(sys.modules)
    if _name_digest(preload) != expect["preload_modules_sha256"]:
        _fail("preload_modules_mismatch")
    exe_hash = _exe_sha256()
    exe_accepted = {h for h in (expect["exe_sha256"], expect.get("base_exe_sha256")) if h}
    if exe_accepted and exe_hash not in exe_accepted:
        _fail("executable_image_mismatch")
    startup_files = [tuple(row) for row in expect["startup_files"]]
    if _startup_files() != sorted(path for path, _ in startup_files):
        _fail("startup_files_mismatch")
    if _changed_files(startup_files):
        _fail("startup_file_changed")
    natives = [tuple(row) for row in expect["natives"]] if expect["natives"] is not None else None
    known = {os.path.realpath(sys.executable): exe_hash} if exe_hash else None
    if natives is not None and _changed_files(natives, known):
        _fail("native_file_changed")
    start_mapped = _mapped_files()
    if start_mapped is None:
        _fail("native_inventory_unavailable")
    native_pins, native_index, satisfied = {}, {}, set()
    if natives is not None:
        native_pins, native_index = _native_index(natives)
        for path in start_mapped:
            if path.startswith("/memfd:"):
                continue
            if os.path.normcase(os.path.realpath(path)) not in native_pins:
                _fail("native_mapping_unlisted_at_start", native=path[:100])
            satisfied.update(_file_names(path))

    entries, inputs, input_hashes = {}, {}, {}
    owned_tops = set()
    for item in header["modules"]:
        entry = _Entry()
        entry.name, entry.root, entry.path, entry.package, entry.sha256 = item[0], item[1], item[2], item[3], item[4]
        entry.sites = {}
        for site in item[6]:
            names = entry.sites.setdefault((site[0], site[1], site[2], site[3]), set())
            names.update(p for name in site[4] for p in _prefixes(name))
        entry.data = _read_exact(item[5])
        if _sha(entry.data) != entry.sha256:
            _fail("blob_hash_mismatch", blob=entry.name)
        entries[entry.name] = entry
        owned_tops.add(entry.name.partition(".")[0])
    for name, length, digest in header["inputs"]:
        data = _read_exact(length)
        if _sha(data) != digest:
            _fail("blob_hash_mismatch", blob=name)
        inputs[name], input_hashes[name] = data, digest
    if os.read(0, 1):
        _fail("frame_trailing_bytes")
    for name in entries:
        if name in sys.modules:
            _fail("closure_module_preloaded", module=name)
    table = {row[0]: list(row) for row in header["table"]}
    overlap = owned_tops & ({n.partition(".")[0] for n in table} | set(expect["stdlib_module_names"]) |
                            {n.partition(".")[0] for n in _STARTUP} | {n.partition(".")[0] for n in preload})
    if overlap:
        _fail("closure_name_shadows_runtime", names=sorted(overlap))

    dep_ops = header["dep_ops"]
    if type(dep_ops) is not list or len(dep_ops) > MAX_DEPENDENCY_OPERATIONS:
        _fail("frame_dependency_operations")
    for item in dep_ops:
        if type(item) is not list or len(item) != 3 or not all(type(part) is str for part in item) or \
                item[1] not in DEPENDENCY_OPERATION_FORMS or item[0] not in table or table[item[0]][1] in ("ext", "ambiguous") or \
                item[2].partition(".")[0] in DENIED_IMPORTS or item[2].partition(".")[0] in owned_tops:
            _fail("frame_dependency_operations")
    import_only = mode in ("import", "confirm")
    strict = mode != "import"
    _STATE.update(entries=entries, table=table, owned_tops=frozenset(owned_tops), strict=strict,
                  dep_ops=frozenset(tuple(item) for item in dep_ops),
                  file_names={row[2]: row[0] for row in sorted(table.values(), reverse=True) if row[1] not in ("ext", "ambiguous")},
                  by_file={"closure/" + e.root + "/" + e.path: e for e in entries.values()},
                  runtime_files=frozenset(row[2] for row in table.values() if row[1] not in ("ext", "ambiguous")),
                  native_pins=native_pins, native_index=native_index, satisfied=satisfied,
                  proxy=_ImportlibProxy(_mediated_import_module))
    for denied in [n for n in sys.modules if n.partition(".")[0] in DENIED_IMPORTS and n.partition(".")[0] != "builtins"]:
        del sys.modules[denied]
    sys.modules["builtins"].__import__ = _mediated_import
    _install_entry_points()   # every supported or reachable entry point, then the captured-reference audit (fails closed)
    keep = [f for f in _STARTUP_META if getattr(f, "__name__", "") in ("BuiltinImporter", "FrozenImporter")]
    finder = _Finder()
    _STATE["finder"] = finder
    _STATE["meta"] = [finder] + keep
    sys.meta_path[:] = _STATE["meta"]
    sys.path_importer_cache.clear()
    sys.addaudithook(_audit)

    out, err = _Sink(), _Sink()
    devnull0 = os.open(os.devnull, os.O_RDWR)
    os.dup2(devnull0, 0)
    os.close(devnull0)
    real_out, real_err = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = out, err
    result, exception_type, result_error = None, None, None
    _STATE["armed"] = True
    try:
        module = __import__(header["entry"][0], fromlist=["_"])
        function = getattr(module, header["entry"][1])
        if not import_only:
            result = function(inputs, header["params"])
    except BaseException as exc:  # noqa: BLE001 - reported, never swallowed silently
        exception_type = type(exc).__name__
        result = None
    _STATE["armed"] = False
    sys.stdout, sys.stderr = real_out, real_err
    if exception_type is None and not import_only:
        try:
            if len(_dumps(result)) > MAX_RESULT:
                result, result_error = None, "too_large"
        except (ValueError, RecursionError):
            result, result_error = None, "not_json"

    loaded = {"closure": {}, "builtin": 0, "frozen": 0, "stdlib": 0, "startup": 0, "package": {}, "native": {}}
    runtime_modules = []
    for name, module in list(sys.modules.items()):
        if module is None or name == "__main__":
            continue
        kind = _classify(name, module)
        if kind == "closure":
            if _CLOSURE.created.get(name) is not module:
                _violation("closure_module_replaced:" + name)
            else:
                loaded["closure"][name] = entries[name].sha256
        elif kind == "runtime":
            if _RUNTIME.created.get(name) is not module:
                _violation("runtime_module_replaced:" + name)
            else:
                row = table[name]
                runtime_modules.append([name, row[3]])
                if row[5]:
                    loaded["package"][row[5]] = loaded["package"].get(row[5], 0) + 1
                else:
                    loaded["stdlib"] += 1
        elif kind == "native":
            row = _NATIVE.created[name][1]
            loaded["native"][name] = row[3]
            runtime_modules.append([name, row[3]])
            if row[5]:
                loaded["package"][row[5]] = loaded["package"].get(row[5], 0) + 1
            else:
                loaded["stdlib"] += 1
        elif kind == "builtin":
            loaded["builtin"] += 1
        elif kind == "frozen":
            loaded["frozen"] += 1
        elif name in _STARTUP or name in preload:
            loaded["startup"] += 1
        elif kind == "nospec" and name in ("typing.io", "typing.re") and type(module).__module__ == "typing" and \
                sys.modules.get("typing") is _RUNTIME.created.get("typing"):
            pass
        else:
            _violation("module_from_unlisted_location:" + name)
    for name in _CLOSURE.created:
        if name not in sys.modules:
            _violation("closure_module_removed:" + name)
    for name in _RUNTIME.created:
        if name not in sys.modules:
            _violation("runtime_module_removed:" + name)
    for name in _NATIVE.created:
        if name not in sys.modules:
            _violation("native_module_removed:" + name)
    if sys.path != _STARTUP_PATH or sys.path_hooks != _STARTUP_HOOKS:
        _violation("import_state_mutated")
    if len(sys.meta_path) != len(_STATE["meta"]) or any(a is not b for a, b in zip(sys.meta_path, _STATE["meta"])):
        _violation("meta_path_mutated")

    mapped = _mapped_files()
    loaded_natives = {os.path.normcase(os.path.realpath(row[2])): row[3] for _, row in _NATIVE.created.values()} \
        if sys.platform == "win32" else {}
    if sys.platform == "win32":
        loaded_natives.update({os.path.normcase(os.path.realpath(path)): digest for path, digest in _NATIVE.plan})
    if mapped is None:
        _violation("native_inventory_unavailable")
    elif strict:
        allowed = {os.path.normcase(os.path.realpath(path)) for path, _ in natives} if natives is not None else set()
        allowed.update(loaded_natives)
        for path in mapped:
            if path.startswith(("/memfd:pvc-ext", "/memfd:pvc-dep")):
                if not path.endswith(" (deleted)"):
                    _violation("native_mapping_unexpected:" + path[:80])
            elif os.path.normcase(os.path.realpath(path)) not in allowed:
                _violation("unlisted_native_mapping:" + path[:100])
        if sys.platform.startswith("linux"):
            live = _mapped_memfds()
            if live is None or live - set(_NATIVE.retained):
                _violation("native_mapping_unexpected:memfd_identity")
    for path in _changed_files(startup_files):
        _violation("startup_file_changed:" + path[:100])
    for path in _changed_files(natives or ()):
        _violation("native_file_changed:" + path[:100])
    for path, digest in loaded_natives.items():
        if _changed_files([(path, digest)]):
            _violation("native_file_changed:" + path[:100])
    exe_after = _exe_sha256()
    if exe_accepted and exe_after not in exe_accepted:
        _violation("executable_image_changed")

    report = {
        "protocol": PROTOCOL, "status": "RESULT", "mode": mode, "nonce": nonce, "header_sha256": header_sha256,
        "bootstrap_sha256": _BOOTSTRAP_SHA256, "manifest_sha256": header["manifest_sha256"], "release_sha256": header["release_sha256"],
        "entry": list(header["entry"]), "result": result, "result_error": result_error,
        "exception_type": exception_type, "violations": sorted(_REPORT["violations"]),
        "refused": sorted(_REPORT["refused"]), "loaded": loaded, "runtime_modules": sorted(runtime_modules),
        "native_plan": sorted(_NATIVE.plan),
        "inputs": input_hashes, "mapped": sorted({os.path.realpath(p) for p in mapped if not p.startswith("/memfd:")})
        if mapped is not None else None,
        "stdout_bytes": out.total, "stderr_bytes": err.total, "stdout_sha256": out.sha256(), "stderr_sha256": err.sha256(),
        "exe_sha256": exe_after, "flags": observed}
    _finish(report, 0)


if __name__ == "__main__":
    main()
