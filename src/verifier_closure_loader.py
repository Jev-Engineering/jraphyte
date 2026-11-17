"""Closure-pinned loader for external qualification verifiers (issue #97).

A verifier release is a separate approved root plus a versioned release
contract that pins every local source file the verifier can execute: the entry
module, its transitive static imports, package ``__init__`` files and declared
dynamic dependencies. The static closure is hashed with
``parallel_source_v4.common.method_hashes`` and cross-checked against a
stricter scan here. Nothing from the verifier root executes until the complete
closure matches the contract.

Execution uses only the verified in-memory bytes. Local modules are compiled
from those bytes into private module objects that are never placed in
``sys.modules``; ``__pycache__`` is never read or written. Local imports resolve
only against the verified map through a private ``__import__``. Stdlib imports
use fixed host-provided exports declared in the contract. Import machinery, ``exec``/``eval``/
``compile`` and undeclared ``__import__`` calls are rejected before execution.
After the verifier returns, the closure and the inputs are checked again before
its result is accepted.

This is an integrity boundary for reviewed code, not a sandbox against hostile
code (see SECURITY.md): reviewed verifier code is part of the trusted base.
A mechanical PASS from this loader is not a qualification result. The private
V6 evaluator and the real issue20, issue22 and recovery verifier releases are
not part of this repository.
"""
from __future__ import annotations

import ast
import builtins
from contextlib import ExitStack
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import stat
import sys
import types
from pathlib import Path

from trace_gc.pdf_source_parallel_v4 import json_bytes
from src.parallel_source_v4.common import method_hashes

CONTRACT = "verifier_closure_release_v1"
CONTRACT_KEYS = {"contract", "verifier_id", "entry", "callable", "runtime",
                 "approved_external", "approved_dynamic", "closure"}
RESULTS = ("PASS", "HOLD")
# The host supplies these already-loaded functions. Giving the verifier a
# limited namespace avoids doing a normal import or package from-list lookup.
EXTERNAL_EXPORTS = {"json": {"loads": json.loads, "dumps": json.dumps}}
# Preserve the explicit rejection code for names associated with code loading.
DENIED_EXTERNAL = frozenset({"builtins", "importlib", "imp", "marshal", "pkgutil",
                             "runpy", "site", "sys", "zipimport", "ctypes", "code", "codeop",
                             "os", "posix", "nt", "subprocess", "multiprocessing", "concurrent",
                             "pickle", "shelve", "copyreg", "types", "inspect", "gc",
                             "pdb", "bdb", "trace", "profile", "cProfile", "zipapp"})
DENIED_NAMES = frozenset({"exec", "eval", "compile", "__builtins__", "__loader__", "__spec__",
                          "globals", "vars", "breakpoint"})
DENIED_ATTRIBUTES = frozenset({"__import__", "__builtins__", "__loader__", "__spec__", "__globals__",
                               "__code__", "__subclasses__"})


class VerifierClosureError(ValueError):
    """A verifier closure was rejected; no unverified result is accepted."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(code + (":" + detail if detail else ""))
        self.code = code


def _fail(code: str, detail: str = ""):
    raise VerifierClosureError(code, detail)


def runtime_identity() -> dict:
    return {"implementation": sys.implementation.name,
            "version": "%d.%d" % sys.version_info[:2]}


def contract_sha256(contract: dict) -> str:
    """Hash the canonical representation accepted by the verifier loader."""
    return hashlib.sha256(_canonical_json(contract, "invalid_verifier_contract")).hexdigest()


def _is_indirect_path(path: Path) -> bool:
    if path.is_symlink():
        return True
    if os.name != "nt":
        return False
    attributes = getattr(path.lstat(), "st_file_attributes", 0)
    return bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def _checked_root_path(item) -> Path:
    raw = Path(item).absolute()
    if any(_is_indirect_path(path) for path in (*raw.parents, raw)):
        _fail("symlinked_verifier_root")
    return raw.resolve()


def _approved_root(root, approved_roots) -> Path:
    try:
        resolved = _checked_root_path(root)
        approved = {_checked_root_path(item) for item in approved_roots}
    except (OSError, RuntimeError, TypeError) as exc:
        _fail("unapproved_verifier_root", type(exc).__name__)
    if resolved not in approved or not resolved.is_dir():
        _fail("unapproved_verifier_root")
    return resolved


def _root_identity(supplied: Path, resolved: Path) -> tuple:
    try:
        if _checked_root_path(supplied) != resolved or not resolved.is_dir():
            _fail("verifier_root_changed")
        identities = tuple(path.stat() for path in (*resolved.parents, resolved))
    except OSError:
        _fail("verifier_root_changed")
    return tuple((entry.st_dev, entry.st_ino) for entry in identities)


def _module_file(root: Path, module: str):
    """Return (relative path, is_package) for a local module, or None."""
    target = root.joinpath(*module.split("."))
    plain, package = target.with_suffix(".py"), target / "__init__.py"
    if plain.is_file() and package.is_file():
        _fail("ambiguous_module_resolution", module)
    if plain.is_file():
        return plain.relative_to(root).as_posix(), False
    if package.is_file():
        return package.relative_to(root).as_posix(), True
    if target.is_dir():
        _fail("namespace_package_unsupported", module)
    return None


def _no_symlink(root: Path, relative: str) -> None:
    current = root
    for part in Path(relative).parts:
        current = current / part
        if _is_indirect_path(current):
            _fail("symlink_in_closure", relative)


def _source_bytes(root: Path, relative: str) -> bytes:
    path = root / relative
    _no_symlink(root, relative)
    read_flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
    with ExitStack() as stack:
        if os.open in os.supports_dir_fd and hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY"):
            directory_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY
            directory = os.open(root.anchor, directory_flags)
            stack.callback(os.close, directory)
            for part in (*root.parts[1:], *Path(relative).parts[:-1]):
                directory = os.open(part, directory_flags, dir_fd=directory)
                stack.callback(os.close, directory)
            handle = os.open(path.name, read_flags | os.O_NOFOLLOW, dir_fd=directory)
        else:
            handle = os.open(path, read_flags)
        with os.fdopen(handle, "rb") as source:
            opened = os.fstat(source.fileno())
            require_regular = stat.S_ISREG(opened.st_mode)
            if not require_regular or not os.path.samestat(opened, path.lstat()):
                _fail("closure_file_identity_changed")
            contents = source.read()
        _no_symlink(root, relative)
        if not os.path.samestat(opened, path.lstat()):
            _fail("closure_file_identity_changed")
    return contents


def _top_level_bindings(tree) -> set:
    names = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = list(node.targets) if isinstance(node, ast.Assign) else (
                [node.target] if node.value is not None else [])
            while targets:
                target = targets.pop()
                if isinstance(target, ast.Name):
                    names.add(target.id)
                elif isinstance(target, (ast.Tuple, ast.List)):
                    targets.extend(target.elts)
                elif isinstance(target, ast.Starred):
                    targets.append(target.value)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            names.update((alias.asname or alias.name).split(".")[0] for alias in node.names)
    return names


def _check_external_names(approved_external) -> None:
    for name in approved_external:
        if name in DENIED_EXTERNAL:
            _fail("import_machinery_denied", name)
        if name not in EXTERNAL_EXPORTS:
            _fail("external_dependency_unsupported", name)


def _external(name: str, approved_external, fromlist=()) -> None:
    top = name.split(".")[0]
    if top in DENIED_EXTERNAL:
        _fail("import_machinery_denied", name)
    if top not in approved_external:
        _fail("unpinned_import", name)
    if name != top or any(item not in EXTERNAL_EXPORTS[top] for item in fromlist):
        _fail("external_import_unsupported", name)


def scan_closure(root: Path, entry: str, *, approved_external=(), approved_dynamic=()) -> dict:
    """Statically resolve the closure; read and parse failures become closure errors."""
    try:
        return _scan_closure(root, entry, approved_external=approved_external, approved_dynamic=approved_dynamic)
    except VerifierClosureError:
        raise
    except UnicodeDecodeError:
        _fail("closure_not_utf8")
    except RecursionError:
        _fail("closure_source_too_deep")
    except SyntaxError as exc:
        _fail("closure_syntax_error", "%s:%s" % (exc.filename, exc.lineno))
    except OSError as exc:
        _fail("closure_unreadable", type(exc).__name__)
    except (ImportError, ValueError) as exc:  # e.g. relative import beyond the package
        _fail("invalid_module_reference", str(exc))


def _scan_closure(root: Path, entry: str, *, approved_external=(), approved_dynamic=()) -> dict:
    """Statically resolve the strict local closure without executing it.

    Returns ({module: relative_path}, {relative_path: bytes}); the bytes are
    the exact buffers that were parsed, so later hashing and execution use the
    same representation that was scanned. Imports resolve to a local file
    or to declared host-provided exports.
    """
    local_tops = set()
    for module in (entry, *approved_dynamic):
        if not isinstance(module, str) or not module or not all(p.isidentifier() for p in module.split(".")):
            _fail("expected_local_module_root")
        local_tops.add(module.split(".")[0])
    if local_tops != {entry.split(".")[0]}:
        _fail("dynamic_dependency_outside_verifier_package")
    approved_external = set(approved_external)
    _check_external_names(approved_external)
    modules, payloads, bindings = {}, {}, {}
    pending = [entry, *approved_dynamic]
    required_bindings = []
    while pending:
        module = pending.pop()
        if module in modules:
            continue
        found = _module_file(root, module)
        if found is None:
            _fail("missing_dependency", module)
        relative, is_package = found
        modules[module] = relative
        parts = module.split(".")
        pending.extend(".".join(parts[:i]) for i in range(1, len(parts)))
        payloads[relative] = _source_bytes(root, relative)
        tree = ast.parse(payloads[relative].decode("utf-8"), filename=relative)
        bindings[module] = _top_level_bindings(tree)
        package = module if is_package else module.rpartition(".")[0]
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] in local_tops:
                        pending.append(alias.name)
                    else:
                        _external(alias.name, approved_external)
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    name = importlib.util.resolve_name("." * node.level + (node.module or ""), package)
                else:
                    name = node.module or ""
                names = [alias.name for alias in node.names]
                if "*" in names:
                    _fail("star_import_unsupported", name)
                if name.split(".")[0] not in local_tops:
                    _external(name, approved_external, names)
                    continue
                pending.append(name)
                for attribute in names:
                    candidate = name + "." + attribute
                    if _module_file(root, candidate) is not None:
                        pending.append(candidate)
                    else:
                        required_bindings.append((name, attribute))
            elif isinstance(node, ast.Name) and node.id in DENIED_NAMES:
                _fail("unapproved_dynamic_execution", node.id)
            elif isinstance(node, ast.Attribute) and node.attr in DENIED_ATTRIBUTES:
                _fail("unapproved_dynamic_execution", node.attr)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "__import__":
                if (len(node.args) != 1 or node.keywords or not isinstance(node.args[0], ast.Constant)
                        or node.args[0].value not in approved_dynamic):
                    _fail("unapproved_dynamic_import")
        names = [n for n in ast.walk(tree) if isinstance(n, ast.Name) and n.id == "__import__"]
        calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                 and n.func.id == "__import__"]
        if len(names) != len(calls):
            _fail("unapproved_dynamic_import", "__import__ reference")
    for name in modules:
        parent = name.rpartition(".")[0]
        if parent and not modules[parent].endswith("/__init__.py"):
            _fail("module_parent_is_not_package", parent)
    for parent, attribute in required_bindings:
        if attribute not in bindings[parent]:
            _fail("missing_dependency", parent + "." + attribute)
    return modules, payloads


def _check_unambiguous(root: Path, modules: dict) -> None:
    """A local top-level name must not also resolve elsewhere or be cached."""
    outside = []
    for item in sys.path:
        try:
            if Path(item or ".").resolve() != root:
                outside.append(item)
        except OSError:
            continue
    for module in modules:
        if module in sys.modules:
            _fail("module_cached_outside_closure", module)
    for top in {module.split(".")[0] for module in modules}:
        if top in sys.stdlib_module_names or top in sys.builtin_module_names:
            _fail("module_shadows_stdlib", top)
        if importlib.machinery.PathFinder.find_spec(top, outside) is not None:
            _fail("import_path_ambiguity", top)


def _read_closure(root: Path, contract: dict, *, check_ambiguity: bool) -> tuple[dict, dict]:
    modules, payloads = scan_closure(root, contract["entry"], approved_external=contract["approved_external"],
                                     approved_dynamic=contract["approved_dynamic"])
    if check_ambiguity:
        try:
            _check_unambiguous(root, modules)
        except (ImportError, ValueError, OSError) as exc:
            if isinstance(exc, VerifierClosureError):
                raise
            _fail("import_path_check_failed", type(exc).__name__)
    hashes = {relative: hashlib.sha256(raw).hexdigest() for relative, raw in payloads.items()}
    try:
        reused = method_hashes(root, additional_roots=(contract["entry"], *contract["approved_dynamic"]))
    except (ValueError, OSError, RecursionError) as exc:
        _fail("closure_changed_while_reading", type(exc).__name__)
    if reused != hashes:
        _fail("closure_scan_disagreement", ",".join(sorted(set(reused) ^ set(hashes))) or "hash")
    return modules, payloads


def _compile_closure(root: Path, payloads: dict) -> dict:
    try:
        return {relative: compile(raw.decode("utf-8"), str(root / relative), "exec",
                                  dont_inherit=True, optimize=0)
                for relative, raw in payloads.items()}
    except (SyntaxError, UnicodeError, ValueError, RecursionError):
        _fail("verifier_compile_failed")


def build_release_contract(root, entry: str, *, verifier_id: str, approved_roots,
                           callable_name: str = "evaluate", approved_external=(), approved_dynamic=()) -> dict:
    """Author a contract from a reviewed root. Review must happen out of band."""
    root = _approved_root(root, approved_roots)
    approved_external = _author_names(approved_external, "approved_external")
    approved_dynamic = _author_names(approved_dynamic, "approved_dynamic")
    contract = {"contract": CONTRACT, "verifier_id": verifier_id, "entry": entry,
                "callable": callable_name, "runtime": runtime_identity(),
                "approved_external": approved_external,
                "approved_dynamic": approved_dynamic, "closure": {}}
    _validate_contract_fields(contract)
    _, payloads = _read_closure(root, contract, check_ambiguity=True)
    _compile_closure(root, payloads)
    contract["closure"] = {relative: hashlib.sha256(raw).hexdigest() for relative, raw in payloads.items()}
    return contract


def _author_names(names, key) -> list:
    try:
        names = list(names)
    except TypeError:
        _fail("expected_sorted_name_list", key)
    if not all(type(name) is str for name in names):
        _fail("expected_sorted_name_list", key)
    return sorted(names)


def _validate_contract_fields(contract) -> None:
    for key in ("approved_external", "approved_dynamic"):
        value = contract[key]
        if (not isinstance(value, list) or not all(type(name) is str for name in value)
                or value != sorted(set(value))):
            _fail("expected_sorted_name_list", key)
    if type(contract["verifier_id"]) is not str or not contract["verifier_id"]:
        _fail("expected_verifier_id")
    if type(contract["entry"]) is not str:
        _fail("expected_local_module_root")
    if type(contract["callable"]) is not str or not contract["callable"].isidentifier():
        _fail("expected_callable_name")
    runtime = contract["runtime"]
    if (type(runtime) is not dict or not all(type(v) is str for v in runtime.values())
            or runtime != runtime_identity()):
        _fail("unsupported_runtime")


def _validate_contract(contract) -> None:
    if not isinstance(contract, dict) or set(contract) != CONTRACT_KEYS or contract["contract"] != CONTRACT:
        _fail("unsupported_release_contract")
    _validate_contract_fields(contract)
    closure = contract["closure"]
    if (not isinstance(closure, dict) or not closure or not all(
            type(k) is str and type(v) is str and len(v) == 64 and set(v) <= set("0123456789abcdef")
            for k, v in closure.items())):
        _fail("expected_closure_hashes")


class _PrivateImporter:
    """Resolve local imports from verified bytes only; never touch sys.modules."""

    def __init__(self, root: Path, modules: dict, compiled: dict, contract: dict):
        self.root, self.modules, self.compiled = root, modules, compiled
        self.local_top = contract["entry"].split(".")[0]
        self.external = {name: types.SimpleNamespace(**EXTERNAL_EXPORTS[name])
                         for name in contract["approved_external"]}
        self.loaded = {}
        self.violation = None  # kept even if the verifier swallows the ImportError
        self.builtins = dict(builtins.__dict__)
        self.builtins["__import__"] = self.import_

    def module(self, name: str):
        if name in self.loaded:
            return self.loaded[name]
        if name not in self.modules:
            self.reject_import(VerifierClosureError("unpinned_import_at_runtime"))
        parent = name.rpartition(".")[0]
        if parent:
            self.module(parent)
            if name in self.loaded:
                return self.loaded[name]
        relative = self.modules[name]
        module = types.ModuleType(name)
        is_package = relative.endswith("/__init__.py")
        module.__file__ = str(self.root / relative)
        module.__package__ = name if is_package else parent
        module.__builtins__ = self.builtins
        if is_package:
            module.__path__ = []  # no finder may search the directory
        self.loaded[name] = module
        try:
            exec(self.compiled[relative], module.__dict__)
        except BaseException:
            self.loaded.pop(name, None)
            raise
        if parent:
            setattr(self.loaded[parent], name.rpartition(".")[2], module)
        return module

    def reject_import(self, error: VerifierClosureError) -> None:
        self.violation = self.violation or error
        raise ImportError(error.code) from None

    def import_(self, name, globals=None, locals=None, fromlist=(), level=0):
        if level:
            package = (globals or {}).get("__package__") or ""
            try:
                name = importlib.util.resolve_name("." * level + name, package)
            except (ImportError, TypeError, ValueError):
                self.reject_import(VerifierClosureError("invalid_relative_import"))
        fromlist = fromlist or ()
        try:
            if "*" in fromlist:
                _fail("star_import_unsupported")
            if name.split(".")[0] != self.local_top:
                _external(name, self.external, fromlist)
                return self.external[name]
        except VerifierClosureError as exc:
            self.reject_import(exc)
        module = self.module(name)
        for item in fromlist:
            submodule = name + "." + item
            # Python loads a from-list submodule only if the package has not
            # already bound that name. Retain the full conservative pin set.
            if item not in module.__dict__ and submodule in self.modules:
                self.module(submodule)
            if item not in module.__dict__:
                self.reject_import(VerifierClosureError("local_import_binding_missing"))
        return module if fromlist else self.loaded[self.local_top]


def _copy_json(value):
    """Copy exact JSON-native types before serialization can coerce values."""
    kind = type(value)
    if value is None or kind is str or kind is bool or kind is int or kind is float:
        return value
    if kind is list:
        return [_copy_json(item) for item in value]
    if kind is dict and all(type(key) is str for key in value):
        return {key: _copy_json(item) for key, item in value.items()}
    raise TypeError("expected JSON-native value")


def _canonical_json(value, rejection: str) -> bytes:
    try:
        return json_bytes(_copy_json(value))
    except (TypeError, ValueError, RuntimeError):
        _fail(rejection)


def _exception_name(exc) -> str:
    kind = type(exc)
    return kind.__name__ if getattr(builtins, kind.__name__, None) is kind else "verifier_error"


def run_verifier(root, contract: dict, inputs, *, approved_roots) -> dict:
    """Verify the full closure, execute only those bytes, recheck, then accept."""
    contract_bytes = _canonical_json(contract, "invalid_verifier_contract")
    contract = json.loads(contract_bytes)
    _validate_contract(contract)
    input_bytes = _canonical_json(inputs, "invalid_verifier_inputs")
    snapshot = json.loads(input_bytes)
    try:
        supplied = Path(root).absolute()
    except (OSError, TypeError):
        _fail("unapproved_verifier_root")
    root = _approved_root(supplied, approved_roots)
    root_identity = _root_identity(supplied, root)
    modules, payloads = _read_closure(root, contract, check_ambiguity=True)
    actual = {relative: hashlib.sha256(raw).hexdigest() for relative, raw in payloads.items()}
    if actual != contract["closure"]:
        changed = sorted(k for k in set(actual) | set(contract["closure"])
                         if actual.get(k) != contract["closure"].get(k))
        _fail("closure_mismatch", ",".join(changed))
    importer = _PrivateImporter(root, modules, _compile_closure(root, payloads), contract)
    outcome, error = "HOLD", None
    try:
        entry = importer.module(contract["entry"])
    except (Exception, SystemExit) as exc:
        entry, error = None, "import_" + _exception_name(exc)
    # Lookup only a binding in the loaded module; this cannot call __getattr__.
    function = entry.__dict__.get(contract["callable"]) if entry is not None else None
    if entry is not None and not isinstance(function, types.FunctionType):
        _fail("verifier_callable_missing", contract["callable"])
    if function is not None:
        try:
            outcome = function(snapshot)
        except (Exception, SystemExit) as exc:
            outcome, error = "HOLD", _exception_name(exc)
    if type(outcome) is str and outcome in RESULTS:
        outcome = RESULTS[RESULTS.index(outcome)]  # canonical literal, never a subclass
    else:
        outcome, error = "HOLD", error or "unrecognized_verifier_result"
    if importer.violation is not None:
        raise importer.violation
    if _root_identity(supplied, root) != root_identity:
        _fail("verifier_root_changed")
    _, after = _read_closure(root, contract, check_ambiguity=False)
    if _root_identity(supplied, root) != root_identity:
        _fail("verifier_root_changed")
    if after != payloads:
        _fail("closure_changed_during_execution")
    if any(_canonical_json(value, "inputs_changed_during_execution") != input_bytes
           for value in (snapshot, inputs)):
        _fail("inputs_changed_during_execution")
    record = {"contract": CONTRACT, "verifier_id": contract["verifier_id"],
              "release_contract_sha256": hashlib.sha256(contract_bytes).hexdigest(),
              "input_sha256": hashlib.sha256(input_bytes).hexdigest(),
              "status": outcome,
              "executed_representation": "verified_source_bytes_compiled_in_memory",
              "evidence": "mechanical_closure_check_not_qualification"}
    if error:
        record["hold_reason"] = error
    return record


def evaluate_closure_gate(root, contract: dict, inputs, *, approved_roots) -> dict:
    """Gate form: any closure rejection is HOLD with its code, never PASS."""
    try:
        return run_verifier(root, contract, inputs, approved_roots=approved_roots)
    except VerifierClosureError as exc:
        return {"contract": CONTRACT, "status": "HOLD", "rejected": exc.code, "detail": exc.code,
                "evidence": "mechanical_closure_check_not_qualification"}
