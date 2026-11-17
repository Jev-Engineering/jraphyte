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
must be declared in the contract. Import machinery, ``exec``/``eval``/
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
import copy
import hashlib
import importlib.machinery
import importlib.util
import sys
import types
from pathlib import Path

from trace_gc.pdf_source_parallel_v4 import json_bytes
from src.parallel_source_v4.common import method_hashes

CONTRACT = "verifier_closure_release_v1"
CONTRACT_KEYS = {"contract", "verifier_id", "entry", "callable", "runtime",
                 "approved_external", "approved_dynamic", "closure"}
RESULTS = ("PASS", "HOLD")
# Modules that can redirect imports, reach sys.modules/sys.path or load other
# executable representations. They cannot be approved as external imports.
DENIED_EXTERNAL = frozenset({"builtins", "importlib", "imp", "marshal", "pkgutil",
                             "runpy", "site", "sys", "zipimport", "ctypes", "code", "codeop"})
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
    return hashlib.sha256(json_bytes(contract)).hexdigest()


def _approved_root(root, approved_roots) -> Path:
    raw = Path(root)
    if raw.is_symlink():
        _fail("symlinked_verifier_root")
    resolved = raw.resolve()
    approved = {Path(item).resolve() for item in approved_roots}
    if resolved not in approved or not resolved.is_dir():
        _fail("unapproved_verifier_root")
    return resolved


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
        if current.is_symlink():
            _fail("symlink_in_closure", relative)


def _top_level_bindings(tree) -> set:
    names = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            for target in (node.targets if isinstance(node, ast.Assign) else [node.target]):
                names.update(n.id for n in ast.walk(target) if isinstance(n, ast.Name))
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            names.update((alias.asname or alias.name).split(".")[0] for alias in node.names)
    return names


def _external(name: str, approved_external) -> None:
    top = name.split(".")[0]
    if top in DENIED_EXTERNAL:
        _fail("import_machinery_denied", name)
    if top not in approved_external:
        _fail("unpinned_import", name)


def scan_closure(root: Path, entry: str, *, approved_external=(), approved_dynamic=()) -> dict:
    """Statically resolve the strict local closure without executing it.

    Returns ({module: relative_path}, {relative_path: bytes}); the bytes are
    the exact buffers that were parsed, so later hashing and execution use the
    same representation that was scanned. Every import must resolve to exactly
    one local file or to a declared stdlib module; anything else is rejected.
    """
    local_tops = set()
    for module in (entry, *approved_dynamic):
        if not isinstance(module, str) or not module or not all(p.isidentifier() for p in module.split(".")):
            _fail("expected_local_module_root")
        local_tops.add(module.split(".")[0])
    if local_tops != {entry.split(".")[0]}:
        _fail("dynamic_dependency_outside_verifier_package")
    approved_external = set(approved_external)
    for name in approved_external:
        if name in DENIED_EXTERNAL:
            _fail("import_machinery_denied", name)
        if name not in sys.stdlib_module_names:
            _fail("external_dependency_not_stdlib", name)
    modules, payloads, pending = {}, {}, [entry, *approved_dynamic]
    while pending:
        module = pending.pop()
        if module in modules:
            continue
        found = _module_file(root, module)
        if found is None:
            _fail("missing_dependency", module)
        relative, is_package = found
        _no_symlink(root, relative)
        modules[module] = relative
        parts = module.split(".")
        pending.extend(".".join(parts[:i]) for i in range(1, len(parts)))
        payloads[relative] = (root / relative).read_bytes()
        tree = ast.parse(payloads[relative].decode("utf-8"), filename=relative)
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
                if name.split(".")[0] not in local_tops:
                    _external(name, approved_external)
                    continue
                pending.append(name)
                for alias in node.names:
                    if alias.name == "*":
                        _fail("star_import_unsupported", name)
                    pending.append(name + "." + alias.name + "?")
            elif isinstance(node, ast.Name) and node.id in DENIED_NAMES:
                _fail("unapproved_dynamic_execution", node.id)
            elif isinstance(node, ast.Attribute) and node.attr in DENIED_ATTRIBUTES:
                _fail("unapproved_dynamic_execution", node.attr)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "__import__":
                if (len(node.args) != 1 or node.keywords or not isinstance(node.args[0], ast.Constant)
                        or node.args[0].value not in approved_dynamic):
                    _fail("unapproved_dynamic_import", ast.unparse(node))
        names = [n for n in ast.walk(tree) if isinstance(n, ast.Name) and n.id == "__import__"]
        calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                 and n.func.id == "__import__"]
        if len(names) != len(calls):
            _fail("unapproved_dynamic_import", "__import__ reference")
        # Resolve deferred `from X import name` candidates: submodule or binding.
        resolved = []
        for item in pending:
            if not item.endswith("?"):
                resolved.append(item)
                continue
            candidate = item[:-1]
            parent, _, attribute = candidate.rpartition(".")
            if _module_file(root, candidate) is not None:
                resolved.append(candidate)
                continue
            parent_file = _module_file(root, parent)
            if parent_file is None:
                _fail("missing_dependency", parent)
            parent_tree = ast.parse((root / parent_file[0]).read_bytes().decode("utf-8"))
            if attribute not in _top_level_bindings(parent_tree):
                _fail("missing_dependency", candidate)
        pending = resolved
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
        _check_unambiguous(root, modules)
    hashes = {relative: hashlib.sha256(raw).hexdigest() for relative, raw in payloads.items()}
    try:
        reused = method_hashes(root, additional_roots=(contract["entry"], *contract["approved_dynamic"]))
    except ValueError as exc:
        _fail("closure_changed_while_reading", str(exc))
    if reused != hashes:
        _fail("closure_scan_disagreement", ",".join(sorted(set(reused) ^ set(hashes))) or "hash")
    return modules, payloads


def build_release_contract(root, entry: str, *, verifier_id: str, approved_roots,
                           callable_name: str = "evaluate", approved_external=(), approved_dynamic=()) -> dict:
    """Author a contract from a reviewed root. Review must happen out of band."""
    root = _approved_root(root, approved_roots)
    contract = {"contract": CONTRACT, "verifier_id": verifier_id, "entry": entry,
                "callable": callable_name, "runtime": runtime_identity(),
                "approved_external": sorted(approved_external),
                "approved_dynamic": sorted(approved_dynamic), "closure": {}}
    _, payloads = _read_closure(root, contract, check_ambiguity=True)
    contract["closure"] = {relative: hashlib.sha256(raw).hexdigest() for relative, raw in payloads.items()}
    return contract


def _validate_contract(contract) -> None:
    if not isinstance(contract, dict) or set(contract) != CONTRACT_KEYS or contract["contract"] != CONTRACT:
        _fail("unsupported_release_contract")
    for key in ("approved_external", "approved_dynamic"):
        value = contract[key]
        if not isinstance(value, list) or value != sorted(set(value)) or not all(isinstance(v, str) for v in value):
            _fail("expected_sorted_name_list", key)
    if not isinstance(contract["callable"], str) or not contract["callable"].isidentifier():
        _fail("expected_callable_name")
    closure = contract["closure"]
    if (not isinstance(closure, dict) or not closure or not all(
            isinstance(v, str) and len(v) == 64 and set(v) <= set("0123456789abcdef") for v in closure.values())):
        _fail("expected_closure_hashes")
    if contract["runtime"] != runtime_identity():
        _fail("unsupported_runtime", json_bytes(contract["runtime"]).decode())


class _PrivateImporter:
    """Resolve local imports from verified bytes only; never touch sys.modules."""

    def __init__(self, root: Path, modules: dict, payloads: dict, contract: dict):
        self.root, self.modules, self.payloads = root, modules, payloads
        self.local_top = contract["entry"].split(".")[0]
        self.external = set(contract["approved_external"])
        self.loaded = {}
        self.builtins = dict(builtins.__dict__)
        self.builtins["__import__"] = self.import_

    def module(self, name: str):
        if name in self.loaded:
            return self.loaded[name]
        if name not in self.modules:
            raise ImportError("unpinned_import_at_runtime:" + name)
        parent = name.rpartition(".")[0]
        if parent:
            self.module(parent)
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
            code = compile(self.payloads[relative], module.__file__, "exec", dont_inherit=True)
            exec(code, module.__dict__)
        except BaseException:
            self.loaded.pop(name, None)
            raise
        if parent:
            setattr(self.loaded[parent], name.rpartition(".")[2], module)
        return module

    def import_(self, name, globals=None, locals=None, fromlist=(), level=0):
        if level:
            package = (globals or {}).get("__package__") or ""
            name = importlib.util.resolve_name("." * level + name, package)
        if name.split(".")[0] != self.local_top:
            if name.split(".")[0] not in self.external:
                raise ImportError("unpinned_import_at_runtime:" + name)
            return builtins.__import__(name, None, None, fromlist, 0)
        module = self.module(name)
        for item in fromlist or ():
            if name + "." + item in self.modules:
                self.module(name + "." + item)
        return module if fromlist else self.loaded[self.local_top]


def run_verifier(root, contract: dict, inputs, *, approved_roots) -> dict:
    """Verify the full closure, execute only those bytes, recheck, then accept."""
    _validate_contract(contract)
    root = _approved_root(root, approved_roots)
    modules, payloads = _read_closure(root, contract, check_ambiguity=True)
    actual = {relative: hashlib.sha256(raw).hexdigest() for relative, raw in payloads.items()}
    if actual != contract["closure"]:
        changed = sorted(k for k in set(actual) | set(contract["closure"])
                         if actual.get(k) != contract["closure"].get(k))
        _fail("closure_mismatch", ",".join(changed))
    input_sha = hashlib.sha256(json_bytes(inputs)).hexdigest()
    importer = _PrivateImporter(root, modules, payloads, contract)
    outcome, error = "HOLD", None
    try:
        entry = importer.module(contract["entry"])
    except Exception as exc:  # import-time failure is a HOLD, never a PASS
        entry, error = None, "import_" + type(exc).__name__
    function = getattr(entry, contract["callable"], None) if entry is not None else None
    if entry is not None and not isinstance(function, types.FunctionType):
        _fail("verifier_callable_missing", contract["callable"])
    if function is not None:
        try:
            outcome = function(copy.deepcopy(inputs))
        except Exception as exc:  # a verifier failure is a HOLD, never a PASS
            outcome, error = "HOLD", type(exc).__name__
    _, after = _read_closure(root, contract, check_ambiguity=False)
    if after != payloads:
        _fail("closure_changed_during_execution")
    if hashlib.sha256(json_bytes(inputs)).hexdigest() != input_sha:
        _fail("inputs_changed_during_execution")
    record = {"contract": CONTRACT, "verifier_id": contract["verifier_id"],
              "release_contract_sha256": contract_sha256(contract), "input_sha256": input_sha,
              "status": outcome if outcome in RESULTS else "HOLD",
              "executed_representation": "verified_source_bytes_compiled_in_memory",
              "evidence": "mechanical_closure_check_not_qualification"}
    if error or outcome not in RESULTS:
        record["hold_reason"] = error or "unrecognized_verifier_result"
    return record


def evaluate_closure_gate(root, contract: dict, inputs, *, approved_roots) -> dict:
    """Gate form: any closure rejection is HOLD with its code, never PASS."""
    try:
        return run_verifier(root, contract, inputs, approved_roots=approved_roots)
    except VerifierClosureError as exc:
        return {"contract": CONTRACT, "status": "HOLD", "rejected": exc.code, "detail": str(exc),
                "evidence": "mechanical_closure_check_not_qualification"}
