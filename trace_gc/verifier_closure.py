"""Executable dependency closure for externally reviewed qualification verifiers (#97).

A verifier's top-level source hash does not bind what actually runs: ordinary imports resolve helper files,
``sys.modules`` entries, bytecode caches and ambient packages.  This module adds a versioned contract that binds them:

* ``build_manifest`` records the complete verifier closure (module bytes, import graph, approved dynamic imports,
  declared third-party distributions, the interpreter/standard-library census and the native libraries) as a manifest.
* ``release_record`` binds that manifest to the exact implementation files (parent, child bootstrap, canonical
  encoder), the child execution contract and the runtime pins.  Reviewers supply the manifest digest and the
  release digest *externally*.
* ``run_verifier`` authenticates both digests before any child process starts, then executes the verifier in a fresh
  isolated interpreter whose import system serves closure modules from captured bytes and runtime modules from a
  census table with hash-on-read, enforces approved imports before loading, and returns a strict, bounded,
  nonce-bound result inside a receipt.

This is an integrity boundary for reviewed code, not a sandbox for hostile Python.  See
``docs/paper_verifier_closure.md`` for the exact guarantees and exclusions.
``src.parallel_source_v4.common.method_hashes`` is deliberately untouched.
"""
from __future__ import annotations

import argparse
import ast
import errno
import hashlib
import json
import math
import os
import re
import secrets
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import marshal
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from .canonical import canonical_bytes, digest as canonical_digest, dumps as canonical_dumps, loads as canonical_loads
from .errors import ContractError

VERSION = "paper-verifier-closure-v1"
RECEIPT_VERSION = "paper-verifier-closure-receipt-v1"
RELEASE_VERSION = "paper-verifier-closure-release-v1"
PROTOCOL = "PVCLOS03"
FRAME_MAGIC = b"PVCLOS03"
PROBE_MAGIC = b"PVCPROBE"
RESULT_PREFIX = "PVCLOSURE-RESULT "
PACKAGE_DIR = Path(__file__).parent
IMPLEMENTATION_FILES = ("__init__.py", "canonical.py", "errors.py", "verifier_closure.py", "verifier_closure_bootstrap.py",
                        "verifier_closure_launcher.py")

SHA = re.compile(r"^[0-9a-f]{64}$")
MODULE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$")
ALIAS = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
INPUT_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
COMPONENT = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.+-]*$")
WINDOWS_RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}

MAX_MODULE_BYTES = 4 << 20
MAX_INPUT_BYTES = 256 << 20
MAX_REPORT_BYTES = 4 << 20
MAX_STDERR_BYTES = 8 << 20
MAX_MANIFEST_BYTES = 16 << 20
MAX_TIMEOUT = 3600.0
MAX_TIMEOUT_MS = int(MAX_TIMEOUT * 1000)
PROBE_TIMEOUT = 120.0
CLEANUP_GRACE = 10.0   # the ONE cleanup allowance of a run: every cleanup step shares the deadline ``operation deadline + CLEANUP_GRACE``
FINALIZE_GRACE = 2.0   # the ONE finalization allowance: sealing a rejection ends by ``cleanup deadline + FINALIZE_GRACE`` (see ``_seal``)
FINALIZE_FLOOR = 0.25  # least time one sealing attempt is given when the window above has already ended
JANITOR_INTERVAL = 1.0   # seconds between background retries of unsettled owned resources
SETTLE_FLOOR = 1.0   # the background janitor's own allowance per owned record per pass (never a caller's budget)
SETTLE_BACKOFF_AFTER = 30   # passes after which the janitor's pause grows; ownership of an unsettled record is never given up
MAX_INPUTS = 64
MAX_MODULES = 4096
MAX_PACKAGES = 256
MAX_DYNAMIC = 4096
MAX_NATIVES = 4096
MAX_BOOTSTRAP_BYTES = 2 << 20
MAX_COMMAND_UNITS = 24000
MAX_EXPOSURE_ENTRIES = 400000
REPARSE_POINT = 0x400
CENSUS_EXCLUDED_DIRS = frozenset({"__pycache__", "site-packages", "dist-packages"})
INTERPRETER_FLAGS = ("-I", "-S", "-B", "-X", "utf8")
# Reviewed import operations of census-loaded dependencies on denylisted modules: ``(form, module)``.  Identical to the
# bootstrap's table; every other denylisted import by a dependency is a recorded violation.
DEPENDENCY_IMPORT_OPERATIONS = (("import", "builtins"),)
# Manifest-declared dependency operations ``{"importer","form","module"}`` (identical to the bootstrap's forms and
# bounds) on pinned AND unpinned modules.  A dependency's attempt on an unpinned or ambiguous module, and its dynamic
# operation (import_module, explicit __import__, find_spec) on a pinned module, is a violation unless declared.
DEPENDENCY_OPERATION_FORMS = ("import", "import_module", "find_spec")
# Reviewed standard-library dynamic operations that need no declaration: ``(importer, form, module, submodules)``;
# identical to the bootstrap's table.
DEPENDENCY_STDLIB_OPERATIONS = (("encodings", "import", "encodings", True),)
DEPENDENCY_OPERATION_PREFIX = "dependency_operation:"
MAX_DEPENDENCY_OPERATIONS = 32

def _sha_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# Set (in this module's namespace, before it executes) only by ``verifier_closure_launcher``: the exact bytes of every
# implementation file the launcher hashed against externally supplied digests.  ``None`` for any other way of loading.
_LAUNCHER_CAPTURE = globals().get("_PVC_LAUNCHER_CAPTURE")


# The ``-c`` program of every child.  It is short, ASCII and independent of the bootstrap size (a Windows command line
# is limited to 32,767 UTF-16 units, the bootstrap alone is larger): it reads the bootstrap's bytes from stdin with
# unbuffered ``os.read`` (so no frame byte is consumed), refuses any bytes whose SHA-256 differs from the digest the
# parent embedded, and only then executes exactly those bytes.
STUB_TEMPLATE = (
    "import sys\n"
    "_pvc_startup=sorted(sys.modules)\n"
    "import os\n"
    "try:\n"
    " from _sha2 import sha256 as _h\n"
    "except ImportError:\n"
    " from _sha256 import sha256 as _h\n"
    "def _r(n):\n"
    " b=b''\n"
    " while len(b)<n:\n"
    "  p=os.read(0,n-len(b))\n"
    "  if not p:\n"
    "   raise SystemExit(70)\n"
    "  b+=p\n"
    " return b\n"
    "_n=int.from_bytes(_r(8),'big')\n"
    "if _n>%(limit)d:\n"
    " raise SystemExit(71)\n"
    "_d=_r(_n)\n"
    "if _h(_d).hexdigest()!='%(digest)s':\n"
    " raise SystemExit(72)\n"
    "exec(compile(_d,'<pvc-bootstrap>','exec'),{'__name__':'__main__','_PVC_STARTUP':_pvc_startup,"
    "'_PVC_BOOTSTRAP_SHA256':'%(digest)s'})\n")

CONTRACT = {
    "protocol": PROTOCOL, "interpreter_flags": list(INTERPRETER_FLAGS) + ["-X", "pycache_prefix=<empty directory>"],
    "environment": "minimal allow-list; no PYTHON*, LD_*, DYLD_* or PATH inheritance",
    "limits": {"report_bytes": MAX_REPORT_BYTES, "stderr_bytes": MAX_STDERR_BYTES, "module_bytes": MAX_MODULE_BYTES,
               "input_bytes": MAX_INPUT_BYTES, "manifest_bytes": MAX_MANIFEST_BYTES, "max_timeout_seconds": MAX_TIMEOUT,
               "probe_timeout_seconds": PROBE_TIMEOUT, "cleanup_grace_seconds": CLEANUP_GRACE,
               "finalize_grace_seconds": FINALIZE_GRACE, "finalize_floor_seconds": FINALIZE_FLOOR,
               "janitor_interval_seconds": JANITOR_INTERVAL, "settle_floor_seconds": SETTLE_FLOOR,
               "settle_backoff_after_passes": SETTLE_BACKOFF_AFTER, "max_inputs": MAX_INPUTS,
               "bootstrap_bytes": MAX_BOOTSTRAP_BYTES, "command_utf16_units": MAX_COMMAND_UNITS,
               "modules": MAX_MODULES, "packages": MAX_PACKAGES, "natives": MAX_NATIVES,
               "dynamic": MAX_DYNAMIC, "dependency_operations": MAX_DEPENDENCY_OPERATIONS, "native_plan": 256,
               "native_depth": 16},
    "launch": {"command": "python <interpreter flags> -c <bounded ASCII stub>", "stub_sha256": _sha_text(STUB_TEMPLATE),
               "transport": "stdin = 8-byte big-endian length + bootstrap bytes + (request frame | PVCPROBE); the stub "
                            "executes the bootstrap only after its SHA-256 equals the digest embedded in the stub, "
                            "and the request header repeats that digest"},
    "status_mapping": {"PASS": "verifier returned status PASS and every integrity check held",
                       "HOLD": "verifier returned status HOLD and every integrity check held",
                       "REJECTED": "closure/runtime/input/protocol/containment failure, verifier exception or timeout"},
    "failure_classes": ["arguments", "closure", "containment", "execution", "input", "protocol", "release", "runtime"],
    "arguments": "timeout is a real number with 0 < timeout <= max_timeout_seconds (non-finite and out-of-range "
                 "values, including integers too large for a float, are rejected); the recorded timeout_ms is the "
                 "timeout rounded UP to whole milliseconds and is never 0; relative input paths are checked and all "
                 "arguments captured once before any interpreter, census or child process exists",
    "runtime_authentication": "pinned executables, start-up configuration and files, core libraries, census and natives "
                              "are hashed and compared before the first interpreter process; the parent and launcher "
                              "are authenticated only by externally supplied digests",
    "executing_parent": "the release implementation rows are the bytes the reviewed launcher hashed and executed "
                        "(implementation_source launcher_capture); a disk re-read is recorded as disk_reread and is "
                        "not acceptance grade",
    "runtime_protection": "required unless the caller explicitly allows an unprotected run (which acceptance refuses): "
                          "before the first interpreter process every pinned runtime path, its symlink targets and "
                          "ancestors, the package roots, extension files, closure roots and native files are inspected "
                          "for write exposure; the operator names the trusted principals (--trusted-uid / --trusted-sid, "
                          "in addition to root or SYSTEM/Administrators/TrustedInstaller) and the evaluating principal "
                          "is never trusted implicitly: the evaluator and the writers of the protected paths are "
                          "separate principals, so an evaluator that holds a trusted administrative identity (uid 0, "
                          "or an enabled SYSTEM/Administrators/TrustedInstaller token SID) is refused with "
                          "runtime_evaluator_privileged and its receipt is never acceptance grade, and an "
                          "unprivileged evaluator that can write any inspected path is exposed (evaluator_writable); "
                          "POSIX policy posix-owner-mode-acl-v2 (owner, mode, group "
                          "membership, ACL presence) and Windows policy windows-owner-dacl-v1 (owner SID and decoded "
                          "DACL, NOT_RUN until hosted CI); any exposed or uninspectable path, any inspection error, "
                          "and a platform without a reviewed inspector refuses the run; the policy and trusted "
                          "principals are recorded in the receipt and acceptance requires them; the Linux "
                          "containment supervisor executes no cached bytecode (fresh pycache prefix that is checked "
                          "empty after the run) and the modules it imports (supervisor_modules) are part of the probe "
                          "and therefore of the pinned runtime closure before any effect; the trusted interpreter, "
                          "launcher and digests remain deployment prerequisites supplied by the operator",
    "native_closure": "the process mapping inventory must be complete (unavailable or partial, including a Windows "
                      "module whose name cannot be read = refusal, never a smaller set); every extension module and "
                      "every library it needs, transitively, must be a pinned native: the loader reads each file's "
                      "hashed bytes, parses its dependency list (ELF DT_NEEDED / PE import table), resolves the names "
                      "only against the pinned set, and pre-loads the dependencies first from verified bytes (Linux "
                      "sealed memfd, Windows pinned path with write access denied) before the extension itself; "
                      "Linux dependency names are matched the way glibc matches a DT_NEEDED string against an object "
                      "it holds (the object's DT_SONAME, never its file basename; a dependency without a DT_SONAME "
                      "cannot satisfy an entry and refuses the plan); every memfd that backs a loaded object is "
                      "retained until exit with a unique device and inode and /proc/self/maps must show exactly that "
                      "identity after each load and before the extension initialiser runs; a Windows API-set import "
                      "must resolve (GetModuleHandleW, with an output buffer type built before the audit hook is "
                      "armed, so the resolver issues only the permitted boot-frame foreign calls and no ctypes "
                      "allocation event) to a loaded pinned host or the plan is refused; an "
                      "unparsable image, an unpinned, ambiguous or cyclic dependency, a plan larger than the bound, "
                      "RPATH/RUNPATH in every mode, audit/filter entries, PE delay-load imports and path-named "
                      "dependencies refuse before the library loads; the pre-load plan is recorded as native_plan "
                      "and the resolved mapping is compared with the pins at the end as defence in depth, never as "
                      "the identity decision",
    "imports": "every import operation in a closure module must be a static import statement or a literal "
               "importlib.import_module/__import__ call; each is approved by its exact source position "
               "(line, end line, column, end column) and name set, enforced at run time for first loads, sys.modules "
               "cache hits, from-imports and the importlib module object; dependency modules are hash-pinned census "
               "files whose every import operation (statement, __import__, importlib.import_module; absolute or "
               "relative, resolved against both the requesting frame and the globals argument; fresh or cached) runs "
               "through the same mediated functions and is admitted by one policy: a denylisted module is a recorded "
               "violation (forbidden_dependency_import) unless it is one of the reviewed dependency import "
               "operations (dependency_import_operations: the import statement or __import__ of builtins only); "
               "one operation contract covers pinned and unpinned targets alike: a dependency's attempt to load a "
               "module that is not pinned (or is ambiguous) is always refused as absent, and a dependency's DYNAMIC "
               "operation on any target, pinned (including builtin and frozen modules) or not, is approved only when "
               "it is a reviewed standard-library operation (dependency_stdlib_operations) or the manifest declares "
               "exactly that (importer, form, module) operation (dependency_operations; form import, import_module or "
               "find_spec). Dynamic means importlib.import_module (absolute or relative, fresh or cached), an "
               "explicit __import__ call (any call that is not an import statement, the instruction being measured "
               "at start-up, not assumed), a __import__ fromlist item that names a pinned submodule, and find_spec "
               "(importlib.util.find_spec, absolute or relative, cached or not, directly or through an alias: the "
               "supported function is replaced by a mediated one that decides BEFORE its cache shortcut, so a "
               "cached target is an operation like an uncached one; a request that reaches the finder outside it, "
               "for example importlib.reload, is gated at the finder); importlib.util is imported by the bootstrap "
               "before arming so that a frozen build cannot skip its mediation; every other reachable entry point "
               "is mediated the same way, before any cache shortcut: importlib.__import__, "
               "importlib._bootstrap.__import__, _gcd_import, _find_and_load, _find_and_load_unlocked, _load, "
               "_load_unlocked, importlib.find_loader, and find_spec of BuiltinImporter, FrozenImporter, PathFinder "
               "and FileFinder; the bootstrap then refuses to start (captured_import_reference) if any loaded "
               "module still holds an original, so a captured reference cannot go around the contract; an import "
               "statement of a pinned module that is "
               "not denylisted is the pinned census graph itself and needs no declaration; expected absence and "
               "ImportError handling are the dependency's own; an undeclared operation is a recorded violation "
               "(undeclared_dependency_operation), never informational, and there is no module-wide exemption; "
               "the importer of an operation is the pinned census module whose code issued the request (a helper "
               "dependency is its own importer, and the real find_spec's own internal requests are attributed to "
               "the caller, not declared separately); "
               "indirect forms (aliases, "
               "getattr, reflection) are rejected by the static scan and denied at run time; process, ctypes and "
               "code-execution operations by dependencies are refused by the audit hook; this is defence in depth, "
               "not a hostile-code sandbox",
    "dependency_import_operations": [list(item) for item in DEPENDENCY_IMPORT_OPERATIONS],
    "dependency_operation_forms": list(DEPENDENCY_OPERATION_FORMS),
    "dependency_stdlib_operations": [list(item) for item in DEPENDENCY_STDLIB_OPERATIONS],
    "dependency_operations": "manifest list of {importer, form, module}: importer is a pinned census module (not "
                             "an extension or ambiguous row), module is a pinned or unpinned module that is neither "
                             "denylisted nor closure-owned, at most max dependency_operations rows, each recorded "
                             "observation is dependency_operation:<importer>:<form>:<module> in the receipt refused "
                             "list (an unpinned target is refused as absent, a pinned one is performed) and must equal "
                             "a declared row",
    "receipt_binding": "unkeyed sha256 over every receipt field except itself: integrity of a stored receipt, not provenance",
    "receipt_evidence": "every status carries retained evidence (runtime module rows, native file rows, native plan, "
                        "mapped files) that is cross-checked against the closure, loaded, runtime-pin and protection "
                        "context, including for REJECTED receipts that carry it; with embed_result=False acceptance "
                        "requires the caller to supply the result, whose digest and status are then verified",
    "module_identity": "the receipt records module_table_sha256, the digest of the complete census-derived module map; "
                       "acceptance requires the independently reviewed map itself (expected_module_table, from "
                       "VerifiedClosure.table at release review): the receipt commitment must equal the digest of that "
                       "map, and every runtime, package, extension and native identity the receipt reports (and the "
                       "loaded counts) must be rows of it, and the extension identities the map assigns to the reported "
                       "runtime modules must equal EXACTLY the receipt's native_files rows and EXACTLY loaded.native "
                       "(an extension omitted from both representations, an extra row or a duplicate is refused); a "
                       "digest or count recomputed from the receipt's own rows is never the relationship. The map is an "
                       "operator-supplied deployment prerequisite and its external custody is mandatory for acceptance",
    "containment": "Windows: child created suspended, assigned to a kill-on-close Job Object, then resumed (NOT_RUN "
                   "until hosted CI); Linux: the child runs under a supervisor that is a PR_SET_CHILD_SUBREAPER, so "
                   "every descendant it ever owns, however it detaches or re-parents, is adopted and enumerated by "
                   "pidfd and start time, never by environment, directory or string-prefix matching; cleanup signals "
                   "only supervised pidfds and unresolved ownership is cleanup uncertainty; stdin is delivered only "
                   "after the supervisor reports ready; pipes are raw, bounded and closed after their threads ended; "
                   "a suspended Windows child that could not be assigned to the Job is terminated and reaped "
                   "directly (it is owned and not yet in the Job); an empty supervised tree is accepted only when "
                   "the supervisor's atomic no-child check (waitid P_ALL with WNOWAIT) is confirmed twice; "
                   "one operation deadline covers argument capture (copying and canonicalizing the manifest and "
                   "params), run-directory setup, probe, census, runtime-pin hashing, start-up file reads, launch, "
                   "delivery, execution, inspection, hashing, every digest and serialization of the outcome, and "
                   "sealing of an acceptance (a phase that succeeds after the deadline is not accepted); every cleanup "
                   "step shares ONE cleanup deadline (operation deadline + cleanup_grace_seconds, never a fresh "
                   "allowance per stage) that also bounds the supervisor kill/quit protocol, thread joins, the "
                   "temporary-directory removal and its absence check; sealing a rejection has ONE finalization window "
                   "(cleanup deadline + finalize_grace_seconds, at least finalize_floor_seconds): the full receipt "
                   "first (a rewrite keeps the causal reason and the process evidence and never seals a reason that "
                   "contradicts them), then a fixed-field canonical safety receipt that is a VALID v1 rejection, "
                   "bound through the plain digest function and, if that too does not finish, by one constant-size "
                   "inline computation; so every returned receipt is sealed and valid, and nothing is retried outside "
                   "the window; every caller-supplied value, hash and parse is a bounded phase; the "
                   "verdict (PASS, HOLD or any rejection) is constructed only AFTER the required cleanup finished "
                   "and the final applicable deadline was checked, and a cleanup that did not finish inside the "
                   "shared deadline is containment_cleanup_failed, never a pass; no helper starts a NEW effect after "
                   "its caller gave up (cancellation is checked before every pipe, directory creation, process "
                   "creation and removal, and again after every blocking inspection that precedes one); every "
                   "blocking inspection, "
                   "read, hash, directory, census and security phase of the verifying parent runs on a worker "
                   "thread that the caller stops waiting for when the deadline expires (the caller gets "
                   "operation_deadline_exceeded within the deadline); an abandoned worker is not discarded "
                   "silently: a process launch that outlives the caller's wait is an owned launch attempt whose "
                   "child, pipes, reader threads, supervisor prefix and scratch directory stay owned by the "
                   "process-wide owned registry, which is retried (settle_orphans spends ONE caller budget across "
                   "all records and never starts a record once it is spent; the background janitor has its own "
                   "settle_floor_seconds per record per pass and slows down after settle_backoff_after_passes "
                   "passes but never gives up) until the late child is terminated, waited for, reaped and its "
                   "descriptors and streams closed; a supervisor is NEVER ended while a descendant is unconfirmed: if "
                   "it answers that processes live it stays alive and owned, and if it cannot answer its "
                   "descendants are ended by this process (pidfd and start time) and it is ended only after that "
                   "is confirmed (a supervisor that already died by itself leaves nothing that could enumerate its "
                   "re-parented descendants: an operating-system fact reported as cleanup_failed); one cleanup "
                   "worker per record; a status descriptor whose reader is still blocked is closed by that reader "
                   "when it ends, and a closed containment accepts no adoption; no resource is parked in a list "
                   "without a consumer; a scratch directory a late worker creates after the caller gave up is "
                   "recorded against the directory's creation identity so it is removed when it appears, and a "
                   "directory whose creation identity could not be established stays owned as uncertain and is "
                   "never removed by name (only a confirmed absence resolves it); pathname removal "
                   "is bound to the directory identity captured at creation, checks the stop deadline between "
                   "individual removals, and never removes a directory or link that replaced the owned one; the "
                   "residual operating-system facts are stated, not hidden: a system call blocked in the kernel "
                   "cannot be cancelled and may complete after the call returned, Windows has no "
                   "descriptor-relative removal so a replacement between the identity check and the removal of one "
                   "entry is not excluded there, POSIX removal by name can only remove a replaced directory that "
                   "is empty, orphans are retained in-process only (not across process death) and zombie reaping "
                   "depends on the supervisor's answer; an unconfirmed removal is a cleanup failure "
                   "(containment_cleanup_failed), never a pass; uncertainty about any cleanup is a failure and no "
                   "process outside the supervised tree is ever signalled",
}

# Constructs a closure module may not use.  ``importlib.import_module`` and ``__import__`` are supported only as
# explicitly approved literal imports; everything else that could load unbound code is rejected statically *and*
# refused at run time by the bootstrap's import finder and audit hook.
FORBIDDEN_MODULES = frozenset({"runpy", "pkgutil", "imp", "zipimport", "ctypes", "_ctypes", "cffi", "subprocess",
                               "multiprocessing", "_winapi", "_posixsubprocess", "pty", "builtins", "msvcrt"})
FORBIDDEN_OS = frozenset({"system", "popen", "startfile", "add_dll_directory", "fork", "forkpty",
                          "posix_spawn", "posix_spawnp",
                          *(f"exec{s}" for s in ("l", "le", "lp", "lpe", "v", "ve", "vp", "vpe")),
                          *(f"spawn{s}" for s in ("l", "le", "lp", "lpe", "v", "ve", "vp", "vpe"))})
FORBIDDEN_SYS = frozenset({"path", "meta_path", "path_hooks", "path_importer_cache", "modules", "setdlopenflags"})
FORBIDDEN_NAMES = frozenset({"exec", "eval", "compile", "__builtins__", "breakpoint", "globals", "__loader__", "__spec__"})
# Attribute names that reach the import state or interpreter frames from any base object.
FORBIDDEN_ATTRIBUTES = frozenset({"__builtins__", "__import__", "__loader__", "__spec__", "__globals__", "__code__",
                                  "f_globals", "f_builtins", "f_back", "gi_frame", "cr_frame", "_getframe",
                                  "_current_frames", "modules", "meta_path", "path_hooks", "path_importer_cache",
                                  "setdlopenflags"})


class ClosureRejected(ValueError):
    """A closure/runtime/input contract violation; ``code`` is a bounded identifier."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(code + (":" + detail if detail else ""))
        self.code, self.detail = code, detail


def _reject(code: str, detail: str = ""):
    raise ClosureRejected(code, detail)


def _require(condition: bool, code: str, detail: str = ""):
    if not condition:
        _reject(code, detail)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# The ONE reason-head-to-class table.  No prefix of one class is a prefix of, or begins with, a prefix of another class
# (a test checks this), so the classes are decided independently of order and the published receipt schema encodes every
# class by the same prefixes; a reason head that matches none of them is the fallback class.
FAILURE_CLASS_PREFIXES = (
    ("containment", ("containment_", "process_containment")),
    ("protocol", ("protocol_",)),
    ("execution", ("execution_", "operation_")),
    ("release", ("release_", "implementation_", "expected_release", "expected_digest", "manifest_digest", "bootstrap_")),
    ("runtime", ("runtime_", "unsupported_runtime", "census_", "native_", "interpreter_")),
    ("input", ("input_", "inputs_", "params_")),
    ("arguments", ("invalid_arguments", "roots_", "root_")),
)
FAILURE_CLASS_FALLBACK = "closure"


def failure_class(code: str) -> str:
    for name, prefixes in FAILURE_CLASS_PREFIXES:
        if code.startswith(prefixes):
            return name
    return FAILURE_CLASS_FALLBACK


# --------------------------------------------------------------------------- paths

def _linklike(st: os.stat_result) -> bool:
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & REPARSE_POINT)


def _check_relative(relative: str, code: str = "unsafe_relative_path") -> list[str]:
    _require(isinstance(relative, str) and relative and "\\" not in relative and not relative.startswith("/"), code, str(relative)[:80])
    parts = relative.split("/")
    for part in parts:
        _require(part not in ("", ".", "..") and COMPONENT.match(part) is not None, code, part[:40])
        _require(not part.endswith((".", " ")) and part.split(".")[0].lower() not in WINDOWS_RESERVED, code, part[:40])
    return parts


def _root(path: Path | str, alias: str) -> str:
    text = os.path.abspath(os.fspath(path))
    _require(os.path.isabs(text), "root_not_absolute", alias)
    try:
        st = os.lstat(text)
    except OSError:
        _reject("root_missing", alias)
    _require(stat.S_ISDIR(st.st_mode) and not _linklike(st), "root_not_plain_directory", alias)
    # Every ancestor must be a plain directory too: a symlink/junction anywhere above the root redirects it.
    child, parent = text, os.path.dirname(text)
    while parent != child:
        try:
            pst = os.lstat(parent)
        except OSError:
            _reject("root_ancestor_unreadable", alias)
        _require(stat.S_ISDIR(pst.st_mode) and not _linklike(pst), "root_ancestor_link_or_reparse_point", alias)
        child, parent = parent, os.path.dirname(parent)
    return text


def _walk_components(root: str, parts: Sequence[str], *, final_dir: bool = False) -> str:
    """Resolve ``parts`` below ``root`` refusing links/reparse points and case/short-name substitutes."""
    current = root
    for index, part in enumerate(parts):
        try:
            names = {entry.name for entry in os.scandir(current)}
        except OSError:
            _reject("path_missing", "/".join(parts)[:80])
        _require(part in names, "path_missing_or_case_mismatch", "/".join(parts)[:80])
        current = os.path.join(current, part)
        st = os.lstat(current)
        _require(not _linklike(st), "path_link_or_reparse_point", "/".join(parts[:index + 1])[:80])
        last = index == len(parts) - 1
        if not last or final_dir:
            _require(stat.S_ISDIR(st.st_mode), "path_not_directory", part[:40])
        else:
            _require(stat.S_ISREG(st.st_mode), "path_not_regular_file", part[:40])
    return current


def _read_file(root: str, relative: str, limit: int) -> bytes:
    path = _walk_components(root, _check_relative(relative))
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    before = os.lstat(path)
    fd = os.open(path, flags)
    try:
        after = os.fstat(fd)
        _require(stat.S_ISREG(after.st_mode) and after.st_size <= limit, "file_too_large_or_irregular", relative[:80])
        if before.st_ino and after.st_ino:
            _require((before.st_dev, before.st_ino) == (after.st_dev, after.st_ino), "path_replaced_during_read", relative[:80])
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(limit + 1)
    finally:
        os.close(fd)
    _require(len(data) <= limit, "file_too_large_or_irregular", relative[:80])
    return data


def _identity(info: os.stat_result) -> tuple[int, int]:
    return (info.st_dev, info.st_ino)


def _link_like(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & REPARSE_POINT)


def _cleanup_slice(cleanup_end: float | None, cap: float) -> float:
    """Seconds a cleanup step may still use: at most ``cap`` and never past the one shared ``cleanup_end``."""
    if cleanup_end is None:
        return cap
    return max(0.0, min(cap, cleanup_end - time.monotonic()))


_ORPHANS: dict[str, tuple[int, int] | None] = {}   # owned directories no cleanup could confirm gone: path -> identity at
_ORPHANS_LOCK = threading.Lock()                    # creation, or None when that identity could not be established (uncertain)
_LATE_OUTCOMES: list[tuple[str, str, str]] = []   # (kind, path, outcome) of late creations the run had already given up on


def _keep_orphan(path: str, identity: tuple[int, int] | None) -> None:
    with _ORPHANS_LOCK:
        _ORPHANS[path] = identity


def _record_late(kind: str, path: str, outcome: str) -> None:
    with _ORPHANS_LOCK:
        _LATE_OUTCOMES.append((kind, path, outcome))
        del _LATE_OUTCOMES[:-256]


def _creation_identity(path: str) -> tuple[tuple[int, int] | None, bool]:
    """``(identity, absent)`` of a directory this code has just created.  ``absent`` is True only for a CONFIRMED absence
    (``FileNotFoundError``/``NotADirectoryError``); any other failure reports ``(None, False)``: the creation identity is
    UNKNOWN and the directory stays owned, uncertain.

    The pathname is looked up exactly ONCE.  Where a directory can be opened (POSIX) that lookup yields a RETAINED object
    (``O_DIRECTORY | O_NOFOLLOW``), and only the object is queried again if its ``fstat`` fails: a repeated query of the
    same descriptor cannot return a different thing, whereas a repeated lookup of the NAME could return whatever occupies
    the name by then.  A later successful lookup therefore never identifies the original creation; where no directory can
    be opened (Windows) the single ``lstat`` is the only attempt.  The first lookup after creation is the establishing
    event; the interval between ``mkdtemp`` returning and that lookup is inherent to name-based creation."""
    if hasattr(os, "O_DIRECTORY"):
        flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            descriptor = os.open(path, flags)
        except (FileNotFoundError, NotADirectoryError):
            return None, True
        except OSError:
            return None, False
        try:
            for attempt in range(3):
                try:
                    return _identity(os.fstat(descriptor)), False
                except OSError:
                    if attempt < 2:
                        time.sleep(0.01)
            return None, False
        finally:
            os.close(descriptor)
    try:
        return _identity(os.lstat(path)), False
    except (FileNotFoundError, NotADirectoryError):
        return None, True
    except OSError:
        return None, False


def _remove_by_creation(path: str, budget: float, identity: tuple[int, int] | None) -> str:
    """Remove something THIS code created, bound to its creation identity.  Without that identity nothing is ever
    removed (a later occupant of the pathname is not the thing that was created): only a confirmed absence resolves the
    record (``"removed"``), anything else is ``"uncertain"`` and stays a cleanup failure until it is resolved."""
    if identity is not None:
        return _bounded_remove(path, budget, identity)
    state, value = _attempt(time.monotonic() + max(0.0, budget), os.lstat, path)
    if state == "error" and isinstance(value, (FileNotFoundError, NotADirectoryError)):
        return "removed"
    return "uncertain"


_OWNED: dict[int, tuple[str, Any]] = {}   # token -> (label, settler): resources no cleanup could release yet
_OWNED_LOCK = threading.Lock()
_OWNED_NEXT = [0]
_JANITOR: list[threading.Thread] = []


def _own(label: str, settler) -> int:
    """Take durable ownership of resources a run could not release (a child, its descriptors, its streams, a thread's
    descriptor).  ``settler(budget) -> bool`` retries the release within ``budget`` seconds (0: one attempt that does not
    wait) and returns True only when nothing is left.  The record stays until a retry succeeds: by ``settle_orphans``, by an
    explicit ``_LaunchAttempt.settle`` or by the background janitor, which retries every ``JANITOR_INTERVAL`` seconds while
    any record exists.  A record that nothing ever retries would not be ownership, so every record has these consumers."""
    with _OWNED_LOCK:
        _OWNED_NEXT[0] += 1
        token = _OWNED_NEXT[0]
        _OWNED[token] = (label, settler)
        if not _JANITOR:
            thread = threading.Thread(target=_janitor, daemon=True, name="pvc-janitor")
            _JANITOR.append(thread)
            thread.start()
    return token


def _disown(token: int) -> None:
    with _OWNED_LOCK:
        _OWNED.pop(token, None)


def _settle_owned(budget: float, per_record: float | None = None) -> list[str]:
    """One pass over the owned records inside ONE ``budget``; the labels (``label#token``) that are still unsettled.

    The budget is a hard shared limit: each settler receives only what is left of it (and ``per_record`` at most), and once
    it is spent no further record is started, so a caller never waits longer than it asked.  Records that were not reached
    simply stay owned.  A settler that cannot take its own lock inside its slice reports "not settled" instead of waiting."""
    end = time.monotonic() + max(0.0, budget)
    with _OWNED_LOCK:
        records = sorted(_OWNED.items())
    for token, (_label, settler) in records:
        left = end - time.monotonic()
        if left <= 0:
            break
        with _OWNED_LOCK:
            running = _SETTLING.get(token)
            if running is not None:
                continue   # a worker for this record is still in flight (blocked): never a duplicate, the record stays owned
            finished = _SETTLING[token] = threading.Event()
        slice_ = left if per_record is None else min(left, per_record)

        def attempt(token=token, settler=settler, finished=finished, slice_=slice_):
            try:
                if settler(slice_):
                    _disown(token)   # also when it finishes after the caller stopped waiting
            except BaseException:   # noqa: BLE001 - a failing retry leaves the record in place
                pass
            finally:
                with _OWNED_LOCK:
                    _SETTLING.pop(token, None)
                finished.set()
        threading.Thread(target=attempt, daemon=True, name="pvc-settle").start()
        if not finished.wait(max(0.0, end - time.monotonic())):
            break   # the shared budget ended while this settler was blocked: nothing further is started
    with _OWNED_LOCK:
        return ["%s#%d" % (label, token) for token, (label, _settler) in sorted(_OWNED.items())]


_SETTLING: dict[int, threading.Event] = {}   # token -> event of the one settle worker currently in flight for that record


def _janitor() -> None:
    """The background consumer.  Its retries have their OWN allowance (``SETTLE_FLOOR`` per record per pass), never a
    caller's budget; the pause between passes grows (to 16 times ``JANITOR_INTERVAL``) once a record has survived
    ``SETTLE_BACKOFF_AFTER`` passes, but ownership is NEVER given up: an unsettled record is retried for as long as it exists."""
    passes = 0
    while True:
        time.sleep(JANITOR_INTERVAL * (1 + min(15, passes // max(1, SETTLE_BACKOFF_AFTER))))
        with _OWNED_LOCK:
            count = len(_OWNED)
        _settle_owned(max(1, count) * SETTLE_FLOOR, SETTLE_FLOOR)
        passes += 1
        with _OWNED_LOCK:
            if not _OWNED:
                _JANITOR.clear()   # under the lock: a concurrent ``_own`` then starts a new janitor
                return


class _LateAbandoned(Exception):
    """Raised inside a helper whose caller already gave up: the helper has settled what it created and stops."""


class _ScratchLedger:
    """Durable ownership of every scratch directory one run creates, each bound to the identity it had when created.

    A creation may complete AFTER the caller of its bounded helper gave up (``mkdtemp`` cannot be cancelled).  The
    creating thread therefore registers the directory itself, in the same step: while the ledger is open the run's
    cleanup removes it; once the ledger is closed (the run's cleanup already ran) the creating thread removes it
    itself, identity-bound, and a removal that cannot be confirmed stays in ``_ORPHANS`` for ``settle_orphans``."""

    def __init__(self):
        self._lock = threading.Lock()
        # path -> (creation identity or None when it could not be established, removed by this run's cleanup)
        self._entries: dict[str, tuple[tuple[int, int] | None, bool]] = {}
        self._closed = False

    def adopt(self, path: str, remove: bool = True) -> bool:
        """``True`` while the run still owns ``path``; ``False`` (after settling it) when the run's cleanup already ended.

        Only a CONFIRMED absence means there is nothing to own.  An inspection that fails for any other reason leaves the
        creation identity unknown: the directory is still owned, as an uncertain record that is never removed by name (a
        later occupant of the pathname is not what was created) and that stays a cleanup failure until it is resolved."""
        identity, absent = _creation_identity(path)
        if absent:
            return True
        with self._lock:
            if not self._closed:
                self._entries[path] = (identity, remove)
                return True
        outcome = _remove_by_creation(path, CLEANUP_GRACE, identity)
        if outcome not in ("removed", "replaced"):
            _keep_orphan(path, identity)
        _record_late("scratch", path, outcome)
        return False

    def holds(self, path: str) -> bool:
        with self._lock:
            return path in self._entries

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._closed

    def release_all(self, budget: float) -> bool:
        """Close the ledger and remove every entry this run is to remove within the ONE ``budget``; ``True`` only when
        each is verified gone.  An entry that is not confirmed gone is retained in ``_ORPHANS``."""
        with self._lock:
            self._closed = True
            entries = sorted(self._entries.items(), key=lambda item: len(item[0]))
            self._entries = {}
        end = time.monotonic() + max(0.0, budget)
        every = True
        for path, (identity, remove) in entries:
            if not remove:
                continue
            if time.monotonic() >= end:   # the shared budget is spent: no further removal is started, ownership is kept
                every = False
                _keep_orphan(path, identity)
                continue
            outcome = _remove_by_creation(path, max(0.0, end - time.monotonic()), identity)
            if outcome == "removed":
                continue
            every = False
            if outcome != "replaced":
                _keep_orphan(path, identity)
        return every


def settle_orphans(budget: float | None = None) -> list[str]:
    """Retry, within ONE ``budget`` (default ``CLEANUP_GRACE``), the identity-bound removal of directories an earlier run
    could not confirm gone.  A path that was replaced since is no longer ours and is dropped (never deleted).  Returns the
    paths that are still unsettled."""
    with _ORPHANS_LOCK:
        pending = sorted(_ORPHANS.items(), key=lambda item: len(item[0]))
    end = time.monotonic() + max(0.0, CLEANUP_GRACE if budget is None else budget)
    for path, identity in pending:
        if time.monotonic() >= end:
            break
        outcome = _remove_by_creation(path, max(0.0, end - time.monotonic()), identity)
        if outcome in ("removed", "replaced"):
            with _ORPHANS_LOCK:
                _ORPHANS.pop(path, None)
    owned = _settle_owned(max(0.0, end - time.monotonic()))   # children, descriptors and streams: the SAME one budget
    with _ORPHANS_LOCK:
        return sorted(_ORPHANS) + owned


def _scratch_mkdtemp(prefix: str, parent: str | None = None, remove: bool = True) -> str:
    """Create one scratch directory owned by the current run's ledger (plain ``mkdtemp`` outside a run).

    Registration happens in the creating thread: a creation the run already gave up on is removed by that same
    thread before it returns, and ``_LateAbandoned`` tells the (discarded) caller so.  A creation that has not begun when
    the caller gave up (a bounded phase was abandoned, or the ledger closed) never begins."""
    operation = _Operation.current()
    if operation is not None and (operation.cancelled.is_set() or operation.scratch.closed):
        raise _LateAbandoned(prefix)
    path = tempfile.mkdtemp(prefix=prefix, dir=parent)
    if operation is not None and not operation.scratch.adopt(path, remove):
        raise _LateAbandoned(path)
    return path


class _Operation:
    """The single wall-clock deadline of one public run: probe, protection inspection, census, hashing, launch,
    execution and post-checks all spend from it.  The ONE cleanup deadline ``cleanup_end`` (``CLEANUP_GRACE`` after the
    operation deadline) is shared by every cleanup step of the run; no step gets a fresh allowance."""

    _local = threading.local()

    def __init__(self, timeout: float):
        self.deadline = time.monotonic() + validate_timeout(timeout)
        self.cleanup_end = self.deadline + CLEANUP_GRACE
        self.finalize_end = self.cleanup_end + FINALIZE_GRACE   # sealing a rejection ends here (``_seal``)
        self.abandoned: list[str] = []
        self.cancelled = threading.Event()   # set the moment any phase is abandoned: no helper starts a NEW effect after it
        self.scratch = _ScratchLedger()

    @classmethod
    def cleanup_left(cls, cap: float | None = None) -> float:
        """Seconds a cleanup step may use: at most ``cap`` and never past the run's one shared cleanup deadline."""
        cap = CLEANUP_GRACE if cap is None else cap
        operation = cls.current()
        if operation is None:
            return cap
        return max(0.0, min(cap, operation.cleanup_end - time.monotonic()))

    def __enter__(self):
        self._previous = getattr(self._local, "current", None)
        self._local.current = self
        return self

    def __exit__(self, *exc):
        self._local.current = self._previous
        return False

    @classmethod
    def current(cls) -> "_Operation | None":
        return getattr(cls._local, "current", None)

    @classmethod
    def remaining(cls, cap: float) -> float:
        """Seconds a phase may use: ``cap`` outside a run, else the smaller of ``cap`` and the time left."""
        operation = cls.current()
        if operation is None:
            return cap
        left = operation.deadline - time.monotonic()
        _require(left > 0, "operation_deadline_exceeded", "before_phase")
        return min(cap, left)

    @classmethod
    def tick(cls, where: str) -> None:
        operation = cls.current()
        if operation is not None:
            _require(time.monotonic() < operation.deadline, "operation_deadline_exceeded", where)

    @classmethod
    def bounded(cls, where: str, function, *args, **kwargs):
        """Run one blocking step (stat, read, hash, directory walk, security query, scratch-directory creation) so that
        the CALLER regains control at the whole-operation deadline even while the system call itself is stuck.

        Inside a run the call executes in a helper thread that carries the same operation (so its cooperative checks
        keep working) and the caller waits no longer than the time left.  A call that has not finished by then is
        abandoned and fails closed with ``operation_deadline_exceeded:<where>:blocked``.  A blocked system call cannot
        be cancelled: the abandoned helper is never signalled or killed and its late RESULT is discarded, but any
        side effect it still performs is owned, not forgotten.  The only side-effecting steps run through this method
        create scratch directories, and they register each one in the run's ``_ScratchLedger`` from the creating thread
        (``_scratch_mkdtemp``), so a late creation is removed by that thread, identity-bound, and never leaks.  Every
        other step is a read-only inspection or a computation over data it is handed (argument capture, digests,
        serialization).  The moment a phase is abandoned ``operation.cancelled`` is set, and ``_scratch_mkdtemp`` starts
        no creation after that.  A phase that SUCCEEDS after the deadline is not accepted
        (``operation_deadline_exceeded:<where>:late``); a rejection the phase decided itself is passed through unchanged.
        Outside a run the function is called directly.
        """
        operation = cls.current()
        if operation is None:
            return function(*args, **kwargs)
        left = operation.deadline - time.monotonic()
        _require(left > 0, "operation_deadline_exceeded", where + ":before_phase")
        box: dict[str, Any] = {}
        finished = threading.Event()

        def worker():
            cls._local.current = operation
            try:
                box["value"] = function(*args, **kwargs)
            except BaseException as exc:   # noqa: BLE001 - handed to the caller verbatim
                box["error"] = exc
            finally:
                finished.set()

        threading.Thread(target=worker, daemon=True, name="pvc-bounded-" + where[:24]).start()
        if not finished.wait(left):
            operation.abandoned.append(where)
            operation.cancelled.set()
            _reject("operation_deadline_exceeded", where + ":blocked")
        if "error" in box:   # a rejection the phase itself decided is the truthful outcome, whenever it arrives
            raise box["error"]
        if time.monotonic() >= operation.deadline:   # but a SUCCESS that arrives after the deadline is not accepted
            operation.cancelled.set()
            _reject("operation_deadline_exceeded", where + ":late")
        return box["value"]


HASH_CHUNK = 1 << 20


def _stream_sha256(stream) -> str:
    """SHA-256 of an open binary stream, checking the whole-operation deadline between bounded chunks."""
    digest = hashlib.sha256()
    while True:
        _Operation.tick("hash")
        chunk = stream.read(HASH_CHUNK)
        if not chunk:
            return digest.hexdigest()
        digest.update(chunk)


def _file_sha256(path: str, code: str) -> str:
    _Operation.tick("hash")
    try:
        st = os.stat(path)
        _require(stat.S_ISREG(st.st_mode), code, "not_a_file")
        with open(path, "rb") as stream:
            return _stream_sha256(stream)
    except OSError:
        _reject(code, "unreadable")


def _hash_tree(base: str, label: str, relprefix: str = "", sink: dict | None = None) -> list[list[Any]]:
    """Hash every regular file below ``base`` (no links, no ``__pycache__``) into census rows.

    ``sink`` receives ``absolute path -> sha256`` for module-table construction.
    """
    rows: list[list[Any]] = []
    for here, dirs, files in os.walk(base, followlinks=False):
        _Operation.tick("census")
        dirs[:] = sorted(d for d in dirs if d not in CENSUS_EXCLUDED_DIRS)
        for d in dirs:
            _require(not _linklike(os.lstat(os.path.join(here, d))), "census_linked_directory", label + "/" + d)
        for name in sorted(files):
            _Operation.tick("census")
            path = os.path.join(here, name)
            st = os.lstat(path)
            if stat.S_ISLNK(st.st_mode) and not (getattr(st, "st_file_attributes", 0) & REPARSE_POINT):
                st = os.stat(path)  # file symlink in a system runtime: hash the target bytes
            else:
                _require(not _linklike(st), "census_linked_file", label + "/" + name)
            _require(stat.S_ISREG(st.st_mode), "census_irregular_file", label + "/" + name)
            with open(path, "rb") as stream:
                data_hash = _stream_sha256(stream)
            rel = relprefix + os.path.relpath(path, base).replace(os.sep, "/")
            rows.append([label, "f", rel, st.st_size, data_hash])
            if sink is not None:
                sink[path] = data_hash
    return rows


# --------------------------------------------------------------------------- source scan

@dataclass
class Scan:
    imports: list[tuple[str, tuple[str, ...]]] = field(default_factory=list)   # (absolute base, from-names)
    dynamic: list[str] = field(default_factory=list)                              # literal dynamic targets
    rejections: list[str] = field(default_factory=list)
    # (line, end line, column, end column, absolute names): the exact AST position of an import statement or of a
    # literal import call; the child compares it with the position of the executing instruction.
    sites: list[tuple[int, int, int, int, tuple[str, ...]]] = field(default_factory=list)


def _alias_maps(tree: ast.AST):
    aliases: dict[str, str] = {}
    from_names: dict[str, tuple[str, str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                aliases[item.asname or item.name.partition(".")[0]] = item.name if item.asname else item.name.partition(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for item in node.names:
                from_names[item.asname or item.name] = (node.module, item.name)
    return aliases, from_names


def _span(node: ast.AST) -> tuple[int, int, int, int]:
    """Exact source position of a node, as the interpreter records it for the node's executing instruction."""
    return node.lineno, node.end_lineno, node.col_offset, node.end_col_offset  # type: ignore[attr-defined]


def scan_source(data: bytes, module: str, package: bool) -> Scan:
    """Static, conservative import/dynamic-construct scan of one captured module.

    This is an *authoring and early-rejection* aid, not the enforcement point: arbitrary Python cannot be proven
    closed by an AST scan.  The child bootstrap enforces the recorded sites again, by exact instruction position,
    for every import route before anything is loaded.  A dynamic ``importlib.import_module`` call must have its
    callee on the line the call starts (otherwise the compiler records a shifted call position).
    """
    result = Scan()
    try:
        tree = ast.parse(data, filename=module)
    except (SyntaxError, ValueError):
        result.rejections.append("syntax_error:" + module)
        return result
    aliases, from_names = _alias_maps(tree)
    importlib_aliases = {k for k, v in aliases.items() if v == "importlib"}
    importlib_calls = {k for k, (m, n) in from_names.items() if m == "importlib" and n == "import_module"}
    parents = {id(child): node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    package_name = module if package else module.rpartition(".")[0]
    uses_importlib = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                top = item.name.partition(".")[0]
                if top == "importlib":
                    uses_importlib = True
                    if item.name != "importlib":
                        result.rejections.append("forbidden_import:" + item.name)
                elif top in FORBIDDEN_MODULES:
                    result.rejections.append("forbidden_import:" + item.name)
                result.imports.append((item.name, ()))
            result.sites.append((*_span(node), tuple(item.name for item in node.names)))
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                parts = package_name.split(".") if package_name else []
                keep = len(parts) - (node.level - 1)
                if keep <= 0:
                    result.rejections.append("invalid_relative_import:" + module)
                    continue
                base = ".".join(parts[:keep]) + ("." + node.module if node.module else "")
            else:
                base = node.module or ""
            top = base.partition(".")[0]
            names = tuple(item.name for item in node.names)
            if top == "importlib":
                uses_importlib = True
                if base != "importlib" or any(n != "import_module" for n in names):
                    result.rejections.append("forbidden_import:" + base + "." + ",".join(names))
            elif top in FORBIDDEN_MODULES:
                result.rejections.append("forbidden_import:" + base)
            elif base == "os" and any(n in FORBIDDEN_OS for n in names):
                result.rejections.append("forbidden_os_call:" + ",".join(n for n in names if n in FORBIDDEN_OS))
            elif base == "sys" and any(n in FORBIDDEN_SYS for n in names):
                result.rejections.append("forbidden_sys_attribute:" + ",".join(n for n in names if n in FORBIDDEN_SYS))
            result.imports.append((base, names))
            if base:
                result.sites.append((*_span(node), (base, *(base + "." + n for n in names if n != "*"))))
    call_funcs: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        kind = None
        if isinstance(func, ast.Name) and (func.id == "__import__" or func.id in importlib_calls):
            kind = func.id
        elif isinstance(func, ast.Attribute) and func.attr == "import_module" and isinstance(func.value, ast.Name) \
                and func.value.id in importlib_aliases:
            kind = "importlib.import_module"
        if kind is None:
            continue
        call_funcs.add(id(func))
        if len(node.args) == 1 and not node.keywords and isinstance(node.args[0], ast.Constant) \
                and isinstance(node.args[0].value, str) and MODULE.match(node.args[0].value):
            if isinstance(func, ast.Attribute) and func.end_lineno != node.lineno:
                result.rejections.append("dynamic_import_layout:" + kind)
                continue
            result.dynamic.append(node.args[0].value)
            result.sites.append((*_span(node), (node.args[0].value,)))
        else:
            result.rejections.append("dynamic_import_not_literal:" + kind)
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and id(node) not in call_funcs:
            if node.id in FORBIDDEN_NAMES or node.id == "__import__":
                result.rejections.append("dynamic_execution:" + node.id)
            elif node.id in importlib_aliases | importlib_calls:
                parent = parents.get(id(node))
                if not (isinstance(parent, ast.Call) and parent.func is node) and not (
                        isinstance(parent, ast.Attribute) and id(parent) in call_funcs):
                    result.rejections.append("importlib_reference_not_call")
        elif isinstance(node, ast.Attribute):
            base = node.value
            if isinstance(base, ast.Name):
                origin = aliases.get(base.id)
                if origin == "os" and node.attr in FORBIDDEN_OS:
                    result.rejections.append("forbidden_os_call:" + node.attr)
                elif origin == "sys" and node.attr in FORBIDDEN_SYS:
                    result.rejections.append("forbidden_sys_attribute:" + node.attr)
                elif base.id in importlib_aliases and id(node) not in call_funcs:
                    result.rejections.append("importlib_attribute:" + node.attr)
            if node.attr == "__builtins__":
                result.rejections.append("dynamic_execution:__builtins__")
            elif node.attr in FORBIDDEN_ATTRIBUTES:
                result.rejections.append("reflective_attribute:" + node.attr)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                and node.func.id in ("getattr", "setattr", "delattr", "hasattr") and len(node.args) >= 2 \
                and isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str):
            attribute, target = node.args[1].value, node.args[0]
            origin = aliases.get(target.id) if isinstance(target, ast.Name) else None
            if attribute in FORBIDDEN_ATTRIBUTES or attribute == "__builtins__" \
                    or (origin == "os" and attribute in FORBIDDEN_OS) or (origin == "sys" and attribute in FORBIDDEN_SYS):
                result.rejections.append("reflective_attribute:" + attribute)
    result.sites = sorted(set(result.sites))
    if uses_importlib and not (result.dynamic or any(r.startswith("dynamic_import_not_literal") for r in result.rejections)):
        result.rejections.append("importlib_without_approved_dynamic_import")
    result.rejections = sorted(set(result.rejections))
    return result


def _ancestors(name: str) -> list[str]:
    parts = name.split(".")
    return [".".join(parts[:i]) for i in range(1, len(parts))]


def _entry_binds(data: bytes, name: str) -> bool:
    """True when the entry module's top level (statically) binds a synchronous ``name``."""
    try:
        body = ast.parse(data).body
    except (SyntaxError, ValueError):
        return False
    for node in body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name == name:
            return True
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            return True
        if isinstance(node, (ast.Import, ast.ImportFrom)) and any(
                (a.asname or a.name.partition(".")[0]) == name for a in node.names):
            return True
    return False


def analyse(modules: Mapping[str, tuple[bytes, bool]], *, entry: str, entry_callable: str, stdlib_names: frozenset[str],
            package_tops: frozenset[str], approved_dynamic: Mapping[str, frozenset[str]]):
    """Pure closure analysis: ``(edges, from_import_candidates, allowed_imports, sites)`` or ``ClosureRejected``.

    ``allowed_imports`` is, per module, every absolute name the module may import at run time.  ``sites`` is, per
    module, the exact import sites ``[line, end line, column, end column, [absolute names]]`` (import statements and
    literal dynamic calls, by AST position): the child admits an import only when the executing instruction has
    exactly one of these positions and the import names one of its names, and refuses anything else before loading it.
    """
    tops = {name.partition(".")[0] for name in modules}
    for top in sorted(tops):
        _require(top not in stdlib_names and top not in package_tops, "closure_name_shadows_runtime", top)
    _require(entry in modules, "entry_module_missing", entry)
    _require(_entry_binds(modules[entry][0], entry_callable), "entry_callable_missing", entry + ":" + entry_callable)
    folded = {}
    for name in modules:
        _require(folded.setdefault(name.casefold(), name) == name, "module_name_case_collision", name)
    edges: dict[str, set[str]] = {name: set() for name in modules}
    allowed: dict[str, set[str]] = {name: set() for name in modules}
    sites: dict[str, list[list[Any]]] = {name: [] for name in modules}
    from_candidates: list[tuple[str, str]] = []

    def link(owner: str, target: str):
        chain = [*_ancestors(target), target]
        for item in chain:
            _require(item in modules, "unlisted_module", item)
            if item != chain[-1]:
                _require(modules[item][1], "namespace_package_unsupported", item)
        for item in chain:
            if item != owner:
                edges[owner].add(item)

    for name, (data, package) in sorted(modules.items()):
        for ancestor in _ancestors(name):
            _require(ancestor in modules and modules[ancestor][1], "namespace_package_unsupported", ancestor)
            edges[name].add(ancestor)
        scan = scan_source(data, name, package)
        _require(not scan.rejections, scan.rejections[0].partition(":")[0] if scan.rejections else "", scan.rejections[0] if scan.rejections else "")
        approved = approved_dynamic.get(name, frozenset())
        for target in scan.dynamic:
            _require(target in approved, "unapproved_dynamic_import", name + "->" + target)
        _require(set(scan.dynamic) == set(approved), "dynamic_approval_mismatch", name)
        sites[name] = [[line, end_line, column, end_column, list(names)]
                       for line, end_line, column, end_column, names in scan.sites]
        for base, names in scan.imports:
            if not base:
                continue
            allowed[name].add(base)
            allowed[name].update(base + "." + item for item in names if item != "*")
            top = base.partition(".")[0]
            if top in tops:
                link(name, base)
            elif top not in package_tops and top not in stdlib_names:
                _reject("unpinned_import", name + "->" + base)
            if top in tops:
                for item in names:
                    if item == "*":
                        continue
                    sub = base + "." + item
                    if sub in modules:
                        link(name, sub)
                    else:
                        from_candidates.append((name, sub))
        for target in scan.dynamic:
            allowed[name].add(target)
            top = target.partition(".")[0]
            if top in tops:
                link(name, target)
            elif not (top in package_tops or top in stdlib_names):
                _reject("unpinned_import", name + "->" + target)
    seen, queue = set(), [entry]
    while queue:
        item = queue.pop()
        if item in seen:
            continue
        seen.add(item)
        queue.extend(edges[item])
    _require(seen == set(modules), "unreachable_module", ",".join(sorted(set(modules) - seen))[:120])
    return ({k: sorted(v) for k, v in sorted(edges.items())}, from_candidates,
            {k: sorted(v) for k, v in sorted(allowed.items())}, dict(sorted(sites.items())))


# --------------------------------------------------------------------------- process containment and execution

SUPERVISOR_PURGE = 4.0
CONTAIN_START = 10.0

# The ``-c`` program of the Linux containment supervisor.  It runs in the authenticated interpreter BEFORE any verifier
# byte exists: it becomes a child subreaper, starts the verifier interpreter as its own child with the inherited
# pipes, and from then on every process of the run is a descendant of the supervisor by kernel parenthood (an orphan
# is re-parented to the nearest subreaper, which is the supervisor, never to an unrelated process).  Ownership is
# the parent/child relation of the process table, never a name, environment, directory or session.  Signals use a
# pidfd after the process start time was re-read, so a recycled pid is never signalled.
#
# The supervisor is part of the trusted execution path, so its own dependencies are authenticated like the verifier's:
# it runs with ``-I -S -B`` and a fresh, empty ``pycache_prefix`` (no cached executable representation can exist),
# its sources are in the censused standard library, and every module it imports (``SUPERVISOR_MODULES``) is imported by
# the bootstrap's probe BEFORE the native inventory is taken, so their extension modules and shared libraries are
# pinned and hashed by ``authenticate_runtime`` before any process is created.  ``probe_runtime`` refuses a probe whose
# ``supervisor_modules`` differ from this constant.
SUPERVISOR_MODULES = ("ctypes", "os", "select", "signal", "subprocess", "sys", "time")
SUPERVISOR_TEMPLATE = (
    "import %(modules)s\n"
    "_A=%(argv)s\n"
    "_R=%(ctl)d\n"
    "_W=%(st)d\n"
    "_G=%(grace)s\n"
    "def _say(t):\n"
    " try:\n"
    "  os.write(_W,t.encode())\n"
    " except OSError:\n"
    "  pass\n"
    "try:\n"
    " if ctypes.CDLL(None,use_errno=True).prctl(36,1,0,0,0)!=0:\n"
    "  raise OSError\n"
    " os.close(os.pidfd_open(os.getpid()))\n"
    " _p=subprocess.Popen(_A,stdin=0,stdout=1,stderr=2,close_fds=True)\n"
    "except BaseException:\n"
    " _say('E\\n')\n"
    " os._exit(97)\n"
    "_n=os.open(os.devnull,os.O_RDWR)\n"
    "for _f in (0,1,2):\n"
    " os.dup2(_n,_f)\n"
    "os.close(_n)\n"
    "_say('R'+str(_p.pid)+'\\n')\n"
    "_me=os.getpid()\n"
    "def _stat(pid):\n"
    " with open('/proc/'+str(pid)+'/stat','rb') as f:\n"
    "  s=f.read().rpartition(b')')[2].split()\n"
    " return s[0],int(s[1]),s[19]\n"
    "def _tree():\n"
    " kids={}\n"
    " unc=False\n"
    " try:\n"
    "  names=os.listdir('/proc')\n"
    " except OSError:\n"
    "  return [],True\n"
    " for n in names:\n"
    "  if n.isdigit():\n"
    "   try:\n"
    "    st,pp,sv=_stat(n)\n"
    "   except (FileNotFoundError,ProcessLookupError):\n"
    "    continue\n"
    "   except (OSError,ValueError,IndexError):\n"
    "    unc=True\n"
    "    continue\n"
    "   kids.setdefault(pp,[]).append((int(n),st,sv,pp))\n"
    " out=[]\n"
    " q=[_me]\n"
    " seen={_me}\n"
    " while q:\n"
    "  for e in kids.get(q.pop(),()):\n"
    "   if e[0] not in seen:\n"
    "    seen.add(e[0])\n"
    "    out.append(e)\n"
    "    q.append(e[0])\n"
    " return out,unc\n"
    "def _kill1(e):\n"
    " try:\n"
    "  fd=os.pidfd_open(e[0])\n"
    " except OSError:\n"
    "  return\n"
    " try:\n"
    "  if _stat(e[0])[2]==e[2]:\n"
    "   signal.pidfd_send_signal(fd,9)\n"
    " except (OSError,ValueError,IndexError):\n"
    "  pass\n"
    " finally:\n"
    "  os.close(fd)\n"
    "def _gone():\n"
    " while True:\n"
    "  _p.poll()\n"
    "  try:\n"
    "   r=os.waitid(os.P_ALL,0,os.WEXITED|os.WNOHANG|os.WNOWAIT)\n"
    "  except ChildProcessError:\n"
    "   return True\n"
    "  except OSError:\n"
    "   return False\n"
    "  if r is None or not r.si_pid:\n"
    "   return False\n"
    "  if r.si_pid!=_p.pid:\n"
    "   try:\n"
    "    os.waitpid(r.si_pid,os.WNOHANG)\n"
    "   except OSError:\n"
    "    return False\n"
    "def _empty():\n"
    " if not _gone():\n"
    "  return False\n"
    " time.sleep(0.01)\n"
    " return _gone()\n"
    "def _purge(limit):\n"
    " end=time.monotonic()+limit\n"
    " while True:\n"
    "  if _empty():\n"
    "   return 0,0\n"
    "  out,unc=_tree()\n"
    "  live=[e for e in out if e[1]!=b'Z']\n"
    "  for e in live:\n"
    "   _kill1(e)\n"
    "  if time.monotonic()>end:\n"
    "   return max(1,len(live)),int(unc)\n"
    "  time.sleep(0.02)\n"
    "_x=False\n"
    "while True:\n"
    " if not _x and _p.poll() is not None:\n"
    "  _x=True\n"
    "  _say('X'+str(_p.returncode)+'\\n')\n"
    " if select.select([_R],[],[],0.05)[0]:\n"
    "  c=os.read(_R,1)\n"
    "  if c==b'S':\n"
    "   if _empty():\n"
    "    _say('S0 0\\n')\n"
    "   else:\n"
    "    o,u=_tree()\n"
    "    _say('S'+str(max(1,len([e for e in o if e[1]!=b'Z'])))+' '+str(int(u))+'\\n')\n"
    "  elif c==b'K':\n"
    "   a,b=_purge(_G)\n"
    "   _say('K'+str(a)+' '+str(b)+'\\n')\n"
    "  else:\n"
    "   if c!=b'Q':\n"
    "    _purge(_G)\n"
    "   os._exit(0)\n")


def _proc_stat(pid: int) -> tuple[bytes, int, bytes] | None:
    """``(state, parent pid, start time)`` from ``/proc``; ``None`` when the process vanished; other errors propagate."""
    try:
        with open("/proc/%d/stat" % pid, "rb") as stream:
            fields = stream.read().rpartition(b")")[2].split()
    except (FileNotFoundError, ProcessLookupError):
        return None
    return fields[0], int(fields[1]), fields[19]


def _live_descendants(root: int) -> tuple[list[tuple[int, bytes]], bool]:
    """``(live descendants of root as (pid, start time), uncertain)`` read from ``/proc`` (zombies are not live).  A
    subreaper's adopted orphans are its children, so walking the parent/child relation from the supervisor finds the whole
    run.  Any unreadable entry or an unreadable ``/proc`` makes the answer ``uncertain``."""
    try:
        names = os.listdir("/proc")
    except OSError:
        return [], True
    kids: dict[int, list[tuple[int, bytes, bytes]]] = {}
    uncertain = False
    for name in names:
        if not name.isdigit():
            continue
        try:
            info = _proc_stat(int(name))
        except (OSError, ValueError, IndexError):
            uncertain = True
            continue
        if info is not None:
            kids.setdefault(info[1], []).append((int(name), info[0], info[2]))
    found, seen, queue = [], {root}, [root]
    while queue:
        for pid, state, start in kids.get(queue.pop(), ()):
            if pid not in seen:
                seen.add(pid)
                queue.append(pid)
                if state != b"Z":
                    found.append((pid, start))
    return found, uncertain


def _kill_pidfd(pid: int, start: bytes) -> None:
    """SIGKILL ``pid`` through a pidfd after re-reading its start time, so a recycled pid is never signalled."""
    try:
        descriptor = os.pidfd_open(pid)
    except OSError:
        return
    try:
        info = _proc_stat(pid)
        if info is not None and info[2] == start:
            signal.pidfd_send_signal(descriptor, signal.SIGKILL)
    except (OSError, ValueError, IndexError):
        pass
    finally:
        os.close(descriptor)


def _kill_descendants(root: int, budget: float) -> bool:
    """End every live descendant of ``root`` from THIS process, within ``budget``; ``True`` only after two consecutive
    certain scans found none.  This is how a run is settled when its supervisor cannot answer: the supervisor itself is ended
    only after this returned ``True``, so no descendant is ever left without an owner."""
    end, quiet = time.monotonic() + max(0.0, budget), 0
    while True:
        found, uncertain = _live_descendants(root)
        if found:
            quiet = 0
            for pid, start in found:
                _kill_pidfd(pid, start)
        elif uncertain:
            quiet = 0
        else:
            quiet += 1
            if quiet >= 2:
                return True
        if time.monotonic() >= end:
            return False
        time.sleep(0.02)


class _Containment:
    """Kill the verifier and every descendant, with membership owned before the verifier exists.

    Windows: the child is created suspended, assigned to a kill-on-close Job Object and only then resumed, so it never
    runs outside the job.  Linux: the launched process is a supervisor (``SUPERVISOR_TEMPLATE``) that becomes a child
    subreaper, spawns the verifier interpreter as its child and owns every descendant by kernel parenthood; it
    enumerates and kills exactly its own descendants on request and when the host disappears.  Any step that cannot
    be completed or inspected (``/proc`` unreadable, supervisor lost or silent, purge incomplete) is uncertainty and
    counts as a surviving process.  A same-user process that deliberately kills the supervisor ends the guarantee; that
    is observed (the supervisor must still answer when the run ends) and the run is then rejected as uncertain, never
    accepted.  This is containment for reviewed code, not a sandbox for hostile code.
    """

    def __init__(self, cwd: str | None = None, cleanup_end: float | None = None):
        self.job, self.cwd = None, cwd
        self.cleanup_end = cleanup_end   # the ONE monotonic cleanup deadline every step of this containment shares
        self._sup_identity: tuple[int, int] | None = None
        self._mute = False          # the supervisor failed to answer a request: it is not trusted to answer again
        self.tree_settled = False   # no descendant is left to own: the supervisor reported an empty tree, or this process ended them
        self._closed = False    # set by ``close``: a closed containment accepts no adoption and is never written again
        self._closing = False   # the status reader closes the status descriptor itself when it ends after ``close``
        self._fd_lock = threading.Lock()
        self.kind = "job_object" if sys.platform == "win32" else "subreaper"
        self._cond = threading.Condition()
        self._state: dict[str, Any] = {"ready": False, "error": False, "rc": None, "exited": False, "lost": False,
                                       "replies": {}, "child": None}
        self._fds: tuple[int, int] | None = None
        self._ctl_w: int | None = None
        self._st_r: int | None = None
        self._reader: threading.Thread | None = None
        self._sup_prefix: str | None = None
        self._clean: bool | None = None
        self._assigned = False
        if sys.platform == "win32":
            import ctypes
            from ctypes import wintypes as wt

            class IO(ctypes.Structure):
                _fields_ = [(n, ctypes.c_ulonglong) for n in ("a", "b", "c", "d", "e", "f")]

            class BASIC(ctypes.Structure):
                _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                            ("LimitFlags", wt.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                            ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wt.DWORD),
                            ("Affinity", ctypes.c_size_t), ("PriorityClass", wt.DWORD), ("SchedulingClass", wt.DWORD)]

            class EXTENDED(ctypes.Structure):
                _fields_ = [("Basic", BASIC), ("Io", IO), ("ProcessMemoryLimit", ctypes.c_size_t),
                            ("JobMemoryLimit", ctypes.c_size_t), ("PeakProcessMemoryUsed", ctypes.c_size_t),
                            ("PeakJobMemoryUsed", ctypes.c_size_t)]

            class ACCOUNTING(ctypes.Structure):
                _fields_ = [("a", ctypes.c_int64), ("b", ctypes.c_int64), ("c", ctypes.c_int64), ("d", ctypes.c_int64),
                            ("TotalPageFaultCount", wt.DWORD), ("TotalProcesses", wt.DWORD),
                            ("ActiveProcesses", wt.DWORD), ("TotalTerminatedProcesses", wt.DWORD)]

            self._ctypes, self._accounting = ctypes, ACCOUNTING
            self._k = k = ctypes.WinDLL("kernel32", use_last_error=True)
            k.CreateJobObjectW.restype = wt.HANDLE
            k.CreateJobObjectW.argtypes = [wt.LPVOID, wt.LPCWSTR]
            k.SetInformationJobObject.argtypes = [wt.HANDLE, ctypes.c_int, wt.LPVOID, wt.DWORD]
            k.QueryInformationJobObject.argtypes = [wt.HANDLE, ctypes.c_int, wt.LPVOID, wt.DWORD, wt.LPVOID]
            k.AssignProcessToJobObject.argtypes = [wt.HANDLE, wt.HANDLE]
            k.TerminateJobObject.argtypes = [wt.HANDLE, wt.UINT]
            k.CloseHandle.argtypes = [wt.HANDLE]
            self._nt = ctypes.WinDLL("ntdll")
            self._nt.NtResumeProcess.argtypes = [wt.HANDLE]
            self._nt.NtResumeProcess.restype = ctypes.c_long
            self._open_job(EXTENDED)
        elif sys.platform.startswith("linux"):
            answered, proc_present = _call_within(_Operation.remaining(CLEANUP_GRACE), os.path.isdir, "/proc")
            _require(answered and proc_present is True and hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"),
                     "process_containment_unavailable", "subreaper_prerequisites")
        else:
            _reject("process_containment_unavailable", "platform")

    def _open_job(self, extended) -> None:
        """Create the kill-on-close Job Object and OWN the handle from the moment it exists: any failure of the setup that
        follows closes exactly that handle (nothing is in the job yet) and the failure is raised, so the handle can never
        be left without an owner.  ``extended`` is the ``JOBOBJECT_EXTENDED_LIMIT_INFORMATION`` structure type."""
        k, ctypes = self._k, self._ctypes
        job = k.CreateJobObjectW(None, None)
        _require(bool(job), "process_containment_unavailable", "create_job")
        self.job = job
        try:
            info = extended()
            info.Basic.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            _require(bool(k.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info))),
                     "process_containment_unavailable", "limit_job")
        except BaseException:
            self.job = None
            try:
                k.CloseHandle(job)
            except Exception:   # noqa: BLE001 - the setup failure is what is reported
                pass
            raise

    def _slice(self, cap: float) -> float:
        return _cleanup_slice(getattr(self, "cleanup_end", None), cap)

    def adopt(self, attempt: "_LaunchAttempt") -> None:
        """Take over the resources of a launch attempt that finished inside its deadline (state ``adopted``): from here
        on this containment, and not the attempt's thread, owns and settles them.  A closed containment adopts nothing."""
        _require(not self._closed, "containment_closed", "adopt")
        self._fds = attempt.sup_fds
        self._ctl_w, self._st_r = attempt.ctl_w, attempt.st_r
        self._sup_prefix, self._sup_identity = attempt.prefix, attempt.prefix_identity

    def supervisor_cache_clean(self) -> bool:
        """The supervisor's private bytecode directory stayed empty (nothing executable was cached for it to load).

        The listing runs under the cleanup bound; a listing that blocks or fails is uncertainty, so not clean."""
        prefix = self._sup_prefix
        if prefix is None:
            return True
        finished, value = _call_within(self._slice(CLEANUP_GRACE), lambda: not os.listdir(prefix))
        return finished and value is True

    def remove_supervisor_prefix(self) -> bool:
        """Remove the supervisor's private bytecode directory, bound to the identity it was created with, inside the
        shared cleanup deadline; ``False`` when it is not verified gone (the directory stays owned in ``_ORPHANS``)."""
        prefix = self._sup_prefix
        if prefix is None:
            return True
        outcome = _remove_by_creation(prefix, self._slice(CLEANUP_GRACE), self._sup_identity)
        if outcome == "removed":
            self._sup_prefix = None
            return True
        if outcome != "replaced":
            _keep_orphan(prefix, self._sup_identity)   # also when the creation identity is unknown: uncertain, never removed by name
        return False

    def launched(self):
        """The host no longer needs the supervisor's ends of the two pipes."""
        if self._fds is not None:
            for fd in self._fds:
                try:
                    os.close(fd)
                except OSError:
                    pass
            self._fds = None

    def _on_line(self, line: bytes):
        text = line.decode("ascii", "replace")
        tag, rest = text[:1], text[1:]
        with self._cond:
            try:
                if tag == "R":
                    self._state["ready"], self._state["child"] = True, int(rest)
                elif tag == "E":
                    self._state["error"] = True
                elif tag == "X":
                    self._state["exited"], self._state["rc"] = True, int(rest)
                elif tag in ("S", "K"):
                    live, uncertain = rest.split()
                    self._state["replies"][tag] = (int(live), int(uncertain))
                else:
                    self._state["error"] = True
            except ValueError:
                self._state["error"] = True
            self._cond.notify_all()

    def _pump_status(self, fd: int):
        buffered = b""
        while True:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                chunk = b""
            if not chunk:
                break
            buffered += chunk
            if len(buffered) > 4096 and b"\n" not in buffered:
                self._on_line(b"?")
                break
            while b"\n" in buffered:
                line, _, buffered = buffered.partition(b"\n")
                self._on_line(line)
        with self._cond:
            self._state["lost"] = True
            self._cond.notify_all()
        if self._closing:   # ``close`` left the descriptor to this reader because it was still blocked on it
            self._close_status()

    def _close_status(self) -> None:
        """Close the status descriptor exactly once, by whichever of ``close`` and the finished reader gets here first."""
        with self._fd_lock:
            fd, self._st_r = self._st_r, None
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass

    def _wait(self, predicate, limit: float) -> bool:
        end = time.monotonic() + max(0.0, limit)
        with self._cond:
            while not predicate(self._state):
                left = end - time.monotonic()
                if left <= 0:
                    return False
                self._cond.wait(min(left, 0.25))
        return True

    def _ask(self, tag: str, limit: float):
        """One request/reply with the supervisor; ``None`` means no answer (lost, silent or unwritable)."""
        if self._ctl_w is None:
            return None
        with self._cond:
            self._state["replies"].pop(tag, None)
        try:
            os.write(self._ctl_w, tag.encode("ascii"))
        except OSError:
            return None
        self._wait(lambda s: tag in s["replies"] or s["lost"], limit)
        with self._cond:
            return self._state["replies"].get(tag)

    def attach(self, process: subprocess.Popen, limit: float = 10.0):
        """Fail closed.  Windows: assign the suspended child to the job, then resume it.  Linux: wait until the
        subreaper supervisor reports that it is armed and has started the verifier interpreter.  The request frame is
        only written after this returns, so no verifier byte is delivered to anything that is not yet contained."""
        if self.job is not None:
            _require(bool(self._k.AssignProcessToJobObject(self.job, int(process._handle))),
                     "containment_attach_failed", "assign_job")
            self._assigned = True
            _require(self._nt.NtResumeProcess(int(process._handle)) >= 0, "containment_attach_failed", "resume")
            return
        self.launched()
        self._reader = threading.Thread(target=self._pump_status, args=(self._st_r,), daemon=True)
        self._reader.start()
        self._wait(lambda s: s["ready"] or s["error"] or s["lost"], limit)
        with self._cond:
            armed = self._state["ready"] and not self._state["error"]
        _require(armed, "containment_attach_failed", "subreaper")

    def wait_exit(self, process: subprocess.Popen) -> tuple[bool, int | None]:
        """``(exited, exit code)`` of the verifier interpreter (Windows: the process itself)."""
        if self.job is not None or self._st_r is None:
            code = process.poll()
            return code is not None, code
        with self._cond:
            return self._state["exited"], self._state["rc"]

    def survivors(self, process: subprocess.Popen) -> bool:
        if self.job is not None:
            info = self._accounting()
            ok = self._k.QueryInformationJobObject(self.job, 1, self._ctypes.byref(info), self._ctypes.sizeof(info), None)
            return (not ok) or info.ActiveProcesses > 0
        reply = self._ask("S", self._slice(5.0))   # inside the shared cleanup deadline like every other protocol wait
        return reply is None or reply[0] > 0 or bool(reply[1])

    def reap(self, process: subprocess.Popen, grace: float) -> bool:
        """Kill the whole run and confirm, within ``grace`` seconds and never past the shared cleanup deadline, that the
        child is reaped and nothing survives."""
        grace = self._slice(grace)
        end = time.monotonic() + grace
        if self.job is None:
            if self._clean is True:   # only a confirmed outcome is final; a failed one can be retried
                return True
            reply = None
            if not self._mute:   # a supervisor that did not answer once is not asked again: its tree is ended from here
                reply = self._ask("K", min(max(0.0, end - time.monotonic()), SUPERVISOR_PURGE + 2.0))
                self._mute = reply is None
            if reply is not None and reply != (0, 0):
                # the supervisor answered that processes live or are uncertain: it stays alive and owned (it is the only
                # thing that can still find them), so a later retry of this method can ask again
                return False
            if reply is None and not _kill_descendants(process.pid, max(0.0, end - time.monotonic())):
                # it cannot answer: its descendants are ended from here, and only when that is CONFIRMED may it be ended
                # itself; otherwise it stays alive and owned for a later retry
                return False
            self.tree_settled = True
            clean = reply == (0, 0)
            if self._ctl_w is not None:
                try:
                    os.write(self._ctl_w, b"Q")
                except OSError:
                    clean = False
            try:
                process.wait(timeout=max(0.0, end - time.monotonic()))
            except subprocess.TimeoutExpired:
                clean = False
                try:
                    process.kill()
                except OSError:
                    pass
            if clean and process.returncode == 0:
                self._clean = True
            return clean and process.returncode == 0
        while True:
            self._k.TerminateJobObject(self.job, 1)
            if not self._assigned:   # a suspended child that never joined the job is not reached by TerminateJobObject
                try:
                    process.kill()
                except OSError:
                    pass
            try:
                process.wait(timeout=0.05)
            except subprocess.TimeoutExpired:
                pass
            if process.poll() is not None and not self.survivors(process):
                return True
            if time.monotonic() >= end:
                return False
            time.sleep(0.02)

    def close(self, process: subprocess.Popen | None = None):
        """Release what this containment owns, once.  A status descriptor whose reader is still blocked on it is not closed
        under the reader: the reader closes it itself when it ends (``_pump_status``), so it is released, never abandoned."""
        if self._closed:
            return True
        if self.job is None and process is not None and process.poll() is None and not self.tree_settled:
            return False   # the supervisor is the only owner of a live tree: it is never abandoned by a close
        self._closed = True
        self._closing = True
        if self.job is not None:
            if process is not None and not self._assigned and process.poll() is None:
                try:
                    process.kill()
                except OSError:
                    pass
            self._k.TerminateJobObject(self.job, 1)
            self._k.CloseHandle(self.job)
            self.job = None
            return True
        self.launched()
        prefix, self._sup_prefix = self._sup_prefix, None
        if prefix is not None:
            if _remove_by_creation(prefix, self._slice(CLEANUP_GRACE), self._sup_identity) not in ("removed", "replaced"):
                _keep_orphan(prefix, self._sup_identity)
        if process is not None and process.poll() is None:
            try:
                process.kill()
            except OSError:
                pass
        reader = self._reader
        if reader is not None:
            reader.join(timeout=self._slice(1.0))
        if self._ctl_w is not None:
            try:
                os.close(self._ctl_w)
            except OSError:
                pass
            self._ctl_w = None
        if reader is None or not reader.is_alive():
            self._close_status()
        return True


_ENV_KEYS = ("SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "TEMP", "TMP")


def _child_env() -> dict[str, str]:
    env = {k: os.environ[k] for k in _ENV_KEYS if k in os.environ}
    if sys.platform != "win32":
        env.update({"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"})
    return env


def _command_units(command: Sequence[str]) -> int:
    """UTF-16 code units of the Windows command line this argument vector would produce."""
    return len(subprocess.list2cmdline(list(command)).encode("utf-16-le", "surrogatepass")) // 2


def _interpreter_command(python: str, prefix: str, bootstrap_sha256: str) -> list[str]:
    """The bounded launch command: interpreter flags plus the fixed ASCII stub, never the bootstrap itself."""
    _require(SHA.match(bootstrap_sha256) is not None, "bootstrap_digest_invalid")
    stub = STUB_TEMPLATE % {"limit": MAX_BOOTSTRAP_BYTES, "digest": bootstrap_sha256}
    command = [python, *INTERPRETER_FLAGS, "-X", "pycache_prefix=" + prefix, "-c", stub]
    _require(_command_units(command) <= MAX_COMMAND_UNITS, "execution_command_too_long", str(_command_units(command)))
    return command


def _bootstrap_stream(bootstrap: bytes, payload: bytes) -> bytes:
    """What the stub reads from stdin: length-prefixed bootstrap bytes, then the request frame or probe magic."""
    _require(0 < len(bootstrap) <= MAX_BOOTSTRAP_BYTES, "bootstrap_size_invalid", str(len(bootstrap)))
    return len(bootstrap).to_bytes(8, "big") + bootstrap + payload


def _fresh_dirs(work: str) -> tuple[str, str]:
    """The child's private bytecode and working directories, created through the run's scratch ledger.  Inside a caller
    supplied ``work`` they stay in place (the caller owns that directory) unless the creation turns out to be late."""
    operation = _Operation.current()
    remove = operation is None or operation.scratch.holds(work)
    prefix = _scratch_mkdtemp("pvc-bytecode-", work, remove)
    cwd = _scratch_mkdtemp("pvc-cwd-", work, remove)
    return prefix, cwd


@dataclass
class Execution:
    returncode: int | None = None
    stdout: bytes = b""
    stderr_sha256: str = _sha(b"")
    stderr_bytes: int = 0
    timed_out: bool = False
    overflow: str | None = None
    descendants: bool = False
    cleanup_failed: bool = False
    launch_error: str | None = None
    containment: str | None = None


def validate_timeout(timeout: Any) -> float:
    """The one supported timeout contract: a real finite number, ``0 < timeout <= MAX_TIMEOUT`` seconds.

    Total: any int or float yields either the validated float or ``ClosureRejected`` (never ``OverflowError``).
    """
    _require(isinstance(timeout, (int, float)) and not isinstance(timeout, bool), "invalid_arguments", "timeout_type")
    try:
        value = float(timeout)
    except (OverflowError, ValueError):
        _reject("invalid_arguments", "timeout_out_of_range")
    _require(math.isfinite(value), "invalid_arguments", "timeout_not_finite")
    _require(0 < value <= MAX_TIMEOUT, "invalid_arguments", "timeout_out_of_range")
    return value


def timeout_ms(timeout: float) -> int:
    """Recorded timeout: the validated seconds rounded UP to whole milliseconds, so a positive timeout is never 0."""
    return max(1, math.ceil(round(validate_timeout(timeout) * 1000, 6)))


def _call_within(budget: float, function, *args) -> tuple[bool, Any]:
    """``(True, value)`` when ``function`` finished within ``budget`` seconds without raising, else ``(False, None)``.

    Used for cleanup-phase inspections that must answer even when the deadline of the run already expired: the caller
    regains control after ``budget`` regardless of a stuck system call, and the abandoned helper only reads."""
    box: dict[str, Any] = {}
    finished = threading.Event()

    def worker():
        try:
            box["value"] = function(*args)
        except BaseException:   # noqa: BLE001 - any failure is "not confirmed"
            pass
        finally:
            finished.set()

    threading.Thread(target=worker, daemon=True, name="pvc-within").start()
    if finished.wait(max(0.0, budget)) and "value" in box:
        return True, box["value"]
    return False, None


class _LaunchAttempt:
    """One process-creation attempt and EVERYTHING it may create, owned by the attempt, never by the caller.

    ``mkdtemp``, ``os.pipe`` and ``Popen`` cannot be cancelled once they block.  The attempt's thread therefore records
    each resource here, in the same step that creates it, and the attempt's state moves exactly once, under ``_lock``,
    from ``running`` to ``adopted`` (the caller took the live process and resources: ``_Containment.adopt``), ``failed``
    (creation raised) or ``abandoned`` (the caller's deadline passed first).  After ``abandoned`` or ``failed`` the thread
    creates nothing more and settles what exists: the late child is killed (the supervisor is asked first), waited for and
    reaped, its pipes and streams are closed, and the supervisor directory is removed bound to the identity it was
    created with.  ``settled`` is set when the first release finished.  Cleanup is a retryable, idempotent step
    (``_settle_once``): when it could not finish (a child that will not die yet, a directory that will not go) the attempt
    registers itself in the owned registry (``_own``) and ``settle``, ``settle_orphans`` and the janitor retry it until
    ``released``; ``clean`` is the TRUTH (released, and on Linux the supervisor confirmed an empty tree).  Nothing is
    parked in a list that no consumer reads.  The caller's ``_Containment`` is never read or written by this thread, so a
    closed containment can never be reused by a late effect."""

    def __init__(self, argv: Sequence[str], cwd: str, *, windows: bool):
        self.argv, self.cwd, self.windows = list(argv), cwd, windows
        self._lock = threading.Lock()
        self._settle_lock = threading.Lock()
        self._token: int | None = None
        self._attempts = 0
        self._reaped = False
        self._streams_closed = False
        self._tree: bool | None = None   # the supervisor's answer: True empty, False live/uncertain, None no answer
        self._tree_settled = False       # no descendant is left to own (confirmed by the supervisor or ended from here)
        self._mute = False               # the supervisor failed to answer a request: it is not trusted to answer again
        self.released = False
        self.state = "running"
        self.process: subprocess.Popen | None = None
        self.error: str | None = None
        self.sup_fds: tuple[int, int] | None = None   # supervisor ends: (request read, status write)
        self.ctl_w: int | None = None
        self.st_r: int | None = None
        self.prefix: str | None = None
        self.prefix_identity: tuple[int, int] | None = None
        self._fds: list[int] = []
        self.created = threading.Event()
        self.settled = threading.Event()
        self.clean = True

    def start(self) -> None:
        threading.Thread(target=self._run, daemon=True, name="pvc-launch").start()

    def settle(self, budget: float) -> bool:
        """``True`` only when an unadopted attempt released everything it owned within ``budget`` seconds AND the outcome
        is clean.  A release that has not finished is retried here, inside the same budget, not merely waited for."""
        end = time.monotonic() + max(0.0, budget)
        if not self.settled.wait(max(0.0, end - time.monotonic())):
            return False
        if not self.released:
            self._retry(max(0.0, end - time.monotonic()))
        return self.released and self.clean

    def _live(self) -> bool:
        with self._lock:
            return self.state == "running"

    def _run(self) -> None:
        try:
            self._create()
        except BaseException as exc:   # noqa: BLE001 - any creation failure is a launch failure
            self.error = type(exc).__name__
        with self._lock:
            if self.state == "running":
                if self.error is None and self.process is not None:
                    self.created.set()
                    return
                self.state = "failed"
        self._release()
        self.created.set()
        self.settled.set()

    def _create(self) -> None:
        command, kwargs = list(self.argv), {}
        if self.windows:
            # new process group, no console window, CREATE_SUSPENDED: no instruction runs before the job assignment
            kwargs = {"creationflags": 0x00000200 | 0x08000000 | 0x00000004}
        else:
            if not self._live():
                return
            request_read, request_write = os.pipe()          # host -> supervisor requests
            self._fds += [request_read, request_write]
            os.set_blocking(request_write, False)            # a request write can never block a caller past its deadline
            if not self._live():                             # cancellation is checked before EVERY new effect, not only the first
                return
            status_read, status_write = os.pipe()            # supervisor -> host replies
            self._fds += [status_read, status_write]
            self.ctl_w, self.st_r, self.sup_fds = request_write, status_read, (request_read, status_write)
            if not self._live():
                return
            self.prefix = tempfile.mkdtemp(prefix="pvc-supervisor-bytecode-")
            self.prefix_identity, absent = _creation_identity(self.prefix)
            if absent:   # confirmed gone right after its creation: there is nothing to own and nothing safe to launch with
                self.prefix = None
                raise OSError("the supervisor bytecode directory vanished after it was created")
            # an identity that could not be established stays None: the directory is then UNCERTAIN (owned, never removed by
            # name, a cleanup failure until it is confirmed absent) - a later occupant of the pathname is not ours
            program = SUPERVISOR_TEMPLATE % {"modules": ",".join(SUPERVISOR_MODULES), "argv": repr(self.argv),
                                             "ctl": request_read, "st": status_write, "grace": repr(SUPERVISOR_PURGE)}
            command = [self.argv[0], *INTERPRETER_FLAGS, "-X", "pycache_prefix=" + self.prefix, "-c", program]
            kwargs = {"start_new_session": True, "pass_fds": self.sup_fds}
        if not self._live():
            return
        self.process = subprocess.Popen(command, cwd=self.cwd, env=_child_env(), stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0, **kwargs)

    def _late_supervisor_kill(self, budget: float) -> bool | None:
        """Ask the late supervisor to kill and reap its descendants.  ``True``: an inspected, empty tree.  ``False``: the
        supervisor answered that processes live or are uncertain.  ``None``: no answer (unwritable, lost, silent)."""
        import select
        if self.ctl_w is None or self.st_r is None:
            return None
        try:
            os.write(self.ctl_w, b"K")
        except OSError:
            return None
        end, buffered = time.monotonic() + max(0.0, budget), b""
        while time.monotonic() < end:
            try:
                ready, _, _ = select.select([self.st_r], [], [], min(0.25, max(0.0, end - time.monotonic())))
                if not ready:
                    continue
                chunk = os.read(self.st_r, 4096)
            except (OSError, ValueError):
                return None
            if not chunk:
                return None
            buffered += chunk
            for line in buffered.split(b"\n")[:-1]:
                if line.startswith(b"K"):   # reply "K<live> <uncertain>": clean only when nothing lives and nothing is uncertain
                    return line[1:].split() == [b"0", b"0"]
            buffered = buffered[buffered.rfind(b"\n") + 1:]
        return None

    def _reap_late_child(self, process: subprocess.Popen, budget: float) -> bool:
        """Terminate, wait for and reap the late child within ``budget``; ``True`` only when it is gone.  Linux: the
        supervisor is asked first.  An answer that processes still live keeps the supervisor alive and owned (it is the only
        thing that can still find them) for as long as it takes: it is NEVER ended while any descendant is unconfirmed.  A
        supervisor that cannot answer is not abandoned either: its descendants are ended from here, and it is ended only
        after that is confirmed."""
        end = time.monotonic() + max(0.0, budget)
        if not self.windows and process.poll() is None:
            if not self._tree_settled:
                answer = None
                if not self._mute:
                    answer = self._late_supervisor_kill(min(max(0.0, end - time.monotonic()), SUPERVISOR_PURGE + 2.0))
                    self._mute = answer is None
                if answer is False:
                    return False
                if answer is None and not _kill_descendants(process.pid, max(0.0, end - time.monotonic())):
                    return False
                self._tree = answer   # True: the supervisor confirmed an empty tree; None: this process did (still a failure)
                self._tree_settled = True
            if self.ctl_w is not None:
                try:
                    os.write(self.ctl_w, b"Q")
                except OSError:
                    pass
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                pass
        if process.poll() is None:
            try:
                process.kill()
            except OSError:
                pass
        try:
            process.wait(timeout=max(0.0, end - time.monotonic()))
        except subprocess.TimeoutExpired:
            return False
        return True

    def _settle_once(self, budget: float) -> bool:
        """Idempotent release of everything this attempt still owns, inside ONE ``budget``; ``True`` when nothing is left.

        The supervisor's pipes stay open until the child is gone (the kill protocol needs them); the streams are closed only
        once it is reaped; the directory is removed bound to its creation identity.  A step that cannot finish is simply
        repeated by the next call.  The lock is taken inside the same budget: a call that cannot get it (another settlement
        is in progress) reports "not settled" and starts nothing, so there is never a second cleanup worker for the record."""
        end = time.monotonic() + max(0.0, budget)
        if not self._settle_lock.acquire(timeout=max(0.0, budget)):
            return False
        try:
            self._attempts += 1
            process = self.process
            if process is not None and not self._reaped:
                self._reaped = self._reap_late_child(process, max(0.0, end - time.monotonic()))
                if self._reaped:
                    _record_late("child", str(process.pid), "reaped")
            gone = process is None or self._reaped
            if gone:
                for fd in self._fds:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                self._fds = []
                if process is not None and not self._streams_closed:
                    for stream in (process.stdin, process.stdout, process.stderr):
                        try:
                            stream.close()
                        except (OSError, ValueError, AttributeError):
                            pass
                    self._streams_closed = True
            if self.prefix is not None:
                outcome = _remove_by_creation(self.prefix, max(0.0, end - time.monotonic()), self.prefix_identity)
                if outcome in ("removed", "replaced"):
                    _record_late("supervisor_dir", self.prefix, outcome)
                    self.prefix = None
            return gone and self.prefix is None
        finally:
            self._settle_lock.release()

    def _finish(self, released: bool) -> None:
        self.released = released
        self.clean = released and (self.windows or self.process is None or self._tree is True)
        if released and self._token is not None:
            _disown(self._token)
            self._token = None

    def _retry(self, budget: float) -> bool:
        """One more settlement attempt (the registered settler): ``True`` when the attempt has now released everything."""
        if self.released:
            return True
        self._finish(self._settle_once(budget))
        return self.released

    def _release(self) -> None:
        self._finish(self._settle_once(CLEANUP_GRACE))
        if not self.released:
            # durable ownership: retried (by whoever settles, with that caller's budget or the janitor's own allowance)
            self._token = _own("launch", self._retry)


def _bounded_launch(attempt: _LaunchAttempt, deadline: float):
    """Run the blocking process creation of ``attempt`` bounded by ``deadline``.

    Returns ``(process, None)`` (the attempt is then ``adopted`` and the caller owns every resource) or
    ``(None, reason)``.  The creation itself cannot be cancelled; an attempt the deadline passed is marked ``abandoned``
    in the same locked step that decides it, so the attempt's own thread creates nothing further and settles whatever
    it still creates (see ``_LaunchAttempt``).  ``reason`` never claims the late effects are gone: ``attempt.settle``
    reports that."""
    attempt.start()
    attempt.created.wait(max(0.0, deadline - time.monotonic()))
    with attempt._lock:
        if attempt.state == "running":
            if attempt.created.is_set():
                attempt.state = "adopted"
                return attempt.process, None
            attempt.state = "abandoned"
    return None, ("child_launch_failed" if attempt.created.is_set() else "child_launch_timeout")


def _build_containment(cwd: str | None, cleanup_end: float | None, end: float) -> "_Containment | None":
    """Construct a containment as a bounded step with ownership of its late effect: ``None`` when it did not finish by
    ``end``, in which case the helper closes whatever it builds afterwards (a Windows job handle is released, never left
    without an owner).  A construction failure is raised exactly as the constructor raised it."""
    lock, finished, box = threading.Lock(), threading.Event(), {"state": "running"}
    operation = _Operation.current()

    def worker():
        _Operation._local.current = operation
        try:
            built = ("done", _Containment(cwd, cleanup_end))
        except BaseException as exc:   # noqa: BLE001 - handed to the caller
            built = ("error", exc)
        with lock:
            if box["state"] == "abandoned":
                if built[0] == "done":
                    built[1].close(None)
                return
            box["built"], box["state"] = built, "delivered"
        finished.set()

    threading.Thread(target=worker, daemon=True, name="pvc-containment").start()
    if not finished.wait(max(0.0, end - time.monotonic())):
        with lock:
            if box["state"] != "delivered":
                box["state"] = "abandoned"
                return None
    kind, value = box["built"]
    if kind == "error":
        raise value
    return value


class _ExecutionOwner:
    """Owns one live execution (process, containment, pump threads, pipe streams) until EVERY part is released.

    ``settle`` is idempotent and retryable: it asks the containment to reap (the Linux supervisor stays alive and owned while
    it answers that processes live, however long that takes), closes the containment only once the process is gone (a
    Windows job is always closed: closing it kills what is in it),
    joins the pump threads and closes the pipe streams only after those threads ended, so a stream is never closed under a
    thread and never left without a consumer that will close it.  ``_execute`` calls it once with the shared cleanup slice;
    if that does not finish, the same method is registered in the owned registry and retried."""

    def __init__(self, contain: "_Containment", process: subprocess.Popen, threads: list, stop: threading.Event):
        self.contain, self.process, self.threads, self.stop = contain, process, threads, stop
        self._lock = threading.Lock()
        self._attempts = 0
        self._streams_closed = False
        self._contain_closed = False
        self.released = False

    def settle(self, budget: float) -> bool:
        """One settlement attempt inside ONE ``budget`` (lock acquisition included: a call that cannot get the lock reports
        "not settled" and starts nothing).  The supervisor of a live tree is never ended here: if it keeps answering that
        processes live it stays alive and owned and the attempt simply reports "not settled" (the registry retries it); if
        it cannot answer, ``Containment.reap`` ends the descendants from this process first.  The one release that is not
        gated on a confirmed tree is a supervisor that already died by itself: its adopted descendants were re-parented by
        the kernel and no owner remains that could enumerate them (an operating-system fact, reported as ``cleanup_failed``)."""
        if not self._lock.acquire(timeout=max(0.0, budget)):
            return False
        try:
            if self.released:
                return True
            self._attempts += 1
            contain, process = self.contain, self.process
            end = time.monotonic() + max(0.0, budget)
            self.stop.set()
            if contain.job is not None or process.poll() is None:
                contain.reap(process, max(0.0, end - time.monotonic()))
            gone = process.poll() is not None
            if (gone or contain.job is not None) and not self._contain_closed:
                self._contain_closed = bool(contain.close(process))
            for thread in self.threads:
                thread.join(timeout=max(0.0, end - time.monotonic()))
            alive = any(thread.is_alive() for thread in self.threads)
            if gone and not alive and not self._streams_closed:
                for stream in (process.stdin, process.stdout, process.stderr):
                    try:
                        stream.close()
                    except (OSError, ValueError, AttributeError):
                        pass
                self._streams_closed = True
            self.released = gone and not alive and self._streams_closed
            return self.released
        finally:
            self._lock.release()

    def retry(self, budget: float) -> bool:
        """The registered settler.  It runs after the run's shared cleanup deadline, so the containment is released from that
        deadline, but it spends ONLY the budget it is given: the caller's own for ``settle_orphans``, the janitor's own
        allowance for the background pass.  No floor is added here."""
        self.contain.cleanup_end = None
        return self.settle(budget)


def _execute(argv: Sequence[str], cwd: str, stdin_bytes: bytes, timeout: float, max_stdout: int, max_stderr: int,
             deadline: float | None = None) -> Execution:
    """Run one child with bounded output, a hard deadline and verified descendant cleanup.

    The deadline (``deadline`` if given, else now + ``timeout``) covers launch and containment; it is checked before
    any stdin byte is delivered and again when the child's exit is observed, so a child that finishes late is a
    timeout rather than a result.  The pipes are raw (unbuffered): nothing here can block in a buffered ``close()``,
    and a descriptor a thread may still be blocked on is never closed (it is parked instead).
    """
    deadline = time.monotonic() + validate_timeout(timeout) if deadline is None else deadline
    operation = _Operation.current()
    cleanup_end = deadline + CLEANUP_GRACE
    if operation is not None:
        cleanup_end = min(cleanup_end, operation.cleanup_end)
    contain = _build_containment(cwd, cleanup_end, max(deadline, time.monotonic() + FINALIZE_FLOOR))
    if contain is None:   # construction did not finish in time; the helper closes whatever it builds late
        return Execution(containment="job_object" if sys.platform == "win32" else "subreaper",
                         launch_error="containment_build_timeout", cleanup_failed=True)
    result = Execution(containment=contain.kind)
    process = None
    threads: list[threading.Thread] = []
    stop = threading.Event()
    try:
        attempt = _LaunchAttempt(argv, cwd, windows=contain.job is not None)
        process, failure = _bounded_launch(attempt, deadline)
        if process is None:
            result.launch_error = failure
            # an abandoned or failed attempt settles its own late effects; the verdict is only as clean as that is confirmed
            result.cleanup_failed = not attempt.settle(_cleanup_slice(cleanup_end, CLEANUP_GRACE))
            return result
        contain.adopt(attempt)
        try:
            contain.attach(process, max(0.1, min(CONTAIN_START, deadline - time.monotonic())))
        except ClosureRejected:
            result.launch_error = "containment_attach_failed"
            result.cleanup_failed = not contain.reap(process, CLEANUP_GRACE)
            return result
        if time.monotonic() >= deadline:
            result.timed_out = True
            result.cleanup_failed = not contain.reap(process, CLEANUP_GRACE)
            return result
        out, err_hash, err_total = bytearray(), hashlib.sha256(), [0]

        def pump_out():
            fd = process.stdout.fileno()
            while True:
                try:
                    chunk = os.read(fd, 1 << 16)
                except OSError:
                    break
                if not chunk:
                    break
                if len(out) + len(chunk) > max_stdout:
                    result.overflow = "stdout"
                    stop.set()
                    break
                out.extend(chunk)

        def pump_err():
            fd = process.stderr.fileno()
            while True:
                try:
                    chunk = os.read(fd, 1 << 16)
                except OSError:
                    break
                if not chunk:
                    break
                err_total[0] += len(chunk)
                err_hash.update(chunk)
                if err_total[0] > max_stderr:
                    result.overflow = "stderr"
                    stop.set()
                    break

        def feed():
            fd = process.stdin.fileno()
            view = memoryview(stdin_bytes)
            try:
                while view and not stop.is_set():
                    view = view[os.write(fd, view):]
            except (OSError, ValueError):
                pass
            try:
                process.stdin.close()   # raw descriptor: a plain close(2), cannot flush or block
            except (OSError, ValueError):
                pass

        threads = [threading.Thread(target=target, daemon=True) for target in (pump_out, pump_err, feed)]
        for thread in threads:
            thread.start()
        supervisor_lost = False
        while True:
            exited, code = contain.wait_exit(process)
            if exited:
                break
            if contain.job is None and process.poll() is not None:
                supervisor_lost = True
                break
            if stop.is_set():
                break
            if time.monotonic() >= deadline:
                result.timed_out = True
                break
            time.sleep(0.01)
        exited, code = contain.wait_exit(process)
        if exited and time.monotonic() >= deadline:
            result.timed_out = True
        if supervisor_lost:
            result.descendants = True
        elif exited and not result.timed_out and not stop.is_set():
            result.descendants = contain.survivors(process)
        result.cleanup_failed = (not contain.reap(process, CLEANUP_GRACE) or supervisor_lost
                                 or not contain.supervisor_cache_clean() or not contain.remove_supervisor_prefix())
        stop.set()
        join_end = time.monotonic() + _cleanup_slice(cleanup_end, CLEANUP_GRACE)
        for thread in threads:
            thread.join(timeout=max(0.0, join_end - time.monotonic()))
        if any(thread.is_alive() for thread in threads):
            result.cleanup_failed = True
        result.returncode = code if exited else (process.returncode if contain.job is not None else None)
        result.stdout, result.stderr_bytes, result.stderr_sha256 = bytes(out), err_total[0], err_hash.hexdigest()
        return result
    finally:
        if process is None:
            contain.close(None)
        else:
            owner = _ExecutionOwner(contain, process, threads, stop)
            if not owner.settle(_cleanup_slice(cleanup_end, CLEANUP_GRACE)):
                result.cleanup_failed = True   # the prompt outcome is a failure ...
                _own("execution", owner.retry)   # ... and the release is still owed: retried until the parts are gone


# --------------------------------------------------------------------------- implementation and release

def _capture_state() -> dict[str, bytes] | None:
    capture = _LAUNCHER_CAPTURE
    if capture is None:
        return None
    expected = {"trace_gc/" + name for name in IMPLEMENTATION_FILES}
    _require(isinstance(capture, dict) and set(capture) == expected
             and all(type(value) is bytes and 0 < len(value) <= MAX_MODULE_BYTES for value in capture.values()),
             "implementation_capture_invalid")
    return capture


def implementation_source() -> str:
    """``launcher_capture``: the rows are the bytes the reviewed launcher hashed and executed.  ``disk_reread``: the
    rows were read from disk by code of unknown provenance; recorded, and refused by acceptance."""
    return "launcher_capture" if _capture_state() is not None else "disk_reread"


def implementation_files() -> dict[str, bytes]:
    """The implementation bytes the release record binds: the launcher's capture when present, else one disk read.
    Callers hash and execute (send to the child) exactly the returned bytes."""
    captured = _capture_state()
    if captured is not None:
        return dict(captured)
    files = {}
    for name in IMPLEMENTATION_FILES:
        try:
            files["trace_gc/" + name] = (PACKAGE_DIR / name).read_bytes()
        except OSError:
            _reject("implementation_unreadable", name)
    return files


def release_record(manifest: Mapping[str, Any], files: Mapping[str, bytes] | None = None) -> dict[str, Any]:
    """The exact record whose digest a reviewer supplies out of band as the release digest."""
    files = files if files is not None else implementation_files()
    manifest = validate_manifest(dict(manifest))
    return {"version": RELEASE_VERSION,
            "implementation": [{"path": path, "sha256": _sha(data), "bytes": len(data)} for path, data in sorted(files.items())],
            "contract": CONTRACT, "runtime": manifest["runtime"], "manifest_sha256": canonical_digest(manifest)}


def release_digest(manifest: Mapping[str, Any], files: Mapping[str, bytes] | None = None) -> str:
    return canonical_digest(release_record(manifest, files))


# --------------------------------------------------------------------------- runtime

def _digest_rows(rows: Sequence[Sequence[Any]]) -> str:
    return canonical_digest({"entries": [list(row) for row in rows]})


def _launch_arguments(python: str, prefix: str, program: bytes, payload: bytes) -> tuple[list[str], bytes]:
    """``(command, stdin stream)`` of one interpreter launch: hashes the bootstrap and builds the length-prefixed stream.
    Data-dependent work, so callers run it as a bounded phase."""
    return _interpreter_command(python, prefix, _sha(program)), _bootstrap_stream(program, payload)


def _parse_probe(stdout: bytes, program: bytes) -> dict[str, Any]:
    """Strictly parse the probe's one JSON document and bind it to the bootstrap that produced it (a bounded phase)."""
    try:
        probe = canonical_loads(stdout.decode("ascii"))
    except (ContractError, UnicodeError):
        _reject("runtime_probe_failed")
    _require(isinstance(probe, dict) and probe.get("protocol") == PROTOCOL, "runtime_probe_failed", "shape")
    _require(probe.get("bootstrap_sha256") == _sha(program), "runtime_probe_failed", "bootstrap_binding")
    return probe


def probe_runtime(python: str | os.PathLike, work: str | None = None, bootstrap: bytes | None = None) -> dict[str, Any]:
    """Run only interpreter built-ins plus the bootstrap's probe mode in the exact isolated mode used for verification."""
    python = os.path.abspath(os.fspath(python))
    program = bootstrap if bootstrap is not None else _Operation.bounded(
        "implementation", implementation_files)["trace_gc/verifier_closure_bootstrap.py"]
    own = work is None
    work = work or tempfile.mkdtemp(prefix="pvc-probe-")
    identity = _identity(os.lstat(work)) if own else None
    removed = True
    try:
        prefix, cwd = _Operation.bounded("probe_dirs", _fresh_dirs, work)
        command, stream = _Operation.bounded("probe_command", _launch_arguments, python, prefix, program, PROBE_MAGIC)
        done = _execute(command, cwd, stream, _Operation.remaining(PROBE_TIMEOUT), MAX_REPORT_BYTES, 1 << 20)
    finally:
        if own:
            removed = _bounded_rmtree(work, _Operation.cleanup_left(), identity)
    _require(removed, "containment_cleanup_failed", "probe_work")
    _require(not done.cleanup_failed, "containment_cleanup_failed", "probe")
    _Operation.tick("probe")
    _require(done.launch_error is None and done.returncode == 0 and not done.timed_out and not done.overflow
             and not done.descendants, "runtime_probe_failed")
    probe = _Operation.bounded("probe_parse", _parse_probe, done.stdout, program)
    _require(isinstance(probe.get("native_mappings"), list), "native_inventory_unavailable", "probe")
    _require(probe.get("supervisor_modules") == list(SUPERVISOR_MODULES), "runtime_probe_failed", "supervisor_modules")
    flags = probe["flags"]
    _require(probe["platform"] in ("win32", "linux"), "unsupported_runtime", "platform " + str(probe["platform"])[:20])
    _require(probe["implementation"] == "cpython" and tuple(int(x) for x in probe["version"].split(".")[:2]) >= (3, 11),
             "unsupported_runtime", probe["implementation"] + " " + probe["version"])
    _require(flags["isolated"] and flags["no_site"] and flags["dont_write_bytecode"], "unsupported_runtime", "flags")
    return probe


@dataclass
class Census:
    """Every file the isolated interpreter can load from its own paths, plus the derived module table."""

    sha256: str
    files: int
    hashes: dict[str, str]
    entries: list[str]


def runtime_census(probe: Mapping[str, Any]) -> Census:
    """Digest every file below each ``sys.path`` entry reported by the isolated interpreter.

    Directory trees are hashed without ``__pycache__``/site directories, archive entries as files, and *absent*
    entries are recorded so a later-created path is detected.  The same pass yields ``path -> sha256`` for the
    module table the child loads from.
    """
    base_prefix = probe["base_prefix"]
    entries = sorted({os.path.abspath(p) for p in probe["sys_path"] if os.path.isabs(p)}, key=lambda p: (len(p), p))
    rows: list[list[Any]] = []
    hashes: dict[str, str] = {}
    done: list[str] = []
    for index, path in enumerate(entries):
        norm = os.path.normcase(path)
        if any(norm.startswith(os.path.normcase(parent) + os.sep) for parent in done):
            continue
        try:
            label = os.path.relpath(path, base_prefix).replace(os.sep, "/")
            if label.startswith(".."):
                raise ValueError
        except ValueError:
            label = "sp%d" % index
        if not os.path.lexists(path):
            rows.append([label, "absent", "", 0, ""])
            continue
        st = os.lstat(path)
        if stat.S_ISDIR(st.st_mode):
            _require(not _linklike(st), "census_linked_directory", label)
            rows.extend(_hash_tree(path, label, sink=hashes))
            done.append(path)
        else:
            _require(stat.S_ISREG(st.st_mode) or (stat.S_ISLNK(st.st_mode) and os.path.isfile(path)), "census_irregular_entry", label)
            sha = _file_sha256(path, "census_unreadable")
            rows.append([label, "f", "", os.stat(path).st_size, sha])
            hashes[path] = sha
    for core in probe["core_files"]:
        _require(bool(core) and os.path.isfile(core), "unsupported_runtime", "core_library_unreadable")
        rows.append(["core", "f", os.path.basename(core), os.stat(core).st_size, _file_sha256(core, "census_unreadable")])
    rows.sort(key=lambda row: (row[0], row[1], row[2]))
    return Census(_digest_rows(rows), len(rows), hashes, [e for e in entries if os.path.isdir(e)])


def _module_candidate(rel: str, suffixes: Sequence[str]) -> tuple[str, str, bool] | None:
    """Map a path relative to a module root to ``(module name, kind, is_package)``; ``None`` if not importable."""
    parts = rel.split("/")
    leaf = parts[-1]
    if leaf == "__init__.py":
        kind, parts, package = "py", parts[:-1], True
    elif leaf.endswith(".py"):
        kind, parts, package = "py", [*parts[:-1], leaf[:-3]], False
    else:
        for suffix in sorted(suffixes, key=len, reverse=True):
            if leaf.endswith(suffix) and len(leaf) > len(suffix):
                kind, package = "ext", False
                parts = [*parts[:-1], leaf[:-len(suffix)]]
                break
        else:
            return None
    if not parts:
        return None
    name = ".".join(parts)
    return (name, kind, package) if MODULE.match(name) and name.isascii() else None


def module_table(roots: Sequence[str], hashes: Mapping[str, str], suffixes: Sequence[str],
                 owners: Mapping[str, str] | None = None) -> list[list[Any]]:
    """Exact ``module -> file`` table over ordered module-root directories.

    The distribution of a row is the distribution that declared and censused that exact *file* (``owners``), never a
    property of the root: modules of two distributions installed under one shared root keep separate labels, and a
    stdlib/sys.path file has ``None``.  A name found twice (two roots, package-vs-module, or differing only by case)
    becomes ``ambiguous`` and is refused if imported; sourceless bytecode and namespace directories never enter it.
    """
    owners = owners or {}
    found: dict[str, list[list[Any]]] = {}
    for base in dict.fromkeys(roots):
        prefix = base.rstrip(os.sep) + os.sep
        for path, sha in hashes.items():
            if not path.startswith(prefix):
                continue
            candidate = _module_candidate(path[len(prefix):].replace(os.sep, "/"), suffixes)
            if candidate is not None:
                name, kind, package = candidate
                if any(row[2] == path for row in found.get(name, ())):
                    continue  # the same file reached through two listed roots is one candidate, not an ambiguity
                found.setdefault(name, []).append([name, kind, path, sha, package, owners.get(path)])
    folded: dict[str, set[str]] = {}
    for name in found:
        folded.setdefault(name.casefold(), set()).add(name)
    table = []
    for name in sorted(found):
        rows = found[name]
        if len(rows) > 1 or len(folded[name.casefold()]) > 1:
            table.append([name, "ambiguous", "", "", False, None])
        else:
            table.append(rows[0])
    return table


def _normalise_table(table: Any) -> list[list[Any]]:
    """Exact shape of a complete module map (``module_table`` rows): sorted, unique names, bounded, typed."""
    _require(isinstance(table, (list, tuple)) and len(table) <= MAX_RUNTIME_ROWS, "module_table_invalid", "shape")
    rows: list[list[Any]] = []
    for row in table:
        _require(isinstance(row, (list, tuple)) and len(row) == 6, "module_table_invalid", "row")
        name, kind, path, sha, package, dist = row
        _require(isinstance(name, str) and MODULE.match(name) is not None and name.isascii() and kind in ("py", "ext", "ambiguous")
                 and isinstance(path, str) and len(path) <= 4096 and isinstance(sha, str) and type(package) is bool
                 and ((kind == "ambiguous" and path == "" and sha == "" and package is False and dist is None)
                      or (kind != "ambiguous" and _is_absolute_claim(path) and _is_sha(sha)))
                 and (dist is None or (isinstance(dist, str) and _DISTRIBUTION.match(dist) is not None)),
                 "module_table_invalid", "row:" + str(name)[:60])
        rows.append([name, kind, path, sha, package, dist])
    names = [row[0] for row in rows]
    _require(names == sorted(names) and len(set(names)) == len(names), "module_table_invalid", "order")
    return rows


def module_table_digest(table: Any) -> str:
    """Commitment to a complete module map: the digest an operator records for the independently reviewed table.

    ``VerifiedClosure.table`` (the map ``verify_closure`` derived from the authenticated census) is what a reviewer
    obtains; acceptance of a receipt requires that same map and re-derives this digest from it.
    """
    return canonical_digest(_normalise_table(table))


def _resolve_executable(python: str) -> dict[str, Any]:
    invoked = os.path.abspath(python)
    resolved = os.path.realpath(invoked)
    cfg = None
    for directory in (os.path.dirname(invoked), os.path.dirname(os.path.dirname(invoked))):
        candidate = os.path.join(directory, "pyvenv.cfg")
        if os.path.isfile(candidate):
            cfg = _file_sha256(candidate, "runtime_executable_unreadable")
            break
    return {"invoked_executable": invoked, "executable_resolved": resolved,
            "executable_sha256": _file_sha256(invoked, "runtime_executable_unreadable"), "pyvenv_cfg_sha256": cfg}


def _native_rows(paths: Sequence[str]) -> list[dict[str, str]]:
    rows = {}
    for path in paths:
        real = os.path.realpath(path)
        if os.path.isfile(real):
            rows[real] = _file_sha256(real, "native_unreadable")
    return [{"path": path, "sha256": rows[path]} for path in sorted(rows)]


def _startup_rows(probe: Mapping[str, Any]) -> list[list[str]]:
    return [[path, _file_sha256(path, "runtime_startup_file_unreadable")] for path in sorted(probe["startup_files"])]


def _startup_config_rows(invoked: str, base_executable: str, version: str) -> list[list[str]]:
    """Interpreter start-up configuration files: ``[path, sha256 | "absent"]`` for every location the interpreter
    consults beside the invoked and base executables.  Absent entries pin the *absence*, so a later-created file is
    detected.  The Windows registry ``PythonPath`` is not inventoried (documented limit)."""
    major, minor = version.split(".")[:2]
    names = ("pyvenv.cfg", "python%s%s._pth" % (major, minor))
    candidates = set()
    for executable in (invoked, base_executable):
        directory = os.path.dirname(executable)
        stem = os.path.splitext(os.path.basename(executable))[0]
        for base in (directory, os.path.dirname(directory)):
            candidates.update(os.path.join(base, name) for name in names)
        candidates.add(os.path.join(directory, stem + "._pth"))
    rows = []
    for path in sorted(candidates):
        rows.append([path, _file_sha256(path, "runtime_startup_file_unreadable") if os.path.isfile(path) else "absent"])
    return rows


def _runtime_pins(python: str, probe: Mapping[str, Any], census: Census) -> dict[str, Any]:
    exe = _resolve_executable(python)
    _require(probe["executable"] == exe["invoked_executable"], "runtime_mismatch", "executable")
    startup = _startup_rows(probe)
    return {"implementation": probe["implementation"], "version": probe["version"], "cache_tag": probe["cache_tag"],
            "magic": probe["magic"], "platform": probe["platform"], "bits": probe["bits"], **exe,
            "base_executable": probe["base_executable"],
            "base_executable_sha256": _file_sha256(probe["base_executable"], "runtime_executable_unreadable"),
            "base_prefix": probe["base_prefix"], "sys_path": list(probe["sys_path"]), "core_files": sorted(probe["core_files"]),
            "census_sha256": census.sha256, "census_files": census.files,
            "startup_modules_sha256": _sha("\n".join(probe["startup_modules"]).encode("utf-8")),
            "preload_modules_sha256": _sha("\n".join(probe["preload_modules"]).encode("utf-8")),
            "startup_files": startup, "startup_files_sha256": canonical_digest(startup),
            "startup_config": _startup_config_rows(exe["invoked_executable"], probe["base_executable"], probe["version"]),
            "natives": _native_rows(probe["native_mappings"])}


def authenticate_runtime(python: str, pins: Mapping[str, Any]) -> Census:
    """Authenticate the pinned runtime from the filesystem *before* any interpreter process exists.

    Executables, start-up configuration, start-up files, core libraries, the standard-library census and every pinned
    native library are hashed and compared with the manifest pins using the same ``runtime_mismatch:<key>`` codes the
    later live probe uses.  The parent (this module) is itself authenticated externally by the release digest and
    the reviewed launcher, never by itself; see the contract document.
    """
    _require(python == pins["invoked_executable"], "runtime_mismatch", "invoked_executable")
    exe = _resolve_executable(python)
    for key in ("executable_resolved", "executable_sha256", "pyvenv_cfg_sha256"):
        _require(exe[key] == pins[key], "runtime_mismatch", key)
    _require(_file_sha256(pins["base_executable"], "runtime_executable_unreadable") == pins["base_executable_sha256"],
             "runtime_mismatch", "base_executable_sha256")
    _require(_startup_config_rows(pins["invoked_executable"], pins["base_executable"], pins["version"]) == pins["startup_config"],
             "runtime_mismatch", "startup_config")
    rows = [[path, _file_sha256(path, "runtime_startup_file_unreadable")] for path, _ in pins["startup_files"]]
    _require(rows == pins["startup_files"], "runtime_mismatch", "startup_files")
    census = runtime_census({"base_prefix": pins["base_prefix"], "sys_path": pins["sys_path"], "core_files": pins["core_files"]})
    _require(census.sha256 == pins["census_sha256"] and census.files == pins["census_files"], "runtime_mismatch", "census_sha256")
    for item in pins["natives"]:
        _require(_file_sha256(item["path"], "native_unreadable") == item["sha256"], "runtime_mismatch",
                 "native_changed:" + os.path.basename(item["path"]))
    return census


POSIX_POLICY = "posix-owner-mode-acl-v2"
WINDOWS_POLICY = "windows-owner-dacl-v1"
BUILTIN_SIDS = ("S-1-5-18", "S-1-5-32-544", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")
SID_PATTERN = re.compile(r"^S-1-\d{1,10}(-\d{1,10}){1,15}$")
# FILE_WRITE_DATA/ADD_FILE, FILE_APPEND_DATA/ADD_SUBDIRECTORY, FILE_WRITE_EA, FILE_DELETE_CHILD, FILE_WRITE_ATTRIBUTES,
# DELETE, WRITE_DAC, WRITE_OWNER, MAXIMUM_ALLOWED, GENERIC_ALL, GENERIC_WRITE
_WINDOWS_WRITE_MASK = 0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x10000 | 0x40000 | 0x80000 | 0x2000000 | 0x10000000 | 0x40000000
# What can replace or rename an EXISTING directory entry on the way to a protected object (creating siblings cannot).
_WINDOWS_REPLACE_MASK = 0x40 | 0x10000 | 0x40000 | 0x80000 | 0x2000000 | 0x10000000 | 0x40000000


@dataclass(frozen=True)
class ProtectionPolicy:
    """Principals the operator trusts to write the runtime, in addition to the built-in administrators.

    POSIX: ``uids`` always contains 0.  Windows: ``sids`` always contains SYSTEM, Administrators and TrustedInstaller.
    The evaluating principal is NEVER a trusted writer: a policy naming it is refused, and an evaluator that is itself
    the superuser/administrator (or holds any enabled trusted SID) is a separation failure, refused when enforcing.
    """
    uids: frozenset = frozenset({0})
    sids: frozenset = frozenset(BUILTIN_SIDS)

    @classmethod
    def build(cls, trusted_uids: Sequence[int] = (), trusted_sids: Sequence[str] = ()) -> "ProtectionPolicy":
        _require(all(type(u) is int and 0 <= u < 1 << 32 for u in trusted_uids), "runtime_protection_policy_invalid", "uid")
        _require(all(isinstance(s, str) and SID_PATTERN.match(s) is not None for s in trusted_sids),
                 "runtime_protection_policy_invalid", "sid")
        return cls(frozenset({0, *trusted_uids}), frozenset({*BUILTIN_SIDS, *trusted_sids}))

    def labels(self, kind: str) -> list[str]:
        return sorted("uid:%d" % u for u in self.uids) if kind == "posix" else sorted("sid:" + s for s in self.sids)


class _ProtectionStop(Exception):
    """Inspection could not be completed (distinct from 'something is exposed')."""


class ProtectionView:
    """The file-system and principal facts the inspector needs; tests substitute a synthetic subclass."""
    kind = "posix"
    name = POSIX_POLICY

    def __init__(self, policy: ProtectionPolicy):
        self.policy = policy

    def evaluators(self) -> set[str]:
        return {"uid:%d" % os.geteuid()}

    def lstat(self, path: str) -> os.stat_result:
        return os.lstat(path)

    def realpath(self, path: str) -> str:
        return os.path.realpath(path)

    def listdir(self, path: str) -> list[str]:
        return sorted(os.listdir(path))

    def link_target(self, path: str, st: os.stat_result) -> str | None:
        if not stat.S_ISLNK(st.st_mode):
            return None
        return os.path.normpath(os.path.join(os.path.dirname(path), os.readlink(path)))

    def privileged_evaluator(self) -> str | None:
        """The trusted-writer principal the evaluator itself runs as (it could then rewrite what it verifies), else None."""
        held = sorted(self.evaluators() & set(self.policy.labels(self.kind)))
        return held[0] if held else None

    def writable_by_evaluator(self, path: str) -> bool:
        return os.access(path, os.W_OK, effective_ids=True)

    def acl_present(self, path: str) -> bool:
        getter = getattr(os, "getxattr", None)
        if getter is None:
            raise OSError(errno.ENOSYS, "xattr_unavailable")
        try:
            getter(path, "system.posix_acl_access", follow_symlinks=False)
        except OSError as exc:
            if exc.errno in (errno.ENODATA, errno.ENOTSUP, errno.EOPNOTSUPP):
                return False
            raise
        return True

    def trusted_group(self, gid: int) -> bool:
        if gid != 0:
            return False
        try:
            import grp
            import pwd
            return all(name == "root" for name in grp.getgrgid(0).gr_mem) and all(
                entry.pw_uid == 0 for entry in pwd.getpwall() if entry.pw_gid == 0)
        except (ImportError, KeyError, OSError):
            return False

    def assess(self, path: str, st: os.stat_result, strict: bool) -> str | None:
        """Why ``path`` could be rewritten by an untrusted principal, else None.  ``strict`` = content/entries matter."""
        if st.st_uid not in self.policy.uids:
            return "owner:%d" % st.st_uid
        if stat.S_ISLNK(st.st_mode):
            return None
        sticky_dir = stat.S_ISDIR(st.st_mode) and bool(st.st_mode & stat.S_ISVTX) and not strict
        if st.st_mode & stat.S_IWOTH and not sticky_dir:
            return "other_write"
        if st.st_mode & stat.S_IWGRP and not sticky_dir and not self.trusted_group(st.st_gid):
            return "group_write:%d" % st.st_gid
        if self.acl_present(path):
            return "acl"
        if not sticky_dir and self.privileged_evaluator() is None and self.writable_by_evaluator(path):
            return "evaluator_writable"
        return None


def _dacl_reason(owner: str, aces: Sequence[Sequence[Any]] | None, trusted: frozenset, strict: bool) -> str | None:
    """Pure decision over a decoded owner and DACL: ``aces`` rows are (type, flags, mask, sid); None = NULL DACL."""
    if owner not in trusted:
        return "owner:" + owner
    if aces is None:
        return "null_dacl"
    mask_bits = _WINDOWS_WRITE_MASK if strict else _WINDOWS_REPLACE_MASK
    for ace_type, flags, mask, sid in aces:
        if ace_type in (4, 5, 11):
            raise OSError(errno.EINVAL, "unsupported_ace_type:%d" % ace_type)
        if ace_type not in (0, 9) or flags & 0x08:
            continue
        if mask & mask_bits and sid not in trusted:
            return "dacl_write:%s:%#x" % (sid, mask & mask_bits)
    return None


def _windows_security(path: str) -> tuple[str, list[tuple[int, int, int, str]] | None]:
    """Owner SID string and decoded DACL of ``path`` through the Win32 security API (native Windows only; NOT_RUN)."""
    import ctypes
    import struct
    from ctypes import wintypes
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    advapi.GetNamedSecurityInfoW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p),
                                             ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
                                             ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p)]
    advapi.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    advapi.GetAce.restype = wintypes.BOOL
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    advapi.ConvertSidToStringSidW.restype = wintypes.BOOL

    def sid_text(pointer: int) -> str:
        out = wintypes.LPWSTR()
        if not advapi.ConvertSidToStringSidW(ctypes.c_void_p(pointer), ctypes.byref(out)):
            raise OSError(ctypes.get_last_error(), "sid_conversion_failed")
        try:
            return out.value or ""
        finally:
            kernel.LocalFree(ctypes.cast(out, ctypes.c_void_p))

    owner, dacl, descriptor = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
    status = advapi.GetNamedSecurityInfoW(path, 1, 1 | 4, ctypes.byref(owner), None, ctypes.byref(dacl), None, ctypes.byref(descriptor))
    if status != 0:
        raise OSError(status, "security_query_failed")
    try:
        if not owner.value:
            raise OSError(errno.EINVAL, "owner_missing")
        owner_text = sid_text(owner.value)
        if not dacl.value:
            return owner_text, None
        count = struct.unpack("<BBHHH", ctypes.string_at(dacl.value, 8))[3]
        rows = []
        for index in range(count):
            ace = ctypes.c_void_p()
            if not advapi.GetAce(ctypes.c_void_p(dacl.value), index, ctypes.byref(ace)):
                raise OSError(ctypes.get_last_error(), "ace_read_failed")
            ace_type, flags, size = struct.unpack("<BBH", ctypes.string_at(ace.value, 4))
            if ace_type in (0, 9):
                mask = struct.unpack("<I", ctypes.string_at(ace.value + 4, 4))[0]
                rows.append((ace_type, flags, mask, sid_text(ace.value + 8)))
            else:
                rows.append((ace_type, flags, 0, ""))
        return owner_text, rows
    finally:
        kernel.LocalFree(descriptor)


def _windows_token_sids() -> set[str]:
    """SIDs of the evaluating process token (user and groups), for refusing a policy that trusts the evaluator."""
    import ctypes
    from ctypes import wintypes
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.OpenProcessToken.restype = wintypes.BOOL
    advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi.GetTokenInformation.restype = wintypes.BOOL
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    advapi.ConvertSidToStringSidW.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    token = wintypes.HANDLE()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x8, ctypes.byref(token)):
        raise OSError(ctypes.get_last_error(), "token_open_failed")
    try:
        def sid_text(pointer: int) -> str:
            out = wintypes.LPWSTR()
            if not advapi.ConvertSidToStringSidW(ctypes.c_void_p(pointer), ctypes.byref(out)):
                raise OSError(ctypes.get_last_error(), "sid_conversion_failed")
            try:
                return out.value or ""
            finally:
                kernel.LocalFree(ctypes.cast(out, ctypes.c_void_p))

        def query(info_class: int):
            needed = wintypes.DWORD()
            advapi.GetTokenInformation(token, info_class, None, 0, ctypes.byref(needed))
            buffer = ctypes.create_string_buffer(needed.value)
            if not advapi.GetTokenInformation(token, info_class, buffer, needed.value, ctypes.byref(needed)):
                raise OSError(ctypes.get_last_error(), "token_query_failed")
            return buffer

        width = ctypes.sizeof(ctypes.c_void_p)
        sids: set[str] = set()
        user = query(1)
        sids.add(sid_text(ctypes.c_void_p.from_buffer(user).value))
        groups = query(2)
        base = ctypes.addressof(groups)
        for index in range(ctypes.c_uint32.from_buffer(groups).value):
            entry = base + width + index * 2 * width
            if ctypes.c_uint32.from_address(entry + width).value & 0x4:
                sids.add(sid_text(ctypes.c_void_p.from_address(entry).value))
        return sids
    finally:
        kernel.CloseHandle(token)


class WindowsProtectionView(ProtectionView):
    """Owner and DACL inspector for native Windows (NOT_RUN until hosted CI); reparse points are followed and inspected."""
    kind = "windows"
    name = WINDOWS_POLICY

    def __init__(self, policy: ProtectionPolicy, security=None, token_sids=None):
        super().__init__(policy)
        self._security = security or _windows_security
        self._token_sids = token_sids or _windows_token_sids

    def evaluators(self) -> set[str]:
        return {"sid:" + sid for sid in self._token_sids()}

    def link_target(self, path: str, st: os.stat_result) -> str | None:
        if not _linklike(st):
            return None
        target = os.readlink(path)
        if target.startswith("\\\\?\\"):
            target = target[4:]
        return os.path.normpath(os.path.join(os.path.dirname(path), target))

    def assess(self, path: str, st: os.stat_result, strict: bool) -> str | None:
        owner, aces = self._security(path)
        return _dacl_reason(owner, aces, frozenset(self.policy.sids), strict)


def _check_policy_not_evaluator(view: ProtectionView) -> None:
    """A policy that names the evaluating principal as an extra trusted writer is same-user trust: refuse it.

    The built-in superuser and administrator principals are not "extra"; an evaluator running as one of them is a
    separate condition (``privileged_evaluator``) that enforcement refuses and diagnostics record.
    """
    if view.kind == "posix":
        extra = {"uid:%d" % u for u in view.policy.uids if u != 0}
    else:
        extra = {"sid:" + s for s in view.policy.sids if s not in BUILTIN_SIDS}
    overlap = sorted(extra & view.evaluators())
    if overlap:
        _require(False, "runtime_protection_policy_invalid", "trusts_evaluator:" + overlap[0])


class _Inspection:
    def __init__(self, view: ProtectionView):
        self.view, self.exposed, self.count = view, [], 0
        self.examined: set[tuple[str, bool]] = set()
        self.queued: set[tuple[str, bool]] = set()

    def stop(self, path: str, exc: BaseException) -> "_ProtectionStop":
        return _ProtectionStop("%s: %s" % (path, getattr(exc, "strerror", None) or type(exc).__name__))

    def look(self, path: str, strict: bool) -> os.stat_result | None:
        _Operation.tick("protection")
        try:
            st = self.view.lstat(path)
        except (FileNotFoundError, NotADirectoryError):
            return None
        except OSError as exc:
            raise self.stop(path, exc) from None
        key = (path, strict)
        if key not in self.examined:
            self.examined.add(key)
            self.count += 1
            if self.count > MAX_EXPOSURE_ENTRIES:
                raise _ProtectionStop("entry_limit")
            try:
                reason = self.view.assess(path, st, strict)
            except OSError as exc:
                raise self.stop(path, exc) from None
            if reason:
                self.exposed.append("%s [%s]" % (path, reason))
        return st

    def chain(self, seed: str, strict: bool) -> None:
        pending = [(os.path.abspath(seed), strict)]
        while pending:
            path, flag = pending.pop()
            if (path, flag) in self.queued:
                continue
            self.queued.add((path, flag))
            current, first = path, True
            while True:
                st = self.look(current, flag and first)
                if st is not None:
                    try:
                        target = self.view.link_target(current, st)
                    except OSError as exc:
                        raise self.stop(current, exc) from None
                    if target is not None:
                        pending.append((target, flag and first))
                parent = os.path.dirname(current)
                if parent == current:
                    break
                current, first = parent, False
            try:
                real = self.view.realpath(path)
            except OSError as exc:
                raise self.stop(path, exc) from None
            if real != path:
                pending.append((real, flag))

    def walk(self, root: str) -> None:
        self.chain(root, True)
        try:
            top = self.view.realpath(os.path.abspath(root))
        except OSError as exc:
            raise self.stop(root, exc) from None
        stack, seen = [top], set()
        while stack:
            directory = stack.pop()
            if directory in seen:
                continue
            seen.add(directory)
            st = self.look(directory, True)
            if st is None or stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
                continue
            try:
                names = self.view.listdir(directory)
            except OSError as exc:
                raise self.stop(directory, exc) from None
            for name in names:
                full = os.path.join(directory, name)
                child = self.look(full, True)
                if child is None:
                    continue
                if self.view.link_target(full, child) is not None:
                    self.chain(full, True)
                    try:
                        resolved = self.view.realpath(full)
                    except OSError as exc:
                        raise self.stop(full, exc) from None
                    stack.append(resolved)
                elif stat.S_ISDIR(child.st_mode):
                    stack.append(full)


def default_protection_view(policy: ProtectionPolicy) -> ProtectionView | None:
    if sys.platform == "win32":
        return WindowsProtectionView(policy)
    return ProtectionView(policy) if hasattr(os, "geteuid") else None


def runtime_write_exposure(pins: Mapping[str, Any], package_roots: Sequence[str] = (), trees: Sequence[str] = (),
                           files: Sequence[str] = (), *, policy: ProtectionPolicy | None = None,
                           view: ProtectionView | None = None) -> dict[str, Any]:
    """Which pinned runtime and closure paths could be rewritten by a principal the policy does not trust.

    Every pinned file, every ``sys.path`` tree, every closure root and file, every package top-level entry (directory
    tree, module file, extension file, ``.dist-info``) and EVERY ancestor of each, following symbolic links and
    reparse points one step at a time so that each link, its parent and its target are inspected.  The evaluating
    principal is not trusted (POSIX: ``os.access`` for write must be refused for a non-superuser evaluator; owner,
    group, other and POSIX ACL entries are inspected; Windows: owner and DACL write rights of every untrusted
    principal).  ``inspected`` is False when any inspection step failed, when the entry limit was exceeded, and on a
    platform without a reviewer inspector; enforcement treats that as a refusal, never as "nothing exposed".
    """
    policy = policy or ProtectionPolicy()
    view = view or default_protection_view(policy)
    evidence: dict[str, Any] = {"inspected": False, "enforced": False, "paths_checked": 0, "exposed": [],
                                "policy": view.name if view else "unavailable",
                                "trusted": view.policy.labels(view.kind) if view else []}
    if view is None:
        return evidence
    _check_policy_not_evaluator(view)
    inspection = _Inspection(view)
    held = view.privileged_evaluator()
    if held:
        inspection.exposed.append("evaluator [privileged_evaluator:%s]" % held)
    strict_seeds = {pins["invoked_executable"], pins["executable_resolved"], pins["base_executable"], *pins["core_files"],
                    *(p for p, _ in pins["startup_files"]), *(n["path"] for n in pins["natives"]), *package_roots, *files,
                    *(p for p, sha in pins["startup_config"] if sha != "absent")}
    walk_roots = sorted({os.path.abspath(p) for p in [*pins["sys_path"], *trees] if os.path.isabs(p)})
    try:
        for path in sorted(strict_seeds):
            inspection.chain(path, True)
        for base in walk_roots:
            inspection.walk(base)
    except _ProtectionStop as stop:
        evidence.update(paths_checked=inspection.count, exposed=(inspection.exposed + [str(stop)])[:50])
        return evidence
    evidence.update(inspected=True, paths_checked=inspection.count, exposed=inspection.exposed[:50])
    return evidence


def observe_runtime(python: str | os.PathLike, work: str | None = None) -> dict[str, Any]:
    python = os.path.abspath(os.fspath(python))
    probe = probe_runtime(python, work)
    census = runtime_census(probe)
    return {"probe": probe, "pins": _runtime_pins(python, probe, census), "census": census}


# --------------------------------------------------------------------------- packages

def _normalize_dist(name: str) -> str:
    return re.sub(r"[-_.]+", "_", name).lower()


def package_census(root: str, entry: Mapping[str, Any], extension_suffixes: Sequence[str], sink: dict | None = None) -> tuple[str, int]:
    """Digest the declared top-level trees/files and the exact ``.dist-info`` of one distribution."""
    _Operation.tick("package_census")
    names = {e.name for e in os.scandir(root)}
    rows: list[list[Any]] = []
    for top in entry["top_level"]:
        _require(MODULE.match(top) is not None and "." not in top, "package_top_level_invalid", top)
        found = []
        if top in names:
            found.append(("dir", top))
        if top + ".py" in names:
            found.append(("py", top + ".py"))
        found.extend(("ext", n) for n in sorted(names) if n.startswith(top + ".") and any(n.endswith(s) for s in extension_suffixes))
        for n in names:
            _require(not (n.casefold() == top.casefold() and n != top), "package_case_collision", top)
        _require(len(found) == 1, "package_resolution_ambiguous_or_missing", top)
        kind, item = found[0]
        _walk_components(root, [item], final_dir=kind == "dir")
        if kind == "dir":
            rows.extend(_hash_tree(os.path.join(root, item), top, item + "/", sink))
        else:
            file_hash = _file_sha256(os.path.join(root, item), "package_unreadable")
            rows.append([top, "f", item, os.stat(os.path.join(root, item)).st_size, file_hash])
            if sink is not None:
                sink[os.path.join(root, item)] = file_hash
    infos = []
    for n in sorted(names):
        if n.endswith(".dist-info"):
            dist_name, _, dist_version = n[:-len(".dist-info")].rpartition("-")
            if _normalize_dist(dist_name) == _normalize_dist(entry["distribution"]) and dist_version == entry["version"].replace("-", "_"):
                infos.append(n)
    _require(len(infos) == 1, "package_dist_info_missing_or_ambiguous", entry["distribution"])
    _walk_components(root, [infos[0]], final_dir=True)
    metadata = _read_file(root, infos[0] + "/METADATA", 8 << 20).decode("utf-8", "replace")
    head = metadata.partition("\n\n")[0]
    declared = {k.strip().lower(): v.strip() for k, _, v in (line.partition(":") for line in head.splitlines()) if _}
    _require(_normalize_dist(declared.get("name", "")) == _normalize_dist(entry["distribution"]) and declared.get("version") == entry["version"],
             "package_metadata_mismatch", entry["distribution"])
    rows.extend(_hash_tree(os.path.join(root, infos[0]), "dist-info", infos[0] + "/", sink))
    rows.sort(key=lambda row: (row[0], row[2]))
    return canonical_digest({"entries": rows}), len(rows)


# --------------------------------------------------------------------------- resolution on disk

def _candidates(name: str, probe_suffixes: Sequence[str]) -> list[str]:
    base = name.replace(".", "/")
    out = [base + ".py", base + ".pyc", base + "/__init__.py", base + "/__init__.pyc", base]
    out.extend(base + s for s in probe_suffixes)
    out.extend(base + "/__init__" + s for s in probe_suffixes)
    return out


def _resolution_check(roots: Mapping[str, str], root_alias: str, name: str, package: bool, suffixes: Sequence[str]):
    """Refuse package-vs-module, sourceless/extension, case and multi-root ambiguity for one module."""
    expected = _derived_path(name, package)
    parts = expected.split("/")
    parent = os.path.join(roots[root_alias], *parts[:-1])
    stem = name.rpartition(".")[2]
    listing = {e.name for e in os.scandir(parent)}
    if package:
        owner = os.path.dirname(parent)
        siblings = {e.name for e in os.scandir(owner)}
        _require(stem + ".py" not in siblings and stem + ".pyc" not in siblings and not any(
            (stem + s) in siblings for s in suffixes), "ambiguous_resolution", name + ":package_vs_module")
        _require(not ({"__init__.pyc"} & listing) and not any(("__init__" + s) in listing for s in suffixes), "ambiguous_resolution", name + ":sourceless_init")
        for n in siblings:
            _require(n == stem or n.casefold() != stem.casefold(), "case_collision", name)
        for n in listing:
            _require(n == "__init__.py" or n.casefold() != "__init__.py", "case_collision", name)
    else:
        _require(stem not in listing and stem + ".pyc" not in listing and not any((stem + s) in listing for s in suffixes),
                 "ambiguous_resolution", name + ":module_vs_package_or_sourceless")
        for n in listing:
            _require(n == parts[-1] or n.casefold() != parts[-1].casefold(), "case_collision", name)
    for alias, other in roots.items():
        if alias == root_alias:
            continue
        for candidate in _candidates(name, suffixes):
            _require(not os.path.lexists(os.path.join(other, *candidate.split("/"))), "ambiguous_multiple_roots", name + "@" + alias)


def _discover(name: str, roots: Mapping[str, str], suffixes: Sequence[str]):
    """Find the single on-disk module named ``name`` in importlib's order; returns (alias, package) or None."""
    found = []
    for alias, root in roots.items():
        base = os.path.join(root, *name.split("."))
        if os.path.lexists(base + ".py"):
            found.append((alias, False))
        if os.path.lexists(os.path.join(base, "__init__.py")):
            found.append((alias, True))
    _require(len({alias for alias, _ in found}) <= 1, "ambiguous_multiple_roots", name)
    _require(len(found) <= 1, "ambiguous_resolution", name)
    return found[0] if found else None


def _importable_somewhere(name: str, roots: Mapping[str, str], suffixes: Sequence[str]) -> bool:
    """True if anything the import system could resolve for ``name`` exists under any root."""
    return any(os.path.lexists(os.path.join(root, *candidate.split("/")))
               for root in roots.values() for candidate in _candidates(name, suffixes))



# --------------------------------------------------------------------------- manifest

def _derived_path(name: str, package: bool) -> str:
    base = name.replace(".", "/")
    return base + ("/__init__.py" if package else ".py")


_RUNTIME_KEYS = {"implementation", "version", "cache_tag", "magic", "platform", "bits", "invoked_executable",
                 "executable_resolved", "executable_sha256", "pyvenv_cfg_sha256", "base_executable",
                 "base_executable_sha256", "base_prefix", "sys_path", "core_files", "census_sha256", "census_files",
                 "startup_modules_sha256", "preload_modules_sha256", "startup_files", "startup_files_sha256",
                 "startup_config", "natives"}


def validate_manifest(manifest: Any) -> dict[str, Any]:
    """Strict, exact-shape validation; returns the manifest unchanged when valid."""
    _require(isinstance(manifest, dict) and set(manifest) == {"version", "name", "entry", "modules", "edges", "dynamic",
                                                                "dependency_operations", "packages", "runtime"}, "manifest_shape")
    _require(manifest["version"] == VERSION, "manifest_version")
    _require(isinstance(manifest["name"], str) and 1 <= len(manifest["name"]) <= 120, "manifest_name")
    entry = manifest["entry"]
    _require(isinstance(entry, dict) and set(entry) == {"module", "callable"} and MODULE.match(str(entry["module"])) is not None
             and re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", str(entry["callable"])) is not None, "manifest_entry")
    modules = manifest["modules"]
    _require(isinstance(modules, list) and 0 < len(modules) <= MAX_MODULES, "manifest_modules")
    names = []
    for item in modules:
        _require(isinstance(item, dict) and set(item) == {"name", "root", "path", "sha256", "bytes", "package"}, "manifest_module_shape")
        _require(isinstance(item["name"], str) and MODULE.match(item["name"]) is not None and item["name"].isascii(), "manifest_module_name", str(item["name"])[:60])
        _require(isinstance(item["root"], str) and ALIAS.match(item["root"]) is not None, "manifest_module_root", item["name"])
        _require(type(item["package"]) is bool and item["path"] == _derived_path(item["name"], item["package"]), "manifest_module_path", item["name"])
        _require(isinstance(item["sha256"], str) and SHA.match(item["sha256"]) is not None, "manifest_module_hash", item["name"])
        _require(type(item["bytes"]) is int and 0 <= item["bytes"] <= MAX_MODULE_BYTES, "manifest_module_size", item["name"])
        names.append(item["name"])
    _require(names == sorted(names) and len(set(names)) == len(names), "manifest_modules_unsorted_or_duplicate")
    _require(isinstance(manifest["edges"], dict) and set(manifest["edges"]) == set(names) and all(
        isinstance(v, list) and v == sorted(set(v)) and set(v) <= set(names) for v in manifest["edges"].values()), "manifest_edges")
    dynamic = manifest["dynamic"]
    _require(isinstance(dynamic, list) and len(dynamic) <= MAX_DYNAMIC and all(isinstance(d, dict) and set(d) == {"module", "target"} and d["module"] in names and
                                                MODULE.match(str(d["target"])) is not None for d in dynamic)
             and dynamic == sorted(dynamic, key=lambda d: (d["module"], d["target"])), "manifest_dynamic")
    _require(len({(d["module"], d["target"]) for d in dynamic}) == len(dynamic), "manifest_dynamic")
    _validate_dependency_operations(manifest["dependency_operations"], set(names))
    packages = manifest["packages"]
    _require(isinstance(packages, list) and len(packages) <= MAX_PACKAGES, "manifest_packages")
    seen_tops: set[str] = set()
    for item in packages:
        _require(isinstance(item, dict) and set(item) == {"distribution", "version", "root", "top_level", "census_sha256", "census_files"}
                 and isinstance(item["distribution"], str) and re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*$", item["distribution"]) is not None
                 and isinstance(item["version"], str) and re.match(r"^[A-Za-z0-9][A-Za-z0-9._+!-]*$", item["version"]) is not None
                 and isinstance(item["root"], str) and ALIAS.match(item["root"]) is not None
                 and isinstance(item["top_level"], list) and item["top_level"] and item["top_level"] == sorted(set(item["top_level"]))
                 and all(isinstance(t, str) and MODULE.match(t) is not None and "." not in t for t in item["top_level"])
                 and isinstance(item["census_sha256"], str) and SHA.match(item["census_sha256"]) is not None
                 and type(item["census_files"]) is int and item["census_files"] > 0, "manifest_package_shape")
        _require(not (seen_tops & set(item["top_level"])), "manifest_package_duplicate_top")
        seen_tops |= set(item["top_level"])
    _require(packages == sorted(packages, key=lambda p: p["distribution"].lower()), "manifest_packages_unsorted")
    _validate_runtime(manifest["runtime"])
    canonical_bytes(manifest)  # canonical data domain (bounded integers, valid unicode)
    return manifest


def _validate_dependency_operations(operations: Any, owned: set[str]) -> None:
    """Exact shape of the declared dependency operations; sorted, unique, bounded, never on a denylisted or closure-owned
    module (whether the module is pinned is a census fact, checked against the table in ``_verify_core``)."""
    _require(isinstance(operations, list) and len(operations) <= MAX_DEPENDENCY_OPERATIONS, "manifest_dependency_operations")
    tops = {n.partition(".")[0] for n in owned}
    for item in operations:
        _require(isinstance(item, dict) and set(item) == {"importer", "form", "module"}
                 and all(isinstance(item[k], str) for k in ("importer", "form", "module"))
                 and MODULE.match(item["importer"]) is not None and MODULE.match(item["module"]) is not None
                 and item["importer"].isascii() and item["module"].isascii()
                 and item["form"] in DEPENDENCY_OPERATION_FORMS
                 and item["module"].partition(".")[0] not in FORBIDDEN_MODULES
                 and item["module"].partition(".")[0] not in tops and item["importer"].partition(".")[0] not in tops
                 and len(DEPENDENCY_OPERATION_PREFIX + ":".join((item["importer"], item["form"], item["module"]))) <= 120,
                 "manifest_dependency_operations", str(item)[:60])
    keys = [(d["importer"], d["form"], d["module"]) for d in operations]
    _require(keys == sorted(set(keys)), "manifest_dependency_operations", "unsorted_or_duplicate")


def _check_dependency_operations(manifest: Mapping[str, Any], table: Sequence[Sequence[Any]]) -> None:
    """Every declared operation names a pinned Python census module as importer; the module may be pinned or not (shape
    and the denylist are ``_validate_dependency_operations``).  A declaration of an operation the reviewed tables already
    approve is harmless and accepted."""
    rows = {row[0]: row for row in table}
    for item in manifest["dependency_operations"]:
        importer = rows.get(item["importer"])
        _require(importer is not None and importer[1] not in ("ext", "ambiguous"), "dependency_operation_importer_unpinned",
                 item["importer"][:60])


def _validate_runtime(runtime: Any) -> None:
    """Exact shape, types and bounds of a runtime pin record (shared by manifests and receipts)."""
    _require(isinstance(runtime, dict) and set(runtime) == _RUNTIME_KEYS, "manifest_runtime_shape")
    for key in ("executable_sha256", "base_executable_sha256", "census_sha256", "startup_modules_sha256",
                "preload_modules_sha256", "startup_files_sha256"):
        _require(isinstance(runtime[key], str) and SHA.match(runtime[key]) is not None, "manifest_runtime_hash", key)
    _require(runtime["pyvenv_cfg_sha256"] is None or (isinstance(runtime["pyvenv_cfg_sha256"], str)
                                                     and SHA.match(runtime["pyvenv_cfg_sha256"]) is not None), "manifest_runtime_hash", "pyvenv_cfg_sha256")
    _require(all(isinstance(runtime[k], str) and 0 < len(runtime[k]) <= 4096 for k in (
        "implementation", "version", "cache_tag", "magic", "platform", "invoked_executable", "executable_resolved",
        "base_executable", "base_prefix"))
             and type(runtime["bits"]) is int and type(runtime["census_files"]) is int and runtime["census_files"] >= 0,
             "manifest_runtime_types")
    for key in ("sys_path", "core_files"):
        value = runtime[key]
        _require(isinstance(value, list) and len(value) <= 256 and all(isinstance(p, str) and 0 < len(p) <= 4096 for p in value)
                 and (key == "sys_path" or len(set(value)) == len(value)), "manifest_runtime_paths", key)
    _require(runtime["core_files"] == sorted(runtime["core_files"]), "manifest_runtime_paths", "core_files")
    for key, allow_absent in (("startup_files", False), ("startup_config", True)):
        rows = runtime[key]
        _require(isinstance(rows, list) and len(rows) <= 256 and all(
            isinstance(r, list) and len(r) == 2 and isinstance(r[0], str) and 0 < len(r[0]) <= 4096 and isinstance(r[1], str)
            and (SHA.match(r[1]) is not None or (allow_absent and r[1] == "absent")) for r in rows)
            and [r[0] for r in rows] == sorted({r[0] for r in rows}), "manifest_runtime_rows", key)
    _require(runtime["startup_files_sha256"] == canonical_digest(runtime["startup_files"]), "manifest_runtime_rows", "startup_files_sha256")
    natives = runtime["natives"]
    _require(isinstance(natives, list) and len(natives) <= MAX_NATIVES and all(
        isinstance(n, dict) and set(n) == {"path", "sha256"} and isinstance(n["path"], str) and 0 < len(n["path"]) <= 4096
        and isinstance(n["sha256"], str) and SHA.match(n["sha256"]) is not None for n in natives)
             and [n["path"] for n in natives] == sorted({n["path"] for n in natives}), "manifest_runtime_natives")


def manifest_digest(manifest: Mapping[str, Any]) -> str:
    """Canonical (TRACE-C14N-1) digest; the reviewed release records this value externally."""
    return canonical_digest(validate_manifest(dict(manifest)))


# --------------------------------------------------------------------------- build / verify

def _parse_roots(roots: Mapping[str, Path | str]) -> dict[str, str]:
    _require(isinstance(roots, Mapping) and roots, "roots_required")
    out = {}
    for alias, path in roots.items():
        _require(isinstance(alias, str) and ALIAS.match(alias) is not None, "root_alias_invalid", str(alias)[:40])
        out[alias] = _root(path, alias)
    values = [os.path.normcase(v) for v in out.values()]
    _require(len(set(values)) == len(values), "roots_not_distinct")
    for a in values:
        for b in values:
            _require(a == b or not b.startswith(a + os.sep), "roots_nested")
    return out


@dataclass
class VerifiedClosure:
    manifest: dict[str, Any]
    manifest_sha256: str
    release_sha256: str | None
    roots: dict[str, str]
    modules: dict[str, bytes]
    sites: dict[str, list[list[Any]]]
    probe: dict[str, Any]
    pins: dict[str, Any]
    python: str
    table: list[list[Any]]
    startup_rows: list[list[str]]
    files: dict[str, bytes]
    package_census: dict[str, str]
    exposure: dict[str, Any] = field(default_factory=dict)
    implementation_source: str = "disk_reread"


def _package_entries(root: str, entry: Mapping[str, Any]) -> list[str]:
    """Every top-level entry of ``root`` that can supply one of the distribution's modules or its metadata."""
    tops = [top.casefold() for top in entry["top_level"]]
    wanted = _normalize_dist(entry["distribution"])
    found = []
    for name in sorted(os.listdir(root)):
        folded = name.casefold()
        if any(folded == top or folded.startswith(top + ".") for top in tops):
            found.append(os.path.join(root, name))
        elif name.endswith(".dist-info") and _normalize_dist(name[:-len(".dist-info")].rpartition("-")[0]) == wanted:
            found.append(os.path.join(root, name))
    return found


def _protection_gate(pins: Mapping[str, Any], parsed: Mapping[str, str], manifest: Mapping[str, Any], enforce: bool,
                     policy: ProtectionPolicy | None = None, view: ProtectionView | None = None) -> dict[str, Any]:
    """Inspect write-exposure of every pinned runtime and closure path; with ``enforce`` refuse before anything runs."""
    trees: list[str] = []
    try:
        for item in manifest["packages"]:
            trees.extend(_package_entries(parsed[item["root"]], item))
    except OSError as exc:
        if enforce:
            _reject("runtime_protection_not_inspectable", ("%s: %s" % (exc.filename, exc.strerror))[:100])
    files = [os.path.join(parsed[item["root"]], *item["path"].split("/")) for item in manifest["modules"]]
    exposure = runtime_write_exposure(pins, [*parsed.values()], trees, files, policy=policy, view=view)
    exposure["enforced"] = bool(enforce)
    if enforce:
        if not exposure["inspected"]:
            _reject("runtime_protection_not_inspectable", (exposure["exposed"] or [sys.platform])[-1][:100])
        if exposure["exposed"]:
            first = exposure["exposed"][0]
            if first.startswith("evaluator [privileged_evaluator:"):
                _reject("runtime_evaluator_privileged", first[len("evaluator [privileged_evaluator:"):-1][:100])
            _reject("runtime_writable_by_others", first[:100])
    return exposure


def _check_natives(pins: Mapping[str, Any], live: Mapping[str, Any]) -> None:
    pinned = {n["path"]: n["sha256"] for n in pins["natives"]}
    for path, sha in pinned.items():
        _require(_file_sha256(path, "native_unreadable") == sha, "runtime_mismatch", "native_changed:" + os.path.basename(path))
    for item in live["natives"]:
        _require(pinned.get(item["path"]) == item["sha256"], "runtime_mismatch", "native_startup_unpinned:" + os.path.basename(item["path"]))


def _read_closure_modules(manifest: Mapping[str, Any], parsed: Mapping[str, str], suffixes: Sequence[str]) -> dict[str, bytes]:
    modules: dict[str, bytes] = {}
    for item in manifest["modules"]:
        _Operation.tick("closure_read")
        data = _read_file(parsed[item["root"]], item["path"], MAX_MODULE_BYTES)
        _require(len(data) == item["bytes"] and _sha(data) == item["sha256"], "closure_module_changed", item["name"])
        _resolution_check(parsed, item["root"], item["name"], item["package"], suffixes)
        modules[item["name"]] = data
    return modules


def _verify_core(manifest: dict[str, Any], parsed: dict[str, str], python: str, work: str, files: dict[str, bytes],
                 observed: Mapping[str, Any] | None = None, enforce_protection: bool = False,
                 protection_policy: ProtectionPolicy | None = None, protection_view: ProtectionView | None = None) -> VerifiedClosure:
    """Verify runtime, every module byte and every path against ``manifest``; executes no verifier code.

    With ``enforce_protection`` the write-exposure gate runs FIRST, before the runtime is hashed and before the first
    interpreter process exists.
    """
    for item in [*manifest["modules"], *manifest["packages"]]:
        _require(item["root"] in parsed, "root_not_supplied", item["root"])
    pins = manifest["runtime"]
    _require(python == pins["invoked_executable"], "runtime_mismatch", "invoked_executable")
    exposure = _Operation.bounded("protection", _protection_gate, pins, parsed, manifest, enforce_protection,
                                  protection_policy, protection_view)
    if observed is not None:
        probe, census = observed["probe"], observed["census"]
    else:
        # no interpreter process exists until the pinned runtime files matched
        _Operation.bounded("authenticate", authenticate_runtime, python, pins)
        probe = probe_runtime(python, work, files["trace_gc/verifier_closure_bootstrap.py"])
        census = _Operation.bounded("census", runtime_census, probe)
    live = _Operation.bounded("runtime_pins", _runtime_pins, python, probe, census)
    for key, value in live.items():
        if key != "natives":
            _require(pins[key] == value, "runtime_mismatch", key)
    suffixes = probe["extension_suffixes"]
    stdlib = frozenset(probe["stdlib_module_names"]) | {n.partition(".")[0] for n in probe["startup_modules"]}
    _Operation.bounded("natives", _check_natives, pins, live)
    modules = _Operation.bounded("closure_read", _read_closure_modules, manifest, parsed, suffixes)
    hashes = dict(census.hashes)
    module_roots: list[str] = _Operation.bounded(
        "sys_path", lambda: [path for path in probe["sys_path"] if os.path.isabs(path) and os.path.isdir(path)])
    package_tops, package_census_map = set(), {}
    owners: dict[str, str] = {}
    for item in manifest["packages"]:
        sink: dict[str, str] = {}
        digest, count = _Operation.bounded("package_census", package_census, parsed[item["root"]], item, suffixes, sink)
        _require(digest == item["census_sha256"] and count == item["census_files"], "package_changed", item["distribution"])
        hashes.update(sink)
        for path in sink:
            owners[path] = item["distribution"]
        module_roots.append(parsed[item["root"]])
        package_tops.update(item["top_level"])
        package_census_map[item["distribution"]] = digest
    approved: dict[str, set[str]] = {}
    for item in manifest["dynamic"]:
        approved.setdefault(item["module"], set()).add(item["target"])
    meta = {m["name"]: m["package"] for m in manifest["modules"]}
    def graph_and_table():
        found = analyse(
            {n: (modules[n], meta[n]) for n in modules}, entry=manifest["entry"]["module"],
            entry_callable=manifest["entry"]["callable"], stdlib_names=stdlib, package_tops=frozenset(package_tops),
            approved_dynamic={k: frozenset(v) for k, v in approved.items()})
        _require(found[0] == manifest["edges"], "import_graph_mismatch")
        for owner, sub in found[1]:
            _require(not _importable_somewhere(sub, parsed, suffixes), "unlisted_module", owner + "->" + sub)
        built = module_table(module_roots, hashes, suffixes, owners)
        _check_dependency_operations(manifest, built)
        return found[3], built

    sites, table = _Operation.bounded("graph_and_table", graph_and_table)
    # the start-up rows were hashed by the bounded ``runtime_pins`` step and compared with the manifest pins above: no
    # further filesystem read happens here
    return VerifiedClosure(manifest, _Operation.bounded("manifest_digest", canonical_digest, manifest), None, parsed, modules, sites, probe, dict(pins), python,
                           table, live["startup_files"], files, package_census_map, exposure, implementation_source())


def _authenticated_manifest(manifest: Mapping[str, Any], expected_manifest_sha256: str) -> dict[str, Any]:
    """Serialize, copy, validate and digest the caller's manifest (one bounded phase: it is data-dependent work)."""
    checked = validate_manifest(json.loads(json.dumps(manifest)))
    _require(canonical_digest(checked) == expected_manifest_sha256, "manifest_digest_mismatch")
    return checked


def _authenticate_release(manifest: Mapping[str, Any], files: Mapping[str, bytes], expected_release_sha256: str) -> None:
    _require(canonical_digest(release_record(manifest, files)) == expected_release_sha256, "release_digest_mismatch")


def verify_closure(manifest: Mapping[str, Any], expected_manifest_sha256: str, *, expected_release_sha256: str,
                   roots: Mapping[str, Path | str], python: str | os.PathLike | None = None,
                   work: str | None = None, allow_unprotected_runtime: bool = False,
                   protection_policy: ProtectionPolicy | None = None,
                   protection_view: ProtectionView | None = None,
                   expected_module_table_sha256: str | None = None) -> VerifiedClosure:
    """Authenticate manifest and release digests, then verify runtime and every closure byte; no verifier code runs.

    With ``expected_module_table_sha256`` (the digest of the independently reviewed complete module map, see
    ``module_table_digest``) the live census-derived map must equal it before any interpreter process exists
    (``runtime_module_table_mismatch``).

    Runtime protection is REQUIRED by default: a runtime or closure path that a principal outside ``protection_policy``
    (never the evaluator itself) could rewrite, a path that cannot be inspected, and any platform without an inspector
    refuse the run before the first interpreter process exists.  ``allow_unprotected_runtime=True`` records the
    evidence only; such a receipt is not acceptance grade.  ``protection_view`` is a test seam that replaces the file
    system facts; it is not reachable from the command line or the launcher.
    """
    _require(type(allow_unprotected_runtime) is bool, "invalid_arguments", "flag_type")
    _require(protection_policy is None or isinstance(protection_policy, ProtectionPolicy), "invalid_arguments", "protection_policy")
    _require(isinstance(expected_manifest_sha256, str) and SHA.match(expected_manifest_sha256) is not None, "expected_digest_required")
    _require(isinstance(expected_release_sha256, str) and SHA.match(expected_release_sha256) is not None, "expected_release_required")
    manifest = _Operation.bounded("manifest", _authenticated_manifest, manifest, expected_manifest_sha256)
    files = _Operation.bounded("implementation", implementation_files)
    _Operation.bounded("release", _authenticate_release, manifest, files, expected_release_sha256)
    parsed = _Operation.bounded("roots", _parse_roots, roots)
    python = os.path.abspath(os.fspath(python or sys.executable))
    own = work is None
    work = work or tempfile.mkdtemp(prefix="pvc-verify-")
    identity = _identity(os.lstat(work)) if own else None
    removed = True
    try:
        verified = _verify_core(manifest, parsed, python, work, files, None, not allow_unprotected_runtime,
                                protection_policy, protection_view)
    finally:
        if own:
            removed = _bounded_rmtree(work, _Operation.cleanup_left(), identity)
    _require(removed, "containment_cleanup_failed", "verify_work")
    if expected_module_table_sha256 is not None:
        _require(_Operation.bounded("module_table", module_table_digest, verified.table) == expected_module_table_sha256,
                 "runtime_module_table_mismatch")
    verified.release_sha256 = expected_release_sha256
    return verified


def build_manifest(*, name: str, roots: Mapping[str, Path | str], entry_module: str, entry_callable: str = "verify",
                   python: str | os.PathLike | None = None, packages: Sequence[Mapping[str, Any]] = (),
                   dynamic: Sequence[Mapping[str, str]] = (), observation: Mapping[str, Any] | None = None,
                   discover_natives: bool = True,
                   dependency_operations: Sequence[Mapping[str, str]] = ()) -> dict[str, Any]:
    """Discover the complete closure from ``entry_module`` and return a manifest.

    ``packages`` entries are ``{"distribution","version","root","top_level"}``; ``dynamic`` entries are
    ``{"module","target"}`` literal ``import_module``/``__import__`` approvals; ``dependency_operations`` entries are the
    reviewed ``{"importer","form","module"}`` operations of census-loaded dependencies on unpinned modules and their
    dynamic operations on pinned ones (``DEPENDENCY_STDLIB_OPERATIONS`` need none).  Discovery
    (``discover_natives``) observes the operations the entry import really performs and rejects with
    ``dependency_operation_undeclared`` naming the first one that was not declared.  ``observation`` may carry an earlier
    ``observe_runtime`` result for the same interpreter; ``verify_closure`` always re-derives the runtime pins itself.
    With ``discover_natives`` the entry module is imported once in a policy-enforcing child to record the native
    libraries the closure maps, which are then pinned.  Anything the scan cannot bind (unresolved or ambiguous
    imports, unapproved dynamic constructs, undeclared third-party imports) is a rejection.
    """
    parsed = _parse_roots(roots)
    work = tempfile.mkdtemp(prefix="pvc-build-")
    work_identity = _identity(os.lstat(work))
    try:
        python = os.path.abspath(os.fspath(python or sys.executable))
        files = implementation_files()
        runtime = dict(observation) if observation is not None else None
        if runtime is None:
            probe = probe_runtime(python, work, files["trace_gc/verifier_closure_bootstrap.py"])
            census = runtime_census(probe)
            runtime = {"probe": probe, "census": census, "pins": _runtime_pins(python, probe, census)}
        probe = runtime["probe"]
        suffixes = probe["extension_suffixes"]
        stdlib = frozenset(probe["stdlib_module_names"]) | {n.partition(".")[0] for n in probe["startup_modules"]}
        package_entries = []
        for item in packages:
            _require(item.get("root") in parsed, "package_root_unknown", str(item.get("distribution")))
            clean = {k: item[k] for k in ("distribution", "version", "root", "top_level")}
            clean["top_level"] = sorted(set(clean["top_level"]))
            digest, count = package_census(parsed[clean["root"]], clean, suffixes)
            package_entries.append({**clean, "census_sha256": digest, "census_files": count})
        package_entries.sort(key=lambda p: p["distribution"].lower())
        package_tops = frozenset(t for p in package_entries for t in p["top_level"])
        approved: dict[str, set[str]] = {}
        for item in dynamic:
            approved.setdefault(item["module"], set()).add(item["target"])
        captured: dict[str, tuple[bytes, bool, str]] = {}
        queue = [entry_module]
        while queue:
            module = queue.pop()
            if module in captured:
                continue
            found = _discover(module, parsed, suffixes)
            _require(found is not None, "unresolved_import", module)
            alias, package = found
            data = _read_file(parsed[alias], _derived_path(module, package), MAX_MODULE_BYTES)
            captured[module] = (data, package, alias)
            for ancestor in _ancestors(module):
                queue.append(ancestor)
            scan = scan_source(data, module, package)
            _require(not scan.rejections, scan.rejections[0].partition(":")[0] if scan.rejections else "", scan.rejections[0] if scan.rejections else "")
            names = [base for base, _ in scan.imports if base] + list(scan.dynamic)
            for base, items in scan.imports:
                names.extend(base + "." + i for i in items if base and i != "*")
            for target in names:
                top = target.partition(".")[0]
                if top in package_tops or top in stdlib:
                    continue
                for prefix in [*_ancestors(target), target]:
                    if _discover(prefix, parsed, suffixes) is not None:
                        queue.append(prefix)
        owned = {m: (d, p) for m, (d, p, _) in captured.items()}
        edges, from_candidates, _, _ = analyse(owned, entry=entry_module, entry_callable=entry_callable, stdlib_names=stdlib,
                                               package_tops=package_tops,
                                               approved_dynamic={k: frozenset(v) for k, v in approved.items()})
        for owner, sub in from_candidates:
            _require(not _importable_somewhere(sub, parsed, suffixes), "unlisted_module", owner + "->" + sub)
        modules = []
        for module in sorted(captured):
            data, package, alias = captured[module]
            _resolution_check(parsed, alias, module, package, suffixes)
            modules.append({"name": module, "root": alias, "path": _derived_path(module, package), "sha256": _sha(data),
                            "bytes": len(data), "package": package})
        manifest = {"version": VERSION, "name": name, "entry": {"module": entry_module, "callable": entry_callable},
                    "modules": modules, "edges": edges,
                    "dynamic": sorted(({"module": m, "target": t} for m, ts in approved.items() for t in ts),
                                      key=lambda d: (d["module"], d["target"])),
                    "dependency_operations": sorted(({"importer": d["importer"], "form": d["form"], "module": d["module"]}
                                                     for d in dependency_operations),
                                                    key=lambda d: (d["importer"], d["form"], d["module"])),
                    "packages": package_entries, "runtime": json.loads(json.dumps(runtime["pins"]))}
        validate_manifest(manifest)
        if discover_natives:
            # 1. discovery: import the entry once with native pins not yet enforced and record what is mapped
            verified = _verify_core(manifest, parsed, python, work, files, runtime)
            report = _import_pass(verified, "import", work)
            _require(isinstance(report["mapped"], list), "native_inventory_unavailable", "discovery")
            paths = {n["path"] for n in manifest["runtime"]["natives"]} | set(report["mapped"])
            manifest["runtime"]["natives"] = _native_rows(sorted(paths))
            validate_manifest(manifest)
            # 2. confirmation: the same import under the final pins with full native-closure enforcement
            confirmed = _verify_core(manifest, parsed, python, work, files, runtime)
            _import_pass(confirmed, "confirm", work)
        return manifest
    finally:
        if not _bounded_rmtree(work, _Operation.cleanup_left(), work_identity):   # a discovery tool: a leftover is no verification verdict
            _keep_orphan(work, work_identity)


def _import_pass(verified: "VerifiedClosure", mode: str, work: str) -> dict[str, Any]:
    execution, nonce, header_sha, _ = _launch(verified, {}, None, mode, 120.0, work)
    report = _accept_report(execution, nonce, header_sha, verified, mode)
    if report["violations"] or report["exception_type"]:
        _reject("closure_import_failed", (report["violations"] or [report["exception_type"]])[0][:100])
    declared = {_operation_entry(d) for d in verified.manifest["dependency_operations"]}
    undeclared = sorted(r for r in report["refused"] if r.startswith(DEPENDENCY_OPERATION_PREFIX) and r not in declared)
    _require(not undeclared, "dependency_operation_undeclared", undeclared[0][len(DEPENDENCY_OPERATION_PREFIX):][:100] if undeclared else "")
    return report


def _operation_entry(item: Mapping[str, str]) -> str:
    return DEPENDENCY_OPERATION_PREFIX + ":".join((item["importer"], item["form"], item["module"]))


# --------------------------------------------------------------------------- execution

@dataclass(frozen=True)
class InputSpec:
    """A verifier input captured once, hash-checked against an externally supplied digest."""

    root: Path | str
    relative: str
    sha256: str


@dataclass
class ClosureRun:
    status: str
    reason: str
    receipt: dict[str, Any]

    @property
    def passed(self) -> bool:
        return self.status == "PASS"


def _frame(verified: VerifiedClosure, inputs: Mapping[str, bytes], params: Any, nonce: str, prefix: str, mode: str) -> tuple[bytes, str]:
    """``params`` must already be the canonical snapshot: the frame, ``params_sha256`` and the receipt share one capture."""
    manifest, probe, pins = verified.manifest, verified.probe, verified.pins
    modules, blobs = [], []
    for item in manifest["modules"]:
        data = verified.modules[item["name"]]
        modules.append([item["name"], item["root"], item["path"], item["package"], item["sha256"], len(data),
                        verified.sites[item["name"]]])
        blobs.append(data)
    input_rows = []
    for name in sorted(inputs):
        input_rows.append([name, len(inputs[name]), _sha(inputs[name])])
        blobs.append(inputs[name])
    header = {
        "nonce": nonce, "mode": mode, "entry": [manifest["entry"]["module"], manifest["entry"]["callable"]],
        "params": params, "params_sha256": canonical_digest(params), "manifest_sha256": verified.manifest_sha256,
        "release_sha256": verified.release_sha256 or "", "modules": modules, "inputs": input_rows, "table": verified.table,
        "dep_ops": [[d["importer"], d["form"], d["module"]] for d in manifest["dependency_operations"]],
        "expect": {"pycache_prefix": prefix, "version": probe["version"], "cache_tag": probe["cache_tag"],
                   "bootstrap_sha256": _sha(verified.files["trace_gc/verifier_closure_bootstrap.py"]),
                   "executable": probe["executable"], "startup_modules_sha256": pins["startup_modules_sha256"],
                   "preload_modules_sha256": pins["preload_modules_sha256"], "sys_path": probe["sys_path"],
                   "meta_path": probe["meta_path"], "stdlib_module_names": probe["stdlib_module_names"],
                   "exe_sha256": pins["executable_sha256"], "base_exe_sha256": pins["base_executable_sha256"],
                   "startup_files": verified.startup_rows,
                   "natives": [[n["path"], n["sha256"]] for n in pins["natives"]]}}
    raw = marshal.dumps(header, 4)
    return FRAME_MAGIC + len(raw).to_bytes(8, "big") + raw + b"".join(blobs), _sha(raw)


def _launch(verified: VerifiedClosure, captured: Mapping[str, bytes], params: Any, mode: str, timeout: float, work: str):
    _require(mode in ("import", "confirm", "run"), "invalid_arguments", "mode")
    program = verified.files["trace_gc/verifier_closure_bootstrap.py"]

    def prepare():
        directories = _fresh_dirs(work)
        token = secrets.token_hex(16)
        frame, header_sha = _frame(verified, captured, params, token, directories[0], mode)
        command, stream = _launch_arguments(verified.python, directories[0], program, frame)   # hashes included: one phase
        return directories, token, header_sha, command, stream

    (prefix, cwd), nonce, header_sha, command, stream = _Operation.bounded("frame", prepare)
    execution = _execute(command, cwd, stream, _Operation.remaining(timeout), MAX_REPORT_BYTES + 4096, MAX_STDERR_BYTES)
    return execution, nonce, header_sha, prefix


def _capture_inputs(specs: Sequence[tuple[str, str, str, str]]) -> dict[str, bytes]:
    """Read each ``(name, root, relative, sha256)`` spec once, hash-checked against its externally supplied digest."""
    captured: dict[str, bytes] = {}
    total = 0
    for name, root, relative, sha256 in specs:
        data = _read_file(_root(root, "input"), relative, MAX_INPUT_BYTES)
        total += len(data)
        _require(total <= MAX_INPUT_BYTES, "inputs_too_large")
        _require(_sha(data) == sha256, "input_hash_mismatch", name)
        captured[name] = data
    return captured


def _parse_report(stdout: bytes, nonce: str) -> dict[str, Any] | None:
    """Exactly one bounded, strict-JSON result line carrying ``nonce``; any other output is a protocol failure."""
    marker = (RESULT_PREFIX + nonce + " ").encode("ascii")
    lines = [line for line in stdout.split(b"\n") if line]
    if len(lines) != 1 or not lines[0].startswith(marker) or len(lines[0]) > MAX_REPORT_BYTES:
        return None
    try:
        value = canonical_loads(lines[0][len(marker):].decode("ascii"))
    except (ContractError, UnicodeError):
        return None
    return value if isinstance(value, dict) else None


_REPORT_KEYS = {"protocol", "status", "mode", "nonce", "header_sha256", "bootstrap_sha256", "manifest_sha256", "release_sha256", "entry", "result",
                "result_error", "exception_type", "violations", "refused", "loaded", "runtime_modules", "inputs", "mapped",
                "native_plan", "stdout_bytes", "stderr_bytes", "stdout_sha256", "stderr_sha256", "exe_sha256", "flags"}


def _accept_report(execution: Execution, nonce: str, header_sha: str, verified: VerifiedClosure, mode: str) -> dict[str, Any]:
    """Validate process outcome and report shape/bindings; raises ``ClosureRejected`` with a failure class code."""
    if execution.cleanup_failed:
        _reject("containment_cleanup_failed")
    if execution.launch_error == "containment_attach_failed":
        _reject("containment_attach_failed")
    if execution.launch_error:
        _reject("execution_launch_failed")
    if execution.timed_out:
        _reject("execution_timeout")
    if execution.overflow:
        _reject("protocol_output_overflow", execution.overflow)
    if execution.descendants:
        _reject("containment_unresolved_descendants")
    report = _parse_report(execution.stdout, nonce)
    if report is None:
        _reject("protocol_no_valid_result", "exit_%s" % execution.returncode)
    if report.get("status") == "BOOTSTRAP_REJECT":
        _reject("runtime_bootstrap_reject", str(report.get("reason"))[:60])
    _require(set(report) == _REPORT_KEYS and report["protocol"] == PROTOCOL and report["status"] == "RESULT"
             and report["mode"] == mode, "protocol_report_shape")
    _require(report["nonce"] == nonce and report["header_sha256"] == header_sha, "protocol_request_binding")
    _require(report["bootstrap_sha256"] == _sha(verified.files["trace_gc/verifier_closure_bootstrap.py"]),
             "protocol_request_binding", "bootstrap")
    _require(report["manifest_sha256"] == verified.manifest_sha256 and report["release_sha256"] == (verified.release_sha256 or "")
             and report["entry"] == [verified.manifest["entry"]["module"], verified.manifest["entry"]["callable"]],
             "protocol_request_binding", "manifest_release_entry")
    _require(isinstance(report["violations"], list) and all(isinstance(v, str) for v in report["violations"])
             and isinstance(report["refused"], list) and isinstance(report["loaded"], dict)
             and isinstance(report["runtime_modules"], list) and isinstance(report["inputs"], dict), "protocol_report_shape")
    _require(len(report["refused"]) <= 200 and all(
        isinstance(r, str) and r.startswith(DEPENDENCY_OPERATION_PREFIX) and len(r) <= 120 for r in report["refused"]),
        "protocol_report_shape", "refused")
    if mode != "import":
        declared = {_operation_entry(d) for d in verified.manifest["dependency_operations"]}
        _require(set(report["refused"]) <= declared, "dependency_operation_undeclared",
                 min(set(report["refused"]) - declared, default="")[len(DEPENDENCY_OPERATION_PREFIX):][:100])
    _require(isinstance(report["mapped"], list) and len(report["mapped"]) <= MAX_MAPPED
             and all(isinstance(p, str) and 0 < len(p) <= 4096 for p in report["mapped"]),
             "native_inventory_unavailable", "mapped")
    _require(len(report["runtime_modules"]) <= MAX_RUNTIME_ROWS and all(
        isinstance(r, list) and len(r) == 2 and isinstance(r[0], str) and MODULE.match(r[0]) is not None and _is_sha(r[1])
        for r in report["runtime_modules"]), "protocol_report_shape", "runtime_modules")
    pinned = {(n["path"], n["sha256"]) for n in verified.pins["natives"]}
    plan = report["native_plan"]
    _require(isinstance(plan, list) and len(plan) <= MAX_NATIVES and all(
        isinstance(r, list) and len(r) == 2 and isinstance(r[0], str) and _is_sha(r[1]) and (r[0], r[1]) in pinned
        for r in plan) and plan == sorted(plan) and len({r[0] for r in plan}) == len(plan),
        "protocol_report_shape", "native_plan")
    _require(execution.returncode == 0, "protocol_exit_status", "exit_%s" % execution.returncode)
    return report


def _binding(receipt: Mapping[str, Any]) -> str:
    """Digest of EVERY receipt field except the digest itself.

    This is an unkeyed integrity binding: it detects field edits in a stored receipt but does not prove who produced
    it.  Provenance needs an external signature or a trusted channel (see the contract document).
    """
    return _direct_binding(receipt)


def _direct_binding(receipt: Mapping[str, Any]) -> str:
    """The binding computation itself; the last-resort safety receipt is bound through this one function only."""
    return canonical_digest({k: v for k, v in receipt.items() if k != "binding_sha256"})


def _digest_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) and len(value) == 64 and SHA.match(value) is not None else None


def _attempt(end: float, function, *args):
    """Run ``function`` on a helper thread until the monotonic time ``end``: ``("done", value)``, ``("error", exception)`` or
    ``("late", None)``.  For steps that touch only the data they are handed (serialization, digests): a late completion is
    discarded and the helper owns no resource, so nothing further is owed when it is abandoned."""
    box: dict[str, Any] = {}
    finished = threading.Event()

    def worker():
        try:
            box["value"] = function(*args)
        except BaseException as exc:   # noqa: BLE001 - reported to the caller as an error outcome
            box["error"] = exc
        finally:
            finished.set()

    threading.Thread(target=worker, daemon=True, name="pvc-attempt").start()
    if not finished.wait(max(0.0, end - time.monotonic())):
        return "late", None
    if "error" in box:
        return "error", box["error"]
    return "done", box["value"]


def _receipt(**fields: Any) -> dict[str, Any]:
    receipt: dict[str, Any] = {
        "version": RECEIPT_VERSION, "status": "REJECTED", "reason": "not_started", "failure_class": "arguments",
        "manifest_sha256": None, "release_sha256": None, "implementation": None, "implementation_source": None,
        "runtime": None, "runtime_protection": None,
        "closure": None, "inputs": {}, "params_sha256": None, "request": None, "verifier": None, "loaded": None,
        "violations": [], "refused": [], "process": None, "post_checks": None, "evidence": None,
        "parent_sys_modules_collisions": [], "binding_sha256": None}
    receipt.update(fields)
    return receipt


def _consistent_reason(receipt: Mapping[str, Any], reason: str) -> str:
    """``reason`` if the receipt's retained process evidence agrees with it under the SAME rule the validator applies
    (``_cross_check_rejected``), else the neutral ``execution_internal_error:<tail>``, which agrees with any process record.
    A rewrite therefore never produces a reason/process contradiction, and never erases the evidence to avoid one."""
    try:
        _cross_check_rejected({**receipt, "reason": reason})
        return reason
    except Exception:   # noqa: BLE001 - an inconsistent or malformed process record: the neutral reason agrees with any
        return "execution_internal_error:" + reason.partition(":")[0][:60]


def _to_rejection(receipt: dict[str, Any], reason: str) -> None:
    """Turn ``receipt`` into a REJECTED one, dropping the result-bearing fields (they are what failed) but KEEPING the
    process and post-check evidence: the reason is made consistent with it (``_consistent_reason``), never the reverse."""
    reason = _consistent_reason(receipt, reason)
    receipt.update(status="REJECTED", reason=reason, failure_class=failure_class(reason.partition(":")[0]), verifier=None,
                   loaded=None, violations=[], refused=[], evidence=None)


def _withhold_content(receipt: dict[str, Any]) -> None:
    """A REJECTED receipt that is not canonical: drop the result-bearing content, keep its causal reason and its process
    evidence, and record that content was withheld."""
    receipt.update(verifier=None, loaded=None, violations=[], refused=["finalization_content_withheld"], evidence=None)


def _safe_reason(reason: Any) -> str:
    """A short, canonical, code-shaped reason: anything that is not encodable or too long becomes a neutral internal one."""
    try:
        if isinstance(reason, str) and 0 < len(reason) <= 200:
            reason.encode("utf-8", errors="strict")
            return reason
    except UnicodeError:
        pass
    return "execution_internal_error:reason_not_canonical"


def _minimal_rejection(receipt: Mapping[str, Any]) -> dict[str, Any]:
    """The last-resort safety receipt, a fully VALID v1 rejection: fixed fields only (the already validated digests, a
    short canonical reason and its class), truthful (REJECTED with the receipt's own causal reason; ``finalization_fallback``
    recorded in ``refused``; no process claim, which the validator accepts for any reason) and independent of any content
    the caller or the child produced, so it is canonical and of constant size by construction."""
    reason = receipt["reason"] if receipt["status"] == "REJECTED" else "operation_deadline_exceeded:seal:blocked"
    reason = _safe_reason(reason)
    return _receipt(status="REJECTED", reason=reason, failure_class=failure_class(reason.partition(":")[0]),
                    manifest_sha256=_digest_or_none(receipt.get("manifest_sha256")),
                    release_sha256=_digest_or_none(receipt.get("release_sha256")),
                    params_sha256=_digest_or_none(receipt.get("params_sha256")), refused=["finalization_fallback"])


def _safety_binding(minimal: Mapping[str, Any]) -> str:
    """Bind the safety receipt on the calling thread.  This is the one inline computation of finalization and it is bounded
    by construction: ``_minimal_rejection`` has a fixed shape (three 64-hex digests, one reason of at most 200 characters,
    one fixed ``refused`` entry), the computation touches no file, no process and no caller object, and it cannot recurse."""
    return canonical_digest({k: v for k, v in minimal.items() if k != "binding_sha256"})


def _finalize_window(operation: "_Operation | None") -> float:
    """End of the ONE finalization window: ``FINALIZE_GRACE`` from now, never past ``operation.finalize_end`` (cleanup
    deadline + ``FINALIZE_GRACE``), and at least ``FINALIZE_FLOOR`` so a sealing attempt always gets to run once."""
    now = time.monotonic()
    end = now + FINALIZE_GRACE if operation is None else min(now + FINALIZE_GRACE, operation.finalize_end)
    return max(end, now + FINALIZE_FLOOR)


def _seal(receipt: dict[str, Any], within_deadline: bool = False) -> None:
    """Bind the receipt; never raises, never blocks past its window, and never leaves a verdict that was not sealed in time.

    Acceptance (a PASS/HOLD, ``within_deadline``): serialization is bounded by the OPERATION deadline and checked again
    after it completed (a seal that finishes late is no seal); a blocked, late or non-canonical seal turns the verdict into
    a REJECTED receipt of the true reason.  Rejection: the full receipt is sealed within the first half of the finalization
    window (one retry on a content-withheld receipt if it is not canonical: its causal reason and process evidence stay,
    so the retry can never seal a reason/process contradiction); if that fails the fixed-field safety receipt
    (``_minimal_rejection``) is sealed through ``_direct_binding`` within the rest of the window; if even that does not
    finish, the same safety receipt is bound inline by ``_safety_binding`` (constant size, no helper, no recursion).  The
    result is therefore ALWAYS a valid, sealed v1 receipt of a truthful rejection, and nothing is retried outside the
    window."""
    operation = _Operation.current()
    if within_deadline and operation is not None and receipt["status"] in ("PASS", "HOLD"):
        state, value = _attempt(operation.deadline, _binding, dict(receipt))
        if state == "done" and time.monotonic() < operation.deadline:
            receipt["binding_sha256"] = value
            return
        if state == "error" and isinstance(value, ContractError):
            reason = "protocol_receipt_not_canonical"
        elif state == "error":
            reason = "execution_internal_error:" + type(value).__name__[:40]
        else:
            reason = "operation_deadline_exceeded:seal:" + ("late" if state == "done" else "blocked")
        operation.cancelled.set()
        _to_rejection(receipt, reason)
    end = _finalize_window(operation)
    start = time.monotonic()
    half = start + (end - start) / 2
    state, value = _attempt(half, _binding, dict(receipt))
    if state == "error" and "finalization_content_withheld" not in receipt["refused"]:
        if receipt["status"] == "REJECTED":
            _withhold_content(receipt)
        else:   # a verdict that cannot be serialized: the protocol failure, consistent with the (clear) process record
            _to_rejection(receipt, "protocol_receipt_not_canonical")
        state, value = _attempt(half, _binding, dict(receipt))
    if state == "done":
        receipt["binding_sha256"] = value
        return
    minimal = _minimal_rejection(receipt)
    state, value = _attempt(end, _direct_binding, minimal)
    minimal["binding_sha256"] = value if state == "done" else _safety_binding(minimal)
    receipt.clear()
    receipt.update(minimal)


def _capture_arguments(manifest, expected_manifest_sha256, expected_release_sha256, roots, python, inputs, params, timeout,
                       embed_result, allow_unprotected_runtime, protection_policy, expected_module_table_sha256, work_dir):
    """``(request, work, error)``: EVERY caller-controlled value is read or copied here, as one phase for
    ``_Operation.bounded`` (the manifest and params are serialized and canonicalized, the ``python`` and ``work_dir`` paths
    are converted with ``os.fspath``, the module-table commitment is validated); it builds new objects only and mutates
    nothing shared, so a late result is simply dropped.  Nothing the caller supplied is touched afterwards."""
    try:
        request = _snapshot(manifest, expected_manifest_sha256, expected_release_sha256, roots, python, inputs, params, timeout,
                            embed_result, allow_unprotected_runtime, protection_policy, expected_module_table_sha256)
        work = None if work_dir is None else os.fspath(work_dir)
        _require(work is None or isinstance(work, str), "invalid_arguments", "work_dir_type")
        return request, work, None
    except Exception as exc:   # noqa: BLE001 - handed to the caller, which records it as the truthful rejection
        return None, None, exc


@dataclass(frozen=True)
class _Request:
    """One immutable capture of every caller-supplied argument; nothing later re-reads the caller's objects."""

    manifest: dict[str, Any]
    expected_manifest_sha256: str
    expected_release_sha256: str
    roots: dict[str, str]
    python: str | None
    specs: tuple[tuple[str, str, str, str], ...]
    params: Any
    timeout: float
    embed_result: bool
    allow_unprotected_runtime: bool
    protection_policy: ProtectionPolicy | None = None
    expected_module_table_sha256: str | None = None


def _snapshot(manifest, expected_manifest_sha256, expected_release_sha256, roots, python, inputs, params, timeout,
              embed_result, allow_unprotected_runtime, protection_policy=None, expected_module_table_sha256=None) -> _Request:
    """Validate and copy all arguments before any probe, census, hashing or child process exists."""
    timeout = validate_timeout(timeout)
    _require(expected_module_table_sha256 is None or (isinstance(expected_module_table_sha256, str)
                                                      and SHA.match(expected_module_table_sha256) is not None),
             "invalid_arguments", "module_table_digest")
    _require(type(embed_result) is bool and type(allow_unprotected_runtime) is bool, "invalid_arguments", "flag_type")
    _require(protection_policy is None or isinstance(protection_policy, ProtectionPolicy), "invalid_arguments", "protection_policy")
    _require(isinstance(expected_manifest_sha256, str) and SHA.match(expected_manifest_sha256) is not None, "expected_digest_required")
    _require(isinstance(expected_release_sha256, str) and SHA.match(expected_release_sha256) is not None, "expected_release_required")
    _require(isinstance(roots, Mapping) and 0 < len(roots) <= 32, "roots_required")
    root_copy = {}
    for alias, path in roots.items():
        _require(isinstance(alias, str), "root_alias_invalid", str(alias)[:40])
        root_copy[alias] = os.fspath(path)
    _require(python is None or isinstance(python, (str, os.PathLike)), "invalid_arguments", "python_type")
    specs = []
    if inputs is not None:
        _require(isinstance(inputs, Mapping) and len(inputs) <= MAX_INPUTS, "inputs_invalid")
        for name, spec in sorted(inputs.items(), key=lambda item: str(item[0])):
            _require(isinstance(name, str) and INPUT_NAME.match(name) is not None, "input_name_invalid", str(name)[:40])
            _require(isinstance(spec, InputSpec) and isinstance(spec.sha256, str) and SHA.match(spec.sha256) is not None
                     and isinstance(spec.relative, str), "input_digest_required", name)
            _check_relative(spec.relative, "input_path_invalid")   # cheap syntax check: before any probe or census
            specs.append((name, os.fspath(spec.root), spec.relative, spec.sha256))
    try:
        frozen_params = canonical_loads(canonical_dumps(params))
    except ContractError:
        _reject("params_not_canonical")
    return _Request(json.loads(json.dumps(manifest)), expected_manifest_sha256, expected_release_sha256, root_copy,
                    None if python is None else os.path.abspath(os.fspath(python)), tuple(specs), frozen_params, timeout, embed_result,
                    allow_unprotected_runtime, protection_policy, expected_module_table_sha256)


def run_verifier(manifest: Mapping[str, Any], expected_manifest_sha256: str, *, expected_release_sha256: str,
                 roots: Mapping[str, Path | str], python: str | os.PathLike | None = None,
                 inputs: Mapping[str, InputSpec] | None = None, params: Any = None, timeout: float = 120.0,
                 work_dir: str | os.PathLike | None = None, embed_result: bool = True,
                 allow_unprotected_runtime: bool = False, protection_policy: ProtectionPolicy | None = None,
                 expected_module_table_sha256: str | None = None) -> ClosureRun:
    """Authenticate, verify, then execute one verifier from its closure; never raises for contract violations.

    ``expected_module_table_sha256`` (optional) makes a live module map that differs from the reviewed one a
    ``runtime_module_table_mismatch`` rejection before the first interpreter process; the receipt always records the
    commitment, and acceptance (``verify_receipt``) requires the reviewed map itself.

    ``timeout`` is the deadline of the WHOLE operation (probe, protection inspection, census, hashing, launch,
    execution and post-checks); only the bounded cleanup after it expires may follow.

    ``PASS``/``HOLD`` are returned only for the verifier's own genuine result when every integrity check held.  Every
    closure, runtime, input, protocol or containment failure, a verifier exception and a timeout are ``REJECTED``
    with a ``failure_class`` that distinguishes them from a genuine verifier ``HOLD``.  Arguments (including the
    finite ``0 < timeout <= MAX_TIMEOUT`` and the syntax of every input path) are validated and captured before any
    interpreter, census or child exists.  Runtime write-protection is required (see ``verify_closure``) unless the
    caller explicitly passes ``allow_unprotected_runtime=True``, which no acceptance check will take.
    """
    receipt = _receipt(manifest_sha256=_digest_or_none(expected_manifest_sha256),
                       release_sha256=_digest_or_none(expected_release_sha256))
    try:
        seconds = validate_timeout(timeout)   # arithmetic on one number: the only thing that must precede the operation
    except ClosureRejected as exc:
        _fail_receipt(receipt, exc)
        _seal(receipt)
        return ClosureRun(receipt["status"], receipt["reason"], receipt)
    with _Operation(seconds) as operation:
        try:
            verdict = None
            try:
                # argument capture (copying and canonicalizing the caller's manifest and params) is a bounded phase of the
                # operation like every other: a capture that blocks ends the run at the deadline, and its late result is dropped
                request, caller_work, error = _Operation.bounded(
                    "arguments", _capture_arguments, manifest, expected_manifest_sha256, expected_release_sha256, roots,
                    python, inputs, params, timeout, embed_result, allow_unprotected_runtime, protection_policy,
                    expected_module_table_sha256, work_dir)
                if error is not None:
                    raise error
                # the scratch directory is created inside the operation, through its ledger: a creation that finishes
                # late is removed by the creating thread itself
                work = _Operation.bounded("run_dir", _scratch_mkdtemp, "pvc-run-") if caller_work is None else caller_work
                verdict = _run(request, work, receipt)
            except Exception as exc:   # an unforeseen defect is a truthful, sealed REJECTED receipt, never an escaping traceback
                _fail_receipt(receipt, exc)
            # required cleanup first (every step shares the ONE cleanup deadline), then the final applicable deadline,
            # then the verdict, then the seal: a PASS/HOLD exists only after all of them held
            removed = operation.scratch.release_all(_Operation.cleanup_left())
            if verdict is not None:
                if not removed:
                    _settle_cleanup(receipt, False, pending=True)
                else:
                    try:
                        _Operation.tick("final")
                        receipt["verifier"] = verdict.verifier
                        receipt.update(status=verdict.status, reason=verdict.reason, failure_class=None)
                    except ClosureRejected as exc:
                        _fail_receipt(receipt, exc)
            else:
                _settle_cleanup(receipt, removed)
            _seal(receipt, within_deadline=receipt["status"] in ("PASS", "HOLD"))
        finally:
            operation.scratch.release_all(_Operation.cleanup_left())   # idempotent; covers an escaping BaseException
    return ClosureRun(receipt["status"], receipt["reason"], receipt)


def _fail_receipt(receipt: dict[str, Any], exc: Exception) -> None:
    """Record ``exc`` as the truthful REJECTED outcome of the run."""
    if isinstance(exc, ClosureRejected):
        receipt.update(status="REJECTED", reason=exc.code + (":" + exc.detail if exc.detail else ""),
                       failure_class=failure_class(exc.code), verifier=None)
    elif isinstance(exc, (OSError, ValueError, KeyError, TypeError, ArithmeticError)):
        receipt.update(status="REJECTED", reason="invalid_arguments:" + type(exc).__name__, failure_class="arguments",
                       verifier=None)
    else:
        receipt.update(status="REJECTED", reason="execution_internal_error:" + type(exc).__name__[:40],
                       failure_class="execution", verifier=None, loaded=None, violations=[], refused=[])


def _settle_cleanup(receipt: dict[str, Any], removed: bool, pending: bool = False) -> None:
    """The run's own scratch tree is part of the verdict: a PASS/HOLD is built only if it was verifiably removed.

    The removal happens BEFORE the verdict is applied and the receipt is sealed.  A tree that is still present (or whose
    removal was not confirmed inside the shared cleanup deadline) turns a PASS/HOLD (``pending`` while the genuine result
    has not been applied yet) into ``REJECTED containment_cleanup_failed:work_directory`` with ``process.cleanup_failed``
    set; a receipt that is already REJECTED keeps its own reason and records the leftover in ``refused``.
    """
    if removed:
        return
    if pending or receipt["status"] in ("PASS", "HOLD"):
        if isinstance(receipt.get("process"), dict):
            receipt["process"]["cleanup_failed"] = True
        receipt.update(status="REJECTED", reason="containment_cleanup_failed:work_directory", failure_class="containment",
                       verifier=None)
    elif len(receipt["refused"]) < 50:
        receipt["refused"] = [*receipt["refused"], "work_directory_not_removed"]


class _Stopped(Exception):
    """The caller's budget ended: no further individual removal may be started."""


class _Replaced(Exception):
    """The path no longer is the directory this run created: it is left exactly as it is."""


_DIR_FD_REMOVAL = (hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW") and os.open in os.supports_dir_fd
                   and os.unlink in os.supports_dir_fd and os.rmdir in os.supports_dir_fd
                   and os.stat in os.supports_dir_fd and os.listdir in os.supports_fd)


def _checkpoint(stop: threading.Event) -> None:
    if stop.is_set():
        raise _Stopped()


def _clear_by_fd(fd: int, stop: threading.Event) -> None:
    """POSIX: every entry is resolved relative to a directory descriptor whose identity was verified, and every
    subdirectory is opened ``O_NOFOLLOW`` and re-verified, so a link or a swapped directory is never entered."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    for name in os.listdir(fd):
        _checkpoint(stop)
        try:
            info = os.lstat(name, dir_fd=fd)
        except FileNotFoundError:
            continue
        if stat.S_ISDIR(info.st_mode):
            try:
                child = os.open(name, flags, dir_fd=fd)
            except OSError:
                continue   # swapped for a link or removed since the lstat: left alone
            try:
                if _identity(os.fstat(child)) != _identity(info):
                    continue
                _clear_by_fd(child, stop)
            finally:
                os.close(child)
            _checkpoint(stop)
            try:
                os.rmdir(name, dir_fd=fd)
            except OSError:
                pass
        else:
            _checkpoint(stop)
            try:
                os.unlink(name, dir_fd=fd)
            except OSError:
                pass


def _clear_by_path(path: str, identity: tuple[int, int], stop: threading.Event) -> None:
    """Without descriptor-relative removal (Windows) the directory's identity is re-verified immediately before it is
    listed and each entry is classified by ``lstat``; a link is removed itself and never entered.  The residual race
    between that verification and the individual removal cannot be closed with the standard library."""
    info = os.lstat(path)
    if _link_like(info) or _identity(info) != identity or not stat.S_ISDIR(info.st_mode):
        raise _Replaced()
    with os.scandir(path) as entries:
        names = [entry.name for entry in entries]
    for name in names:
        _checkpoint(stop)
        full = os.path.join(path, name)
        try:
            child = os.lstat(full)
        except FileNotFoundError:
            continue
        if stat.S_ISDIR(child.st_mode) and not _link_like(child):
            try:
                _clear_by_path(full, _identity(child), stop)
            except _Replaced:
                continue
            _checkpoint(stop)
            try:
                os.rmdir(full)
            except OSError:
                pass
        else:
            _checkpoint(stop)
            try:
                os.unlink(full)
            except OSError:
                _checkpoint(stop)   # the failed (possibly blocked) unlink is not a licence to start another removal
                try:
                    os.rmdir(full)   # a directory link on Windows
                except OSError:
                    pass


def _remove_tree(path: str, stop: threading.Event, identity: tuple[int, int] | None = None) -> str:
    """Remove the directory tree ``path`` ONLY while it still is the directory this run created.

    ``identity`` is the ``(st_dev, st_ino)`` recorded at creation (observed now when not given).  A path that is a
    link, not a directory or a different directory is ``"replaced"`` and is left untouched.  ``stop`` is honoured
    BETWEEN individual removals.  Returns ``"removed"`` only when the path is verified absent at the end; a stop, a
    leftover or an unreadable result is ``"unconfirmed"``."""
    try:
        top = os.lstat(path)
    except FileNotFoundError:
        return "removed"
    except OSError:
        return "unconfirmed"
    if _link_like(top) or not stat.S_ISDIR(top.st_mode) or (identity is not None and _identity(top) != identity):
        return "replaced"
    identity = _identity(top)
    try:
        if _DIR_FD_REMOVAL:
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                if _identity(os.fstat(fd)) != identity:
                    raise _Replaced()
                _clear_by_fd(fd, stop)
            finally:
                os.close(fd)
        else:
            _clear_by_path(path, identity, stop)
        _checkpoint(stop)
        try:
            again = os.lstat(path)
        except FileNotFoundError:
            return "removed"
        if _link_like(again) or _identity(again) != identity:
            return "replaced"
        _checkpoint(stop)   # the inspection above may have blocked past the caller's deadline: no new removal then
        os.rmdir(path)
    except _Stopped:
        return "unconfirmed"
    except _Replaced:
        return "replaced"
    except FileNotFoundError:
        pass
    except OSError:
        pass
    try:
        os.lstat(path)
    except FileNotFoundError:
        return "removed"
    except OSError:
        return "unconfirmed"
    return "unconfirmed"


def _bounded_remove(path: str, budget: float, identity: tuple[int, int] | None = None) -> str:
    """Identity-bound removal of ``path`` (``_remove_tree``) including the concluding absence check, all inside ONE helper
    thread the caller waits for at most ``budget`` seconds.

    On expiry the helper is told to stop and the caller regains control; a system call that is blocked inside the helper
    cannot be cancelled, but the helper starts no further individual removal after ``stop`` and never touches a path
    that was replaced.  Returns ``"removed"``, ``"replaced"`` or ``"unconfirmed"`` (timeout included): uncertainty is
    never reported as success.

    There is at most ONE worker per ``(path, identity)``: while a worker that an earlier caller abandoned (or another
    caller started) is still in flight, a new call waits for it inside its own budget and never starts a duplicate; once it
    has ended, the call starts a fresh worker.  Repeated retries of a stuck removal therefore cannot pile up threads."""
    end = time.monotonic() + max(0.0, budget)
    key = (path, identity)
    while True:
        with _REMOVING_LOCK:
            current = _REMOVING.get(key)
            mine = current is None
            if mine:
                stop, finished, box = threading.Event(), threading.Event(), {}
                _REMOVING[key] = (stop, finished)
            else:
                stop, finished = current
        if mine:
            def worker(stop=stop, finished=finished, box=box):
                try:
                    box["outcome"] = _remove_tree(path, stop, identity)
                except BaseException:   # noqa: BLE001 - an unreadable result is "unconfirmed"
                    box["outcome"] = "unconfirmed"
                finally:
                    with _REMOVING_LOCK:
                        _REMOVING.pop(key, None)
                    finished.set()
            threading.Thread(target=worker, daemon=True, name="pvc-cleanup").start()
        if not finished.wait(max(0.0, end - time.monotonic())):
            if mine:
                stop.set()
            return "unconfirmed"
        if mine:
            outcome = box.get("outcome")
            return outcome if outcome in ("removed", "replaced") else "unconfirmed"
        if time.monotonic() >= end:
            return "unconfirmed"


_REMOVING: dict[tuple[str, tuple[int, int] | None], tuple[threading.Event, threading.Event]] = {}
_REMOVING_LOCK = threading.Lock()


def _bounded_rmtree(path: str, budget: float, identity: tuple[int, int] | None = None) -> bool:
    """``True`` only when ``path`` is verified absent after a bounded, identity-bound removal (see ``_bounded_remove``)."""
    return _bounded_remove(path, budget, identity) == "removed"


def _evidence(report: Mapping[str, Any], verified: VerifiedClosure) -> dict[str, Any]:
    """Self-consistent, individually checkable identities of what the child reported (shape already validated)."""
    by_name = dict((name, sha) for name, sha in report["runtime_modules"])
    rows = sorted([name, sha] for name, sha in by_name.items())
    mapped = sorted(set(report["mapped"]))
    table = {row[0]: row for row in verified.table}
    loaded_native = report["loaded"].get("native") if isinstance(report["loaded"], dict) else None
    native = sorted([name, table[name][2], table[name][3]] for name in (loaded_native or {})
                    if isinstance(name, str) and name in table and by_name.get(name) == table[name][3])
    return {"report_sha256": canonical_digest(report), "runtime_modules": len(rows),
            "module_table_sha256": module_table_digest(verified.table),
            "runtime_modules_sha256": canonical_digest(rows), "runtime_rows": rows, "native_files": native,
            "native_plan": [list(r) for r in report["native_plan"]],
            "mapped": mapped, "mapped_sha256": canonical_digest(mapped)}


def _recheck_closure(verified: "VerifiedClosure") -> None:
    for item in verified.manifest["modules"]:
        _Operation.tick("post_checks")
        _require(_read_file(verified.roots[item["root"]], item["path"], MAX_MODULE_BYTES) == verified.modules[item["name"]],
                 "closure_module_changed_during_execution", item["name"])
    for item in verified.manifest["packages"]:
        _Operation.tick("post_checks")
        digest, _ = package_census(verified.roots[item["root"]], item, verified.probe["extension_suffixes"])
        _require(digest == item["census_sha256"], "package_changed_during_execution", item["distribution"])


def _recheck_inputs(specs: Sequence[tuple[str, str, str, str]], captured: Mapping[str, bytes]) -> None:
    for name, root, relative, _ in specs:
        _Operation.tick("post_checks")
        _require(_read_file(_root(root, "input"), relative, MAX_INPUT_BYTES) == captured[name],
                 "input_changed_during_execution", name)


@dataclass(frozen=True)
class _Verdict:
    """The verifier's genuine result, NOT yet applied to the receipt: ``run_verifier`` applies it only after the run's
    required cleanup and only if the operation deadline still holds."""

    status: str
    reason: str
    verifier: dict[str, Any]


def _run_facts(verified: VerifiedClosure, captured: Mapping[str, bytes]) -> dict[str, Any]:
    """Receipt facts derived from data (implementation and input digests, closure rows, parent-collision names) as ONE
    bounded phase; builds new objects only."""
    names = {m["name"] for m in verified.manifest["modules"]}
    return {
        "implementation": [{"path": p, "sha256": _sha(d), "bytes": len(d)} for p, d in sorted(verified.files.items())],
        "closure": {"modules": [{"name": m["name"], "sha256": m["sha256"], "bytes": m["bytes"]} for m in verified.manifest["modules"]],
                    "packages": [{"distribution": p["distribution"], "version": p["version"], "census_sha256": p["census_sha256"]}
                                 for p in verified.manifest["packages"]]},
        "inputs": {n: {"sha256": _sha(d), "bytes": len(d)} for n, d in captured.items()},
        "input_digests": {n: _sha(d) for n, d in captured.items()},
        "collisions": sorted(n for n in sys.modules if n in names)}


def _check_report_rows(report: Mapping[str, Any], verified: VerifiedClosure) -> None:
    """The child's reported runtime rows, loaded counts and natives against the verified table (one bounded phase)."""
    table_hashes = {row[0]: row[3] for row in verified.table}
    rows = report["runtime_modules"]
    _require(all(isinstance(r, list) and len(r) == 2 and isinstance(r[0], str) and isinstance(r[1], str)
                 and table_hashes.get(r[0]) == r[1] for r in rows) and len({r[0] for r in rows}) == len(rows),
             "runtime_loaded_module_mismatch")
    _validate_loaded(report["loaded"], modules={m["name"]: m["sha256"] for m in verified.manifest["modules"]},
                     distributions={p["distribution"] for p in verified.manifest["packages"]}, runtime_modules=len(rows),
                     entry=verified.manifest["entry"]["module"], code="closure_loaded_module_mismatch")
    _require(set(report["loaded"]["native"]) <= {r[0] for r in rows}
             and all(table_hashes.get(n) == h for n, h in report["loaded"]["native"].items()), "runtime_loaded_module_mismatch", "native")


def _run(request: _Request, work: str, receipt: dict[str, Any]) -> "_Verdict":
    receipt["params_sha256"] = _Operation.bounded("params_digest", canonical_digest, request.params)
    verified = verify_closure(request.manifest, request.expected_manifest_sha256,
                              expected_release_sha256=request.expected_release_sha256, roots=request.roots,
                              python=request.python, work=work, allow_unprotected_runtime=request.allow_unprotected_runtime,
                              protection_policy=request.protection_policy,
                              expected_module_table_sha256=request.expected_module_table_sha256)
    params, inputs_spec, timeout = request.params, request.specs, request.timeout
    captured = _Operation.bounded("inputs", _capture_inputs, inputs_spec)
    facts = _Operation.bounded("facts", _run_facts, verified, captured)   # every hash and comprehension over data: one phase
    receipt["implementation"] = facts["implementation"]
    receipt["implementation_source"] = verified.implementation_source
    receipt.update(runtime=dict(verified.pins), runtime_protection=verified.exposure, closure=facts["closure"],
                   inputs=facts["inputs"], parent_sys_modules_collisions=facts["collisions"])
    execution, nonce, header_sha, prefix = _launch(verified, captured, params, "run", timeout, work)
    receipt["request"] = {"nonce": nonce, "header_sha256": header_sha}
    receipt["process"] = {"exit_code": execution.returncode, "timed_out": execution.timed_out,
                          "stdout_bytes": len(execution.stdout), "stderr_bytes": execution.stderr_bytes,
                          "stderr_sha256": execution.stderr_sha256, "descendants": execution.descendants,
                          "cleanup_failed": execution.cleanup_failed, "overflow": execution.overflow,
                          "timeout_ms": timeout_ms(timeout), "containment": execution.containment}
    post = {"closure_unchanged": False, "inputs_unchanged": False, "runtime_unchanged": False, "bytecode_dir_empty": False}
    receipt["post_checks"] = post
    report = _Operation.bounded("report", _accept_report, execution, nonce, header_sha, verified, "run")
    receipt["evidence"] = _Operation.bounded("evidence", _evidence, report, verified)
    _Operation.bounded("post_closure", _recheck_closure, verified)
    post["closure_unchanged"] = True
    _Operation.bounded("post_inputs", _recheck_inputs, inputs_spec, captured)
    post["inputs_unchanged"] = True
    try:
        _Operation.bounded("post_runtime", authenticate_runtime, verified.python, verified.pins)
    except ClosureRejected as exc:
        if exc.code == "operation_deadline_exceeded":
            raise
        _reject("runtime_changed_during_execution", (exc.detail or exc.code)[:60])
    post["runtime_unchanged"] = True
    post["bytecode_dir_empty"] = _Operation.bounded("post_bytecode", lambda: not os.listdir(prefix))
    _require(post["bytecode_dir_empty"], "bytecode_written_during_execution")
    receipt["violations"] = [v[:120] for v in report["violations"]][:50]
    receipt["refused"] = [v[:120] for v in report["refused"]][:50]
    if report["violations"]:
        _reject("closure_runtime_violation", report["violations"][0][:100])
    _Operation.bounded("report_rows", _check_report_rows, report, verified)
    receipt["loaded"] = report["loaded"]
    _require(report["inputs"] == facts["input_digests"], "protocol_inputs_binding")
    if report["exception_type"]:
        _reject("execution_verifier_exception", str(report["exception_type"])[:60])
    if report["result_error"]:
        _reject("execution_result_" + str(report["result_error"])[:30])
    result = report["result"]
    if not isinstance(result, dict) or result.get("status") not in ("PASS", "HOLD"):
        _reject("execution_result_invalid")
    status = result["status"]
    result_sha256 = _Operation.bounded("result_digest", canonical_digest, result)
    return _Verdict(status, "ok" if status == "PASS" else "verifier_hold",
                    {"returned": True, "exception_type": None, "result_sha256": result_sha256,
                     "result": result if request.embed_result else None})


# --------------------------------------------------------------------------- receipts

_RECEIPT_KEYS = frozenset(_receipt())
_POST_KEYS = frozenset({"closure_unchanged", "inputs_unchanged", "runtime_unchanged", "bytecode_dir_empty"})
_PROCESS_KEYS = frozenset({"exit_code", "timed_out", "stdout_bytes", "stderr_bytes", "stderr_sha256", "descendants",
                           "cleanup_failed", "overflow", "timeout_ms", "containment"})
_EVIDENCE_KEYS = frozenset({"report_sha256", "runtime_modules", "runtime_modules_sha256", "runtime_rows", "native_files",
                            "native_plan", "mapped", "mapped_sha256", "module_table_sha256"})
_EXPOSURE_KEYS = frozenset({"inspected", "enforced", "paths_checked", "exposed", "policy", "trusted"})
MAX_RUNTIME_ROWS = 1 << 16
MAX_MAPPED = 8192
PROTECTION_POLICIES = (POSIX_POLICY, WINDOWS_POLICY, "unavailable")
CONTAINMENTS = ("job_object", "subreaper")
_TRUSTED_LABEL = re.compile(r"^(uid:[0-9]{1,10}|sid:S-1-[0-9-]{1,200})$")
_VERIFIER_KEYS = frozenset({"returned", "exception_type", "result_sha256", "result"})
_LOADED_KEYS = frozenset({"closure", "builtin", "frozen", "stdlib", "startup", "package", "native"})
_NONCE = re.compile(r"^[0-9a-f]{32}$")
_DISTRIBUTION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_IMPLEMENTATION_SOURCES = ("launcher_capture", "disk_reread")
MAX_LOADED = 1 << 20


def _is_sha(value: Any) -> bool:
    return isinstance(value, str) and SHA.match(value) is not None


def _is_count(value: Any, upper: int = MAX_LOADED) -> bool:
    return type(value) is int and 0 <= value <= upper


def _validate_loaded(loaded: Any, *, modules: Mapping[str, str] | None = None, distributions: Any = None,
                     runtime_modules: int | None = None, entry: str | None = None, code: str = "receipt_shape") -> None:
    """Exact shape and types of the ``loaded`` evidence, and (when the trusted context is given) its meaning.

    ``modules`` maps manifest module names to their digests, ``distributions`` is the set of manifest distribution
    labels, ``runtime_modules`` the number of census-table modules the child reported.  The count invariant is
    ``runtime_modules == stdlib + sum(package.values())`` (every census module is counted exactly once, under its
    own distribution or as standard library).
    """
    _require(isinstance(loaded, dict) and set(loaded) == _LOADED_KEYS, code, "loaded_keys")
    for key in ("builtin", "frozen", "stdlib", "startup"):
        _require(_is_count(loaded[key]), code, "loaded_" + key)
    closure, package, native = loaded["closure"], loaded["package"], loaded["native"]
    _require(isinstance(closure, dict) and len(closure) <= MAX_MODULES and all(
        isinstance(n, str) and MODULE.match(n) is not None and _is_sha(h) for n, h in closure.items()), code, "loaded_closure")
    _require(isinstance(package, dict) and len(package) <= MAX_PACKAGES and all(
        isinstance(k, str) and len(k) <= 200 and _DISTRIBUTION.match(k) is not None and _is_count(v) and v > 0
        for k, v in package.items()), code, "loaded_package")
    _require(isinstance(native, dict) and len(native) <= MAX_NATIVES and all(
        isinstance(n, str) and MODULE.match(n) is not None and _is_sha(h) for n, h in native.items()), code, "loaded_native")
    if modules is not None:
        _require(all(modules.get(n) == h for n, h in closure.items()), code, "loaded_closure_mismatch")
        _require(entry is None or entry in closure, code, "loaded_entry_missing")
    if distributions is not None:
        _require(set(package) <= set(distributions), code, "loaded_package_label")
    if runtime_modules is not None:
        _require(runtime_modules == loaded["stdlib"] + sum(package.values()) and len(native) <= runtime_modules,
                 code, "loaded_count")


def _shape(condition: bool, detail: str) -> None:
    _require(condition, "receipt_shape", detail)


def _validate_receipt_fields(receipt: Mapping[str, Any]) -> None:
    """Every field that is present is validated for every status: absence is allowed only for ``REJECTED``."""
    implementation = receipt["implementation"]
    if implementation is not None:
        _shape(isinstance(implementation, list) and [r.get("path") if isinstance(r, dict) else None for r in implementation]
               == sorted("trace_gc/" + n for n in IMPLEMENTATION_FILES) and all(
            set(r) == {"path", "sha256", "bytes"} and _is_sha(r["sha256"]) and type(r["bytes"]) is int and 0 < r["bytes"] <= MAX_MODULE_BYTES
            for r in implementation), "implementation")
    _shape(receipt["implementation_source"] is None or receipt["implementation_source"] in _IMPLEMENTATION_SOURCES,
           "implementation_source")
    if receipt["runtime"] is not None:
        try:
            _validate_runtime(receipt["runtime"])
        except ClosureRejected:
            _reject("receipt_shape", "runtime")
    exposure = receipt["runtime_protection"]
    if exposure is not None:
        _shape(isinstance(exposure, dict) and set(exposure) == _EXPOSURE_KEYS and type(exposure["inspected"]) is bool
               and type(exposure["enforced"]) is bool and _is_count(exposure["paths_checked"], 1 << 40)
               and isinstance(exposure["exposed"], list) and len(exposure["exposed"]) <= 50
               and all(isinstance(p, str) and len(p) <= 4096 for p in exposure["exposed"])
               and exposure["policy"] in PROTECTION_POLICIES and isinstance(exposure["trusted"], list)
               and len(exposure["trusted"]) <= 64 and exposure["trusted"] == sorted(set(exposure["trusted"]))
               and all(isinstance(t, str) and _TRUSTED_LABEL.match(t) is not None for t in exposure["trusted"])
               and (exposure["policy"] != "unavailable" or (not exposure["inspected"] and not exposure["trusted"])),
               "runtime_protection")
    closure = receipt["closure"]
    if closure is not None:
        _shape(isinstance(closure, dict) and set(closure) == {"modules", "packages"} and isinstance(closure["modules"], list)
               and 0 < len(closure["modules"]) <= MAX_MODULES and all(
            isinstance(m, dict) and set(m) == {"name", "sha256", "bytes"} and isinstance(m["name"], str)
            and MODULE.match(m["name"]) is not None and _is_sha(m["sha256"]) and _is_count(m["bytes"], MAX_MODULE_BYTES)
            for m in closure["modules"])
               and len({m["name"] for m in closure["modules"]}) == len(closure["modules"])
               and isinstance(closure["packages"], list) and len(closure["packages"]) <= MAX_PACKAGES and all(
            isinstance(p, dict) and set(p) == {"distribution", "version", "census_sha256"}
            and isinstance(p["distribution"], str) and _DISTRIBUTION.match(p["distribution"]) is not None
            and isinstance(p["version"], str) and 0 < len(p["version"]) <= 200 and _is_sha(p["census_sha256"])
            for p in closure["packages"])
               and len({p["distribution"] for p in closure["packages"]}) == len(closure["packages"]), "closure")
    request = receipt["request"]
    if request is not None:
        _shape(isinstance(request, dict) and set(request) == {"nonce", "header_sha256"} and isinstance(request["nonce"], str)
               and _NONCE.match(request["nonce"]) is not None and _is_sha(request["header_sha256"]), "request")
    verifier = receipt["verifier"]
    if verifier is not None:
        _shape(isinstance(verifier, dict) and set(verifier) == _VERIFIER_KEYS and type(verifier["returned"]) is bool
               and (verifier["exception_type"] is None
                    or (isinstance(verifier["exception_type"], str) and 0 < len(verifier["exception_type"]) <= 200))
               and _is_sha(verifier["result_sha256"]) and (verifier["result"] is None or isinstance(verifier["result"], dict)),
               "verifier")
    if receipt["loaded"] is not None:
        _validate_loaded(receipt["loaded"])
    process = receipt["process"]
    if process is not None:
        _shape(isinstance(process, dict) and set(process) == _PROCESS_KEYS
               and (process["exit_code"] is None or (type(process["exit_code"]) is int and -(1 << 40) < process["exit_code"] < (1 << 40)))
               and type(process["timed_out"]) is bool and type(process["descendants"]) is bool
               and type(process["cleanup_failed"]) is bool and (process["overflow"] is None or process["overflow"] in ("stdout", "stderr"))
               and _is_count(process["stdout_bytes"], 1 << 40) and _is_count(process["stderr_bytes"], 1 << 40)
               and _is_sha(process["stderr_sha256"]) and type(process["timeout_ms"]) is int
               and 0 < process["timeout_ms"] <= MAX_TIMEOUT_MS and process["containment"] in CONTAINMENTS, "process")
    post = receipt["post_checks"]
    if post is not None:
        _shape(isinstance(post, dict) and set(post) == _POST_KEYS and all(type(v) is bool for v in post.values()), "post_checks")
    evidence = receipt["evidence"]
    if evidence is not None:
        _shape(isinstance(evidence, dict) and set(evidence) == _EVIDENCE_KEYS and _is_sha(evidence["report_sha256"])
               and _is_sha(evidence["runtime_modules_sha256"]) and _is_count(evidence["runtime_modules"], MAX_RUNTIME_ROWS)
               and _is_sha(evidence["mapped_sha256"]) and _is_sha(evidence["module_table_sha256"])
               and isinstance(evidence["runtime_rows"], list) and len(evidence["runtime_rows"]) <= MAX_RUNTIME_ROWS
               and all(isinstance(r, list) and len(r) == 2 and isinstance(r[0], str) and MODULE.match(r[0]) is not None
                       and _is_sha(r[1]) for r in evidence["runtime_rows"])
               and isinstance(evidence["native_files"], list) and len(evidence["native_files"]) <= MAX_NATIVES
               and all(isinstance(r, list) and len(r) == 3 and isinstance(r[0], str) and MODULE.match(r[0]) is not None
                       and isinstance(r[1], str) and 0 < len(r[1]) <= 4096 and _is_sha(r[2])
                       for r in evidence["native_files"])
               and isinstance(evidence["native_plan"], list) and len(evidence["native_plan"]) <= MAX_NATIVES
               and all(isinstance(r, list) and len(r) == 2 and isinstance(r[0], str) and 0 < len(r[0]) <= 4096
                       and _is_sha(r[1]) for r in evidence["native_plan"])
               and isinstance(evidence["mapped"], list) and len(evidence["mapped"]) <= MAX_MAPPED
               and all(isinstance(p, str) and 0 < len(p) <= 4096 for p in evidence["mapped"]), "evidence")
    _shape(all(isinstance(v, str) and len(v) <= 120 for v in [*receipt["violations"], *receipt["refused"]])
           and len(receipt["violations"]) <= 50 and len(receipt["refused"]) <= 50
           and len(receipt["parent_sys_modules_collisions"]) <= MAX_MODULES
           and all(MODULE.match(v) is not None for v in receipt["parent_sys_modules_collisions"]), "lists")


def _is_absolute_claim(path: Any) -> bool:
    """Platform-independent absolute-path shape (POSIX root, drive letter or UNC) for a path a receipt claims."""
    return isinstance(path, str) and 0 < len(path) <= 4096 and (
        path.startswith("/") or path.startswith("\\\\") or re.match(r"^[A-Za-z]:[\\/]", path) is not None)


_PROCESS_FLAGS = (("containment_cleanup_failed", "cleanup_failed", lambda v: v is True),
                  ("execution_timeout", "timed_out", lambda v: v is True),
                  ("protocol_output_overflow", "overflow", lambda v: v is not None),
                  ("containment_unresolved_descendants", "descendants", lambda v: v is True))
_PROCESS_NEUTRAL = ("operation_deadline_exceeded", "execution_internal_error")


def _cross_check_rejected(receipt: Mapping[str, Any]) -> None:
    """A REJECTED reason and the retained process evidence must tell the same story.

    ``_accept_report`` classifies a finished child in a fixed order (cleanup, attach, launch, timeout, overflow,
    descendants).  A reason that names a flag needs that flag set and every earlier flag clear; any other reason
    (attach/launch failure, report validation, post checks) needs every flag clear.
    """
    process = receipt["process"]
    if process is None:
        return
    head = receipt["reason"].partition(":")[0]
    if head in _PROCESS_NEUTRAL:
        return
    flags = {key: test(process[key]) for _, key, test in _PROCESS_FLAGS}
    order = [key for _, key, _ in _PROCESS_FLAGS]
    named = {reason: key for reason, key, _ in _PROCESS_FLAGS}
    if head in named:
        key = named[head]
        _require(flags[key] and not any(flags[earlier] for earlier in order[:order.index(key)]),
                 "receipt_evidence_inconsistent", "reason_process:" + head)
    else:
        _require(not any(flags.values()), "receipt_evidence_inconsistent", "reason_process:" + head)


def _cross_check(receipt: Mapping[str, Any]) -> None:
    """Relationships between the fields that are present, checked for every status (a REJECTED receipt included)."""
    code = "receipt_evidence_inconsistent"
    evidence, loaded, closure, runtime = receipt["evidence"], receipt["loaded"], receipt["closure"], receipt["runtime"]
    if loaded is not None and closure is not None:
        _validate_loaded(loaded, modules={m["name"]: m["sha256"] for m in closure["modules"]},
                         distributions={p["distribution"] for p in closure["packages"]}, code=code)
    if evidence is None:
        return
    rows = evidence["runtime_rows"]
    by_name = {name: sha for name, sha in rows}
    _require(len(by_name) == len(rows) and rows == sorted(rows) and evidence["runtime_modules"] == len(rows)
             and canonical_digest(rows) == evidence["runtime_modules_sha256"], code, "runtime_rows")
    native = evidence["native_files"]
    _require(native == sorted(native) and len({r[0] for r in native}) == len(native)
             and all(by_name.get(name) == sha for name, _, sha in native), code, "native_files")
    plan = evidence["native_plan"]
    _require(plan == sorted(plan) and len({r[0] for r in plan}) == len(plan), code, "native_plan")
    mapped = evidence["mapped"]
    _require(mapped == sorted(set(mapped)) and canonical_digest(mapped) == evidence["mapped_sha256"], code, "mapped")
    if runtime is not None:
        pinned = {(item["path"], item["sha256"]) for item in runtime["natives"]}
        _require(all((path, sha) in pinned for path, sha in plan), code, "native_plan_unpinned")
        fold = str.lower if runtime["platform"] == "win32" else str
        allowed = {fold(item["path"]) for item in runtime["natives"]}
        _require(all(fold(path) in allowed for path in mapped), code, "mapped_unpinned")
        pinned_sha = {fold(item["path"]): item["sha256"] for item in runtime["natives"]}
        # A claimed extension file is never trusted by its own claim: it must be an absolute path, and if the trusted
        # pins name the same file the digests must agree.  (Files outside the pins are bound by the census digests the
        # verifier recomputed before launch, not by the receipt.)
        _require(all(_is_absolute_claim(path) and pinned_sha.get(fold(path), sha) == sha for _, path, sha in native),
                 code, "native_files_pin")
    if loaded is not None:
        _require({name for name, _, _ in native} == set(loaded["native"])
                 and all(loaded["native"][name] == sha for name, _, sha in native), code, "native_identity")
        _validate_loaded(loaded, runtime_modules=evidence["runtime_modules"], code=code)


def validate_receipt(receipt: Any) -> dict[str, Any]:
    """Strict, exact-shape and invariant validation of a stored receipt (no external schema library needed).

    Checks the unkeyed binding over every field first, then each field's shape and the cross-field invariants that
    make ``PASS``/``HOLD`` mean what the contract says.  A caller that re-seals an edited receipt still fails these.
    """
    _require(isinstance(receipt, dict) and set(receipt) == _RECEIPT_KEYS, "receipt_shape", "keys")
    _require(receipt["version"] == RECEIPT_VERSION, "receipt_version")
    try:
        canonical_bytes(receipt)
    except ContractError:
        _reject("receipt_not_canonical")
    _require(_is_sha(receipt["binding_sha256"]) and receipt["binding_sha256"] == _binding(receipt), "receipt_binding_mismatch")
    status = receipt["status"]
    _require(status in ("PASS", "HOLD", "REJECTED"), "receipt_status")
    _require(isinstance(receipt["reason"], str) and 0 < len(receipt["reason"]) <= 200, "receipt_shape", "reason")
    for key in ("manifest_sha256", "release_sha256", "params_sha256"):
        _require(receipt[key] is None or _is_sha(receipt[key]), "receipt_shape", key)
    _shape(isinstance(receipt["violations"], list) and all(isinstance(v, str) for v in receipt["violations"])
           and isinstance(receipt["refused"], list) and all(isinstance(v, str) for v in receipt["refused"])
           and isinstance(receipt["parent_sys_modules_collisions"], list)
           and all(isinstance(v, str) for v in receipt["parent_sys_modules_collisions"]), "lists")
    _shape(isinstance(receipt["inputs"], dict) and len(receipt["inputs"]) <= MAX_INPUTS and all(
        isinstance(n, str) and INPUT_NAME.match(n) is not None and isinstance(v, dict) and set(v) == {"sha256", "bytes"}
        and _is_sha(v["sha256"]) and _is_count(v["bytes"], MAX_INPUT_BYTES) for n, v in receipt["inputs"].items()), "inputs")
    _validate_receipt_fields(receipt)
    _cross_check(receipt)
    if status == "REJECTED":
        _require(receipt["failure_class"] in CONTRACT["failure_classes"]
                 and receipt["failure_class"] == failure_class(receipt["reason"].partition(":")[0]), "receipt_status", "failure_class")
        _require(receipt["verifier"] is None, "receipt_result_unbound", "rejected_with_verifier")
        _cross_check_rejected(receipt)
        return receipt
    _require(receipt["failure_class"] is None and receipt["reason"] == ("ok" if status == "PASS" else "verifier_hold"),
             "receipt_result_unbound", "reason")
    _require(all(_is_sha(receipt[k]) for k in ("manifest_sha256", "release_sha256", "params_sha256")), "receipt_shape", "digests")
    _require(not receipt["violations"], "receipt_result_unbound", "violations")
    for key in ("implementation", "implementation_source", "runtime", "runtime_protection", "closure", "request", "verifier",
                "loaded", "process", "post_checks", "evidence"):
        _require(receipt[key] is not None, "receipt_shape", "missing_" + key)
    verifier = receipt["verifier"]
    _require(verifier["returned"] is True and verifier["exception_type"] is None, "receipt_result_unbound", "verifier")
    if verifier["result"] is not None:
        _require(canonical_digest(verifier["result"]) == verifier["result_sha256"]
                 and verifier["result"].get("status") == status, "receipt_result_digest_mismatch")
    process = receipt["process"]
    _require(process["exit_code"] == 0 and process["timed_out"] is False and process["descendants"] is False
             and process["cleanup_failed"] is False and process["overflow"] is None, "receipt_result_unbound", "process")
    _require(all(v is True for v in receipt["post_checks"].values()), "receipt_result_unbound", "post_checks")
    closure = receipt["closure"]
    _validate_loaded(receipt["loaded"], modules={m["name"]: m["sha256"] for m in closure["modules"]},
                     distributions={p["distribution"] for p in closure["packages"]},
                     runtime_modules=receipt["evidence"]["runtime_modules"])
    return receipt


def _check_module_table(receipt: Mapping[str, Any], table: Any, manifest: Mapping[str, Any] | None) -> None:
    """Relate every individual runtime, package, extension and native identity in the receipt to the trusted map.

    ``table`` is the independently reviewed complete module map.  The receipt's own commitment must equal the digest of
    THAT map (not of the receipt's rows), each reported identity must be a row of it with the same digest (and path for
    an extension), the loaded counts must be exactly what the trusted map assigns to the reported modules, and the
    extension identities the map assigns to the reported runtime modules must be exactly ``native_files`` and exactly
    ``loaded.native`` (a bijection, so mutual omission of an extension is refused).
    """
    code = "receipt_module_identity_mismatch"
    rows = _normalise_table(table)
    evidence, loaded = receipt["evidence"], receipt["loaded"]
    _require(canonical_digest(rows) == evidence["module_table_sha256"], code, "table_commitment")
    by_name = {row[0]: row for row in rows}
    if manifest is not None:
        labels = {p["distribution"] for p in manifest["packages"]}
        _require(all(row[5] is None or row[5] in labels for row in rows), code, "table_distribution")
    stdlib, package, required = 0, {}, []
    for name, sha in evidence["runtime_rows"]:
        row = by_name.get(name)
        _require(row is not None and row[1] != "ambiguous" and row[3] == sha, code, "runtime_row:" + name[:60])
        if row[1] == "ext":
            required.append([name, row[2], row[3]])
        if row[5] is None:
            stdlib += 1
        else:
            package[row[5]] = package.get(row[5], 0) + 1
    for name, path, sha in evidence["native_files"]:
        row = by_name.get(name)
        _require(row is not None and row[1] == "ext" and row[2] == path and row[3] == sha, code, "native_file:" + name[:60])
    # Exact bijection: the extension identities the trusted map assigns to the reported runtime modules are EXACTLY the
    # reported native_files rows and EXACTLY loaded.native; a module omitted from both representations is not accepted.
    required.sort()
    reported = sorted([list(r) for r in evidence["native_files"]])
    _require(reported == required, code, "native_files_incomplete")
    _require(loaded["native"] == {name: sha for name, _, sha in required}, code, "loaded_native_incomplete")
    _require(loaded["stdlib"] == stdlib and loaded["package"] == package, code, "loaded_counts")


def verify_receipt(receipt: Mapping[str, Any], *, expected_manifest_sha256: str, expected_release_sha256: str,
                   expected_inputs: Mapping[str, str] | None = None, expected_params_sha256: str | None = None,
                   manifest: Mapping[str, Any] | None = None, require_acceptance: bool = True,
                   result: Mapping[str, Any] | None = None, expected_module_table: Any = None) -> str:
    """Consumer-side readback: returns the receipt status after strict validation and expected-value comparison.

    Acceptance mode (the default) is the only mode a consumer may treat as acceptance of a ``PASS``/``HOLD``.  It
    additionally REQUIRES the trusted context: the ``manifest`` (checked against ``expected_manifest_sha256``), the
    ``expected_inputs`` digests, the ``expected_params_sha256`` and the ``expected_module_table`` (the independently
    reviewed complete module map: every individual runtime, package, extension and native identity the receipt reports
    must be a row of it, and the receipt's table commitment must equal its digest); and it refuses a receipt whose implementation was
    not the launcher-captured bytes, whose runtime protection was not inspected, enforced under a known policy that
    trusts at least the built-in administrative principals, and free of exposed paths, or whose containment was not
    the platform's owned-membership backend.  A receipt written with ``embed_result=False`` carries only the result
    digest: acceptance then requires the caller to supply the verifier's ``result`` object, whose digest and status
    must equal the receipt's.  With ``require_acceptance=False`` the context is checked only where supplied
    (diagnostics, tests).  The binding is unkeyed: it proves internal consistency, not who produced the receipt.
    """
    _require(type(require_acceptance) is bool, "invalid_arguments", "flag_type")
    validate_receipt(receipt)
    _require(receipt["manifest_sha256"] == expected_manifest_sha256, "receipt_manifest_mismatch")
    _require(receipt["release_sha256"] == expected_release_sha256, "receipt_release_mismatch")
    if receipt["status"] in ("PASS", "HOLD"):
        verifier = receipt["verifier"]
        if verifier["result"] is None and (require_acceptance or result is not None):
            _require(result is not None, "receipt_context_required", "result")
        if result is not None:
            _require(isinstance(result, Mapping), "receipt_result_digest_mismatch", "type")
            try:
                bound = canonical_digest(json.loads(json.dumps(result)))
            except (ContractError, TypeError, ValueError):
                _reject("receipt_result_digest_mismatch", "not_canonical")
            _require(bound == verifier["result_sha256"] and result.get("status") == receipt["status"]
                     and (verifier["result"] is None or dict(result) == verifier["result"]), "receipt_result_digest_mismatch")
        if require_acceptance:
            _require(manifest is not None and expected_inputs is not None and expected_params_sha256 is not None,
                     "receipt_context_required", "manifest_inputs_params")
            _require(expected_module_table is not None, "receipt_context_required", "module_table")
            _require(receipt["implementation_source"] == "launcher_capture", "receipt_not_acceptance_grade", "implementation_source")
            protection = receipt["runtime_protection"]
            required = {"posix": ("posix", POSIX_POLICY, ["uid:0"]),
                        "win32": ("windows", WINDOWS_POLICY, sorted("sid:" + sid for sid in BUILTIN_SIDS))}[
                "win32" if receipt["runtime"]["platform"] == "win32" else "posix"]
            _require(protection["inspected"] is True and protection["enforced"] is True and protection["exposed"] == []
                     and protection["policy"] == required[1] and set(required[2]) <= set(protection["trusted"])
                     and protection["paths_checked"] > 0, "receipt_not_acceptance_grade", "runtime_protection")
            _require(receipt["process"]["containment"] == ("job_object" if required[0] == "windows" else "subreaper"),
                     "receipt_not_acceptance_grade", "containment")
        if expected_inputs is not None:
            _require({k: v["sha256"] for k, v in receipt["inputs"].items()} == dict(expected_inputs), "receipt_inputs_mismatch")
        if expected_params_sha256 is not None:
            _require(receipt["params_sha256"] == expected_params_sha256, "receipt_params_mismatch")
        if manifest is not None:
            manifest = validate_manifest(json.loads(json.dumps(manifest)))
            _require(canonical_digest(manifest) == expected_manifest_sha256, "receipt_manifest_mismatch", "manifest_argument")
            _require(receipt["runtime"] == manifest["runtime"], "receipt_manifest_mismatch", "runtime")
            _require(receipt["closure"]["modules"] == [{"name": m["name"], "sha256": m["sha256"], "bytes": m["bytes"]}
                                                       for m in manifest["modules"]], "receipt_manifest_mismatch", "modules")
            _require(receipt["closure"]["packages"] == [{"distribution": p["distribution"], "version": p["version"],
                                                         "census_sha256": p["census_sha256"]} for p in manifest["packages"]],
                     "receipt_manifest_mismatch", "packages")
            _validate_loaded(receipt["loaded"], modules={m["name"]: m["sha256"] for m in manifest["modules"]},
                             distributions={p["distribution"] for p in manifest["packages"]},
                             runtime_modules=receipt["evidence"]["runtime_modules"], entry=manifest["entry"]["module"],
                             code="receipt_manifest_mismatch")
            rebuilt = {"version": RELEASE_VERSION, "implementation": receipt["implementation"], "contract": CONTRACT,
                       "runtime": manifest["runtime"], "manifest_sha256": expected_manifest_sha256}
            _require(canonical_digest(rebuilt) == expected_release_sha256, "receipt_release_mismatch", "recomputed")
            declared = {_operation_entry(d) for d in manifest["dependency_operations"]}
            _require(set(receipt["refused"]) <= declared, "receipt_manifest_mismatch", "dependency_operations")
        if expected_module_table is not None:
            _check_module_table(receipt, expected_module_table, manifest)
    return receipt["status"]


def _write_all(fd: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(fd, view)
        _require(written > 0, "write_incomplete")
        view = view[written:]


def _publish_new(path: str | os.PathLike, payload: bytes) -> None:
    """Fully write and fsync a private temporary file, then publish it atomically; never overwrites ``path``.

    ``path`` either does not exist or holds the complete payload: no empty or partial destination is ever visible.
    The publication is a hard link (fails if ``path`` exists).  Where links are unavailable, Windows uses
    ``os.rename`` (which refuses to replace on that platform); every other platform fails closed with
    ``ClosureRejected("publish_unsupported")`` because its rename would silently replace an existing file.
    """
    target = os.path.abspath(os.fspath(path))
    fd, temporary = tempfile.mkstemp(prefix=".pvc-write-", dir=os.path.dirname(target))
    try:
        try:
            _write_all(fd, payload)
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.link(temporary, target)
        except FileExistsError:
            raise
        except OSError:
            if sys.platform != "win32":
                _reject("publish_unsupported", "hard_links_unavailable")
            try:
                os.rename(temporary, target)
            except FileExistsError:
                raise
            except OSError:
                _reject("publish_unsupported", "rename_failed")
    finally:
        try:
            os.unlink(temporary)
        except OSError:
            pass


def write_receipt(path: str | os.PathLike, receipt: Mapping[str, Any]) -> str:
    """Create ``path`` exclusively (never overwrite), completely or not at all; return the SHA-256 of the bytes."""
    payload = (json.dumps(receipt, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")
    _publish_new(path, payload)
    return _sha(payload)


# --------------------------------------------------------------------------- command line

def _pairs(values: Sequence[str]) -> dict[str, str]:
    _require(len(values) <= 32, "argument_pair_invalid", "too_many")
    out = {}
    for item in values:
        key, sep, value = item.partition("=")
        _require(bool(sep) and bool(key) and bool(value) and key not in out, "argument_pair_invalid", item[:40])
        out[key] = value
    return out


def _input_specs(values: Sequence[str]) -> dict[str, InputSpec]:
    """Parse ``NAME=SHA256=PATH`` triples: bounded count, no duplicate names, well-formed digests and paths."""
    _require(len(values) <= MAX_INPUTS, "argument_pair_invalid", "too_many_inputs")
    specs: dict[str, InputSpec] = {}
    for item in values:
        name, _, rest = item.partition("=")
        sha, _, path = rest.partition("=")
        _require(INPUT_NAME.match(name) is not None and name not in specs and SHA.match(sha) is not None and bool(path),
                 "argument_pair_invalid", item[:40])
        location = Path(path).absolute()
        specs[name] = InputSpec(location.parent, location.name, sha)
    return specs


def _write_new(path: str, payload: Mapping[str, Any]):
    _publish_new(path, (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("ascii"))


def _read_json_file(path: str, limit: int = MAX_MANIFEST_BYTES) -> Any:
    """Bounded, regular-file-only, strict (duplicate-key and NaN rejecting) JSON read."""
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        _require(stat.S_ISREG(os.fstat(fd).st_mode), "manifest_not_regular_file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(limit + 1)
    finally:
        os.close(fd)
    _require(len(data) <= limit, "manifest_too_large")
    try:
        return canonical_loads(data.decode("utf-8"))
    except (ContractError, UnicodeError, ValueError):
        _reject("manifest_unparseable")


def _cli_timeout(text: str) -> float:
    try:
        return validate_timeout(float(text))
    except (ValueError, ClosureRejected):
        raise argparse.ArgumentTypeError("timeout must be a finite number of seconds with 0 < timeout <= %g" % MAX_TIMEOUT)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build", help="discover a closure and write its manifest")
    build.add_argument("--name", required=True)
    build.add_argument("--root", action="append", default=[], metavar="ALIAS=DIR")
    build.add_argument("--entry", required=True, metavar="MODULE[:CALLABLE]")
    build.add_argument("--python")
    build.add_argument("--dependency-operation", action="append", default=[], metavar="IMPORTER:FORM:MODULE",
                       help="reviewed attempt of a census dependency on an unpinned module (form: import, import_module, find_spec)")
    build.add_argument("--output", required=True)
    digest = sub.add_parser("digest", help="print the canonical manifest digest")
    digest.add_argument("manifest")
    release = sub.add_parser("release", help="write the release record and print its digest")
    release.add_argument("manifest")
    release.add_argument("--output")
    run = sub.add_parser("run", help="authenticate, verify and execute a verifier from its closure")
    run.add_argument("manifest")
    run.add_argument("--expected-sha256", required=True)
    run.add_argument("--expected-release-sha256", required=True)
    run.add_argument("--root", action="append", default=[], metavar="ALIAS=DIR")
    run.add_argument("--input", action="append", default=[], metavar="NAME=SHA256=PATH")
    run.add_argument("--python")
    run.add_argument("--timeout", type=_cli_timeout, default=120.0)
    run.add_argument("--allow-unprotected-runtime", action="store_true",
                     help="record write-exposure instead of refusing it; such a receipt is not acceptance grade")
    run.add_argument("--trusted-uid", action="append", type=int, default=[], metavar="UID",
                     help="POSIX principal (besides root) allowed to own or write the runtime; never the evaluator")
    run.add_argument("--trusted-sid", action="append", default=[], metavar="SID",
                     help="Windows SID (besides SYSTEM, Administrators and TrustedInstaller) allowed to own or write the runtime")
    run.add_argument("--expected-module-table-sha256", metavar="SHA256",
                     help="digest of the independently reviewed complete module map; a differing live map is refused before launch")
    run.add_argument("--receipt", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            module, _, function = args.entry.partition(":")
            operations = []
            for item in args.dependency_operation:
                importer, form, target = item.split(":", 2) if item.count(":") == 2 else ("", "", "")
                _require(bool(importer and form and target), "argument_pair_invalid", item[:40])
                operations.append({"importer": importer, "form": form, "module": target})
            manifest = build_manifest(name=args.name, roots=_pairs(args.root), entry_module=module,
                                      entry_callable=function or "verify", python=args.python,
                                      dependency_operations=operations)
            _write_new(args.output, manifest)
            print(json.dumps({"manifest_sha256": manifest_digest(manifest), "release_sha256": release_digest(manifest),
                              "modules": len(manifest["modules"])}))
            return 0
        manifest = _read_json_file(args.manifest)
        if args.command == "digest":
            print(manifest_digest(manifest))
            return 0
        if args.command == "release":
            record = release_record(manifest)
            if args.output:
                _write_new(args.output, record)
            print(canonical_digest(record))
            return 0
        specs = _input_specs(args.input)
        roots = _pairs(args.root)
        _require(not os.path.lexists(args.receipt), "invalid_arguments", "receipt_exists")
        outcome = run_verifier(manifest, args.expected_sha256, expected_release_sha256=args.expected_release_sha256,
                               roots=roots, python=args.python, inputs=specs, timeout=args.timeout,
                               allow_unprotected_runtime=args.allow_unprotected_runtime,
                               protection_policy=ProtectionPolicy.build(args.trusted_uid, args.trusted_sid),
                               expected_module_table_sha256=args.expected_module_table_sha256)
        write_receipt(args.receipt, outcome.receipt)
        print(json.dumps({"status": outcome.status, "reason": outcome.reason, "failure_class": outcome.receipt["failure_class"]}))
        return 0 if outcome.passed else 1
    except ClosureRejected as exc:
        print(json.dumps({"status": "REJECTED", "reason": exc.code + (":" + exc.detail if exc.detail else "")}))
        return 2
    except (OSError, ValueError, KeyError, TypeError, ArithmeticError) as exc:
        print(json.dumps({"status": "REJECTED", "reason": "invalid_arguments:" + type(exc).__name__}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
