# Closure-pinned external verifier loader (issue #97)

`src/verifier_closure_loader.py` is the public, offline half of the issue #97
repair. It binds an external qualification verifier to its complete local
executable closure and refuses to run it when any part of that closure differs
from the reviewed release contract. It does not contain, bind or run the private
V6 evaluator or the real issue20, issue22 and recovery verifier releases. Those
gates remain HOLD.

## Why a top-level pin is not enough

The frozen V6 evaluator pinned the top-level verifier files and then imported
them normally. Ordinary imports resolve helpers through `sys.path`,
`sys.modules` and `__pycache__`, none of which a top-level SHA-256 binds. The
authored reproduction in `tests/test_verifier_closure_loader.py` shows this
with a synthetic fixture. Changing only `helper.py` turns HOLD into PASS while
`entry.py` stays byte-identical. A stale timestamp-validated `.pyc` can also
make ordinary import execute PASS logic while the helper source on disk hashes
to the reviewed HOLD bytes. The legacy runner in that test is an authored model
of a top-level-only pin. It is not V6.

## Release contract `verifier_closure_release_v1`

| Field | Meaning |
| --- | --- |
| `contract` | `verifier_closure_release_v1` |
| `verifier_id` | Reviewed verifier name |
| `entry`, `callable` | Entry module (dotted, inside the release root) and the function called with the inputs |
| `runtime` | `{"implementation", "version"}` (major.minor); any other runtime is rejected |
| `approved_external` | Sorted stdlib modules the closure may import. Import machinery and code-loading modules (`DENIED_EXTERNAL`: `importlib`, `sys`, `builtins`, `runpy`, `pkgutil`, `zipimport`, `marshal`, `site`, `imp`, `ctypes`, `code`, `codeop`, `os`, `posix`, `nt`, `subprocess`, `multiprocessing`, `concurrent`, `pickle`, `shelve`, `copyreg`, `types`, `inspect`, `gc`, `pdb`, `bdb`, `trace`, `profile`, `cProfile`, `zipapp`) cannot be approved, and neither can a module outside the stdlib. This is a denylist, not an allowlist: every other approved module must be reviewed, as part of the trusted base, for whether it can load or run code outside the closure |
| `approved_dynamic` | Sorted modules inside the verifier package that the code loads with a literal `__import__("...")`. They are pinned like static imports |
| `closure` | `{relative path: sha256}` for every local file: entry, transitive helpers, package `__init__` files and approved dynamic modules |

The contract digest is the SHA-256 of its canonical JSON (`json_bytes`).
`build_release_contract` produces a contract from a root for review. The review
itself, signing and delivery happen out of band and are not performed here.

## What `run_verifier` checks

1. The contract shape and the current runtime.
2. The root is one of the caller's approved roots, after resolution, and is not
   a symlink.
3. A strict static scan of the entry and approved dynamic modules. It covers
   function-local imports too, and it rejects the following:
   - missing modules and unresolved `from X import name`
   - `x.py` next to `x/__init__.py`
   - namespace packages and star imports
   - symlinked path components
   - undeclared or non-stdlib external imports and import machinery
   - `exec`, `eval`, `compile`, `globals`, `vars`, `__builtins__` and
     `__loader__`/`__spec__`, plus non-literal or undeclared `__import__`
4. The file set and hashes must equal
   `parallel_source_v4.common.method_hashes(root, additional_roots=(entry,
   *approved_dynamic))`. Disagreement fails closed. This happens, for
   example, when a local `json.py` would shadow the declared stdlib import, or
   when the root carries files that `method_hashes` seeds by default.
5. No closure module may already be in `sys.modules`. No closure top-level name
   may be a stdlib name or resolve anywhere else on `sys.path`.
6. Each approved external, and each of its submodules already in
   `sys.modules`, must be builtin or frozen or have its spec origin (and
   `__file__`) under the base runtime's `stdlib`/`platstdlib` directories (plus
   `DLLs` on Windows), outside any `site-packages`. A stdlib-named module found
   elsewhere on `sys.path`, or a cached `sys.modules` entry from elsewhere,
   fails closed with `external_module_not_from_stdlib`.
7. The hashes of the scanned bytes must equal `closure` exactly.

Only after all of these checks pass does any verifier code run. The scanned
bytes are compiled in memory with `dont_inherit=True` into private module
objects. Those objects are never inserted into `sys.modules`, and their packages
get an empty `__path__`. No `__pycache__` file is read or written. A private
`__import__` resolves local names only from the verified map and passes only
declared stdlib names to the normal import system. It re-checks the stdlib
origin of each imported name before and after that import. A failed runtime
check rejects the run even if the verifier catches the `ImportError`. Afterwards the closure is
re-read and must be byte-identical, and the inputs must have the same digest
before the result is accepted. A verifier exception, an import-time exception or
any result other than the exact `str` `PASS`/`HOLD` (a `str` subclass or an
object with its own `__eq__` is not accepted) becomes HOLD. The record stores
the canonical literal. `evaluate_closure_gate` turns every closure rejection
into a HOLD record that carries the rejection code. Read and parse failures in
the scan map to `closure_unreadable`, `closure_not_utf8`,
`closure_syntax_error` and `invalid_module_reference`.

## Boundaries

The loader is an integrity boundary for reviewed code, not a sandbox. As
`SECURITY.md` states, reviewed verifier code is part of the trusted base. Code
that reaches the interpreter internals through reflection is outside the scope
of the static scan. Approved stdlib modules are trusted as part of the recorded
runtime; their bytes are not pinned here. Private module objects do not support
code that looks itself up in `sys.modules`, such as pickling verifier-defined
classes.

Every result is labelled `mechanical_closure_check_not_qualification`. The
following remain open for #97:
- the versioned private evaluator that uses this loader
- the real verifier releases and their reviewed contracts
- signed delivery and binding to the controller and stage releases
- separate attributed review
- running the real prerequisite verifiers once their receipts exist

Missing gates remain NOT_RUN or HOLD.
