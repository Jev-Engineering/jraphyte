# External verifier executable dependency closure (`paper-verifier-closure-v1`)

Tracks issue #97 (`Refs #97`; this document and its implementation do not close it). The public
primitive binds an externally reviewed *verifier* to everything that can actually execute when it
runs, and executes it from the verified representation only. It is an integrity boundary for
reviewed code, **not a sandbox** for hostile Python.

**Evidence status of this document.** Everything below describes the *source*. No test, build, wheel,
sdist, native-Windows run or generator run has been executed against the current source (see
*Status of evidence*). Statements about behaviour are design contracts that the authored tests in
`tests/test_paper_verifier_closure_v1.py` are written to check; they are **AUTHORED_NOT_RUN**, not results.

Shipped namespace (six implementation files, all part of the `trace_gc*` wheel; nothing is imported
from a checkout, `src/`, or `PYTHONPATH`):

| file | role |
|---|---|
| `trace_gc/__init__.py`, `errors.py`, `canonical.py` | package root, error type, TRACE-C14N-1 encoder |
| `trace_gc/verifier_closure.py` | parent: manifest, authentication, launch, containment, receipt, CLI |
| `trace_gc/verifier_closure_bootstrap.py` | child program (standard library only), delivered over stdin and hash-checked by a fixed stub |
| `trace_gc/verifier_closure_launcher.py` | stdlib-only external launcher for the parent (see *Pre-execution trust*) |

## Why a top-level hash is not enough

A frozen evaluator that pins only the top-level verifier module still lets ordinary imports
resolve other executable representations. `tests/test_paper_verifier_closure_v1.py` reproduces the
mechanisms with real subprocesses:

1. **Helper-only change.** An imported helper changes from `HOLD` to `PASS`; the top-level bytes and
   pin are identical.
2. **Resolution ambiguity.** With both `pkg.py` and `pkg/__init__.py`, the import system executes the
   package while `src.parallel_source_v4.common.method_hashes` hashes `pkg.py`. (`method_hashes` is
   deliberately unchanged, see *Frozen `method_hashes`*. This contract rejects the ambiguity.)
3. **Stale bytecode.** An `unchecked-hash` `.pyc` runs under `python -I -B` after the source changed;
   `-B` only stops writing. The runner serves modules from captured bytes and uses an empty
   `pycache_prefix`.
4. **Pre-imported / import-and-remove.** A module already in `sys.modules`, or one imported and then
   deleted from `sys.modules` before a final scan, would be invisible to a post-run `sys.modules` check.
   Imports are refused *before* loading and recorded when attempted, including imports of modules that
   are already cached (see *Import and load enforcement*).

## Workflow and the two external digests

```text
reviewer   build_manifest()  ->  manifest  ->  manifest digest + release digest (recorded out of band)
evaluator  launcher -- run ...   or   run_verifier(manifest, expected_manifest_sha256,
                        expected_release_sha256=..., roots=..., inputs=..., python=...)  ->  ClosureRun
consumer   verify_receipt(receipt, expected_manifest_sha256=..., expected_release_sha256=...,
                          expected_inputs=..., expected_params_sha256=..., manifest=...,
                          expected_module_table=<the reviewed complete module map>)
```

The reviewer also keeps the **complete module map** of the reviewed closure on the reviewed interpreter
(`verify_closure(...).table`, committed by `module_table_digest(table)`). It is the trusted expected context for
every individual runtime, package, extension and native identity a receipt reports (see *Receipts*), and
`run_verifier` / `verify_closure` accept its digest as `expected_module_table_sha256`
(`--expected-module-table-sha256` on the command line; a live census-derived map that differs is
`runtime_module_table_mismatch`; the comparison happens after the verify core, which includes the probe child, and
before the verifier child exists).

* **Manifest digest** — TRACE-C14N-1 (`trace_gc.canonical`) digest of the manifest.
* **Release digest** — `release_digest(manifest)`: canonical digest of
  `{version, implementation rows {path, sha256, bytes} for the six files above, contract,
  manifest.runtime, manifest_sha256}`. It authenticates the parent, the bootstrap, the launcher, the
  canonicaliser, the child-side contract (flags, limits, launch stub digest, status mapping, failure
  classes, argument and containment rules) and the full runtime pins.

Both are supplied by the caller (`expected_*` are required; a self-declared digest is never
trusted).

Command line: `python -m trace_gc.verifier_closure build|digest|release|run` (see `--help`), or the same
arguments after `--` through the launcher. `run` refuses an unprotected runtime unless
`--allow-unprotected-runtime` is given (see *Runtime write protection*).

A verifier is a module exposing a synchronous `verify(inputs: dict[str, bytes], params) -> dict`
whose result contains `"status": "PASS"` or `"HOLD"`. It receives only the captured inputs.

## Pre-execution trust: what is and is not authenticated

A Python module cannot authenticate the interpreter that is already running it. Hashing shipped files
from inside the parent therefore proves only that the files on disk match the release digest, not that
the code now executing is those files. The contract is split accordingly:

* **The executing parent is bound to the release through the launcher.** The launcher
  (`trace_gc/verifier_closure_launcher.py`, standard library only) is started as
  `python -I -S -B -X utf8 launcher --package-dir ABS --sha256 name=HEX ... -- <parent arguments>` with a
  digest for **each of the six** implementation files. It reads every file exactly once, compares each
  with its supplied digest, checks that the launcher file it hashed is the file now running
  (`launcher_not_the_pinned_file`), registers the package in `sys.modules`, executes the four parent-side
  files from exactly those bytes, and hands the bytes of all six to the parent as `_PVC_LAUNCHER_CAPTURE`.
  The parent builds the release record, the child's bootstrap and the receipt's implementation rows from
  that capture, so there is no later disk re-read: the bytes that were authenticated are the bytes that are
  bound and sent to the child. The receipt records `implementation_source: "launcher_capture"`.
* **Anything else is `disk_reread`.** A parent imported by other means (`python -m trace_gc.verifier_closure`,
  an ordinary import) reads the six files from disk once, and the receipt records
  `implementation_source: "disk_reread"`. That is permitted as a diagnostic, but a consumer in acceptance mode
  (below) refuses such a receipt (`receipt_not_acceptance_grade`).
* **Authenticated by the parent before any child interpreter exists.** `authenticate_runtime(python,
  pins)` runs *before* the probe child. It compares, in order: the invoked executable path, the resolved
  executable path and SHA-256, `pyvenv.cfg`, the base executable SHA-256, the startup-configuration
  rows (`pyvenv.cfg`, `pythonXY._pth` and `<exe-stem>._pth` beside and one level above the invoked and
  base executables; **absent files are pinned as absent**, so a later-created file is detected), the
  startup-file rows, the standard-library census and every pinned native. A mismatch is
  `runtime_mismatch:<key>` with `process=None` in the receipt; no interpreter was started. Facts that only
  a live interpreter can report (version, cache tag, startup and preload module sets) are compared
  immediately afterwards, and the whole authentication is repeated after the run
  (`runtime_changed_during_execution`).
* **What no software here can establish.** The interpreter, the launcher file, and the pinned digests
  must reach the evaluator through a trusted channel (a signed release, a hardened deployment, or a
  trusted shell). A parent started without the launcher is only as trustworthy as the process that
  imported it. This is a genuine external prerequisite, not something this change closes.

### Runtime write protection (required by default)

`runtime_write_exposure` inspects every pinned runtime file and its ancestor directories, every `sys.path`
tree, every declared package tree (including extension modules and other files under it), every closure root
and every pinned native. A symbolic link is followed as well as inspected: the link, its target, and the
target's ancestors must all pass, for absolute and relative links, and a symlinked ancestor is judged by what
it resolves to. The inspection runs **first**, before `authenticate_runtime`, before the census and before the
first interpreter exists (`_protection_gate`).

* **Trusted principals are named by the operator, never inferred.** The trusted writers are root (uid 0) on
  POSIX, or SYSTEM / Administrators / TrustedInstaller on Windows, plus whatever the operator adds with
  `--trusted-uid` / `--trusted-sid` (`ProtectionPolicy.build`; a malformed value is
  `runtime_protection_policy_invalid`). The evaluating principal (the uid or token SID that is running the
  parent) is **never trusted implicitly**: a policy that names it is refused (`runtime_protection_policy_invalid`,
  detail `trusts_evaluator:<label>`). The evaluator and the writers of the protected paths are **separate
  principals**, and that includes administrative ones: an evaluator that holds a trusted administrative
  identity (uid 0 on POSIX; an enabled SYSTEM / Administrators / TrustedInstaller token SID on Windows) is
  itself a principal that can rewrite every protected path, so the run is refused with
  `runtime_evaluator_privileged` (receipt reason `runtime_evaluator_privileged:uid:0`, or the SID label) and is
  never acceptance grade. Consequently an acceptance-grade run needs an **unprivileged** evaluator
  (for example a dedicated uid that was started from a root-owned launcher with privileges dropped) over a runtime
  and closure tree that is owned by root (or another principal the operator has named who is not the
  evaluator) and is not writable by the evaluator. A non-root evaluator running out of its own home-directory
  venv cannot be acceptance grade; a root evaluator over a root-owned tree cannot be acceptance grade either.
  Both are deployment prerequisites, not something software can establish. The authored protected positive
  (`test_a_non_privileged_evaluator_over_a_root_owned_unexposed_tree_yields_an_acceptance_grade_pass`) drops privilege to a
  non-privileged uid over a root-owned tree; a second positive
  (`test_the_installed_wheel_yields_an_acceptance_grade_pass_for_a_non_privileged_evaluator`) does the same over the
  genuine installed wheel. Both are AUTHORED_NOT_RUN and need root and a root-owned interpreter; on a host without
  them they are skips, and failures under `PVC_REQUIRE_PROTECTED=1`. That a host cannot provide the tree is a
  refusal of an unsupported configuration, distinct from the working required path these positives exercise.
* **POSIX policy `posix-owner-mode-acl-v2`.** Each inspected path must be owned by a trusted uid, have no
  other-write bit, no group-write bit (the only group accepted is gid 0, and only if every member of that group
  is root), carry no POSIX ACL (a failure to read ACLs is an inspection error, not "no ACL"), and, when the
  evaluator is not root, not be writable by the evaluator (`owner:<uid>`, `other_write`, `group_write:<gid>`,
  `acl`, `evaluator_writable`). A sticky directory is tolerated only as an ancestor, never as a path whose
  entries matter. A privileged evaluator is reported first, as the marker `evaluator [privileged_evaluator:<label>]`
  in `exposed`, so the receipt reason names the privilege rather than a path; a path walk that finds no overlap
  between the evaluator's groups and the path's group no longer indexes an empty overlap (the eager
  `IndexError` is gone) and yields a `REJECTED` receipt with the true reason.
* **Windows policy `windows-owner-dacl-v1` (NOT_RUN).** The owner SID must be trusted and the decoded DACL may
  grant write/replace rights only to trusted SIDs (`owner:<sid>`, `null_dacl`, `dacl_write:<sid>:<mask>`);
  deny entries and inherit-only entries are ignored, a DACL with an unsupported ACE type is an inspection
  error, and ancestors are judged by the replace mask rather than the full write mask. The view needs the
  process token SIDs; it has been written against the documented structures but has **not** been executed on
  Windows. It is evidence for hosted CI, not a completed Windows implementation.
  A real-process positive is authored (`WindowsProtectedAcceptance`, AUTHORED_NOT_RUN): an elevated test process
  creates a disposable tree whose DACL grants only SYSTEM / Administrators write (Authenticated Users read), copies the
  interpreter into it, and runs the launcher in a **separate non-privileged evaluator process** created from a
  restricted copy of the caller's own token (`CreateRestrictedToken` with `DISABLE_MAX_PRIVILEGE`; the Administrators
  SID becomes deny-only; no account, group, subscription or host change, and the token is used for that one child).
  The test first reads the evaluator's own enabled token SIDs, elevation and write ability through a probe running
  inside it (and the same probe in a deliberately privileged process, which must report the opposite), then requires an acceptance-grade `PASS` whose receipt records the Windows
  policy, `job_object` containment, `enforced`/`inspected` true and no exposed path. It cannot pass by permanent
  refusal, by injected facts alone, or by a skip switch: a missing prerequisite is a skip only while
  `PVC_REQUIRE_WINDOWS_PROTECTED` is unset and a failure when the hosted Windows job sets it; the gate lives in
  `setUpClass` and the class has no `skipUnless`, so a non-Windows host with the requirement set fails instead of
  skipping. The same tree also runs a second closure that imports a real extension file of the copied interpreter which
  imports an API set (found from the file's own PE import names, never assumed), under the restricted evaluator, and
  requires an acceptance-grade `PASS` with that extension in `loaded.native` and `native_files`: the armed native
  path with a real process. A privileged evaluator is refused before a writable tree is reported, on both platforms,
  and the real-run negatives expect that precedence (`runtime_evaluator_privileged`) when the suite itself runs
  privileged. Native execution stays NOT_RUN until the delivered change runs in normal hosted CI.
* **Fail closed.** A path that cannot be examined (any error other than "absent"), a tree larger than
  `MAX_EXPOSURE_ENTRIES`, a failed ACL or link-target read, and a platform without an inspector all end the run as
  `REJECTED` with `runtime_protection_not_inspectable`; an exposed path is `runtime_writable_by_others`. Both
  happen before anything is executed.
* `allow_unprotected_runtime=True` (`--allow-unprotected-runtime`) records the same evidence and continues.
  The receipt's `runtime_protection` is `{inspected, enforced, paths_checked, exposed, policy, trusted}`;
  such a run has `enforced: false` and is **never acceptance grade**. It is the diagnostic mode only.
* This is an inspection at one moment, not proof of immutability: root and the named trusted principals can
  still change a file later; the post-run authentication and the single-read capture bound that window.

### Receipts: integrity, not provenance

`binding_sha256` is an **unkeyed** SHA-256 over every other receipt field. It detects accidental or
partial edits of a stored receipt; anyone can recompute it after editing, so it is **not** provenance
and not a signature. Provenance requires an external signing or custody step, which is outside this
module. `validate_receipt` therefore checks, in order: exact key set, versions, canonical form, the
binding, status and reason, the shape of **every field that is present for every status** (a `REJECTED`
receipt may omit evidence but anything it carries must be well formed), the **cross-checks between the
fields that are present** (`receipt_evidence_inconsistent`: loaded modules against the closure, the retained
runtime-module rows and their digest, native file rows against `loaded` and the runtime rows, the native
plan and mapped files against the pinned natives), and then the status-specific invariants (below).
The cross-checks run for `REJECTED` receipts too, so a rejected receipt cannot carry evidence that
contradicts its own closure or runtime. A *resealed* edit that breaks any invariant is still rejected.

**Acceptance mode.** `verify_receipt(..., require_acceptance=True)` is the default and the only mode a
consumer may treat as acceptance of a `PASS` or `HOLD`. It requires the trusted context: the `manifest`
(recomputed and compared with `expected_manifest_sha256`), the `expected_inputs` digests and the
`expected_params_sha256` (`receipt_context_required` when any is missing), and the `expected_module_table`
(`receipt_context_required`, detail `module_table`). The table is the **trusted expected context**, supplied by the
reviewer out of band: the receipt records only its commitment (`evidence.module_table_sha256`), and the consumer
checks (`receipt_module_identity_mismatch`) that the commitment equals the digest of the supplied table, that every
reported runtime row `(module, sha256)` is a row of that table with the same hash, that every reported native file
is a table row of a native extension with the same path and hash, that the `loaded.stdlib` and per-distribution
`loaded.package` counts equal exactly what the table assigns to the reported modules, and (with the manifest) that
every distribution the table assigns a file to is a declared one. A digest
or count recomputed only from the receipt's own rows can therefore no longer satisfy acceptance: a forged or
missing table, a table for another interpreter or closure, and a row that is not in the table are each refused.
Operator-supplied trusted inputs are a deployment prerequisite; the API enforces the correspondence. Acceptance
additionally refuses
(`receipt_not_acceptance_grade`) a receipt whose `implementation_source` is not `launcher_capture`; whose
`runtime_protection` is not inspected and enforced, with no exposed path, with the exact policy for the
platform, with the trusted set containing root (`uid:0`), and with `paths_checked > 0`; or whose
`process.containment` is not `subreaper` (POSIX) or `job_object` (Windows). The receipt carries a canonical
result digest and status for every run. If the run used `embed_result=False` the receipt contains no result
body, so acceptance additionally requires the consumer to supply `result=`; its digest and status are checked
against the receipt, so a `PASS`/`HOLD` can never be accepted without something to compare it with. With
`require_acceptance=False` the context is checked only where supplied; that mode is for diagnostics and tests.

## Manifest (`paper-verifier-closure-manifest`)

Schema: `schemas/runtime/paper-verifier-closure-manifest.schema.json` (also packaged under
`trace_gc/data/schemas/`; generated by `tools/verifier_closure_schemas.py` through
`tools/build_schemas.py`). Shape is validated exactly (no extra keys, sorted lists, derived paths,
bounded path lists, unique native and core-file entries).

| field | content |
|---|---|
| `entry` | `{module, callable}`; the callable must be statically bound at module top level |
| `modules[]` | `{name, root, path, sha256, bytes, package}` for **every** executable closure module; `path` is derived from `name` |
| `edges` | module -> modules it statically imports (including ancestors and approved dynamic targets), recomputed from captured bytes and compared |
| `dynamic[]` | approved literal dynamic imports `{module, target}` |
| `dependency_operations[]` | reviewed per-importer dependency operations `{importer, form, module}` with `form` one of `import`, `import_module`, `find_spec` (at most 32); each is an explicitly approved operation by a pinned census module on an unpinned or ambiguous module (answered as absent) **or** a dynamic operation on a pinned module (performed), see "Import and load enforcement" |
| `packages[]` | declared third-party distributions: `{distribution, version, root, top_level[], census_sha256, census_files}` |
| `runtime` | exact interpreter, standard-library, native and startup contract |

Root *paths* are supplied at run time (`roots={alias: directory}`), never recorded.

### Roots

* Each root must be an existing plain directory, and **every ancestor up to the file-system root must
  be a plain directory**: a symlink, junction or reparse point anywhere above a root redirects it and is
  `root_ancestor_link_or_reparse_point`. (A checkout reached through a symlinked parent must be
  supplied by its real path.) Inputs follow the same rule.
* Two roots may not be equal (`roots_not_distinct`) or nested (`roots_nested`).
* Several declared distributions may share one install root. The root is owned once, the module table
  lists each file once, and **each file is owned by the distribution whose declared top-level names contain
  it** (never by a combined label such as `a+b`). Files that no declared top-level name covers are
  rejected, and genuine ambiguity (the same module name from two different files, case collisions,
  package vs module) is still rejected. The `loaded.package` counts and the receipt therefore name
  individual distributions.

## Order of operations

1. Arguments: finite `0 < timeout <= 3600` (total: any int or float, including one too large for a float,
   is accepted or rejected, never an exception), flag types, digests, roots, input specifications **including
   the syntax of every relative input path**, and `params` are validated and **copied once**
   (`_snapshot`) before any census, interpreter or child exists. Later steps never re-read the caller's
   objects. `params` must be canonical JSON data (`params_not_canonical`). The recorded `timeout_ms` is the
   timeout rounded **up** to whole milliseconds, so a positive timeout is never recorded as `0`. That same
   timeout is one deadline for the **whole operation** (`_Operation`): protection inspection, hashing, the
   census, the probe, package census, launch, delivery, execution, cleanup and the post-run checks all draw on
   it, and exhausting it ends the run as `REJECTED` with `operation_deadline_exceeded` (class `execution`).
2. Release digest over the six implementation files (the launcher's capture when present), then manifest
   shape and manifest digest. Nothing from the manifest is executed.
3. Runtime write-protection gate (above), then runtime authentication, then the probe child (the same
   bootstrap, probe mode) reports facts only; the parent compares them with `manifest.runtime`.
4. Closure modules: path components (no symlink/junction/reparse point, exact on-disk case, no
   Windows device/ADS/short-name forms), regular file, size, SHA-256; all bytes are **captured**.
5. Resolution ambiguity: package-vs-module, sourceless `.pyc`, extension siblings, case collisions,
   namespace packages, and the same module name resolvable under another supplied root.
6. A fresh static scan of the captured bytes (graph equals `edges`, every module reachable, no
   shadowing of standard-library or declared-package names), which also records the **import sites**
   (exact source positions and names) the child enforces per call site.
7. Declared packages: complete census of declared top-level names and the exact `.dist-info`.
8. Inputs: each `InputSpec(root, relative, sha256)` is read once and must match the supplied hash.
9. Launch (below): the child is created contained, and only then receives its stdin stream (on Linux, only
   after the supervisor has reported that it is ready).
10. Result acceptance (below) and post-run rechecks of closure, inputs, runtime and the bytecode prefix.

## Launch: a bounded command and an authenticated bootstrap transport

The bootstrap is far larger than the Windows command-line limit (32,767 UTF-16 units), so it is never put
on a command line. The child is started as

```text
python -I -S -B -X utf8 -X pycache_prefix=<new empty dir> -c <fixed ASCII stub>
```

The stub (`STUB_TEMPLATE`, a few hundred bytes; its SHA-256 is part of the release contract) embeds the
SHA-256 of the bootstrap and reads stdin with unbuffered `os.read`, so no later frame byte is consumed:

1. an 8-byte big-endian length, refused above `MAX_BOOTSTRAP_BYTES` (exit 71);
2. exactly that many bootstrap bytes, refused unless their SHA-256 equals the embedded digest (exit 72;
   a short stream exits 70);
3. only then does it `exec` those bytes, passing `_PVC_STARTUP` (the module names present before the stub
   imported anything) and `_PVC_BOOTSTRAP_SHA256`.

The same stdin then carries the request frame (`PVCLOS03`) or `PVCPROBE`. The parent refuses to start a
command longer than `MAX_COMMAND_UNITS` (`execution_command_too_long`), the request header repeats the
bootstrap digest and the child fails `bootstrap_binding` if it differs, and the report carries
`bootstrap_sha256` which the parent compares. The child never reads closure or input files itself.

## Runtime contract and the artifact census

The child runs with a private empty working directory and a minimal allow-listed environment (no
`PYTHON*`, `LD_*`, `PATH`). Behaviour of `-S` differs across Python versions; the pins therefore include
the observed startup module set rather than assuming it.

`manifest.runtime` pins, and every run re-derives:

* `invoked_executable` (the venv `python` as invoked) and `executable_resolved` are kept **separate**;
  `executable_sha256` is the hash of the resolved bytes, `pyvenv_cfg_sha256` covers the venv config
  that selects the home, `base_executable_sha256` covers the base interpreter.
* `version`, `cache_tag`, bytecode `magic`, `platform`, `bits`.
* `startup_config` (rows `[path, sha256 | "absent"]`) and `startup_files` plus its digest:
  interpreter startup inputs read before the bootstrap runs.
* `startup_modules_sha256` and `preload_modules_sha256`: modules loaded when isolated startup
  finishes and the ones the bootstrap preloads (built-in/frozen only).
* `census_sha256`/`census_files`: every file under each isolated-startup `sys.path` entry
  (standard library, `lib-dynload`/`DLLs`, `pythonXY.zip`), excluding `__pycache__`,
  `site-packages`, `dist-packages`; **absent entries are recorded**.
* `natives[]`: native shared objects mapped into the probe process (interpreter library, extension
  modules, startup dependencies) with path and SHA-256.

At run time the child serves standard-library and declared-package modules **only from the census
table** (name -> file, hash-on-read, compiled from exactly the bytes hashed). `sys.path` and
`PathFinder` are not consulted.

### Native libraries

* **The inventory is complete or unavailable.** The mapped-file inventory is `/proc/self/maps` on Linux and a
  module enumeration on Windows. If it cannot be enumerated completely (unreadable `/proc`, a failed
  enumeration, a module whose name cannot be read, a buffer that does not converge after bounded retries) the
  result is "unavailable", never a smaller set, and the child stops (`native_inventory_unavailable`). The
  probe does the same. Any other platform has no inventory and is refused.
* **At start.** After the frame bytes have been read and hash-checked (they are data, not executed) and before
  the import machinery is armed or any closure or census module is loaded, the child compares every file
  mapping with the pinned natives; an unlisted mapping stops it with `native_mapping_unlisted_at_start`.
* **Dependencies are resolved from hashed bytes and loaded first.** When a pinned extension module is about to
  be loaded, the child holds its hash-checked bytes, parses the dependency list from those bytes (ELF
  `DT_NEEDED`, PE import table) and builds a plan: each name must resolve to **exactly one** pinned native or
  to a library already mapped (on Linux by the object's `DT_SONAME` only, as glibc matches a `DT_NEEDED`
  string against an object it holds; on Windows by module name, with API-set names resolved to a loaded
  pinned host); each such native's own bytes are read and
  hash-checked, its dependencies are parsed in turn, and the plan lists dependencies before dependents (bounded
  by `MAX_NATIVE_PLAN` entries and `MAX_NATIVE_DEPTH` levels). Only then are the planned libraries loaded, in order,
  from verified bytes (Linux: sealed `memfd` via `dlopen`; Windows: the pinned path with `LoadLibraryExW`), so
  that when the extension itself loads the loader finds each dependency already in the process and performs
  no search. The loaded plan is recorded as `native_plan`. Refused **before the extension is loaded**: an
  unparsable image, a dependency that is unpinned, ambiguous or cyclic, a plan above the bounds, a dependency
  named by a path, audit/filter/auxiliary entries, PE delay-load imports, and `RPATH`/`RUNPATH` **in every
  mode, including discovery** (`native_closure_unparsable`, `native_dependency_unsupported`,
  `native_dependency_unpinned`, `native_dependency_ambiguous`, `native_dependency_cycle`,
  `native_dependency_plan_too_large`, `native_seal_failed`, `native_preload_failed`, `runtime_file_changed`).
  The discovery pass (`import` mode) does not plan (it exists to enumerate natives) but applies the same
  per-image unsupported-entry refusals, so source, `CONTRACT` and this document agree on `RPATH`/`RUNPATH`.
  After the run the resolved mapping is compared with the pins again (`unlisted_native_mapping`,
  `native_mapping_unexpected`).
* **What the plan does and does not establish.** The plan fixes which verified bytes are mapped for the
  dependencies a pinned extension names, and the identity decision is taken **before** any dependent loads:
  every backing memfd is retained until exit (so a descriptor number, which is the loader name of an object
  loaded from `/proc/self/fd/N`, is never reused), and after each `dlopen` `/proc/self/maps` must show a
  mapping with exactly that memfd's device and inode before the next object or the extension initialiser runs.
  The post-run mapping comparison is defence in depth only and never the identity decision.
  Narrowings, stated openly: (1) on Linux a pinned dependency **without a `DT_SONAME`** cannot satisfy a
  `DT_NEEDED` entry (the loader would not match it) and the plan is refused, even where the file basename
  happens to equal the needed name; (2) a pinned **extension module** is `dlopen`ed by the bootstrap before its
  `PyInit` runs, from its hashed bytes. Operating-system libraries that the interpreter itself needs (`libc`,
  the dynamic loader) are pinned by the mapping comparison, not preloaded. Dependencies that appear only
  through later `dlopen` calls from native code are outside the plan. The glibc matching behaviour and the
  Windows API-set host resolution (`GetModuleHandleW`) are written to the documented semantics and are
  **unverified until first execution**.
* **Windows (NOT_RUN).** An extension is opened through a handle that denies writers (`FILE_SHARE_READ` only) and
  re-hashed after the run. The bootstrap preloads `ctypes` for the handle work, which changes the preload
  pins and is a Windows-specific difference. The PE parser, import-name matching and `LoadLibraryExW` preload
  have never run on Windows. The Windows registry `PythonPath` is **not** inventoried and DLL search paths are
  not independently enumerated. Windows is therefore *implemented in source, not evidenced*; the Windows
  protection view is also unrun (see *Runtime write protection*).

### Residual runtime trust (honest)

* **Replace-execute-restore.** Hashing before and after a run cannot exclude an attacker replacing a
  file, executing, and restoring it. For closure modules, inputs, standard-library sources and loaded
  extensions this is closed because they are executed from bytes captured/hashed in the same read.
  Remaining windows: interpreter startup files read before the bootstrap runs, the interpreter image
  and `/proc`-mapped native libraries (`libc`, `ld.so`), and the interval between the launcher's single read
  and the moment the reviewer pinned the digests. A principal that is **named as trusted** (root, SYSTEM or an
  operator-named uid/SID) and rewrites the interpreter, libraries or these files is outside the model. The
  evaluating principal is not in that set: if it can write them, the protection gate refuses the run (and
  acceptance refuses the receipt), so the OS file-permission boundary is inspected and enforced, not assumed.
* Operating-system libraries, kernel behaviour, hash-randomisation seed, time, CPU/memory limits
  (only a wall-clock timeout) are not bound.
* A native not seen at build/probe time is not admitted: the import of a non-pinned extension module
  is refused (`unpinned_import:<name>`) at the finder, and a library that appears only in the mapping is
  `unlisted_native_mapping`.

Unsupported environments are rejected, not approximated: non-CPython, CPython < 3.11, platforms
other than Windows and Linux, a standard library containing a linked directory.

## Import and load enforcement (before loading)

The child installs a first `sys.meta_path` finder and an audit hook before any closure code runs, replaces
`builtins.__import__` and `importlib.import_module` with mediating functions, and classifies the **requesting
frame** by its code object's file name (never by `__name__`) as closure code, dependency code (census-loaded
standard-library and declared-package files), bootstrap, or other.

* **One policy, every route.** Every import statement, every `__import__` call, every `import_module` call, a
  first load, a `sys.modules` cache hit and each `from X import Y` submodule (when `X.Y` is already cached) goes
  through the same admission function *before loading and before the module cache is consulted*.
  Catching `ImportError` or deleting the module afterwards does not hide the attempt, because the attempt is
  recorded when it is refused.
* **Closure modules: exact source positions.** For each closure module the parent records its import sites as
  `(line, end_line, column, end_column, [names])` taken from the AST of the captured bytes. At run time the
  child reads the executing instruction's position from the frame (`co_positions()` at `f_lasti`) and the
  import is approved only if a recorded site of that module has **exactly that position** and names the
  requested module, and the module is a closure module, a census standard-library name or a declared package.
  Two calls on one line, or a literal import elsewhere in the same file, therefore do not approve one another.
  A refusal is `undeclared_import:X`, `unpinned_import:X` or `forbidden_import:X`.
  If the instruction has no complete position, there is no site and the import is refused. A callee written
  across lines (`importlib\n.import_module(...)`) cannot be attributed to a single site and is rejected
  statically (`dynamic_import_layout:<kind>`).
* `import importlib` in a closure module yields a small proxy (`_ImportlibProxy`) exposing only the mediated
  `import_module`. Its call is checked at the caller's exact position against the same sites; a non-literal
  argument has no site and is refused (`dynamic_import_not_literal:importlib`).
* **Dependencies.** Census-loaded standard-library and declared-package modules are hash-pinned but are not
  reviewed line by line, so they do **not** get positional approval. Their imports are mediated by the same
  functions, including `sys.modules` cache hits and `import_module`, and **every** denied module is refused
  to them under one admission policy (`_admit`). The policy is the reviewed operation table
  `DEPENDENCY_IMPORT_OPERATIONS`, a set of `(form, module)` pairs, currently `("import", "builtins")` only
  (the `import`/`__import__` form of `builtins`, which the standard library itself uses; `import_module` of
  `builtins` is not in it). This is an operation-level entry, not a module-level exemption: a denylisted
  module reached by any other operation is a **recorded violation** (`forbidden_dependency_import:<name>`, a
  receipt violation that makes the run `REJECTED`), in every route: fresh load, `sys.modules` cache hit, a
  relative name (resolved first against the requesting frame's package and against the `globals` argument of
  `__import__`, so a relative `import_module(".x", package)` cannot hide a denied absolute name), and an
  `importlib.import_module` call. Denied modules the interpreter preloaded are removed from
  `sys.modules` before the hook is armed. The audit hook additionally refuses process
  creation, `ctypes` use, dynamic library loading and (outside a short exact allowlist of standard-library callers)
  `exec`/`compile`/`marshal.loads` events, from any non-bootstrap caller. The only `ctypes` events a boot frame may
  raise are `ctypes.call_function` and `ctypes.dlopen`; the Windows API-set resolver therefore builds its output
  buffer **type** (`ctypes.c_wchar * 32768`) before the hook is armed, because instantiating an array type raises no
  event while `ctypes.create_unicode_buffer` raises a (denied) one. No allowance for any other `ctypes` event was
  added, and a dependency calling the same foreign function pointer from its own frame is refused.
* **One dependency-operation contract for pinned AND unpinned targets (declared, not informational).**
  Standard-library code legitimately probes optional modules under `try/except ImportError`, and libraries load
  modules by name at run time. Two kinds of operation need a declaration in `dependency_operations[]`
  (`{importer, form, module}`, where `importer` is the pinned census module whose code file issued the request, `form`
  is `import`, `import_module` or `find_spec`, and `module` is the absolute name; it may be pinned or unpinned but is
  never denylisted or closure-owned, `manifest_dependency_operations` otherwise; at most 32 rows, sorted, unique):
  1. an attempt to load a module that is **not pinned** (or is ambiguous): always answered as absent
     (`ModuleNotFoundError`), whatever the form;
  2. a **dynamic operation on a pinned module** (builtin and frozen modules included), performed when declared:
     `importlib.import_module` (absolute or relative, fresh or cached, directly or through an alias), an **explicit
     `__import__` call** (every call that is not an `import` statement, which includes a request made by C code on
     behalf of the importer, for example the `_strptime` import behind `datetime.strptime`; the instruction is
     *measured* at start-up with a recording stand-in, not taken from an opcode table, and an unmeasurable
     instruction makes every request dynamic, which only demands more declarations), a `__import__` `fromlist` item that
     names a pinned submodule, and `find_spec`: `importlib.util.find_spec` (absolute or relative, **cached or not**,
     directly or through an alias) is replaced by a mediating function that decides **before** the real function's
     cache shortcut (which returns a loaded module's spec without consulting any finder), attributing the operation to
     the caller. `importlib.util` is imported by the bootstrap itself BEFORE arming (it is a frozen module on some builds,
     which no loader hook would ever see), and every reachable entry point is replaced at arming by `_install_entry_points`:
     `importlib.import_module`, `importlib.__import__` and `importlib._bootstrap.__import__` (as `__import__`),
     `importlib._bootstrap._gcd_import`, `_find_and_load`, `_find_and_load_unlocked`, `_load` and `_load_unlocked` (as
     `import_module`), the deprecated `importlib.find_loader` where it exists, and `find_spec` of `BuiltinImporter`,
     `FrozenImporter`, `PathFinder` and `FileFinder` (as `find_spec`). The machinery's own calls (frozen importlib frames,
     `importlib/__init__`) and the boot frame pass through unchanged, so an `import` statement is never double-counted. A
     request that reaches the finder some other way, such as `importlib.reload`, is gated at the finder. The real
     `find_spec`'s own internal requests (its parent `__import__`, its finder call) are made on behalf of an already decided
     call and are not declared separately.
  An `import` **statement** of a pinned, non-denylisted module is the pinned census graph itself and needs no
  declaration. A declared operation is recorded in the receipt's `refused` list as
  `dependency_operation:<importer>:<form>:<module>` (the list name is historical: an unpinned target was refused as
  absent, a pinned one was performed); an **undeclared** operation in a verification run is a recorded violation
  (`undeclared_dependency_operation:<importer>:<form>:<module>`, `REJECTED`), never an informational entry, also
  when the dependency swallows the `ImportError`. There is no module-wide exemption: the same module by another importer or
  another form is a different operation. Two tables are reviewed and identical in the bootstrap, the parent and the
  `CONTRACT`: `DEPENDENCY_IMPORT_OPERATIONS` (the one denylisted target a dependency may import, `builtins` by
  `import`/`__import__`) and `DEPENDENCY_STDLIB_OPERATIONS` (`(importer, form, module, submodules)`, currently the single
  row `("encodings", "import", "encodings", True)`: the interpreter's codec search function loads `encodings.<codec>`
  with an explicit `__import__` call, which any closure that encodes text with an unloaded codec reaches; a test
  parses the real `encodings` package to check that this is what it does). Discovery (`build_manifest`) observes the
  operations and refuses to build while any is undeclared (`dependency_operation_undeclared`, naming the first in
  sorted order); the operator reviews the observed list and declares the rows deliberately (a conservative choice
  that needs no new authority). When the parent accepts the child's report it also requires every reported `refused`
  entry to be a `dependency_operation:` entry equal to a declared row. Residual limits, stated: the importer is
  identified by code file, so a helper dependency is its own importer; unpickling and other data-driven loads need
  declarations for the module names the data selects; a dependency's dynamic import of a closure-owned module cannot be
  declared and is refused. **Captured references fail closed**: after the replacement the bootstrap scans every loaded
  module for a remaining reference to any original entry point (`_captured_references`) and refuses to start
  (`captured_import_reference`) if one exists, so a cached or indirect operation cannot go around the contract through a
  reference taken before arming. The one thing that is not an import-system request is reading an already loaded module
  out of `sys.modules` (a dictionary read, not a load or a lookup); the functions `_find_spec`, `_exec`, `_init_module_attrs`
  and the loaders' own methods are not replaced because they take specs, not requests, and a spec can only come from an
  entry point above. Loaded-module identity is not a waiver for any entry point listed. These attributions are
  source-reasoned and first exercised in the hosted run.
* The same denied set is enforced statically and at run time: `runpy, pkgutil, imp, zipimport, ctypes,
  _ctypes, cffi, subprocess, multiprocessing, _winapi, _posixsubprocess, pty, builtins, msvcrt`
  (`forbidden_import:<name>`, including `from builtins import ...`). A test compares the two sets.
* Closure modules are served from captured bytes (`closure:<root>/<path>`; the loader class and
  compile name are fixed) and may not be replaced (`closure_module_replaced`); any module from an
  unlisted location is `module_from_unlisted_location`.
* The audit hook denies `exec`/`compile`/`marshal.loads` from non-bootstrap callers (a few exact
  stdlib callers such as `dataclasses`/`collections.namedtuple` are allowlisted), process creation,
  `ctypes`, dynamic library loading, `os.add_dll_directory`, `sys.setdlopenflags`, `winreg`.
* Preloaded/runtime shadowing: the finder and the final classification both reject a closure
  module whose name collides with a preloaded or runtime module.
* Sourceless bytecode, namespace packages, duplicate roots, case collisions and package-vs-module
  ambiguity are rejected statically and at the finder.

### Supported language and dynamic API policy

An AST scan **cannot prove closure**, and this document does not claim the denylist scan is the boundary.
The scan defines the *supported language* and rejects early; the exact-position runtime guard above, together
with the audit hook, is the enforcement. Indirect and aliased routes to an import (`print.__self__`, a
`vars()` lookup, a computed attribute name, a cached module) are not all visible to a static scan; they are
not "allowed" either: whatever object they reach is the mediated `__import__`/`import_module`, which finds no
recorded site for that position and refuses at run time. The guard lives in the same process as the code it
mediates, which is the honest limit of an in-process guard and why the primitive is not a sandbox. Rejected in
closure modules: `exec`, `eval`, `compile`, `__builtins__`, `breakpoint`; imports of
the denied set above; `os.system/popen/exec*/spawn*/fork*`, `os.add_dll_directory`; references to
`sys.path`, `sys.meta_path`, `sys.path_hooks`, `sys.path_importer_cache`, `sys.modules`,
`sys.setdlopenflags`; and any use of the name `importlib` other than a call to `import_module` (a bare
reference such as `x = importlib` is `importlib_reference_not_call`; importing it without an approved
dynamic import is `importlib_without_approved_dynamic_import`).

The **exact dynamic allowlist** is `importlib.import_module("literal")` or `__import__("literal")`
(absolute, one positional argument), each approved in the manifest as `{module, target}`. An
unapproved call, a non-literal argument or an unused approval is rejected, both statically and at
runtime (withdrawn approval -> `undeclared_import`). Everything else dynamic is unsupported.

## Request binding, result acceptance and statuses

The child reports on a private descriptor (stdin/stdout are devnull for the verifier) a single line
`PVCLOSURE-RESULT <nonce> <ascii-json>`. The parent accepts it only if, in this order of rejection:
containment cleanup succeeded and attach succeeded, the launch succeeded and did not time out, output did
not overflow, no unresolved descendants remain, and then:

* the line appears exactly once with the run's nonce, JSON is strict (duplicate keys, NaN/Infinity,
  non-ASCII and trailing data rejected; size <= 4 MiB) and has exactly the expected key set;
* it echoes the nonce, header digest, bootstrap digest, manifest digest, release digest, entry, mode, and
  input hashes (`protocol_request_binding`, `protocol_report_shape`, `protocol_no_valid_result`);
* exit code is 0 (`protocol_exit_status`);
* the loaded modules equal the manifest's, runtime modules equal the table, bytes unchanged after the
  run, the bytecode prefix is empty.

| status | meaning |
|---|---|
| `PASS` | every integrity check held and the verifier returned `PASS` |
| `HOLD` | every integrity check held and the verifier genuinely returned `HOLD` (`reason: verifier_hold`) |
| `REJECTED` | anything else, with `failure_class` in `arguments, closure, containment, execution, input, protocol, release, runtime` |

A verifier **exception, invalid result or timeout is `REJECTED`** with `execution_verifier_exception:<Type>`,
`execution_result_invalid` or `execution_timeout`; it is *not* reported as `HOLD`, so a genuine
verifier HOLD is never confused with a closure or execution failure. (This mapping was requested in
review and is recorded here for the reviewing authority to confirm.)

### Receipt (`paper-verifier-closure-receipt`)

Records manifest and release digests, the implementation rows and their `implementation_source`, runtime
pins and `runtime_protection`, closure and package digests, input hashes, `params_sha256`, the request
`{nonce, header_sha256}`, the canonical result digest and status (the body is embedded unless `embed_result=False`), `evidence`
(`report_sha256`, the runtime-module rows with their count and digest, the native file rows, the `native_plan`
and the mapped native paths), classification of loaded modules (closure and native modules as name to SHA-256, counts for the rest), violations,
the declared dependency operations that were observed (`dependency_operation:` entries; refused as absent for an unpinned target, performed for a pinned one), process facts (including `containment` and `timeout_ms >= 1`), `post_checks`
and `binding_sha256`. A `REJECTED` receipt is valid evidence only with `failure_class == failure_class(reason's
code)` and no verifier block, and any evidence it does carry must pass the same cross-checks as a `PASS`;
`PASS`/`HOLD` must carry the sorted implementation list, all four `post_checks` true, no violations and the
evidence block. The published schemas constrain the same shapes and the limits the validator enforces
(bounds on lists, strings and counts), including the status-dependent rules, where JSON Schema can express
them; the Python validator is authoritative for the cross-field rules a schema cannot state.

**Reason/process relationships.** A `REJECTED` reason and the process flags must agree
(`receipt_evidence_inconsistent`, detail `reason_process:<head>`). The flags are ordered `cleanup_failed`,
`timed_out`, `overflow`, `descendants`: a reason that names one of them requires that flag set and every
earlier flag clear; any other reason requires all four clear, except the neutral reasons
`operation_deadline_exceeded` and `execution_internal_error`, which may carry any flags. The schema states the
same table (`allOf`) and also states the status conditionals: an embedded `PASS`/`HOLD` result's status must
match the receipt status, `PASS`/`HOLD` require the evidence block, true `post_checks` and no violations, and
`REJECTED` requires a coded reason. `implementation` has exactly six positions (`prefixItems`, one per
release file in order, `items: false`), not a list of "at least" six; Python and schema share the runtime
string bounds, including the rule that a runtime string has `0 < length`.

**Individual runtime, package, extension and native identities.** Each individual row is related to a trusted
expected context, not only to an aggregate recomputed from the receipt's own rows. The reviewer-held complete module
map (`expected_module_table`; the verifier's `module_table`, a sorted list of `(module, kind, path, sha256, package, distribution)`
rows, `kind` being `py`, `ext` or `ambiguous`, with a canonical digest `module_table_digest`) is the context: acceptance compares the receipt's
`evidence.module_table_sha256` commitment with that map and then checks each reported runtime row, native file row and
loaded count against it (`receipt_module_identity_mismatch`, details `table_commitment`, `table_distribution`,
`runtime_row:<n>`, `native_file:<n>`, `loaded_counts`, `native_files_incomplete`, `loaded_native_incomplete`). The required
extension identities are **derived** from the reported runtime modules and the trusted map (every reported runtime module
the map classifies as `ext`, with the map's path and digest) and must equal **exactly** both extension-evidence
representations, `evidence.native_files` and `loaded.native`: an extension omitted from both, an extra or duplicated
row, or a forged path is refused, and the complete external map stays mandatory for acceptance
(`receipt_context_required`, detail `module_table`). A `native_files` row whose absolute path names a pinned native
must still carry that pin's digest (paths compared case-folded on Windows), and the plan and mapped files must lie
within the pins. At run time `verify_closure(..., expected_module_table_sha256=...)` (CLI
`--expected-module-table-sha256`) compares the live table with the operator's commitment after the verify core (whose
probe child has already run) and before the verifier child exists (`runtime_module_table_mismatch`); the digest
computation is a bounded phase. **Residual limits, stated:** the operator must obtain the map from a trusted
build or review (a deployment prerequisite, not something this module can create), and the receipt carries only the
commitment, so a consumer without the map can still check structure but cannot accept. The release `CONTRACT` text is
hashed into the release digest, so every edit of it changes that digest, which is intended; this completion changed it
(dependency-operation contract for pinned and unpinned targets, the reviewed standard-library table, the shared
cleanup deadline and late-effect ownership, the exact extension relationship), so any digest recorded earlier is
superseded.

**Reason/class relationship (complete).** `failure_class(reason head)` is one ordered table,
`FAILURE_CLASS_PREFIXES` (containment, protocol, execution, release, runtime, input, arguments), with the fallback
`closure`; no prefix of one class is a prefix of, or begins with, a prefix of another, so the result does not depend on
order. The published receipt schema encodes **every** class by the same prefixes (`if reason matches the prefixes then
failure_class is that class, else it is not`) and the fallback (`closure` exactly for a reason that matches none), and
the generator's `CLASS_PREFIXES`/`CLASS_FALLBACK` equal the validator's table (a test compares them and runs every reason
head against all eight classes through both the schema and the validator). Byte equality of the schema copies is not
parity; the parity is the matrix test. The generator itself has not been run (the copies were edited by hand).

### Transport and writes

* Manifest files given on the command line are read through an open descriptor, must be regular files (a FIFO is refused
  without blocking), are bounded by `MAX_MANIFEST_BYTES` and are parsed with the strict loader
  `trace_gc.canonical.loads`. That loader **accepts finite floats** (they hash as IEEE-754 binary64) and
  rejects duplicate keys, `NaN`/`Infinity`, numbers that overflow to infinity, integers beyond
  +/-(2**53-1) and integers too long to parse; every such failure is `manifest_unparseable`.
* `--root` and `--input` pairs are bounded (32 roots, 64 inputs), well formed and **duplicate free**
  (`argument_pair_invalid`). `--timeout` must be finite with `0 < t <= 3600`.
* `write_receipt` and the CLI writers loop until every byte is written (`write_incomplete` on zero
  progress). They write a private temporary file in the destination directory, `fsync` it, and publish it
  with `os.link`, which fails if the destination exists: the destination is either absent or complete, never
  empty or partial. Where hard links are unavailable, Windows uses `os.rename` (which refuses to replace);
  **every other platform fails closed** with `publish_unsupported` instead of an unsafe rename or an
  `O_EXCL` create-then-write. An existing target is never overwritten (`--receipt` that exists exits 2 with
  `receipt_exists`), and a failure leaves no partial target and no temporary file.

## Containment

The run has one operation deadline, described under *Order of operations*, ONE cleanup deadline
(`cleanup_end = operation deadline + CLEANUP_GRACE`, held by the `_Operation`) and ONE finalization window for sealing a
rejection (`finalize_end = cleanup_end + FINALIZE_GRACE`, at least `FINALIZE_FLOOR` long). The operation deadline is
checked before any stdin byte is delivered, when the child's exit is observed (a child that exits after the deadline is a
timeout, not a result), and once more after the required cleanup and immediately before a `PASS` or `HOLD` is applied
(`_Operation.tick("final")`); a deadline that has expired by then is `REJECTED` with `operation_deadline_exceeded`.

**The deadline is enforced on blocking system calls, not only between chunks.** Each blocking phase of the verify
core and the run (argument capture, which copies and canonicalizes the caller's manifest and `params`; run-directory
creation, protection inspection, runtime authentication, census, the runtime-pin step that hashes the start-up files and
resolves the executables, native inventory, closure read, `sys.path` and package census, graph and table, implementation
capture, roots, probe directories, frame, input capture, every manifest/release/params/result/evidence digest, the
acceptance of the child's report, and the post-run closure, input, runtime and bytecode checks) goes through
`_Operation.bounded(where, function, ...)`; the bounded set also includes the caller's `work_dir` and `python` path
conversion, the module-table commitment digest, the bootstrap hashing and stdin-stream construction of every launch
(probe and verifier), the probe's JSON parse, the implementation, input and closure digests and comprehensions, and the
checks of the child's reported rows. Tests check, by walking the syntax of `run_verifier`, `_run`, `_launch`,
`verify_closure`, `probe_runtime` and `_verify_core` (comprehensions and nested functions included), that none of these
operations is called there directly. The construction of the containment (the Windows job handle) is a bounded step with
its own late-effect ownership (`_build_containment`). Only `validate_timeout`, arithmetic on one number, precedes the operation. Inside a run
the call executes in a helper thread that carries the same operation, and the caller waits no longer than the time
left: a call that has not finished then is abandoned (`operation.cancelled` is set at once) and the run ends as
`REJECTED operation_deadline_exceeded:<where>:blocked` (`...:before_phase` when the deadline had already passed and
the phase never started). A phase that *succeeds* after the deadline is not accepted either
(`operation_deadline_exceeded:<where>:late`); a rejection the phase decided itself is passed through unchanged. The
caller therefore regains control at the deadline even if a read, `stat`, `mkdtemp` or security query is stuck in the kernel.

**Sealing.** An acceptance (`PASS`/`HOLD`) is serialized and bound inside the OPERATION deadline and the deadline is
checked again after the binding returned: a seal that blocks, finishes late or meets a non-canonical receipt turns the
verdict into a `REJECTED` receipt of the true reason (`operation_deadline_exceeded:seal:blocked|late`,
`protocol_receipt_not_canonical`, or the neutral `execution_internal_error:...` when the retained process evidence would
contradict the protocol reason). A rejection is sealed in the finalization window: the full receipt gets the first half
(one retry on a receipt whose result-bearing content is *withheld*: `refused ["finalization_content_withheld"]`, the causal
reason and the process evidence stay, so the retry can never seal a reason/process contradiction; the reason is only ever
re-chosen by `_consistent_reason`, with the validator's own rule); if that fails, the fixed-field **safety receipt**
(`_minimal_rejection`: only the already validated digests, a short canonical reason and its class, `refused`
`["finalization_fallback"]`, no process claim) is bound through `_direct_binding` for the rest of the window; if even that
does not finish, the same fixed-shape receipt is bound inline by `_safety_binding` (constant size, no helper, no I/O, no
caller data, no recursion). The result is therefore ALWAYS a valid sealed v1 receipt of a truthful rejection, the CLI
publishes only valid receipts, and no consumer needs a second return type. Nothing is retried outside the window.

**Abandoned work is owned, not forgotten.** A system call blocked in the kernel cannot be cancelled and may complete
after the caller returned. Every side effect it can still produce therefore has a durable owner:

* *Scratch directories* are created through the run's `_ScratchLedger` by the creating thread itself (`mkdtemp` is a
  side-effecting call, not a read). Each directory is recorded with the `(st_dev, st_ino)` it had when created. While
  the run is open its cleanup removes it; if the creation finishes after the run's cleanup ended, the creating
  thread removes it identity-bound, records the outcome, and an unconfirmed removal stays in `_ORPHANS` until
  `settle_orphans()` removes it (bound to the same identity; a path that was replaced is dropped, never deleted). **Only
  a confirmed absence** (`FileNotFoundError`/`NotADirectoryError`) means there is nothing to own: an inspection that fails
  any other way is retried briefly and, if it still fails, leaves the creation identity UNKNOWN. The directory then stays
  owned as an uncertain record (`_ORPHANS[path] = None`; the launch attempt's `prefix_identity` is `None`): it is never
  removed by name, because a later occupant of the pathname is not what was created, and it remains a cleanup failure
  until the pathname is confirmed absent. A readable occupant is not a confirmation.
* *Process launch* is a `_LaunchAttempt` that owns the pipes, the supervisor bytecode directory, the child, its
  streams and its thread, in an immutable state machine (`running -> adopted | failed | abandoned`, decided once under
  a lock). `_bounded_launch` does not cancel the creation; on timeout the attempt is marked `abandoned`, and
  cancellation is checked before **every** new effect (each of the two pipes, the directory, the process) so that
  nothing is started after a blocked call returns. When an in-flight `Popen` completes late the attempt itself asks the
  late supervisor to kill and reap its tree (`K`, `Q`), kills and waits for the child, closes its streams and descriptors
  and removes its directory by identity. That release is an idempotent, retryable step (`_settle_once`): if it cannot
  finish (the child is not reapable yet, the supervisor answers that processes still live, the directory will not go)
  the attempt registers itself in the owned registry and the caller's report says so (`cleanup_failed`). The attempt
  holds no reference to the caller's `_Containment`, so a closed containment is never written by a late effect, and a
  closed containment adopts nothing (`containment_closed`).
* *Executions* (`_ExecutionOwner`) own the live process, its containment, the pump threads and the pipe streams until
  every part is released: reap, close the containment once the process is gone, join the threads, and only then close
  the streams. **The Linux supervisor is the only owner of the run's descendants and is never ended while any of them is
  unconfirmed**: if it answers that processes live (or uncertain) it stays alive and owned for as long as that takes (the
  janitor only slows its pace after `SETTLE_BACKOFF_AFTER` passes, it never gives up); if it cannot answer, the
  descendants are enumerated from `/proc` by this process and ended through pidfds after a start-time re-check
  (`_kill_descendants`, two consecutive certain empty scans), and only then is the supervisor ended; `close` itself
  refuses to close a containment whose live supervisor has an unconfirmed tree. The one release that is not gated on a
  confirmed tree is a supervisor that already died by itself: its re-parented descendants have no owner left that could
  enumerate them (an operating-system fact, reported as `cleanup_failed`). A status descriptor whose reader is still
  blocked is closed by that reader when it ends. Nothing is parked in a list without a consumer.
* *The owned registry* (`_own`, `_OWNED`) holds a settler for every such debt. Consumers: `settle_orphans()` (directories
  and owned resources, ONE caller budget that each settler receives the remainder of, and no record is started once it is
  spent), an explicit `_LaunchAttempt.settle`, and a background janitor thread (a pass every `JANITOR_INTERVAL`
  seconds) whose retries have their OWN allowance
  (`SETTLE_FLOOR` per record per pass, never a caller's budget). A settler takes its lock inside its budget (a call that
  cannot get it reports "not settled" and starts nothing), supervisor requests are written to a non-blocking pipe, a
  supervisor that did not answer once is not asked again, there is one cleanup worker per record (a retry joins the worker
  in flight; `_REMOVING` for removals, `_SETTLING` for settlers) and a blocked settler never delays an unrelated record. A
  record is removed only when its settler reports that nothing is left. Truth is not changed by a later success: the run
  that could not release promptly reported `cleanup_failed`, and still does.
* *Pathname removal* (`_remove_tree`) is bound to the directory identity captured at creation: a path that is now a
  link, a non-directory or a different directory is `replaced` and left exactly as it is. On POSIX every entry is
  resolved relative to a verified directory descriptor and opened `O_NOFOLLOW`; the stop signal is checked **between**
  individual removals and again after every blocking inspection that precedes one (before the final `rmdir` that follows
  the last `lstat`, and between the Windows `unlink` and its `rmdir` fallback), so an abandoned removal does not start
  another one, and the concluding absence check runs inside
  the same bounded worker (`_bounded_remove`), so a stuck final `lstat` is "unconfirmed", never a pass.

**Cleanup is bounded, shared, and part of the verdict.** Every cleanup step spends from the ONE `cleanup_end`: the
`/proc` check, the supervisor kill/quit protocol, the supervisor-directory removal and listing, the thread joins, the
work-directory removal and its absence check (`_cleanup_slice`, `_Operation.cleanup_left`); no stage receives a fresh
allowance, so stuck steps cannot add up past `operation deadline + CLEANUP_GRACE`. `run_verifier` releases its
scratch ledger *before* the verdict is applied and the receipt is sealed; if removal is not confirmed inside the shared
deadline, `_settle_cleanup` turns a `PASS`/`HOLD` into `REJECTED containment_cleanup_failed:work_directory` with
`process.cleanup_failed` set, and a receipt that is already `REJECTED` keeps its reason and records
`work_directory_not_removed` in `refused`. The child's pipes are raw and unbuffered, so no `close()` can flush and
block; a stream a thread may still be blocked on is closed only after that thread ended, by the owner that retries
until then (`cleanup_failed` is recorded if it could not be done inside the shared deadline). A caller-supplied
`work_dir` belongs to the caller and is not removed.

**Residual operating-system facts (stated, not relabelled as external gaps).** (1) A blocked system call cannot be
cancelled; ownership guarantees that its eventual effect is settled, not that it never happens. (2) Windows has no
descriptor-relative removal, so a replacement between the identity check and the removal of one entry is not excluded
there; the identity check is repeated before each directory is listed. (3) On POSIX a removal by name can only remove a
replaced directory that is empty. (4) Orphans are retained in this process only; a crash of the verifying process ends
that retention. (5) A zombie is reaped only if the supervisor answers its kill/quit request or this process confirms the
tree empty itself; a supervisor that dies by itself leaves its re-parented descendants without an owner (`cleanup_failed`
stays the reported truth). (6) A directory whose creation identity could not be inspected stays an uncertain owned record
until the pathname is confirmed absent; this module cannot decide by name that an occupant is its own. All of this is
source-reasoned and covered by authored tests (`EnforcedDeadlines`, `LateEffectOwnership`, `FinalizationAndCancellation`; AUTHORED_NOT_RUN); the
blocked-call tests are timing based and need a first execution to confirm the margins.

* **Windows (NOT_RUN).** The Job Object handle has an owner from the moment it exists (`_Containment._open_job`): a
  failed `SetInformationJobObject` (or any exception after `CreateJobObjectW`) closes exactly that handle before the
  failure is raised, and the whole construction is a bounded step (`_build_containment`) whose late result is closed by
  the builder. The child is created `CREATE_SUSPENDED`, assigned to a kill-on-close Job Object,
  and only then resumed, so no child instruction runs outside the job. If assignment fails, the child is
  owned but not yet in the Job (`_assigned` is false): the parent terminates and reaps that one process
  directly through the handle it created (closing the Job would not touch it), then reports
  `containment_attach_failed`; the child has received nothing. If resume fails after assignment the Job is
  terminated. Only handles the parent created are ever signalled. Windows containment, including this
  path, is source and recording fakes only (NOT_RUN).
* **Linux: a subreaper supervisor owns the run.** The verifier interpreter is not started directly. The
  authenticated interpreter first runs a short supervisor program (`SUPERVISOR_TEMPLATE`, part of the release
  contract through the parent file) that sets `PR_SET_CHILD_SUBREAPER`, opens a `pidfd` for itself, starts the
  verifier interpreter as its own child and reports `R<pid>`. From then on **every descendant of the verifier,
  however it detaches, daemonises or is orphaned, is re-parented to the supervisor by the kernel** and is
  found by walking the process table from the supervisor. Membership is the kernel parent/child relation:
  it is not decided by an environment marker, a working directory, a session, or any string prefix of a path or
  command line, and no process outside that tree is ever signalled. A kill re-reads the process start time and
  signals through a `pidfd` so that a recycled pid is not hit.
* **Attach before data.** The parent writes no stdin byte (bootstrap or frame) until the supervisor has
  reported that it is armed and has started the verifier; failure to arm is `containment_attach_failed`, and the
  child receives nothing. Cleanup asks the supervisor for a bounded purge (`K`), confirms with its reply, and
  requires the supervisor itself to exit cleanly.
* **Uncertainty counts as survival.** An unreadable `/proc`, an entry that cannot be inspected, a missing or
  silent supervisor, or an incomplete purge is reported as a surviving process (`containment_cleanup_failed`
  or `containment_unresolved_descendants`), never as "none found". A vanished process is not uncertainty.
  An empty supervised tree is accepted only after the supervisor's atomic no-child check (`waitid(P_ALL,
  WEXITED|WNOHANG|WNOWAIT)`, which reports "no children" without reaping) is confirmed on two consecutive
  queries, so an orphan adopted between enumeration and the check is not missed.
* **Supervisor executes no cached bytecode and its dependencies are pinned.** The supervisor interpreter is
  started with a fresh, empty `-X pycache_prefix` directory (`supervisor_cache_clean()` requires it to be
  empty and readable after the run, otherwise the run is rejected), so no `.pyc` is trusted; the modules it
  imports (`SUPERVISOR_MODULES`: `ctypes`, `os`, `select`, `signal`, `subprocess`, `sys`, `time`) are part of
  the pre-effect probe and therefore of the pinned runtime/census closure before any effect.
* **Prerequisites and limit.** The supervisor needs `prctl`, `pidfd_open` and `pidfd_send_signal` (Linux 5.3 or
  later), a readable `/proc` and `ctypes` in the pinned interpreter; if any is missing the run is refused
  (`process_containment_unavailable`). A same-user process that deliberately kills the supervisor ends the
  guarantee; the end-of-run query then gets no answer, which is observed as uncertainty and the run is
  `REJECTED`, never accepted. This is containment for reviewed code, not a sandbox for hostile code.
* Cleanup is a bounded kill-and-verify loop (`CLEANUP_GRACE` seconds). A child that cannot be shown to
  be gone is `containment_cleanup_failed`; a child that cannot be started is `execution_launch_failed`;
  unresolved descendants are `containment_unresolved_descendants`. None of these is reported as PASS.

## Frozen `method_hashes` and the real identity impact

`src/parallel_source_v4/common.py` is unchanged by this work and none of the new files is a seed or an
import-closure member of the frozen `method_hashes()` computation, so on the **pre-integration** base the
complete output map is expected to equal the recorded baseline
`tests/data/method_hashes_baseline_04acabe.json` (87 files, recorded from `git archive 04acabe`, file SHA-256
`ab5f4014aeea3be429b18288f44f802e5f177a488ac1978c5bd432439f8485c4`). That baseline is **immutable**.

After the actual trustee-110 delivery is integrated this is no longer true and must not be claimed:
`trace_gc/phase_authority.py` is one of the 87 files and changes (baseline `b2ffc2e1...`, candidate
`0a97d666...`), and the delivered base may add closure members. The test therefore accepts exactly two
outcomes: the whole map equals the immutable baseline (and no dossier exists), or it equals the baseline with
the changes of a **reviewed dossier**, `tests/data/method_hashes_integration_dossier.json`
(`schema: method-hashes-integration-dossier-v1`; `baseline_sha256`, `delivered_base`, and per-path
`changed {from, to, reason}`, `added`, `removed`). A change whose `from` is not the baseline value, a change
without a reason, an undeclared difference or a missing dossier fails. **The dossier does not exist yet and
must not be invented**: it is produced at authorized validation against the delivered main by computing the
complete `method_hashes()` including any new closure members. No receipt may be labelled "unchanged" or
"frozen" for a map that differs from the baseline. Private historical receipts are not relabelled, and a
new binding does not authorize an expired private run.

That is **not** "no full-binding impact". `PaperPilot.implementation_identity()`
(`trace_gc/paper_pilot.py`) and `local_semantics.implementation_sha256()` hash
`sorted(root.rglob("*.py") + (root / "data/schemas").glob("*.json"))` over the **whole** `trace_gc`
package. These files therefore change both identities:

* `trace_gc/verifier_closure.py`, `verifier_closure_bootstrap.py`, `verifier_closure_launcher.py`;
* `trace_gc/data/schemas/paper-verifier-closure-manifest.schema.json` and
  `...-receipt.schema.json`.

Any edit to those five files after a given run changes the identity again. Existing phase, controller
and stage bindings that embed these identities cannot be relabelled. As recorded in
`docs/paper_pilot_workflow.md`, historical runs keep their pinned parent runtime, and consuming this
primitive from a private successor requires a separately reviewed compatibility handoff and the
authorized versioned release/rebinding process. The #19/#20 historical 97/111 receipt binding needs the
original approved mapping or a renewed real gate; missing private mapper or artifacts must be stated
explicitly, not reconstructed. `tests/test_paper_verifier_closure_v1.py` asserts that the enumeration used
by both consumers covers every implementation file and both schemas; it cannot show what any private
binding contains. Release and sdist packaging must list the new launcher file explicitly (`MANIFEST` and the
sdist file selection are outside this change and are owned by the integrating authority).

## What this does *not* do

A private successor to the frozen fresh-pilot evaluator would build a manifest for each of the
issue20, issue22 and recovery verifiers, have it reviewed, record the manifest and release digests
and the exact interpreter in the signed release, and call `run_verifier` through the launcher. The
original V6 evaluator and its history are untouched. The V7 rebinding, exact controller/stage release
rebinding and real prerequisite verifier runs are **NOT_RUN**; missing private V6 originals remain
missing and are not reconstructed. Mechanical success of this module does not satisfy the real
issue20/issue22/recovery gates or close #97.

## Status of evidence

* **Nothing is currently passing by execution.** Earlier runs of a previous revision (CPython 3.12:
  74 passed, 2 failed, 1 skipped; an installed-wheel run) and the interrupted CPython 3.11 and 3.13
  runs predate the later edits and are **not** acceptance evidence. The earlier claims that eleven, and then
  nine, findings were fixed are withdrawn. Independent review (Astra 10, CHANGES_REQUIRED) raised six finding
  groups (runtime protection, native verification, containment and deadline, import mediation,
  receipt/evidence/schema consistency, and test/installation gates); they are addressed **in source only**,
  and **none is closed** until an independent re-review of the exact delivered head says so. The earlier statement
  that no gaps were known is **superseded**: Astra 12 (CHANGES_REQUIRED) found seven further source findings (whole-operation
  and shared cleanup deadline, late-effect ownership, the API-set resolver under the armed audit hook, the dependency
  operation contract for pinned targets, exact extension-map completeness, full reason/class schema parity, and
  unreachable or skippable test gates); they are addressed **in source only** and are likewise not closed. Astra 13
  (CHANGES_REQUIRED, source coverage incomplete) then found four more in the repair itself (argument capture and rejection
  sealing outside the deadline model, cancellation not checked before every subsequent effect, retained resources with no
  consumer, and the cached `find_spec` exemption); they too are addressed in source only, and no group is closed until a
  new independent review has read all thirteen current files. Astra 14 (CHANGES_REQUIRED, all thirteen files read; a
  diagnostic review of a quota-partial candidate) then found nine more: a finalization result that violated its own
  receipt interface, a rewrite that could seal a reason contradicting the retained process evidence, remaining
  synchronous work outside the deadline, a supervisor ended while descendants were unconfirmed, a registry that did not
  honor its shared budget, lost or substituted directory identity after a failed inspection, a Windows job handle leaked on
  a failed setup, cached-operation mediation that a frozen module or a captured reference bypassed, and a fixture
  call that could not reach its assertion. They are addressed in source only (see *Containment* and *Import and load
  enforcement*), nothing is closed, and the earlier statements that no gap was known stay withdrawn. The schema
  copies are source-authored by hand (four JSON files, the two manifest copies identical to each other and the two
  receipt copies identical to each other) and not generator output yet.
* The tests for the current source are **AUTHORED_NOT_RUN**, never executed here: bounded launch command and stub
  digest refusal; required protection with a synthetic view (each reason, trusted-principal positives, symlink
  targets and ancestors, every fail-closed error, Windows decisions) and a protected acceptance run that needs a
  root-owned runtime; ELF and PE parsers (including malformed images), the transitive native plan (order,
  diamond, SONAME alias, unpinned/ambiguous/cyclic/changed, size and depth bounds), the mapped-file and
  Windows-module inventories; exact-position import approval, cached-import enforcement, the importlib
  proxy, dependency mediation under the reviewed operation table (cached, indirect and relative forms),
  denied-import parity; whole-operation and total
  timeouts and `timeout_ms >= 1`; immutable capture; attach-before-frame containment and supervisor
  ordering with fake supervisors; Windows Job-before-Resume and attach-failure direct-termination recording
  fakes; a Linux adoption test; the supervisor bytecode-cache test; late-deadline and
  stdin-ignoring-child shutdown; uncertain Linux
  discovery; receipt validation (every present field, cross-checks for REJECTED receipts, reason/process
  relationships, acceptance context, `embed_result=False`); per-file distribution ownership; crash-safe
  publication; finite-float transport;
  schema parity with the generator; the baseline-or-dossier method map; the external launcher with all
  six pins, a privileged-evaluator refusal and a privilege-dropped protected positive (the caller-argument test
  is only a diagnostic opt-out and is not the protected positive); package-wide identity coverage; the
  decision table of the wheel gate (`PVC_REQUIRE_WHEEL` overrides `PVC_SKIP_WHEEL`); and an installed-wheel gate
  that builds an sdist, builds a wheel from it and installs that wheel with `pip` into a fresh virtual
  environment (it is a required failure when `PVC_REQUIRE_WHEEL` is set and a skip otherwise). The Windows
  protection view-model tests run on every platform, including Windows. Added in the completion pass (all
  AUTHORED_NOT_RUN): `EnforcedDeadlines` (blocked calls in every bounded phase before and after the launch, late
  phases that never start, bounded and unconfirmed scratch removal, the final acceptance tick, a blocked supervisor
  prefix, and the same run still passing inside the same deadline); the dependency-operation tests (declared
  absence, undeclared violation, wrong importer or form, discovery refusal); the trusted-module-map tests
  (`TrustedModuleIdentity`: agree, disagree, missing, forged commitment, forged row, wrong distribution, wrong
  counts); the installed-wheel acceptance-grade positive for a privilege-dropped evaluator
  (`InstalledWheel`); and the Windows real-process positive (`WindowsProtectedAcceptance`, with its restricted-token
  evaluator helper and gate-decision tests), which requires an acceptance-grade `PASS` and cannot pass by refusal,
  injected facts or a skip switch. Native execution of the Windows tests stays NOT_RUN until hosted
  `native-windows-verifier-closure` CI runs the delivered change.
  Added for the Astra 12 findings (AUTHORED_NOT_RUN): `LateEffectOwnership` (late `Popen`/`mkdtemp` resumption with the
  eventual child, descriptors, streams, directories, ledger and replaced-path/link cases) and the additions to
  `EnforcedDeadlines` (runtime-pin and start-up-file phase, run-directory creation, seal, absence check, shared cleanup
  deadline, a positive inside the bound); `ArmedCtypesAuditPolicy` (real interpreters, recorded `ctypes.*` events, the
  boot-frame call versus the same call from a dependency frame) and `WindowsArmedNativePath` (the real kernel32 binding
  resolving a real API set under the armed hook, its unresolved-host and unpinned-host negatives, and a closure that
  loads a real extension file that imports an API set); the pinned and unpinned dependency-operation matrix (fresh,
  cached, relative, indirect, `fromlist` and `find_spec` forms, each declared and undeclared) with the reviewed
  codec-lookup row checked against the real `encodings` package; the exact extension-evidence cases in
  `TrustedModuleIdentity`; the reason-head by class matrix over all eight classes; and the gate tests (discovery-denied
  and runtime-denied dependency tests are separate, the privileged-evaluator precedence on both platforms, no
  class-level skip on the required Windows classes, a failure when `PVC_REQUIRE_WINDOWS_PROTECTED` is set on a host
  without native Windows). Whether a given host runs the Windows classes is decided by that gate, not by a decorator.
  Added for the Astra 13 findings (AUTHORED_NOT_RUN): `FinalizationAndCancellation` (blocked and late argument capture,
  the late-success rule, repeated blocking of the first and of the fallback binding (a valid sealed safety receipt),
  non-canonical rewrite, the second pipe, the final `rmdir` and the Windows `unlink`/`rmdir` transitions, the second
  scratch creation, a child that cannot be reaped yet and is later reaped and closed by an explicit retry, by
  `settle_orphans` and by the janitor, an execution owner with retry (and no forced end), the reader-closed
  descriptor, the supervisor that answers "live" and is asked again, and the closed-containment rule), and the cached,
  relative and indirect `find_spec` rows plus the `importlib.__import__` and private `_gcd_import` rows of the
  dependency-operation matrix, with the denied variants of each.
  Several expected violation strings and the hand-built ELF/PE images are derived by reading, not by running,
  and may need correction at first execution.
* The generated schema copies were edited by hand to match `tools/verifier_closure_schemas.py`; the
  generator must be run and both copies compared byte-for-byte at integration.
* Wheel and sdist: the artifact gate above is authored; it has not run. The integrating authority must run it
  with `PVC_REQUIRE_WHEEL=1` and also install the actual release wheel built from the actual sdist.
* Native Windows (junction/reparse ancestors, Job Object, suspended creation, DLL loading, PE parsing and
  preload, the module enumeration, the ACL/DACL protection view, case-insensitive collisions, write-denied
  handle loading): **NOT_RUN** until hosted `native-windows-verifier-closure` CI. Source for a Windows
  protection view exists; it is untested, and a Windows acceptance claim needs that CI.
* Not a sandbox; the nonce is not secret from malicious closure code; the parent cannot authenticate
  itself (see *Pre-execution trust*).
* Undeclared file reads by a verifier are outside the binding; use `inputs`.
* Closure module and input path components are limited to `[A-Za-z0-9_][A-Za-z0-9_.+-]*`.
* Ancestor-link rejection may reject legitimately symlinked install locations; supply real paths.
* The post-run authentication and re-census add cost to every run.

## Limitations (stated, not waived)

* **Dependency code is pinned and mediated, not individually approved.** Census and declared-package files
  are authenticated by hash and receive the same mediated import functions, the denylist applied through the
  reviewed operation tables (only the `import` form of `builtins` and the one codec-lookup row are permitted) and
  the audit hook, but no per-import approval of static imports. Attempts to import unknown (unpinned or ambiguous)
  modules are refused as absent, and dynamic operations on pinned modules are performed, but both are violations
  unless the manifest declares that exact `(importer, form, module)` operation (see *Import and load
  enforcement*); declared operations are the reviewed per-dependency exceptions.
* **Acceptance needs a trusted writer other than the evaluator, and the evaluator unprivileged.** The runtime,
  packages and closure roots must be owned by root (or an operator-named, non-evaluating principal) and not
  writable by the evaluator, and the evaluator must not itself be uid 0 or hold an administrative Windows
  token (`runtime_evaluator_privileged`). A non-root evaluator working from its own tree can only produce
  diagnostic (`--allow-unprotected-runtime`) receipts. Establishing that the interpreter, launcher and pinned
  digests are the intended ones remains the external trusted-channel prerequisite described under
  *Pre-execution trust*.
* **Trusted module map is an operator input.** Individual standard-library, package and extension identities are
  checked row by row against the reviewer-held complete module map in acceptance; the map must come from a trusted
  build or review and is not something the receipt can supply for itself.
* **Blocked system calls are abandoned, not killed, and what they still produce is owned.** The deadline returns
  control to the caller and fails closed; a stuck helper thread is left to finish on its own, its result is discarded,
  and any scratch directory, child, descriptor or stream it still creates is settled by its owner (see *Containment*).
  The operating-system facts that remain are listed there (a blocked call cannot be cancelled, no descriptor-relative
  removal on Windows, name-based removal on POSIX, in-process retention, supervisor-dependent reaping); they are not
  gaps relabelled as external.
* **Operator-held trusted pins and the module map are legitimate deployment prerequisites, not replacements for
  software checks.** The software still derives and compares every identity it can (for example the exact extension
  relationship above); the operator supplies only what the software cannot create: the trusted interpreter, launcher
  and digests, the complete reviewed module map, and the unprivileged evaluator over a protected tree.
* **Linux no-SONAME dependencies are refused** and pinned extension modules are `dlopen`ed by the bootstrap before
  their `PyInit` (see *Native libraries*); both are deliberate narrowings, not silent ones.
* **Windows.** There is no permanent Windows refusal: the Windows protection view, DACL decisions, Job
  Object containment and PE/API-set handling are written in source, decision-tested with injected facts and
  covered by the authored real-process positive, but nothing has run on Windows. Windows first-execution risks:
  `CreateProcessAsUserW` needing `SeIncreaseQuotaPrivilege`, desktop access for the restricted token, copying the
  interpreter tree, short versus canonical path equality of `invoked_executable`, nested Job Objects, the system
  drive root ACL tripping the ancestor replace mask, `icacls /setowner` permission, and `DISABLE_MAX_PRIVILEGE`
  only disabling (not removing) privileges.
* **Same-user supervisor kill.** The Linux containment guarantee ends if a same-user process kills the supervisor;
  that is observed as uncertainty and rejected, not prevented.
* **Loader behaviour.** The native plan and the memfd loading rely on glibc-style handling of already-loaded
  libraries by `DT_SONAME`; Windows relies on `LoadLibraryExW` name reuse and `GetModuleHandleW` API-set
  resolution. The per-load device/inode check and retained descriptors are the pre-load identity decision on
  Linux; the post-run mapping comparison is observational only.
* **Interpreter assumptions to verify per version.** The exact-position check depends on CPython's
  `co_positions()` for the instruction being executed (3.11 to 3.13, including multi-line calls and the
  3.12 location of method calls). The patched `builtins.__import__` is used instead of the interpreter's
  `import_name` fast path; the bootstrap's preloading of `importlib` and `_ctypes` changes the preload pins. These are checked by authored tests that have not run.
* **Supervisor runtime dependencies.** The supervisor executes the pinned runtime's `ctypes`, `os`, `select`,
  `signal`, `subprocess`, `sys` and `time` files before the verifier; they are pinned census files probed before
  any effect, not closure code, and it runs with a fresh empty bytecode prefix. The interpreter itself, the
  launcher and the digests are deployment prerequisites, not waived.
* **First-execution risks (AUTHORED_NOT_RUN).** Expected violation strings, hand-built ELF/PE images, the
  `BASELINE` hash under CRLF checkouts, synthetic-view gate tests that walk the real runtime tree, the
  supervisor prerequisites (Linux >= 5.3, `/proc`), `co_positions` on 3.11 to 3.13, memfd/SONAME loader
  behaviour, the timing of the adoption test, the timing-based deadline tests (`TIMEOUT=6`; earlier real phases must
  finish inside it), declared-operation importer attribution by code file, and the protected positives (they need
  root, a root-owned readable interpreter tree and `subprocess.run(user=, group=, extra_groups=[])`, Python >= 3.9; a
  venv whose base interpreter is not root-owned makes the wheel positive skip, or fail under `PVC_REQUIRE_PROTECTED`) may all need correction
  at first execution. The wheel gate needs `build`, `setuptools`, `pip` and `venv`/`ensurepip`.
* **Not a sandbox.** Hostile closure code can still reach the in-process mediation functions' environment; the
  guard raises the cost and records attempts, it is not a security boundary against hostile Python.
