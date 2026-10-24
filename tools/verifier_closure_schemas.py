"""Strict versioned schemas for the external verifier executable dependency closure (#97).

The numeric bounds repeat the ``trace_gc.verifier_closure`` constants (MAX_MODULES, MAX_PACKAGES, MAX_NATIVES,
MAX_DYNAMIC, MAX_DEPENDENCY_OPERATIONS, MAX_INPUTS, MAX_MODULE_BYTES, MAX_INPUT_BYTES, MAX_TIMEOUT_MS, MAX_RUNTIME_ROWS, MAX_MAPPED, MAX_LOADED);
a test compares them.  JSON Schema cannot express every rule of the Python validators (unique module names across
rows, digest cross-references, sorted order, count invariants, evidence-versus-context relationships); those stay in
``validate_receipt`` / ``verify_receipt`` and the schemas are the structural, status-dependent subset that includes
every length, count, byte, pattern and enumeration limit the Python validators enforce, the six exact implementation
positions, the embedded-result status of PASS/HOLD, the COMPLETE REJECTED reason/failure_class mapping (every class
prefix of ``FAILURE_CLASS_PREFIXES`` plus the ``closure`` fallback for a reason that matches none) and the REJECTED
reason/process-flag relationships (``_cross_check_rejected``; keep ``CLASS_PREFIXES``/``PROCESS_REASONS`` in step).
"""
from copy import deepcopy

MAX_MODULES = 4096
MAX_PACKAGES = 256
MAX_NATIVES = 4096
MAX_DYNAMIC = 4096
MAX_DEPENDENCY_OPERATIONS = 32
DEPENDENCY_OPERATION_FORMS = ["import", "import_module", "find_spec"]
MAX_INPUTS = 64
MAX_MODULE_BYTES = 4 << 20
MAX_INPUT_BYTES = 256 << 20
MAX_TIMEOUT_MS = 3600 * 1000
MAX_RUNTIME_ROWS = 1 << 16
MAX_MAPPED = 8192
MAX_LOADED = 1 << 20
MAX_COUNTER = 1 << 40

MODULE_PATTERN = r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$"
ALIAS_PATTERN = r"^[a-z][a-z0-9_-]{0,31}$"
INPUT_NAME_PATTERN = r"^[A-Za-z0-9_.-]{1,64}$"
DISTRIBUTION_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]*$"
VERSION_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._+!-]*$"
CALLABLE_PATTERN = r"^[A-Za-z_][A-Za-z0-9_]*$"
TRUSTED_PATTERN = r"^(uid:[0-9]{1,10}|sid:S-1-[0-9-]{1,200})$"
PROTECTION_POLICIES = ["posix-owner-mode-acl-v2", "windows-owner-dacl-v1", "unavailable"]
CONTAINMENTS = ["job_object", "subreaper"]
IMPLEMENTATION_PATHS = ["trace_gc/__init__.py", "trace_gc/canonical.py", "trace_gc/errors.py",
                        "trace_gc/verifier_closure.py", "trace_gc/verifier_closure_bootstrap.py",
                        "trace_gc/verifier_closure_launcher.py"]
CLASS_PREFIXES = [("containment", ["containment_", "process_containment"]), ("protocol", ["protocol_"]),
                  ("execution", ["execution_", "operation_"]),
                  ("release", ["release_", "implementation_", "expected_release", "expected_digest", "manifest_digest",
                               "bootstrap_"]),
                  ("runtime", ["runtime_", "unsupported_runtime", "census_", "native_", "interpreter_"]),
                  ("input", ["input_", "inputs_", "params_"]),
                  ("arguments", ["invalid_arguments", "roots_", "root_"])]
CLASS_FALLBACK = "closure"
_OFF = {"const": False}
PROCESS_REASONS = [
    ("containment_cleanup_failed", {"cleanup_failed": {"const": True}}),
    ("execution_timeout", {"timed_out": {"const": True}, "cleanup_failed": _OFF}),
    ("protocol_output_overflow", {"overflow": {"enum": ["stdout", "stderr"]}, "timed_out": _OFF, "cleanup_failed": _OFF}),
    ("containment_unresolved_descendants", {"descendants": {"const": True}, "overflow": {"type": "null"},
                                            "timed_out": _OFF, "cleanup_failed": _OFF}),
]
NEUTRAL_REASONS = ["operation_deadline_exceeded", "execution_internal_error"]
CLEAR_FLAGS = {"cleanup_failed": _OFF, "timed_out": _OFF, "descendants": _OFF, "overflow": {"type": "null"}}


def extend(schemas):
    text = {"type": "string", "minLength": 1}
    sha = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    flag = {"type": "boolean"}

    def count(upper=MAX_LOADED):
        return {"type": "integer", "minimum": 0, "maximum": upper}

    def bounded(upper, lower=1):
        return {"type": "string", "minLength": lower, "maxLength": upper}

    def pattern(value, upper=None):
        out = {"type": "string", "pattern": value}
        if upper is not None:
            out["maxLength"] = upper
        return out

    def obj(fields):
        return {"type": "object", "properties": deepcopy(fields),
                "required": list(fields), "additionalProperties": False}

    def nullable(value):
        return {"anyOf": [deepcopy(value), {"type": "null"}]}

    def listing(items, upper, *, lower=None, unique=True):
        value = {"type": "array"}
        if lower is not None:
            value["minItems"] = lower
        value["maxItems"] = upper
        if unique:
            value["uniqueItems"] = True
        value["items"] = deepcopy(items)
        return value

    path = bounded(4096)
    module = pattern(MODULE_PATTERN)
    native = obj({"path": path, "sha256": sha})
    path_list = {"type": "array", "maxItems": 256, "items": path}
    file_row = {"type": "array", "minItems": 2, "maxItems": 2, "prefixItems": [path, sha], "items": False}
    config_row = {"type": "array", "minItems": 2, "maxItems": 2,
                  "prefixItems": [path, {"anyOf": [deepcopy(sha), {"const": "absent"}]}], "items": False}
    runtime = obj({"implementation": bounded(4096), "version": bounded(4096), "cache_tag": bounded(4096),
                   "magic": bounded(4096), "platform": bounded(4096), "bits": {"type": "integer"},
                   "invoked_executable": bounded(4096), "executable_resolved": bounded(4096),
                   "executable_sha256": sha, "pyvenv_cfg_sha256": nullable(sha), "base_executable": bounded(4096),
                   "base_executable_sha256": sha, "base_prefix": bounded(4096), "sys_path": path_list,
                   "core_files": {"type": "array", "maxItems": 256, "uniqueItems": True, "items": path},
                   "census_sha256": sha, "census_files": {"type": "integer", "minimum": 0},
                   "startup_modules_sha256": sha, "preload_modules_sha256": sha,
                   "startup_files": {"type": "array", "maxItems": 256, "items": file_row},
                   "startup_files_sha256": sha,
                   "startup_config": {"type": "array", "maxItems": 256, "items": config_row},
                   "natives": listing(native, MAX_NATIVES)})
    schemas["paper-verifier-closure-manifest"] = obj({
        "version": {"const": "paper-verifier-closure-v1"},
        "name": {"type": "string", "minLength": 1, "maxLength": 120},
        "entry": obj({"module": module, "callable": pattern(CALLABLE_PATTERN)}),
        "modules": listing(obj({"name": module, "root": pattern(ALIAS_PATTERN), "path": text, "sha256": sha,
                                "bytes": count(MAX_MODULE_BYTES), "package": flag}), MAX_MODULES, lower=1),
        "edges": {"type": "object", "maxProperties": MAX_MODULES,
                  "additionalProperties": listing(module, MAX_MODULES)},
        "dynamic": listing(obj({"module": module, "target": module}), MAX_DYNAMIC),
        "dependency_operations": listing(obj({"importer": module, "form": {"enum": DEPENDENCY_OPERATION_FORMS},
                                              "module": module}), MAX_DEPENDENCY_OPERATIONS),
        "packages": listing(obj({
            "distribution": pattern(DISTRIBUTION_PATTERN), "version": pattern(VERSION_PATTERN),
            "root": pattern(ALIAS_PATTERN),
            "top_level": listing(pattern(r"^[A-Za-z_][A-Za-z0-9_]*$"), MAX_MODULES, lower=1),
            "census_sha256": sha, "census_files": {"type": "integer", "minimum": 1}}), MAX_PACKAGES),
        "runtime": runtime,
    })

    loaded = obj({"closure": {"type": "object", "maxProperties": MAX_MODULES, "propertyNames": module,
                              "additionalProperties": deepcopy(sha)},
                  "builtin": count(), "frozen": count(), "stdlib": count(), "startup": count(),
                  "package": {"type": "object", "maxProperties": MAX_PACKAGES,
                              "propertyNames": pattern(DISTRIBUTION_PATTERN, 200),
                              "additionalProperties": {"type": "integer", "minimum": 1, "maximum": MAX_LOADED}},
                  "native": {"type": "object", "maxProperties": MAX_NATIVES, "propertyNames": module,
                             "additionalProperties": deepcopy(sha)}})
    line = {"type": "string", "minLength": 0, "maxLength": 120}
    sha_row = {"type": "array", "minItems": 2, "maxItems": 2, "prefixItems": [module, sha], "items": False}
    native_row = {"type": "array", "minItems": 3, "maxItems": 3, "prefixItems": [module, path, sha], "items": False}
    plan_row = {"type": "array", "minItems": 2, "maxItems": 2, "prefixItems": [path, sha], "items": False}
    receipt = obj({
        "version": {"const": "paper-verifier-closure-receipt-v1"},
        "status": {"enum": ["PASS", "HOLD", "REJECTED"]},
        "reason": bounded(200),
        "failure_class": nullable({"enum": ["arguments", "closure", "containment", "execution", "input", "protocol",
                                            "release", "runtime"]}),
        "manifest_sha256": nullable(sha),
        "release_sha256": nullable(sha),
        "implementation": nullable({"type": "array", "minItems": 6, "maxItems": 6,
                                    "prefixItems": [obj({"path": {"const": item}, "sha256": sha,
                                                         "bytes": {"type": "integer", "minimum": 1,
                                                                   "maximum": MAX_MODULE_BYTES}})
                                                    for item in IMPLEMENTATION_PATHS],
                                    "items": False}),
        "implementation_source": nullable({"enum": ["launcher_capture", "disk_reread"]}),
        "runtime": nullable(runtime),
        "runtime_protection": nullable(dict(obj({
            "inspected": flag, "enforced": flag, "paths_checked": count(MAX_COUNTER),
            "exposed": {"type": "array", "maxItems": 50, "items": {"type": "string", "maxLength": 4096}},
            "policy": {"enum": PROTECTION_POLICIES},
            "trusted": {"type": "array", "maxItems": 64, "uniqueItems": True, "items": pattern(TRUSTED_PATTERN)}}),
            allOf=[{"if": {"properties": {"policy": {"const": "unavailable"}}, "required": ["policy"]},
                    "then": {"properties": {"inspected": {"const": False}, "trusted": {"type": "array", "maxItems": 0}}}}])),
        "closure": nullable(obj({
            "modules": listing(obj({"name": module, "sha256": sha, "bytes": count(MAX_MODULE_BYTES)}), MAX_MODULES,
                               lower=1, unique=False),
            "packages": listing(obj({"distribution": pattern(DISTRIBUTION_PATTERN),
                                     "version": bounded(200), "census_sha256": sha}), MAX_PACKAGES,
                                unique=False)})),
        "inputs": {"type": "object", "maxProperties": MAX_INPUTS, "propertyNames": pattern(INPUT_NAME_PATTERN),
                   "additionalProperties": obj({"sha256": sha, "bytes": count(MAX_INPUT_BYTES)})},
        "params_sha256": nullable(sha),
        "request": nullable(obj({"nonce": {"type": "string", "pattern": "^[0-9a-f]{32}$"}, "header_sha256": sha})),
        "verifier": nullable(obj({
            "returned": flag, "exception_type": nullable(bounded(200)), "result_sha256": sha,
            "result": nullable({"type": "object"})})),
        "loaded": nullable(loaded),
        "violations": listing(line, 50, unique=False),
        "refused": listing(line, 50, unique=False),
        "process": nullable(obj({"exit_code": nullable({"type": "integer", "exclusiveMinimum": -(1 << 40),
                                                        "exclusiveMaximum": 1 << 40}),
                                 "timed_out": flag, "stdout_bytes": count(MAX_COUNTER),
                                 "stderr_bytes": count(MAX_COUNTER), "stderr_sha256": sha, "descendants": flag,
                                 "cleanup_failed": flag, "overflow": nullable({"enum": ["stdout", "stderr"]}),
                                 "timeout_ms": {"type": "integer", "minimum": 1, "maximum": MAX_TIMEOUT_MS},
                                 "containment": {"enum": CONTAINMENTS}})),
        "post_checks": nullable(obj({"closure_unchanged": flag, "inputs_unchanged": flag, "runtime_unchanged": flag,
                                     "bytecode_dir_empty": flag})),
        "evidence": nullable(obj({"report_sha256": sha, "runtime_modules": count(MAX_RUNTIME_ROWS),
                                  "runtime_modules_sha256": sha,
                                  "runtime_rows": listing(sha_row, MAX_RUNTIME_ROWS, unique=False),
                                  "native_files": listing(native_row, MAX_NATIVES, unique=False),
                                  "native_plan": listing(plan_row, MAX_NATIVES, unique=False),
                                  "mapped": {"type": "array", "maxItems": MAX_MAPPED,
                                             "items": {"type": "string", "minLength": 1, "maxLength": 4096}},
                                  "mapped_sha256": sha, "module_table_sha256": sha})),
        "parent_sys_modules_collisions": listing(module, MAX_MODULES, unique=False),
        "binding_sha256": sha,
    })

    def when(statuses, then):
        return {"if": {"properties": {"status": {"enum": list(statuses)}}, "required": ["status"]}, "then": then}

    def embedded_result(status_value):
        return {"type": "object", "properties": {"result": {"anyOf": [
            {"type": "null"},
            {"type": "object", "properties": {"status": {"const": status_value}}, "required": ["status"]}]}}}

    def reason_pattern(codes):
        return "^(" + "|".join(codes) + ")(:|$)"

    def class_rule(prefixes, name):
        # failure_class() maps a reason head by these (disjoint) prefixes: the class holds exactly for such reasons
        return {"if": {"properties": {"reason": {"pattern": "^(" + "|".join(prefixes) + ")"}}, "required": ["reason"]},
                "then": {"properties": {"failure_class": {"const": name}}},
                "else": {"properties": {"failure_class": {"not": {"const": name}}}}}

    def fallback_rule():
        # a reason that matches none of the class prefixes is the fallback class, and only such a reason is
        every = [prefix for _, prefixes in CLASS_PREFIXES for prefix in prefixes]
        return {"if": {"properties": {"reason": {"pattern": "^(" + "|".join(every) + ")"}}, "required": ["reason"]},
                "then": {"properties": {"failure_class": {"not": {"const": CLASS_FALLBACK}}}},
                "else": {"properties": {"failure_class": {"const": CLASS_FALLBACK}}}}

    def process_flags(flags):
        return {"properties": {"process": {"anyOf": [{"type": "null"},
                                                     {"type": "object", "properties": deepcopy(flags)}]}}}

    def process_rule(code, flags):
        return {"if": {"properties": {"reason": {"pattern": reason_pattern([code])}}, "required": ["reason"]},
                "then": process_flags(flags)}

    obj_type = {"type": "object"}
    receipt["allOf"] = [
        when(["PASS", "HOLD"], {"properties": {
            "failure_class": {"type": "null"}, "manifest_sha256": deepcopy(sha), "release_sha256": deepcopy(sha),
            "params_sha256": deepcopy(sha), "implementation": {"type": "array"},
            "implementation_source": {"enum": ["launcher_capture", "disk_reread"]},
            "runtime": deepcopy(obj_type), "runtime_protection": deepcopy(obj_type), "closure": deepcopy(obj_type),
            "request": deepcopy(obj_type), "loaded": deepcopy(obj_type), "evidence": deepcopy(obj_type),
            "verifier": {"type": "object", "properties": {"returned": {"const": True}, "exception_type": {"type": "null"}}},
            "process": {"type": "object", "properties": {"exit_code": {"const": 0}, "timed_out": {"const": False},
                                                          "descendants": {"const": False}, "cleanup_failed": {"const": False},
                                                          "overflow": {"type": "null"}}},
            "post_checks": {"type": "object", "properties": {"closure_unchanged": {"const": True},
                                                              "inputs_unchanged": {"const": True},
                                                              "runtime_unchanged": {"const": True},
                                                              "bytecode_dir_empty": {"const": True}}},
            "violations": {"type": "array", "maxItems": 0}}}),
        when(["PASS"], {"properties": {"reason": {"const": "ok"}, "verifier": embedded_result("PASS")}}),
        when(["HOLD"], {"properties": {"reason": {"const": "verifier_hold"}, "verifier": embedded_result("HOLD")}}),
        when(["REJECTED"], {
            "properties": {"failure_class": {"type": "string"}, "verifier": {"type": "null"}},
            "allOf": [class_rule(prefixes, name) for name, prefixes in CLASS_PREFIXES] + [fallback_rule(),
                *[process_rule(code, flags) for code, flags in PROCESS_REASONS],
                {"if": {"properties": {"reason": {"not": {"pattern": reason_pattern(
                    [code for code, _ in PROCESS_REASONS] + list(NEUTRAL_REASONS))}}}, "required": ["reason"]},
                 "then": process_flags(CLEAR_FLAGS)}]}),
    ]
    schemas["paper-verifier-closure-receipt"] = receipt
