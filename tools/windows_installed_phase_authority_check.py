#!/usr/bin/env python3
"""Exercise the INSTALLED trace_gc wheel's phase-fence receipt validation on Windows.

Run it with the wheel installed in a clean environment, from a directory outside
the checkout, and in isolated mode so no checkout directory can shadow the wheel::

    python -I tools/windows_installed_phase_authority_check.py --source-sha256 <hex>

``--source-sha256`` is the SHA-256 of the checkout's ``trace_gc/phase_authority.py``;
the installed copy must be byte-identical, proving the wheel under test was built
from the reviewed source. The script imports only the standard library and
``trace_gc`` (never ``src``), builds an owned disposable layout, lets Windows
spell real DACLs, and checks that ``PhaseAuthority.verify_fence`` accepts a
receipt whose numeric SID Windows serialized as an alias while still rejecting a
different trustee, a distinct account/domain SID that shares RID 500, a changed
mask/flag/ACE type and a changed digest or archive byte. Only deny/allow ACEs
added here to paths beneath its own temporary directory are ever removed; no
ancestor or shared ACL is changed. Prints one JSON object; exit status 1 on any
failed check or unverified cleanup.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

USERS_SID = "S-1-5-32-545"      # serialized by Windows as the alias BU
GUESTS_SID = "S-1-5-32-546"     # an unrelated trustee, serialized as BG
FOREIGN_RID500_SID = "S-1-5-21-1111111111-2222222222-3333333333-500"  # fabricated domain
NAMES = ("checkpoint.sqlite3", "graph.sqlite3", "budget.sqlite3",
         "application-journal.sqlite3", "controller.lock")
PREFIX = "jraphyte-installed-phase-"


def call(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(list(args), capture_output=True, text=True, timeout=30)


def icacls(*args: str) -> None:
    result = call("icacls.exe", *args)
    if result.returncode != 0:
        raise RuntimeError("icacls failed")


def current_sid() -> str:
    out = call("whoami.exe", "/user", "/fo", "csv", "/nh").stdout.strip()
    match = re.search(r'"(S-1-5-[0-9-]+)"\s*$', out)
    if match is None:
        raise RuntimeError("current SID unavailable")
    return match.group(1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-sha256", required=True)
    args = parser.parse_args()
    report = {"python": sys.version.split()[0], "checks": {}}
    ok = True

    def check(name: str, passed: bool) -> None:
        nonlocal ok
        report["checks"][name] = bool(passed)
        ok = ok and bool(passed)

    if os.name != "nt":
        report["error"] = "Windows required"
        print(json.dumps(report, indent=2))
        return 1
    from trace_gc import phase_authority as authority
    from trace_gc.canonical import bytes_digest, dumps
    from trace_gc.errors import ContractError

    installed = Path(authority.__file__).resolve()
    parts = {part.lower() for part in installed.parts}
    check("imported_from_site_packages", "site-packages" in parts)
    check("cwd_is_not_a_checkout", not (Path.cwd() / "src").exists()
          and not (Path.cwd() / "trace_gc").exists())
    check("installed_matches_reviewed_source",
          hashlib.sha256(installed.read_bytes()).hexdigest() == args.source_sha256)
    check("sources_not_importable_from_checkout", "src" not in sys.modules)
    report["installed_module_sha256"] = hashlib.sha256(installed.read_bytes()).hexdigest()

    runner = current_sid()
    prefix = re.fullmatch(r"(S-1-5-21-[0-9]+-[0-9]+-[0-9]+)-[0-9]+", runner)
    if prefix is None:
        report["error"] = "machine/domain account SID required"
        print(json.dumps(report, indent=2))
        return 1
    local_rid500 = prefix.group(1) + "-500"
    plain = runner if not runner.endswith("-500") else prefix.group(1) + "-1001"
    owned_sids = {USERS_SID, GUESTS_SID, runner, local_rid500}

    # The canonical spelling is the operating system's own forward conversion.
    check("numeric_users_sid_is_serialized_as_alias", authority.canonical_dacl_trustee(USERS_SID) == "BU")
    check("foreign_rid500_stays_numeric",
          authority.canonical_dacl_trustee(FOREIGN_RID500_SID) == FOREIGN_RID500_SID)
    check("plain_account_stays_numeric", authority.canonical_dacl_trustee(plain) == plain)
    canonical = {authority.canonical_dacl_trustee(s)
                 for s in (local_rid500, FOREIGN_RID500_SID, plain)}
    check("distinct_rid500_and_plain_never_collapse", len(canonical) == 3)
    original = authority._is_windows
    authority._is_windows = lambda: False
    try:
        try:
            authority.canonical_dacl_trustee(FOREIGN_RID500_SID)
            failed_closed = False
        except ContractError as error:
            failed_closed = error.code == "PHASE_PLATFORM"
        check("numeric_sid_fails_closed_without_windows", failed_closed)
        check("alias_text_never_mapped_without_windows",
              authority.canonical_dacl_trustee("LA") == "LA")
    finally:
        authority._is_windows = original

    base_dir = None
    try:
        with tempfile.TemporaryDirectory(prefix=PREFIX) as temp:
            base_dir = Path(temp)
            parent = base_dir / "old-app"
            old = parent / "state"
            archived = base_dir / "archive" / "state"
            parent.mkdir()
            archived.mkdir(parents=True)
            files = {}
            for name in NAMES:
                body = ("installed:" + name).encode()
                (archived / name).write_bytes(body)
                files[name] = bytes_digest(body)
            receipt = base_dir / "fence.json"

            def lift(path: Path) -> None:
                for sid in owned_sids:
                    call("icacls.exe", str(path), "/remove:d", "*" + sid)
                call("icacls.exe", str(path), "/remove:g", "*" + USERS_SID)

            def write(deny_sid, *, dacl_sha=None):
                raw = authority.directory_dacl_sddl(parent)
                body = {"version": "paper-pilot-phase-namespace-fence-v1",
                        "old_root_path": str(old), "archived_root_path": str(archived),
                        "old_parent_dacl_sha256": dacl_sha or bytes_digest(raw.encode("utf-8")),
                        "archived_files_sha256": files, "deny_sid": deny_sid,
                        "status": "OLD_PATH_FENCED_NEW_PHASE_ALLOWED"}
                receipt.write_bytes((dumps(body) + "\n").encode("utf-8"))
                return raw

            def verify() -> bool:
                instance = object.__new__(authority.PhaseAuthority)
                instance.binding = {"fence_receipt_path": str(receipt),
                                    "fence_receipt_sha256": bytes_digest(receipt.read_bytes()),
                                    "old_root_path": str(old),
                                    "archived_old_root_path": str(archived)}
                instance._archived_lock_file = None
                try:
                    instance.verify_fence()
                except ContractError as error:
                    return error.code == "PHASE_FENCE" and "rejected"
                return True

            def accepted() -> bool:
                return verify() is True

            def rejected() -> bool:
                return verify() == "rejected"

            try:
                icacls(str(parent), "/deny", "*" + USERS_SID + ":(AD)")
                raw = write(USERS_SID)
                check("real_dacl_spells_numeric_sid_as_alias",
                      "(D;;LC;;;BU)" in raw and USERS_SID not in raw)
                check("alias_deny_accepted_by_installed_validator", accepted())
                write(GUESTS_SID)
                check("other_trustee_rejected", rejected())
                write(USERS_SID, dacl_sha="0" * 64)
                check("changed_raw_digest_rejected", rejected())
                write(USERS_SID)
                (archived / "graph.sqlite3").write_bytes(b"changed")
                check("changed_archive_bytes_rejected", rejected())
                (archived / "graph.sqlite3").write_bytes(("installed:graph.sqlite3").encode())
                check("restored_archive_bytes_accepted_again", accepted())
                for label, mask_args in (
                        ("mask", ("/deny", "*" + USERS_SID + ":(WD)")),
                        ("inheritance_flag", ("/deny", "*" + USERS_SID + ":(OI)(AD)")),
                        ("ace_type", ("/grant", "*" + USERS_SID + ":(AD)"))):
                    lift(parent)
                    icacls(str(parent), *mask_args)
                    write(USERS_SID)
                    check("wrong_" + label + "_rejected", rejected())
                lift(parent)

                # Machine RID-500 spelled by Windows (LA on this machine), then a
                # distinct RID-500 domain SID and an unrelated account must not match.
                icacls(str(parent), "/deny", "*" + local_rid500 + ":(AD)")
                write(local_rid500)
                check("machine_rid500_deny_accepted", accepted())
                for label, wrong in (("foreign_domain_rid500", FOREIGN_RID500_SID),
                                     ("plain_account", plain), ("users_group", USERS_SID)):
                    write(wrong)
                    check("machine_rid500_deny_rejected_for_" + label, rejected())
                lift(parent)

                # The runner's natural identity (LA on a hosted RID-500 runner).
                icacls(str(parent), "/deny", "*" + runner + ":(AD)")
                write(runner)
                check("natural_runner_deny_accepted", accepted())
                lift(parent)
                write(runner)
                check("absent_deny_rejected", rejected())
            finally:
                for path in [parent, *parent.rglob("*"), *archived.rglob("*")]:
                    if path.exists():
                        lift(path)
        check("owned_tree_removed", base_dir is not None and not base_dir.exists())
    except Exception as error:   # report the bounded type only, never paths or names
        report["error_type"] = type(error).__name__
        check("completed_without_exception", False)
    print(json.dumps(report, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
