#!/usr/bin/env python3
"""Exercise the INSTALLED trace_gc wheel's phase authority and trustee handling.

Run it with the wheel installed in a clean environment, from a directory outside the
checkout, in isolated mode so no checkout directory or PYTHONPATH can shadow the wheel::

    python -I tools/installed_phase_authority_check.py \\
        --declared-source phase_authority.py=<sha256> [--declared-source ...] [--require-windows]

Each ``--declared-source NAME=SHA256`` names a file inside the installed ``trace_gc``
package and the digest of the reviewed checkout source; the installed bytes must be
identical, proving the wheel under test was built from the reviewed source. Only the
standard library and ``trace_gc`` are imported (never ``src`` or a checkout path).

Two groups of checks are reported separately:

* ``portable_checks`` run on every platform: installation provenance, the fail-closed
  off-Windows contract (a numeric SID is never guessed, alias text is never mapped back
  to a numeric SID, the real ``PhaseAuthority`` constructor refuses to run).
* ``windows_checks`` run only on Windows: real DACL spelling by the operating system,
  the real ``PhaseAuthority`` constructor over a real signed activation pointer, and
  acceptance/rejection through ``write()`` and ``staging()`` with owned state unchanged
  after every rejection.

``native_windows`` is ``RUN`` or ``NOT_RUN``; off Windows nothing native is claimed.
Only ACEs this script added beneath its own temporary directory are ever removed. One
JSON object is printed; the exit status is 1 on any failed check, on unverified
cleanup, or (with ``--require-windows``) when not on Windows.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import tempfile

USERS_SID = "S-1-5-32-545"      # serialized by Windows as the alias BU
GUESTS_SID = "S-1-5-32-546"     # an unrelated trustee, serialized as BG
FOREIGN_RID500_SID = "S-1-5-21-1111111111-2222222222-3333333333-500"  # fabricated domain
PARENT_ACE = "(D;;LC;;;{sid})"
NAMES = ("checkpoint.sqlite3", "graph.sqlite3", "budget.sqlite3",
         "application-journal.sqlite3", "controller.lock")
PREFIX = "jraphyte-installed-phase-"
RUN_ID = "installed-run"
LIMITS = {"retrieval_requests": 5, "model_calls": 5, "retries": 5,
          "solver_expansions": 5, "review_actions": 5, "request_bytes": 5}


def call(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(list(args), capture_output=True, text=True, timeout=30)


def icacls(*args: str) -> None:
    if call("icacls.exe", *args).returncode != 0:
        raise RuntimeError("icacls failed")


def current_sid() -> str:
    out = call("whoami.exe", "/user", "/fo", "csv", "/nh").stdout.strip()
    match = re.search(r'"(S-1-5-[0-9-]+)"\s*$', out)
    if match is None:
        raise RuntimeError("current SID unavailable")
    return match.group(1)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Report:
    def __init__(self):
        self.data = {"python": sys.version.split()[0], "platform": sys.platform,
                     "native_windows": "RUN" if os.name == "nt" else "NOT_RUN",
                     "portable_checks": {}, "windows_checks": {}}
        self.ok = True
        self.group = "portable_checks"

    def check(self, name: str, passed) -> None:
        self.data[self.group][name] = bool(passed)
        self.ok = self.ok and bool(passed)


def portable(report: Report, declared: dict[str, str]) -> None:
    from trace_gc import phase_authority as authority
    from trace_gc.errors import ContractError
    report.group = "portable_checks"
    package = Path(authority.__file__).resolve().parent
    parts = {part.lower() for part in package.parts}
    report.check("imported_from_site_packages", "site-packages" in parts)
    report.check("isolated_mode", bool(sys.flags.isolated))
    report.check("no_checkout_in_cwd", not (Path.cwd() / "src").exists()
                 and not (Path.cwd() / "trace_gc").exists())
    report.check("no_source_package_imported",
                 not any(name == "src" or name.startswith("src.") for name in sys.modules))
    report.check("no_checkout_on_sys_path",
                 not any((Path(item or ".") / "src" / "paper_pilot_phase_cutover.py").exists()
                         for item in sys.path))
    report.check("declared_sources_declared", bool(declared))
    digests = {}
    for name, expected in sorted(declared.items()):
        target = (package / name).resolve()
        inside = target.is_relative_to(package) and target.is_file()
        digests[name] = sha(target.read_bytes()) if inside else None
        report.check("installed_matches_reviewed_source:" + name, digests[name] == expected)
    report.data["installed_source_sha256"] = digests

    original = authority._is_windows
    authority._is_windows = lambda: False
    try:
        def code(call_it):
            try:
                call_it()
            except ContractError as error:
                return error.code
            return None
        report.check("numeric_sid_fails_closed_without_windows",
                     code(lambda: authority.canonical_dacl_trustee(FOREIGN_RID500_SID))
                     == "PHASE_PLATFORM")
        report.check("numeric_query_against_alias_never_guessed",
                     code(lambda: authority.dacl_has_ace("D:(D;;LC;;;LA)", PARENT_ACE,
                                                         FOREIGN_RID500_SID)) == "PHASE_PLATFORM")
        report.check("alias_text_never_mapped_without_windows",
                     authority.canonical_dacl_trustee("LA") == "LA"
                     and authority.dacl_has_ace("D:(D;;LC;;;LA)", PARENT_ACE, "LA")
                     and not authority.dacl_has_ace("D:(D;;LC;;;LA)", PARENT_ACE, "BA"))
    finally:
        authority._is_windows = original
    if os.name != "nt":
        report.check("phase_authority_constructor_refuses_off_windows",
                     code(lambda: authority.PhaseAuthority({}, None)) == "PHASE_PLATFORM")


def database_dump(path: Path) -> str:
    connection = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
    try:
        return "\n".join(connection.iterdump())
    finally:
        connection.close()


def native(report: Report) -> None:
    from trace_gc import phase_authority as authority
    from trace_gc.budget import RunBudget
    from trace_gc.canonical import bytes_digest, dumps
    from trace_gc.errors import ContractError
    from trace_gc.phase_authority import PhaseAuthority, binding_sha256
    from trace_gc.trust import IssuerPolicy, Signer, TrustStore
    report.group = "windows_checks"

    runner = current_sid()
    prefix = re.fullmatch(r"(S-1-5-21-[0-9]+-[0-9]+-[0-9]+)-[0-9]+", runner)
    if prefix is None:
        raise RuntimeError("machine/domain account SID required")
    local_rid500 = prefix.group(1) + "-500"
    plain = runner if not runner.endswith("-500") else prefix.group(1) + "-1001"
    owned_sids = {USERS_SID, GUESTS_SID, FOREIGN_RID500_SID, runner, local_rid500, plain}

    report.check("numeric_users_sid_is_serialized_as_alias",
                 authority.canonical_dacl_trustee(USERS_SID) == "BU")
    report.check("foreign_rid500_stays_numeric",
                 authority.canonical_dacl_trustee(FOREIGN_RID500_SID) == FOREIGN_RID500_SID)
    report.check("plain_account_stays_numeric",
                 authority.canonical_dacl_trustee(plain) == plain)
    report.check("distinct_rid500_and_plain_never_collapse",
                 len({authority.canonical_dacl_trustee(s)
                      for s in (local_rid500, FOREIGN_RID500_SID, plain)}) == 3)

    base_dir = None
    handles = []
    with tempfile.TemporaryDirectory(prefix=PREFIX) as temp:
        base_dir = Path(temp)
        parent = base_dir / "old-app"
        old = parent / "state"
        archived = base_dir / "archive" / "state"
        phase = base_dir / "phase"
        for directory in (parent, archived, phase):
            directory.mkdir(parents=True)
        (phase / "phase.lock").write_bytes(b"0")
        files = {}
        for name in NAMES:
            body = ("installed:" + name).encode()
            (archived / name).write_bytes(body)
            files[name] = bytes_digest(body)
        receipt = base_dir / "fence.json"
        pointer = phase / "active.json"
        signer = Signer.ephemeral("installed-phase-reviewer")
        trust = TrustStore()
        trust.enroll(signer.issuer, IssuerPolicy(
            signer.public_key(), "installed-phase-reviewer", frozenset({"AUTHORIZATION"}),
            frozenset({"PHASE_ACTIVATE"}), frozenset({"isolated-test"}), frozenset({"LIVE"}),
            can_review=True))

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

        def binding(activation_sha):
            return {"phase_id": "installed-phase", "run_id": RUN_ID,
                    "capsule_sha256": "a" * 64, "implementation_sha256": "b" * 64,
                    "activation_path": str(pointer), "activation_sha256": activation_sha,
                    "activation_epoch": 1, "phase_lock_path": str(phase / "phase.lock"),
                    "fence_receipt_path": str(receipt),
                    "fence_receipt_sha256": bytes_digest(receipt.read_bytes()),
                    "old_root_path": str(old), "archived_old_root_path": str(archived),
                    "capsule_path": str(phase / "capsule.json"),
                    "authorization_path": str(phase / "auth.json"),
                    "authorization_sha256": "c" * 64}

        def bound(*, activate: bool) -> PhaseAuthority:
            probe = PhaseAuthority(binding("0" * 64), trust)
            try:
                signed = signer.issue("AUTHORIZATION", probe.activation_payload(),
                                      lifetime_seconds=3600)
            finally:
                probe.close()
            raw = (dumps(signed) + "\n").encode("utf-8")
            instance = PhaseAuthority(binding(bytes_digest(raw)), trust)
            handles.append(instance)
            pointer.unlink(missing_ok=True)
            if activate:
                pointer.write_bytes(raw)
            return instance

        def attempt(scope) -> str:
            try:
                with scope():
                    return "entered"
            except ContractError as error:
                return error.code
            except Exception as error:      # bounded type only
                return "other:" + type(error).__name__

        def accepted() -> bool:
            instance = bound(activate=True)
            return attempt(instance.write) == "entered" and attempt(instance.staging) == "entered"

        def rejected() -> bool:
            instance = bound(activate=True)
            return attempt(instance.write) == "PHASE_FENCE" and attempt(instance.staging) == "PHASE_FENCE"

        def state_hash() -> str:
            return sha(b"".join(bytes_digest((archived / name).read_bytes()).encode()
                                for name in NAMES) + authority.directory_dacl_sddl(parent).encode())

        try:
            icacls(str(parent), "/deny", "*" + USERS_SID + ":(AD)")
            raw = write(USERS_SID)
            report.check("real_dacl_spells_numeric_sid_as_alias",
                         "(D;;LC;;;BU)" in raw and USERS_SID not in raw)
            report.check("alias_deny_accepted_write_and_staging", accepted())
            instance = bound(activate=True)
            instance.check()
            report.check("check_accepts_current_phase", True)

            inactive = bound(activate=False)
            report.check("fenced_inactive_stages_but_rejects_current_write",
                         attempt(inactive.staging) == "entered"
                         and attempt(inactive.write) == "PHASE_INACTIVE")

            # State-unchanged proof: a persisted-binding ledger, consumed while current,
            # is rejected and left byte-identical once the fence is invalid.
            current = bound(activate=True)
            ledger_path = phase / "budget.sqlite3"
            ledger_path.unlink(missing_ok=True)
            connection = sqlite3.connect(ledger_path)
            try:
                connection.execute("CREATE TABLE trace_phase_binding (id INTEGER PRIMARY KEY "
                                   "CHECK(id=1), binding_sha256 TEXT NOT NULL)")
                connection.execute("INSERT INTO trace_phase_binding VALUES (1,?)",
                                   (binding_sha256(current.binding),))
                connection.commit()
            finally:
                connection.close()
            ledger = RunBudget(ledger_path, RUN_ID, LIMITS, phase_authority=current)
            try:
                ledger.consume("model_calls")
                before = database_dump(ledger_path)
                (archived / "graph.sqlite3").write_bytes(b"changed")
                try:
                    ledger.consume("model_calls")
                    consume_code = None
                except ContractError as error:
                    consume_code = error.code
                report.check("changed_archive_rejects_ledger_write", consume_code == "PHASE_FENCE")
                report.check("rejected_write_leaves_ledger_unchanged",
                             database_dump(ledger_path) == before)
                (archived / "graph.sqlite3").write_bytes(b"installed:graph.sqlite3")
            finally:
                ledger.close()

            write(GUESTS_SID)
            report.check("other_trustee_rejected", rejected())
            write(USERS_SID, dacl_sha="0" * 64)
            report.check("changed_raw_digest_rejected", rejected())
            write(USERS_SID)
            (archived / "graph.sqlite3").write_bytes(b"changed")
            report.check("changed_archive_bytes_rejected", rejected())
            (archived / "graph.sqlite3").write_bytes(b"installed:graph.sqlite3")
            report.check("restored_archive_bytes_accepted_again", accepted())

            for label, args in (("mask", ("/deny", "*" + USERS_SID + ":(WD)")),
                                ("inheritance_flag", ("/deny", "*" + USERS_SID + ":(OI)(AD)")),
                                ("ace_type", ("/grant", "*" + USERS_SID + ":(AD)"))):
                lift(parent)
                icacls(str(parent), *args)
                write(USERS_SID)
                snapshot = state_hash()
                report.check("wrong_" + label + "_rejected", rejected())
                report.check("wrong_" + label + "_leaves_state_unchanged",
                             state_hash() == snapshot)
            lift(parent)

            icacls(str(parent), "/deny", "*" + local_rid500 + ":(AD)")
            write(local_rid500)
            report.check("machine_rid500_deny_accepted", accepted())
            for label, wrong in (("foreign_domain_rid500", FOREIGN_RID500_SID),
                                 ("plain_account", plain), ("users_group", USERS_SID)):
                write(wrong)
                report.check("machine_rid500_deny_rejected_for_" + label, rejected())
            lift(parent)

            icacls(str(parent), "/deny", "*" + FOREIGN_RID500_SID + ":(AD)")
            write(local_rid500)
            report.check("foreign_rid500_deny_rejected_for_local_account", rejected())
            write(FOREIGN_RID500_SID)
            report.check("foreign_rid500_deny_accepted_for_itself", accepted())
            lift(parent)

            icacls(str(parent), "/deny", "*" + runner + ":(AD)")
            write(runner)
            report.check("natural_runner_deny_accepted", accepted())
            lift(parent)
            write(runner)
            report.check("absent_deny_rejected", rejected())
        finally:
            for item in handles:
                if not item._lock_file.closed:
                    item.close()
            for path in [parent, *parent.rglob("*"), *archived.rglob("*")]:
                if path.exists():
                    lift(path)
    report.check("owned_tree_removed", base_dir is not None and not base_dir.exists())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--declared-source", action="append", default=[],
                        metavar="NAME=SHA256")
    parser.add_argument("--require-windows", action="store_true")
    args = parser.parse_args()
    declared = {}
    for item in args.declared_source:
        name, separator, digest = item.partition("=")
        if not separator or not re.fullmatch(r"[0-9a-f]{64}", digest):
            parser.error("--declared-source expects NAME=<64 hex sha256>")
        declared[name] = digest
    report = Report()
    try:
        portable(report, declared)
        if os.name == "nt":
            native(report)
    except Exception as error:   # bounded type only, never paths or names
        report.data["error_type"] = type(error).__name__
        report.ok = False
    if args.require_windows and os.name != "nt":
        report.data["error"] = "Windows required"
        report.ok = False
    print(json.dumps(report.data, indent=2))
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
