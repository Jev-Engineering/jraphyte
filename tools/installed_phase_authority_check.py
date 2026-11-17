"""Verify installed wheel trustee helpers and signed phase activation outside the checkout.

Run it with the interpreter of an environment where the wheel is installed, from a working
directory outside the source tree (``python path/to/tools/installed_phase_authority_check.py``).
Python then puts only ``tools/`` on ``sys.path``, so ``trace_gc`` must come from the installed
package; the script refuses to run against the checkout copy. Portable checks run everywhere;
the native checks (real Windows SID spelling and a real alias-spelled DACL on an owned
temporary directory with a signed activation fixture) run on Windows only. Other platforms
report them as ``NOT_RUN``. The report carries no path, account or machine SID. Exit status 0
means every check that ran passed.
"""
from __future__ import annotations

from contextlib import closing
import json
import os
from pathlib import Path
import subprocess
import sys
import sysconfig
import tempfile

USERS_SID, GUESTS_SID = "S-1-5-32-545", "S-1-5-32-546"
FOREIGN_RID500_SID = "S-1-5-21-1111111111-2222222222-3333333333-500"
PARENT_ACE = "(D;;LC;;;{sid})"
CHECKOUT = Path(__file__).resolve().parents[1]


def signed_fence_checks(authority, base: Path, directory: Path, raw: str) -> dict[str, bool]:
    """Bind the raw fence receipt through a locally enrolled synthetic activation signer."""
    from trace_gc.canonical import bytes_digest, dumps
    from trace_gc.errors import ContractError
    from trace_gc.trust import IssuerPolicy, Signer, TrustStore

    old = directory / "state"
    archive = base / "archive"
    archive.mkdir()
    pins = {}
    for name in ("checkpoint.sqlite3", "graph.sqlite3", "budget.sqlite3",
                 "application-journal.sqlite3", "controller.lock"):
        content = b"0" if name == "controller.lock" else name.encode("ascii")
        (archive / name).write_bytes(content)
        pins[name] = bytes_digest(content)
    fence_path = base / "fence.json"
    activation_path = base / "activation.json"
    lock_path = base / "phase.lock"
    lock_path.write_bytes(b"0")

    signer = Signer.ephemeral("installed-wheel-fixture")
    trust = TrustStore()
    trust.enroll(signer.issuer, IssuerPolicy(
        public_key=signer.public_key(), principal=signer.issuer,
        purposes=frozenset({"AUTHORIZATION"}), operations=frozenset({"PHASE_ACTIVATE"}),
        scopes=frozenset(), modes=frozenset(), can_review=True))
    fence = {
        "version": "paper-pilot-phase-namespace-fence-v1",
        "status": "OLD_PATH_FENCED_NEW_PHASE_ALLOWED",
        "old_root_path": str(old),
        "archived_root_path": str(archive),
        "old_parent_dacl_sha256": bytes_digest(raw.encode("utf-8")),
        "archived_files_sha256": pins,
        "deny_sid": USERS_SID,
    }
    binding = {
        "phase_id": "installed-wheel-fixture", "run_id": "installed-wheel-fixture",
        "capsule_path": str(base / "capsule.json"), "capsule_sha256": "a" * 64,
        "implementation_sha256": "b" * 64,
        "activation_path": str(activation_path), "activation_sha256": "0" * 64,
        "activation_epoch": 1, "authorization_path": str(base / "authorization.json"),
        "authorization_sha256": "c" * 64, "phase_lock_path": str(lock_path),
        "fence_receipt_path": str(fence_path), "fence_receipt_sha256": "0" * 64,
        "old_root_path": str(old), "archived_old_root_path": str(archive),
    }

    other_signer = Signer.ephemeral(signer.issuer)
    results: dict[str, bool] = {}
    for name, changes, fixture_signer, expected in (
        ("signed_alias_fence_accepted", {}, signer, None),
        ("signed_fence_rejects_unrelated_trustee", {"deny_sid": GUESTS_SID}, signer, "PHASE_FENCE"),
        ("signed_fence_rejects_foreign_rid500", {"deny_sid": FOREIGN_RID500_SID}, signer, "PHASE_FENCE"),
        ("signed_fence_rejects_wrong_dacl_digest",
         {"old_parent_dacl_sha256": "0" * 64}, signer, "PHASE_FENCE"),
        ("activation_rejects_wrong_signing_key", {}, other_signer, "SIGNATURE_INVALID"),
    ):
        fence_bytes = dumps({**fence, **changes}).encode("utf-8")
        fence_path.write_bytes(fence_bytes)
        binding["fence_receipt_sha256"] = bytes_digest(fence_bytes)
        with closing(authority.PhaseAuthority(binding, trust)) as phase:
            # The activation hash is excluded from activation_payload to avoid a digest cycle.
            activation = fixture_signer.issue("AUTHORIZATION", phase.activation_payload())
        activation_bytes = dumps(activation).encode("utf-8")
        activation_path.write_bytes(activation_bytes)
        binding["activation_sha256"] = bytes_digest(activation_bytes)
        with closing(authority.PhaseAuthority(binding, trust)) as phase:
            try:
                # The public activation gate validates the signature, then calls verify_fence.
                phase.check()
            except ContractError as error:
                results[name] = error.code == expected
            else:
                results[name] = expected is None
    return results


def main() -> int:
    try:
        import trace_gc
        from trace_gc import phase_authority as authority
        from trace_gc.errors import ContractError
    except ImportError:
        print(json.dumps({"results": {"installed_package_importable": False},
                          "native_windows": "NOT_RUN"}, sort_keys=True))
        return 1
    results: dict[str, bool] = {}
    location = Path(authority.__file__).resolve()
    site = Path(sysconfig.get_paths()["purelib"]).resolve()
    results["imported_from_installed_package"] = (
        location.is_relative_to(site) and not location.is_relative_to(CHECKOUT) and
        Path(trace_gc.__file__).resolve().parent == location.parent)
    if not results["imported_from_installed_package"]:
        print(json.dumps({"results": results, "native_windows": "NOT_RUN"}, sort_keys=True))
        return 1
    results["helpers_exported"] = all(hasattr(authority, name) for name in (
        "canonical_dacl_trustee", "canonical_dacl_ace", "canonical_dacl_aces", "dacl_has_ace",
        "dacl_has_deny_trustee"))
    results["alias_text_passes_through"] = authority.canonical_dacl_trustee("BU") == "BU"
    native = "NOT_RUN"
    if os.name != "nt":
        try:
            authority.canonical_dacl_trustee(USERS_SID)
            results["numeric_sid_fails_closed_off_windows"] = False
        except ContractError as error:
            results["numeric_sid_fails_closed_off_windows"] = error.code == "PHASE_PLATFORM"
    else:
        native = "RUN"
        try:
            spell = authority.canonical_dacl_trustee
            results["users_spelled_bu"] = spell(USERS_SID) == "BU"
            results["foreign_rid500_stays_numeric"] = spell(FOREIGN_RID500_SID) == FOREIGN_RID500_SID
            with tempfile.TemporaryDirectory(prefix="jraphyte-installed-trustee-") as temporary:
                directory = Path(temporary) / "parent"
                directory.mkdir()
                try:
                    added = subprocess.run(
                        ["icacls.exe", str(directory), "/deny", "*" + USERS_SID + ":(AD)"],
                        capture_output=True, text=True, timeout=30)
                    raw = authority.directory_dacl_sddl(directory)
                    results["real_dacl_spells_alias"] = added.returncode == 0 and "(D;;LC;;;BU)" in raw
                    results["real_alias_deny_matches"] = authority.dacl_has_ace(raw, PARENT_ACE, USERS_SID)
                    results["real_alias_deny_rejects_others"] = not any(
                        authority.dacl_has_ace(raw, PARENT_ACE, sid) or
                        authority.dacl_has_deny_trustee(raw, sid)
                        for sid in (GUESTS_SID, FOREIGN_RID500_SID))
                    results.update(signed_fence_checks(authority, Path(temporary), directory, raw))
                finally:
                    removed = subprocess.run(["icacls.exe", str(directory), "/remove:d", "*" + USERS_SID],
                                             capture_output=True, text=True, timeout=30)
                    results["owned_fixture_restored"] = removed.returncode == 0
        except (ContractError, OSError, subprocess.SubprocessError):
            results["native_fixture_completed"] = False
    print(json.dumps({"results": results, "native_windows": native,
                      "checks_run": len(results)}, sort_keys=True))
    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
