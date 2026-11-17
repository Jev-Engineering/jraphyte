"""Check the trustee helpers of an INSTALLED ``trace_gc`` wheel, from outside the checkout.

Run it with the interpreter of an environment where the wheel is installed, from a working
directory outside the source tree (``python path/to/tools/installed_phase_authority_check.py``).
Python then puts only ``tools/`` on ``sys.path``, so ``trace_gc`` must come from the installed
package; the script refuses to run against the checkout copy. Portable checks run everywhere;
the native checks (real Windows SID spelling and a real alias-spelled DACL on an owned
temporary directory) run on Windows only and are reported as ``NOT_RUN`` elsewhere. The report
carries no path, account or machine SID. Exit status 0 means every check that ran passed.
"""
from __future__ import annotations

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
        spell = authority.canonical_dacl_trustee
        results["users_spelled_bu"] = spell(USERS_SID) == "BU"
        results["foreign_rid500_stays_numeric"] = spell(FOREIGN_RID500_SID) == FOREIGN_RID500_SID
        with tempfile.TemporaryDirectory(prefix="jraphyte-installed-trustee-") as temporary:
            directory = Path(temporary) / "parent"
            directory.mkdir()
            added = subprocess.run(["icacls.exe", str(directory), "/deny", "*" + USERS_SID + ":(AD)"],
                                   capture_output=True, text=True, timeout=30)
            try:
                raw = authority.directory_dacl_sddl(directory)
                results["real_dacl_spells_alias"] = added.returncode == 0 and "(D;;LC;;;BU)" in raw
                results["real_alias_deny_matches"] = authority.dacl_has_ace(raw, PARENT_ACE, USERS_SID)
                results["real_alias_deny_rejects_others"] = not any(
                    authority.dacl_has_ace(raw, PARENT_ACE, sid) or
                    authority.dacl_has_deny_trustee(raw, sid)
                    for sid in (GUESTS_SID, FOREIGN_RID500_SID))
            finally:
                removed = subprocess.run(["icacls.exe", str(directory), "/remove:d", "*" + USERS_SID],
                                         capture_output=True, text=True, timeout=30)
                results["owned_fixture_restored"] = removed.returncode == 0
    print(json.dumps({"results": results, "native_windows": native,
                      "checks_run": len(results)}, sort_keys=True))
    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
