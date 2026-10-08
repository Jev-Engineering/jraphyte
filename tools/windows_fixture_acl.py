"""Deterministic DACLs for owned, disposable Windows test fixtures.

Hosted Windows Server 2025 traces show that ``icacls /deny`` on an object that is not
protected and carries inherited allows leaves explicit copies of those allows behind,
which the production strict comparison rightly rejects. A test fixture therefore must not
depend on whatever ACL its temporary parent happens to pass down.

This module gives each fixture object the same three allows the CPython ``0o700`` base
directory already carries (SYSTEM, Administrators, Owner Rights; full control, directories
inheritable), as *explicit* ACEs with inheritance removed. No principal is added or widened
relative to that base. The result is verified before anything is pinned. This only changes
what the disposable fixtures start from; it does not alter or relax any production check,
and whether it is sufficient on the hosted runner is for hosted evidence to show.
"""
from __future__ import annotations

from pathlib import Path
import re
import subprocess

REVIEWED_ALLOWS = (("SY", "S-1-5-18"), ("BA", "S-1-5-32-544"), ("OW", "S-1-3-4"))
TIMEOUT_SECONDS = 30
_ACE = re.compile(r"\([^)]*\)")
_CONTROL = re.compile(r"AI|AR|P")
_FLAG = re.compile("..")


class FixtureAclError(Exception):
    """The fixture ACL could not be stabilized; only fixed target labels and codes are kept."""

    def __init__(self, problems: list[tuple[str, str]]):
        super().__init__("owned fixture ACL not stabilized")
        self.problems = problems


def grant_arguments(is_dir: bool) -> list[str]:
    rights = "(OI)(CI)(F)" if is_dir else "(F)"
    return ["/inheritance:r", "/grant:r"] + ["*" + sid + ":" + rights for _, sid in REVIEWED_ALLOWS]


def fixture_acl_problems(sddl: str, is_dir: bool) -> list[str]:
    """Fixed problem codes for a DACL that is not the stabilized fixture shape (text only)."""
    found: list[str] = []
    control = _CONTROL.findall(sddl.split("(", 1)[0].removeprefix("D:"))
    if "P" not in control:
        found.append("NOT_PROTECTED")
    expected_flags = ["CI", "OI"] if is_dir else []
    trustees = []
    for ace in _ACE.findall(sddl):
        fields = ace[1:-1].split(";")
        if len(fields) != 6:
            found.append("MALFORMED_ACE")
            continue
        kind, flags, rights, trustee = fields[0], _FLAG.findall(fields[1]), fields[2], fields[5]
        trustees.append(trustee)
        if "ID" in flags:
            found.append("INHERITED_ACE")
        if kind != "A":
            found.append("NON_ALLOW_ACE")
        if rights != "FA":
            found.append("UNREVIEWED_RIGHTS")
        if sorted(flag for flag in flags if flag != "ID") != expected_flags:
            found.append("UNREVIEWED_FLAGS")
    if sorted(trustees) != sorted(alias for alias, _ in REVIEWED_ALLOWS):
        found.append("UNREVIEWED_TRUSTEES")
    return list(dict.fromkeys(found))


def stabilize_owned_fixture(base, targets, *, read, run=subprocess.run) -> None:
    """Protect each target and give it exactly the reviewed explicit allows, then verify.

    ``targets`` is an ordered list of ``(label, path)``; every path must lie strictly inside
    ``base`` (the fixture's own directory), so no ancestor ACL is ever touched. Raises
    ``FixtureAclError`` carrying fixed codes if any target is outside, any icacls call fails,
    or any resulting DACL is not the verified shape.
    """
    root = Path(base).resolve()
    for label, path in targets:
        resolved = Path(path).resolve()
        if resolved == root or not resolved.is_relative_to(root):
            raise FixtureAclError([(label, "OUTSIDE_OWNED_FIXTURE")])
    problems: list[tuple[str, str]] = []
    for label, path in targets:
        is_dir = Path(path).is_dir()
        try:
            done = run(["icacls.exe", str(path), *grant_arguments(is_dir)],
                       capture_output=True, text=True, timeout=TIMEOUT_SECONDS)
            applied = done.returncode == 0
        except Exception:
            applied = False
        if not applied:
            problems.append((label, "ICACLS_FAILED"))
            continue
        try:
            codes = fixture_acl_problems(read(path), is_dir)
        except Exception:
            codes = ["DACL_UNREADABLE"]
        problems.extend((label, code) for code in codes)
    if problems:
        raise FixtureAclError(problems)
