"""Shared fixtures for the phase-fence trustee tests. This module defines no tests.

``PhaseHarness`` builds a real ``PhaseAuthority`` (real constructor, real signed
activation pointer, real ``RunBudget`` consumer) and is used by both the native
Windows tests and the modeled tests.

``WindowsModel`` is a *model* of the Windows seams the fences use: DACL text per
path, ``icacls`` and SID-to-SDDL spelling. It lets the real fence, receipt and
phase code run on any platform against alias-spelled DACLs. It is not Windows
evidence: only the native test classes prove behavior of the operating system.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
from unittest.mock import patch

from trace_gc import phase_authority as authority
from trace_gc.budget import RunBudget
from trace_gc.canonical import bytes_digest, dumps
from trace_gc.phase_authority import PhaseAuthority, binding_sha256
from trace_gc.trust import IssuerPolicy, Signer, TrustStore

USERS_SID = "S-1-5-32-545"      # serialized by Windows as the alias BU
GUESTS_SID = "S-1-5-32-546"     # an unrelated trustee, serialized as BG
ACCOUNT_PREFIX = "S-1-5-21-4000000001-4000000002-4000000003"
LOCAL_RID500_SID = ACCOUNT_PREFIX + "-500"        # this (modeled) machine's Administrator
PLAIN_ACCOUNT_SID = ACCOUNT_PREFIX + "-1001"
FOREIGN_RID500_SID = "S-1-5-21-1111111111-2222222222-3333333333-500"   # another domain
NEAR_RID500_SID = "S-1-5-21-4000000001-4000000002-4000000004-500"      # one sub-authority off
PARENT_ACE = "(D;;LC;;;{sid})"
FILE_ACE = "(D;;DCLC;;;{sid})"
NAMES = ("checkpoint.sqlite3", "graph.sqlite3", "budget.sqlite3",
         "application-journal.sqlite3", "controller.lock")
LIMITS = {"retrieval_requests": 5, "model_calls": 5, "retries": 5,
          "solver_expansions": 5, "review_actions": 5, "request_bytes": 5}
RUN_ID = "authored-run"


def sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def database_dump(path: Path) -> str:
    """Logical content of an owned SQLite file, used to prove 'state unchanged'."""
    connection = sqlite3.connect(f"file:{Path(path).as_posix()}?mode=ro", uri=True)
    try:
        return "\n".join(connection.iterdump())
    finally:
        connection.close()


class PhaseHarness:
    """A real PhaseAuthority over a real signed activation pointer in an owned phase dir."""

    def __init__(self, test, base: Path, old: Path, archived: Path):
        self.test, self.old, self.archived = test, old, archived
        self.phase = base / "phase"
        self.phase.mkdir()
        (self.phase / "phase.lock").write_bytes(b"0")
        self.pointer = self.phase / "active.json"
        self.signer = Signer.ephemeral("authored-phase-reviewer")
        self.trust = TrustStore()
        self.trust.enroll(self.signer.issuer, IssuerPolicy(
            self.signer.public_key(), "authored-phase-reviewer",
            frozenset({"AUTHORIZATION"}), frozenset({"PHASE_ACTIVATE"}),
            frozenset({"isolated-test"}), frozenset({"LIVE"}), can_review=True))
        self.opened: list[PhaseAuthority] = []
        self.raw_pointer: bytes | None = None
        test.addCleanup(self.close)

    def close(self):
        for instance in self.opened:
            if not instance._lock_file.closed:
                instance.close()

    def binding(self, fence: Path, activation_sha: str) -> dict:
        return {"phase_id": "authored-phase", "run_id": RUN_ID,
                "capsule_sha256": "a" * 64, "implementation_sha256": "b" * 64,
                "activation_path": str(self.pointer), "activation_sha256": activation_sha,
                "activation_epoch": 1, "phase_lock_path": str(self.phase / "phase.lock"),
                "fence_receipt_path": str(fence),
                "fence_receipt_sha256": bytes_digest(fence.read_bytes()),
                "old_root_path": str(self.old), "archived_old_root_path": str(self.archived),
                "capsule_path": str(self.phase / "capsule.json"),
                "authorization_path": str(self.phase / "auth.json"),
                "authorization_sha256": "c" * 64}

    def authority(self, fence: Path, *, activate: bool = False) -> PhaseAuthority:
        """Bind the exact signed pointer; ``activate`` publishes it, otherwise it is absent."""
        probe = PhaseAuthority(self.binding(fence, "0" * 64), self.trust)
        try:
            signed = self.signer.issue("AUTHORIZATION", probe.activation_payload(),
                                       lifetime_seconds=3600)
        finally:
            probe.close()
        self.raw_pointer = (dumps(signed) + "\n").encode("utf-8")
        instance = PhaseAuthority(self.binding(fence, bytes_digest(self.raw_pointer)), self.trust)
        self.opened.append(instance)
        self.pointer.unlink(missing_ok=True)
        if activate:
            self.activate()
        return instance

    def peer(self, instance: PhaseAuthority) -> PhaseAuthority:
        """A second constructor over the identical binding (a concurrent opener)."""
        other = PhaseAuthority(dict(instance.binding), self.trust)
        self.opened.append(other)
        return other

    def activate(self):
        self.pointer.write_bytes(self.raw_pointer)

    def deactivate(self):
        self.pointer.unlink(missing_ok=True)

    def budget_path(self, instance: PhaseAuthority) -> Path:
        """A budget database carrying the persisted binding marker, as import writes it."""
        path = self.phase / "budget.sqlite3"
        path.unlink(missing_ok=True)
        connection = sqlite3.connect(path)
        try:
            connection.execute("CREATE TABLE trace_phase_binding "
                               "(id INTEGER PRIMARY KEY CHECK(id=1), binding_sha256 TEXT NOT NULL)")
            connection.execute("INSERT INTO trace_phase_binding VALUES (1,?)",
                               (binding_sha256(instance.binding),))
            connection.commit()
        finally:
            connection.close()
        return path

    def budget(self, path: Path, instance: PhaseAuthority) -> RunBudget:
        ledger = RunBudget(path, RUN_ID, LIMITS, phase_authority=instance)
        self.test.addCleanup(ledger.close)
        return ledger


class _NtOs:
    """``os`` that reports Windows and re-keys the DACL model on rename."""

    def __init__(self, model):
        self._model = model
        self.name = "nt"

    def rename(self, source, destination):
        os.rename(source, destination)
        self._model.rekey(source, destination)

    def __getattr__(self, name):
        return getattr(os, name)


class _Subprocess:
    def __init__(self, model):
        self._model = model

    def run(self, args, **kwargs):
        return self._model.icacls(list(args))


class _Msvcrt:
    """Byte-lock model: LK_NBLCK fails while another handle holds the same file."""
    LK_LOCK, LK_NBLCK, LK_UNLCK = 1, 2, 0

    def __init__(self):
        self.held: dict[tuple, int] = {}

    def locking(self, fd, mode, nbytes):
        stat = os.fstat(fd)
        key = (stat.st_dev, stat.st_ino)
        if mode == self.LK_UNLCK:
            self.held.pop(key, None)
            return
        if key in self.held and self.held[key] != fd:
            raise OSError("modeled byte lock is held")
        self.held[key] = fd


class WindowsModel:
    """Model of per-path DACL text, ``icacls`` and SID spelling; see the module docstring."""

    ALIASES = {USERS_SID: "BU", GUESTS_SID: "BG", LOCAL_RID500_SID: "LA", "S-1-5-18": "SY"}
    RIGHTS = {("AD",): "LC", ("WD", "AD"): "DCLC", ("X",): "FX", ("WD",): "DC"}

    def __init__(self, test, *, current_sid: str = USERS_SID, modules=()):
        self.test, self.current_sid, self.modules = test, current_sid, modules
        self.dacls: dict[str, tuple[str, list[str]]] = {}
        self.msvcrt = _Msvcrt()

    # -- lifecycle ---------------------------------------------------------
    def start(self):
        patches = [patch.object(authority, "_is_windows", return_value=True, create=True),
                   patch.object(authority, "_windows_trustee", side_effect=self.spell, create=True),
                   patch.object(authority, "directory_dacl_sddl", side_effect=self.sddl),
                   patch.object(authority, "os", _NtOs(self)),
                   patch.dict(sys.modules, {"msvcrt": self.msvcrt})]
        for module in self.modules:
            patches += [patch.object(module, "directory_dacl_sddl", side_effect=self.sddl),
                        patch.object(module, "_current_sid", return_value=self.current_sid),
                        patch.object(module, "subprocess", _Subprocess(self)),
                        patch.object(module, "os", _NtOs(self))]
        for item in patches:
            item.start()
            self.test.addCleanup(item.stop)
        return self

    # -- Windows spelling --------------------------------------------------
    def spell(self, sid: str) -> str:
        return self.ALIASES.get(sid, sid)

    # -- DACL store --------------------------------------------------------
    @staticmethod
    def key(path) -> str:
        return str(Path(path).resolve(strict=True))

    def default(self, path: Path) -> tuple[str, list[str]]:
        if Path(path).is_dir():
            return "PAI", ["(A;;FA;;;BA)", "(A;OICIID;FA;;;SY)", "(A;OICIID;FA;;;BA)"]
        return "AI", ["(A;ID;FA;;;BA)", "(A;ID;FA;;;SY)"]

    def entry(self, path) -> tuple[str, list[str]]:
        key = self.key(path)
        if key not in self.dacls:
            self.dacls[key] = self.default(Path(path))
        return self.dacls[key]

    def sddl(self, path) -> str:
        flags, aces = self.entry(path)
        return "D:" + flags + "".join(aces)

    def set(self, path, flags: str, aces: list[str]):
        self.entry(path)
        self.dacls[self.key(path)] = (flags, list(aces))

    def rekey(self, source, destination):
        source, destination = str(Path(source).resolve()), str(Path(destination).resolve())
        for key in list(self.dacls):
            if key == source or key.startswith(source + os.sep):
                self.dacls[destination + key[len(source):]] = self.dacls.pop(key)

    # -- icacls ------------------------------------------------------------
    @staticmethod
    def inherited(ace: str) -> bool:
        return "ID" in ace[1:-1].split(";")[1]

    def explicit(self, ace: str, kind: str, trustee: str) -> bool:
        fields = ace[1:-1].split(";")
        return fields[0] == kind and fields[5] == trustee and not self.inherited(ace)

    def icacls(self, args: list[str]) -> subprocess.CompletedProcess:
        assert args[0] == "icacls.exe", args
        path, verb, rest = Path(args[1]), args[2], args[3:]
        flags, aces = self.entry(path)
        aces = list(aces)
        sid = rest[0].lstrip("*").split(":")[0]
        trustee = self.spell(sid)
        if verb in ("/deny", "/grant"):
            spec = rest[0].split(":", 1)[1]
            inherit = ""
            names = []
            for part in [item for item in spec.replace(")(", ")|(").split("|")]:
                words = part.strip("()").split(",")
                if words[0] in ("OI", "CI") and len(words) == 1:
                    inherit += words[0]
                else:
                    names.extend(words)
            rights = self.RIGHTS[tuple(names)]
            ace = f"({'D' if verb == '/deny' else 'A'};{inherit};{rights};;;{trustee})"
            if verb == "/deny":
                aces.insert(0, ace)
            else:
                aces.insert(sum(1 for item in aces if not self.inherited(item)), ace)
        elif verb == "/remove:d":
            aces = [item for item in aces if not self.explicit(item, "D", trustee)]
        elif verb == "/remove:g":
            aces = [item for item in aces if not self.explicit(item, "A", trustee)]
        else:
            raise AssertionError("unmodeled icacls verb " + verb)
        self.dacls[self.key(path)] = (flags, aces)
        return subprocess.CompletedProcess(args, 0, "", "")


class DescriptorModel:
    """The descriptor seam of ``tools/windows_native_acl.WindowsNative`` over a ``WindowsModel``.

    A model, not Windows: numeric trustees are stored in the spelling the model gives them (so a
    deny installed for ``S-1-5-32-545`` reads back as ``BU``), exactly the situation a literal
    ACE comparison cannot survive and a canonical one must.
    """

    OWNER = "O:BA"

    def __init__(self, model):
        self.model = model

    def read_dacl(self, path) -> str:
        return self.model.sddl(path)

    def read_owner(self, path) -> str:
        return self.OWNER

    def apply_dacl(self, path, sddl: str) -> None:
        match = re.fullmatch(r"D:([A-Z]*)((?:\([^)]*\))*)", sddl)
        assert match is not None, sddl
        spelled = []
        for ace in re.findall(r"\([^)]*\)", match.group(2)):
            fields = ace[1:-1].split(";")
            fields[5] = self.model.spell(fields[5])
            spelled.append("(" + ";".join(fields) + ")")
        self.model.set(path, match.group(1), spelled)

    def canonical_trustee(self, sid: str) -> str:
        return self.model.spell(sid)


class Sids:
    """The identities one host (native or modeled) uses for the shared scenarios."""

    def __init__(self, *, natural: str, local500: str, plain: str, near500: str):
        self.users, self.guests, self.foreign500 = USERS_SID, GUESTS_SID, FOREIGN_RID500_SID
        self.natural, self.local500, self.plain, self.near500 = natural, local500, plain, near500


class ReceiptValidatorScenarios:
    """PhaseAuthority receipt validation against a parent DACL the host spells.

    Not a TestCase: concrete classes combine it with ``unittest.TestCase`` and supply
    ``harness``, ``sids``, ``parent``, ``old``, ``archived``, ``receipt``, ``files`` and
    the ``raw``/``deny``/``grant``/``lift_deny``/``lift_grant`` hooks. The authority is
    always the real constructor over a real signed pointer; accepted means both
    ``write()`` (current) and ``staging()`` enter, rejected means both raise PHASE_FENCE.
    """

    def write_receipt(self, deny_sid, *, dacl_sha=None, files=None) -> str:
        from trace_gc.canonical import loads  # noqa: F401
        raw = self.raw()
        body = {"version": "paper-pilot-phase-namespace-fence-v1",
                "old_root_path": str(self.old), "archived_root_path": str(self.archived),
                "old_parent_dacl_sha256": dacl_sha or bytes_digest(raw.encode("utf-8")),
                "archived_files_sha256": files or self.files,
                "deny_sid": deny_sid, "status": "OLD_PATH_FENCED_NEW_PHASE_ALLOWED"}
        self.receipt.write_bytes((dumps(body) + "\n").encode("utf-8"))
        return raw

    def bound(self, *, activate=True) -> PhaseAuthority:
        return self.harness.authority(self.receipt, activate=activate)

    def assert_accepted(self):
        instance = self.bound()
        with instance.write():
            pass
        with instance.staging():
            pass
        instance.check()

    def assert_rejected(self, code="PHASE_FENCE"):
        from trace_gc.errors import ContractError
        instance = self.bound()
        for scope in (instance.write, instance.staging):
            with self.assertRaises(ContractError) as caught:
                with scope():
                    self.fail("phase scope entered despite an invalid fence")
            self.assertEqual(caught.exception.code, code)

    def test_group_alias_parent_deny_is_accepted_with_raw_digest_pin(self):
        from trace_gc.canonical import loads
        self.deny(self.sids.users, "(AD)")
        raw = self.write_receipt(self.sids.users)
        self.assertIn("(D;;LC;;;BU)", raw)
        self.assertNotIn(self.sids.users, raw)
        self.assertEqual(loads(self.receipt.read_bytes())["old_parent_dacl_sha256"],
                         bytes_digest(raw.encode("utf-8")))
        self.assert_accepted()

    def test_machine_rid500_parent_deny_is_accepted(self):
        self.deny(self.sids.local500, "(AD)")
        self.write_receipt(self.sids.local500)
        self.assert_accepted()

    def test_natural_identity_parent_deny_is_accepted(self):
        self.deny(self.sids.natural, "(AD)")
        self.write_receipt(self.sids.natural)
        self.assert_accepted()

    def test_distinct_rid500_and_other_trustees_are_not_the_receipt_trustee(self):
        self.deny(self.sids.local500, "(AD)")
        for wrong in (self.sids.foreign500, self.sids.near500, self.sids.plain,
                      self.sids.users, self.sids.guests):
            if wrong == self.sids.local500:
                continue
            self.write_receipt(wrong)
            self.assert_rejected()
        self.write_receipt(self.sids.local500)
        self.assert_accepted()

    def test_foreign_rid500_deny_is_not_the_local_account_deny(self):
        self.deny(self.sids.foreign500, "(AD)")
        self.write_receipt(self.sids.local500)
        self.assert_rejected()
        self.write_receipt(self.sids.foreign500)
        self.assert_accepted()

    def test_wrong_trustee_alias_deny_is_rejected(self):
        self.deny(self.sids.guests, "(AD)")
        self.write_receipt(self.sids.users)
        self.assert_rejected()

    def test_wrong_mask_flags_or_type_are_rejected(self):
        users = self.sids.users
        for verb, spec in (("deny", "(WD)"),            # different mask
                           ("deny", "(OI)(AD)"),        # inheritance flag
                           ("grant", "(AD)")):          # allow, not deny
            self.lift_deny(users)
            self.lift_grant(users)
            getattr(self, verb)(users, spec)
            self.write_receipt(users)
            self.assert_rejected()

    def test_absent_deny_and_changed_pins_are_rejected(self):
        users = self.sids.users
        self.write_receipt(users)
        self.assert_rejected()
        self.deny(users, "(AD)")
        self.write_receipt(users, dacl_sha="0" * 64)
        self.assert_rejected()
        self.write_receipt(users)
        self.assert_accepted()
        (self.archived / "graph.sqlite3").write_bytes(b"changed")
        self.assert_rejected()

    def test_fenced_but_inactive_pointer_stages_and_rejects_current_writes(self):
        from trace_gc.errors import ContractError
        self.deny(self.sids.users, "(AD)")
        self.write_receipt(self.sids.users)
        instance = self.bound(activate=False)
        with instance.staging():
            pass
        with self.assertRaises(ContractError) as caught:
            with instance.write():
                self.fail("inactive phase entered a current write")
        self.assertEqual(caught.exception.code, "PHASE_INACTIVE")


class PhaseOwnershipScenarios:
    """Real PhaseAuthority + RunBudget over a fence the host created.

    Host supplies ``harness``, ``fence()`` (returns the sealed fence receipt path),
    ``remove_parent_deny()`` and ``tamper_archive()``.
    """

    def ledger(self, activate):
        instance = self.harness.authority(self.fence_receipt, activate=activate)
        path = self.harness.budget_path(instance)
        return instance, path

    def used(self, path):
        import sqlite3
        connection = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
        try:
            from trace_gc.canonical import loads
            return loads(connection.execute("SELECT used FROM trace_budgets").fetchone()[0])
        finally:
            connection.close()

    def rejects(self, call, code):
        from trace_gc.errors import ContractError
        with self.assertRaises(ContractError) as caught:
            call()
        self.assertEqual(caught.exception.code, code)

    def test_inactive_fenced_phase_stages_but_current_writes_are_rejected_state_unchanged(self):
        instance, path = self.ledger(activate=False)
        with instance.staging():
            pass
        ledger = self.harness.budget(path, instance)       # staging open of the DB is allowed
        before = database_dump(path)
        self.rejects(lambda: ledger.consume("model_calls"), "PHASE_INACTIVE")
        self.rejects(instance.check, "PHASE_INACTIVE")
        self.assertEqual(database_dump(path), before)
        self.assertEqual(self.used(path)["model_calls"], 0)

    def test_current_phase_writes_and_persists_over_the_alias_fence(self):
        instance, path = self.ledger(activate=True)
        ledger = self.harness.budget(path, instance)
        before = database_dump(path)
        self.assertEqual(ledger.consume("model_calls", 2)["model_calls"], 2)
        instance.check()
        with instance.staging():
            pass
        self.assertNotEqual(database_dump(path), before)
        self.assertEqual(self.used(path)["model_calls"], 2)
        reopened = self.harness.budget(path, instance)      # current: write-mode open
        self.assertEqual(reopened.snapshot()["used"]["model_calls"], 2)

    def test_removed_parent_deny_rejects_staging_writes_and_opens_state_unchanged(self):
        instance, path = self.ledger(activate=True)
        ledger = self.harness.budget(path, instance)
        ledger.consume("model_calls")
        before = database_dump(path)
        self.remove_parent_deny()
        self.rejects(lambda: ledger.consume("model_calls"), "PHASE_FENCE")
        self.rejects(instance.check, "PHASE_FENCE")
        with self.assertRaises(Exception) as caught:
            with instance.staging():
                self.fail("staging entered without the parent deny")
        self.assertEqual(getattr(caught.exception, "code", None), "PHASE_FENCE")
        self.rejects(lambda: self.harness.budget(path, instance), "PHASE_FENCE")
        self.assertEqual(database_dump(path), before)

    def test_changed_archive_byte_rejects_writes_and_staging_state_unchanged(self):
        instance, path = self.ledger(activate=True)
        ledger = self.harness.budget(path, instance)
        before = database_dump(path)
        self.tamper_archive()
        self.rejects(lambda: ledger.consume("model_calls"), "PHASE_FENCE")
        with self.assertRaises(Exception) as caught:
            with instance.staging():
                self.fail("staging entered over a changed archive")
        self.assertEqual(getattr(caught.exception, "code", None), "PHASE_FENCE")
        self.assertEqual(database_dump(path), before)

    def test_changed_signed_pointer_is_not_current_state_unchanged(self):
        instance, path = self.ledger(activate=True)
        ledger = self.harness.budget(path, instance)
        before = database_dump(path)
        self.harness.pointer.write_bytes(self.harness.raw_pointer.replace(b"authored-phase",
                                                                           b"another-phase"))
        self.rejects(lambda: ledger.consume("model_calls"), "PHASE_INACTIVE")
        self.assertEqual(database_dump(path), before)
