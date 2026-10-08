"""Strict-DACL contract regressions for the guarded admission barrier.

The barrier pins the original DACL of the fence parent and of every state file
and, after each of its own ``icacls`` writes, requires the remaining ACE list to
be *identical* (same ACEs, count, flags and order; only the admission deny added
and the ``AI`` control flag tolerated). An explicit allow ACE is not equivalent
to an inherited one: it survives a later revocation or removal of the parent
grant, so an unexpected explicit allow copy must fail closed, never be absorbed.

Hosted Windows Server 2025 logs show the fence parent and state files carrying explicit
copies of the inherited allows. Which step produced them (fixture creation, inheritance
propagation, or the guard's own ``icacls`` calls) is not established, and fixture
stabilization is not claimed to fix it; hosted before/after traces are still required.
These cases pin the strict behavior and use real ``icacls`` grants on disposable
fixtures only to build that shape; they do not bless it.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from src import paper_pilot_phase_cutover_guarded_v2 as guarded


ALIAS = "BU"    # an already-serialized trustee keeps the text cases off ctypes
FILE_ORIGINAL = "D:(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;OW)"
FILE_WITH_COPIES = ("D:AI(D;;DCLC;;;BU)(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)"
                    "(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;OW)")
PARENT_ORIGINAL = "D:(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;FA;;;OW)"
PARENT_WITH_COPIES = ("D:AI(D;;LC;;;BU)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)"
                      "(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;FA;;;OW)")
TRUSTEE_SIDS = {"SY": "S-1-5-18", "BA": "S-1-5-32-544", "OW": "S-1-3-4"}
EVERYONE_SID = "S-1-1-0"
TEMP_PREFIX = "jraphyte-fence-strict-"
OPEN_FOR_WRITE = "from pathlib import Path; import sys; Path(sys.argv[1]).open('a+b').close()"


class StrictAclContractTests(unittest.TestCase):
    def file_ok(self, original, current):
        return guarded._only_admission_dacl_added(original, current, ALIAS)

    def parent_ok(self, original, current):
        return guarded._only_parent_admission_added(original, current, ALIAS)

    def test_identical_aces_with_only_the_admission_deny_and_ai_are_accepted(self):
        self.assertTrue(self.file_ok(FILE_ORIGINAL, "D:AI(D;;DCLC;;;BU)" + FILE_ORIGINAL[2:]))
        self.assertTrue(self.parent_ok(PARENT_ORIGINAL, "D:AI(D;;LC;;;BU)" + PARENT_ORIGINAL[2:]))
        self.assertTrue(guarded._same_effective_dacl(FILE_ORIGINAL, "D:AI" + FILE_ORIGINAL[2:]))

    def test_explicit_copies_of_inherited_allows_are_rejected_everywhere(self):
        # The hosted-runner shape. Explicit allows outlive revocation of the
        # inherited grant, so this is a different ACL, not a representation.
        self.assertFalse(self.file_ok(FILE_ORIGINAL, FILE_WITH_COPIES))
        self.assertFalse(self.parent_ok(PARENT_ORIGINAL, PARENT_WITH_COPIES))
        after_remove = FILE_WITH_COPIES.replace("(D;;DCLC;;;BU)", "")
        self.assertFalse(guarded._same_effective_dacl(FILE_ORIGINAL, after_remove))
        parent_after_remove = PARENT_WITH_COPIES.replace("(D;;LC;;;BU)", "")
        self.assertFalse(guarded._same_effective_dacl(PARENT_ORIGINAL, parent_after_remove))

    def test_explicit_and_inherited_spellings_of_one_allow_are_different_aces(self):
        explicit, inherited = "D:(A;;FA;;;SY)", "D:(A;ID;FA;;;SY)"
        self.assertNotEqual(guarded._aces(explicit), guarded._aces(inherited))
        self.assertFalse(guarded._same_effective_dacl(explicit, inherited))
        self.assertFalse(guarded._same_effective_dacl(inherited, explicit))
        self.assertFalse(self.file_ok(inherited, "D:AI(D;;DCLC;;;BU)(A;;FA;;;SY)"))
        self.assertFalse(self.parent_ok("D:(A;OICIID;FA;;;SY)", "D:AI(D;;LC;;;BU)(A;OICI;FA;;;SY)"))

    def test_any_changed_count_flag_order_or_deny_is_rejected(self):
        for original, now in (
                ("D:(A;ID;FR;;;SY)", "D:AI(D;;DCLC;;;BU)(A;;FA;;;SY)(A;ID;FR;;;SY)"),     # extra, wider
                (FILE_ORIGINAL, "D:AI(D;;DCLC;;;BU)" + FILE_ORIGINAL[2:] + "(A;;FR;;;WD)"),  # new trustee
                ("D:(A;ID;FA;;;SY)", "D:AI(D;;DCLC;;;BU)(A;ID;FA;;;SY)(A;ID;FA;;;SY)"),     # duplicated
                (FILE_ORIGINAL, "D:AI(D;;DCLC;;;BU)(A;ID;FA;;;SY)(A;ID;FA;;;BA)"),          # lost
                (FILE_ORIGINAL,
                 "D:AI(D;;DCLC;;;BU)(A;ID;FA;;;BA)(A;ID;FA;;;SY)(A;ID;FA;;;OW)"),           # reordered
                (FILE_ORIGINAL, "D:PAI(D;;DCLC;;;BU)" + FILE_ORIGINAL[2:]),                  # P changed
                (FILE_ORIGINAL, "D:AI(D;;DC;;;BU)" + FILE_ORIGINAL[2:]),                     # wrong mask
                (FILE_ORIGINAL, "D:AI(D;;DCLC;;;BG)" + FILE_ORIGINAL[2:]),                   # wrong trustee
                (FILE_ORIGINAL, "D:AI(D;OI;DCLC;;;BU)" + FILE_ORIGINAL[2:]),                 # wrong flags
                (FILE_ORIGINAL, "D:AI(D;;DCLC;;;BU)(D;;DCLC;;;BU)" + FILE_ORIGINAL[2:])):    # two denies
            self.assertFalse(self.file_ok(original, now), now)
        for now in (PARENT_ORIGINAL.replace("D:", "D:AI(D;;LC;;;BU)(A;OICI;FR;;;WD)", 1),
                    "D:AI(D;;LC;;;BG)" + PARENT_ORIGINAL[2:],
                    "D:AI(D;;DCLC;;;BU)" + PARENT_ORIGINAL[2:]):
            self.assertFalse(self.parent_ok(PARENT_ORIGINAL, now), now)

    def test_explicit_copy_detector_flags_only_explicit_twins_of_inherited_allows(self):
        self.assertEqual(len(_explicit_twins(FILE_WITH_COPIES)), 3)
        self.assertEqual(len(_explicit_twins(PARENT_WITH_COPIES)), 3)
        self.assertEqual(_explicit_twins(FILE_ORIGINAL), [])
        self.assertEqual(_explicit_twins(PARENT_ORIGINAL), [])
        # An explicit allow with no inherited twin, and a deny, are not copies.
        self.assertEqual(_explicit_twins("D:AI(D;;DCLC;;;BU)(A;;FR;;;WD)(A;ID;FA;;;SY)"), [])


def _call(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(list(args), capture_output=True, text=True, timeout=30)


def _icacls(*args: str) -> None:
    result = _call("icacls.exe", *args)
    assert result.returncode == 0, result.stderr or result.stdout


def _inherited_twin(ace: str) -> str:
    """Inherited spelling of an explicit allow ACE (test-local, independent of the guard)."""
    fields = ace[1:-1].split(";")
    return "(" + ";".join(fields[:1] + [fields[1] + "ID"] + fields[2:]) + ")" if fields[0] == "A" else ""


def _explicit_twins(sddl: str) -> list[str]:
    """Explicit ACEs whose inherited spelling is also present (test-local, independent of the guard)."""
    aces = guarded._aces(sddl)
    return [ace for ace in aces if _inherited_twin(ace) and _inherited_twin(ace) in aces]


def _grant_explicit_copies(path: Path) -> None:
    """Real icacls grants that build the hosted shape on an owned fixture (a shape, not a cause)."""
    # The fixture is declared before it is changed: copies must be introduced here,
    # not already present, or the case would prove nothing.
    assert not _explicit_twins(guarded.directory_dacl_sddl(path)), "fixture baseline already has explicit copies"
    inherited = [ace.split(";")[5].rstrip(")") for ace in guarded._aces(guarded.directory_dacl_sddl(path))
                 if ace.startswith("(A;") and "ID" in ace.split(";")[1]]
    wanted = [alias for alias in TRUSTEE_SIDS if alias in inherited]
    assert wanted, "no inherited SY/BA/OW allow to copy"
    rights = "(OI)(CI)(F)" if path.is_dir() else "(F)"
    # icacls prepends each grant, so pass them reversed to keep SY, BA, OW order.
    _icacls(str(path), "/grant", *["*" + TRUSTEE_SIDS[alias] + ":" + rights for alias in reversed(wanted)])
    assert _explicit_twins(guarded.directory_dacl_sddl(path)), "hosted shape not reached"


@unittest.skipUnless(os.name == "nt", "Windows ACL contract")
class StrictAclFenceTests(unittest.TestCase):
    def setUp(self):
        self.sid = guarded._current_sid()
        self.temp = tempfile.TemporaryDirectory(prefix=TEMP_PREFIX)
        self.addCleanup(self._cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "old-app"
        self.old = self.root / "state"
        self.old.mkdir(parents=True)
        self.archive = self.base / "archive" / "state"
        self.archive.parent.mkdir()
        self.receipts = self.base / "receipts"
        self.receipts.mkdir()
        self.content = {}
        for name in guarded.NAMES:
            body = b"0" if name == "controller.lock" else ("strict:" + name).encode()
            (self.old / name).write_bytes(body)
            self.content[name] = hashlib.sha256(body).hexdigest()
        for name in ("source-stage.lock", "phase-stage.lock"):
            (self.root / name).write_bytes(b"0")
        self.pin()

    def pin(self):
        """Declare the source ACL: pins are taken only after the fixture ACL is final."""
        self.original_parent = guarded.directory_dacl_sddl(self.root)
        self.original_files = {name: guarded.directory_dacl_sddl(self.old / name)
                               for name in guarded.NAMES}
        self.parent_acl_sha = hashlib.sha256(self.original_parent.encode()).hexdigest()
        self.file_acl_sha = {name: hashlib.sha256(value.encode()).hexdigest()
                             for name, value in self.original_files.items()}

    def _cleanup(self):
        targets = [self.root] + [base / name for base in (self.old, self.archive)
                                 for name in guarded.NAMES]
        for target in targets:
            if target.exists():
                _call("icacls.exe", str(target), "/remove:d", "*" + self.sid)
        self.temp.cleanup()
        self.assertFalse(self.base.exists())

    def invoke(self):
        return guarded.fence_closed_old_phase_guarded(
            old_root=self.old, archived_root=self.archive,
            expected_file_sha256=self.content,
            source_stage_lock=self.root / "source-stage.lock",
            phase_stage_lock=self.root / "phase-stage.lock", deny_sid=self.sid,
            expected_parent_dacl_sha256=self.parent_acl_sha,
            expected_file_dacl_sha256=self.file_acl_sha,
            barrier_receipt_path=self.receipts / "barrier.json",
            fence_receipt_path=self.receipts / "fence.json")

    def after_guard_deny(self, then):
        """Wrap the guard's real icacls: after each real deny, apply ``then(path)``."""
        actual = guarded._icacls

        def wrapped(path, *args):
            actual(path, *args)
            if "/deny" in args:
                then(Path(path))
        return patch.object(guarded, "_icacls", side_effect=wrapped)

    def contender_denied(self, name):
        return _call(sys.executable, "-c", OPEN_FOR_WRITE, str(self.old / name)).returncode != 0

    def contenders_denied_before_rename(self):
        seen = {}
        actual_rename = guarded.os.rename

        def observe(source, destination):
            for name in guarded.NAMES:
                seen[name] = self.contender_denied(name)
            return actual_rename(source, destination)
        return seen, patch.object(guarded.os, "rename", side_effect=observe)

    def assert_failed_closed(self, message, *, expect_denied_controller=True):
        """Nothing moved, no completion receipt, and the real admission barrier still holds."""
        self.assertTrue(self.old.exists())
        self.assertFalse(self.archive.exists())
        self.assertFalse((self.receipts / "fence.json").exists())
        if expect_denied_controller:
            self.assertTrue(guarded._file_deny(self.old / "controller.lock", self.sid))
            self.assertTrue(self.contender_denied("controller.lock"))

    def test_declared_explicit_and_inherited_source_is_preserved_exactly(self):
        # Fixture ACL declared (and verified) before pinning: explicit + inherited allows.
        _grant_explicit_copies(self.root)
        for name in guarded.NAMES:
            _grant_explicit_copies(self.old / name)
        self.pin()
        self.assertTrue(_explicit_twins(self.original_parent))
        self.assertTrue(all(_explicit_twins(value) for value in self.original_files.values()))
        seen, rename = self.contenders_denied_before_rename()
        with rename:
            result = self.invoke()
        self.assertEqual(seen, {name: True for name in guarded.NAMES})
        self.assertEqual(result["status"], "OLD_PATH_FENCED_NEW_PHASE_ALLOWED")
        # Exact preservation: same ACE count, flags and order; only the parent deny added.
        deny = guarded._canonical_ace(guarded.DENY_PARENT_ACE.format(sid=self.sid))
        parent_now = guarded._aces(guarded.directory_dacl_sddl(self.root))
        self.assertIn(deny, parent_now)
        parent_now.remove(deny)
        self.assertEqual(parent_now, guarded._aces(self.original_parent))
        for name in guarded.NAMES:
            self.assertEqual(guarded._aces(guarded.directory_dacl_sddl(self.archive / name)),
                             guarded._aces(self.original_files[name]), name)
            self.assertFalse(guarded._file_deny(self.archive / name, self.sid))
        self.assertEqual({name: hashlib.sha256((self.archive / name).read_bytes()).hexdigest()
                          for name in guarded.NAMES}, self.content)

    def test_unexpected_explicit_copies_on_the_parent_fail_closed_before_the_rename(self):
        def copies_on_parent(path):
            if path == self.root:
                _grant_explicit_copies(path)
        with self.after_guard_deny(copies_on_parent), \
                patch.object(guarded.os, "rename", wraps=os.rename) as rename:
            with self.assertRaisesRegex(Exception, "old parent DACL broadened"):
                self.invoke()
            rename.assert_not_called()
        self.assert_failed_closed("parent")

    def test_unexpected_explicit_copies_on_a_denied_file_fail_closed_on_replay(self):
        calls = {"count": 0}

        def copies_then_crash(path):
            _grant_explicit_copies(path)
            calls["count"] += 1
            if calls["count"] == 1:
                raise RuntimeError("injected post-controller-deny crash")
        with self.after_guard_deny(copies_then_crash):
            with self.assertRaisesRegex(RuntimeError, "injected"):
                self.invoke()
        with patch.object(guarded.os, "rename", wraps=os.rename) as rename:
            with self.assertRaisesRegex(Exception, "unreviewed old file DACL drift"):
                self.invoke()
            rename.assert_not_called()
        self.assert_failed_closed("file")

    def test_real_parent_broadening_after_the_guard_deny_fails_closed(self):
        def broaden_parent(path):
            if path == self.root:
                _icacls(str(path), "/grant", "*" + EVERYONE_SID + ":(R)")
        with self.after_guard_deny(broaden_parent), \
                patch.object(guarded.os, "rename", wraps=os.rename) as rename:
            with self.assertRaisesRegex(Exception, "old parent DACL broadened"):
                self.invoke()
            rename.assert_not_called()
        self.assert_failed_closed("parent")

    def test_real_file_broadening_is_rejected_on_replay_before_the_rename(self):
        calls = {"count": 0}

        def broaden_then_crash(path):
            calls["count"] += 1
            if calls["count"] == 1:
                _icacls(str(path), "/grant", "*" + EVERYONE_SID + ":(R)")
                raise RuntimeError("injected post-controller-deny crash")
        with self.after_guard_deny(broaden_then_crash):
            with self.assertRaisesRegex(RuntimeError, "injected"):
                self.invoke()
        with patch.object(guarded.os, "rename", wraps=os.rename) as rename:
            with self.assertRaisesRegex(Exception, "unreviewed old file DACL drift"):
                self.invoke()
            rename.assert_not_called()
        self.assert_failed_closed("file")


if __name__ == "__main__":
    unittest.main()
