"""Disposable Windows namespace fencing; authored data, no real pilot run."""
from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from trace_gc.canonical import bytes_digest
from trace_gc.errors import ContractError
from trace_gc.phase_authority import dacl_has_ace, directory_dacl_sddl
from src.paper_pilot_phase_cutover import (NAMES, TOKEN_NOT_REFUSED, _current_sid,
                                           fence_closed_old_phase)
from tests.windows_privilege_scope import privileges_disabled
from tools import windows_fixture_acl

PARENT_DENY = "(D;;LC;;;{sid})"


def token_creates_beneath_own_deny(root: Path, sid: str) -> bool:
    """Independent probe: can this process token create beneath a parent deny naming ``sid``?"""
    parent = root / "token-probe"
    parent.mkdir()
    windows_fixture_acl.stabilize_owned_fixture(root, [("probe", parent)], read=directory_dacl_sddl)
    added = subprocess.run(["icacls.exe", str(parent), "/deny", "*" + sid + ":(AD)"],
                           capture_output=True, text=True, timeout=30)
    assert added.returncode == 0, added.stderr or added.stdout
    try:
        try:
            (parent / "child").mkdir()
        except OSError as error:
            assert getattr(error, "winerror", None) == 5, error
            return False
        (parent / "child").rmdir()
        return True
    finally:
        removed = subprocess.run(["icacls.exe", str(parent), "/remove:d", "*" + sid],
                                 capture_output=True, text=True, timeout=30)
        assert removed.returncode == 0, removed.stderr or removed.stdout
        parent.rmdir()


@unittest.skipUnless(os.name == "nt", "requires disposable NTFS DACL fixture")
class PhaseNamespaceFenceTests(unittest.TestCase):
    def setUp(self):
        base = os.environ.get("ISSUE90_TEST_TMPDIR")
        self.temp = tempfile.TemporaryDirectory(dir=base)
        self.root = Path(self.temp.name)
        self.old = self.root / "old-application" / "state"
        self.old.parent.mkdir()
        # Protected and explicit before anything is pinned: Windows marks a rewritten unprotected
        # DACL auto-inherited (AI), so an unprotected parent could never read back equal to its
        # pre-state and the strict restoration check would (rightly) hold.
        windows_fixture_acl.stabilize_owned_fixture(
            self.root, [("parent", self.old.parent)], read=directory_dacl_sddl)
        self.old.mkdir()
        self.archived = self.root / "archive" / "historical-state"
        self.archived.parent.mkdir()
        self.receipt = self.root / "control" / "fence-receipt.json"
        self.receipt.parent.mkdir()
        for name in sorted(NAMES):
            if name.endswith(".sqlite3"):
                connection = sqlite3.connect(self.old / name)
                try:
                    connection.execute("CREATE TABLE fixture (id INTEGER PRIMARY KEY)")
                    connection.execute("INSERT INTO fixture VALUES (1)")
                    connection.commit()
                finally:
                    connection.close()
            else:
                (self.old / name).write_bytes(b"0")
        self.expected = {name: bytes_digest((self.old / name).read_bytes()) for name in NAMES}
        self.sid = _current_sid()

    def tearDown(self):
        result = subprocess.run(["icacls.exe", str(self.old.parent), "/remove:d", "*" + self.sid],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0)
        self.temp.cleanup()

    def fence(self):
        return fence_closed_old_phase(old_root=self.old, archived_root=self.archived,
            expected_file_sha256=self.expected, deny_sid=self.sid, receipt_path=self.receipt)

    def test_exact_replay_after_closed_directory_move(self):
        self.assertFalse(dacl_has_ace(directory_dacl_sddl(self.old.parent), PARENT_DENY, self.sid))
        # The positive path needs a token the deny refuses; see tests/windows_privilege_scope.py.
        with privileges_disabled():
            first = self.fence()
            self.assertEqual(first["status"], "OLD_PATH_FENCED_NEW_PHASE_ALLOWED")
            self.assertFalse(self.old.exists())
            self.assertEqual({name: bytes_digest((self.archived / name).read_bytes())
                              for name in NAMES}, self.expected)
            self.assertTrue(dacl_has_ace(directory_dacl_sddl(self.old.parent), PARENT_DENY,
                                         self.sid))
            with self.assertRaises(PermissionError) as refused:
                self.old.mkdir()
            self.assertEqual(refused.exception.winerror, 5)
            second = self.fence()
        self.assertEqual(first, second)
        connection = sqlite3.connect(self.root / "target.sqlite3")
        try:
            connection.execute("CREATE TABLE target (id INTEGER)")
            connection.commit()
        finally:
            connection.close()

    def test_full_process_token_fences_only_when_the_deny_refuses_it(self):
        creates = token_creates_beneath_own_deny(self.root, self.sid)
        print("\nfull-token-creates-beneath-deny=%s" % creates, file=sys.stderr)
        before = directory_dacl_sddl(self.old.parent)
        if not creates:
            self.assertEqual(self.fence()["status"], "OLD_PATH_FENCED_NEW_PHASE_ALLOWED")
            return
        with self.assertRaises(ContractError) as held:
            self.fence()
        # Held before any effect: the added deny is removed and the DACL reads back exactly.
        self.assertEqual((held.exception.code, held.exception.detail),
                         ("PHASE_FENCE", TOKEN_NOT_REFUSED))
        self.assertEqual(directory_dacl_sddl(self.old.parent), before)
        self.assertTrue(self.old.is_dir())
        self.assertFalse(self.archived.exists())
        self.assertFalse(self.receipt.exists())
        self.assertEqual([p.name for p in self.old.parent.iterdir()], ["state"])

    def test_wrong_hash_holds_before_acl_change(self):
        wrong = {**self.expected, "graph.sqlite3": "0" * 64}
        with self.assertRaises(ContractError):
            fence_closed_old_phase(old_root=self.old, archived_root=self.archived,
                expected_file_sha256=wrong, deny_sid=self.sid, receipt_path=self.receipt)
        self.assertTrue(self.old.exists())
        self.assertFalse(self.archived.exists())
        self.assertFalse(dacl_has_ace(directory_dacl_sddl(self.old.parent), PARENT_DENY, self.sid))

    def test_junction_archive_parent_holds_before_acl_or_rename(self):
        junction = self.root / "redirected-archive"
        script = self.root / "create-junction.ps1"
        script.write_text("param([string]$Link,[string]$Target)\n"
                          "New-Item -ItemType Junction -Path $Link -Target $Target | Out-Null\n",
                          encoding="utf-8")
        created = subprocess.run(["pwsh.exe", "-NoProfile", "-NonInteractive",
                                  "-File", str(script), str(junction), str(self.archived.parent)],
                                 capture_output=True, text=True, timeout=15)
        self.assertEqual(created.returncode, 0, created.stderr)
        try:
            before = directory_dacl_sddl(self.old.parent)
            with self.assertRaises(ContractError):
                fence_closed_old_phase(old_root=self.old,
                    archived_root=junction / "state", expected_file_sha256=self.expected,
                    deny_sid=self.sid, receipt_path=self.receipt)
            self.assertEqual(before, directory_dacl_sddl(self.old.parent))
            self.assertTrue(self.old.exists())
            self.assertFalse(self.archived.exists())
            self.assertFalse(self.receipt.exists())
        finally:
            junction.rmdir()


if __name__ == "__main__":
    unittest.main()
