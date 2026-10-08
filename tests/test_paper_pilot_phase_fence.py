"""Disposable Windows namespace fencing; authored data, no real pilot run."""
from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest

from trace_gc.canonical import bytes_digest
from trace_gc.errors import ContractError
from trace_gc.phase_authority import dacl_has_ace, directory_dacl_sddl
from src.paper_pilot_phase_cutover import NAMES, _current_sid, fence_closed_old_phase
from tools.windows_native_acl import WindowsNative, require_recreation_denied

PARENT_DENY = "(D;;LC;;;{sid})"


@unittest.skipUnless(os.name == "nt", "requires disposable NTFS DACL fixture")
class PhaseNamespaceFenceTests(unittest.TestCase):
    def setUp(self):
        base = os.environ.get("ISSUE90_TEST_TMPDIR")
        self.temp = tempfile.TemporaryDirectory(dir=base)
        self.root = Path(self.temp.name)
        self.old = self.root / "old-application" / "state"
        self.old.mkdir(parents=True)
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

    def test_exact_replay_after_closed_directory_move(self):
        self.assertFalse(dacl_has_ace(directory_dacl_sddl(self.old.parent), PARENT_DENY, self.sid))
        first = fence_closed_old_phase(old_root=self.old, archived_root=self.archived,
            expected_file_sha256=self.expected, deny_sid=self.sid, receipt_path=self.receipt)
        self.assertEqual(first["status"], "OLD_PATH_FENCED_NEW_PHASE_ALLOWED")
        self.assertFalse(self.old.exists())
        self.assertEqual({name: bytes_digest((self.archived / name).read_bytes())
                          for name in NAMES}, self.expected)
        self.assertTrue(dacl_has_ace(directory_dacl_sddl(self.old.parent), PARENT_DENY, self.sid))
        require_recreation_denied(WindowsNative(), self.old.parent, self.old)
        self.assertFalse(self.old.exists())
        second = fence_closed_old_phase(old_root=self.old, archived_root=self.archived,
            expected_file_sha256=self.expected, deny_sid=self.sid, receipt_path=self.receipt)
        self.assertEqual(first, second)
        connection = sqlite3.connect(self.root / "target.sqlite3")
        try:
            connection.execute("CREATE TABLE target (id INTEGER)")
            connection.commit()
        finally:
            connection.close()

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
