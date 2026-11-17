"""Check checkout refusal and the portable model of the signed wheel fixture."""
from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools import installed_phase_authority_check as check
import trace_gc
from trace_gc import phase_authority as authority


class CheckoutRefusalTests(unittest.TestCase):
    def test_the_checkout_copy_is_never_reported_as_the_installed_package(self):
        self.assertTrue(check.Path(trace_gc.__file__).resolve().is_relative_to(check.CHECKOUT))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(check.main(), 1)
        report = json.loads(output.getvalue())
        self.assertEqual(report, {"results": {"imported_from_installed_package": False},
                                  "native_windows": "NOT_RUN"})


class SignedFenceFixtureTests(unittest.TestCase):
    def test_signed_activation_reaches_fence_verification(self):
        raw = "D:(D;;LC;;;BU)"
        windows_os = SimpleNamespace(name="nt", fstat=os.fstat, stat=os.stat)
        windows_lock = SimpleNamespace(locking=lambda *_: None, LK_LOCK=1, LK_UNLCK=0)

        def spell(sid):
            return "BU" if sid == check.USERS_SID else sid

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            parent = base / "parent"
            parent.mkdir()
            # Keep signing, pinning and validation real. Model the Windows-only OS calls.
            with (patch.object(authority, "os", windows_os),
                  patch.object(authority, "directory_dacl_sddl", return_value=raw),
                  patch.object(authority, "_windows_trustee", side_effect=spell),
                  patch.dict("sys.modules", {"msvcrt": windows_lock})):
                results = check.signed_fence_checks(authority, base, parent, raw)
        self.assertEqual(results, {
            "signed_alias_fence_accepted": True,
            "signed_fence_rejects_unrelated_trustee": True,
            "signed_fence_rejects_foreign_rid500": True,
            "signed_fence_rejects_wrong_dacl_digest": True,
            "activation_rejects_wrong_signing_key": True,
        })


if __name__ == "__main__":
    unittest.main()
