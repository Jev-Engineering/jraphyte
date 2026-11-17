"""The installed-wheel trustee check must refuse to pass against the checkout copy."""
from __future__ import annotations

import contextlib
import io
import json
import unittest

from tools import installed_phase_authority_check as check
import trace_gc


class CheckoutRefusalTests(unittest.TestCase):
    def test_the_checkout_copy_is_never_reported_as_the_installed_package(self):
        self.assertTrue(check.Path(trace_gc.__file__).resolve().is_relative_to(check.CHECKOUT))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(check.main(), 1)
        report = json.loads(output.getvalue())
        self.assertEqual(report, {"results": {"imported_from_installed_package": False},
                                  "native_windows": "NOT_RUN"})


if __name__ == "__main__":
    unittest.main()
