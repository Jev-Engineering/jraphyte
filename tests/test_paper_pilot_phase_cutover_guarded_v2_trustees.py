"""Windows SID/SDDL trustee-alias regressions for the guarded admission barrier.

Windows serializes some numeric SIDs in a DACL string as SDDL aliases (the
built-in Administrator, RID 500, is ``LA``; the Users group S-1-5-32-545 is
``BU``). The barrier must recognize its own deny ACE under either spelling while
still rejecting a different trustee, mask, inheritance flag, ACE order or extra
ACE. These cases are a separate hosted gate from the nine original fence cases.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from src import paper_pilot_phase_cutover_guarded_v2 as guarded
from src.paper_pilot_phase_cutover import _current_sid
from tools import windows_fixture_acl


USERS_SID = "S-1-5-32-545"      # serialized by Windows as the alias BU
GUESTS_SID = "S-1-5-32-546"     # an unrelated trustee, serialized as BG
ADMINS_SID = "S-1-5-32-544"     # an unrelated trustee, serialized as BA
TEMP_PREFIX = "jraphyte-fence-trustee-"


def _icacls(*args: str) -> None:
    result = subprocess.run(["icacls.exe", *args], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr or result.stdout


FOREIGN_RID500_SID = "S-1-5-21-1111111111-2222222222-3333333333-500"  # fabricated domain


def _account_prefix() -> str:
    prefix = re.fullmatch(r"(S-1-5-21-\d+-\d+-\d+)-\d+", _current_sid())
    assert prefix is not None, "test requires a machine/domain account SID"
    return prefix.group(1)


def _rid500_sid() -> str:
    # The machine account domain's built-in Administrator; derived from the
    # runner's own SID so no account lookup or account change is needed.
    return _account_prefix() + "-500"


def _plain_account_sid() -> str:
    # A same-domain account that has no SDDL alias (never RID 500).
    current = _current_sid()
    return current if not current.endswith("-500") else _account_prefix() + "-1001"


@unittest.skipUnless(os.name == "nt", "Windows SID/SDDL contract")
class TrusteeSemanticsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix=TEMP_PREFIX)
        self.addCleanup(self._cleanup)
        self.file = Path(self.temp.name) / "probe.bin"
        self.file.write_bytes(b"0")

    def _cleanup(self):
        for sid in (USERS_SID, GUESTS_SID, ADMINS_SID, _rid500_sid(), FOREIGN_RID500_SID):
            subprocess.run(["icacls.exe", str(self.file), "/remove:d", "*" + sid],
                           capture_output=True, text=True, timeout=30)
        self.temp.cleanup()
        self.assertFalse(Path(self.temp.name).exists())

    def test_canonical_trustee_uses_windows_serialization(self):
        self.assertEqual(guarded._canonical_trustee(USERS_SID), "BU")
        self.assertEqual(guarded._canonical_trustee("S-1-5-18"), "SY")
        self.assertEqual(guarded._canonical_trustee("S-1-1-0"), "WD")
        # Aliases, SIDs without an alias and non-SID text pass through unchanged.
        self.assertEqual(guarded._canonical_trustee("BU"), "BU")
        self.assertEqual(guarded._canonical_trustee("S-1-5-21-1-2-3-1001"),
                         "S-1-5-21-1-2-3-1001")
        injected = "S-1-5-18)(A;;FA;;;WD"
        self.assertEqual(guarded._canonical_trustee(injected), injected)

    def test_real_dacl_alias_matches_numeric_deny_and_nothing_else(self):
        _icacls(str(self.file), "/deny", "*" + USERS_SID + ":(WD,AD)")
        raw = guarded.directory_dacl_sddl(self.file)
        # The OS really does serialize the numeric SID as the alias, so a
        # literal numeric comparison cannot see this ACE.
        self.assertIn("(D;;DCLC;;;BU)", raw)
        self.assertNotIn(USERS_SID, raw)
        self.assertNotIn(guarded.DENY_FILE_ACE.format(sid=USERS_SID), raw)
        self.assertTrue(guarded._file_deny(self.file, USERS_SID))
        self.assertTrue(guarded._owner_deny_present(raw, USERS_SID))
        self.assertFalse(guarded._file_deny(self.file, ADMINS_SID))
        self.assertFalse(guarded._file_deny(self.file, GUESTS_SID))
        self.assertFalse(guarded._owner_deny_present(raw, ADMINS_SID))

    def test_machine_administrator_rid500_deny_is_recognized(self):
        sid = _rid500_sid()
        self.assertFalse(guarded._file_deny(self.file, sid))
        _icacls(str(self.file), "/deny", "*" + sid + ":(WD,AD)")
        raw = guarded.directory_dacl_sddl(self.file)
        # Whichever spelling Windows chose (numeric, or LA on the runner whose
        # own identity is RID 500) the exact barrier ACE must be recognized.
        self.assertTrue(guarded._file_deny(self.file, sid), raw)
        self.assertTrue(guarded._owner_deny_present(raw, sid), raw)

    def test_foreign_domain_rid500_is_not_collapsed_into_local_administrator(self):
        local, foreign, plain = _rid500_sid(), FOREIGN_RID500_SID, _plain_account_sid()
        self.assertNotEqual(local, foreign)
        canonical = {sid: guarded._canonical_trustee(sid) for sid in (local, foreign, plain)}
        # In-memory Windows conversion only: a SID from another domain that
        # shares RID 500 gets no alias, and neither does a plain account.
        self.assertEqual(canonical[foreign], foreign)
        self.assertEqual(canonical[plain], plain)
        self.assertNotIn(canonical[foreign], ("LA", canonical[local]))
        self.assertEqual(len(set(canonical.values())), 3, canonical)
        # Same RID 500 and same first two domain sub-authorities, different last one.
        near = _account_prefix().rsplit("-", 1)[0] + "-" + str(int(_account_prefix().rsplit("-", 1)[1]) + 1) + "-500"
        self.assertEqual(guarded._canonical_trustee(near), near)
        self.assertNotEqual(guarded._canonical_trustee(near), canonical[local])

    def test_ace_matching_never_crosses_local_foreign_and_plain_accounts(self):
        sids = {"local": _rid500_sid(), "foreign": FOREIGN_RID500_SID, "plain": _plain_account_sid()}
        for ace_name, ace_sid in sids.items():
            # Both spellings Windows may use: the serialized (alias) form and the numeric form.
            for spelling in (guarded._canonical_trustee(ace_sid), ace_sid):
                file_deny = "D:AI(D;;DCLC;;;" + spelling + ")(A;ID;FA;;;SY)"
                parent_deny = "D:AI(D;;LC;;;" + spelling + ")(A;OICIID;FA;;;SY)"
                for query_name, query_sid in sids.items():
                    same = ace_name == query_name
                    label = (ace_name, spelling, query_name)
                    self.assertEqual(guarded._has_ace(file_deny, guarded.DENY_FILE_ACE, query_sid),
                                     same, label)
                    self.assertEqual(guarded._has_ace(parent_deny, guarded.DENY_PARENT_ACE, query_sid),
                                     same, label)
                    self.assertEqual(guarded._owner_deny_present(file_deny, query_sid), same, label)
                    self.assertEqual(guarded._only_admission_dacl_added(
                        "D:(A;ID;FA;;;SY)", file_deny, query_sid), same, label)
                    self.assertEqual(guarded._only_parent_admission_added(
                        "D:(A;OICIID;FA;;;SY)", parent_deny, query_sid), same, label)
        # An effective-DACL comparison must not equate two different RID-500 trustees.
        self.assertFalse(guarded._same_effective_dacl(
            "D:(D;;DCLC;;;" + guarded._canonical_trustee(sids["local"]) + ")",
            "D:(D;;DCLC;;;" + FOREIGN_RID500_SID + ")"))
        self.assertTrue(guarded._same_effective_dacl(
            "D:(D;;DCLC;;;" + guarded._canonical_trustee(sids["local"]) + ")",
            "D:AI(D;;DCLC;;;" + sids["local"] + ")"))

    def test_real_local_rid500_deny_does_not_match_foreign_or_plain_accounts(self):
        # icacls cannot install an unresolvable foreign-domain SID, so the real
        # DACL leg uses the machine's own RID 500 and queries the other two.
        sid = _rid500_sid()
        _icacls(str(self.file), "/deny", "*" + sid + ":(WD,AD)")
        raw = guarded.directory_dacl_sddl(self.file)
        self.assertTrue(guarded._file_deny(self.file, sid), raw)
        for other in (FOREIGN_RID500_SID, _plain_account_sid(), USERS_SID):
            if other == sid:   # the runner itself is the plain account only when not RID 500
                continue
            self.assertFalse(guarded._file_deny(self.file, other), (other, raw))
            self.assertFalse(guarded._owner_deny_present(raw, other), (other, raw))

    def test_numeric_and_alias_spellings_are_equivalent_in_sddl_text(self):
        alias = "D:AI(D;;DCLC;;;BU)(A;ID;FA;;;SY)"
        numeric = "D:AI(D;;DCLC;;;" + USERS_SID + ")(A;ID;FA;;;SY)"
        for text in (alias, numeric):
            self.assertTrue(guarded._has_ace(text, guarded.DENY_FILE_ACE, USERS_SID))
            self.assertTrue(guarded._owner_deny_present(text, USERS_SID))
        self.assertTrue(guarded._only_admission_dacl_added(
            "D:(A;ID;FA;;;SY)", alias, USERS_SID))
        self.assertTrue(guarded._only_admission_dacl_added(
            "D:(A;ID;FA;;;SY)", numeric, USERS_SID))
        parent = "D:AI(D;;LC;;;BU)(A;OICIID;FA;;;SY)"
        self.assertTrue(guarded._only_parent_admission_added(
            "D:(A;OICIID;FA;;;SY)", parent, USERS_SID))
        self.assertTrue(guarded._same_effective_dacl(
            "D:(D;;DCLC;;;BU)(A;ID;FA;;;SY)", "D:AI(D;;DCLC;;;" + USERS_SID + ")(A;ID;FA;;;SY)"))

    def test_wrong_trustee_mask_flags_or_type_are_rejected(self):
        for text in (
                "D:(D;;DCLC;;;BA)",             # different trustee
                "D:(D;;DCLC;;;BG)",
                "D:(D;;DC;;;BU)",               # narrower mask
                "D:(D;;DCLCWP;;;BU)",           # broader mask
                "D:(D;OI;DCLC;;;BU)",           # inheritance flag added
                "D:(D;ID;DCLC;;;BU)",
                "D:(A;;DCLC;;;BU)",             # allow, not deny
                "D:(OD;;DCLC;;;BU)"):           # object deny
            self.assertFalse(guarded._has_ace(text, guarded.DENY_FILE_ACE, USERS_SID), text)
        self.assertFalse(guarded._has_ace("D:(D;;LC;;;BU)", guarded.DENY_FILE_ACE, USERS_SID))
        self.assertFalse(guarded._has_ace("D:(D;;DCLC;;;BU)", guarded.DENY_PARENT_ACE, USERS_SID))
        # An allow ACE or a deny of another trustee is not an owner deny.
        self.assertFalse(guarded._owner_deny_present("D:(A;;FA;;;BU)", USERS_SID))
        self.assertFalse(guarded._owner_deny_present("D:(D;;FX;;;BA)", USERS_SID))
        self.assertTrue(guarded._owner_deny_present("D:(D;;FX;;;BU)", USERS_SID))

    def test_only_the_exact_deny_may_be_added_in_original_order(self):
        original = "D:(A;ID;FA;;;SY)(A;ID;FA;;;BA)"
        good = "D:AI(D;;DCLC;;;BU)(A;ID;FA;;;SY)(A;ID;FA;;;BA)"
        self.assertTrue(guarded._only_admission_dacl_added(original, good, USERS_SID))
        for current in (
                "D:AI(D;;DCLC;;;BG)(A;ID;FA;;;SY)(A;ID;FA;;;BA)",           # wrong trustee
                "D:AI(D;;DC;;;BU)(A;ID;FA;;;SY)(A;ID;FA;;;BA)",             # wrong mask
                "D:AI(D;OI;DCLC;;;BU)(A;ID;FA;;;SY)(A;ID;FA;;;BA)",         # wrong flags
                "D:AI(D;;DCLC;;;BU)(A;ID;FA;;;BA)(A;ID;FA;;;SY)",           # reordered
                "D:AI(D;;DCLC;;;BU)(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;;FR;;;WD)",  # extra access
                "D:AI(D;;DCLC;;;BU)(A;ID;FA;;;SY)",                         # removed access
                "D:PAI(D;;DCLC;;;BU)(A;ID;FA;;;SY)(A;ID;FA;;;BA)"):         # protection changed
            self.assertFalse(guarded._only_admission_dacl_added(original, current, USERS_SID),
                             current)
        self.assertFalse(guarded._only_parent_admission_added(
            "D:(A;OICIID;FA;;;SY)", "D:AI(D;;DC;;;BU)(A;OICIID;FA;;;SY)", USERS_SID))


@unittest.skipUnless(os.name == "nt", "Windows SID/SDDL contract")
class AliasIdentityFenceTests(unittest.TestCase):
    """Run the real barrier as an identity whose SDDL trustee is an alias (BU)."""

    def setUp(self):
        self.sid = USERS_SID
        patcher = patch.object(guarded, "_current_sid", return_value=self.sid)
        patcher.start()
        self.addCleanup(patcher.stop)
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
            body = b"0" if name == "controller.lock" else ("alias:" + name).encode()
            (self.old / name).write_bytes(body)
            self.content[name] = hashlib.sha256(body).hexdigest()
        for name in ("source-stage.lock", "phase-stage.lock"):
            (self.root / name).write_bytes(b"0")
        # Explicit, protected and verified before the first pin (see tools/windows_fixture_acl.py).
        windows_fixture_acl.stabilize_owned_fixture(
            self.base, [("parent", self.root), ("state", self.old)]
            + [("file:" + name, self.old / name) for name in sorted(guarded.NAMES)],
            read=guarded.directory_dacl_sddl)
        self._pin()

    def _pin(self):
        self.parent_acl_sha = hashlib.sha256(
            guarded.directory_dacl_sddl(self.root).encode()).hexdigest()
        self.file_acl_sha = {name: hashlib.sha256(
            guarded.directory_dacl_sddl(self.old / name).encode()).hexdigest()
            for name in guarded.NAMES}

    def _cleanup(self):
        for target in (self.root, *(base / name for base in (self.old, self.archive)
                                    for name in guarded.NAMES)):
            if target.exists():
                for sid in (USERS_SID, GUESTS_SID):
                    subprocess.run(["icacls.exe", str(target), "/remove:d", "*" + sid],
                                   capture_output=True, text=True, timeout=30)
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

    def test_fence_completes_when_trustee_is_serialized_as_alias(self):
        result = self.invoke()
        self.assertEqual(result["status"], "OLD_PATH_FENCED_NEW_PHASE_ALLOWED")
        self.assertFalse(self.old.exists())
        self.assertEqual({name: hashlib.sha256((self.archive / name).read_bytes()).hexdigest()
                          for name in guarded.NAMES}, self.content)
        # The parent deny stays durable, spelled by Windows as the alias.
        self.assertIn("(D;;LC;;;BU)", guarded.directory_dacl_sddl(self.root))
        # Archived per-file denies were restored away.
        for name in guarded.NAMES:
            self.assertFalse(guarded._file_deny(self.archive / name, self.sid))
        self.assertEqual(result, self.invoke())

    def test_crash_after_first_alias_deny_replays(self):
        actual = guarded._icacls
        calls = {"count": 0}

        def first_deny_then_crash(path, *args):
            actual(path, *args)
            calls["count"] += 1
            if calls["count"] == 1:
                raise RuntimeError("injected post-controller-deny crash")
        with patch.object(guarded, "_icacls", side_effect=first_deny_then_crash):
            with self.assertRaisesRegex(RuntimeError, "injected"):
                self.invoke()
        self.assertIn("(D;;DCLC;;;BU)",
                      guarded.directory_dacl_sddl(self.old / "controller.lock"))
        self.assertTrue(guarded._file_deny(self.old / "controller.lock", self.sid))
        self.assertEqual(self.invoke()["status"], "OLD_PATH_FENCED_NEW_PHASE_ALLOWED")

    def test_preexisting_alias_file_deny_is_preserved_and_rejected(self):
        path = self.old / "checkpoint.sqlite3"
        _icacls(str(path), "/deny", "*" + self.sid + ":(X)")
        prior = guarded.directory_dacl_sddl(path)
        self.assertIn(";;;BU)", prior)
        self.file_acl_sha[path.name] = hashlib.sha256(prior.encode()).hexdigest()
        with self.assertRaisesRegex(Exception, "existing owner deny"):
            self.invoke()
        self.assertEqual(guarded.directory_dacl_sddl(path), prior)
        self.assertFalse((self.receipts / "barrier.json").exists())
        self.assertTrue(self.old.exists())

    def test_preexisting_alias_parent_deny_is_preserved_and_rejected(self):
        _icacls(str(self.root), "/deny", "*" + self.sid + ":(X)")
        prior = guarded.directory_dacl_sddl(self.root)
        self.assertIn(";;;BU)", prior)
        # Windows re-propagates inheritance to children when the parent ACL
        # changes (adding AI), so re-pin them: only the owner deny may reject.
        self._pin()
        with self.assertRaisesRegex(Exception, "existing owner deny"):
            self.invoke()
        self.assertEqual(guarded.directory_dacl_sddl(self.root), prior)
        self.assertFalse((self.receipts / "barrier.json").exists())

    def test_preexisting_deny_for_a_different_trustee_is_not_an_owner_deny(self):
        path = self.old / "checkpoint.sqlite3"
        _icacls(str(path), "/deny", "*" + GUESTS_SID + ":(X)")
        prior = guarded.directory_dacl_sddl(path)
        self.assertIn(";;;BG)", prior)
        self.file_acl_sha[path.name] = hashlib.sha256(prior.encode()).hexdigest()
        self.assertEqual(self.invoke()["status"], "OLD_PATH_FENCED_NEW_PHASE_ALLOWED")
        # The unrelated deny is preserved byte-for-byte in the archive.
        self.assertTrue(guarded._same_effective_dacl(
            prior, guarded.directory_dacl_sddl(self.archive / path.name)))
        self.assertIn(";;;BG)", guarded.directory_dacl_sddl(self.archive / path.name))


if __name__ == "__main__":
    unittest.main()
