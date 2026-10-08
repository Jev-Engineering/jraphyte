"""Platform-independent checks of the guarded fence and the hosted diagnostics.

The real ``fence_closed_old_phase_guarded`` and the real ``trace_fence`` run here
on any OS against an in-memory stand-in for Windows DACL reads and ``icacls``
writes. The stand-in is a test model written from the SDDL shapes seen in the
hosted logs; it is NOT Windows. Passing here proves the strict comparison logic
and the diagnostics' structure and sanitization, and nothing about what NTFS or
``icacls`` actually do. Native behavior is covered only by the Windows-only
fence tests.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
import hashlib
import importlib.util
import inspect
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from src import paper_pilot_phase_cutover_guarded_v2 as guarded
from trace_gc.errors import ContractError

ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "windows_fence_diagnostics_under_simulation", ROOT / "tools" / "windows_fence_diagnostics.py")
diagnostics = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(diagnostics)

SID = "S-1-5-21-111-222-333-1001"
PREFIX = "jraphyte-fence-"
CRASH = "injected post-deny crash"
PARENT_COPIES = "D:AI(D;;LC;;;BU)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)" \
                "(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;FA;;;OW)"


def _tokens(flags: str) -> list[str]:
    return re.findall("..", flags)


def _inherited_ace(ace: str, is_dir: bool) -> str | None:
    kind, flags, *rest = ace[1:-1].split(";")
    tokens = _tokens(flags)
    if kind != "A":
        return None
    if is_dir and "CI" in tokens:
        kept = "".join(t for t in tokens if t in ("OI", "CI"))
    elif not is_dir and "OI" in tokens:
        kept = ""
    else:
        return None
    return "(" + ";".join([kind, kept + "ID"] + rest) + ")"


class SimulatedDacls:
    """In-memory DACLs: lazy inheritance from the parent, icacls /deny and /remove:d."""

    PROTECTED_BASE = ["(A;OICI;FA;;;SY)", "(A;OICI;FA;;;BA)", "(A;OICI;FA;;;OW)"]
    MASKS = {"(WD,AD)": "DCLC", "(AD)": "LC"}

    def __init__(self):
        self.entries: dict[str, dict] = {}
        # A test switch that forces the hosted SHAPE after a deny; it does not assert Windows does this.
        self.deny_adds_explicit_copies = False
        self.hooks = []

    def ensure(self, path) -> dict:
        path = Path(path)
        key = str(path)
        if key not in self.entries:
            if path.name.startswith(PREFIX):
                entry = {"control": "P", "aces": list(self.PROTECTED_BASE)}
            elif path.parent == path:
                entry = {"control": "", "aces": ["(A;OICI;FA;;;SY)", "(A;OICI;FA;;;BA)"]}
            else:
                parent = self.ensure(path.parent)
                inherited = (_inherited_ace(ace, path.is_dir()) for ace in parent["aces"])
                entry = {"control": "", "aces": [ace for ace in inherited if ace]}
            self.entries[key] = entry
        return self.entries[key]

    def read(self, path) -> str:
        entry = self.ensure(path)
        return "D:" + entry["control"] + "".join(entry["aces"])

    def _leading_denies(self, entry) -> int:
        count = 0
        while count < len(entry["aces"]) and entry["aces"][count].startswith("(D;"):
            count += 1
        return count

    def icacls(self, path, *args) -> None:
        entry = self.ensure(path)
        if args[0] == "/deny":
            trustee, rights = args[1].split(":", 1)
            ace = "(D;;" + self.MASKS[rights] + ";;;" + trustee.lstrip("*") + ")"
            if ace not in entry["aces"]:
                entry["aces"].insert(0, ace)
            if "AI" not in entry["control"]:
                entry["control"] += "AI"
            if self.deny_adds_explicit_copies:
                self.add_explicit_copies(path)
        elif args[0] == "/remove:d":
            trustee = args[1].lstrip("*")
            entry["aces"] = [ace for ace in entry["aces"]
                             if not (ace.startswith("(D;") and ace.endswith(";;;" + trustee + ")"))]
        else:
            raise AssertionError("unmodelled icacls operation")
        for hook in list(self.hooks):
            hook(Path(path), args)

    def add_explicit_copies(self, path) -> None:
        entry = self.ensure(path)
        copies = []
        for ace in entry["aces"]:
            fields = ace[1:-1].split(";")
            if fields[0] == "A" and "ID" in _tokens(fields[1]):
                fields[1] = "".join(t for t in _tokens(fields[1]) if t != "ID")
                copy = "(" + ";".join(fields) + ")"
                if copy not in entry["aces"]:
                    copies.append(copy)
        position = self._leading_denies(entry)
        entry["aces"][position:position] = copies

    def broaden(self, path) -> None:
        entry = self.ensure(path)
        entry["aces"].insert(self._leading_denies(entry), "(A;;FR;;;WD)")

    def materialize_tree(self, path) -> None:
        self.ensure(path)
        for child in Path(path).rglob("*"):
            self.ensure(child)

    def moved(self, source, destination) -> None:
        old, new = str(source), str(destination)
        for key in [k for k in self.entries if k == old or k.startswith(old + os.sep)]:
            self.entries[new + key[len(old):]] = self.entries.pop(key)


class _NtOs:
    """The os module with ``name == 'nt'`` and a rename that carries the simulated DACLs along."""

    name = "nt"

    def __init__(self, model: SimulatedDacls):
        self._model = model
        self.renames = []
        self.at_rename = None

    def rename(self, source, destination):
        self.renames.append((source, destination))
        if self.at_rename is not None:
            self.at_rename()
        self._model.materialize_tree(source)
        os.rename(source, destination)
        self._model.moved(source, destination)

    def __getattr__(self, attribute):
        return getattr(os, attribute)


@contextmanager
def simulated_windows(model: SimulatedDacls):
    with ExitStack() as stack:
        proxy = _NtOs(model)
        stack.enter_context(patch.object(guarded, "os", proxy))
        stack.enter_context(patch.object(guarded, "directory_dacl_sddl", model.read))
        stack.enter_context(patch.object(guarded, "_icacls", model.icacls))
        stack.enter_context(patch.object(guarded, "_stage_lock", lambda path: path.open("r+b")))
        stack.enter_context(patch.object(guarded, "_current_sid", lambda: SID))
        stack.enter_context(patch.object(guarded, "_canonical_trustee", lambda trustee: trustee))
        yield proxy


class SimulatedModelTests(unittest.TestCase):
    def setUp(self):
        self.model = SimulatedDacls()
        self.temp = tempfile.TemporaryDirectory(prefix=PREFIX)
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)

    def test_fixture_inheritance_matches_the_shapes_seen_in_hosted_logs(self):
        child = self.base / "dir"
        child.mkdir()
        (child / "file").write_bytes(b"0")
        self.assertEqual(self.model.read(self.base),
                         "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)")
        self.assertEqual(self.model.read(child),
                         "D:(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;FA;;;OW)")
        self.assertEqual(self.model.read(child / "file"),
                         "D:(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;OW)")

    def test_deny_is_prepended_with_ai_and_remove_lifts_only_that_trustee(self):
        child = self.base / "file"
        child.write_bytes(b"0")
        before = self.model.read(child)
        self.model.icacls(child, "/deny", "*" + SID + ":(WD,AD)")
        self.assertEqual(self.model.read(child), "D:AI(D;;DCLC;;;" + SID + ")" + before[2:])
        self.model.icacls(child, "/remove:d", "*S-1-1-0")
        self.assertIn(SID, self.model.read(child))
        self.model.icacls(child, "/remove:d", "*" + SID)
        self.assertEqual(self.model.read(child), "D:AI" + before[2:])

    def test_explicit_copy_shape_matches_the_hosted_logs(self):
        directory = self.base / "dir"
        directory.mkdir()
        self.model.read(directory)
        self.model.icacls(directory, "/deny", "*BU:(AD)")
        self.model.add_explicit_copies(directory)
        self.assertEqual(self.model.read(directory), PARENT_COPIES)


class SimulatedFenceCase(unittest.TestCase):
    def setUp(self):
        self.model = SimulatedDacls()
        self.proxy = self.enterContext(simulated_windows(self.model))
        self.temp = tempfile.TemporaryDirectory(prefix=PREFIX)
        self.addCleanup(self.temp.cleanup)
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
            body = b"0" if name == "controller.lock" else ("simulated:" + name).encode()
            (self.old / name).write_bytes(body)
            self.content[name] = hashlib.sha256(body).hexdigest()
        for name in ("source-stage.lock", "phase-stage.lock"):
            (self.root / name).write_bytes(b"0")

    def pin(self):
        self.original_parent = self.model.read(self.root)
        self.original_files = {name: self.model.read(self.old / name) for name in guarded.NAMES}
        self.parent_acl_sha = hashlib.sha256(self.original_parent.encode()).hexdigest()
        self.file_acl_sha = {name: hashlib.sha256(value.encode()).hexdigest()
                             for name, value in self.original_files.items()}

    def invoke(self):
        return guarded.fence_closed_old_phase_guarded(
            old_root=self.old, archived_root=self.archive, expected_file_sha256=self.content,
            source_stage_lock=self.root / "source-stage.lock",
            phase_stage_lock=self.root / "phase-stage.lock", deny_sid=SID,
            expected_parent_dacl_sha256=self.parent_acl_sha,
            expected_file_dacl_sha256=self.file_acl_sha,
            barrier_receipt_path=self.receipts / "barrier.json",
            fence_receipt_path=self.receipts / "fence.json")

    def crash_after_first_deny(self, also=None):
        seen = {"count": 0}

        def hook(path, args):
            if args[0] == "/deny":
                seen["count"] += 1
                if seen["count"] == 1:
                    if also is not None:
                        also(path)
                    raise RuntimeError(CRASH)
        self.model.hooks.append(hook)

    def assert_failed_closed(self):
        self.assertEqual(self.proxy.renames, [])
        self.assertTrue(self.old.is_dir())
        self.assertFalse(self.archive.exists())
        self.assertFalse((self.receipts / "fence.json").exists())
        self.assertTrue(guarded._file_deny(self.old / "controller.lock", SID))


class SimulatedGuardTests(SimulatedFenceCase):
    def test_faithful_icacls_completes_and_preserves_every_original_ace(self):
        self.pin()
        at_rename = {}

        def observe():
            at_rename["files"] = {name: guarded._file_deny(self.old / name, SID)
                                  for name in guarded.NAMES}
            at_rename["parent"] = guarded._has_ace(self.model.read(self.root),
                                                   guarded.DENY_PARENT_ACE, SID)
        self.proxy.at_rename = observe
        result = self.invoke()
        self.assertEqual(result["status"], "OLD_PATH_FENCED_NEW_PHASE_ALLOWED")
        self.assertEqual(at_rename, {"files": {name: True for name in guarded.NAMES}, "parent": True})
        deny = "(D;;LC;;;" + SID + ")"
        parent_now = guarded._aces(self.model.read(self.root))
        self.assertIn(deny, parent_now)
        parent_now.remove(deny)
        self.assertEqual(parent_now, guarded._aces(self.original_parent))
        for name in guarded.NAMES:
            self.assertEqual(guarded._aces(self.model.read(self.archive / name)),
                             guarded._aces(self.original_files[name]), name)
            self.assertFalse(guarded._file_deny(self.archive / name, SID))

    def test_declared_explicit_and_inherited_source_is_preserved_exactly(self):
        self.model.add_explicit_copies(self.root)
        for name in guarded.NAMES:
            self.model.add_explicit_copies(self.old / name)
        self.pin()
        self.assertEqual(len([a for a in guarded._aces(self.original_parent) if a.startswith("(A;OICI;")]), 3)
        self.invoke()
        parent_now = guarded._aces(self.model.read(self.root))
        parent_now.remove("(D;;LC;;;" + SID + ")")
        self.assertEqual(parent_now, guarded._aces(self.original_parent))
        for name in guarded.NAMES:
            self.assertEqual(guarded._aces(self.model.read(self.archive / name)),
                             guarded._aces(self.original_files[name]), name)

    def test_unexpected_explicit_copies_on_the_parent_fail_closed_before_the_rename(self):
        self.pin()
        self.model.deny_adds_explicit_copies = True
        with self.assertRaisesRegex(ContractError, "old parent DACL broadened during fence"):
            self.invoke()
        self.assertEqual(self.proxy.renames, [])
        self.assertTrue(self.old.is_dir())
        self.assertFalse(self.archive.exists())
        self.assertFalse((self.receipts / "fence.json").exists())
        self.assertTrue(guarded._file_deny(self.old / "controller.lock", SID))

    def test_unexpected_explicit_copies_on_a_denied_file_fail_closed_on_replay(self):
        self.pin()
        self.model.deny_adds_explicit_copies = True
        self.crash_after_first_deny()
        with self.assertRaisesRegex(RuntimeError, CRASH):
            self.invoke()
        self.model.hooks.clear()
        with self.assertRaisesRegex(ContractError, "unreviewed old file DACL drift"):
            self.invoke()
        self.assert_failed_closed()

    def test_real_parent_broadening_after_the_guard_deny_fails_closed(self):
        self.pin()
        self.model.hooks.append(lambda path, args: self.model.broaden(path)
                                if path == self.root and args[0] == "/deny" else None)
        with self.assertRaisesRegex(ContractError, "old parent DACL broadened during fence"):
            self.invoke()
        self.assert_failed_closed()

    def test_real_file_broadening_is_rejected_on_replay_before_the_rename(self):
        self.pin()
        self.crash_after_first_deny(also=self.model.broaden)
        with self.assertRaisesRegex(RuntimeError, CRASH):
            self.invoke()
        self.model.hooks.clear()
        with self.assertRaisesRegex(ContractError, "unreviewed old file DACL drift"):
            self.invoke()
        self.assert_failed_closed()


class SimulatedTraceTests(SimulatedFenceCase):
    """The real trace_fence, run on its own fixture, against the same simulated layer."""

    LABELS = {"temp_parent", "base", "parent", "state"} | {"file:" + n for n in guarded.NAMES}
    SECRET = r"C:\Users\private-account\secret S-1-5-21-1-2-3-1001"

    def run_trace(self, *, remove_exit=0, factory=tempfile.TemporaryDirectory, timeouts=(), on_cleanup=None):
        """Cleanup-time ``icacls.exe`` calls (numbered from 1) listed in ``timeouts`` time out."""
        real_run = subprocess.run
        calls = {"cleanup": 0}

        def fake_run(args, *rest, **options):
            if args and args[0] == "icacls.exe":
                calls["cleanup"] += 1
                if calls["cleanup"] == 1 and on_cleanup is not None:
                    on_cleanup()
                if calls["cleanup"] in timeouts:
                    raise subprocess.TimeoutExpired(args, 30)
                if remove_exit == 0:
                    self.model.icacls(Path(args[1]), *args[2:])
                return subprocess.CompletedProcess(args, remove_exit, "", "")
            return real_run(args, *rest, **options)
        with patch.object(diagnostics.subprocess, "run", side_effect=fake_run):
            return diagnostics.trace_fence(guarded, temp_factory=factory)

    def deny_parent_and_a_file_then_fail(self):
        def deny_then_fail(**request):
            guarded._icacls(request["old_root"] / "controller.lock", "/deny", "*" + SID + ":(WD,AD)")
            guarded._icacls(request["old_root"].parent, "/deny", "*" + SID + ":(AD)")
            raise PermissionError(self.SECRET)
        return patch.object(guarded, "fence_closed_old_phase_guarded", side_effect=deny_then_fail)

    def test_completed_fence_trace_records_every_phase_with_strict_verdicts(self):
        trace, ok = self.run_trace()
        self.assertTrue(ok, trace)
        self.assertEqual(trace["outcome"], {"status": "OLD_PATH_FENCED_NEW_PHASE_ALLOWED"})
        for phase in ("setup", "at_end", "after_remove_d"):
            self.assertEqual(set(trace[phase]), self.LABELS, phase)
        setup = trace["setup"]
        self.assertTrue(setup["base"]["protected"])
        self.assertEqual((setup["parent"]["control"], setup["parent"]["inherited_allow"],
                          setup["parent"]["explicit_allow"], setup["parent"]["deny"]), ("", 3, 0, 0))
        self.assertEqual(setup["state"]["inherited_allow"], 3)
        self.assertEqual(setup["file:controller.lock"]["explicit_copies_of_inherited"], 0)
        self.assertNotIn("strict", setup["parent"])

        steps = {(step["target"], step["operation"]): step for step in trace["steps"]}
        self.assertEqual(len(trace["steps"]), 11)
        parent_deny = steps[("parent", "deny")]
        self.assertEqual(parent_deny["icacls"], "ok")
        self.assertEqual(set(parent_deny["before"]), self.LABELS)
        self.assertEqual(set(parent_deny["after"]), self.LABELS)
        self.assertEqual(parent_deny["before"]["parent"]["deny"], 0)
        self.assertEqual(parent_deny["before"]["parent"]["strict"],
                         {"admission_only_added": True, "same_as_original": True})
        self.assertEqual(parent_deny["after"]["parent"]["strict"],
                         {"admission_only_added": True, "same_as_original": False})
        self.assertTrue(parent_deny["after"]["parent"]["auto_inherited"])
        self.assertEqual(parent_deny["after"]["parent"]["deny"], 1)
        released = steps[("archived:controller.lock", "remove_deny")]
        self.assertEqual(released["after"]["file:controller.lock"]["strict"],
                         {"admission_only_added": True, "same_as_original": True})
        # Nothing but the guard's own calls runs between the deny steps: each pre-state is the last post-state.
        for earlier, later in zip(trace["steps"][:5], trace["steps"][1:6]):
            self.assertEqual(later["before"], earlier["after"])

        self.assertEqual(trace["at_end"]["parent"]["strict"],
                         {"admission_only_added": True, "same_as_original": False})
        self.assertEqual(trace["after_remove_d"]["parent"]["strict"],
                         {"admission_only_added": True, "same_as_original": True})
        cleanup = trace["cleanup"]
        self.assertEqual({key: cleanup[key] for key in cleanup if key != "steps"},
                         {"paths_checked": 6, "denies_remaining": 0, "verification_errors": 0,
                          "removal_failures": [], "directory_removal": "ok"})
        self.assertEqual([step["target"] for step in cleanup["steps"]],
                         ["parent"] + ["archived:" + n for n in sorted(guarded.NAMES)])
        parent_cleanup = cleanup["steps"][0]
        self.assertEqual((parent_cleanup["before"]["parent"]["deny"], parent_cleanup["after"]["parent"]["deny"],
                          parent_cleanup["icacls_exit"]), (1, 0, 0))
        self.assertEqual(set(parent_cleanup["before"]), self.LABELS)

    def test_explicit_copies_are_reported_as_a_strict_failure_and_still_cleaned_up(self):
        self.model.deny_adds_explicit_copies = True
        trace, ok = self.run_trace()
        self.assertTrue(ok, trace)
        self.assertEqual(trace["outcome"], {"error": {
            "type": "ContractError", "category": "PHASE_FENCE",
            "detail_code": "PARENT_BROADENED_DURING_FENCE"}})
        steps = {(step["target"], step["operation"]): step for step in trace["steps"]}
        self.assertEqual(len(trace["steps"]), 6)
        parent = steps[("parent", "deny")]["after"]["parent"]
        self.assertEqual((parent["ace_count"], parent["protected"], parent["auto_inherited"],
                          parent["explicit_copies_of_inherited"]), (7, False, True, 3))
        self.assertEqual(parent["strict"],
                         {"admission_only_added": False, "same_as_original": False})
        end = trace["at_end"]
        self.assertEqual(end["state"]["explicit_copies_of_inherited"], 0)
        self.assertEqual(end["file:controller.lock"]["explicit_copies_of_inherited"], 3)
        self.assertEqual(end["file:controller.lock"]["strict"]["admission_only_added"], False)
        # Lifting the fixture's own denies does not lift the copies: reported as it is.
        after = trace["after_remove_d"]
        self.assertEqual((after["parent"]["deny"], after["parent"]["explicit_copies_of_inherited"]), (0, 3))
        self.assertEqual(after["parent"]["strict"]["same_as_original"], False)
        self.assertEqual(trace["cleanup"]["denies_remaining"], 0)

    def test_trace_is_sanitized(self):
        for shaped in (False, True):
            self.model.deny_adds_explicit_copies = shaped
            trace, _ = self.run_trace()
            rendered = json.dumps(trace)
            self.assertNotIn(tempfile.gettempdir(), rendered)
            self.assertNotIn("111-222-333", rendered)
            self.assertIn("S-1-5-21-<machine>-1001", rendered)
            self.assertNotIn(PREFIX, rendered)

    def test_unverified_cleanup_is_reported_as_not_ok(self):
        trace, ok = self.run_trace(remove_exit=5)
        self.assertFalse(ok)
        self.assertGreater(trace["cleanup"]["denies_remaining"], 0)
        self.assertEqual({failure["target"] for failure in trace["cleanup"]["removal_failures"]},
                         {step["target"] for step in trace["cleanup"]["steps"]})
        self.assertTrue(all(failure["exit_code"] == 5 for failure in trace["cleanup"]["removal_failures"]))

    def test_a_failure_raised_after_real_denies_is_reported_and_cleaned_up(self):
        with self.deny_parent_and_a_file_then_fail():
            trace, ok = self.run_trace()
        self.assertTrue(ok, trace)
        self.assertEqual(trace["outcome"],
                         {"error": {"type": "PermissionError", "category": "unspecified"}})
        self.assertEqual([(s["target"], s["operation"]) for s in trace["steps"]],
                         [("old:controller.lock", "deny"), ("parent", "deny")])
        self.assertEqual(trace["at_end"]["parent"]["deny"], 1)
        self.assertEqual(trace["after_remove_d"]["parent"]["deny"], 0)
        self.assertEqual(trace["after_remove_d"]["file:controller.lock"]["deny"], 0)
        self.assertNotIn("private-account", json.dumps(trace))

    def test_a_failing_icacls_call_is_recorded_with_its_pre_and_post_state_before_it_propagates(self):
        def failing(path, *args):
            raise ContractError("PHASE_FENCE", "Windows DACL update failed")
        with patch.object(guarded, "_icacls", side_effect=failing):
            trace, ok = self.run_trace()
        self.assertTrue(ok, trace)
        self.assertEqual(trace["outcome"]["error"]["detail_code"], "ICACLS_UPDATE_FAILED")
        step = trace["steps"][0]
        self.assertEqual(step["icacls"], "failed")
        self.assertEqual(step["error"], {"type": "ContractError", "category": "PHASE_FENCE"})
        self.assertEqual(set(step["before"]), self.LABELS)
        self.assertEqual(step["before"], step["after"])

    def test_a_comparator_that_raises_is_reported_without_masking_the_trace(self):
        real = guarded._only_parent_admission_added

        def raises_for_the_diagnostics_only(*args):
            caller = next(frame for frame in inspect.stack()[1:]
                          if not frame.filename.endswith("mock.py"))
            if caller.filename.endswith("windows_fence_diagnostics.py"):
                raise ValueError(r"C:\Users\private-account")
            return real(*args)
        with patch.object(guarded, "_only_parent_admission_added",
                          side_effect=raises_for_the_diagnostics_only):
            trace, ok = self.run_trace()
        self.assertEqual(trace["outcome"], {"status": "OLD_PATH_FENCED_NEW_PHASE_ALLOWED"})
        parent = {(s["target"], s["operation"]): s for s in trace["steps"]}[("parent", "deny")]
        self.assertIsNone(parent["after"]["parent"]["strict"]["admission_only_added"])
        self.assertEqual(parent["after"]["parent"]["strict"]["admission_only_added_error"],
                         {"type": "ValueError", "category": "unspecified"})
        self.assertNotIn("private-account", json.dumps(trace))
        self.assertTrue(ok)

    def test_a_first_target_removal_timeout_does_not_stop_the_later_targets(self):
        with self.deny_parent_and_a_file_then_fail():
            trace, ok = self.run_trace(timeouts={1})
        cleanup = trace["cleanup"]
        self.assertFalse(ok)
        self.assertEqual(cleanup["removal_failures"],
                         [{"target": "parent", "error": {"type": "TimeoutExpired", "category": "unspecified"}}])
        # The first target (the parent) kept its deny and is reported as such ...
        self.assertEqual(cleanup["denies_remaining"], 1)
        self.assertEqual(trace["after_remove_d"]["parent"]["deny"], 1)
        # ... while the later targets each still got their own removal attempt, and it worked.
        self.assertEqual([step["target"] for step in cleanup["steps"]],
                         ["parent"] + ["old:" + n for n in sorted(guarded.NAMES)])
        self.assertEqual(trace["after_remove_d"]["file:controller.lock"]["deny"], 0)
        lifted = {step["target"]: step for step in cleanup["steps"]}["old:controller.lock"]
        self.assertEqual((lifted["icacls_exit"], lifted["before"]["file:controller.lock"]["deny"],
                          lifted["after"]["file:controller.lock"]["deny"]), (0, 1, 0))
        self.assertEqual(cleanup["steps"][0]["icacls"], "failed")
        self.assertEqual(cleanup["steps"][0]["after"]["parent"]["deny"], 1)
        self.assertEqual(cleanup["paths_checked"], 6)

    def test_a_removal_failure_is_not_clean_even_when_verification_finds_no_survivor(self):
        with patch.object(guarded, "fence_closed_old_phase_guarded", side_effect=RuntimeError(self.SECRET)):
            trace, ok = self.run_trace(timeouts={3})
        self.assertFalse(ok)
        self.assertEqual(trace["cleanup"]["denies_remaining"], 0)
        self.assertEqual([failure["target"] for failure in trace["cleanup"]["removal_failures"]],
                         ["old:" + sorted(guarded.NAMES)[1]])
        self.assertNotIn("private-account", json.dumps(trace))

    def test_an_unreadable_survivor_fails_verification_and_the_other_targets_are_still_verified(self):
        unreadable = {"armed": False}
        real_read = self.model.read

        def read(path):
            if unreadable["armed"] and Path(path).name == "old-app":
                raise OSError(self.SECRET)
            return real_read(path)

        def arm():
            unreadable["armed"] = True
        with patch.object(guarded, "directory_dacl_sddl", read):
            with self.deny_parent_and_a_file_then_fail():
                trace, ok = self.run_trace(on_cleanup=arm)
        cleanup = trace["cleanup"]
        self.assertFalse(ok)
        self.assertEqual((cleanup["verification_errors"], cleanup["denies_remaining"],
                          cleanup["paths_checked"]), (1, 1, 6))
        self.assertEqual(cleanup["steps"][0]["after"]["parent"],
                         {"error": {"type": "OSError", "category": "unspecified"}})
        self.assertEqual(trace["after_remove_d"]["parent"], {"error": {"type": "OSError", "category": "unspecified"}})
        self.assertEqual(trace["after_remove_d"]["file:controller.lock"]["deny"], 0)
        self.assertNotIn("private-account", json.dumps(trace))

    def test_a_failed_temp_directory_removal_makes_the_status_not_clean_and_is_reported(self):
        class FailsOnRemoval(tempfile.TemporaryDirectory):
            def __exit__(self, *exc):
                super().__exit__(*exc)
                raise OSError(SimulatedTraceTests.SECRET)
        trace, ok = self.run_trace(factory=FailsOnRemoval)
        self.assertFalse(ok)
        cleanup = trace["cleanup"]
        self.assertEqual(cleanup["denies_remaining"], 0)
        self.assertEqual(cleanup["directory_removal"], "failed")
        self.assertEqual(cleanup["directory_removal_error"], {"type": "OSError", "category": "unspecified"})
        self.assertNotIn("error", trace)
        self.assertEqual(trace["outcome"], {"status": "OLD_PATH_FENCED_NEW_PHASE_ALLOWED"})
        self.assertNotIn("private-account", json.dumps(trace))

    def test_a_failed_setup_is_not_clean(self):
        class FailsToCreate(tempfile.TemporaryDirectory):
            def __enter__(self):
                self.cleanup()
                raise PermissionError(SimulatedTraceTests.SECRET)
        trace, ok = self.run_trace(factory=FailsToCreate)
        self.assertFalse(ok)
        self.assertEqual(trace["error"], {"type": "PermissionError", "category": "unspecified"})
        self.assertIsNone(trace["cleanup"]["denies_remaining"])
        self.assertEqual(trace["cleanup"]["directory_removal"], "not_reached")

    def test_recording_is_bounded_and_the_overflow_is_counted(self):
        with patch.object(diagnostics, "MAX_RECORDED_OPERATIONS", 4):
            trace, ok = self.run_trace()
        recorded = len(trace["steps"]) + len(trace["cleanup"]["steps"])
        self.assertEqual(recorded, 4)
        self.assertEqual(trace["operations_dropped"], 11 + 6 - 4)
        self.assertTrue(ok, trace)


class DescribeDaclTests(unittest.TestCase):
    def test_hosted_shape_is_described_structurally(self):
        shape = diagnostics.describe_dacl(PARENT_COPIES)
        self.assertEqual({key: shape[key] for key in shape if key != "sddl"},
                         {"control": "AI", "protected": False, "auto_inherited": True,
                          "ace_count": 7, "deny": 1, "explicit_allow": 3, "inherited_allow": 3,
                          "explicit_copies_of_inherited": 3})

    def test_protected_and_auto_inherited_control_flags_are_separate(self):
        base = "(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)"
        for header, protected, auto_inherited in (("D:", False, False), ("D:P", True, False),
                                                  ("D:AI", False, True), ("D:PAI", True, True)):
            shape = diagnostics.describe_dacl(header + base)
            self.assertEqual((shape["control"], shape["protected"], shape["auto_inherited"]),
                             (header[2:], protected, auto_inherited), header)
            self.assertEqual(shape["explicit_copies_of_inherited"], 0)

    def test_an_explicit_allow_without_an_inherited_twin_is_not_a_copy(self):
        shape = diagnostics.describe_dacl("D:(A;;FR;;;WD)(A;ID;FA;;;SY)(A;;FA;;;BA)")
        self.assertEqual((shape["explicit_allow"], shape["inherited_allow"],
                          shape["explicit_copies_of_inherited"]), (2, 1, 0))

    def test_machine_and_directory_sub_authorities_are_redacted(self):
        text = diagnostics.describe_dacl(
            "D:(D;;LC;;;S-1-5-21-1-2-3-500)(A;;FA;;;S-1-12-1-11-22-33-44)(A;;FA;;;S-1-5-18)")["sddl"]
        self.assertEqual(text, "D:(D;;LC;;;S-1-5-21-<machine>-500)"
                               "(A;;FA;;;S-1-12-1-<directory>)(A;;FA;;;S-1-5-18)")


if __name__ == "__main__":
    unittest.main()
