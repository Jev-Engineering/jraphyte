"""The sdist/wheel discovery that CI uses must work for every supported build-backend spelling.

setuptools 68 (the declared floor) writes ``trace-gc-0.4.0.tar.gz`` with root ``trace-gc-0.4.0``;
setuptools 84 writes ``trace_gc-0.4.0.tar.gz``. These tests run the helper on archives of each
spelling, require missing and ambiguous candidates to fail, and run the exact discovery commands
that the workflow contains. The real-backend archive is exercised in ``test_sdist_phase_distribution``.
"""
from __future__ import annotations

import io
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

from tools import sdist_discovery as discovery

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "test.yml"
HELPER = ROOT / "tools" / "sdist_discovery.py"
BUILD_STEP = "Build the sdist and the wheel from it"
PKG_INFO = "Metadata-Version: 2.1\nName: %s\nVersion: 0.4.0\n"


def add_file(archive: tarfile.TarFile, name: str, data: bytes = b"") -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    archive.addfile(info, io.BytesIO(data))


def make_sdist(dist: Path, archive_name: str, root: str, *, project: str = "trace_gc", pkg_info: bool = True,
               extra=()) -> Path:
    path = dist / archive_name
    with tarfile.open(path, "w:gz") as archive:
        if pkg_info:
            add_file(archive, root + "/PKG-INFO", (PKG_INFO % project).encode())
        add_file(archive, root + "/pyproject.toml", b"[project]\n")
        add_file(archive, root + "/tests/test_example.py", b"")
        for name, data in extra:
            add_file(archive, name, data)
    return path


class DiscoveryCase(unittest.TestCase):
    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="sdist-discovery-"))
        self.addCleanup(shutil.rmtree, self.work, ignore_errors=True)
        self.dist = self.work / "dist"
        self.dist.mkdir()
        self.into = self.work / "sdist"

    def cli(self, *arguments):
        return subprocess.run([sys.executable, str(HELPER), *arguments], cwd=ROOT, capture_output=True,
                              timeout=120)


class SpellingTests(DiscoveryCase):
    VARIANTS = (
        ("setuptools 68", "trace-gc-0.4.0.tar.gz", "trace-gc-0.4.0"),
        ("setuptools 84", "trace_gc-0.4.0.tar.gz", "trace_gc-0.4.0"),
        ("mixed", "trace_gc-0.4.0.tar.gz", "trace-gc-0.4.0"),
    )

    def test_the_actual_archive_and_actual_extracted_root_are_found_for_each_spelling(self):
        for label, archive_name, root in self.VARIANTS:
            with self.subTest(label):
                for child in self.dist.iterdir():
                    child.unlink()
                shutil.rmtree(self.into, ignore_errors=True)
                make_sdist(self.dist, archive_name, root)
                found = discovery.extract_sdist(self.dist, self.into, "trace-gc")
                self.assertEqual(found, self.into / root)
                self.assertTrue((found / "PKG-INFO").is_file())
                self.assertTrue((found / "tests" / "test_example.py").is_file())

    def test_the_command_line_prints_only_the_resolved_root(self):
        for label, archive_name, root in self.VARIANTS:
            with self.subTest(label):
                for child in self.dist.iterdir():
                    child.unlink()
                shutil.rmtree(self.into, ignore_errors=True)
                make_sdist(self.dist, archive_name, root)
                done = self.cli("extract", "--project", "trace-gc", "--dist", str(self.dist), "--into", str(self.into))
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertEqual(done.stdout, (str((self.into / root).resolve()) + "\n").encode())
                self.assertNotIn(b"\r", done.stdout)

    def test_a_wheel_is_found_by_its_actual_name(self):
        wheel = self.dist / "trace_gc-0.4.0-py3-none-any.whl"
        wheel.write_bytes(b"PK")
        self.assertEqual(discovery.find_wheel(self.dist, "trace-gc"), wheel)
        done = self.cli("wheel", "--project", "trace-gc", "--dist", str(self.dist))
        self.assertEqual((done.returncode, done.stdout), (0, (str(wheel.resolve()) + "\n").encode()))


class RejectionTests(DiscoveryCase):
    def assert_rejected(self, *fragments):
        with self.assertRaises(discovery.DiscoveryError) as caught:
            discovery.extract_sdist(self.dist, self.into, "trace-gc")
        for fragment in fragments:
            self.assertIn(fragment, str(caught.exception))

    def test_a_missing_archive_fails(self):
        self.assert_rejected("no .tar.gz file")
        done = self.cli("extract", "--project", "trace-gc", "--dist", str(self.dist), "--into", str(self.into))
        self.assertEqual((done.returncode, done.stdout), (1, b""))
        self.assertIn(b"no .tar.gz file", done.stderr)

    def test_a_missing_dist_directory_fails(self):
        shutil.rmtree(self.dist)
        self.assert_rejected("not a directory")

    def test_two_archives_are_ambiguous_whatever_their_spelling(self):
        make_sdist(self.dist, "trace-gc-0.4.0.tar.gz", "trace-gc-0.4.0")
        make_sdist(self.dist, "trace_gc-0.4.0.tar.gz", "trace_gc-0.4.0")
        self.assert_rejected("ambiguous", "trace-gc-0.4.0.tar.gz", "trace_gc-0.4.0.tar.gz")
        self.assertFalse(self.into.exists())
        done = self.cli("extract", "--project", "trace-gc", "--dist", str(self.dist), "--into", str(self.into))
        self.assertEqual((done.returncode, done.stdout), (1, b""))

    def test_an_archive_of_another_project_fails(self):
        make_sdist(self.dist, "other_project-0.4.0.tar.gz", "other_project-0.4.0")
        self.assert_rejected("is not a distribution of trace-gc")

    def test_pkg_info_naming_another_project_fails(self):
        make_sdist(self.dist, "trace_gc-0.4.0.tar.gz", "trace_gc-0.4.0", project="other-project")
        self.assert_rejected("does not name trace-gc")

    def test_an_archive_without_pkg_info_fails(self):
        make_sdist(self.dist, "trace-gc-0.4.0.tar.gz", "trace-gc-0.4.0", pkg_info=False)
        self.assert_rejected("no PKG-INFO")

    def test_several_top_level_directories_fail(self):
        make_sdist(self.dist, "trace-gc-0.4.0.tar.gz", "trace-gc-0.4.0", extra=(("stray/file.txt", b"x"),))
        self.assert_rejected("exactly one top-level directory")

    def test_path_traversal_and_absolute_members_fail_before_any_extraction(self):
        for member in ("trace-gc-0.4.0/../escape.txt", "/absolute.txt", "trace-gc-0.4.0\\..\\escape.txt"):
            with self.subTest(member):
                for child in self.dist.iterdir():
                    child.unlink()
                make_sdist(self.dist, "trace-gc-0.4.0.tar.gz", "trace-gc-0.4.0", extra=((member, b"x"),))
                self.assert_rejected("unsafe member name")
                self.assertFalse(self.into.exists())
                self.assertFalse((self.work / "escape.txt").exists())

    def test_link_members_fail(self):
        with tarfile.open(self.dist / "trace-gc-0.4.0.tar.gz", "w:gz") as archive:
            add_file(archive, "trace-gc-0.4.0/PKG-INFO", (PKG_INFO % "trace_gc").encode())
            link = tarfile.TarInfo("trace-gc-0.4.0/link")
            link.type = tarfile.SYMTYPE
            link.linkname = "/etc/passwd"
            archive.addfile(link)
        self.assert_rejected("neither a file nor a directory")

    def test_a_non_empty_extraction_target_fails(self):
        make_sdist(self.dist, "trace-gc-0.4.0.tar.gz", "trace-gc-0.4.0")
        self.into.mkdir()
        (self.into / "stale").write_text("old")
        self.assert_rejected("not an empty directory")

    def test_wheels_missing_and_ambiguous_fail(self):
        with self.assertRaises(discovery.DiscoveryError):
            discovery.find_wheel(self.dist, "trace-gc")
        (self.dist / "trace_gc-0.4.0-py3-none-any.whl").write_bytes(b"PK")
        (self.dist / "trace_gc-0.4.1-py3-none-any.whl").write_bytes(b"PK")
        with self.assertRaises(discovery.DiscoveryError) as caught:
            discovery.find_wheel(self.dist, "trace-gc")
        self.assertIn("ambiguous", str(caught.exception))
        done = self.cli("wheel", "--project", "trace-gc", "--dist", str(self.dist))
        self.assertEqual((done.returncode, done.stdout), (1, b""))

    def test_a_wheel_of_another_project_fails(self):
        (self.dist / "other_project-0.4.0-py3-none-any.whl").write_bytes(b"PK")
        with self.assertRaises(discovery.DiscoveryError):
            discovery.find_wheel(self.dist, "trace-gc")


def build_step() -> str:
    text = WORKFLOW.read_text(encoding="utf-8")
    start = text.index("      - name: " + BUILD_STEP)
    following = re.search(r"^      - name: ", text[start + 1:], re.MULTILINE)
    return text[start:start + 1 + following.start()] if following else text[start:]


class WorkflowDiscoveryTests(DiscoveryCase):
    COMMAND = re.compile(r'(?P<variable>\w+)="\$\(python (?P<command>tools/sdist_discovery\.py [^)]*)\)"')

    def commands(self):
        found = {match["variable"]: match["command"] for match in self.COMMAND.finditer(build_step())}
        self.assertEqual(sorted(found), ["SDIST", "WHEEL"])
        return found

    def run_workflow_command(self, variable):
        command = self.commands()[variable].replace("$RUNNER_TEMP", self.work.as_posix())
        return subprocess.run([sys.executable, *shlex.split(command)], cwd=ROOT, capture_output=True, timeout=120)

    def test_the_build_step_assumes_no_archive_spelling_and_no_first_match(self):
        step = build_step()
        self.assertNotIn("trace_gc-", step)
        self.assertNotIn("trace-gc-", step)
        self.assertNotIn("glob.glob", step)
        self.assertNotIn("[0]", step)
        self.assertNotIn(".tar.gz", step)
        self.assertIn("set -euo pipefail", step)
        self.assertIn('"$INSTALLED" -m pip install --no-deps "$WHEEL"', step)
        for command in self.commands().values():
            self.assertIn("--project trace-gc", command)
            self.assertIn('--dist "$RUNNER_TEMP/dist"', command)

    def test_the_workflow_discovery_commands_resolve_both_spellings(self):
        wheel = self.dist / "trace_gc-0.4.0-py3-none-any.whl"
        for label, archive_name, root in SpellingTests.VARIANTS:
            with self.subTest(label):
                for child in self.dist.iterdir():
                    child.unlink()
                shutil.rmtree(self.into, ignore_errors=True)
                make_sdist(self.dist, archive_name, root)
                wheel.write_bytes(b"PK")
                sdist = self.run_workflow_command("SDIST")
                self.assertEqual(sdist.returncode, 0, sdist.stderr)
                self.assertEqual(sdist.stdout.decode().strip(), str((self.into / root).resolve()))
                built = self.run_workflow_command("WHEEL")
                self.assertEqual(built.stdout.decode().strip(), str(wheel.resolve()))

    def test_the_workflow_discovery_commands_fail_on_missing_and_ambiguous_artifacts(self):
        for variable in ("SDIST", "WHEEL"):
            with self.subTest("missing " + variable):
                done = self.run_workflow_command(variable)
                self.assertEqual((done.returncode, done.stdout), (1, b""))
        make_sdist(self.dist, "trace-gc-0.4.0.tar.gz", "trace-gc-0.4.0")
        make_sdist(self.dist, "trace_gc-0.4.0.tar.gz", "trace_gc-0.4.0")
        (self.dist / "trace_gc-0.4.0-py3-none-any.whl").write_bytes(b"PK")
        (self.dist / "trace_gc-0.4.1-py3-none-any.whl").write_bytes(b"PK")
        for variable in ("SDIST", "WHEEL"):
            with self.subTest("ambiguous " + variable):
                done = self.run_workflow_command(variable)
                self.assertEqual((done.returncode, done.stdout), (1, b""))
                self.assertIn(b"ambiguous", done.stderr)
        self.assertFalse(self.into.exists())


if __name__ == "__main__":
    unittest.main()
