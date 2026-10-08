"""Strict discovery of a freshly built sdist, its extracted root and its wheel.

Build backends disagree about the archive spelling: setuptools 68 writes ``trace-gc-0.4.0.tar.gz``
with the root ``trace-gc-0.4.0`` and setuptools 84 writes ``trace_gc-0.4.0.tar.gz``. Nothing here
assumes either spelling. The one archive in the output directory is used, the extracted root is
whatever single top-level directory the archive holds, and zero or several candidates fail.
"""
from __future__ import annotations

import argparse
from pathlib import Path, PurePosixPath
import re
import sys
import tarfile


class DiscoveryError(Exception):
    pass


def _normalized(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _single(directory: Path, suffix: str, project: str | None) -> Path:
    if not directory.is_dir():
        raise DiscoveryError("not a directory: %s" % directory)
    found = sorted(path for path in directory.iterdir() if path.is_file() and path.name.endswith(suffix))
    if not found:
        raise DiscoveryError("no %s file in %s" % (suffix, directory))
    if len(found) > 1:
        raise DiscoveryError("ambiguous: %d %s files in %s: %s"
                             % (len(found), suffix, directory, ", ".join(path.name for path in found)))
    if project is not None:
        distribution = found[0].name[:-len(suffix)].rsplit("-", 1)[0] if suffix == ".tar.gz" \
            else found[0].name.split("-", 1)[0]
        if _normalized(distribution) != _normalized(project):
            raise DiscoveryError("%s is not a distribution of %s" % (found[0].name, project))
    return found[0]


def find_wheel(dist: Path, project: str | None = None) -> Path:
    return _single(dist, ".whl", project)


def find_sdist(dist: Path, project: str | None = None) -> Path:
    return _single(dist, ".tar.gz", project)


def extract_sdist(dist: Path, into: Path, project: str | None = None) -> Path:
    archive = find_sdist(dist, project)
    if into.exists() and (not into.is_dir() or any(into.iterdir())):
        raise DiscoveryError("extraction target is not an empty directory: %s" % into)
    with tarfile.open(archive) as handle:
        members = handle.getmembers()
        roots = set()
        for member in members:
            name = PurePosixPath(member.name)
            if name.is_absolute() or ".." in name.parts or "\\" in member.name or not name.parts:
                raise DiscoveryError("unsafe member name %r in %s" % (member.name, archive.name))
            if not (member.isfile() or member.isdir()):
                raise DiscoveryError("member %r in %s is neither a file nor a directory" % (member.name, archive.name))
            roots.add(name.parts[0])
        if len(roots) != 1:
            raise DiscoveryError("%s must hold exactly one top-level directory, found %s"
                                 % (archive.name, sorted(roots)))
        into.mkdir(parents=True, exist_ok=True)
        if hasattr(tarfile, "data_filter"):
            handle.extractall(into, filter="data")
        else:
            handle.extractall(into)
    root = into / next(iter(roots))
    if not root.is_dir():
        raise DiscoveryError("%s does not extract to a directory" % archive.name)
    info = root / "PKG-INFO"
    if not info.is_file():
        raise DiscoveryError("%s has no PKG-INFO; it is not an sdist" % root.name)
    if project is not None:
        declared = re.search(r"^Name:\s*(\S+)\s*$", info.read_text(encoding="utf-8"), re.MULTILINE)
        if declared is None or _normalized(declared.group(1)) != _normalized(project):
            raise DiscoveryError("PKG-INFO of %s does not name %s" % (root.name, project))
    return root


def _emit(path: Path) -> None:
    sys.stdout.buffer.write((str(path.resolve()) + "\n").encode("utf-8"))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("extract", "wheel"):
        command = commands.add_parser(name)
        command.add_argument("--dist", type=Path, required=True)
        command.add_argument("--project")
        if name == "extract":
            command.add_argument("--into", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = extract_sdist(args.dist, args.into, args.project) if args.command == "extract" \
            else find_wheel(args.dist, args.project)
    except (DiscoveryError, tarfile.TarError, OSError) as error:
        print("sdist discovery failed: %s" % error, file=sys.stderr)
        return 1
    _emit(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
