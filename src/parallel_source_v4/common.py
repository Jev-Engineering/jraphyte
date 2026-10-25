"""Explicit authorized roots and immutable, content-bound research receipts."""
from __future__ import annotations

import hashlib
import ast
import importlib.util
import json
import os
import tempfile
from pathlib import Path, PureWindowsPath
from trace_gc.pdf_source_parallel_v4 import json_bytes

REPO = Path(__file__).resolve().parents[2]


def digest(path: Path) -> str:
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read(path: Path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def read_hashed_json(path: Path):
    """Parse and identify the same byte buffer, never two separate file reads."""
    payload = Path(path).read_bytes()
    return json.loads(payload), hashlib.sha256(payload).hexdigest()


def within(root: Path, path: Path) -> Path:
    root, path = Path(root).resolve(), Path(path).resolve()
    if path != root and root not in path.parents:
        raise ValueError("path_outside_authorized_root")
    return path


def child(root: Path, relative: str) -> Path:
    if (not isinstance(relative,str) or "\\" in relative or PureWindowsPath(relative).drive or
            Path(relative).is_absolute() or ".." in Path(relative).parts):
        raise ValueError("expected_safe_relative_path")
    return within(root, Path(root)/relative)


def data_root(explicit: str | Path | None = None) -> Path:
    root = Path(explicit or os.environ.get("TRACE_GC_TEST_DATA_ROOT") or REPO.parent/"TRACE-GC_RealPaper_Test").expanduser().resolve()
    if root == REPO or REPO in root.parents:
        raise ValueError("private_test_data_must_be_outside_repository")
    return root


def write_once(path: Path, value: object) -> str:
    """Atomically publish an immutable receipt; never expose a partial JSON file."""
    payload = json_bytes(value)+b"\n"
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".receipt-", suffix=".tmp", dir=path.parent)
    temporary=Path(name)
    try:
        with os.fdopen(fd,"wb") as stream:
            stream.write(payload); stream.flush(); os.fsync(stream.fileno())
        try:
            os.link(temporary,path)
        except FileExistsError:
            if path.read_bytes()!=payload:
                raise ValueError("immutable_receipt_conflict") from None
    finally:
        temporary.unlink(missing_ok=True)
    return hashlib.sha256(payload).hexdigest()


def method_hashes(repo: Path = REPO, *, additional_roots: tuple[str, ...] = ()) -> dict:
    """Hash local import closure, including the dynamically loaded frozen replay.

    Resolve imports statically so recording code never imports a worker/model or
    adopts its import-time data root. All v4 modules are seeds, including newly
    added metric modules. Function-local local imports are included as well.
    Callers outside that default family must name their entry modules in
    ``additional_roots`` so their own transitive imports are included. Explicit
    roots must exist locally; unresolved ordinary imports may be dependencies
    supplied by the separately recorded runtime.
    """
    seeds = ["trace_gc.pdf_source_parallel_v4", "trace_gc.pdf_structure_parallel_v4",
             "src.abstract_validation_expanded.extraction"]
    seeds += ["src.parallel_source_v4."+p.stem for p in (repo/"src/parallel_source_v4").glob("*.py")]
    if not isinstance(additional_roots, (tuple, list)):
        raise ValueError("expected_local_module_roots")
    for module in additional_roots:
        if not isinstance(module, str) or not all(part.isidentifier() for part in module.split(".")):
            raise ValueError("expected_local_module_root")
        target = repo.joinpath(*module.split("."))
        if not target.with_suffix(".py").is_file() and not (target/"__init__.py").is_file():
            raise ValueError("missing_local_module_root:"+module)
    seeds += list(additional_roots)
    pending, visited, snapshots = list(seeds), set(), {}
    while pending:
        module = pending.pop()
        if module in visited:
            continue
        visited.add(module)
        target = repo.joinpath(*module.split("."))
        path = target.with_suffix(".py")
        if not path.is_file():
            path = target/"__init__.py"
        if not path.is_file():
            continue  # standard library, external dependency, or namespace
        payload = path.read_bytes()
        snapshots[path.relative_to(repo).as_posix()] = hashlib.sha256(payload).hexdigest()
        parts = module.split(".")
        for i in range(1, len(parts)):
            package = repo.joinpath(*parts[:i])/"__init__.py"
            if package.is_file():
                pending.append(".".join(parts[:i])+".__init__")
        package_name = module if path.name == "__init__.py" else module.rpartition(".")[0]
        if package_name.endswith(".__init__"):
            package_name = package_name.rpartition(".")[0]
        for node in ast.walk(ast.parse(payload.decode("utf-8"))):
            if isinstance(node, ast.Import):
                pending.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                name = node.module or ""
                if node.level:
                    name = importlib.util.resolve_name("."*node.level+name, package_name)
                if name:
                    pending.append(name)
                    pending.extend(name+"."+alias.name for alias in node.names if alias.name != "*")
    for pattern in ("*.lock.json", "requirements*.txt"):
        for path in (repo/"src/parallel_source_v4").glob(pattern):
            snapshots[path.relative_to(repo).as_posix()] = digest(path)
    verify_files(repo, snapshots)
    return dict(sorted(snapshots.items()))


def verify_files(root: Path, hashes: dict) -> None:
    for relative, expected in hashes.items():
        if digest(child(root, relative)) != expected:
            raise ValueError("frozen_file_hash_mismatch:"+relative)


def verify_first_page_bundle(root: Path, row: dict) -> list[dict]:
    """Check that the page, native spans and source-review image depict page zero.

    Render comparison is deliberately strict. A renderer change requires a new
    source-review preparation receipt, not a silently weakened image check.
    """
    import fitz
    from PIL import Image, ImageChops
    from trace_gc.pdf_source_parallel_v4 import source_lines, digest_value
    with fitz.open(child(root,row['source_relative'])) as source, fitz.open(child(root,row['page_relative'])) as page:
        if len(page)!=1 or not len(source):raise ValueError('expected_single_first_page_extract')
        left=source[0].get_pixmap(dpi=120,alpha=False)
        right=page[0].get_pixmap(dpi=120,alpha=False)
        if (left.width,left.height)!=(right.width,right.height):
            raise ValueError('cached_page_does_not_match_first_physical_page')
        if left.samples != right.samples:
            # PyMuPDF insert_pdf can change text antialiasing by up to two
            # channel values while preserving the source page contents.
            source_image = Image.frombytes('RGB',(left.width,left.height),left.samples)
            cached_image = Image.frombytes('RGB',(right.width,right.height),right.samples)
            difference = ImageChops.difference(source_image,cached_image)
            if max(channel[1] for channel in difference.getextrema()) > 2:
                raise ValueError('cached_page_does_not_match_first_physical_page')
        with Image.open(child(root,row['image_relative'])) as image:
            image=image.convert('RGB')
            if image.size!=(left.width,left.height) or image.tobytes()!=left.samples:
                raise ValueError('review_image_not_original_first_page')
        native=source_lines(source[0])
        if digest_value(native)!=digest_value(read(child(root,row['native_relative']))):
            raise ValueError('native_review_spans_not_from_original_first_page')
    return native
