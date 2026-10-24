"""External launcher for ``trace_gc.verifier_closure`` (#97): standard library only, loads only bytes it has hashed.

The parent module cannot authenticate itself.  A reviewer therefore pins this small file's SHA-256 out of band and starts
the parent through it::

    python -I -S -B -X utf8 verifier_closure_launcher.py --package-dir DIR \\
        --sha256 __init__.py=HEX --sha256 errors.py=HEX --sha256 canonical.py=HEX \\
        --sha256 verifier_closure.py=HEX --sha256 verifier_closure_bootstrap.py=HEX \\
        --sha256 verifier_closure_launcher.py=HEX -- run MANIFEST ...

Each of the six implementation files is read once and compared with the supplied digest.  Four of them are executed from
exactly those bytes (the package is registered in ``sys.modules`` before anything is imported, so ``from .canonical
import ...`` never reaches the file system again).  The bytes of all six are then handed to the parent module as
``_PVC_LAUNCHER_CAPTURE``: the release record, the child's bootstrap and the receipt's implementation rows are built from
that capture, so the files that were authenticated are the files that are bound and executed, with no later disk
re-read.  The launcher's own digest is checked against the bytes read from ``--package-dir`` and that file must be the
file running here.

A replace-and-restore of a file between the single read above and the moment the reviewer pinned its digest is an
operating-system trust boundary this launcher cannot close.  The interpreter, this launcher and the digests themselves
must come from a trusted channel.
"""
import hashlib
import json
import os
import stat
import sys
import types

LOAD = ("__init__.py", "errors.py", "canonical.py", "verifier_closure.py")
ALL = ("__init__.py", "canonical.py", "errors.py", "verifier_closure.py", "verifier_closure_bootstrap.py",
       "verifier_closure_launcher.py")
MAX_BYTES = 4 << 20


def _reject(reason):
    print(json.dumps({"status": "REJECTED", "reason": reason}))
    return 2


def _read(directory, name):
    path = os.path.join(directory, name)
    st = os.lstat(path)
    if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_BYTES:
        raise ValueError("launcher_file_irregular:" + name)
    with open(path, "rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES or not data:
        raise ValueError("launcher_file_irregular:" + name)
    return path, data


def _parse(argv):
    if "--" not in argv:
        raise ValueError("launcher_arguments:missing_separator")
    split = argv.index("--")
    head, rest = argv[:split], argv[split + 1:]
    directory, digests, index = None, {}, 0
    while index < len(head):
        flag = head[index]
        if flag not in ("--package-dir", "--sha256") or index + 1 >= len(head):
            raise ValueError("launcher_arguments:" + flag[:40])
        value = head[index + 1]
        index += 2
        if flag == "--package-dir":
            if directory is not None or not os.path.isabs(value):
                raise ValueError("launcher_arguments:package_dir")
            directory = value
        else:
            name, sep, hexdigest = value.partition("=")
            ok = len(hexdigest) == 64 and all(c in "0123456789abcdef" for c in hexdigest)
            if not sep or name not in ALL or name in digests or not ok:
                raise ValueError("launcher_arguments:sha256")
            digests[name] = hexdigest
    if directory is None or set(digests) != set(ALL):
        raise ValueError("launcher_arguments:incomplete")
    return directory, digests, rest


def main(argv):
    if not (sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode):
        return _reject("launcher_requires_isolated_mode")
    try:
        directory, digests, rest = _parse(list(argv))
        verified = {}
        for name in ALL:
            path, data = _read(directory, name)
            if hashlib.sha256(data).hexdigest() != digests[name]:
                return _reject("launcher_hash_mismatch:" + name)
            verified[name] = (path, data)
        if not os.path.samefile(verified["verifier_closure_launcher.py"][0], __file__):
            return _reject("launcher_not_the_pinned_file")
    except (OSError, ValueError) as exc:
        return _reject(str(exc)[:80] if isinstance(exc, ValueError) else "launcher_unreadable")
    capture = {"trace_gc/" + name: verified[name][1] for name in ALL}
    package = types.ModuleType("trace_gc")
    package.__path__ = []
    package.__file__ = verified["__init__.py"][0]
    package.__package__ = "trace_gc"
    sys.modules["trace_gc"] = package
    exec(compile(verified["__init__.py"][1], package.__file__, "exec"), package.__dict__)
    for name in LOAD[1:]:
        stem = name[:-3]
        module = types.ModuleType("trace_gc." + stem)
        module.__package__ = "trace_gc"
        module.__file__ = verified[name][0]
        if stem == "verifier_closure":
            module.__dict__["_PVC_LAUNCHER_CAPTURE"] = capture
        sys.modules[module.__name__] = module
        setattr(package, stem, module)
        exec(compile(verified[name][1], module.__file__, "exec"), module.__dict__)
    return sys.modules["trace_gc.verifier_closure"].main(rest)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
