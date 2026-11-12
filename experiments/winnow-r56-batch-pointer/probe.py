#!/usr/bin/env python3
"""R56 public synthetic generation-pointer crash experiment, not Winnow source."""
import errno
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys

def sync_dir(p):
    fd = os.open(p, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def atomic_json(path, object_value):
    tmp = path.with_name(path.name + ".new")
    payload = (json.dumps(object_value, sort_keys=True) + "\n").encode()
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as f:
            f.write(payload)
            f.flush()
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    sync_dir(path.parent)

def records(kind):
    return [{"id": i, "generation": kind, "phase": "COMPLETE"} for i in range(3)]

def read_current(root):
    ptr = json.loads((root / "current.json").read_text())
    if set(ptr) != {"generation"} or not isinstance(ptr["generation"], str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,48}", ptr["generation"]):
        raise RuntimeError("R56_POINTER_INVALID")
    current = root / "gens" / ptr["generation"] / "records.json"
    content = json.loads(current.read_text())
    if content != records(ptr["generation"]):
        raise RuntimeError("R56_MIXED_OR_PARTIAL_GENERATION")
    return ptr["generation"]

def writer(root, mode):
    gen = root / "gens" / "candidate"
    gen.mkdir(mode=0o700)
    payload = records("candidate")
    if mode == "bad-late-record":
        payload[-1] = {"id": 2, "generation": "WRONG", "phase": "COMPLETE"}
    atomic_json(gen / "records.json", payload)
    sync_dir(root / "gens")
    if mode == "before-pointer":
        os._exit(71)
    if mode == "bad-late-record":
        try:
            read_in = json.loads((gen / "records.json").read_text())
            if read_in != records("candidate"):
                os._exit(73)
        except (OSError, ValueError):
            os._exit(73)
        os._exit(99)
    if mode != "after-pointer":
        os._exit(98)
    if json.loads((gen / "records.json").read_text()) != records("candidate"):
        os._exit(97)
    atomic_json(root / "current.json", {"generation": "candidate"})
    os._exit(72)

def trial(base, mode, repetition):
    root = base / ("trial-" + str(repetition) + "-" + mode)
    gens = root / "gens"
    gens.mkdir(parents=True, mode=0o700)
    old = gens / "base"
    old.mkdir(mode=0o700)
    atomic_json(old / "records.json", records("base"))
    sync_dir(gens)
    atomic_json(root / "current.json", {"generation": "base"})
    if read_current(root) != "base":
        raise RuntimeError("R56_INITIAL_OLD_STATE_FAILED")
    p = subprocess.run([sys.executable, "-B", __file__, "writer", str(root), mode],
                       timeout=4, stdin=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       check=False)
    expected = {"before-pointer": (71, "base"), "after-pointer": (72, "candidate"),
                "bad-late-record": (73, "base")}
    wanted_exit, wanted_gen = expected[mode]
    if p.returncode != wanted_exit:
        raise RuntimeError("R56_WRITER_CRASH_EXIT_WRONG:%s:%s" % (mode, p.returncode))
    current = read_current(root)
    if current != wanted_gen or not (gens / "candidate" / "records.json").exists():
        raise RuntimeError("R56_POINTER_ATOMICITY_FAILED:%s:%s" % (mode, current))
    if mode == "bad-late-record" and json.loads((gens / "candidate" / "records.json").read_text()) == records("candidate"):
        raise RuntimeError("R56_INVALID_LATE_RECORD_NOT_TESTED")
    for path in sorted(root.rglob("*"), key=lambda p: len(p.parts), reverse=True):
        if path.is_symlink():
            raise RuntimeError("R56_SYMLINK_UNEXPECTED")
        if path.is_file():
            path.unlink()
        elif path.is_dir():
            path.rmdir()
    root.rmdir()
    if root.exists():
        raise RuntimeError("R56_CLEANUP_FAILED")
    return {"mode": mode, "repetition": repetition, "crash_exit": p.returncode,
            "visible_generation": current, "complete_view": True, "cleaned": True}

def main():
    if len(sys.argv) == 4 and sys.argv[1] == "writer":
        writer(Path(sys.argv[2]), sys.argv[3])
        return
    if len(sys.argv) != 3:
        raise RuntimeError("R56_ARGUMENTS_INVALID")
    host_ns, base_name = sys.argv[1:]
    if os.readlink("/proc/self/ns/net") == host_ns:
        raise RuntimeError("R56_NET_NAMESPACE_UNSEPARATED")
    if (os.geteuid(), os.getegid()) != (65534, 65534):
        raise RuntimeError("R56_NONROOT_MISSING")
    cap = [x.split()[1] for x in Path("/proc/self/status").read_text().splitlines() if x.startswith("CapEff:")]
    if len(cap) != 1 or int(cap[0], 16) != 0:
        raise RuntimeError("R56_CAPS_NOT_ZERO")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(.25)
        e = sock.connect_ex(("192.0.2.1", 443))
    if e not in {errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EPERM, errno.EACCES}:
        raise RuntimeError("R56_NETWORK_DENIAL_MISSING")
    base = Path(base_name).resolve()
    observed = [trial(base, mode, rep) for rep in range(3)
                for mode in ("before-pointer", "after-pointer", "bad-late-record")]
    if len(observed) != 9 or list(base.iterdir()):
        raise RuntimeError("R56_REPS_OR_CLEANUP_INCOMPLETE")
    result = {"scope": "PUBLIC_SYNTHETIC_SINGLE_POINTER_ATOMICITY_ONLY",
              "arch": os.uname().machine, "repetitions": 3, "observed": observed,
              "power_failure_durability_proven": False,
              "multiple_writer_safety_proven": False,
              "concurrent_reader_gc_proven": False,
              "production_winnow_recovery_implemented": False,
              "private_code_present": False, "real_media_requests": 0,
              "release_admitted": False}
    print(json.dumps(result, sort_keys=True), flush=True)
    print("R56_SYNTHETIC_BATCH_POINTER_CRASH_PASS arch=%s reps=3 release=HOLD" % result["arch"], flush=True)

if __name__ == "__main__":
    main()
