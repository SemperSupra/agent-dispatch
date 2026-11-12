#!/usr/bin/env python3
"""R59: deterministic public-only lost-update red-team against naive atomic pointer."""
import errno
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def replace_json(path, obj):
    tmp = path.with_name(path.name + "." + str(os.getpid()) + ".tmp")
    with open(tmp, "x", encoding="utf-8") as f:
        json.dump(obj, f, sort_keys=True)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    fsync_dir(path.parent)

def entry(name):
    return {"generation": name, "records": [{"id": name, "status": "complete"}]}

def current(root):
    name = json.loads((root / "current.json").read_text())["generation"]
    body = json.loads((root / "gens" / name / "records.json").read_text())
    if body != entry(name):
        raise RuntimeError("R59_MIXED_OR_INVALID_GENERATION")
    return name

def writer(root, name):
    if current(root) != "base":
        raise RuntimeError("R59_EXPECTED_SHARED_BASE")
    dest = root / "gens" / name
    dest.mkdir(mode=0o700)
    replace_json(dest / "records.json", entry(name))
    (root / ("ready-" + name)).write_text("base")
    deadline = time.monotonic() + 4
    while not (root / ("allow-" + name)).exists():
        if time.monotonic() > deadline:
            raise RuntimeError("R59_WRITER_BARRIER_TIMEOUT")
        time.sleep(.01)
    # Both writers believe they are committing a successor of BASE, but there
    # is no compare-and-swap/lock; last pointer wins and drops the prior writer.
    replace_json(root / "current.json", {"generation": name})
    (root / ("done-" + name)).write_text("ok")

def wait_for(path, children):
    deadline = time.monotonic() + 4
    while time.monotonic() < deadline:
        if path.is_file():
            return
        if any(p.poll() not in (None, 0) for p in children):
            raise RuntimeError("R59_WRITER_EARLY_FAILURE")
        time.sleep(.012)
    raise RuntimeError("R59_WRITER_BARRIER_TIMEOUT:" + path.name)

def trial(work, rep):
    root = work / ("trial-" + str(rep))
    gens = root / "gens"
    gens.mkdir(parents=True, mode=0o700)
    base = gens / "base"
    base.mkdir(mode=0o700)
    replace_json(base / "records.json", entry("base"))
    replace_json(root / "current.json", {"generation": "base"})
    a = subprocess.Popen([sys.executable, "-B", __file__, "writer", str(root), "a"],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, close_fds=True)
    b = subprocess.Popen([sys.executable, "-B", __file__, "writer", str(root), "b"],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, close_fds=True)
    try:
        wait_for(root / "ready-a", [a, b])
        wait_for(root / "ready-b", [a, b])
        if (root / "ready-a").read_text() != "base" or (root / "ready-b").read_text() != "base":
            raise RuntimeError("R59_WITNESS_NOT_OVERLAPPING")
        (root / "allow-a").touch()
        wait_for(root / "done-a", [a, b])
        if current(root) != "a":
            raise RuntimeError("R59_FIRST_POINTER_COMMIT_MISSING")
        (root / "allow-b").touch()
        wait_for(root / "done-b", [a, b])
        if a.wait(timeout=2) != 0 or b.wait(timeout=2) != 0:
            raise RuntimeError("R59_WRITER_FAILED")
        if current(root) != "b" or not (gens / "a" / "records.json").is_file():
            raise RuntimeError("R59_LOST_UPDATE_NEGATIVE_NOT_PROVEN")
        result = {"rep": rep, "both_read_base": True, "both_writers_success": True,
                  "first_pointer_a_then_overwritten_by_b": True,
                  "complete_visible_generation": "b", "unreferenced_a_remains": True}
    finally:
        for p in (a, b):
            if p.poll() is None:
                p.kill()
            p.wait(timeout=2)
        for path in sorted(root.rglob("*"), key=lambda p: len(p.parts), reverse=True):
            if path.is_symlink():
                raise RuntimeError("R59_UNEXPECTED_SYMLINK")
            if path.is_file():
                path.unlink()
            else:
                path.rmdir()
        root.rmdir()
    if root.exists():
        raise RuntimeError("R59_CLEANUP_FAILED")
    return result

def main():
    if len(sys.argv) == 4 and sys.argv[1] == "writer":
        writer(Path(sys.argv[2]), sys.argv[3])
        return
    if len(sys.argv) != 3:
        raise RuntimeError("R59_ARGS_INVALID")
    host_ns, path = sys.argv[1:]
    if os.readlink("/proc/self/ns/net") == host_ns:
        raise RuntimeError("R59_NETNS_NOT_SEPARATE")
    if (os.geteuid(), os.getegid()) != (65534, 65534):
        raise RuntimeError("R59_NONROOT_MISSING")
    caps = [x.split()[1] for x in Path("/proc/self/status").read_text().splitlines() if x.startswith("CapEff:")]
    if len(caps) != 1 or int(caps[0], 16) != 0:
        raise RuntimeError("R59_CAPS_NOT_ZERO")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(.2)
        e = sock.connect_ex(("192.0.2.1", 443))
    if e not in (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EPERM, errno.EACCES):
        raise RuntimeError("R59_NETWORK_ROUTE_UNEXPECTED")
    work = Path(path).resolve()
    observed = [trial(work, i) for i in range(3)]
    if len(observed) != 3 or list(work.iterdir()):
        raise RuntimeError("R59_REPETITION_OR_CLEANUP_FAILED")
    report = {"scope": "PUBLIC_SYNTHETIC_MULTIWRITER_LOST_UPDATE_NEGATIVE_ONLY",
              "arch": os.uname().machine, "reps": 3, "cases": observed,
              "single_pointer_atomicity_preserved": True,
              "multiwriter_transactionality_proven": False,
              "locking_and_compare_and_swap_required_for_promotion": True,
              "power_loss_durability_proven": False,
              "private_winnow_code_used": False, "real_media_requests": 0, "release": "HOLD"}
    print(json.dumps(report, sort_keys=True), flush=True)
    print("R59_TWO_WRITER_LOST_UPDATE_WITNESS_PASS arch=%s reps=3 product=NOT_QUALIFIED" % report["arch"], flush=True)

if __name__ == "__main__":
    main()
