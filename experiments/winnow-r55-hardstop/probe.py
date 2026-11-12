#!/usr/bin/env python3
"""R55 public-only Linux kernel containment experiment. No private source/media."""
import errno
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time

QUOTA = 256 * 1024
DENIALS = {errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EPERM, errno.EACCES}

def proc_stopped(pid):
    try:
        s = (Path("/proc") / str(pid) / "stat").read_text().split()
        return len(s) > 2 and s[2] in {"Z", "X"}
    except FileNotFoundError:
        return True

def child(mode, stage):
    if mode == "normal":
        (stage / "payload.bin").write_bytes(b"synthetic-only\n" * 100)
        return
    if mode == "aggregate-quota":
        (stage / "first.bin").write_bytes(b"x" * (160 * 1024))
        fd = os.open(stage / "second.bin", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            for _ in range(40):
                os.write(fd, b"y" * 4096)
        except OSError as exc:
            if exc.errno == errno.ENOSPC:
                return 28
            raise
        finally:
            os.close(fd)
        raise RuntimeError("R55_QUOTA_NOT_HARD_DENIED")
    if mode == "noncooperative":
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        desc = subprocess.Popen(["/bin/sleep", "30"], close_fds=True)
        (stage / "descendant.pid").write_text(str(desc.pid))
        (stage / "synthetic.tmp").write_bytes(b"not-an-approved-output")
        while True:
            time.sleep(.1)
    raise RuntimeError("R55_UNKNOWN_CASE")

def killpg(p, sig):
    try:
        os.killpg(p.pid, sig)
    except ProcessLookupError:
        pass

def verify(mnt, net, stage):
    if os.readlink("/proc/self/ns/mnt") == mnt:
        raise RuntimeError("R55_MNT_NAMESPACE_UNSEPARATED")
    if os.readlink("/proc/self/ns/net") == net:
        raise RuntimeError("R55_NET_NAMESPACE_UNSEPARATED")
    if (os.geteuid(), os.getegid()) != (65534, 65534):
        raise RuntimeError("R55_PRIVILEGE_DROP_MISSING")
    caps = [l.split()[1] for l in Path("/proc/self/status").read_text().splitlines() if l.startswith("CapEff:")]
    if len(caps) != 1 or int(caps[0], 16):
        raise RuntimeError("R55_CAPS_NOT_ZERO")
    if not os.path.ismount(stage):
        raise RuntimeError("R55_TMPFS_MOUNT_MISSING")
    if os.statvfs(stage).f_blocks * os.statvfs(stage).f_frsize != QUOTA:
        raise RuntimeError("R55_TMPFS_CAPACITY_INVALID")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(.25)
        e = sock.connect_ex(("192.0.2.1", 443))
    if e not in DENIALS:
        raise RuntimeError("R55_NETWORK_NOT_KERNEL_DENIED")
    return e

def attempt(stage, mode):
    p = subprocess.Popen([sys.executable, __file__, "child", mode, str(stage)],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True)
    descended = None
    kill_witness = False
    try:
        if mode == "noncooperative":
            end = time.monotonic() + 3
            pidfile = stage / "descendant.pid"
            while time.monotonic() < end and not pidfile.is_file():
                if p.poll() is not None:
                    raise RuntimeError("R55_NONCOOPERATIVE_EXITED_EARLY")
                time.sleep(.015)
            if not pidfile.is_file():
                raise RuntimeError("R55_DESCENDANT_UNOBSERVED")
            descended = int(pidfile.read_text())
            killpg(p, signal.SIGTERM)
            time.sleep(.15)
            if p.poll() is not None:
                raise RuntimeError("R55_NONCOOPERATIVE_HONORED_TERM")
            killpg(p, signal.SIGKILL)
            kill_witness = True
            try:
                p.wait(timeout=3)
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError("R55_HARDSTOP_FAILED") from exc
            for _ in range(30):
                if proc_stopped(descended):
                    break
                time.sleep(.05)
            if not proc_stopped(descended):
                raise RuntimeError("R55_DESCENDANT_SURVIVED")
        else:
            p.wait(timeout=3)
        sizes = {x.name: x.stat().st_size for x in stage.iterdir() if x.is_file()}
        if sum(sizes.values()) > QUOTA:
            raise RuntimeError("R55_CAPACITY_EXCEEDED")
        if mode == "normal" and (p.returncode != 0 or list(sizes) != ["payload.bin"]):
            raise RuntimeError("R55_NORMAL_FAILED")
        if mode == "aggregate-quota" and (p.returncode != 28 or sizes.get("first.bin") != 160 * 1024 or sizes.get("second.bin", QUOTA) >= 160 * 1024):
            raise RuntimeError("R55_HARD_QUOTA_FAILED")
        if mode == "noncooperative" and (not kill_witness or p.returncode != -signal.SIGKILL or descended is None or "synthetic.tmp" not in sizes):
            raise RuntimeError("R55_HARDSTOP_WITNESS_MISSING")
        return {"case": mode, "exit_code": p.returncode, "stage_bytes": sum(sizes.values()),
                "kernel_quota_denied": mode == "aggregate-quota",
                "noncooperative_process_group_killed": kill_witness,
                "descendant_not_running": bool(descended and proc_stopped(descended))}
    finally:
        killpg(p, signal.SIGKILL)
        try:
            p.wait(timeout=3)
        except subprocess.TimeoutExpired:
            pass
        for x in list(stage.iterdir()):
            if not x.is_file() or x.is_symlink():
                raise RuntimeError("R55_UNSAFE_CLEANUP_ENTRY")
            x.unlink()
        if list(stage.iterdir()):
            raise RuntimeError("R55_STAGE_CLEANUP_INCOMPLETE")

def main():
    if len(sys.argv) == 4 and sys.argv[1] == "child":
        ret = child(sys.argv[2], Path(sys.argv[3]))
        sys.exit(ret or 0)
    if len(sys.argv) != 4:
        raise SystemExit("R55_ARGS_INVALID")
    host_mnt, host_net, root = sys.argv[1:]
    root = Path(root).resolve()
    denial = verify(host_mnt, host_net, root)
    records = [attempt(root, m) for _ in range(3)
               for m in ("normal", "aggregate-quota", "noncooperative")]
    if len(records) != 9 or any(root.iterdir()):
        raise RuntimeError("R55_REPS_OR_FINAL_CLEANUP_INCOMPLETE")
    result = {"scope": "PUBLIC_SYNTHETIC_OS_CAPABILITY_ONLY", "arch": os.uname().machine,
              "repetitions": 3, "cases": records, "network_denial_errno": denial,
              "tmpfs_limit_bytes": QUOTA, "real_extractor_executed": False,
              "private_source_present": False, "winnow_runtime_integrated": False,
              "source_rights_qualified": False, "mvp_release_admitted": False}
    print(json.dumps(result, sort_keys=True), flush=True)
    print("R55_HARDSTOP_TMPFS_SYNTHETIC_PASS arch=%s reps=3 private=NONE release=HOLD" % result["arch"], flush=True)

if __name__ == "__main__":
    main()
