#!/usr/bin/env python3
"""R58 negative proof: POSIX process-group kill does not constrain setsid descendants."""
import errno
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time

def stopped(pid):
    try:
        stat = (Path("/proc") / str(pid) / "stat").read_text().split()
        return len(stat) >= 3 and stat[2] in ("Z", "X")
    except FileNotFoundError:
        return True

def terminate(pid):
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass

def kill_group(pid):
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass

def trial(root, rep):
    stage = root / ("rep-" + str(rep))
    stage.mkdir(mode=0o700)
    spawner = subprocess.Popen([sys.executable, "-B", __file__, "spawner", str(stage)],
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, close_fds=True,
                               start_new_session=True)
    desc = None
    try:
        pidfile = stage / "detached.pid"
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and not pidfile.is_file():
            if spawner.poll() is not None:
                raise RuntimeError("R58_SPAWNER_EXITED_BEFORE_HANDOFF")
            time.sleep(.015)
        if not pidfile.is_file():
            raise RuntimeError("R58_DETACHED_CHILD_NOT_CREATED")
        desc = int(pidfile.read_text())
        if desc <= 1 or stopped(desc):
            raise RuntimeError("R58_DETACHED_CHILD_NOT_ALIVE")
        kill_group(spawner.pid)
        spawner.wait(timeout=3)
        if spawner.returncode != -signal.SIGKILL:
            raise RuntimeError("R58_GROUP_NOT_KILLED")
        time.sleep(.08)
        if stopped(desc):
            raise RuntimeError("R58_NO_SETSID_ESCAPE_OBSERVED")
        terminate(desc)
        for _ in range(40):
            if stopped(desc):
                break
            time.sleep(.025)
        if not stopped(desc):
            raise RuntimeError("R58_EXPLICIT_PID_CLEANUP_FAILED")
        return {"rep": rep, "group_parent_killed": True,
                "detached_descendant_survived_group_kill": True,
                "explicit_pid_cleanup_verified": True}
    finally:
        kill_group(spawner.pid)
        if desc is not None:
            terminate(desc)
        try:
            spawner.wait(timeout=3)
        except subprocess.TimeoutExpired:
            pass
        for p in stage.iterdir():
            if not p.is_file() or p.is_symlink():
                raise RuntimeError("R58_CLEANUP_UNSAFE_PATH")
            p.unlink()
        stage.rmdir()

def run():
    if len(sys.argv) == 3 and sys.argv[1] == "spawner":
        stage = Path(sys.argv[2])
        # This descendant establishes a distinct session and process group,
        # demonstrating why the parent's killpg is not a whole-tree sandbox.
        child = subprocess.Popen(["/bin/sleep", "30"], start_new_session=True,
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, close_fds=True)
        (stage / "detached.pid").write_text(str(child.pid))
        time.sleep(30)
        return
    if len(sys.argv) != 3:
        raise RuntimeError("R58_ARGS_INVALID")
    host_ns, path = sys.argv[1:]
    if os.readlink("/proc/self/ns/net") == host_ns:
        raise RuntimeError("R58_NETNS_UNSEPARATED")
    if (os.geteuid(), os.getegid()) != (65534, 65534):
        raise RuntimeError("R58_NONROOT_NOT_ENFORCED")
    caps = [x.split()[1] for x in Path("/proc/self/status").read_text().splitlines() if x.startswith("CapEff:")]
    if len(caps) != 1 or int(caps[0], 16) != 0:
        raise RuntimeError("R58_CAPS_NOT_ZERO")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(.2)
        e = s.connect_ex(("192.0.2.1", 443))
    if e not in (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EPERM, errno.EACCES):
        raise RuntimeError("R58_NET_DENIAL_MISSING")
    root = Path(path).resolve()
    results = [trial(root, rep) for rep in range(3)]
    if len(results) != 3 or list(root.iterdir()):
        raise RuntimeError("R58_POST_REPS_CLEANUP_FAILED")
    report = {"scope": "PUBLIC_SYNTHETIC_PROCESS_GROUP_ESCAPE_NEGATIVE_ONLY",
              "arch": os.uname().machine, "reps": 3, "cases": results,
              "group_kill_is_sufficient_for_untrusted_process_trees": False,
              "entire_process_tree_confinement_qualified": False,
              "private_winnow_source": False, "real_extractor": False,
              "source_rights": "HOLD", "release": "HOLD"}
    print(json.dumps(report, sort_keys=True), flush=True)
    print("R58_SETSID_PROCESS_GROUP_ESCAPE_WITNESS_PASS arch=%s reps=3 product=NOT_QUALIFIED" % report["arch"], flush=True)

if __name__ == "__main__":
    run()
