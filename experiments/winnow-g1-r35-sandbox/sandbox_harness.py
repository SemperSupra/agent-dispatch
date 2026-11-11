#!/usr/bin/env python3
"""Public-only R35 bounded synthetic extractor process qualification.

Runs inside an *already separated, route-less Linux network namespace* as
uid 65534, no effective capabilities. The parent uses kernel RLIMIT quotas
and a new child session/process group. No real Instagram, credentials,
private repositories, media or production integration.
"""
import errno
import json
import os
from pathlib import Path
import resource
import selectors
import signal
import socket
import subprocess
import sys
import time

LIMIT_STDOUT_STDERR = 8 << 10
LIMIT_FILE_BYTES = 64 << 10
LIMIT_ADDRESS_SPACE = 192 << 20
LIMIT_WALL_SECONDS = 4.0


def rlimits():
    resource.setrlimit(resource.RLIMIT_FSIZE, (LIMIT_FILE_BYTES, LIMIT_FILE_BYTES))
    resource.setrlimit(resource.RLIMIT_AS, (LIMIT_ADDRESS_SPACE, LIMIT_ADDRESS_SPACE))
    resource.setrlimit(resource.RLIMIT_CPU, (2, 3))
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
    os.umask(0o077)


def not_running(pid):
    proc = Path("/proc") / str(pid) / "stat"
    try:
        # Zombie is no longer running/executing but may await init reaping.
        fields = proc.read_text().split()
        return len(fields) >= 3 and fields[2] in ("Z", "X")
    except FileNotFoundError:
        return True


def kill_group(p):
    try:
        os.killpg(p.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def run_one(shim, base, mode, deadline):
    stage = base / ("stage-" + mode)
    stage.mkdir(mode=0o700)
    p = subprocess.Popen(
        [sys.executable, str(shim), mode, str(stage)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
        start_new_session=True,
        preexec_fn=rlimits,
    )
    reason = "EXITED"
    total = 0
    text = bytearray()
    sel = selectors.DefaultSelector()
    sel.register(p.stdout, selectors.EVENT_READ)
    sel.register(p.stderr, selectors.EVENT_READ)
    expires = time.monotonic() + deadline
    try:
        while sel.get_map():
            if time.monotonic() >= expires:
                reason = "WALL_DEADLINE"
                kill_group(p)
                break
            ready = sel.select(timeout=min(0.1, max(0, expires-time.monotonic())))
            for key, _ in ready:
                chunk = os.read(key.fd, 4096)
                if not chunk:
                    sel.unregister(key.fileobj)
                    continue
                total += len(chunk)
                if len(text) < LIMIT_STDOUT_STDERR:
                    text.extend(chunk[:LIMIT_STDOUT_STDERR-len(text)])
                if total > LIMIT_STDOUT_STDERR:
                    reason = "OUTPUT_BUDGET"
                    kill_group(p)
                    break
            if reason == "OUTPUT_BUDGET":
                break
        if reason == "EXITED":
            remaining = expires - time.monotonic()
            if remaining <= 0:
                reason = "WALL_DEADLINE"
                kill_group(p)
            else:
                try:
                    p.wait(timeout=remaining)
                except subprocess.TimeoutExpired:
                    reason = "WALL_DEADLINE"
                    kill_group(p)
    finally:
        sel.close()
        if reason != "EXITED":
            kill_group(p)
        p.wait(timeout=3)
        p.stdout.close()
        p.stderr.close()

    files = sorted(stage.iterdir())
    max_size = max((f.stat().st_size for f in files if f.is_file()), default=0)
    outcome = {
        "mode": mode,
        "reason": reason,
        "exit_nonzero": p.returncode != 0,
        "observed_output_bytes": total,
        "max_staged_file_bytes": max_size,
        "file_limit_bytes": LIMIT_FILE_BYTES,
        "output_limit_bytes": LIMIT_STDOUT_STDERR,
        "stage_entry_count": len(files),
    }
    if mode == "normal":
        if reason != "EXITED" or p.returncode != 0 or len(files) != 1 or files[0].name != "fixture.bin":
            raise RuntimeError("R35_NORMAL_FIXTURE_FAILED")
        if b"SYNTHETIC_FIXTURE_OK" not in text:
            raise RuntimeError("R35_NORMAL_RECEIPT_MISSING")
    elif mode == "net":
        if reason != "EXITED" or p.returncode != 0 or b"NETWORK_NAMESPACE_DENIED" not in text or files:
            raise RuntimeError("R35_KERNEL_NET_DENIAL_NOT_OBSERVED")
    elif mode == "stdout":
        if reason != "OUTPUT_BUDGET" or total > LIMIT_STDOUT_STDERR + 4096 or files:
            raise RuntimeError("R35_STDOUT_CAP_UNQUALIFIED")
    elif mode == "disk":
        if reason != "EXITED" or p.returncode == 0 or b"FILE_SIZE_LIMIT_DENIED" not in text or max_size > LIMIT_FILE_BYTES:
            raise RuntimeError("R35_FILE_RLIMIT_UNQUALIFIED")
    elif mode == "memory":
        if reason != "EXITED" or p.returncode == 0 or b"ADDRESS_SPACE_LIMIT_DENIED" not in text or files:
            raise RuntimeError("R35_MEMORY_RLIMIT_UNQUALIFIED")
    elif mode == "cpu":
        if reason != "EXITED" or p.returncode == 0 or files:
            raise RuntimeError("R35_CPU_RLIMIT_UNQUALIFIED")
    elif mode == "descendant":
        pid_file = stage / "child.pid"
        if reason != "WALL_DEADLINE" or not pid_file.is_file():
            raise RuntimeError("R35_DESCENDANT_TIMEOUT_NOT_OBSERVED")
        child_pid = int(pid_file.read_text().strip())
        for _ in range(20):
            if not_running(child_pid):
                break
            time.sleep(0.05)
        if not not_running(child_pid):
            raise RuntimeError("R35_DESCENDANT_STILL_RUNNING")
        outcome["descendant_not_running"] = True
    else:
        raise RuntimeError("R35_UNKNOWN_MODE")

    # Clean stage in each trial; no unbounded objects persist between reps.
    for file in files:
        if not file.is_file() or file.is_symlink():
            raise RuntimeError("R35_UNEXPECTED_STAGE_ENTRY")
        file.unlink()
    stage.rmdir()
    if stage.exists():
        raise RuntimeError("R35_STAGE_CLEANUP_FAILED")
    outcome["cleanup_pass"] = True
    return outcome


def main():
    if len(sys.argv) != 4:
        raise RuntimeError("R35_ARGS_INVALID")
    host_ns, shim_s, base_s = sys.argv[1:]
    actual_ns = os.readlink("/proc/self/ns/net")
    if actual_ns == host_ns or not actual_ns.startswith("net:["):
        raise RuntimeError("R35_NETWORK_NAMESPACE_NOT_SEPARATE")
    if os.geteuid() != 65534 or os.getegid() != 65534:
        raise RuntimeError("R35_OS_IDENTITY_NOT_UNPRIVILEGED")
    cap = [s.split()[1] for s in Path("/proc/self/status").read_text().splitlines() if s.startswith("CapEff:")]
    if len(cap) != 1 or int(cap[0], 16) != 0:
        raise RuntimeError("R35_OS_CAPABILITIES_NOT_ZERO")
    # Do not rely on Python socket monkeypatching. Kernel must reject outbound.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(.5)
        error = sock.connect_ex(("192.0.2.1", 443))
    if error not in (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EPERM, errno.EACCES):
        raise RuntimeError("R35_HOST_NETWORK_ROUTE_UNEXPECTED:" + str(error))

    shim = Path(shim_s)
    base = Path(base_s)
    if not shim.is_file() or not base.is_dir():
        raise RuntimeError("R35_SYNTHETIC_FIXTURE_MISSING")
    modes = ["normal", "net", "stdout", "disk", "memory", "cpu", "descendant"]
    results = [run_one(shim, base, mode, 1.25 if mode == "descendant" else LIMIT_WALL_SECONDS) for mode in modes]
    if [r["mode"] for r in results] != modes or len(list(base.iterdir())) != 1:
        # base retains only the shim.py, never stage files.
        raise RuntimeError("R35_POST_BATCH_HYGIENE_FAILED")
    report = {
        "schema_version": 1,
        "scope": "PUBLIC_SYNTHETIC_EXTRACTOR_OS_SANDBOX_ONLY",
        "arch": os.uname().machine,
        "source_rights_qualified": False,
        "instagram_requests": 0,
        "real_downloader_instantiated": False,
        "private_winnow_code_used": False,
        "network_namespace_separate": True,
        "kernel_network_denial_observed": True,
        "nonroot_zero_caps": True,
        "resource_limits": {
            "file_bytes": LIMIT_FILE_BYTES,
            "address_space_bytes": LIMIT_ADDRESS_SPACE,
            "cpu_seconds_soft": 2,
            "cpu_seconds_hard": 3,
            "file_descriptors": 32,
            "stdout_stderr_bytes": LIMIT_STDOUT_STDERR,
        },
        "cases": results,
    }
    print(json.dumps(report, sort_keys=True), flush=True)
    print("R35_FAKE_EXTRACTOR_OS_SANDBOX_PASS arch=%s cases=7 private_source=NONE instagram=NOT_RUN" % report["arch"], flush=True)


if __name__ == "__main__":
    main()
