#!/usr/bin/env python3
"""R36: Real pinned package CLI smoke inside a route-less Linux netns.

No URLs or usernames are passed to the tool. No Instagram/media acquisition.
Only pinned version commands, constrained by kernel resource limits, in a
disposable, nonroot isolated process. These are not extractor-function tests.
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

CAP_OUTPUT = 16384
VERSION = {"gallery": ("gallery-dl", "1.32.19"), "parth": ("parth-dl", "1.2.1")}


def limits():
    resource.setrlimit(resource.RLIMIT_AS, (512 << 20, 512 << 20))
    resource.setrlimit(resource.RLIMIT_FSIZE, (65536, 65536))
    resource.setrlimit(resource.RLIMIT_CPU, (2, 3))
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
    os.umask(0o077)


def run_version(binfile, ver, env):
    start = time.monotonic()
    p = subprocess.Popen(
        [str(binfile), "--version"], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True,
        start_new_session=True, preexec_fn=limits, env=env,
    )
    sel = selectors.DefaultSelector()
    sel.register(p.stdout, selectors.EVENT_READ)
    sel.register(p.stderr, selectors.EVENT_READ)
    total = 0
    captured = bytearray()
    reason = "EXITED"
    deadline = start + 4
    try:
        while sel.get_map():
            if time.monotonic() >= deadline:
                reason = "WALL_LIMIT"
                break
            for key, _ in sel.select(timeout=0.05):
                data = os.read(key.fd, 4096)
                if not data:
                    sel.unregister(key.fileobj)
                    continue
                total += len(data)
                if len(captured) < CAP_OUTPUT:
                    captured.extend(data[:CAP_OUTPUT-len(captured)])
                if total > CAP_OUTPUT:
                    reason = "OUTPUT_LIMIT"
                    break
            if reason != "EXITED":
                break
        if reason == "EXITED":
            try:
                p.wait(timeout=max(0.01, deadline-time.monotonic()))
            except subprocess.TimeoutExpired:
                reason = "WALL_LIMIT"
    finally:
        sel.close()
        if reason != "EXITED":
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        p.wait(timeout=2)
        p.stdout.close()
        p.stderr.close()

    # The actual package version string is proof that the pinned CLI was
    # dispatched. It is NOT an extraction, dependency-SBOM, or source PASS.
    output = captured.decode("utf-8", errors="replace")
    if reason != "EXITED" or p.returncode != 0 or ver not in output:
        raise RuntimeError("R36_NATIVE_CLI_FAILED:%s:code=%s:reason=%s" %
                           (binfile.name, p.returncode, reason))
    return {"process_exit_zero": True, "version_present": True,
            "observed_output_bytes": total,
            "elapsed_ms": round(1000*(time.monotonic()-start), 3)}


def main():
    if len(sys.argv) != 5:
        raise RuntimeError("R36_ARGS_INVALID")
    host_ns, candidate, executable_s, venv_s = sys.argv[1:]
    if candidate not in VERSION:
        raise RuntimeError("R36_UNQUALIFIED_CANDIDATE")
    if os.readlink("/proc/self/ns/net") == host_ns:
        raise RuntimeError("R36_NETNS_NOT_SEPARATED")
    if (os.geteuid(), os.getegid()) != (65534, 65534):
        raise RuntimeError("R36_NOT_NONROOT")
    caps = [l.split()[1] for l in Path("/proc/self/status").read_text().splitlines() if l.startswith("CapEff:")]
    if len(caps) != 1 or int(caps[0], 16) != 0:
        raise RuntimeError("R36_EFFECTIVE_CAPABILITIES_NOT_ZERO")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.3)
        result = sock.connect_ex(("192.0.2.1", 443))
    if result not in (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EACCES, errno.EPERM):
        raise RuntimeError("R36_KERNEL_NETWORK_DENIAL_MISSING")
    binary, version = VERSION[candidate]
    executable = Path(executable_s)
    if executable.name != binary or not executable.is_file() or not os.access(executable, os.X_OK):
        raise RuntimeError("R36_BINARY_PATH_INVALID")
    env = {
        "PATH": str(Path(venv_s) / "bin") + ":/usr/bin:/bin",
        "HOME": "/nonexistent", "XDG_CONFIG_HOME": "/nonexistent",
        "XDG_CACHE_HOME": "/nonexistent", "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1", "NO_COLOR": "1",
        "LANG": "C.UTF-8",
    }
    observations = [run_version(executable, version, env) for _ in range(5)]
    report = {
        "schema_version": 1,
        "scope": "PINNED_PUBLIC_DOWNLOADER_CLI_STARTUP_IN_NONROOT_NETNS_ONLY",
        "arch": os.uname().machine,
        "candidate": candidate,
        "version": version,
        "samples": observations,
        "sample_count": len(observations),
        "network_namespace_isolated": True,
        "os_network_denial_canary": True,
        "effective_capabilities_zero": True,
        "no_source_url_supplied": True,
        "real_instagram_requests": 0,
        "no_login_live_source_verified": False,
        "actual_extraction_verified": False,
        "stable_carousel_identity_verified": False,
        "authorized_original_media_verified": False,
        "production_host_sandbox_verified": False,
    }
    print(json.dumps(report, sort_keys=True), flush=True)
    print("R36_PINNED_REAL_CLI_SANDBOX_PASS arch=%s candidate=%s reps=5 source=NOT_RUN" %
          (report["arch"], candidate), flush=True)


if __name__ == "__main__":
    main()
