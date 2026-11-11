#!/usr/bin/env python3
"""R45: positive kernel aggregate file-quota denial, public synthetic only.

This code runs unprivileged inside a private mount+network namespace. A
privileged disposable GHA setup mounts a small tmpfs then drops privileges.
It does not execute gallery-dl, parth-dl, Winnow or Instagram extraction.
"""
import errno
import json
import os
from pathlib import Path
import socket
import sys

QUOTA = 256 * 1024
EACH = 160 * 1024


def verify_namespace(host_mount, host_net, root):
    if os.readlink("/proc/self/ns/mnt") == host_mount:
        raise RuntimeError("R45_MOUNT_NAMESPACE_NOT_SEPARATE")
    if os.readlink("/proc/self/ns/net") == host_net:
        raise RuntimeError("R45_NETWORK_NAMESPACE_NOT_SEPARATE")
    if (os.geteuid(), os.getegid()) != (65534, 65534):
        raise RuntimeError("R45_PRIVILEGE_DROP_FAILED")
    caps = [x.split()[1] for x in Path("/proc/self/status").read_text().splitlines()
            if x.startswith("CapEff:")]
    if len(caps) != 1 or int(caps[0], 16) != 0:
        raise RuntimeError("R45_CAPABILITIES_NOT_ZERO")
    if not os.path.ismount(root):
        raise RuntimeError("R45_STAGE_NOT_MOUNTPOINT")
    mount_lines = Path("/proc/self/mountinfo").read_text().splitlines()
    if not any((" " + str(root) + " ") in x and " - tmpfs " in x for x in mount_lines):
        raise RuntimeError("R45_STAGE_NOT_EXPLICIT_TMPFS")
    stat = os.statvfs(root)
    capacity = stat.f_blocks * stat.f_frsize
    if capacity != QUOTA:
        raise RuntimeError("R45_UNEXPECTED_TMPFS_CAPACITY:" + str(capacity))
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.3)
        outcome = s.connect_ex(("192.0.2.1", 443))
    if outcome not in (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EPERM, errno.EACCES):
        raise RuntimeError("R45_TCP_KERNEL_DENIAL_MISSING")
    return outcome


def write_exact_or_errno(path, count):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    written = 0
    failure = None
    try:
        while written < count:
            try:
                n = os.write(fd, b"s" * min(4096, count - written))
            except OSError as exc:
                failure = exc.errno
                break
            if n <= 0:
                raise RuntimeError("R45_ZERO_PROGRESS_WRITE")
            written += n
    finally:
        os.close(fd)
    return written, failure


def main():
    if len(sys.argv) != 4:
        raise RuntimeError("R45_INVALID_ARGS")
    host_mnt, host_net, directory = sys.argv[1:]
    root = Path(directory).resolve()
    network_errno = verify_namespace(host_mnt, host_net, root)
    first = root / "synthetic-1.bin"
    second = root / "synthetic-2.bin"
    first_written, first_error = write_exact_or_errno(first, EACH)
    if first_written != EACH or first_error is not None:
        raise RuntimeError("R45_FIRST_WRITE_FAILED")
    second_written, second_error = write_exact_or_errno(second, EACH)
    if second_error != errno.ENOSPC or second_written >= EACH:
        raise RuntimeError("R45_AGGREGATE_DISK_QUOTA_NOT_DENIED:written=%s errno=%s" %
                           (second_written, second_error))
    observed = sum(f.stat().st_size for f in (first, second))
    if observed > QUOTA or observed < first_written or observed != first_written + second_written:
        raise RuntimeError("R45_ACCOUNTED_STAGE_BYTES_INVALID")
    report = {
        "schema_version": 1,
        "scope": "PUBLIC_EPHEMERAL_LINUX_TMPFS_AGGREGATE_QUOTA_CAPABILITY_ONLY",
        "arch": os.uname().machine,
        "mount_namespace_separate": True,
        "network_namespace_separate": True,
        "nonroot_zero_caps": True,
        "kernel_tcp_denial_errno": network_errno,
        "tmpfs_max_bytes": QUOTA,
        "requested_file_bytes_each": EACH,
        "first_file_written_bytes": first_written,
        "second_file_written_bytes": second_written,
        "second_file_write_errno": second_error,
        "aggregate_written_bytes": observed,
        "quota_denial_observed": True,
        "private_winnow_source_present": False,
        "real_vendor_download_executed": False,
        "production_runtime_confined": False,
        "real_instagram_requests": 0,
        "live_original_media_verified": False,
        "mvp_release_admitted": False,
    }
    for file in (first, second):
        file.unlink()
    if list(root.iterdir()):
        raise RuntimeError("R45_STAGE_CLEANUP_FAILED")
    print(json.dumps(report, sort_keys=True))
    print("R45_KERNEL_TMPFS_AGGREGATE_QUOTA_PASS arch=%s enospc=%d bytes=%d max=%d release=HOLD" %
          (report["arch"], second_error, observed, QUOTA))


if __name__ == "__main__":
    main()
