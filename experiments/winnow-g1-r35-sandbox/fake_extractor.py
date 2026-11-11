#!/usr/bin/env python3
"""Synthetic public fixture only. Never contacts Instagram or reads private data.

One process mode per invocation. The parent harness constrains this child's
wall time, output, per-file bytes, virtual memory, CPU and open descriptors.
"""
import errno
import os
from pathlib import Path
import socket
import subprocess
import sys
import time


def main():
    if len(sys.argv) != 3:
        raise SystemExit(20)
    mode, stage_s = sys.argv[1:]
    stage = Path(stage_s)
    if not stage.is_dir():
        raise SystemExit(21)
    if mode == "normal":
        (stage / "fixture.bin").write_bytes(b"synthetic-public-fixture\n" * 16)
        print("SYNTHETIC_FIXTURE_OK", flush=True)
    elif mode == "net":
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.25)
            result = s.connect_ex(("192.0.2.1", 443))
        if result not in (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EPERM, errno.EACCES):
            raise RuntimeError("UNEXPECTED_NETWORK_RESULT:%s" % result)
        print("NETWORK_NAMESPACE_DENIED errno=%d" % result, flush=True)
    elif mode == "stdout":
        for _ in range(1024):
            sys.stdout.buffer.write(b"x" * 4096)
            sys.stdout.flush()
    elif mode == "disk":
        try:
            (stage / "oversized.bin").write_bytes(b"b" * (1 << 20))
        except OSError as exc:
            if exc.errno == errno.EFBIG:
                print("FILE_SIZE_LIMIT_DENIED", flush=True)
                raise SystemExit(47)
            raise
        raise RuntimeError("UNBOUNDED_DISK_WRITE")
    elif mode == "memory":
        try:
            _ = bytearray(512 << 20)
        except MemoryError:
            print("ADDRESS_SPACE_LIMIT_DENIED", flush=True)
            raise SystemExit(48)
        raise RuntimeError("UNBOUNDED_MEMORY_ALLOCATION")
    elif mode == "cpu":
        while True:
            pass
    elif mode == "descendant":
        child = subprocess.Popen(["/bin/sleep", "30"], close_fds=True)
        (stage / "child.pid").write_text(str(child.pid) + "\n")
        print("CHILD_SPAWNED", flush=True)
        time.sleep(30)
    else:
        raise SystemExit(22)


if __name__ == "__main__":
    main()
