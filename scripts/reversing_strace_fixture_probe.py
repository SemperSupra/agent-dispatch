#!/usr/bin/env python3
"""Fixed synthetic Linux strace qualification; never accepts external targets.

Runs a known-source C fixture in an ephemeral directory, traces only a child
spawned by strace, independently verifies its file output, and emits a compact
public-safe receipt. A parsed trace is evidence, not arbitrary-code permission.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

SOURCE = r'''#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
static const char path[] = "trace-proof-output.bin";
static const char payload[] = "trace-proof-v1\n";
int main(void) {
  int fd = openat(AT_FDCWD, path, O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0600);
  if (fd < 0) return 41;
  if (write(fd, payload, sizeof(payload) - 1) != (ssize_t)(sizeof(payload) - 1)) return 42;
  if (close(fd) != 0) return 43;
  return 0;
}
'''
PAYLOAD = b"trace-proof-v1\n"
FILE = "trace-proof-output.bin"
SYS_PREFIX = r"(?:\[pid +[0-9]+\] +)?"
OPEN = re.compile(r'^' + SYS_PREFIX + r'openat\(AT_FDCWD, "trace-proof-output\.bin", ([A-Z0-9_|]+), 0600\) += +([0-9]+)(?:<[^>]*>)?$')
WRITE = re.compile(r'^' + SYS_PREFIX + r'write\(([0-9]+)(?:<[^>]*>)?, "trace-proof-v1\\n", 15\) += +([0-9]+)$')
CLOSE = re.compile(r'^' + SYS_PREFIX + r'close\(([0-9]+)(?:<[^>]*>)?\) += +(0|-1 .*)$')
EXIT = re.compile(r'^' + SYS_PREFIX + r'exit_group\(([-0-9]+)\) += +\?$')
FINAL = re.compile(r'^' + SYS_PREFIX + r'\+\+\+ exited with ([0-9]+) \+\+\+$')


class OracleError(RuntimeError):
    """Evidence fails to support the fixed synthetic trace assertion."""


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def check_trace(raw):
    """Require one fixture PID, exact ordered syscall witness and no extras."""
    lines = raw.splitlines()
    if not lines or len(lines) > 512 or len(raw) > 65536:
        raise OracleError("trace length outside bounded fixture contract")
    if any("<unfinished ...>" in x or "resumed>" in x or "detached" in x for x in lines):
        raise OracleError("incomplete/detached syscall trace")
    collected = []
    pid_bound = False
    bound_pid = None
    pid_prefix = re.compile(r"^\[pid +([0-9]+)\] +")

    def bind_pid(line):
        nonlocal pid_bound, bound_pid
        pm = pid_prefix.match(line)
        pid = int(pm.group(1)) if pm else None
        if not pid_bound:
            bound_pid, pid_bound = pid, True
        elif pid != bound_pid:
            raise OracleError("fixture trace crosses process identity or PID-format boundary")

    for index, line in enumerate(lines):
        if m := OPEN.fullmatch(line):
            bind_pid(line)
            flags = m.group(1).split("|")
            if set(flags) != {"O_WRONLY", "O_CREAT", "O_EXCL", "O_CLOEXEC"} or len(flags) != 4:
                raise OracleError("unexpected fixture open flags")
            collected.append(("open", index, int(m.group(2))))
        elif m := WRITE.fullmatch(line):
            bind_pid(line)
            collected.append(("write", index, int(m.group(1)), int(m.group(2))))
        elif m := CLOSE.fullmatch(line):
            if not any(x[0] == "open" for x in collected):
                continue  # Loader closes before the unique fixture open.
            owned_fd = next(x[2] for x in collected if x[0] == "open")
            if int(m.group(1)) != owned_fd:
                raise OracleError("unexpected close of non-fixture fd after fixture open")
            bind_pid(line)
            if m.group(2) != "0":
                raise OracleError("fixture close failed")
            collected.append(("close", index, owned_fd))
        elif m := EXIT.fullmatch(line):
            bind_pid(line)
            collected.append(("exit", index, int(m.group(1))))
        elif m := FINAL.fullmatch(line):
            bind_pid(line)
            collected.append(("final", index, int(m.group(1))))
        elif (any(x[0] == "open" for x in collected)
              or "trace-proof-output.bin" in line
              or '"trace-proof-v1\\n"' in line):
            raise OracleError("unrecognized trace event in fixed fixture")

    expected = ["open", "write", "close", "exit", "final"]
    if [x[0] for x in collected] != expected:
        raise OracleError("missing, duplicated or reordered fixture evidence")
    opened, written, closed, exited, final = collected
    fd = opened[2]
    if fd < 0 or written[2] != fd or written[3] != len(PAYLOAD) or closed[2] != fd:
        raise OracleError("fd identity or write byte-count oracle failed")
    if exited[2] != 0 or final[2] != 0:
        raise OracleError("inferior exit was not clean")
    return {
        "opened_fd": fd, "wrote_bytes": written[3], "event_kinds": expected,
        "witness_lines": [lines[x[1]] for x in collected],
    }


def run_checked(argv, *, cwd, timeout):
    cp = subprocess.run(argv, cwd=cwd, input=b"", capture_output=True,
                        timeout=timeout, check=False)
    if cp.returncode != 0:
        if Path(argv[0]).name == "strace" and any(marker in cp.stderr for marker in
                (b"Operation not permitted", b"Permission denied", b"ptrace(PTRACE_TRACEME)")):
            raise OracleError("BLOCKED_CAPABILITY: strace ptrace permission denied")
        raise OracleError(f"{Path(argv[0]).name} exited {cp.returncode}")
    return cp


def execute():
    missing = [x for x in ("gcc", "strace") if shutil.which(x) is None]
    if missing:
        raise OracleError("BLOCKED_CAPABILITY: missing " + ",".join(missing))
    with tempfile.TemporaryDirectory(prefix="strace-fixed-fixture-") as td:
        tmp = Path(td)
        source, exe, trace = tmp / "fixture.c", tmp / "fixture", tmp / "trace.txt"
        source.write_text(SOURCE, encoding="utf-8")
        run_checked(["gcc", "-std=c11", "-O0", "-Wall", "-Wextra", "-Werror",
                     "-o", str(exe), str(source)], cwd=td, timeout=30)
        executable_hash = sha256(exe.read_bytes())
        run_checked(["strace", "-s", "64", "-e", "trace=openat,write,close,exit_group",
                     "-o", str(trace), "--", str(exe)], cwd=td, timeout=20)
        facts = check_trace(trace.read_text(encoding="utf-8", errors="strict"))
        actual = (tmp / FILE).read_bytes()
        if actual != PAYLOAD:
            raise OracleError("independent output-file payload oracle failed")
        return {
            "schema": "strace-fixed-fixture-receipt/v0.1",
            "status": "NATIVE_SYSCALL_TRACE_FIXTURE_PASS",
            "scope": "synthetic-generated-linux-elf-only",
            "source_sha256": sha256(SOURCE.encode()),
            "executable_sha256": executable_hash,
            "trace_sha256": sha256(trace.read_bytes()),
            "output_sha256": sha256(actual),
            "observed": facts,
            "limitations": ["no-all-path-coverage", "no-instruction-level-attribution",
                            "no-causal-inference-from-timing", "no-private-targets",
                            "not-yet-cross-tool-ghidra-mapped"],
        }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    if args.output.exists() or args.output.is_symlink():
        raise OracleError("receipt path already exists; use a fresh run-scoped path")
    receipt = execute()
    with args.output.open("x", encoding="utf-8") as fp:
        fp.write(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
    print(receipt["status"])


if __name__ == "__main__":
    main()
