#!/usr/bin/env python3
"""Synthetic no-guest-OS QMP/TCG capability probe; Python stdlib test-only.

No network listener, firmware flash, guest image, credentials, or trusted device
passthrough. Does NOT qualify ISA kernel boot, sandbox isolation or performance.
"""
import argparse
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path

TARGETS = {
    "x86_64": ("qemu-system-x86_64", ("-machine", "q35", "-cpu", "qemu64")),
    "aarch64": ("qemu-system-aarch64", ("-machine", "virt", "-cpu", "cortex-a57")),
    "riscv64": ("qemu-system-riscv64", ("-machine", "virt", "-cpu", "rv64")),
}


def qmp_receive(stream):
    for _ in range(100):
        line = stream.readline()
        if not line:
            raise RuntimeError("QMP closed without a command response")
        message = json.loads(line)
        if "event" in message:
            continue
        if "error" in message:
            raise RuntimeError("QMP command failed: " + str(message["error"]))
        return message
    raise RuntimeError("excessive QMP events without response")


def qmp_command(sock, stream, name):
    sock.sendall((json.dumps({"execute": name}) + "\n").encode("utf-8"))
    reply = qmp_receive(stream)
    if "return" not in reply:
        raise RuntimeError("malformed QMP response to " + name)
    return reply["return"]


def probe(arch):
    binary, machine_args = TARGETS[arch]
    exe = shutil.which(binary)
    if not exe:
        raise RuntimeError("QEMU binary unavailable: " + binary)
    with tempfile.TemporaryDirectory(prefix="public-qmp-") as directory:
        sockpath = str(Path(directory) / "qmp.sock")
        command = [
            exe, *machine_args, "-accel", "tcg", "-smp", "1", "-m", "128M",
            "-nodefaults", "-display", "none", "-serial", "none",
            "-monitor", "none", "-S",
            "-qmp", "unix:" + sockpath + ",server=on,wait=off",
        ]
        begin = time.monotonic()
        proc = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(6)
            connected = False
            for _ in range(100):
                if proc.poll() is not None:
                    raise RuntimeError("QEMU exited before local QMP connected")
                try:
                    sock.connect(sockpath)
                    connected = True
                    break
                except (FileNotFoundError, ConnectionRefusedError):
                    time.sleep(0.1)
            if not connected:
                raise RuntimeError("QMP local socket did not become ready")
            with sock:
                stream = sock.makefile("r", encoding="utf-8")
                with stream:
                    greeting = qmp_receive(stream)
                    if "QMP" not in greeting:
                        raise RuntimeError("invalid QMP greeting")
                    qmp_command(sock, stream, "qmp_capabilities")
                    status = qmp_command(sock, stream, "query-status")
                    kvm = qmp_command(sock, stream, "query-kvm")
                    machines = qmp_command(sock, stream, "query-machines")
                    version = qmp_command(sock, stream, "query-version")
                    if status.get("running") is not False:
                        raise RuntimeError("expected suspended preboot machine")
                    if kvm.get("enabled") is not False:
                        raise RuntimeError("TCG experiment silently enabled KVM")
                    if not machines:
                        raise RuntimeError("QMP machine catalog unexpectedly empty")
                    elapsed = round(time.monotonic() - begin, 3)
                    print("R01_QMP_TCG_PREBOOT=PASS")
                    print("R01_QMP_ACCELERATOR=TCG_VERIFIED")
                    print("R01_QMP_UNIX_SOCKET_ONLY=CONFIGURED_NOT_ISOLATION_PROOF")
                    print("R01_GUEST_FIRMWARE_KERNEL_BOOT=NOT_TESTED")
                    print("R01_AGENT_SANDBOX_ESCAPE_RESISTANCE=NOT_TESTED")
                    print("R01_INDEPENDENT_GUEST_FUNCTION=NOT_TESTED")
                    print("R01_QMP_RECEIPT=" + json.dumps({
                        "arch": arch, "machine": machine_args[1],
                        "qemu": version.get("qemu", {}),
                        "kvm_enabled": kvm.get("enabled"),
                        "running": status.get("running"),
                        "preboot_qmp_ready_seconds": elapsed,
                        "test_scope": "QMP_TCG_PREBOOT_ONLY",
                    }, sort_keys=True))
                    qmp_command(sock, stream, "quit")
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                raise RuntimeError("QEMU failed to exit after QMP quit")
            if proc.returncode != 0:
                raise RuntimeError("QEMU returned nonzero after quit")
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            if proc.returncode != 0:
                details = proc.stderr.read().decode("utf-8", "replace") if proc.stderr else ""
                print("R01_QEMU_STDERR=" + details[-1200:])
            if proc.stderr:
                proc.stderr.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--arch", choices=sorted(TARGETS), required=True)
    args = parser.parse_args()
    probe(args.arch)
