#!/usr/bin/env python3
"""Cheap QEMU 10.x topology oracle for the TrueNAS T3 installed-boot shape."""
from __future__ import annotations

import argparse
import json
import pathlib
import socket
import subprocess
import tempfile
import time


NIC_SLOT = 3
BOOT_SLOT = 4
DATA_SLOTS = [5, 6]
DATA_SERIALS = ["RDTE_DATA_0", "RDTE_DATA_1"]


class QMP:
    def __init__(self, path: pathlib.Path, timeout: float = 5.0):
        deadline = time.monotonic() + timeout
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        while True:
            try:
                self.sock.connect(str(path))
                break
            except (FileNotFoundError, ConnectionRefusedError):
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.05)
        self.file = self.sock.makefile("rwb", buffering=0)
        greeting = self._recv()
        if "QMP" not in greeting:
            raise RuntimeError(f"missing QMP greeting: {greeting!r}")
        self.execute("qmp_capabilities")

    def _recv(self):
        line = self.file.readline()
        if not line:
            raise EOFError("QMP closed")
        return json.loads(line)

    def execute(self, command, arguments=None):
        request = {"execute": command}
        if arguments is not None:
            request["arguments"] = arguments
        self.file.write((json.dumps(request, separators=(",", ":")) + "\n").encode())
        while True:
            reply = self._recv()
            if "event" in reply:
                continue
            if "error" in reply:
                raise RuntimeError(f"{command}: {reply['error']!r}")
            return reply.get("return")

    def close(self):
        try:
            self.execute("quit")
        except Exception:
            pass
        try:
            self.file.close()
        finally:
            self.sock.close()


def flatten_pci(buses):
    rows = []
    def walk(devices):
        for dev in devices:
            rows.append({
                "bus": dev["bus"],
                "slot": dev["slot"],
                "function": dev["function"],
                "qdev_id": dev.get("qdev_id", ""),
                "vendor": dev.get("id", {}).get("vendor"),
                "device": dev.get("id", {}).get("device"),
            })
            bridge = dev.get("pci_bridge")
            if bridge:
                walk(bridge.get("devices", []))
    for bus in buses:
        walk(bus.get("devices", []))
    return rows


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--out", required=True)
    p.add_argument("--qemu", default="qemu-system-x86_64")
    a = p.parse_args()

    out = pathlib.Path(a.out)
    payload = {
        "schema": "qemu-truenas-t3-topology/v1",
        "classification": "ORACLE_FAILURE",
        "oracleSatisfied": False,
        "expected": {
            "nic_slot": NIC_SLOT,
            "boot_slot": BOOT_SLOT,
            "data_slots": DATA_SLOTS,
            "bootindex": 1,
            "data_serials": DATA_SERIALS,
        },
    }

    qemu = None
    try:
        version = subprocess.check_output([a.qemu, "--version"], text=True).splitlines()[0]
        payload["qemu_version"] = version

        with tempfile.TemporaryDirectory(prefix="rdte-qemu-topology-") as td:
            root = pathlib.Path(td)
            for name in ("boot", "data0", "data1"):
                subprocess.run(
                    ["qemu-img", "create", "-q", "-f", "qcow2", str(root / f"{name}.qcow2"), "64M"],
                    check=True,
                )
            qmp_path = root / "qmp.sock"
            pidfile = root / "qemu.pid"
            args = [
                a.qemu,
                "-S",
                "-display", "none",
                "-serial", "none",
                "-monitor", "none",
                "-m", "256",
                "-smp", "1",
                "-drive", f"file={root / 'boot.qcow2'},if=none,id=rdteboot,format=qcow2",
                "-device", "virtio-blk-pci,drive=rdteboot,id=rdte-boot,addr=0x4,bootindex=1",
                "-drive", f"file={root / 'data0.qcow2'},if=none,id=rdtedata0,format=qcow2",
                "-device", "virtio-blk-pci,drive=rdtedata0,id=rdte-data0,serial=RDTE_DATA_0,addr=0x5",
                "-drive", f"file={root / 'data1.qcow2'},if=none,id=rdtedata1,format=qcow2",
                "-device", "virtio-blk-pci,drive=rdtedata1,id=rdte-data1,serial=RDTE_DATA_1,addr=0x6",
                "-netdev", "user,id=net0",
                "-device", "virtio-net-pci,netdev=net0,id=rdte-nic,mac=52:54:00:54:4e:26,addr=0x3",
                "-boot", "strict=on",
                "-qmp", f"unix:{qmp_path},server=on,wait=off",
                "-daemonize",
                "-pidfile", str(pidfile),
            ]
            payload["command_shape"] = [
                arg.replace(str(root), "$TMP") for arg in args[1:]
            ]
            subprocess.run(args, check=True)
            qemu = int(pidfile.read_text().strip())

            qmp = QMP(qmp_path)
            try:
                pci = flatten_pci(qmp.execute("query-pci"))
                payload["pci"] = pci
                by_id = {row["qdev_id"]: row for row in pci if row["qdev_id"]}
                payload["bootindex"] = qmp.execute(
                    "qom-get",
                    {"path": "/machine/peripheral/rdte-boot", "property": "bootindex"},
                )
                payload["data_serials"] = [
                    qmp.execute(
                        "qom-get",
                        {"path": f"/machine/peripheral/rdte-data{i}", "property": "serial"},
                    )
                    for i in range(2)
                ]
                payload["qtree"] = qmp.execute(
                    "human-monitor-command",
                    {"command-line": "info qtree"},
                )

                checks = {
                    "nic_slot": by_id.get("rdte-nic", {}).get("slot") == NIC_SLOT,
                    "boot_slot": by_id.get("rdte-boot", {}).get("slot") == BOOT_SLOT,
                    "data0_slot": by_id.get("rdte-data0", {}).get("slot") == DATA_SLOTS[0],
                    "data1_slot": by_id.get("rdte-data1", {}).get("slot") == DATA_SLOTS[1],
                    "all_functions_zero": all(
                        by_id.get(name, {}).get("function") == 0
                        for name in ("rdte-nic", "rdte-boot", "rdte-data0", "rdte-data1")
                    ),
                    "bootindex": payload["bootindex"] == 1,
                    "data_serials": payload["data_serials"] == DATA_SERIALS,
                }
                payload["checks"] = checks
                if not all(checks.values()):
                    raise RuntimeError(f"topology checks failed: {checks!r}")
            finally:
                qmp.close()

        payload["classification"] = "SUPPORTED"
        payload["oracleSatisfied"] = True
        payload["detail"] = (
            "actual hosted-runner QEMU realized NIC@0x3, boot@0x4 bootindex=1, "
            "and uniquely serialized data disks @0x5/0x6"
        )
    except Exception as exc:
        payload["detail"] = f"{type(exc).__name__}: {exc}"
    finally:
        if qemu:
            try:
                subprocess.run(["kill", str(qemu)], check=False)
            except Exception:
                pass
        out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps(payload, indent=2, sort_keys=True))

    return 0 if payload["oracleSatisfied"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
