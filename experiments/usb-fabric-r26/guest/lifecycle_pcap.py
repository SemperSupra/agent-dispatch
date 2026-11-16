#!/usr/bin/env python3
"""Public synthetic QEMU xHCI attach/detach and PCAP header probe.

This is HOST QMP topology only; guest driver removal, USB transfer contents,
physical USB, and cross-host isolation are deliberately NOT claimed.
"""
import hashlib
import json
import os
import socket
import subprocess
import tempfile
import time
from pathlib import Path

class QMP:
    def __init__(self, sock):
        self.sock = sock
        self.fp = sock.makefile("r", encoding="utf-8")
        self.events = []
        hello = self.read()
        if "QMP" not in hello:
            raise RuntimeError("missing QMP greeting")
        self.call("qmp_capabilities")

    def read(self):
        line = self.fp.readline()
        if not line:
            raise RuntimeError("QMP disconnected")
        return json.loads(line)

    def call(self, name, args=None):
        request = {"execute": name}
        if args is not None:
            request["arguments"] = args
        self.sock.sendall((json.dumps(request) + "\n").encode("utf-8"))
        for _ in range(100):
            result = self.read()
            if "event" in result:
                self.events.append(result)
                continue
            if "error" in result:
                raise RuntimeError("QMP " + name + " error: " + str(result["error"]))
            if "return" not in result:
                raise RuntimeError("unknown QMP response: " + str(result))
            return result["return"]
        raise RuntimeError("QMP response lost")

    def poll_event(self, name, seconds=5):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            for event in self.events:
                if event.get("event") == name:
                    return event
            self.sock.settimeout(min(0.5, max(0.05, end - time.monotonic())))
            try:
                result = self.read()
            except (socket.timeout, TimeoutError):
                continue
            if "event" in result:
                self.events.append(result)
            else:
                raise RuntimeError("unsolicited QMP response")
        raise RuntimeError("missing QMP event " + name)

def connect(path, proc):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(5)
    for _ in range(150):
        if proc.poll() is not None:
            raise RuntimeError("QEMU exited prematurely")
        try:
            sock.connect(path)
            return sock
        except (FileNotFoundError, ConnectionRefusedError):
            time.sleep(0.05)
    raise RuntimeError("QMP socket was not available")

def main():
    with tempfile.TemporaryDirectory(prefix="r26-qmp-", dir="/tmp") as directory:
        sock_path = directory + "/qmp.sock"
        pcap_path = directory + "/keyboard.pcap"
        cmd = [
            "qemu-system-x86_64", "-machine", "q35", "-accel", "tcg",
            "-cpu", "qemu64", "-m", "256", "-smp", "1", "-S",
            "-nodefaults", "-display", "none", "-monitor", "none",
            "-serial", "none", "-net", "none", "-no-reboot",
            "-device", "qemu-xhci,id=xhci0",
            "-qmp", "unix:" + sock_path + ",server=on,wait=off",
        ]
        proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        try:
            with connect(sock_path, proc) as sock:
                q = QMP(sock)
                if q.call("query-kvm").get("enabled") is not False:
                    raise RuntimeError("unexpected KVM acceleration")
                q.call("device_add", {
                    "driver": "usb-kbd", "id": "r26-keyboard",
                    "bus": "xhci0.0", "pcap": pcap_path,
                })
                objects = q.call("qom-list", {"path": "/machine/peripheral"})
                if not any(x.get("name") == "r26-keyboard" for x in objects):
                    raise RuntimeError("host QOM missing attached USB keyboard")
                print("R26_QMP_USB_ATTACH_HOST_VISIBLE=PASS", flush=True)
                q.call("device_del", {"id": "r26-keyboard"})
                event = q.poll_event("DEVICE_DELETED")
                data = event.get("data", {})
                if data.get("device") not in ("r26-keyboard", None) and data.get("path") is None:
                    raise RuntimeError("unexpected DEVICE_DELETED identity " + str(data))
                objects = q.call("qom-list", {"path": "/machine/peripheral"})
                if any(x.get("name") == "r26-keyboard" for x in objects):
                    raise RuntimeError("QMP removed event but QOM still reports keyboard")
                print("R26_QMP_DEVICE_DELETED_EVENT_AND_QOM_ABSENCE=PASS", flush=True)
                if not os.path.exists(pcap_path):
                    raise RuntimeError("QEMU did not write USB capture header")
                blob = Path(pcap_path).read_bytes()
                if len(blob) < 24 or blob[:4] not in (
                    bytes.fromhex("d4c3b2a1"), bytes.fromhex("a1b2c3d4"),
                    bytes.fromhex("4d3cb2a1"), bytes.fromhex("a1b23c4d")
                ):
                    raise RuntimeError("invalid PCAP header length/magic")
                print("R26_QEMU_USB_PCAP_HEADER=PASS sha256=" +
                      hashlib.sha256(blob).hexdigest(), flush=True)
                print("R26_QEMU_USB_PCAP_PAYLOAD_TRANSFERS=NOT_TESTED", flush=True)
                print("R26_GUEST_DEVICE_REMOVAL=NOT_TESTED", flush=True)
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
if __name__ == "__main__":
    main()
