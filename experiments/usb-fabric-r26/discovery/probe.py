#!/usr/bin/env python3
"""R26-G: actual QEMU synthetic USB port occupancy and reconnect probe.

The only asserted free port is the explicit, successfully reused test slot.
Other controller ports remain UNKNOWN; no guest enumeration or HIL is claimed.
"""
import json
import os
import socket
import subprocess
import tempfile
import time

class QMP:
    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        self.sock.connect(path)
        self.file = self.sock.makefile("r", encoding="utf-8")
        self.events = []
        if "QMP" not in self.read():
            raise RuntimeError("QMP greeting missing")
        self.call("qmp_capabilities")

    def read(self):
        line = self.file.readline()
        if not line:
            raise RuntimeError("QMP session unexpectedly closed")
        return json.loads(line)

    def call(self, command, arguments=None):
        request = {"execute": command}
        if arguments is not None:
            request["arguments"] = arguments
        self.sock.sendall((json.dumps(request) + "\n").encode())
        for _ in range(200):
            message = self.read()
            if "event" in message:
                self.events.append(message)
                continue
            if "error" in message:
                raise RuntimeError(str(message["error"]))
            if "return" not in message:
                raise RuntimeError("QMP response missing return")
            return message["return"]
        raise RuntimeError("QMP response limit exceeded")

    def wait_deleted(self, device, deadline=5.0):
        until = time.monotonic() + deadline
        while time.monotonic() < until:
            for event in self.events:
                if event.get("event") == "DEVICE_DELETED":
                    data = event.get("data", {})
                    if data.get("device") == device:
                        return True
            self.sock.settimeout(max(0.05, min(0.5, until - time.monotonic())))
            try:
                event = self.read()
            except (socket.timeout, TimeoutError):
                continue
            if "event" in event:
                self.events.append(event)
            else:
                raise RuntimeError("unmatched QMP response while waiting for delete")
        return False

    def seen(self, device):
        return device in {
            obj.get("name") for obj in self.call("qom-list", {
                "path": "/machine/peripheral"
            })
        }

    def close(self):
        self.file.close()
        self.sock.close()

def connect(path, proc):
    for _ in range(150):
        if proc.poll() is not None:
            raise RuntimeError("QEMU exited before QMP connection")
        if os.path.exists(path):
            try:
                return QMP(path)
            except (FileNotFoundError, ConnectionRefusedError):
                pass
        time.sleep(0.05)
    raise RuntimeError("QMP socket unavailable")

def main():
    with tempfile.TemporaryDirectory(prefix="r26-port-probe-", dir="/tmp") as root:
        path = root + "/qmp.sock"
        cmd = [
            "qemu-system-x86_64", "-machine", "q35", "-accel", "tcg",
            "-m", "256", "-smp", "1", "-S", "-nodefaults", "-display",
            "none", "-monitor", "none", "-serial", "none", "-net", "none",
            "-device", "qemu-xhci,id=xhci0",
            "-qmp", "unix:" + path + ",server=on,wait=off"
        ]
        proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        session = None
        try:
            session = connect(path, proc)
            session.call("device_add", {
                "driver": "usb-kbd", "id": "r26-g-kbd",
                "bus": "xhci0.0", "port": "1"
            })
            if not session.seen("r26-g-kbd"):
                raise RuntimeError("QMP QOM cannot see explicit USB port occupant")
            print("R26_G_EXPLICIT_USB_PORT_OCCUPIED=PASS", flush=True)
            session.close()
            session = connect(path, proc)
            if not session.seen("r26-g-kbd"):
                raise RuntimeError("QMP reconnect lost previously attached device")
            print("R26_G_QMP_RECONNECT_RETAINS_OCCUPIED_STATE=PASS", flush=True)
            try:
                session.call("device_add", {
                    "driver": "usb-tablet", "id": "r26-g-collision",
                    "bus": "xhci0.0", "port": "1"
                })
            except RuntimeError:
                print("R26_G_OCCUPIED_PORT_COLLISION_DENIED=PASS", flush=True)
            else:
                raise RuntimeError("QEMU allowed two devices on explicit port 1")
            session.call("device_del", {"id": "r26-g-kbd"})
            if not session.wait_deleted("r26-g-kbd"):
                raise RuntimeError("port cannot be released without DEVICE_DELETED")
            if session.seen("r26-g-kbd"):
                raise RuntimeError("DEVICE_DELETED with retained QOM device")
            print("R26_G_DEVICE_DELETE_CONFIRMED_BEFORE_REUSE=PASS", flush=True)
            session.call("device_add", {
                "driver": "usb-tablet", "id": "r26-g-tablet",
                "bus": "xhci0.0", "port": "1"
            })
            if not session.seen("r26-g-tablet"):
                raise RuntimeError("port not reusable after confirmed deletion")
            print("R26_G_EXPLICIT_TEST_PORT_REUSED_AFTER_CLEAN_DELETE=PASS", flush=True)
            print("R26_G_OTHER_XHCI_PORTS_FREE=UNKNOWN", flush=True)
            print("R26_G_GUEST_USB_DRIVER_PORT_OBSERVATION=NOT_TESTED", flush=True)
            print("R26_G_PHYSICAL_USB_OR_DISTRIBUTED_RECLAIM=NOT_TESTED", flush=True)
        finally:
            if session is not None:
                session.close()
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()

if __name__ == "__main__":
    main()
