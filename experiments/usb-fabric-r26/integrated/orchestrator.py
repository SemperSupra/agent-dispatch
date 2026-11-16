#!/usr/bin/env python3
"""End-to-end synthetic Go broker/QMP/real Linux evdev qualification.
No network/physical USB/credentials. Guest is genuine Debian Linux via TCG.
"""
import hashlib
import json
import os
from pathlib import Path
import select
import subprocess
import tempfile
import time

def send(broker, request, timeout=15):
    if broker.poll() is not None:
        raise RuntimeError("Go broker died before request")
    broker.stdin.write(json.dumps(request) + "\n")
    broker.stdin.flush()
    ready, _, _ = select.select([broker.stdout], [], [], timeout)
    if not ready:
        raise RuntimeError("Go broker response timed out")
    line = broker.stdout.readline()
    if not line:
        raise RuntimeError("Go broker disconnected")
    return json.loads(line)

def expect(resp, accepted, label):
    if bool(resp.get("ok")) != accepted:
        raise RuntimeError(label + " unexpected broker response " + str(resp))
    print(label + "=PASS", flush=True)

def main():
    with tempfile.TemporaryDirectory(prefix="r26-integration-", dir="/tmp") as d:
        marker = b"PUBLIC_R26_SYNTHETIC_USB_MEDIA"
        media = Path(d) / "media.img"
        media.write_bytes(marker + bytes(2097152 - len(marker)))
        old_hash = hashlib.sha256(media.read_bytes()).hexdigest()
        pcap = Path(d) / "keyboard.pcap"
        qmp = d + "/qmp.sock"
        cmd = [
            "qemu-system-x86_64", "-machine", "q35", "-accel", "tcg",
            "-cpu", "qemu64", "-m", "1024M", "-smp", "1",
            "-S", "-nodefaults", "-display", "none", "-monitor", "none",
            "-serial", "stdio", "-net", "none", "-no-reboot",
            "-kernel", "/guest/kernel", "-initrd", "/guest/initrd.gz",
            "-append", "console=ttyS0 rdinit=/init loglevel=7 panic=-1",
            "-device", "qemu-xhci,id=xhci0",
            "-qmp", "unix:" + qmp + ",server=on,wait=off",
        ]
        vm = subprocess.Popen(cmd, stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        broker = subprocess.Popen(
            ["/guest/r26-broker", "--qmp", qmp, "--media", str(media),
             "--capture", str(pcap)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, bufsize=1)
        try:
            ready, _, _ = select.select([broker.stdout], [], [], 12)
            if not ready:
                raise RuntimeError("initial broker QMP handshake timed out")
            expect(json.loads(broker.stdout.readline()), True,
                   "R26_INITIAL_BROKER_QMP_CONNECTED")
            old_grant = send(broker, {"op": "reserve", "actor": "approved-agent"})
            expect(old_grant, True, "R26_PRE_RESTART_LEASE_GRANTED")
            old_epoch = old_grant["epoch"]
            old_generation = old_grant["generation"]
            broker.stdin.close()
            if broker.wait(timeout=5) != 0:
                raise RuntimeError("original broker did not close cleanly")
            print("R26_ACTUAL_GO_BROKER_PROCESS_RESTART=PASS", flush=True)
            broker = subprocess.Popen(
                ["/guest/r26-broker", "--qmp", qmp, "--media", str(media),
                 "--capture", str(pcap)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, bufsize=1)
            ready, _, _ = select.select([broker.stdout], [], [], 12)
            if not ready:
                raise RuntimeError("restarted broker QMP handshake timed out")
            expect(json.loads(broker.stdout.readline()), True,
                   "R26_RESTARTED_GO_BROKER_QMP_CONNECTED")
            denied = send(broker, {"op": "reserve", "actor": "rogue"})
            expect(denied, False, "R26_UNAUTHORIZED_ACTOR_DENIED")
            grant = send(broker, {"op": "reserve", "actor": "approved-agent"})
            expect(grant, True, "R26_GO_EXCLUSIVE_LEASE_GRANTED")
            generation, epoch = grant["generation"], grant["epoch"]
            if generation != old_generation or epoch == old_epoch or len(epoch) != 32:
                raise RuntimeError("restart epoch isolation precondition failed")
            replay = send(broker, {
                "op": "attach", "actor": "approved-agent",
                "generation": old_generation, "epoch": old_epoch})
            expect(replay, False, "R26_RESTARTED_BROKER_REJECTED_OLD_LEASE")
            bad = send(broker, {"op": "attach", "actor": "rogue",
                                "generation": generation, "epoch": epoch})
            expect(bad, False, "R26_ATTACH_WRONG_ACTOR_DENIED")
            attached = send(broker, {"op": "attach", "actor": "approved-agent",
                                     "generation": generation, "epoch": epoch})
            expect(attached, True, "R26_GO_TO_QMP_USB_THREE_DEVICES_ATTACHED")
            started = send(broker, {"op": "start", "actor": "approved-agent",
                                    "generation": generation, "epoch": epoch})
            expect(started, True, "R26_GUEST_STARTED_AFTER_AUTHORIZED_ATTACH")
            stale = send(broker, {"op": "input", "actor": "approved-agent",
                                  "generation": 0, "epoch": epoch,
                                  "command": "key-a-down"})
            expect(stale, False, "R26_STALE_GENERATION_INPUT_DENIED")
            chunks = []
            partial = b""
            injected = False
            revoked = False
            deadline = time.monotonic() + 150
            while time.monotonic() < deadline:
                rd, _, _ = select.select([vm.stdout], [], [], 0.35)
                if rd:
                    raw = os.read(vm.stdout.fileno(), 65536)
                    if raw:
                        chunks.append(raw)
                        partial += raw
                        while b"\n" in partial:
                            line, partial = partial.split(b"\n", 1)
                            if b"R15_GUEST_HID_OBSERVER_READY=PASS" in line and not injected:
                                down = send(broker, {
                                    "op": "input", "actor": "approved-agent",
                                    "generation": generation, "epoch": epoch, "command": "key-a-down"})
                                expect(down, True, "R26_GO_FENCED_KEY_DOWN_SUBMITTED")
                                time.sleep(0.30)
                                release = send(broker, {
                                    "op": "revoke", "actor": "approved-agent",
                                    "generation": generation, "epoch": epoch})
                                expect(release, True, "R26_GO_QMP_RELEASE_ON_REVOKE")
                                revoked = True
                                after = send(broker, {
                                    "op": "input", "actor": "approved-agent",
                                    "generation": generation, "epoch": epoch, "command": "key-a-down"})
                                expect(after, False, "R26_GO_POST_REVOKE_INPUT_DENIED")
                                injected = True
                    elif vm.poll() is not None:
                        break
                elif vm.poll() is not None:
                    break
            if vm.poll() is None:
                vm.kill()
                vm.wait(timeout=5)
                raise RuntimeError("actual Linux guest did not terminate in time")
            output = b"".join(chunks).decode("utf-8", "replace")
            markers = [
                "R15_GUEST_PID1_STARTED=PASS",
                "R15_GUEST_USB_ALL_THREE_ENUMERATED=PASS",
                "R15_GUEST_HID_OBSERVER_READY=PASS",
                "R15_GUEST_USB_KEY_A_DOWN=PASS",
                "R15_GUEST_USB_KEY_A_UP=PASS",
                "R15_REAL_USB_KEY_A_DOWN_AND_UP_OBSERVED=PASS",
            ]
            for line in output.splitlines():
                if line.startswith("R15_GUEST_USB_KEY_") or "R15_REAL_USB_KEY_A_DOWN_AND_UP_OBSERVED" in line:
                    print(line[:240], flush=True)
            missing = [mark for mark in markers if mark not in output]
            if missing or not injected or not revoked or vm.returncode != 0:
                print("R26_MISSING_GUEST_ORACLE=" + str(missing), flush=True)
                print("R26_GUEST_TAIL=" + output[-1500:].replace("\n", ";"), flush=True)
                raise RuntimeError("integrated real guest HID oracle failed")
            print("R26_REAL_LINUX_GUEST_SAW_FENCED_GO_INPUT_AND_REVOKE=PASS", flush=True)
            if not pcap.is_file():
                raise RuntimeError("integrated QEMU PCAP missing")
            blob = pcap.read_bytes()
            if len(blob) <= 24 or blob[:4] not in (
                bytes.fromhex("d4c3b2a1"), bytes.fromhex("a1b2c3d4"),
                bytes.fromhex("4d3cb2a1"), bytes.fromhex("a1b23c4d")
            ):
                raise RuntimeError("integrated PCAP has no actual captured records")
            print("R26_REAL_GUEST_USB_PCAP_RECORDS=PASS bytes=" + str(len(blob)) +
                  " sha256=" + hashlib.sha256(blob).hexdigest(), flush=True)
            if hashlib.sha256(media.read_bytes()).hexdigest() != old_hash:
                raise RuntimeError("synthetic read-only USB storage changed")
            print("R26_SYNTHETIC_STORAGE_UNCHANGED=PASS", flush=True)
            print("R26_CROSS_HOST_FENCING_AND_PHYSICAL_USB=NOT_TESTED", flush=True)
        finally:
            if not broker.stdin.closed:
                broker.stdin.close()
            if broker.poll() is None:
                broker.terminate()
                try:
                    broker.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    broker.kill()
                    broker.wait()
            if vm.poll() is None:
                vm.terminate()
                try:
                    vm.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    vm.kill()
                    vm.wait()

if __name__ == "__main__":
    main()
