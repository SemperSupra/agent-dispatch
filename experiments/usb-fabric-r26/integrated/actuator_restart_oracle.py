#!/usr/bin/env python3
"""R26-L3 actual QEMU/Linux guest: actuator SIGKILL followed by journal-based recovery.

Synthetic key A only. The frontend is never supplied the QMP Unix path.
Synthetic process-crash recovery only: the ledger is on ephemeral tmpfs, not resilient to host power loss.
"""
import hashlib
import json
import os
from pathlib import Path
import select
import subprocess
import tempfile
import time

def expect(value, success, label):
    if bool(value.get("ok")) != success:
        raise RuntimeError(label + " unexpected response: " + str(value))
    print(label + "=PASS", flush=True)

def request(frontend, payload, seconds=15):
    frontend.stdin.write(json.dumps(payload) + "\n")
    frontend.stdin.flush()
    ready, _, _ = select.select([frontend.stdout], [], [], seconds)
    if not ready:
        raise RuntimeError("frontend response timeout")
    line = frontend.stdout.readline()
    if not line:
        raise RuntimeError("frontend disconnected")
    return json.loads(line)

def ready(proc, label, seconds=14):
    found, _, _ = select.select([proc.stdout], [], [], seconds)
    if not found:
        raise RuntimeError(label + " readiness timeout")
    line = proc.stdout.readline().strip()
    if label not in line:
        raise RuntimeError("wrong readiness: " + line)
    print(label, flush=True)

def main():
    with tempfile.TemporaryDirectory(prefix="r26-l2-", dir="/tmp") as d:
        media = Path(d) / "media.img"
        marker = b"PUBLIC_R26_SOLE_OWNER_SYNTHETIC"
        media.write_bytes(marker + bytes(2097152-len(marker)))
        original = hashlib.sha256(media.read_bytes()).hexdigest()
        capture = Path(d) / "keyboard.pcap"
        qmp = d + "/qmp.sock"
        api = d + "/actuator.sock"
        api2 = d + "/actuator-recovered.sock"
        journal = Path(d) / "held.json"
        qemu = subprocess.Popen([
            "qemu-system-x86_64", "-machine", "q35", "-accel", "tcg",
            "-cpu", "qemu64", "-m", "1024M", "-smp", "1", "-S",
            "-nodefaults", "-display", "none", "-monitor", "none",
            "-serial", "stdio", "-net", "none", "-no-reboot",
            "-kernel", "/guest/kernel", "-initrd", "/guest/initrd.gz",
            "-append", "console=ttyS0 rdinit=/init loglevel=7 panic=-1",
            "-device", "qemu-xhci,id=xhci0",
            "-qmp", "unix:" + qmp + ",server=on,wait=off",
        ], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT)
        actuator = subprocess.Popen([
            "/guest/r26-actuator", "--qmp", qmp, "--socket", api,
            "--media", str(media), "--capture", str(capture),
            "--journal", str(journal),
        ], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, bufsize=1)
        frontend = None
        competing = None
        recovered_actuator = None
        try:
            ready(actuator, "R26_L_SOLE_QMP_ACTUATOR_LISTENING=PASS")
            frontend = subprocess.Popen([
                "/guest/r26-frontend", "--socket", api,
            ], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, bufsize=1)
            ready(frontend, '"state":"frontend-ready"')
            bad = request(frontend, {"op":"reserve","actor":"unapproved"})
            expect(bad, False, "R26_L_UNAPPROVED_ACTOR_DENIED")
            lease = request(frontend, {"op":"reserve","actor":"approved-agent"})
            expect(lease, True, "R26_L_ACTUATOR_LEASE_GRANTED")
            epoch, generation = lease["epoch"], lease["generation"]

            # A second local client may open the IPC but cannot take control.
            competing = subprocess.Popen([
                "/guest/r26-frontend", "--socket", api,
            ], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, bufsize=1)
            ready(competing, '"state":"frontend-ready"')
            denial = request(competing,{"op":"reserve","actor":"approved-agent"})
            expect(denial, False, "R26_L_COMPETING_FRONTEND_DENIED")
            competing.stdin.close()
            competing.wait(timeout=4)

            unauthorized = request(frontend,{
                "op":"raw-qmp","actor":"approved-agent",
                "epoch":epoch,"generation":generation})
            expect(unauthorized,False,"R26_L_RAW_QMP_FORBIDDEN")
            attached = request(frontend,{
                "op":"attach","actor":"approved-agent",
                "epoch":epoch,"generation":generation})
            expect(attached,True,"R26_L_ACTUATOR_ATTACHED_SYNTHETIC_USB")
            started = request(frontend,{
                "op":"start","actor":"approved-agent",
                "epoch":epoch,"generation":generation})
            expect(started,True,"R26_L_SOLE_ACTUATOR_STARTED_GUEST")

            output_chunks = []
            pending = b""
            sent = killed = False
            until = time.monotonic() + 140
            while time.monotonic() < until:
                readers, _, _ = select.select([qemu.stdout], [], [], 0.4)
                if readers:
                    data = os.read(qemu.stdout.fileno(), 65536)
                    if data:
                        output_chunks.append(data)
                        pending += data
                        while b"\n" in pending:
                            line, pending = pending.split(b"\n", 1)
                            if b"R15_GUEST_HID_OBSERVER_READY=PASS" in line and not sent:
                                cmd = request(frontend,{
                                    "op":"input","actor":"approved-agent",
                                    "epoch":epoch,"generation":generation,
                                    "command":"key-a-down"})
                                expect(cmd,True,"R26_L_FRONTEND_REQUESTED_KEY_DOWN")
                                sent = True
                            if b"R15_GUEST_USB_KEY_A_DOWN=PASS" in line and not killed:
                                actuator.kill()
                                actuator.wait(timeout=4)
                                killed = True
                                print("R26_L3_ACTUATOR_SIGKILL_AFTER_REAL_GUEST_KEY_DOWN=PASS", flush=True)
                                record = json.loads(journal.read_text())
                                if not record.get("held") or record.get("sequence") != 1:
                                    raise RuntimeError("crash did not leave durable held state")
                                print("R26_L3_HELD_KEY_JOURNAL_SURVIVED_ACTUATOR_EXIT=PASS", flush=True)
                                recovered_actuator = subprocess.Popen([
                                    "/guest/r26-actuator", "--qmp", qmp,
                                    "--socket", api2, "--media", str(media),
                                    "--capture", str(capture),
                                    "--journal", str(journal),
                                ],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE,text=True,bufsize=1)
                                stdout,stderr=recovered_actuator.communicate(timeout=15)
                                if recovered_actuator.returncode != 0:
                                    raise RuntimeError("journal recovery failed: " + stderr[-700:])
                                if "R26_L3_ACTUATOR_RESTART_FORCED_QMP_KEY_UP=PASS" not in stdout:
                                    raise RuntimeError("no restarted actuator QMP release confirmation")
                                if "R26_L3_RECOVERY_HOLD_REQUIRES_TOPOLOGY_RECONCILIATION=PASS" not in stdout:
                                    raise RuntimeError("new lease admission not held after crash")
                                if "R26_L3_JOURNAL_REMAINS_HELD_PENDING_GUEST_ATTESTATION=PASS" not in stdout:
                                    raise RuntimeError("QMP-only release incorrectly cleared uncertainty")
                                record = json.loads(journal.read_text())
                                if not record.get("held") or record.get("sequence") != 1:
                                    raise RuntimeError("QMP ACK must NOT clear held state before trusted guest confirmation")
                                print("R26_L3_RECOVERED_ACTUATOR_QMP_RELEASE_AND_ADMISSION_HOLD=PASS",flush=True)
                                print("R26_L3_JOURNAL_REMAINS_QUARANTINED_PENDING_GUEST_ATTESTATION=PASS",flush=True)
                    elif qemu.poll() is not None:
                        break
                elif qemu.poll() is not None:
                    break
            if qemu.poll() is None:
                qemu.kill()
                qemu.wait(timeout=5)
                raise RuntimeError("guest did not finish")
            guest = b"".join(output_chunks).decode("utf-8","replace")
            for line in guest.splitlines():
                if ("R15_GUEST_USB_KEY_A_" in line or
                    "R15_REAL_USB_KEY_A_DOWN_AND_UP_OBSERVED" in line):
                    print(line[:220], flush=True)
            needed = (
                "R15_GUEST_USB_KEY_A_DOWN=PASS",
                "R15_GUEST_USB_KEY_A_UP=PASS",
                "R15_REAL_USB_KEY_A_DOWN_AND_UP_OBSERVED=PASS",
            )
            if not sent or not killed or qemu.returncode != 0 or any(x not in guest for x in needed):
                raise RuntimeError("guest did not independently observe crash recovery key-up")
            print("R26_L3_ACTUAL_GUEST_KEY_UP_AFTER_ACTUATOR_CRASH_RECOVERY=PASS",flush=True)
            if recovered_actuator is None or recovered_actuator.returncode != 0:
                raise RuntimeError("recovered actuator process missing or failed")
            print("R26_L3_JOURNAL_RECOVERY_REAL_GUEST_ORACLE=PASS",flush=True)
            if hashlib.sha256(media.read_bytes()).hexdigest() != original:
                raise RuntimeError("synthetic storage mutated")
            if not capture.exists() or capture.stat().st_size <= 24:
                raise RuntimeError("QEMU USB capture records missing")
            b = capture.read_bytes()
            print("R26_L_SOLE_ACTUATOR_USB_PCAP=PASS bytes=" +
                  str(len(b)) + " sha256=" + hashlib.sha256(b).hexdigest(),flush=True)
            print("R26_L3_HOST_POWER_LOSS_DURABILITY=NOT_TESTED",flush=True)
            print("R26_L3_PRODUCTION_AUTH_AND_REAL_USBIP=NOT_TESTED",flush=True)
        finally:
            for proc in (competing,frontend,actuator,recovered_actuator,qemu):
                if proc is not None and proc.poll() is None:
                    proc.kill()
                    proc.wait(timeout=5)

if __name__=="__main__":
    main()
