#!/usr/bin/env python3
"""R27-F independent real-QEMU negative: wrong host-pinned guest public key.
The guest signs real Linux KEY_A events, but the host MUST refuse them,
retain the fsynced held journal and deny re-admission. No production keys.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

from r27c_signed_guest_oracle import Lines,ready,request,expect,stop

def main():
    with tempfile.TemporaryDirectory(prefix="r27f-wrong-key-",dir="/tmp") as temp:
        root=Path(temp)
        media=root/"media.img"
        data=b"R27F-PUBLIC-TEST-ONLY"
        media.write_bytes(data+bytes(2097152-len(data)))
        expected=hashlib.sha256(media.read_bytes()).hexdigest()
        wrong=root/"wrong-pinned-public"
        original=Path("/guest/r27-guest-public").read_bytes()
        if len(original)!=32:
            raise RuntimeError("host image-builder expected public key absent")
        for i in range(5):
            wrong_bytes=os.urandom(32)
            if wrong_bytes!=original:break
        else:
            raise RuntimeError("could not generate distinct fake host-pinned key")
        wrong.write_bytes(wrong_bytes)
        wrong.chmod(0o600)
        qmp=str(root/"qmp.sock")
        receipt=str(root/"receipt.sock")
        api=str(root/"api.sock")
        journal=root/"journal.json"
        capture=root/"capture.pcap"
        qemu=actuator=first=second=None
        try:
            qemu=subprocess.Popen([
                "qemu-system-x86_64","-machine","q35","-accel","tcg",
                "-cpu","qemu64","-m","1024M","-smp","1","-S",
                "-nodefaults","-display","none","-monitor","none",
                "-serial","stdio","-net","none","-no-reboot",
                "-kernel","/guest/kernel","-initrd","/guest/initrd.gz",
                "-append","console=ttyS0 rdinit=/init loglevel=7 panic=-1 r27_signed=1",
                "-device","qemu-xhci,id=xhci0",
                "-device","virtio-serial-pci,id=vs0",
                "-chardev","socket,id=receipt,path="+receipt+",server=on,wait=off",
                "-device","virtserialport,chardev=receipt,name=org.r26.receipts",
                "-qmp","unix:"+qmp+",server=on,wait=off",
            ],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
              stderr=subprocess.STDOUT)
            qlog=Lines(qemu)
            actuator=subprocess.Popen([
                "/guest/r26-actuator","--qmp",qmp,"--socket",api,
                "--media",str(media),"--capture",str(capture),
                "--journal",str(journal),"--receipt",receipt,
                "--scoped-receipts","--runtime-guest-public",str(wrong),
            ],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
              stderr=subprocess.STDOUT)
            alog=Lines(actuator)
            alog.wait("R26_L_SOLE_QMP_ACTUATOR_LISTENING=PASS",20)
            first=subprocess.Popen(
                ["/guest/r26-frontend","--socket",api],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,text=True,bufsize=1)
            ready(first,'"state":"frontend-ready"')
            lease=request(first,{"op":"reserve","actor":"approved-agent"})
            expect(lease,True,"R27F_INITIAL_SYNTHETIC_LEASE")
            args={"actor":"approved-agent",
                  "epoch":lease["epoch"],"generation":lease["generation"]}
            expect(request(first,dict(args,op="attach")),True,
                   "R27F_SYNTHETIC_KEYBOARD_ATTACHED")
            expect(request(first,dict(args,op="start")),True,
                   "R27F_REAL_GUEST_BOOTED")
            qlog.wait("R27C_REAL_LINUX_ED25519_EVDEV_READY=PASS")
            qlog.wait("R27C_GUEST_HOST_CHALLENGE_BOUND=PASS")
            expect(request(first,dict(args,op="input",command="key-a-down")),True,
                   "R27F_REAL_QMP_KEY_A_DOWN")
            qlog.wait("R27C_REAL_SIGNED_GUEST_DOWN=PASS cycle=1",25)
            # The real guest DID sign and send; the mismatched trusted
            # public key must prevent its admission as host proof.
            if any("R27C_REAL_ED25519_GUEST_DOWN_VERIFIED=PASS" in line
                   for line in alog.lines):
                raise RuntimeError("P0: wrong pinned key verified guest DOWN")
            held=json.loads(journal.read_text())
            if not held.get("held") or held.get("sequence")!=1:
                raise RuntimeError("write-ahead held journal absent before SIGKILL")
            first.kill();first.wait(timeout=5);first=None
            alog.wait("R26_L_ACK_ONLY_RELEASE_QUARANTINED_PENDING_GUEST_PROOF=PASS",30)
            qlog.wait("R27C_REAL_SIGNED_GUEST_UP=PASS cycle=1",20)
            held=json.loads(journal.read_text())
            if not held.get("held") or held.get("sequence")!=1:
                raise RuntimeError("P0: forged authenticated guest release cleared journal")
            if held.get("release_phase")!="qmp-acked":
                raise RuntimeError("QMP ACK stage not durable; cannot distinguish failed proof")
            print("R27F_WRONG_PINNED_KEY_HELD_JOURNAL_REMAINS_QUARANTINED=PASS",flush=True)
            second=subprocess.Popen(
                ["/guest/r26-frontend","--socket",api],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,text=True,bufsize=1)
            ready(second,'"state":"frontend-ready"')
            denied=request(second,{"op":"reserve","actor":"approved-agent"})
            expect(denied,False,"R27F_WRONG_PINNED_KEY_FRESH_LEASE_DENIED")
            if any("R27C_ACTUAL_ED25519_UP_FSYNC_AND_READMISSION=PASS" in line
                   for line in alog.lines):
                raise RuntimeError("P0: untrusted guest UP authorized readmission")
            if hashlib.sha256(media.read_bytes()).hexdigest()!=expected:
                raise RuntimeError("synthetic media mutated")
            print("R27F_REAL_GUEST_WRONG_KEY_FAIL_CLOSED=PASS",flush=True)
            print("R27F_EXTRACTABLE_TEST_IMAGE_PRODUCTION_ATTESTATION=NOT_TESTED",flush=True)
        finally:
            for p in (second,first,actuator,qemu):stop(p)
            print("R27F_ALL_DISPOSABLE_PROCESSES_STOPPED=PASS",flush=True)

if __name__=="__main__":
    main()
