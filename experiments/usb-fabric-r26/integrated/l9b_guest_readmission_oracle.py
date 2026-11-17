#!/usr/bin/env python3
"""R26-L9B: actual QEMU Linux evdev => trusted-TEST-ONLY virtio receipt
=> host actuator verifies QMP+receipt => fsynced journal => fresh lease.

The guest MAC key is PUBLIC TEST-ONLY. This is never production attestation.
No physical devices, network API, host device access, passwords or secrets.
"""
import hashlib
import json
import os
from pathlib import Path
import select
import subprocess
import tempfile
import threading
import time

class Lines:
    """Continuously drain a real process' stdout without false readiness."""
    def __init__(self, proc):
        self.proc=proc
        self.cv=threading.Condition()
        self.lines=[]
        self.done=False
        threading.Thread(target=self.drain,daemon=True).start()
    def drain(self):
        pending=b""
        try:
            while True:
                data=os.read(self.proc.stdout.fileno(),65536)
                if not data:
                    break
                pending+=data
                while b"\n" in pending:
                    line,pending=pending.split(b"\n",1)
                    decoded=line.decode("utf-8","replace").strip()
                    with self.cv:
                        self.lines.append(decoded)
                        if len(self.lines)>4000:self.lines=self.lines[-2000:]
                        self.cv.notify_all()
        finally:
            with self.cv:
                self.done=True
                self.cv.notify_all()
    def wait(self,marker,timeout=140):
        deadline=time.monotonic()+timeout
        with self.cv:
            while not any(marker in line for line in self.lines):
                left=deadline-time.monotonic()
                if left<=0 or self.done:
                    raise RuntimeError("missing live marker "+marker+
                        "; tail="+repr(self.lines[-16:]))
                self.cv.wait(min(0.8,left))
        print(marker,flush=True)

def ready(proc,label,seconds=15):
    limit=time.monotonic()+seconds
    while time.monotonic()<limit:
        if proc.poll() is not None:
            raise RuntimeError("frontend closed before readiness "+label)
        readable,_,_=select.select([proc.stdout],[],[],0.2)
        if readable:
            line=proc.stdout.readline()
            if label not in line:
                raise RuntimeError("unexpected frontend readiness "+line)
            return
    raise RuntimeError("frontend readiness timeout "+label)

def request(proc,payload,timeout=15):
    proc.stdin.write(json.dumps(payload)+"\n")
    proc.stdin.flush()
    readable,_,_=select.select([proc.stdout],[],[],timeout)
    if not readable:
        raise RuntimeError("frontend response timeout "+payload["op"])
    line=proc.stdout.readline()
    if not line:
        raise RuntimeError("frontend closed during "+payload["op"])
    return json.loads(line)

def expect(result,ok,label):
    if bool(result.get("ok"))!=ok:
        raise RuntimeError(label+" unexpected result "+repr(result))
    print(label+"=PASS",flush=True)

def stop(proc):
    if proc is not None and proc.poll() is None:
        proc.kill()
        proc.wait(timeout=7)

def main():
    with tempfile.TemporaryDirectory(prefix="r26-l9b-",dir="/tmp") as d:
        root=Path(d)
        media=root/"media.img"
        marker=b"R26-L9B-PUBLIC-SYNTHETIC"
        media.write_bytes(marker+bytes(2097152-len(marker)))
        original=hashlib.sha256(media.read_bytes()).hexdigest()
        journal=root/"held.json"
        capture=root/"usb.pcap"
        qmp=str(root/"qmp.sock")
        receipt=str(root/"receipt.sock")
        api=str(root/"api.sock")
        qemu=actuator=first=second=None
        qlogs=alogs=None
        try:
            qemu=subprocess.Popen([
                "qemu-system-x86_64","-machine","q35","-accel","tcg",
                "-cpu","qemu64","-m","1024M","-smp","1","-S",
                "-nodefaults","-display","none","-monitor","none",
                "-serial","stdio","-net","none","-no-reboot",
                "-kernel","/guest/kernel","-initrd","/guest/initrd.gz",
                "-append","console=ttyS0 rdinit=/init loglevel=7 panic=-1",
                "-device","qemu-xhci,id=xhci0",
                "-device","virtio-serial-pci,id=vs0",
                "-chardev","socket,id=receipt,path="+receipt+",server=on,wait=off",
                "-device","virtserialport,chardev=receipt,name=org.r26.receipts",
                "-qmp","unix:"+qmp+",server=on,wait=off",
            ],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
            qlogs=Lines(qemu)
            actuator=subprocess.Popen([
                "/guest/r26-actuator","--qmp",qmp,"--socket",api,
                "--media",str(media),"--capture",str(capture),
                "--journal",str(journal),"--receipt",receipt,
            ],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
              stderr=subprocess.STDOUT)
            alogs=Lines(actuator)
            alogs.wait("R26_L_SOLE_QMP_ACTUATOR_LISTENING=PASS",20)
            first=subprocess.Popen([
                "/guest/r26-frontend","--socket",api,
            ],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
              stderr=subprocess.PIPE,text=True,bufsize=1)
            ready(first,'"state":"frontend-ready"')
            lease=request(first,{"op":"reserve","actor":"approved-agent"})
            expect(lease,True,"R26_L9B_INITIAL_LEASE")
            base={"actor":"approved-agent","epoch":lease["epoch"],
                  "generation":lease["generation"]}
            expect(request(first,dict(base,op="attach")),True,"R26_L9B_GUEST_USB_ATTACHED")
            expect(request(first,dict(base,op="start")),True,"R26_L9B_GUEST_BOOTED_BY_ACTUATOR")
            qlogs.wait("R26_L8_REAL_GUEST_VIRTIO_EVDEV_OBSERVER_READY=PASS")
            expect(request(first,dict(base,op="input",command="key-a-down")),
                   True,"R26_L9B_FIRST_HOST_QMP_KEY_DOWN")
            alogs.wait("R26_L9B_FIRST_REAL_GUEST_EVDEV_DOWN_VERIFIED=PASS")
            held=json.loads(journal.read_text())
            if not held.get("held") or held.get("sequence")!=1:
                raise RuntimeError("host did not write-ahead durable key down")
            print("R26_L9B_REAL_GUEST_DOWN_HELD_JOURNAL=PASS",flush=True)
            first.kill()
            first.wait(timeout=5)
            first=None
            print("R26_L9B_FRONTEND_SIGKILL_AFTER_REAL_GUEST_DOWN=PASS",flush=True)
            alogs.wait("R26_L9B_REAL_GUEST_VERIFIED_RELEASE_FSYNC_AND_READMISSION=PASS",35)
            released=json.loads(journal.read_text())
            if released.get("held") or released.get("sequence")!=2 or (
                released.get("last_release_event_sequence")!=11 or
                len(released.get("last_release_proof_hash",""))!=64 or
                released.get("release_phase","")!=""):
                raise RuntimeError("guest UP did not durably clear held journal: "+repr(released))
            print("R26_L9B_ACTUAL_GUEST_UP_FSYNCED_HELD_FALSE=PASS",flush=True)

            second=subprocess.Popen([
                "/guest/r26-frontend","--socket",api,
            ],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
              stderr=subprocess.PIPE,text=True,bufsize=1)
            ready(second,'"state":"frontend-ready"')
            fresh=request(second,{"op":"reserve","actor":"approved-agent"})
            expect(fresh,True,"R26_L9B_NEW_FRONTEND_RE_ADMITTED_AFTER_GUEST_PROOF")
            if fresh["generation"]==lease["generation"] or fresh["epoch"]!=lease["epoch"]:
                raise RuntimeError("lease generation not advanced or actor epoch changed")
            new={"actor":"approved-agent","epoch":fresh["epoch"],
                 "generation":fresh["generation"]}
            expect(request(second,dict(new,op="attach")),True,
                   "R26_L9B_SECOND_GUEST_LEASE_ATTACHED")
            expect(request(second,dict(new,op="start")),True,
                   "R26_L9B_SECOND_GUEST_LEASE_STARTED")
            expect(request(second,dict(new,op="input",command="key-a-down")),
                   True,"R26_L9B_SECOND_HOST_KEY_DOWN")
            qlogs.wait("R26_L9B_SECOND_ACTUAL_GUEST_EVDEV_DOWN=PASS",25)
            # The test L8 guest has only first-lease scope. It must NOT be
            # trusted to release the second lease (scope/sequence mismatch).
            up=request(second,dict(new,op="input",command="key-a-up"))
            expect(up,False,"R26_L9B_SECOND_UNSCOPED_RELEASE_QUARANTINED")
            qlogs.wait("R26_L9B_SECOND_ACTUAL_GUEST_EVDEV_UP=PASS",25)
            again=json.loads(journal.read_text())
            if not again.get("held") or again.get("sequence")!=3:
                raise RuntimeError("second lease released without newly scoped proof")
            print("R26_L9B_SECOND_RELEASE_REQUIRES_NEW_SCOPED_PROOF=PASS",flush=True)
            if hashlib.sha256(media.read_bytes()).hexdigest()!=original:
                raise RuntimeError("synthetic storage content mutated")
            if not capture.exists() or capture.stat().st_size<=24:
                raise RuntimeError("real QEMU USB pcap missing")
            print("R26_L9B_ACTUAL_QEMU_USB_PCAP=PASS bytes="+str(capture.stat().st_size),flush=True)
            print("R26_L9B_SAME_RUN_FIRST_VERIFIED_RELEASE_SECOND_LEASE=PASS",flush=True)
            print("R26_L9B_TEST_ONLY_PUBLIC_MAC_PRODUCTION_AUTH=NOT_TESTED",flush=True)
            print("R26_L9B_SECOND_LEASE_PROOF_AND_DETACH=NOT_TESTED",flush=True)
        finally:
            for p in (second,first,actuator,qemu):stop(p)
            print("R26_L9B_ALL_SYNTHETIC_PROCESSES_STOPPED=PASS",flush=True)

if __name__=="__main__":
    main()
