#!/usr/bin/env python3
"""R26-L9C: actual QEMU Linux evdev => trusted-TEST-ONLY virtio receipt
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

def control_snapshot(api,op,expected_state,expected_occupied,expected_held):
    result=subprocess.run(
        ["/guest/r26ctl","--socket",api,"--op",op],
        capture_output=True,text=True,timeout=12,check=False)
    if result.returncode!=0:
        raise RuntimeError("r26ctl "+op+" failed: "+result.stderr[-500:])
    response=json.loads(result.stdout.strip())
    if not response.get("ok"):
        raise RuntimeError("r26ctl "+op+" denied "+repr(response))
    ports=response.get("ports") if op=="ports" else [response.get("port")]
    if not isinstance(ports,list) or len(ports)!=1:
        raise RuntimeError("incorrect one-port controller schema "+repr(response))
    port=ports[0]
    if (port.get("protocol")!="usb-fabric-r27/v1" or
        port.get("id")!="xhci0/auto" or
        port.get("device")!="keyboard" or
        port.get("state")!=expected_state or
        port.get("occupied")!=expected_occupied or
        port.get("held")!=expected_held or
        port.get("credential_mode")!="linux-so-peercred-uid"):
        raise RuntimeError("controller status contract incorrect "+repr(port))
    if "qmp" in json.dumps(port).lower() or "private_key" in json.dumps(port).lower():
        raise RuntimeError("privileged internal data leaked to CLI")
    print("R27_REAL_QEMU_GUARDED_"+op.upper()+"_"+expected_state.upper()+"=PASS",flush=True)

def stop(proc):
    if proc is not None and proc.poll() is None:
        proc.kill()
        proc.wait(timeout=7)

def main():
    with tempfile.TemporaryDirectory(prefix="r26-l9c-",dir="/tmp") as d:
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
        qemu=actuator=first=second=third=None
        qlogs=alogs=None
        try:
            qemu=subprocess.Popen([
                "qemu-system-x86_64","-machine","q35","-accel","tcg",
                "-cpu","qemu64","-m","1024M","-smp","1","-S",
                "-nodefaults","-display","none","-monitor","none",
                "-serial","stdio","-net","none","-no-reboot",
                "-kernel","/guest/kernel","-initrd","/guest/initrd.gz",
                "-append","console=ttyS0 rdinit=/init loglevel=7 panic=-1 r26_scoped=1",
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
                "--journal",str(journal),"--receipt",receipt,"--scoped-receipts",
                "--authorized-peer-uid","65532",
            ],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
              stderr=subprocess.STDOUT)
            alogs=Lines(actuator)
            alogs.wait("R26_L_SOLE_QMP_ACTUATOR_LISTENING=PASS",20)
            control_snapshot(api,"status","available",False,False)
            control_snapshot(api,"ports","available",False,False)
            first=subprocess.Popen([
                "/guest/r26-frontend","--socket",api,
            ],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
              stderr=subprocess.PIPE,text=True,bufsize=1)
            ready(first,'"state":"frontend-ready"')
            lease=request(first,{"op":"reserve","actor":"approved-agent"})
            expect(lease,True,"R26_L9C_INITIAL_LEASE")
            base={"actor":"approved-agent","epoch":lease["epoch"],
                  "generation":lease["generation"]}
            expect(request(first,dict(base,op="attach")),True,"R26_L9C_GUEST_USB_ATTACHED")
            expect(request(first,dict(base,op="start")),True,"R26_L9C_GUEST_BOOTED_BY_ACTUATOR")
            qlogs.wait("R26_L8_REAL_GUEST_VIRTIO_EVDEV_OBSERVER_READY=PASS")
            qlogs.wait("R26_L9C_GUEST_PER_LEASE_SCOPE_BOUND=PASS")
            alogs.wait("R26_L9C_HOST_PER_LEASE_SCOPE_BOUND=PASS generation="+str(lease["generation"])+" release=1")
            expect(request(first,dict(base,op="input",command="key-a-down")),
                   True,"R26_L9C_FIRST_HOST_QMP_KEY_DOWN")
            alogs.wait("R26_L9C_REAL_GUEST_DOWN_SCOPE_VERIFIED=PASS generation="+str(lease["generation"]))
            held=json.loads(journal.read_text())
            if not held.get("held") or held.get("sequence")!=1:
                raise RuntimeError("host did not write-ahead durable key down")
            print("R26_L9C_REAL_GUEST_DOWN_HELD_JOURNAL=PASS",flush=True)
            first.kill()
            first.wait(timeout=5)
            first=None
            print("R26_L9C_FRONTEND_SIGKILL_AFTER_REAL_GUEST_DOWN=PASS",flush=True)
            alogs.wait("R26_L9C_REAL_GUEST_UP_FSYNC_AND_RELEASE=PASS generation="+str(lease["generation"])+" release=1",35)
            released=json.loads(journal.read_text())
            if released.get("held") or released.get("sequence")!=2 or (
                released.get("last_release_event_sequence")!=11 or
                len(released.get("last_release_proof_hash",""))!=64 or
                released.get("release_phase","")!=""):
                raise RuntimeError("guest UP did not durably clear held journal: "+repr(released))
            print("R26_L9C_ACTUAL_GUEST_UP_FSYNCED_HELD_FALSE=PASS",flush=True)

            second=subprocess.Popen([
                "/guest/r26-frontend","--socket",api,
            ],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
              stderr=subprocess.PIPE,text=True,bufsize=1)
            ready(second,'"state":"frontend-ready"')
            fresh=request(second,{"op":"reserve","actor":"approved-agent"})
            expect(fresh,True,"R26_L9C_NEW_FRONTEND_RE_ADMITTED_AFTER_GUEST_PROOF")
            if fresh["generation"]==lease["generation"] or fresh["epoch"]!=lease["epoch"]:
                raise RuntimeError("lease generation not advanced or actor epoch changed")
            new={"actor":"approved-agent","epoch":fresh["epoch"],
                 "generation":fresh["generation"]}
            expect(request(second,dict(new,op="attach")),True,
                   "R26_L9C_SECOND_GUEST_LEASE_ATTACHED")
            expect(request(second,dict(new,op="start")),True,
                   "R26_L9C_SECOND_GUEST_LEASE_STARTED")
            alogs.wait("R26_L9C_HOST_PER_LEASE_SCOPE_BOUND=PASS generation="+str(fresh["generation"])+" release=3")
            qlogs.wait("R26_L9C_GUEST_REPLAYED_OLD_SCOPE_SENT=PASS")
            alogs.wait("R26_L9C_REPLAYED_OLD_LEASE_RECEIPT_REJECTED=PASS")
            expect(request(second,dict(new,op="input",command="key-a-down")),
                   True,"R26_L9C_SECOND_HOST_KEY_DOWN")
            qlogs.wait("R26_L9C_SECOND_ACTUAL_GUEST_EVDEV_DOWN=PASS",25)
            # Each distinct lease requires its own scoped signed DOWN and
            # UP; a QMP ACK alone must remain untrusted.
            up=request(second,dict(new,op="input",command="key-a-up"))
            expect(up,False,"R26_L9C_SECOND_QMP_ACK_ALONE_DENIED")
            qlogs.wait("R26_L9C_SECOND_ACTUAL_GUEST_EVDEV_UP=PASS",25)
            alogs.wait("R26_L9C_REAL_GUEST_UP_FSYNC_AND_RELEASE=PASS generation="+str(fresh["generation"])+" release=3",35)
            again=json.loads(journal.read_text())
            if (again.get("held") or again.get("sequence")!=4 or
                again.get("release_phase","")!="" or
                again.get("last_release_event_sequence")!=13 or
                len(again.get("last_release_proof_hash",""))!=64 or
                again.get("last_release_proof_hash")==released.get("last_release_proof_hash")):
                raise RuntimeError("second lease guest proof failed to fsync clean: "+repr(again))
            print("R26_L9C_SECOND_DISTINCT_LEASE_UP_FSYNCED=PASS",flush=True)
            # Detach is a separate, fail-closed port transition: manager
            # quarantines BEFORE QMP device_del; DEVICE_DELETED is required.
            expect(request(second,dict(new,op="detach")),True,
                   "R26_L9C_KEYBOARD_DEVICE_DEL_REQUEST_CONFIRMED")
            alogs.wait("R26_L9C_QMP_DEVICE_DELETED_EVENT=PASS id=r26-l-kbd")
            alogs.wait("R26_L9C_HOST_QMP_KEYBOARD_DETACHED=PASS")
            qlogs.wait("R26_L9C_GUEST_SYSFS_KEYBOARD_DETACHED=PASS",35)
            print("R26_L9C_HOST_AND_GUEST_TOPOLOGY_DETACH_CONVERGED=PASS",flush=True)
            third=subprocess.Popen([
                "/guest/r26-frontend","--socket",api,
            ],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
              stderr=subprocess.PIPE,text=True,bufsize=1)
            ready(third,'"state":"frontend-ready"')
            denied=request(third,{"op":"reserve","actor":"approved-agent"})
            expect(denied,False,"R26_L9C_NO_REASSIGN_DURING_POST_DETACH_QUARANTINE")
            control_snapshot(api,"status","quarantined",True,False)
            control_snapshot(api,"ports","quarantined",True,False)
            print("R27_REAL_QEMU_PEER_GATED_CLI_AND_TOPOLOGY=PASS",flush=True)
            if hashlib.sha256(media.read_bytes()).hexdigest()!=original:
                raise RuntimeError("synthetic storage content mutated")
            if not capture.exists() or capture.stat().st_size<=24:
                raise RuntimeError("real QEMU USB pcap missing")
            print("R26_L9C_ACTUAL_QEMU_USB_PCAP=PASS bytes="+str(capture.stat().st_size),flush=True)
            print("R26_L9C_SAME_RUN_TWO_SCOPED_RELEASES_AND_GUEST_DETACH=PASS",flush=True)
            print("R26_L9C_TEST_ONLY_PUBLIC_MAC_PRODUCTION_AUTH=NOT_TESTED",flush=True)
            print("R26_L9C_SECURE_PER_VM_ATTESTATION_AND_NETWORK_NAMESPACE=NOT_TESTED",flush=True)
        finally:
            for p in (third,second,first,actuator,qemu):stop(p)
            print("R26_L9C_ALL_SYNTHETIC_PROCESSES_STOPPED=PASS",flush=True)

if __name__=="__main__":
    main()
