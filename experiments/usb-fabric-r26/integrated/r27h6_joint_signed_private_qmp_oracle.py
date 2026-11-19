#!/usr/bin/env python3
"""R26-L9C: actual QEMU Linux evdev => trusted-TEST-ONLY virtio receipt
=> host actuator verifies QMP+receipt => fsynced journal => fresh lease.

The guest key is built by the host and the private half is extractable from
the synthetic initramfs. This is NOT measured boot or production attestation.
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
import importlib.util

# Reuse R27-B independently qualified actual CLI test helper, installed
# under its immutable hyphenated Docker path.
spec=importlib.util.spec_from_file_location("r27_broker_helpers","/guest/r27-broker-cli-oracle.py")
helpers=importlib.util.module_from_spec(spec)
spec.loader.exec_module(helpers)
control_snapshot=helpers.control_snapshot  # superseded by protected H6 wrapper

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

# R27-H6: keep host service and client in distinct Linux principals.
SERVICE_UID=65532
CLIENT_UID=65533

def as_uid(uid):
    def drop():
        os.setgroups([])
        os.setgid(uid)
        os.setuid(uid)
    return drop

def user_run(args,uid,**kwargs):
    return subprocess.run(args,preexec_fn=as_uid(uid),timeout=12,**kwargs)

def service_chmod(path,mode):
    command=["python3","-c","import os,sys;os.chmod(sys.argv[1],int(sys.argv[2],8))",
             str(path),oct(mode)]
    result=user_run(command,SERVICE_UID,text=True,capture_output=True)
    if result.returncode!=0:
        raise RuntimeError("service socket chmod failed: "+result.stderr)

def service_json(path):
    code="import pathlib,sys;print(pathlib.Path(sys.argv[1]).read_text())"
    result=user_run(["python3","-c",code,str(path)],SERVICE_UID,
                    text=True,capture_output=True)
    if result.returncode!=0:raise RuntimeError("service journal read failed: "+result.stderr)
    return json.loads(result.stdout)

def service_file_size(path):
    code="import os,sys;print(os.stat(sys.argv[1]).st_size)"
    result=user_run(["python3","-c",code,str(path)],SERVICE_UID,
                    text=True,capture_output=True)
    if result.returncode!=0:raise RuntimeError("service capture stat failed: "+result.stderr)
    return int(result.stdout.strip())

def service_media_hash(path):
    code="import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())"
    result=user_run(["python3","-c",code,str(path)],SERVICE_UID,
                    text=True,capture_output=True)
    if result.returncode!=0:raise RuntimeError("service media hash failed: "+result.stderr)
    return result.stdout.strip()

def hostile_qmp_denied(path):
    code="import socket,sys;s=socket.socket(socket.AF_UNIX);s.settimeout(3);s.connect(sys.argv[1])"
    result=user_run(["python3","-c",code,str(path)],CLIENT_UID,
                    text=True,capture_output=True)
    if result.returncode==0 or "Permission denied" not in result.stderr:
        raise RuntimeError("P0 raw QMP access was not denied: "+repr((result.returncode,result.stderr)))
    print("R27H6_REAL_QEMU_HOSTILE_RAW_QMP_DENIED=PASS",flush=True)

def protected_control_snapshot(api,op,expected_state,occupied,held):
    result=user_run(["/guest/r26ctl","--socket",api,"--op",op],CLIENT_UID,
                    text=True,capture_output=True)
    if result.returncode!=0:raise RuntimeError("client CLI failed: "+result.stderr)
    response=json.loads(result.stdout.strip())
    if not response.get("ok"):raise RuntimeError("client CLI denied "+repr(response))
    ports=response.get("ports") if op=="ports" else [response.get("port")]
    if not isinstance(ports,list) or len(ports)!=1:
        raise RuntimeError("invalid broker ports "+repr(response))
    p=ports[0]
    if (p.get("state")!=expected_state or p.get("occupied")!=occupied or
        p.get("held")!=held or p.get("credential_mode")!="linux-so-peercred-uid"):
        raise RuntimeError("unexpected protected broker state "+repr(p))
    if "qmp" in json.dumps(p).lower() or "private_key" in json.dumps(p).lower():
        raise RuntimeError("internal QMP data leaked")
    print("R27H6_DISTINCT_UID_BROKER_"+op.upper()+"_"+expected_state.upper()+"=PASS",flush=True)

def stop_as(proc,uid):
    if proc is None or proc.poll() is not None:return
    code="import os,signal,sys;os.kill(int(sys.argv[1]),signal.SIGKILL)"
    r=user_run(["python3","-c",code,str(proc.pid)],uid,text=True,capture_output=True)
    if r.returncode!=0:raise RuntimeError("unable to stop "+str(uid)+" process: "+r.stderr)
    proc.wait(timeout=8)

def main():
    if os.geteuid()!=0:
        raise RuntimeError("disposable identity constructor requires root test harness")
    with tempfile.TemporaryDirectory(prefix="r27h6-signed-protected-",dir="/tmp") as d:
        root=Path(d)
        root.chmod(0o755)
        private=root/"service-qmp"
        private.mkdir(mode=0o700)
        media=root/"media.img"
        marker=b"R26-L9B-PUBLIC-SYNTHETIC"
        media.write_bytes(marker+bytes(2097152-len(marker)))
        original=hashlib.sha256(media.read_bytes()).hexdigest()
        journal=private/"held.json"
        capture=private/"usb.pcap"
        qmp=str(private/"qmp.sock")
        receipt=str(private/"receipt.sock")
        broker_dir=root/"broker"
        broker_dir.mkdir(mode=0o755)
        os.chown(broker_dir,SERVICE_UID,SERVICE_UID)
        api=str(broker_dir/"api.sock")
        os.chown(media,SERVICE_UID,SERVICE_UID)
        os.chown(private,SERVICE_UID,SERVICE_UID)
        qemu=actuator=first=second=third=None
        qlogs=alogs=None
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
            ],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
              preexec_fn=as_uid(SERVICE_UID))
            qlogs=Lines(qemu)
            actuator=subprocess.Popen([
                "/guest/r26-actuator","--qmp",qmp,"--socket",api,
                "--media",str(media),"--capture",str(capture),
                "--journal",str(journal),"--receipt",receipt,"--scoped-receipts",
                "--runtime-guest-public","/guest/r27-guest-public",
                "--authorized-peer-uid","65533",
                "--permitted-operations","status,ports,reserve,attach,start,input,detach",
            ],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
              stderr=subprocess.STDOUT,preexec_fn=as_uid(SERVICE_UID))
            alogs=Lines(actuator)
            alogs.wait("R26_L_SOLE_QMP_ACTUATOR_LISTENING=PASS",20)
            service_chmod(qmp,0o666)
            service_chmod(api,0o666)
            hostile_qmp_denied(qmp)
            protected_control_snapshot(api,"status","available",False,False)
            protected_control_snapshot(api,"ports","available",False,False)
            print("R27E_COMBINED_SIGNED_GUEST_PEER_GATED_AVAILABLE=PASS",flush=True)
            first=subprocess.Popen([
                "/guest/r26-frontend","--socket",api,
            ],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
              stderr=subprocess.PIPE,text=True,bufsize=1,preexec_fn=as_uid(CLIENT_UID))
            ready(first,'"state":"frontend-ready"')
            lease=request(first,{"op":"reserve","actor":"approved-agent"})
            expect(lease,True,"R26_L9C_INITIAL_LEASE")
            base={"actor":"approved-agent","epoch":lease["epoch"],
                  "generation":lease["generation"]}
            expect(request(first,dict(base,op="attach")),True,"R26_L9C_GUEST_USB_ATTACHED")
            expect(request(first,dict(base,op="start")),True,"R26_L9C_GUEST_BOOTED_BY_ACTUATOR")
            qlogs.wait("R27C_REAL_LINUX_ED25519_EVDEV_READY=PASS")
            qlogs.wait("R27C_GUEST_HOST_CHALLENGE_BOUND=PASS")
            alogs.wait("R27C_HOST_BUILDER_GUEST_PUBLIC_KEY_PINNED=PASS")
            alogs.wait("R27C_HOST_FRESH_ED25519_SCOPE_BOUND=PASS generation="+str(lease["generation"])+" release=1")
            expect(request(first,dict(base,op="input",command="key-a-down")),
                   True,"R26_L9C_FIRST_HOST_QMP_KEY_DOWN")
            alogs.wait("R27C_REAL_ED25519_GUEST_DOWN_VERIFIED=PASS generation="+str(lease["generation"]))
            held=service_json(journal)
            if not held.get("held") or held.get("sequence")!=1:
                raise RuntimeError("host did not write-ahead durable key down")
            print("R26_L9C_REAL_GUEST_DOWN_HELD_JOURNAL=PASS",flush=True)
            stop_as(first,CLIENT_UID)
            first=None
            print("R26_L9C_FRONTEND_SIGKILL_AFTER_REAL_GUEST_DOWN=PASS",flush=True)
            alogs.wait("R27C_ACTUAL_ED25519_UP_FSYNC_AND_READMISSION=PASS generation="+str(lease["generation"])+" release=1",35)
            released=service_json(journal)
            if released.get("held") or released.get("sequence")!=2 or (
                released.get("last_release_event_sequence")!=11 or
                len(released.get("last_release_proof_hash",""))!=64 or
                released.get("release_phase","")!=""):
                raise RuntimeError("guest UP did not durably clear held journal: "+repr(released))
            print("R26_L9C_ACTUAL_GUEST_UP_FSYNCED_HELD_FALSE=PASS",flush=True)

            second=subprocess.Popen([
                "/guest/r26-frontend","--socket",api,
            ],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
              stderr=subprocess.PIPE,text=True,bufsize=1,preexec_fn=as_uid(CLIENT_UID))
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
            alogs.wait("R27C_HOST_FRESH_ED25519_SCOPE_BOUND=PASS generation="+str(fresh["generation"])+" release=3")
            qlogs.wait("R27C_GUEST_SIGNED_PRIOR_CHALLENGE_REPLAY_SENT=PASS")
            alogs.wait("R27C_OLD_SIGNED_GUEST_SCOPE_REPLAY_REJECTED=PASS")
            expect(request(second,dict(new,op="input",command="key-a-down")),
                   True,"R26_L9C_SECOND_HOST_KEY_DOWN")
            qlogs.wait("R27C_REAL_SIGNED_GUEST_DOWN=PASS cycle=2",25)
            # Each distinct lease requires its own scoped signed DOWN and
            # UP; a QMP ACK alone must remain untrusted.
            up=request(second,dict(new,op="input",command="key-a-up"))
            expect(up,False,"R26_L9C_SECOND_QMP_ACK_ALONE_DENIED")
            qlogs.wait("R27C_REAL_SIGNED_GUEST_UP=PASS cycle=2",25)
            alogs.wait("R27C_ACTUAL_ED25519_UP_FSYNC_AND_READMISSION=PASS generation="+str(fresh["generation"])+" release=3",35)
            again=service_json(journal)
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
            qlogs.wait("R27C_GUEST_SYSFS_KEYBOARD_ABSENT=PASS",35)
            print("R26_L9C_HOST_AND_GUEST_TOPOLOGY_DETACH_CONVERGED=PASS",flush=True)
            third=subprocess.Popen([
                "/guest/r26-frontend","--socket",api,
            ],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
              stderr=subprocess.PIPE,text=True,bufsize=1,preexec_fn=as_uid(CLIENT_UID))
            ready(third,'"state":"frontend-ready"')
            denied=request(third,{"op":"reserve","actor":"approved-agent"})
            expect(denied,False,"R26_L9C_NO_REASSIGN_DURING_POST_DETACH_QUARANTINE")
            protected_control_snapshot(api,"status","quarantined",True,False)
            protected_control_snapshot(api,"ports","quarantined",True,False)
            print("R27E_COMBINED_SIGNED_GUEST_PEER_GATED_QUARANTINE=PASS",flush=True)
            if service_media_hash(media)!=original:
                raise RuntimeError("synthetic storage content mutated")
            if service_file_size(capture)<=24:
                raise RuntimeError("real QEMU USB pcap missing")
            print("R26_L9C_ACTUAL_QEMU_USB_PCAP=PASS bytes="+str(service_file_size(capture)),flush=True)
            public=Path("/guest/r27-guest-public")
            if not public.is_file() or len(public.read_bytes())!=32:
                raise RuntimeError("host did not independently pin exact 32-byte guest builder public key")
            print("R27C_HOST_PINNED_PUBLIC_KEY_STAGED_OUT_OF_BAND=PASS",flush=True)
            print("R27C_REAL_QEMU_TWO_ED25519_GUEST_RELEASES_AND_DETACH=PASS",flush=True)
            print("R27E_SAME_RUN_ED25519_GUEST_PEER_CAPABILITIES_AND_CLI=PASS",flush=True)
            print("R27H6_PROTECTED_SERVICE_TWO_SIGNED_RELEASES_AND_DETACH=PASS",flush=True)
            print("R27H6_SAME_UID_ATTACKER=NOT_TESTED",flush=True)
            print("R27H6_PRODUCTION_GUEST_ATTESTATION=NOT_TESTED",flush=True)
            print("R27C_EXTRACTABLE_INITRAMFS_PRODUCTION_ATTESTATION=NOT_TESTED",flush=True)
            print("R27C_SEALED_HARDWARE_GUEST_IDENTITY=NOT_TESTED",flush=True)
        finally:
            for p in (third,second,first):stop_as(p,CLIENT_UID)
            for p in (actuator,qemu):stop_as(p,SERVICE_UID)
            os.chown(private,0,0)
            private.chmod(0o700)
            os.chown(broker_dir,0,0)
            print("R26_L9C_ALL_SYNTHETIC_PROCESSES_STOPPED=PASS",flush=True)

if __name__=="__main__":
    main()
