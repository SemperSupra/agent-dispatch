#!/usr/bin/env python3
"""R27-H5 actual QEMU protected socket + distinct UID broker proof.

Synthetic container test, root harness only for launching identities. Production
host service custody, root compromise and same-UID attacker remain NOT TESTED.
"""
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
from r27c_signed_guest_oracle import Lines,stop

SERVICE=65532
CLIENT=65533

def as_uid(uid):
    def drop():
        os.setgroups([])
        os.setgid(uid)
        os.setuid(uid)
    return drop

def launch(argv,uid):
    return subprocess.Popen(argv,preexec_fn=as_uid(uid),stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,stderr=subprocess.STDOUT)

def run_client(argv,uid):
    return subprocess.run(argv,preexec_fn=as_uid(uid),capture_output=True,
        text=True,timeout=12)

def service_chmod(path,mode):
    # The unprivileged service owns these sockets; harness root does not
    # have CAP_DAC_OVERRIDE and must not chmod through a 0700 service dir.
    cmd=["python3","-c","import os,sys; os.chmod(sys.argv[1],int(sys.argv[2],8))",str(path),oct(mode)]
    result=run_client(cmd,SERVICE)
    if result.returncode!=0:
        raise RuntimeError("service chmod failed: "+repr(result.stderr))

def service_hash(path):
    cmd=["python3","-c","import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())",str(path)]
    result=run_client(cmd,SERVICE)
    if result.returncode!=0:raise RuntimeError("service hash failed: "+result.stderr)
    return result.stdout.strip()

def stop_service(proc):
    if proc is None or proc.poll() is not None:return
    cmd=["python3","-c","import os,signal,sys;os.kill(int(sys.argv[1]),signal.SIGKILL)",str(proc.pid)]
    result=run_client(cmd,SERVICE)
    if result.returncode!=0:raise RuntimeError("service failed to stop child: "+result.stderr)
    proc.wait(timeout=7)

def raw_connect_check(path):
    # Run the raw-QMP connector in a genuinely distinct process/UID.
    probe='import socket,sys; s=socket.socket(socket.AF_UNIX);s.settimeout(3);s.connect(sys.argv[1]);print("RAW_QMP_CONNECTED")'
    return run_client(["python3","-c",probe,str(path)],CLIENT)

def main():
    if os.geteuid()!=0:raise RuntimeError("disposable test requires root harness")
    with tempfile.TemporaryDirectory(prefix="r27h5-qmp-dac-",dir="/tmp") as d:
        root=Path(d);root.chmod(0o711)
        secret=root/"controller-only";secret.mkdir(mode=0o700)
        media=secret/"media.img"; media.write_bytes(b"R27H5-PUBLIC-TEST-ONLY"+bytes(1024*1024))
        digest=hashlib.sha256(media.read_bytes()).hexdigest()
        os.chown(media,SERVICE,SERVICE)
        os.chown(secret,SERVICE,SERVICE)
        api_root=root/"broker";api_root.mkdir(mode=0o755)
        os.chown(api_root,SERVICE,SERVICE)
        journal=secret/"held.json";capture=secret/"capture.pcap"
        qmp=secret/"qmp.sock";api=api_root/"api.sock"
        qemu=actuator=None
        try:
            qemu=launch(["qemu-system-x86_64","-machine","q35",
                "-accel","tcg","-cpu","qemu64","-m","512M","-smp","1",
                "-S","-nodefaults","-display","none","-monitor","none",
                "-serial","none","-net","none","-no-reboot",
                "-device","qemu-xhci,id=xhci0",
                "-qmp","unix:"+str(qmp)+",server=on,wait=off"],SERVICE)
            actuator=launch(["/guest/r26-actuator","--qmp",str(qmp),
                "--socket",str(api),"--media",str(media),"--capture",str(capture),
                "--journal",str(journal),"--authorized-peer-uid",str(CLIENT),
                "--permitted-operations","status,ports"],SERVICE)
            Lines(actuator).wait("R26_L_SOLE_QMP_ACTUATOR_LISTENING=PASS",25)
            print("R27H5_ACTUAL_QEMU_AND_CONTROLLER_SERVICE_UID_BOUND=PASS",flush=True)
            # An intentionally permissive socket must still be inaccessible through
            # its protected ancestor. This checks actual kernel DAC on real QEMU.
            service_chmod(qmp,0o666)
            before=raw_connect_check(qmp)
            if before.returncode==0 or "Permission denied" not in before.stderr:
                raise RuntimeError("P0: client reached raw QMP: "+repr((before.returncode,before.stderr)))
            print("R27H5_DISTINCT_UID_RAW_REAL_QMP_DENIED=PASS",flush=True)
            # Only expose the broker socket to a distinct principal. SO_PEERCRED
            # and the host allowlist must admit status/ports and reject reserve.
            service_chmod(api,0o666)
            for op in ("status","ports"):
                result=run_client(["/guest/r26ctl","--socket",str(api),"--op",op],CLIENT)
                if result.returncode!=0:raise RuntimeError(op+" CLI failed: "+result.stderr)
                obj=json.loads(result.stdout.strip())
                if not obj.get("ok"):raise RuntimeError(op+" returned failure")
                print("R27H5_DISTINCT_UID_READ_ONLY_"+op.upper()+"_ALLOWED=PASS",flush=True)
            # Send a genuine forbidden mutation on the read-only broker.
            denied=subprocess.run(["/guest/r26ctl","--socket",str(api),"--batch"],
                input="reserve\n",text=True,capture_output=True,timeout=10,
                preexec_fn=as_uid(CLIENT))
            if denied.returncode==0 or "outside authenticated peer grant" not in denied.stderr:
                raise RuntimeError("P0 broker mutation not rejected: "+repr((denied.returncode,denied.stderr)))
            print("R27H5_DISTINCT_UID_BROKER_RESERVE_DENIED=PASS",flush=True)
            if service_hash(media)!=digest:
                raise RuntimeError("media modified by denied raw QMP request")
            print("R27H5_MEDIA_UNCHANGED=PASS",flush=True)
            print("R27H5_SAME_UID_HOSTILE_ACTOR=NOT_TESTED",flush=True)
            print("R27H5_PRODUCTION_SERVICE_AUTH=NOT_TESTED",flush=True)
            print("R27H5_MULTI_HOST=NOT_TESTED",flush=True)
        finally:
            for proc in (actuator,qemu):stop_service(proc)
            # Release private service ownership only after killing QEMU and
            # the actuator; root harness has no CAP_DAC_OVERRIDE.
            os.chown(secret,0,0)
            secret.chmod(0o700)
            os.chown(api_root,0,0)
            print("R27H5_DISPOSABLE_QEMU_STOPPED=PASS",flush=True)
if __name__=="__main__":main()
