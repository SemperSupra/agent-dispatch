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

def raw_connect_check(path):
    # Run the raw-QMP connector in a genuinely distinct process/UID.
    probe='import socket,sys; s=socket.socket(socket.AF_UNIX);s.settimeout(3);s.connect(sys.argv[1]);print("RAW_QMP_CONNECTED")'
    return run_client(["python3","-c",probe,str(path)],CLIENT)

def main():
    if os.geteuid()!=0:raise RuntimeError("disposable test requires root harness")
    with tempfile.TemporaryDirectory(prefix="r27h5-qmp-dac-",dir="/tmp") as d:
        root=Path(d);root.chmod(0o711)
        secret=root/"controller-only";secret.mkdir(mode=0o700)
        os.chown(secret,SERVICE,SERVICE)
        api_root=root/"broker";api_root.mkdir(mode=0o755)
        os.chown(api_root,SERVICE,SERVICE)
        media=root/"media.img"; media.write_bytes(b"R27H5-PUBLIC-TEST-ONLY"+bytes(1024*1024))
        digest=hashlib.sha256(media.read_bytes()).hexdigest()
        os.chown(media,SERVICE,SERVICE)
        journal=root/"held.json";capture=root/"capture.pcap"
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
            qmp.chmod(0o666)
            before=raw_connect_check(qmp)
            if before.returncode==0 or "Permission denied" not in before.stderr:
                raise RuntimeError("P0: client reached raw QMP: "+repr((before.returncode,before.stderr)))
            print("R27H5_DISTINCT_UID_RAW_REAL_QMP_DENIED=PASS",flush=True)
            # Only expose the broker socket to a distinct principal. SO_PEERCRED
            # and the host allowlist must admit status/ports and reject reserve.
            api.chmod(0o666)
            for op in ("status","ports"):
                result=run_client(["/guest/r26ctl","--socket",str(api),"--op",op],CLIENT)
                if result.returncode!=0:raise RuntimeError(op+" CLI failed: "+result.stderr)
                obj=json.loads(result.stdout.strip())
                if not obj.get("ok"):raise RuntimeError(op+" returned failure")
                print("R27H5_DISTINCT_UID_READ_ONLY_"+op.upper()+"_ALLOWED=PASS",flush=True)
            denied=run_client(["/guest/r26ctl","--socket",str(api),"--batch"],CLIENT)
            # --batch without stdin contains zero requests; use an actual request below.
            denied=subprocess.run(["/guest/r26ctl","--socket",str(api),"--batch"],
                input="reserve\n",text=True,capture_output=True,timeout=10,
                preexec_fn=as_uid(CLIENT))
            if denied.returncode==0 or "outside authenticated peer grant" not in denied.stderr:
                raise RuntimeError("P0 broker mutation not rejected: "+repr((denied.returncode,denied.stderr)))
            print("R27H5_DISTINCT_UID_BROKER_RESERVE_DENIED=PASS",flush=True)
            if hashlib.sha256(media.read_bytes()).hexdigest()!=digest:
                raise RuntimeError("media modified by denied raw QMP request")
            print("R27H5_MEDIA_UNCHANGED=PASS",flush=True)
            print("R27H5_SAME_UID_HOSTILE_ACTOR=NOT_TESTED",flush=True)
            print("R27H5_PRODUCTION_SERVICE_AUTH=NOT_TESTED",flush=True)
            print("R27H5_MULTI_HOST=NOT_TESTED",flush=True)
        finally:
            for proc in (actuator,qemu):stop(proc)
            print("R27H5_DISPOSABLE_QEMU_STOPPED=PASS",flush=True)
if __name__=="__main__":main()
