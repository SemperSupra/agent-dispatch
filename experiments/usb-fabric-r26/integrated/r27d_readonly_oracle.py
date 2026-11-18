#!/usr/bin/env python3
"""R27-D real QEMU local controller with restricted read-only SO_PEERCRED peer.
No guest boot, virtual keyboard input or production credentials required.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

# Reuse the unchanged qualified L9C/R27-B controller test primitives from
# their immutable installed path; Docker intentionally uses a hyphenated file.
import importlib.util
spec=importlib.util.spec_from_file_location("r27_broker_test_helpers","/guest/r27-broker-cli-oracle.py")
helpers=importlib.util.module_from_spec(spec)
spec.loader.exec_module(helpers)
Lines=helpers.Lines
ready=helpers.ready
request=helpers.request
stop=helpers.stop
control_snapshot=helpers.control_snapshot

def main():
    with tempfile.TemporaryDirectory(prefix="r27d-readonly-",dir="/tmp") as temp:
        root=Path(temp)
        media=root/"media.img"
        media.write_bytes(b"R27D-TEST-ONLY"+bytes(1024*1024))
        digest=hashlib.sha256(media.read_bytes()).hexdigest()
        journal=root/"journal.json"
        qmp=root/"qmp.sock"
        sock=root/"controller.sock"
        capture=root/"capture.pcap"
        qemu=controller=frontend=None
        try:
            qemu=subprocess.Popen([
                "qemu-system-x86_64","-machine","q35","-accel","tcg",
                "-cpu","qemu64","-m","1024M","-smp","1","-S",
                "-nodefaults","-display","none","-monitor","none",
                "-serial","stdio","-net","none","-no-reboot",
                "-kernel","/guest/kernel","-initrd","/guest/initrd.gz",
                "-append","console=ttyS0 rdinit=/init loglevel=7 panic=-1",
                "-device","qemu-xhci,id=xhci0",
                "-qmp","unix:"+str(qmp)+",server=on,wait=off",
            ],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
            qlog=Lines(qemu)
            controller=subprocess.Popen([
                "/guest/r26-actuator","--qmp",str(qmp),
                "--socket",str(sock),"--media",str(media),
                "--capture",str(capture),"--journal",str(journal),
                "--authorized-peer-uid","65532",
                "--permitted-operations","status,ports",
            ],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
            log=Lines(controller)
            log.wait("R26_L_SOLE_QMP_ACTUATOR_LISTENING=PASS",25)
            control_snapshot(str(sock),"status","available",False,False)
            control_snapshot(str(sock),"ports","available",False,False)
            print("R27D_REAL_QEMU_READ_ONLY_PEER_CAN_DISCOVER=PASS",flush=True)
            frontend=subprocess.Popen(
                ["/guest/r26-frontend","--socket",str(sock)],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,text=True,bufsize=1)
            ready(frontend,'"state":"frontend-ready"')
            denied=request(frontend,{"op":"reserve","actor":"approved-agent"})
            if denied.get("ok") or "outside authenticated peer grant" not in denied.get("error",""):
                raise RuntimeError("same-UID test frontend obtained unauthorized reserve: "+repr(denied))
            print("R27D_REAL_QEMU_CAPABILITY_DENIED_RESERVE=PASS",flush=True)
            denied=request(frontend,{"op":"input","actor":"approved-agent",
                                     "epoch":"forged","generation":999,
                                     "command":"key-a-down"})
            if denied.get("ok") or "outside authenticated peer grant" not in denied.get("error",""):
                raise RuntimeError("frontend bypassed capability with fabricated lease")
            print("R27D_FORGED_LEASE_CANNOT_BYPASS_OPERATION_POLICY=PASS",flush=True)
            # Attempt actor/role/capability impersonation in the untrusted
            # JSON body. The controller must use only host-side OS identity
            # and its configured capability allowlist.
            denied=request(frontend,{
                "op":"reserve","actor":"approved-agent",
                "principal_uid":65532,"role":"administrator",
                "capabilities":["reserve","input","detach"],
                "admin":True,
            })
            if denied.get("ok") or "outside authenticated peer grant" not in denied.get("error",""):
                raise RuntimeError("client-controlled JSON escalated host capability")
            print("R27D_CLIENT_ROLE_CAPABILITY_SPOOF_REJECTED=PASS",flush=True)
            denied=request(frontend,{"op":"detach","actor":"approved-agent",
                                     "epoch":"forged","generation":999})
            if denied.get("ok") or "outside authenticated peer grant" not in denied.get("error",""):
                raise RuntimeError("frontend bypassed detachment policy")
            print("R27D_UNAUTHORIZED_DEVICE_DETACH_DENIED=PASS",flush=True)
            if journal.exists():
                contents=json.loads(journal.read_text())
                if contents.get("held") or contents.get("sequence")!=0:
                    raise RuntimeError("mutating request changed durable journal")
            if hashlib.sha256(media.read_bytes()).hexdigest()!=digest:
                raise RuntimeError("unauthorized request modified synthetic media")
            control_snapshot(str(sock),"status","available",False,False)
            print("R27D_DENIED_MUTATIONS_NO_JOURNAL_OR_MEDIA_TAINT=PASS",flush=True)
        finally:
            for p in (frontend,controller,qemu):stop(p)
            print("R27D_DISPOSABLE_SYNTHETIC_QEMU_STOPPED=PASS",flush=True)
if __name__=="__main__":
    main()
