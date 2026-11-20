#!/usr/bin/env python3
"""R27-H28: real QEMU explicit QMP FD-transfer adversarial witness.

A successful test demonstrates a RED security boundary, never release approval.
All QEMU processes and sockets are disposable on a public free CI runner.
"""
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time

OWNER_UID = 65532
ATTACKER_UID = 65534


def drop_to(uid):
    def drop():
        os.setgroups([])
        os.setgid(uid)
        os.setuid(uid)
    return drop


DENY_FRESH = r"""
import socket,sys
s=socket.socket(socket.AF_UNIX)
s.settimeout(3)
try:
    s.connect(sys.argv[1])
except OSError:
    print("R27H28_PATH_ACL_DENIED_FRESH_CONNECT=PASS",flush=True)
else:
    raise SystemExit("untrusted UID unexpectedly reached actual QMP pathname")
"""

INHERITED_QMP_ATTACK = r"""
import json,os,socket,sys
assert os.geteuid()==65534,("incorrect attacker UID",os.geteuid())
fd=int(sys.argv[1])
s=socket.socket(fileno=fd)
s.settimeout(7)
f=s.makefile("rwb",buffering=0)
greeting=json.loads(f.readline())
assert "QMP" in greeting,greeting
print("R27H28_ATTACKER_DIFFERENT_UID_REAL_QMP_GREETING=PASS",flush=True)
seen_events=[]
def call(command,arguments=None):
    request={"execute":command,"id":command}
    if arguments is not None:
        request["arguments"]=arguments
    f.write((json.dumps(request)+"\n").encode())
    for _ in range(48):
        reply=json.loads(f.readline())
        if "event" in reply:
            seen_events.append(reply)
            continue
        if reply.get("id") != command:
            raise AssertionError(("wrong QMP response id",reply))
        if "error" in reply:
            raise AssertionError(("QMP rejected command",command,reply))
        assert "return" in reply,reply
        return reply["return"]
    raise AssertionError(("missing actual QMP command receipt",command))
call("qmp_capabilities")
status=call("query-status")
assert status["status"]=="prelaunch",status
call("device_add",{"driver":"usb-kbd","id":"h28kbd","bus":"h28xhci.0"})
print("R27H28_ATTACKER_QMP_DEVICE_ADD_RECEIPT=RED",flush=True)
call("device_del",{"id":"h28kbd"})
for _ in range(48):
    if any(e.get("event")=="DEVICE_DELETED" for e in seen_events):
        break
    next_event=json.loads(f.readline())
    if "event" in next_event:
        seen_events.append(next_event)
    else:
        raise AssertionError(("unexpected QMP response",next_event))
else:
    raise AssertionError("actual DEVICE_DELETED event absent")
print("R27H28_ATTACKER_QMP_DEVICE_DELETED_EVENT=RED",flush=True)
print("R27H28_EXPLICIT_INHERITED_FD_ACTUAL_QEMU_BYPASS=RED",flush=True)
"""


def main():
    if os.geteuid()!=0:
        raise RuntimeError("disposable root-owned public CI test required, not a PASS")
    with tempfile.TemporaryDirectory(prefix="r27h28-",dir="/tmp") as tmp:
        root=Path(tmp)
        root.chmod(0o755)
        private=root/"private-qmp"
        private.mkdir(mode=0o700)
        os.chown(private,OWNER_UID,OWNER_UID)
        address=str(private/"qmp.sock")
        qemu=subprocess.Popen(
            ["qemu-system-x86_64","-machine","q35","-accel","tcg",
             "-m","128M","-smp","1","-S","-display","none",
             "-nodefaults","-monitor","none",
             "-device","qemu-xhci,id=h28xhci",
             "-qmp","unix:"+address+",server=on,wait=off"],
            stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,preexec_fn=drop_to(OWNER_UID))
        try:
            for _ in range(100):
                if qemu.poll() is not None:
                    raise RuntimeError("disposable actual QEMU exited before QMP ready")
                if os.path.exists(address):
                    break
                time.sleep(0.1)
            else:
                raise RuntimeError("QMP socket not created by actual QEMU")
            os.chmod(address,0o600)
            denied=subprocess.run(
                [sys.executable,"-c",DENY_FRESH,address],
                preexec_fn=drop_to(ATTACKER_UID),capture_output=True,
                text=True,timeout=8)
            if denied.returncode or "R27H28_PATH_ACL_DENIED_FRESH_CONNECT=PASS" not in denied.stdout:
                raise RuntimeError("different UID fresh QMP pathname denial failed: "+repr((denied.stdout,denied.stderr)))
            print("R27H28_PATH_ACL_DENIED_FRESH_CONNECT=PASS",flush=True)
            # The privileged test orchestrator, not the unprivileged actor,
            # intentionally obtains and explicitly transfers a live descriptor.
            # CLOEXEC alone cannot prevent deliberate pass_fds()/SCM_RIGHTS leaks.
            qmp=socket.socket(socket.AF_UNIX)
            qmp.settimeout(7)
            qmp.connect(address)
            qmp.set_inheritable(False)
            if os.get_inheritable(qmp.fileno()):
                raise RuntimeError("CLOEXEC precondition absent")
            print("R27H28_CLOEXEC_SET_ON_PARENT_FD=PASS",flush=True)
            try:
                hostile=subprocess.run(
                    [sys.executable,"-c",INHERITED_QMP_ATTACK,str(qmp.fileno())],
                    pass_fds=(qmp.fileno(),),preexec_fn=drop_to(ATTACKER_UID),
                    capture_output=True,text=True,timeout=25)
                markers=[
                    "R27H28_ATTACKER_DIFFERENT_UID_REAL_QMP_GREETING=PASS",
                    "R27H28_ATTACKER_QMP_DEVICE_ADD_RECEIPT=RED",
                    "R27H28_ATTACKER_QMP_DEVICE_DELETED_EVENT=RED",
                    "R27H28_EXPLICIT_INHERITED_FD_ACTUAL_QEMU_BYPASS=RED",
                ]
                if hostile.returncode or any(m not in hostile.stdout.splitlines() for m in markers):
                    raise RuntimeError("QMP hostile FD witness unqualified: "+repr((hostile.returncode,hostile.stdout,hostile.stderr)))
                for marker in markers:
                    print(marker,flush=True)
            finally:
                qmp.close()
            if qemu.poll() is not None:
                raise RuntimeError("QEMU exited before attack completion")
            print("R27H28_REAL_QEMU_SURVIVED_HOSTILE_MUTATION=PASS",flush=True)
            print("R27H28_SAME_UID_QMP_ATTACK=RED",flush=True)
            print("R27H28_PRODUCTION_PRIVILEGED_BROKER=NOT_TESTED",flush=True)
            print("R27H28_FSYNced_HELD_CLEAR_AND_NEXT_LEASE=NOT_TESTED",flush=True)
        finally:
            if qemu.poll() is None:
                qemu.send_signal(signal.SIGTERM)
                try:
                    qemu.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    qemu.kill()
                    qemu.wait(timeout=5)
            if qemu.poll() is None:
                raise RuntimeError("disposable QEMU escaped cleanup")
    if os.path.exists(tmp):
        raise RuntimeError("temporary test directory escaped cleanup")
    print("R27H28_DISPOSABLE_QEMU_AND_SOCKET_CLEANUP=PASS",flush=True)


if __name__=="__main__":
    main()
