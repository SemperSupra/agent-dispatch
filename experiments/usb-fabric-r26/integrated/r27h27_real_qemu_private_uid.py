#!/usr/bin/env python3
"""Disposable actual-QEMU QMP private-UID negative witness.

This validates an actual QEMU monitor's host filesystem access boundary,
not the full broker or same-UID attacker. H7 and H24 remain RED.
"""
import json
import os
import pathlib
import pwd
import shutil
import signal
import socket
import subprocess
import tempfile
import time

OWNER=65532
ATTACKER=65534

def as_uid(uid):
    def drop():
        os.setgroups([])
        os.setgid(uid)
        os.setuid(uid)
    return drop

def connect(path,uid):
    script="import socket,sys;s=socket.socket(socket.AF_UNIX);s.settimeout(3);s.connect(sys.argv[1]);print('CONNECTED')"
    return subprocess.run(["python3","-c",script,path],preexec_fn=as_uid(uid),capture_output=True,text=True,timeout=8)

def qmp_owner(path):
    cmd=["python3","-c",'''
import json,socket,sys
s=socket.socket(socket.AF_UNIX);s.settimeout(4);s.connect(sys.argv[1])
f=s.makefile("rwb",buffering=0)
g=json.loads(f.readline())
assert "QMP" in g
def call(op):
 f.write((json.dumps({"execute":op})+"\\n").encode())
 for _ in range(30):
  x=json.loads(f.readline())
  if "event" in x:continue
  assert "return" in x,x
  return x["return"]
 raise RuntimeError("no QMP result")
call("qmp_capabilities")
s=call("query-status")
assert s["status"]=="prelaunch",s
print("R27H27_OWNER_REAL_QMP_QUERY_STATUS=PASS")
''',path]
    return subprocess.run(cmd,preexec_fn=as_uid(OWNER),capture_output=True,text=True,timeout=12)

def main():
    if os.geteuid()!=0:
        raise RuntimeError("disposable root-owned test required; do not claim PASS")
    with tempfile.TemporaryDirectory(prefix="r27h27-",dir="/tmp") as root:
        os.chmod(root,0o755)
        private=pathlib.Path(root)/"private-qmp"
        private.mkdir(mode=0o700)
        os.chown(private,OWNER,OWNER)
        sock=str(private/"qmp.sock")
        qemu=subprocess.Popen([
            "qemu-system-x86_64","-machine","q35","-accel","tcg",
            "-m","128M","-smp","1","-S","-display","none",
            "-nodefaults","-monitor","none",
            "-qmp","unix:"+sock+",server=on,wait=off"
        ],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
          preexec_fn=as_uid(OWNER))
        try:
            for _ in range(80):
                if qemu.poll() is not None:
                    raise RuntimeError("QEMU exited before QMP ready")
                if os.path.exists(sock):break
                time.sleep(.1)
            else:raise RuntimeError("QMP socket did not appear")
            os.chmod(sock,0o600)
            owner=qmp_owner(sock)
            if owner.returncode!=0 or "R27H27_OWNER_REAL_QMP_QUERY_STATUS=PASS" not in owner.stdout:
                raise RuntimeError("actual owner QMP query failed "+repr((owner.stdout,owner.stderr)))
            print("R27H27_OWNER_REAL_QMP_QUERY_STATUS=PASS",flush=True)
            hostile=connect(sock,ATTACKER)
            if hostile.returncode==0 or "CONNECTED" in hostile.stdout:
                raise RuntimeError("different UID opened raw QMP despite private dir")
            print("R27H27_REAL_QEMU_DISTINCT_UID_HOSTILE_CONNECT_DENIED=PASS",flush=True)
            # While private directory is locked, the attacker may still
            # learn the pathname; that disclosure does not grant access.
            if qemu.poll() is not None:
                raise RuntimeError("QEMU died during isolation")
            print("R27H27_REAL_QEMU_SURVIVED_HOSTILE_ATTEMPT=PASS",flush=True)
            print("R27H27_SAME_UID_RAW_QMP_ACTOR=RED",flush=True)
            print("R27H27_EXISTING_EXPLICITLY_TRANSFERRED_QMP_FD=RED",flush=True)
            print("R27H27_PRIVILEGED_BROKER_RECOVERY_INTEGRATION=NOT_TESTED",flush=True)
        finally:
            if qemu.poll() is None:
                qemu.send_signal(signal.SIGTERM)
                try:qemu.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    qemu.kill();qemu.wait(timeout=4)
            print("R27H27_DISPOSABLE_QEMU_CLEANUP=PASS",flush=True)
if __name__=="__main__":main()
