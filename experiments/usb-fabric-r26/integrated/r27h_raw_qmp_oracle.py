#!/usr/bin/env python3
"""Disposable RED falsifier: controller lock is not a QMP authorization layer."""
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
from r27c_signed_guest_oracle import Lines,stop

def qmp_send(sock,command,args=None):
    obj={"execute":command}
    if args is not None:obj["arguments"]=args
    sock.sendall((json.dumps(obj)+"\n").encode())
    for _ in range(100):
        line=b""
        while not line.endswith(b"\n"):
            part=sock.recv(4096)
            if not part:raise RuntimeError("QMP connection closed")
            line+=part
        response=json.loads(line)
        if "event" in response:continue
        return response
    raise RuntimeError("QMP response limit")

def connect_qmp(path):
    deadline=time.monotonic()+15
    while True:
        try:
            s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            s.settimeout(8)
            s.connect(path)
            break
        except OSError:
            s.close()
            if time.monotonic()>deadline:raise
            time.sleep(.05)
    greeting=b""
    while not greeting.endswith(b"\n"):greeting+=s.recv(4096)
    if "QMP" not in json.loads(greeting):raise RuntimeError("QMP greeting missing")
    r=qmp_send(s,"qmp_capabilities")
    if "return" not in r:raise RuntimeError("QMP capabilities refused "+str(r))
    return s

def main():
    with tempfile.TemporaryDirectory(prefix="r27h-qmp-red-",dir="/tmp") as temp:
        root=Path(temp)
        media=root/"media.img"
        media.write_bytes(b"R27H-TEST-ONLY"+bytes(1024*1024))
        first=str(root/"owner-qmp.sock")
        second=str(root/"hostile-qmp.sock")
        api=str(root/"controller.sock")
        qemu=controller=None
        hostile=None
        try:
            qemu=subprocess.Popen([
                "qemu-system-x86_64","-machine","q35","-accel","tcg",
                "-cpu","qemu64","-m","512M","-smp","1","-S",
                "-nodefaults","-display","none","-monitor","none",
                "-serial","none","-net","none","-no-reboot",
                "-device","qemu-xhci,id=xhci0",
                "-qmp","unix:"+first+",server=on,wait=off",
                "-qmp","unix:"+second+",server=on,wait=off",
            ],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
            controller=subprocess.Popen([
                "/guest/r26-actuator","--qmp",first,"--socket",api,
                "--media",str(media),"--capture",str(root/"capture.pcap"),
                "--journal",str(root/"held.json"),
                "--authorized-peer-uid",str(os.geteuid()),
                "--permitted-operations","status,ports",
            ],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
            Lines(controller).wait("R26_L_SOLE_QMP_ACTUATOR_LISTENING=PASS",25)
            print("R27H_SOLE_CONTROLLER_INITIALIZED=PASS",flush=True)
            hostile=connect_qmp(second)
            print("R27H_HOSTILE_DIRECT_RAW_QMP_CONNECTED=PASS",flush=True)
            r=qmp_send(hostile,"device_add",
                {"driver":"usb-kbd","id":"r27h-rogue-kbd","bus":"xhci0.0"})
            if "return" in r:
                print("R27H_RED_UNPRIVILEGED_RAW_QMP_DEVICE_ADD_BYPASS=REPRODUCED",flush=True)
                removed=qmp_send(hostile,"device_del",{"id":"r27h-rogue-kbd"})
                print("R27H_RED_DIRECT_DEVICE_DEL_RESPONSE="+("ACCEPTED" if "return" in removed else "DENIED"),flush=True)
            else:
                print("R27H_RAW_QMP_DEVICE_ADD=REJECTED",flush=True)
                print("R27H_SECURITY_BOUNDARY_EXPLANATION_REQUIRED="+str(r),flush=True)
            # Detect rather than silently asserting a non-existent source fix.
            if "return" not in r:
                raise RuntimeError("RED falsifier did not reproduce; investigate QMP error")
            print("R27H_BLUE_PROTECTED_QMP_NAMESPACE=NOT_TESTED",flush=True)
            print("R27H_PRODUCTION_ISOLATION=NOT_TESTED",flush=True)
        finally:
            if hostile:hostile.close()
            for p in (controller,qemu):stop(p)
            print("R27H_DISPOSABLE_QMP_PROCESSES_STOPPED=PASS",flush=True)
if __name__=="__main__":main()
