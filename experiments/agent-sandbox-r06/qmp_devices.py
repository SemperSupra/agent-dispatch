#!/usr/bin/env python3
"""Public synthetic QMP host-device lifecycle smoke, *not* guest OS enumeration.

All QEMU, device image, sockets and tests live in a disposable, unprivileged,
no-network OCI runtime. No real physical device, credential or host path.
"""
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time

class QMP:
    def __init__(self,sock):
        self.sock=sock
        self.file=sock.makefile("r",encoding="utf-8")
        self.events=[]
        greeting=self._read(expect_greeting=True)
        if "QMP" not in greeting: raise RuntimeError("invalid QMP greeting")
        self.call("qmp_capabilities")
    def _read(self,expect_greeting=False):
        while True:
            line=self.file.readline()
            if not line:raise RuntimeError("QMP disconnected")
            msg=json.loads(line)
            if not expect_greeting and "event" in msg:
                self.events.append(msg)
                continue
            return msg
    def call(self,name,args=None,negative=False):
        message={"execute":name}
        if args is not None: message["arguments"]=args
        self.sock.sendall((json.dumps(message,separators=(",",":"))+"\n").encode())
        msg=self._read()
        if negative:
            if "error" not in msg: raise RuntimeError("unexpected positive for negative QMP command "+name)
            return msg["error"].get("class","unknown")
        if "error" in msg:raise RuntimeError("QMP "+name+" rejected "+json.dumps(msg["error"]))
        if "return" not in msg:raise RuntimeError("QMP missing return "+name)
        return msg["return"]
    def close(self):self.file.close()

def connect(sockpath,proc):
    s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    s.settimeout(10)
    for _ in range(90):
        if proc.poll() is not None:raise RuntimeError("QEMU exited before local QMP")
        try:s.connect(sockpath);return s
        except (FileNotFoundError,ConnectionRefusedError): time.sleep(.05)
    raise RuntimeError("local QMP unavailable")

def children(q):
    return {x["name"] for x in q.call("qom-list",{"path":"/machine/peripheral"}) if "name" in x}

def main():
    with tempfile.TemporaryDirectory(prefix="r06-",dir="/tmp") as d:
        sockpath=d+"/qmp.sock"
        disk=Path(d)/"synthetic-usb.img"
        disk.write_bytes(b"R06_PUBLIC_SYNTHETIC_MEDIA_ONLY" + bytes(1024*1024-31))
        before=hashlib.sha256(disk.read_bytes()).hexdigest()
        cmd=["qemu-system-x86_64","-machine","q35","-accel","tcg",
          "-cpu","qemu64","-m","128M","-smp","1","-S","-nodefaults",
          "-display","none","-monitor","none","-serial","none",
          "-device","qemu-xhci,id=xhci0",
          "-qmp","unix:"+sockpath+",server=on,wait=off"]
        proc=subprocess.Popen(cmd,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        q=None
        try:
            with connect(sockpath,proc) as sock:
                q=QMP(sock)
                status=q.call("query-status")
                kvm=q.call("query-kvm")
                if status.get("running") or kvm.get("enabled"):raise RuntimeError("preboot TCG not verified")
                print("R06_LOCAL_QMP_PREBOOT_TCG=PASS")
                starting=children(q)
                if "xhci0" not in starting: raise RuntimeError("xHCI controller missing from QOM")
                print("R06_USB_XHCI_CONTROLLER_PRESENT=PASS")
                q.call("device_add",{"driver":"usb-kbd","id":"r06kbd","bus":"xhci0.0"})
                q.call("device_add",{"driver":"usb-tablet","id":"r06tablet","bus":"xhci0.0"})
                after=children(q)
                if not {"r06kbd","r06tablet"}.issubset(after):
                    raise RuntimeError("USB HID not observable in QOM: "+str(after))
                print("R06_QMP_HID_ATTACH_HOST_OBSERVED=PASS")
                q.call("blockdev-add",{"driver":"file","filename":str(disk),"node-name":"r06file","read-only":True})
                q.call("blockdev-add",{"driver":"raw","file":"r06file","node-name":"r06raw","read-only":True})
                q.call("device_add",{"driver":"usb-storage","id":"r06drive","drive":"r06raw","bus":"xhci0.0"})
                if "r06drive" not in children(q):raise RuntimeError("USB storage device missing from host QOM")
                print("R06_SYNTHETIC_READONLY_USB_ATTACH=PASS")
                neg=q.call("device_add",{"driver":"not-a-real-device-r06","id":"not-allowed"},negative=True)
                if "not-allowed" in children(q):raise RuntimeError("invalid device became visible")
                print("R06_INVALID_DEVICE_REJECTED=PASS CLASS="+str(neg))
                for dev in ("r06kbd","r06tablet","r06drive"):
                    q.call("device_del",{"id":dev})
                # USB hot unplug may be async; QOM polling is host-only evidence.
                missing=[]
                for _ in range(60):
                    now=children(q)
                    missing=[x for x in ("r06kbd","r06tablet","r06drive") if x in now]
                    if not missing:break
                    time.sleep(.05)
                if missing:raise RuntimeError("devices still in host QOM after detach "+str(missing))
                print("R06_QMP_DEVICE_DETACH_HOST_OBSERVED=PASS")
                q.call("quit")
                q.close();q=None
            proc.wait(timeout=5)
            if proc.returncode!=0:raise RuntimeError("QEMU exit="+str(proc.returncode))
            if hashlib.sha256(disk.read_bytes()).hexdigest()!=before:
                raise RuntimeError("readonly backing image changed")
            print("R06_USB_BACKING_MEDIA_READONLY_HASH=PASS")
            print("R06_GUEST_OS_ENUMERATION=NOT_TESTED")
            print("R06_HUMAN_AGENT_HID_EFFECT=NOT_TESTED")
            print("R06_ACTUAL_HOST_PASSTHROUGH=NOT_TESTED")
            print("R06_QMP_NETWORK_EXPOSURE=NONE_CONFIGURED")
        finally:
            if q is not None: q.close()
            if proc.poll() is None:
                proc.terminate()
                try:proc.wait(timeout=5)
                except subprocess.TimeoutExpired:proc.kill();proc.wait()
            if proc.returncode!=0 and proc.stderr:
                err=proc.stderr.read().decode("utf-8","replace")
                print("R06_QEMU_DIAGNOSTIC="+err[-1000:].replace("\n",";"))
            if proc.stderr:proc.stderr.close()

if __name__=="__main__":main()
