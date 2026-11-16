#!/usr/bin/env python3
"""Host-controlled QMP device injection followed by *real guest sysfs* USB proof.
Official Debian kernel and own synthetic init only; QEMU TCG is not a secure
untrusted guest isolation boundary. No secret, real USB, host mount or network.
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
  self.fp=sock.makefile("r",encoding="utf-8")
  welcome=self.next()
  if "QMP" not in welcome:raise RuntimeError("QMP greeting missing")
  self.call("qmp_capabilities")
 def next(self):
  for _ in range(500):
   line=self.fp.readline()
   if not line:raise RuntimeError("QMP closed early")
   o=json.loads(line)
   if "event" in o:continue
   return o
  raise RuntimeError("too many QMP events")
 def call(self,command,args=None):
  m={"execute":command}
  if args is not None:m["arguments"]=args
  self.sock.sendall((json.dumps(m)+chr(10)).encode())
  o=self.next()
  if "return" not in o:raise RuntimeError("QMP command "+command+" error="+str(o.get("error")))
  return o["return"]
 def close(self):self.fp.close()

def connect(path,process):
 sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
 sock.settimeout(10)
 for _ in range(100):
  if process.poll() is not None:raise RuntimeError("QEMU preboot exit")
  try:
   sock.connect(path)
   return sock
  except (FileNotFoundError,ConnectionRefusedError):time.sleep(.05)
 raise RuntimeError("QMP unavailable")

def main():
 with tempfile.TemporaryDirectory(prefix="r15-",dir="/tmp") as d:
  media=Path(d)/"synthetic-usb.img"
  media.write_bytes(b"PUBLIC_R15_SYNTHETIC_MEDIA" + bytes(2097152-26))
  start_hash=hashlib.sha256(media.read_bytes()).hexdigest()
  sockname=d+"/qmp.sock"
  cmd=["qemu-system-x86_64","-machine","q35","-accel","tcg","-cpu","qemu64",
    "-m","1024M","-smp","1","-S","-nodefaults","-display","none",
    "-monitor","none","-serial","stdio","-net","none","-no-reboot",
    "-kernel","/guest/kernel","-initrd","/guest/initrd.gz",
    "-append","console=ttyS0 rdinit=/init loglevel=7 panic=-1",
    "-device","qemu-xhci,id=xhci0",
    "-qmp","unix:"+sockname+",server=on,wait=off"]
  proc=subprocess.Popen(cmd,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT)
  connected=False
  try:
   with connect(sockname,proc) as sock:
    q=QMP(sock)
    if q.call("query-kvm").get("enabled") is not False:raise RuntimeError("unexpected non-TCG")
    if q.call("query-status").get("running") is not False:raise RuntimeError("VM not paused")
    q.call("device_add",{"driver":"usb-kbd","id":"r15-key","bus":"xhci0.0"})
    q.call("device_add",{"driver":"usb-tablet","id":"r15-tablet","bus":"xhci0.0"})
    q.call("blockdev-add",{"driver":"file","filename":str(media),"node-name":"r15file","read-only":True})
    q.call("blockdev-add",{"driver":"raw","file":"r15file","node-name":"r15raw","read-only":True})
    q.call("device_add",{"driver":"usb-storage","id":"r15disk","drive":"r15raw","bus":"xhci0.0"})
    names={x["name"] for x in q.call("qom-list",{"path":"/machine/peripheral"}) if "name" in x}
    if not {"r15-key","r15-tablet","r15disk"}.issubset(names):
     raise RuntimeError("host QOM lacks expected device")
    print("R15_HOST_QMP_THREE_USB_DEVICES_ATTACHED=PASS",flush=True)
    q.call("cont")
    # Consume actual serial console output; only after guest input device
    # observer announces readiness do remote QMP key down/up operations.
    import select
    chunks=[]
    partial=b""
    injected=False
    deadline=time.monotonic()+130
    while time.monotonic()<deadline:
     ready,_,_=select.select([proc.stdout],[],[],0.5)
     if ready:
      chunk=os.read(proc.stdout.fileno(),65536)
      if chunk:
       chunks.append(chunk)
       partial+=chunk
       while b"\n" in partial:
        line,partial=partial.split(b"\n",1)
        if b"R15_GUEST_HID_OBSERVER_READY=PASS" in line and not injected:
         if q.call("query-status").get("running") is not True:
          raise RuntimeError("QMP guest not running when event observer ready")
         q.call("input-send-event",{"events":[{"type":"key","data":{
          "down":True,"key":{"type":"qcode","data":"a"}}}]})
         time.sleep(0.3)
         q.call("input-send-event",{"events":[{"type":"key","data":{
          "down":False,"key":{"type":"qcode","data":"a"}}}]})
         injected=True
         print("R15_HOST_QMP_KEY_A_PRESS_AND_RELEASE_SUBMITTED=PASS",flush=True)
      elif proc.poll() is not None:
       break
     elif proc.poll() is not None:
      break
    if proc.poll() is None:
     proc.kill()
     proc.wait(timeout=5)
     raise RuntimeError("guest did not terminate before bounded timeout")
    q.close()
   output=b"".join(chunks).decode("utf-8","replace")
   if not injected:
    print("R15_HOST_QMP_EVENT_TRIGGER=RED",flush=True)
   for line in output.splitlines():
    if "R15_" in line:print(line[:230],flush=True)
   required=[
    "Linux version",
    "R15_GUEST_PID1_STARTED=PASS",
    "R15_GUEST_USB_KEYBOARD_ENUMERATED=PASS",
    "R15_GUEST_USB_TABLET_ENUMERATED=PASS",
    "R15_GUEST_USB_MASS_STORAGE_ENUMERATED=PASS",
    "R15_GUEST_USB_ALL_THREE_ENUMERATED=PASS",
    "R15_GUEST_HID_OBSERVER_READY=PASS",
    "R15_GUEST_USB_KEY_A_DOWN=PASS",
    "R15_GUEST_USB_KEY_A_UP=PASS",
    "R15_REAL_USB_KEY_A_DOWN_AND_UP_OBSERVED=PASS",
    "R15_GUEST_KEY_EVENT_CAPTURE=PASS"
   ]
   missing=[x for x in required if x not in output]
   if missing or proc.returncode!=0:
    print("R15_GUEST_USB_SYSFS_ORACLE=RED MISSING="+str(missing),flush=True)
    print("R15_GUEST_CONSOLE_TAIL="+output[-1600:].replace(chr(10),";"),flush=True)
    raise RuntimeError("real guest enumeration did not pass; exit="+str(proc.returncode))
   print("R15_GUEST_USB_SYSFS_ORACLE=PASS",flush=True)
   print("R15_HOST_REMOTE_QMP_AND_GUEST_ENUMERATION_CORRELATED=PASS",flush=True)
   if hashlib.sha256(media.read_bytes()).hexdigest()!=start_hash:
    raise RuntimeError("backing USB image changed")
   print("R15_READONLY_SYNTHETIC_MEDIA_HASH=PASS",flush=True)
   print("R15_GUI_POINTER_AND_WINDOWS_INPUT=NOT_TESTED",flush=True)
   print("R15_REAL_CAC_PHYSICAL_PASSTHROUGH=NOT_TESTED",flush=True)
   print("R15_TCG_HOSTILE_GUEST_ISOLATION=NOT_TESTED",flush=True)
  finally:
   if proc.poll() is None:
    proc.terminate()
    try:proc.wait(timeout=3)
    except subprocess.TimeoutExpired:proc.kill();proc.wait()
if __name__=="__main__":main()
