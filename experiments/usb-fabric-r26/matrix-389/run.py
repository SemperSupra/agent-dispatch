#!/usr/bin/env python3
"""Enumerate multiple synthetic USB peripheral classes in real Linux guest.

QMP attach != guest driver function. Uses R15's independent sysfs printer and
real USB keyboard event witness to prove guest boot and inspection occurred.
No real network, audio samples, smartcard identity or physical device access.
"""
import json, os, select, socket, subprocess, tempfile, time
from pathlib import Path
class QMP:
 def __init__(self,sock):
  self.s=sock
  self.f=sock.makefile("r",encoding="utf-8")
  self.events=[]
  if "QMP" not in self.read():raise RuntimeError("no QMP greeting")
  self.call("qmp_capabilities")
 def read(self):
  v=self.f.readline()
  if not v:raise RuntimeError("QMP EOF")
  return json.loads(v)
 def call(self,command,args=None):
  cmd={"execute":command}
  if args is not None:cmd["arguments"]=args
  self.s.sendall((json.dumps(cmd)+"\n").encode())
  for i in range(200):
   v=self.read()
   if "event" in v:
    self.events.append(v);continue
   if "error" in v:raise RuntimeError(str(v["error"]))
   if "return" in v:return v["return"]
   raise RuntimeError("unknown QMP message")
  raise RuntimeError("QMP response bound")
 def has(self,dev):
  return dev in {x.get("name") for x in self.call("qom-list",{"path":"/machine/peripheral"})}
def connect(path,proc):
 for i in range(200):
  if proc.poll() is not None:raise RuntimeError("QEMU exit before QMP")
  if os.path.exists(path):
   try:
    s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect(path)
    return QMP(s)
   except (FileNotFoundError,ConnectionRefusedError):
    pass
  time.sleep(.05)
 raise RuntimeError("QMP timeout")
def main():
 with tempfile.TemporaryDirectory(prefix="r26-m3-",dir="/tmp") as root:
  directory=Path(root)
  qmp=str(directory/"qmp.sock")
  mtp=directory/"mtp"
  mtp.mkdir()
  (mtp/"SYNTHETIC-README.txt").write_text("R26 test only. No real user files.\n")
  media=directory/"media.img"
  media.write_bytes(b"R26_USB_CLASS_DISCOVERY"+bytes(2097152-23))
  cmd=["qemu-system-x86_64","-machine","q35","-accel","tcg",
       "-cpu","qemu64","-m","1024M","-smp","1","-S",
       "-nodefaults","-display","none","-serial","stdio",
       "-monitor","none","-net","none","-no-reboot",
       "-kernel","/guest/kernel","-initrd","/guest/initrd.gz",
       "-append","console=ttyS0 rdinit=/init loglevel=5 panic=-1",
       "-device","qemu-xhci,id=xhci0",
       "-chardev","null,id=r26serial",
       "-netdev","user,id=r26net",
       "-audiodev","none,id=r26audio",
       "-qmp","unix:"+qmp+",server=on,wait=off"]
  vm=subprocess.Popen(cmd,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
  try:
   q=connect(qmp,vm)
   for driver,name,props in [
    ("usb-kbd","base-kbd",{}),("usb-tablet","base-tablet",{}),
   ]:
    q.call("device_add",dict(driver=driver,id=name,bus="xhci0.0",**props))
   q.call("blockdev-add",{"driver":"file","node-name":"r26-file","filename":str(media),"read-only":True})
   q.call("blockdev-add",{"driver":"raw","node-name":"r26-raw","file":"r26-file","read-only":True})
   q.call("device_add",{"driver":"usb-storage","id":"base-disk","bus":"xhci0.0","drive":"r26-raw"})
   matrix=[
    ("usb-net",{"netdev":"r26net"}),
    ("usb-serial",{"chardev":"r26serial"}),
    ("usb-audio",{"audiodev":"r26audio"}),
    ("usb-ccid",{}),
    ("usb-mtp",{"rootdir":str(mtp)}),
   ]
   accepted=[]
   rejected={}
   for driver,props in matrix:
    ident="r26-"+driver
    try:
     q.call("device_add",dict(driver=driver,id=ident,bus="xhci0.0",**props))
     if not q.has(ident):raise RuntimeError("QOM absent after device_add")
     accepted.append(driver)
     print("R26_M3_HOST_QMP_"+driver.upper().replace("-","_")+"=PASS",flush=True)
    except Exception as e:
     rejected[driver]=str(e)[:190]
     print("R26_M3_HOST_QMP_"+driver.upper().replace("-","_")+"=RED reason="+str(e)[:110],flush=True)
   if len(accepted)<3:
    raise RuntimeError("less than 3 synthetic USB peripheral classes attached: "+str(rejected))
   q.call("cont")
   data=[];pending=b"";sent=False
   deadline=time.monotonic()+125
   while time.monotonic()<deadline:
    ready,_,_=select.select([vm.stdout],[],[],0.45)
    if ready:
     block=os.read(vm.stdout.fileno(),65536)
     if block:
      data.append(block);pending+=block
      while b"\n" in pending:
       line,pending=pending.split(b"\n",1)
       if b"R15_GUEST_HID_OBSERVER_READY=PASS" in line and not sent:
        q.call("input-send-event",{"events":[{"type":"key","data":{"down":True,"key":{"type":"qcode","data":"a"}}}]})
        time.sleep(.23)
        q.call("input-send-event",{"events":[{"type":"key","data":{"down":False,"key":{"type":"qcode","data":"a"}}}]})
        sent=True
     elif vm.poll() is not None:break
    elif vm.poll() is not None:break
   if vm.poll() is None:
    vm.kill();vm.wait()
    raise RuntimeError("real guest did not shut down")
   output=b"".join(data).decode("utf-8","replace")
   products=[line.split("=",1)[1].strip() for line in output.splitlines() if line.startswith("R15_GUEST_USB_SYSFS_PRODUCT=")]
   for product in products:print("R26_M3_GUEST_SYSFS_PRODUCT="+product[:130],flush=True)
   if "R15_GUEST_USB_ALL_THREE_ENUMERATED=PASS" not in output or "R15_REAL_USB_KEY_A_DOWN_AND_UP_OBSERVED=PASS" not in output:
    raise RuntimeError("Linux guest baseline USB/evdev proof absent: "+output[-1300:])
   extra=[]
   for driver in accepted:
    token={"usb-net":"Network","usb-serial":"Serial","usb-audio":"Audio",
           "usb-ccid":"CCID","usb-mtp":"filesharing"}[driver]
    observed=any(token.lower() in p.lower() for p in products)
    print("R26_M3_GUEST_SYSFS_"+driver.upper().replace("-","_")+"="+("PASS" if observed else "UNKNOWN"),flush=True)
    if observed:extra.append(driver)
   if len(extra)<2:
    raise RuntimeError("additional USB classes not witnessed in guest sysfs: "+str(products))
   print("R26_M3_EXTRA_GUEST_SYSFS_CLASSES="+",".join(extra),flush=True)
   print("R26_M3_REAL_GUEST_SYSFS_AND_KEYBOARD_INDEPENDENT=PASS",flush=True)
   print("R26_M3_FUNCTIONAL_SERIAL_AUDIO_NETWORK_SMARTCARD=NOT_TESTED",flush=True)
  finally:
   if vm.poll() is None:vm.terminate();vm.wait(timeout=5)
if __name__=="__main__":main()
