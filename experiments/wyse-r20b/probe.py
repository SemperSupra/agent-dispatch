#!/usr/bin/env python3
"""R20B Linux-only disposable USBIP/VHCI and QEMU usbredir feasibility.
NO physical hardware, host kernel module load, USB/IP URB bridge or guest OS.
"""
import argparse,glob,json,os,socket,subprocess,tempfile,time

def kernel():
 files=glob.glob("/lib/modules/*/kernel/drivers/usb/usbip/vhci-hcd.ko*")
 print("R20B_PACKAGED_LINUX_VHCI_MODULE_COUNT="+str(len(files)))
 if files:
  p=subprocess.run(["modinfo","-F","name",files[0]],capture_output=True,text=True)
  if p.returncode or "vhci" not in p.stdout:
   raise RuntimeError("packaged module not independently inspectable")
  print("R20B_PACKAGED_VHCI_KMOD_METADATA=PASS")
 else:print("R20B_PACKAGED_VHCI_KMOD_METADATA=NOT_AVAILABLE")
 print("R20B_GUEST_KERNEL_VHCI_AND_USBIP_DRIVER_FEASIBILITY_SURVEY=PASS")
 print("R20B_REAL_LINUX_GUEST_MODULE_LOAD=NOT_TESTED")
 print("R20B_REAL_LINUX_GUEST_USBIP_IMPORT=NOT_TESTED")

def exporter():
 p=subprocess.run(["qemu-system-x86_64","-device","help"],capture_output=True,
                  text=True,timeout=15)
 if p.returncode:raise RuntimeError("QEMU cannot enumerate devices")
 has="x-usb-redir-server" in p.stdout
 print("R20B_QEMU_USBREDIR_EXPORTER="+("AVAILABLE" if has else "NOT_AVAILABLE"))
 print("R20B_QEMU_USBREDIR_EXPORTER_VERSION_PROBED=PASS")
 if not has:print("R20B_EXPERIMENTAL_EXPORTER_PATCH_NOT_IN_PACKAGED_QEMU=BLOCKED")
 print("R20B_TRUE_EXPORT_TO_GUEST_USBIP_BRIDGE=NOT_TESTED")

class QMP:
 def __init__(self,s):
  self.s=s
  self.f=s.makefile("r",encoding="utf-8")
  if "QMP" not in self.recv():raise RuntimeError("QMP greeting missing")
  self.call("qmp_capabilities")
 def recv(self):
  for i in range(160):
   line=self.f.readline()
   if not line:raise RuntimeError("QMP closed")
   o=json.loads(line)
   if "event" in o:continue
   return o
  raise RuntimeError("QMP event flood")
 def call(self,name,args=None,negative=False):
  o={"execute":name}
  if args is not None:o["arguments"]=args
  self.s.sendall((json.dumps(o)+"\n").encode())
  ans=self.recv()
  if negative:
   if "error" not in ans:raise RuntimeError("forbidden device accepted")
   return
  if "return" not in ans:raise RuntimeError("QMP failure: "+str(ans))
  return ans["return"]
 def close(self):self.f.close()

def backend():
 with tempfile.TemporaryDirectory(prefix="r20b-",dir="/tmp") as d:
  qmp=d+"/qmp.sock";red=d+"/red.sock"
  p=subprocess.Popen(["qemu-system-x86_64","-machine","q35","-cpu","qemu64",
   "-accel","tcg","-m","128M","-smp","1","-S","-nodefaults",
   "-display","none","-monitor","none","-serial","none","-net","none",
   "-device","qemu-xhci,id=xhci0",
   "-chardev","socket,id=relay,path="+red+",server=on,wait=off",
   "-qmp","unix:"+qmp+",server=on,wait=off"],stdin=subprocess.DEVNULL,
   stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
  try:
   sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
   sock.settimeout(5)
   for i in range(100):
    if p.poll() is not None:raise RuntimeError("QEMU exited")
    try:sock.connect(qmp);break
    except (FileNotFoundError,ConnectionRefusedError):time.sleep(.06)
   else:raise RuntimeError("QMP unavailable")
   with sock:
    q=QMP(sock)
    try:
     q.call("device_add",{"driver":"usb-redir","id":"bad",
            "chardev":"does-not-exist","bus":"xhci0.0"},negative=True)
     q.call("device_add",{"driver":"usb-redir","id":"red0",
            "chardev":"relay","bus":"xhci0.0"})
     names={i["name"] for i in q.call("qom-list",{"path":"/machine/peripheral"})}
     if "red0" not in names or "bad" in names:raise RuntimeError("QMP host topology wrong")
     print("R20B_QEMU_USBREDIR_HOST_BACKEND_ATTACHED=PASS")
     q.call("device_del",{"id":"red0"})
     for i in range(100):
      names={j["name"] for j in q.call("qom-list",{"path":"/machine/peripheral"})}
      if "red0" not in names:break
      time.sleep(.02)
     else:raise RuntimeError("QMP redir detach failed")
     print("R20B_QEMU_USBREDIR_INVALID_CHANNEL_REJECTED_AND_DETACHED=PASS")
     q.call("quit")
    finally:q.close()
   p.wait(timeout=7)
   if p.returncode:raise RuntimeError("QEMU exit nonzero")
   print("R20B_USBREDIR_PEER_PACKET_HANDSHAKE=NOT_TESTED")
  finally:
   if p.poll() is None:p.kill();p.wait()
   p.stderr.close()

if __name__=="__main__":
 parser=argparse.ArgumentParser()
 parser.add_argument("--lane",required=True,choices=["kernel","backend","exporter"])
 name=parser.parse_args().lane
 {"kernel":kernel,"backend":backend,"exporter":exporter}[name]()
