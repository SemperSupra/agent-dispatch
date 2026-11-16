#!/usr/bin/env python3
"""R14 public synthetic QEMU usbredir backend and denial across guest ISAs.

One local unix usbredir transport endpoint is created as an unconnected
synthetic channel. NO protocol/URB forwarding or real USB device exists.
Even a successful QMP usb-redir attach is not guest USB enumeration.
"""
import argparse
import json
import socket
import subprocess
import tempfile
import time

MACHINES={
 "x86_64":("qemu-system-x86_64","q35","qemu64"),
 "aarch64":("qemu-system-aarch64","virt","cortex-a57"),
 "riscv64":("qemu-system-riscv64","virt","rv64"),
}
class QMP:
 def __init__(self,s):
  self.sock=s
  self.fp=s.makefile("r",encoding="utf-8")
  if "QMP" not in self.recv():raise RuntimeError("QMP greeting missing")
  self.call("qmp_capabilities")
 def recv(self):
  for _ in range(300):
   line=self.fp.readline()
   if not line:raise RuntimeError("QMP closed")
   out=json.loads(line)
   if "event" in out:continue
   return out
  raise RuntimeError("event flood")
 def call(self,cmd,args=None,deny=False):
  m={"execute":cmd}
  if args is not None:m["arguments"]=args
  self.sock.sendall((json.dumps(m)+"\n").encode("utf-8"))
  response=self.recv()
  if deny:
   if "error" not in response:raise RuntimeError("unauthorized QMP command accepted")
   return response["error"]
  if "return" not in response:raise RuntimeError(cmd+" rejected: "+str(response))
  return response["return"]
 def topology(self):
  return {x["name"] for x in self.call("qom-list",{"path":"/machine/peripheral"}) if "name" in x}
 def close(self):self.fp.close()
def connect(path,proc):
 s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
 s.settimeout(8)
 for _ in range(80):
  if proc.poll() is not None:raise RuntimeError("QEMU quit before QMP")
  try:s.connect(path);return s
  except (FileNotFoundError,ConnectionRefusedError):time.sleep(.08)
 raise RuntimeError("QMP socket not ready")
def main(arch):
 binary,machine,cpu=MACHINES[arch]
 with tempfile.TemporaryDirectory(dir="/tmp",prefix="r14-") as d:
  qmp_path=d+"/qmp.sock"
  redir_path=d+"/redir.sock"
  cmd=[binary,"-machine",machine,"-cpu",cpu,"-accel","tcg",
   "-m","192M","-smp","1","-S","-nodefaults","-display","none",
   "-serial","none","-monitor","none","-device","qemu-xhci,id=xhci0",
   "-chardev","socket,id=redir0,path="+redir_path+",server=on,wait=off",
   "-qmp","unix:"+qmp_path+",server=on,wait=off"]
  proc=subprocess.Popen(cmd,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
  try:
   with connect(qmp_path,proc) as sock:
    q=QMP(sock)
    try:
     if q.call("query-kvm").get("enabled") is not False or q.call("query-status").get("running"):
      raise RuntimeError("TCG preboot required")
     char_names={x["label"] for x in q.call("query-chardev") if "label" in x}
     if "redir0" not in char_names:raise RuntimeError("independent usbredir channel not visible")
     print("R14_USBREDIR_TRANSPORT_LOCAL_ONLY=PASS ISA="+arch)
     if "xhci0" not in q.topology():raise RuntimeError("XHCI controller missing")
     print("R14_XHCI_GUEST_CONTROLLER_PRESENT_HOST_QOM=PASS")
     error=q.call("device_add",{"driver":"usb-redir","id":"r14-invalid",
       "chardev":"not-authorized","bus":"xhci0.0"},deny=True)
     if "r14-invalid" in q.topology():raise RuntimeError("invalid channel device appeared")
     print("R14_INVALID_USBREDIR_CHANNEL_REJECTED=PASS CLASS="+str(error.get("class")))
     q.call("device_add",{"driver":"usb-redir","id":"r14relay",
       "chardev":"redir0","bus":"xhci0.0"})
     if "r14relay" not in q.topology():
      raise RuntimeError("USB redirection device absent from QOM")
     print("R14_USBREDIR_DEVICE_ATTACHED_HOST_QMP=PASS ISA="+arch)
     # Negative: No actual physical or mocked USB/IP forwarding source is
     # connected; this proves the endpoint is available but not productive.
     q.call("device_del",{"id":"r14relay"})
     for _ in range(100):
      if "r14relay" not in q.topology():break
      time.sleep(.04)
     if "r14relay" in q.topology():raise RuntimeError("usbredir QOM detach failed")
     print("R14_USBREDIR_DEVICE_DETACHED=PASS ISA="+arch)
     q.call("quit")
    finally:q.close()
   proc.wait(timeout=7)
   if proc.returncode!=0:raise RuntimeError("QEMU returned nonzero")
   print("R14_USBIP_TO_USBREDIR_URB_TRANSLATION=NOT_TESTED")
   print("R14_GUEST_OS_REAL_USB_ENUMERATION=NOT_TESTED")
   print("R14_WINDOWS_DRIVER_COMPATIBILITY=NOT_TESTED")
   print("R14_TRANSPORT_HAS_BUILTIN_EXTERNAL_AUTH=NOT_ASSUMED")
  finally:
   if proc.poll() is None:
    proc.terminate()
    try:proc.wait(timeout=4)
    except subprocess.TimeoutExpired:proc.kill();proc.wait()
   if proc.returncode and proc.stderr:
    print("R14_QEMU_DIAGNOSTIC="+proc.stderr.read().decode("utf-8","replace")[-1500:].replace("\n",";"))
   if proc.stderr:proc.stderr.close()
if __name__=="__main__":
 p=argparse.ArgumentParser()
 p.add_argument("--arch",choices=sorted(MACHINES),required=True)
 main(p.parse_args().arch)
