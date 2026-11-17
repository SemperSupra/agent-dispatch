#!/usr/bin/env python3
"""QEMU pointer events -> real Linux evdev, one synthetic device per guest."""
import argparse, json, os, select, socket, subprocess, tempfile, time

class QMP:
 def __init__(self, sock):
  self.s=sock
  self.f=sock.makefile("r",encoding="utf-8")
  if "QMP" not in self.read():raise RuntimeError("missing QMP greeting")
  self.call("qmp_capabilities")
 def read(self):
  value=self.f.readline()
  if not value:raise RuntimeError("QMP EOF")
  return json.loads(value)
 def call(self, command,arguments=None):
  request={"execute":command}
  if arguments is not None:request["arguments"]=arguments
  self.s.sendall((json.dumps(request)+"\n").encode())
  for i in range(200):
   answer=self.read()
   if "event" in answer:continue
   if "error" in answer:raise RuntimeError(str(answer["error"]))
   if "return" in answer:return answer["return"]
   raise RuntimeError("unknown QMP result")
  raise RuntimeError("QMP response bound")

def connect(path, proc):
 for i in range(200):
  if proc.poll() is not None:raise RuntimeError("VM exited before QMP")
  if os.path.exists(path):
   try:
    sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    sock.settimeout(12)
    sock.connect(path)
    return QMP(sock)
   except (FileNotFoundError,ConnectionRefusedError):
    pass
  time.sleep(.05)
 raise RuntimeError("QMP timeout")

def main():
 p=argparse.ArgumentParser()
 p.add_argument("--kind",required=True,choices=["mouse","tablet"])
 kind=p.parse_args().kind
 driver="usb-"+kind
 with tempfile.TemporaryDirectory(prefix="r26-m1-",dir="/tmp") as root:
  path=root+"/qmp.sock"
  cmd=["qemu-system-x86_64","-machine","q35","-accel","tcg",
       "-cpu","qemu64","-m","1024M","-smp","1","-S",
       "-nodefaults","-display","none","-serial","stdio","-monitor","none",
       "-net","none","-no-reboot","-kernel","/guest/kernel",
       "-initrd","/guest/r26-initrd.gz",
       "-append","console=ttyS0 rdinit=/init loglevel=5 panic=-1 r26_kind="+kind,
       "-device","qemu-xhci,id=xhci0",
       "-device",driver+",id=r26pointer,bus=xhci0.0",
       "-qmp","unix:"+path+",server=on,wait=off"]
  vm=subprocess.Popen(cmd,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
  try:
   q=connect(path,vm)
   if "r26pointer" not in {item.get("name") for item in q.call("qom-list",{"path":"/machine/peripheral"})}:
    raise RuntimeError("QMP pointer object missing")
   print("R26_M1_QMP_USB_"+kind.upper()+"_DEVICE_PRESENT=PASS",flush=True)
   q.call("cont")
   chunks=[];partial=b"";sent=False
   deadline=time.monotonic()+110
   while time.monotonic()<deadline:
    ready,_,_=select.select([vm.stdout],[],[],0.4)
    if ready:
     raw=os.read(vm.stdout.fileno(),65536)
     if raw:
      chunks.append(raw);partial+=raw
      while b"\n" in partial:
       line,partial=partial.split(b"\n",1)
       if b"R26_M1_GUEST_POINTER_OBSERVER_READY=PASS" in line and not sent:
        if kind=="mouse":
         events=[
          {"type":"rel","data":{"axis":"x","value":66}},
          {"type":"rel","data":{"axis":"y","value":29}},
         ]
        else:
         events=[
          {"type":"abs","data":{"axis":"x","value":22000}},
          {"type":"abs","data":{"axis":"y","value":10300}},
         ]
        q.call("input-send-event",{"events":events})
        q.call("input-send-event",{"events":[
          {"type":"btn","data":{"button":"left","down":True}}]})
        time.sleep(.32)
        q.call("input-send-event",{"events":[
          {"type":"btn","data":{"button":"left","down":False}}]})
        sent=True
        print("R26_M1_QMP_POINTER_MOTION_AND_BTN_SUBMITTED=PASS kind="+kind,flush=True)
     elif vm.poll() is not None:break
    elif vm.poll() is not None:break
   if vm.poll() is None:
    vm.kill();vm.wait()
    raise RuntimeError("guest pointer test timeout")
   output=b"".join(chunks).decode("utf-8","replace")
   for line in output.splitlines():
    if line.startswith("R26_M1_"):print(line[:180],flush=True)
   if not sent or "R26_M1_REAL_GUEST_POINTER_FUNCTION=PASS kind="+kind not in output:
    raise RuntimeError(kind+" lacked guest pointer motion and button evidence: "+output[-1400:])
   if vm.returncode!=0:raise RuntimeError("guest exited "+str(vm.returncode))
   print("R26_M1_REAL_GUEST_"+kind.upper()+"_RELATIVE_OR_ABSOLUTE_AND_CLICK=PASS",flush=True)
   print("R26_M1_WHEEL_MULTIBUTTON_MULTITOUCH_PRESSURE=NOT_TESTED",flush=True)
  finally:
   if vm.poll() is None:vm.terminate();vm.wait(timeout=5)
if __name__=="__main__":main()
