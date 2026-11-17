#!/usr/bin/env python3
"""Actual guest mixed synthetic USB workload with app data validity oracles.

Tests one QEMU TCG xHCI guest running USB HID, RNDIS TFTP, USB ALSA PCM,
read-only mass storage and CCID reader *simultaneously*. Not physical USB/IP,
not a guest CAC transaction, not a multi-VM production throughput SLA.
"""
import hashlib,json,os,runpy,select,socket,statistics,struct,subprocess,tempfile,time
from pathlib import Path
validate_audio=runpy.run_path("/guest/run.py")["validate_audio"]

def qmp(path,proc):
 for _ in range(160):
  if proc.poll() is not None:raise RuntimeError("QEMU exited before QMP")
  if os.path.exists(path):
   try:
    sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    sock.settimeout(12)
    sock.connect(path)
    stream=sock.makefile("r",encoding="utf-8")
    greet=json.loads(stream.readline())
    if "QMP" not in greet:raise RuntimeError("QMP greeting absent")
    sender=(sock,stream)
    transact(sender,"qmp_capabilities")
    return sender
   except (OSError,ConnectionRefusedError):
    pass
  time.sleep(.05)
 raise RuntimeError("QMP timed out")
def transact(channel,name,args=None):
 sock,reader=channel
 obj={"execute":name}
 if args is not None:obj["arguments"]=args
 sock.sendall((json.dumps(obj)+"\n").encode())
 for _ in range(150):
  line=reader.readline()
  if not line:raise RuntimeError("QMP EOF")
  value=json.loads(line)
  if "event" in value:continue
  if "error" in value:raise RuntimeError(str(value["error"]))
  if "return" in value:return value["return"]
 raise RuntimeError("QMP response bound")
def sendkey(channel,down):
 transact(channel,"input-send-event",{"events":[
  {"type":"key","data":{"down":down,"key":{"type":"qcode","data":"a"}}}]})
def pct(values,x):
 if not values:return 0
 values=sorted(values)
 return values[int((len(values)-1)*x)]

def run_case(reps):
 with tempfile.TemporaryDirectory(prefix="r26-p5-",dir="/tmp") as d:
  root=Path(d)
  payload=bytes((i*31+17)%256 for i in range(96*1024))
  (root/"payload.bin").write_bytes(payload)
  netsha=hashlib.sha256(payload).hexdigest()
  sector=b"R26_MIXED_READONLY_USB_DISK".ljust(512,b"\0")
  disk=root/"synthetic-usb-disk.img"
  with disk.open("wb") as f:
   f.write(sector)
   f.truncate(16*1024*1024)
  before=hashlib.sha256(disk.read_bytes()).hexdigest()
  disksha=hashlib.sha256(sector).hexdigest()
  wav=root/"capture.wav"; qmpath=str(root/"qmp.sock")
  cmd=["qemu-system-x86_64","-machine","q35","-accel","tcg","-cpu","qemu64",
       "-m","1024M","-smp","1","-S","-nodefaults","-display","none",
       "-serial","stdio","-monitor","none","-net","none","-no-reboot",
       "-kernel","/guest/kernel","-initrd","/guest/r26-mixed-initrd.gz",
       "-append",f"console=ttyS0 rdinit=/init loglevel=4 panic=-1 r26_reps={reps} r26_netsha={netsha} r26_disksha={disksha}",
       "-device","qemu-xhci,id=xhci0",
       "-device","usb-kbd,id=mixed-kbd,bus=xhci0.0",
       "-drive","if=none,id=mixed-disk,format=raw,readonly=on,file="+str(disk),
       "-device","usb-storage,id=mixed-storage,drive=mixed-disk,bus=xhci0.0",
       "-netdev","user,id=mixed-net,restrict=on,tftp="+str(root),
       "-device","usb-net,id=mixed-rndis,netdev=mixed-net,bus=xhci0.0",
       "-audiodev","wav,id=mixed-audio,path="+str(wav),
       "-device","usb-audio,id=mixed-usbaudio,audiodev=mixed-audio,bus=xhci0.0",
       "-device","usb-ccid,id=mixed-ccid,bus=xhci0.0",
       "-qmp","unix:"+qmpath+",server=on,wait=off"]
  started=time.monotonic()
  vm=subprocess.Popen(cmd,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
  try:
   channel=qmp(qmpath,vm)
   transact(channel,"cont")
   print(f"R26_P5_MIXED_GUEST_STARTED=PASS reps={reps}",flush=True)
   data=[];partial=b"";sent=False
   until=time.monotonic()+160
   while time.monotonic()<until:
    ready,_,_=select.select([vm.stdout],[],[],0.4)
    if ready:
     block=os.read(vm.stdout.fileno(),65536)
     if block:
      data.append(block);partial+=block
      while b"\n" in partial:
       line,partial=partial.split(b"\n",1)
       if b"R15_GUEST_HID_OBSERVER_READY=PASS" in line and not sent:
        sendkey(channel,True)
        time.sleep(.22)
        sendkey(channel,False)
        sent=True
        print("R26_P5_MIXED_HOST_SENT_SYNTHETIC_HID_DOWN_UP=PASS",flush=True)
     elif vm.poll() is not None:break
    elif vm.poll() is not None:break
   if vm.poll() is None:
    vm.kill();vm.wait()
    raise RuntimeError("mixed guest timeout")
   out=b"".join(data).decode("utf-8","replace")
   for line in out.splitlines():
    if (line.startswith("R26_P5_") or line.startswith("R15_GUEST_USB_KEY_A_") or
        line.startswith("R15_REAL_USB_KEY_A_")):
     print(line[:260],flush=True)
   required=[
    "R26_P5_GUEST_USB_HID_STORAGE_RNDIS_AUDIO_CCID_ENUMERATED=PASS",
    "R26_P5_GUEST_USB_STORAGE_READONLY_SHA=PASS",
    f"R26_P5_NETWORK_SHA_TRANSFERS=PASS count={reps}",
    f"R26_P5_USB_DISK_BULK_READS=PASS count={reps}",
    "R26_P5_USB_AUDIO_PCM_PLAYS=PASS",
    "R15_GUEST_USB_KEY_A_DOWN=PASS","R15_GUEST_USB_KEY_A_UP=PASS",
    f"R26_P5_GUEST_ALL_MIXED_CLASSES_APP_IO=PASS count={reps}",
   ]
   missing=[x for x in required if x not in out]
   if not sent or vm.returncode!=0 or "R26_P5_GUEST_FAILURE=RED" in out or missing:
    raise RuntimeError("mixed workload failed: missing="+str(missing)+" tail="+out[-1000:])
   times=[]
   for line in out.splitlines():
    if line.startswith("R26_P5_TFTP_MS="):
     times.append(float(line.split("=",1)[1]))
   if len(times)!=reps:raise RuntimeError("missing network iteration latency receipts")
   if hashlib.sha256(disk.read_bytes()).hexdigest()!=before:
    raise RuntimeError("read-only USB backing mutated under stress")
   validate_audio(wav)
   elapsed=time.monotonic()-started
   print(f"R26_P5_MIXED_REAL_USB_IO=PASS reps={reps} tftp_p50_ms={pct(times,.5):.1f} tftp_p95_ms={pct(times,.95):.1f} tftp_p99_ms={pct(times,.99):.1f} elapsed_s={elapsed:.2f}",flush=True)
   print("R26_P5_MIXED_SYNTHETIC_DISK_IMMUTABLE=PASS",flush=True)
   return {"reps":reps,"p50":pct(times,.5),"p95":pct(times,.95),"p99":pct(times,.99),"elapsed":elapsed}
  finally:
   if vm.poll() is None:vm.kill();vm.wait(timeout=5)
def main():
 low=run_case(4)
 high=run_case(32)
 print(f"R26_P5_CONTENDED_QEMU_APP_LATENCY_RATIO_P95={high['p95']/max(low['p95'],.001):.2f}",flush=True)
 print("R26_P5_REAL_DISTRIBUTED_USBIP_CAC_APDU_OPTICAL_BURN=NOT_TESTED",flush=True)
 print("R26_P5_ACTUAL_GUEST_MIXED_DEVICE_FUNCTION=PASS",flush=True)
if __name__=="__main__":main()
