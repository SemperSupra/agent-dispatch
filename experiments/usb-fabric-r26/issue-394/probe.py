#!/usr/bin/env python3
"""Synthetic QEMU USB CCID + libcacard backend qualification.

NSS identities are generated INSIDE disposable OCI and never exported.
No real CAC, physical reader, PIN, certificate or private key is touched.
"""
import hashlib
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import tempfile
import time

def cmd(*args, timeout=35):
 return subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                       text=True,timeout=timeout)

def qmp_connect(path,process):
 for _ in range(140):
  if process.poll() is not None:raise RuntimeError("QEMU exited before QMP")
  if os.path.exists(path):
   try:
    sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect(path)
    f=sock.makefile("r",encoding="utf-8")
    greeting=json.loads(f.readline())
    if "QMP" not in greeting:raise RuntimeError("QMP greeting absent")
    sock.sendall(b'{"execute":"qmp_capabilities"}\n')
    while True:
     msg=json.loads(f.readline())
     if "event" in msg:continue
     if "return" not in msg:raise RuntimeError("QMP capabilities refused")
     break
    return sock,f
   except (OSError,ConnectionRefusedError):
    pass
  time.sleep(.05)
 raise RuntimeError("QMP socket never ready")

def certificates(db):
 # NSS and private material intentionally ephemeral, created as
 # brand-new fake test-only identities; no personal or DoD data.
 run=cmd("certutil","-N","--empty-password","-d","sql:"+str(db))
 if run.returncode:raise RuntimeError("synthetic NSS init failed "+run.stderr[-300:])
 # certutil -z reads to EOF: use a bounded test-only entropy file.
 noise=db.parent/"r26-entropy.bin"
 noise.write_bytes(os.urandom(2048))
 os.chmod(noise,0o600)
 ca="R26 Synthetic CA"
 run=cmd("certutil","-S","-d","sql:"+str(db),"-x",
   "-s","CN=R26 Synthetic CA","-n",ca,"-t","CT,CT,CT",
   "-m","101","-v","1","-z",str(noise),timeout=45)
 if run.returncode:raise RuntimeError("synthetic CA creation failed "+run.stderr[-350:])
 for i,nick in enumerate(["id-cert","signing-cert","encryption-cert"],start=102):
  run=cmd("certutil","-S","-d","sql:"+str(db),
   "-s","CN=R26 Synthetic "+nick,"-n",nick,"-c",ca,
   "-t",",,","-m",str(i),"-v","1","-z",str(noise),timeout=45)
  if run.returncode:
   raise RuntimeError("synthetic leaf "+nick+" creation failed "+run.stderr[-350:])
 print("R26_N5_THREE_SYNTHETIC_NSS_CERTIFICATES_CREATED=PASS",flush=True)

def main():
 out=cmd("qemu-system-x86_64","-device","help")
 if out.returncode:raise RuntimeError("QEMU device-list failed")
 if "usb-ccid" not in out.stdout:raise RuntimeError("QEMU lacks usb-ccid reader")
 print("R26_N5_QEMU_USB_CCID_READER_MODEL_AVAILABLE=PASS",flush=True)
 if "ccid-card-emulated" not in out.stdout:
  print("R26_N5_QEMU_LIBCACARD_EMULATOR=NOT_AVAILABLE",flush=True)
  print("R26_N5_REAL_GUEST_PCSC_APDU=NOT_TESTED",flush=True)
  return
 print("R26_N5_QEMU_LIBCACARD_CARD_MODEL_AVAILABLE=PASS",flush=True)
 with tempfile.TemporaryDirectory(prefix="r26-n5-",dir="/tmp") as temp:
  db=Path(temp)/"nss"
  db.mkdir()
  certificates(db)
  qmp=str(Path(temp)/"qmp.sock")
  media=Path(temp)/"media.img"
  media.write_bytes(b"R26_SYNTHETIC_CARD_GUEST_DISK"+bytes(2097152-29))
  opts=[
   "qemu-system-x86_64","-machine","q35","-accel","tcg","-cpu","qemu64",
   "-m","1024M","-smp","1","-S","-nodefaults","-display","none",
   "-serial","stdio","-monitor","none","-net","none","-no-reboot",
   "-kernel","/guest/kernel","-initrd","/guest/initrd.gz",
   "-append","console=ttyS0 rdinit=/init loglevel=5 panic=-1",
   "-device","qemu-xhci,id=xhci0",
   "-device","usb-kbd,id=r26-kbd,bus=xhci0.0",
   "-device","usb-tablet,id=r26-tab,bus=xhci0.0",
   "-drive","if=none,id=usbdisk,format=raw,readonly=on,file="+str(media),
   "-device","usb-storage,id=r26-disk,bus=xhci0.0,drive=usbdisk",
   "-device","usb-ccid,id=r26-reader,bus=xhci0.0",
   "-device","ccid-card-emulated,id=r26-virtual-card,bus=r26-reader.0,"
      +"backend=certificates,db=sql:"+str(db)
      +",cert1=id-cert,cert2=signing-cert,cert3=encryption-cert",
   "-qmp","unix:"+qmp+",server=on,wait=off",
  ]
  vm=subprocess.Popen(opts,stdin=subprocess.DEVNULL,
    stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
  try:
   s,f=qmp_connect(qmp,vm)
   print("R26_N5_QEMU_VIRTUAL_CAC_CARD_BACKEND_LOADED=PASS",flush=True)
   s.sendall(b'{"execute":"cont"}\n')
   while True:
    ans=json.loads(f.readline())
    if "event" in ans:continue
    if "return" not in ans:raise RuntimeError("QEMU guest start failed")
    break
   chunks=[];partial=b"";sent=False
   deadline=time.monotonic()+95
   while time.monotonic()<deadline:
    ready,_,_=select.select([vm.stdout],[],[],0.4)
    if ready:
     block=os.read(vm.stdout.fileno(),65536)
     if block:
      chunks.append(block);partial+=block
      while b"\n" in partial:
       line,partial=partial.split(b"\n",1)
       if b"R15_GUEST_HID_OBSERVER_READY=PASS" in line and not sent:
        for down in (True,False):
         req={"execute":"input-send-event","arguments":{"events":[
          {"type":"key","data":{"down":down,"key":{"type":"qcode","data":"a"}}}]}}
         s.sendall((json.dumps(req)+"\n").encode())
         while True:
          msg=json.loads(f.readline())
          if "event" in msg:continue
          if "return" not in msg:raise RuntimeError("QMP synthetic key failed")
          break
         if down:time.sleep(.2)
        sent=True
     elif vm.poll() is not None:break
    elif vm.poll() is not None:break
   if vm.poll() is None:vm.kill();vm.wait();raise RuntimeError("CCID guest timeout")
   guest=b"".join(chunks).decode("utf-8","replace")
   ccid=any("CCID" in line for line in guest.splitlines()
            if "R15_GUEST_USB_SYSFS_PRODUCT=" in line)
   if not ccid:raise RuntimeError("guest did not enumerate actual USB CCID "+guest[-1000:])
   if "R15_REAL_USB_KEY_A_DOWN_AND_UP_OBSERVED=PASS" not in guest:
    raise RuntimeError("Linux guest independent input observer absent")
   print("R26_N5_REAL_GUEST_USB_CCID_READER_SYSFS=PASS",flush=True)
   print("R26_N5_USB_CCID_READER_PLUS_EMULATED_CARD_LINUX_GUEST=PASS",flush=True)
   print("R26_N5_PCSC_ATR_APDU_SELECT_READ_WRITE=NOT_TESTED",flush=True)
   print("R26_N5_REAL_CAC_KEYS_CERT_WRITE_PIN=NOT_TESTED",flush=True)
  finally:
   if vm.poll() is None:vm.terminate();vm.wait(timeout=5)
if __name__=="__main__":main()
