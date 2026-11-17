#!/usr/bin/env python3
"""Real guest PCSC over QEMU virtual USB CCID and synthetic NSS test card.
No real CAC, personal certificate, PIN, APDU payload or signing key exported.
"""
import hashlib, json, os, runpy, subprocess, tempfile, time
from pathlib import Path
parent=runpy.run_path("/guest/r26-n5-probe.py")
certificates=parent["certificates"]
qmp_connect=parent["qmp_connect"]
cmd=parent["cmd"]
def main():
 helpout=cmd("qemu-system-x86_64","-device","help")
 if helpout.returncode or "usb-ccid" not in helpout.stdout or "ccid-card-emulated" not in helpout.stdout:
  raise RuntimeError("QEMU libcacard emulated backend unavailable")
 with tempfile.TemporaryDirectory(prefix="r26-n5b-",dir="/tmp") as temp:
  db=Path(temp)/"nss"
  db.mkdir()
  certificates(db)
  path=Path(temp)/"qmp.sock"
  vm=subprocess.Popen([
   "qemu-system-x86_64","-machine","q35","-accel","tcg","-cpu","qemu64",
   "-m","1024M","-smp","1","-S","-nodefaults","-display","none",
   "-serial","stdio","-monitor","none","-net","none","-no-reboot",
   "-kernel","/guest/kernel","-initrd","/guest/r26-pcsc-initrd.gz",
   "-append","console=ttyS0 rdinit=/init loglevel=5 panic=-1",
   "-device","qemu-xhci,id=xhci0",
   "-device","usb-ccid,id=r26reader,bus=xhci0.0",
   "-device","ccid-card-emulated,id=r26-virtual-card,bus=r26reader.0,"
     "backend=certificates,db=sql:"+str(db)
     +",cert1=id-cert,cert2=signing-cert,cert3=encryption-cert",
   "-qmp","unix:"+str(path)+",server=on,wait=off",
  ],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
  try:
   sock,file=qmp_connect(str(path),vm)
   print("R26_N5B_QEMU_EMULATED_CAC_CARD_BACKEND_READY=PASS",flush=True)
   sock.sendall(b'{"execute":"cont"}\n')
   while True:
    value=json.loads(file.readline())
    if "event" in value:continue
    if "return" not in value:raise RuntimeError("cannot start Linux guest")
    break
   try:
    output,_=vm.communicate(timeout=125)
   except subprocess.TimeoutExpired:
    vm.kill()
    output,_=vm.communicate()
    raise RuntimeError("guest PCSC timed out; tail="+output.decode("utf-8","replace")[-700:])
   text=output.decode("utf-8","replace")
   for line in text.splitlines():
    if line.startswith("R26_N5B_"):print(line[:200],flush=True)
   required=[
    "R26_N5B_REAL_GUEST_USB_CCID_SYSFS=PASS",
    "R26_N5B_REAL_GUEST_PCSC_CONTEXT=PASS",
    "R26_N5B_REAL_GUEST_USB_CCID_PCSC_READER_PRESENT=PASS",
    "R26_N5B_REAL_GUEST_PCSC_CARD_CONNECTED=PASS",
    "R26_N5B_REAL_GUEST_PCSC_ATR_PRESENT=PASS",
    "R26_N5B_REAL_GUEST_APDU_TRANSPORT=PASS",
    "R26_N5B_REAL_GUEST_USB_CCID_APDU_ORACLE=PASS",
   ]
   missing=[x for x in required if x not in text]
   if missing or vm.returncode!=0:
    raise RuntimeError("real Linux PCSC/APDU oracle RED missing="+str(missing)+" tail="+text[-850:])
   print("R26_N5B_REAL_LINUX_PCSC_CCID_APDU_ROUNDTRIP=PASS",flush=True)
   print("R26_N5B_WRITABLE_TEST_APPLET_AND_REAL_CAC=NOT_TESTED",flush=True)
  finally:
   if vm.poll() is None:vm.terminate();vm.wait(timeout=5)
if __name__=="__main__":main()
