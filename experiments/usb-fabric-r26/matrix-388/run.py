#!/usr/bin/env python3
"""Real guest USB BOT/UAS block read and write-protect; synthetic media only."""
import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import time

def main():
 p=argparse.ArgumentParser()
 p.add_argument("--mode",choices=["usb-storage","usb-bot","usb-uas"],required=True)
 mode=p.parse_args().mode
 with tempfile.TemporaryDirectory(prefix="r26-m2-",dir="/tmp") as d:
  path=Path(d)/"synthetic.img"
  sector=(b"R26_SYNTHETIC_"+mode.encode()+b"_BLOCK_").ljust(512,b"\0")
  path.write_bytes(sector+bytes(8*1024*1024-512))
  expected=hashlib.sha256(sector).hexdigest()
  original=hashlib.sha256(path.read_bytes()).hexdigest()
  cmd=["qemu-system-x86_64","-machine","q35","-accel","tcg","-cpu","qemu64",
       "-m","1024M","-smp","1","-nodefaults","-display","none",
       "-serial","stdio","-monitor","none","-net","none","-no-reboot",
       "-kernel","/guest/kernel","-initrd","/guest/r26-initrd.gz",
       "-append","console=ttyS0 rdinit=/init loglevel=4 panic=-1 r26_sha="+expected,
       "-device","qemu-xhci,id=xhci0",
       "-drive","if=none,id=usbdisk,format=raw,file="+str(path)+",readonly=on"]
  if mode=="usb-storage":
   cmd+=["-device","usb-storage,id=media0,bus=xhci0.0,drive=usbdisk"]
  else:
   cmd+=["-device",mode+",id=transport0,bus=xhci0.0",
         "-device","scsi-hd,bus=transport0.0,drive=usbdisk,lun=0"]
  print("R26_M2_VARIANT="+mode,flush=True)
  proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
  try:
   output,_=proc.communicate(timeout=115)
  except subprocess.TimeoutExpired:
   proc.kill()
   output,_=proc.communicate()
   print(output.decode("utf-8","replace")[-2200:],flush=True)
   raise RuntimeError("guest storage read timed out")
  text=output.decode("utf-8","replace")
  for line in text.splitlines():
   if "R26_M2_" in line:print(line[:220],flush=True)
  for item in ["R26_M2_REAL_LINUX_GUEST_BOOTED=PASS",
               "R26_M2_GUEST_SCSI_BLOCK_NODE=PASS",
               "R26_M2_GUEST_BLOCK_READONLY=PASS",
               "R26_M2_GUEST_READONLY_STORAGE_DATA_INTEGRITY=PASS"]:
   if item not in text:raise RuntimeError(mode+": expected guest oracle missing "+item+"; tail="+text[-900:])
  if proc.returncode!=0:raise RuntimeError("guest abnormal exit "+str(proc.returncode))
  if hashlib.sha256(path.read_bytes()).hexdigest()!=original:
   raise RuntimeError("host synthetic disk altered despite read-only policy")
  print("R26_M2_HOST_SYNTHETIC_DISK_IMMUTABLE=PASS",flush=True)
  print("R26_M2_REAL_GUEST_"+mode.upper().replace("-","_")+"_READONLY_BLOCK=PASS",flush=True)
  print("R26_M2_FILESYSTEM_MOUNT_AND_SAFE_EJECT=NOT_TESTED",flush=True)
if __name__=="__main__":main()
