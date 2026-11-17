#!/usr/bin/env python3
"""Actual Linux USB-backed ext4: in-guest format, reboot and new VM instances.
Backing image is disposable and deliberately writable; never use /dev/host.
"""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile

def sha(path):
 h=hashlib.sha256()
 with open(path,"rb") as f:
  for chunk in iter(lambda:f.read(1024*1024),b""):h.update(chunk)
 return h.hexdigest()

def guest(disk,mode):
 cmd=["qemu-system-x86_64","-machine","q35","-accel","tcg","-cpu","qemu64",
      "-m","1024M","-smp","1","-nodefaults","-display","none",
      "-serial","stdio","-monitor","none","-net","none",
      "-kernel","/guest/kernel","-initrd","/guest/r26-initrd.gz",
      "-append","console=ttyS0 rdinit=/init loglevel=4 panic=-1 r26_mode="+mode,
      "-device","qemu-xhci,id=xhci0",
      "-drive","if=none,id=usbdisk,format=raw,file="+str(disk)+",cache=writeback",
      "-device","usb-storage,id=r26disk,bus=xhci0.0,drive=usbdisk"]
 print("R26_N2_START_DISTINCT_QEMU_VM="+mode,flush=True)
 proc=subprocess.Popen(cmd,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT)
 try:
  data,_=proc.communicate(timeout=170)
 except subprocess.TimeoutExpired:
  proc.kill()
  data,_=proc.communicate()
  print(data.decode("utf-8","replace")[-2500:],flush=True)
  raise RuntimeError("QEMU USB ext4 guest timed out in "+mode)
 output=data.decode("utf-8","replace")
 for line in output.splitlines():
  if line.startswith("R26_N2_") or "R26_N2_GUEST" in line:
   print(line[:240],flush=True)
 if proc.returncode!=0:
  raise RuntimeError(mode+" QEMU process failure "+str(proc.returncode)+" "+output[-1000:])
 if "R26_N2_GUEST_RESULT=RED" in output:
  raise RuntimeError(mode+" guest failed "+output[-1700:])
 return output

def main():
 with tempfile.TemporaryDirectory(prefix="r26-n2-",dir="/tmp") as temp:
  disk=Path(temp)/"r26-usb-writable.img"
  with disk.open("wb") as f:f.truncate(128*1024*1024)
  original=sha(disk)
  first=guest(disk,"initial")
  for mark in ("R26_N2_ACTUAL_GUEST_EXT4_FORMAT=PASS",
               "R26_N2_GUEST_FILE_FIRST_WRITE_SYNC_UMOUNT=PASS",
               "R26_N2_SAME_QEMU_KERNEL_REBOOT_FILE_PERSISTED=PASS",
               "R26_N2_SECOND_BOOT_FILE_WRITE_SYNC_UMOUNT=PASS"):
   if mark not in first:raise RuntimeError("initial guest missing "+mark)
  if sha(disk)==original:raise RuntimeError("actual guest never wrote disk")
  print("R26_N2_SAME_VM_REBOOT_INPLACE_IMAGE_CHANGED=PASS",flush=True)
  # The prior QEMU process has terminated; the next process opens the exact
  # same synthetic disk path. No concurrent writable owners.
  second=guest(disk,"second")
  for mark in ("R26_N2_DIFFERENT_QEMU_VM_READ_PRIOR_FILES=PASS",
               "R26_N2_DIFFERENT_QEMU_VM_WRITE_SYNC_UMOUNT=PASS"):
   if mark not in second:raise RuntimeError("second instance missing "+mark)
  third=guest(disk,"verify")
  if "R26_N2_THIRD_QEMU_INSTANCE_ALL_THREE_FILES_VALID=PASS" not in third:
   raise RuntimeError("third instance could not verify all files")
  print("R26_N2_EXT4_FILES_FORMAT_READ_WRITE_REBOOT_CROSS_INSTANCE=PASS",flush=True)
  print("R26_N2_FINAL_SYNTHETIC_IMAGE_SHA256="+sha(disk),flush=True)
  print("R26_N2_GUEST_CACHE_FLUSH_AND_UNMOUNT=PASS",flush=True)
  print("R26_N2_CONCURRENT_WRITERS_CRASH_UNPLUG=NOT_TESTED",flush=True)
if __name__=="__main__":main()
