#!/usr/bin/env python3
"""Actual QEMU USB UAS/SCSI optical ISO/UDF read; write denial verified.
This does not establish CD-R/DVD-R/BD-R burner profiles or laser behaviour.
"""
import argparse,hashlib,subprocess,time
from pathlib import Path
def digest(path):
 h=hashlib.sha256()
 with path.open("rb") as f:
  for b in iter(lambda:f.read(1024*1024),b""):h.update(b)
 return h.hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument("--kind",choices=["iso9660","udf"],required=True)
 kind=p.parse_args().kind
 image=Path("/guest/discs")/(kind+".iso")
 before=digest(image)
 cmd=["qemu-system-x86_64","-machine","q35","-accel","tcg","-cpu","qemu64",
      "-m","1024M","-smp","1","-nodefaults","-display","none",
      "-serial","stdio","-monitor","none","-net","none","-no-reboot",
      "-kernel","/guest/kernel","-initrd","/guest/r26-optical-initrd.gz",
      "-append","console=ttyS0 rdinit=/init loglevel=5 panic=-1 r26_kind="+kind,
      "-device","qemu-xhci,id=xhci0",
      "-drive","if=none,id=r26-disc,format=raw,media=cdrom,readonly=on,file="+str(image),
      "-device","usb-uas,id=r26-uas,bus=xhci0.0",
      "-device","scsi-cd,id=r26-optical,drive=r26-disc,bus=r26-uas.0,scsi-id=0,lun=0"]
 print("R26_P3_START_LINUX_USB_OPTICAL_MEDIA="+kind,flush=True)
 t0=time.monotonic()
 vm=subprocess.Popen(cmd,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
 try:
  b,_=vm.communicate(timeout=125)
 except subprocess.TimeoutExpired:
  vm.kill();b,_=vm.communicate()
  raise RuntimeError("QEMU guest optical timeout "+b.decode("utf-8","replace")[-1200:])
 text=b.decode("utf-8","replace")
 for line in text.splitlines():
  if line.startswith("R26_P3_"):print(line[:240],flush=True)
 if vm.returncode!=0 or "R26_P3_GUEST_ORACLE=RED" in text:
  raise RuntimeError("optical guest failed "+text[-1350:])
 checks=["R26_P3_REAL_GUEST_USB_UAS_SCSI_CD_DEVICE=PASS",
         "R26_P3_REAL_GUEST_OPTICAL_READONLY=PASS",
         "R26_P3_REAL_GUEST_OPTICAL_FILE_READ=PASS",
         "R26_P3_REAL_GUEST_2048_BYTE_OPTICAL_SECTORS=PASS",
         "R26_P3_REAL_GUEST_OPTICAL_BLOCK_WRITE_DENIED=PASS",
         "R26_P3_REAL_GUEST_OPTICAL_UNMOUNT=PASS"]
 if any(c not in text for c in checks):raise RuntimeError("guest optical oracle missing "+text[-1200:])
 if digest(image)!=before:raise RuntimeError("synthetic optical media changed")
 print(f"R26_P3_USB_OPTICAL_{kind.upper()}_READ_DENY_WRITE=PASS duration_ms={int((time.monotonic()-t0)*1000)}",flush=True)
 print("R26_P3_CD_DVD_BD_R_RW_RE_BURNING_PROFILE=NOT_TESTED",flush=True)
if __name__=="__main__":main()
