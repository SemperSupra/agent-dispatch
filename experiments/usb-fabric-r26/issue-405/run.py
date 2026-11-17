#!/usr/bin/env python3
"""QEMU xHCI actual guest network TFTP payload or USB audio PCM through
WAV backend, all confined to isolated nonnetworked OCI and synthetic data.
"""
import argparse,hashlib,math,os,select,struct,subprocess,tempfile,time,wave
from pathlib import Path

def validate_audio(path):
 if not path.is_file() or path.stat().st_size<8192:
  raise RuntimeError("QEMU WAV backend never received nontrivial output")
 with wave.open(str(path),"rb") as f:
  rate=f.getframerate(); channels=f.getnchannels(); width=f.getsampwidth()
  raw=f.readframes(f.getnframes())
 if width!=2 or channels not in (1,2) or not (8000<=rate<=96000):
  raise RuntimeError("unexpected QEMU audio output format")
 stride=2*channels
 samples=[struct.unpack_from("<h",raw,i)[0] for i in range(0,len(raw)-stride,stride)]
 if len(samples)<rate//4:raise RuntimeError("insufficient captured samples")
 nonzero=sum(1 for x in samples if abs(x)>100)
 if nonzero<rate//20:raise RuntimeError("audio all silent")
 # Compare 440 Hz Goertzel power to off-target 730Hz.
 def power(freq):
  w=2*math.pi*freq/rate
  coef=2*math.cos(w)
  s1=s2=0.0
  for v in samples[:min(len(samples),rate*2)]:
   s=float(v)+coef*s1-s2;s2=s1;s1=s
  return s1*s1+s2*s2-coef*s1*s2
 p440,p730=power(440),power(730)
 if p440<max(p730*3,1e7):
  raise RuntimeError("USB audio output lacks expected 440 Hz spectral energy")
 rms=math.sqrt(sum(x*x for x in samples)/len(samples))
 print(f"R26_P2_USB_AUDIO_QEMU_WAV=PASS samples={len(samples)} rate={rate} channels={channels} rms={rms:.1f} signal_to_control={p440/max(p730,1):.1f}",flush=True)

def main():
 a=argparse.ArgumentParser();a.add_argument("--mode",choices=["network","audio"],required=True)
 mode=a.parse_args().mode
 with tempfile.TemporaryDirectory(prefix="r26-p2-",dir="/tmp") as d:
  root=Path(d)
  payload=bytes((i*31+17)%256 for i in range(96*1024))
  (root/"payload.bin").write_bytes(payload)
  sha=hashlib.sha256(payload).hexdigest()
  wav=root/"captured.wav"
  cmd=["qemu-system-x86_64","-machine","q35","-accel","tcg","-cpu","qemu64",
       "-m","1024M","-smp","1","-nodefaults","-display","none",
       "-serial","stdio","-monitor","none","-net","none","-no-reboot",
       "-kernel","/guest/kernel","-initrd","/guest/r26-p2-initrd.gz",
       "-append","console=ttyS0 rdinit=/init loglevel=4 panic=-1 r26_mode="+mode+" r26_sha="+sha,
       "-device","qemu-xhci,id=xhci0"]
  if mode=="network":
   cmd+=["-netdev","user,id=usblan,restrict=on,tftp="+str(root),
         "-device","usb-net,id=r26-usbnet,netdev=usblan,bus=xhci0.0"]
  else:
   cmd+=["-audiodev","wav,id=r26a,path="+str(wav),
         "-device","usb-audio,id=r26-usbaudio,audiodev=r26a,bus=xhci0.0"]
  print("R26_P2_START_ACTUAL_GUEST="+mode,flush=True)
  t0=time.monotonic()
  vm=subprocess.Popen(cmd,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
  try:
   out,_=vm.communicate(timeout=120)
  except subprocess.TimeoutExpired:
   vm.kill();out,_=vm.communicate()
   raise RuntimeError("guest timed out "+mode+" "+out.decode("utf-8","replace")[-900:])
  text=out.decode("utf-8","replace")
  for line in text.splitlines():
   if line.startswith("R26_P2_"):print(line[:260],flush=True)
  if vm.returncode!=0 or "R26_P2_GUEST_ORACLE=RED" in text:
   raise RuntimeError("guest error "+mode+" "+text[-1200:])
  needed="R26_P2_REAL_GUEST_USB_NET_UDP_TFTP_4X_SHA256=PASS" if mode=="network" else "R26_P2_REAL_GUEST_USB_AUDIO_PLAYBACK=PASS"
  if needed not in text:raise RuntimeError("missing independent guest proof "+needed+" "+text[-1000:])
  if mode=="audio":validate_audio(wav)
  print(f"R26_P2_REAL_USB_{mode.upper()}_DATA_PATH=PASS elapsed_ms={int(1000*(time.monotonic()-t0))}",flush=True)
  print("R26_P2_REAL_DEVICE_USBIP_AND_MULTIGUEST_STRESS=NOT_TESTED",flush=True)

if __name__=="__main__":main()
