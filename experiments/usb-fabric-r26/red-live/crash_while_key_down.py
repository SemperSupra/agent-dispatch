#!/usr/bin/env python3
"""Synthetic red-team: crash Go broker while key is down.
Expected finding: no external owner forces key-up; real Linux evdev waits
and times out. This script deliberately exits nonzero on confirmed defect.
"""
import json
import os
from pathlib import Path
import runpy
import select
import subprocess
import sys
import tempfile
import time

control = runpy.run_path("/guest/r26-orchestrator.py")
send, expect = control["send"], control["expect"]

def main():
    with tempfile.TemporaryDirectory(prefix="r26-crash-red-",dir="/tmp") as d:
        media=Path(d)/"synthetic.img"
        marker=b"PUBLIC_R26_RED_SYNTHETIC_MEDIA"
        media.write_bytes(marker+bytes(2097152-len(marker)))
        cmd=[
            "qemu-system-x86_64","-machine","q35","-accel","tcg",
            "-cpu","qemu64","-m","1024M","-smp","1","-S",
            "-nodefaults","-display","none","-monitor","none",
            "-serial","stdio","-net","none","-no-reboot",
            "-kernel","/guest/kernel","-initrd","/guest/initrd.gz",
            "-append","console=ttyS0 rdinit=/init loglevel=7 panic=-1",
            "-device","qemu-xhci,id=xhci0",
            "-qmp","unix:"+d+"/qmp.sock,server=on,wait=off",
        ]
        vm=subprocess.Popen(cmd,stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        broker=subprocess.Popen(
            ["/guest/r26-broker","--qmp",d+"/qmp.sock",
             "--media",str(media),"--capture",d+"/keyboard.pcap"],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,text=True,bufsize=1)
        try:
            ready,_,_=select.select([broker.stdout],[],[],12)
            if not ready:raise RuntimeError("broker did not open QMP")
            expect(json.loads(broker.stdout.readline()),True,
                   "R26_H_REAL_GO_QMP_BROKER_CONNECTED")
            grant=send(broker,{"op":"reserve","actor":"approved-agent"})
            expect(grant,True,"R26_H_EXCLUSIVE_LEASE")
            epoch,generation=grant["epoch"],grant["generation"]
            expect(send(broker,{"op":"attach","actor":"approved-agent",
                                "epoch":epoch,"generation":generation}),
                   True,"R26_H_USB_ATTACHED")
            expect(send(broker,{"op":"start","actor":"approved-agent",
                                "epoch":epoch,"generation":generation}),
                   True,"R26_H_GUEST_STARTED")
            chunks=[];partial=b"";killed=False
            until=time.monotonic()+75
            while time.monotonic()<until:
                rd,_,_=select.select([vm.stdout],[],[],0.5)
                if rd:
                    data=os.read(vm.stdout.fileno(),65536)
                    if data:
                        chunks.append(data)
                        partial+=data
                        while b"\n" in partial:
                            line,partial=partial.split(b"\n",1)
                            if b"R15_GUEST_HID_OBSERVER_READY=PASS" in line and not killed:
                                expect(send(broker,{
                                    "op":"input","actor":"approved-agent",
                                    "epoch":epoch,"generation":generation,
                                    "command":"key-a-down"}),
                                  True,"R26_H_REAL_QMP_KEY_DOWN")
                                # QMP ACK is not guest receipt; wait for guest
                                # evidence before killing broker.
                            if b"R15_GUEST_USB_KEY_A_DOWN=PASS" in line and not killed:
                                broker.kill()
                                broker.wait(timeout=5)
                                killed=True
                                print("R26_H_BROKER_KILLED_AFTER_REAL_GUEST_KEY_DOWN=PASS",flush=True)
                    elif vm.poll() is not None:break
                elif vm.poll() is not None:break
            text=b"".join(chunks).decode("utf-8","replace")
            for line in text.splitlines():
                if "R15_GUEST_USB_KEY_A_" in line or "R15_REAL_USB_HID_EVENT_ORACLE" in line:
                    print(line[:180],flush=True)
            if not killed:raise RuntimeError("no independent guest key-down before broker crash")
            if "R15_GUEST_USB_KEY_A_UP=PASS" in text:
                raise RuntimeError("guest saw release; assumed crash defect not reproduced")
            if "R15_REAL_USB_HID_EVENT_ORACLE=RED" not in text:
                raise RuntimeError("guest did not prove no key-release within its deadline")
            print("R26_H_P0_CRASH_WHILE_KEY_HELD_MISSED_RELEASE=RED",flush=True)
            print("R26_H_SUPERVISOR_RELEASE_BARRIER_REQUIRED=BLOCKED",flush=True)
            sys.exit(17)
        finally:
            if broker.poll() is None:
                broker.kill()
                broker.wait()
            if vm.poll() is None:
                vm.terminate()
                try:vm.wait(timeout=3)
                except subprocess.TimeoutExpired:vm.kill();vm.wait()

if __name__=="__main__":main()
