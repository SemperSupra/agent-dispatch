#!/usr/bin/env python3
"""Synthetic blue recovery: host-local supervisor survives broker SIGKILL.
Require QMP forced release AND actual Linux guest evdev key-up proof.
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
        watchdog=subprocess.Popen(
            ["/guest/r26-watchdog","--broker-pid",str(broker.pid),
             "--qmp",d+"/qmp.sock"],
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,text=True)
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
                if "R15_GUEST_USB_KEY_A_" in line or "R15_REAL_USB_KEY_A_DOWN_AND_UP_OBSERVED" in line:
                    print(line[:180],flush=True)
            if not killed:raise RuntimeError("no independent guest key-down before broker crash")
            if "R15_GUEST_USB_KEY_A_UP=PASS" not in text:
                raise RuntimeError("guest did not observe supervisor key release")
            if "R15_REAL_USB_KEY_A_DOWN_AND_UP_OBSERVED=PASS" not in text:
                raise RuntimeError("guest never confirmed both key transitions")
            out,err=watchdog.communicate(timeout=10)
            if watchdog.returncode!=0 or "R26_K_INDEPENDENT_PROCESS_FORCED_QMP_KEY_UP=PASS" not in out:
                raise RuntimeError("supervisor did not confirm forced QMP release: "+err[-500:])
            print(out.strip(),flush=True)
            print("R26_K_REAL_GUEST_KEY_UP_AFTER_BROKER_SIGKILL=PASS",flush=True)
            print("R26_K_FAILED_RELEASE_REASSIGNMENT=QUARANTINE_REQUIRED",flush=True)
            print("R26_K_DURABLE_PROCESS_FENCING=NOT_TESTED",flush=True)
        finally:
            if watchdog.poll() is None:
                watchdog.kill()
                watchdog.wait()
            if broker.poll() is None:
                broker.kill()
                broker.wait()
            if vm.poll() is None:
                vm.terminate()
                try:vm.wait(timeout=3)
                except subprocess.TimeoutExpired:vm.kill();vm.wait()

if __name__=="__main__":main()
