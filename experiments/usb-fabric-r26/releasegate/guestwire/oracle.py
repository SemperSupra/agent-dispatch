#!/usr/bin/env python3
"""Actual QEMU Linux evdev -> virtio-serial -> test-only MAC -> Go gate.
No mock evdev, no serial text accepted as attestation, no real credentials.
"""
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import tempfile
import time

def call(q,channel,command,args=None):
    request={"execute":command}
    if args is not None:request["arguments"]=args
    channel.write((json.dumps(request)+"\n").encode())
    channel.flush()
    for _ in range(100):
        response=json.loads(channel.readline().decode())
        if "event" in response:continue
        if "error" in response:raise RuntimeError("QMP "+command+": "+str(response["error"]))
        if "return" in response:return response["return"]
        raise RuntimeError("QMP response malformed "+str(response))
    raise RuntimeError("QMP response flood")

def send(host,msg):
    host.stdin.write(json.dumps(msg)+"\n")
    host.stdin.flush()
    ready,_,_=select.select([host.stdout],[],[],15)
    if not ready:raise RuntimeError("host verifier response timeout")
    line=host.stdout.readline()
    if not line:raise RuntimeError("host verifier exited")
    return json.loads(line)

def guest_line(conn,buffer):
    deadline=time.monotonic()+25
    while b"\n" not in buffer:
        timeout=deadline-time.monotonic()
        if timeout<=0:raise RuntimeError("guest virtio receipt timeout")
        ready,_,_=select.select([conn],[],[],timeout)
        if not ready:raise RuntimeError("guest virtio message timeout")
        chunk=conn.recv(8192)
        if not chunk:raise RuntimeError("guest virtio port closed before receipt")
        buffer+=chunk
        if len(buffer)>16384:raise RuntimeError("guest receipt too large")
    line,rest=buffer.split(b"\n",1)
    return json.loads(line.decode()),rest

def wait_serial(proc,needle,limit=125):
    until=time.monotonic()+limit
    carry=b""
    while time.monotonic()<until:
        readers,_,_=select.select([proc.stdout],[],[],0.3)
        if readers:
            chunk=os.read(proc.stdout.fileno(),32768)
            if not chunk:break
            carry+=chunk
            while b"\n" in carry:
                line,carry=carry.split(b"\n",1)
                if needle.encode() in line:
                    print(needle,flush=True)
                    return
                if b"R26_L8_" in line and b"RED" in line:
                    raise RuntimeError("guest Linux initialization failed: "+line.decode(errors="replace")[-350:])
                if len(carry)>32768:carry=carry[-16384:]
        if proc.poll() is not None:break
    raise RuntimeError("no actual Linux guest observer readiness")

def stop(p):
    if p is not None and p.poll() is None:
        p.kill()
        p.wait(timeout=6)

def main():
    with tempfile.TemporaryDirectory(prefix="r26-l8-",dir="/tmp") as d:
        root=Path(d)
        wire_path=str(root/"receipt.sock")
        qmp_path=str(root/"qmp.sock")
        server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        server.bind(wire_path)
        server.listen(1)
        server.settimeout(25)
        qemu=host=None
        qmp=conn=channel=None
        try:
            host=subprocess.Popen(["/guest/r26-hostbridge"],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,text=True,bufsize=1)
            qemu=subprocess.Popen([
                "qemu-system-x86_64","-machine","q35","-accel","tcg",
                "-cpu","qemu64","-m","1024M","-smp","1","-S",
                "-nodefaults","-display","none","-monitor","none",
                "-serial","stdio","-net","none","-no-reboot",
                "-kernel","/guest/kernel","-initrd","/guest/initrd.gz",
                "-append","console=ttyS0 rdinit=/init loglevel=7 panic=-1",
                "-device","qemu-xhci,id=xhci0",
                "-device","usb-kbd,id=lab-kbd,bus=xhci0.0",
                "-device","virtio-serial-pci,id=vs0",
                "-chardev","socket,id=receipt,path="+wire_path+",server=off",
                "-device","virtserialport,chardev=receipt,name=org.r26.receipts",
                "-qmp","unix:"+qmp_path+",server=on,wait=off",
            ],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
              stderr=subprocess.STDOUT)
            conn,_=server.accept()
            qmp=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            until=time.monotonic()+18
            while True:
                try:qmp.connect(qmp_path);break
                except (FileNotFoundError,ConnectionRefusedError):
                    if time.monotonic()>until:raise
                    time.sleep(0.05)
            qmp.settimeout(16)
            channel=qmp.makefile("rwb",buffering=0)
            hello=json.loads(channel.readline().decode())
            if "QMP" not in hello:raise RuntimeError("QMP greeting missing")
            call(qmp,channel,"qmp_capabilities")
            call(qmp,channel,"cont")
            wait_serial(qemu,"R26_L8_REAL_GUEST_VIRTIO_EVDEV_OBSERVER_READY=PASS")
            # Arbitrary console/actor text MUST not pass the typed proof gate.
            forged=send(host,{"op":"event","event":{"Source":"qemu.serial",
                "KeyCode":"key-a","Down":False,"EventSequence":500,
                "Proof":"R15_GUEST_USB_KEY_A_UP=PASS"}})
            if forged["ok"] or forged["reclaimable"]:
                raise RuntimeError("fabricated console receipt accepted")
            print("R26_L8_CONSOLE_FORGERY_REJECTED=PASS",flush=True)
            call(qmp,channel,"input-send-event",{"events":[{
                "type":"key","data":{"down":True,
                "key":{"type":"qcode","data":"a"}}}]})
            data=b""
            down,data=guest_line(conn,data)
            if down.get("Down") is not True:raise RuntimeError("first signed event not real evdev key down")
            down_ok=send(host,{"op":"event","event":down})
            if not down_ok["ok"] or down_ok["reclaimable"]:
                raise RuntimeError("signed guest down not accepted or prematurely reclaimed: "+str(down_ok))
            print("R26_L8_ACTUAL_GUEST_VIRTIO_SIGNED_DOWN_VERIFIED=PASS",flush=True)
            call(qmp,channel,"input-send-event",{"events":[{
                "type":"key","data":{"down":False,
                "key":{"type":"qcode","data":"a"}}}]})
            ack=send(host,{"op":"qmp-up-ack"})
            if not ack["ok"] or ack["reclaimable"]:
                raise RuntimeError("QMP ACK prematurely reclaimed held key: "+str(ack))
            print("R26_L8_QMP_ACK_ALONE_RECLAIM_DENIED=PASS",flush=True)
            up,data=guest_line(conn,data)
            if up.get("Down") is not False:raise RuntimeError("second guest event not evdev release")
            wrong=dict(up);wrong["Proof"]="forged"+up.get("Proof","")
            bad=send(host,{"op":"event","event":wrong})
            if bad["ok"] or bad["reclaimable"]:
                raise RuntimeError("forged guest proof accepted")
            print("R26_L8_FORGED_GUEST_RECEIPT_REJECTED=PASS",flush=True)
            good=send(host,{"op":"event","event":up})
            if not good["ok"] or not good["reclaimable"]:
                raise RuntimeError("actual guest evdev release proof not accepted: "+str(good))
            print("R26_L8_REAL_GUEST_VIRTIO_RECEIPT_GATE_RELEASED=PASS",flush=True)
            replay=send(host,{"op":"event","event":up})
            if replay["ok"]:
                raise RuntimeError("guest event replay accepted")
            print("R26_L8_SIGNED_EVENT_REPLAY_REJECTED=PASS",flush=True)
            print("R26_L8_TEST_ONLY_PUBLIC_KEY_PRODUCTION_AUTH=NOT_TESTED",flush=True)
            print("R26_L8_ACTUATOR_JOURNAL_REAL_RE_ADMISSION=NOT_TESTED",flush=True)
        finally:
            for stream in (channel,qmp,conn,server):
                if stream is not None:
                    try:stream.close()
                    except OSError:pass
            stop(qemu)
            stop(host)
            print("R26_L8_DISPOSABLE_PROCESSES_STOPPED=PASS",flush=True)

if __name__=="__main__":
    main()
