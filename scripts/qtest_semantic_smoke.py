#!/usr/bin/env python3
"""Public synthetic QTest device-model experiments; no guest, no external hardware."""
import json
import pathlib
import socket
import subprocess
import sys
import tempfile
import time

def require(condition, message):
    if not condition:
        raise AssertionError(message)

def witness(name, actual, expected):
    print(json.dumps(dict(test=name, observed=actual, expected=expected)), flush=True)
    require(actual == expected, name)

def connect(path, process):
    end = time.monotonic() + 12
    while time.monotonic() < end:
        require(process.poll() is None, "QEMU exited before socket ready")
        s = socket.socket(socket.AF_UNIX)
        try:
            s.connect(str(path))
            s.settimeout(8)
            return s
        except OSError:
            s.close()
            time.sleep(.05)
    raise TimeoutError(str(path))

class Session:
    def __init__(self, root, process):
        self.q = connect(root / "test", process)
        self.m = connect(root / "qmp", process)
        self.qf = self.q.makefile("rb")
        self.mf = self.m.makefile("rb")
        self.events = []
        self.seq = 0
        require("QMP" in json.loads(self.mf.readline()), "QMP greeting")
        self.cmd("qmp_capabilities")
    def close(self):
        for f in (self.qf,self.mf,self.q,self.m):
            f.close()
    def qt(self, op):
        self.q.sendall((op+"\n").encode())
        while True:
            line = self.qf.readline().decode().strip()
            if line.startswith("IRQ "):
                continue
            require(line.startswith("OK"), "QTest: "+line)
            fields=line.split()
            return int(fields[1],0) if len(fields)>1 else None
    def cmd(self, name, args=None, error=False):
        self.seq += 1
        request = dict(execute=name, id=self.seq)
        if args is not None:
            request["arguments"] = args
        self.m.sendall((json.dumps(request)+"\n").encode())
        while True:
            reply = json.loads(self.mf.readline())
            if "event" in reply:
                self.events.append(reply)
                continue
            require(reply.get("id")==self.seq, "QMP response mismatch")
            if error:
                require("error" in reply, "expected QMP refusal: "+name)
                print(json.dumps(dict(test=name, negative=reply["error"]["class"])),flush=True)
                return reply["error"]
            require("return" in reply, str(reply))
            return reply["return"]
    def pci(self, slot, offset, value=None, width="l"):
        self.qt(f"outl 0xcf8 {0x80000000|(slot<<11)|(offset&~3):#x}")
        port=0xcfc+(offset&3)
        if value is None:
            return self.qt(f"in{width} {port:#x}")
        return self.qt(f"out{width} {port:#x} {value:#x}")
    def peripheral(self):
        return {x["name"] for x in self.cmd("qom-list",{"path":"/machine/peripheral"})}
    def pci_id(self, slot):
        matches=[x for bus in self.cmd("query-pci") for x in bus["devices"] if x["slot"]==slot and x["function"]==0]
        require(len(matches)==1,"QMP PCI topology")
        ids=matches[0]["id"]
        witness("PCI config vs QMP",self.pci(slot,0),ids["vendor"]|(ids["device"]<<16))
        return ids

def usb(s):
    ids=s.pci_id(5)
    witness("xhci vendor",ids["vendor"],0x1b36)
    witness("xhci device",ids["device"],0x000d)
    witness("xhci class",s.pci(5,8)>>8,0x0c0330)
    # Read actual xHCI port state independently of QOM topology (same model).
    base=0xfeb00000
    s.pci(5,0x10,base)
    s.pci(5,0x14,0)
    s.pci(5,4,2,"w")
    cap=s.qt(f"readl {base:#x}") & 0xff
    ports=s.qt(f"readl {base+4:#x}") >> 24
    require(cap==0x40 and 0<ports<=32,"xHCI MMIO geometry")
    addresses=[base+cap+0x400+16*i for i in range(ports)]
    def connected():
        return [i for i,a in enumerate(addresses) if s.qt(f"readl {a:#x}") & 1]
    witness("initial ports disconnected",len(connected()),0)
    require("fixture" not in s.peripheral(),"clean start")
    s.cmd("device_add",dict(driver="usb-kbd",bus="xhci.0",id="fixture"))
    witness("present after add","fixture" in s.peripheral(),True)
    attached=connected()
    witness("single connected port",len(attached),1)
    port=addresses[attached[0]]
    witness("connect change",bool(s.qt(f"readl {port:#x}") & (1<<17)),True)
    s.qt(f"writel {port:#x} {((1<<9)|(1<<17)):#x}")
    witness("connect change W1C",bool(s.qt(f"readl {port:#x}") & (1<<17)),False)
    s.qt(f"writel {port:#x} {((1<<9)|(1<<4)):#x}")
    witness("port reset enabled",bool(s.qt(f"readl {port:#x}") & 2),True)
    witness("port reset completion",bool(s.qt(f"readl {port:#x}") & (1<<21)),True)
    s.cmd("device_add",dict(driver="usb-kbd",bus="xhci.0",id="fixture"),error=True)
    s.cmd("device_add",dict(driver="usb-kbd",bus="nonexistent-bus",id="wrong"),error=True)
    witness("no phantom device","wrong" in s.peripheral(),False)
    witness("negative controls preserve port",connected(),attached)
    s.cmd("device_del",dict(id="fixture"))
    end=time.monotonic()+5
    while time.monotonic()<end:
        s.qt("clock_step 1000000")
        if "fixture" not in s.peripheral():
            break
    witness("removed","fixture" in s.peripheral(),False)
    witness("disconnect observed in PORTSC",len(connected()),0)
    witness("delete event",any(e["event"]=="DEVICE_DELETED" and e.get("data",{}).get("device")=="fixture" for e in s.events),True)
    s.cmd("device_add",dict(driver="usb-kbd",bus="xhci.0",id="fixture"))
    witness("reattach","fixture" in s.peripheral(),True)
    witness("reattach connected port count",len(connected()),1)

def virtio(s):
    ids=s.pci_id(6)
    witness("virtio vendor",ids["vendor"],0x1af4)
    witness("virtio legacy block device",ids["device"],0x1001)
    s.pci(6,0x10,0x1001)
    s.pci(6,4,1,"w")
    witness("BAR0 IO assignment",s.pci(6,0x10)&~3,0x1000)
    witness("initial status",s.qt("inb 0x1012"),0)
    s.qt("outb 0x1012 1")
    witness("acknowledge",s.qt("inb 0x1012"),1)
    s.qt("outb 0x1012 3")
    witness("driver",s.qt("inb 0x1012"),3)
    s.qt("outw 0x100e 0")
    size=s.qt("inw 0x100c")
    require(size>0 and size&(size-1)==0,"queue 0 valid power-of-two size")
    print(json.dumps(dict(test="queue 0",observed=size)),flush=True)
    s.qt("outw 0x100e 1")
    witness("nonexistent queue 1",s.qt("inw 0x100c"),0)
    witness("absent queue initial PFN",s.qt("inl 0x1008"),0)
    s.qt("outl 0x1008 1")
    witness("absent queue PFN mutation refused",s.qt("inl 0x1008"),0)
    s.qt("outw 0x1010 1")
    witness("status after nonexistent notify",s.qt("inb 0x1012"),3)
    s.qt("outw 0x100e 0")
    witness("valid queue PFN undisturbed",s.qt("inl 0x1008"),0)
    witness("valid queue recovered",s.qt("inw 0x100c"),size)
    s.qt("outb 0x1012 0")
    witness("reset status",s.qt("inb 0x1012"),0)

def main():
    lane=sys.argv[1]
    require(lane in ("usb","virtio"),"unknown lane")
    with tempfile.TemporaryDirectory(prefix="qtest-semantic-") as td:
        root=pathlib.Path(td)
        disk=root/"disk.raw"
        with disk.open("wb") as f: f.truncate(4*1024*1024)
        args=["qemu-system-x86_64","-machine","q35,accel=qtest","-nodefaults","-display","none","-m","64","-qtest",f"unix:{root/'test'},server=on,wait=off","-qmp",f"unix:{root/'qmp'},server=on,wait=off"]
        if lane=="usb":
            args+=["-device","qemu-xhci,id=xhci,addr=05.0"]
        else:
            args+=["-drive",f"if=none,id=disk,format=raw,file={disk}","-device","virtio-blk-pci,drive=disk,id=blk,disable-modern=on,num-queues=1,addr=06.0"]
        log=root/"qemu.log"
        with log.open("wb") as err:
            proc=subprocess.Popen(args,stdout=err,stderr=err)
            sess=None
            try:
                sess=Session(root,proc)
                (usb if lane=="usb" else virtio)(sess)
                sess.cmd("quit")
                require(proc.wait(timeout=8)==0,"QEMU clean exit")
            finally:
                if sess: sess.close()
                if proc.poll() is None:
                    proc.terminate()
                    try: proc.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=3)
                print(json.dumps(dict(lane=lane,process_exit=proc.returncode)),flush=True)
                if log.exists():
                    print(log.read_text(errors="replace")[-12000:],flush=True)
    print(json.dumps(dict(lane=lane,result="PASS",cleanup=True)),flush=True)
if __name__=="__main__":
    main()
