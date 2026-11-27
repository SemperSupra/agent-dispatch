#!/usr/bin/env python3
"""Bounded modern VirtIO PCI proxy/core observations, no guest or submissions."""
import json
import pathlib
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "scripts"))
from qtest_semantic_smoke import Session, require
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "qtest-replay"))
from replay import common, stop

PATH = "/machine/peripheral/blk/virtio-backend"
RINGS = (0x100000, 0x101000, 0x102000)
ARMS = ("absent", "queue-reset", "device-reset")

class Trace(Session):
    def cmd(self, name, args=None, error=False):
        print(json.dumps({"qmp_request": name, "args": args, "expected_error": error}), flush=True)
        result = super().cmd(name, args, error)
        print(json.dumps({"qmp_result": result}), flush=True)
        return result

def config(s):
    ids = s.pci_id(6)
    require((ids["vendor"], ids["device"]) == (0x1af4, 0x1042), "modern PCI identity")
    def pci(off, width="l", value=None):
        return s.pci(6, off, value, width)
    require(pci(6, "w") & 0x10, "capability list")
    pos = pci(0x34, "b")
    visited = set()
    caps = {}
    while pos:
        require(0x40 <= pos <= 0xf0 and pos % 4 == 0 and pos not in visited, "capability pointer")
        visited.add(pos)
        typ, nxt = pci(pos, "b"), pci(pos+1, "b")
        if typ == 9:
            length = pci(pos+2, "b")
            require(length >= 16 and pos+length <= 256, "vendor capability bounds")
            kind = pci(pos+3, "b")
            if kind in (1, 2, 3, 4):
                require(kind not in caps, "duplicate capability")
                caps[kind] = (pci(pos+4, "b"), pci(pos+8), pci(pos+12))
        pos = nxt
    require(set(caps) == {1,2,3,4}, "modern capability set")
    bar, offset, length = caps[1]
    require(0 <= bar <= 4 and length >= 56, "common capability")
    require(all(x[0] == bar for x in caps.values()), "shared BAR fixture")
    reg = 0x10 + 4*bar
    require(pci(reg) & 7 == 4, "64-bit memory BAR")
    pci(4, "w", 0)
    pci(reg, value=0xffffffff)
    pci(reg+4, value=0xffffffff)
    mask = (pci(reg+4)<<32) | (pci(reg)&~15)
    size = ((~mask)&((1<<64)-1))+1
    base = 0xfeb00000
    require(0 < size <= 0x100000 and size&(size-1)==0 and base%size==0, "BAR size/alignment")
    require(all(o+n<=size and n>0 for _,o,n in caps.values()), "capability inside BAR")
    pci(reg, value=base)
    pci(reg+4, value=0)
    require((pci(reg)&~15)==base and pci(reg+4)==0, "BAR readback")
    pci(4, "w", 2)
    require(pci(4, "w")&7==2, "memory only, no bus mastering")
    print(json.dumps({"caps":caps,"bar_size":size,"common_base":base+offset}), flush=True)
    return base+offset, length

def execute(s, arm):
    base, length = config(s)
    def rd(off, width):
        require(off+{"b":1,"w":2,"l":4}[width]<=length, "read outside common cap")
        return s.qt(f"read{width} {base+off:#x}")
    def wr(off, width, val):
        require(off+{"b":1,"w":2,"l":4}[width]<=length, "write outside common cap")
        s.qt(f"write{width} {base+off:#x} {val:#x}")
    def core(q, path=PATH, error=False):
        return s.cmd("x-query-virtio-queue-status", {"path":path,"queue":q}, error=error)
    def refusal(q, path, description):
        e = core(q,path,True)
        require(e == {"class":"GenericError","desc":description}, "wrong refusal: "+str(e))
    def snap(q, phase, absent=False):
        wr(22,"w",q)
        regs = {"selector":rd(22,"w"),"size":rd(24,"w"),"enable":rd(28,"w"),
                "rings":[rd(i,"l")|(rd(i+4,"l")<<32) for i in (32,40,48)],
                "status":rd(20,"b")}
        require(regs["selector"]==q and regs["status"]&4==0, "selector/DRIVER_OK")
        if absent:
            refusal(q, PATH, f"Invalid virtqueue number {q}")
            c = None
        else:
            c = core(q)
            require(c["queue-index"]==q and c["name"]=="virtio-blk", "core identity")
            require(c["inuse"]==0 and c["last-avail-idx"]==0 and c["used-idx"]==0, "no submitted work")
        print(json.dumps({"arm":arm,"phase":phase,"proxy":regs,"core":c}),flush=True)
        return regs,c
    def ring(c):
        return tuple(c[k] for k in ("vring-desc","vring-avail","vring-used"))
    def program(q):
        wr(22,"w",q)
        wr(24,"w",16)
        for off, addr in zip((32,40,48),RINGS):
            wr(off,"l",addr)
            wr(off+4,"l",0)
    wr(20,"b",0)
    require(rd(20,"b")==0,"initial reset")
    wr(20,"b",1)
    wr(20,"b",3)
    wr(0,"l",1)
    hi = rd(4,"l")
    require(hi&1, "VERSION_1 not offered")
    features = 1
    if arm=="queue-reset":
        require(hi&256 and length>=60, "RING_RESET not offered or mapped")
        features |= 256
    wr(8,"l",0); wr(12,"l",0)
    wr(8,"l",1); wr(12,"l",features)
    require(rd(12,"l")==features,"driver features readback")
    wr(20,"b",11)
    require(rd(20,"b")==11,"FEATURES_OK not accepted")
    require(rd(18,"w")==1,"fixture queue count")
    print(json.dumps({"arm":arm,"offered_hi":hi,"negotiated_hi":features}),flush=True)
    s.qt("memset 0x100000 0x3000 0")
    refusal(0,"/machine/peripheral/blk","Path /machine/peripheral/blk is not a VirtIODevice")
    r,c=snap(0,"initial")
    require(r["enable"]==0 and r["size"]==c["vring-num"]>0 and ring(c)==(0,0,0),"initial present")
    if arm=="absent":
        r,_=snap(1,"absent-initial",True)
        require(r["size"]==0 and r["enable"]==0,"initial absent")
        program(1)
        r,_=snap(1,"absent-programmed",True)
        require(r["size"]==0 and tuple(r["rings"])==RINGS,"absent proxy only")
        wr(28,"w",1)
        r,_=snap(1,"absent-enabled",True)
        require(r["enable"]==1 and r["size"]==0,"proxy enable without core")
        r,c=snap(0,"present-undisturbed")
        require(r["enable"]==0 and ring(c)==(0,0,0),"present preserved")
    else:
        program(0)
        r,c=snap(0,"programmed-before-enable")
        require(r["enable"]==0 and tuple(r["rings"])==RINGS and ring(c)==(0,0,0),"proxy/core before enable")
        wr(28,"w",1)
        r,c=snap(0,"enabled")
        require(r["enable"]==1 and r["size"]==c["vring-num"]==16 and ring(c)==RINGS,"effective ring")
        if arm=="queue-reset":
            wr(58,"w",1)
            r,c=snap(0,"queue-reset")
            require(rd(58,"w")==0 and r["enable"]==0 and r["status"]==11 and ring(c)==(0,0,0),"queue reset postcondition")
    wr(20,"b",0)
    r,c=snap(0,"device-reset")
    require(r["status"]==0 and r["enable"]==0 and ring(c)==(0,0,0),"whole reset postcondition")
    refusal(1,PATH,"Invalid virtqueue number 1")

def main():
    out = pathlib.Path(sys.argv[1])
    out.mkdir()
    failed = []
    for arm in ARMS:
        start=time.monotonic_ns()
        try:
            with tempfile.TemporaryDirectory(prefix="qtest-modern-") as td:
                root=pathlib.Path(td)
                args=common(root,"qtest")
                args[-1]=args[-1].replace("disable-modern=on","disable-legacy=on")
                args += ["-qtest",f"unix:{root/'test'},server=on,wait=off",
                         "-qmp",f"unix:{root/'qmp'},server=on,wait=off"]
                with (out/(arm+".raw")).open("wb") as log:
                    proc=subprocess.Popen(args,stdout=log,stderr=log)
                    sess=None
                    try:
                        sess=Trace(root,proc)
                        execute(sess,arm)
                        sess.cmd("quit")
                        require(proc.wait(timeout=8)==0,"QEMU exit")
                    finally:
                        if sess: sess.close()
                        stop(proc)
                        print(json.dumps({"arm":arm,"process_exit":proc.returncode}),flush=True)
            require(not root.exists(),"cleanup")
            print(json.dumps({"arm":arm,"result":"PASS","cleanup":True,"reported_elapsed_ns":time.monotonic_ns()-start}),flush=True)
        except Exception as exc:
            failed.append(arm)
            print(json.dumps({"arm":arm,"result":"FAIL","error":repr(exc)}),flush=True)
    raise SystemExit(bool(failed))

if __name__=="__main__":
    main()
