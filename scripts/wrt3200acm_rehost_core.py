#!/usr/bin/env python3
from __future__ import annotations
import struct
from pathlib import Path
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_MODE_LITTLE_ENDIAN, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn.arm_const import UC_ARM_REG_SP, UC_ARM_REG_LR

PAGE=0x1000
def align_up(x,a=PAGE): return (x+a-1)&~(a-1)

class FirmwareImage:
    def __init__(self,path):
        self.path=Path(path); self.data=self.path.read_bytes()
    def segments(self):
        d=self.data
        if d[:4]!=b"\x7fELF" or d[4]!=1 or d[5]!=1: raise ValueError("expected ELF32 LE")
        phoff=struct.unpack_from("<I",d,28)[0]; ents=struct.unpack_from("<H",d,42)[0]; n=struct.unpack_from("<H",d,44)[0]
        out=[]
        for i in range(n):
            off=phoff+i*ents
            typ,fo,va,_pa,fs,ms,_fl,_al=struct.unpack_from("<IIIIIIII",d,off)
            if typ==1 and fs: out.append((va,d[fo:fo+fs],ms))
        return out

class Runner:
    def __init__(self,image:FirmwareImage):
        self.uc=Uc(UC_ARCH_ARM,UC_MODE_ARM|UC_MODE_LITTLE_ENDIAN)
        self.trace=[]; self.mem=[]; self.stop_reason=None
        mapped=set()
        for va,blob,ms in image.segments():
            base=va&~(PAGE-1); size=align_up((va-base)+max(ms,len(blob)))
            for p in range(base,base+size,PAGE):
                if p not in mapped:
                    self.uc.mem_map(p,PAGE); mapped.add(p)
            self.uc.mem_write(va,blob)
        self._mapped=mapped
    def map_scratch(self,address,size):
        base=address&~(PAGE-1); end=align_up(address+size)
        for p in range(base,end,PAGE):
            if p not in self._mapped:
                self.uc.mem_map(p,PAGE); self._mapped.add(p)
    def run(self,start,stops=(),count=10000,trace_cap=5000,mem_cap=5000):
        stopset=set(stops)
        def code(uc,address,size,user):
            if len(self.trace)<trace_cap:self.trace.append({"address":address,"size":size})
            if address in stopset:
                self.stop_reason={"kind":"stop-address","address":address}; uc.emu_stop()
        def memhook(uc,access,address,size,value,user):
            if len(self.mem)<mem_cap:self.mem.append({"access":access,"address":address,"size":size,"value":value})
        self.uc.hook_add(UC_HOOK_CODE,code)
        self.uc.hook_add(UC_HOOK_MEM_READ|UC_HOOK_MEM_WRITE,memhook)
        self.uc.emu_start(start,0xffffffff,count=count)
        return {"stop_reason":self.stop_reason,"trace":self.trace,"memory_accesses":self.mem}
