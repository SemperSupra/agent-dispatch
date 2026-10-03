#!/usr/bin/env python3
"""Recover semantics of imported ROM services used by UPDATE_ENCRYPTION.

The transient ELF may contain multiple PT_LOAD segments. This probe disassembles
only bounded derived instruction windows and never publishes firmware bytes.
"""
from __future__ import annotations
import argparse, importlib.util, json, re, struct, subprocess
from pathlib import Path

P=Path(__file__).with_name("wrt3200acm_dispatch_probe.py")
spec=importlib.util.spec_from_file_location("dp",P)
dp=importlib.util.module_from_spec(spec); assert spec.loader; spec.loader.exec_module(dp)

VENEERS={
  "set_key_a":(0x44148,0x4414c),
  "set_key_b":(0x44160,0x44164),
  "remove_key":(0x44230,0x44234),
}
CALL_TARGETS={0x44148,0x44160,0x44230}
FW_SHA256="ca23f5bb730fde399359a716481651c120e09c299d4e6bbec6fe718c6e87e751"

def segments(elf:Path):
    d=elf.read_bytes()
    if d[:4]!=b"\x7fELF" or d[4]!=1 or d[5]!=1: raise ValueError("expected ELF32 little-endian")
    phoff=struct.unpack_from("<I",d,28)[0]; pe=struct.unpack_from("<H",d,42)[0]; pn=struct.unpack_from("<H",d,44)[0]
    out=[]
    for i in range(pn):
        o=phoff+i*pe
        typ,fo,va,_pa,fs,ms,fl,al=struct.unpack_from("<IIIIIIII",d,o)
        if typ==1 and fs:
            out.append({"offset":fo,"vaddr":va,"filesz":fs,"memsz":ms,"flags":fl,"align":al})
    return out

def containing_segment(segs,address):
    for x in segs:
        if x["vaddr"] <= address < x["vaddr"]+x["filesz"]: return x
    raise ValueError(f"address {address:#x} not in PT_LOAD")

def read_u32(elf:Path,address:int)->int:
    d=elf.read_bytes(); seg=containing_segment(segments(elf),address)
    off=seg["offset"]+(address-seg["vaddr"])
    return struct.unpack_from("<I",d,off)[0]

def disasm_segment(elf:Path,start:int,end:int,thumb:bool)->str:
    d=elf.read_bytes(); seg=containing_segment(segments(elf),start)
    if not (seg["vaddr"] <= end-1 < seg["vaddr"]+seg["filesz"]):
        raise ValueError("bounded disassembly crosses PT_LOAD")
    raw=elf.with_name(f"{elf.name}.seg-{seg['vaddr']:08x}.tmp")
    raw.write_bytes(d[seg["offset"]:seg["offset"]+seg["filesz"]])
    try:
        machine_opts="force-thumb,reg-names-std" if thumb else "reg-names-std"
        cmd=["arm-linux-gnueabi-objdump","-D","-b","binary","-m","arm","-EL","-M",machine_opts,
             f"--adjust-vma=0x{seg['vaddr']:x}",f"--start-address=0x{start:x}",f"--stop-address=0x{end:x}",str(raw)]
        cp=subprocess.run(cmd,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False,timeout=120)
        if cp.returncode: raise RuntimeError("objdump failed: "+cp.stderr[-4000:])
        return cp.stdout
    finally:
        raw.unlink(missing_ok=True)

def context(ins,idx,before=12,after=8):
    return [x["text"] for x in ins[max(0,idx-before):min(len(ins),idx+after+1)]]

def classify_shape(ins):
    mn=[x["mnemonic"] for x in ins]
    text="\n".join(x["text"] for x in ins)
    counts={m:mn.count(m) for m in sorted(set(mn))}
    return {
      "instruction_count":len(ins),
      "mnemonic_counts":counts,
      "has_byte_load_store":any(m.startswith("ldrb") for m in mn) and any(m.startswith("strb") for m in mn),
      "has_halfword_load_store":any(m.startswith("ldrh") for m in mn) and any(m.startswith("strh") for m in mn),
      "has_word_load_store":any(m in {"ldr","ldmia","ldm","ldm.w"} for m in mn) and any(m in {"str","stmia","stm","stm.w"} for m in mn),
      "has_xor":any(m.startswith("eor") for m in mn),
      "has_loop_branch":any(x["mnemonic"].startswith("b") and (dp.branch_target(x) or 1<<60) < x["address"] for x in ins),
      "references_r0_r1_r2":{r:bool(re.search(rf"\b{r}\b",text)) for r in ("r0","r1","r2")},
    }

def main()->int:
    ap=argparse.ArgumentParser(); ap.add_argument("--elf",required=True); ap.add_argument("--out",required=True)
    ns=ap.parse_args(); elf=Path(ns.elf); out=Path(ns.out); out.mkdir(parents=True,exist_ok=True)
    segs=segments(elf)
    veneer={}
    for name,(entry,lit) in VENEERS.items():
        target=read_u32(elf,lit)
        base=target & ~1
        veneer[name]={"entry":entry,"literal":lit,"target":target,"thumb":bool(target&1),"target_base":base,
                      "segment":containing_segment(segs,base)}
    unique=sorted({x["target_base"] for x in veneer.values()})
    rom={}
    for base in unique:
        text=disasm_segment(elf,base,base+0x180,True)
        ins=dp.parse_instructions(text)
        rom[f"0x{base:08x}"]={"instructions":[x["text"] for x in ins],"shape":classify_shape(ins)}
        (out/f"rom-{base:08x}.txt").write_text(text)

    low=dp.parse_instructions(dp.run_objdump(elf,0,0x57018))
    callers=[]
    for i,x in enumerate(low):
        if x["mnemonic"]=="bl" and dp.branch_target(x) in CALL_TARGETS:
            callers.append({"pc":x["address"],"target":dp.branch_target(x),"context":context(low,i,18,10)})

    report={
      "schema":"wrt8964-rom-import-semantics/v1",
      "firmware_sha256":FW_SHA256,
      "segments":segs,
      "veneers":veneer,
      "callers":callers,
      "rom_targets":rom,
      "checks":{
        "rom_segment_present":any(x["vaddr"]==0xd4800000 for x in segs),
        "set_key_veneers_share_target":veneer["set_key_a"]["target"]==veneer["set_key_b"]["target"],
        "set_key_target_is_thumb":veneer["set_key_a"]["thumb"],
        "remove_key_target_is_thumb":veneer["remove_key"]["thumb"],
        "set_key_target_differs_from_remove":veneer["set_key_a"]["target"]!=veneer["remove_key"]["target"],
        "set_key_has_three_direct_callers":sum(1 for x in callers if x["target"]==0x44148)>=3,
        "remove_key_has_direct_caller":any(x["target"]==0x44230 for x in callers),
      },
      "guardrail":"Do not name ROM services or runtime regions from address proximity. Promote semantics only from instruction behavior plus caller/source agreement."
    }
    (out/"rom-import-semantics.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps(report,indent=2,sort_keys=True))
    return 0 if all(report["checks"].values()) else 3

if __name__=="__main__": raise SystemExit(main())
