#!/usr/bin/env python3
"""Recover a bounded host-command case map from the 88W8964 dispatcher.

Input is the transient ELF reconstructed by wrt3200acm_fw_to_elf.py.  Output is
derived instruction/control-flow metadata only; no firmware-bearing file is
written to the evidence directory.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import urllib.request
from pathlib import Path
from typing import Any

HOSTCMD_URL = "https://raw.githubusercontent.com/kaloz/mwlwifi/db97edf20fadea2617805006f5230665fadc6a8c/hif/hostcmd.h"
CMD_RE = re.compile(r"^\s*#define\s+(HOSTCMD_CMD_[A-Z0-9_]+)\s+(0x[0-9A-Fa-f]+)\b", re.M)
INS_RE = re.compile(r"^\s*([0-9a-fA-F]+):\s+(?:[0-9a-fA-F]{2,8}\s+)+([a-zA-Z][a-zA-Z0-9.]*)\s*(.*?)\s*$")
IMM_RE = re.compile(r"#(0x[0-9a-fA-F]+|[0-9]+)")
REG_RE = re.compile(r"\b(r(?:1[0-2]|[0-9])|lr|ip)\b", re.I)

DISPATCH_START = 0x36454
DISPATCH_END = 0x390EC

def fetch_text(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent":"SemperSupra-WRT-dispatch-probe/1.0"})
    with urllib.request.urlopen(req, timeout=45) as r:
        return r.read().decode("utf-8", "replace")

def parse_hostcmd(text: str) -> dict[int, str]:
    return {int(v,16): n for n,v in CMD_RE.findall(text)}

def run_objdump(elf: Path, start: int, end: int) -> str:
    """Disassemble the 0-based PT_LOAD even though the synthetic ELF is sectionless."""
    data=elf.read_bytes()
    if data[:4] != b"\x7fELF" or data[4] != 1 or data[5] != 1:
        raise ValueError("expected ELF32 little-endian analysis container")
    phoff=__import__("struct").unpack_from("<I",data,28)[0]
    phentsize=__import__("struct").unpack_from("<H",data,42)[0]
    phnum=__import__("struct").unpack_from("<H",data,44)[0]
    segment=None
    for i in range(phnum):
        off=phoff+i*phentsize
        p_type,p_offset,p_vaddr,_p_paddr,p_filesz,_p_memsz,_flags,_align=__import__("struct").unpack_from("<IIIIIIII",data,off)
        if p_type==1 and p_vaddr==0:
            segment=data[p_offset:p_offset+p_filesz]
            break
    if segment is None:
        raise ValueError("0-based PT_LOAD not found")
    raw=elf.with_name(elf.name+".seg0.tmp")
    raw.write_bytes(segment)
    try:
        cmd=[
            "arm-linux-gnueabi-objdump","-D","-b","binary","-m","arm","-EL","-M","reg-names-std",
            f"--start-address=0x{start:x}",f"--stop-address=0x{end:x}",str(raw)
        ]
        cp=subprocess.run(cmd,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False,timeout=120)
        if cp.returncode:
            raise RuntimeError("objdump failed: "+cp.stderr[-4000:])
        return cp.stdout
    finally:
        raw.unlink(missing_ok=True)

def parse_instructions(text: str) -> list[dict[str, Any]]:
    out=[]
    for line in text.splitlines():
        m=INS_RE.match(line)
        if not m:
            continue
        out.append({
            "address": int(m.group(1),16),
            "mnemonic": m.group(2).lower(),
            "operands": m.group(3).strip(),
            "text": f"{m.group(1).lower()}: {m.group(2).lower()} {m.group(3).strip()}".rstrip(),
        })
    return out

def branch_target(ins: dict[str, Any]) -> int|None:
    if not ins["mnemonic"].startswith("b"):
        return None
    m=re.search(r"\b([0-9a-fA-F]{4,8})\b",ins["operands"])
    return int(m.group(1),16) if m else None

def immediate(ins: dict[str, Any]) -> int|None:
    m=IMM_RE.search(ins["operands"])
    return int(m.group(1),0) if m else None

def dest_reg(ins: dict[str, Any]) -> str|None:
    op=ins["operands"].split(",",1)[0].strip().lower()
    return op if re.fullmatch(r"r(?:1[0-2]|[0-9])|lr|ip",op) else None

def recover_cases(insns: list[dict[str, Any]], commands: dict[int,str]) -> list[dict[str, Any]]:
    cases=[]
    seen=set()

    def emit(i:int,value:int,target:int,kind:str,seq_start:int):
        if value not in commands:
            return
        key=(value,target)
        if key in seen:
            return
        seen.add(key)
        lo=max(0,seq_start)
        hi=min(len(insns),i+2)
        cases.append({
            "command":commands[value],
            "value":value,
            "hex":f"0x{value:04x}",
            "branch_target":target,
            "match_kind":kind,
            "evidence":[x["text"] for x in insns[lo:hi]],
        })

    # Direct compare/subtract of r12 against immediate, followed by BEQ.
    for i,ins in enumerate(insns):
        if ins["mnemonic"] not in {"cmp","cmn","sub","subs","subw"}:
            continue
        if "r12" not in ins["operands"].lower():
            continue
        val=immediate(ins)
        if val is None or val not in commands:
            continue
        for j in range(i+1,min(len(insns),i+4)):
            if insns[j]["mnemonic"]=="beq":
                t=branch_target(insns[j])
                if t is not None:
                    emit(j,val,t,"direct-immediate",i)
                break
            if insns[j]["mnemonic"].startswith("b") and insns[j]["mnemonic"]!="beq":
                break

    # mov/movw reg,#command then compare/sub r12 against that reg, then BEQ.
    for i,ins in enumerate(insns):
        if ins["mnemonic"] not in {"mov","movw"}:
            continue
        val=immediate(ins)
        reg=dest_reg(ins)
        if val is None or reg is None or val not in commands:
            continue
        for j in range(i+1,min(len(insns),i+6)):
            x=insns[j]
            ops=x["operands"].lower()
            if x["mnemonic"] in {"cmp","cmn","sub","subs","subw"} and "r12" in ops and re.search(r"\b"+re.escape(reg)+r"\b",ops):
                for k in range(j+1,min(len(insns),j+4)):
                    if insns[k]["mnemonic"]=="beq":
                        t=branch_target(insns[k])
                        if t is not None:
                            emit(k,val,t,"loaded-immediate",i)
                        break
                    if insns[k]["mnemonic"].startswith("b") and insns[k]["mnemonic"]!="beq":
                        break
                break
    return sorted(cases,key=lambda x:(x["value"],x["branch_target"]))

def main() -> int:
    ap=argparse.ArgumentParser()
    ap.add_argument("--elf",required=True)
    ap.add_argument("--out",required=True)
    ns=ap.parse_args()
    out=Path(ns.out); out.mkdir(parents=True,exist_ok=True)
    elf=Path(ns.elf)
    commands=parse_hostcmd(fetch_text(HOSTCMD_URL))
    disasm=run_objdump(elf,DISPATCH_START,DISPATCH_END)
    insns=parse_instructions(disasm)
    cases=recover_cases(insns,commands)

    normalized=[
        i for i in insns
        if i["address"] in range(0x364b0,0x36590)
    ]
    report={
        "schema":"wrt8964-hostcmd-dispatch-case-map/v1",
        "source_hostcmd":HOSTCMD_URL,
        "dispatcher":{"start":DISPATCH_START,"end":DISPATCH_END},
        "instruction_count":len(insns),
        "known_hostcmd_count":len(commands),
        "recovered_case_count":len(cases),
        "recovered_distinct_command_count":len({c["value"] for c in cases}),
        "cases":cases,
        "normalization_region":[i["text"] for i in normalized],
        "acceptance_checks":{
            "ap_beacon_0x1101_to_0x36edc":any(c["value"]==0x1101 and c["branch_target"]==0x36edc for c in cases),
            "set_rf_channel_0x010a_to_0x37984":any(c["value"]==0x010a and c["branch_target"]==0x37984 for c in cases),
        },
        "caveat":"This maps static comparison/branch cases. Handler semantics remain hypotheses until each branch target is independently characterized."
    }
    (out/"dispatch-case-map.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    # Derived bounded disassembly only; never copy the ELF into evidence.
    (out/"dispatcher-disassembly.txt").write_text(disasm)
    print(json.dumps({
        "instructions":len(insns),
        "cases":len(cases),
        "distinct_commands":len({c["value"] for c in cases}),
        "acceptance":report["acceptance_checks"]
    },indent=2,sort_keys=True))
    if not all(report["acceptance_checks"].values()):
        return 3
    return 0

if __name__=="__main__":
    raise SystemExit(main())
