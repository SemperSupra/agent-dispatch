#!/usr/bin/env python3
"""E2-D13: recover MIPS PIC/GOT call targets inside exact libsvctl functions.

D12 localized R9's fixed sizes to _svctl_init (8) and _svctl_send_pkt (260) but
could not resolve PIC calls. D13 maps selected MIPS GOT entries from readelf to
gp-relative loads inside only the five admitted libsvctl functions, then accepts
a call edge only when a selected GOT load into t9 is followed by jalr t9 in a
bounded instruction window.

Durable output contains only symbol-to-symbol edges and counts. GOT addresses,
offsets, instruction addresses, and disassembly are not published.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib
import re
import shutil
import subprocess

_D12_PATH=pathlib.Path(__file__).with_name("fritz_qemu_e2_d12_libsvctl_functions.py")
_SPEC=importlib.util.spec_from_file_location("fritz_qemu_e2_d12_libsvctl_functions",_D12_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError("unable to load D12")
d12=importlib.util.module_from_spec(_SPEC);_SPEC.loader.exec_module(d12)
base=d12.base

SCHEMA_VERSION=1
EXPERIMENT="fritz-qemu-e2-d13-libsvctl-got/v1"
LIB=d12.LIB
FUNCTIONS=d12.FUNCTIONS
TARGETS=set(d12.CALL_ALLOWLIST)


def readelf_selected_got(path:pathlib.Path)->dict[int,str]:
    readelf=shutil.which("readelf")
    if not readelf:raise RuntimeError("readelf unavailable")
    cp=subprocess.run([readelf,"-a",str(path)],capture_output=True,text=True,timeout=30)
    if cp.returncode:raise RuntimeError("readelf -a failed")
    mapping={}
    for line in cp.stdout.splitlines():
        target=next(
            (name for name in TARGETS
             if re.search(rf"(?<![A-Za-z0-9_]){re.escape(name)}(?:@[^\s]+)?\s*$",line)),
            None,
        )
        if target is None:continue
        # GNU readelf MIPS GOT tables print signed gp access as N(gp).
        m=re.search(r"(?P<off>-?\d+)\(gp\)",line)
        if m:
            mapping[int(m.group("off"))]=target
    return mapping


def asm_instructions(disassembly:str)->list[str]:
    out=[]
    for line in disassembly.splitlines():
        a=d12.asm_line(line)
        if a is not None:out.append(a)
    return out


def got_load(asm:str)->tuple[str,int]|None:
    # Canonical PIC form: lw t9,OFFSET(gp), with optional register aliases.
    m=re.search(
        r"\b(?:lw|ld)\s+(?P<reg>\$?(?:t9|25))\s*,\s*(?P<off>-?\d+)\(\$?gp\)",
        asm,
    )
    if not m:return None
    return m.group("reg").lstrip("$"),int(m.group("off"))


def is_jalr_t9(asm:str)->bool:
    return bool(re.search(r"\bjalr\b[^\n]*\$?(?:t9|25)\b",asm))


def function_edges(path:pathlib.Path,objdump:str,name:str,got:dict[int,str])->dict:
    cp=subprocess.run([objdump,"-dr",f"--disassemble={name}",str(path)],
                      capture_output=True,text=True,timeout=30)
    if cp.returncode:raise RuntimeError(f"objdump failed for {name}")
    ins=asm_instructions(cp.stdout)
    loaded=[]
    accepted=[]
    for i,a in enumerate(ins):
        g=got_load(a)
        if not g:continue
        reg,off=g
        target=got.get(off)
        if target is None:continue
        loaded.append(target)
        if reg in ("t9","25") and any(is_jalr_t9(x) for x in ins[i+1:i+5]):
            accepted.append(target)
    return {
        "symbol":name,
        "selectedGotLoads":sorted(set(loaded)),
        "acceptedPicCallTargets":sorted(set(accepted)),
        "selectedGotLoadCount":len(loaded),
        "acceptedPicCallCount":len(accepted),
    }


def classify(functions:list[dict],got_count:int)->str:
    if got_count<=0:return "E2_D13_SELECTED_GOT_MAP_NOT_RECOVERED"
    if any(x["acceptedPicCallCount"]>0 for x in functions):
        return "E2_D13_LIBSVCTL_PIC_CALL_EDGES_RECOVERED"
    if any(x["selectedGotLoadCount"]>0 for x in functions):
        return "E2_D13_LIBSVCTL_GOT_LOADS_RECOVERED_CALL_PARTIAL"
    return "E2_D13_SELECTED_GOT_UNUSED_IN_BOUNDED_FUNCTIONS"


def run_probe(args):
    work=pathlib.Path(args.work_dir).resolve()
    firmware=work/"firmware.image";payload=work/"payload";roots=work/"roots";scratch=work/"scratch"
    for p in (firmware.parent,payload,roots,scratch):p.mkdir(parents=True,exist_ok=True)
    exact=base.download_exact(args.firmware_url,firmware,expected_size=args.expected_size,expected_sha256=args.expected_sha256)
    base.extract_outer(firmware,payload)
    rs=base.extract_squashfs_roots(payload,roots,scratch);root=base.select_root(rs)
    lib=(root/LIB.lstrip("/")).resolve()
    objdump=shutil.which(args.objdump)
    if not objdump:raise RuntimeError("objdump unavailable")
    got=readelf_selected_got(lib)
    funcs=[function_edges(lib,objdump,name,got) for name in FUNCTIONS]
    edge_set=sorted({
        (f["symbol"],target)
        for f in funcs for target in f["acceptedPicCallTargets"]
    })
    derived={
        "sendCallsLibcSend":("_svctl_send","send") in edge_set,
        "readCallsLibcRead":("_svctl_read","read") in edge_set,
        "connectCallsLibcConnect":("_svctl_connect","connect") in edge_set,
        "connectCallsLibcSocket":("_svctl_connect","socket") in edge_set,
        "sendPktCallsSend":("_svctl_send_pkt","_svctl_send") in edge_set,
        "initCallsConnect":("_svctl_init","_svctl_connect") in edge_set,
    }
    return {
        "schemaVersion":SCHEMA_VERSION,"experiment":EXPERIMENT,
        "classification":classify(funcs,len(got)),"oracleSatisfied":True,
        "target":{"expectedBytes":args.expected_size,"expectedSha256":args.expected_sha256.lower(),
                  "observedBytes":exact["bytes"],"observedSha256":exact["sha256"]},
        "library":{"path":LIB,"selectedGotSymbolCount":len(set(got.values())),
                   "functionPicSummaries":funcs,
                   "acceptedCallEdges":[{"source":a,"target":b} for a,b in edge_set],
                   "derived":derived},
        "interpretationBoundary":{
            "gotOffsetMappingUsedEphemerally":True,
            "boundedLoadThenJalrRequiredForAcceptedEdge":True,
            "acceptedStaticCallEdgeIsNotRuntimeExecutionProof":True,
            "r9SendOrderAccepted":False,
            "packetFieldLayoutAccepted":False,
            "protocolEnumValuesAccepted":False,
        },
        "safety":{
            "rawFirmwarePublished":False,"rootfsPublished":False,"binaryPayloadPublished":False,
            "rawDisassemblyPublished":False,"instructionAddressesPublished":False,"gotOffsetsPublished":False,
            "arbitraryBinaryStringsPublished":False,"wirePayloadPublished":False,
            "physicalRouterContact":False,"routerMutationAuthorized":False,
        },
    }


def parse_args(argv=None):
 p=argparse.ArgumentParser();p.add_argument("--firmware-url",required=True);p.add_argument("--expected-size",type=int,required=True)
 p.add_argument("--expected-sha256",required=True);p.add_argument("--objdump",default="mips-linux-gnu-objdump")
 p.add_argument("--work-dir",required=True);p.add_argument("--receipt",required=True);return p.parse_args(argv)


def main(argv=None):
 args=parse_args(argv);rp=pathlib.Path(args.receipt);rp.parent.mkdir(parents=True,exist_ok=True)
 try:data=run_probe(args);rc=0
 except Exception as exc:
  data={"schemaVersion":SCHEMA_VERSION,"experiment":EXPERIMENT,"classification":"HARNESS_FAILURE","oracleSatisfied":False,
        "error":{"type":type(exc).__name__,"message":str(exc)[:1000]},
        "safety":{"rawFirmwarePublished":False,"rootfsPublished":False,"binaryPayloadPublished":False,
                  "rawDisassemblyPublished":False,"instructionAddressesPublished":False,"gotOffsetsPublished":False,
                  "arbitraryBinaryStringsPublished":False,"wirePayloadPublished":False,
                  "physicalRouterContact":False,"routerMutationAuthorized":False}}
  rc=3
 rp.write_text(json.dumps(data,indent=2,sort_keys=True)+"\n",encoding="utf-8")
 print(json.dumps({"classification":data["classification"],"oracleSatisfied":data["oracleSatisfied"]},sort_keys=True));return rc

if __name__=="__main__":raise SystemExit(main())
