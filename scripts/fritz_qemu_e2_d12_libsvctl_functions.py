#!/usr/bin/env python3
"""E2-D12: symbol-bounded static reduction of exact libsvctl functions.

D11 established that /lib/libsvctl.so.1 is the transport carrier and exports the
named svctl functions. D12 disassembles only those exact symbols ephemerally and
persists only function sizes, instruction/branch counts, fixed 8/260/268 constant
presence, and allowlisted call-reference names.

No raw disassembly, instruction addresses, arbitrary strings, or packet bytes.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib
import re
import shutil
import subprocess

_D11_PATH=pathlib.Path(__file__).with_name("fritz_qemu_e2_d11_protocol_deps.py")
_SPEC=importlib.util.spec_from_file_location("fritz_qemu_e2_d11_protocol_deps",_D11_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError("unable to load D11 reducer")
d11=importlib.util.module_from_spec(_SPEC);_SPEC.loader.exec_module(d11)
d10=d11.d10
base=d11.base

SCHEMA_VERSION=1
EXPERIMENT="fritz-qemu-e2-d12-libsvctl-functions/v1"
LIB="/lib/libsvctl.so.1"
FUNCTIONS=("_svctl_init","_svctl_connect","_svctl_send_pkt","_svctl_send","_svctl_read")
CALL_ALLOWLIST=set(FUNCTIONS) | set(d11.ALLOWLIST_IO)
BRANCH_PREFIXES=("b","j")


def symbol_sizes(path: pathlib.Path) -> dict[str,int]:
    readelf=shutil.which("readelf")
    if not readelf:
        raise RuntimeError("readelf unavailable")
    cp=subprocess.run([readelf,"-Ws",str(path)],capture_output=True,text=True,timeout=30)
    if cp.returncode:
        raise RuntimeError("readelf symbols failed")
    out={}
    rx=re.compile(
        r"^\s*\d+:\s+[0-9A-Fa-f]+\s+(?P<size>\d+)\s+FUNC\s+\S+\s+\S+\s+"
        r"(?P<ndx>\S+)\s+(?P<name>\S+)\s*$"
    )
    for line in cp.stdout.splitlines():
        m=rx.match(line)
        if not m or m.group("ndx")=="UND":
            continue
        name=m.group("name").split("@",1)[0]
        if name in FUNCTIONS:
            out[name]=max(out.get(name,0),int(m.group("size")))
    return out


def asm_line(line: str) -> str | None:
    m=re.match(r"^\s*[0-9a-fA-F]+:\s+(?:[0-9a-fA-F]{2,8}\s+)+(?P<asm>.+)$",line)
    return m.group("asm").strip() if m else None


def mnemonic(asm: str) -> str:
    return asm.split(None,1)[0] if asm else ""


def function_summary(path: pathlib.Path, objdump: str, name: str, size: int) -> dict:
    cp=subprocess.run(
        [objdump,"-dr",f"--disassemble={name}",str(path)],
        capture_output=True,text=True,timeout=30,
    )
    if cp.returncode:
        raise RuntimeError(f"objdump symbol failed: {name}")
    instructions=[]
    calls=set()
    fixed={}
    branch_count=0
    for line in cp.stdout.splitlines():
        a=asm_line(line)
        if a is not None:
            instructions.append(a)
            op=mnemonic(a)
            if op.startswith(BRANCH_PREFIXES):
                branch_count+=1
            for hit in d10.fixed_size_hits(a):
                fixed[hit["bytes"]]=hit
        for target in CALL_ALLOWLIST:
            if target==name:
                continue
            if re.search(rf"(?<![A-Za-z0-9_]){re.escape(target)}(?![A-Za-z0-9_])",line):
                calls.add(target)
    return {
        "symbol":name,
        "functionBytes":size,
        "instructionCount":len(instructions),
        "branchOrJumpCount":branch_count,
        "fixedSizesPresent":[fixed[k] for k in sorted(fixed)],
        "allowlistedCallReferences":sorted(calls),
    }


def run_probe(args) -> dict:
    work=pathlib.Path(args.work_dir).resolve()
    firmware=work/"firmware.image";payload=work/"payload";roots=work/"roots";scratch=work/"scratch"
    for p in (firmware.parent,payload,roots,scratch): p.mkdir(parents=True,exist_ok=True)
    exact=base.download_exact(args.firmware_url,firmware,expected_size=args.expected_size,expected_sha256=args.expected_sha256)
    base.extract_outer(firmware,payload)
    rs=base.extract_squashfs_roots(payload,roots,scratch)
    root=base.select_root(rs)
    libpath=root/LIB.lstrip("/")
    if not libpath.exists():
        raise RuntimeError("exact libsvctl missing")
    real=libpath.resolve()
    objdump=shutil.which(args.objdump)
    if not objdump:
        raise RuntimeError("objdump unavailable")
    sizes=symbol_sizes(real)
    summaries=[]
    missing=[]
    for name in FUNCTIONS:
        if name not in sizes:
            missing.append(name);continue
        summaries.append(function_summary(real,objdump,name,sizes[name]))

    by={x["symbol"]:x for x in summaries}
    send_pkt=by.get("_svctl_send_pkt",{})
    read=by.get("_svctl_read",{})
    init=by.get("_svctl_init",{})
    connect=by.get("_svctl_connect",{})
    classification=(
        "E2_D12_LIBSVCTL_FUNCTION_SLICE_RECOVERED"
        if not missing else "E2_D12_LIBSVCTL_SYMBOLS_PARTIAL"
    )
    return {
        "schemaVersion":SCHEMA_VERSION,
        "experiment":EXPERIMENT,
        "classification":classification,
        "oracleSatisfied":True,
        "target":{
            "expectedBytes":args.expected_size,
            "expectedSha256":args.expected_sha256.lower(),
            "observedBytes":exact["bytes"],
            "observedSha256":exact["sha256"],
        },
        "library":{
            "path":LIB,
            "functionSummaries":summaries,
            "missingFunctions":missing,
            "derived":{
                "sendPktCallsSend": "_svctl_send" in send_pkt.get("allowlistedCallReferences",[]),
                "sendCallsLibcSend": "send" in by.get("_svctl_send",{}).get("allowlistedCallReferences",[]),
                "readCallsLibcRead": "read" in read.get("allowlistedCallReferences",[]),
                "connectCallsLibcConnect": "connect" in connect.get("allowlistedCallReferences",[]),
                "initCallsConnect": "_svctl_connect" in init.get("allowlistedCallReferences",[]),
                "sendPktHas8": any(x["bytes"]==8 for x in send_pkt.get("fixedSizesPresent",[])),
                "sendPktHas260": any(x["bytes"]==260 for x in send_pkt.get("fixedSizesPresent",[])),
                "readHas260": any(x["bytes"]==260 for x in read.get("fixedSizesPresent",[])),
            },
        },
        "interpretationBoundary":{
            "symbolBoundedDisassemblyUsedEphemerally":True,
            "callReferenceIsNotRuntimeCallProof":True,
            "fixedConstantPresenceIsNotFieldLayoutProof":True,
            "r9WireShapeMappedToStructFields":False,
            "protocolEnumValuesAccepted":False,
            "responseStateSemanticsAccepted":False,
        },
        "safety":{
            "rawFirmwarePublished":False,
            "rootfsPublished":False,
            "binaryPayloadPublished":False,
            "rawDisassemblyPublished":False,
            "instructionAddressesPublished":False,
            "arbitraryBinaryStringsPublished":False,
            "wirePayloadPublished":False,
            "physicalRouterContact":False,
            "routerMutationAuthorized":False,
        },
    }


def parse_args(argv=None):
    p=argparse.ArgumentParser()
    p.add_argument("--firmware-url",required=True)
    p.add_argument("--expected-size",type=int,required=True)
    p.add_argument("--expected-sha256",required=True)
    p.add_argument("--objdump",default="mips-linux-gnu-objdump")
    p.add_argument("--work-dir",required=True)
    p.add_argument("--receipt",required=True)
    return p.parse_args(argv)


def main(argv=None):
    args=parse_args(argv);rp=pathlib.Path(args.receipt);rp.parent.mkdir(parents=True,exist_ok=True)
    try:data=run_probe(args);rc=0
    except Exception as exc:
        data={"schemaVersion":SCHEMA_VERSION,"experiment":EXPERIMENT,"classification":"HARNESS_FAILURE","oracleSatisfied":False,
              "error":{"type":type(exc).__name__,"message":str(exc)[:1000]},
              "safety":{"rawFirmwarePublished":False,"rootfsPublished":False,"binaryPayloadPublished":False,
                        "rawDisassemblyPublished":False,"instructionAddressesPublished":False,
                        "arbitraryBinaryStringsPublished":False,"wirePayloadPublished":False,
                        "physicalRouterContact":False,"routerMutationAuthorized":False}}
        rc=3
    rp.write_text(json.dumps(data,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(json.dumps({"classification":data["classification"],"oracleSatisfied":data["oracleSatisfied"]},sort_keys=True));return rc

if __name__=="__main__":raise SystemExit(main())
