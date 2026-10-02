#!/usr/bin/env python3
"""Public-safe H0-D1c symbol/call graph for exact FRITZ 7590/8.25 OSP source."""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import tarfile

SCHEMA_VERSION = 1
EXPERIMENT = "fritz-h0-d1c-boot-selector-symbol-graph/v1"

FILES = (
    "sources/kernel/linux/drivers/mtd/avm/avm_mtd.c",
    "sources/kernel/linux/drivers/mtd/avm/partparse.c",
    "sources/kernel/linux/drivers/char/tffs/include/uapi/avm/tffs/tffs.h",
    "sources/kernel/linux/drivers/char/tffs/env.c",
    "sources/kernel/linux/drivers/char/tffs/nand.c",
    "sources/kernel/linux/drivers/char/tffs/nand_noob.c",
    "sources/kernel/linux/drivers/char/avm_new/prom_config.c",
    "sources/kernel/linux/drivers/char/avm_new/prom_config_procfs.c",
    "sources/kernel/linux/drivers/char/avm_new/include/avm/enh/prom_config.h",
    "sources/kernel/linux/arch/mips/lantiq/grx500/prom.c",
    "sources/kernel/linux/arch/mips/boot/dts/lantiq/avm/grx_common.dtsi",
)

SEEDS = ("linux_fs_start", "tffs", "mtd", "prom", "urlader", "nand", "partition")
CALL_PREFIXES = ("tffs", "avm", "prom", "mtd", "nand", "urlader", "ltq", "of_")
C_KEYWORDS = {
    "if","for","while","switch","return","sizeof","typeof","do","else",
    "case","defined","__attribute__","likely","unlikely",
}
IDENT_CALL = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
FUNC_HEAD = re.compile(
    r"(?m)^[\t ]*(?:static\s+)?(?:inline\s+)?"
    r"(?:[A-Za-z_][A-Za-z0-9_\s\*]*?)[\t ]+"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\)\s*\{"
)
INCLUDE_RE = re.compile(r'(?m)^\s*#\s*include\s*[<"]([^>"]+)[>"]')
DEFINE_RE = re.compile(r"(?m)^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)\b([^\n]*)")


def sha256_file(path: pathlib.Path) -> str:
    h=hashlib.sha256()
    with path.open("rb") as fp:
        for chunk in iter(lambda:fp.read(1024*1024),b""):
            h.update(chunk)
    return h.hexdigest()


def download_exact(url,path,expected_size,expected_sha256):
    cp=subprocess.run(["curl","--fail","--location","--silent","--show-error","--output",str(path),url],
                      capture_output=True,text=True,timeout=900)
    if cp.returncode:
        raise RuntimeError(f"download failed exit={cp.returncode} stderrBytes={len(cp.stderr.encode())}")
    size=path.stat().st_size
    digest=sha256_file(path)
    if size!=expected_size: raise RuntimeError(f"size mismatch expected={expected_size} observed={size}")
    if digest.lower()!=expected_sha256.lower(): raise RuntimeError("sha256 mismatch")
    return {"bytes":size,"sha256":digest}


def extract_selected(archive: pathlib.Path) -> dict[str,str]:
    wanted=set(FILES)
    out={}
    with tarfile.open(archive,"r:*") as tf:
        for m in tf:
            name=m.name[2:] if m.name.startswith("./") else m.name
            if name not in wanted or not m.isfile():
                continue
            fp=tf.extractfile(m)
            if fp is None: continue
            out[name]=fp.read().decode("utf-8",errors="replace")
    return out


def matching_brace(text: str, open_index: int) -> int | None:
    depth=0
    i=open_index
    in_str=None
    escape=False
    while i<len(text):
        ch=text[i]
        if in_str:
            if escape:
                escape=False
            elif ch=="\\":
                escape=True
            elif ch==in_str:
                in_str=None
            i+=1
            continue
        if ch in ("'",'"'):
            in_str=ch
        elif ch=="{":
            depth+=1
        elif ch=="}":
            depth-=1
            if depth==0: return i
        i+=1
    return None


def functions(text: str) -> list[dict]:
    out=[]
    for m in FUNC_HEAD.finditer(text):
        name=m.group(1)
        if name in C_KEYWORDS:
            continue
        open_index=text.find("{",m.start(),m.end()+1)
        if open_index<0: continue
        close=matching_brace(text,open_index)
        if close is None: continue
        body=text[open_index+1:close]
        calls=sorted({
            c for c in IDENT_CALL.findall(body)
            if c not in C_KEYWORDS and c!=name
            and (c.startswith(CALL_PREFIXES) or any(seed in c.lower() for seed in SEEDS))
        })
        seed_hits=sorted(seed for seed in SEEDS if re.search(rf"\b{re.escape(seed)}\b",body,re.I))
        out.append({"name":name,"calls":calls,"seedTokens":seed_hits})
    return out


def reduce_file(path: str, text: str) -> dict:
    funcs=functions(text)
    seed_funcs=[f for f in funcs if f["seedTokens"] or f["calls"]]
    macros=[]
    for m in DEFINE_RE.finditer(text):
        name,value=m.group(1),m.group(2)
        hits=sorted(seed for seed in SEEDS if re.search(rf"\b{re.escape(seed)}\b",value,re.I))
        if hits or any(seed in name.lower() for seed in SEEDS):
            macros.append({"name":name,"seedTokens":hits})
    includes=sorted(set(INCLUDE_RE.findall(text)))
    file_tokens={seed:len(re.findall(rf"\b{re.escape(seed)}\b",text,re.I)) for seed in SEEDS}
    file_tokens={k:v for k,v in file_tokens.items() if v}
    return {
        "path":path,
        "fileTokens":file_tokens,
        "includes":includes[:100],
        "functions":seed_funcs,
        "macros":macros,
    }


def graph(reduced: dict[str,dict]) -> dict:
    defs={}
    for path,item in reduced.items():
        for f in item["functions"]:
            defs.setdefault(f["name"],[]).append(path)
    edges=[]
    for path,item in reduced.items():
        for f in item["functions"]:
            for callee in f["calls"]:
                edges.append({
                    "caller":f["name"],
                    "callerFile":path,
                    "callee":callee,
                    "calleeFiles":sorted(defs.get(callee,[])),
                })
    unique={json.dumps(x,sort_keys=True):x for x in edges}
    seed_symbols=[]
    for path,item in reduced.items():
        for f in item["functions"]:
            if f["seedTokens"]:
                seed_symbols.append({"file":path,"symbol":f["name"],"seedTokens":f["seedTokens"]})
    return {
        "seedSymbols":sorted(seed_symbols,key=lambda x:(x["file"],x["symbol"])),
        "callEdges":[unique[k] for k in sorted(unique)],
    }


def run_probe(args):
    work=pathlib.Path(args.work_dir).resolve()
    work.mkdir(parents=True,exist_ok=True)
    archive=work/"source-files.tar.gz"
    exact=download_exact(args.osp_url,archive,args.expected_size,args.expected_sha256)
    selected=extract_selected(archive)
    missing=sorted(set(FILES)-set(selected))
    reduced={path:reduce_file(path,text) for path,text in sorted(selected.items())}
    g=graph(reduced)
    return {
        "schemaVersion":SCHEMA_VERSION,
        "experiment":EXPERIMENT,
        "classification":"H0_D1C_SYMBOL_GRAPH_RECOVERED" if not missing else "H0_D1C_SELECTED_SOURCE_MISSING",
        "oracleSatisfied":not missing,
        "sourceArtifact":{
            "provider":"AVM OSP",
            "expectedBytes":args.expected_size,
            "expectedSha256":args.expected_sha256.lower(),
            "observedBytes":exact["bytes"],
            "observedSha256":exact["sha256"],
        },
        "selectedFiles":reduced,
        "missingFiles":missing,
        "graph":g,
        "interpretationBoundary":{
            "sourceLevelSymbolGraph":True,
            "exactPartitionLayoutAccepted":False,
            "dualBootSafetyAccepted":False,
            "flashDestinationAccepted":False,
            "stateTransitionSemanticsAccepted":False,
        },
        "safety":{
            "rawOspArchivePublished":False,
            "sourcePayloadPublished":False,
            "sourceSnippetsPublished":False,
            "physicalRouterContact":False,
            "flashWriteAuthorized":False,
            "bootEnvironmentMutationAuthorized":False,
        },
    }


def parse_args(argv=None):
    p=argparse.ArgumentParser()
    p.add_argument("--osp-url",required=True)
    p.add_argument("--expected-size",type=int,required=True)
    p.add_argument("--expected-sha256",required=True)
    p.add_argument("--work-dir",required=True)
    p.add_argument("--receipt",required=True)
    return p.parse_args(argv)


def main(argv=None):
    args=parse_args(argv)
    receipt=pathlib.Path(args.receipt)
    receipt.parent.mkdir(parents=True,exist_ok=True)
    try:
        data=run_probe(args)
        rc=0 if data["oracleSatisfied"] else 2
    except Exception as exc:
        data={
            "schemaVersion":SCHEMA_VERSION,"experiment":EXPERIMENT,
            "classification":"HARNESS_FAILURE","oracleSatisfied":False,
            "error":{"type":type(exc).__name__,"message":str(exc)[:1000]},
            "safety":{
                "rawOspArchivePublished":False,"sourcePayloadPublished":False,
                "sourceSnippetsPublished":False,"physicalRouterContact":False,
                "flashWriteAuthorized":False,"bootEnvironmentMutationAuthorized":False,
            },
        }
        rc=3
    receipt.write_text(json.dumps(data,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(json.dumps({"classification":data["classification"],"oracleSatisfied":data["oracleSatisfied"]},sort_keys=True))
    return rc


if __name__=="__main__":
    raise SystemExit(main())
