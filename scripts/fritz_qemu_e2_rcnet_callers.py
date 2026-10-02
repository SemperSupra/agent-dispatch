#!/usr/bin/env python3
"""Public-safe FRITZ!OS E2-D8 rc.net caller and argv binding recovery."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import re

_BASE=pathlib.Path(__file__).with_name("fritz_qemu_user_probe.py")
_BSPEC=importlib.util.spec_from_file_location("fritz_qemu_user_probe",_BASE)
if _BSPEC is None or _BSPEC.loader is None: raise RuntimeError("unable to load base")
base=importlib.util.module_from_spec(_BSPEC);_BSPEC.loader.exec_module(base)

_D2=pathlib.Path(__file__).with_name("fritz_qemu_e2_startup_semantics.py")
_D2SPEC=importlib.util.spec_from_file_location("fritz_qemu_e2_startup_semantics",_D2)
if _D2SPEC is None or _D2SPEC.loader is None: raise RuntimeError("unable to load startup reducer")
d2=importlib.util.module_from_spec(_D2SPEC);_D2SPEC.loader.exec_module(d2)

SCHEMA_VERSION=1
EXPERIMENT="fritz-qemu-e2-rcnet-callers/v1"
RC_NET="/etc/init.d/rc.net"
SAFE_SERVICES={"ctlmgr","avmipcd","net_basic","multid","dsld"}
SAFE_VERBS={"start","stop","reload","status","restart"}
UNIT_RE=re.compile(r"^[A-Za-z0-9_.@:-]+\.(?:service|target|socket|path|mount|timer)$")
SCAN_PREFIXES=("etc/","var/","usr/")
MAX_TEXT=2*1024*1024


def read_text(path:pathlib.Path)->str|None:
    try:data=path.read_bytes()
    except OSError:return None
    if len(data)>MAX_TEXT or b"\x00" in data[:8192]:return None
    return data.decode("utf-8",errors="replace")


def safe_arg(token:str)->dict:
    t=d2.clean_token(token)
    k=d2.token_kind(t)
    if t in SAFE_SERVICES:return {"kind":"service","value":t}
    if t in SAFE_VERBS:return {"kind":"verb","value":t}
    if UNIT_RE.fullmatch(t):return {"kind":"unit","value":t}
    if k.get("kind") in ("variable","absolute_path","option"):return k
    if re.fullmatch(r"\$[0-9]",t):return {"kind":"positional","index":int(t[1:])}
    return {"kind":"opaque","sha256":hashlib.sha256(t.encode()).hexdigest(),"length":len(t)}


def simple_bindings(text:str,source:str)->list[dict]:
    out=[]
    assign=re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^#;]+)")
    for line in text.splitlines():
        m=assign.match(line)
        if not m:continue
        var=m.group(1);rhs=m.group(2).strip().strip("'\"")
        if rhs in SAFE_SERVICES:
            out.append({"source":source,"variable":var,"valueKind":"service","value":rhs,"binding":"assignment"})
        elif UNIT_RE.fullmatch(rhs):
            out.append({"source":source,"variable":var,"valueKind":"unit","value":rhs,"binding":"assignment"})
    for_re=re.compile(r"\bfor\s+([A-Za-z_][A-Za-z0-9_]*)\s+in\s+([^;]+)")
    for line in text.splitlines():
        m=for_re.search(line)
        if not m:continue
        var=m.group(1)
        for tok in (d2.clean_token(x) for x in m.group(2).split()):
            if tok in SAFE_SERVICES:
                out.append({"source":source,"variable":var,"valueKind":"service","value":tok,"binding":"for-list"})
            elif UNIT_RE.fullmatch(tok):
                out.append({"source":source,"variable":var,"valueKind":"unit","value":tok,"binding":"for-list"})
    uniq={json.dumps(x,sort_keys=True):x for x in out}
    return [uniq[k] for k in sorted(uniq)]


def rcnet_calls(text:str,source:str)->list[dict]:
    out=[]
    for line in text.splitlines():
        if "rc.net" not in line:continue
        words=d2.safe_shell_words(line)
        for i,w in enumerate(words):
            t=d2.clean_token(w)
            if pathlib.PurePosixPath(t).name!="rc.net":continue
            args=[]
            for raw in words[i+1:]:
                z=d2.clean_token(raw)
                if z in (";","&&","||","|"):break
                args.append(safe_arg(z))
            out.append({"source":source,"controller":RC_NET if t.startswith("/") else "rc.net","args":args[:8],"argCount":len(args)})
    return out


def resolve(calls:list[dict],bindings:list[dict])->list[dict]:
    by_var={}
    for b in bindings:by_var.setdefault((b["source"],b["variable"]),[]).append(b)
    out=[]
    for call in calls:
        if not call["args"]:continue
        first=call["args"][0]
        if first.get("kind") in ("service","unit"):
            out.append({"source":call["source"],"argv1Kind":first["kind"],"argv1":first["value"],"evidence":"literal"})
        elif first.get("kind")=="variable":
            for b in by_var.get((call["source"],first["name"]),[]):
                out.append({"source":call["source"],"argv1Kind":b["valueKind"],"argv1":b["value"],"variable":first["name"],"evidence":"same-file-variable-binding","binding":b["binding"]})
    uniq={json.dumps(x,sort_keys=True):x for x in out}
    return [uniq[k] for k in sorted(uniq)]


def recover(root:pathlib.Path)->dict:
    calls=[];binds=[];scanned=[]
    for path in base.regular_files(root):
        rel=str(path.relative_to(root)).replace(os.sep,"/")
        if not rel.startswith(SCAN_PREFIXES):continue
        text=read_text(path)
        if text is None or "rc.net" not in text:continue
        source="/"+rel
        scanned.append(source)
        calls.extend(rcnet_calls(text,source))
        binds.extend(simple_bindings(text,source))
    resolved=resolve(calls,binds)
    ctl=[x for x in resolved if x["argv1"]=="ctlmgr"]
    admitted=[x for x in resolved if x["argv1"] in SAFE_SERVICES or x["argv1"].endswith((".service",".target"))]
    return {
        "scannedCallerFiles":sorted(set(scanned)),
        "rcNetCalls":calls,
        "safeBindings":binds,
        "resolvedArgv1":resolved,
        "resolvedCtlmgrCallers":ctl,
        "resolvedServiceOrUnitCallers":admitted,
        "derived":{
            "callerCount":len(calls),
            "resolvedArgv1Count":len(resolved),
            "ctlmgrBindingProven":bool(ctl),
        },
    }


def run_probe(args):
    work=pathlib.Path(args.work_dir).resolve()
    fw=work/"original"/"firmware.image";payload=work/"payload";roots=work/"roots";scratch=work/"scratch"
    for p in (fw.parent,payload,roots,scratch):p.mkdir(parents=True,exist_ok=True)
    exact=base.download_exact(args.firmware_url,fw,expected_size=args.expected_size,expected_sha256=args.expected_sha256)
    outer=base.extract_outer(fw,payload);rs=base.extract_squashfs_roots(payload,roots,scratch);root=base.select_root(rs)
    rec=recover(root)
    return {
        "schemaVersion":SCHEMA_VERSION,"experiment":EXPERIMENT,
        "classification":"E2_RCNET_CALLERS_RECOVERED","oracleSatisfied":True,
        "target":{"expectedBytes":args.expected_size,"expectedSha256":args.expected_sha256.lower(),"observedBytes":exact["bytes"],"observedSha256":exact["sha256"]},
        "extraction":{"outerMemberCount":len(outer),"squashfsRootCount":len(rs),"selectedRootRegularFileCount":base.root_file_count(root)},
        "callers":rec,
        "safety":{"rawFirmwarePublished":False,"rootfsPublished":False,"rawInitContentPublished":False,"arbitraryStringsPublished":False,"physicalRouterContact":False,"routerMutationAuthorized":False},
    }


def parse_args(argv=None):
    p=argparse.ArgumentParser()
    for name in ("firmware-url","expected-sha256","work-dir","receipt"):p.add_argument("--"+name,required=True)
    p.add_argument("--expected-size",type=int,required=True)
    return p.parse_args(argv)


def main(argv=None):
    args=parse_args(argv);rp=pathlib.Path(args.receipt);rp.parent.mkdir(parents=True,exist_ok=True)
    try:data=run_probe(args);rc=0
    except Exception as exc:
        data={"schemaVersion":SCHEMA_VERSION,"experiment":EXPERIMENT,"classification":"HARNESS_FAILURE","oracleSatisfied":False,
              "error":{"type":type(exc).__name__,"message":str(exc)[:1000]},
              "safety":{"rawFirmwarePublished":False,"rootfsPublished":False,"rawInitContentPublished":False,"arbitraryStringsPublished":False,"physicalRouterContact":False,"routerMutationAuthorized":False}}
        rc=3
    rp.write_text(json.dumps(data,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(json.dumps({"classification":data["classification"],"oracleSatisfied":data["oracleSatisfied"]},sort_keys=True))
    return rc
if __name__=="__main__":raise SystemExit(main())
