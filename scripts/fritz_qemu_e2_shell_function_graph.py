#!/usr/bin/env python3
"""Public-safe FRITZ!OS E2-D9 shell include/function activation graph."""
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
EXPERIMENT="fritz-qemu-e2-shell-function-graph/v1"
SCAN_PREFIXES=("etc/init.d/","etc/boot.d/","etc/rc")
MAX_TEXT=2*1024*1024
SAFE_SERVICES={"ctlmgr","avmipcd","net_basic","multid","dsld"}
SAFE_VERBS={"start","stop","reload","status","restart"}
UNIT_RE=re.compile(r"^[A-Za-z0-9_.@:-]+\.(?:service|target|socket|path|mount|timer)$")
FUNC_RE=re.compile(r"^\s*(?:function\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(?:\(\s*\))?\s*\{")


def read_text(path:pathlib.Path)->str|None:
    try:data=path.read_bytes()
    except OSError:return None
    if len(data)>MAX_TEXT or b"\x00" in data[:8192]: return None
    return data.decode("utf-8",errors="replace")


def safe_value(token:str)->dict:
    t=d2.clean_token(token)
    k=d2.token_kind(t)
    if t in SAFE_SERVICES:return {"kind":"service","value":t}
    if t in SAFE_VERBS:return {"kind":"verb","value":t}
    if UNIT_RE.fullmatch(t):return {"kind":"unit","value":t}
    if k.get("kind")=="variable":
        name=k.get("name")
        if name and name.isdigit():
            return {"kind":"positional","index":int(name)}
        return k
    if k.get("kind") in ("absolute_path","option"):return k
    return {"kind":"opaque","sha256":hashlib.sha256(t.encode()).hexdigest(),"length":len(t)}


def include_edges(text:str,source:str)->list[dict]:
    out=[]
    for line in text.splitlines():
        words=d2.safe_shell_words(line)
        if len(words)<2:continue
        first=d2.clean_token(words[0])
        if first not in (".","source"):continue
        p=d2.clean_token(words[1])
        if p.startswith("/etc/") and len(p)<=512:
            out.append({"source":source,"includedPath":p,"kind":"shell-source"})
    uniq={json.dumps(x,sort_keys=True):x for x in out}
    return [uniq[k] for k in sorted(uniq)]


def function_blocks(text:str)->list[tuple[str,list[str]]]:
    lines=text.splitlines()
    out=[]
    i=0
    while i<len(lines):
        m=FUNC_RE.match(lines[i])
        if not m:
            i+=1;continue
        name=m.group(1)
        body=[]
        depth=lines[i].count("{")-lines[i].count("}")
        i+=1
        while i<len(lines) and depth>0:
            body.append(lines[i])
            depth+=lines[i].count("{")-lines[i].count("}")
            i+=1
        out.append((name,body))
    return out


def function_semantics(text:str,source:str)->list[dict]:
    out=[]
    for name,body_lines in function_blocks(text):
        svctl=[]
        for line in body_lines:
            if "svctl" not in line:continue
            words=d2.safe_shell_words(line)
            for idx,w in enumerate(words):
                if pathlib.PurePosixPath(d2.clean_token(w)).name!="svctl":continue
                tail=[]
                for raw in words[idx+1:]:
                    t=d2.clean_token(raw)
                    if t in (";","&&","||","|"):break
                    tail.append(t)
                verb=next((x for x in tail if x in SAFE_VERBS),None)
                after=[]
                if verb:
                    vi=tail.index(verb);after=tail[vi+1:vi+4]
                svctl.append({
                    "verb":verb,
                    "operandShape":[safe_value(x) for x in after],
                    "argCount":len(tail),
                })
        if svctl:
            out.append({"source":source,"function":name,"svctl":svctl})
    return out


def simple_bindings(text:str,source:str)->list[dict]:
    out=[]
    assign=re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^#;]+)")
    for line in text.splitlines():
        m=assign.match(line)
        if not m:continue
        var=m.group(1);rhs=m.group(2).strip().strip("'\"")
        if rhs in SAFE_SERVICES:
            out.append({"source":source,"variable":var,"kind":"service","value":rhs})
        elif UNIT_RE.fullmatch(rhs):
            out.append({"source":source,"variable":var,"kind":"unit","value":rhs})
    return out


def function_calls(text:str,source:str,known:set[str])->list[dict]:
    out=[]
    inside=set(name for name,_ in function_blocks(text))
    for line in text.splitlines():
        words=d2.safe_shell_words(line)
        if not words:continue
        cmd=d2.clean_token(words[0])
        if cmd not in known or cmd in inside:
            continue
        args=[]
        for raw in words[1:]:
            t=d2.clean_token(raw)
            if t in (";","&&","||","|"):break
            args.append(safe_value(t))
        out.append({"source":source,"function":cmd,"args":args[:8],"argCount":len(args)})
    return out


def resolve_call_to_svctl(call:dict,semantics:dict[str,list[dict]],bindings:list[dict])->list[dict]:
    out=[]
    by_var={(b["source"],b["variable"]):b for b in bindings}
    for f in semantics.get(call["function"],[]):
        for sv in f.get("svctl",[]):
            if not sv.get("verb"):continue
            operands=sv.get("operandShape",[])
            if not operands:continue
            op=operands[0]
            resolved=None
            if op.get("kind")=="positional":
                idx=op["index"]-1
                if 0<=idx<len(call["args"]):
                    arg=call["args"][idx]
                    if arg.get("kind") in ("service","unit"):
                        resolved={"kind":arg["kind"],"value":arg["value"],"evidence":"call-literal"}
                    elif arg.get("kind")=="variable":
                        b=by_var.get((call["source"],arg["name"]))
                        if b:
                            resolved={"kind":b["kind"],"value":b["value"],"evidence":"caller-variable-binding","variable":arg["name"]}
            elif op.get("kind") in ("service","unit"):
                resolved={"kind":op["kind"],"value":op["value"],"evidence":"function-literal"}
            if resolved:
                out.append({
                    "callerSource":call["source"],
                    "function":call["function"],
                    "verb":sv["verb"],
                    "operandKind":resolved["kind"],
                    "operand":resolved["value"],
                    "evidence":resolved["evidence"],
                    **({"variable":resolved["variable"]} if "variable" in resolved else {}),
                })
    return out


def recover(root:pathlib.Path)->dict:
    texts={}
    includes=[]
    func_sem=[]
    binds=[]
    for path in base.regular_files(root):
        rel=str(path.relative_to(root)).replace(os.sep,"/")
        if not rel.startswith(SCAN_PREFIXES):continue
        text=read_text(path)
        if text is None:continue
        source="/"+rel
        edge=include_edges(text,source)
        fs=function_semantics(text,source)
        if edge or fs or "rc.ptest.env" in rel or "rc.net" in rel:
            texts[source]=text
        includes.extend(edge);func_sem.extend(fs);binds.extend(simple_bindings(text,source))

    known={x["function"] for x in func_sem}
    calls=[]
    for source,text in texts.items():
        calls.extend(function_calls(text,source,known))

    semantics={}
    for item in func_sem:semantics.setdefault(item["function"],[]).append(item)
    resolved=[]
    for call in calls:resolved.extend(resolve_call_to_svctl(call,semantics,binds))
    uniq={json.dumps(x,sort_keys=True):x for x in resolved}
    resolved=[uniq[k] for k in sorted(uniq)]
    ctl=[x for x in resolved if x["operand"]=="ctlmgr" and x["verb"]=="start"]

    return {
        "includeEdges":includes,
        "svctlFunctionDefinitions":func_sem,
        "functionCalls":calls,
        "safeBindings":binds,
        "resolvedControlRelations":resolved,
        "resolvedCtlmgrStartRelations":ctl,
        "derived":{
            "includeEdgeCount":len(includes),
            "svctlFunctionCount":len(func_sem),
            "callCount":len(calls),
            "resolvedControlRelationCount":len(resolved),
            "ctlmgrStartBindingProven":bool(ctl),
        },
    }


def run_probe(args):
    work=pathlib.Path(args.work_dir).resolve()
    fw=work/"original"/"firmware.image";payload=work/"payload";roots=work/"roots";scratch=work/"scratch"
    for p in (fw.parent,payload,roots,scratch):p.mkdir(parents=True,exist_ok=True)
    exact=base.download_exact(args.firmware_url,fw,expected_size=args.expected_size,expected_sha256=args.expected_sha256)
    outer=base.extract_outer(fw,payload);rs=base.extract_squashfs_roots(payload,roots,scratch);root=base.select_root(rs)
    graph=recover(root)
    return {
        "schemaVersion":SCHEMA_VERSION,"experiment":EXPERIMENT,
        "classification":"E2_SHELL_FUNCTION_GRAPH_RECOVERED","oracleSatisfied":True,
        "target":{"expectedBytes":args.expected_size,"expectedSha256":args.expected_sha256.lower(),"observedBytes":exact["bytes"],"observedSha256":exact["sha256"]},
        "extraction":{"outerMemberCount":len(outer),"squashfsRootCount":len(rs),"selectedRootRegularFileCount":base.root_file_count(root)},
        "graph":graph,
        "safety":{"rawFirmwarePublished":False,"rootfsPublished":False,"rawShellContentPublished":False,"arbitraryStringsPublished":False,"physicalRouterContact":False,"routerMutationAuthorized":False},
    }


def parse_args(argv=None):
    p=argparse.ArgumentParser()
    p.add_argument("--firmware-url",required=True);p.add_argument("--expected-size",type=int,required=True)
    p.add_argument("--expected-sha256",required=True);p.add_argument("--work-dir",required=True);p.add_argument("--receipt",required=True)
    return p.parse_args(argv)


def main(argv=None):
    args=parse_args(argv);rp=pathlib.Path(args.receipt);rp.parent.mkdir(parents=True,exist_ok=True)
    try:data=run_probe(args);rc=0
    except Exception as exc:
        data={"schemaVersion":SCHEMA_VERSION,"experiment":EXPERIMENT,"classification":"HARNESS_FAILURE","oracleSatisfied":False,
              "error":{"type":type(exc).__name__,"message":str(exc)[:1000]},
              "safety":{"rawFirmwarePublished":False,"rootfsPublished":False,"rawShellContentPublished":False,"arbitraryStringsPublished":False,"physicalRouterContact":False,"routerMutationAuthorized":False}}
        rc=3
    rp.write_text(json.dumps(data,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(json.dumps({"classification":data["classification"],"oracleSatisfied":data["oracleSatisfied"]},sort_keys=True))
    return rc
if __name__=="__main__":raise SystemExit(main())
