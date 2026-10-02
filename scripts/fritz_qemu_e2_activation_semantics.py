#!/usr/bin/env python3
"""Public-safe FRITZ!OS E2-D7 supervisor/svctl activation-semantics recovery."""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import pathlib
import re

_BASE = pathlib.Path(__file__).with_name("fritz_qemu_user_probe.py")
_BSPEC = importlib.util.spec_from_file_location("fritz_qemu_user_probe", _BASE)
if _BSPEC is None or _BSPEC.loader is None:
    raise RuntimeError("unable to load base probe")
base = importlib.util.module_from_spec(_BSPEC)
_BSPEC.loader.exec_module(base)

_D2 = pathlib.Path(__file__).with_name("fritz_qemu_e2_startup_semantics.py")
_D2SPEC = importlib.util.spec_from_file_location("fritz_qemu_e2_startup_semantics", _D2)
if _D2SPEC is None or _D2SPEC.loader is None:
    raise RuntimeError("unable to load startup reducer")
d2 = importlib.util.module_from_spec(_D2SPEC)
_D2SPEC.loader.exec_module(d2)

SCHEMA_VERSION = 1
EXPERIMENT = "fritz-qemu-e2-activation-semantics/v1"
SUPERVISOR = "/bin/supervisor"
SVCTL = "/bin/svctl"
FIXED_VERBS = ("start","stop","restart","reload","status")
FIXED_OBJECT_WORDS = ("service","target","unit","supervisor")
SCAN_PREFIXES = ("etc/init.d/","etc/boot.d/","etc/rc")
UNIT_RE = re.compile(r"^[A-Za-z0-9_.@:-]+\.(?:service|target|socket|path|mount|timer)$")
MAX_TEXT = 2 * 1024 * 1024


def binary_fixed_tokens(path: pathlib.Path) -> dict:
    data=path.read_bytes()
    def count_ascii(token: str) -> int:
        rx=re.compile(rb"(?<![A-Za-z0-9_])"+re.escape(token.encode())+rb"(?![A-Za-z0-9_])", re.I)
        return len(rx.findall(data))
    return {
        "path":"/"+str(path).split("/",1)[-1] if False else None,
        "verbCounts":{v:count_ascii(v) for v in FIXED_VERBS},
        "objectWordCounts":{v:count_ascii(v) for v in FIXED_OBJECT_WORDS},
        "bytes":len(data),
    }


def classify_operand(token: str) -> dict:
    t=d2.clean_token(token)
    k=d2.token_kind(t)
    if UNIT_RE.fullmatch(t):
        return {"kind":"unit","value":t}
    if k.get("kind") in ("variable","service","absolute_path","verb","option"):
        return k
    if re.fullmatch(r"\$[0-9]",t):
        return {"kind":"positional","index":int(t[1:])}
    return {"kind":"opaque","sha256":k.get("sha256"),"length":k.get("length")}


def svctl_invocations(text: str, source: str) -> list[dict]:
    out=[]
    for line in text.splitlines():
        if "svctl" not in line:
            continue
        words=d2.safe_shell_words(line)
        for i,w in enumerate(words):
            if pathlib.PurePosixPath(d2.clean_token(w)).name!="svctl":
                continue
            tail=[]
            for x in words[i+1:]:
                t=d2.clean_token(x)
                if t in (";","&&","||","|"):
                    break
                tail.append(t)
            verb=next((t for t in tail if t in FIXED_VERBS),None)
            after=[]
            if verb is not None:
                vi=tail.index(verb)
                after=tail[vi+1:vi+4]
            out.append({
                "source":source,
                "verb":verb,
                "operandShape":[classify_operand(x) for x in after],
                "argCount":len(tail),
            })
    return out


def variable_unit_bindings(text: str, source: str) -> list[dict]:
    out=[]
    assign=re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^#;]+)")
    for line in text.splitlines():
        m=assign.match(line)
        if not m:
            continue
        var=m.group(1)
        rhs=m.group(2).strip().strip("'\"")
        if UNIT_RE.fullmatch(rhs):
            out.append({"source":source,"variable":var,"unit":rhs,"binding":"assignment"})
        default=re.fullmatch(
            r"\$\{([A-Za-z_][A-Za-z0-9_]*):-([A-Za-z0-9_.@:-]+\.(?:service|target|socket|path|mount|timer))\}",
            rhs
        )
        if default:
            out.append({
                "source":source,"variable":var,"unit":default.group(2),
                "binding":"parameter-default","sourceVariable":default.group(1)
            })
    for_re=re.compile(r"\bfor\s+([A-Za-z_][A-Za-z0-9_]*)\s+in\s+([^;]+)")
    for line in text.splitlines():
        m=for_re.search(line)
        if not m:
            continue
        for tok in [d2.clean_token(x) for x in m.group(2).split()]:
            if UNIT_RE.fullmatch(tok):
                out.append({"source":source,"variable":m.group(1),"unit":tok,"binding":"for-list"})
    uniq={json.dumps(x,sort_keys=True):x for x in out}
    return [uniq[k] for k in sorted(uniq)]


def correlate(invocations: list[dict], bindings: list[dict]) -> list[dict]:
    by_var={}
    for b in bindings:
        by_var.setdefault((b["source"],b["variable"]),[]).append(b)
    rel=[]
    for inv in invocations:
        if inv.get("verb") is None:
            continue
        for op in inv.get("operandShape",[]):
            if op.get("kind")=="unit":
                rel.append({
                    "source":inv["source"],"controller":"svctl","verb":inv["verb"],
                    "unit":op["value"],"evidence":"literal"
                })
            elif op.get("kind")=="variable":
                for b in by_var.get((inv["source"],op["name"]),[]):
                    rel.append({
                        "source":inv["source"],"controller":"svctl","verb":inv["verb"],
                        "unit":b["unit"],"variable":op["name"],
                        "evidence":"same-file-variable-binding",
                        "binding":b["binding"]
                    })
    uniq={json.dumps(x,sort_keys=True):x for x in rel}
    return [uniq[k] for k in sorted(uniq)]


def read_text(path: pathlib.Path) -> str|None:
    try:data=path.read_bytes()
    except OSError:return None
    if len(data)>MAX_TEXT or b"\x00" in data[:8192]:return None
    return data.decode("utf-8",errors="replace")


def recover(root: pathlib.Path) -> dict:
    supervisor=root/SUPERVISOR.lstrip("/")
    svctl=root/SVCTL.lstrip("/")
    if not supervisor.is_file() or not svctl.is_file():
        raise RuntimeError("supervisor/svctl missing")
    bins={
        "supervisor":binary_fixed_tokens(supervisor),
        "svctl":binary_fixed_tokens(svctl),
    }
    bins["supervisor"]["path"]=SUPERVISOR
    bins["svctl"]["path"]=SVCTL

    inv=[]
    bindings=[]
    supervisor_inv=[]
    scanned=[]
    for path in base.regular_files(root):
        rel=str(path.relative_to(root)).replace(os.sep,"/")
        if not rel.startswith(SCAN_PREFIXES):
            continue
        text=read_text(path)
        if text is None or not any(k in text for k in ("svctl","supervisor")):
            continue
        source="/"+rel
        scanned.append(source)
        inv.extend(svctl_invocations(text,source))
        bindings.extend(variable_unit_bindings(text,source))
        supervisor_inv.extend(d2.supervisor_invocations(text,source))
    relations=correlate(inv,bindings)

    start_inv=[x for x in inv if x.get("verb")=="start"]
    exact_start_rel=[x for x in relations if x.get("verb")=="start"]
    target_start_rel=[x for x in exact_start_rel if x["unit"].endswith(".target")]
    service_start_rel=[x for x in exact_start_rel if x["unit"].endswith(".service")]

    return {
        "binaryFixedTokens":bins,
        "scannedTextFiles":sorted(set(scanned)),
        "supervisorInvocations":supervisor_inv,
        "svctlInvocations":inv,
        "unitBindings":bindings,
        "resolvedSvctlRelations":relations,
        "derived": {
            "svctlStartTokenPresent": bins["svctl"]["verbCounts"]["start"] > 0,
            "startupUsesSvctlStart": bool(start_inv),
            "resolvedLiteralOrBoundStartRelations":len(exact_start_rel),
            "resolvedTargetStartRelations":target_start_rel,
            "resolvedServiceStartRelations":service_start_rel,
            "supervisorBootInvocationCount":len(supervisor_inv),
        },
    }


def run_probe(args):
    work=pathlib.Path(args.work_dir).resolve()
    firmware=work/"original"/"firmware.image"
    payload=work/"payload"; roots=work/"roots"; scratch=work/"scratch"
    for p in (firmware.parent,payload,roots,scratch):p.mkdir(parents=True,exist_ok=True)
    exact=base.download_exact(args.firmware_url,firmware,expected_size=args.expected_size,expected_sha256=args.expected_sha256)
    outer=base.extract_outer(firmware,payload)
    rs=base.extract_squashfs_roots(payload,roots,scratch)
    root=base.select_root(rs)
    activation=recover(root)
    return {
        "schemaVersion":SCHEMA_VERSION,
        "experiment":EXPERIMENT,
        "classification":"E2_ACTIVATION_SEMANTICS_RECOVERED",
        "oracleSatisfied":activation["derived"]["svctlStartTokenPresent"] and activation["derived"]["startupUsesSvctlStart"],
        "target":{"expectedBytes":args.expected_size,"expectedSha256":args.expected_sha256.lower(),
                  "observedBytes":exact["bytes"],"observedSha256":exact["sha256"]},
        "extraction":{"outerMemberCount":len(outer),"squashfsRootCount":len(rs),
                      "selectedRootRegularFileCount":base.root_file_count(root)},
        "activation":activation,
        "safety":{
            "rawFirmwarePublished":False,"rootfsPublished":False,"binaryPayloadPublished":False,
            "arbitraryBinaryStringsPublished":False,"rawInitContentPublished":False,
            "physicalRouterContact":False,"routerMutationAuthorized":False,
        },
    }


def parse_args(argv=None):
    p=argparse.ArgumentParser()
    p.add_argument("--firmware-url",required=True)
    p.add_argument("--expected-size",required=True,type=int)
    p.add_argument("--expected-sha256",required=True)
    p.add_argument("--work-dir",required=True)
    p.add_argument("--receipt",required=True)
    return p.parse_args(argv)


def main(argv=None):
    args=parse_args(argv)
    rp=pathlib.Path(args.receipt);rp.parent.mkdir(parents=True,exist_ok=True)
    try:
        data=run_probe(args);rc=0 if data["oracleSatisfied"] else 2
    except Exception as exc:
        data={"schemaVersion":SCHEMA_VERSION,"experiment":EXPERIMENT,"classification":"HARNESS_FAILURE",
              "oracleSatisfied":False,"error":{"type":type(exc).__name__,"message":str(exc)[:1000]},
              "safety":{"rawFirmwarePublished":False,"rootfsPublished":False,"binaryPayloadPublished":False,
                        "arbitraryBinaryStringsPublished":False,"rawInitContentPublished":False,
                        "physicalRouterContact":False,"routerMutationAuthorized":False}}
        rc=3
    rp.write_text(json.dumps(data,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(json.dumps({"classification":data["classification"],"oracleSatisfied":data["oracleSatisfied"]},sort_keys=True))
    return rc


if __name__=="__main__":
    raise SystemExit(main())
