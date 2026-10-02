#!/usr/bin/env python3
"""H0-D1f: public-safe lexical/syntactic context classification for linux_fs_start.

D1e falsified the hypothesis that the eight exact occurrences can be recovered
as ordinary global initializer records by the bounded owner parser. D1f does not
assume a table. It classifies each exact occurrence as code/string/comment,
preprocessor/non-preprocessor, and bounded delimiter/context shape while emitting
only safe identifiers and booleans/counts.

No source lines, string values, numeric literals, offsets, or HIL mutation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import tarfile

SCHEMA_VERSION = 1
EXPERIMENT = "fritz-h0-d1f-selector-context/v1"
KEY = "linux_fs_start"
FILES = (
    "sources/kernel/linux/drivers/mtd/avm/avm_mtd.c",
    "sources/kernel/linux/drivers/char/tffs/include/uapi/avm/tffs/tffs.h",
    "sources/kernel/linux/drivers/char/tffs/env.c",
)
IDENT_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
C_KEYWORDS = {
    "auto","break","case","char","const","continue","default","do","double","else",
    "enum","extern","float","for","goto","if","inline","int","long","register",
    "restrict","return","short","signed","sizeof","static","struct","switch",
    "typedef","union","unsigned","void","volatile","while","true","false","NULL",
}
SAFE_DIRECTIVES = {"define","ifdef","ifndef","if","elif","else","endif","include","undef"}
MAX_IDENTIFIERS = 24


def sha256_file(path: pathlib.Path) -> str:
    h=hashlib.sha256()
    with path.open("rb") as fp:
        for chunk in iter(lambda:fp.read(1024*1024),b""):
            h.update(chunk)
    return h.hexdigest()


def download_exact(url: str, path: pathlib.Path, size: int, digest: str) -> dict:
    path.parent.mkdir(parents=True,exist_ok=True)
    cp=subprocess.run(
        ["curl","--fail","--location","--silent","--show-error","--output",str(path),url],
        capture_output=True,text=True,timeout=900,
    )
    if cp.returncode:
        raise RuntimeError(f"download failed exit={cp.returncode}")
    if path.stat().st_size != size:
        raise RuntimeError("size mismatch")
    got=sha256_file(path)
    if got.lower()!=digest.lower():
        raise RuntimeError("sha256 mismatch")
    return {"bytes":path.stat().st_size,"sha256":got}


def extract_selected(archive: pathlib.Path) -> dict[str,str]:
    wanted=set(FILES)
    out={}
    with tarfile.open(archive,"r:*") as tf:
        for member in tf:
            name=member.name[2:] if member.name.startswith("./") else member.name
            if name not in wanted or not member.isfile():
                continue
            fp=tf.extractfile(member)
            if fp is not None:
                out[name]=fp.read().decode("utf-8",errors="replace")
    return out


def lexical_state_at(text: str, target: int) -> str:
    state="code"
    quote=None
    i=0
    while i < len(text) and i <= target:
        ch=text[i]
        nxt=text[i+1] if i+1<len(text) else ""
        if state=="line-comment":
            if ch=="\n":
                state="code"
            i+=1
            continue
        if state=="block-comment":
            if ch=="*" and nxt=="/":
                state="code"; i+=2; continue
            i+=1; continue
        if state=="string":
            if ch=="\\":
                i+=2; continue
            if ch==quote:
                state="code"; quote=None
            i+=1; continue

        if ch=="/" and nxt=="/":
            if i <= target < len(text):
                state="line-comment"
            i+=2; continue
        if ch=="/" and nxt=="*":
            state="block-comment"; i+=2; continue
        if ch in ("'", '"'):
            state="string"; quote=ch; i+=1; continue
        i+=1

    if state in ("line-comment","block-comment"):
        return "comment"
    if state=="string":
        return "string"
    return "code"


def mask_values_and_comments(text: str) -> str:
    out=list(text)
    state="code"
    quote=None
    i=0
    while i<len(out):
        ch=out[i]
        nxt=out[i+1] if i+1<len(out) else ""
        if state=="line-comment":
            if ch=="\n":
                state="code"
            else:
                out[i]=" "
            i+=1; continue
        if state=="block-comment":
            if ch=="*" and nxt=="/":
                out[i]=out[i+1]=" "; state="code"; i+=2; continue
            if ch!="\n": out[i]=" "
            i+=1; continue
        if state=="string":
            if ch=="\\":
                out[i]=" "
                if i+1<len(out): out[i+1]=" "
                i+=2; continue
            if ch==quote:
                state="code"
            out[i]=" "
            i+=1; continue
        if ch=="/" and nxt=="/":
            out[i]=out[i+1]=" "; state="line-comment"; i+=2; continue
        if ch=="/" and nxt=="*":
            out[i]=out[i+1]=" "; state="block-comment"; i+=2; continue
        if ch in ("'", '"'):
            quote=ch; state="string"; out[i]=" "; i+=1; continue
        if ch.isdigit():
            out[i]=" "
        i+=1
    return "".join(out)


def delimiter_depth(masked: str, pos: int) -> dict:
    braces=parens=brackets=0
    for ch in masked[:pos]:
        if ch=="{": braces+=1
        elif ch=="}": braces=max(0,braces-1)
        elif ch=="(": parens+=1
        elif ch==")": parens=max(0,parens-1)
        elif ch=="[": brackets+=1
        elif ch=="]": brackets=max(0,brackets-1)
    return {"braceDepth":braces,"parenDepth":parens,"bracketDepth":brackets}


def line_bounds(text: str, pos: int) -> tuple[int,int]:
    start=text.rfind("\n",0,pos)+1
    end=text.find("\n",pos)
    if end<0: end=len(text)
    return start,end


def directive_name(masked_line: str) -> str | None:
    m=re.match(r"\s*#\s*([A-Za-z_][A-Za-z0-9_]*)",masked_line)
    if not m:
        return None
    value=m.group(1)
    return value if value in SAFE_DIRECTIVES else "other"


def safe_identifiers(masked_line: str) -> list[str]:
    ids=[
        x for x in IDENT_RE.findall(masked_line)
        if x not in C_KEYWORDS and x != KEY
    ]
    return sorted(set(ids))[:MAX_IDENTIFIERS]


def context_class(state: str, preprocessor: bool, depth: dict, line_flags: dict) -> str:
    if state=="comment":
        return "comment"
    if preprocessor:
        return f"preprocessor-{state}"
    if state=="string":
        if depth["braceDepth"]>0:
            return "brace-contained-string"
        if line_flags["hasEquals"]:
            return "assignment-string"
        return "expression-string"
    if depth["braceDepth"]>0:
        return "brace-contained-code"
    if depth["parenDepth"]>0:
        return "paren-contained-code"
    return "top-level-code"


def classify_occurrence(path: str, text: str, pos: int, ordinal: int) -> dict:
    state=lexical_state_at(text,pos)
    masked=mask_values_and_comments(text)
    ls,le=line_bounds(text,pos)
    masked_line=masked[ls:le]
    depth=delimiter_depth(masked,pos)
    directive=directive_name(masked_line)
    flags={
        "hasEquals":"=" in masked_line,
        "hasComma":"," in masked_line,
        "hasOpenBrace":"{" in masked_line,
        "hasCloseBrace":"}" in masked_line,
        "hasOpenParen":"(" in masked_line,
        "hasCloseParen":")" in masked_line,
        "hasArrayBrackets":"[" in masked_line or "]" in masked_line,
    }
    preprocessor=directive is not None
    return {
        "file":path,
        "occurrenceOrdinal":ordinal,
        "lineOrdinal":text.count("\n",0,pos)+1,
        "lexicalState":state,
        "preprocessor":preprocessor,
        "directive":directive,
        "delimiterDepth":depth,
        "lineShape":flags,
        "safeIdentifiers":safe_identifiers(masked_line),
        "contextClass":context_class(state,preprocessor,depth,flags),
    }


def reduce(selected: dict[str,str]) -> dict:
    occurrences=[]
    for path,text in sorted(selected.items()):
        positions=[m.start() for m in re.finditer(r"\blinux_fs_start\b",text)]
        for ordinal,pos in enumerate(positions,start=1):
            occurrences.append(classify_occurrence(path,text,pos,ordinal))

    by_class={}
    by_state={}
    for item in occurrences:
        by_class[item["contextClass"]]=by_class.get(item["contextClass"],0)+1
        by_state[item["lexicalState"]]=by_state.get(item["lexicalState"],0)+1
    return {
        "occurrences":occurrences,
        "derived":{
            "occurrenceCount":len(occurrences),
            "contextClassCounts":dict(sorted(by_class.items())),
            "lexicalStateCounts":dict(sorted(by_state.items())),
            "commentOccurrenceCount":by_state.get("comment",0),
            "preprocessorOccurrenceCount":sum(1 for x in occurrences if x["preprocessor"]),
        },
    }


def classify(context: dict, missing: list[str]) -> tuple[str,bool]:
    if missing:
        return "H0_D1F_SOURCE_MISSING",False
    if context["derived"]["occurrenceCount"]<=0:
        return "H0_D1F_SELECTOR_OCCURRENCES_MISSING",True
    if context["derived"]["commentOccurrenceCount"] == context["derived"]["occurrenceCount"]:
        return "H0_D1F_ALL_OCCURRENCES_NONCODE_COMMENTS",True
    return "H0_D1F_SELECTOR_CONTEXT_RECOVERED",True


def run_probe(args) -> dict:
    work=pathlib.Path(args.work_dir).resolve()
    work.mkdir(parents=True,exist_ok=True)
    archive=work/"source-files.tar.gz"
    exact=download_exact(args.osp_url,archive,args.expected_size,args.expected_sha256)
    selected=extract_selected(archive)
    missing=sorted(set(FILES)-set(selected))
    context=reduce(selected)
    classification,oracle=classify(context,missing)
    return {
        "schemaVersion":SCHEMA_VERSION,
        "experiment":EXPERIMENT,
        "classification":classification,
        "oracleSatisfied":oracle,
        "sourceArtifact":{
            "expectedBytes":args.expected_size,
            "expectedSha256":args.expected_sha256.lower(),
            "observedBytes":exact["bytes"],
            "observedSha256":exact["sha256"],
        },
        "missingFiles":missing,
        "context":context,
        "interpretationBoundary":{
            "lexicalAndDelimiterContextRecovered":True,
            "sourceLinesPublished":False,
            "stringValuesPublished":False,
            "numericValuesPublished":False,
            "exactValueToSlotMappingAccepted":False,
            "exactPartitionLayoutAccepted":False,
            "dualBootSafetyAccepted":False,
        },
        "safety":{
            "rawOspArchivePublished":False,
            "sourcePayloadPublished":False,
            "sourceSnippetsPublished":False,
            "arbitraryStringLiteralsPublished":False,
            "numericOffsetsPublished":False,
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
    rp=pathlib.Path(args.receipt)
    rp.parent.mkdir(parents=True,exist_ok=True)
    try:
        data=run_probe(args); rc=0 if data["oracleSatisfied"] else 2
    except Exception as exc:
        data={
            "schemaVersion":SCHEMA_VERSION,"experiment":EXPERIMENT,
            "classification":"HARNESS_FAILURE","oracleSatisfied":False,
            "error":{"type":type(exc).__name__,"message":str(exc)[:1000]},
            "safety":{
                "rawOspArchivePublished":False,"sourcePayloadPublished":False,
                "sourceSnippetsPublished":False,"arbitraryStringLiteralsPublished":False,
                "numericOffsetsPublished":False,"physicalRouterContact":False,
                "flashWriteAuthorized":False,"bootEnvironmentMutationAuthorized":False,
            },
        }
        rc=3
    rp.write_text(json.dumps(data,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(json.dumps({"classification":data["classification"],"oracleSatisfied":data["oracleSatisfied"]},sort_keys=True))
    return rc


if __name__=="__main__":
    raise SystemExit(main())
