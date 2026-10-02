#!/usr/bin/env python3
"""H0-D1h: exact linux_fs_start switch-case and destination reduction.

D1g proved the direct environment-key -> p -> kstrtoul -> linux_fs_start ->
switch dataflow. D1h reduces only that exact switch body and emits derived case
labels plus safe destination assignments. It also counts exact destination-name
matches in independently selected AVM partition/device-tree source files.

No source lines or source snippets are emitted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import tarfile

SCHEMA_VERSION=1
EXPERIMENT="fritz-h0-d1h-selector-switch/v1"
SELECTOR="linux_fs_start"
FILES=(
 "sources/kernel/linux/drivers/mtd/avm/avm_mtd.c",
 "sources/kernel/linux/drivers/mtd/avm/partparse.c",
 "sources/kernel/linux/arch/mips/boot/dts/lantiq/avm/grx_common.dtsi",
)
IDENT=r"[A-Za-z_][A-Za-z0-9_]*"
SAFE_DEST_LHS={"new_name"}
SAFE_DEST_RE=re.compile(r"^[A-Za-z][A-Za-z0-9_.+-]{0,63}$")


def sha256_file(path:pathlib.Path)->str:
 h=hashlib.sha256()
 with path.open("rb") as fp:
  for c in iter(lambda:fp.read(1024*1024),b""):h.update(c)
 return h.hexdigest()


def download_exact(url,path,size,digest):
 path.parent.mkdir(parents=True,exist_ok=True)
 cp=subprocess.run(["curl","--fail","--location","--silent","--show-error","--output",str(path),url],
                   capture_output=True,text=True,timeout=900)
 if cp.returncode:raise RuntimeError(f"download failed exit={cp.returncode}")
 if path.stat().st_size!=size:raise RuntimeError("size mismatch")
 got=sha256_file(path)
 if got.lower()!=digest.lower():raise RuntimeError("sha256 mismatch")
 return {"bytes":path.stat().st_size,"sha256":got}


def extract_selected(archive:pathlib.Path)->dict[str,str]:
 wanted=set(FILES);out={}
 with tarfile.open(archive,"r:*") as tf:
  for m in tf:
   name=m.name[2:] if m.name.startswith("./") else m.name
   if name not in wanted or not m.isfile():continue
   fp=tf.extractfile(m)
   if fp is not None:out[name]=fp.read().decode("utf-8",errors="replace")
 return out


def match_brace(text:str,open_idx:int)->int|None:
 depth=0;quote=None;comment=None;i=open_idx
 while i<len(text):
  ch=text[i];nxt=text[i+1] if i+1<len(text) else ""
  if comment=="line":
   if ch=="\n":comment=None
   i+=1;continue
  if comment=="block":
   if ch=="*" and nxt=="/":comment=None;i+=2;continue
   i+=1;continue
  if quote:
   if ch=="\\":i+=2;continue
   if ch==quote:quote=None
   i+=1;continue
  if ch=="/" and nxt=="/":comment="line";i+=2;continue
  if ch=="/" and nxt=="*":comment="block";i+=2;continue
  if ch in ("'",'"'):quote=ch;i+=1;continue
  if ch=="{":depth+=1
  elif ch=="}":
   depth-=1
   if depth==0:return i
  i+=1
 return None


def mask_comments_strings(text:str)->str:
 out=list(text);state="code";quote=None;i=0
 while i<len(out):
  ch=out[i];nxt=out[i+1] if i+1<len(out) else ""
  if state=="line":
   if ch=="\n":state="code"
   else:out[i]=" "
   i+=1;continue
  if state=="block":
   if ch=="*" and nxt=="/":out[i]=out[i+1]=" ";state="code";i+=2;continue
   if ch!="\n":out[i]=" "
   i+=1;continue
  if state=="string":
   if ch=="\\":out[i]=" ";out[i+1]=" " if i+1<len(out) else "";i+=2;continue
   if ch==quote:state="code"
   out[i]=" ";i+=1;continue
  if ch=="/" and nxt=="/":out[i]=out[i+1]=" ";state="line";i+=2;continue
  if ch=="/" and nxt=="*":out[i]=out[i+1]=" ";state="block";i+=2;continue
  if ch in ("'",'"'):quote=ch;state="string";out[i]=" ";i+=1;continue
  i+=1
 return "".join(out)


def top_level_labels(body:str)->list[dict]:
 masked=mask_comments_strings(body)
 labels=[];depth=0
 rx=re.compile(r"\bcase\s+(?P<case>[^:]+):|\b(?P<default>default)\s*:")
 for m in rx.finditer(masked):
  # compute brace depth only; switch body itself starts at depth zero.
  depth=0
  for ch in masked[:m.start()]:
   if ch=="{":depth+=1
   elif ch=="}":depth=max(0,depth-1)
  if depth!=0:continue
  labels.append({
   "start":m.start(),
   "end":m.end(),
   "rawCase":m.group("case").strip() if m.group("case") else None,
   "default":bool(m.group("default")),
  })
 return labels


def normalize_case(raw:str|None,default:bool)->dict:
 if default:return {"caseKind":"default"}
 assert raw is not None
 s=raw.strip()
 if re.fullmatch(r"0[xX][0-9A-Fa-f]+|\d+",s):
  return {"caseKind":"integer","caseValue":int(s,0)}
 if re.fullmatch(IDENT,s):
  return {"caseKind":"identifier","caseIdentifier":s}
 ids=sorted(set(re.findall(IDENT,s)))
 return {
  "caseKind":"expression",
  "caseExpressionSha256":hashlib.sha256(s.encode()).hexdigest(),
  "caseIdentifiers":ids[:12],
 }


def safe_assignment(lhs:str,rhs:str)->dict:
 rec={"lhs":lhs}
 rhs=rhs.strip()
 sm=re.fullmatch(r'["\']([^"\']+)["\']',rhs)
 if lhs in SAFE_DEST_LHS and sm and SAFE_DEST_RE.fullmatch(sm.group(1)):
  rec.update({"rhsKind":"safe-destination","destination":sm.group(1)})
 elif re.fullmatch(IDENT,rhs):
  rec.update({"rhsKind":"identifier","rhsIdentifier":rhs})
 elif re.fullmatch(r"0[xX][0-9A-Fa-f]+|\d+",rhs):
  rec.update({"rhsKind":"integer","integerValue":int(rhs,0)})
 elif sm:
  rec.update({
   "rhsKind":"string-hash",
   "rhsSha256":hashlib.sha256(sm.group(1).encode()).hexdigest(),
   "rhsLength":len(sm.group(1)),
  })
 else:
  rec.update({"rhsKind":"expression-opaque"})
 return rec


def reduce_switch(text:str)->dict:
 sm=re.search(r"\bswitch\s*\(\s*linux_fs_start\s*\)\s*\{",text)
 if not sm:return {"switchFound":False,"cases":[]}
 open_idx=text.find("{",sm.start(),sm.end())
 close_idx=match_brace(text,open_idx)
 if close_idx is None:return {"switchFound":True,"switchClosed":False,"cases":[]}
 body=text[open_idx+1:close_idx]
 labels=top_level_labels(body)
 cases=[]
 for idx,label in enumerate(labels):
  seg_start=label["end"]
  seg_end=labels[idx+1]["start"] if idx+1<len(labels) else len(body)
  segment=body[seg_start:seg_end]
  assignments=[]
  for am in re.finditer(rf"\b(?P<lhs>{IDENT})\s*=\s*(?P<rhs>[^;\n]+)\s*;",segment):
   assignments.append(safe_assignment(am.group("lhs"),am.group("rhs")))
  calls=sorted(set(
   name for name in re.findall(rf"\b({IDENT})\s*\(",mask_comments_strings(segment))
   if name not in {"if","for","while","switch","sizeof"}
  ))[:24]
  cases.append({
   **normalize_case(label["rawCase"],label["default"]),
   "assignments":assignments[:24],
   "safeDestinations":sorted({
    x["destination"] for x in assignments if x.get("rhsKind")=="safe-destination"
   }),
   "callIdentifiers":calls,
   "hasBreak":bool(re.search(r"\bbreak\s*;",mask_comments_strings(segment))),
   "hasReturn":bool(re.search(r"\breturn\b",mask_comments_strings(segment))),
  })
 return {"switchFound":True,"switchClosed":True,"cases":cases}


def crosscheck(destinations:list[str],selected:dict[str,str])->list[dict]:
 out=[]
 for dest in sorted(set(destinations)):
  per=[]
  for path,text in sorted(selected.items()):
   if path.endswith("avm_mtd.c"):continue
   count=len(re.findall(rf"(?<![A-Za-z0-9_.+-]){re.escape(dest)}(?![A-Za-z0-9_.+-])",text))
   if count:per.append({"file":path,"count":count})
  out.append({"destination":dest,"independentMatches":per,"independentlyObserved":bool(per)})
 return out


def run_probe(args):
 work=pathlib.Path(args.work_dir).resolve();work.mkdir(parents=True,exist_ok=True)
 archive=work/"source-files.tar.gz"
 exact=download_exact(args.osp_url,archive,args.expected_size,args.expected_sha256)
 selected=extract_selected(archive);missing=sorted(set(FILES)-set(selected))
 avm=selected.get("sources/kernel/linux/drivers/mtd/avm/avm_mtd.c","")
 sw=reduce_switch(avm)
 destinations=sorted({d for c in sw.get("cases",[]) for d in c.get("safeDestinations",[])})
 checks=crosscheck(destinations,selected)
 if missing:
  classification="H0_D1H_SOURCE_MISSING";oracle=False
 elif not sw.get("switchFound"):
  classification="H0_D1H_SELECTOR_SWITCH_NOT_FOUND";oracle=True
 elif not sw.get("switchClosed"):
  classification="H0_D1H_SELECTOR_SWITCH_PARSE_PARTIAL";oracle=True
 elif destinations:
  classification="H0_D1H_SELECTOR_SWITCH_DESTINATIONS_RECOVERED";oracle=True
 else:
  classification="H0_D1H_SELECTOR_SWITCH_SCHEMA_RECOVERED";oracle=True
 return {
  "schemaVersion":SCHEMA_VERSION,"experiment":EXPERIMENT,"classification":classification,"oracleSatisfied":oracle,
  "sourceArtifact":{"expectedBytes":args.expected_size,"expectedSha256":args.expected_sha256.lower(),
                    "observedBytes":exact["bytes"],"observedSha256":exact["sha256"]},
  "missingFiles":missing,
  "selectorSwitch":sw,
  "destinationCrosscheck":checks,
  "derived":{"caseCount":len(sw.get("cases",[])),"safeDestinationCount":len(destinations),
             "independentlyObservedDestinationCount":sum(1 for x in checks if x["independentlyObserved"])},
  "interpretationBoundary":{
   "caseValuesAreDerivedSourceFacts":True,
   "safeDestinationIdentifiersAreDerivedSourceFacts":True,
   "destinationNameMatchIsNotBootabilityProof":True,
   "exactFlashOffsetsAccepted":False,
   "rollbackSafetyAccepted":False,
   "modifiedHilAuthorized":False,
  },
  "safety":{
   "rawOspArchivePublished":False,"sourcePayloadPublished":False,"sourceSnippetsPublished":False,
   "arbitraryStringLiteralsPublished":False,"physicalRouterContact":False,"flashWriteAuthorized":False,
   "bootEnvironmentMutationAuthorized":False,
  },
 }


def parse_args(argv=None):
 p=argparse.ArgumentParser();p.add_argument("--osp-url",required=True);p.add_argument("--expected-size",type=int,required=True)
 p.add_argument("--expected-sha256",required=True);p.add_argument("--work-dir",required=True);p.add_argument("--receipt",required=True)
 return p.parse_args(argv)


def main(argv=None):
 args=parse_args(argv);rp=pathlib.Path(args.receipt);rp.parent.mkdir(parents=True,exist_ok=True)
 try:data=run_probe(args);rc=0 if data["oracleSatisfied"] else 2
 except Exception as exc:
  data={"schemaVersion":SCHEMA_VERSION,"experiment":EXPERIMENT,"classification":"HARNESS_FAILURE","oracleSatisfied":False,
        "error":{"type":type(exc).__name__,"message":str(exc)[:1000]},
        "safety":{"rawOspArchivePublished":False,"sourcePayloadPublished":False,"sourceSnippetsPublished":False,
                  "arbitraryStringLiteralsPublished":False,"physicalRouterContact":False,"flashWriteAuthorized":False,
                  "bootEnvironmentMutationAuthorized":False}}
  rc=3
 rp.write_text(json.dumps(data,indent=2,sort_keys=True)+"\n",encoding="utf-8")
 print(json.dumps({"classification":data["classification"],"oracleSatisfied":data["oracleSatisfied"]},sort_keys=True));return rc

if __name__=="__main__":raise SystemExit(main())
