#!/usr/bin/env python3
"""H0-D1g: bounded whole-file selector dataflow recovery for linux_fs_start.

D1f showed an exact prom_getenv assignment context followed by numeric parsing
and selector-controlled code. D1g avoids the brittle function-header parser and
recovers only direct whole-file relations:
- prom_getenv("linux_fs_start") assignment variable;
- numeric parser input/output identifiers;
- condition operator classes involving the selector;
- bounded assignments in selector-bearing branch blocks, with string RHS hashed;
- direct getter/setter key uses.

No source lines, arbitrary string values, numeric values/offsets, or HIL mutation.
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
EXPERIMENT="fritz-h0-d1g-selector-dataflow/v1"
KEY="linux_fs_start"
FILES=(
 "sources/kernel/linux/drivers/mtd/avm/avm_mtd.c",
 "sources/kernel/linux/drivers/char/tffs/include/uapi/avm/tffs/tffs.h",
 "sources/kernel/linux/drivers/char/tffs/env.c",
)
IDENT=r"[A-Za-z_][A-Za-z0-9_]*"
GETTERS=("prom_getenv","avm_urlader_getenv","avm_urlader_getenv_value")
SETTERS=("prom_setenv","avm_urlader_setenv","avm_urlader_setenv_value")
PARSERS=("kstrtoul","simple_strtoul","strtoul")
COMPARE_OPS=("==","!=","<=",">=","<",">")


def sha256_file(path:pathlib.Path)->str:
 h=hashlib.sha256()
 with path.open("rb") as fp:
  for c in iter(lambda:fp.read(1024*1024),b""): h.update(c)
 return h.hexdigest()


def download_exact(url,path,size,digest):
 path.parent.mkdir(parents=True,exist_ok=True)
 cp=subprocess.run(["curl","--fail","--location","--silent","--show-error","--output",str(path),url],
                   capture_output=True,text=True,timeout=900)
 if cp.returncode: raise RuntimeError(f"download failed exit={cp.returncode}")
 if path.stat().st_size!=size: raise RuntimeError("size mismatch")
 got=sha256_file(path)
 if got.lower()!=digest.lower(): raise RuntimeError("sha256 mismatch")
 return {"bytes":path.stat().st_size,"sha256":got}


def extract_selected(archive:pathlib.Path)->dict[str,str]:
 wanted=set(FILES);out={}
 with tarfile.open(archive,"r:*") as tf:
  for m in tf:
   name=m.name[2:] if m.name.startswith("./") else m.name
   if name not in wanted or not m.isfile(): continue
   fp=tf.extractfile(m)
   if fp is not None: out[name]=fp.read().decode("utf-8",errors="replace")
 return out


def direct_getter_assignments(path:str,text:str)->list[dict]:
 out=[]
 for getter in GETTERS:
  rx=re.compile(
   rf"\b(?P<var>{IDENT})\s*=\s*{re.escape(getter)}\s*\(\s*[\"']{KEY}[\"']\s*\)"
  )
  for m in rx.finditer(text):
   out.append({"file":path,"getter":getter,"assignedVariable":m.group("var")})
 return sorted(out,key=lambda x:(x["file"],x["getter"],x["assignedVariable"]))


def direct_key_calls(path:str,text:str,names:tuple[str,...],kind:str)->list[dict]:
 out=[]
 for callee in names:
  rx=re.compile(rf"\b{re.escape(callee)}\s*\(\s*[\"']{KEY}[\"']")
  count=len(list(rx.finditer(text)))
  if count:
   out.append({"file":path,"kind":kind,"callee":callee,"count":count})
 return out


def numeric_parse_relations(path:str,text:str,input_vars:set[str])->list[dict]:
 out=[]
 for parser in PARSERS:
  # Kernel/simple parsers differ in arity. Capture only safe identifier
  # arguments and omit numeric/base literals.
  for m in re.finditer(rf"\b{re.escape(parser)}\s*\((?P<args>[^;\n)]*)\)",text):
   args=[x.strip() for x in m.group("args").split(",")]
   if not args: continue
   first=re.fullmatch(IDENT,args[0])
   if not first or first.group(0) not in input_vars: continue
   identifiers=[]
   for arg in args[1:]:
    ids=re.findall(IDENT,arg)
    for ident in ids:
     if ident not in {"NULL"}:
      identifiers.append(ident)
   out.append({
    "file":path,
    "parser":parser,
    "inputVariable":first.group(0),
    "otherIdentifierArguments":sorted(set(identifiers)),
    "argumentCount":len(args),
   })
 return out


def selector_variables(getters:list[dict],parses:list[dict])->set[str]:
 out={x["assignedVariable"] for x in getters}
 for p in parses:
  out.update(p["otherIdentifierArguments"])
 return out


def condition_relations(path:str,text:str,selectors:set[str])->list[dict]:
 out=[]
 for keyword in ("if","while","switch"):
  rx=re.compile(rf"\b{keyword}\s*\((?P<cond>[^)]*)\)")
  for m in rx.finditer(text):
   cond=m.group("cond")
   touched=sorted(v for v in selectors if re.search(rf"\b{re.escape(v)}\b",cond))
   if not touched: continue
   operators=[op for op in COMPARE_OPS if op in cond]
   out.append({
    "file":path,
    "control":keyword,
    "selectorVariables":touched,
    "comparisonOperators":operators,
    "hasNumericLiteral":bool(re.search(r"\b(?:0[xX][0-9A-Fa-f]+|\d+)\b",cond)),
    "hasIdentifierPeer":bool(
      [x for x in re.findall(IDENT,cond) if x not in touched and x not in ("if","while","switch")]
    ),
   })
 return out


def match_brace(text:str,open_idx:int)->int|None:
 depth=0;quote=None;comment=None;i=open_idx
 while i<len(text):
  ch=text[i];nxt=text[i+1] if i+1<len(text) else ""
  if comment=="line":
   if ch=="\n": comment=None
   i+=1;continue
  if comment=="block":
   if ch=="*" and nxt=="/": comment=None;i+=2;continue
   i+=1;continue
  if quote:
   if ch=="\\": i+=2;continue
   if ch==quote: quote=None
   i+=1;continue
  if ch=="/" and nxt=="/": comment="line";i+=2;continue
  if ch=="/" and nxt=="*": comment="block";i+=2;continue
  if ch in ("'",'"'): quote=ch;i+=1;continue
  if ch=="{": depth+=1
  elif ch=="}":
   depth-=1
   if depth==0:return i
  i+=1
 return None


def safe_rhs(rhs:str)->dict:
 rhs=rhs.strip()
 sm=re.fullmatch(r'[\"\']([^\"\']+)[\"\']',rhs)
 if sm:
  value=sm.group(1)
  return {
   "rhsKind":"string-hash",
   "rhsSha256":hashlib.sha256(value.encode()).hexdigest(),
   "rhsLength":len(value),
  }
 im=re.fullmatch(IDENT,rhs)
 if im:
  return {"rhsKind":"identifier","rhsIdentifier":im.group(0)}
 if re.fullmatch(r"(?:0[xX][0-9A-Fa-f]+|\d+)",rhs):
  return {"rhsKind":"numeric-opaque"}
 return {"rhsKind":"expression-opaque"}


def selector_branch_assignments(path:str,text:str,selectors:set[str])->list[dict]:
 out=[]
 # Limit to braced if-blocks whose condition mentions a selector variable.
 for m in re.finditer(r"\bif\s*\((?P<cond>[^)]*)\)\s*\{",text):
  cond=m.group("cond")
  touched=sorted(v for v in selectors if re.search(rf"\b{re.escape(v)}\b",cond))
  if not touched: continue
  open_idx=text.find("{",m.start(),m.end())
  close_idx=match_brace(text,open_idx)
  if close_idx is None: continue
  body=text[open_idx+1:close_idx]
  assignments=[]
  for am in re.finditer(rf"\b(?P<lhs>{IDENT})\s*=\s*(?P<rhs>[^;\n]+)\s*;",body):
   rec={"lhs":am.group("lhs"),**safe_rhs(am.group("rhs"))}
   assignments.append(rec)
  out.append({
   "file":path,
   "selectorVariables":touched,
   "comparisonOperators":[op for op in COMPARE_OPS if op in cond],
   "assignmentCount":len(assignments),
   "assignments":assignments[:24],
  })
 return out


def reduce(selected:dict[str,str])->dict:
 getters=[];getter_calls=[];setter_calls=[]
 for path,text in sorted(selected.items()):
  getters.extend(direct_getter_assignments(path,text))
  getter_calls.extend(direct_key_calls(path,text,GETTERS,"getter"))
  setter_calls.extend(direct_key_calls(path,text,SETTERS,"setter"))
 input_vars={x["assignedVariable"] for x in getters}
 parses=[]
 for path,text in sorted(selected.items()):
  parses.extend(numeric_parse_relations(path,text,input_vars))
 selectors=selector_variables(getters,parses)
 conditions=[];branches=[]
 for path,text in sorted(selected.items()):
  conditions.extend(condition_relations(path,text,selectors))
  branches.extend(selector_branch_assignments(path,text,selectors))
 return {
  "getterAssignments":getters,
  "directGetterKeyCalls":getter_calls,
  "directSetterKeyCalls":setter_calls,
  "numericParseRelations":parses,
  "selectorVariables":sorted(selectors),
  "selectorConditions":conditions,
  "selectorBranchAssignments":branches,
  "derived":{
   "getterAssignmentCount":len(getters),
   "directGetterKeyCallCount":sum(x["count"] for x in getter_calls),
   "directSetterKeyCallCount":sum(x["count"] for x in setter_calls),
   "numericParseRelationCount":len(parses),
   "selectorConditionCount":len(conditions),
   "selectorBranchCount":len(branches),
  },
 }


def classify(data:dict,missing:list[str])->tuple[str,bool]:
 if missing:return "H0_D1G_SOURCE_MISSING",False
 if data["derived"]["getterAssignmentCount"]<=0:
  return "H0_D1G_DIRECT_GETTER_NOT_RECOVERED",True
 if data["derived"]["numericParseRelationCount"]<=0:
  return "H0_D1G_GETTER_RECOVERED_PARSE_RELATION_PARTIAL",True
 if data["derived"]["selectorConditionCount"]<=0:
  return "H0_D1G_SELECTOR_DATAFLOW_PARTIAL",True
 return "H0_D1G_SELECTOR_DATAFLOW_RECOVERED",True


def run_probe(args):
 work=pathlib.Path(args.work_dir).resolve();work.mkdir(parents=True,exist_ok=True)
 archive=work/"source-files.tar.gz"
 exact=download_exact(args.osp_url,archive,args.expected_size,args.expected_sha256)
 selected=extract_selected(archive);missing=sorted(set(FILES)-set(selected))
 data=reduce(selected);classification,oracle=classify(data,missing)
 return {
  "schemaVersion":SCHEMA_VERSION,"experiment":EXPERIMENT,
  "classification":classification,"oracleSatisfied":oracle,
  "sourceArtifact":{"expectedBytes":args.expected_size,"expectedSha256":args.expected_sha256.lower(),
                    "observedBytes":exact["bytes"],"observedSha256":exact["sha256"]},
  "missingFiles":missing,"dataflow":data,
  "interpretationBoundary":{
   "directGetterPatternMechanicallyRecovered":data["derived"]["getterAssignmentCount"]>0,
   "numericLiteralValuesPublished":False,
   "stringLiteralValuesPublished":False,
   "hashedBranchStringValuesAreNotPartitionIdentityProof":True,
   "exactValueToSlotMappingAccepted":False,
   "exactPartitionLayoutAccepted":False,
   "dualBootSafetyAccepted":False,
  },
  "safety":{
   "rawOspArchivePublished":False,"sourcePayloadPublished":False,"sourceSnippetsPublished":False,
   "arbitraryStringLiteralsPublished":False,"numericValuesPublished":False,
   "physicalRouterContact":False,"flashWriteAuthorized":False,"bootEnvironmentMutationAuthorized":False,
  },
 }


def parse_args(argv=None):
 p=argparse.ArgumentParser()
 p.add_argument("--osp-url",required=True);p.add_argument("--expected-size",type=int,required=True)
 p.add_argument("--expected-sha256",required=True);p.add_argument("--work-dir",required=True)
 p.add_argument("--receipt",required=True);return p.parse_args(argv)


def main(argv=None):
 args=parse_args(argv);rp=pathlib.Path(args.receipt);rp.parent.mkdir(parents=True,exist_ok=True)
 try:data=run_probe(args);rc=0 if data["oracleSatisfied"] else 2
 except Exception as exc:
  data={"schemaVersion":SCHEMA_VERSION,"experiment":EXPERIMENT,"classification":"HARNESS_FAILURE","oracleSatisfied":False,
        "error":{"type":type(exc).__name__,"message":str(exc)[:1000]},
        "safety":{"rawOspArchivePublished":False,"sourcePayloadPublished":False,"sourceSnippetsPublished":False,
                  "arbitraryStringLiteralsPublished":False,"numericValuesPublished":False,
                  "physicalRouterContact":False,"flashWriteAuthorized":False,"bootEnvironmentMutationAuthorized":False}}
  rc=3
 rp.write_text(json.dumps(data,indent=2,sort_keys=True)+"\n",encoding="utf-8")
 print(json.dumps({"classification":data["classification"],"oracleSatisfied":data["oracleSatisfied"]},sort_keys=True));return rc

if __name__=="__main__":raise SystemExit(main())
