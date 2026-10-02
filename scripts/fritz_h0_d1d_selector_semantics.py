#!/usr/bin/env python3
"""Public-safe H0-D1d linux_fs_start selector semantic reduction."""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import tarfile

SCHEMA_VERSION=1
EXPERIMENT="fritz-h0-d1d-selector-semantics/v1"
FILES=(
 "sources/kernel/linux/drivers/mtd/avm/avm_mtd.c",
 "sources/kernel/linux/drivers/char/tffs/include/uapi/avm/tffs/tffs.h",
 "sources/kernel/linux/drivers/char/tffs/env.c",
)
KEY="linux_fs_start"
CALL_RE=re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
FUNC_RE=re.compile(
 r"(?m)^[\t ]*(?:static\s+)?(?:inline\s+)?(?:[A-Za-z_][A-Za-z0-9_\s\*]*?)[\t ]+([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\)\s*\{"
)


def sha256_file(path:pathlib.Path)->str:
 h=hashlib.sha256()
 with path.open("rb") as fp:
  for c in iter(lambda:fp.read(1024*1024),b""):h.update(c)
 return h.hexdigest()


def download_exact(url,path,size,digest):
 cp=subprocess.run(["curl","--fail","--location","--silent","--show-error","--output",str(path),url],capture_output=True,text=True,timeout=900)
 if cp.returncode:raise RuntimeError(f"download failed exit={cp.returncode}")
 if path.stat().st_size!=size:raise RuntimeError("size mismatch")
 got=sha256_file(path)
 if got.lower()!=digest.lower():raise RuntimeError("sha256 mismatch")
 return {"bytes":path.stat().st_size,"sha256":got}


def extract(archive:pathlib.Path)->dict[str,str]:
 wanted=set(FILES);out={}
 with tarfile.open(archive,"r:*") as tf:
  for m in tf:
   name=m.name[2:] if m.name.startswith("./") else m.name
   if name not in wanted or not m.isfile():continue
   fp=tf.extractfile(m)
   if fp:out[name]=fp.read().decode("utf-8",errors="replace")
 return out


def match_brace(text:str,open_idx:int)->int|None:
 depth=0;quote=None;esc=False
 for i in range(open_idx,len(text)):
  ch=text[i]
  if quote:
   if esc:esc=False
   elif ch=="\\":esc=True
   elif ch==quote:quote=None
   continue
  if ch in ("'",'"'):quote=ch;continue
  if ch=="{":depth+=1
  elif ch=="}":
   depth-=1
   if depth==0:return i
 return None


def funcs(text:str)->list[tuple[str,int,int,str]]:
 out=[]
 for m in FUNC_RE.finditer(text):
  o=text.find("{",m.start(),m.end()+1)
  if o<0:continue
  z=match_brace(text,o)
  if z is None:continue
  out.append((m.group(1),o+1,z,text[o+1:z]))
 return out


def safe_string(v:str)->str|None:
 return v if v in ("0","1","2","linux_fs_start","filesystem","kernel","rootfs") else None


def selector_calls(path:str,text:str)->list[dict]:
 out=[]
 for name,start,end,body in funcs(text):
  if KEY not in body:continue
  calls=sorted(set(CALL_RE.findall(body)))
  key_calls=[]
  for m in re.finditer(r'([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*"linux_fs_start"\s*\)',body):
   key_calls.append(m.group(1))
  assigns=[]
  for m in re.finditer(r'([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*"linux_fs_start"\s*\)',body):
   assigns.append({"variable":m.group(1),"callee":m.group(2)})
  comps=[]
  for a in assigns:
   var=re.escape(a["variable"])
   for m in re.finditer(rf'\bstrcmp\s*\(\s*{var}\s*,\s*"([^"]+)"\s*\)',body):
    s=safe_string(m.group(1))
    comps.append({"variable":a["variable"],"kind":"strcmp","value":s if s is not None else "opaque"})
   for m in re.finditer(rf'\b{var}\s*\[\s*0\s*\]\s*(==|!=)\s*\'([^\']+)\'',body):
    s=safe_string(m.group(2))
    comps.append({"variable":a["variable"],"kind":"char-compare","operator":m.group(1),"value":s if s is not None else "opaque"})
   if re.search(rf'\bsimple_strtoul\s*\(\s*{var}\b',body):
    comps.append({"variable":a["variable"],"kind":"numeric-parse"})
  out.append({
   "file":path,"function":name,
   "keyOccurrenceCount":len(re.findall(r'\blinux_fs_start\b',body)),
   "keyCallCallees":sorted(set(key_calls)),
   "keyAssignments":assigns,
   "comparisons":comps,
   "relatedCalls":[c for c in calls if c.startswith(("prom_","mtd_","TFFS","ubi_","simple_"))],
  })
 return out


def nonfunction_occurrences(path:str,text:str)->list[dict]:
 ranges=[(s,e) for _,s,e,_ in funcs(text)]
 def inside(i):return any(s<=i<e for s,e in ranges)
 out=[]
 for m in re.finditer(r'\blinux_fs_start\b',text):
  if inside(m.start()):continue
  line=text[:m.start()].count("\n")+1
  prefix=text[max(0,m.start()-120):m.start()]
  kind="global-or-table"
  if "#define" in prefix.split("\n")[-1]:kind="macro"
  elif re.search(r'["\']\s*$',prefix):kind="string-table-or-initializer"
  out.append({"file":path,"lineOrdinal":line,"kind":kind})
 return out


def reduce(selected:dict[str,str])->dict:
 functions=[];globals=[]
 for path,text in selected.items():
  functions.extend(selector_calls(path,text))
  globals.extend(nonfunction_occurrences(path,text))
 header=selected.get("sources/kernel/linux/drivers/char/tffs/include/uapi/avm/tffs/tffs.h","")
 env_name_present=bool(re.search(r'\blinux_fs_start\b',header))
 return {
  "functionContexts":functions,
  "nonFunctionOccurrences":globals,
  "tffsPublicNamePresent":env_name_present,
  "derived":{
   "promGetenvKeyUseProven":any("prom_getenv" in x["keyCallCallees"] or any(a["callee"]=="prom_getenv" for a in x["keyAssignments"]) for x in functions),
   "selectorFunctionCount":len(functions),
   "nonFunctionOccurrenceCount":len(globals),
  }
 }


def run_probe(args):
 work=pathlib.Path(args.work_dir).resolve();work.mkdir(parents=True,exist_ok=True)
 archive=work/"source-files.tar.gz"
 exact=download_exact(args.osp_url,archive,args.expected_size,args.expected_sha256)
 selected=extract(archive);missing=sorted(set(FILES)-set(selected))
 semantic=reduce(selected)
 return {
  "schemaVersion":SCHEMA_VERSION,"experiment":EXPERIMENT,
  "classification":"H0_D1D_SELECTOR_SEMANTICS_RECOVERED" if not missing else "H0_D1D_SOURCE_MISSING",
  "oracleSatisfied":not missing,
  "sourceArtifact":{"expectedBytes":args.expected_size,"expectedSha256":args.expected_sha256.lower(),"observedBytes":exact["bytes"],"observedSha256":exact["sha256"]},
  "missingFiles":missing,"semantics":semantic,
  "interpretationBoundary":{
   "linuxFsStartStorageNameProven":semantic["tffsPublicNamePresent"],
   "linuxFsStartPromGetenvUseProven":semantic["derived"]["promGetenvKeyUseProven"],
   "exactValueToSlotMappingAccepted":False,
   "exactPartitionLayoutAccepted":False,
   "dualBootSafetyAccepted":False,
  },
  "safety":{"rawOspArchivePublished":False,"sourcePayloadPublished":False,"sourceSnippetsPublished":False,"arbitraryStringLiteralsPublished":False,"physicalRouterContact":False,"flashWriteAuthorized":False,"bootEnvironmentMutationAuthorized":False}
 }


def parse_args(argv=None):
 p=argparse.ArgumentParser();p.add_argument("--osp-url",required=True);p.add_argument("--expected-size",type=int,required=True);p.add_argument("--expected-sha256",required=True);p.add_argument("--work-dir",required=True);p.add_argument("--receipt",required=True);return p.parse_args(argv)


def main(argv=None):
 args=parse_args(argv);rp=pathlib.Path(args.receipt);rp.parent.mkdir(parents=True,exist_ok=True)
 try:data=run_probe(args);rc=0 if data["oracleSatisfied"] else 2
 except Exception as exc:
  data={"schemaVersion":SCHEMA_VERSION,"experiment":EXPERIMENT,"classification":"HARNESS_FAILURE","oracleSatisfied":False,"error":{"type":type(exc).__name__,"message":str(exc)[:1000]},"safety":{"rawOspArchivePublished":False,"sourcePayloadPublished":False,"sourceSnippetsPublished":False,"arbitraryStringLiteralsPublished":False,"physicalRouterContact":False,"flashWriteAuthorized":False,"bootEnvironmentMutationAuthorized":False}};rc=3
 rp.write_text(json.dumps(data,indent=2,sort_keys=True)+"\n",encoding="utf-8")
 print(json.dumps({"classification":data["classification"],"oracleSatisfied":data["oracleSatisfied"]},sort_keys=True));return rc
if __name__=="__main__":raise SystemExit(main())
