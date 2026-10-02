#!/usr/bin/env python3
"""H0-D1i: recover downstream linux_fs_start -> destination expression mapping.

D1h proved the selector is normalized to {0,1} by an exact switch. D1i scans only
assignments whose RHS directly references linux_fs_start and normalizes simple
two-arm ternary expressions into case-value -> safe destination facts.

No source lines are emitted. Only restrictive destination-like string tokens are
published as derived facts.
"""
from __future__ import annotations
import argparse,hashlib,json,pathlib,re,subprocess,tarfile

SCHEMA_VERSION=1
EXPERIMENT="fritz-h0-d1i-selector-destination/v1"
SELECTOR="linux_fs_start"
FILES=(
 "sources/kernel/linux/drivers/mtd/avm/avm_mtd.c",
 "sources/kernel/linux/drivers/mtd/avm/partparse.c",
 "sources/kernel/linux/arch/mips/boot/dts/lantiq/avm/grx_common.dtsi",
)
IDENT=r"[A-Za-z_][A-Za-z0-9_]*"
SAFE_DEST_RE=re.compile(r"^[A-Za-z][A-Za-z0-9_.+-]{0,63}$")


def sha256_file(path):
 h=hashlib.sha256()
 with open(path,"rb") as f:
  for c in iter(lambda:f.read(1024*1024),b""):h.update(c)
 return h.hexdigest()


def download_exact(url,path,size,digest):
 path.parent.mkdir(parents=True,exist_ok=True)
 cp=subprocess.run(["curl","--fail","--location","--silent","--show-error","--output",str(path),url],capture_output=True,text=True,timeout=900)
 if cp.returncode:raise RuntimeError(f"download failed exit={cp.returncode}")
 if path.stat().st_size!=size:raise RuntimeError("size mismatch")
 got=sha256_file(path)
 if got.lower()!=digest.lower():raise RuntimeError("sha256 mismatch")
 return {"bytes":path.stat().st_size,"sha256":got}


def extract_selected(archive):
 wanted=set(FILES);out={}
 with tarfile.open(archive,"r:*") as tf:
  for m in tf:
   name=m.name[2:] if m.name.startswith("./") else m.name
   if name not in wanted or not m.isfile():continue
   fp=tf.extractfile(m)
   if fp is not None:out[name]=fp.read().decode("utf-8",errors="replace")
 return out


def safe_strings(expr):
 vals=[]
 for m in re.finditer(r'["\']([^"\']+)["\']',expr):
  v=m.group(1)
  if SAFE_DEST_RE.fullmatch(v):vals.append(v)
 return vals


def normalize_condition(cond):
 c=re.sub(r"\s+","",cond)
 c=re.sub(r"^\((.*)\)$",r"\1",c)
 if c==SELECTOR:return {0:False,1:True}
 patterns=[
  (rf"{SELECTOR}==0", {0:True,1:False}),
  (rf"0=={SELECTOR}", {0:True,1:False}),
  (rf"{SELECTOR}==1", {0:False,1:True}),
  (rf"1=={SELECTOR}", {0:False,1:True}),
  (rf"{SELECTOR}!=0", {0:False,1:True}),
  (rf"0!={SELECTOR}", {0:False,1:True}),
  (rf"{SELECTOR}!=1", {0:True,1:False}),
  (rf"1!={SELECTOR}", {0:True,1:False}),
 ]
 for p,mapping in patterns:
  if re.fullmatch(p,c):return mapping
 return None


def ternary_mapping(rhs):
 # Bounded simple ternary with destination strings in each arm.
 m=re.fullmatch(r"\s*\(?\s*(?P<cond>[^?]+?)\s*\)?\s*\?\s*(?P<t>[^:]+?)\s*:\s*(?P<f>.+?)\s*",rhs,re.S)
 if not m:return None
 truth=normalize_condition(m.group("cond"))
 if truth is None:return None
 t=safe_strings(m.group("t"));f=safe_strings(m.group("f"))
 if len(t)!=1 or len(f)!=1:return None
 return {str(v):(t[0] if is_true else f[0]) for v,is_true in truth.items()}


def selector_assignments(path,text):
 out=[]
 # Keep to single-statement assignments; this is sufficient to classify the
 # exact downstream expression without publishing the statement itself.
 rx=re.compile(rf"\b(?P<lhs>{IDENT})\s*=\s*(?P<rhs>[^;\n]*\b{SELECTOR}\b[^;\n]*)\s*;")
 for m in rx.finditer(text):
  rhs=m.group("rhs")
  strings=safe_strings(rhs)
  mapping=ternary_mapping(rhs)
  out.append({
   "file":path,
   "lhs":m.group("lhs"),
   "selectorReferenceCount":len(re.findall(rf"\b{SELECTOR}\b",rhs)),
   "ternary": "?" in rhs and ":" in rhs,
   "comparisonOperators":[op for op in ("==","!=","<=",">=","<",">") if op in rhs],
   "safeStringTokens":strings,
   "normalizedCaseMapping":mapping,
   "rhsSha256":hashlib.sha256(rhs.encode()).hexdigest(),
  })
 return out


def crosscheck(names,selected):
 out=[]
 for name in sorted(set(names)):
  matches=[]
  for path,text in sorted(selected.items()):
   if path.endswith("avm_mtd.c"):continue
   count=len(re.findall(rf"(?<![A-Za-z0-9_.+-]){re.escape(name)}(?![A-Za-z0-9_.+-])",text))
   if count:matches.append({"file":path,"count":count})
  out.append({"destination":name,"independentMatches":matches,"independentlyObserved":bool(matches)})
 return out


def run_probe(args):
 work=pathlib.Path(args.work_dir).resolve();work.mkdir(parents=True,exist_ok=True)
 archive=work/"source-files.tar.gz"
 exact=download_exact(args.osp_url,archive,args.expected_size,args.expected_sha256)
 selected=extract_selected(archive);missing=sorted(set(FILES)-set(selected))
 assignments=[]
 for path,text in sorted(selected.items()):
  assignments.extend(selector_assignments(path,text))
 mappings=[]
 for a in assignments:
  if a["normalizedCaseMapping"]:
   mappings.append({"file":a["file"],"lhs":a["lhs"],"caseMapping":a["normalizedCaseMapping"]})
 names=[v for m in mappings for v in m["caseMapping"].values()]
 checks=crosscheck(names,selected)
 if missing:classification="H0_D1I_SOURCE_MISSING";oracle=False
 elif mappings:classification="H0_D1I_SELECTOR_DESTINATION_MAPPING_RECOVERED";oracle=True
 elif assignments:classification="H0_D1I_SELECTOR_ASSIGNMENT_PARTIAL";oracle=True
 else:classification="H0_D1I_SELECTOR_ASSIGNMENT_NOT_FOUND";oracle=True
 return {
  "schemaVersion":SCHEMA_VERSION,"experiment":EXPERIMENT,"classification":classification,"oracleSatisfied":oracle,
  "sourceArtifact":{"expectedBytes":args.expected_size,"expectedSha256":args.expected_sha256.lower(),"observedBytes":exact["bytes"],"observedSha256":exact["sha256"]},
  "missingFiles":missing,"selectorAssignments":assignments,"normalizedMappings":mappings,
  "destinationCrosscheck":checks,
  "derived":{"assignmentCount":len(assignments),"normalizedMappingCount":len(mappings),"destinationCount":len(set(names)),
             "independentlyObservedDestinationCount":sum(1 for x in checks if x["independentlyObserved"])},
  "interpretationBoundary":{"selectorDomainAssumedFromAcceptedD1h":[0,1],"normalizedTernaryMappingIsDerivedSourceFact":bool(mappings),
    "destinationNameMatchIsNotBootabilityProof":True,"exactFlashOffsetsAccepted":False,"rollbackSafetyAccepted":False,"modifiedHilAuthorized":False},
  "safety":{"rawOspArchivePublished":False,"sourcePayloadPublished":False,"sourceSnippetsPublished":False,
    "arbitraryStringLiteralsPublished":False,"physicalRouterContact":False,"flashWriteAuthorized":False,"bootEnvironmentMutationAuthorized":False}
 }


def parse_args(argv=None):
 p=argparse.ArgumentParser();p.add_argument("--osp-url",required=True);p.add_argument("--expected-size",type=int,required=True)
 p.add_argument("--expected-sha256",required=True);p.add_argument("--work-dir",required=True);p.add_argument("--receipt",required=True);return p.parse_args(argv)


def main(argv=None):
 args=parse_args(argv);rp=pathlib.Path(args.receipt);rp.parent.mkdir(parents=True,exist_ok=True)
 try:data=run_probe(args);rc=0 if data["oracleSatisfied"] else 2
 except Exception as exc:
  data={"schemaVersion":SCHEMA_VERSION,"experiment":EXPERIMENT,"classification":"HARNESS_FAILURE","oracleSatisfied":False,
    "error":{"type":type(exc).__name__,"message":str(exc)[:1000]},
    "safety":{"rawOspArchivePublished":False,"sourcePayloadPublished":False,"sourceSnippetsPublished":False,"arbitraryStringLiteralsPublished":False,
      "physicalRouterContact":False,"flashWriteAuthorized":False,"bootEnvironmentMutationAuthorized":False}}
  rc=3
 rp.write_text(json.dumps(data,indent=2,sort_keys=True)+"\n",encoding="utf-8")
 print(json.dumps({"classification":data["classification"],"oracleSatisfied":data["oracleSatisfied"]},sort_keys=True));return rc
if __name__=="__main__":raise SystemExit(main())
