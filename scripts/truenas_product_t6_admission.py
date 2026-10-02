#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, pathlib
from typing import Any

ALLOWED={"HOLD_GENERIC_CONTROL","SOURCE_READY","ADMITTED_EXISTING","ADMITTED"}
ADMITTED={"ADMITTED_EXISTING","ADMITTED"}

class AdmissionError(RuntimeError): pass

def load(path:pathlib.Path)->dict[str,Any]:
    try: v=json.loads(path.read_text(encoding="utf-8"))
    except (OSError,json.JSONDecodeError) as exc: raise AdmissionError(f"cannot read {path}: {exc}") from exc
    if not isinstance(v,dict): raise AdmissionError(f"{path} must contain object")
    return v

def targets(reg:dict[str,Any])->list[str]:
    if reg.get("schema")!="gha-kvm-truenas-targets/v1": raise AdmissionError("unsupported target registry schema")
    rows=reg.get("targets")
    if not isinstance(rows,list) or not rows: raise AdmissionError("target registry empty")
    versions=[x.get("version") for x in rows if isinstance(x,dict)]
    if any(not isinstance(x,str) or not x for x in versions) or len(versions)!=len(set(versions)):
        raise AdmissionError("invalid target versions")
    return versions

def git_blob_sha(path:pathlib.Path)->str:
    data=path.read_bytes()
    header=f"blob {len(data)}\0".encode()
    return hashlib.sha1(header+data).hexdigest()

def validate(cfg:dict[str,Any],target_reg:dict[str,Any],repo_root:pathlib.Path)->dict[str,Any]:
    if cfg.get("schema")!="gha-kvm-truenas-product-t6-admission/v1": raise AdmissionError("unsupported admission schema")
    versions=targets(target_reg)
    rows=cfg.get("products")
    if not isinstance(rows,list) or not rows: raise AdmissionError("products missing")
    ids=set(); summary=[]
    for p in rows:
        pid=p.get("id")
        if not isinstance(pid,str) or not pid or pid in ids: raise AdmissionError(f"invalid/duplicate product {pid!r}")
        ids.add(pid)
        prod=p.get("producer"); cons=p.get("consumer")
        if not isinstance(prod,dict) or not isinstance(cons,dict): raise AdmissionError(f"{pid}: producer/consumer missing")
        ref=prod.get("ref")
        if not isinstance(ref,str) or len(ref)!=40 or any(c not in "0123456789abcdef" for c in ref):
            raise AdmissionError(f"{pid}: exact producer ref required")
        path=cons.get("path"); expected=cons.get("blob_sha")
        if not isinstance(path,str) or not isinstance(expected,str) or len(expected)!=40:
            raise AdmissionError(f"{pid}: consumer identity invalid")
        local=repo_root/path
        if not local.is_file(): raise AdmissionError(f"{pid}: consumer missing: {path}")
        actual=git_blob_sha(local)
        if actual!=expected: raise AdmissionError(f"{pid}: consumer blob drift: expected={expected} actual={actual}")
        states=p.get("target_admission")
        if not isinstance(states,dict) or list(states)!=versions:
            raise AdmissionError(f"{pid}: target admission keys/order must exactly match target registry")
        for version in versions:
            cell=states[version]
            status=cell.get("status") if isinstance(cell,dict) else None
            if status not in ALLOWED: raise AdmissionError(f"{pid}/{version}: invalid status {status!r}")
            ev=cell.get("evidence")
            if status in ADMITTED and not isinstance(ev,dict):
                raise AdmissionError(f"{pid}/{version}: admitted state requires evidence")
            if status not in ADMITTED and ev is not None:
                raise AdmissionError(f"{pid}/{version}: non-admitted state must not carry acceptance evidence")
        summary.append({"id":pid,"admission":{v:states[v]["status"] for v in versions}})
    return {"schema":"gha-kvm-truenas-product-t6-admission-validation/v1","status":"PASS","targets":versions,"products":summary,
            "claim_boundary":"admission contract only; runtime qualification remains receipt-driven"}

def get_product(cfg:dict[str,Any],pid:str)->dict[str,Any]:
    rows=[x for x in cfg.get("products",[]) if x.get("id")==pid]
    if len(rows)!=1: raise AdmissionError(f"unknown product: {pid}")
    return rows[0]

def main()->int:
    ap=argparse.ArgumentParser()
    ap.add_argument("--admission",type=pathlib.Path,default=pathlib.Path("config/truenas-product-t6-admission.json"))
    ap.add_argument("--targets",type=pathlib.Path,default=pathlib.Path("config/truenas-rdte-targets.json"))
    ap.add_argument("--repo-root",type=pathlib.Path,default=pathlib.Path("."))
    ap.add_argument("--validate-only",action="store_true")
    ap.add_argument("--product")
    ap.add_argument("--version")
    ap.add_argument("--require-admitted",action="store_true")
    args=ap.parse_args()
    try:
        cfg=load(args.admission); reg=load(args.targets); result=validate(cfg,reg,args.repo_root)
        if args.validate_only:
            print(json.dumps(result,indent=2,sort_keys=True)); return 0
        if not args.product or not args.version: raise AdmissionError("--product and --version required")
        p=get_product(cfg,args.product)
        cell=p["target_admission"].get(args.version)
        if not isinstance(cell,dict): raise AdmissionError(f"{args.product}/{args.version}: exact target not present")
        status=cell["status"]
        out={"schema":"gha-kvm-truenas-product-t6-admission-decision/v1","product":args.product,"version":args.version,
             "status":status,"admitted":status in ADMITTED,"producer":p["producer"],"consumer":p["consumer"],
             "product_authority":p["product_authority"],"matrix_id":p["matrix_id"]}
        if args.require_admitted and status not in ADMITTED:
            raise AdmissionError(f"{args.product}/{args.version}: execution blocked by admission status {status}")
        print(json.dumps(out,indent=2,sort_keys=True)); return 0
    except AdmissionError as exc:
        print(json.dumps({"status":"ERROR","error":str(exc)},sort_keys=True)); return 2
if __name__=="__main__": raise SystemExit(main())
