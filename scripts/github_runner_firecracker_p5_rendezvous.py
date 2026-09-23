#!/usr/bin/env python3
"""GitHub-native bounded offer/ack rendezvous for P5 live-runner coordination."""
from __future__ import annotations
import argparse,hashlib,json,os,pathlib,time,urllib.request,zipfile

API="https://api.github.com"

def _headers()->dict:
    token=os.environ.get("GITHUB_TOKEN")
    if not token: raise RuntimeError("GITHUB_TOKEN unavailable")
    return {"Authorization":f"Bearer {token}","Accept":"application/vnd.github+json","User-Agent":"SemperSupra-firecracker-p5"}

def _get_json(url:str)->dict:
    req=urllib.request.Request(url,headers=_headers())
    with urllib.request.urlopen(req,timeout=15) as r:return json.loads(r.read())

def wait_artifact(name:str,out_dir:pathlib.Path,timeout_s:int)->dict:
    repo=os.environ["GITHUB_REPOSITORY"]; run_id=os.environ["GITHUB_RUN_ID"]
    list_url=f"{API}/repos/{repo}/actions/runs/{run_id}/artifacts?per_page=100"
    started=time.perf_counter(); artifact=None; polls=0
    deadline=time.monotonic()+timeout_s
    while time.monotonic()<deadline:
        polls+=1
        data=_get_json(list_url)
        artifact=next((a for a in data.get("artifacts",[]) if a.get("name")==name and not a.get("expired")),None)
        if artifact:break
        time.sleep(1)
    if not artifact:raise RuntimeError(f"artifact {name} not visible within {timeout_s}s")
    visible_ms=(time.perf_counter()-started)*1000
    out_dir.mkdir(parents=True,exist_ok=True); zpath=out_dir/"artifact.zip"
    req=urllib.request.Request(artifact["archive_download_url"],headers=_headers())
    dl=time.perf_counter()
    with urllib.request.urlopen(req,timeout=30) as r:zpath.write_bytes(r.read())
    download_ms=(time.perf_counter()-dl)*1000
    digest=hashlib.sha256(zpath.read_bytes()).hexdigest()
    with zipfile.ZipFile(zpath) as z:z.extractall(out_dir)
    zpath.unlink()
    return {"classification":"SUPPORTED","artifact_name":name,"artifact_id":artifact["id"],
            "artifact_size_in_bytes":artifact.get("size_in_bytes"),"artifact_digest":artifact.get("digest"),
            "downloaded_zip_sha256":digest,"polls":polls,"visibility_wait_ms":round(visible_ms,3),
            "download_ms":round(download_ms,3)}

def make_ack(offer:pathlib.Path,status:pathlib.Path,out:pathlib.Path)->dict:
    offer_bytes=offer.read_bytes(); consumer=json.loads(status.read_text())
    ack={"schema":"firecracker-p5-ack/v1","run_id":os.environ.get("GITHUB_RUN_ID"),
         "offer_sha256":hashlib.sha256(offer_bytes).hexdigest(),"consumer_status":consumer}
    out.parent.mkdir(parents=True,exist_ok=True); out.write_text(json.dumps(ack,indent=2,sort_keys=True)+"\n")
    return ack

def validate(offer:pathlib.Path,ack:pathlib.Path,producer_status:pathlib.Path)->dict:
    offer_hash=hashlib.sha256(offer.read_bytes()).hexdigest()
    a=json.loads(ack.read_text()); p=json.loads(producer_status.read_text())
    c=a.get("consumer_status",{})
    checks={"offer_hash":a.get("offer_sha256")==offer_hash,
            "run_id":a.get("run_id")==os.environ.get("GITHUB_RUN_ID"),
            "producer_vm_alive":bool(p.get("alive") and p.get("ready_observed")),
            "consumer_vm_alive_at_ack":bool(c.get("alive") and c.get("ready_observed"))}
    return {"schema":"firecracker-p5-coordination-receipt/v1",
            "classification":"SUPPORTED" if all(checks.values()) else "ORACLE_FAILURE",
            "checks":checks,"producer_status":p,"consumer_status_at_ack":c}

def main()->int:
    p=argparse.ArgumentParser(); s=p.add_subparsers(dest="cmd",required=True)
    w=s.add_parser("wait"); w.add_argument("--name",required=True); w.add_argument("--out-dir",type=pathlib.Path,required=True); w.add_argument("--receipt",type=pathlib.Path,required=True); w.add_argument("--timeout",type=int,default=45)
    a=s.add_parser("ack"); a.add_argument("--offer",type=pathlib.Path,required=True); a.add_argument("--status",type=pathlib.Path,required=True); a.add_argument("--out",type=pathlib.Path,required=True)
    v=s.add_parser("validate"); v.add_argument("--offer",type=pathlib.Path,required=True); v.add_argument("--ack",type=pathlib.Path,required=True); v.add_argument("--producer-status",type=pathlib.Path,required=True); v.add_argument("--out",type=pathlib.Path,required=True)
    x=p.parse_args()
    try:
        if x.cmd=="wait":
            result=wait_artifact(x.name,x.out_dir,x.timeout); x.receipt.parent.mkdir(parents=True,exist_ok=True); x.receipt.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
        elif x.cmd=="ack": result=make_ack(x.offer,x.status,x.out)
        else:
            result=validate(x.offer,x.ack,x.producer_status); x.out.parent.mkdir(parents=True,exist_ok=True); x.out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
        print(json.dumps(result,indent=2,sort_keys=True))
        return 0 if result.get("classification","SUPPORTED")=="SUPPORTED" else 1
    except Exception as e:
        print(json.dumps({"classification":"HARNESS_FAILURE","reason":f"{type(e).__name__}: {e}"},indent=2)); return 1
if __name__=="__main__": raise SystemExit(main())
