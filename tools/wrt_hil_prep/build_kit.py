#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, os, pathlib, shutil, tempfile, urllib.request, zipfile

OPENWRT_VERSION="25.12.5"
OPENWRT_BASE=f"https://downloads.openwrt.org/releases/{OPENWRT_VERSION}/targets/mvebu/cortexa9"
DEVICE_PREFIX=f"openwrt-{OPENWRT_VERSION}-mvebu-cortexa9-linksys_wrt3200acm"
OPENWRT_FILES=[
    "sha256sums","sha256sums.asc","profiles.json",
    f"{DEVICE_PREFIX}-initramfs-kernel.bin",
    f"{DEVICE_PREFIX}-squashfs-factory.img",
    f"{DEVICE_PREFIX}-squashfs-sysupgrade.bin",
]
CP0_ARTIFACT_ID=11329764103
CP0_RUN_ID=37273250460
PRPLMESH_SHA256="0adddf13bac7161fb97c5db3f9e9d9a1390c886add6793cd19a3037357e322a7"
KIT_NAME="wrt3200acm-hil-prep-kit-20261005"

def sha256_file(path):
    h=hashlib.sha256()
    with open(path,"rb") as f:
        for chunk in iter(lambda:f.read(8*1024*1024),b""): h.update(chunk)
    return h.hexdigest()

def download(url,path,headers=None):
    path=pathlib.Path(path); path.parent.mkdir(parents=True,exist_ok=True)
    req=urllib.request.Request(url,headers=headers or {"User-Agent":"SemperSupra-WRT-HIL-Kit/1"})
    with urllib.request.urlopen(req,timeout=120) as r, open(path,"wb") as f:
        shutil.copyfileobj(r,f,length=1024*1024)

def deterministic_zip(source,dest):
    source=pathlib.Path(source); dest=pathlib.Path(dest)
    with zipfile.ZipFile(dest,"w",compression=zipfile.ZIP_STORED,allowZip64=True) as z:
        for p in sorted(x for x in source.rglob("*") if x.is_file()):
            info=zipfile.ZipInfo(p.relative_to(source).as_posix())
            info.date_time=(1980,1,1,0,0,0); info.compress_type=zipfile.ZIP_STORED
            info.external_attr=((0o100755 if os.access(p,os.X_OK) else 0o100644)<<16)
            with open(p,"rb") as src,z.open(info,"w",force_zip64=True) as dst:
                shutil.copyfileobj(src,dst,length=8*1024*1024)

def main():
    ap=argparse.ArgumentParser();ap.add_argument("--output",default="dist");ap.add_argument("--cp0-dir");a=ap.parse_args()
    repo_root=pathlib.Path(__file__).resolve().parents[2]
    payload=repo_root/"tools"/"wrt_hil_prep"/"payload"
    out=pathlib.Path(a.output).resolve();out.mkdir(parents=True,exist_ok=True)
    kit=out/KIT_NAME
    if kit.exists(): shutil.rmtree(kit)
    shutil.copytree(payload,kit)
    images=kit/"images"/"openwrt"; images.mkdir(parents=True,exist_ok=True)
    meta=kit/"metadata"; meta.mkdir(parents=True,exist_ok=True)
    for name in OPENWRT_FILES:
        download(f"{OPENWRT_BASE}/{name}",images/name)
    sums=(images/"sha256sums").read_text(errors="replace"); selected={}
    for name in OPENWRT_FILES[3:]:
        official=next((x.split()[0] for x in sums.splitlines() if x.strip().endswith(name)),None)
        actual=sha256_file(images/name)
        if not official or actual!=official: raise SystemExit(f"OpenWrt SHA mismatch/missing: {name}")
        selected[name]={"sha256":actual,"size_bytes":(images/name).stat().st_size,"url":f"{OPENWRT_BASE}/{name}"}
    cp0=meta/"cp0"; cp0.mkdir(parents=True,exist_ok=True)
    if not a.cp0_dir: raise SystemExit("--cp0-dir is required")
    cp0_source=pathlib.Path(a.cp0_dir).resolve()
    if not cp0_source.is_dir(): raise SystemExit(f"CP0 directory not found: {cp0_source}")
    for p in cp0_source.rglob("*"):
        if p.is_file():
            rel=p.relative_to(cp0_source); dst=cp0/rel; dst.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(p,dst)
    pkg=next(cp0.rglob("prplmesh-6.0.1-r1.apk"),None)
    if pkg is None or sha256_file(pkg)!=PRPLMESH_SHA256: raise SystemExit("qualified prplMesh package mismatch")
    (kit/"packages").mkdir(exist_ok=True); shutil.copy2(pkg,kit/"packages"/pkg.name)
    provenance={
      "schema":"wrt3200acm-hil-prep-kit/v1","date":"2026-10-05","kit":KIT_NAME,
      "qualified_baseline":{"openwrt":OPENWRT_VERSION,"target":"mvebu/cortexa9","device":"linksys_wrt3200acm",
        "prplmesh":"6.0.1-r1","prplmesh_sha256":PRPLMESH_SHA256,"cp0_run_id":CP0_RUN_ID,"cp0_artifact_id":CP0_ARTIFACT_ID},
      "openwrt_files":selected,
      "authority_boundary":{"current_phase":"R1_READ_ONLY","persistent_dut_writes_allowed":False,"prplmesh_install_allowed_now":False},
      "sources":["https://openwrt.org/releases/25.12/start","https://openwrt.org/toh/linksys/wrt3200acm",
        "https://openwrt.org/toh/linksys/wrt_ac_series",OPENWRT_BASE+"/","SemperSupra/wrt3200acm-recovery-private","SemperSupra/agent-dispatch"]
    }
    (meta/"provenance.json").write_text(json.dumps(provenance,indent=2,sort_keys=True)+"\n")
    files=sorted(p for p in kit.rglob("*") if p.is_file() and p.name!="SHA256SUMS")
    (meta/"SHA256SUMS").write_text("\n".join(f"{sha256_file(p)}  {p.relative_to(kit).as_posix()}" for p in files)+"\n")
    dest=out/f"{KIT_NAME}.zip"; deterministic_zip(kit,dest)
    result={"schema":"wrt3200acm-hil-prep-kit-build/v1","zip":str(dest),"zip_sha256":sha256_file(dest),
      "zip_size_bytes":dest.stat().st_size,"file_count":len([p for p in kit.rglob("*") if p.is_file()]),
      "openwrt_verified":True,"prplmesh_verified":True}
    (out/f"{KIT_NAME}.build.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print(json.dumps(result,indent=2,sort_keys=True))
if __name__=="__main__": main()
