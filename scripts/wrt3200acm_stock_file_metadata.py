#!/usr/bin/env python3
"""CRC-valid reconstruction of selected stock WRT3200ACM JFFS2 files, metadata only."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import subprocess
from pathlib import Path
from typing import Any

_HELPER_PATH = Path(__file__).with_name("jffs2_target_extract.py")
_HELPER_SPEC = importlib.util.spec_from_file_location("jffs2_target_extract_local", _HELPER_PATH)
if _HELPER_SPEC is None or _HELPER_SPEC.loader is None:
    raise RuntimeError("cannot load jffs2_target_extract.py")
jffs = importlib.util.module_from_spec(_HELPER_SPEC)
_HELPER_SPEC.loader.exec_module(jffs)

DEFAULT_PATHS = [
    "/lib/modules/3.10.70/W8964.bin",
    "/lib/modules/3.10.70/ap8x.ko",
    "/lib/modules/3.10.70/mlan.ko",
    "/lib/modules/3.10.70/sd8xxx.ko",
    "/etc/WlanCalData_ext.conf",
    "/lib/firmware/mrvl/WlanCalData_ext.conf",
    "/lib/firmware/mrvl/sd8887_uapsta_a2.bin",
    "/lib/firmware/mrvl/sd8887_bt_a2.bin",
    "/lib/libjnap_wirelessap_marvell.so",
    "/lib/libwlan.so.1.0.0",
    "/usr/sbin/hostapd",
    "/sbin/wlancfg",
]
KNOWN_PUBLIC_88W8964_SHA256 = "ca23f5bb730fde399359a716481651c120e09c299d4e6bbec6fe718c6e87e751"

def sha256(path: Path) -> str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(1024*1024),b""):
            h.update(chunk)
    return h.hexdigest()

def run(cmd:list[str], **kwargs) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False,**kwargs)

def extract_one(fs:bytes, logical_path:str, work:Path) -> dict[str,Any]:
    safe=logical_path.strip("/").replace("/","__") or "root"
    dest=work/safe
    rec:dict[str,Any]={"path":logical_path,"extractor":"crc-valid-all-fragment-replay"}
    try:
        blob, replay = jffs.extract_path(fs,logical_path)
    except Exception as exc:
        rec.update({"status":"failed","error":repr(exc)})
        return rec
    dest.write_bytes(blob)
    rec.update({
        "status":"ok",
        "size":len(blob),
        "sha256":hashlib.sha256(blob).hexdigest(),
        "jffs2_replay":{
            "inode":replay["inode"],
            "raw_inode_node_count":replay["raw_inode_node_count"],
            "crc_valid_inode_node_count":replay["crc_valid_inode_node_count"],
            "crc_invalid_inode_node_count":replay["crc_invalid_inode_node_count"],
            "compression_types":replay["compression_types"],
        }
    })
    file_result=run(["file","-b",str(dest)],timeout=30)
    rec["file"]=file_result.stdout.strip()
    if logical_path.endswith(".ko"):
        m=run(["modinfo",str(dest)],timeout=30)
        rec["modinfo_rc"]=m.returncode
        rec["modinfo"]=[line for line in m.stdout.splitlines() if line.startswith(
            ("filename:","license:","description:","author:","version:","srcversion:","depends:","vermagic:","name:")
        )][:50]
    if logical_path.endswith("W8964.bin"):
        rec["matches_public_mwlwifi_88w8964"]=(rec["sha256"]==KNOWN_PUBLIC_88W8964_SHA256)
        strings=run(["strings","-a","-n","6",str(dest)],timeout=60)
        markers=[]
        for line in strings.stdout.splitlines():
            low=line.lower()
            if any(k in low for k in ("version","8006.img","marvell","hostcmd","cmd_process","copyright")):
                markers.append(line[:500])
            if len(markers)>=80:
                break
        rec["selected_strings"]=markers
    dest.unlink(missing_ok=True)
    return rec

def main()->int:
    ap=argparse.ArgumentParser()
    ap.add_argument("jffs2_image")
    ap.add_argument("--out",required=True)
    ap.add_argument("--work",required=True)
    ap.add_argument("--path",action="append",default=[])
    ns=ap.parse_args()
    image=Path(ns.jffs2_image)
    out=Path(ns.out); work=Path(ns.work)
    out.parent.mkdir(parents=True,exist_ok=True); work.mkdir(parents=True,exist_ok=True)
    fs=image.read_bytes()
    paths=ns.path or DEFAULT_PATHS
    records=[extract_one(fs,p,work) for p in paths]
    report={
        "schema":"wrt3200acm-stock-selected-file-metadata/v2",
        "extractor":"CRC-valid all-fragment JFFS2 replay",
        "jffs2_image_size":image.stat().st_size,
        "selected_path_count":len(paths),
        "success_count":sum(r["status"]=="ok" for r in records),
        "failed_count":sum(r["status"]!="ok" for r in records),
        "records":records,
        "firmware_identity":{
            "stock_path":"/lib/modules/3.10.70/W8964.bin",
            "public_mwlwifi_sha256":KNOWN_PUBLIC_88W8964_SHA256,
            "stock_sha256":next((r.get("sha256") for r in records if r["path"].endswith("W8964.bin")),None),
            "byte_identical":next((r.get("matches_public_mwlwifi_88w8964") for r in records if r["path"].endswith("W8964.bin")),None),
        },
        "note":"Selected files existed only in ephemeral runner storage; durable result contains hashes/metadata/selected strings, not file payloads."
    }
    out.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps(report["firmware_identity"],indent=2,sort_keys=True))
    for r in records:
        print(r["status"],r["path"],r.get("size"),r.get("sha256"))
    if report["success_count"] < 4:
        return 3
    if report["firmware_identity"]["stock_sha256"] is None:
        return 4
    return 0

if __name__=="__main__":
    raise SystemExit(main())
