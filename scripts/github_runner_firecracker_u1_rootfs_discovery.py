#!/usr/bin/env python3
"""Discover and hash the Ubuntu squashfs companion inside the already-pinned Firecracker CI prefix."""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import urllib.parse
import urllib.request

SCHEMA="firecracker-u1-rootfs-discovery/v1"
AUTHORITY="SemperSupra/agent-dispatch-private#287"
KERNEL_MANIFEST=pathlib.Path("experiments/firecracker/guest-kernel-6.18.48-x86_64.json")
S3="https://s3.amazonaws.com/spec.ccfc.min"

def _sha256(path:pathlib.Path)->str:
    h=hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda:fh.read(1024*1024),b""):
            h.update(chunk)
    return h.hexdigest()

def _fetch_text(url:str)->str:
    with urllib.request.urlopen(url,timeout=30) as response:
        return response.read().decode("utf-8")

def _download(url:str,dst:pathlib.Path)->None:
    with urllib.request.urlopen(url,timeout=60) as response, dst.open("wb") as fh:
        while True:
            chunk=response.read(1024*1024)
            if not chunk: break
            fh.write(chunk)

def _version_key(key:str)->tuple[int,...]:
    m=re.search(r"ubuntu-([0-9]+(?:\.[0-9]+)+)\.squashfs$",key)
    if not m:
        return ()
    return tuple(int(x) for x in m.group(1).split("."))

def discover()->dict:
    km=json.loads(KERNEL_MANIFEST.read_text())
    prefix=f"{km['firecracker_ci_prefix']}{km['architecture']}/ubuntu-"
    query=urllib.parse.urlencode({"list-type":"2","prefix":prefix})
    xml=_fetch_text(f"{S3}?{query}")
    keys=re.findall(r"<Key>([^<]+)</Key>",xml)
    candidates=[k for k in keys if re.search(r"/ubuntu-[0-9]+(?:\.[0-9]+)+\.squashfs$",k)]
    if not candidates:
        raise RuntimeError(f"no Ubuntu squashfs found under {prefix}")
    selected=max(candidates,key=_version_key)
    return {
        "ci_prefix":km["firecracker_ci_prefix"],
        "architecture":km["architecture"],
        "kernel_version":km["kernel_version"],
        "rootfs_key":selected,
        "rootfs_version":".".join(str(x) for x in _version_key(selected)),
        "rootfs_url":f"{S3}/{selected}",
        "candidate_keys":sorted(candidates),
    }

def run(out_dir:pathlib.Path)->dict:
    d=discover()
    dst=out_dir/pathlib.Path(d["rootfs_key"]).name
    _download(d["rootfs_url"],dst)
    return {
        "schema":SCHEMA,
        "authority":AUTHORITY,
        "result":{"classification":"SUPPORTED"},
        **d,
        "rootfs_sha256":_sha256(dst),
        "rootfs_size_bytes":dst.stat().st_size,
        "downloaded_filename":dst.name,
        "purpose":"Pin the normal-userspace companion artifact for U1; no guest boot claimed.",
    }

def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("--out",type=pathlib.Path,required=True); p.add_argument("--download-dir",type=pathlib.Path,required=True)
    a=p.parse_args(); a.out.parent.mkdir(parents=True,exist_ok=True); a.download_dir.mkdir(parents=True,exist_ok=True)
    try: receipt=run(a.download_dir)
    except Exception as exc:
        receipt={"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"HARNESS_FAILURE","reason":f"{type(exc).__name__}: {exc}"}}
    a.out.write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n"); print(json.dumps(receipt,indent=2,sort_keys=True))
    return 0 if receipt["result"]["classification"]=="SUPPORTED" else 1

if __name__=="__main__": raise SystemExit(main())
