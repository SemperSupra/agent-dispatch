#!/usr/bin/env python3
"""Reduce WRT R1 read-only evidence into an RDTE device descriptor.

R1 may establish inventory sufficiency, but it cannot by itself admit R2.
R2 admission additionally requires independently evidenced recovery capabilities.
"""
import argparse, json, re
from pathlib import Path

R2_EXTERNAL_PRECONDITIONS = [
    "serial_console",
    "independent_power_cycle",
    "gold_image_identity",
    "rescue_image_identity",
    "independent_evidence_sink",
    "human_review",
]

def text(path):
    try: return Path(path).read_text(errors="replace").strip()
    except FileNotFoundError: return ""

def parse_mtd(s):
    out=[]
    rx=re.compile(r'^(mtd\d+):\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+"([^"]+)"')
    for line in s.splitlines():
        m=rx.match(line.strip())
        if not m: continue
        out.append({
            "device":m.group(1),
            "size_bytes":int(m.group(2),16),
            "erase_bytes":int(m.group(3),16),
            "name":m.group(4)
        })
    return out

def parse_kv(s):
    d={}
    for line in s.splitlines():
        if "=" in line:
            k,v=line.split("=",1); d[k.strip()]=v.strip()
    return d

def classify_partition(name):
    n=name.lower()
    if any(x in n for x in ("u-boot","uboot","bootloader","devinfo","art","calib","factory")):
        return "protected"
    if n in ("kernel1","rootfs1","kernel2","rootfs2") or any(x in n for x in ("kernel1","rootfs1","kernel2","rootfs2")):
        return "candidate-firmware-slot"
    return "unknown"

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("evidence_dir")
    ap.add_argument("-o","--output")
    args=ap.parse_args()
    root=Path(args.evidence_dir)
    boot=parse_kv(text(root/"boot-env-selected.txt"))
    mtd=parse_mtd(text(root/"proc-mtd.txt"))
    for p in mtd:
        p["classification"]=classify_partition(p["name"])
    r1_minimum_complete=bool(mtd and boot.get("boot_part"))
    descriptor={
        "schema":"rdte-wrt-r1-device-descriptor/v1",
        "adapter":"wrt-linksys-dual-nand/v1",
        "board":text(root/"board_name.txt") or None,
        "model":text(root/"model.txt") or None,
        "boot":{
            "boot_part":boot.get("boot_part"),
            "bootcount":boot.get("bootcount") or boot.get("boot_count"),
            "bootlimit":boot.get("bootlimit")
        },
        "partitions":mtd,
        "protected_or_unknown":[p["device"] for p in mtd if p["classification"] in ("protected","unknown")],
        "write_authority":"DENIED_R1_READ_ONLY",
        "r1_inventory_minimum_complete":r1_minimum_complete,
        "ready_for_r2":False,
        "r2_admission":{
            "state":"BLOCKED_REQUIRES_EXTERNAL_PRECONDITIONS",
            "missing":list(R2_EXTERNAL_PRECONDITIONS)
        },
        "source_evidence":str(root)
    }
    out=json.dumps(descriptor,indent=2,sort_keys=True)+"\n"
    if args.output: Path(args.output).write_text(out)
    else: print(out,end="")

if __name__=="__main__": main()
