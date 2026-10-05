#!/usr/bin/env python3
import argparse,json,re
from pathlib import Path
def text(path):
    try: return Path(path).read_text(errors="replace").strip()
    except FileNotFoundError: return ""
def parse_kv(s):
    d={}
    for line in s.splitlines():
        if "=" in line:
            k,v=line.split("=",1); d[k.strip()]=v.strip()
    return d
def parse_mtd(s):
    out=[]; rx=re.compile(r'^(mtd\d+):\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+"([^"]+)"')
    for line in s.splitlines():
        m=rx.match(line.strip())
        if m:
            out.append({"device":m.group(1),"size_bytes":int(m.group(2),16),
                        "erase_bytes":int(m.group(3),16),"name":m.group(4)})
    return out
def classify(name):
    n=name.lower()
    if any(x in n for x in ("u-boot","uboot","bootloader","devinfo","art","calib","factory")):
        return "protected"
    if any(x in n for x in ("kernel1","rootfs1","kernel2","rootfs2")):
        return "candidate-firmware-slot"
    return "unknown"
p=argparse.ArgumentParser(); p.add_argument("evidence_dir"); p.add_argument("-o","--output"); a=p.parse_args()
root=Path(a.evidence_dir); boot=parse_kv(text(root/"boot-env-selected.txt")); parts=parse_mtd(text(root/"proc-mtd.txt"))
for item in parts: item["classification"]=classify(item["name"])
d={"schema":"rdte-wrt-r1-device-descriptor/v1","adapter":"wrt-linksys-dual-nand/v1",
   "board":text(root/"board_name.txt") or None,"model":text(root/"model.txt") or None,
   "boot":{"boot_part":boot.get("boot_part"),"bootcount":boot.get("bootcount") or boot.get("boot_count"),"bootlimit":boot.get("bootlimit")},
   "partitions":parts,"protected_or_unknown":[x["device"] for x in parts if x["classification"] in ("protected","unknown")],
   "write_authority":"DENIED_R1_READ_ONLY","ready_for_r2":bool(parts and boot.get("boot_part")),"source_evidence":str(root)}
s=json.dumps(d,indent=2,sort_keys=True)+"\n"
Path(a.output).write_text(s) if a.output else print(s,end="")
