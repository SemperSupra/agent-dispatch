#!/usr/bin/env python3
from __future__ import annotations
import argparse, importlib.util, json, re, urllib.request
from pathlib import Path

REF="db97edf20fadea2617805006f5230665fadc6a8c"
BASE=f"https://raw.githubusercontent.com/kaloz/mwlwifi/{REF}/hif/"
CMD_RE=re.compile(r"^\s*#define\s+(HOSTCMD_CMD_[A-Z0-9_]+)\s+(0x[0-9A-Fa-f]+)\b",re.M)
LABEL_RE=re.compile(r'\{\s*(HOSTCMD_CMD_[A-Z0-9_]+)\s*,\s*"([^"]+)"\s*\}')

def fetch(name):
    with urllib.request.urlopen(urllib.request.Request(BASE+name,headers={"User-Agent":"SemperSupra-WRT-ABI/1.0"}),timeout=45) as r:
        return r.read().decode("utf-8","replace")

def main()->int:
    ap=argparse.ArgumentParser(); ap.add_argument("--elf",required=True); ap.add_argument("--out",required=True); ns=ap.parse_args()
    host=fetch("hostcmd.h"); fw=fetch("fwcmd.c")
    labels=dict(LABEL_RE.findall(fw))
    cmds=[]
    for n,v in CMD_RE.findall(host):
        val=int(v,16); cmds.append({"name":n,"value":val,"hex":f"0x{val:04x}","label":labels.get(n)})
    P=Path(__file__).with_name("wrt3200acm_dispatch_probe.py")
    spec=importlib.util.spec_from_file_location("dp",P); dp=importlib.util.module_from_spec(spec); assert spec.loader; spec.loader.exec_module(dp)
    dis=dp.run_objdump(Path(ns.elf),0x36454,0x390ec)
    cases=dp.recover_cases(dp.parse_instructions(dis),{c["value"]:c["name"] for c in cmds})
    byval={c["value"]:c for c in cases}
    for c in cmds:
        if c["value"] in byval:
            c["firmware_branch_target"]=byval[c["value"]]["branch_target"]
            c["firmware_match_kind"]=byval[c["value"]]["match_kind"]
    report={
      "schema":"wrt8964-hostcmd-abi-map/v1","source_ref":REF,
      "command_count":len(cmds),"mapped_dispatch_cases":len(cases),
      "commands":cmds,
      "unmapped_commands":[c["name"] for c in cmds if "firmware_branch_target" not in c],
      "guardrail":"Command IDs/names are exact host-source facts. Branch targets are static firmware observations. Handler semantics are separate findings."
    }
    Path(ns.out).write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"commands":len(cmds),"mapped":len(cases),"unmapped":len(report["unmapped_commands"])},indent=2))
    return 0
if __name__=="__main__": raise SystemExit(main())
