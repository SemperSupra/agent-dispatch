#!/usr/bin/env python3
"""Fake independent-power actuator used to qualify R2 orchestration without hardware."""
import argparse, json, sys
from pathlib import Path

class PowerError(RuntimeError): pass

def load(p): return json.loads(Path(p).read_text())
def save(p,o): Path(p).write_text(json.dumps(o,indent=2,sort_keys=True)+"\n")

def require_independent(s):
    if s.get("schema")!="rdte-fake-power-state/v1": raise PowerError("unexpected state schema")
    if not s.get("independent_from_dut_data_plane"): raise PowerError("power actuator is not independent")
    if not s.get("evidence_sink_independent"): raise PowerError("evidence sink is not independent")

def set_power(s,target):
    require_independent(s)
    if target not in ("on","off"): raise PowerError("invalid power target")
    s["power_state"]=target
    s["sequence"]=int(s.get("sequence",0))+1
    s.setdefault("events",[]).append({"sequence":s["sequence"],"action":"set","target":target})

def cold_cycle(s):
    require_independent(s)
    set_power(s,"off")
    set_power(s,"on")
    s.setdefault("events",[]).append({"sequence":s["sequence"],"action":"cold-cycle-complete"})

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--state",required=True)
    sub=ap.add_subparsers(dest="cmd",required=True)
    p=sub.add_parser("set"); p.add_argument("target",choices=["on","off"])
    sub.add_parser("cold-cycle"); sub.add_parser("status")
    a=ap.parse_args(); s=load(a.state)
    try:
        if a.cmd=="set": set_power(s,a.target); save(a.state,s)
        elif a.cmd=="cold-cycle": cold_cycle(s); save(a.state,s)
        print(json.dumps(s,indent=2,sort_keys=True))
    except PowerError as e:
        print(str(e),file=sys.stderr); raise SystemExit(2)

if __name__=="__main__": main()
