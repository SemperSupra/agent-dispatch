#!/usr/bin/env python3
"""Admit an R1 descriptor to R2 planning only when every recovery precondition has independent evidence."""
import argparse, json, sys
from copy import deepcopy
from pathlib import Path

REQUIRED = (
    "serial_console",
    "independent_power_cycle",
    "gold_image_identity",
    "rescue_image_identity",
    "independent_evidence_sink",
    "human_review",
)

class AdmissionError(RuntimeError):
    pass

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("descriptor")
    ap.add_argument("admission_evidence")
    ap.add_argument("-o","--output")
    args=ap.parse_args()

    d=json.loads(Path(args.descriptor).read_text())
    a=json.loads(Path(args.admission_evidence).read_text())

    if d.get("write_authority") != "DENIED_R1_READ_ONLY":
        raise AdmissionError("R1 descriptor write-authority invariant missing")
    if not d.get("r1_inventory_minimum_complete"):
        raise AdmissionError("R1 inventory minimum is incomplete")
    if a.get("schema") != "rdte-wrt-r2-admission-evidence/v1":
        raise AdmissionError("unexpected R2 admission evidence schema")

    checks=a.get("checks", {})
    missing=[]
    refs={}
    for name in REQUIRED:
        item=checks.get(name, {})
        if item.get("qualified") is not True or not item.get("evidence_ref"):
            missing.append(name)
        else:
            refs[name]=item["evidence_ref"]

    if missing:
        raise AdmissionError("R2 admission blocked: " + ", ".join(missing))

    outd=deepcopy(d)
    outd["ready_for_r2"]=True
    outd["r2_admission"]={
        "state":"ADMITTED_FOR_PLAN_ONLY",
        "missing":[],
        "evidence_refs":refs
    }
    out=json.dumps(outd,indent=2,sort_keys=True)+"\n"
    if args.output:
        Path(args.output).write_text(out)
    else:
        print(out,end="")

if __name__=="__main__":
    try:
        main()
    except AdmissionError as e:
        print(str(e),file=sys.stderr)
        raise SystemExit(2)
