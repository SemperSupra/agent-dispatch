#!/usr/bin/env python3
"""Reduce R2 Gold/Rescue rep evidence into a fail-closed promotion verdict."""
import argparse, json
from pathlib import Path

REQUIRED_REPS = ("R2-1","R2-2","R2-3","R2-4","R2-5","R2-6")
REQUIRED_INVARIANTS = (
    "gold_identity_match","rescue_identity_match","serial_available","power_actuator_available",
    "protected_surfaces_unchanged","boot_env_expected","evidence_sink_available",
    "nominal_recovery_without_manual_intervention",
)

def reduce_evidence(d):
    reps=d.get("reps",{})
    missing=[r for r in REQUIRED_REPS if r not in reps]
    failed=[r for r in REQUIRED_REPS if reps.get(r,{}).get("verdict")!="PASS"]
    inv=d.get("invariants",{})
    bad_inv=[k for k in REQUIRED_INVARIANTS if inv.get(k) is not True]
    repeat=reps.get("R2-6",{}).get("consecutive_passes",0)
    if repeat < 3 and "R2-6" not in failed: failed.append("R2-6")
    promoted=not missing and not failed and not bad_inv
    return {
      "schema":"rdte-wrt-r2-verdict/v1",
      "status":"GREEN_R3_ADMITTED" if promoted else "RED_OR_INCOMPLETE_R3_BLOCKED",
      "r3_admitted":promoted,
      "missing_reps":missing,
      "failed_or_incomplete_reps":sorted(set(failed)),
      "failed_or_missing_invariants":bad_inv,
      "physical_write_authority":"R3_EXTERNAL_GENERATION_ONLY" if promoted else "DENIED",
      "protected_nand_write_authority":"DENIED",
    }

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("evidence"); ap.add_argument("-o","--output"); a=ap.parse_args()
    d=json.loads(Path(a.evidence).read_text())
    if d.get("schema")!="rdte-wrt-r2-evidence/v1": raise SystemExit("unexpected R2 evidence schema")
    out=json.dumps(reduce_evidence(d),indent=2,sort_keys=True)+"\n"
    if a.output: Path(a.output).write_text(out)
    else: print(out,end="")

if __name__=="__main__": main()
