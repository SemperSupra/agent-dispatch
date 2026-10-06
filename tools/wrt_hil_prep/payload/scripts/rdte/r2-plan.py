#!/usr/bin/env python3
"""Generate (never execute) an R2 Gold/Rescue recovery plan from accepted R1 evidence."""
import argparse,json,sys
from pathlib import Path

class PlanError(RuntimeError): pass

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("descriptor")
    ap.add_argument("-o","--output")
    args=ap.parse_args()
    d=json.loads(Path(args.descriptor).read_text())
    if d.get("write_authority")!="DENIED_R1_READ_ONLY":
        raise PlanError("R1 descriptor write authority invariant missing")
    if not d.get("ready_for_r2"):
        raise PlanError("R1 descriptor is not ready_for_r2")
    boot=d.get("boot",{})
    if not boot.get("boot_part"):
        raise PlanError("boot_part is not observed")
    slots=[p for p in d.get("partitions",[]) if p.get("classification")=="candidate-firmware-slot"]
    if len(slots)<4:
        raise PlanError("expected dual kernel/rootfs slot surfaces are not sufficiently observed")
    plan={
      "schema":"rdte-wrt-r2-plan/v1",
      "device":{"board":d.get("board"),"model":d.get("model")},
      "observed_boot_part":boot.get("boot_part"),
      "candidate_slot_surfaces":slots,
      "protected_or_unknown":d.get("protected_or_unknown",[]),
      "authority":"PLAN_ONLY_NO_EXECUTION",
      "required_human_review":["Gold slot assignment","Rescue slot assignment","protected-surface map","serial recovery","independent power"],
      "sequence":[
        "verify-gold-identity",
        "verify-rescue-identity",
        "boot-rescue-once",
        "verify-rescue-health",
        "return-gold",
        "verify-gold-health",
        "network-watchdog-recovery",
        "cold-power-recovery",
        "repeatability-x3"
      ],
      "stop_on":["identity-mismatch","serial-loss","power-actuator-loss","protected-surface-drift","evidence-loss","return-to-gold-failure"]
    }
    out=json.dumps(plan,indent=2,sort_keys=True)+"\n"
    if args.output: Path(args.output).write_text(out)
    else: print(out,end="")

if __name__=="__main__":
    try: main()
    except PlanError as e:
        print(str(e),file=sys.stderr); raise SystemExit(2)
