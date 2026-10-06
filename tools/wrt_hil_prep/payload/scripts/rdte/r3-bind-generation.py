#!/usr/bin/env python3
"""Bind an emulator-qualified WRT generation intent to reviewed physical R1/R2 facts."""
import argparse, json, sys
from pathlib import Path

class BindError(RuntimeError): pass

ROLES={
 "dut-a-rdte":"Multi-AP-Controller-and-Agent",
 "dut-b-rdte":"Multi-AP-Agent",
}
REQUIRED_BINDINGS=(
 "asset_id","management_ip","lan_interface","radio_interface",
 "network_uci_section","wireless_device_section","wireless_iface_section",
 "gold_image_sha256","rescue_image_sha256","gold_slot","rescue_slot",
)

def bind(intent, descriptor, r2, physical):
    if r2.get("schema")!="rdte-wrt-r2-verdict/v1" or r2.get("r3_admitted") is not True:
        raise BindError("R3 binding denied: R2 is not green")
    if r2.get("protected_nand_write_authority")!="DENIED":
        raise BindError("protected NAND deny invariant missing")
    if descriptor.get("write_authority")!="DENIED_R1_READ_ONLY":
        raise BindError("R1 descriptor authority invariant missing")
    missing=[k for k in REQUIRED_BINDINGS if not physical.get(k)]
    if missing: raise BindError("missing physical bindings: "+",".join(missing))
    if physical["gold_slot"]==physical["rescue_slot"]:
        raise BindError("Gold and Rescue slots must be distinct")
    generation=intent.get("generation")
    if generation not in ("dut-a-gold","dut-b-gold","dut-a-rdte","dut-b-rdte"):
        raise BindError("unknown generation")
    rdte=generation.endswith("-rdte")
    return {
      "schema":"rdte-wrt-r3-bound-generation/v1",
      "generation":generation,
      "asset_id":physical["asset_id"],
      "board":descriptor.get("board"),
      "model":descriptor.get("model"),
      "management":{"ip":physical["management_ip"],"lan_interface":physical["lan_interface"],"uci_network_section":physical["network_uci_section"]},
      "radio":{"interface":physical["radio_interface"],"uci_device_section":physical["wireless_device_section"],"uci_iface_section":physical["wireless_iface_section"]},
      "recovery":{
        "gold_slot":physical["gold_slot"],"rescue_slot":physical["rescue_slot"],
        "gold_image_sha256":physical["gold_image_sha256"],
        "rescue_image_sha256":physical["rescue_image_sha256"],
      },
      "easymesh":{"enabled":rdte,"management_mode":ROLES.get(generation)},
      "write_scope":"EXTERNAL_PACKAGE_CONFIG_GENERATION_ONLY" if rdte else "GOLD_BASELINE_NO_EXPERIMENTAL_MUTATION",
      "protected_or_unknown_mtd":descriptor.get("protected_or_unknown",[]),
      "protected_nand_write_authority":"DENIED",
    }

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("intent"); ap.add_argument("descriptor"); ap.add_argument("r2_verdict"); ap.add_argument("physical_bindings")
    ap.add_argument("-o","--output")
    a=ap.parse_args()
    try:
        out=bind(*(json.loads(Path(p).read_text()) for p in (a.intent,a.descriptor,a.r2_verdict,a.physical_bindings)))
    except BindError as e:
        print(str(e),file=sys.stderr); raise SystemExit(2)
    s=json.dumps(out,indent=2,sort_keys=True)+"\n"
    if a.output: Path(a.output).write_text(s)
    else: print(s,end="")

if __name__=="__main__": main()
