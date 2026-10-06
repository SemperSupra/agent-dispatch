#!/usr/bin/env python3
"""Render a bound R3 generation into an offline UCI batch; never applies it."""
import argparse, hashlib, json, re, sys
from pathlib import Path

class RenderError(RuntimeError): pass

UCI_TOKEN=re.compile(r"^[A-Za-z0-9_]+$")
IFACE_TOKEN=re.compile(r"^[-A-Za-z0-9_.:]+$")
MODES={"Multi-AP-Controller-and-Agent","Multi-AP-Agent"}

def require_token(name,value,rx):
    if not isinstance(value,str) or not rx.fullmatch(value):
        raise RenderError(f"unsafe or missing {name}")
    return value

def render(bound,outdir):
    if bound.get("schema")!="rdte-wrt-r3-bound-generation/v1":
        raise RenderError("unexpected bound-generation schema")
    if bound.get("protected_nand_write_authority")!="DENIED":
        raise RenderError("protected NAND deny invariant missing")
    generation=bound.get("generation","")
    if generation not in ("dut-a-gold","dut-b-gold","dut-a-rdte","dut-b-rdte"):
        raise RenderError("unknown generation")
    out=Path(outdir); out.mkdir(parents=True,exist_ok=True)
    batch=out/"config.uci-batch"
    lines=[]
    rdte=generation.endswith("-rdte")
    if rdte:
        em=bound.get("easymesh",{})
        if em.get("enabled") is not True or em.get("management_mode") not in MODES:
            raise RenderError("RDTE generation lacks qualified EasyMesh role")
        mg=bound.get("management",{}); radio=bound.get("radio",{})
        net=require_token("uci network section",mg.get("uci_network_section"),UCI_TOKEN)
        lan=require_token("LAN interface",mg.get("lan_interface"),IFACE_TOKEN)
        rdev=require_token("UCI wireless device section",radio.get("uci_device_section"),UCI_TOKEN)
        riface=require_token("UCI wireless iface section",radio.get("uci_iface_section"),UCI_TOKEN)
        wlan=require_token("radio interface",radio.get("interface"),IFACE_TOKEN)
        mode=em["management_mode"]
        lines=[
          f"set wireless.{rdev}.disabled='0'",
          f"set wireless.{riface}.device='{rdev}'",
          f"set wireless.{riface}.disabled='0'",
          f"set wireless.{riface}.mode='ap'",
          f"set wireless.{riface}.network='{net}'",
          f"set wireless.{riface}.ssid='rdte-hil0'",
          f"set wireless.{riface}.encryption='psk2'",
          f"set wireless.{riface}.key='rdte-hil0-pass'",
          "set prplmesh.config.enabled='1'",
          f"set prplmesh.config.management_mode='{mode}'",
          f"set prplmesh.config.mandatory_interfaces='{wlan}'",
          f"set prplmesh.config.backhaul_wire_iface='{lan}'",
          "set prplmesh.main_24_5.ssid='rdte-hil0'",
          "set prplmesh.main_24_5.key='rdte-hil0-pass'",
          "set prplmesh.main_24_5.encryption='psk2'",
        ]
    text=("\n".join(lines)+"\n") if lines else ""
    batch.write_text(text)
    sha=hashlib.sha256(batch.read_bytes()).hexdigest()
    manifest={
      "schema":"rdte-wrt-r3-rendered-config/v1",
      "generation":generation,
      "asset_id":bound.get("asset_id"),
      "mutation_count":len(lines),
      "uci_batch":"config.uci-batch",
      "uci_batch_sha256":sha,
      "apply_authority":"R3_REQUIRED_NOT_GRANTED_BY_RENDER",
      "write_scope":bound.get("write_scope"),
      "protected_nand_write_authority":"DENIED",
      "service_restart_included":False,
      "flash_or_boot_env_commands_included":False,
    }
    (out/"render-manifest.json").write_text(json.dumps(manifest,indent=2,sort_keys=True)+"\n")
    return manifest

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("bound_generation"); ap.add_argument("output_dir"); a=ap.parse_args()
    try: m=render(json.loads(Path(a.bound_generation).read_text()),a.output_dir)
    except RenderError as e:
        print(str(e),file=sys.stderr); raise SystemExit(2)
    print(json.dumps(m,indent=2,sort_keys=True))

if __name__=="__main__": main()
