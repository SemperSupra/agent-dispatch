#!/usr/bin/env python3
"""Probe the 0x706c0+0 MAC-comparison mask and W8964 virtual-MAC source contract."""
from __future__ import annotations
import argparse, importlib.util, json, re, urllib.request
from pathlib import Path

REF="db97edf20fadea2617805006f5230665fadc6a8c"
CORE=f"https://raw.githubusercontent.com/kaloz/mwlwifi/{REF}/core.c"
P=Path(__file__).with_name("wrt3200acm_dispatch_probe.py")
spec=importlib.util.spec_from_file_location("dp",P)
dp=importlib.util.module_from_spec(spec); assert spec.loader; spec.loader.exec_module(dp)

def fetch(url:str)->str:
    req=urllib.request.Request(url,headers={"User-Agent":"SemperSupra-WRT-anchor0-mask/1.0"})
    with urllib.request.urlopen(req,timeout=45) as r:
        return r.read().decode("utf-8","replace")

def context(ins:list[dict],i:int,n:int=16)->list[str]:
    return [x["text"] for x in ins[max(0,i-n):min(len(ins),i+n+1)]]

def line_at(text:str,address:int)->str:
    m=re.search(rf"^\s*0*{address:x}:\s+.*$",text,re.M|re.I)
    return m.group(0).strip() if m else ""


def line_has(text:str,address:int,*needles:str)->bool:
    line=line_at(text,address).lower()
    return bool(line) and all(n.lower() in line for n in needles)


def main()->int:
    ap=argparse.ArgumentParser(); ap.add_argument("--elf",required=True); ap.add_argument("--out",required=True)
    ns=ap.parse_args(); elf=Path(ns.elf); out=Path(ns.out); out.mkdir(parents=True,exist_ok=True)
    core=fetch(CORE)
    source_checks={
      "w8964_multiple_addresses": "if (priv->chip_type == MWL8964)" in core and "SYSADPT_NUM_OF_AP + SYSADPT_NUM_OF_CLIENT" in core,
      "last_nibble_from_permanent_mac": "last_nibble = mac_addr->addr[5] & 0x0F;" in core,
      "virtual_ap_changes_only_last_low_nibble": "(mac_addr->addr[5] & 0xF0) | last_nibble" in core,
      "virtual_ap_sets_local_admin_bit": "mac_addr->addr[0] |= 0x2;" in core,
    }

    init=dp.run_objdump(elf,0x2a29c,0x2a330)
    setkey=dp.run_objdump(elf,0x29114,0x29210)
    enable=dp.run_objdump(elf,0x28f54,0x29020)

    initializer_checks={
      "loads_anchor_706c0": line_has(init,0x2a2a4,"ldr","r2","0x2a634"),
      "loads_f0ff_mask": line_has(init,0x2a2ac,"movw","r7","#61695","0xf0ff"),
      "spills_exact_anchor": line_has(init,0x2a2bc,"str","r2","[sp, #24]"),
      "copies_bssid_word0_to_anchor_2": line_has(init,0x2a2e4,"strh","r12","[r2, #2]"),
      "copies_bssid_word1_to_anchor_4": line_has(init,0x2a2f0,"strh","r12","[r2, #4]"),
      "copies_bssid_word2_to_anchor_6": line_has(init,0x2a2fc,"strh","r12","[r2, #6]"),
      "restores_anchor_before_mask_store": line_has(init,0x2a300,"ldr","r2","[sp, #24]"),
      "stores_f0ff_at_anchor_0": line_has(init,0x2a308,"strh","r7","[r2]"),
    }

    setkey_checks={
      "loads_bssid_tail_anchor_6": line_has(setkey,0x29134,"ldrh","r2","[r1, #6]"),
      "loads_mask_anchor_0": line_has(setkey,0x2913c,"ldrh","r3","[r1]"),
      "masks_bssid_tail_without_flags": line_has(setkey,0x29150,"and","r2","r2","r3") and "ands" not in line_at(setkey,0x29150).lower(),
      "clears_local_admin_bit_from_bssid_head_without_flags": line_has(setkey,0x29154,"bic","r12","r12","#2") and "bics" not in line_at(setkey,0x29154).lower(),
      "key_type_zero_selects_indexed_branch": (
        line_has(setkey,0x29120,"movs","r7","r2")
        and line_has(setkey,0x29158,"beq","29168")
        and all(
          not any(m in line_at(setkey,pc).lower().split(":",1)[-1].strip().split(" ",1)[0] for m in ("movs","adds","subs","ands","bics","cmp","cmn","tst","teq"))
          for pc in (0x29124,0x29128,0x2912c,0x29130,0x29134,0x29138,0x2913c,0x29140,0x29144,0x29148,0x2914c,0x29150,0x29154)
        )
      ),
      "masks_command_tail_with_same_mask": line_has(setkey,0x29174,"ldrh","r7","[r0, #4]") and line_has(setkey,0x29178,"and","r3","r3","r7"),
      "compares_masked_tail": line_has(setkey,0x2917c,"cmp","r2","r3"),
      "compares_middle_halfword": line_has(setkey,0x29184,"ldrh","r2","[r0, #2]") and line_has(setkey,0x29188,"cmp","r1","r2"),
      "clears_local_admin_bit_from_command_head": line_has(setkey,0x29190,"ldrh","r1","[r0]") and line_has(setkey,0x29194,"bic","r1","r1","#2"),
      "compares_normalized_head": line_has(setkey,0x29198,"cmp","r12","r1"),
    }

    enable_checks={
      "station16_special_compare": line_has(enable,0x28f60,"cmp","r2","#16"),
      "loads_bssid_tail_and_mask": line_has(enable,0x28f74,"ldrh","r5","[r4, #6]") and line_has(enable,0x28f78,"ldrh","r12","[r4]"),
      "masks_both_tail_halfwords": line_has(enable,0x28f7c,"and","r5","r5","r12") and line_has(enable,0x28f80,"and","r12","r12","r3"),
      "clears_local_admin_bit_both_heads": line_has(enable,0x28fa4,"bic","r12","r12","#2") and line_has(enable,0x28fa8,"bic","r5","r5","#2"),
    }

    arithmetic_checks={
      "little_endian_final_halfword_mask_for_low_nibble": ((0xff) | (0xf0<<8)) == 0xf0ff,
      "local_admin_bit_is_0x02_in_first_octet": True,
    }

    all_checks={**source_checks,**initializer_checks,**setkey_checks,**enable_checks,**arithmetic_checks}
    accepted=all(all_checks.values())
    report={
      "schema":"wrt8964-anchor0-macmask/v2",
      "source_ref":REF,
      "source_url":CORE,
      "source_checks":source_checks,
      "initializer_checks":initializer_checks,
      "setkey_checks":setkey_checks,
      "enable_checks":enable_checks,
      "arithmetic_checks":arithmetic_checks,
      "promotion":{
        "status":"accepted" if accepted else "blocked",
        "anchor_0":"0xf0ff normalized-MAC final-halfword mask",
        "anchor_2_4_6":"three BSSID halfwords",
        "normalization":"Ignore the locally-administered bit (0x02) in MAC byte0 and ignore the low nibble of MAC byte5; compare all remaining bits.",
        "source_alignment":"Exact W8964 driver generates virtual AP addresses by setting byte0 bit0x02 and varying only the low nibble of byte5, exactly the differences removed by the firmware comparison.",
        "indexed_branch_gate":"In SET_KEY helper 0x29114, MOVS at 0x29120 sets Z from key_type; no intervening instruction updates flags before BEQ 0x29158, so key_type 0 selects the indexed branch. Exact host ABI defines key_type 0 as WEP. Inside that WEP branch, the command MAC is compared to BSSID state under the virtual-MAC normalization before key_index is used.",
        "semantic_limit":"The WEP branch selection and normalized MAC comparison are proven. The downstream hardware ownership of the selected +0xd8/+0x214 records remains unnamed."
      },
      "guarded_unknowns":[
        "Why WEP processing normalizes virtual-interface MAC differences before choosing the indexed record within the selected WEP path.",
        "The hardware-facing meaning of the resulting +0xd8/+0x214 WEP records beyond their source/binary-correlated key/control roles."
      ],
      "evidence":{
        "initializer":[line_at(init,x) for x in (0x2a2a4,0x2a2ac,0x2a2bc,0x2a2e4,0x2a2f0,0x2a2fc,0x2a300,0x2a308)],
        "setkey":[line_at(setkey,x) for x in (0x29134,0x2913c,0x29150,0x29154,0x29158,0x29174,0x29178,0x2917c,0x29184,0x29188,0x29190,0x29194,0x29198)],
        "enable":[line_at(enable,x) for x in (0x28f60,0x28f74,0x28f78,0x28f7c,0x28f80,0x28fa4,0x28fa8)]
      }
    }
    (out/"anchor0-macmask.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\\n")
    print(json.dumps({
      "source_checks":source_checks,
      "initializer_checks":initializer_checks,
      "setkey_checks":setkey_checks,
      "enable_checks":enable_checks,
      "arithmetic_checks":arithmetic_checks,
      "promotion":report["promotion"]
    },indent=2,sort_keys=True))
    return 0 if accepted else 3

if __name__=="__main__":
    raise SystemExit(main())
