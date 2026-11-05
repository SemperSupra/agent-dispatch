#!/usr/bin/env python3
"""Find independent consumers/updaters of the W8964 encryption-control +2/+4 pair.

This is a provenance-oriented candidate miner. It does not promote semantic
names. It searches the complete low executable region for:
  * paired +2 (halfword) and +4 (word) accesses through one base register;
  * load/update/store shapes consistent with a split 48-bit counter;
  * consumers reached through a pointer loaded from object offset +48, the
    independently recovered station-record encryption-control backpointer.

Output is derived text/JSON only.
"""
from __future__ import annotations
import argparse, importlib.util, json, re, struct
from pathlib import Path

P=Path(__file__).with_name("wrt3200acm_dispatch_probe.py")
spec=importlib.util.spec_from_file_location("dp",P)
dp=importlib.util.module_from_spec(spec); assert spec.loader; spec.loader.exec_module(dp)

REG=r"(?:r(?:1[0-2]|[0-9])|sp|lr)"
MEM_RE=re.compile(r"\[\s*("+REG+r")\s*(?:,\s*#(\d+))?\s*\]")
DST_RE=re.compile(r"^\s*("+REG+r")\b")

def low_end(path:Path)->int:
    d=path.read_bytes()
    ph=struct.unpack_from("<I",d,28)[0]; pe=struct.unpack_from("<H",d,42)[0]; pn=struct.unpack_from("<H",d,44)[0]
    ends=[]
    for i in range(pn):
        o=ph+i*pe
        typ,_fo,va,_pa,fs,_ms,_fl,_al=struct.unpack_from("<IIIIIIII",d,o)
        if typ==1 and fs and va<0x1000000: ends.append(va+fs)
    return max(ends)

def mem_refs(ins):
    out=[]
    for m in MEM_RE.finditer(ins["operands"]):
        out.append((m.group(1),int(m.group(2) or "0")))
    return out

def dst(ins):
    mn=ins["mnemonic"]
    if mn.startswith(("str","stm","cmp","cmn","tst","teq","b","push")): return None
    m=DST_RE.match(ins["operands"])
    return m.group(1) if m else None

def is_barrier(ins):
    mn=ins["mnemonic"]; ops=ins["operands"]
    return mn in {"b","bx"} or (mn=="pop" and "pc" in ops) or (mn.startswith("ldm") and "pc" in ops)

def context(ins,idx,radius=14):
    return [x["text"] for x in ins[max(0,idx-radius):min(len(ins),idx+radius+1)]]

RAW_INS_RE=re.compile(r"^\\s*([0-9a-fA-F]+):\\s+([0-9a-fA-F]{8})\\s+([a-zA-Z][a-zA-Z0-9.]*)\\s*(.*?)\\s*$",re.M)

def raw_ins_at(text,address):
    m=re.search(rf"^\\s*0*{address:x}:\\s+[0-9a-fA-F]{{8}}\\s+([a-zA-Z][a-zA-Z0-9.]*)\\s*(.*?)\\s*$",text,re.M|re.I)
    return (m.group(1).lower(),m.group(2).strip().lower()) if m else ("","")

def raw_has(text,address,mnemonic,*operand_tokens):
    mn,ops=raw_ins_at(text,address)
    return mn==mnemonic and all(tok.lower() in ops for tok in operand_tokens)

def main()->int:
    ap=argparse.ArgumentParser(); ap.add_argument("--elf",required=True); ap.add_argument("--out",required=True)
    ns=ap.parse_args(); elf=Path(ns.elf); out=Path(ns.out); out.mkdir(parents=True,exist_ok=True)
    raw=dp.run_objdump(elf,0,low_end(elf))
    ins=dp.parse_instructions(raw)

    # Exact target-firmware closure for the +2/+4 promotion gate.
    #
    # UPDATE_ENCRYPTION SET_KEY writes an evidence-backed +0x214 slot pointer
    # into a key-indexed subrecord at +48/+64.  The TX-side path reaches the
    # same subrecord shape, loads +48, gates on the already accepted mode byte
    # at slot +8, then advances u16 +2 and carries into u32 +4 on wrap.  It
    # exports the advanced low/high pieces to packet-side state at +46/+48.
    counter_contract={
      "set_key_producer_208_subrecord": (
        raw_has(raw,0x291a0,"ldr","r0","r4","520")
        and raw_has(raw,0x291ac,"ldr","r0","r0","#44")
        and raw_has(raw,0x291bc,"add","r1","r0","r5","lsl #2")
      ),
      "set_key_writes_214_pointer_at_key_subrecord_48_64": (
        raw_has(raw,0x291c8,"ldr","r2","r4","532")
        and raw_has(raw,0x291cc,"add","r0","r2","r6","lsl #5")
        and raw_has(raw,0x291d4,"str","r0","r1","#48")
        and raw_has(raw,0x291d8,"str","r0","r1","#64")
      ),
      "tx_side_loads_matching_key_subrecord_48_pointer": (
        raw_has(raw,0x24008,"ldr","r3","r0","#8")
        and raw_has(raw,0x24010,"ldr","r2","r3","#44")
        and raw_has(raw,0x24018,"addge","r1","r2","r1","lsl #2")
        and raw_has(raw,0x24020,"ldrge","r12","r1","#48")
      ),
      "tx_side_mode_gate_selects_non_wep_modes": (
        raw_has(raw,0x24084,"ldrb","r1","r12","#8")
        and raw_has(raw,0x24088,"cmp","r1","#2")
        and raw_has(raw,0x2408c,"bhi","0x240c0")
      ),
      "low16_increment_and_wrap_test": (
        raw_has(raw,0x240c0,"ldrh","r4","r12","#2")
        and raw_has(raw,0x240c4,"add","r1","r12","#2")
        and raw_has(raw,0x240c8,"add","r4","r4","#1")
        and raw_has(raw,0x240cc,"lsl","r4","r4","#16")
        and raw_has(raw,0x240d0,"lsrs","r4","r4","#16")
        and raw_has(raw,0x240d4,"strh","r4","r12","#2")
        and raw_has(raw,0x240d8,"bne","0x240e8")
      ),
      "wrap_carries_into_high32": (
        raw_has(raw,0x240dc,"ldr","r4","r1","#2")
        and raw_has(raw,0x240e0,"add","r4","r4","#1")
        and raw_has(raw,0x240e4,"str","r4","r1","#2")
      ),
      "advanced_counter_exported_to_packet_state": (
        raw_has(raw,0x240e8,"ldrh","r1","r12","#2")
        and raw_has(raw,0x240ec,"strh","r1","r0","#46")
        and raw_has(raw,0x240f0,"ldr","r1","r12","#4")
        and raw_has(raw,0x240f4,"str","r1","r0","#48")
      ),
    }

    # Candidate A: same base register sees both +2 and +4 within a tight region.
    pair_candidates=[]
    seen=set()
    for i,x in enumerate(ins):
        refs=mem_refs(x)
        for base,off in refs:
            if off not in {2,4}: continue
            lo=max(0,i-18); hi=min(len(ins),i+19)
            local=ins[lo:hi]
            same=[]
            for y in local:
                for b,o in mem_refs(y):
                    if b==base and o in {2,4}:
                        kind="write" if y["mnemonic"].startswith("str") else "read" if y["mnemonic"].startswith("ldr") else "other"
                        same.append({"pc":y["address"],"offset":o,"kind":kind,"mnemonic":y["mnemonic"],"text":y["text"]})
            offs={r["offset"] for r in same}
            if offs!={2,4}: continue
            key=(min(r["pc"] for r in same),max(r["pc"] for r in same),base)
            if key in seen: continue
            seen.add(key)
            kinds={(r["offset"],r["kind"]) for r in same}
            arithmetic=[y["text"] for y in local if y["mnemonic"] in {"add","adds","adc","adcs","sub","subs","sbc","sbcs","orr","lsl","lsr","cmp","cmn"}]
            score=0
            if (2,"read") in kinds: score+=1
            if (4,"read") in kinds: score+=1
            if (2,"write") in kinds: score+=2
            if (4,"write") in kinds: score+=2
            if arithmetic: score+=1
            pair_candidates.append({
              "base_reg":base,"score":score,"first_pc":key[0],"last_pc":key[1],
              "accesses":same,"arithmetic":arithmetic[:24],"context":context(ins,i,20)
            })

    # Candidate B: station record +48 pointer provenance into +2/+4/+8.
    backptr_candidates=[]
    for i,x in enumerate(ins):
        if not x["mnemonic"].startswith("ldr"): continue
        refs=mem_refs(x)
        if not any(off==48 for _b,off in refs): continue
        d=dst(x)
        if not d: continue
        uses=[]
        # Keep a bounded straight-line provenance interval. Calls are allowed
        # only for callee-saved registers; direct writes to d kill provenance.
        for j in range(i+1,min(len(ins),i+65)):
            y=ins[j]
            if is_barrier(y): break
            if y["mnemonic"]=="bl" and d in {"r0","r1","r2","r3","r12","lr"}: break
            yd=dst(y)
            if yd==d:
                # Memory loads into another register do not write d; a load with d
                # as destination does and therefore kills the pointer.
                if y["mnemonic"].startswith("ldr") or not y["mnemonic"].startswith("str"):
                    break
            for b,o in mem_refs(y):
                if b==d and o in {0,2,4,8}:
                    uses.append({"pc":y["address"],"offset":o,
                                 "kind":"write" if y["mnemonic"].startswith("str") else "read" if y["mnemonic"].startswith("ldr") else "other",
                                 "text":y["text"]})
        if uses:
            backptr_candidates.append({
              "pointer_load_pc":x["address"],"pointer_load":x["text"],"pointer_reg":d,
              "uses":uses,"context":context(ins,i,24)
            })

    # Candidate C: explicit split-counter update idioms. Score paired regions
    # for add-with-carry / compare-wrap behavior and retain only highest-value.
    update_like=[]
    for rec in pair_candidates:
        kinds={(a["offset"],a["kind"]) for a in rec["accesses"]}
        has_rw=all((o,"read") in kinds and (o,"write") in kinds for o in (2,4))
        carryish=any(re.search(r"\b(adc|adcs|sbc|sbcs)\b",s) for s in rec["arithmetic"])
        incish=any(re.search(r"\b(add|adds)\b.*#1\b",s) for s in rec["arithmetic"])
        if has_rw or carryish or incish:
            update_like.append({**rec,"has_read_write_both":has_rw,"carryish":carryish,"incrementish":incish})

    pair_candidates.sort(key=lambda r:(-r["score"],r["first_pc"]))
    update_like.sort(key=lambda r:(-int(r["has_read_write_both"]),-int(r["carryish"]),-int(r["incrementish"]),-r["score"],r["first_pc"]))

    report={
      "schema":"wrt8964-crypto-control-counter-consumers/v1",
      "firmware_sha256":"ca23f5bb730fde399359a716481651c120e09c299d4e6bbec6fe718c6e87e751",
      "search":{
        "paired_offset_candidates":pair_candidates[:160],
        "station_record_plus48_consumers":backptr_candidates[:160],
        "update_like_candidates":update_like[:100],
      },
      "counts":{
        "paired_offset_candidates":len(pair_candidates),
        "station_record_plus48_consumers":len(backptr_candidates),
        "update_like_candidates":len(update_like),
      },
      "counter_contract":counter_contract,
      "counter_contract_evidence":{f"0x{pc:x}":raw_ins_at(raw,pc) for pc in (
        0x291a0,0x291ac,0x291bc,0x291c8,0x291cc,0x291d4,0x291d8,
        0x24008,0x24010,0x24018,0x24020,0x24084,0x24088,0x2408c,
        0x240c0,0x240c4,0x240c8,0x240cc,0x240d0,0x240d4,0x240d8,
        0x240dc,0x240e0,0x240e4,0x240e8,0x240ec,0x240f0,0x240f4
      )},
      "interpretation_gate":{
        "accepted_prior":"station record +48 is an encryption-control-slot backpointer; +0x214 slot +8 is encryption mode; +2/+4 are repeatedly reset together as u16+u32",
        "candidate_prior":"+2/+4 match the public W8964 vendor-source legacy TKIP TSC shape (u16 low + u32 high)",
        "promotion_required":"A candidate must show independent read/update/use behavior consistent with sequence-counter semantics and must not be better explained by a generic six-byte field.",
        "target_binary_gate_closed":all(counter_contract.values()),
        "qualified_target_behavior":"For accepted non-WEP encryption modes, the +48-linked +0x214 key-control slot advances u16 +2 on transmit preparation, carries into u32 +4 exactly on 16-bit wrap, and exports the advanced 48-bit value to packet-side state.",
      },
      "promotion_assessment":{
        "status":"target-binary-gate-closed" if all(counter_contract.values()) else "blocked",
        "semantic_floor":"48-bit per-key transmit encryption sequence counter" if all(counter_contract.values()) else "strong candidate",
        "source_correlation":"Pinned public W8964 source independently names the matching u16-low/u32-high transmit sequence-counter representation as TSC/TxIV16+TxIV32; use that to name TSC/PN only after this target-binary gate is green.",
        "hardware_ownership":"UNKNOWN",
      },
      "guardrail":"The target-binary contract may promote software-side sequence-counter semantics only. It does not establish a hardware register/descriptor owner."
    }
    (out/"crypto-control-counter-consumers.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps({
      "counts":report["counts"],
      "top_update_like":[{k:v for k,v in r.items() if k in {"base_reg","score","first_pc","last_pc","has_read_write_both","carryish","incrementish","accesses","arithmetic"}} for r in update_like[:12]],
      "station_record_plus48_consumers":backptr_candidates[:12],
      "counter_contract":counter_contract,
      "promotion_assessment":report["promotion_assessment"],
    },indent=2,sort_keys=True))
    return 0 if all(counter_contract.values()) else 3

if __name__=="__main__":
    raise SystemExit(main())
