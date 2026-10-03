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

def main()->int:
    ap=argparse.ArgumentParser(); ap.add_argument("--elf",required=True); ap.add_argument("--out",required=True)
    ns=ap.parse_args(); elf=Path(ns.elf); out=Path(ns.out); out.mkdir(parents=True,exist_ok=True)
    ins=dp.parse_instructions(dp.run_objdump(elf,0,low_end(elf)))

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
      "interpretation_gate":{
        "accepted_prior":"station record +48 is an encryption-control-slot backpointer; +0x214 slot +8 is encryption mode; +2/+4 are repeatedly reset together as u16+u32",
        "candidate_prior":"+2/+4 match the public W8964 vendor-source legacy TKIP TSC shape (u16 low + u32 high)",
        "promotion_required":"A candidate must show independent read/update/use behavior consistent with sequence-counter semantics and must not be better explained by a generic six-byte field.",
      },
      "guardrail":"This miner reports structural candidates only. It does not promote TSC/PN semantics or hardware ownership."
    }
    (out/"crypto-control-counter-consumers.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps({
      "counts":report["counts"],
      "top_update_like":[{k:v for k,v in r.items() if k in {"base_reg","score","first_pc","last_pc","has_read_write_both","carryish","incrementish","accesses","arithmetic"}} for r in update_like[:12]],
      "station_record_plus48_consumers":backptr_candidates[:12],
    },indent=2,sort_keys=True))
    return 0

if __name__=="__main__":
    raise SystemExit(main())
