#!/usr/bin/env python3
"""Recover the SET_NEW_STN create/add/modify producer path without naming unknown objects."""
from __future__ import annotations
import argparse, importlib.util, json, re, struct, urllib.request
from collections import defaultdict, deque
from pathlib import Path

P=Path(__file__).with_name("wrt3200acm_dispatch_probe.py")
spec=importlib.util.spec_from_file_location("dp",P)
dp=importlib.util.module_from_spec(spec); assert spec.loader; spec.loader.exec_module(dp)

FW_SHA256="ca23f5bb730fde399359a716481651c120e09c299d4e6bbec6fe718c6e87e751"
HOST_REF="db97edf20fadea2617805006f5230665fadc6a8c"
HOSTCMD_URL=f"https://raw.githubusercontent.com/kaloz/mwlwifi/{HOST_REF}/hif/hostcmd.h"
FWCMD_URL=f"https://raw.githubusercontent.com/kaloz/mwlwifi/{HOST_REF}/hif/fwcmd.c"
WRAPPER=0x37b94
DESCRIPTOR_LITERAL=0x38398
LOOKUP_A=0x3fb34
LOOKUP_B=0x3fbe4
INSERT=0x3fc94
REMOVE=0x3fd34

def fetch_text(url:str)->str:
    req=urllib.request.Request(url,headers={"User-Agent":"SemperSupra-WRT-set-new-stn/1.0"})
    with urllib.request.urlopen(req,timeout=45) as r:
        return r.read().decode("utf-8","replace")

def excerpt(src:str, needle:str, radius:int=35)->dict:
    lines=src.splitlines()
    hits=[i for i,x in enumerate(lines) if needle.lower() in x.lower()]
    if not hits:
        return {"needle":needle,"found":False,"lines":[]}
    i=hits[0]
    a=max(0,i-radius); b=min(len(lines),i+radius+1)
    return {"needle":needle,"found":True,"start_line":a+1,"end_line":b,
            "lines":[f"{n+1}: {lines[n]}" for n in range(a,b)]}

def elf_low_end(path:Path)->int:
    d=path.read_bytes(); ph=struct.unpack_from("<I",d,28)[0]; pe=struct.unpack_from("<H",d,42)[0]; pn=struct.unpack_from("<H",d,44)[0]
    ends=[]
    for i in range(pn):
        o=ph+i*pe
        typ,_fo,va,_pa,fs,_ms,_fl,_al=struct.unpack_from("<IIIIIIII",d,o)
        if typ==1 and fs and va<0x1000000: ends.append(va+fs)
    return max(ends)

def read_u32(path:Path,address:int)->int:
    d=path.read_bytes(); ph=struct.unpack_from("<I",d,28)[0]; pe=struct.unpack_from("<H",d,42)[0]; pn=struct.unpack_from("<H",d,44)[0]
    for i in range(pn):
        o=ph+i*pe
        typ,fo,va,_pa,fs,_ms,_fl,_al=struct.unpack_from("<IIIIIIII",d,o)
        if typ==1 and va<=address and address+4<=va+fs:
            return struct.unpack_from("<I",d,fo+address-va)[0]
    raise ValueError(hex(address))

def ctxt(ins:list[dict], idx:int, before:int=14, after:int=8)->list[str]:
    return [x["text"] for x in ins[max(0,idx-before):min(len(ins),idx+after+1)]]

def imm_mov_to_r0(x:dict)->int|None:
    if x["mnemonic"] not in {"mov","movw"}: return None
    m=re.fullmatch(r"r0, #(0x[0-9a-fA-F]+|[0-9]+).*",x["operands"])
    return int(m.group(1),0) if m else None

def branch_edges(ins:list[dict])->list[tuple[int,int]]:
    out=[]
    for x in ins:
        if x["mnemonic"]=="bl":
            t=dp.branch_target(x)
            if t is not None: out.append((x["address"],t))
    return out

def main()->int:
    ap=argparse.ArgumentParser(); ap.add_argument("--elf",required=True); ap.add_argument("--out",required=True)
    ns=ap.parse_args(); elf=Path(ns.elf); out=Path(ns.out); out.mkdir(parents=True,exist_ok=True)
    low_end=elf_low_end(elf)
    whole=dp.parse_instructions(dp.run_objdump(elf,0,low_end))
    by_pc={x["address"]:i for i,x in enumerate(whole)}

    wrapper=dp.parse_instructions(dp.run_objdump(elf,WRAPPER,0x37c10))
    wrapper_text="\n".join(x["text"] for x in wrapper)
    wrapper_checks={
      "action_u16_at_cmd_18_19": all(s in wrapper_text for s in ("37b94: ldrb r0, [r4, #19]","37b98: ldrb r1, [r4, #18]","37ba0: cmp r0, #2")),
      "non_remove_generic_helper": all(s in wrapper_text for s in ("37ba8: mov r1, r4","37bac: ldr r0, [pc, #2020]","37bb0: bl 0x21c68")),
      "remove_mac_plus_10": all(s in wrapper_text for s in ("37bc8:","r4, #10","37bcc: mov r0, #1","37bd0: bl 0x3fb34")),
    }

    descriptor=read_u32(elf,DESCRIPTOR_LITERAL)
    descriptor_exec=0 <= descriptor < low_end
    handler_probe=dp.parse_instructions(dp.run_objdump(elf,descriptor,min(descriptor+0x1800,low_end))) if descriptor_exec else []
    handler_calls=[{"pc":x["address"],"target":dp.branch_target(x),"text":x["text"]} for x in handler_probe if x["mnemonic"]=="bl" and dp.branch_target(x) is not None]

    edges=branch_edges(whole)
    direct_targets=sorted({t for _,t in edges if 0<=t<low_end} | {descriptor})
    def nearest_start(pc:int)->int|None:
        candidates=[x for x in direct_targets if x<=pc]
        if not candidates: return None
        s=candidates[-1]
        return s if pc-s <= 0x1800 else None

    target_xrefs=defaultdict(list)
    for x in whole:
        if x["mnemonic"]!="bl": continue
        t=dp.branch_target(x)
        if t in {LOOKUP_A,LOOKUP_B,INSERT,REMOVE}:
            i=by_pc[x["address"]]
            target_xrefs[t].append({"pc":x["address"],"text":x["text"],"context":ctxt(whole,i,18,10)})

    insert_candidates=[]
    for rec in target_xrefs[INSERT]:
        i=by_pc[rec["pc"]]
        pre=whole[max(0,i-12):i]
        disc=None
        for x in reversed(pre):
            v=imm_mov_to_r0(x)
            if v is not None:
                disc=v; break
        prior_lookup_b=[x for x in pre if x["mnemonic"]=="bl" and dp.branch_target(x)==LOOKUP_B]
        same_ptr_pattern=any(re.search(r"mov\s+r1, r2",x["text"]) for x in pre) and any(re.search(r"mov\s+r2, r[0-9]+",x["text"]) for x in pre)
        fs=nearest_start(rec["pc"])
        insert_candidates.append({
          "pc":rec["pc"],"discriminator":disc,"prior_lookup_b":bool(prior_lookup_b),
          "same_pointer_marshalling_pattern":same_ptr_pattern,"function_start":fs,
          "context":ctxt(whole,i,28,28)
        })

    disc1=[x for x in insert_candidates if x["discriminator"]==1 and x["prior_lookup_b"]]
    candidate_starts=sorted({x["function_start"] for x in disc1 if x["function_start"] is not None})

    callers=defaultdict(list)
    for pc,t in edges:
        if t in candidate_starts:
            i=by_pc.get(pc)
            callers[t].append({"pc":pc,"caller_start":nearest_start(pc),"context":ctxt(whole,i,12,5) if i is not None else []})

    # Build a conservative direct-call graph using nearest direct-call targets as candidate function starts.
    graph=defaultdict(set)
    for pc,t in edges:
        s=nearest_start(pc)
        if s is not None and t in direct_targets:
            graph[s].add(t)
    paths=[]
    for goal in candidate_starts:
        q=deque([(descriptor,[descriptor])]); seen={descriptor}
        while q:
            node,path=q.popleft()
            if node==goal:
                paths.append(path); break
            if len(path)>=6: continue
            for nxt in sorted(graph.get(node,())):
                if nxt not in seen:
                    seen.add(nxt); q.append((nxt,path+[nxt]))

    candidate_regions={}
    for s in candidate_starts:
        e=min(s+0x1200,low_end)
        region=dp.parse_instructions(dp.run_objdump(elf,s,e))
        field_refs={}
        for off in (0xd8,0x208,0x214,0x21c):
            hits=[x["text"] for x in region if f"@ 0x{off:x}" in x["text"].lower() or f"#{off}" in x["operands"]]
            field_refs[f"+0x{off:x}"]=hits[:80]
        candidate_regions[f"0x{s:x}"]={
          "field_refs":field_refs,
          "insert_sites":[f"0x{x['pc']:x}" for x in disc1 if x["function_start"]==s],
          "callers":callers[s],
          "first_instructions":[x["text"] for x in region[:220]],
        }

    producer_call_pc=0x35528
    producer_call_context=ctxt(whole,by_pc[producer_call_pc],80,10) if producer_call_pc in by_pc else []
    insert_region=dp.parse_instructions(dp.run_objdump(elf,INSERT,REMOVE))
    insert_text="\n".join(x["text"] for x in insert_region)
    insert_contract={
      "copies_key_6_bytes_from_r1": all(s in insert_text for s in (
        "3fcb4: ldrh r4, [r1]","3fcbc: strh r4, [r0, #8]",
        "3fcc0: ldrh r4, [r1, #2]","3fcc4: strh r4, [r0, #10]",
        "3fcc8: ldrh r4, [r1, #4]","3fccc: strh r4, [r0, #12]")),
      "stores_discriminator_at_node_14":"3fcd0: strb r12, [r0, #14]" in insert_text,
      "stores_payload_r2_at_node_4":"3fcd4: str r2, [r0, #4]" in insert_text,
      "links_node_into_anchor_4c": all(s in insert_text for s in (
        "3fd14: ldr r2, [r3, #76]","3fd20: str r2, [r0]","3fd28: str r0, [r2, r1, lsl #2]")),
    }

    lookup_a_consumers=[]
    for rec in target_xrefs[LOOKUP_A]:
        if rec["pc"] in {0x29028,0x290b8,0x293a0}:
            i=by_pc[rec["pc"]]
            lookup_a_consumers.append({"pc":rec["pc"],"context":ctxt(whole,i,16,28)})

    hostcmd=fetch_text(HOSTCMD_URL); fwcmd=fetch_text(FWCMD_URL)
    source={
      "hostcmd_h":excerpt(hostcmd,"struct hostcmd_cmd_set_new_stn",45),
      "fwcmd_add":excerpt(fwcmd,"int mwl_fwcmd_set_new_stn_add(",95),
      "fwcmd_del":excerpt(fwcmd,"int mwl_fwcmd_set_new_stn_del(",55),
      "ref":HOST_REF,
      "urls":[HOSTCMD_URL,FWCMD_URL],
    }

    report={
      "schema":"wrt8964-set-new-stn-producer/v1",
      "firmware_sha256":FW_SHA256,
      "wrapper":{"address":WRAPPER,"checks":wrapper_checks,"instructions":[x["text"] for x in wrapper]},
      "descriptor":{"literal_address":DESCRIPTOR_LITERAL,"value":descriptor,"executable":descriptor_exec,
                    "handler_probe_calls":handler_calls[:240],"handler_probe_first":[x["text"] for x in handler_probe[:500]]},
      "hash_primitives":{"lookup_a":LOOKUP_A,"lookup_b":LOOKUP_B,"insert":INSERT,"remove":REMOVE},
      "insert_candidates":insert_candidates,
      "discriminator1_lookup_before_insert_candidates":disc1,
      "candidate_function_starts":candidate_starts,
      "direct_call_paths_from_descriptor_target":paths,
      "candidate_regions":candidate_regions,
      "producer_call":{"pc":producer_call_pc,"context":producer_call_context},
      "insert_contract":{"address":INSERT,"checks":insert_contract,"instructions":[x["text"] for x in insert_region]},
      "update_encryption_lookup_consumers":lookup_a_consumers,
      "source_contract":source,
      "guardrail":"The node+4 payload may be promoted as the exact object constructed by the SET_NEW_STN producer only when the insertion store, producer argument provenance, exact-source MAC field, and UPDATE_ENCRYPTION lookup consumer all agree. Semantic object naming remains gated on field-level role evidence."
    }
    (out/"set-new-stn-producer.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps({
      "wrapper_checks":wrapper_checks,
      "descriptor":hex(descriptor),
      "descriptor_exec":descriptor_exec,
      "descriptor_calls":[{"pc":hex(x["pc"]),"target":hex(x["target"]),"text":x["text"]} for x in handler_calls[:100]],
      "disc1_candidates":[{
        "pc":hex(x["pc"]),"function_start":hex(x["function_start"]) if x["function_start"] is not None else None,
        "prior_lookup_b":x["prior_lookup_b"],"same_pointer_marshalling_pattern":x["same_pointer_marshalling_pattern"],
        "context":x["context"]
      } for x in disc1],
      "paths":[[hex(y) for y in x] for x in paths],
      "candidate_regions":candidate_regions,
      "producer_call_context":producer_call_context,
      "insert_contract":insert_contract,
      "insert_region":[x["text"] for x in insert_region],
      "update_encryption_lookup_consumers":lookup_a_consumers,
      "source_found":{"hostcmd_h":source["hostcmd_h"]["found"],"fwcmd_add":source["fwcmd_add"]["found"],"fwcmd_del":source["fwcmd_del"]["found"]},
    },indent=2,sort_keys=True))
    ok=all(wrapper_checks.values()) and descriptor_exec and bool(disc1) and all(insert_contract.values()) and source["hostcmd_h"]["found"] and source["fwcmd_add"]["found"] and source["fwcmd_del"]["found"]
    return 0 if ok else 3

if __name__=="__main__":
    raise SystemExit(main())
