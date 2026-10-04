#!/usr/bin/env python3
"""Bounded W8964 spectrum/DFS dispatcher probe.

This probe answers one question: how do exact host commands 0x1128
(SET_SPECTRUM_MGMT) and 0x0120 (802.11H_DETECT_RADAR) appear in the target
firmware dispatcher/control-flow slice?

It deliberately does not fail when a target mapping remains unresolved.
An unresolved or falsified mapping is evidence, not CI infrastructure failure.
Only acquisition/parser/source-contract failures return non-zero.

Output is derived disassembly/control-flow metadata only.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import urllib.request
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
DP_PATH = HERE / "wrt3200acm_dispatch_probe.py"
spec = importlib.util.spec_from_file_location("wrt_dispatch_probe", DP_PATH)
dp = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(dp)

HOSTCMD_URL = "https://raw.githubusercontent.com/kaloz/mwlwifi/db97edf20fadea2617805006f5230665fadc6a8c/hif/hostcmd.h"
FWCMD_URL = "https://raw.githubusercontent.com/kaloz/mwlwifi/db97edf20fadea2617805006f5230665fadc6a8c/hif/fwcmd.c"

TARGETS = {
    0x1128: "HOSTCMD_CMD_SET_SPECTRUM_MGMT",
    0x0120: "HOSTCMD_CMD_802_11H_DETECT_RADAR",
}
CANDIDATE_IMMEDIATES = {
    0x1128: {0x1128, 0x128, 0x28, 0x11},
    0x0120: {0x0120, 0x120, 0x20, 0x12},
}

def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "SemperSupra-WRT-spectrum-dfs/1.0"})
    with urllib.request.urlopen(req, timeout=45) as r:
        return r.read().decode("utf-8", "replace")

def source_contract() -> dict[str, Any]:
    host = fetch(HOSTCMD_URL)
    fw = fetch(FWCMD_URL)
    for value, name in TARGETS.items():
        pat = re.compile(rf"^\s*#define\s+{re.escape(name)}\s+0x{value:04x}\b", re.M | re.I)
        if not pat.search(host):
            raise RuntimeError(f"exact host-source command invariant missing: {name}=0x{value:04x}")
    required = [
        "struct hostcmd_cmd_set_spectrum_mgmt",
        "struct hostcmd_cmd_802_11h_detect_radar",
        "mwl_fwcmd_set_spectrum_mgmt",
        "mwl_fwcmd_set_radar_detect",
    ]
    missing = [x for x in required if x not in host and x not in fw]
    if missing:
        raise RuntimeError("exact host-source contract missing: " + ", ".join(missing))
    return {
        "hostcmd_url": HOSTCMD_URL,
        "fwcmd_url": FWCMD_URL,
        "commands": [{"id": f"0x{k:04x}", "name": v} for k, v in TARGETS.items()],
        "radar_host_fields": [
            "action", "radar_type_code", "min_chirp_cnt", "chirp_time_intvl",
            "pw_filter", "min_num_radar", "pri_min_num"
        ],
        "spectrum_host_fields": ["spectrum_mgmt"],
    }

def imm(op: str) -> int | None:
    m = re.search(r"#(0x[0-9a-fA-F]+|[0-9]+)", op)
    return int(m.group(1), 0) if m else None

def reg_const_before(insns: list[dict[str, Any]], idx: int, reg: str, limit: int = 16) -> int | None:
    for j in range(idx - 1, max(-1, idx - limit - 1), -1):
        x = insns[j]
        dst = x["operands"].split(",", 1)[0].strip().lower()
        if dst != reg:
            continue
        if x["mnemonic"] in {"mov", "movw"}:
            return imm(x["operands"])
        return None
    return None

def branch_after(insns: list[dict[str, Any]], idx: int, limit: int = 4) -> dict[str, Any] | None:
    for j in range(idx + 1, min(len(insns), idx + 1 + limit)):
        x = insns[j]
        if x["mnemonic"] == "beq":
            return {"pc": x["address"], "target": dp.branch_target(x), "text": x["text"]}
        if x["mnemonic"].startswith("b") and x["mnemonic"] != "beq":
            break
    return None

def window(insns: list[dict[str, Any]], idx: int, before: int = 8, after: int = 5) -> list[str]:
    lo = max(0, idx - before)
    hi = min(len(insns), idx + after + 1)
    return [x["text"] for x in insns[lo:hi]]

def targeted_candidates(insns: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for i, x in enumerate(insns):
        ops = x["operands"].lower()
        if x["mnemonic"] not in {"cmp", "cmn", "sub", "subs", "subw", "add", "adds", "addw"}:
            continue
        if "r12" not in ops:
            continue
        val = imm(ops)
        regs = re.findall(r"\b(r(?:1[0-2]|[0-9])|lr|ip)\b", ops)
        loaded = None
        if val is None:
            for reg in regs:
                if reg != "r12":
                    loaded = reg_const_before(insns, i, reg)
                    if loaded is not None:
                        val = loaded
                        break
        if val is None:
            continue
        hits = []
        for cmd, vals in CANDIDATE_IMMEDIATES.items():
            if val in vals:
                hits.append(cmd)
        if not hits:
            continue
        out.append({
            "pc": x["address"],
            "text": x["text"],
            "immediate_or_loaded_constant": val,
            "candidate_commands": [f"0x{c:04x}" for c in hits],
            "following_beq": branch_after(insns, i),
            "context": window(insns, i),
        })
    return out

def affine_fallthrough_candidates(insns: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Conservative linear-fallthrough tracker for r12 = input + offset.

    The dispatcher is a comparison chain; this model is intentionally not a
    proof across joins. It is only a candidate generator. Exact promotion still
    requires a bounded control-flow/data-flow follow-up.
    """
    offset: int | None = 0
    consts: dict[str, int] = {}
    out = []
    for i, x in enumerate(insns):
        m = x["mnemonic"]
        ops = [p.strip().lower() for p in x["operands"].split(",")]
        if not ops:
            continue
        dst = ops[0]
        if m in {"mov", "movw"} and re.fullmatch(r"r(?:1[0-2]|[0-9])|lr|ip", dst):
            v = imm(x["operands"])
            if v is not None:
                consts[dst] = v
            else:
                consts.pop(dst, None)
        elif dst == "r12" and m in {"sub", "subs", "subw", "add", "adds", "addw"} and len(ops) >= 3 and ops[1] == "r12":
            v = imm(x["operands"])
            if v is None and len(ops) >= 3:
                v = consts.get(ops[2])
            if v is None or offset is None:
                offset = None
            elif m.startswith("sub"):
                offset -= v
            else:
                offset += v
        elif dst == "r12" and m not in {"cmp", "cmn"} and m.startswith(("mov", "ldr", "and", "eor", "orr", "bic", "ubfx", "uxt", "lsl", "lsr", "asr")):
            offset = None

        if m in {"cmp", "cmn"} and "r12" in x["operands"].lower() and offset is not None:
            v = imm(x["operands"])
            if v is None:
                regs = re.findall(r"\b(r(?:1[0-2]|[0-9])|lr|ip)\b", x["operands"].lower())
                for reg in regs:
                    if reg != "r12" and reg in consts:
                        v = consts[reg]
                        break
            if v is None:
                continue
            original = v - offset
            if original in TARGETS:
                out.append({
                    "command": TARGETS[original],
                    "command_id": f"0x{original:04x}",
                    "pc": x["address"],
                    "comparison": x["text"],
                    "tracked_r12_offset": offset,
                    "comparison_value": v,
                    "following_beq": branch_after(insns, i),
                    "context": window(insns, i, 10, 6),
                    "confidence": "candidate-only-linear-fallthrough",
                })
    return out

def r12_control_slice(insns: list[dict[str, Any]]) -> list[dict[str, Any]]:
    selected = []
    for i, x in enumerate(insns):
        if "r12" not in x["operands"].lower():
            continue
        if x["mnemonic"] not in {
            "cmp", "cmn", "sub", "subs", "subw", "add", "adds", "addw",
            "and", "ands", "eor", "orr", "bic", "ubfx", "uxtb", "uxth",
            "lsl", "lsr", "asr", "mov", "movw", "movt"
        }:
            continue
        selected.append({
            "pc": x["address"],
            "text": x["text"],
            "following_beq": branch_after(insns, i),
        })
    return selected

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--elf", required=True)
    ap.add_argument("--out", required=True)
    ns = ap.parse_args()
    out = Path(ns.out)
    out.mkdir(parents=True, exist_ok=True)

    src = source_contract()
    dis = dp.run_objdump(Path(ns.elf), dp.DISPATCH_START, dp.DISPATCH_END)
    insns = dp.parse_instructions(dis)
    direct = dp.recover_cases(insns, TARGETS)
    targeted = targeted_candidates(insns)
    affine = affine_fallthrough_candidates(insns)
    r12slice = r12_control_slice(insns)

    per_target = {}
    for cmd, name in TARGETS.items():
        direct_hits = [x for x in direct if x["value"] == cmd]
        affine_hits = [x for x in affine if x["command_id"] == f"0x{cmd:04x}"]
        targeted_hits = [x for x in targeted if f"0x{cmd:04x}" in x["candidate_commands"]]
        status = "direct-mapped" if direct_hits else ("affine-candidate" if affine_hits else ("literal-candidate" if targeted_hits else "unresolved"))
        per_target[f"0x{cmd:04x}"] = {
            "name": name,
            "status": status,
            "direct_hits": direct_hits,
            "affine_candidates": affine_hits,
            "literal_candidates": targeted_hits,
        }

    report = {
        "schema": "wrt8964-spectrum-dfs-dispatch-probe/v1",
        "firmware_semantic_scope": "dispatcher/control-flow only",
        "source_contract": src,
        "dispatcher": {"start": dp.DISPATCH_START, "end": dp.DISPATCH_END, "instruction_count": len(insns)},
        "targets": per_target,
        "r12_control_slice": r12slice,
        "interpretation": {
            "richer_telemetry": "UNKNOWN",
            "hardware_or_event_boundary": "UNKNOWN",
            "note": "This first bounded wave localizes dispatcher paths. Handler/callee semantics require a follow-up only if this evidence yields concrete targets."
        },
        "guardrails": [
            "No target semantic is promoted from source naming alone.",
            "Affine/literal hits are candidate generators, not proof across control-flow joins.",
            "Unresolved mapping is a valid result and does not fail CI."
        ]
    }
    (out / "spectrum-dfs-dispatch.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    (out / "spectrum-dfs-r12-slice.txt").write_text("\n".join(x["text"] for x in r12slice) + "\n")
    print(json.dumps({
        "targets": {k: v["status"] for k, v in per_target.items()},
        "r12_control_instructions": len(r12slice),
        "direct_hits": len(direct),
        "affine_hits": len(affine),
        "literal_hits": len(targeted),
    }, indent=2, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
