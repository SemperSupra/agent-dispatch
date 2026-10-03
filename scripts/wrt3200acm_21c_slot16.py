#!/usr/bin/env python3
"""Resolve the 17th 0x706c0+0x21c stride and station-record +80 relationship."""
from __future__ import annotations

import argparse
import importlib.util
import json
import urllib.request
from pathlib import Path

REF = "db97edf20fadea2617805006f5230665fadc6a8c"
BASE = f"https://raw.githubusercontent.com/kaloz/mwlwifi/{REF}"
URLS = {
    "core": f"{BASE}/core.c",
    "mac80211": f"{BASE}/mac80211.c",
    "fwcmd": f"{BASE}/hif/fwcmd.c",
}

P = Path(__file__).with_name("wrt3200acm_dispatch_probe.py")
spec = importlib.util.spec_from_file_location("dp", P)
dp = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(dp)


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "SemperSupra-WRT-21c-slot16/1.0"})
    with urllib.request.urlopen(req, timeout=45) as r:
        return r.read().decode("utf-8", "replace")


def function_slice(src: str, signature: str) -> str:
    start = src.find(signature)
    if start < 0:
        return ""
    candidates = []
    for marker in ("\nint ", "\nstatic int ", "\nstatic void ", "\nvoid "):
        pos = src.find(marker, start + len(signature))
        if pos >= 0:
            candidates.append(pos)
    end = min(candidates) if candidates else len(src)
    return src[start:end]


def text_range(elf: Path, lo: int, hi: int) -> str:
    return dp.run_objdump(elf, lo, hi)


def has_all(text: str, needles: tuple[str, ...]) -> bool:
    return all(n in text for n in needles)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--elf", required=True)
    ap.add_argument("--out", required=True)
    ns = ap.parse_args()
    elf = Path(ns.elf)
    out = Path(ns.out)
    out.mkdir(parents=True, exist_ok=True)

    core = fetch(URLS["core"])
    mac = fetch(URLS["mac80211"])
    fw = fetch(URLS["fwcmd"])

    add_if = function_slice(mac, "static int mwl_mac80211_add_interface(")
    sta_add = function_slice(mac, "static int mwl_mac80211_sta_add(")
    sc4 = function_slice(fw, "int mwl_fwcmd_set_new_stn_add_sc4(")

    init = text_range(elf, 0x227d8, 0x22808)
    ap_writer = text_range(elf, 0x2a23c, 0x2a29c)
    set_new_stn = text_range(elf, 0x354c8, 0x35534)
    producer = text_range(elf, 0x295c0, 0x29734)

    source_checks = {
        "ap_macid_mask_0_15": "priv->ap_macids_supported = 0x0000ffff;" in core,
        "sta_macid_mask_bit16_only": "priv->sta_macids_supported = 0x00010000;" in core,
        "station_interface_selects_sta_mask": has_all(add_if, (
            "case NL80211_IFTYPE_STATION:",
            "macids_supported = priv->sta_macids_supported;",
        )),
        "allocator_uses_ffs_then_minus_one": has_all(add_if, (
            "macid = ffs(macids_supported & ~priv->macids_used);",
            "macid--;",
            "mwl_vif->macid = macid;",
        )),
        "w8964_sta_add_uses_sc4": has_all(sta_add, (
            "if (priv->chip_type == MWL8964)",
            "mwl_fwcmd_set_new_stn_add_sc4(hw, vif, sta, 0);",
        )),
        "sc4_command_carries_vif_macid": "pcmd->cmd_hdr.macid = mwl_vif->macid;" in sc4,
        "sc4_station_mode_executes_set_new_stn": has_all(sc4, (
            "if (vif->type == NL80211_IFTYPE_STATION)",
            "mwl_hif_exec_cmd(hw, HOSTCMD_CMD_SET_NEW_STN)",
        )),
    }

    binary_checks = {
        "allocates_1088_bytes": "227ec: mov r0, #1088" in init,
        "stores_allocation_at_anchor_21c": "227f8: str r0, [r4, #540]" in init,
        "ap_writer_rejects_macid_16_plus": has_all(ap_writer, (
            "2a240: cmp r0, #16",
            "2a24c: bcs 0x2a298",
        )),
        "ap_writer_indexes_21c_by_64_macid": has_all(ap_writer, (
            "2a244: ldr r3, [r2, #540]",
            "2a248:",
            "lsl #6",
        )),
        "set_new_stn_reads_cmd_header_macid": "354d4: ldrb r2, [r4, #5]" in set_new_stn,
        "set_new_stn_marshals_macid_to_producer_stack": "354e4: str r2, [sp, #12]" in set_new_stn,
        "producer_recovers_marshaled_macid": "295dc: ldr r10, [sp, #132]" in producer,
        "producer_indexes_21c_by_64_macid": has_all(producer, (
            "296b8: ldr r1, [r6, #540]",
            "296bc:",
            "r10, lsl #6",
        )),
        "producer_stores_21c_entry_at_record_80": "296c0: str r1, [r4, #80]" in producer,
    }

    ap_slots = 16
    sta_macid = 16
    allocated_bytes = 1088
    stride = 64
    slots = allocated_bytes // stride

    arithmetic_checks = {
        "allocated_slots_are_17": slots == 17,
        "ap_namespace_is_0_15": ap_slots == 16,
        "station_mask_resolves_to_macid_16": sta_macid == 16,
        "slot16_is_within_allocation": sta_macid < slots,
        "slot16_offset_is_0x400": sta_macid * stride == 0x400,
        "allocation_covers_slot16": (sta_macid + 1) * stride == allocated_bytes,
    }

    all_checks = {**source_checks, **binary_checks, **arithmetic_checks}
    accepted = all(all_checks.values())

    report = {
        "schema": "wrt8964-runtime-21c-slot16/v1",
        "source_ref": REF,
        "source_urls": URLS,
        "source_checks": source_checks,
        "binary_checks": binary_checks,
        "arithmetic_checks": arithmetic_checks,
        "derived": {
            "allocation_bytes": allocated_bytes,
            "stride_bytes": stride,
            "slot_count": slots,
            "ap_macids": "0..15",
            "station_macid": sta_macid,
            "slot16_offset": sta_macid * stride,
        },
        "promotion": {
            "status": "accepted" if accepted else "blocked",
            "claim": (
                "The 17th 64-byte stride at 0x706c0+0x21c exists to cover the W8964 MACID namespace through MACID 16. "
                "Exact host source reserves MACIDs 0..15 for AP/mesh and bit 16 for station interfaces; the W8964 station-add path uses SET_NEW_STN_SC4 with cmd_hdr.macid=mwl_vif->macid. "
                "Firmware SET_NEW_STN reads cmd_hdr.macid and its producer indexes +0x21c by 64*macid, storing that entry pointer at the per-station record +80. "
                "The AP_BEACON BSSID writer separately rejects macid>=16, explaining why only slots 0..15 receive that AP-BSSID write while slot 16 remains available to station-mode SET_NEW_STN state."
            ),
            "semantic_limit": (
                "This resolves allocation/reachability and the station-record +80 relationship. "
                "It does not assert that slot 16 contains an AP BSSID or assign names to other bytes in the 64-byte record."
            ),
        },
        "evidence": {
            "initializer": init.splitlines(),
            "ap_writer": ap_writer.splitlines(),
            "set_new_stn_macid_marshalling": set_new_stn.splitlines(),
            "producer_21c_link": producer.splitlines(),
        },
    }

    (out / "runtime-21c-slot16.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n"
    )
    print(json.dumps({
        "source_checks": source_checks,
        "binary_checks": binary_checks,
        "arithmetic_checks": arithmetic_checks,
        "promotion": report["promotion"],
    }, indent=2, sort_keys=True))
    return 0 if accepted else 3


if __name__ == "__main__":
    raise SystemExit(main())
