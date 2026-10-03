#!/usr/bin/env python3
"""E2-D16: resolve _svctl_read across one call/return boundary.

D15 refined the unresolved path after the selected libc read GOT load to a
terminal_or_call transfer. D16 treats t9 as caller-saved and therefore dead
across a call unless either:
  1) the selected read target is freshly reloaded into t9 after return; or
  2) a directly resolved bounded callee is proven to contain no t9 writes and
     no nested calls before returning.

The reducer follows only the post-return fallthrough until the next control
transfer. No instruction addresses, disassembly, GOT offsets, or proprietary
bytes are emitted.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib
import re
import shutil
import subprocess

_D15_PATH = pathlib.Path(__file__).with_name("fritz_qemu_e2_d15_libsvctl_successor_liveness.py")
_SPEC = importlib.util.spec_from_file_location("fritz_qemu_e2_d15_libsvctl_successor_liveness", _D15_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError("unable to load D15")
d15 = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(d15)
d14 = d15.d14
d13 = d15.d13
base = d15.base

SCHEMA_VERSION = 1
EXPERIMENT = "fritz-qemu-e2-d16-libsvctl-call-return/v1"
LIB = d15.LIB
FUNCTION = "_svctl_read"
TARGET = "read"

_SAFE_SYMBOL_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.$@+-]{0,95}$")
_ANGLE_SYMBOL_RE = re.compile(r"<(?P<sym>[A-Za-z_][A-Za-z0-9_.$@+-]*)(?:\+0x[0-9a-fA-F]+)?>")


def transfer_class(asm: str) -> str | None:
    mnemonic, _ = d14._parts(asm)
    if mnemonic in {"jal", "bal"}:
        return "direct_call"
    if mnemonic == "jalr":
        return "indirect_call"
    if mnemonic == "jr":
        return "return_or_indirect_jump"
    if mnemonic in {"j", "b"}:
        return "direct_jump"
    if mnemonic.startswith("b") and mnemonic != "break":
        return "conditional_branch"
    return None


def safe_target_symbol(asm: str) -> str | None:
    m = _ANGLE_SYMBOL_RE.search(asm)
    if not m:
        return None
    sym = m.group("sym")
    return sym if _SAFE_SYMBOL_RE.fullmatch(sym) else None


def is_call_asm(asm: str) -> bool:
    mnemonic, _ = d14._parts(asm)
    return mnemonic in {"jal", "jalr", "bal"}


def is_return_asm(asm: str) -> bool:
    mnemonic, operands = d14._parts(asm)
    return mnemonic == "jr" and bool(operands) and d14._reg(operands[0]) in {"ra", "31"}


def callee_static_summary(path: pathlib.Path, objdump: str, symbol: str) -> dict:
    cp = subprocess.run(
        [objdump, "-dr", f"--disassemble={symbol}", str(path)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if cp.returncode:
        return {
            "symbol": symbol,
            "disassemblyAvailable": False,
            "t9WriteCount": 0,
            "nestedCallCount": 0,
            "returnCount": 0,
            "t9PreservationProven": False,
        }

    ins = d13.asm_instructions(cp.stdout)
    t9_writes = sum(1 for a in ins if d14.writes_t9(a))
    nested_calls = sum(1 for a in ins if is_call_asm(a))
    returns = sum(1 for a in ins if is_return_asm(a))
    preserved = bool(ins) and t9_writes == 0 and nested_calls == 0 and returns > 0
    return {
        "symbol": symbol,
        "disassemblyAvailable": bool(ins),
        "t9WriteCount": t9_writes,
        "nestedCallCount": nested_calls,
        "returnCount": returns,
        "t9PreservationProven": preserved,
    }


def post_return_path(records: list[dict], start_index: int, got: dict[int, str], initial_target_live: bool) -> dict:
    live = initial_target_live
    reloads = 0

    for rec in records[start_index:]:
        asm = rec["asm"]
        load = d13.got_load(asm)
        if load:
            reg, off = load
            if reg in {"t9", "25"} and got.get(off) == TARGET:
                live = True
                reloads += 1
                continue

        if d13.is_jalr_t9(asm):
            return {
                "accepted": live,
                "reason": "post_return_target_live_to_jalr" if live else "post_return_jalr_without_live_read_target",
                "freshReadReloadCount": reloads,
            }

        if d14.writes_t9(asm):
            live = False

        if d14.control_transfer(asm):
            return {
                "accepted": False,
                "reason": "next_control_transfer_before_read_jalr",
                "freshReadReloadCount": reloads,
            }

    return {
        "accepted": False,
        "reason": "function_ended_before_read_jalr",
        "freshReadReloadCount": reloads,
    }


def analyze_read_call_boundary(path: pathlib.Path, objdump: str, got: dict[int, str]) -> dict:
    cp = subprocess.run(
        [objdump, "-dr", f"--disassemble={FUNCTION}", str(path)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if cp.returncode:
        raise RuntimeError("objdump failed for _svctl_read")

    records = d15.instruction_records(cp.stdout)
    selected_loads = 0

    for load_index, rec in enumerate(records):
        load = d13.got_load(rec["asm"])
        if not load:
            continue
        reg, off = load
        if reg not in {"t9", "25"} or got.get(off) != TARGET:
            continue
        selected_loads += 1

        for i in range(load_index + 1, len(records)):
            asm = records[i]["asm"]

            if d13.is_jalr_t9(asm):
                return {
                    "symbol": FUNCTION,
                    "selectedReadGotLoadCount": selected_loads,
                    "firstTransferClass": "target_jalr",
                    "firstTransferTargetSymbol": None,
                    "delaySlotT9Clobber": False,
                    "callee": None,
                    "postReturn": {
                        "accepted": True,
                        "reason": "same_block_target_live_to_jalr",
                        "freshReadReloadCount": 0,
                    },
                    "acceptedReadCallEdge": True,
                }

            if d14.writes_t9(asm):
                return {
                    "symbol": FUNCTION,
                    "selectedReadGotLoadCount": selected_loads,
                    "firstTransferClass": "pre_transfer_t9_clobber",
                    "firstTransferTargetSymbol": None,
                    "delaySlotT9Clobber": False,
                    "callee": None,
                    "postReturn": None,
                    "acceptedReadCallEdge": False,
                }

            if not d14.control_transfer(asm):
                continue

            tclass = transfer_class(asm) or "unsupported_transfer"
            target_symbol = safe_target_symbol(asm)
            delay_asm = records[i + 1]["asm"] if i + 1 < len(records) else ""
            delay_clobber = bool(delay_asm and d14.writes_t9(delay_asm))

            callee = None
            if tclass == "direct_call" and target_symbol:
                callee = callee_static_summary(path, objdump, target_symbol)

            callee_preserved = bool(callee and callee["t9PreservationProven"])
            initial_live = (not delay_clobber) and callee_preserved
            post_start = i + 2
            post = post_return_path(records, post_start, got, initial_live) if tclass in {"direct_call", "indirect_call"} else {
                "accepted": False,
                "reason": "first_transfer_is_not_returning_call",
                "freshReadReloadCount": 0,
            }

            return {
                "symbol": FUNCTION,
                "selectedReadGotLoadCount": selected_loads,
                "firstTransferClass": tclass,
                "firstTransferTargetSymbol": target_symbol,
                "delaySlotT9Clobber": delay_clobber,
                "callee": callee,
                "postReturn": post,
                "acceptedReadCallEdge": bool(post["accepted"]),
            }

    return {
        "symbol": FUNCTION,
        "selectedReadGotLoadCount": selected_loads,
        "firstTransferClass": "not_recovered",
        "firstTransferTargetSymbol": None,
        "delaySlotT9Clobber": False,
        "callee": None,
        "postReturn": None,
        "acceptedReadCallEdge": False,
    }


def classify(summary: dict, got_count: int) -> str:
    if got_count <= 0:
        return "E2_D16_SELECTED_GOT_MAP_NOT_RECOVERED"
    if summary["acceptedReadCallEdge"]:
        return "E2_D16_LIBSVCTL_READ_EDGE_RECOVERED"
    if summary["selectedReadGotLoadCount"] > 0 and summary["firstTransferClass"] != "not_recovered":
        return "E2_D16_LIBSVCTL_CALL_RETURN_PARTIAL"
    if summary["selectedReadGotLoadCount"] > 0:
        return "E2_D16_READ_BOUNDARY_NOT_RECOVERED"
    return "E2_D16_READ_GOT_LOAD_NOT_RECOVERED"


def run_probe(args):
    work = pathlib.Path(args.work_dir).resolve()
    firmware = work / "firmware.image"
    payload = work / "payload"
    roots = work / "roots"
    scratch = work / "scratch"
    for p in (firmware.parent, payload, roots, scratch):
        p.mkdir(parents=True, exist_ok=True)

    exact = base.download_exact(
        args.firmware_url,
        firmware,
        expected_size=args.expected_size,
        expected_sha256=args.expected_sha256,
    )
    base.extract_outer(firmware, payload)
    rs = base.extract_squashfs_roots(payload, roots, scratch)
    root = base.select_root(rs)
    lib = (root / LIB.lstrip("/")).resolve()

    objdump = shutil.which(args.objdump)
    if not objdump:
        raise RuntimeError("objdump unavailable")

    got = d13.readelf_selected_got(lib)
    summary = analyze_read_call_boundary(lib, objdump, got)
    classification = classify(summary, len(got))

    return {
        "schemaVersion": SCHEMA_VERSION,
        "experiment": EXPERIMENT,
        "classification": classification,
        "oracleSatisfied": True,
        "target": {
            "expectedBytes": args.expected_size,
            "expectedSha256": args.expected_sha256.lower(),
            "observedBytes": exact["bytes"],
            "observedSha256": exact["sha256"],
        },
        "library": {
            "path": LIB,
            "readBoundarySummary": summary,
            "derived": {
                "readCallsLibcRead": summary["acceptedReadCallEdge"],
                "freshPostReturnReadReloadObserved": bool(
                    summary.get("postReturn")
                    and summary["postReturn"].get("freshReadReloadCount", 0) > 0
                ),
                "boundedCalleeT9PreservationProven": bool(
                    summary.get("callee")
                    and summary["callee"].get("t9PreservationProven")
                ),
            },
        },
        "interpretationBoundary": {
            "t9AssumedCallerSavedByDefault": True,
            "singleCallReturnBoundaryOnly": True,
            "mipsDelaySlotModeled": True,
            "postReturnStopsAtNextControlTransfer": True,
            "calleePreservationRequiresNoT9WritesNoNestedCallsAndReturn": True,
            "acceptedStaticCallEdgeIsNotRuntimeExecutionProof": True,
            "instructionAddressesPublished": False,
            "rawDisassemblyPublished": False,
            "packetFieldLayoutAccepted": False,
            "protocolEnumValuesAccepted": False,
        },
        "safety": {
            "rawFirmwarePublished": False,
            "rootfsPublished": False,
            "binaryPayloadPublished": False,
            "rawDisassemblyPublished": False,
            "instructionAddressesPublished": False,
            "gotOffsetsPublished": False,
            "arbitraryBinaryStringsPublished": False,
            "wirePayloadPublished": False,
            "physicalRouterContact": False,
            "routerMutationAuthorized": False,
        },
    }


def parse_args(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--firmware-url", required=True)
    p.add_argument("--expected-size", type=int, required=True)
    p.add_argument("--expected-sha256", required=True)
    p.add_argument("--objdump", default="mips-linux-gnu-objdump")
    p.add_argument("--work-dir", required=True)
    p.add_argument("--receipt", required=True)
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    receipt = pathlib.Path(args.receipt)
    receipt.parent.mkdir(parents=True, exist_ok=True)
    try:
        data = run_probe(args)
        rc = 0
    except Exception as exc:
        data = {
            "schemaVersion": SCHEMA_VERSION,
            "experiment": EXPERIMENT,
            "classification": "HARNESS_FAILURE",
            "oracleSatisfied": False,
            "error": {"type": type(exc).__name__, "message": str(exc)[:1000]},
            "safety": {
                "rawFirmwarePublished": False,
                "rootfsPublished": False,
                "binaryPayloadPublished": False,
                "rawDisassemblyPublished": False,
                "instructionAddressesPublished": False,
                "gotOffsetsPublished": False,
                "arbitraryBinaryStringsPublished": False,
                "wirePayloadPublished": False,
                "physicalRouterContact": False,
                "routerMutationAuthorized": False,
            },
        }
        rc = 3
    receipt.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"classification": data["classification"], "oracleSatisfied": data["oracleSatisfied"]}, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
