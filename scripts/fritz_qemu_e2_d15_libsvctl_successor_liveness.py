#!/usr/bin/env python3
"""E2-D15: resolve _svctl_read across one mechanically identified CFG boundary.

D14 stopped when the selected libc read GOT target, loaded into t9, reached a
basic-block exit before jalr. D15 follows only that first direct control-flow
boundary and models the MIPS delay slot explicitly. An edge is accepted only
when the same selected t9 target remains live to jalr t9 on a direct successor
path without crossing a second control transfer.

Durable output contains only symbol names, branch/successor classes, outcome
counts, and exact target identity. Instruction addresses, disassembly, GOT
offsets, and proprietary bytes are never written to the receipt.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib
import re
import shutil
import subprocess

_D14_PATH = pathlib.Path(__file__).with_name("fritz_qemu_e2_d14_libsvctl_liveness.py")
_SPEC = importlib.util.spec_from_file_location("fritz_qemu_e2_d14_libsvctl_liveness", _D14_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError("unable to load D14")
d14 = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(d14)
d13 = d14.d13
base = d14.base

SCHEMA_VERSION = 1
EXPERIMENT = "fritz-qemu-e2-d15-libsvctl-successor-liveness/v1"
LIB = d14.LIB
FUNCTION = "_svctl_read"
TARGET = "read"

_LINE_RE = re.compile(
    r"^\s*(?P<addr>[0-9a-fA-F]+):\s+(?:[0-9a-fA-F]{2,8}\s+)+(?P<asm>.+)$"
)
_BRANCH_TARGET_RE = re.compile(
    r"(?:^|,)\s*(?P<addr>(?:0x)?[0-9a-fA-F]+)(?:\s*<[^>]+>)?\s*$"
)
_BRANCH_LIKELY = {
    "beql", "bnel", "blezl", "bgtzl", "bltzl", "bgezl",
    "bc1tl", "bc1fl",
}
_UNCONDITIONAL_DIRECT = {"b", "j"}


def instruction_records(disassembly: str) -> list[dict]:
    out = []
    for line in disassembly.splitlines():
        m = _LINE_RE.match(line)
        if not m:
            continue
        out.append({"addr": int(m.group("addr"), 16), "asm": m.group("asm").strip()})
    return out


def branch_target_addr(asm: str) -> int | None:
    m = _BRANCH_TARGET_RE.search(asm.split("#", 1)[0].strip())
    if not m:
        return None
    token = m.group("addr")
    return int(token, 16)


def branch_class(asm: str) -> str | None:
    mnemonic, _ = d14._parts(asm)
    if mnemonic in _UNCONDITIONAL_DIRECT:
        return "unconditional_direct"
    if mnemonic in {"jr", "jal", "jalr", "bal"}:
        return "terminal_or_call"
    if mnemonic.startswith("b") and mnemonic != "break":
        return "conditional_likely" if mnemonic in _BRANCH_LIKELY else "conditional"
    return None


def scan_successor_block(records: list[dict], start_index: int) -> str:
    if start_index < 0 or start_index >= len(records):
        return "successor_outside_function"
    for rec in records[start_index:]:
        asm = rec["asm"]
        if d13.is_jalr_t9(asm):
            return "successor_target_live_to_jalr"
        if d14.writes_t9(asm):
            return "successor_t9_clobbered_before_jalr"
        if d14.control_transfer(asm):
            return "second_control_transfer_before_jalr"
    return "function_ended_before_jalr"


def successor_liveness(records: list[dict], load_index: int) -> dict:
    addr_to_index = {r["addr"]: i for i, r in enumerate(records)}

    for i in range(load_index + 1, len(records)):
        asm = records[i]["asm"]
        if d13.is_jalr_t9(asm):
            return {
                "accepted": True,
                "reason": "same_basic_block_target_live_to_jalr",
                "boundaryClass": "none",
                "successorOutcomes": {"same_block": "successor_target_live_to_jalr"},
            }
        if d14.writes_t9(asm):
            return {
                "accepted": False,
                "reason": "t9_clobbered_before_first_boundary",
                "boundaryClass": "none",
                "successorOutcomes": {},
            }
        if not d14.control_transfer(asm):
            continue

        bclass = branch_class(asm)
        if bclass == "terminal_or_call":
            return {
                "accepted": False,
                "reason": "terminal_or_call_before_target_jalr",
                "boundaryClass": bclass,
                "successorOutcomes": {},
            }

        delay_index = i + 1
        delay_asm = records[delay_index]["asm"] if delay_index < len(records) else ""
        target_addr = branch_target_addr(asm)
        target_index = addr_to_index.get(target_addr) if target_addr is not None else None
        fallthrough_index = i + 2

        successors: list[tuple[str, int, bool]] = []
        if bclass == "unconditional_direct":
            if target_index is not None:
                successors.append(("taken", target_index, True))
        elif bclass in {"conditional", "conditional_likely"}:
            if target_index is not None:
                successors.append(("taken", target_index, True))
            if fallthrough_index < len(records):
                # Branch-likely annuls the delay slot on the not-taken path.
                successors.append(("fallthrough", fallthrough_index, bclass != "conditional_likely"))

        if not successors:
            return {
                "accepted": False,
                "reason": "first_boundary_successor_not_resolved",
                "boundaryClass": bclass or "unsupported",
                "successorOutcomes": {},
            }

        outcomes: dict[str, str] = {}
        for kind, start, executes_delay in successors:
            if executes_delay and delay_asm:
                if d13.is_jalr_t9(delay_asm):
                    outcomes[kind] = "delay_slot_target_live_to_jalr"
                    continue
                if d14.writes_t9(delay_asm):
                    outcomes[kind] = "delay_slot_t9_clobbered"
                    continue
                if d14.control_transfer(delay_asm):
                    outcomes[kind] = "delay_slot_control_transfer_unsupported"
                    continue
            outcomes[kind] = scan_successor_block(records, start)

        accepted = any(
            v in {"successor_target_live_to_jalr", "delay_slot_target_live_to_jalr"}
            for v in outcomes.values()
        )
        return {
            "accepted": accepted,
            "reason": "successor_path_target_live_to_jalr" if accepted else "no_admissible_successor_reaches_target_jalr",
            "boundaryClass": bclass or "unsupported",
            "successorOutcomes": dict(sorted(outcomes.items())),
        }

    return {
        "accepted": False,
        "reason": "function_ended_before_first_boundary_or_jalr",
        "boundaryClass": "none",
        "successorOutcomes": {},
    }


def function_successor_edge(path: pathlib.Path, objdump: str, got: dict[int, str]) -> dict:
    cp = subprocess.run(
        [objdump, "-dr", f"--disassemble={FUNCTION}", str(path)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if cp.returncode:
        raise RuntimeError("objdump failed for _svctl_read")
    records = instruction_records(cp.stdout)

    selected = 0
    accepted = 0
    boundary_classes: dict[str, int] = {}
    outcome_counts: dict[str, int] = {}
    successor_outcome_counts: dict[str, int] = {}

    for i, rec in enumerate(records):
        load = d13.got_load(rec["asm"])
        if not load:
            continue
        reg, off = load
        if reg not in {"t9", "25"} or got.get(off) != TARGET:
            continue
        selected += 1
        result = successor_liveness(records, i)
        boundary_classes[result["boundaryClass"]] = boundary_classes.get(result["boundaryClass"], 0) + 1
        outcome_counts[result["reason"]] = outcome_counts.get(result["reason"], 0) + 1
        for v in result["successorOutcomes"].values():
            successor_outcome_counts[v] = successor_outcome_counts.get(v, 0) + 1
        if result["accepted"]:
            accepted += 1

    return {
        "symbol": FUNCTION,
        "selectedReadGotLoadCount": selected,
        "acceptedReadCallEdgeCount": accepted,
        "acceptedReadCallTargets": [TARGET] if accepted else [],
        "firstBoundaryClassCounts": dict(sorted(boundary_classes.items())),
        "outcomeCounts": dict(sorted(outcome_counts.items())),
        "successorOutcomeCounts": dict(sorted(successor_outcome_counts.items())),
    }


def classify(summary: dict, got_count: int) -> str:
    if got_count <= 0:
        return "E2_D15_SELECTED_GOT_MAP_NOT_RECOVERED"
    if summary["acceptedReadCallEdgeCount"] > 0:
        return "E2_D15_LIBSVCTL_READ_EDGE_RECOVERED"
    if summary["selectedReadGotLoadCount"] > 0:
        return "E2_D15_LIBSVCTL_SUCCESSOR_PARTIAL"
    return "E2_D15_READ_GOT_LOAD_NOT_RECOVERED"


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
    summary = function_successor_edge(lib, objdump, got)
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
            "functionSuccessorSummary": summary,
            "derived": {
                "readCallsLibcRead": summary["acceptedReadCallEdgeCount"] > 0,
            },
        },
        "interpretationBoundary": {
            "firstDirectControlFlowBoundaryOnly": True,
            "mipsDelaySlotModeled": True,
            "branchLikelyAnnulModeled": True,
            "secondControlTransferStopsPath": True,
            "t9MustRemainLiveToJalr": True,
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
