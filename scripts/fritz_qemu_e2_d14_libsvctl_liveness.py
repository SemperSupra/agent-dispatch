#!/usr/bin/env python3
"""E2-D14: refine selected libsvctl PIC edges with basic-block t9 liveness.

D13 proved selected GOT loads and several PIC call edges, but its fixed four-
instruction load->jalr window left _svctl_init and _svctl_read partial. D14
removes that arbitrary distance bound while becoming stricter about control
flow: an edge is accepted only when a selected GOT target is loaded into t9
and remains live to jalr t9 within the same basic block.

Durable output contains only function/symbol names, edge classes, and counts.
Instruction addresses, disassembly, GOT offsets, and proprietary bytes are not
published.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib
import re
import shutil
import subprocess

_D13_PATH = pathlib.Path(__file__).with_name("fritz_qemu_e2_d13_libsvctl_got.py")
_SPEC = importlib.util.spec_from_file_location("fritz_qemu_e2_d13_libsvctl_got", _D13_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError("unable to load D13")
d13 = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(d13)
d12 = d13.d12
base = d13.base

SCHEMA_VERSION = 1
EXPERIMENT = "fritz-qemu-e2-d14-libsvctl-liveness/v1"
LIB = d13.LIB
TARGETS = d13.TARGETS
FUNCTIONS = ("_svctl_init", "_svctl_read")

_NO_FIRST_OPERAND_DEST = {
    "sw", "sd", "sb", "sh", "swl", "swr", "sdl", "sdr",
    "beq", "bne", "beql", "bnel", "bgez", "bgtz", "blez", "bltz",
    "bgezl", "bgtzl", "blezl", "bltzl", "bgezal", "bltzal",
    "j", "jr", "jal", "jalr", "bal",
    "mult", "multu", "div", "divu", "mthi", "mtlo",
    "syscall", "break", "sync", "nop",
}


def _parts(asm: str) -> tuple[str, list[str]]:
    s = asm.strip()
    if not s:
        return "", []
    fields = s.split(None, 1)
    mnemonic = fields[0].lower()
    operands = []
    if len(fields) > 1:
        operands = [x.strip() for x in fields[1].split(",")]
    return mnemonic, operands


def _reg(token: str) -> str:
    return token.strip().lstrip("$").lower()


def writes_t9(asm: str) -> bool:
    """Conservatively detect explicit writes to t9 in ordinary MIPS syntax."""
    mnemonic, operands = _parts(asm)
    if not operands or mnemonic in _NO_FIRST_OPERAND_DEST:
        return False
    return _reg(operands[0]) in {"t9", "25"}


def control_transfer(asm: str) -> bool:
    mnemonic, _ = _parts(asm)
    if not mnemonic:
        return False
    if mnemonic in {"j", "jr", "jal", "jalr", "bal"}:
        return True
    # MIPS conditional branch mnemonics begin with b; exclude break.
    return mnemonic.startswith("b") and mnemonic != "break"


def live_to_jalr(ins: list[str], load_index: int) -> dict:
    """Classify whether the t9 value loaded at load_index reaches jalr t9."""
    for asm in ins[load_index + 1 :]:
        if d13.is_jalr_t9(asm):
            return {"accepted": True, "reason": "same_basic_block_target_live_to_jalr"}
        if writes_t9(asm):
            return {"accepted": False, "reason": "t9_clobbered_before_jalr"}
        if control_transfer(asm):
            return {"accepted": False, "reason": "basic_block_ended_before_jalr"}
    return {"accepted": False, "reason": "function_ended_before_jalr"}


def function_liveness_edges(path: pathlib.Path, objdump: str, name: str, got: dict[int, str]) -> dict:
    cp = subprocess.run(
        [objdump, "-dr", f"--disassemble={name}", str(path)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if cp.returncode:
        raise RuntimeError(f"objdump failed for {name}")
    ins = d13.asm_instructions(cp.stdout)

    selected_loads = 0
    accepted: list[str] = []
    outcomes: dict[str, int] = {}
    for i, asm in enumerate(ins):
        load = d13.got_load(asm)
        if not load:
            continue
        reg, off = load
        target = got.get(off)
        if target is None or reg not in {"t9", "25"}:
            continue
        selected_loads += 1
        outcome = live_to_jalr(ins, i)
        outcomes[outcome["reason"]] = outcomes.get(outcome["reason"], 0) + 1
        if outcome["accepted"]:
            accepted.append(target)

    return {
        "symbol": name,
        "selectedGotLoadCount": selected_loads,
        "acceptedLivePicCallTargets": sorted(set(accepted)),
        "acceptedLivePicCallCount": len(accepted),
        "outcomeCounts": dict(sorted(outcomes.items())),
    }


def classify(functions: list[dict], got_count: int) -> str:
    if got_count <= 0:
        return "E2_D14_SELECTED_GOT_MAP_NOT_RECOVERED"
    if any(x["acceptedLivePicCallCount"] > 0 for x in functions):
        return "E2_D14_LIBSVCTL_LIVENESS_EDGES_RECOVERED"
    if any(x["selectedGotLoadCount"] > 0 for x in functions):
        return "E2_D14_LIBSVCTL_LIVENESS_PARTIAL"
    return "E2_D14_SELECTED_GOT_UNUSED_IN_TARGET_FUNCTIONS"


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
    funcs = [function_liveness_edges(lib, objdump, name, got) for name in FUNCTIONS]
    new_edges = sorted(
        {
            (f["symbol"], target)
            for f in funcs
            for target in f["acceptedLivePicCallTargets"]
        }
    )

    # Recompute D13's full bounded edge set from the same exact binary so the
    # combined derived predicates are reproducible on this run.
    d13_funcs = [d13.function_edges(lib, objdump, name, got) for name in d13.FUNCTIONS]
    d13_edges = sorted(
        {
            (f["symbol"], target)
            for f in d13_funcs
            for target in f["acceptedPicCallTargets"]
        }
    )
    combined = sorted(set(d13_edges) | set(new_edges))

    derived = {
        "initCallsSend": ("_svctl_init", "_svctl_send") in combined,
        "readCallsLibcRead": ("_svctl_read", "read") in combined,
        "sendPktCallsSend": ("_svctl_send_pkt", "_svctl_send") in combined,
        "sendCallsLibcSend": ("_svctl_send", "send") in combined,
    }

    return {
        "schemaVersion": SCHEMA_VERSION,
        "experiment": EXPERIMENT,
        "classification": classify(funcs, len(got)),
        "oracleSatisfied": True,
        "target": {
            "expectedBytes": args.expected_size,
            "expectedSha256": args.expected_sha256.lower(),
            "observedBytes": exact["bytes"],
            "observedSha256": exact["sha256"],
        },
        "library": {
            "path": LIB,
            "targetFunctionLivenessSummaries": funcs,
            "newlyAcceptedCallEdges": [
                {"source": source, "target": target} for source, target in new_edges
            ],
            "combinedAcceptedCallEdges": [
                {"source": source, "target": target} for source, target in combined
            ],
            "derived": derived,
        },
        "interpretationBoundary": {
            "sameBasicBlockRequired": True,
            "t9MustRemainLiveToJalr": True,
            "arbitraryInstructionWindowUsed": False,
            "acceptedStaticCallEdgeIsNotRuntimeExecutionProof": True,
            "r9SendOrderAccepted": False,
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
