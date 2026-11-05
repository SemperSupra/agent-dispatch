#!/usr/bin/env python3
"""E2-D18d: recover bounded _svctl_send callsite argument roles.

D18c exhausted the admitted function-entry argument dimensions at _svctl_init
and _svctl_send_pkt. D13/D14 already establish that both paths converge on
_svctl_send, and D12 associates the accepted 8-byte and 260-byte constants with
those source functions.

This reducer follows only those already-accepted edges and emits same-basic-
block a0..a3 setup classes at the _svctl_send call boundary. The MIPS jalr
delay slot is included because it executes before the callee begins.

No instruction addresses, raw disassembly, GOT offsets, argument values, binary
payload, or wire payload are published.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib
import shutil
import subprocess

_D17_PATH = pathlib.Path(__file__).with_name("fritz_qemu_e2_d17_svctl_callsite_args.py")
_SPEC = importlib.util.spec_from_file_location("fritz_qemu_e2_d17_svctl_callsite_args", _D17_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError("unable to load D17")
d17 = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(d17)
d13 = d17.d13
d14 = d17.d14
base = d17.base

SCHEMA_VERSION = 1
EXPERIMENT = "fritz-qemu-e2-d18d-downstream-send-args/v1"
LIB = d13.LIB
SOURCE_FUNCTIONS = ("_svctl_init", "_svctl_send_pkt")
TARGET = "_svctl_send"
ARG_REGS = d17.ARG_REGS
_ACCEPTED_SIZE_CLASSES = {8: "accepted_r9_size_8", 260: "accepted_r9_size_260"}


def _literal_int(token: str) -> int | None:
    try:
        return int(token.strip(), 0)
    except ValueError:
        return None


def classify_arg_write(asm: str, reg: str) -> dict:
    """Reuse D17 classes while tagging only already-admitted R9 size constants."""
    base_class = d17.classify_write(asm, reg)
    mnemonic, operands = d14._parts(asm)
    literal = None
    if mnemonic == "li" and len(operands) >= 2:
        literal = _literal_int(operands[1])
    elif mnemonic in {"addiu", "addi", "daddiu", "daddi"} and len(operands) >= 3:
        literal = _literal_int(operands[2])
    if literal in _ACCEPTED_SIZE_CLASSES:
        base_class = dict(base_class)
        base_class["acceptedSizeClass"] = _ACCEPTED_SIZE_CLASSES[literal]
    return base_class


def selected_jalr_index(ins: list[str], load_index: int) -> int | None:
    """Accept only a live selected t9 target in the same basic block."""
    for i in range(load_index + 1, len(ins)):
        asm = ins[i]
        if d13.is_jalr_t9(asm):
            return i
        if d14.writes_t9(asm) or d14.control_transfer(asm):
            return None
    return None


def call_argument_signature(ins: list[str], load_index: int, jalr_index: int) -> dict:
    start = d17.basic_block_start(ins, load_index)
    delay_index = jalr_index + 1 if jalr_index + 1 < len(ins) else None
    out = {}
    for reg in ARG_REGS:
        last = None
        delay_slot_write = False
        for asm in ins[start:jalr_index]:
            if d17.writes_register(asm, reg):
                last = classify_arg_write(asm, reg)
                delay_slot_write = False
        if delay_index is not None and d17.writes_register(ins[delay_index], reg):
            last = classify_arg_write(ins[delay_index], reg)
            delay_slot_write = True
        out[reg] = {
            "setup": last if last is not None else {"kind": "not_set_in_block"},
            "writtenInJalrDelaySlot": delay_slot_write,
        }
    return out


def recover_source(path: pathlib.Path, objdump: str, got: dict[int, str], source: str) -> dict:
    cp = subprocess.run(
        [objdump, "-dr", f"--disassemble={source}", str(path)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if cp.returncode:
        raise RuntimeError(f"objdump failed for {source}")
    ins = d13.asm_instructions(cp.stdout)

    selected_loads = 0
    signatures = []
    for i, asm in enumerate(ins):
        load = d13.got_load(asm)
        if not load:
            continue
        reg, off = load
        if reg not in {"t9", "25"} or got.get(off) != TARGET:
            continue
        selected_loads += 1
        jalr = selected_jalr_index(ins, i)
        if jalr is None:
            continue
        signatures.append(call_argument_signature(ins, i, jalr))

    unique = {}
    for sig in signatures:
        unique[json.dumps(sig, sort_keys=True)] = sig

    size_classes = sorted({
        rec["setup"]["acceptedSizeClass"]
        for sig in signatures
        for rec in sig.values()
        if isinstance(rec.get("setup"), dict)
        and rec["setup"].get("acceptedSizeClass")
    })
    return {
        "source": source,
        "target": TARGET,
        "selectedTargetLoadCount": selected_loads,
        "acceptedSameBlockCallsiteCount": len(signatures),
        "distinctArgumentSignatureCount": len(unique),
        "argumentSignatures": [unique[k] for k in sorted(unique)],
        "acceptedSizeClasses": size_classes,
    }


def classify(sources: list[dict]) -> str:
    counts = {x["source"]: x["acceptedSameBlockCallsiteCount"] for x in sources}
    if all(counts.get(source, 0) == 1 for source in SOURCE_FUNCTIONS):
        if any(x["acceptedSizeClasses"] for x in sources):
            return "E2_D18D_DOWNSTREAM_SEND_ARGUMENT_ROLES_RECOVERED"
        return "E2_D18D_DOWNSTREAM_SEND_CALLS_RECOVERED_ARGUMENT_SIZE_PARTIAL"
    if any(x["acceptedSameBlockCallsiteCount"] > 0 for x in sources):
        return "E2_D18D_DOWNSTREAM_SEND_CALLSITE_PARTIAL"
    return "E2_D18D_DOWNSTREAM_SEND_CALLSITE_NOT_REPRODUCED"


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
    sources = [recover_source(lib, objdump, got, source) for source in SOURCE_FUNCTIONS]

    return {
        "schemaVersion": SCHEMA_VERSION,
        "experiment": EXPERIMENT,
        "classification": classify(sources),
        "oracleSatisfied": True,
        "target": {
            "expectedBytes": args.expected_size,
            "expectedSha256": args.expected_sha256.lower(),
            "observedBytes": exact["bytes"],
            "observedSha256": exact["sha256"],
        },
        "downstreamSend": {
            "libraryPath": LIB,
            "target": TARGET,
            "sources": sources,
        },
        "derived": {
            "initToSendCallsiteCount": next(
                x["acceptedSameBlockCallsiteCount"] for x in sources
                if x["source"] == "_svctl_init"
            ),
            "sendPktToSendCallsiteCount": next(
                x["acceptedSameBlockCallsiteCount"] for x in sources
                if x["source"] == "_svctl_send_pkt"
            ),
            "mechanicallyJustifiedRuntimePoint": all(
                x["acceptedSameBlockCallsiteCount"] == 1 for x in sources
            ),
        },
        "interpretationBoundary": {
            "onlyPreviouslyAcceptedStaticEdgesFollowed": True,
            "sameBasicBlockTargetLivenessRequired": True,
            "mipsJalrDelaySlotModeled": True,
            "acceptedR9SizeConstantsOnly": True,
            "argumentSetupClassesOnly": True,
            "argumentValuesPublished": False,
            "verbAssociationAccepted": False,
            "runtimeOrderAccepted": False,
            "protocolEnumValuesAccepted": False,
            "packetFieldLayoutAccepted": False,
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
    print(json.dumps({
        "classification": data["classification"],
        "oracleSatisfied": data["oracleSatisfied"],
        "derived": data.get("derived", {}),
    }, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
