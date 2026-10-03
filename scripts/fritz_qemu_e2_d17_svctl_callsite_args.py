#!/usr/bin/env python3
"""E2-D17: bounded /bin/svctl callsite argument-class recovery.

R9 proved that status/start/status share the same 260-byte request object while
the first 8-byte request chunk differs for start. D11-D16 localized the transport
carrier but intentionally did not assign protocol enums or packet fields.

D17 analyzes exact /bin/svctl callsites into selected libsvctl entry points and
emits only:
- target symbol names;
- callsite counts;
- argument setup classes for a0-a3 within the same basic block;
- fixed start/status token counts already admitted by D10.

No argument values other than generic classes, callsite addresses, disassembly,
GOT offsets, binary bytes, or wire payload are persisted.
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
d14_path = pathlib.Path(__file__).with_name("fritz_qemu_e2_d14_libsvctl_liveness.py")
_D14_SPEC = importlib.util.spec_from_file_location("fritz_qemu_e2_d14_libsvctl_liveness", d14_path)
if _D14_SPEC is None or _D14_SPEC.loader is None:
    raise RuntimeError("unable to load D14")
d14 = importlib.util.module_from_spec(_D14_SPEC)
_D14_SPEC.loader.exec_module(d14)
d10 = d13.d12.d11.d10
base = d13.base

SCHEMA_VERSION = 1
EXPERIMENT = "fritz-qemu-e2-d17-svctl-callsite-args/v1"
SVCTL = "/bin/svctl"
TARGETS = {"_svctl_init", "_svctl_send_pkt", "_svctl_send", "_svctl_read", "_svctl_connect"}
ARG_REGS = ("a0", "a1", "a2", "a3")

_NO_FIRST_OPERAND_DEST = {
    "sw", "sd", "sb", "sh", "swl", "swr", "sdl", "sdr",
    "beq", "bne", "beql", "bnel", "bgez", "bgtz", "blez", "bltz",
    "bgezl", "bgtzl", "blezl", "bltzl", "bgezal", "bltzal",
    "j", "jr", "jal", "jalr", "bal",
    "mult", "multu", "div", "divu", "mthi", "mtlo",
    "syscall", "break", "sync", "nop",
}


def reg_class(token: str) -> str:
    reg = token.strip().lstrip("$").lower()
    if reg in {"a0", "a1", "a2", "a3"}:
        return "argument"
    if reg in {"v0", "v1"}:
        return "return"
    if re.fullmatch(r"t\d", reg):
        return "temporary"
    if re.fullmatch(r"s\d", reg):
        return "saved"
    if reg in {"sp", "fp", "s8"}:
        return "stack_frame"
    if reg == "gp":
        return "global_pointer"
    if reg in {"ra", "31"}:
        return "return_address"
    if reg in {"zero", "0"}:
        return "zero"
    return "other"


def immediate_class(token: str) -> str:
    s = token.strip()
    try:
        value = int(s, 0)
    except ValueError:
        return "nonliteral"
    if value == 0:
        return "zero"
    if value == 1:
        return "one"
    if -16 <= value < 0:
        return "small_negative"
    if 1 < value <= 16:
        return "small_positive"
    if -32768 <= value <= 65535:
        return "word_immediate"
    return "large_immediate"


def writes_register(asm: str, reg: str) -> bool:
    mnemonic, operands = d14._parts(asm)
    if not operands or mnemonic in _NO_FIRST_OPERAND_DEST:
        return False
    return d14._reg(operands[0]) == reg


def classify_write(asm: str, reg: str) -> dict:
    mnemonic, operands = d14._parts(asm)
    if not operands or d14._reg(operands[0]) != reg:
        return {"kind": "unknown"}

    if mnemonic == "li" and len(operands) >= 2:
        return {"kind": "immediate", "immediateClass": immediate_class(operands[1])}

    if mnemonic == "move" and len(operands) >= 2:
        return {"kind": "register_move", "sourceRegisterClass": reg_class(operands[1])}

    if mnemonic in {"lw", "ld", "lb", "lbu", "lh", "lhu"} and len(operands) >= 2:
        m = re.search(r"\((?P<base>\$?[A-Za-z0-9]+)\)", operands[1])
        return {
            "kind": "memory_load",
            "baseRegisterClass": reg_class(m.group("base")) if m else "unknown",
        }

    if mnemonic in {"addiu", "addi", "daddiu", "daddi"} and len(operands) >= 3:
        return {
            "kind": "base_plus_immediate",
            "baseRegisterClass": reg_class(operands[1]),
            "immediateClass": immediate_class(operands[2]),
        }

    if mnemonic == "lui":
        return {"kind": "constant_construction"}

    if mnemonic in {"ori", "andi", "xori"} and len(operands) >= 3:
        return {
            "kind": "alu_immediate",
            "sourceRegisterClass": reg_class(operands[1]),
            "immediateClass": immediate_class(operands[2]),
        }

    if mnemonic == "la":
        return {"kind": "address_pseudo"}

    return {"kind": "other_write", "mnemonicClass": mnemonic}


def basic_block_start(ins: list[str], index: int) -> int:
    start = 0
    for i in range(index - 1, -1, -1):
        if d14.control_transfer(ins[i]):
            start = i + 1
            break
    return start


def selected_call_target(ins: list[str], load_index: int) -> bool:
    for asm in ins[load_index + 1:]:
        if d13.is_jalr_t9(asm):
            return True
        if d14.writes_t9(asm) or d14.control_transfer(asm):
            return False
    return False


def argument_signature(ins: list[str], load_index: int) -> dict:
    start = basic_block_start(ins, load_index)
    out = {}
    for reg in ARG_REGS:
        last = None
        for asm in ins[start:load_index]:
            if writes_register(asm, reg):
                last = classify_write(asm, reg)
        out[reg] = last if last is not None else {"kind": "not_set_in_block"}
    return out


def recover_callsites(path: pathlib.Path, objdump: str, got: dict[int, str]) -> dict:
    cp = subprocess.run(
        [objdump, "-dr", str(path)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if cp.returncode:
        raise RuntimeError("objdump failed for /bin/svctl")
    ins = d13.asm_instructions(cp.stdout)

    per_target: dict[str, list[dict]] = {name: [] for name in sorted(TARGETS)}
    selected_load_count = 0

    for i, asm in enumerate(ins):
        load = d13.got_load(asm)
        if not load:
            continue
        reg, off = load
        target = got.get(off)
        if target not in TARGETS or reg not in {"t9", "25"}:
            continue
        selected_load_count += 1
        if not selected_call_target(ins, i):
            continue
        per_target[target].append(argument_signature(ins, i))

    summaries = []
    for target in sorted(TARGETS):
        signatures = per_target[target]
        unique = {}
        for sig in signatures:
            key = json.dumps(sig, sort_keys=True)
            unique[key] = sig
        summaries.append({
            "target": target,
            "acceptedCallsiteCount": len(signatures),
            "distinctArgumentSignatureCount": len(unique),
            "argumentSignatures": [unique[k] for k in sorted(unique)],
        })

    return {
        "selectedGotLoadCount": selected_load_count,
        "targets": summaries,
    }


def classify(slice_: dict, got_count: int) -> str:
    if got_count <= 0:
        return "E2_D17_SELECTED_GOT_MAP_NOT_RECOVERED"
    counts = {x["target"]: x["acceptedCallsiteCount"] for x in slice_["targets"]}
    if counts.get("_svctl_init", 0) > 0 or counts.get("_svctl_send_pkt", 0) > 0:
        return "E2_D17_SVCTL_CALLSITE_ARGUMENT_CLASSES_RECOVERED"
    if slice_["selectedGotLoadCount"] > 0:
        return "E2_D17_SELECTED_GOT_LOADS_CALLSITE_PARTIAL"
    return "E2_D17_SELECTED_LIBSVCTL_TARGETS_UNUSED"


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
    svctl = (root / SVCTL.lstrip("/")).resolve()

    objdump = shutil.which(args.objdump)
    if not objdump:
        raise RuntimeError("objdump unavailable")

    got = d13.readelf_selected_got(svctl)
    callsites = recover_callsites(svctl, objdump, got)
    data = svctl.read_bytes()
    tokens = d10.fixed_token_counts(data)

    return {
        "schemaVersion": SCHEMA_VERSION,
        "experiment": EXPERIMENT,
        "classification": classify(callsites, len(got)),
        "oracleSatisfied": True,
        "target": {
            "expectedBytes": args.expected_size,
            "expectedSha256": args.expected_sha256.lower(),
            "observedBytes": exact["bytes"],
            "observedSha256": exact["sha256"],
        },
        "binary": {
            "path": SVCTL,
            "fixedVerbCounts": {
                "start": tokens.get("start", 0),
                "status": tokens.get("status", 0),
            },
            "callsiteSlice": callsites,
        },
        "derived": {
            "startTokenPresent": tokens.get("start", 0) > 0,
            "statusTokenPresent": tokens.get("status", 0) > 0,
            "initCallsiteCount": next(
                x["acceptedCallsiteCount"] for x in callsites["targets"]
                if x["target"] == "_svctl_init"
            ),
            "sendPktCallsiteCount": next(
                x["acceptedCallsiteCount"] for x in callsites["targets"]
                if x["target"] == "_svctl_send_pkt"
            ),
        },
        "interpretationBoundary": {
            "argumentValuesPublished": False,
            "argumentSetupClassesOnly": True,
            "verbToCallsiteAssociationAccepted": False,
            "protocolEnumValuesAccepted": False,
            "packetFieldLayoutAccepted": False,
            "staticCallsiteIsNotRuntimeExecutionProof": True,
            "instructionAddressesPublished": False,
            "rawDisassemblyPublished": False,
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
