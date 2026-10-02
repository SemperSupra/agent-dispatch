#!/usr/bin/env python3
"""E2-D10: public-safe static recovery of the shipped svctl/supervisor protocol surface.

The reducer binds two exact inputs:
- FRITZ!OS 8.25 firmware for the shipped /bin/svctl and /bin/supervisor binaries;
- the matching AVM OSP archive for a source-coverage check.

It emits only fixed-token counts, ELF/import metadata, fixed-size adjacency around
known call symbols, and OSP file/token presence. Raw binaries, source snippets,
disassembly, arbitrary strings, and wire payloads are never persisted.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import pathlib
import re
import shutil
import subprocess
import tarfile

_BASE = pathlib.Path(__file__).with_name("fritz_qemu_user_probe.py")
_SPEC = importlib.util.spec_from_file_location("fritz_qemu_user_probe", _BASE)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError("unable to load firmware base probe")
base = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(base)

SCHEMA_VERSION = 1
EXPERIMENT = "fritz-qemu-e2-d10-protocol-static/v1"

BINARIES = ("/bin/svctl", "/bin/supervisor")
FIXED_VERBS = ("start", "stop", "restart", "reload", "status")
FIXED_BINARY_TOKENS = (
    "ctlmgr",
    "supervisor",
    "supervisor.ctrl.socket",
    *FIXED_VERBS,
)
FIXED_IMPORTS = (
    "socket", "connect", "send", "sendto", "recv", "recvfrom",
    "read", "write", "close", "strcmp", "strncmp", "strcpy",
    "strncpy", "memcpy", "memset",
)
FIXED_SIZES = {
    8: "r9FirstRequestChunkBytes",
    260: "r9SecondRequestOrResponseChunkBytes",
    268: "r9AggregateRequestBytes",
}
OSP_STRONG_TOKENS = ("svctl", "supervisor.ctrl.socket")
OSP_GENERIC_TOKEN = "supervisor"
OSP_TEXT_SUFFIXES = {
    ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".sh", ".mk",
    ".in", ".txt", ".service", ".target",
}
MAX_OSP_TEXT_BYTES = 2 * 1024 * 1024


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fp:
        for chunk in iter(lambda: fp.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def download_exact(url: str, path: pathlib.Path, expected_size: int, expected_sha256: str) -> dict:
    cp = subprocess.run(
        ["curl", "--fail", "--location", "--silent", "--show-error", "--output", str(path), url],
        capture_output=True,
        text=True,
        timeout=900,
    )
    if cp.returncode:
        raise RuntimeError(f"download failed exit={cp.returncode} stderrBytes={len(cp.stderr.encode())}")
    size = path.stat().st_size
    digest = sha256_file(path)
    if size != expected_size:
        raise RuntimeError(f"size mismatch expected={expected_size} observed={size}")
    if digest.lower() != expected_sha256.lower():
        raise RuntimeError("sha256 mismatch")
    return {"bytes": size, "sha256": digest}


def fixed_token_counts(data: bytes) -> dict:
    out = {}
    for token in FIXED_BINARY_TOKENS:
        rx = re.compile(
            rb"(?<![A-Za-z0-9_.-])" + re.escape(token.encode()) + rb"(?![A-Za-z0-9_.-])",
            re.I,
        )
        out[token] = len(rx.findall(data))
    return out


def dynamic_imports(path: pathlib.Path) -> dict:
    readelf = shutil.which("readelf")
    if not readelf:
        raise RuntimeError("readelf unavailable")
    cp = subprocess.run([readelf, "-Ws", str(path)], capture_output=True, text=True, timeout=30)
    if cp.returncode:
        raise RuntimeError(f"readelf symbols failed exit={cp.returncode}")
    result = {}
    for name in FIXED_IMPORTS:
        rx = re.compile(rf"\bUND\b.*\b{re.escape(name)}(?:@[^\s]+)?\s*$")
        result[name] = sum(1 for line in cp.stdout.splitlines() if rx.search(line))
    return result


def _asm_operand_text(line: str) -> str:
    if "\t" in line:
        parts = [p for p in line.split("\t") if p]
        if parts:
            return parts[-1]
    m = re.match(r"^\s*[0-9a-fA-F]+:\s+[0-9a-fA-F ]+\s+(.+)$", line)
    return m.group(1) if m else ""


def fixed_size_hits(text: str) -> list[dict]:
    hits = []
    for value, label in FIXED_SIZES.items():
        dec = re.compile(rf"(?<![0-9A-Za-z_]){value}(?![0-9A-Za-z_])")
        hx = re.compile(rf"(?<![0-9A-Fa-f])0x{value:x}(?![0-9A-Fa-f])", re.I)
        bare_hex = re.compile(rf"(?<![0-9A-Fa-f]){value:x}(?![0-9A-Fa-f])", re.I)
        if dec.search(text) or hx.search(text) or (value >= 16 and bare_hex.search(text)):
            hits.append({"bytes": value, "meaning": label})
    return hits


def callsite_fixed_size_summary(disassembly: str, radius: int = 12) -> list[dict]:
    lines = disassembly.splitlines()
    raw = []
    for idx, line in enumerate(lines):
        symbol = next((name for name in FIXED_IMPORTS if re.search(rf"\b{re.escape(name)}\b", line)), None)
        if symbol is None:
            continue
        lo = max(0, idx - radius)
        hi = min(len(lines), idx + radius + 1)
        sizes = {}
        instruction_count = 0
        for nearby in lines[lo:hi]:
            asm = _asm_operand_text(nearby)
            if not asm:
                continue
            instruction_count += 1
            for hit in fixed_size_hits(asm):
                sizes[hit["bytes"]] = hit
        raw.append({
            "symbol": symbol,
            "fixedSizesNearby": [sizes[k] for k in sorted(sizes)],
            "windowInstructionCount": instruction_count,
        })

    # Objdump may mention a symbol on both the instruction and a relocation line.
    # Collapse consecutive equivalent observations and assign only ordinals.
    out = []
    previous = None
    ordinals = {}
    for item in raw:
        key = json.dumps(item, sort_keys=True)
        if key == previous:
            continue
        previous = key
        ordinals[item["symbol"]] = ordinals.get(item["symbol"], 0) + 1
        out.append({**item, "ordinal": ordinals[item["symbol"]]})
    return out


def binary_metadata(root: pathlib.Path, guest: str, objdump: str) -> dict:
    path = root / guest.lstrip("/")
    if not path.is_file():
        raise RuntimeError(f"missing shipped binary: {guest}")
    header = base.parse_elf_header(path)
    if not header or header.get("machineName") != "MIPS":
        raise RuntimeError(f"unexpected ELF architecture for {guest}")
    data = path.read_bytes()
    cp = subprocess.run([objdump, "-dr", str(path)], capture_output=True, text=True, timeout=60)
    if cp.returncode:
        raise RuntimeError(f"objdump failed for {guest} exit={cp.returncode}")
    calls = callsite_fixed_size_summary(cp.stdout)
    return {
        "path": guest,
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
        "elf": header,
        "fixedTokenCounts": fixed_token_counts(data),
        "dynamicImports": dynamic_imports(path),
        "callsiteFixedSizeSummary": calls,
        "derived": {
            "fixedVerbTokenCount": sum(fixed_token_counts(data)[v] for v in FIXED_VERBS),
            "sendLikeCallsiteCount": sum(1 for x in calls if x["symbol"] in ("send", "sendto", "write")),
            "readLikeCallsiteCount": sum(1 for x in calls if x["symbol"] in ("recv", "recvfrom", "read")),
            "callsiteHas8ByteAdjacency": any(
                any(y["bytes"] == 8 for y in x["fixedSizesNearby"]) for x in calls
            ),
            "callsiteHas260ByteAdjacency": any(
                any(y["bytes"] == 260 for y in x["fixedSizesNearby"]) for x in calls
            ),
        },
    }


def osp_fixed_token_coverage(archive: pathlib.Path) -> dict:
    # "supervisor" is a generic kernel/CPU term and is not sufficient evidence
    # that the OSP archive contains the proprietary FRITZ supervisor surface.
    strong_name_matches = []
    strong_content_matches = []
    generic_supervisor_content_match_count = 0
    scanned_text_files = 0
    with tarfile.open(archive, "r:*") as tf:
        for member in tf:
            if not member.isfile():
                continue
            name = member.name[2:] if member.name.startswith("./") else member.name
            low_name = name.lower()
            name_hits = [token for token in OSP_STRONG_TOKENS if token in low_name]
            if name_hits:
                strong_name_matches.append({"path": name, "tokens": name_hits})

            suffix = pathlib.PurePosixPath(name).suffix.lower()
            if suffix not in OSP_TEXT_SUFFIXES or member.size > MAX_OSP_TEXT_BYTES:
                continue
            fp = tf.extractfile(member)
            if fp is None:
                continue
            data = fp.read()
            scanned_text_files += 1
            low = data.lower()
            hits = [token for token in OSP_STRONG_TOKENS if token.encode() in low]
            if hits:
                strong_content_matches.append({"path": name, "tokens": hits})
            elif OSP_GENERIC_TOKEN.encode() in low:
                generic_supervisor_content_match_count += 1

    def dedupe(items):
        unique = {json.dumps(x, sort_keys=True): x for x in items}
        return [unique[k] for k in sorted(unique)]

    strong_names = dedupe(strong_name_matches)
    strong_content = dedupe(strong_content_matches)
    return {
        "scannedTextFiles": scanned_text_files,
        "strongMemberNameMatches": strong_names,
        "strongContentTokenMatches": strong_content,
        "genericSupervisorContentMatchCount": generic_supervisor_content_match_count,
        "sourceSurfaceFound": bool(strong_names or strong_content),
        "sourceSurfacePredicate": "svctl-or-supervisor-control-socket-only",
    }

def classify(svctl: dict, osp: dict) -> str:
    if svctl["derived"]["fixedVerbTokenCount"] <= 0:
        return "E2_D10_STATIC_VERB_SURFACE_NOT_RECOVERED"
    if svctl["derived"]["callsiteHas8ByteAdjacency"] or svctl["derived"]["callsiteHas260ByteAdjacency"]:
        return "E2_D10_STATIC_PROTOCOL_SURFACE_RECOVERED"
    if osp["sourceSurfaceFound"]:
        return "E2_D10_SOURCE_SURFACE_FOUND_BINARY_CALLSITE_PARTIAL"
    return "E2_D10_STATIC_PROTOCOL_SURFACE_PARTIAL"


def run_probe(args) -> dict:
    work = pathlib.Path(args.work_dir).resolve()
    firmware = work / "firmware" / "FRITZ.Box_7590-08.25.image"
    payload = work / "payload"
    roots = work / "roots"
    scratch = work / "scratch"
    osp_archive = work / "osp" / "source-files.tar.gz"
    for p in (firmware.parent, payload, roots, scratch, osp_archive.parent):
        p.mkdir(parents=True, exist_ok=True)

    exact_fw = base.download_exact(
        args.firmware_url,
        firmware,
        expected_size=args.firmware_expected_size,
        expected_sha256=args.firmware_expected_sha256,
    )
    outer = base.extract_outer(firmware, payload)
    root_candidates = base.extract_squashfs_roots(payload, roots, scratch)
    root = base.select_root(root_candidates)

    objdump = shutil.which(args.objdump)
    if not objdump:
        raise RuntimeError(f"objdump unavailable: {args.objdump}")

    binary = {
        "svctl": binary_metadata(root, "/bin/svctl", objdump),
        "supervisor": binary_metadata(root, "/bin/supervisor", objdump),
    }

    exact_osp = download_exact(
        args.osp_url,
        osp_archive,
        args.osp_expected_size,
        args.osp_expected_sha256,
    )
    osp = osp_fixed_token_coverage(osp_archive)

    classification = classify(binary["svctl"], osp)
    return {
        "schemaVersion": SCHEMA_VERSION,
        "experiment": EXPERIMENT,
        "classification": classification,
        "oracleSatisfied": True,
        "firmware": {
            "expectedBytes": args.firmware_expected_size,
            "expectedSha256": args.firmware_expected_sha256.lower(),
            "observedBytes": exact_fw["bytes"],
            "observedSha256": exact_fw["sha256"],
        },
        "osp": {
            "expectedBytes": args.osp_expected_size,
            "expectedSha256": args.osp_expected_sha256.lower(),
            "observedBytes": exact_osp["bytes"],
            "observedSha256": exact_osp["sha256"],
            "coverage": osp,
        },
        "extraction": {
            "outerMemberCount": len(outer),
            "squashfsRootCount": len(root_candidates),
            "selectedRootRegularFileCount": base.root_file_count(root),
        },
        "binary": binary,
        "interpretationBoundary": {
            "fixedSizeAdjacencyIsNotDataFlowProof": True,
            "dynamicImportPresenceIsNotCallProof": True,
            "fixedVerbTokenPresenceIsNotEnumMappingProof": True,
            "ospTokenAbsenceDoesNotProveNoProprietaryImplementation": True,
            "protocolEnumValuesAccepted": False,
            "protocolFieldLayoutAccepted": False,
            "responseStateSemanticsAccepted": False,
        },
        "safety": {
            "rawFirmwarePublished": False,
            "rootfsPublished": False,
            "binaryPayloadPublished": False,
            "rawDisassemblyPublished": False,
            "arbitraryBinaryStringsPublished": False,
            "rawOspArchivePublished": False,
            "sourcePayloadPublished": False,
            "sourceSnippetsPublished": False,
            "wirePayloadPublished": False,
            "physicalRouterContact": False,
            "routerMutationAuthorized": False,
        },
    }


def parse_args(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--firmware-url", required=True)
    p.add_argument("--firmware-expected-size", type=int, required=True)
    p.add_argument("--firmware-expected-sha256", required=True)
    p.add_argument("--osp-url", required=True)
    p.add_argument("--osp-expected-size", type=int, required=True)
    p.add_argument("--osp-expected-sha256", required=True)
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
                "arbitraryBinaryStringsPublished": False,
                "rawOspArchivePublished": False,
                "sourcePayloadPublished": False,
                "sourceSnippetsPublished": False,
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
