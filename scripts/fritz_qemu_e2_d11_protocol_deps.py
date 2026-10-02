#!/usr/bin/env python3
"""E2-D11: bounded static dependency expansion for the FRITZ svctl control path.

D10 showed that /bin/svctl carries command vocabulary and the control-socket
marker but does not directly import the socket/read/write functions searched by
that reducer. D11 follows only exact ELF DT_NEEDED edges into the shipped
libsvctl/libsupervisor objects and emits sanitized metadata:
- dependency edges;
- hashes/sizes/ELF identity;
- fixed control-token counts;
- allowlisted control-related dynamic symbols;
- fixed-size adjacency around allowlisted I/O call references.

Raw binaries, disassembly, arbitrary strings, and wire payloads are not emitted.
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

_D10_PATH = pathlib.Path(__file__).with_name("fritz_qemu_e2_d10_protocol_static.py")
_D10_SPEC = importlib.util.spec_from_file_location("fritz_qemu_e2_d10_protocol_static", _D10_PATH)
if _D10_SPEC is None or _D10_SPEC.loader is None:
    raise RuntimeError("unable to load D10 reducer")
d10 = importlib.util.module_from_spec(_D10_SPEC)
_D10_SPEC.loader.exec_module(d10)
base = d10.base

SCHEMA_VERSION = 1
EXPERIMENT = "fritz-qemu-e2-d11-protocol-dependency-slice/v1"

ROOT_OBJECTS = ("/bin/svctl", "/bin/supervisor")
INTERESTING_LIB_BASENAMES = ("libsvctl.so.1", "libsupervisor.so.1")
ALLOWLIST_IO = (
    "socket", "connect", "send", "sendto", "recv", "recvfrom",
    "read", "write", "close", "poll", "select",
)
CONTROL_NAME_TOKENS = ("svctl", "supervisor")
MAX_SYMBOLS_PER_OBJECT = 128


def _run(argv: list[str], timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)


def needed_libraries(path: pathlib.Path) -> list[str]:
    readelf = shutil.which("readelf")
    if not readelf:
        raise RuntimeError("readelf unavailable")
    cp = _run([readelf, "-d", str(path)])
    if cp.returncode:
        raise RuntimeError(f"readelf dynamic failed: {path.name}")
    out = []
    for line in cp.stdout.splitlines():
        m = re.search(r"Shared library:\s*\[([^\]]+)\]", line)
        if m:
            out.append(m.group(1))
    return sorted(set(out))


def selected_dynamic_symbols(path: pathlib.Path) -> list[dict]:
    readelf = shutil.which("readelf")
    if not readelf:
        raise RuntimeError("readelf unavailable")
    cp = _run([readelf, "-Ws", str(path)])
    if cp.returncode:
        raise RuntimeError(f"readelf symbols failed: {path.name}")
    out = {}
    # Num: Value Size Type Bind Vis Ndx Name
    rx = re.compile(
        r"^\s*\d+:\s+[0-9A-Fa-f]+\s+\d+\s+"
        r"(?P<type>\S+)\s+(?P<bind>\S+)\s+(?P<vis>\S+)\s+"
        r"(?P<ndx>\S+)\s+(?P<name>\S+)\s*$"
    )
    for line in cp.stdout.splitlines():
        m = rx.match(line)
        if not m:
            continue
        raw_name = m.group("name")
        name = raw_name.split("@", 1)[0]
        low = name.lower()
        if name not in ALLOWLIST_IO and not any(token in low for token in CONTROL_NAME_TOKENS):
            continue
        rec = {
            "name": name,
            "type": m.group("type"),
            "binding": m.group("bind"),
            "defined": m.group("ndx") != "UND",
        }
        out[json.dumps(rec, sort_keys=True)] = rec
    return [out[k] for k in sorted(out)][:MAX_SYMBOLS_PER_OBJECT]


def resolve_needed(root: pathlib.Path, basename: str) -> str | None:
    candidates = (
        root / "lib" / basename,
        root / "usr" / "lib" / basename,
        root / "usr" / "local" / "lib" / basename,
    )
    for p in candidates:
        if p.exists():
            return "/" + str(p.relative_to(root)).replace("\\", "/")
    return None


def fixed_tokens(data: bytes) -> dict:
    return d10.fixed_token_counts(data)


def object_metadata(root: pathlib.Path, guest: str, objdump: str) -> dict:
    path = root / guest.lstrip("/")
    if not path.exists():
        raise RuntimeError(f"missing object {guest}")
    # Follow the firmware symlink for analysis but retain the requested guest path.
    real = path.resolve()
    try:
        real.relative_to(root.resolve())
    except ValueError as exc:
        raise RuntimeError(f"object resolves outside root: {guest}") from exc
    data = real.read_bytes()
    header = base.parse_elf_header(real)
    if not header or header.get("machineName") != "MIPS":
        raise RuntimeError(f"unexpected ELF for {guest}")
    cp = _run([objdump, "-dr", str(real)])
    if cp.returncode:
        raise RuntimeError(f"objdump failed: {guest}")
    calls = d10.callsite_fixed_size_summary(cp.stdout, radius=16)
    needed = needed_libraries(real)
    selected = selected_dynamic_symbols(real)
    io_symbols = sorted({
        x["name"] for x in selected if x["name"] in ALLOWLIST_IO
    })
    control_symbols = sorted({
        x["name"] for x in selected
        if any(token in x["name"].lower() for token in CONTROL_NAME_TOKENS)
    })
    tokens = fixed_tokens(data)
    return {
        "path": guest,
        "resolvedPathClass": "symlink-target" if path.is_symlink() else "direct",
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "elf": header,
        "needed": needed,
        "fixedTokenCounts": tokens,
        "selectedDynamicSymbols": selected,
        "ioSymbolNames": io_symbols,
        "controlSymbolNames": control_symbols,
        "callsiteFixedSizeSummary": calls,
        "derived": {
            "controlSocketTokenPresent": tokens.get("supervisor.ctrl.socket", 0) > 0,
            "ioSymbolCount": len(io_symbols),
            "controlSymbolCount": len(control_symbols),
            "callsiteHas8ByteAdjacency": any(
                any(y["bytes"] == 8 for y in x["fixedSizesNearby"]) for x in calls
            ),
            "callsiteHas260ByteAdjacency": any(
                any(y["bytes"] == 260 for y in x["fixedSizesNearby"]) for x in calls
            ),
        },
    }


def build_slice(root: pathlib.Path, objdump: str) -> dict:
    objects: dict[str, dict] = {}
    edges = []

    for guest in ROOT_OBJECTS:
        meta = object_metadata(root, guest, objdump)
        objects[guest] = meta
        for lib in meta["needed"]:
            resolved = resolve_needed(root, lib)
            edges.append({"source": guest, "needed": lib, "resolvedPath": resolved})

    # D10/R4 specifically identified these two shipped libraries. Admit them only
    # if they are either DT_NEEDED from a root object or present under the exact
    # standard library paths and bear the exact expected basenames.
    admitted = set()
    needed_names = {e["needed"] for e in edges}
    for basename in INTERESTING_LIB_BASENAMES:
        resolved = resolve_needed(root, basename)
        if resolved and (basename in needed_names or basename in INTERESTING_LIB_BASENAMES):
            admitted.add(resolved)

    for guest in sorted(admitted):
        if guest not in objects:
            objects[guest] = object_metadata(root, guest, objdump)
        for lib in objects[guest]["needed"]:
            edges.append({
                "source": guest,
                "needed": lib,
                "resolvedPath": resolve_needed(root, lib),
            })

    candidates = []
    for guest, meta in sorted(objects.items()):
        d = meta["derived"]
        if (
            d["controlSocketTokenPresent"]
            or d["ioSymbolCount"] > 0
            or d["controlSymbolCount"] > 0
            or d["callsiteHas8ByteAdjacency"]
            or d["callsiteHas260ByteAdjacency"]
        ):
            candidates.append({
                "path": guest,
                "controlSocketTokenPresent": d["controlSocketTokenPresent"],
                "ioSymbolCount": d["ioSymbolCount"],
                "controlSymbolCount": d["controlSymbolCount"],
                "callsiteHas8ByteAdjacency": d["callsiteHas8ByteAdjacency"],
                "callsiteHas260ByteAdjacency": d["callsiteHas260ByteAdjacency"],
            })

    return {
        "objects": objects,
        "dependencyEdges": sorted(
            edges, key=lambda x: (x["source"], x["needed"], x.get("resolvedPath") or "")
        ),
        "protocolCarrierCandidates": candidates,
    }


def classify(slice_: dict) -> str:
    objects = slice_["objects"]
    libs = [
        m for p, m in objects.items()
        if pathlib.PurePosixPath(p).name in INTERESTING_LIB_BASENAMES
    ]
    if not libs:
        return "E2_D11_PROTOCOL_LIBRARIES_NOT_RESOLVED"
    if any(
        m["derived"]["callsiteHas8ByteAdjacency"]
        or m["derived"]["callsiteHas260ByteAdjacency"]
        for m in libs
    ):
        return "E2_D11_PROTOCOL_LIBRARY_SIZE_SLICE_RECOVERED"
    if any(m["derived"]["ioSymbolCount"] > 0 for m in libs):
        return "E2_D11_PROTOCOL_LIBRARY_IO_SURFACE_RECOVERED"
    if any(m["derived"]["controlSymbolCount"] > 0 for m in libs):
        return "E2_D11_PROTOCOL_LIBRARY_SYMBOL_SURFACE_RECOVERED"
    return "E2_D11_PROTOCOL_DEPENDENCY_SLICE_PARTIAL"


def run_probe(args) -> dict:
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
    outer = base.extract_outer(firmware, payload)
    rs = base.extract_squashfs_roots(payload, roots, scratch)
    root = base.select_root(rs)
    objdump = shutil.which(args.objdump)
    if not objdump:
        raise RuntimeError(f"objdump unavailable: {args.objdump}")
    slice_ = build_slice(root, objdump)
    return {
        "schemaVersion": SCHEMA_VERSION,
        "experiment": EXPERIMENT,
        "classification": classify(slice_),
        "oracleSatisfied": True,
        "target": {
            "expectedBytes": args.expected_size,
            "expectedSha256": args.expected_sha256.lower(),
            "observedBytes": exact["bytes"],
            "observedSha256": exact["sha256"],
        },
        "extraction": {
            "outerMemberCount": len(outer),
            "squashfsRootCount": len(rs),
            "selectedRootRegularFileCount": base.root_file_count(root),
        },
        "slice": slice_,
        "interpretationBoundary": {
            "dtNeededEdgeIsLoadDependency": True,
            "symbolPresenceIsNotCallProof": True,
            "fixedSizeAdjacencyIsNotDataFlowProof": True,
            "r9WireShapeMappedToStructFields": False,
            "protocolEnumValuesAccepted": False,
            "responseStateSemanticsAccepted": False,
        },
        "safety": {
            "rawFirmwarePublished": False,
            "rootfsPublished": False,
            "binaryPayloadPublished": False,
            "rawDisassemblyPublished": False,
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
    rp = pathlib.Path(args.receipt)
    rp.parent.mkdir(parents=True, exist_ok=True)
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
                "wirePayloadPublished": False,
                "physicalRouterContact": False,
                "routerMutationAuthorized": False,
            },
        }
        rc = 3
    rp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"classification": data["classification"], "oracleSatisfied": data["oracleSatisfied"]}, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
