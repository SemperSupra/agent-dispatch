#!/usr/bin/env python3
"""Public-safe FRITZ!OS E2-D0 Web/auth service discovery.

This script reuses the exact firmware acquisition/extraction contract from the
accepted E0/E1 probe and emits only sanitized metadata:
- file paths;
- ELF metadata;
- DT_NEEDED library names;
- fixed marker booleans;
- mechanically derived init/reference edges.

It never emits firmware/rootfs bytes, arbitrary extracted strings, or Web UI
source/body content.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import pathlib
import re
import shutil
import stat
from typing import Iterable

_BASE_SCRIPT = pathlib.Path(__file__).with_name("fritz_qemu_user_probe.py")
_BASE_SPEC = importlib.util.spec_from_file_location(
    "fritz_qemu_user_probe", _BASE_SCRIPT
)
if _BASE_SPEC is None or _BASE_SPEC.loader is None:
    raise RuntimeError("unable to load fritz_qemu_user_probe.py")
base = importlib.util.module_from_spec(_BASE_SPEC)
_BASE_SPEC.loader.exec_module(base)

SCHEMA_VERSION = 1
EXPERIMENT = "fritz-qemu-e2-web-auth-discovery/v1"

FIXED_MARKERS = {
    "login_sid_lua": b"login_sid.lua",
    "data_lua": b"data.lua",
    "webservices_path": b"/webservices/",
}

PATH_TOKENS = (
    "web",
    "http",
    "cgi",
    "lua",
    "ctlmgr",
    "login",
)

INIT_PREFIXES = (
    "etc/init.d/",
    "etc/rc",
    "etc/boot",
    "etc/init/",
    "etc/avm/",
)


def guest_path(root: pathlib.Path, path: pathlib.Path) -> str:
    return "/" + str(path.relative_to(root)).replace(os.sep, "/")


def file_bytes(path: pathlib.Path, *, max_bytes: int = 8 * 1024 * 1024) -> bytes:
    try:
        if path.stat().st_size > max_bytes:
            with path.open("rb") as f:
                return f.read(max_bytes)
        return path.read_bytes()
    except OSError:
        return b""


def marker_hits(data: bytes) -> list[str]:
    return [
        name for name, marker in FIXED_MARKERS.items()
        if marker in data
    ]


def path_token_hits(path: str) -> list[str]:
    lower = path.lower()
    return [token for token in PATH_TOKENS if token in lower]


def is_init_like(relative_posix: str) -> bool:
    return any(relative_posix.startswith(prefix) for prefix in INIT_PREFIXES)


def readelf_type(path: pathlib.Path) -> str | None:
    readelf = shutil.which("readelf")
    if not readelf:
        return None
    cp = base._run([readelf, "-h", str(path)], timeout=20)
    if cp.returncode != 0:
        return None
    for line in cp.stdout.splitlines():
        if line.strip().startswith("Type:"):
            return line.split(":", 1)[1].strip()
    return None


def needed_libraries(path: pathlib.Path) -> list[str]:
    readelf = shutil.which("readelf")
    if not readelf:
        return []
    cp = base._run([readelf, "-d", str(path)], timeout=20)
    if cp.returncode != 0:
        return []
    libs: list[str] = []
    for line in cp.stdout.splitlines():
        match = re.search(r"Shared library:\s*\[([^\]]+)\]", line)
        if match:
            libs.append(match.group(1))
    return sorted(set(libs))


def executable_mode(path: pathlib.Path) -> bool:
    try:
        return bool(path.lstat().st_mode & 0o111)
    except OSError:
        return False


def classify_regular_file(root: pathlib.Path, path: pathlib.Path) -> dict | None:
    rel = str(path.relative_to(root)).replace(os.sep, "/")
    gpath = "/" + rel
    header = base.parse_elf_header(path)
    data = file_bytes(path)
    markers = marker_hits(data)
    tokens = path_token_hits(gpath)

    reasons: list[str] = []
    for marker in markers:
        reasons.append(f"marker:{marker}")
    for token in tokens:
        reasons.append(f"path-token:{token}")

    if header:
        kind = "elf"
    elif is_init_like(rel):
        kind = "init-text"
    else:
        kind = "other"

    # Only carry forward mechanically interesting files.
    if not reasons and kind not in ("init-text",):
        return None

    item = {
        "path": gpath,
        "kind": kind,
        "markers": markers,
        "pathTokens": tokens,
        "executableMode": executable_mode(path),
        "reasons": reasons,
    }
    if header:
        item.update({
            "elf": {
                **header,
                "type": readelf_type(path),
                "dynamicInterpreter": base.dynamic_interpreter(path),
                "needed": needed_libraries(path),
            }
        })
    return item


def candidate_basename_map(items: list[dict]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for item in items:
        if item.get("kind") != "elf":
            continue
        path = item["path"]
        base_name = pathlib.PurePosixPath(path).name
        if base_name:
            mapping.setdefault(base_name, path)
    return mapping


def init_reference_edges(
    root: pathlib.Path,
    init_items: list[dict],
    candidate_names: dict[str, str],
) -> list[dict]:
    edges: list[dict] = []
    for item in init_items:
        source = item["path"]
        p = root / source.lstrip("/")
        data = file_bytes(p, max_bytes=2 * 1024 * 1024)
        for basename, target in sorted(candidate_names.items()):
            if basename.encode("utf-8", errors="ignore") in data:
                edges.append({
                    "source": source,
                    "target": target,
                    "reference": basename,
                })
    # Deduplicate without exposing source contents.
    unique = {
        (e["source"], e["target"], e["reference"]): e for e in edges
    }
    return [
        unique[k]
        for k in sorted(unique)
    ]


def rank_candidates(items: list[dict], edges: list[dict]) -> list[dict]:
    incoming: dict[str, list[str]] = {}
    for edge in edges:
        incoming.setdefault(edge["target"], []).append(edge["source"])

    ranked: list[dict] = []
    for item in items:
        if item.get("kind") != "elf":
            continue
        reasons = list(item.get("reasons", []))
        init_refs = sorted(set(incoming.get(item["path"], [])))
        for source in init_refs:
            reasons.append(f"init-ref:{source}")

        # Require some direct evidence beyond being an arbitrary ELF.
        if not reasons:
            continue

        marker_count = sum(
            1 for r in reasons if r.startswith("marker:")
        )
        init_ref_count = sum(
            1 for r in reasons if r.startswith("init-ref:")
        )
        token_count = sum(
            1 for r in reasons if r.startswith("path-token:")
        )
        score = marker_count * 100 + init_ref_count * 50 + token_count * 10

        ranked.append({
            "path": item["path"],
            "score": score,
            "reasons": sorted(reasons),
            "elf": item["elf"],
        })

    return sorted(
        ranked,
        key=lambda x: (-x["score"], x["path"]),
    )


def build_discovery(root: pathlib.Path) -> dict:
    interesting: list[dict] = []
    init_items: list[dict] = []
    marker_bearing: list[dict] = []

    scanned = 0
    for path in base.regular_files(root):
        scanned += 1
        item = classify_regular_file(root, path)
        if item is None:
            continue
        interesting.append(item)
        if item["kind"] == "init-text":
            init_items.append(item)
        if item["markers"]:
            marker_bearing.append({
                "path": item["path"],
                "kind": item["kind"],
                "markers": item["markers"],
            })

    candidate_names = candidate_basename_map(interesting)
    edges = init_reference_edges(root, init_items, candidate_names)
    ranked = rank_candidates(interesting, edges)

    return {
        "regularFilesScanned": scanned,
        "interestingFileCount": len(interesting),
        "markerBearingFiles": sorted(
            marker_bearing,
            key=lambda x: x["path"],
        ),
        "initReferenceEdges": edges,
        "rankedElfCandidates": ranked,
    }


def run_probe(args: argparse.Namespace) -> dict:
    work = pathlib.Path(args.work_dir).resolve()
    firmware = work / "original" / "firmware.image"
    payload = work / "payload"
    roots_dir = work / "roots"
    scratch = work / "scratch"
    for p in (firmware.parent, payload, roots_dir, scratch):
        p.mkdir(parents=True, exist_ok=True)

    exact = base.download_exact(
        args.firmware_url,
        firmware,
        expected_size=args.expected_size,
        expected_sha256=args.expected_sha256,
    )
    outer_members = base.extract_outer(firmware, payload)
    roots = base.extract_squashfs_roots(payload, roots_dir, scratch)
    selected = base.select_root(roots)
    discovery = build_discovery(selected)

    classification = (
        "DISCOVERY_SUPPORTED"
        if discovery["rankedElfCandidates"]
        else "DISCOVERY_NEGATIVE"
    )

    return {
        "schemaVersion": SCHEMA_VERSION,
        "experiment": EXPERIMENT,
        "classification": classification,
        "oracleSatisfied": True,
        "target": {
            "kind": "public-runtime-download",
            "expectedBytes": args.expected_size,
            "expectedSha256": args.expected_sha256.lower(),
            "observedBytes": exact["bytes"],
            "observedSha256": exact["sha256"],
        },
        "extraction": {
            "outerMemberCount": len(outer_members),
            "squashfsRootCount": len(roots),
            "selectedRootRegularFileCount": base.root_file_count(selected),
        },
        "discovery": discovery,
        "safety": {
            "rawFirmwarePublished": False,
            "rootfsPublished": False,
            "binaryPayloadPublished": False,
            "rawSourceContentPublished": False,
            "arbitraryExtractedStringsPublished": False,
            "physicalRouterContact": False,
            "routerMutationAuthorized": False,
        },
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--firmware-url", required=True)
    p.add_argument("--expected-size", required=True, type=int)
    p.add_argument("--expected-sha256", required=True)
    p.add_argument("--work-dir", required=True)
    p.add_argument("--receipt", required=True)
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    receipt_path = pathlib.Path(args.receipt)
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        receipt = run_probe(args)
        rc = 0
    except Exception as exc:
        receipt = {
            "schemaVersion": SCHEMA_VERSION,
            "experiment": EXPERIMENT,
            "classification": "HARNESS_FAILURE",
            "oracleSatisfied": False,
            "error": {
                "type": type(exc).__name__,
                "message": str(exc)[:1000],
            },
            "safety": {
                "rawFirmwarePublished": False,
                "rootfsPublished": False,
                "binaryPayloadPublished": False,
                "rawSourceContentPublished": False,
                "arbitraryExtractedStringsPublished": False,
                "physicalRouterContact": False,
                "routerMutationAuthorized": False,
            },
        }
        rc = 3

    receipt_path.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "classification": receipt["classification"],
        "oracleSatisfied": receipt["oracleSatisfied"],
    }, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
