#!/usr/bin/env python3
"""Public-safe FRITZ!OS E2-D1 supervisor/startup discovery.

Scans the exact extracted FRITZ!OS 8.25 root for fixed ctlmgr/svctl/supervisor
markers and emits only path/token metadata, safe service-command relations,
symlink relationships, and ELF dependency metadata. Raw file contents and
arbitrary strings are never emitted.
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

_BASE_SCRIPT = pathlib.Path(__file__).with_name("fritz_qemu_user_probe.py")
_BASE_SPEC = importlib.util.spec_from_file_location(
    "fritz_qemu_user_probe", _BASE_SCRIPT
)
if _BASE_SPEC is None or _BASE_SPEC.loader is None:
    raise RuntimeError("unable to load fritz_qemu_user_probe.py")
base = importlib.util.module_from_spec(_BASE_SPEC)
_BASE_SPEC.loader.exec_module(base)

SCHEMA_VERSION = 1
EXPERIMENT = "fritz-qemu-e2-supervisor-discovery/v1"

FIXED_MARKERS = {
    "ctlmgr": b"ctlmgr",
    "svctl": b"svctl",
    "supervisor": b"supervisor",
}

SAFE_VERBS = ("start", "stop", "restart", "reload", "status")
SCAN_PREFIXES = (
    "etc/",
    "bin/",
    "sbin/",
    "usr/bin/",
    "usr/sbin/",
    "usr/lib/",
    "usr/share/",
)


def read_bounded(path: pathlib.Path, limit: int = 2 * 1024 * 1024) -> bytes:
    try:
        with path.open("rb") as f:
            return f.read(limit)
    except OSError:
        return b""


def marker_hits(data: bytes) -> list[str]:
    return [
        key for key, marker in FIXED_MARKERS.items()
        if marker in data
    ]


def service_command_relations(text: str, source: str) -> list[dict]:
    relations: list[dict] = []
    patterns = [
        re.compile(
            r"\bsvctl\s+(start|stop|restart|reload|status)\s+"
            r"['\"]?ctlmgr['\"]?\b"
        ),
        re.compile(
            r"\bsvctl\s+['\"]?ctlmgr['\"]?\s+"
            r"(start|stop|restart|reload|status)\b"
        ),
    ]
    for line in text.splitlines():
        if "ctlmgr" not in line:
            continue
        if "svctl" in line:
            for pattern in patterns:
                match = pattern.search(line)
                if match:
                    relations.append({
                        "source": source,
                        "controller": "svctl",
                        "verb": match.group(1),
                        "service": "ctlmgr",
                    })
        if (
            re.search(r"\bexec\b", line)
            and re.search(r"\b(?:/usr/bin/)?ctlmgr\b", line)
        ):
            relations.append({
                "source": source,
                "controller": "shell",
                "verb": "exec",
                "service": "ctlmgr",
            })
    unique = {
        (r["source"], r["controller"], r["verb"], r["service"]): r
        for r in relations
    }
    return [unique[k] for k in sorted(unique)]


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
        m = re.search(r"Shared library:\s*\[([^\]]+)\]", line)
        if m:
            libs.append(m.group(1))
    return sorted(set(libs))


def relevant_symlinks(root: pathlib.Path) -> list[dict]:
    out: list[dict] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in [*dirnames, *filenames]:
            path = pathlib.Path(dirpath, name)
            try:
                if not path.is_symlink():
                    continue
                target = os.readlink(path)
            except OSError:
                continue
            rel = "/" + str(path.relative_to(root)).replace(os.sep, "/")
            lowered = (rel + " " + target).lower()
            if not any(k in lowered for k in FIXED_MARKERS):
                continue
            out.append({
                "path": rel,
                "target": target,
                "markers": [
                    k for k in FIXED_MARKERS
                    if k in lowered
                ],
            })
    return sorted(out, key=lambda x: x["path"])


def build_discovery(root: pathlib.Path) -> dict:
    marker_files: list[dict] = []
    relations: list[dict] = []
    elf_objects: list[dict] = []
    scanned = 0

    for path in base.regular_files(root):
        rel_no_slash = str(path.relative_to(root)).replace(os.sep, "/")
        if not rel_no_slash.startswith(SCAN_PREFIXES):
            continue
        scanned += 1
        data = read_bounded(path)
        hits = marker_hits(data)
        path_lower = rel_no_slash.lower()
        path_hits = [k for k in FIXED_MARKERS if k in path_lower]

        if not hits and not path_hits:
            continue

        guest = "/" + rel_no_slash
        header = base.parse_elf_header(path)
        kind = "elf" if header else "text-or-data"

        marker_files.append({
            "path": guest,
            "kind": kind,
            "contentMarkers": hits,
            "pathMarkers": path_hits,
        })

        if header:
            elf_objects.append({
                "path": guest,
                "elf": {
                    **header,
                    "type": readelf_type(path),
                    "dynamicInterpreter": base.dynamic_interpreter(path),
                    "needed": needed_libraries(path),
                },
            })
            continue

        if b"\x00" not in data[:4096]:
            text = data.decode("utf-8", errors="replace")
            relations.extend(service_command_relations(text, guest))

    # Deduplicate relations.
    unique_rel = {
        (r["source"], r["controller"], r["verb"], r["service"]): r
        for r in relations
    }

    return {
        "regularFilesScanned": scanned,
        "markerFiles": sorted(marker_files, key=lambda x: x["path"]),
        "serviceRelations": [unique_rel[k] for k in sorted(unique_rel)],
        "relevantSymlinks": relevant_symlinks(root),
        "elfObjects": sorted(elf_objects, key=lambda x: x["path"]),
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

    svctl_paths = [
        x["path"] for x in discovery["markerFiles"]
        if pathlib.PurePosixPath(x["path"]).name == "svctl"
    ]
    supervisor_paths = [
        x["path"] for x in discovery["markerFiles"]
        if "supervisor" in pathlib.PurePosixPath(x["path"]).name.lower()
    ]

    return {
        "schemaVersion": SCHEMA_VERSION,
        "experiment": EXPERIMENT,
        "classification": "SUPERVISOR_DISCOVERY_COMPLETE",
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
        "discovery": {
            **discovery,
            "svctlPaths": sorted(set(svctl_paths)),
            "supervisorNamedPaths": sorted(set(supervisor_paths)),
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
