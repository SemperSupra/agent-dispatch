#!/usr/bin/env python3
"""Public-safe FRITZ H0-D1a AVM OSP archive topology census.

The official 7590/8.25 OSP tarball is downloaded ephemerally, size-bound to the
official directory entry, hashed, and reduced to path/marker metadata. No OSP
source payload is retained as a workflow artifact.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import tarfile

SCHEMA_VERSION = 1
EXPERIMENT = "fritz-h0-d1a-osp-topology/v1"

PATH_TERMS = (
    "7590", "grx5", "kernel", "linux", "dts", "dtsi", "device-tree",
    "partition", "mtd", "nand", "tffs", "eva", "adam2", "bootloader",
)

FIXED_MARKERS = {
    "linux_fs_start": b"linux_fs_start",
    "mtdparts": b"mtdparts",
    "mtd_partition": b"mtd_partition",
    "tffs": b"tffs",
    "adam2": b"ADAM2",
    "eva": b"EVA",
    "nand": b"nand",
    "grx550": b"GRX550",
    "grx5": b"grx5",
}

NESTED_SUFFIXES = (
    ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".txz",
)


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def download_exact_size(url: str, destination: pathlib.Path, expected_size: int) -> dict:
    destination.parent.mkdir(parents=True, exist_ok=True)
    cp = subprocess.run(
        ["curl", "--fail", "--location", "--silent", "--show-error",
         "--output", str(destination), url],
        check=False,
        capture_output=True,
        text=True,
        timeout=600,
    )
    if cp.returncode != 0:
        raise RuntimeError(
            f"OSP download failed (exit={cp.returncode}, stderrBytes={len(cp.stderr.encode())})"
        )
    size = destination.stat().st_size
    if size != expected_size:
        raise RuntimeError(f"OSP size mismatch: expected {expected_size}, observed {size}")
    return {"bytes": size, "sha256": sha256_file(destination)}


def normalize(name: str) -> str:
    while name.startswith("./"):
        name = name[2:]
    return name


def interesting_path(name: str) -> bool:
    low = name.lower()
    return any(term in low for term in PATH_TERMS)


def scan_fixed_markers(data: bytes) -> dict:
    out = {}
    lower = data.lower()
    for key, marker in FIXED_MARKERS.items():
        needle = marker.lower()
        count = lower.count(needle)
        out[key] = {"present": count > 0, "count": count}
    return out


def member_kind(member: tarfile.TarInfo) -> str:
    if member.isfile():
        return "file"
    if member.isdir():
        return "dir"
    if member.issym():
        return "symlink"
    if member.islnk():
        return "hardlink"
    return "other"


def census(archive: pathlib.Path, max_candidates: int) -> dict:
    total = 0
    regular = 0
    nested = []
    candidates = []
    direct_dts = 0
    marker_files = []

    with tarfile.open(archive, "r:*") as tf:
        for member in tf:
            total += 1
            name = normalize(member.name)
            low = name.lower()
            if member.isfile():
                regular += 1
            if member.isfile() and low.endswith(NESTED_SUFFIXES):
                if len(nested) < max_candidates:
                    nested.append({
                        "path": name,
                        "size": int(member.size),
                        "interesting": interesting_path(name),
                    })
            if low.endswith((".dts", ".dtsi")):
                direct_dts += 1

            is_candidate = interesting_path(name)
            if is_candidate and len(candidates) < max_candidates:
                item = {
                    "path": name,
                    "kind": member_kind(member),
                    "size": int(member.size),
                }
                candidates.append(item)

            if (
                member.isfile()
                and member.size <= 4 * 1024 * 1024
                and is_candidate
                and len(marker_files) < max_candidates
            ):
                f = tf.extractfile(member)
                if f is not None:
                    data = f.read()
                    markers = scan_fixed_markers(data)
                    if any(v["present"] for v in markers.values()):
                        marker_files.append({
                            "path": name,
                            "size": int(member.size),
                            "fixedMarkers": markers,
                        })

    interesting_nested = [x for x in nested if x["interesting"]]
    topology = (
        "DIRECT_SOURCE_TOPOLOGY_VISIBLE"
        if direct_dts > 0 or marker_files
        else "NESTED_SOURCE_ARCHIVE_REQUIRED"
        if nested
        else "SOURCE_TOPOLOGY_NOT_FOUND"
    )
    return {
        "memberCount": total,
        "regularFileCount": regular,
        "directDtsDtsiCount": direct_dts,
        "nestedArchiveCount": len(nested),
        "interestingNestedArchives": interesting_nested[:max_candidates],
        "candidatePaths": candidates[:max_candidates],
        "fixedMarkerFiles": marker_files[:max_candidates],
        "classification": topology,
    }


def run_probe(args: argparse.Namespace) -> dict:
    work = pathlib.Path(args.work_dir).resolve()
    archive = work / "source-files.tar.gz"
    exact = download_exact_size(args.osp_url, archive, args.expected_size)
    source = census(archive, args.max_candidates)
    return {
        "schemaVersion": SCHEMA_VERSION,
        "experiment": EXPERIMENT,
        "classification": "H0_D1A_OSP_CENSUS_PASS",
        "oracleSatisfied": source["memberCount"] > 0,
        "sourceArtifact": {
            "provider": "AVM OSP",
            "fileName": pathlib.PurePosixPath(args.osp_url).name,
            "expectedBytesFromOfficialIndex": args.expected_size,
            "observedBytes": exact["bytes"],
            "observedSha256": exact["sha256"],
            "rawArchivePublished": False,
        },
        "topology": source,
        "interpretationBoundary": {
            "partitionLayoutAccepted": False,
            "dualBootSafetyAccepted": False,
            "linuxFsStartSemanticsAccepted": False,
            "nestedArchiveContentNotRecursivelyExpanded": True,
        },
        "safety": {
            "rawOspArchivePublished": False,
            "sourcePayloadPublished": False,
            "physicalRouterContact": False,
            "flashWriteAuthorized": False,
            "bootEnvironmentMutationAuthorized": False,
        },
    }


def parse_args(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--osp-url", required=True)
    p.add_argument("--expected-size", type=int, required=True)
    p.add_argument("--work-dir", required=True)
    p.add_argument("--receipt", required=True)
    p.add_argument("--max-candidates", type=int, default=250)
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    receipt_path = pathlib.Path(args.receipt)
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        receipt = run_probe(args)
        rc = 0 if receipt["oracleSatisfied"] else 2
    except Exception as exc:
        receipt = {
            "schemaVersion": SCHEMA_VERSION,
            "experiment": EXPERIMENT,
            "classification": "HARNESS_FAILURE",
            "oracleSatisfied": False,
            "error": {"type": type(exc).__name__, "message": str(exc)[:1000]},
            "safety": {
                "rawOspArchivePublished": False,
                "sourcePayloadPublished": False,
                "physicalRouterContact": False,
                "flashWriteAuthorized": False,
                "bootEnvironmentMutationAuthorized": False,
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
