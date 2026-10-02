#!/usr/bin/env python3
"""Public-safe FRITZ H0-D1a targeted AVM OSP topology census.

The exact official 7590/8.25 OSP tarball is size + SHA-256 bound and reduced to
category-separated board/BSP path metadata. No source payload is retained as a
workflow artifact.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import tarfile

SCHEMA_VERSION = 2
EXPERIMENT = "fritz-h0-d1a-osp-topology/v2"

CATEGORIES = ("targetNamed", "mipsDts", "mtd", "bootEnvironment")

TOKEN_PATTERNS = {
    "linux_fs_start": re.compile(rb"(?<![A-Za-z0-9_])linux_fs_start(?![A-Za-z0-9_])", re.I),
    "mtdparts": re.compile(rb"(?<![A-Za-z0-9_])mtdparts(?![A-Za-z0-9_])", re.I),
    "tffs": re.compile(rb"(?<![A-Za-z0-9_])tffs(?![A-Za-z0-9_])", re.I),
    "adam2": re.compile(rb"(?<![A-Za-z0-9_])ADAM2(?![A-Za-z0-9_])"),
    "eva": re.compile(rb"(?<![A-Za-z0-9_])EVA(?![A-Za-z0-9_])"),
    "grx550": re.compile(rb"(?<![A-Za-z0-9_])GRX550(?![A-Za-z0-9_])", re.I),
    "grx5": re.compile(rb"(?<![A-Za-z0-9_])grx5(?![A-Za-z0-9_])", re.I),
}

NESTED_SUFFIXES = (".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".txz")


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fp:
        for chunk in iter(lambda: fp.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def download_exact(
    url: str,
    destination: pathlib.Path,
    expected_size: int,
    expected_sha256: str,
) -> dict:
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
    digest = sha256_file(destination)
    if size != expected_size:
        raise RuntimeError(f"OSP size mismatch: expected {expected_size}, observed {size}")
    if digest.lower() != expected_sha256.lower():
        raise RuntimeError("OSP SHA-256 mismatch")
    return {"bytes": size, "sha256": digest}


def normalize(name: str) -> str:
    while name.startswith("./"):
        name = name[2:]
    return name


def categories_for_path(name: str) -> list[str]:
    low = name.lower()
    out = []
    if re.search(r"(?:^|[/_.-])(7590|grx5|grx550|vrx|xrx|avm|tffs)(?:[/_.-]|$)", low):
        out.append("targetNamed")
    if (
        low.startswith("sources/kernel/linux/arch/mips/")
        and low.endswith((".dts", ".dtsi"))
    ):
        out.append("mipsDts")
    if (
        low.startswith("sources/kernel/linux/drivers/mtd/")
        or "/mtd/" in low
        or re.search(r"(?:^|[/_.-])mtd(?:[/_.-]|$)", low)
    ):
        out.append("mtd")
    if re.search(r"(?:^|[/_.-])(adam2|eva|bootloader|prom|environment)(?:[/_.-]|$)", low):
        out.append("bootEnvironment")
    return out


def scan_tokens(data: bytes) -> dict:
    return {
        key: {"present": bool(rx.search(data)), "count": len(rx.findall(data))}
        for key, rx in TOKEN_PATTERNS.items()
    }


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


def census(archive: pathlib.Path, per_category_limit: int) -> dict:
    total = 0
    regular = 0
    direct_dts = 0
    nested_total = 0
    categories = {key: [] for key in CATEGORIES}
    marker_files = {key: [] for key in CATEGORIES}
    nested_interesting = []

    with tarfile.open(archive, "r:*") as tf:
        for member in tf:
            total += 1
            name = normalize(member.name)
            low = name.lower()
            if member.isfile():
                regular += 1
            if low.endswith((".dts", ".dtsi")):
                direct_dts += 1

            cats = categories_for_path(name)
            for cat in cats:
                if len(categories[cat]) < per_category_limit:
                    categories[cat].append({
                        "path": name,
                        "kind": member_kind(member),
                        "size": int(member.size),
                    })

            if member.isfile() and low.endswith(NESTED_SUFFIXES):
                nested_total += 1
                if cats and len(nested_interesting) < per_category_limit:
                    nested_interesting.append({
                        "path": name,
                        "size": int(member.size),
                        "categories": cats,
                    })

            if (
                member.isfile()
                and cats
                and member.size <= 4 * 1024 * 1024
            ):
                fp = tf.extractfile(member)
                if fp is not None:
                    data = fp.read()
                    markers = scan_tokens(data)
                    if any(v["present"] for v in markers.values()):
                        for cat in cats:
                            if len(marker_files[cat]) < per_category_limit:
                                marker_files[cat].append({
                                    "path": name,
                                    "size": int(member.size),
                                    "fixedMarkers": markers,
                                })

    counts = {k: len(v) for k, v in categories.items()}
    classification = (
        "TARGETED_DIRECT_SOURCE_VISIBLE"
        if any(counts.values())
        else "TARGETED_SOURCE_NOT_FOUND"
    )
    return {
        "memberCount": total,
        "regularFileCount": regular,
        "directDtsDtsiCount": direct_dts,
        "nestedArchiveCount": nested_total,
        "classification": classification,
        "categories": categories,
        "categorySampleCounts": counts,
        "fixedMarkerFiles": marker_files,
        "interestingNestedArchives": nested_interesting,
    }


def run_probe(args: argparse.Namespace) -> dict:
    work = pathlib.Path(args.work_dir).resolve()
    archive = work / "source-files.tar.gz"
    exact = download_exact(
        args.osp_url,
        archive,
        args.expected_size,
        args.expected_sha256,
    )
    topology = census(archive, args.per_category_limit)
    return {
        "schemaVersion": SCHEMA_VERSION,
        "experiment": EXPERIMENT,
        "classification": "H0_D1A_TARGETED_OSP_CENSUS_PASS",
        "oracleSatisfied": topology["classification"] == "TARGETED_DIRECT_SOURCE_VISIBLE",
        "sourceArtifact": {
            "provider": "AVM OSP",
            "fileName": pathlib.PurePosixPath(args.osp_url).name,
            "expectedBytes": args.expected_size,
            "expectedSha256": args.expected_sha256.lower(),
            "observedBytes": exact["bytes"],
            "observedSha256": exact["sha256"],
            "rawArchivePublished": False,
        },
        "topology": topology,
        "interpretationBoundary": {
            "partitionLayoutAccepted": False,
            "dualBootSafetyAccepted": False,
            "linuxFsStartSemanticsAccepted": False,
            "pathAndFixedTokenEvidenceOnly": True,
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
    p.add_argument("--expected-sha256", required=True)
    p.add_argument("--work-dir", required=True)
    p.add_argument("--receipt", required=True)
    p.add_argument("--per-category-limit", type=int, default=120)
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
