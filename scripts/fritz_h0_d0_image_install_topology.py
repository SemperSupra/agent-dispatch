#!/usr/bin/env python3
"""Public-safe FRITZ H0-D0 exact image install-topology discovery.

Downloads the pinned FRITZ!OS image, validates exact identity, inventories the
small outer update archive, and reduces install-script content to a fixed
allowlist of boot/partition markers. Raw firmware/member/install content is
never emitted or retained as an artifact.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import pathlib
import re
import stat
import tarfile

_BASE_SCRIPT = pathlib.Path(__file__).with_name("fritz_qemu_user_probe.py")
_BASE_SPEC = importlib.util.spec_from_file_location("fritz_qemu_user_probe", _BASE_SCRIPT)
if _BASE_SPEC is None or _BASE_SPEC.loader is None:
    raise RuntimeError("unable to load fritz_qemu_user_probe.py")
base = importlib.util.module_from_spec(_BASE_SPEC)
_BASE_SPEC.loader.exec_module(base)

SCHEMA_VERSION = 1
EXPERIMENT = "fritz-h0-d0-image-install-topology/v1"

INSTALL_CANDIDATES = {
    "var/install",
    "./var/install",
    "var/install-new",
    "./var/install-new",
    "var/tmp/install",
    "./var/tmp/install",
}

SHAPE_PATHS = {
    "kernel": {"var/tmp/kernel.image", "./var/tmp/kernel.image"},
    "filesystem": {"var/tmp/filesystem.image", "./var/tmp/filesystem.image"},
    "uimg": {"var/firmware-update.uimg", "./var/firmware-update.uimg"},
    "fit": {"var/tmp/fit-image", "./var/tmp/fit-image"},
    "arm_kernel": {
        "var/remote/var/tmp/kernel.image",
        "./var/remote/var/tmp/kernel.image",
    },
    "arm_filesystem": {
        "var/remote/var/tmp/filesystem.image",
        "./var/remote/var/tmp/filesystem.image",
    },
    "x86_kernel": {
        "var/remote/var/tmp/x86/kernel.image",
        "./var/remote/var/tmp/x86/kernel.image",
    },
    "x86_filesystem": {
        "var/remote/var/tmp/x86/filesystem.image",
        "./var/remote/var/tmp/x86/filesystem.image",
    },
}

FIXED_MARKERS: dict[str, bytes] = {
    "linux_fs_start": b"linux_fs_start",
    "kernel_image": b"kernel.image",
    "filesystem_image": b"filesystem.image",
    "firmware_update_uimg": b"firmware-update.uimg",
    "fit_image": b"fit-image",
    "tffs": b"tffs",
    "adam2": b"ADAM2",
    "eva": b"EVA",
    "ubi": b"ubi",
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalize_member_name(name: str) -> str:
    while name.startswith("./"):
        name = name[2:]
    return name


def classify_shape(paths: list[str]) -> dict:
    normalized = {normalize_member_name(p) for p in paths}
    present = {
        key: any(normalize_member_name(p) in normalized for p in candidates)
        for key, candidates in SHAPE_PATHS.items()
    }

    if present["uimg"]:
        shape = "uimg-container"
    elif present["fit"]:
        shape = "fit-image"
    elif all(
        present[k]
        for k in ("arm_kernel", "arm_filesystem", "x86_kernel", "x86_filesystem")
    ):
        shape = "dual-architecture-components"
    elif present["kernel"] and present["filesystem"]:
        shape = "classic-kernel-filesystem"
    elif present["kernel"]:
        shape = "kernel-container-only"
    else:
        shape = "unknown"

    return {"classification": shape, "markers": present}


def scan_install_bytes(data: bytes) -> dict:
    lower = data.lower()
    markers = {}
    for key, marker in FIXED_MARKERS.items():
        haystack = lower if marker.lower() == marker else data
        needle = marker if haystack is data else marker.lower()
        markers[key] = {
            "present": needle in haystack,
            "count": haystack.count(needle),
        }

    text = data.decode("latin-1", errors="ignore")
    mtd_tokens = sorted(
        set(re.findall(r"(?<![A-Za-z0-9_])mtd(?:block)?(?:/)?\d{1,2}(?!\d)", text, flags=re.I)),
        key=lambda x: (x.lower(), x),
    )
    dev_mtd_tokens = sorted(
        set(re.findall(r"/dev/mtd(?:block)?/?\d{1,2}", text, flags=re.I)),
        key=lambda x: (x.lower(), x),
    )

    # Only fixed-schema identifiers are emitted. No arbitrary strings/lines.
    return {
        "bytes": len(data),
        "sha256": sha256_bytes(data),
        "fixedMarkers": markers,
        "mtdTokens": mtd_tokens[:64],
        "devMtdTokens": dev_mtd_tokens[:64],
    }


def inventory_outer(firmware: pathlib.Path) -> tuple[list[dict], list[dict]]:
    members: list[dict] = []
    install_scans: list[dict] = []
    with tarfile.open(firmware, "r:*") as tf:
        # Reuse the accepted traversal/link validation before reading members.
        base._safe_tar_members(firmware)
        for member in tf.getmembers():
            name = normalize_member_name(member.name)
            item = {
                "path": name,
                "kind": (
                    "file" if member.isfile()
                    else "dir" if member.isdir()
                    else "symlink" if member.issym()
                    else "hardlink" if member.islnk()
                    else "other"
                ),
                "size": int(member.size),
                "mode": int(member.mode),
                "executable": bool(member.mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)),
            }
            if member.isfile():
                f = tf.extractfile(member)
                if f is None:
                    raise RuntimeError(f"unable to read tar member: {name}")
                data = f.read()
                item["sha256"] = sha256_bytes(data)
                if name in {normalize_member_name(x) for x in INSTALL_CANDIDATES}:
                    install_scans.append({
                        "path": name,
                        "executable": item["executable"],
                        **scan_install_bytes(data),
                    })
            members.append(item)
    return members, install_scans


def run_probe(args: argparse.Namespace) -> dict:
    work = pathlib.Path(args.work_dir).resolve()
    firmware = work / "firmware.image"
    firmware.parent.mkdir(parents=True, exist_ok=True)

    exact = base.download_exact(
        args.firmware_url,
        firmware,
        expected_size=args.expected_size,
        expected_sha256=args.expected_sha256,
    )
    members, install_scans = inventory_outer(firmware)
    shape = classify_shape([m["path"] for m in members])

    return {
        "schemaVersion": SCHEMA_VERSION,
        "experiment": EXPERIMENT,
        "classification": (
            "H0_D0_DISCOVERY_PASS"
            if members and install_scans
            else "H0_D0_DISCOVERY_PARTIAL"
        ),
        "oracleSatisfied": bool(members),
        "target": {
            "expectedBytes": args.expected_size,
            "expectedSha256": args.expected_sha256.lower(),
            "observedBytes": exact["bytes"],
            "observedSha256": exact["sha256"],
        },
        "outerArchive": {
            "memberCount": len(members),
            "members": members,
            "shape": shape,
        },
        "installMetadata": {
            "candidateCount": len(install_scans),
            "candidates": install_scans,
            "installExecuted": False,
        },
        "interpretationBoundary": {
            "shapeIsStructuralEvidenceOnly": True,
            "dualBootSafetyInferred": False,
            "inactiveSlotSafetyInferred": False,
            "mtdWriteSemanticsAccepted": False,
            "bootEnvironmentMutationAuthorized": False,
        },
        "safety": {
            "rawFirmwarePublished": False,
            "rawMemberContentPublished": False,
            "rawInstallScriptPublished": False,
            "installScriptExecuted": False,
            "physicalRouterContact": False,
            "flashWriteAuthorized": False,
            "bootEnvironmentMutationAuthorized": False,
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
        rc = 0 if receipt.get("oracleSatisfied") else 2
    except Exception as exc:
        receipt = {
            "schemaVersion": SCHEMA_VERSION,
            "experiment": EXPERIMENT,
            "classification": "HARNESS_FAILURE",
            "oracleSatisfied": False,
            "error": {"type": type(exc).__name__, "message": str(exc)[:1000]},
            "safety": {
                "rawFirmwarePublished": False,
                "rawMemberContentPublished": False,
                "rawInstallScriptPublished": False,
                "installScriptExecuted": False,
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
