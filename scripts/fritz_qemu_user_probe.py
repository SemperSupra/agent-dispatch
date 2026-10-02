#!/usr/bin/env python3
"""Public-safe FRITZ!OS E0/E1 probe: exact artifact -> SquashFS -> ELF ABI -> qemu-user.

The probe intentionally publishes metadata only. It never emits firmware/rootfs payloads.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import stat
import struct
import subprocess
import tarfile
from collections import Counter
from typing import Iterable

SCHEMA_VERSION = 1
EXPERIMENT = "fritz-qemu-user-e0-e1/v1"
SQUASHFS_MAGICS = (b"hsqs", b"sqsh")
MIPS_MACHINE = 8


def _run(argv: list[str], *, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _safe_tar_members(path: pathlib.Path) -> list[str]:
    names: list[str] = []
    with tarfile.open(path, "r:*") as tf:
        for member in tf.getmembers():
            p = pathlib.PurePosixPath(member.name)
            if p.is_absolute() or ".." in p.parts:
                raise ValueError(f"unsafe tar member path: {member.name!r}")
            if member.issym() or member.islnk():
                target = pathlib.PurePosixPath(member.linkname)
                if target.is_absolute() or ".." in target.parts:
                    raise ValueError(
                        f"unsafe tar link target: {member.name!r} -> {member.linkname!r}"
                    )
            names.append(member.name)
    return names


def download_exact(
    url: str,
    destination: pathlib.Path,
    *,
    expected_size: int,
    expected_sha256: str,
) -> dict:
    curl = shutil.which("curl")
    if not curl:
        raise RuntimeError("curl not installed")
    destination.parent.mkdir(parents=True, exist_ok=True)
    cp = _run(
        [
            curl,
            "--fail",
            "--location",
            "--retry",
            "4",
            "--retry-all-errors",
            "--silent",
            "--show-error",
            url,
            "-o",
            str(destination),
        ],
        timeout=180,
    )
    if cp.returncode != 0:
        raise RuntimeError(f"firmware download failed with curl exit {cp.returncode}")
    size = destination.stat().st_size
    if size != expected_size:
        raise RuntimeError(
            f"firmware size mismatch: expected {expected_size}, observed {size}"
        )
    digest = sha256_file(destination)
    if digest.lower() != expected_sha256.lower():
        raise RuntimeError(
            f"firmware sha256 mismatch: expected {expected_sha256}, observed {digest}"
        )
    return {"bytes": size, "sha256": digest}


def extract_outer(firmware: pathlib.Path, payload: pathlib.Path) -> list[str]:
    tar = shutil.which("tar")
    if not tar:
        raise RuntimeError("tar not installed")
    names = _safe_tar_members(firmware)
    payload.mkdir(parents=True, exist_ok=True)
    cp = _run(
        [
            tar,
            "--no-same-owner",
            "--no-same-permissions",
            "-xf",
            str(firmware),
            "-C",
            str(payload),
        ],
        timeout=120,
    )
    if cp.returncode != 0:
        raise RuntimeError(
            f"outer firmware extraction failed with tar exit {cp.returncode}"
        )
    return names


def regular_files(root: pathlib.Path) -> Iterable[pathlib.Path]:
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [
            d for d in dirnames if not pathlib.Path(dirpath, d).is_symlink()
        ]
        for name in filenames:
            p = pathlib.Path(dirpath, name)
            try:
                mode = p.lstat().st_mode
            except OSError:
                continue
            if stat.S_ISREG(mode):
                yield p


def find_squashfs_offsets(payload: pathlib.Path) -> list[tuple[pathlib.Path, int]]:
    offsets: list[tuple[pathlib.Path, int]] = []
    for path in regular_files(payload):
        try:
            data = path.read_bytes()
        except OSError:
            continue
        for magic in SQUASHFS_MAGICS:
            start = 0
            while True:
                off = data.find(magic, start)
                if off < 0:
                    break
                offsets.append((path, off))
                start = off + len(magic)
    seen = set()
    unique: list[tuple[pathlib.Path, int]] = []
    for item in sorted(offsets, key=lambda x: (str(x[0]), x[1])):
        key = (str(item[0]), item[1])
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique


def extract_squashfs_roots(
    payload: pathlib.Path,
    roots_dir: pathlib.Path,
    scratch: pathlib.Path,
) -> list[pathlib.Path]:
    unsquashfs = shutil.which("unsquashfs")
    if not unsquashfs:
        raise RuntimeError("unsquashfs not installed")
    roots_dir.mkdir(parents=True, exist_ok=True)
    scratch.mkdir(parents=True, exist_ok=True)
    extracted: list[pathlib.Path] = []
    for index, (source, offset) in enumerate(
        find_squashfs_offsets(payload), start=1
    ):
        carved = scratch / f"squashfs-{index}.img"
        with source.open("rb") as src, carved.open("wb") as dst:
            src.seek(offset)
            shutil.copyfileobj(src, dst, 1024 * 1024)
        dest = roots_dir / f"root-{index}"
        cp = _run(
            [unsquashfs, "-no-xattrs", "-d", str(dest), str(carved)],
            timeout=180,
        )
        try:
            carved.unlink()
        except OSError:
            pass
        if cp.returncode == 0 and dest.exists():
            extracted.append(dest)
        else:
            shutil.rmtree(dest, ignore_errors=True)
    return extracted


def parse_elf_header(path: pathlib.Path) -> dict | None:
    try:
        with path.open("rb") as f:
            data = f.read(20)
    except OSError:
        return None
    if len(data) < 20 or data[:4] != b"\x7fELF":
        return None
    elf_class = data[4]
    data_encoding = data[5]
    if data_encoding == 1:
        endian = "little"
        fmt = "<H"
    elif data_encoding == 2:
        endian = "big"
        fmt = ">H"
    else:
        return None
    machine = struct.unpack(fmt, data[18:20])[0]
    return {
        "class": {1: "ELF32", 2: "ELF64"}.get(
            elf_class, f"class-{elf_class}"
        ),
        "endian": endian,
        "machine": machine,
        "machineName": "MIPS" if machine == MIPS_MACHINE else f"EM_{machine}",
    }


def root_file_count(root: pathlib.Path) -> int:
    return sum(1 for _ in regular_files(root))


def select_root(roots: list[pathlib.Path]) -> pathlib.Path:
    if not roots:
        raise RuntimeError("no SquashFS roots extracted")
    return max(roots, key=lambda p: (root_file_count(p), str(p)))


def inventory_elf(root: pathlib.Path) -> dict:
    counts: Counter[tuple[str, str, int]] = Counter()
    mips_paths: list[str] = []
    elf_count = 0
    mips_count = 0
    for path in regular_files(root):
        header = parse_elf_header(path)
        if not header:
            continue
        elf_count += 1
        counts[
            (header["class"], header["endian"], header["machine"])
        ] += 1
        if header["machine"] == MIPS_MACHINE:
            mips_count += 1
            if len(mips_paths) < 20:
                mips_paths.append(
                    "/" + str(path.relative_to(root)).replace(os.sep, "/")
                )
    variants = [
        {
            "class": cls,
            "endian": endian,
            "machine": machine,
            "machineName": (
                "MIPS" if machine == MIPS_MACHINE else f"EM_{machine}"
            ),
            "count": count,
        }
        for (cls, endian, machine), count in sorted(counts.items())
    ]
    return {
        "elfCount": elf_count,
        "mipsElfCount": mips_count,
        "variants": variants,
        "mipsPathSamples": sorted(mips_paths),
    }


def qemu_for_header(header: dict) -> str:
    if header.get("machine") != MIPS_MACHINE:
        raise ValueError("candidate is not MIPS")
    endian = header.get("endian")
    if endian == "big":
        return "qemu-mips-static"
    if endian == "little":
        return "qemu-mipsel-static"
    raise ValueError(f"unsupported MIPS endian: {endian!r}")


def select_harmless_candidate(
    root: pathlib.Path,
) -> tuple[pathlib.Path, list[str], dict]:
    candidates = [
        ("bin/true", []),
        ("usr/bin/true", []),
        ("bin/busybox", ["true"]),
        ("usr/bin/busybox", ["true"]),
    ]
    for rel, args in candidates:
        path = root / rel
        try:
            mode = path.lstat().st_mode
        except OSError:
            continue
        if not stat.S_ISREG(mode):
            continue
        header = parse_elf_header(path)
        if header and header["machine"] == MIPS_MACHINE:
            return path, args, header
    raise RuntimeError(
        "no bounded harmless MIPS candidate found (/bin/true or BusyBox)"
    )


def dynamic_interpreter(path: pathlib.Path) -> str | None:
    readelf = shutil.which("readelf")
    if not readelf:
        return None
    cp = _run([readelf, "-l", str(path)], timeout=20)
    if cp.returncode != 0:
        return None
    match = re.search(
        r"Requesting program interpreter:\s*([^\]]+)\]",
        cp.stdout,
    )
    return match.group(1).strip() if match else None


def execute_candidate(
    root: pathlib.Path,
    candidate: pathlib.Path,
    candidate_args: list[str],
    header: dict,
) -> dict:
    qemu_name = qemu_for_header(header)
    qemu = shutil.which(qemu_name)
    if not qemu:
        raise RuntimeError(f"required emulator not installed: {qemu_name}")
    cp = _run(
        [qemu, "-L", str(root), str(candidate), *candidate_args],
        timeout=30,
    )
    return {
        "candidate": (
            "/" + str(candidate.relative_to(root)).replace(os.sep, "/")
        ),
        "candidateArgs": candidate_args,
        "candidateAbi": header,
        "dynamicInterpreter": dynamic_interpreter(candidate),
        "qemu": qemu_name,
        "exitCode": cp.returncode,
        "stdoutBytes": len(cp.stdout.encode("utf-8", errors="replace")),
        "stderrBytes": len(cp.stderr.encode("utf-8", errors="replace")),
        "oracleSatisfied": cp.returncode == 0,
    }


def run_probe(args: argparse.Namespace) -> dict:
    work = pathlib.Path(args.work_dir).resolve()
    firmware = work / "original" / "firmware.image"
    payload = work / "payload"
    roots_dir = work / "roots"
    scratch = work / "scratch"
    for p in (firmware.parent, payload, roots_dir, scratch):
        p.mkdir(parents=True, exist_ok=True)

    exact = download_exact(
        args.firmware_url,
        firmware,
        expected_size=args.expected_size,
        expected_sha256=args.expected_sha256,
    )
    outer_members = extract_outer(firmware, payload)
    roots = extract_squashfs_roots(payload, roots_dir, scratch)
    selected = select_root(roots)
    elf = inventory_elf(selected)
    if elf["mipsElfCount"] < 1:
        raise RuntimeError(
            "E0 failed: extracted root contains no observed MIPS ELF"
        )
    candidate, candidate_args, header = select_harmless_candidate(selected)
    execution = execute_candidate(
        selected,
        candidate,
        candidate_args,
        header,
    )

    return {
        "schemaVersion": SCHEMA_VERSION,
        "experiment": EXPERIMENT,
        "classification": (
            "SUPPORTED"
            if execution["oracleSatisfied"]
            else "ORACLE_FAILURE"
        ),
        "oracleSatisfied": bool(execution["oracleSatisfied"]),
        "target": {
            "kind": "public-runtime-download",
            "expectedBytes": args.expected_size,
            "expectedSha256": args.expected_sha256.lower(),
            "observedBytes": exact["bytes"],
            "observedSha256": exact["sha256"],
        },
        "e0": {
            "outerMemberCount": len(outer_members),
            "squashfsRootCount": len(roots),
            "selectedRootRegularFileCount": root_file_count(selected),
            "elf": elf,
            "oracleSatisfied": (
                len(roots) >= 1 and elf["mipsElfCount"] >= 1
            ),
        },
        "e1": execution,
        "safety": {
            "rawFirmwarePublished": False,
            "rootfsPublished": False,
            "binaryPayloadPublished": False,
            "networkTarget": "artifact-download-only",
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
        rc = 0 if receipt.get("oracleSatisfied") else 2
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
                "physicalRouterContact": False,
                "routerMutationAuthorized": False,
            },
        }
        rc = 3
    receipt_path.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "classification": receipt["classification"],
                "oracleSatisfied": receipt["oracleSatisfied"],
            },
            sort_keys=True,
        )
    )
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
