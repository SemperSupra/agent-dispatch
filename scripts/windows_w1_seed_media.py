#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import shutil
import subprocess
from typing import Any

SEED_LABEL = "ADW1SEED"
REQUIRED_FILES = ("Autounattend.xml", "w1-bootstrap.ps1", "seed-contract.json")


class WindowsW1SeedMediaError(RuntimeError):
    pass


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def validate_seed_dir(seed_dir: pathlib.Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for name in REQUIRED_FILES:
        path = seed_dir / name
        if not path.is_file():
            raise WindowsW1SeedMediaError(f"missing required seed file: {name}")
        out[name] = sha256_file(path)
    contract = json.loads((seed_dir / "seed-contract.json").read_text(encoding="utf-8"))
    if contract.get("schema") != "windows-w1-unattend-seed/v1":
        raise WindowsW1SeedMediaError("seed contract schema mismatch")
    if contract.get("seed_volume_label") != SEED_LABEL:
        raise WindowsW1SeedMediaError("seed contract volume label mismatch")
    return out


def xorriso_command(seed_dir: pathlib.Path, out_iso: pathlib.Path) -> list[str]:
    return [
        "xorriso", "-as", "mkisofs", "-quiet",
        "-output", str(out_iso),
        "-volid", SEED_LABEL,
        "-joliet", "-rock",
        *[str(seed_dir / name) for name in REQUIRED_FILES],
    ]


def build(seed_dir: pathlib.Path, out_iso: pathlib.Path) -> dict[str, Any]:
    files = validate_seed_dir(seed_dir)
    if shutil.which("xorriso") is None:
        raise WindowsW1SeedMediaError("xorriso is required to build W1 seed media")
    out_iso.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(xorriso_command(seed_dir, out_iso), check=True)
    if not out_iso.is_file() or out_iso.stat().st_size <= 0:
        raise WindowsW1SeedMediaError("seed ISO was not created")
    return {
        "schema": "windows-w1-seed-media/v1",
        "classification": "SUPPORTED",
        "oracleSatisfied": True,
        "volume_label": SEED_LABEL,
        "source_contract": "windows-w1-unattend-seed/v1",
        "source_files": files,
        "iso": {
            "sha256": sha256_file(out_iso),
            "size_bytes": out_iso.stat().st_size,
        },
        "claim_boundary": "seed media construction only; Windows boot/install/runtime remains separate",
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--seed-dir", type=pathlib.Path, required=True)
    p.add_argument("--out-iso", type=pathlib.Path, required=True)
    p.add_argument("--receipt", type=pathlib.Path)
    a = p.parse_args()
    try:
        result = build(a.seed_dir, a.out_iso)
        code = 0
    except (OSError, ValueError, json.JSONDecodeError, subprocess.CalledProcessError, WindowsW1SeedMediaError) as exc:
        result = {
            "schema": "windows-w1-seed-media/v1",
            "classification": "HARNESS_FAILURE",
            "oracleSatisfied": False,
            "detail": f"{type(exc).__name__}: {exc}",
        }
        code = 2
    payload = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if a.receipt:
        a.receipt.write_text(payload, encoding="utf-8")
    print(payload, end="")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
