#!/usr/bin/env python3
"""Bounded capacity characterization for an already-passively-qualified runner."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import zlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import github_runner_census as passive

PROBE_VERSION = "public-capacity/1"
HASH_BYTES = 256 * 1024 * 1024
DISK_BYTES = 128 * 1024 * 1024
MEMORY_BYTES = 64 * 1024 * 1024
COMPRESS_BYTES = 32 * 1024 * 1024
SPAWN_COUNT = 20

def _timed(fn):
    start = time.perf_counter()
    value = fn()
    return value, time.perf_counter() - start

def _hash_probe() -> dict:
    block = b"\0" * (4 * 1024 * 1024)
    count = HASH_BYTES // len(block)
    def work():
        h = hashlib.sha256()
        for _ in range(count):
            h.update(block)
        return h.hexdigest()
    digest, seconds = _timed(work)
    return {"name": "capacity:sha256", "value": seconds, "unit": "seconds",
            "note": f"{HASH_BYTES} bytes; digest={digest}"}

def _memory_probe() -> dict:
    src = bytearray(MEMORY_BYTES)
    def work():
        dst = bytearray(src)
        return len(dst)
    copied, seconds = _timed(work)
    return {"name": "capacity:memory-copy", "value": seconds, "unit": "seconds",
            "note": f"{copied} bytes copied once"}

def _disk_probe(directory: pathlib.Path) -> list[dict]:
    path = directory / "capacity-probe.bin"
    block = b"\0" * (4 * 1024 * 1024)
    count = DISK_BYTES // len(block)
    try:
        def write():
            with path.open("wb", buffering=0) as fh:
                for _ in range(count):
                    fh.write(block)
                os.fsync(fh.fileno())
            return path.stat().st_size
        size, write_seconds = _timed(write)

        def read():
            total = 0
            with path.open("rb", buffering=0) as fh:
                while True:
                    chunk = fh.read(len(block))
                    if not chunk:
                        break
                    total += len(chunk)
            return total
        read_size, read_seconds = _timed(read)
        return [
            {"name": "capacity:disk-write", "value": write_seconds, "unit": "seconds",
             "note": f"{size} bytes sequential write + fsync"},
            {"name": "capacity:disk-read", "value": read_seconds, "unit": "seconds",
             "note": f"{read_size} bytes sequential read"},
        ]
    finally:
        try:
            path.unlink()
        except FileNotFoundError:
            pass

def _compression_probe() -> list[dict]:
    pattern = bytes(range(256))
    data = pattern * (COMPRESS_BYTES // len(pattern))
    compressed, compress_seconds = _timed(lambda: zlib.compress(data, level=6))
    restored, decompress_seconds = _timed(lambda: zlib.decompress(compressed))
    if restored != data:
        raise RuntimeError("compression round-trip mismatch")
    return [
        {"name": "capacity:zlib-compress", "value": compress_seconds, "unit": "seconds",
         "note": f"{len(data)} input bytes -> {len(compressed)} compressed bytes"},
        {"name": "capacity:zlib-decompress", "value": decompress_seconds, "unit": "seconds",
         "note": f"{len(compressed)} compressed bytes -> {len(restored)} output bytes"},
    ]

def _spawn_probe() -> dict:
    exe = sys.executable
    def work():
        for _ in range(SPAWN_COUNT):
            subprocess.run([exe, "-c", "pass"], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=10)
        return SPAWN_COUNT
    count, seconds = _timed(work)
    return {"name": "capacity:process-spawn", "value": seconds, "unit": "seconds",
            "note": f"{count} fresh Python processes"}

def build_capacity_receipt(label: str | None = None) -> dict:
    receipt = passive.build_receipt(label)
    receipt["provenance"]["probe_version"] = PROBE_VERSION
    memory_available = receipt["resources"]["memory"].get("available_bytes")
    storage = receipt["resources"].get("storage", [])
    max_free = max((s.get("free_bytes", 0) for s in storage), default=0)

    reasons = []
    if isinstance(memory_available, int) and memory_available < 256 * 1024 * 1024:
        reasons.append("less than 256 MiB observed available memory")
    if max_free < 512 * 1024 * 1024:
        reasons.append("less than 512 MiB observed free storage")

    if reasons:
        receipt["capabilities"].append({
            "name": "probe:capacity",
            "advertised": None,
            "observed": True,
            "installed": True,
            "callable": True,
            "exercised": False,
            "oracleSatisfied": False,
            "classification": "SKIPPED_GUARDRAIL",
            "reason": "; ".join(reasons),
            "evidence": None,
        })
        receipt["warnings"].append("capacity probe skipped by resource guardrail")
        return receipt

    observations = []
    temp_root = pathlib.Path(os.environ.get("RUNNER_TEMP") or tempfile.gettempdir())
    temp_root.mkdir(parents=True, exist_ok=True)
    observations.append(_hash_probe())
    observations.append(_memory_probe())
    observations.extend(_disk_probe(temp_root))
    observations.extend(_compression_probe())
    observations.append(_spawn_probe())
    receipt["observations"].extend(observations)
    receipt["capabilities"].append({
        "name": "probe:capacity",
        "advertised": None,
        "observed": True,
        "installed": True,
        "callable": True,
        "exercised": True,
        "oracleSatisfied": True,
        "classification": "SUPPORTED",
        "reason": "bounded CPU/memory/disk/compression/process probes completed",
        "evidence": {"observation_names": [o["name"] for o in observations]},
    })
    receipt["warnings"].append("capacity timings are feasibility observations, not benchmarks or service guarantees")
    return receipt

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--label")
    args = parser.parse_args()
    receipt = build_capacity_receipt(args.label)
    path = pathlib.Path(args.out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"CAPACITY_RECEIPT={path}")
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
