#!/usr/bin/env python3
"""Bounded, public-synthetic C++ ResMed prior-art qualification.

This is a third-party format-candidate bakeoff, not Mark Medical source code or
an interpretation of patient data. Tests are allowlisted in-memory/generated
synthetic upstream cases only. Never acquire private media or repository files.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tempfile

SCHEMA = "public-cpap-format-bakeoff/v1"
UPSTREAM = "https://github.com/hms-homelab/hms-cpapdash-parser.git"
SHA = "d14acb58012449af75b0c15c0bfb1eb173b60a1f"
TEST_FILTER = "EDFFileTest.*:EDFParserHardening.*:EveMultiBlock.*:STRFamily.*:AirSense11Summary.*:EdfRecordCount.*"
MAX_BYTES = 32768
SAFE_ARCH = {"X64": "x86_64", "ARM64": "aarch64"}


class NotQualified(ValueError):
    pass


def command(args: list[str], *, timeout: int = 60, cwd: Path | None = None) -> bytes:
    if not args or any(not isinstance(x, str) for x in args):
        raise NotQualified("invalid fixed test invocation")
    try:
        p = subprocess.run(args, cwd=cwd, stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise NotQualified("public test invocation unavailable") from exc
    if p.returncode or len(p.stdout) > MAX_BYTES:
        raise NotQualified("public test command failed")
    return p.stdout


def run(receipt_path: Path) -> dict:
    if os.environ.get("GITHUB_REPOSITORY") != "SemperSupra/agent-dispatch":
        raise NotQualified("public executor identity absent")
    arch = os.environ.get("RUNNER_ARCH")
    if arch not in SAFE_ARCH or platform.machine() != SAFE_ARCH[arch] or os.getuid() == 0:
        raise NotQualified("unexpected runner architecture/privilege")
    with tempfile.TemporaryDirectory(prefix="public-cpap-format-") as tmp:
        base = Path(tmp)
        src, build = base / "source", base / "build"
        src.mkdir()
        command(["git", "init", "-q", str(src)], timeout=15)
        command(["git", "-C", str(src), "remote", "add", "origin", UPSTREAM], timeout=15)
        command(["git", "-C", str(src), "fetch", "-q", "--depth", "1", "origin", SHA], timeout=50)
        command(["git", "-C", str(src), "checkout", "-q", "--detach", "FETCH_HEAD"], timeout=15)
        observed = command(["git", "-C", str(src), "rev-parse", "HEAD"]).decode().strip()
        if observed != SHA:
            raise NotQualified("unqualified upstream source revision")
        license_text = (src / "LICENSE").read_bytes()
        if b"MIT License" not in license_text[:300] or len(license_text) > 16_000:
            raise NotQualified("upstream license gate failed")
        # GTest is a test-only OS dependency installed on this disposable runner.
        # Versions are not pinned here: this bakeoff cannot authorize release.
        command(["sudo", "apt-get", "update", "-qq"], timeout=50)
        command(["sudo", "apt-get", "install", "-y", "-qq", "libgtest-dev"], timeout=60)
        # Every tested file is synthetic: in-memory generated EDF, event blocks,
        # STR family labels, AirSense11 protobuf and EDF record-count fixtures.
        # Explicit filters intentionally avoid fixtures from real donor cards.
        command(["cmake", "-S", str(src), "-B", str(build),
                 "-DCPAPDASH_PARSER_BUILD_TESTS=ON",
                 "-DCPAPDASH_PARSER_WITH_LOWENSTEIN=OFF",
                 "-DCPAPDASH_PARSER_WITH_PHILIPS=OFF",
                 "-DCPAPDASH_PARSER_WITH_SEFAM=OFF",
                 "-DCPAPDASH_PARSER_WITH_BMC=OFF",
                 "-DCMAKE_BUILD_TYPE=Release"], timeout=45)
        command(["cmake", "--build", str(build), "--parallel", "2"], timeout=90)
        result = command([str(build / "run_tests"), "--gtest_filter=" + TEST_FILTER,
                          "--gtest_brief=1"], timeout=35)
        # Empty/no-match gtest runs are never a PASS, even with exit code 0.
        match = re.search(rb"\[\s*PASSED\s*\]\s+(\d+) tests?", result)
        if not match or int(match.group(1)) < 20:
            raise NotQualified("synthetic test coverage insufficient")
        receipt = {
            "schema": SCHEMA,
            "status": "CANDIDATE_ONLY",
            "public_synthetic": True,
            "upstream_sha": SHA,
            "upstream_license": "MIT",
            "license_sha256": hashlib.sha256(license_text).hexdigest(),
            "source_sha": os.environ.get("GITHUB_SHA", ""),
            "run_id": os.environ.get("GITHUB_RUN_ID", ""),
            "runner_arch": arch,
            "machine": SAFE_ARCH[arch],
            "compiler_family": "g++/C++17",
            "selected_suites": [
                "EDFFileTest", "EDFParserHardening", "EveMultiBlock",
                "STRFamily", "AirSense11Summary", "EdfRecordCount",
            ],
            "passed_synthetic_tests": int(match.group(1)),
            "production_promotable": False,
            "clinical_semantics_qualified": False,
            "private_source_processed": False,
        }
        receipt_path.parent.mkdir(parents=True, exist_ok=True)
        receipt_path.write_text(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n")
        return receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        run(args.receipt)
    except (NotQualified, ValueError, OSError):
        print('{"qualification":"NOT_QUALIFIED"}')
        return 2
    print('{"qualification":"CANDIDATE_SYNTHETIC_PASS"}')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
