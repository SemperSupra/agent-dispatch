#!/usr/bin/env python3
"""Small oracle-backed primitive exercises for passively qualified GitHub runners."""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import platform
import shutil
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import github_runner_census as passive

PROBE_VERSION = "public-primitive/1"

def _run(argv: list[str], timeout: int = 15) -> tuple[int | None, str, str]:
    try:
        cp = subprocess.run(argv, check=False, capture_output=True, text=True, timeout=timeout)
        return cp.returncode, cp.stdout.strip(), cp.stderr.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        return None, "", str(exc)

def _cap(name: str, *, observed, installed, callable_, exercised, oracle,
         classification: str, reason: str, evidence=None) -> dict:
    return {
        "name": name,
        "advertised": None,
        "observed": observed,
        "installed": installed,
        "callable": callable_,
        "exercised": exercised,
        "oracleSatisfied": oracle,
        "classification": classification,
        "reason": reason,
        "evidence": evidence,
    }

def probe_kvm_api() -> dict:
    path = pathlib.Path("/dev/kvm")
    if platform.system() != "Linux":
        return _cap("linux:kvm-api", observed=False, installed=False, callable_=False,
                    exercised=False, oracle=False, classification="SKIPPED_GUARDRAIL",
                    reason="KVM probe is Linux-only")
    if not path.exists():
        return _cap("linux:kvm-api", observed=False, installed=False, callable_=False,
                    exercised=False, oracle=False, classification="NEGATIVE_OBSERVATION",
                    reason="/dev/kvm not present")
    try:
        import fcntl
        fd = os.open(str(path), os.O_RDWR | getattr(os, "O_CLOEXEC", 0))
        try:
            version = fcntl.ioctl(fd, 0xAE00, 0)  # KVM_GET_API_VERSION
        finally:
            os.close(fd)
    except Exception as exc:
        return _cap("linux:kvm-api", observed=True, installed=True, callable_=False,
                    exercised=True, oracle=False, classification="ORACLE_FAILURE",
                    reason=f"KVM_GET_API_VERSION failed: {type(exc).__name__}: {exc}")
    ok = version == 12
    return _cap("linux:kvm-api", observed=True, installed=True, callable_=ok,
                exercised=True, oracle=ok,
                classification="SUPPORTED" if ok else "ORACLE_FAILURE",
                reason=f"KVM_GET_API_VERSION returned {version}",
                evidence={"api_version": version})

def probe_docker_daemon() -> dict:
    docker = shutil.which("docker")
    if not docker:
        return _cap("docker:daemon-api", observed=False, installed=False, callable_=False,
                    exercised=False, oracle=False, classification="NEGATIVE_OBSERVATION",
                    reason="docker command not found")
    code, out, err = _run([docker, "version", "--format", "{{json .Server}}"], timeout=15)
    ok = code == 0 and bool(out) and out != "null"
    evidence = {"exit_code": code, "server_json": out[:2000] if out else None,
                "stderr": err[:1000] if err else None}
    return _cap("docker:daemon-api", observed=True, installed=True, callable_=ok,
                exercised=True, oracle=ok,
                classification="SUPPORTED" if ok else "ORACLE_FAILURE",
                reason="Docker server API answered" if ok else "Docker CLI present but server API did not answer",
                evidence=evidence)

def probe_rosetta() -> dict:
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        return _cap("macos:rosetta-exec", observed=False, installed=False, callable_=False,
                    exercised=False, oracle=False, classification="SKIPPED_GUARDRAIL",
                    reason="Rosetta execution probe applies only to arm64 macOS")
    marker = pathlib.Path("/Library/Apple/usr/share/rosetta/rosetta")
    if not marker.exists():
        return _cap("macos:rosetta-exec", observed=False, installed=False, callable_=False,
                    exercised=False, oracle=False, classification="NEGATIVE_OBSERVATION",
                    reason="Rosetta marker not present")
    code, out, err = _run(["/usr/bin/arch", "-x86_64", "/usr/bin/true"])
    ok = code == 0
    return _cap("macos:rosetta-exec", observed=True, installed=True, callable_=ok,
                exercised=True, oracle=ok,
                classification="SUPPORTED" if ok else "ORACLE_FAILURE",
                reason="x86_64 /usr/bin/true executed under Rosetta" if ok else "Rosetta execution failed",
                evidence={"exit_code": code, "stderr": err[:1000] if err else None})

def probe_apple_toolchain() -> dict:
    if platform.system() != "Darwin":
        return _cap("macos:toolchain-query", observed=False, installed=False, callable_=False,
                    exercised=False, oracle=False, classification="SKIPPED_GUARDRAIL",
                    reason="Apple toolchain probe is macOS-only")
    xcodebuild = shutil.which("xcodebuild")
    xcrun = shutil.which("xcrun")
    if not xcodebuild or not xcrun:
        return _cap("macos:toolchain-query", observed=False, installed=False, callable_=False,
                    exercised=False, oracle=False, classification="NEGATIVE_OBSERVATION",
                    reason="xcodebuild/xcrun not both present")
    xv, xout, xerr = _run([xcodebuild, "-version"])
    cv, cout, cerr = _run([xcrun, "--find", "clang"])
    sv, sout, serr = _run([xcrun, "simctl", "list", "runtimes", "-j"], timeout=20)
    runtimes = []
    if sv == 0 and sout:
        try:
            payload = json.loads(sout)
            for item in payload.get("runtimes", []):
                runtimes.append({
                    "name": item.get("name"),
                    "identifier": item.get("identifier"),
                    "version": item.get("version"),
                    "isAvailable": item.get("isAvailable"),
                })
        except json.JSONDecodeError:
            pass
    ok = xv == 0 and cv == 0 and sv == 0
    return _cap("macos:toolchain-query", observed=True, installed=True, callable_=ok,
                exercised=True, oracle=ok,
                classification="SUPPORTED" if ok else "ORACLE_FAILURE",
                reason="Xcode, clang lookup, and Simulator runtime query succeeded" if ok
                       else "one or more Apple toolchain queries failed",
                evidence={
                    "xcode_version": xout[:1000] if xout else None,
                    "clang_path": cout[:1000] if cout else None,
                    "runtimes": runtimes,
                    "exit_codes": {"xcodebuild": xv, "xcrun_find": cv, "simctl": sv},
                    "stderr": {
                        "xcodebuild": xerr[:500] if xerr else None,
                        "xcrun_find": cerr[:500] if cerr else None,
                        "simctl": serr[:500] if serr else None,
                    },
                })

PROBES = {
    "kvm-api": probe_kvm_api,
    "docker-daemon": probe_docker_daemon,
    "rosetta": probe_rosetta,
    "apple-toolchain": probe_apple_toolchain,
}

def build_receipt(probe: str, label: str | None = None) -> dict:
    receipt = passive.build_receipt(label)
    receipt["provenance"]["probe_version"] = f"{PROBE_VERSION}:{probe}"
    receipt["capabilities"].append(PROBES[probe]())
    receipt["warnings"].append("primitive result proves only the named oracle; it does not imply workload qualification")
    return receipt

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--probe", choices=sorted(PROBES), required=True)
    parser.add_argument("--label")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    receipt = build_receipt(args.probe, args.label)
    path = pathlib.Path(args.out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"PRIMITIVE_RECEIPT={path}")
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
