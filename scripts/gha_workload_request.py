#!/usr/bin/env python3
"""Agent Dispatch #485: typed, no-secret GHA request -> fixed CPU workload.

This is a binding/planner, not a scheduler. Only committed, reviewed JSON from
a fixed repository directory and a fixed workload/runner allowlist is admitted.
Never execute argv/shell/code/URL received from a request. No credential access.
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
import sys

SCHEMA = "gha-workload-request/v1"
RECEIPT = "gha-workload-receipt/v1"
ROOT = Path(__file__).resolve().parents[1]
REQUEST_DIR = ROOT / "requests" / "gha"
SAFE_PATH = re.compile(r"^requests/gha/[a-z0-9][a-z0-9-]{2,63}\.json$")
SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{2,79}$")
SHAPES = {"ubuntu-24.04": "x86_64", "ubuntu-24.04-arm": "aarch64"}
WORKLOADS = {"arithmetic-oracle", "sealed-contract-native", "microsoft-devproxy-mock", "azurite-blob-transport"}
FIELDS = {"schema", "assignment_id", "runner", "workload", "timeout_seconds",
          "data_class", "max_attempts", "max_cost_usd"}
MAX_BYTES = 4096


class Denied(ValueError):
    pass


def read_request(name: str) -> tuple[dict, str]:
    if not SAFE_PATH.fullmatch(name):
        raise Denied("REQUEST_PATH_NOT_ALLOWED")
    path = ROOT / name
    if path.is_symlink() or not path.is_file() or path.resolve().parent != REQUEST_DIR.resolve():
        raise Denied("REQUEST_NOT_REVIEWED_LOCAL_FILE")
    raw = path.read_bytes()
    if len(raw) < 10 or len(raw) > MAX_BYTES:
        raise Denied("REQUEST_BYTES_OUT_OF_BOUNDS")
    try:
        obj = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise Denied("REQUEST_JSON_INVALID") from exc
    if not isinstance(obj, dict) or set(obj) != FIELDS or obj.get("schema") != SCHEMA:
        raise Denied("REQUEST_SCHEMA_NOT_ALLOWED")
    if not isinstance(obj["assignment_id"], str) or not SAFE_ID.fullmatch(obj["assignment_id"]):
        raise Denied("ASSIGNMENT_ID_INVALID")
    if not isinstance(obj["runner"], str) or obj["runner"] not in SHAPES:
        raise Denied("RUNNER_SHAPE_NOT_ALLOWED")
    if not isinstance(obj["workload"], str) or obj["workload"] not in WORKLOADS:
        raise Denied("WORKLOAD_NOT_ALLOWED")
    if type(obj["timeout_seconds"]) is not int or not 1 <= obj["timeout_seconds"] <= 240:
        raise Denied("RUNTIME_BUDGET_OUT_OF_BOUNDS")
    if obj["data_class"] != "public-synthetic":
        raise Denied("DATA_CLASS_NOT_ALLOWED")
    if type(obj["max_attempts"]) is not int or obj["max_attempts"] != 1:
        raise Denied("ATTEMPT_BUDGET_OUT_OF_BOUNDS")
    if type(obj["max_cost_usd"]) not in (int, float) or obj["max_cost_usd"] != 0:
        raise Denied("COST_BUDGET_NOT_ZERO")
    return obj, hashlib.sha256(raw).hexdigest()


def plan(name: str) -> dict:
    doc, digest = read_request(name)
    return {
        "schema": SCHEMA,
        "request_path": name,
        "request_sha256": digest,
        "assignment_id": doc["assignment_id"],
        "runner": doc["runner"],
        "expected_machine": SHAPES[doc["runner"]],
        "workload": doc["workload"],
        "timeout_seconds": doc["timeout_seconds"],
        "data_class": doc["data_class"],
        "max_attempts": 1,
        "max_cost_usd": 0,
        "operation": "cpu-public-safe",
        "source_ref": "checked-out-default-branch",
    }


def _execute(workload: str, timeout: int) -> dict:
    if workload == "azurite-blob-transport":
        # Fixed source, no input-substituted command, public Azurite emulator account only.
        try:
            cp = subprocess.run(
                ["bash", "scripts/qualify_azurite_transport.sh"],
                cwd=ROOT, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            return {"oracle_verified": False, "classification": "FAIL_TIMEOUT",
                    "emulator_only": True, "provider_access_verified": False,
                    "verdict_sha256": None}
        p = Path(os.environ.get("RUNNER_TEMP", "/nonexistent")) / "azurite-blob" / "verified.json"
        if cp.returncode != 0 or p.is_symlink() or not p.is_file() or p.stat().st_size > 8192:
            return {"oracle_verified": False, "classification": "FAIL_EMULATOR",
                    "emulator_only": True, "provider_access_verified": False,
                    "verdict_sha256": None}
        raw = p.read_bytes()
        try:
            verdict = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            verdict = {}
        accepted = (
            isinstance(verdict, dict) and
            verdict.get("schema") == "azurite-transport-independent-verdict/v1" and
            verdict.get("classification") == "EMULATOR_ONLY_PASS" and
            verdict.get("provider_access_verified") is False and
            verdict.get("revision_changed") is True and
            verdict.get("write_replay_blocked") is True and
            verdict.get("stale_write_blocked") is True and
            verdict.get("stale_read_blocked") is True and
            verdict.get("fresh_client_recovered") is True and
            verdict.get("source_sha") == os.environ.get("GITHUB_SHA") and
            verdict.get("native_run_id") == os.environ.get("GITHUB_RUN_ID"))
        return {"oracle_verified": bool(accepted),
                "classification": "PASS" if accepted else "FAIL_EMULATOR_VERDICT",
                "emulator_only": True, "provider_access_verified": False,
                "verdict_sha256": hashlib.sha256(raw).hexdigest() if accepted else None}
    if workload == "microsoft-devproxy-mock":
        # Fixed reviewed public-synthetic source only; never shell-interpolated inputs.
        try:
            cp = subprocess.run(
                ["bash", "scripts/qualify_microsoft_devproxy.sh"],
                cwd=ROOT, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            return {"oracle_verified": False, "classification": "FAIL_TIMEOUT",
                    "mock_only": True, "provider_access_verified": False,
                    "verdict_sha256": None}
        verdict_path = Path(os.environ.get("RUNNER_TEMP", "/nonexistent")) / "microsoft-mock" / "verified.json"
        if cp.returncode != 0 or not verdict_path.is_file():
            return {"oracle_verified": False, "classification": "FAIL_MOCK_CANARY",
                    "mock_only": True, "provider_access_verified": False,
                    "verdict_sha256": None}
        raw = verdict_path.read_bytes()
        try:
            verdict = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            verdict = {}
        accepted = (isinstance(verdict, dict) and
                    verdict.get("classification") == "MOCK_ONLY_PASS" and
                    verdict.get("verified") is True and
                    verdict.get("provider_access_verified") is False and
                    verdict.get("source_sha") == os.environ.get("GITHUB_SHA") and
                    verdict.get("run_id") == os.environ.get("GITHUB_RUN_ID"))
        return {"oracle_verified": bool(accepted),
                "classification": "PASS" if accepted else "FAIL_MOCK_VERDICT",
                "mock_only": True, "provider_access_verified": False,
                "verdict_sha256": hashlib.sha256(raw).hexdigest() if accepted else None}
    if workload == "arithmetic-oracle":
        nums = [i*i for i in range(256)]
        ok = sum(nums) == 5559680 and len(nums) == 256
        return {"oracle_verified": ok, "classification": "PASS" if ok else "FAIL_MATH",
                "task_count": len(nums),
                "fixture_sha256": hashlib.sha256(
                    json.dumps(nums, separators=(",", ":")).encode()).hexdigest()}
    if workload == "sealed-contract-native":
        try:
            cp = subprocess.run(
                [sys.executable, "-m", "unittest", "discover", "-s", "tests",
                 "-p", "test_sealed_public_execution.py"],
                cwd=ROOT, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            return {"oracle_verified": False, "classification": "FAIL_TIMEOUT"}
        return {"oracle_verified": cp.returncode == 0,
                "classification": "PASS" if cp.returncode == 0 else "FAIL_TESTS"}
    raise Denied("WORKLOAD_NOT_ALLOWED")


def run(name: str, expected_digest: str) -> dict:
    p = plan(name)
    if not re.fullmatch(r"[0-9a-f]{64}", expected_digest) or expected_digest != p["request_sha256"]:
        raise Denied("REQUEST_DIGEST_CHANGED")
    system = platform.system()
    machine = platform.machine()
    runner_arch = os.environ.get("RUNNER_ARCH", "")
    verified = system == "Linux" and machine == p["expected_machine"] and (
        runner_arch in (("X64",) if machine == "x86_64" else ("ARM64",))
    )
    result = _execute(p["workload"], p["timeout_seconds"]) if verified else {
        "classification": "FAIL_RUNNER_SHAPE", "oracle_verified": False,
    }
    return {
        "schema": RECEIPT,
        "assignment_id": p["assignment_id"],
        "request_sha256": p["request_sha256"],
        "request_path": name,
        "workload": p["workload"],
        "requested_runner": p["runner"],
        "observed_architecture": machine if system == "Linux" else "unqualified",
        "shape_verified": verified,
        "data_class": "public-synthetic",
        "source_sha": os.environ.get("GITHUB_SHA", ""),
        "run_id": os.environ.get("GITHUB_RUN_ID", ""),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
        "result": result,
        "qualified": verified and result["oracle_verified"] is True,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--action", choices=["plan", "run"], required=True)
    parser.add_argument("--request", required=True)
    parser.add_argument("--digest", default="")
    parser.add_argument("--github-output")
    parser.add_argument("--receipt")
    opts = parser.parse_args()
    try:
        p = plan(opts.request)
        if opts.action == "plan":
            if opts.github_output:
                with open(opts.github_output, "a", encoding="utf-8") as fh:
                    for key in ("runner", "request_sha256", "assignment_id"):
                        fh.write(f"{key}={p[key]}\n")
            print(json.dumps(p, sort_keys=True))
            return 0
        if not opts.receipt:
            raise Denied("RECEIPT_PATH_REQUIRED")
        result = run(opts.request, opts.digest)
        encoded = json.dumps(result, sort_keys=True, indent=2) + "\n"
        dest = Path(opts.receipt)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(encoded, encoding="utf-8")
        print("GHA_REQUEST_QUALIFIED=" + str(result["qualified"]).lower())
        print("GHA_RECEIPT_SHA256=" + hashlib.sha256(encoded.encode()).hexdigest())
        return 0 if result["qualified"] else 2
    except (Denied, OSError):
        print("GHA_REQUEST_BLOCKED", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
