#!/usr/bin/env python3
"""Public-safe WinGet Configuration preflight on hosted Windows.

This is a methodology/substrate qualifier only. It never invokes the bare
`winget configure -f ...` apply path. It validates and tests one synthetic
public configuration, recording exact runner/tool evidence for later placement.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import platform
import shutil
import subprocess
import tempfile
import time
from typing import Any

SCHEMA = "github-runner-winget-config-preflight/v1"
PROBE_VERSION = "winget-config-preflight/1"

SYNTHETIC_CONFIGURATION = """\
# yaml-language-server: $schema=https://aka.ms/configuration-dsc-schema/0.2
properties:
  resources:
    - resource: Microsoft.WinGet.DSC/WinGetPackage
      id: git
      directives:
        description: Public synthetic Git package presence check
      settings:
        id: Git.Git
        source: winget
  configurationVersion: 0.2.0
"""


def _run(argv: list[str], *, timeout: int = 180) -> tuple[int | None, str, str, float]:
    started = time.monotonic()
    try:
        cp = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return cp.returncode, cp.stdout.strip(), cp.stderr.strip(), time.monotonic() - started
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return None, stdout.strip(), (stderr.strip() or f"timeout after {timeout}s"), time.monotonic() - started
    except (OSError, subprocess.SubprocessError) as exc:
        return None, "", str(exc), time.monotonic() - started


def _base(label: str) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "provenance": {
            "requested_label": label,
            "workflow_sha": os.environ.get("GITHUB_SHA", ""),
            "run_id": os.environ.get("GITHUB_RUN_ID", ""),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
            "image_os": os.environ.get("ImageOS"),
            "image_version": os.environ.get("ImageVersion"),
            "probe_version": PROBE_VERSION,
        },
        "runner": {
            "system": platform.system(),
            "machine": platform.machine(),
            "runner_arch": os.environ.get("RUNNER_ARCH"),
        },
        "configuration": {
            "resource_type": "Microsoft.WinGet.DSC/WinGetPackage",
            "package_id": "Git.Git",
            "configuration_sha256": hashlib.sha256(SYNTHETIC_CONFIGURATION.encode("utf-8")).hexdigest(),
            "desired_state_apply_performed": False,
        },
        "result": {
            "classification": "INCONCLUSIVE",
            "passed": False,
            "reason": "not executed",
            "evidence": {},
        },
        "warnings": [
            "this qualifies only the synthetic public WinGet Configuration procedure on the observed hosted image",
            "winget configure test may materialize processor/resource cache state but this probe never invokes desired-state apply",
            "no private configuration or native WinBot acceptance is implied",
        ],
    }


def _finish(
    receipt: dict[str, Any],
    classification: str,
    passed: bool,
    reason: str,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    receipt["result"] = {
        "classification": classification,
        "passed": passed,
        "reason": reason,
        "evidence": evidence,
    }
    return receipt


def qualify_winget_config_preflight(label: str) -> dict[str, Any]:
    receipt = _base(label)
    if platform.system() != "Windows":
        return _finish(
            receipt,
            "SKIPPED_GUARDRAIL",
            False,
            "WinGet Configuration preflight is Windows-only",
            {},
        )

    winget = shutil.which("winget")
    if not winget:
        return _finish(
            receipt,
            "SKIPPED_GUARDRAIL",
            False,
            "winget is not present on PATH",
            {},
        )

    version_code, version_out, version_err, version_elapsed = _run([winget, "--version"], timeout=30)
    if version_code != 0:
        return _finish(
            receipt,
            "ORACLE_FAILURE",
            False,
            "winget version probe failed",
            {
                "winget_path": winget,
                "version_exit": version_code,
                "version_stdout": version_out[:1200],
                "version_stderr": version_err[:1200],
                "version_elapsed_seconds": round(version_elapsed, 3),
            },
        )

    help_code, help_out, help_err, help_elapsed = _run([winget, "configure", "--help"], timeout=30)
    if help_code != 0:
        return _finish(
            receipt,
            "ORACLE_FAILURE",
            False,
            "winget configure surface is unavailable",
            {
                "winget_path": winget,
                "winget_version": version_out,
                "configure_help_exit": help_code,
                "configure_help_stdout": help_out[:1600],
                "configure_help_stderr": help_err[:1600],
                "configure_help_elapsed_seconds": round(help_elapsed, 3),
            },
        )

    with tempfile.TemporaryDirectory(prefix="agent-dispatch-winget-config-") as td:
        config_path = pathlib.Path(td) / "synthetic.winget"
        config_path.write_text(SYNTHETIC_CONFIGURATION, encoding="utf-8", newline="\n")

        validate_cmd = [
            winget,
            "configure",
            "validate",
            "-f",
            str(config_path),
            "--disable-interactivity",
        ]
        validate_code, validate_out, validate_err, validate_elapsed = _run(validate_cmd)
        if validate_code != 0:
            return _finish(
                receipt,
                "ORACLE_FAILURE",
                False,
                "synthetic WinGet configuration did not validate",
                {
                    "winget_path": winget,
                    "winget_version": version_out,
                    "validate_exit": validate_code,
                    "validate_stdout": validate_out[-6000:],
                    "validate_stderr": validate_err[-4000:],
                    "validate_elapsed_seconds": round(validate_elapsed, 3),
                },
            )

        test_cmd = [
            winget,
            "configure",
            "test",
            "-f",
            str(config_path),
            "--accept-configuration-agreements",
            "--disable-interactivity",
        ]
        test_code, test_out, test_err, test_elapsed = _run(test_cmd)

    evidence = {
        "winget_path": winget,
        "winget_version": version_out,
        "configure_help_exit": help_code,
        "configure_help_excerpt": (help_out or help_err)[:1600],
        "configure_help_elapsed_seconds": round(help_elapsed, 3),
        "validate_exit": validate_code,
        "validate_stdout": validate_out[-6000:],
        "validate_stderr": validate_err[-4000:],
        "validate_elapsed_seconds": round(validate_elapsed, 3),
        "test_exit": test_code,
        "test_stdout": test_out[-6000:],
        "test_stderr": test_err[-4000:],
        "test_elapsed_seconds": round(test_elapsed, 3),
    }

    if test_code is None:
        return _finish(
            receipt,
            "ORACLE_FAILURE",
            False,
            "winget configure test did not reach a bounded terminal result",
            evidence,
        )
    if test_code != 0:
        return _finish(
            receipt,
            "ORACLE_FAILURE",
            False,
            "winget configure validate passed but test did not report desired-state conformance",
            evidence,
        )

    return _finish(
        receipt,
        "SUPPORTED",
        True,
        "winget configure validate and test both passed for the synthetic public configuration",
        evidence,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--label", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    receipt = qualify_winget_config_preflight(args.label)
    path = pathlib.Path(args.out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"WINGET_CONFIG_RECEIPT={path}")
    print(json.dumps(receipt, indent=2, sort_keys=True))
    # The receipt is the oracle. Keep the runner step alive long enough to
    # upload evidence even when the synthetic task is unsupported/nonconverged.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
