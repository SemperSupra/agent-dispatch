#!/usr/bin/env python3
"""Deterministic, harness-only WinBot 9.5 readiness diagnostic patch.

Input is the exact previously authorized PowerShell control Git blob. The
output is a new control candidate, never an implicit authorization to execute.
No product, projected guest payload, secret, or provision marker is modified.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

PARENT_BLOB = "e8156d246bab134a38f33a4f49e5cd18831d4257"
FLAGS = (
    "api_present", "python_present", "token_present", "task_present",
    "authenticated_health", "gsudo_present", "sshd_capability_installed",
    "sshd_running", "sshd_startup_automatic", "ssh_firewall_enabled",
)


def git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def replace_once(source: str, old: str, new: str) -> str:
    if source.count(old) != 1:
        raise ValueError("control anchor not unique / expected identity changed")
    return source.replace(old, new, 1)


def patch_control(original: bytes) -> bytes:
    if git_blob_sha(original) != PARENT_BLOB:
        raise ValueError("parent control Git blob identity mismatch")
    text = original.decode("utf-8-sig")
    text = replace_once(
        text,
        "    $provisionFailureTlsHostReady = $null\n    $authorityRehydrationApplicable",
        "    $provisionFailureTlsHostReady = $null\n"
        "    $criticalFailureMarkerState = 'absent'\n"
        "    $criticalFailureFlags = $null\n"
        "    $authorityRehydrationApplicable",
    )
    text = replace_once(
        text,
        "                $failurePath = 'C:\\WinBot\\.provision-failed'\n"
        "                if (Test-Path -LiteralPath $failurePath) {",
        "                $failurePath = 'C:\\WinBot\\.provision-failed'\n"
        "                $criticalMarkerState = 'absent'\n"
        "                $criticalFlags = $null\n"
        "                if (Test-Path -LiteralPath $failurePath) {",
    )
    # Guest PowerShell Direct uses Windows PowerShell 5.1: -AsHashtable is
    # unavailable there. Explicit exact-case property inspection is required.
    read_marker = """
                        if ([string]$phase -ceq '9.5/9-ready' -and [string]$phaseStatus -ceq 'failed') {
                            $criticalMarkerState = 'malformed'
                            $required = @('api_present','python_present','token_present','task_present','authenticated_health','gsudo_present','sshd_capability_installed','sshd_running','sshd_startup_automatic','ssh_firewall_enabled')
                            $names = @($failureObj.PSObject.Properties | ForEach-Object { [string]$_.Name })
                            if ($names.Count -eq ($required.Count + 2) -and
                                $names -ccontains 'phase' -and $names -ccontains 'timestamp' -and
                                [string]$failureObj.phase -ceq '9.5/9-ready') {
                                $valid = $true
                                foreach ($name in $names) {
                                    if ($name -cnotin ($required + @('phase','timestamp'))) { $valid = $false; break }
                                }
                                if ($valid) {
                                    $values = [ordered]@{}
                                    foreach ($name in $required) {
                                        $p = @($failureObj.PSObject.Properties | Where-Object { $_.Name -ceq $name })
                                        if ($p.Count -ne 1 -or $p[0].Value -isnot [bool]) { $valid = $false; break }
                                        $values[$name] = [bool]$p[0].Value
                                    }
                                    if ($valid) {
                                        $criticalFlags = $values
                                        $criticalMarkerState = 'valid'
                                    }
                                }
                            }
                        }
"""
    text = replace_once(
        text,
        "                        $failureReason = [string]$failureObj.reason",
        "                        $failureReason = [string]$failureObj.reason" + read_marker.rstrip("\n"),
    )
    # Reading/JSON parsing failure is distinguished from file absence; never
    # propagate raw exception text or marker fields.
    text = replace_once(
        text,
        "                    } catch {}\n                }\n                [PSCustomObject]@{\n"
        "                    Token = $observedToken",
        "                    } catch {\n"
        "                        if ([string]$phase -ceq '9.5/9-ready' -and [string]$phaseStatus -ceq 'failed') {\n"
        "                            $criticalMarkerState = 'unreadable'\n"
        "                            $criticalFlags = $null\n"
        "                        }\n"
        "                    }\n"
        "                }\n"
        "                [PSCustomObject]@{\n"
        "                    CriticalFailureMarkerState = $criticalMarkerState\n"
        "                    CriticalFailureFlags = $criticalFlags\n"
        "                    Token = $observedToken",
    )
    text = replace_once(
        text,
        "            $provisionFailureTlsHostReady = $guest.FailureTlsHostReady",
        "            $provisionFailureTlsHostReady = $guest.FailureTlsHostReady\n"
        "            $criticalFailureMarkerState = [string]$guest.CriticalFailureMarkerState\n"
        "            $criticalFailureFlags = $guest.CriticalFailureFlags",
    )
    text = replace_once(
        text,
        "        if ([string]$provisionStatus -eq 'failed' -and -not [string]::IsNullOrWhiteSpace([string]$provisionFailureReason)) {",
        "        if ([string]$provisionStatus -eq 'failed' -and\n"
        "            (([string]$provisionPhase -eq '9.5/9-ready') -or\n"
        "             (-not [string]::IsNullOrWhiteSpace([string]$provisionFailureReason)))) {",
    )
    text = replace_once(
        text,
        "        ProvisionFailureTlsHostReady = $provisionFailureTlsHostReady\n        AuthorityRehydrationApplicable",
        "        ProvisionFailureTlsHostReady = $provisionFailureTlsHostReady\n"
        "        CriticalFailureMarkerState = $criticalFailureMarkerState\n"
        "        CriticalFailureFlags = $criticalFailureFlags\n"
        "        AuthorityRehydrationApplicable",
    )
    text = replace_once(
        text,
        "    $record.work_cells.a.provision_failure_tls_host_ready = $readyA.ProvisionFailureTlsHostReady",
        "    $record.work_cells.a.provision_failure_tls_host_ready = $readyA.ProvisionFailureTlsHostReady\n"
        "    $record.work_cells.a.critical_failure_marker_state = [string]$readyA.CriticalFailureMarkerState\n"
        "    $record.work_cells.a.critical_failure_flags = $readyA.CriticalFailureFlags",
    )
    return text.encode("utf-8")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("input", type=Path)
    ap.add_argument("output", type=Path)
    ap.add_argument("--expected-output-blob", required=True)
    args = ap.parse_args()
    target = patch_control(args.input.read_bytes())
    observed = git_blob_sha(target)
    if observed != args.expected_output_blob:
        raise SystemExit("candidate control expected Git identity mismatch")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(target)
    print("control identity verified", observed)


if __name__ == "__main__":
    main()
