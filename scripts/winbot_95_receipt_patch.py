#!/usr/bin/env python3
"""Fail-closed bounded receipt transformation for the WinBot 9.5 diagnostic.

Does not authorize or launch a sealed guest execution. This module edits a
pinned source workflow and must be tested before a fresh graph is admitted.
"""
from __future__ import annotations
import hashlib

PARENT_WORKFLOW_BLOB = "7ff7918f02736c95eab6100da51f6275d70387de"
FLAGS = (
    "api_present", "python_present", "token_present", "task_present",
    "authenticated_health", "gsudo_present", "sshd_capability_installed",
    "sshd_running", "sshd_startup_automatic", "ssh_firewall_enabled",
)

def git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()

def patch_receipt(parent: bytes) -> bytes:
    if git_blob_sha(parent) != PARENT_WORKFLOW_BLOB:
        raise ValueError("pinned workflow identity mismatch")
    src = parent.decode("utf-8-sig")
    marker = "            $out = [ordered]@{\n"
    if src.count(marker) != 1:
        raise ValueError("bounded receipt entrypoint mismatch")
    validator = """
            # Validate again on the trusted side before allowing diagnostic keys
            # into the bounded public artifact (sealed full result is untrusted).
            $criticalState = 'absent'
            $criticalFlags = $null
            $rawState = [string]$r.work_cells.a.critical_failure_marker_state
            if ($rawState -in @('absent','valid','malformed','unreadable')) {
              $criticalState = $rawState
            } elseif (-not [string]::IsNullOrWhiteSpace($rawState)) {
              $criticalState = 'malformed'
            }
            if ($criticalState -eq 'valid') {
              $keys = @('api_present','python_present','token_present','task_present','authenticated_health','gsudo_present','sshd_capability_installed','sshd_running','sshd_startup_automatic','ssh_firewall_enabled')
              $rawFlags = $r.work_cells.a.critical_failure_flags
              $valid = ($rawFlags -is [System.Collections.IDictionary])
              if ($valid) {
                $observedKeys = @($rawFlags.Keys)
                $valid = ($observedKeys.Count -eq $keys.Count)
                foreach ($key in $keys) {
                  if ($observedKeys -cnotcontains $key -or $rawFlags[$key] -isnot [bool]) {
                    $valid = $false
                    break
                  }
                }
              }
              if ($valid) {
                $criticalFlags = [ordered]@{}
                foreach ($key in $keys) { $criticalFlags[$key] = $rawFlags[$key] }
              } else {
                $criticalState = 'malformed'
              }
            }
"""
    src = src.replace(marker, validator.lstrip("\n") + marker, 1)
    old = "                provision_failure_tls_host_ready = $r.work_cells.a.provision_failure_tls_host_ready\n"
    new = (old +
           "                critical_failure_marker_state = $criticalState\n" +
           "                critical_failure_flags = $criticalFlags\n")
    if src.count(old) != 1:
        raise ValueError("bounded receipt whitelist anchor mismatch")
    return src.replace(old, new, 1).encode("utf-8")
