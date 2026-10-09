#!/usr/bin/env python3
"""Strict second-boundary allowlist for WinBot upstream 9.5 dependency probes."""
import hashlib
PARENT="8de3136c2e053b131ae83827676d54d0dc03362f"
from winbot_95_dependency_probe_patch import SIGNALS
def identity(raw):
    return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def once(s,a,b):
    if s.count(a)!=1: raise ValueError("receipt pin drift")
    return s.replace(a,b,1)
def patch(raw):
    if identity(raw)!=PARENT: raise ValueError("unqualified receipt parent")
    s=raw.decode("utf-8-sig")
    keys=",".join("'"+x+"'" for x in SIGNALS)
    validator="""
            $dependencyState = 'not_applicable'
            $dependencyFlags = $null
            $observedState = [string]$r.work_cells.a.dependency_probe_state
            if ($observedState -in @('not_applicable','valid','unavailable','missing_log')) {
              $dependencyState = $observedState
            } else {
              $dependencyState = 'unavailable'
            }
            if ($dependencyState -eq 'valid') {
              $needed = @(KEYLIST)
              $values = $r.work_cells.a.dependency_probe
              $ok = $values -is [System.Collections.IDictionary]
              if ($ok) {
                $observed = @($values.Keys)
                $ok = ($observed.Count -eq $needed.Count)
                foreach ($key in $needed) {
                  if ($observed -cnotcontains $key -or $values[$key] -isnot [bool]) {
                    $ok = $false
                    break
                  }
                }
              }
              if ($ok) {
                $dependencyFlags = [ordered]@{}
                foreach ($key in $needed) { $dependencyFlags[$key] = $values[$key] }
              } else {
                $dependencyState = 'unavailable'
              }
            }
""".replace("KEYLIST",keys)
    s=once(s,"            $out = [ordered]@{\n",validator+"            $out = [ordered]@{\n")
    s=once(s,"                critical_failure_flags = $criticalFlags\n",
           "                critical_failure_flags = $criticalFlags\n"
           "                dependency_probe_state = $dependencyState\n"
           "                dependency_probe = $dependencyFlags\n")
    return s.encode("utf-8")
