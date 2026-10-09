#!/usr/bin/env python3
"""Bounded WinBot upstream-dependency probe: exact-parent harness-only patch.

Requires previously qualified 9.5 control. No product/projection mutation.
Only predefined booleans from stage log and PowerShell Direct are returned.
"""
import hashlib
PARENT="e0853ca10c7b2474010fc271a73808f90afd0d94"
SIGNALS=("winget_version_seen","winget_not_found_seen","winget_config_apply_seen",
 "winget_individual_fallback_seen","winget_config_warning_seen","choco_fallback_seen",
 "choco_python_attempt_seen","choco_gsudo_attempt_seen","ssh_capability_install_attempt_seen",
 "remote_config_failure_seen","api_task_install_attempt_seen",
 "python_command_visible_at_probe","gsudo_command_visible_at_probe",
 "winget_command_visible_at_probe","choco_command_visible_at_probe",
 "python_binary_known_location_at_probe","sshd_service_exists_at_probe",
 "psdirect_elevated_at_probe")
def identity(raw):
    return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def once(text,old,new):
    if text.count(old)!=1: raise ValueError("pinned control anchor drift")
    return text.replace(old,new,1)
def patch(raw):
    if identity(raw)!=PARENT: raise ValueError("unqualified parent")
    s=raw.decode("utf-8-sig")
    s=once(s,"    $criticalFailureFlags = $null\n    $authorityRehydrationApplicable",
      "    $criticalFailureFlags = $null\n    $dependencyProbeState = 'not_applicable'\n"
      "    $dependencyProbe = $null\n    $authorityRehydrationApplicable")
    guest=r"""
                # Only on terminal 9.5 failure. Do not emit raw logs/paths/errors.
                $dependencyProbeState = 'not_applicable'
                $dependencyProbe = $null
                if ([string]$phase -ceq '9.5/9-ready' -and [string]$phaseStatus -ceq 'failed') {
                    $dependencyProbeState = 'unavailable'
                    try {
                        $phaseLog = 'C:\WinBot\logs\provision.log'
                        if (Test-Path -LiteralPath $phaseLog) {
                            $sample = (Get-Content -LiteralPath $phaseLog -Tail 400 -ErrorAction Stop) -join "BTn"
                            $psDirectElevated = $false
                            try {
                                $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
                                $psDirectElevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
                            } catch {}
                            $pythonKnown = $false
                            foreach ($candidate in @('C:\Python313\python.exe','C:\Python312\python.exe',
                                "$env:ProgramFiles\Python313\python.exe", "$env:LOCALAPPDATA\Programs\Python\Python313\python.exe")) {
                                if (Test-Path -LiteralPath $candidate) { $pythonKnown = $true; break }
                            }
                            $dependencyProbe = [ordered]@{
                                winget_version_seen = [bool]($sample -match 'WinGet version:')
                                winget_not_found_seen = [bool]($sample -match 'WinGet not found')
                                winget_config_apply_seen = [bool]($sample -match 'Applying winget configuration')
                                winget_individual_fallback_seen = [bool]($sample -match 'Falling back to individual winget install')
                                winget_config_warning_seen = [bool]($sample -match 'winget configure (?:exited|validation failed|failed)')
                                choco_fallback_seen = [bool]($sample -match 'Installing Chocolatey package manager')
                                choco_python_attempt_seen = [bool]($sample -match 'Running: choco install python313')
                                choco_gsudo_attempt_seen = [bool]($sample -match 'Installing gsudo elevation helper')
                                ssh_capability_install_attempt_seen = [bool]($sample -match 'Installing Windows OpenSSH Server capability')
                                remote_config_failure_seen = [bool]($sample -match 'Remote access config failed')
                                api_task_install_attempt_seen = [bool]($sample -match 'Installing WinBot API as logon Scheduled Task')
                                python_command_visible_at_probe = [bool](Get-Command python -ErrorAction SilentlyContinue)
                                gsudo_command_visible_at_probe = [bool](Get-Command gsudo -ErrorAction SilentlyContinue)
                                winget_command_visible_at_probe = [bool](Get-Command winget -ErrorAction SilentlyContinue)
                                choco_command_visible_at_probe = [bool](Get-Command choco -ErrorAction SilentlyContinue)
                                python_binary_known_location_at_probe = [bool]$pythonKnown
                                sshd_service_exists_at_probe = [bool](Get-Service sshd -ErrorAction SilentlyContinue)
                                psdirect_elevated_at_probe = [bool]$psDirectElevated
                            }
                            $dependencyProbeState = 'valid'
                        } else {
                            $dependencyProbeState = 'missing_log'
                        }
                    } catch {
                        $dependencyProbeState = 'unavailable'
                        $dependencyProbe = $null
                    }
                }
""".replace("BTn","`n")
    s=once(s,"                [PSCustomObject]@{\n                    CriticalFailureMarkerState = $criticalMarkerState",
      guest.rstrip("\n")+"\n"+"                [PSCustomObject]@{\n                    CriticalFailureMarkerState = $criticalMarkerState")
    s=once(s,"                    CriticalFailureFlags = $criticalFlags\n                    Token = $observedToken",
       "                    CriticalFailureFlags = $criticalFlags\n"
       "                    DependencyProbeState = $dependencyProbeState\n"
       "                    DependencyProbe = $dependencyProbe\n"
       "                    Token = $observedToken")
    s=once(s,"            $criticalFailureFlags = $guest.CriticalFailureFlags",
      "            $criticalFailureFlags = $guest.CriticalFailureFlags\n"
      "            $dependencyProbeState = [string]$guest.DependencyProbeState\n"
      "            $dependencyProbe = $guest.DependencyProbe")
    s=once(s,"        CriticalFailureFlags = $criticalFailureFlags\n        AuthorityRehydrationApplicable",
      "        CriticalFailureFlags = $criticalFailureFlags\n"
      "        DependencyProbeState = $dependencyProbeState\n"
      "        DependencyProbe = $dependencyProbe\n"
      "        AuthorityRehydrationApplicable")
    s=once(s,"    $record.work_cells.a.critical_failure_flags = $readyA.CriticalFailureFlags",
      "    $record.work_cells.a.critical_failure_flags = $readyA.CriticalFailureFlags\n"
      "    $record.work_cells.a.dependency_probe_state = [string]$readyA.DependencyProbeState\n"
      "    $record.work_cells.a.dependency_probe = $readyA.DependencyProbe")
    return s.encode("utf-8")
