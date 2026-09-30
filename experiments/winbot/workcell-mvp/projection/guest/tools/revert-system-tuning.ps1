# WinBot — Revert System Tuning
# Restores original Windows settings saved by stage-provision.ps1.
# Idempotent: safe to run multiple times. Skips if no backup exists.
#
# Usage: powershell -File revert-system-tuning.ps1

$ErrorActionPreference = "Continue"
$originalsFile = "C:\WinBot\.system-originals.json"

if (-not (Test-Path $originalsFile)) {
    Write-Host "No originals backup found at $originalsFile — nothing to revert." -ForegroundColor Yellow
    exit 0
}

try { $originals = Get-Content $originalsFile -Raw | ConvertFrom-Json } catch {
    Write-Host "Failed to parse $originalsFile — skipping revert." -ForegroundColor Red
    exit 1
}

Write-Host "=== WinBot System Tuning Revert ===" -ForegroundColor Cyan
$restored = 0; $skipped = 0; $failed = 0

$originals.PSObject.Properties | ForEach-Object {
    $key = $_.Name
    $entry = $_.Value
    if (-not $entry.Existed) {
        Write-Host ("  REMOVE " + $key + " (was not set before tuning)") -ForegroundColor Gray
        try { Remove-ItemProperty -Path $entry.Path -Name $key -Force -ErrorAction SilentlyContinue; $restored++ } catch { $failed++; Write-Warning ("  FAILED: " + $key) }
    } else {
        Write-Host ("  RESTORE " + $key + " -> " + $entry.Value) -ForegroundColor Gray
        try {
            $type = if ($entry.Value -is [int]) { "DWord" } else { "String" }
            Set-ItemProperty -Path $entry.Path -Name $key -Value $entry.Value -Type $type -Force -ErrorAction Stop
            $restored++
        } catch { $failed++; Write-Warning ("  FAILED: " + $key) }
    }
}

# Services that were disabled — re-enable common ones
$reEnable = @("WSearch","SysMain","FontCache","wlidsvc","StiSvc")
foreach ($svcName in $reEnable) {
    try { Set-Service -Name $svcName -StartupType Manual -ErrorAction SilentlyContinue; Write-Host ("  Service " + $svcName + " -> Manual") -ForegroundColor Gray } catch {}
}

# Re-enable Windows Update
try {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
    Write-Host "  Windows Update -> re-enabled" -ForegroundColor Gray
} catch {}

# Remove the originals file so next run is a clean slate
Remove-Item $originalsFile -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host ("Revert complete: " + $restored + " restored, " + $skipped + " skipped, " + $failed + " failed") -ForegroundColor Green
Write-Host ""
Write-Host "NOTE: Some changes are irreversible:" -ForegroundColor Yellow
Write-Host "  - Removed AppX packages (bloatware) are gone permanently" -ForegroundColor Gray
Write-Host "  - DISM WinSxS cleanup cannot be undone" -ForegroundColor Gray
Write-Host "  - Cleared event logs are gone" -ForegroundColor Gray
Write-Host "  - System restore points (if any) were deleted" -ForegroundColor Gray
Write-Host "  Rebuild the golden master for a full factory reset." -ForegroundColor Gray
