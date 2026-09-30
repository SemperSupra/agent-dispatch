# WinBot: Enable Unified Write Filter (UWF)
# Protects the system disk from writes — all changes go to a RAM overlay.
# Reset = reboot (overlay discarded), no re-image needed.
#
# UWF is ideal for Wyse 5070 thin clients with eMMC storage:
#   - Zero write wear on eMMC
#   - Instant reset (reboot = back to pristine)
#   - Configurable exclusions for logs, sessions, API token
#
# Prerequisites: Windows 10/11 Enterprise or Education
# (UWF is not available in Pro/Home editions)
#
# Usage:
#   .\enable-uwf.ps1
#   .\enable-uwf.ps1 -ProtectDrive C: -OverlaySizeMB 2048
#   .\enable-uwf.ps1 -Disable   # Turn off UWF
#   .\enable-uwf.ps1 -Status    # Show current UWF status

param(
    [string]$ProtectDrive = "C:",
    [int]$OverlaySizeMB = 2048,         # RAM overlay size (default 2 GB)
    [string[]]$Exclusions = @(),        # Additional paths to exclude from UWF
    [switch]$Disable,                   # Turn off UWF
    [switch]$Status                     # Show status only
)

$ErrorActionPreference = "Stop"

# VM guardrail — UWF is typically used on physical machines, but can be tested in VMs
if ((Test-Path "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters") -and -not $env:WINBOT_SKIP_VM_GUARDRAIL) {
    Write-Warning "Running inside a Hyper-V VM. UWF can be tested here but is designed for physical machines."
    Write-Warning "Set `$env:WINBOT_SKIP_VM_GUARDRAIL=1 to suppress this warning."
}

# ============================================================
# Helper functions
# ============================================================
function Get-UWFStatus {
    try {
        $uwf = Get-WMIObject -Namespace "root\standardcimv2\embedded" -Class "UWF_Filter" -ErrorAction Stop
        $volumes = Get-WMIObject -Namespace "root\standardcimv2\embedded" -Class "UWF_Volume" -ErrorAction SilentlyContinue
        $overlay = Get-WMIObject -Namespace "root\standardcimv2\embedded" -Class "UWF_Overlay" -ErrorAction SilentlyContinue
        $exclusions = Get-WMIObject -Namespace "root\standardcimv2\embedded" -Class "UWF_ExcludedFile" -ErrorAction SilentlyContinue

        return @{
            Enabled = $uwf.CurrentEnabled
            NextEnabled = $uwf.NextEnabled
            Volumes = @($volumes | ForEach-Object {
                @{
                    DriveLetter = $_.DriveLetter
                    Protected = $_.Protected
                    BindByDriveLetter = $_.BindByDriveLetter
                }
            })
            Overlay = if ($overlay) {
                @{
                    MaxSizeMB = [math]::Round($overlay.MaxSize / 1MB, 0)
                    CurrentUsageMB = [math]::Round($overlay.CurrentUsage / 1MB, 0)
                    AvailableMB = [math]::Round($overlay.Available / 1MB, 0)
                    CriticalOverlay = $overlay.CriticalOverlay
                }
            } else { $null }
            Exclusions = @($exclusions | ForEach-Object { $_.FileName })
        }
    } catch {
        return @{ Enabled = $false; Error = "UWF not available. Requires Windows Enterprise/Education." }
    }
}

# ============================================================
# Status mode
# ============================================================
if ($Status) {
    Write-Host "=== Unified Write Filter Status ===" -ForegroundColor Cyan
    $status = Get-UWFStatus
    if ($status.Error) {
        Write-Host "  $($status.Error)" -ForegroundColor Red
        Write-Host ""
        Write-Host "  UWF is only available on:" -ForegroundColor Yellow
        Write-Host "    - Windows 10/11 Enterprise" -ForegroundColor Yellow
        Write-Host "    - Windows 10/11 Education" -ForegroundColor Yellow
        Write-Host "    - Windows 10/11 IoT Enterprise" -ForegroundColor Yellow
        exit 1
    }

    Write-Host "  UWF Enabled:    $($status.Enabled)" -ForegroundColor $(if ($status.Enabled) { "Green" } else { "Yellow" })
    Write-Host "  Next Boot:      $($status.NextEnabled)" -ForegroundColor $(if ($status.NextEnabled) { "Green" } else { "Gray" })

    if ($status.Volumes) {
        Write-Host "  Volumes:" -ForegroundColor White
        foreach ($vol in $status.Volumes) {
            $protected = if ($vol.Protected) { "PROTECTED" } else { "unprotected" }
            Write-Host "    $($vol.DriveLetter): $protected" -ForegroundColor $(if ($vol.Protected) { "Green" } else { "Gray" })
        }
    }

    if ($status.Overlay) {
        $pct = if ($status.Overlay.MaxSizeMB -gt 0) { [math]::Round($status.Overlay.CurrentUsageMB / $status.Overlay.MaxSizeMB * 100, 1) } else { 0 }
        Write-Host "  Overlay:" -ForegroundColor White
        Write-Host "    Max:     $($status.Overlay.MaxSizeMB) MB" -ForegroundColor Gray
        Write-Host "    Used:    $($status.Overlay.CurrentUsageMB) MB ($pct%)" -ForegroundColor $(if ($pct -gt 80) { "Red" } else { "Green" })
        Write-Host "    Free:    $($status.Overlay.AvailableMB) MB" -ForegroundColor Green
        if ($status.Overlay.CriticalOverlay) { Write-Host "    WARNING: Overlay near capacity!" -ForegroundColor Red }
    }

    if ($status.Exclusions) {
        Write-Host "  Exclusions (${$($status.Exclusions.Count)}):" -ForegroundColor White
        foreach ($exc in $status.Exclusions) {
            Write-Host "    $exc" -ForegroundColor Gray
        }
    }

    exit 0
}

# ============================================================
# Disable mode
# ============================================================
if ($Disable) {
    Write-Host "=== Disabling Unified Write Filter ===" -ForegroundColor Cyan

    $uwf = Get-WMIObject -Namespace "root\standardcimv2\embedded" -Class "UWF_Filter" -ErrorAction Stop
    if (-not $uwf.CurrentEnabled) {
        Write-Host "  UWF is not currently enabled." -ForegroundColor Yellow
        exit 0
    }

    $uwf.FilterDisable()
    Write-Host "  UWF will be disabled after reboot." -ForegroundColor Green
    Write-Host "  REBOOT REQUIRED to apply changes." -ForegroundColor Yellow
    exit 0
}

# ============================================================
# Enable UWF
# ============================================================
Write-Host "=== Enabling Unified Write Filter ===" -ForegroundColor Cyan

# Check UWF is available
$status = Get-UWFStatus
if ($status.Error) {
    Write-Host "  $($status.Error)" -ForegroundColor Red
    Write-Host "  Consider using native VHDX boot instead:" -ForegroundColor Yellow
    Write-Host "    .\guest\deploy-physical-vhdx.ps1" -ForegroundColor Yellow
    exit 1
}

if ($status.Enabled) {
    Write-Host "  UWF is already enabled. Use -Status to see details." -ForegroundColor Yellow
    exit 0
}

# Get the UWF filter object
$uwf = Get-WMIObject -Namespace "root\standardcimv2\embedded" -Class "UWF_Filter" -ErrorAction Stop

# Set overlay size
try {
    $overlayConfig = Get-WMIObject -Namespace "root\standardcimv2\embedded" -Class "UWF_OverlayConfig" -ErrorAction SilentlyContinue
    if ($overlayConfig) {
        $overlayConfig.MaximumOverlaySize = $OverlaySizeMB * 1MB
        $overlayConfig.Put() | Out-Null
        Write-Host "  Overlay size: ${OverlaySizeMB} MB" -ForegroundColor Green
    }
} catch {
    Write-Warning "Could not set overlay size: $_"
}

# Protect the system drive
try {
    $volume = Get-WMIObject -Namespace "root\standardcimv2\embedded" -Class "UWF_Volume" -Filter "DriveLetter='$ProtectDrive'" -ErrorAction SilentlyContinue
    if (-not $volume) {
        # Volume not yet in UWF, add it
        $uwf.ProtectVolume($ProtectDrive)
        Write-Host "  Protected volume: ${ProtectDrive}:" -ForegroundColor Green
    } elseif (-not $volume.Protected) {
        $volume.Protect()
        Write-Host "  Protected volume: ${ProtectDrive}:" -ForegroundColor Green
    } else {
        Write-Host "  Volume already protected: ${ProtectDrive}:" -ForegroundColor Green
    }
} catch {
    throw "Failed to protect volume ${ProtectDrive}: $_"
}

# Configure exclusions (paths that CAN write to disk)
$defaultExclusions = @(
    "C:\WinBot\logs",
    "C:\WinBot\logs\api-stdout.log",
    "C:\WinBot\logs\api-stderr.log",
    "C:\WinBot\logs\security.log",
    "C:\WinBot\sessions",
    "C:\WinBot\.api_token",
    "C:\WinBot\.provisioned",
    "C:\WinBot\.system-originals.json",
    "C:\Windows\System32\winevt\Logs"   # Event logs survive reboots for diagnostics
)

$allExclusions = $defaultExclusions + $Exclusions

Write-Host "  Configuring file exclusions..." -ForegroundColor Gray
foreach ($exclusionPath in $allExclusions) {
    # Ensure parent directory exists
    $parent = Split-Path $exclusionPath -Parent
    if ($parent -and -not (Test-Path $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    # Touch the file if it doesn't exist
    if (-not (Test-Path $exclusionPath) -and $exclusionPath -like "*.*") {
        New-Item -ItemType File -Path $exclusionPath -Force | Out-Null
    } elseif (-not (Test-Path $exclusionPath)) {
        New-Item -ItemType Directory -Path $exclusionPath -Force | Out-Null
    }

    try {
        $existing = Get-WMIObject -Namespace "root\standardcimv2\embedded" -Class "UWF_ExcludedFile" -Filter "FileName='$exclusionPath'" -ErrorAction SilentlyContinue
        if (-not $existing) {
            $uwf.AddExclusion($exclusionPath)
            Write-Host "    [EXCLUDED] $exclusionPath" -ForegroundColor Green
        } else {
            Write-Host "    [already]  $exclusionPath" -ForegroundColor Gray
        }
    } catch {
        Write-Warning "    [SKIPPED] $exclusionPath — $_"
    }
}

# Registry exclusions (WinBot-related registry keys persist across reboots)
$regExclusions = @(
    "HKLM\SOFTWARE\WinBot",
    "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
)
Write-Host "  Configuring registry exclusions..." -ForegroundColor Gray
foreach ($regPath in $regExclusions) {
    try {
        $existing = Get-WMIObject -Namespace "root\standardcimv2\embedded" -Class "UWF_RegistryExclusion" -Filter "Key='$regPath'" -ErrorAction SilentlyContinue
        if (-not $existing) {
            $uwf.AddRegistryExclusion($regPath)
            Write-Host "    [EXCLUDED] $regPath" -ForegroundColor Green
        }
    } catch {
        Write-Warning "    [SKIPPED] $regPath — $_"
    }
}

# Enable UWF
Write-Host "  Enabling UWF..." -ForegroundColor Yellow
$uwf.FilterEnable()

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Unified Write Filter Enabled" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Protected:   ${ProtectDrive}:" -ForegroundColor Cyan
Write-Host "  Overlay:     ${OverlaySizeMB} MB (RAM)" -ForegroundColor Cyan
Write-Host "  Exclusions:  $($allExclusions.Count) paths" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "  REBOOT REQUIRED for UWF to take effect." -ForegroundColor Yellow
Write-Host ""
Write-Host "  After reboot, all disk writes go to RAM overlay." -ForegroundColor White
Write-Host "  To reset: simply reboot the machine." -ForegroundColor White
Write-Host "  Overlay is discarded on shutdown/restart." -ForegroundColor White
Write-Host ""
Write-Host "  To see status:   .\enable-uwf.ps1 -Status" -ForegroundColor Cyan
Write-Host "  To disable UWF:  .\enable-uwf.ps1 -Disable" -ForegroundColor Cyan

return @{
    Success = $true
    ProtectedDrive = $ProtectDrive
    OverlaySizeMB = $OverlaySizeMB
    Exclusions = $allExclusions
    RebootRequired = $true
}
