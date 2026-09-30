# WinBot: Build a provisioning VHD containing the guest/ files
# The VHD is attached to new VMs during unattended Windows install
# so FirstLogonCommands can copy the WinBot API and scripts from D:\
#
# Usage: powershell -ExecutionPolicy Bypass -File build-provision-vhd.ps1 [-OutputPath <path>]

param(
    [string]$OutputPath = "C:\WinBot\master\provision.vhdx",
    [string]$GuestDir = $null
)

$ErrorActionPreference = "Stop"; if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw "This script requires Administrator privileges. Run PowerShell as Administrator." }

# Resolve guest directory
if (-not $GuestDir) {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $GuestDir = $scriptDir  # This script lives in guest/ itself
}

if (-not (Test-Path $GuestDir)) {
    throw "Guest directory not found: $GuestDir"
}

# === WinBot Guardrail: VM-Only ===
function Test-IsHyperVVM {
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    if ($cs -and $cs.Manufacturer -eq "Microsoft Corporation" -and $cs.Model -eq "Virtual Machine") { return $true }
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters") { return $true }
    $hvServices = @("vmicheartbeat", "vmictimesync", "vmickvpexchange", "vmicshutdown", "vmicvss")
    foreach ($svcName in $hvServices) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq "Running") { return $true }
    }
    $bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
    if ($bios -and $bios.SMBIOSBIOSVersion -match "Hyper-V|VRTUAL") { return $true }
    return $false
}
# This is a build tool â€" it CAN run on the host. It creates a VHD, doesn't modify settings.
# No host guardrail needed for this script.

Write-Host "[WinBot] Building provisioning VHD..." -ForegroundColor Cyan
Write-Host "  Source:      $GuestDir" -ForegroundColor Gray
Write-Host "  Destination: $OutputPath" -ForegroundColor Gray

# Suppress Explorer pop-ups during VHD mount/format
$shellHwWasRunning = $false
try {
    $svc = Get-Service -Name ShellHWDetection -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'Running') { $shellHwWasRunning = $true; Stop-Service ShellHWDetection -Force -ErrorAction SilentlyContinue }
} catch {}

# Remove existing VHD if present
if (Test-Path $OutputPath) {
    Write-Host "  Removing existing VHD..." -ForegroundColor Yellow
    try {
        Dismount-VHD -Path $OutputPath -ErrorAction SilentlyContinue | Out-Null
    } catch {}
    try {
        Remove-Item $OutputPath -Force
    } catch {
        Write-Host "  File locked -- renaming out of the way..." -ForegroundColor Yellow
        $suffix = 1
        while (Test-Path "$OutputPath.old$suffix") { $suffix += 1 }
        Rename-Item $OutputPath "$(Split-Path $OutputPath -Leaf).old$suffix" -Force
        Write-Host "  Renamed to .old$suffix" -ForegroundColor Gray
    }
}

# Create a small VHDX (50MB: FAT32 minimum is ~33MB, scripts are ~50KB)
Write-Host "  Creating VHDX..." -ForegroundColor Gray
New-VHD -Path $OutputPath -SizeBytes 50MB -Dynamic -ErrorAction Stop | Out-Null

# Mount the VHDX
Write-Host "  Mounting VHDX..." -ForegroundColor Gray
$mountResult = Mount-VHD -Path $OutputPath -Passthru -ErrorAction Stop
try {
    Start-Sleep -Seconds 2

    # Get the disk number and initialize
    $disk = $mountResult | Get-Disk
    if (-not $disk) {
        $disk = Get-Disk | Where-Object { $_.Location -like "*$OutputPath*" } | Select-Object -First 1
    }
    if (-not $disk) { throw "Could not find mounted disk for: $OutputPath" }

    Write-Host "  Disk number: $($disk.Number)" -ForegroundColor Gray

    if ($disk.PartitionStyle -eq "RAW") {
        Initialize-Disk -Number $disk.Number -PartitionStyle MBR -ErrorAction Stop
        Start-Sleep -Seconds 2
    }

    # Remove any existing W: drive letter (could be leftover from a prior failed run)
    try {
        $oldW = Get-Partition -DriveLetter W -ErrorAction Stop
        Remove-PartitionAccessPath -DriveLetter W -ErrorAction Stop
        Write-Host "  Released previously assigned W:" -ForegroundColor Gray
    } catch { }

    $partition = New-Partition -DiskNumber $disk.Number -UseMaximumSize -DriveLetter W -ErrorAction Stop
    if (-not $partition) { throw "Failed to create partition on disk $($disk.Number)" }

    Format-Volume -DriveLetter W -FileSystem FAT32 -NewFileSystemLabel "WINBOT-SETUP" -Confirm:$false -Force -ErrorAction Stop
    Write-Host "  Formatted as FAT32 (W:)" -ForegroundColor Green

    Write-Host "  Copying guest files..." -ForegroundColor Gray
    $sourceItems = Get-ChildItem $GuestDir -ErrorAction Stop
    foreach ($item in $sourceItems) {
        $destPath = Join-Path "W:\" $item.Name
        if ($item.PSIsContainer) {
            Copy-Item $item.FullName -Destination $destPath -Recurse -Force -ErrorAction SilentlyContinue
        } else {
            Copy-Item $item.FullName -Destination $destPath -Force -ErrorAction SilentlyContinue
        }
    }
    Write-Host "  Files copied." -ForegroundColor Green

    # Verify key files
    $checks = @("W:\api\main.py", "W:\setup-service.ps1", "W:\setup-remote.ps1", "W:\tools\install-all.ps1")
    $allOk = $true
    foreach ($check in $checks) {
        if (Test-Path $check) { Write-Host "    [OK] $check" -ForegroundColor Green }
        else { Write-Host "    [MISSING] $check" -ForegroundColor Red; $allOk = $false }
    }
} finally {
    Write-Host "  Dismounting VHDX..." -ForegroundColor Gray
    Dismount-VHD -Path $OutputPath -ErrorAction SilentlyContinue
    # Restore Explorer auto-mount behavior
    if ($shellHwWasRunning) { Start-Service ShellHWDetection -ErrorAction SilentlyContinue }
}

if ($allOk) {
    Write-Host "[WinBot] Provisioning VHD built successfully: $OutputPath" -ForegroundColor Green
} else {
    Write-Warning "[WinBot] VHD built but some files are missing. Verify the guest directory structure."
}

return @{
    Path = $OutputPath
    Size = (Get-Item $OutputPath).Length
    AllFilesPresent = $allOk
}
