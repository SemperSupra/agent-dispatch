# WinBot: Install x64dbg (Windows debugger)
# Run as Administrator on the VM
# Usage: powershell -ExecutionPolicy Bypass -File install-x64dbg.ps1

$ErrorActionPreference = "Stop"

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
$skipCheck = $env:WINBOT_SKIP_VM_GUARDRAIL -eq "1"
if (-not $skipCheck -and -not (Test-IsHyperVVM)) {
    Write-Host "`n========================================" -ForegroundColor Red
    Write-Host "  SAFETY GUARDRAIL: HOST PROTECTION" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "  This script modifies system settings and MUST only run" -ForegroundColor Red
    Write-Host "  inside a Hyper-V VM, NEVER on a physical host." -ForegroundColor Red
    Write-Host "  Current system is NOT a Hyper-V VM." -ForegroundColor Red
    Write-Host "`n  To override (DANGEROUS): Set WINBOT_SKIP_VM_GUARDRAIL=1" -ForegroundColor Yellow
    Write-Host "  Run PowerShell as Administrator to use this script." -ForegroundColor Yellow
    Write-Host "========================================`n" -ForegroundColor Red
    exit 1
}
if ($skipCheck) {
    Write-Host "[WinBot] WARNING: VM guardrail overridden via WINBOT_SKIP_VM_GUARDRAIL" -ForegroundColor Yellow
}
# === End Guardrail ===

Write-Host "[WinBot] Installing x64dbg (debugger)..." -ForegroundColor Cyan

$installDir = "C:\WinBot\tools\x64dbg"

# Check if already installed
if (Test-Path "$installDir\release\x64\x64dbg.exe") {
    Write-Host "  x64dbg already installed at: $installDir" -ForegroundColor Green
    exit 0
}

# Chocolatey install (recommended)
if (Get-Command choco -ErrorAction SilentlyContinue) {
    Write-Host "  Installing via Chocolatey..." -ForegroundColor Gray
    choco install x64dbg -y --no-progress 2>&1 | Out-Null
    Write-Host "  x64dbg installed via Chocolatey" -ForegroundColor Green

    # Find installation path
    $chocoX64dbg = Get-ChildItem "C:\Program Files" -Recurse -Filter "x64dbg.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($chocoX64dbg) {
        Write-Host "  Path: $($chocoX64dbg.FullName)" -ForegroundColor Green
    }
} else {
    # Direct download
    Write-Host "  Downloading snapshot release..." -ForegroundColor Gray
    $snapshotUrl = "https://github.com/x64dbg/x64dbg/releases/latest/download/snapshot.zip"
    $zipPath = "$env:TEMP\x64dbg-snapshot.zip"

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $snapshotUrl -OutFile $zipPath -ErrorAction Stop
    } catch {
        Write-Host "  Download failed: $_" -ForegroundColor Red
        Write-Host "  Download manually from: https://x64dbg.com/" -ForegroundColor Yellow
        exit 1
    }

    # Extract
    if (-not (Test-Path $installDir)) {
        New-Item -ItemType Directory -Path $installDir -Force | Out-Null
    }
    Expand-Archive -Path $zipPath -DestinationPath $installDir -Force
    Remove-Item $zipPath -Force

    # Find the binary
    $exe = Get-ChildItem $installDir -Recurse -Filter "x64dbg.exe" | Select-Object -First 1
    if ($exe) {
        Write-Host "  x64dbg installed: $($exe.FullName)" -ForegroundColor Green
    } else {
        Write-Host "  WARNING: Archive structure unexpected. Check $installDir" -ForegroundColor Yellow
    }
}

# Install x64dbgpy plugin for Python scripting (optional, for agent-driven automation)
Write-Host "  Note: For Python scripting in x64dbg, install x64dbgpy plugin." -ForegroundColor Gray
Write-Host "  https://github.com/x64dbg/x64dbgpy" -ForegroundColor Gray

Write-Host "[WinBot] x64dbg installation complete" -ForegroundColor Green
Write-Host "[WinBot] Agent usage: launch_gui via AHK for setup, x64dbgpy for automation" -ForegroundColor Gray
