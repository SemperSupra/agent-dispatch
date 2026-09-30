# WinBot: Install AutoIt v3
# Run as Administrator on the VM
# Usage: powershell -ExecutionPolicy Bypass -File install-autoit.ps1

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
    Write-Host ""
    Write-Host "  To run inside a VM:" -ForegroundColor Yellow
    Write-Host "    winbotctl.ps1 connect <name>" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  To override (DANGEROUS â€” testing only):" -ForegroundColor Yellow
    Write-Host "    Set WINBOT_SKIP_VM_GUARDRAIL=1 and run again." -ForegroundColor Yellow
    Write-Host "  Run PowerShell as Administrator to use this script." -ForegroundColor Yellow
    Write-Host "========================================`n" -ForegroundColor Red
    exit 1
}
if ($skipCheck) {
    Write-Host "[WinBot] WARNING: VM guardrail overridden via WINBOT_SKIP_VM_GUARDRAIL" -ForegroundColor Yellow
}
# === End Guardrail ===

Write-Host "[WinBot] Installing AutoIt v3..." -ForegroundColor Cyan

# Check if already installed
$autoitPath = "C:\Program Files (x86)\AutoIt3\AutoIt3.exe"
if (Test-Path $autoitPath) {
    Write-Host "[WinBot] AutoIt already installed at: $autoitPath" -ForegroundColor Green
    & $autoitPath /version 2>$null
    exit 0
}

# Install via Chocolatey
if (Get-Command choco -ErrorAction SilentlyContinue) {
    choco install autoit -y --no-progress
} else {
    # Direct download fallback
    Write-Host "[WinBot] Chocolatey not found, downloading AutoIt directly..." -ForegroundColor Yellow
    $url = "https://www.autoitscript.com/files/autoit3/autoit-v3-setup.exe"
    $installer = "$env:TEMP\autoit-v3-setup.exe"

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $url -OutFile $installer

    # Silent install
    Start-Process -FilePath $installer -ArgumentList "/S" -Wait -NoNewWindow
    Remove-Item $installer -Force
}

# Verify installation
Start-Sleep -Seconds 2
if (Test-Path $autoitPath) {
    Write-Host "[WinBot] AutoIt installed successfully" -ForegroundColor Green
    # Add to PATH for current session
    $env:PATH = "C:\Program Files (x86)\AutoIt3;C:\Program Files (x86)\AutoIt3\AutoItX;$env:PATH"
} else {
    Write-Host "[WinBot] WARNING: AutoIt install path not found, checking alternative locations..." -ForegroundColor Yellow
    $found = Get-ChildItem -Path "C:\Program Files" -Recurse -Filter "AutoIt3.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) {
        Write-Host "[WinBot] AutoIt found at: $($found.FullName)" -ForegroundColor Green
    } else {
        Write-Host "[WinBot] ERROR: AutoIt installation failed" -ForegroundColor Red
        exit 1
    }
}
