# WinBot: Install Wireshark + TShark (network protocol analysis)
# Run as Administrator on the VM
# Usage: powershell -ExecutionPolicy Bypass -File install-wireshark.ps1
param([switch]$SkipGUI)

$ErrorActionPreference = "Stop"

# === WinBot Guardrail: VM-Only ===
function Test-IsHyperVVM {
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    if ($cs -and $cs.Manufacturer -eq "Microsoft Corporation" -and $cs.Model -eq "Virtual Machine") { return $true }
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters") { return $true }
    $hvServices = @("vmicheartbeat","vmictimesync","vmickvpexchange","vmicshutdown","vmicvss")
    foreach ($sn in $hvServices) { $s = Get-Service -Name $sn -ErrorAction SilentlyContinue; if ($s -and $s.Status -eq "Running") { return $true } }
    $b = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
    if ($b -and $b.SMBIOSBIOSVersion -match "Hyper-V|VRTUAL") { return $true }
    return $false
}
$skip = $env:WINBOT_SKIP_VM_GUARDRAIL -eq "1"
if (-not $skip -and -not (Test-IsHyperVVM)) {
    Write-Host "`n========================================" -ForegroundColor Red
    Write-Host "  SAFETY GUARDRAIL: HOST PROTECTION" -ForegroundColor Red
    Write-Host "  This script MUST only run inside a Hyper-V VM." -ForegroundColor Red
    Write-Host "  Current system is NOT a Hyper-V VM." -ForegroundColor Red
    Write-Host "  Run PowerShell as Administrator to use this script." -ForegroundColor Yellow
    Write-Host "========================================`n" -ForegroundColor Red
    exit 1
}

Write-Host "[WinBot] Installing Wireshark + TShark..." -ForegroundColor Cyan

# Check for existing
if (Get-Command tshark -ErrorAction SilentlyContinue) {
    Write-Host "  Already installed: $(tshark --version 2>&1 | Select-Object -First 1)" -ForegroundColor Green
    exit 0
}

# Chocolatey install (includes tshark CLI)
if (Get-Command choco -ErrorAction SilentlyContinue) {
    Write-Host "  Installing via Chocolatey..." -ForegroundColor Gray
    if ($SkipGUI) {
        # TShark only (headless)
        choco install wireshark --params "/NoDesktopShortcut /NoQuickLaunch" -y --no-progress 2>&1 | Out-Null
    } else {
        choco install wireshark -y --no-progress 2>&1 | Out-Null
    }
} else {
    Write-Host "  WARNING: Chocolatey not found. Install manually: https://www.wireshark.org/" -ForegroundColor Yellow
    exit 1
}

# Add to PATH
$wiresharkDir = "C:\Program Files\Wireshark"
if (Test-Path $wiresharkDir) {
    [Environment]::SetEnvironmentVariable("PATH", "$wiresharkDir;$env:PATH", "Machine")
    $env:PATH = "$wiresharkDir;$env:PATH"
}

# Verify
Start-Sleep -Seconds 3
if (Get-Command tshark -ErrorAction SilentlyContinue) {
    $ver = tshark --version 2>&1 | Select-Object -First 1
    Write-Host "  tshark: $ver" -ForegroundColor Green
    Write-Host "[WinBot] Wireshark/TShark installed" -ForegroundColor Green
    Write-Host "[WinBot] Headless: tshark -i Ethernet0 -c 100 -w capture.pcap" -ForegroundColor Gray
    Write-Host "[WinBot] GUI: Wireshark.exe (use AHK for automation)" -ForegroundColor Gray
} else {
    Write-Host "[WinBot] WARNING: Verification failed. Check PATH." -ForegroundColor Yellow
}
