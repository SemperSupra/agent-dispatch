# WinBot: Install Frida (dynamic instrumentation toolkit)
# Run as Administrator on the VM
# Usage: powershell -ExecutionPolicy Bypass -File install-frida.ps1

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

Write-Host "[WinBot] Installing Frida (dynamic instrumentation)..." -ForegroundColor Cyan

# Frida tools: Python bindings (pip) + frida-tools CLI + frida-server for remote
# Frida is the primary dynamic analysis tool for WinBot â€” Python API, no GUI needed.

# Install Python bindings
Write-Host "  Installing frida-tools via pip..." -ForegroundColor Gray
python -m pip install frida-tools --quiet 2>&1 | Out-Null
Write-Host "  Frida Python bindings installed." -ForegroundColor Green

# Verify
try {
    $ver = python -c "import frida; print(frida.__version__)" 2>&1
    Write-Host "  Version: $ver" -ForegroundColor Green
} catch {
    Write-Host "  WARNING: Frida import failed: $_" -ForegroundColor Yellow
    Write-Host "  Try: python -m pip install frida-tools" -ForegroundColor Gray
}

# Install frida-server for the current platform (for remote/agent-based injection)
# Frida server allows attaching to processes from outside the VM
Write-Host "  Downloading frida-server for Windows x64..." -ForegroundColor Gray
$fridaServerDir = "C:\WinBot\tools\frida"
if (-not (Test-Path $fridaServerDir)) {
    New-Item -ItemType Directory -Path $fridaServerDir -Force | Out-Null
}

try {
    $fridaVersion = python -c "import frida; print(frida.__version__)" 2>&1
    $serverUrl = "https://github.com/frida/frida/releases/download/$fridaVersion/frida-server-$fridaVersion-windows-x86_64.exe"
    $serverPath = "$fridaServerDir\frida-server.exe"
    if (-not (Test-Path $serverPath)) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $serverUrl -OutFile $serverPath -ErrorAction Stop
    }
    Write-Host "  frida-server: $serverPath" -ForegroundColor Green
} catch {
    Write-Host "  WARNING: Could not download frida-server: $_" -ForegroundColor Yellow
    Write-Host "  Download manually from: https://github.com/frida/frida/releases" -ForegroundColor Gray
}

Write-Host "[WinBot] Frida installation complete" -ForegroundColor Green
