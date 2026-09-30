# WinBot: Install radare2 / rizin (reverse engineering framework)
# Run as Administrator on the VM
# Usage: powershell -ExecutionPolicy Bypass -File install-radare2.ps1

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

Write-Host "[WinBot] Installing radare2/rizin (CLI RE framework)..." -ForegroundColor Cyan

# radare2 is the most agent-friendly RE tool â€” pure CLI, scriptable via r2pipe
# Perfect for WinBot's /run/python endpoint: `import r2pipe; r2 = r2pipe.open("binary")`

# Check if already installed
if (Get-Command radare2 -ErrorAction SilentlyContinue) {
    $ver = radare2 -v 2>&1 | Select-Object -First 1
    Write-Host "  radare2 already installed: $ver" -ForegroundColor Green
    exit 0
}

# Method 1: Chocolatey (preferred)
if (Get-Command choco -ErrorAction SilentlyContinue) {
    Write-Host "  Installing radare2 via Chocolatey..." -ForegroundColor Gray
    choco install radare2 -y --no-progress 2>&1 | Out-Null

    # Refresh PATH
    $env:PATH = [Environment]::GetEnvironmentVariable("PATH", "Machine")

    if (Get-Command radare2 -ErrorAction SilentlyContinue) {
        $ver = radare2 -v 2>&1 | Select-Object -First 1
        Write-Host "  radare2: $ver" -ForegroundColor Green
    }
}

# Method 2: Direct download (fallback)
if (-not (Get-Command radare2 -ErrorAction SilentlyContinue)) {
    Write-Host "  Downloading radare2 Windows binaries..." -ForegroundColor Gray
    $r2Url = "https://github.com/radareorg/radare2/releases/latest/download/radare2-windows.zip"
    $zipPath = "$env:TEMP\radare2.zip"
    $installDir = "C:\WinBot\tools\radare2"

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $r2Url -OutFile $zipPath -ErrorAction Stop
    } catch {
        Write-Host "  Download failed: $_" -ForegroundColor Red
        Write-Host "  Install manually: https://github.com/radareorg/radare2/releases" -ForegroundColor Yellow
        exit 1
    }

    if (-not (Test-Path $installDir)) {
        New-Item -ItemType Directory -Path $installDir -Force | Out-Null
    }
    Expand-Archive -Path $zipPath -DestinationPath $installDir -Force
    Remove-Item $zipPath -Force

    # Add to PATH
    $r2Bin = Get-ChildItem $installDir -Recurse -Filter "radare2.exe" | Select-Object -First 1
    if ($r2Bin) {
        $binDir = Split-Path $r2Bin.FullName -Parent
        [Environment]::SetEnvironmentVariable("PATH", "$binDir;$env:PATH", "Machine")
        $env:PATH = "$binDir;$env:PATH"
        Write-Host "  radare2 installed: $($r2Bin.FullName)" -ForegroundColor Green
    }
}

# Install Python bindings
Write-Host "  Installing r2pipe Python bindings..." -ForegroundColor Gray
python -m pip install r2pipe --quiet 2>&1 | Out-Null
Write-Host "  r2pipe installed" -ForegroundColor Green

# Verify
try {
    if (Get-Command radare2 -ErrorAction SilentlyContinue) {
        $ver = radare2 -v 2>&1 | Select-Object -First 1
        Write-Host "  radare2: $ver" -ForegroundColor Green
    }
    $pyTest = python -c "import r2pipe; print('OK')" 2>&1
    if ($pyTest -eq "OK") {
        Write-Host "  r2pipe Python: OK" -ForegroundColor Green
    }
} catch {
    Write-Host "  WARNING: Verification failed: $_" -ForegroundColor Yellow
}

Write-Host "[WinBot] radare2 installation complete" -ForegroundColor Green
Write-Host "[WinBot] Usage: radare2 -q -c 'aaaa; afl' binary.exe  (static analysis)" -ForegroundColor Gray
Write-Host "[WinBot] Usage: r2 -d binary.exe -c 'dcu main; pd 20'  (dynamic debugging)" -ForegroundColor Gray
