# WinBot: Install FLOSS (FireEye Labs Obfuscated String Solver)
# Run as Administrator on the VM
# Usage: powershell -ExecutionPolicy Bypass -File install-floss.ps1

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
    Write-Host "  Run PowerShell as Administrator to use this script." -ForegroundColor Yellow
    Write-Host "========================================`n" -ForegroundColor Red
    exit 1
}

Write-Host "[WinBot] Installing FLOSS..." -ForegroundColor Cyan

# Check if already installed
if (Get-Command floss -ErrorAction SilentlyContinue) {
    Write-Host "  Already installed: $(floss --version 2>&1 | Select-Object -First 1)" -ForegroundColor Green
    exit 0
}

# FLOSS is distributed as a standalone Windows binary
$flossUrl = "https://github.com/mandiant/flare-floss/releases/latest/download/floss.exe"
$installDir = "C:\WinBot\tools\floss"
$flossExe = "$installDir\floss.exe"

if (Test-Path $flossExe) {
    Write-Host "  Already installed at: $flossExe" -ForegroundColor Green
} else {
    if (-not (Test-Path $installDir)) {
        New-Item -ItemType Directory -Path $installDir -Force | Out-Null
    }
    Write-Host "  Downloading FLOSS..." -ForegroundColor Gray
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $flossUrl -OutFile $flossExe -ErrorAction Stop
        Write-Host "  Downloaded." -ForegroundColor Green
    } catch {
        # Fallback: pip install
        Write-Host "  Binary download failed, trying pip install..." -ForegroundColor Yellow
        try {
            python -m pip install flare-floss --quiet 2>&1 | Out-Null
        } catch {
            Write-Host "  Both methods failed. Install manually:" -ForegroundColor Red
            Write-Host "  https://github.com/mandiant/flare-floss/releases" -ForegroundColor Yellow
            exit 1
        }
    }
}

# Add to PATH
[Environment]::SetEnvironmentVariable("PATH", "$installDir;$env:PATH", "Machine")
$env:PATH = "$installDir;$env:PATH"

# Verify
if (Get-Command floss -ErrorAction SilentlyContinue) {
    try {
        $ver = floss --version 2>&1 | Select-Object -First 1
        Write-Host "  $ver" -ForegroundColor Green
    } catch { }
    Write-Host "[WinBot] FLOSS installed" -ForegroundColor Green
    Write-Host "[WinBot] Usage: floss -j output.json binary.exe  (JSON output)" -ForegroundColor Gray
    Write-Host "[WinBot] Usage: floss --no static --no decoded binary.exe  (static strings only)" -ForegroundColor Gray
} else {
    Write-Host "[WinBot] WARNING: FLOSS verification failed. Check PATH." -ForegroundColor Yellow
}
