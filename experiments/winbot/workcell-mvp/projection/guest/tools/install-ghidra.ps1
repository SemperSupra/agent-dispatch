# WinBot: Install Ghidra (NSA reverse engineering suite)
# Run as Administrator on the VM
# Usage: powershell -ExecutionPolicy Bypass -File install-ghidra.ps1

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

Write-Host "[WinBot] Installing Ghidra (NSA SRE framework)..." -ForegroundColor Cyan

$installDir = "C:\WinBot\tools\Ghidra"
$version = "11.1.2"  # Mirror this to the latest release
$buildDate = "20250228"
$ghidraZip = "ghidra_${version}_PUBLIC_${buildDate}.zip"

# Check if already installed
if (Test-Path "$installDir\ghidraRun.bat") {
    Write-Host "  Ghidra already installed at: $installDir" -ForegroundColor Green
    exit 0
}

# Ghidra requires Java (JDK 17+)
Write-Host "  Checking Java..." -ForegroundColor Gray
if (-not (Get-Command java -ErrorAction SilentlyContinue)) {
    Write-Host "  Installing OpenJDK 21..." -ForegroundColor Yellow
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        choco install openjdk21 -y --no-progress 2>&1 | Out-Null
    } else {
        Write-Host "  WARNING: Chocolatey not found. Install JDK 21 manually." -ForegroundColor Yellow
        Write-Host "  https://adoptium.net/download/" -ForegroundColor Gray
    }
}
try {
    $javaVer = java -version 2>&1 | Select-Object -First 1
    Write-Host "  Java: $javaVer" -ForegroundColor Green
} catch {
    Write-Host "  WARNING: Java not found. Ghidra requires JDK 17+." -ForegroundColor Yellow
}

# Download Ghidra
Write-Host "  Downloading Ghidra $version..." -ForegroundColor Gray
$downloadUrl = "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${version}_build/$ghidraZip"
$zipPath = "$env:TEMP\$ghidraZip"

if (-not (Test-Path $zipPath)) {
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath -ErrorAction Stop
        Write-Host "  Downloaded to: $zipPath" -ForegroundColor Green
    } catch {
        Write-Host "  Download failed: $_" -ForegroundColor Red
        Write-Host "  Alternative: download manually from https://ghidra-sre.org/" -ForegroundColor Yellow
        Write-Host "  Extract to: $installDir" -ForegroundColor Yellow
        exit 1
    }
}

# Extract
Write-Host "  Extracting..." -ForegroundColor Gray
if (-not (Test-Path $installDir)) {
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
}
Expand-Archive -Path $zipPath -DestinationPath $installDir -Force
Write-Host "  Extracted to: $installDir" -ForegroundColor Green

# Verify
if (Test-Path "$installDir\ghidraRun.bat") {
    Write-Host "[WinBot] Ghidra installed successfully" -ForegroundColor Green
    Write-Host "[WinBot] Headless mode: $installDir\support\analyzeHeadless.bat" -ForegroundColor Gray
} else {
    # Extraction may have nested directory
    $nested = Get-ChildItem $installDir -Directory | Select-Object -First 1
    if ($nested -and (Test-Path "$($nested.FullName)\ghidraRun.bat")) {
        Move-Item "$($nested.FullName)\*" $installDir -Force
        Remove-Item $nested.FullName -Recurse -Force
        Write-Host "[WinBot] Ghidra installed successfully (reorganized)" -ForegroundColor Green
    } else {
        Write-Host "[WinBot] WARNING: Ghidra extraction structure unexpected. Check $installDir" -ForegroundColor Yellow
    }
}

# Cleanup
Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
