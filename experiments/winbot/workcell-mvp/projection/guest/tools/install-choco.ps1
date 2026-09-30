# WinBot: Install Chocolatey package manager
# Run as Administrator on the VM
# Usage: powershell -ExecutionPolicy Bypass -File install-choco.ps1

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

Write-Host "[WinBot] Installing Chocolatey..." -ForegroundColor Cyan

# Check if Chocolatey is already installed
if (Get-Command choco -ErrorAction SilentlyContinue) {
    Write-Host "[WinBot] Chocolatey already installed: $(choco --version)" -ForegroundColor Green
    exit 0
}

# Install Chocolatey
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072

$chocoInstallScript = @'
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
'@

# Run the install in a new process to avoid execution policy issues
$scriptPath = "$env:TEMP\install_choco.ps1"
$chocoInstallScript | Out-File -FilePath $scriptPath -Encoding utf8
& powershell -NoProfile -ExecutionPolicy Bypass -File $scriptPath

# Reload environment
$env:ChocolateyInstall = Convert-Path "$env:ProgramData\chocolatey"
$env:PATH = "$env:ChocolateyInstall\bin;$env:PATH"
[Environment]::SetEnvironmentVariable("ChocolateyInstall", $env:ChocolateyInstall, "Machine")
[Environment]::SetEnvironmentVariable("PATH", $env:PATH, "Machine")

# Verify installation
$chocoPath = "$env:ChocolateyInstall\choco.exe"
if (Test-Path $chocoPath) {
    & $chocoPath --version
    Write-Host "[WinBot] Chocolatey installed successfully" -ForegroundColor Green
} else {
    Write-Host "[WinBot] ERROR: Chocolatey installation failed" -ForegroundColor Red
    exit 1
}
