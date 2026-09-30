# WinBot: Install Python 3.13
# Run as Administrator on the VM
# Usage: powershell -ExecutionPolicy Bypass -File install-python.ps1

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
Write-Host " SAFETY GUARDRAIL: HOST PROTECTION" -ForegroundColor Red
Write-Host "========================================" -ForegroundColor Red
Write-Host " This script modifies system settings and MUST only run" -ForegroundColor Red
Write-Host " inside a Hyper-V VM, NEVER on a physical host." -ForegroundColor Red
Write-Host " Current system is NOT a Hyper-V VM." -ForegroundColor Red
Write-Host ""
Write-Host " To run inside a VM:" -ForegroundColor Yellow
Write-Host " winbotctl.ps1 connect <name>" -ForegroundColor Yellow
Write-Host ""
Write-Host " To override (DANGEROUS testing only):" -ForegroundColor Yellow
Write-Host " Set WINBOT_SKIP_VM_GUARDRAIL=1 and run again." -ForegroundColor Yellow
Write-Host " Run PowerShell as Administrator to use this script." -ForegroundColor Yellow
Write-Host "========================================`n" -ForegroundColor Red
exit 1
}
if ($skipCheck) {
Write-Host "[WinBot] WARNING: VM guardrail overridden via WINBOT_SKIP_VM_GUARDRAIL" -ForegroundColor Yellow
}
# === End Guardrail ===

Write-Host "[WinBot] Installing Python 3.13..." -ForegroundColor Cyan

# Check if Python is already installed with the right version
if (Get-Command python -ErrorAction SilentlyContinue) {
$currentVersion = python --version 2>&1
Write-Host "[WinBot] Python already installed: $currentVersion" -ForegroundColor Green
if ($currentVersion -match "3\.13") {
exit 0
}
Write-Host "[WinBot] Existing Python is not 3.13, proceeding with install..." -ForegroundColor Yellow
}

# Install via Chocolatey (preferred -- installs to C:\Python313\, SYSTEM-accessible)
if (Get-Command choco -ErrorAction SilentlyContinue) {
choco install python313 -y --no-progress
} else {
# Direct download
Write-Host "[WinBot] Chocolatey not found, downloading Python directly..." -ForegroundColor Yellow
$url = "https://www.python.org/ftp/python/3.13.3/python-3.13.3-amd64.exe"
$installer = "$env:TEMP\python-3.13.3-amd64.exe"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $url -OutFile $installer

# Silent install for all users, add to PATH
Start-Process -FilePath $installer -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1 Include_test=0" -Wait -NoNewWindow
Remove-Item $installer -Force
}

# Refresh PATH
$env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH", "User")

# Verify installation
Start-Sleep -Seconds 3

# Check common install paths (version-agnostic)
$pythonPaths = @()
foreach ($ver in @("313", "312")) {
$pythonPaths += @(
"C:\Python$ver\python.exe",
"$env:ProgramFiles\Python$ver\python.exe",
"C:\Program Files\Python$ver\python.exe",
"$env:LOCALAPPDATA\Programs\Python\Python$ver\python.exe"
)
}
$pyExe = $null
foreach ($p in $pythonPaths) {
if (Test-Path $p) { $pyExe = $p; break }
}
if (-not $pyExe) { $pyExe = (Get-Command python -ErrorAction SilentlyContinue).Source }

if ($pyExe) {
Write-Host "[WinBot] Python found at: $pyExe" -ForegroundColor Green
$pyDir = Split-Path $pyExe -Parent
# Ensure Python's directory is on the Machine PATH with priority
$machinePath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($machinePath -notlike "*$pyDir*") {
$env:PATH = "$pyDir;$pyDir\Scripts;$env:PATH"
[Environment]::SetEnvironmentVariable("PATH", "$pyDir;$pyDir\Scripts;$machinePath", "Machine")
}
$version = & $pyExe --version 2>&1
Write-Host "[WinBot] Python $version" -ForegroundColor Green
} else {
Write-Host "[WinBot] ERROR: Python installation failed" -ForegroundColor Red
exit 1
}

# Install pip packages needed by WinBot API
Write-Host "[WinBot] Installing Python packages..." -ForegroundColor Cyan
python -m pip install --upgrade pip --quiet
python -m pip install fastapi uvicorn pyautogui pywin32 pillow pynput --quiet

Write-Host "[WinBot] Python setup complete" -ForegroundColor Green
