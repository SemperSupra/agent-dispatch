# ################################################################
# # DEPRECATED -- logic is now in stage-provision.ps1 Step 8. #
# # This script is kept for reference. #
# # See docs/layer-map.md for the full architecture. #
# ################################################################
#
# WinBot: Install the WinBot API as a Windows Service via NSSM (DEPRECATED)
# Run as Administrator on the VM
# Usage: powershell -ExecutionPolicy Bypass -File setup-service.ps1

param(
[string]$ApiDir = "C:\WinBot\api",
[string]$PythonExe = "",
[string]$ApiToken = "" # Optional pre-generated token; random if not provided
)

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

Write-Host "[WinBot] Installing WinBot API as Windows Service..." -ForegroundColor Cyan

# ============================================================
# Generate API token (if not provided)
# ============================================================
if (-not $ApiToken) {
$tokenBytes = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Fill($tokenBytes)
$ApiToken = -join ($tokenBytes | ForEach-Object { "{0:x2}" -f $_ })
Write-Host "[WinBot] Generated random API token" -ForegroundColor Green
} else {
Write-Host "[WinBot] Using provided API token" -ForegroundColor Gray
}

# Save token to file for host-side retrieval
$tokenFile = "C:\WinBot\.api_token"
$ApiToken | Out-File -FilePath $tokenFile -Encoding ascii -NoNewline
# Secure the token file only SYSTEM and Administrators can read
try {
icacls $tokenFile /inheritance:r /grant "SYSTEM:(R)" /grant "BUILTIN\Administrators:(R)" 2>$null | Out-Null
} catch { }
Write-Host "[WinBot] API token saved to: $tokenFile" -ForegroundColor Green

# Find Python -- prefer SYSTEM-accessible (system-wide) paths first.
# NSSM runs the service as SYSTEM, which cannot access per-user AppData paths.
if (-not $PythonExe) {
$knownPaths = @(
"C:\Python313\python.exe", # Chocolatey installs here
"$env:ProgramFiles\Python313\python.exe", # ALLUSERS installer
"C:\Program Files\Python313\python.exe", # ALLUSERS fallback
"$env:LOCALAPPDATA\Programs\Python\Python313\python.exe" # per-user, last resort
)
# Map version-agnostic candidates: try 313, 312, 311, then scan by major
foreach ($ver in @("313", "312", "311", "310")) {
$knownPaths += @(
"C:\Python$ver\python.exe",
"$env:ProgramFiles\Python$ver\python.exe",
"C:\Program Files\Python$ver\python.exe",
"$env:LOCALAPPDATA\Programs\Python\Python$ver\python.exe"
)
}
# Try system-wide paths first (accessible by SYSTEM)
foreach ($p in $knownPaths) {
if (Test-Path $p) {
$PythonExe = $p
break
}
}
}
# Fall back to PATH lookup (may return per-user Python -- will warn below)
if (-not $PythonExe) {
$PythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
}
if (-not $PythonExe -or -not (Test-Path $PythonExe)) {
Write-Host "[WinBot] ERROR: Python not found. Run install-python.ps1 first." -ForegroundColor Red
exit 1
}
Write-Host "[WinBot] Using Python: $PythonExe" -ForegroundColor Gray
if ($PythonExe -match 'AppData\\Local') {
Write-Host "[WinBot] WARNING: Per-user Python path detected. NSSM (SYSTEM) may not access it." -ForegroundColor Yellow
Write-Host "[WinBot] Consider installing Python system-wide (ALLUSERS=1) or granting SYSTEM access." -ForegroundColor Yellow
}

# Find NSSM
$nssmPath = "C:\ProgramData\chocolatey\bin\nssm.exe"
if (-not (Test-Path $nssmPath)) {
$nssmPath = (Get-Command nssm -ErrorAction SilentlyContinue).Source
}
if (-not $nssmPath) {
# Try to install NSSM via chocolatey
if (Get-Command choco -ErrorAction SilentlyContinue) {
choco install nssm -y --no-progress
Start-Sleep -Seconds 3
$nssmPath = "C:\ProgramData\chocolatey\bin\nssm.exe"
}
}
if (-not $nssmPath -or -not (Test-Path $nssmPath)) {
Write-Host "[WinBot] ERROR: NSSM not found. Install NSSM first." -ForegroundColor Red
exit 1
}
Write-Host "[WinBot] Using NSSM: $nssmPath" -ForegroundColor Gray

# Verify API files exist
$apiMain = "$ApiDir\main.py"
if (-not (Test-Path $apiMain)) {
Write-Host "[WinBot] ERROR: API main.py not found at $apiMain" -ForegroundColor Red
exit 1
}

$serviceName = "WinBotAPI"

# Remove existing service if present
$existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existingService) {
Write-Host "[WinBot] Stopping existing $serviceName service..." -ForegroundColor Yellow
Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
& $nssmPath remove $serviceName confirm
Start-Sleep -Seconds 1
}

# Install service with NSSM
Write-Host "[WinBot] Installing $serviceName service..." -ForegroundColor Cyan

# NSSM install
& $nssmPath install $serviceName $PythonExe "-m uvicorn main:app --host 0.0.0.0 --port 8000"
& $nssmPath set $serviceName AppDirectory $ApiDir
& $nssmPath set $serviceName DisplayName "WinBot API Server"
& $nssmPath set $serviceName Description "WinBot automation REST API (FastAPI + uvicorn)"
& $nssmPath set $serviceName Start SERVICE_AUTO_START
& $nssmPath set $serviceName AppStdout "C:\WinBot\logs\api-stdout.log"
& $nssmPath set $serviceName AppStderr "C:\WinBot\logs\api-stderr.log"
& $nssmPath set $serviceName AppStdoutCreationDisposition 4
& $nssmPath set $serviceName AppStderrCreationDisposition 4
& $nssmPath set $serviceName AppRotateFiles 1
& $nssmPath set $serviceName AppRotateOnline 1
& $nssmPath set $serviceName AppRotateSeconds 86400
& $nssmPath set $serviceName AppRotateBytes 1048576
& $nssmPath set $serviceName AppEnvironmentExtra "WINBOT_API_TOKEN=$ApiToken"
& $nssmPath set $serviceName AppExit Default Restart
& $nssmPath set $serviceName AppRestartDelay 5000

# Start the service
Start-Service -Name $serviceName -ErrorAction SilentlyContinue
Start-Sleep -Seconds 3

# Verify
$svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq "Running") {
Write-Host "[WinBot] WinBot API service is RUNNING" -ForegroundColor Green
} else {
Write-Host "[WinBot] WARNING: Service installed but may not be running. Check logs." -ForegroundColor Yellow
if ($svc) { Write-Host " Status: $($svc.Status)" -ForegroundColor Yellow }
}

Write-Host "[WinBot] Service setup complete" -ForegroundColor Green
Write-Host "[WinBot] API Token: $($ApiToken.Substring(0,8))... (full token in $tokenFile)" -ForegroundColor Gray
