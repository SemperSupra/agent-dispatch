# WinBot: Install Detect It Easy (binary type/packer/compiler detection)
# Run as Administrator on the VM
# Usage: powershell -ExecutionPolicy Bypass -File install-die.ps1

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

Write-Host "[WinBot] Installing Detect It Easy (DIE)..." -ForegroundColor Cyan

$installDir = "C:\WinBot\tools\die"

# Check CLI (diec.exe)
if (Get-Command diec -ErrorAction SilentlyContinue) {
    Write-Host "  Already installed: diec on PATH" -ForegroundColor Green
    exit 0
}

# Chocolatey preferred
if (Get-Command choco -ErrorAction SilentlyContinue) {
    Write-Host "  Installing via Chocolatey..." -ForegroundColor Gray
    choco install detect-it-easy -y --no-progress 2>&1 | Out-Null
    Write-Host "  Installed via Chocolatey." -ForegroundColor Green
} else {
    # Direct download from GitHub
    Write-Host "  Downloading from GitHub..." -ForegroundColor Gray
    $dieUrl = "https://github.com/horsicq/Detect-It-Easy/releases/latest/download/die_win64_portable.zip"
    $zipPath = "$env:TEMP\die.zip"
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $dieUrl -OutFile $zipPath -ErrorAction Stop
    } catch {
        Write-Host "  Download failed: $_" -ForegroundColor Red
        Write-Host "  Install manually from: https://github.com/horsicq/Detect-It-Easy" -ForegroundColor Yellow
        exit 1
    }
    if (-not (Test-Path $installDir)) { New-Item -ItemType Directory -Path $installDir -Force | Out-Null }
    Expand-Archive -Path $zipPath -DestinationPath $installDir -Force
    Remove-Item $zipPath -Force

    # Find diec.exe
    $diecExe = Get-ChildItem $installDir -Recurse -Filter "diec.exe" | Select-Object -First 1
    if ($diecExe) {
        $diecDir = Split-Path $diecExe.FullName -Parent
        [Environment]::SetEnvironmentVariable("PATH", "$diecDir;$env:PATH", "Machine")
        $env:PATH = "$diecDir;$env:PATH"
    }
}

# Refresh PATH
$env:PATH = [Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" + [Environment]::GetEnvironmentVariable("PATH", "User")

# Verify
if (Get-Command diec -ErrorAction SilentlyContinue) {
    Write-Host "  CLI (diec): available" -ForegroundColor Green
    Write-Host "[WinBot] DIE installed" -ForegroundColor Green
    Write-Host "[WinBot] Usage: diec -j output.json binary.exe  (JSON output for agents)" -ForegroundColor Gray
    Write-Host "[WinBot] Usage: diec -b binary.exe  (brief mode)" -ForegroundColor Gray
} else {
    Write-Host "[WinBot] WARNING: diec.exe not found on PATH. Check $installDir" -ForegroundColor Yellow
}
