# WinBot: Install Sysinternals Suite (process/system monitoring)
# Run as Administrator on the VM
# Usage: powershell -ExecutionPolicy Bypass -File install-sysinternals.ps1

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
    Write-Host "  Run PowerShell as Administrator to use this script." -ForegroundColor Yellow
    Write-Host "========================================`n" -ForegroundColor Red
    exit 1
}

Write-Host "[WinBot] Installing Sysinternals Suite..." -ForegroundColor Cyan

$installDir = "C:\WinBot\tools\sysinternals"
$sysinternalsUrl = "https://download.sysinternals.com/files/SysinternalsSuite.zip"

# Check if already installed
if (Test-Path "$installDir\procmon.exe") {
    Write-Host "  Already installed at: $installDir" -ForegroundColor Green
    exit 0
}

if (-not (Test-Path $installDir)) {
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
}

# Download and extract
Write-Host "  Downloading Sysinternals Suite..." -ForegroundColor Gray
$zipPath = "$env:TEMP\SysinternalsSuite.zip"
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $sysinternalsUrl -OutFile $zipPath -ErrorAction Stop
    Write-Host "  Downloaded." -ForegroundColor Green
} catch {
    Write-Host "  Download failed: $_" -ForegroundColor Red
    exit 1
}

Write-Host "  Extracting..." -ForegroundColor Gray
Expand-Archive -Path $zipPath -DestinationPath $installDir -Force
Remove-Item $zipPath -Force

# Accept EULA (required for CLI operation)
$tools = @("procmon.exe", "procexp.exe", "ProcDump.exe", "tcpview.exe", "autoruns.exe", "handle.exe", "sigcheck.exe")
foreach ($tool in $tools) {
    $toolPath = Join-Path $installDir $tool
    if (Test-Path $toolPath) {
        # Accept EULA silently by writing registry key
        $toolName = [System.IO.Path]::GetFileNameWithoutExtension($tool)
        $eulaKey = "HKCU:\Software\Sysinternals\$toolName"
        if (-not (Test-Path $eulaKey)) {
            New-Item -Path $eulaKey -Force | Out-Null
        }
        Set-ItemProperty -Path $eulaKey -Name "EulaAccepted" -Value 1 -Force | Out-Null
    }
}

# Add to PATH
[Environment]::SetEnvironmentVariable("PATH", "$installDir;$env:PATH", "Machine")
$env:PATH = "$installDir;$env:PATH"

# Verify key tools
Write-Host "  Verifying tools:" -ForegroundColor Gray
$verified = 0
foreach ($tool in @("procmon.exe","procexp.exe","ProcDump.exe","handle.exe")) {
    if (Test-Path (Join-Path $installDir $tool)) {
        Write-Host "    OK: $tool" -ForegroundColor Green
        $verified++
    } else {
        Write-Host "    MISSING: $tool" -ForegroundColor Yellow
    }
}

Write-Host "[WinBot] Sysinternals installed ($verified key tools verified)" -ForegroundColor Green
Write-Host "[WinBot] Headless usage: procdump -ma <pid>, handle -a <file>, sigcheck <exe>" -ForegroundColor Gray
