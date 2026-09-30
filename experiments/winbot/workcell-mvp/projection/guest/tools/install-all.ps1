# WinBot: Install ALL guest tools
# Run as Administrator on the VM
# Usage: powershell -ExecutionPolicy Bypass -File install-all.ps1

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

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

Write-Host "========================================" -ForegroundColor Magenta
Write-Host "  WinBot â€” Guest Tool Installation" -ForegroundColor Magenta
Write-Host "========================================" -ForegroundColor Magenta
Write-Host ""

# Create WinBot directories
$winBotDirs = @(
    "C:\WinBot",
    "C:\WinBot\tools",
    "C:\WinBot\api",
    "C:\WinBot\sessions",
    "C:\WinBot\logs"
)
foreach ($d in $winBotDirs) {
    if (-not (Test-Path $d)) {
        New-Item -ItemType Directory -Path $d -Force | Out-Null
        Write-Host "[WinBot] Created directory: $d" -ForegroundColor Gray
    }
}

# Step 1: Chocolatey
Write-Host "`n[1/8] Installing Chocolatey..." -ForegroundColor Cyan
& "$scriptDir\install-choco.ps1"

# Step 2: Python 3.13
Write-Host "`n[2/8] Installing Python 3.13..." -ForegroundColor Cyan
& "$scriptDir\install-python.ps1"

# Step 3: AutoIt
Write-Host "`n[3/8] Installing AutoIt..." -ForegroundColor Cyan
& "$scriptDir\install-autoit.ps1"

# Step 4: AutoHotkey
Write-Host "`n[4/8] Installing AutoHotkey..." -ForegroundColor Cyan
& "$scriptDir\install-autohotkey.ps1"

# Step 5: WinSpy
Write-Host "`n[5/8] Installing WinSpy..." -ForegroundColor Cyan
& "$scriptDir\install-winspy.ps1"

# Step 6: NSSM (Non-Sucking Service Manager) for running the API as a service
Write-Host "`n[6/8] Installing NSSM..." -ForegroundColor Cyan
if (Get-Command choco -ErrorAction SilentlyContinue) {
    choco install nssm -y --no-progress
    Write-Host "[WinBot] NSSM installed" -ForegroundColor Green
} else {
    Write-Host "[WinBot] WARNING: Chocolatey not available, NSSM must be installed manually" -ForegroundColor Yellow
}

# Step 7: Frida (dynamic instrumentation)
Write-Host "`n[7/8] Installing Frida..." -ForegroundColor Cyan
& "$scriptDir\install-frida.ps1"

# Step 8: radare2 (CLI RE framework)
Write-Host "`n[8/8] Installing radare2..." -ForegroundColor Cyan
& "$scriptDir\install-radare2.ps1"

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "  WinBot - Automation tools installed!" -ForegroundColor Green
Write-Host "  (Ghidra & x64dbg are optional â€” run install-ghidra.ps1 / install-x64dbg.ps1)" -ForegroundColor Gray
Write-Host "========================================" -ForegroundColor Green

# Smoke test each tool
Write-Host "`nRunning smoke tests..." -ForegroundColor Cyan

$smokePassed = 0
$smokeTotal = 4

# Test Python
try {
    $pyVer = python --version 2>&1
    $pyTest = python -c "print('smoke')" 2>&1
    if ($pyTest -match "smoke") {
        Write-Host "  [PASS] Python: $pyVer" -ForegroundColor Green
        $smokePassed++
    } else {
        Write-Host "  [FAIL] Python: unexpected output: $pyTest" -ForegroundColor Red
    }
} catch {
    Write-Host "  [FAIL] Python: $_" -ForegroundColor Red
}

# Test AutoIt
try {
    $au3Exe = Get-Command "C:\Program Files (x86)\AutoIt3\AutoIt3.exe" -ErrorAction SilentlyContinue
    if (-not $au3Exe) { $au3Exe = Get-Command "C:\Program Files\AutoIt3\AutoIt3.exe" -ErrorAction SilentlyContinue }
    if ($au3Exe) {
        # Create a simple test script that does nothing observable
        $testScript = "$env:TEMP\winbot-smoke-test.au3"
        "Exit(0)" | Out-File $testScript -Encoding ASCII
        $au3Result = & $au3Exe.Source /AutoIt3ExecuteScript $testScript 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  [PASS] AutoIt: $($au3Exe.Source)" -ForegroundColor Green
            $smokePassed++
        } else {
            Write-Host "  [WARN] AutoIt: exit code $LASTEXITCODE" -ForegroundColor Yellow
        }
        Remove-Item $testScript -Force -ErrorAction SilentlyContinue
    } else {
        Write-Host "  [FAIL] AutoIt: not found in expected paths" -ForegroundColor Red
    }
} catch {
    Write-Host "  [FAIL] AutoIt: $_" -ForegroundColor Red
}

# Test AutoHotkey
try {
    $ahkExe = Get-Command "C:\Program Files\AutoHotkey\AutoHotkey.exe" -ErrorAction SilentlyContinue
    if (-not $ahkExe) { $ahkExe = Get-Command "C:\Program Files\AutoHotkey\AutoHotkeyU64.exe" -ErrorAction SilentlyContinue }
    if ($ahkExe) {
        # Create a minimal AHK script that does nothing
        $testScript = "$env:TEMP\winbot-smoke-test.ahk"
        "ExitApp(0)" | Out-File $testScript -Encoding ASCII
        $ahkResult = & $ahkExe.Source $testScript 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  [PASS] AutoHotkey: $($ahkExe.Source)" -ForegroundColor Green
            $smokePassed++
        } else {
            Write-Host "  [WARN] AutoHotkey: exit code $LASTEXITCODE" -ForegroundColor Yellow
        }
        Remove-Item $testScript -Force -ErrorAction SilentlyContinue
    } else {
        Write-Host "  [FAIL] AutoHotkey: not found in expected paths" -ForegroundColor Red
    }
} catch {
    Write-Host "  [FAIL] AutoHotkey: $_" -ForegroundColor Red
}

# Test NSSM
try {
    $nssmExe = Get-Command nssm -ErrorAction SilentlyContinue
    if (-not $nssmExe) { $nssmExe = Get-Command "C:\ProgramData\chocolatey\bin\nssm.exe" -ErrorAction SilentlyContinue }
    if ($nssmExe) {
        $nssmVer = & $nssmExe.Source version 2>&1 | Select-Object -First 1
        Write-Host "  [PASS] NSSM: $nssmVer" -ForegroundColor Green
        $smokePassed++
    } else {
        Write-Host "  [WARN] NSSM: not found (service installation will fail)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  [FAIL] NSSM: $_" -ForegroundColor Red
}

Write-Host "`n  Smoke tests: $smokePassed / $smokeTotal passed" -ForegroundColor $(if ($smokePassed -eq $smokeTotal) { "Green" } else { "Yellow" })

if ($smokePassed -lt $smokeTotal) {
    Write-Host "  Some tools may need reinstallation." -ForegroundColor Yellow
}
