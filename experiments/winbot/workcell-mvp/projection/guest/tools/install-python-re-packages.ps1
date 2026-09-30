# WinBot: Install Python RE packages (pefile, capstone, unicorn, yara-python)
# Run as Administrator on the VM
# Usage: powershell -ExecutionPolicy Bypass -File install-python-re-packages.ps1

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

Write-Host "[WinBot] Installing Python RE toolkit..." -ForegroundColor Cyan

$packages = @(
    @{name="pefile";       import="pefile";        desc="PE file analysis"},
    @{name="capstone";     import="capstone";      desc="Disassembly engine"},
    @{name="unicorn";      import="unicorn";       desc="CPU emulation framework"},
    @{name="yara-python";  import="yara";          desc="YARA pattern matching"},
    @{name="pyelftools";   import="elftools";      desc="ELF file analysis"},
    @{name="python-magic"; import="magic";          desc="File type detection"},
    @{name="lief";         import="lief";           desc="Binary parsing/modification"},
    @{name="keystone-engine"; import="keystone";    desc="Assembly engine"}
)

$installed = @()
$failed = @()

foreach ($pkg in $packages) {
    Write-Host "  Installing $($pkg.name) ($($pkg.desc))..." -ForegroundColor Gray
    try {
        python -m pip install $pkg.name --quiet 2>&1 | Out-Null
        $installed += $pkg
    } catch {
        Write-Host "    WARNING: $($pkg.name) install failed: $_" -ForegroundColor Yellow
        $failed += $pkg
    }
}

# Verify
Write-Host "  Verifying imports..." -ForegroundColor Gray
$verifyScript = ""
foreach ($pkg in $installed) {
    $verifyScript += "import $($pkg.import); print('$($pkg.name): OK'); "
}
$verifyScript = "python -c `"$verifyScript`""
try {
    $result = Invoke-Expression $verifyScript 2>&1
    foreach ($line in ($result -split "`r`n")) {
        if ($line -match "OK") {
            Write-Host "    $line" -ForegroundColor Green
        }
    }
} catch {
    Write-Host "    Verification: $_" -ForegroundColor Yellow
}

Write-Host "[WinBot] Python RE toolkit: $($installed.Count) installed, $($failed.Count) failed" -ForegroundColor $(if($failed.Count -eq 0){"Green"}else{"Yellow"})
Write-Host "[WinBot] Agent usage: import pefile, capstone, unicorn, yara in /run/python scripts" -ForegroundColor Gray
