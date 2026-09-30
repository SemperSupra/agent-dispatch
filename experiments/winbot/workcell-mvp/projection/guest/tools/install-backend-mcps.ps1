# WinBot: Install Backend MCP Servers - revula, ghidra-mcp, pyghidra-mcp
# Run inside the VM AFTER RE tools are installed.
# Usage: powershell -ExecutionPolicy Bypass -File install-backend-mcps.ps1

param(
    [string[]]$MCPs = @("revula", "ghidra-mcp", "pyghidra-mcp"),
    [string]$GhidraPath = "C:\WinBot\tools\Ghidra",
    [switch]$SkipRevula,
    [switch]$SkipGhidraMCP,
    [switch]$SkipPyGhidraMCP
)

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
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "  SAFETY GUARDRAIL: HOST PROTECTION" -ForegroundColor Red
    Write-Host "  This script MUST only run inside a Hyper-V VM." -ForegroundColor Red; Write-Host "  Run PowerShell as Administrator to use this script." -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Red
    exit 1
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  WinBot - Backend MCP Server Installer" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$mcpDir = "C:\WinBot\tools\mcp-servers"
if (-not (Test-Path $mcpDir)) { New-Item -ItemType Directory -Path $mcpDir -Force | Out-Null }

$results = @{}
$ghidraRoot = $GhidraPath

# ============================================================
# revula - Universal RE MCP - 107 tools, pip-installable
# ============================================================
if (-not $SkipRevula) {
    Write-Host "[revula] Installing revula MCP server..." -ForegroundColor Cyan
    try {
        Write-Host "  Installing via pip..." -ForegroundColor Gray
        python -m pip install revula --quiet 2>&1 | Out-Null
        $check = python -c "import revula; print(getattr(revula, '__version__', 'installed'))" 2>&1
        Write-Host "  revula: $check" -ForegroundColor Green

        $launchScript = @'
# WinBot-managed - revula MCP launch script - port 9001
python -m revula --port 9001 --host 127.0.0.1
'@
        $launchScript | Out-File (Join-Path $mcpDir "start-revula.ps1") -Encoding utf8
        $results["revula"] = @{ installed = $true; port = 9001; launch = "$mcpDir\start-revula.ps1" }
        Write-Host "  revula MCP: OK - port 9001" -ForegroundColor Green
    } catch {
        Write-Warning "  revula install failed: $_"
        $results["revula"] = @{ installed = $false; error = $_.Exception.Message }
    }
}

# ============================================================
# ghidra-mcp - 249-tool Ghidra plugin + Python bridge
# ============================================================
if (-not $SkipGhidraMCP) {
    Write-Host "[ghidra-mcp] Installing Ghidra MCP server..." -ForegroundColor Cyan

    $ghidraHeadless = Join-Path $ghidraRoot "support\analyzeHeadless.bat"
    if (-not (Test-Path $ghidraHeadless)) {
        Write-Warning "  Ghidra not found at: $ghidraRoot"
        Write-Warning "  Install Ghidra first: install-ghidra.ps1"
        $results["ghidra-mcp"] = @{ installed = $false; error = "Ghidra not installed" }
    } else {
        try {
            $gmcpDir = "$mcpDir\ghidra-mcp"
            if (Test-Path $gmcpDir) {
                Write-Host "  Updating existing clone..." -ForegroundColor Gray
                Push-Location $gmcpDir; git pull 2>&1 | Out-Null; Pop-Location
            } else {
                Write-Host "  Cloning from github.com/bethington/ghidra-mcp..." -ForegroundColor Gray
                git clone https://github.com/bethington/ghidra-mcp.git $gmcpDir 2>&1 | Out-Null
            }

            # Install Python deps
            $pyReq = Join-Path $gmcpDir "requirements.txt"
            if (Test-Path $pyReq) {
                python -m pip install -r $pyReq --quiet 2>&1 | Out-Null
            }

            # Build Ghidra extension
            Write-Host "  Building Ghidra extension..." -ForegroundColor Gray
            $extDir = Join-Path $ghidraRoot "Ghidra\Extensions\ghidra_mcp"
            if (Test-Path $extDir) { Remove-Item $extDir -Recurse -Force }
            New-Item -ItemType Directory -Path $extDir -Force | Out-Null

            $pyBridge = Join-Path $gmcpDir "python_bridge"
            if (Test-Path $pyBridge) {
                Copy-Item "$pyBridge\*" $extDir -Recurse -Force
            }
            $serverPy = Join-Path $gmcpDir "server.py"
            if (Test-Path $serverPy) {
                Copy-Item $serverPy $extDir -Force
            } else {
                Copy-Item "$gmcpDir\*" $extDir -Recurse -Force -Exclude ".git"
            }

            $results["ghidra-mcp"] = @{ installed = $true; port = 9002; path = $gmcpDir }
            Write-Host "  ghidra-mcp: OK - port 9002" -ForegroundColor Green
        } catch {
            Write-Warning "  ghidra-mcp install failed: $_"
            $results["ghidra-mcp"] = @{ installed = $false; error = $_.Exception.Message }
        }
    }
}

# ============================================================
# pyghidra-mcp - Python-first Ghidra MCP with vector search
# ============================================================
if (-not $SkipPyGhidraMCP) {
    Write-Host "[pyghidra-mcp] Installing PyGhidra MCP server..." -ForegroundColor Cyan

    if (-not (Test-Path $ghidraHeadless)) {
        Write-Warning "  Ghidra not found at: $ghidraRoot"
        $results["pyghidra-mcp"] = @{ installed = $false; error = "Ghidra not installed" }
    } else {
        try {
            $pgmcpDir = "$mcpDir\pyghidra-mcp"
            if (Test-Path $pgmcpDir) {
                Write-Host "  Updating existing clone..." -ForegroundColor Gray
                Push-Location $pgmcpDir; git pull 2>&1 | Out-Null; Pop-Location
            } else {
                Write-Host "  Cloning from github.com/clearbluejar/pyghidra-mcp..." -ForegroundColor Gray
                git clone https://github.com/clearbluejar/pyghidra-mcp.git $pgmcpDir 2>&1 | Out-Null
            }

            Write-Host "  Installing Python dependencies..." -ForegroundColor Gray
            python -m pip install pyghidra chromadb --quiet 2>&1 | Out-Null
            $pyReq = Join-Path $pgmcpDir "requirements.txt"
            if (Test-Path $pyReq) {
                python -m pip install -r $pyReq --quiet 2>&1 | Out-Null
            }

            [Environment]::SetEnvironmentVariable("GHIDRA_INSTALL_DIR", $ghidraRoot, "Machine")
            $env:GHIDRA_INSTALL_DIR = $ghidraRoot

            $results["pyghidra-mcp"] = @{ installed = $true; port = 9003; path = $pgmcpDir }
            Write-Host "  pyghidra-mcp: OK - port 9003" -ForegroundColor Green
            Write-Host "  GHIDRA_INSTALL_DIR set to: $ghidraRoot" -ForegroundColor Gray
        } catch {
            Write-Warning "  pyghidra-mcp install failed: $_"
            $results["pyghidra-mcp"] = @{ installed = $false; error = $_.Exception.Message }
        }
    }
}

# ============================================================
# Summary
# ============================================================
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Backend MCP Installation Results" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
$allOk = $true
foreach ($name in ($results.Keys | Sort-Object)) {
    $r = $results[$name]
    $color = if ($r.installed) { "Green" } else { "Red" }
    $status = if ($r.installed) { "INSTALLED" } else { "FAILED" }
    Write-Host "  $name : $status" -ForegroundColor $color
    if (-not $r.installed) { $allOk = $false }
}
Write-Host "========================================"
if ($allOk) {
    Write-Host "  Backend MCPs installed." -ForegroundColor Green
    Write-Host "  Ports: revula=9001, ghidra-mcp=9002, pyghidra-mcp=9003" -ForegroundColor Gray
} else {
    Write-Host "  Some MCPs failed. Check errors above." -ForegroundColor Yellow
}
exit $(if ($allOk) { 0 } else { 1 })
