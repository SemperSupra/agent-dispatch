# WinBot: Software Loadout Deployer
# Reads the tool catalog, resolves dependencies, installs tools in order.
# Usage:
#   .\deploy-loadout.ps1 -Loadout "windows-re"
#   .\deploy-loadout.ps1 -Loadout "windows-re" -DryRun
#   .\deploy-loadout.ps1 -Loadout "windows-re" -Unattended

param(
    [string]$Loadout = "",
    [string[]]$Tools = @(),
    [string]$Name = "",
    [switch]$DryRun,
    [switch]$Unattended,
    [string]$CatalogPath = ""
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw "This script requires Administrator privileges. Run PowerShell as Administrator." }
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

if (-not $CatalogPath) { $CatalogPath = Join-Path $scriptDir "tools\catalog.json" }
if (-not (Test-Path $CatalogPath)) { throw "Catalog not found: $CatalogPath" }

$catalog = Get-Content $CatalogPath -Raw | ConvertFrom-Json
$allTools = $catalog.tools
$loadoutDefs = $catalog.loadout_templates

# ============================================================
# Resolve tool list
# ============================================================
$toolNames = @()
if ($Tools.Count -gt 0) {
    $toolNames = $Tools
    $Name = if ($Name) { $Name } else { "custom" }
    $toolList = $Tools -join ", "
    Write-Host "[WinBot] Deploying custom tool set: $toolList" -ForegroundColor Cyan
} elseif ($Loadout) {
    $template = $loadoutDefs.PSObject.Properties | Where-Object { $_.Name -eq $Loadout }
    if (-not $template) {
        Write-Host "[WinBot] Available loadouts:" -ForegroundColor Yellow
        foreach ($prop in $loadoutDefs.PSObject.Properties) {
            $line = "  " + $prop.Name + " - " + $prop.Value.display_name
            Write-Host $line -ForegroundColor Gray
        }
        throw "Loadout '$Loadout' not found in catalog."
    }
    $ld = $template.Value
    $toolNames = @($ld.tools)
    $Name = $Loadout
    Write-Host "[WinBot] Deploying loadout: $($ld.display_name)" -ForegroundColor Cyan
    Write-Host "[WinBot] Description: $($ld.description)" -ForegroundColor Gray
} else {
    throw "Specify -Loadout <name> or -Tools @('tool1','tool2')."
}

$toolListStr = $toolNames -join ", "
Write-Host "[WinBot] Requested tools: $toolListStr" -ForegroundColor Gray

# ============================================================
# Dependency resolution - topological sort
# ============================================================
Write-Host "[1/4] Resolving dependencies..." -ForegroundColor Yellow

$resolved = [System.Collections.ArrayList]::new()
$visited = @{}
$processing = @{}

function Resolve-Tool($toolName) {
    if ($visited.ContainsKey($toolName)) { return }
    if ($processing.ContainsKey($toolName)) {
        Write-Warning "  Circular dependency detected: $toolName"
        return
    }
    $processing[$toolName] = $true

    $toolDef = $allTools.PSObject.Properties | Where-Object { $_.Name -eq $toolName }
    if (-not $toolDef) {
        Write-Warning "  Tool '$toolName' not found in catalog - skipping"
        $visited[$toolName] = $true
        return
    }
    $td = $toolDef.Value

    foreach ($dep in $td.dependencies) {
        Resolve-Tool $dep
    }

    $null = $resolved.Add($toolName)
    $visited[$toolName] = $true
}

foreach ($tn in $toolNames) {
    Resolve-Tool $tn
}

$resolvedCount = $resolved.Count
Write-Host "  Resolved $resolvedCount tools - including dependencies:" -ForegroundColor Green
foreach ($tn in $resolved) {
    $td = $allTools.PSObject.Properties | Where-Object { $_.Name -eq $tn }
    if ($td) {
        $display = $td.Value.display_name
        $depStr = ""
        if ($td.Value.dependencies.Count -gt 0) {
            $depList = $td.Value.dependencies -join ", "
            $depStr = " - needs: $depList"
        }
        Write-Host "    $tn - $display$depStr" -ForegroundColor Gray
    }
}

# ============================================================
# Check existing installations
# ============================================================
Write-Host "[2/4] Checking existing installations..." -ForegroundColor Yellow

$toInstall = [System.Collections.ArrayList]::new()
$toSkip = [System.Collections.ArrayList]::new()
$willFail = [System.Collections.ArrayList]::new()

foreach ($tn in $resolved) {
    $td = $allTools.PSObject.Properties | Where-Object { $_.Name -eq $tn }
    if (-not $td) { continue }
    $td = $td.Value

    if ($td.human_only -and $Unattended) {
        Write-Host "  SKIP: $tn - human-only, unattended mode" -ForegroundColor Yellow
        $null = $toSkip.Add($tn)
        continue
    }

    if (-not $td.script) {
        Write-Host "  NOTE: $tn - no installer script, bundled with parent" -ForegroundColor Gray
        $null = $toSkip.Add($tn)
        continue
    }

    # Run verify
    $installed = $false
    $verify = $td.verify
    if ($verify.type -eq "command") {
        try {
            $vcmd = $verify.command
            $vargs = @($verify.args)
            $result = & $vcmd $vargs 2>&1
            if ($LASTEXITCODE -eq $verify.expect_exit) { $installed = $true }
        } catch { }
    } elseif ($verify.type -eq "path") {
        foreach ($p in $verify.paths) {
            if (Test-Path ([Environment]::ExpandEnvironmentVariables($p))) {
                $installed = $true; break
            }
        }
    }

    if ($installed) {
        Write-Host "  SKIP: $tn - already installed" -ForegroundColor Green
        $null = $toSkip.Add($tn)
    } else {
        $tnScript = $td.script
        $scriptPath = Join-Path $scriptDir "tools\$tnScript"
        if (Test-Path $scriptPath) {
            $timeStr = $td.install_time_minutes
            $dn = $td.display_name
            Write-Host "  INSTALL: $tn - $dn [$timeStr min]" -ForegroundColor Cyan
            $null = $toInstall.Add($tn)
        } else {
            Write-Host "  ERROR: $tn - script not found: $tnScript" -ForegroundColor Red
            $null = $willFail.Add($tn)
        }
    }
}

# ============================================================
# Deployment plan
# ============================================================
$installCount = $toInstall.Count
$skipCount = $toSkip.Count
$failCount = $willFail.Count

Write-Host "[3/4] Deployment plan:" -ForegroundColor Yellow
Write-Host "  Install: $installCount tool(s)" -ForegroundColor Cyan
Write-Host "  Skip:    $skipCount tool(s) - already installed or bundled" -ForegroundColor Gray
if ($failCount -gt 0) {
    $failList = $willFail -join ", "
    Write-Host "  Error:   $failCount tool(s) - missing scripts: $failList" -ForegroundColor Red
}

$totalTime = 0
foreach ($tn in $toInstall) {
    $td = $allTools.PSObject.Properties | Where-Object { $_.Name -eq $tn }
    if ($td) { $totalTime += $td.Value.install_time_minutes }
}
Write-Host "  Est time: ~$totalTime min" -ForegroundColor Gray

if ($DryRun) {
    Write-Host ""
    Write-Host "[DryRun] Would install $installCount tools. No changes made." -ForegroundColor Cyan
    return @{
        Loadout = $Name
        Plan = @{ Install = $toInstall; Skip = $toSkip; Error = $willFail }
        EstimatedMinutes = $totalTime
    }
}

if ($installCount -eq 0) {
    Write-Host "[WinBot] Nothing to install - all tools already present." -ForegroundColor Green
    return @{ Loadout = $Name; Installed = @(); Skipped = $toSkip; Failed = @() }
}

# ============================================================
# Install each tool
# ============================================================
Write-Host "[4/4] Installing $installCount tool(s)..." -ForegroundColor Yellow

$installedOk = [System.Collections.ArrayList]::new()
$failedOk = [System.Collections.ArrayList]::new()
$toolIndex = 0

foreach ($tn in $toInstall) {
    $toolIndex = $toolIndex + 1
    $td = $allTools.PSObject.Properties | Where-Object { $_.Name -eq $tn }
    if (-not $td) { continue }
    $td = $td.Value

    $tnScript = $td.script
    $scriptPath = Join-Path $scriptDir "tools\$tnScript"
    $dn = $td.display_name

    Write-Host "  [$toolIndex/$installCount] Installing $dn..." -ForegroundColor Cyan
    Write-Host "    Script: $scriptPath" -ForegroundColor Gray

    try {
        $startTime = Get-Date
        $result = & powershell -ExecutionPolicy Bypass -File $scriptPath 2>&1
        $duration = [math]::Round(((Get-Date) - $startTime).TotalSeconds, 0)
        if ($LASTEXITCODE -eq 0) {
            Write-Host "    OK - $duration s" -ForegroundColor Green
            $null = $installedOk.Add($tn)
        } else {
            Write-Host "    WARNING: Exit code $LASTEXITCODE - $duration s" -ForegroundColor Yellow
            $null = $installedOk.Add($tn)
        }
    } catch {
        Write-Host "    FAILED: $_" -ForegroundColor Red
        $null = $failedOk.Add($tn)
    }
}

# ============================================================
# Summary
# ============================================================
$okCount = $installedOk.Count
$badCount = $failedOk.Count
$success = ($badCount -eq 0)

Write-Host ""
Write-Host "========================================" -ForegroundColor $(if ($success) { "Green" } else { "Yellow" })
Write-Host "  Loadout Deployment: $Name" -ForegroundColor $(if ($success) { "Green" } else { "Yellow" })
Write-Host "========================================" -ForegroundColor $(if ($success) { "Green" } else { "Yellow" })
Write-Host "  Installed: $okCount" -ForegroundColor Green
Write-Host "  Skipped:   $skipCount - already present or bundled" -ForegroundColor Gray
if ($badCount -gt 0) {
    Write-Host "  Failed:    $badCount" -ForegroundColor Red
    foreach ($f in $failedOk) { Write-Host "    - $f" -ForegroundColor Red }
}
Write-Host "========================================" -ForegroundColor $(if ($success) { "Green" } else { "Yellow" })

if ($success) {
    Write-Host "  Run Test-WinBotHealth after reboot to verify all tools." -ForegroundColor Gray
}

return @{
    Loadout = $Name
    Installed = $installedOk
    Skipped = $toSkip
    Failed = $failedOk
    Success = $success
}
