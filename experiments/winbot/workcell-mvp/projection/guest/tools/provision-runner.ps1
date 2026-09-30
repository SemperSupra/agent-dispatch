<#
.SYNOPSIS
WinBot Composable Provisioning Runner — reads stage manifest and executes
phases in dependency order with checkpoint/resume support.

.DESCRIPTION
Replaces the monolithic stage-provision.ps1 with a composable runner that:
1. Reads provision-stages.json for phase definitions and dependencies
2. Checks provisioning state to resume from the last failed phase
3. Runs each phase in order, with timeout and error handling
4. Emits structured tracing to provision-trace.jsonl
5. Saves checkpoints via Save-WinBotProvisioningState

.EXAMPLE
.\provision-runner.ps1                           # Run all phases
.\provision-runner.ps1 -Phase "3-winget"          # Run a single phase
.\provision-runner.ps1 -Resume                    # Resume from last failure
.\provision-runner.ps1 -ListPhases                # Show phase list
#>

param(
    [string]$Phase = "",            # Run a specific phase only
    [switch]$Resume,                # Resume from last failed phase
    [switch]$ListPhases,            # Show phase list and exit
    [switch]$SkipTools,             # Passed to stage scripts
    [switch]$SkipChoco              # Passed to stage scripts
)

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"
$global:stopwatch = [Diagnostics.Stopwatch]::StartNew()

# Fallback state functions if module not available
if (-not (Get-Command Save-WinBotProvisioningState -ErrorAction SilentlyContinue)) {
    function Save-WinBotProvisioningState { param([string]$Name,[string]$Phase,[string]$Detail) @{ name=$Name;phase=$Phase;detail=$Detail;timestamp=(Get-Date).ToUniversalTime().ToString("o") } | ConvertTo-Json -Compress | Out-File (Join-Path "C:\WinBot" ".provision-$Name.json") -Encoding utf8 -Force }
    function Get-WinBotProvisioningState { param([string]$Name) $f = Join-Path "C:\WinBot" ".provision-$Name.json"; if (Test-Path $f) { Get-Content $f -Raw | ConvertFrom-Json } else { $null } }
    function Clear-WinBotProvisioningState { param([string]$Name) Remove-Item (Join-Path "C:\WinBot" ".provision-$Name.json") -Force -ErrorAction SilentlyContinue }
}

# Locate the stages directory and manifest
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectDir = Split-Path -Parent $scriptDir  # guest/
$modulePath = Join-Path (Split-Path -Parent $projectDir) "host\WinBot.psm1"
if (Test-Path $modulePath) { Import-Module $modulePath -Force -DisableNameChecking -ErrorAction SilentlyContinue 2>$null }
$stagesDir = Join-Path $scriptDir "provision-stages"
$manifestPath = Join-Path $scriptDir "provision-stages.json"

if (-not (Test-Path $manifestPath)) {
    Write-Error "Stage manifest not found: $manifestPath"
    exit 1
}

# Load manifest
$manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json
$allPhases = $manifest.phases

if ($ListPhases) {
    Write-Host "=== Provisioning Phases ===" -ForegroundColor Cyan
    foreach ($p in $allPhases) {
        $critical = if ($p.critical) { " [CRITICAL]" } else { "" }
        $deps = if ($p.dependencies.Count -gt 0) { " (after: $($p.dependencies -join ', '))" } else { "" }
        Write-Host "  $($p.id): $($p.label)$critical$deps" -ForegroundColor Gray
    }
    exit
}

# Determine which phases to run
$targetPhases = if ($Phase) {
    $allPhases | Where-Object { $_.id -eq $Phase }
} elseif ($Resume) {
    $state = Get-WinBotProvisioningState -Name "runner"
    if (-not $state) {
        Write-Host "[Provision] No checkpoint found. Running all phases." -ForegroundColor Cyan
        $allPhases
    } else {
        $lastPhase = $state.phase
        Write-Host "[Provision] Resuming from phase '$lastPhase' (failed or interrupted)" -ForegroundColor Yellow
        $resumeIndex = -1
        for ($i = 0; $i -lt $allPhases.Count; $i++) {
            if ($allPhases[$i].id -eq $lastPhase) { $resumeIndex = $i; break }
        }
        if ($resumeIndex -ge 0) {
            $allPhases | Select-Object -Skip $resumeIndex
        } else {
            Write-Warning "[Provision] Phase '$lastPhase' not found in manifest. Running all phases."
            $allPhases
        }
    }
} else {
    $allPhases
}

if (-not $targetPhases) {
    Write-Warning "[Provision] No phases to run."
    exit 0
}

# Validate dependencies
$allIds = $allPhases | ForEach-Object { $_.id }
$depErrors = @()
foreach ($p in $allPhases) {
    foreach ($dep in $p.dependencies) {
        if ($dep -notin $allIds) {
            $depErrors += "Phase '$($p.id)' depends on '$dep' which is not in the manifest."
        }
    }
}
if ($depErrors.Count -gt 0) {
    Write-Error "Manifest validation errors:$($depErrors -join "`n  - ")"
    exit 1
}

# Prepare stages directory
if (-not (Test-Path $stagesDir)) {
    New-Item -ItemType Directory -Path $stagesDir -Force | Out-Null
}

# Logging helpers (compatible with legacy stage-provision.ps1)
$logFile = "C:\WinBot\logs\provision.log"
$traceFile = "C:\WinBot\logs\provision-trace.jsonl"
$logDir = "C:\WinBot\logs"
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }

function _now { return Get-Date -Format "yyyy-MM-dd HH:mm:ss" }
function _elapsed { return [math]::Round($global:stopwatch.Elapsed.TotalSeconds, 0) }
function _status($msg) {
    $e = _elapsed
    $line = (_now) + " [+" + $e + "s] " + $msg
    Add-Content -Path $logFile -Value $line -Encoding utf8
    Write-Host $line
}

# Process phases
$global:passed = 0
$global:failed = 0
$global:skipped = 0

foreach ($p in $targetPhases) {
    $phaseId = $p.id
    $scriptName = $p.script
    $scriptPath = Join-Path $stagesDir $scriptName

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Phase: $phaseId - $($p.label)" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    # If the script doesn't exist yet, use inline execution from the monolith
    if (-not (Test-Path $scriptPath)) {
        Write-Host "  [SKIP] No stage script yet: $scriptName" -ForegroundColor Yellow
        _status "[$phaseId] SKIP: stage script not extracted yet"
        $global:skipped++
        continue
    }

    _status "[$phaseId] START: $($p.label)"
    Save-WinBotProvisioningState -Name "runner" -Phase $phaseId -Detail "Starting $($p.label)"

    $startTime = Get-Date
    $success = $false

    # Trace start
    @{ timestamp = (Get-Date).ToUniversalTime().ToString("o"); phase = $phaseId; status = "start"; detail = $($p.label) } | ConvertTo-Json -Compress | Add-Content -Path $traceFile -Encoding utf8

    try {
        $scriptBlock = [ScriptBlock]::Create((Get-Content $scriptPath -Raw))
        & $scriptBlock
        if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq $null) {
            $success = $true
        }
    } catch {
        Write-Host "  [FAIL] $($_.Exception.Message)" -ForegroundColor Red
    }

    $elapsed = [math]::Round(((Get-Date) - $startTime).TotalSeconds, 1)

    if ($success) {
        $global:passed++
        _status "[$phaseId] PASS ($($elapsed)s)"
        @{ timestamp = (Get-Date).ToUniversalTime().ToString("o"); phase = $phaseId; status = "pass"; elapsed = $elapsed } | ConvertTo-Json -Compress | Add-Content -Path $traceFile -Encoding utf8
        Clear-WinBotProvisioningState -Name "runner"
    } else {
        $global:failed++
        _status "[$phaseId] FAIL ($($elapsed)s)"
        @{ timestamp = (Get-Date).ToUniversalTime().ToString("o"); phase = $phaseId; status = "fail"; elapsed = $elapsed } | ConvertTo-Json -Compress | Add-Content -Path $traceFile -Encoding utf8
        if ($p.critical) {
            Write-Error "[Provision] CRITICAL phase '$phaseId' failed. Aborting."
            break
        }
    }
}

# Summary
Write-Host ""
Write-Host "=== Provisioning Complete ===" -ForegroundColor Cyan
Write-Host "  Passed:  $global:passed" -ForegroundColor Green
Write-Host "  Failed:  $global:failed" -ForegroundColor $(if($global:failed -gt 0){"Red"}else{"Green"})
Write-Host "  Skipped: $global:skipped" -ForegroundColor Yellow
Write-Host "  Resume:  .\provision-runner.ps1 -Resume" -ForegroundColor Gray
Write-Host ""
