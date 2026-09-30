<#
.SYNOPSIS
Uninstall WinBot MCP server and related components from a machine.
Removes NSSM service, Scheduled Task, Python cache, and related config.
Safe to run on both host and guest machines.

.EXAMPLE
.\uninstall-mcp.ps1                  # Uninstall with confirmation
.\uninstall-mcp.ps1 -Force           # Skip confirmation
.\uninstall-mcp.ps1 -WhatIf          # Show what would be removed
#>

param(
    [switch]$Force,
    [switch]$WhatIf
)

$ErrorActionPreference = "Continue"

Write-Host "=== WinBot MCP Uninstall ===" -ForegroundColor Cyan

if (-not $Force -and -not $WhatIf) {
    Write-Warning "This will remove the WinBot API service, MCP server, and related configuration."
    $confirm = Read-Host "Continue? [y/N]"
    if ($confirm -notmatch '^[yY]') {
        Write-Host "Cancelled." -ForegroundColor Yellow
        exit 0
    }
}

$removed = @()
$skipped = @()

function _remove($path, $label) {
    if (Test-Path $path) {
        if ($WhatIf) {
            Write-Host "  [WHATIF] Would remove: $label ($path)" -ForegroundColor Yellow
        } else {
            try {
                Remove-Item $path -Recurse -Force -ErrorAction Stop
                Write-Host "  Removed: $label" -ForegroundColor Green
                $script:removed += $label
            } catch {
                Write-Warning "  Failed to remove $label : $_"
                $script:skipped += $label
            }
        }
    } else {
        Write-Host "  Not found: $label" -ForegroundColor Gray
    }
}

# 1. Stop and remove NSSM service
Write-Host "`n[1/5] Removing API service..." -ForegroundColor Yellow
$nssm = if (Test-Path "C:\ProgramData\chocolatey\bin\nssm.exe") {
    "C:\ProgramData\chocolatey\bin\nssm.exe"
} else {
    (Get-Command nssm -ErrorAction SilentlyContinue).Source
}
if ($nssm) {
    if ($WhatIf) {
        Write-Host "  [WHATIF] Would stop and remove WinBotAPI service" -ForegroundColor Yellow
    } else {
        Stop-Service WinBotAPI -Force -ErrorAction SilentlyContinue
        Start-Sleep 2
        & $nssm remove WinBotAPI confirm 2>$null
        Write-Host "  NSSM service removed" -ForegroundColor Green
        $removed += "WinBotAPI NSSM service"
    }
} else {
    Write-Host "  NSSM not found (already removed or not installed)" -ForegroundColor Gray
}

# 2. Remove Scheduled Task
Write-Host "`n[2/5] Removing Scheduled Task..." -ForegroundColor Yellow
$task = Get-ScheduledTask -TaskName "WinBot API Server" -ErrorAction SilentlyContinue
if ($task) {
    if ($WhatIf) {
        Write-Host "  [WHATIF] Would unregister Scheduled Task" -ForegroundColor Yellow
    } else {
        Stop-ScheduledTask -TaskName "WinBot API Server" -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName "WinBot API Server" -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host "  Scheduled Task removed" -ForegroundColor Green
        $removed += "WinBot API Scheduled Task"
    }
} else {
    Write-Host "  Scheduled Task not found" -ForegroundColor Gray
}

# 3. Remove Python cache
Write-Host "`n[3/5] Cleaning Python cache..." -ForegroundColor Yellow
_remove "C:\WinBot\api\__pycache__" "Python cache"
_remove "C:\WinBot\api\endpoints\__pycache__" "Endpoints cache"
_remove "C:\WinBot\api\core\__pycache__" "Core cache"

# 4. Remove API token (security)
Write-Host "`n[4/5] Removing API token..." -ForegroundColor Yellow
_remove "C:\WinBot\.api_token" "API token file"

# 5. Remove MCP config
Write-Host "`n[5/5] Removing MCP configuration..." -ForegroundColor Yellow
_remove "C:\WinBot\api\mcp_config.json" "MCP config"
_remove "C:\WinBot\api\.mcp_state" "MCP state"

# Kill any remaining Python processes
if (-not $WhatIf) {
    $py = Get-Process python -ErrorAction SilentlyContinue
    if ($py) {
        $py | Stop-Process -Force
        Write-Host "`n  Stopped $($py.Count) Python process(es)" -ForegroundColor Green
    }
}

Write-Host ""
if ($WhatIf) {
    Write-Host "WHATIF: No changes made." -ForegroundColor Yellow
} else {
    Write-Host "=== Uninstall Complete ===" -ForegroundColor Green
    Write-Host "  Removed: $($removed.Count) items" -ForegroundColor Green
    if ($skipped.Count -gt 0) {
        Write-Host "  Skipped: $($skipped.Count) items (check permissions)" -ForegroundColor Yellow
        foreach ($s in $skipped) { Write-Host "    - $s" -ForegroundColor Yellow }
    }
    Write-Host ""
    Write-Host "  Note: Log files at C:\WinBot\logs\ are preserved." -ForegroundColor Gray
    Write-Host "  Note: C:\WinBot\api\ source files are preserved." -ForegroundColor Gray
    Write-Host "  To remove everything: Remove-Item C:\WinBot -Recurse -Force" -ForegroundColor Gray
}
