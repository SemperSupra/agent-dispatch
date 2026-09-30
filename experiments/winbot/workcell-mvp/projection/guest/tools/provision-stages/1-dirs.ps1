# Stage: 1-dirs — Create WinBot directory structure
# Extracted from stage-provision.ps1 Step 1

Write-Host "  Creating WinBot directories..." -ForegroundColor Gray
$dirs = @(
    "C:\WinBot\api\endpoints","C:\WinBot\sessions\screenshots",
    "C:\WinBot\sessions\logs","C:\WinBot\sessions\scripts",
    "C:\WinBot\sessions\artifacts","C:\WinBot\tools","C:\WinBot\logs"
)
foreach ($d in $dirs) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}
# Verify
$allOk = $true
foreach ($d in $dirs) { if (-not (Test-Path $d)) { Write-Warning "  MISSING: $d"; $allOk = $false } }
if ($allOk) { Write-Host "  Directories created OK" -ForegroundColor Green }
