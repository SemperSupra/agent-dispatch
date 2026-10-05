$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Manifest = Join-Path $Root "metadata\SHA256SUMS"
Get-Content $Manifest | ForEach-Object {
    if ($_ -match '^([0-9a-f]{64})  (.+)$') {
        $Expected = $Matches[1]
        $Relative = $Matches[2]
        $Path = Join-Path $Root ($Relative -replace '/', '\')
        $Actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
        if ($Actual -ne $Expected) { throw "SHA256 mismatch: $Relative" }
    }
}
Write-Host "Bundle verification: PASS"
