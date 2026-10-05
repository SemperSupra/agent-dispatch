[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)][string]$HostName,
    [Parameter(Position=1)][string]$OutputDir
)
$ErrorActionPreference = "Stop"
$Collector = Join-Path $PSScriptRoot "rdte\r1-readonly-collector.sh"
$Reducer = Join-Path $PSScriptRoot "rdte\r1-reduce.py"
if (-not (Get-Command ssh.exe -ErrorAction SilentlyContinue)) { throw "ssh.exe not found" }
if (-not (Get-Command scp.exe -ErrorAction SilentlyContinue)) { throw "scp.exe not found" }
if (-not $OutputDir) { $OutputDir = "wrt-r1-" + (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ") }
$OutputDir = [System.IO.Path]::GetFullPath($OutputDir)
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$Remote = "/tmp/rdte-r1-" + [Guid]::NewGuid().ToString("N")
try {
    $args = @("-o","BatchMode=yes",$HostName,"mkdir -p '$Remote' && sh -s -- '$Remote'")
    $p = Start-Process -FilePath "ssh.exe" -ArgumentList $args -RedirectStandardInput $Collector -NoNewWindow -Wait -PassThru
    if ($p.ExitCode -ne 0) { throw "R1 collector failed with ssh exit code $($p.ExitCode)" }
    & scp.exe -q -r "$($HostName):$Remote/." "$OutputDir/"
    if ($LASTEXITCODE -ne 0) { throw "R1 evidence retrieval failed with scp exit code $LASTEXITCODE" }
} finally {
    & ssh.exe -o BatchMode=yes $HostName "rm -rf '$Remote'" 2>$null | Out-Null
}
$Python = $null
foreach ($candidate in @("python3.exe","python.exe","py.exe")) {
    $cmd = Get-Command $candidate -ErrorAction SilentlyContinue
    if ($cmd) { $Python = $cmd.Source; break }
}
if (-not $Python) { throw "Python 3 not found" }
$Descriptor = Join-Path $OutputDir "device-descriptor.json"
if ([System.IO.Path]::GetFileName($Python) -ieq "py.exe") { & $Python -3 $Reducer $OutputDir -o $Descriptor } else { & $Python $Reducer $OutputDir -o $Descriptor }
if ($LASTEXITCODE -ne 0) { throw "R1 reducer failed" }
$d = Get-Content -Raw $Descriptor | ConvertFrom-Json
if ($d.write_authority -ne "DENIED_R1_READ_ONLY") { throw "Fail closed: write-authority invariant missing" }
[ordered]@{
 schema="rdte-wrt-r1-windows-wrapper/v1"
 host=$HostName
 output_dir=$OutputDir
 descriptor=$Descriptor
 write_authority=$d.write_authority
 r1_inventory_minimum_complete=[bool]$d.r1_inventory_minimum_complete
 ready_for_r2=[bool]$d.ready_for_r2
} | ConvertTo-Json
