[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Port,
    [int]$Seconds = 60,
    [string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
if ($Seconds -lt 1) { throw 'Seconds must be >= 1' }
if (-not $OutputDirectory) {
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $OutputDirectory = "wrt-serial-$stamp"
}
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$transcript = Join-Path $OutputDirectory 'serial-transcript.log'
$metadata = Join-Path $OutputDirectory 'serial-capture.json'

$serial = [System.IO.Ports.SerialPort]::new($Port,115200,[System.IO.Ports.Parity]::None,8,[System.IO.Ports.StopBits]::One)
$serial.Handshake = [System.IO.Ports.Handshake]::None
$serial.DtrEnable = $false
$serial.RtsEnable = $false
$serial.ReadTimeout = 250
$serial.WriteTimeout = 250

$start = [DateTime]::UtcNow
$deadline = $start.AddSeconds($Seconds)
$buffer = New-Object System.Collections.Generic.List[byte]
try {
    $serial.Open()
    while ([DateTime]::UtcNow -lt $deadline) {
        $n = $serial.BytesToRead
        if ($n -gt 0) {
            $tmp = New-Object byte[] $n
            $read = $serial.Read($tmp,0,$n)
            for ($i=0; $i -lt $read; $i++) { $buffer.Add($tmp[$i]) }
        } else {
            Start-Sleep -Milliseconds 50
        }
    }
}
finally {
    if ($serial.IsOpen) { $serial.Close() }
    $serial.Dispose()
}
$end = [DateTime]::UtcNow
$transcriptPath = [System.IO.Path]::GetFullPath($transcript)
[System.IO.File]::WriteAllBytes($transcriptPath,$buffer.ToArray())
$sha = (Get-FileHash -Algorithm SHA256 -Path $transcript).Hash.ToLowerInvariant()

[ordered]@{
    schema = 'rdte-wrt-serial-capture/v1'
    authority = 'SENSOR_ONLY_NO_ACTUATION'
    device = $Port
    baud = 115200
    framing = '8N1'
    flow_control = 'none'
    duration_seconds = $Seconds
    captured_utc_start = $start.ToString('yyyy-MM-ddTHH:mm:ssZ')
    captured_utc_end = $end.ToString('yyyy-MM-ddTHH:mm:ssZ')
    bytes_captured = $buffer.Count
    transcript_sha256 = $sha
    serial_payload_bytes_transmitted = 0
    dtr_enabled = $false
    rts_enabled = $false
} | ConvertTo-Json -Depth 4 | Set-Content -Encoding UTF8 $metadata

$python = Get-Command python -ErrorAction SilentlyContinue
if ($python) {
    $candidates = @(
        (Join-Path $PSScriptRoot 'parse_wrt_serial_transcript.py'),
        (Join-Path $PSScriptRoot 'serial-observe.py')
    )
    $parser = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if ($parser) {
        & $python.Source $parser $transcript -o (Join-Path $OutputDirectory 'serial-observation.json')
        if ($LASTEXITCODE -ne 0) { throw 'serial transcript reducer failed' }
    }
}
Write-Output $OutputDirectory
