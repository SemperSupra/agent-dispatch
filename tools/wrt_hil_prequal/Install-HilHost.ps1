param(
  [switch]$CheckOnly,
  [switch]$Install
)
$ErrorActionPreference = 'Stop'
if (-not $CheckOnly -and -not $Install) { $CheckOnly = $true }
$required = @('ssh','python','curl.exe','tar.exe')
$missing = @()
foreach ($name in $required) {
  if (-not (Get-Command $name -ErrorAction SilentlyContinue)) { $missing += $name }
}
if ($Install) {
  Write-Host 'Windows is a staging/admin surface for this campaign; Linux remains the preferred HIL executor.'
  if ($missing.Count -gt 0) {
    throw "Missing required commands: $($missing -join ', '). Install them before HIL use."
  }
}
$result = [ordered]@{
  schema = 'wrt-hil-host-windows-check/v1'
  mode = $(if ($Install) {'install-validate'} else {'check-only'})
  missing = $missing
  qemu_optional = [bool](Get-Command qemu-system-x86_64 -ErrorAction SilentlyContinue)
  serial_ports = @(
    Get-CimInstance Win32_SerialPort -ErrorAction SilentlyContinue |
      Select-Object -ExpandProperty DeviceID
  )
}
$result | ConvertTo-Json -Depth 4
if ($missing.Count -gt 0) { exit 1 }
