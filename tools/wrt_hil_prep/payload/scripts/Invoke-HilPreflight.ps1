[CmdletBinding()]
param(
    [string]$DutA,
    [string]$DutB
)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$verify = Join-Path $PSScriptRoot "Verify-Bundle.ps1"

$bundleOk = $false
try {
    & $verify | Out-Host
    $bundleOk = $true
} catch {
    Write-Warning $_
}

$serial = @(
    Get-CimInstance Win32_SerialPort -ErrorAction SilentlyContinue |
        ForEach-Object {
            [ordered]@{
                device_id = $_.DeviceID
                name = $_.Name
                pnp_device_id = $_.PNPDeviceID
            }
        }
)

$usbSerialHints = @(
    Get-CimInstance Win32_PnPEntity -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -match '(?i)(FTDI|FT232|CP210|CH340|CH341|USB[- ]?Serial|UART)'
        } |
        ForEach-Object {
            [ordered]@{
                name = $_.Name
                pnp_device_id = $_.PNPDeviceID
                status = $_.Status
            }
        }
)

function Test-R1Ssh {
    param([string]$Target)
    if (-not $Target) { return $null }
    $ssh = Get-Command ssh.exe -ErrorAction SilentlyContinue
    if (-not $ssh) {
        return [ordered]@{ target=$Target; ssh_reachable=$false; reason="ssh.exe missing"; r1_eligible=$false }
    }
    $out = & $ssh.Source -o BatchMode=yes -o ConnectTimeout=4 $Target "printf 'R1_SSH_OK
'; (cat /tmp/sysinfo/board_name 2>/dev/null || true)" 2>&1
    $ok = ($LASTEXITCODE -eq 0 -and ($out -join "
") -match 'R1_SSH_OK')
    return [ordered]@{
        target = $Target
        ssh_reachable = $ok
        r1_eligible = ($ok -and $bundleOk)
        observation = ($out -join "
")
        next_action = $(if ($ok -and $bundleOk) { ".\scripts\R1-Readonly-Remote.ps1 $Target" } else { "DO_NOT_FLASH; resolve access/identity first" })
    }
}

$duts = @()
if ($DutA) { $duts += Test-R1Ssh $DutA }
if ($DutB) { $duts += Test-R1Ssh $DutB }

[ordered]@{
    schema = "wrt-hil-arrival-preflight/v1"
    authority = "R1_READ_ONLY"
    bundle_verified = $bundleOk
    serial_ports = $serial
    usb_serial_hints = $usbSerialHints
    serial_requirement = "3.3V TTL; 115200 8N1; GND/TX/RX only; no VCC"
    dut_checks = $duts
    prohibited = @(
        "fw_setenv","sysupgrade","package installation","UCI mutation",
        "reboot/power-cycle experiments","MTD/UBI writes","bootloader writes"
    )
} | ConvertTo-Json -Depth 6
