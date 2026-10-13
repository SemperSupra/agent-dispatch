#requires -Version 7.0
<#
Public fixed H1 nested-Hyper-V SOURCE CANDIDATE; not an admitted mission.
Preflight does read-only host and budget checks. Execute is for a SEPARATELY
ADMITTED fixed Agent Dispatch assignment ONLY. An environment-variable marker
is NOT sufficient authorization. This PR never runs Execute.
No private source, provider accounts, secrets, physical switch or host route.
#>
[CmdletBinding()]
param(
    [ValidateSet('Preflight','Execute')]
    [string]$Mode = 'Preflight'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$FileName = 'alpine-virt-3.24.2-x86_64.iso'
$SourceUrl = 'https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/x86_64/alpine-virt-3.24.2-x86_64.iso'
$ExpectedSha256 = '3ab424762af704b2c2a9e57df1dc37f982af260071504d977f2fb96822e7130b'
$ExpectedBytes = 69206016
$StartupRamBytes = 512MB
$VhdxSizeBytes = 1GB
$CpuCount = 2

function Check-Host {
    if ($env:GITHUB_ACTIONS -ne 'true' -or
        $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
        $env:RUNNER_OS -ne 'Windows') {
        throw 'Host is not a disposable GitHub-hosted Windows runner'
    }
    if ($env:GITHUB_RUN_ID -notmatch '^\d+$' -or
        $env:GITHUB_RUN_ATTEMPT -notmatch '^\d+$') {
        throw 'Host run identity absent'
    }
    if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) {
        throw 'Runner temporary directory absent'
    }
    $required = @(
        'Get-VM', 'New-VM', 'Start-VM', 'Stop-VM', 'Remove-VM',
        'New-VMSwitch', 'Get-VMSwitch', 'Remove-VMSwitch',
        'New-VHD', 'Add-VMHardDiskDrive', 'Add-VMDvdDrive',
        'Get-VMDvdDrive', 'Set-VMFirmware', 'Set-VMProcessor',
        'Set-VMMemory', 'Get-VMNetworkAdapter', 'Get-VMIntegrationService',
        'Get-VMHost'
    )
    $missing = @($required | Where-Object { -not (Get-Command $_ -ErrorAction SilentlyContinue) })
    if ($missing.Count -ne 0) {
        throw ('Missing required Hyper-V commands: ' + ($missing -join ', '))
    }
    $spec = Get-CimInstance -ClassName Win32_ComputerSystem
    $rootDrive = [System.IO.Path]::GetPathRoot($env:RUNNER_TEMP).Substring(0,1)
    $drive = Get-PSDrive -Name $rootDrive
    if ([int]$spec.NumberOfLogicalProcessors -lt 2 -or
        [int64]$spec.TotalPhysicalMemory -lt 8GB -or
        $drive.Free -lt 3GB) {
        throw 'Insufficient hosted CPU/memory/disk budget'
    }
}

$receipt = [ordered]@{
    EvidenceClass = 'PUBLIC_H1_FIXED_SOURCE_PREFLIGHT'
    Mode = $Mode
    AlpineVersion = '3.24.2'
    GuestIsoSha256 = $ExpectedSha256
    GuestBoot = 'NOT_RUN'
    GuestOsIdentity = 'NOT_ATTESTED'
    VSwitchPacketPath = 'NOT_RUN'
    ProductSafety = 'NOT_QUALIFIED'
    Cleanup = 'NOT_RUN'
}
$runRoot = $null
$vmName = $null
$switchName = $null
$createdRoot = $false
$createdSwitch = $false
$createdVm = $false
$failed = $false

try {
    Check-Host
    $receipt.HostControlPlane = 'AVAILABLE'
    if ($Mode -eq 'Preflight') {
        $receipt.Classification = 'PREFLIGHT_ONLY_NO_GUEST_BOOT'
        $receipt.AllowedNext = 'SEPARATELY_ADMITTED_TYPED_H1_ASSIGNMENT_REQUIRED'
    }
    else {
        # This is a secondary refusal guard. Real authorization must be
        # enforced by the Agent Dispatch typed workflow + admission.
        if ($env:GITHUB_EVENT_NAME -ne 'workflow_dispatch' -or
            $env:AGENT_DISPATCH_FIXED_PROBE -ne 'public-alpine-h1-v1') {
            throw 'ADMISSION_DENIED: fixed H1 workflow context absent'
        }
        $unique = $env:GITHUB_RUN_ID + '-' + $env:GITHUB_RUN_ATTEMPT
        $vmName = 'rdte-h1-' + $unique
        $switchName = 'rdte-private-' + $unique
        $runRoot = Join-Path $env:RUNNER_TEMP ('rdte-h1-' + $unique)
        $iso = Join-Path $runRoot $FileName
        $vhdx = Join-Path $runRoot 'empty-disposable.vhdx'
        if ((Test-Path -LiteralPath $runRoot) -or
            (Get-VM -Name $vmName -ErrorAction SilentlyContinue) -or
            (Get-VMSwitch -Name $switchName -ErrorAction SilentlyContinue)) {
            throw 'ADMISSION_DENIED: run-resource identity collision'
        }
        New-Item -ItemType Directory -Path $runRoot -ErrorAction Stop | Out-Null
        $createdRoot = $true

        # Fixed public HTTPS ISO, no user-supplied URL, credentials or redirects.
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $SourceUrl -MaximumRedirection 0 -OutFile $iso -ErrorAction Stop
        $size = (Get-Item -LiteralPath $iso).Length
        if ($size -ne $ExpectedBytes -or $size -gt 128MB) {
            throw 'HARNESS_FAILURE: ISO byte length mismatch'
        }
        $hash = (Get-FileHash -LiteralPath $iso -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($hash -ne $ExpectedSha256) {
            throw 'HARNESS_FAILURE: ISO digest mismatch'
        }
        $receipt.GuestIsoBytesVerified = $size

        # Private vSwitch has no host-management or external physical uplink.
        $sw = New-VMSwitch -Name $switchName -SwitchType Private -ErrorAction Stop
        $createdSwitch = $true
        if ($sw.SwitchType.ToString() -ne 'Private') {
            throw 'ORACLE_FAILURE: unexpected vSwitch attachment class'
        }
        $null = New-VM -Name $vmName -Generation 2 -MemoryStartupBytes $StartupRamBytes -NoVHD -Path $runRoot -SwitchName $switchName -ErrorAction Stop
        $createdVm = $true
        Set-VMMemory -VMName $vmName -DynamicMemoryEnabled:$false
        Set-VMProcessor -VMName $vmName -Count $CpuCount
        $null = New-VHD -Path $vhdx -SizeBytes $VhdxSizeBytes -Dynamic
        Add-VMHardDiskDrive -VMName $vmName -Path $vhdx
        Add-VMDvdDrive -VMName $vmName -Path $iso
        Set-VMFirmware -VMName $vmName -EnableSecureBoot Off
        $dvd = Get-VMDvdDrive -VMName $vmName
        Set-VMFirmware -VMName $vmName -FirstBootDevice $dvd
        $adapter = @(Get-VMNetworkAdapter -VMName $vmName)
        if ($adapter.Count -ne 1 -or $adapter[0].SwitchName -ne $switchName) {
            throw 'ORACLE_FAILURE: unexpected VM NIC topology'
        }
        $receipt.PrivateSwitchOnly = $true
        $receipt.VhdxBytes = $VhdxSizeBytes
        Start-VM -Name $vmName

        # Start-VM does not prove OS boot; require guest integration heartbeat.
        $deadline = (Get-Date).AddSeconds(110)
        $heartbeat = $false
        do {
            $h = Get-VMIntegrationService -VMName $vmName -Name 'Heartbeat' -ErrorAction SilentlyContinue
            if ($h -and $h.PrimaryStatusDescription -eq 'OK') {
                $heartbeat = $true
                break
            }
            Start-Sleep -Seconds 3
        } while ((Get-Date) -lt $deadline)
        if (-not $heartbeat) {
            throw 'ORACLE_FAILURE: guest heartbeat not observed'
        }
        $receipt.GuestBoot = 'HYPERV_HEARTBEAT_OBSERVED'
        $receipt.GuestOsIdentity = 'NOT_ATTESTED'
        $receipt.Classification = 'H1_HEARTBEAT_ONLY_NEEDS_OS_IDENTITY'
    }
}
catch {
    $failed = $true
    $receipt.Classification = 'H1_NOT_QUALIFIED'
    if ($_.Exception.Message -like 'ADMISSION_DENIED*') {
        $receipt.FailureClass = 'ADMISSION_DENIED'
    }
    elseif ($_.Exception.Message -like 'ORACLE_FAILURE*') {
        $receipt.FailureClass = 'ORACLE_FAILURE'
    }
    elseif ($_.Exception.Message -like 'HARNESS_FAILURE*') {
        $receipt.FailureClass = 'HARNESS_FAILURE'
    }
    else {
        $receipt.FailureClass = 'ENVIRONMENT_OR_HARNESS_FAILURE'
    }
}
finally {
    if ($Mode -eq 'Execute') {
        $cleanupOk = $true
        # Exact run-owned identities only. No wildcards or existing resource mutation.
        if ($createdVm) {
            try { Stop-VM -Name $vmName -TurnOff -Force -ErrorAction SilentlyContinue } catch {}
            try { Remove-VM -Name $vmName -Force -ErrorAction Stop } catch { $cleanupOk = $false }
        }
        if ($createdSwitch) {
            try { Remove-VMSwitch -Name $switchName -Force -ErrorAction Stop } catch { $cleanupOk = $false }
        }
        if ($createdRoot) {
            try { Remove-Item -LiteralPath $runRoot -Recurse -Force -ErrorAction Stop } catch { $cleanupOk = $false }
        }
        if (($createdVm -and (Get-VM -Name $vmName -ErrorAction SilentlyContinue)) -or
            ($createdSwitch -and (Get-VMSwitch -Name $switchName -ErrorAction SilentlyContinue)) -or
            ($createdRoot -and (Test-Path -LiteralPath $runRoot))) {
            $cleanupOk = $false
        }
        $receipt.Cleanup = if ($cleanupOk) { 'PASS' } else { 'FAIL' }
        if (-not $cleanupOk) { $failed = $true }
    }
    $receipt | ConvertTo-Json -Depth 5 -Compress | Write-Output
}
if ($failed) { exit 1 }
