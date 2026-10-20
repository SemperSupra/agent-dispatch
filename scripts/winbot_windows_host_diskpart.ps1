# PUBLIC Windows-2025 host-only DiskPart formatting oracle on ONE owned VHDX.
# Does NOT run Windows PE, use evaluation ISO, install Windows, or touch
# non-owned disks. Only a fresh run-owned VHDX may be initialized.
$ErrorActionPreference='Stop'
$run=[guid]::NewGuid().ToString()
$root=Join-Path $env:RUNNER_TEMP ("ad-winbot-diskpart-"+$run)
$evidence=Join-Path $env:RUNNER_TEMP "winbot-owned-diskpart-evidence"
$vhd=Join-Path $root "owned-64gb.vhdx"
$created=$false; $mounted=$false; $failure=$null
if (Test-Path -LiteralPath $evidence) { throw "Refuse preexisting evidence path" }
New-Item -ItemType Directory -Path $evidence -ErrorAction Stop | Out-Null
try {
    if (Test-Path -LiteralPath $root) { throw "Refuse preexisting owned VHD directory" }
    New-Item -ItemType Directory -Path $root -ErrorAction Stop | Out-Null
    $created=$true
    Import-Module Hyper-V -ErrorAction Stop
    Get-Command New-VHD,Mount-VHD,Dismount-VHD,Get-VHD -ErrorAction Stop | Out-Null
    New-VHD -Path $vhd -Dynamic -SizeBytes 64GB -ErrorAction Stop | Out-Null
    if (!(Test-Path -LiteralPath $vhd)) {throw "VHD not created"}
    Mount-VHD -Path $vhd -NoDriveLetter -ErrorAction Stop | Out-Null
    $mounted=$true
    $diskNum=(Get-VHD -Path $vhd -ErrorAction Stop).DiskNumber
    if ($null -eq $diskNum -or [int]$diskNum -le 0) {
        throw "No positive exact owned VHD disk number; refuse disk initialization"
    }
    $d=Get-Disk -Number $diskNum -ErrorAction Stop
    if ([int64]$d.Size -ne [int64]64GB -or $d.PartitionStyle -ne 'RAW') {
        throw "Observed VHD disk size or uninitialized RAW state mismatch"
    }
    if ((Get-VHD -Path $vhd).DiskNumber -ne $diskNum) {
        throw "Disk number drift before run-owned initialization"
    }
    # Initialize ONLY the exact VHD-mapped disk, never Disk 0/system.
    Initialize-Disk -Number $diskNum -PartitionStyle GPT -ErrorAction Stop | Out-Null
    $initialized=Get-Disk -Number $diskNum -ErrorAction Stop
    if ($initialized.PartitionStyle -ne 'GPT') { throw "Owned VHD GPT not confirmed" }
    $hostGuid=[guid]::Parse($initialized.Guid.ToString())
    $lines=@('list disk',('select disk '+$diskNum),'uniqueid disk','exit')
    $script=Join-Path $evidence 'diskpart-commands.txt'
    $lines | Set-Content -LiteralPath $script -Encoding ASCII
    $output=(& diskpart.exe /s $script 2>&1 | Out-String)
    $exitCode=$LASTEXITCODE
    $output | Set-Content -LiteralPath (Join-Path $evidence 'diskpart-host-output.txt') -Encoding UTF8
    if ($exitCode -ne 0) { throw "Read-only DiskPart commands returned nonzero" }
    $idMatches=[regex]::Matches($output,'(?im)^\s*Disk ID:\s*\{?([a-f0-9-]{36})\}?\s*$')
    if ($idMatches.Count -ne 1) { throw "Expected precisely one native DiskPart Disk ID line" }
    $guestFormatGuid=[guid]::Parse($idMatches[0].Groups[1].Value)
    if ($guestFormatGuid -ne $hostGuid) {throw "Owned VHD GPT GUID mismatches native DiskPart"}
    $obs=[ordered]@{
        schema='winbot-diskpart-owned-vhd-host/v1'
        classification='NATIVE_WINDOWS_HOST_DISKPART_FORMAT_CONFIRMED'
        exact_owned_vhd_observed=$true
        disk_number=[int]$diskNum
        owned_gpt_guid=$hostGuid.ToString()
        diskpart_gpt_guid=$guestFormatGuid.ToString()
        native_diskpart_exit_code=$exitCode
        diskpart_commands_readonly=$true
        actual_windows_pe_executed=$false
        winpe_disk_zero_observed=$false
        windows_iso_used=$false
        destructive_windows_setup_authorized=$false
        winbot_guest_qualified=$false
    }
    $obs | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $evidence 'observation.json')
}
catch {
    $failure=$_.Exception.Message
    @{schema='winbot-owned-diskpart-failure/v1';reason=$failure;classification='ENVIRONMENT_OR_ORACLE_FAILURE'} |
      ConvertTo-Json | Set-Content -LiteralPath (Join-Path $evidence 'error.json')
}
finally {
    $cleanupErrors=@()
    if ($mounted) {
        try { Dismount-VHD -Path $vhd -ErrorAction Stop }
        catch { $cleanupErrors+=($_.Exception.Message) }
    }
    if ($created) {
        try { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop }
        catch { $cleanupErrors+=($_.Exception.Message) }
    }
    $absent=!(Test-Path -LiteralPath $root)
    [ordered]@{
        schema='winbot-owned-vhd-cleanup/v1'
        owned_vhd_files_absent=$absent
        cleanup_errors=$cleanupErrors
        primary_failure=$failure
        unowned_disks_initialized=$false
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $evidence 'cleanup.json')
    if (!$absent -or $cleanupErrors.Count -gt 0) { $failure="CLEANUP_FAILURE" }
}
if ($failure) { Write-Error $failure; exit 3 }
Write-Host "HOST Windows DiskPart GPT read-only formatting qualified; not Windows PE"
exit 0
