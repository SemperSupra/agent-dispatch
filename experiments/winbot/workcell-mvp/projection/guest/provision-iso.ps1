# ╔══════════════════════════════════════════════════════════════╗
# ║  DEPRECATED — use build-master.ps1 instead.                 ║
# ║  This script is kept for reference.                          ║
# ║  Canonical pipeline: build-master.ps1 → configure-remote.ps1 ║
# ║  See docs/layer-map.md for the full architecture.            ║
# ╚══════════════════════════════════════════════════════════════╝
#
# WinBot: Fully unattended Windows 11 provisioning from ISO to golden master (DEPRECATED)
# Usage:
#   .\provision-iso.ps1                                          # Auto-download + provision
#   .\provision-iso.ps1 -ProductKey "XXXXX-..."                  # Permanent license via MCT
#   .\provision-iso.ps1 -SourceISO "D:\ISOs\Win11.iso"           # Use existing ISO
#   .\provision-iso.ps1 -NonInteractive                           # No prompts, agent-friendly

param(
    [string]$SourceISO,
    [long]$MemoryBytes = 8589934592,
    [int]$ProcessorCount = 4,
    [string]$SwitchName = "Default Switch",
    [string]$TempVMName = "WinBot-Provision",
    [string]$Password = "",
    [string]$Username = "winbot",
    [string]$ProductKey = "",
    [string]$WindowsEdition = "Enterprise",
    [string]$Architecture = "x64",
    [string]$MasterVHDPath = "C:\WinBot\master\Win11ENT.vhdx",
    [string]$MasterPath = "C:\WinBot\master",
    [int]$InstallTimeoutMinutes = 90,
    [switch]$KeepTempVM,
    [switch]$SkipDownload,
    [switch]$NonInteractive,
    [switch]$Force
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectDir = Split-Path -Parent $scriptDir
$hostDir = Join-Path $projectDir "host"

$modulePath = Join-Path $hostDir "WinBot.psm1"
if (-not (Test-Path $modulePath)) { throw "WinBot module not found: $modulePath" }
Import-Module $modulePath -Force -DisableNameChecking -ErrorAction Stop

$script:Quiet = $NonInteractive -or (-not $host.UI.RawUI.WindowTitle)
$isoLabel = if ($SourceISO) { $SourceISO } else { "auto-download" }
$memGB = [math]::Round($MemoryBytes / 1GB, 1)
$modeStr = if ($script:Quiet) { " - NonInteractive" } else { "" }

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  WinBot - ISO Provisioner$modeStr" -ForegroundColor Cyan
Write-Host "  Windows 11 to Golden Master" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  ISO:        $isoLabel" -ForegroundColor Gray
Write-Host "  Master:     $MasterVHDPath" -ForegroundColor Gray
Write-Host "  VM Memory:  $memGB GB" -ForegroundColor Gray
Write-Host "  VM CPUs:    $ProcessorCount" -ForegroundColor Gray
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# === Step 1: Prerequisites ===
Write-Host "[1/8] Checking prerequisites..." -ForegroundColor Cyan
Assert-Administrator

$hvStatus = Test-HyperVAvailable
if (-not $hvStatus.Available) {
    foreach ($issue in $hvStatus.Issues) { Write-Host "  ISSUE: $issue" -ForegroundColor Red }
    foreach ($sug in $hvStatus.Suggestions) { Write-Host "  FIX: $sug" -ForegroundColor Yellow }
    throw "Hyper-V is required for WinBot provisioning."
}
Write-Host "  Hyper-V: OK" -ForegroundColor Green

if (-not (Test-Path $MasterPath)) { New-Item -ItemType Directory -Path $MasterPath -Force | Out-Null }
$driveLetter = $MasterPath.Substring(0, 1)
$freeGB = [math]::Round((Get-PSDrive -Name $driveLetter).Free / 1GB, 1)
if ($freeGB -lt 50) { Write-Warning "Only $freeGB GB free - need ~50GB for master VHDX" }
Write-Host "  Disk space: $freeGB GB free" -ForegroundColor Green

# Idempotency: existing master check
if (Test-Path $MasterVHDPath) {
    $mSizeGB = [math]::Round((Get-Item $MasterVHDPath).Length / 1GB, 1)
    Write-Host "  Golden master exists: $MasterVHDPath - ${mSizeGB}GB" -ForegroundColor Green
    if ($Force) { Write-Host "  -Force: rebuilding." -ForegroundColor Yellow }
    elseif ($script:Quiet) { Write-Host "  Non-interactive: using existing master." -ForegroundColor Gray; exit 0 }
    else {
        Write-Host "  [S] Skip (default) [R] Replace" -ForegroundColor Gray
        $choice = Read-Host "  Choice [S]"
        if ($choice -ne "R" -and $choice -ne "r") { Write-Host "  Using existing master." -ForegroundColor Green; exit 0 }
        Write-Host "  Rebuilding..." -ForegroundColor Yellow
    }
}

# === Step 2: Obtain Windows ISO ===
Write-Host "[2/8] Obtaining Windows ISO..." -ForegroundColor Cyan
if ($Architecture -notin @("x64","arm64")) { Write-Warning "Unknown arch: $Architecture - using x64"; $Architecture = "x64" }

$Version = "24H2"
$downloadMethod = if ($ProductKey) { "MCT" } else { "EVAL" }
if (-not $ProductKey) {
    $storedKey = Get-WinBotCredential -Name "product-key" -Username "windows" -AsPlaintext -ErrorAction SilentlyContinue
    if ($storedKey) { Write-Host "  Product key from CredMan." -ForegroundColor Green; $ProductKey = $storedKey; $downloadMethod = "MCT" }
}

$isoFileName = "Win11_${WindowsEdition}_${Version}_${downloadMethod}_${Architecture}.iso"
$downloadPath = Join-Path $MasterPath $isoFileName
$provenanceLog = Join-Path $MasterPath "iso-provenance.jsonl"
Write-Host "  Architecture: $Architecture | Method: $downloadMethod" -ForegroundColor Gray

# Show version info from cached ISO and provenance
$isoVersion = Get-WinBotISOVersion
if ($isoVersion.Cached) {
    $age = if ($isoVersion.DownloadTimestamp) {
        $ts = [DateTime]$isoVersion.DownloadTimestamp
        [math]::Round(((Get-Date) - $ts).TotalDays, 0)
    } else { "?" }
    Write-Host "  Cached: $($isoVersion.Edition) $($isoVersion.Version) $($isoVersion.Architecture) - $($isoVersion.ISOSizeGB)GB - downloaded ${age}d ago" -ForegroundColor Gray
} else {
    Write-Host "  No ISO cached - will download." -ForegroundColor Yellow
}

$cachedISO = Get-ChildItem $MasterPath -Filter "Win11*.iso" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1

if ($SourceISO -and (Test-Path $SourceISO)) {
    Write-Host "  Using provided ISO: $SourceISO" -ForegroundColor Green; $isoPath = $SourceISO
} elseif ($cachedISO) {
    $csGB = [math]::Round($cachedISO.Length / 1GB, 1); $cn = $cachedISO.Name
    $isEval = ($cn -like "*EVAL*"); $haveKey = ($ProductKey -ne ""); $wantRefresh = $false
    if ($haveKey -and $isEval) {
        Write-Host "  Product key present but only EVAL ISO cached: $cn - ${csGB}GB" -ForegroundColor Yellow
        Write-Host "  Better: $isoFileName - full licensed" -ForegroundColor Green
        if ($script:Quiet) { Write-Host "  Non-interactive: downloading MCT ISO." -ForegroundColor Gray; $wantRefresh = $true }
        else {
            Write-Host "  [E] Use EVAL  [D] Download MCT" -ForegroundColor Gray
            $choice = Read-Host "  Choice [D]"
            if ($choice -ne "E" -and $choice -ne "e") { $wantRefresh = $true }
        }
    }
    if (-not $wantRefresh) {
        if ($cn -ne $isoFileName) {
            try { $cachedISO | Rename-Item -NewName $isoFileName -ErrorAction Stop }
            catch { Write-Host "  NOTE: Could not rename $cn -> $isoFileName (file locked). Using as-is." -ForegroundColor Gray; $isoFileName = $cn }
        }
        Write-Host "  Cached: $isoFileName - ${csGB}GB" -ForegroundColor Green; $isoPath = Join-Path $MasterPath $isoFileName
    }
} elseif ($SkipDownload) { throw "No ISO found and -SkipDownload set." }

if (-not $isoPath) {
    Write-Host "  Downloading Windows 11 $WindowsEdition via $downloadMethod..." -ForegroundColor Yellow
    $downloadScript = Join-Path $scriptDir "download-windows-iso.ps1"
    if (-not (Test-Path $downloadScript)) { throw "ISO downloader not found: $downloadScript" }
    $dlArgs = @{ OutputPath = $downloadPath; Version = $Version; Language = "English"; WindowsEdition = $WindowsEdition; Architecture = $Architecture }
    if ($downloadMethod -eq "MCT") { $dlArgs["UseMCT"] = $true }
    $dlResult = & $downloadScript @dlArgs
    if (Test-Path $downloadPath) {
        $fs = (Get-Item $downloadPath).Length; $fh = (Get-FileHash -Path $downloadPath -Algorithm SHA256).Hash
        # Rotate provenance log if > 500KB (keep last 500 entries)
        if ((Test-Path $provenanceLog) -and ((Get-Item $provenanceLog).Length -gt 500KB)) {
            $lines = Get-Content $provenanceLog -Tail 500
            $lines | Set-Content $provenanceLog -Encoding utf8
        }
        @{ timestamp = (Get-Date).ToUniversalTime().ToString("o"); filename = $isoFileName; method = $downloadMethod; edition = $WindowsEdition; version = $Version; architecture = $Architecture; status = "completed"; size_bytes = $fs; size_gb = [math]::Round($fs / 1GB, 2); sha256 = $fh } | ConvertTo-Json -Compress | Add-Content -Path $provenanceLog -Encoding utf8
        Write-Host "  ISO ready: $isoFileName"; Write-Host "    SHA256: $($fh.Substring(0,16))..."
        Write-Host "    Provenance: $provenanceLog" -ForegroundColor Gray
    } else { throw "ISO download failed." }
    $isoPath = $downloadPath
}

# === Step 3: Build provisioning VHD ===
Write-Host "[3/8] Building provisioning VHD..." -ForegroundColor Cyan
$ts = Get-Date -Format "yyyyMMdd-HHmmss"; $provisionVhdPath = Join-Path $MasterPath "provision-$ts.vhdx"
$buildScript = Join-Path $scriptDir "build-provision-vhd.ps1"
if (-not (Test-Path $buildScript)) { throw "VHD builder not found: $buildScript" }
& $buildScript -OutputPath $provisionVhdPath -GuestDir $scriptDir
if (-not (Test-Path $provisionVhdPath)) { throw "Provisioning VHD creation failed." }
Write-Host "  Provisioning VHD: $provisionVhdPath" -ForegroundColor Green

# === Step 4: Manage credentials ===
Write-Host "[4/8] Managing credentials..." -ForegroundColor Cyan
if (-not $Password) { $Password = New-WinBotPassword; Write-Host "  Generated random VM password." -ForegroundColor Green }
Register-WinBotCredential -Name "vm-password" -Username $Username -Password $Password
Write-Host "  VM password -> CredMan" -ForegroundColor Green
if ($ProductKey) { Register-WinBotCredential -Name "product-key" -Username "windows" -Password $ProductKey; Write-Host "  Product key -> CredMan" -ForegroundColor Green }
else { Write-Host "  No product key - 90-day eval." -ForegroundColor Yellow }
$existingToken = Get-WinBotAPIKey -Service "winbot" -ErrorAction SilentlyContinue
if ($existingToken) { Write-Host "  Host API token exists - will sync to VM after provisioning." -ForegroundColor Gray }
else { Write-Host "  No host API token yet (will sync from VM after provisioning)." -ForegroundColor Gray }
Write-Host ""

# === Step 5: Generate autounattend.xml and answer VHD ===
Write-Host "[5/8] Generating autounattend.xml..." -ForegroundColor Cyan
$autounattendXml = Get-WinBotDismAutounattend -Password $Password -Username $Username -ComputerName "WinBot-Master" -ProductKey $ProductKey -WindowsEdition $WindowsEdition
$autounattendPath = Join-Path $MasterPath "autounattend.xml"
$autounattendXml | Out-File -FilePath $autounattendPath -Encoding utf8
Write-Host "  autounattend.xml written." -ForegroundColor Green

$ts = Get-Date -Format "yyyyMMdd-HHmmss"; $answerVhdPath = Join-Path $MasterPath "answerfile-$ts.vhdx"
if (Test-Path $answerVhdPath) { try { Dismount-VHD -Path $answerVhdPath -ErrorAction SilentlyContinue | Out-Null } catch {}; Remove-Item $answerVhdPath -Force }
New-VHD -Path $answerVhdPath -SizeBytes 50MB -Dynamic -ErrorAction Stop | Out-Null
$mountResult = Mount-VHD -Path $answerVhdPath -Passthru -ErrorAction Stop
try {
    Start-Sleep -Seconds 2; $disk = $mountResult | Get-Disk
    if (-not $disk) { $disk = Get-Disk | Where-Object { $_.Location -like "*$answerVhdPath*" } | Select-Object -First 1 }
    if ($disk.PartitionStyle -eq "RAW") { Initialize-Disk -Number $disk.Number -PartitionStyle MBR -ErrorAction Stop }
    $part = New-Partition -DiskNumber $disk.Number -UseMaximumSize -DriveLetter X -ErrorAction SilentlyContinue
    if (-not $part) { $part = Get-Partition -DiskNumber $disk.Number | Select-Object -First 1; Set-Partition -DiskNumber $disk.Number -PartitionNumber $part.PartitionNumber -NewDriveLetter X -ErrorAction SilentlyContinue }
    Format-Volume -DriveLetter X -FileSystem FAT32 -NewFileSystemLabel "ANSWER" -Confirm:$false -Force -ErrorAction Stop | Out-Null
    Copy-Item $autounattendPath "X:\autounattend.xml" -Force
} finally { Dismount-VHD -Path $answerVhdPath -ErrorAction SilentlyContinue }
Write-Host "  Answer file disk ready." -ForegroundColor Green

# === Step 6: Create VM ===
Write-Host "[6/8] Creating provisioning VM..." -ForegroundColor Cyan
$ts = Get-Date -Format "yyyyMMdd-HHmmss"; $tempMasterVhd = Join-Path $MasterPath "temp-master-$ts.vhdx"
$existingVM = Get-VM -Name $TempVMName -ErrorAction SilentlyContinue
if ($existingVM) {
    if ($existingVM.State -ne "Off") { Stop-VM -Name $TempVMName -Force -ErrorAction SilentlyContinue; Start-Sleep -Seconds 3 }
    Remove-VM -Name $TempVMName -Force -ErrorAction SilentlyContinue; Start-Sleep -Seconds 2
}
if (Test-Path $tempMasterVhd) { try { Remove-Item $tempMasterVhd -Force } catch { $ts = Get-Date -Format "yyyyMMdd-HHmmss"; $tempMasterVhd = Join-Path $MasterPath "temp-master-$ts.vhdx" } }

Write-Host "  VM: $TempVMName | RAM: $memGB GB | CPUs: $ProcessorCount" -ForegroundColor Gray
$vm = New-VM -Name $TempVMName -MemoryStartupBytes $MemoryBytes -Generation 2 -NewVHDPath $tempMasterVhd -NewVHDSizeBytes 127GB -ErrorAction Stop
Set-VMProcessor -VMName $TempVMName -Count $ProcessorCount -ErrorAction SilentlyContinue
Set-VM -VMName $TempVMName -AutomaticCheckpointsEnabled $false -ErrorAction SilentlyContinue
Set-VMMemory -VMName $TempVMName -DynamicMemoryEnabled $false -ErrorAction SilentlyContinue
$nic = Get-VMNetworkAdapter -VMName $TempVMName -ErrorAction SilentlyContinue
if (-not $nic) { Add-VMNetworkAdapter -VMName $TempVMName -SwitchName $SwitchName -ErrorAction SilentlyContinue }
else { Connect-VMNetworkAdapter -VMName $TempVMName -SwitchName $SwitchName -ErrorAction SilentlyContinue }
Set-VMFirmware -VMName $TempVMName -EnableSecureBoot Off -ErrorAction SilentlyContinue
Add-VMDvdDrive -VMName $TempVMName -Path $isoPath -ErrorAction SilentlyContinue
$dvd = Get-VMDvdDrive -VMName $TempVMName
if ($dvd) { Set-VMFirmware -VMName $TempVMName -FirstBootDevice $dvd -ErrorAction SilentlyContinue }
Write-Host "  VM created." -ForegroundColor Green

# === Step 7: Start install + monitor ===
Write-Host "[7/8] Starting unattended Windows installation..." -ForegroundColor Cyan
Write-Host "  Windows Setup: ~20-30 min | Tools: ~5-10 min | Total: ~25-40 min" -ForegroundColor Yellow
Add-VMHardDiskDrive -VMName $TempVMName -Path $answerVhdPath -ControllerType SCSI -ErrorAction SilentlyContinue
Add-VMHardDiskDrive -VMName $TempVMName -Path $provisionVhdPath -ControllerType SCSI -ErrorAction SilentlyContinue
Start-VM -Name $TempVMName -ErrorAction Stop
Write-Host "  VM started." -ForegroundColor Green; Write-Host ""

$startTime = Get-Date; $timeoutSeconds = $InstallTimeoutMinutes * 60
$elapsed = 0; $phase = "installing"; $rebootCount = 0; $heartbeatWasOk = $false; $done = $false; $provisionStartTime = $null

while (-not $done) {
    $elapsed = [math]::Round((Get-Date).Subtract($startTime).TotalSeconds, 0)
    if ($elapsed -ge $timeoutSeconds) { break }
    $vm = Get-VM -Name $TempVMName -ErrorAction SilentlyContinue
    if (-not $vm) { Write-Warning "VM disappeared - waiting..."; Start-Sleep -Seconds 5; continue }
    $hb = Get-VMIntegrationService -VMName $TempVMName -Name "Heartbeat" -ErrorAction SilentlyContinue
    $hbOk = if ($hb) { $hb.PrimaryOperationalStatus -eq "Ok" } else { $false }

    if ($hbOk -and -not $heartbeatWasOk) {
        $rebootCount += 1; $em = [math]::Round($elapsed / 60, 1)
        if ($rebootCount -eq 1) { Write-Host "  Windows Setup done in $em min - provisioning tools..." -ForegroundColor Cyan }
        else { Write-Host "  Heartbeat OK - reboot#$rebootCount - $em min" -ForegroundColor Gray }
        $heartbeatWasOk = $true; $phase = "provisioning"
        if (-not $provisionStartTime) { $provisionStartTime = Get-Date }
    }
    if (-not $hbOk -and $heartbeatWasOk) { $rm = [math]::Round($elapsed/60, 1); Write-Host "  VM rebooting... ($rm min)" -ForegroundColor Gray; $heartbeatWasOk = $false }

    if (($phase -eq "provisioning") -and $hbOk) {
        $vmIp = $null; $net = Get-VMNetworkAdapter -VMName $TempVMName -ErrorAction SilentlyContinue
        if ($net) { $vmIp = $net.IPAddresses | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+' } | Select-Object -First 1 }
        if ($vmIp) {
            $apiOk = $false
            try { $r = Invoke-WebRequest -Uri "http://${vmIp}:8000/health" -TimeoutSec 5 -ErrorAction SilentlyContinue -UseBasicParsing; if ($r.StatusCode -eq 200) { $apiOk = $true } } catch { }
            if ($apiOk) { $phase = "ready"; $done = $true; $tm = [math]::Round($elapsed / 60, 1); $pm = if ($provisionStartTime) { [math]::Round((Get-Date).Subtract($provisionStartTime).TotalSeconds / 60, 1) } else { "-" }
                Write-Host ""; Write-Host "  *** WinBot API HEALTHY ***" -ForegroundColor Green; Write-Host "  IP: $vmIp | Total: $tm min | Provisioning: $pm min" -ForegroundColor Green }
        }
    }

    if (-not $done) { if ($phase -eq "installing") { Start-Sleep -Seconds 60 } elseif ($phase -eq "provisioning") { Start-Sleep -Seconds 10 } else { Start-Sleep -Seconds 20 } }
    $elapsed = [math]::Round((Get-Date).Subtract($startTime).TotalSeconds, 0)
    if (($elapsed % 120 -eq 0) -and ($elapsed -gt 0)) {
        $m = [math]::Round($elapsed / 60, 0)
        if ($phase -eq "installing") { Write-Host "  ... $m min - Windows Setup (no heartbeat)" -ForegroundColor Gray }
        elseif ($phase -eq "provisioning") { $pm = if ($provisionStartTime) { [math]::Round((Get-Date).Subtract($provisionStartTime).TotalSeconds / 60, 1) } else { 0 }; Write-Host "  ... $m min total - provisioning: $pm min" -ForegroundColor Gray }
    }
}

if ($phase -ne "ready") {
    $vs = (Get-VM -Name $TempVMName -ErrorAction SilentlyContinue).State
    Write-Host "Provisioning timed out. State: $vs Phase: $phase Reboots: $rebootCount" -ForegroundColor Red
    Write-Host "VM preserved for debugging: $TempVMName" -ForegroundColor Yellow
    throw "Provisioning timed out."
}

# === Step 8: Finalize (ATOMIC) ===
Write-Host "[8/8] Finalizing golden master..." -ForegroundColor Cyan

# 8a: Stop VM
Stop-VM -Name $TempVMName -ErrorAction SilentlyContinue
$sw = 0
while (((Get-VM -Name $TempVMName -ErrorAction SilentlyContinue).State -ne "Off") -and ($sw -lt 60)) { Start-Sleep -Seconds 5; $sw += 5 }
if ((Get-VM -Name $TempVMName -ErrorAction SilentlyContinue).State -ne "Off") { Stop-VM -Name $TempVMName -Force -ErrorAction SilentlyContinue; Start-Sleep -Seconds 5 }

# 8b: Copy VHDX BEFORE removing VM (atomicity: if copy fails, VM intact)
try {
    if ($tempMasterVhd -ne $MasterVHDPath) {
        if (Test-Path $MasterVHDPath) { Remove-Item $MasterVHDPath -Force }
        Copy-Item $tempMasterVhd $MasterVHDPath -Force; Remove-Item $tempMasterVhd -Force
    }
    Write-Host "  VHDX copied." -ForegroundColor Green
} catch {
    Write-Host "  VHDX copy FAILED: $_" -ForegroundColor Red
    Write-Host "  VM preserved at: $TempVMName for recovery." -ForegroundColor Yellow
    throw "VHDX copy failed - VM preserved."
}

# 8c: Set read-only + hash (only after copy succeeds)
Set-ItemProperty -Path $MasterVHDPath -Name IsReadOnly -Value $true
Set-WinBotMasterHash -VHDXPath $MasterVHDPath
Write-Host "  Master VHDX read-only + hash registered." -ForegroundColor Green

# INVARIANT: Verify master integrity before removing provision VM
$finalOK = Test-WinBotMasterIntegrity -VHDXPath $MasterVHDPath
if (-not $finalOK) { throw "FINAL INVARIANT FAILED: Master VHDX integrity check failed after provisioning." }

# 8d: Now safe to remove temp VM
Remove-VM -Name $TempVMName -Force -ErrorAction SilentlyContinue
Write-Host "  Provisioning VM removed." -ForegroundColor Green

# Update config
$configPath = Join-Path $projectDir "config.json"
if (Test-Path $configPath) {
    $config = Get-Content $configPath -Raw | ConvertFrom-Json -AsHashtable
    $config.master.vmName = "WinBot-Master"; $config.master.vhdxPath = $MasterVHDPath; $config.master.vmPath = $MasterPath
    $config.credentials.vmUsername = $Username
    $config | ConvertTo-Json -Depth 5 | Out-File -FilePath $configPath -Encoding utf8
}

if (-not $KeepTempVM) { Remove-Item $answerVhdPath -Force -ErrorAction SilentlyContinue; Remove-Item $provisionVhdPath -Force -ErrorAction SilentlyContinue }

$totalMin = [math]::Round($elapsed / 60, 1)
Write-Host ""; Write-Host "========================================" -ForegroundColor Green
Write-Host "  WinBot Golden Master Ready" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Master VHDX: $MasterVHDPath" -ForegroundColor Cyan
Write-Host "  Total time:  $totalMin min | Reboots: $rebootCount" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Create a clone:" -ForegroundColor White
Write-Host "    Import-Module .\host\WinBot.psm1" -ForegroundColor Cyan
Write-Host "    New-WinBotClone -Name test -TimeoutMinutes 10" -ForegroundColor Cyan

return @{ Success = $true; MasterVHDPath = $MasterVHDPath; MasterPath = $MasterPath; TotalMinutes = $totalMin; Reboots = $rebootCount }
