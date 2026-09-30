# ╔══════════════════════════════════════════════════════════════╗
# ║  DEPRECATED — use build-master.ps1 instead.                 ║
# ║  This script is kept for reference.                          ║
# ║  Canonical pipeline: build-master.ps1 → configure-remote.ps1 ║
# ║  See docs/layer-map.md for the full architecture.            ║
# ╚══════════════════════════════════════════════════════════════╝
#
# WinBot: DISM-based golden master provisioning (DEPRECATED)
# Deploys Windows 11 directly to VHD via DISM (no DVD boot).
# Uses SetupComplete.cmd (not FirstLogonCommands) for reliable provisioning.
#
# Usage:
#   .\provision-dism.ps1
#   .\provision-dism.ps1 -SourceISO "D:\ISOs\Win11.iso"
#   .\provision-dism.ps1 -NonInteractive -Force

param(
    [string]$SourceISO,
    [long]$MemoryBytes = 2147483648,
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
    [int]$InstallTimeoutMinutes = 60,
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

# ============================================================
# Banner
# ============================================================
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  WinBot - DISM Golden Master Provisioner" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  ISO:        $isoLabel" -ForegroundColor Gray
Write-Host "  Master:     $MasterVHDPath" -ForegroundColor Gray
Write-Host "  VM Memory:  $memGB GB" -ForegroundColor Gray
Write-Host "  VM CPUs:    $ProcessorCount" -ForegroundColor Gray
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# ============================================================
# 1. Prerequisites
# ============================================================
Write-Host "[1/7] Checking prerequisites..." -ForegroundColor Cyan
Assert-Administrator

# Clean stale VHDs from previous failed runs (prevent disk exhaustion)
Get-ChildItem $MasterPath\temp-master-*.vhdx -ErrorAction SilentlyContinue | ForEach-Object { try { Remove-Item $_.FullName -Force } catch {} }
Get-ChildItem $MasterPath\provision-20*.vhdx -ErrorAction SilentlyContinue | ForEach-Object { if ($_.LastWriteTime -lt (Get-Date).AddHours(-1)) { try { Remove-Item $_.FullName -Force } catch {} } }

$hvStatus = Test-HyperVAvailable
if (-not $hvStatus.Available) {
    foreach ($i in $hvStatus.Issues) { Write-Host "  ISSUE: $i" -ForegroundColor Red }
    throw "Hyper-V is required."
}
Write-Host "  Hyper-V: OK" -ForegroundColor Green

if (-not (Test-Path $MasterPath)) { New-Item -ItemType Directory -Path $MasterPath -Force | Out-Null }
$freeGB = [math]::Round((Get-PSDrive -Name $MasterPath.Substring(0,1)).Free / 1GB, 1)
if ($freeGB -lt 50) { Write-Warning "Only $freeGB GB free - need ~50GB" }
Write-Host "  Disk: $freeGB GB free" -ForegroundColor Green

# Idempotency: skip if master already exists
if (Test-Path $MasterVHDPath) {
    $ms = [math]::Round((Get-Item $MasterVHDPath).Length / 1GB, 1)
    Write-Host "  Golden master exists: ${ms}GB" -ForegroundColor Green
    if ($Force) { Write-Host "  -Force: rebuilding." -ForegroundColor Yellow }
    elseif ($script:Quiet) { Write-Host "  Using existing master." -ForegroundColor Gray; exit 0 }
    else {
        $choice = Read-Host "  [S]kip (default) [R]eplace"
        if ($choice -notmatch '^[Rr]') { Write-Host "  Using existing master." -ForegroundColor Green; exit 0 }
    }
}

# ============================================================
# 2. Obtain Windows ISO
# ============================================================
Write-Host "[2/7] Obtaining Windows ISO..." -ForegroundColor Cyan

$Version = "24H2"
if (-not $ProductKey) {
    $storedKey = Get-WinBotCredential -Name "product-key" -Username "windows" -AsPlaintext -ErrorAction SilentlyContinue
    if ($storedKey) { $ProductKey = $storedKey }
}
$downloadMethod = if ($ProductKey) { "MCT" } else { "EVAL" }
Write-Host "  Architecture: $Architecture | Method: $downloadMethod" -ForegroundColor Gray

$isoFileName = "Win11_${WindowsEdition}_${Version}_${downloadMethod}_${Architecture}.iso"
$downloadPath = Join-Path $MasterPath $isoFileName
$cachedISO = Get-ChildItem $MasterPath -Filter "Win11*.iso" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1

if ($SourceISO -and (Test-Path $SourceISO)) {
    $isoPath = $SourceISO; Write-Host "  Using provided ISO: $SourceISO" -ForegroundColor Green
} elseif ($cachedISO) {
    $isoPath = $cachedISO.FullName; Write-Host "  Cached: $($cachedISO.Name) - $([math]::Round($cachedISO.Length/1GB,1))GB" -ForegroundColor Green
} elseif ($SkipDownload) { throw "No ISO found and -SkipDownload set." }
else {
    Write-Host "  Downloading Windows 11 $WindowsEdition..." -ForegroundColor Yellow
    $dlScript = Join-Path $scriptDir "download-windows-iso.ps1"
    & $dlScript -OutputPath $downloadPath -UseMCT -WindowsEdition $WindowsEdition -Architecture $Architecture
    if (-not (Test-Path $downloadPath)) { throw "ISO download failed." }
    $isoPath = $downloadPath
}

# ============================================================
# 3. Build provisioning VHD
# ============================================================
Write-Host "[3/7] Building provisioning VHD..." -ForegroundColor Cyan
$ts = Get-Date -Format 'yyyyMMdd-HHmmss'
$provisionVhdPath = Join-Path $MasterPath "provision-$ts.vhdx"
$buildScript = Join-Path $scriptDir "build-provision-vhd.ps1"
& $buildScript -OutputPath $provisionVhdPath -GuestDir $scriptDir
Write-Host "  Provisioning VHD: $provisionVhdPath" -ForegroundColor Green

# ============================================================
# 4. Credentials
# ============================================================
Write-Host "[4/7] Managing credentials..." -ForegroundColor Cyan
if (-not $Password) { $Password = New-WinBotPassword -NoSymbols; Write-Host "  Generated random VM password (XML-safe)." -ForegroundColor Green }
Register-WinBotCredential -Name "vm-password" -Username $Username -Password $Password
Write-Host "  VM password -> CredMan" -ForegroundColor Green
if ($ProductKey) { Register-WinBotCredential -Name "product-key" -Username "windows" -Password $ProductKey; Write-Host "  Product key -> CredMan" -ForegroundColor Green }

# ============================================================
# 5. Generate autounattend (DISM variant Ã¢â‚¬â€ no windowsPE pass)
# ============================================================
Write-Host "[5/7] Generating autounattend..." -ForegroundColor Cyan
$autounattendXml = Get-WinBotDismAutounattend -Password $Password -Username $Username -ComputerName "WinBot-Master" -ProductKey $ProductKey -WindowsEdition $WindowsEdition
$autounattendPath = Join-Path $MasterPath "autounattend.xml"
$autounattendXml | Out-File -FilePath $autounattendPath -Encoding utf8
Write-Host "  DISM autounattend written (no windowsPE, with SkipOOBE)" -ForegroundColor Green

# ============================================================
# 6. DISM-deploy Windows to VHD + SetupComplete.cmd
# ============================================================
Write-Host "[6/7] Deploying Windows via DISM..." -ForegroundColor Cyan

# 6a: Create blank VHD
$ts = Get-Date -Format 'yyyyMMdd-HHmmss'
$tempMasterVhd = Join-Path $MasterPath "temp-master-$ts.vhdx"

# Clean stale VM
$existingVM = Get-VM -Name $TempVMName -ErrorAction SilentlyContinue
if ($existingVM) {
    if ($existingVM.State -ne "Off") { Stop-VM -Name $TempVMName -Force -ErrorAction SilentlyContinue; Start-Sleep -Seconds 3 }
    Remove-VM -Name $TempVMName -Force -ErrorAction SilentlyContinue; Start-Sleep -Seconds 2
}
if (Test-Path $tempMasterVhd) { try { Remove-Item $tempMasterVhd -Force } catch { $ts = Get-Date -Format 'yyyyMMdd-HHmmss'; $tempMasterVhd = Join-Path $MasterPath "temp-master-$ts.vhdx" } }

# Stop Shell Hardware Detection to prevent Explorer pop-ups
$shellHwWasRunning = $false
try { $svc = Get-Service ShellHWDetection -ErrorAction SilentlyContinue; if ($svc -and $svc.Status -eq 'Running') { $shellHwWasRunning = $true; Stop-Service ShellHWDetection -Force -ErrorAction SilentlyContinue } } catch {}

Write-Host "  Creating VHDX (127 GB)..." -ForegroundColor Gray
New-VHD -Path $tempMasterVhd -SizeBytes 127GB -Dynamic -ErrorAction Stop | Out-Null
$mountedVhd = Mount-VHD -Path $tempMasterVhd -Passthru -ErrorAction Stop
Start-Sleep -Seconds 2

try {
    # 6b: Partition (GPT for Gen 2 UEFI)
    $disk = $mountedVhd | Get-Disk
    if (-not $disk) { $disk = Get-Disk | Where-Object { $_.Location -like "*$tempMasterVhd*" } | Select-Object -First 1 }
    if (-not $disk) { throw "Could not find mounted VHD disk." }
    $diskNum = $disk.Number
    Write-Host "  VHD mounted as Disk $diskNum" -ForegroundColor Gray

    Write-Host "  Partitioning (GPT: EFI + MSR + Windows)..." -ForegroundColor Gray
    Clear-Disk -Number $diskNum -RemoveData -RemoveOEM -Confirm:$false -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    Initialize-Disk -Number $diskNum -PartitionStyle GPT -ErrorAction Stop
    Start-Sleep -Seconds 1

    $efiPart = New-Partition -DiskNumber $diskNum -Size 100MB -GptType '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}' -ErrorAction Stop
    Start-Sleep -Seconds 1
    $efiPart | Set-Partition -NewDriveLetter S -ErrorAction Stop
    Format-Volume -DriveLetter S -FileSystem FAT32 -NewFileSystemLabel "EFI" -Confirm:$false -Force -ErrorAction Stop | Out-Null

    $msrPart = New-Partition -DiskNumber $diskNum -Size 16MB -GptType '{e3c9e316-0b5c-4db8-817d-f92df00215ae}' -ErrorAction SilentlyContinue

    $winPart = New-Partition -DiskNumber $diskNum -UseMaximumSize -GptType '{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}' -ErrorAction Stop
    Start-Sleep -Seconds 1
    $winPart | Set-Partition -NewDriveLetter T -ErrorAction Stop
    Format-Volume -DriveLetter T -FileSystem NTFS -NewFileSystemLabel "Windows" -Confirm:$false -Force -ErrorAction Stop | Out-Null

    # 6c: Apply Windows image via DISM
    Write-Host "  Applying Windows image (2-4 min)..." -ForegroundColor Yellow
    $isoMount = Mount-DiskImage -ImagePath $isoPath -Passthru -ErrorAction Stop
    $isoDrive = ($isoMount | Get-Volume).DriveLetter
    Write-Host "  ISO at ${isoDrive}:" -ForegroundColor Gray

    $wimPath = "${isoDrive}:\sources\install.wim"
    if (-not (Test-Path $wimPath)) { $wimPath = "${isoDrive}:\sources\install.esd" }
    if (-not (Test-Path $wimPath)) { throw "No install.wim or install.esd on ISO." }

    $dismStart = Get-Date
    $result = dism /Apply-Image /ImageFile:$wimPath /Index:1 /ApplyDir:T:\ /Compact:Off 2>&1
    if ($LASTEXITCODE -ne 0) { throw "DISM failed: $result" }
    $dismDuration = [math]::Round(((Get-Date) - $dismStart).TotalMinutes, 1)
    Write-Host "  DISM applied in ${dismDuration} min." -ForegroundColor Green

    # 6d: Set up boot loader
    Write-Host "  Configuring boot loader (BCDBOOT)..." -ForegroundColor Gray
    bcdboot T:\Windows /s S: /f UEFI 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "BCDBOOT failed." }

    # 6e: Copy autounattend to OOBE location (Panther)
    Write-Host "  Copying autounattend to Panther..." -ForegroundColor Gray
    $pantherDir = "T:\Windows\Panther"
    if (-not (Test-Path $pantherDir)) { New-Item -ItemType Directory -Path $pantherDir -Force | Out-Null }
    Copy-Item $autounattendPath "$pantherDir\Unattend.xml" -Force

    # 6f: Copy provisioning scripts to VHD
    Write-Host "  Copying guest files..." -ForegroundColor Gray
    $provMount = Mount-VHD -Path $provisionVhdPath -Passthru -ErrorAction Stop
    Start-Sleep -Seconds 2
    $provDisk = $provMount | Get-Disk
    if (-not $provDisk) { $provDisk = Get-Disk | Where-Object { $_.Location -like "*$provisionVhdPath*" } | Select-Object -First 1 }
    $provPart = Get-Partition -DiskNumber $provDisk.Number | Select-Object -First 1
    $provDrive = ($provPart | Get-Volume).DriveLetter
    if (-not $provDrive) { $provPart | Set-Partition -NewDriveLetter P; $provDrive = "P" }

    New-Item -ItemType Directory -Path "T:\WinBot" -Force | Out-Null
    Copy-Item "${provDrive}:\api" "T:\WinBot\api" -Recurse -Force -ErrorAction SilentlyContinue
    Copy-Item "${provDrive}:\tools" "T:\WinBot\tools" -Recurse -Force -ErrorAction SilentlyContinue
    Copy-Item "${provDrive}:\setup-service.ps1" "T:\WinBot\" -Force -ErrorAction SilentlyContinue
    Copy-Item "${provDrive}:\setup-remote.ps1" "T:\WinBot\" -Force -ErrorAction SilentlyContinue

    # 6g: Copy the staged-provision script as provision.ps1
    if (Test-Path "${provDrive}:\tools\stage-provision.ps1") {
        Copy-Item "${provDrive}:\tools\stage-provision.ps1" "T:\WinBot\provision.ps1" -Force
        Write-Host "  stage-provision.ps1 -> T:\WinBot\provision.ps1" -ForegroundColor Green
    }

    # 6h: Create SetupComplete.cmd Ã¢â‚¬â€ the RELIABLE post-deployment trigger
    Write-Host "  Creating SetupComplete.cmd..." -ForegroundColor Gray
    $setupDir = "T:\Windows\Setup\Scripts"
    New-Item -ItemType Directory -Path $setupDir -Force | Out-Null
    @"
@echo off
echo WinBot: SetupComplete starting provision.ps1 >> C:\WinBot\logs\setupcomplete.log
powershell -ExecutionPolicy Bypass -File C:\WinBot\provision.ps1 >> C:\WinBot\logs\setupcomplete.log 2>&1
echo WinBot: SetupComplete finished >> C:\WinBot\logs\setupcomplete.log
"@ | Out-File -FilePath "$setupDir\SetupComplete.cmd" -Encoding ascii
    Write-Host "  SetupComplete.cmd created - provisions on first boot" -ForegroundColor Green
    # 6i: Offline registry - write AutoLogon keys directly (belt-and-suspenders)
    #     Works regardless of whether OOBE processes the XML AutoLogon section.
    Write-Host "  Setting AutoLogon via offline registry..." -ForegroundColor Gray
    try {
        reg load HKLM\WinBotSoftware "T:\Windows\System32\config\SOFTWARE" 2>&1 | Out-Null
        $wlPath = "HKLM\WinBotSoftware\Microsoft\Windows NT\CurrentVersion\Winlogon"
        reg add $wlPath /v AutoAdminLogon /t REG_SZ /d "1" /f 2>&1 | Out-Null
        reg add $wlPath /v DefaultUserName /t REG_SZ /d "$Username" /f 2>&1 | Out-Null
        reg add $wlPath /v DefaultPassword /t REG_SZ /d "$Password" /f 2>&1 | Out-Null
        reg add $wlPath /v DefaultDomainName /t REG_SZ /d "" /f 2>&1 | Out-Null
        reg unload HKLM\WinBotSoftware 2>&1 | Out-Null
        Write-Log "Offline AutoLogon registry keys set (belt-and-suspenders)" "INFO"
    } catch {
        Write-Log "Offline AutoLogon registry FAILED: $_" "WARN"
        try { reg unload HKLM\WinBotSoftware 2>$null | Out-Null } catch {}
    }
    Write-Host "  AutoLogon registry keys written offline" -ForegroundColor Green

    # 6i: Copy autounattend also to root (dual-path safety)
    Copy-Item $autounattendPath "T:\autounattend.xml" -Force

    Dismount-VHD -Path $provisionVhdPath -ErrorAction SilentlyContinue
    Dismount-DiskImage -ImagePath $isoPath -ErrorAction SilentlyContinue

} finally {
    Dismount-VHD -Path $tempMasterVhd -ErrorAction SilentlyContinue
    if ($shellHwWasRunning) { Start-Service ShellHWDetection -ErrorAction SilentlyContinue }
    Start-Sleep -Seconds 2
}

Write-Host "  VHD deployment complete." -ForegroundColor Green

# ============================================================
# 7. Create VM and boot
# ============================================================
Write-Host "[7/7] Creating VM and provisioning..." -ForegroundColor Cyan

$vm = New-VM -Name $TempVMName -MemoryStartupBytes $MemoryBytes -Generation 2 -VHDPath $tempMasterVhd -ErrorAction Stop
Set-VMProcessor -VMName $TempVMName -Count $ProcessorCount -ErrorAction SilentlyContinue
Set-VM -VMName $TempVMName -AutomaticCheckpointsEnabled $false -ErrorAction SilentlyContinue
Set-VMMemory -VMName $TempVMName -DynamicMemoryEnabled $false -ErrorAction SilentlyContinue
$nic = Get-VMNetworkAdapter -VMName $TempVMName -ErrorAction SilentlyContinue
if (-not $nic) { Add-VMNetworkAdapter -VMName $TempVMName -SwitchName $SwitchName -ErrorAction SilentlyContinue }
else { Connect-VMNetworkAdapter -VMName $TempVMName -SwitchName $SwitchName -ErrorAction SilentlyContinue }
Set-VMFirmware -VMName $TempVMName -EnableSecureBoot Off -ErrorAction SilentlyContinue

# Attach provisioning VHD as extra data disk
Add-VMHardDiskDrive -VMName $TempVMName -Path $provisionVhdPath -ControllerType SCSI -ErrorAction SilentlyContinue

Write-Host "  Booting VM..." -ForegroundColor Yellow
Write-Host "  SetupComplete.cmd will provision tools on first boot." -ForegroundColor Gray
Write-Host "  Expected timeline: ~5 min boot, ~5-10 min provisioning." -ForegroundColor Gray
Start-VM -Name $TempVMName -ErrorAction Stop

# ============================================================
# Monitor: wait for heartbeat, then API health
# ============================================================
$startTime = Get-Date
$timeoutSeconds = $InstallTimeoutMinutes * 60
$elapsed = 0; $hbOk = $false; $done = $false; $phase = "booting"
$lastStatus = ""

Write-Host ""
Write-Host "  Monitoring VM..." -ForegroundColor Cyan

while (-not $done) {
    $elapsed = [math]::Round(((Get-Date) - $startTime).TotalSeconds, 0)
    if ($elapsed -ge $timeoutSeconds) { break }

    $vm = Get-VM -Name $TempVMName -ErrorAction SilentlyContinue
    if (-not $vm) { Write-Warning "VM disappeared"; Start-Sleep -Seconds 5; continue }

    $hb = Get-VMIntegrationService -VMName $TempVMName -Name "Heartbeat" -ErrorAction SilentlyContinue
    $hbNow = if ($hb) { $hb.PrimaryOperationalStatus -eq "Ok" } else { $false }

    if ($hbNow -and -not $hbOk) {
        $min = [math]::Round($elapsed / 60, 1)
        Write-Host "  Heartbeat OK at ${min} min" -ForegroundColor Green
        $hbOk = $true; $phase = "provisioning"
    }

    if ($hbOk) {
        $net = Get-VMNetworkAdapter -VMName $TempVMName -ErrorAction SilentlyContinue
        $vmIp = $null
        if ($net) { $vmIp = $net.IPAddresses | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+' } | Select-Object -First 1 }
        if ($vmIp) {
            try {
                $r = Invoke-WebRequest -Uri "http://${vmIp}:8000/health" -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
                if ($r.StatusCode -eq 200) {
                    Write-Host "  *** WinBot API HEALTHY at ${vmIp}:8000 ***" -ForegroundColor Green
                    $done = $true; break
                }
            } catch {}
        }
    }

    if (-not $done) {
        if ($phase -eq "booting") { Start-Sleep -Seconds 15 }
        else { Start-Sleep -Seconds 10 }
    }

    $elapsed = [math]::Round(((Get-Date) - $startTime).TotalSeconds, 0)
    if ($elapsed % 30 -eq 0 -and $elapsed -gt 0) {
        $min = [math]::Round($elapsed / 60, 0)
        if ($phase -eq "booting") { Write-Host "  ... $min min - waiting for boot" -ForegroundColor Gray }
        else { Write-Host "  ... $min min - provisioning" -ForegroundColor Gray }
    }
}

# ============================================================
# 8. Finalize golden master
# ============================================================
if (-not $done) {
    $vmState = (Get-VM -Name $TempVMName -ErrorAction SilentlyContinue).State
    Write-Host "Provisioning did not complete. VM state: $vmState" -ForegroundColor Red
    Write-Host "VM preserved for debugging: $TempVMName" -ForegroundColor Yellow
    Write-Host "Check: vmconnect.exe localhost `"$TempVMName`"" -ForegroundColor Yellow
    throw "Provisioning timeout - API not healthy after $InstallTimeoutMinutes min."
}

# 8a: Stop VM
Write-Host "  Stopping VM..." -ForegroundColor Gray
Stop-VM -Name $TempVMName -ErrorAction SilentlyContinue
$sw = 0
while (((Get-VM -Name $TempVMName -ErrorAction SilentlyContinue).State -ne "Off") -and $sw -lt 60) { Start-Sleep -Seconds 5; $sw += 5 }
if ((Get-VM -Name $TempVMName -ErrorAction SilentlyContinue).State -ne "Off") { Stop-VM -Name $TempVMName -Force -ErrorAction SilentlyContinue; Start-Sleep -Seconds 5 }

# 8b: Copy VHDX to master location
try {
    if ($tempMasterVhd -ne $MasterVHDPath) {
        if (Test-Path $MasterVHDPath) { Remove-Item $MasterVHDPath -Force }
        Copy-Item $tempMasterVhd $MasterVHDPath -Force
        Remove-Item $tempMasterVhd -Force
    }
    Write-Host "  Master VHDX copied." -ForegroundColor Green
} catch {
    Write-Host "  VHDX copy FAILED: $_" -ForegroundColor Red
    throw "VHDX copy failed."
}

# 8c: Set read-only + register hash
Set-ItemProperty -Path $MasterVHDPath -Name IsReadOnly -Value $true
Set-WinBotMasterHash -VHDXPath $MasterVHDPath

# 8d: Verify integrity
if (-not (Test-WinBotMasterIntegrity -VHDXPath $MasterVHDPath)) {
    throw "Master VHDX integrity check FAILED after provisioning."
}

# 8e: Remove temp VM
Remove-VM -Name $TempVMName -Force -ErrorAction SilentlyContinue

# 8f: Scrub sensitive files
Remove-Item $autounattendPath -Force -ErrorAction SilentlyContinue
Get-ChildItem $MasterPath -Filter "autounattend*.xml" -ErrorAction SilentlyContinue | Remove-Item -Force
if (-not $KeepTempVM) { Remove-Item $provisionVhdPath -Force -ErrorAction SilentlyContinue }

# 8g: Update config
$configPath = Join-Path $projectDir "config.json"
if (Test-Path $configPath) {
    $config = Get-Content $configPath -Raw | ConvertFrom-Json -AsHashtable
    $config.master.vmName = "WinBot-Master"; $config.master.vhdxPath = $MasterVHDPath; $config.master.vmPath = $MasterPath
    $config.credentials.vmUsername = $Username
    $config | ConvertTo-Json -Depth 5 | Out-File -FilePath $configPath -Encoding utf8
}

$totalMin = [math]::Round($elapsed / 60, 1)
Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  WinBot Golden Master Ready" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Master VHDX: $MasterVHDPath" -ForegroundColor Cyan
Write-Host "  Total time:  $totalMin min" -ForegroundColor Cyan
Write-Host "  Next: Import-Module .\host\WinBot.psm1; New-WinBotClone -Name test" -ForegroundColor White
