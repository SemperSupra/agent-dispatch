# WinBot: Build Golden Master VHDX
# Layer 1 â€" Pure build. Creates a bootable Windows VHD with WinBot staged.
# Does NOT create or launch a VM. Output is a VHDX file.
#
# Usage:
#   .\build-master.ps1
#   .\build-master.ps1 -SourceISO "D:\ISOs\Win11.iso" -MemoryForVM 4096
#   .\build-master.ps1 -Force   # rebuild even if master exists

param(
    [string]$SourceISO,
    [string]$SourceMethod = "",
    [string]$SourceVersion = "",
    [string]$SourceLanguage = "",
    [switch]$ExactSource,
    [string]$WindowsEdition = "Enterprise",
    [string]$Architecture = "x64",
    [string]$MasterVHDPath = "C:\WinBot\master\Win11ENT.vhdx",
    [string]$MasterPath = "C:\WinBot\master",
    [string]$MasterVMName = "WinBot-Master",
    [string]$Username = "winbot",
    [string]$Password = "",           # Empty = resolve the already-authorized canonical VM credential
    [string]$ProductKey = "",         # Empty = pull from CredMan

    # Cross-hypervisor driver injection
    [string[]]$Hypervisors = @(),     # e.g. -Hypervisors "kvm","vmware","vbox"
    [string]$InjectDrivers = "",      # Custom driver path(s) â€" semicolon-separated
    [string]$DriverRoot = "C:\WinBot\drivers",
    [switch]$NICOnly,                 # Only inject NIC + storage drivers
    [switch]$StorageOnly,             # Only inject storage drivers (boot-critical)
    [switch]$CriticalOnly,            # Only boot-critical drivers (NIC + storage)

    [ValidateSet("DISM","Wimlib")]
    [string]$ImageApplyEngine = "DISM",
    [string]$WimlibImagexPath = "",

    [switch]$Force,
    [switch]$SkipDownload
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectDir = Split-Path -Parent $scriptDir
$hostDir = Join-Path $projectDir "host"
$modulePath = Join-Path $hostDir "WinBot.psm1"
if (-not (Test-Path $modulePath)) { throw "WinBot module not found: $modulePath" }
Import-Module $modulePath -Force -DisableNameChecking -ErrorAction Stop

$transcriptStarted = $false
try {
Start-Transcript -Path "C:\WinBot\logs\build-transcript.log" -Append -ErrorAction SilentlyContinue | Out-Null
$transcriptStarted = $true
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  WinBot - Golden Master Builder" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Master:     $MasterVHDPath" -ForegroundColor Gray
Write-Host "  Edition:    $WindowsEdition" -ForegroundColor Gray
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# ============================================================
# 1. Prerequisites
# ============================================================
Write-Host "[1/5] Checking prerequisites..." -ForegroundColor Cyan
Assert-Administrator

$hvStatus = Test-HyperVAvailable
if (-not $hvStatus.Available) { throw "Hyper-V is required." }
Write-Host "  Hyper-V: OK" -ForegroundColor Green

if (-not (Test-Path $MasterPath)) { New-Item -ItemType Directory -Path $MasterPath -Force | Out-Null }
$freeGB = [math]::Round((Get-PSDrive -Name $MasterPath.Substring(0,1)).Free / 1GB, 1)
if ($freeGB -lt 30) { Write-Warning "Only $freeGB GB free - need ~30GB (15 GB VHD + 5 GB ISO)" }
Write-Host "  Disk: $freeGB GB free" -ForegroundColor Green

$masterExistedAtStart = [bool](Test-Path -LiteralPath $MasterVHDPath)
if ($ExactSource -and $Force) {
    throw "ExactSource lifecycle builds never force-replace an existing master. Resolve/adopt/remove the existing target explicitly, then replan."
}

# Idempotency is evidence-based: file presence alone is not convergence.
if ($masterExistedAtStart -and (-not $Force)) {
    $ms = [math]::Round((Get-Item $MasterVHDPath).Length / 1GB, 1)
    if (Test-WinBotMasterIntegrity -VHDXPath $MasterVHDPath) {
        Write-Host "  Accepted golden master already exists: ${ms}GB." -ForegroundColor Green
        return
    }
    throw "Master VHDX exists but is not accepted/verified: $MasterVHDPath. Use -Force to rebuild or explicitly adopt/verify it before reuse."
}

# ============================================================
# 2. Obtain Windows ISO
# ============================================================
Write-Host "[2/5] Obtaining Windows ISO..." -ForegroundColor Cyan

# Source-media identity is independent of licensing/product-key state.
# ExactSource is the lifecycle-controlled path: it must consume one already
# acquired artifact and may not silently select/download a different channel.
if ($ExactSource) {
    if (-not $SourceISO) { throw "ExactSource requires -SourceISO." }
    if (-not $SkipDownload) { throw "ExactSource requires -SkipDownload so the builder cannot acquire media implicitly." }
    foreach ($required in @(
        @{ Name='SourceMethod'; Value=$SourceMethod },
        @{ Name='SourceVersion'; Value=$SourceVersion },
        @{ Name='SourceLanguage'; Value=$SourceLanguage },
        @{ Name='WindowsEdition'; Value=$WindowsEdition },
        @{ Name='Architecture'; Value=$Architecture }
    )) {
        if ([string]::IsNullOrWhiteSpace([string]$required.Value)) {
            throw "ExactSource requires -$($required.Name)."
        }
    }
}

if (-not $SourceISO -and -not $ProductKey) {
    # Legacy/manual acquisition may still use optional product-key presence to
    # choose its historical channel. ExactSource never does.
    try {
        $ProductKey = Get-WinBotCredential -Name "product-key" -Username "windows" -AsPlaintext -NoPrompt
    }
    catch {
        $ProductKey = $null
    }
    if ($ProductKey) { Write-Host "  Product key from CredMan." -ForegroundColor Green }
}

if ($SourceISO) {
    if (-not (Test-Path -LiteralPath $SourceISO)) {
        throw "Explicit source ISO does not exist: $SourceISO"
    }

    $verifyArgs = @{
        ISOPath = $SourceISO
        VerifyHash = $true
        ExpectedEdition = $WindowsEdition
        ExpectedArchitecture = $Architecture
    }
    if ($SourceVersion) { $verifyArgs.ExpectedVersion = $SourceVersion }
    if ($SourceLanguage) { $verifyArgs.ExpectedLanguage = $SourceLanguage }

    $isoInfo = Get-WinBotISOVersion @verifyArgs
    $methodMatches = if (-not $SourceMethod) {
        $true
    } elseif ($SourceMethod -eq "CDN") {
        [string]$isoInfo.Method -like "CDN*"
    } else {
        [string]$isoInfo.Method -eq $SourceMethod
    }

    if (-not $isoInfo.Ready -or -not $methodMatches) {
        $methodDetail = if ($methodMatches) { "" } else { " Method expected=$SourceMethod actual=$($isoInfo.Method)." }
        throw "Source ISO is not verified for build use: $($isoInfo.Reason).$methodDetail"
    }
    $isoPath = (Resolve-Path -LiteralPath $SourceISO -ErrorAction Stop).Path
} else {
    if ($ExactSource) { throw "ExactSource cannot continue without an explicit source artifact." }

    $downloadMethod = if ($ProductKey) { "MCT" } else { "EVAL" }
    $Version = if ($downloadMethod -eq "MCT") { "latest" } else { "24H2" }
    $expectedVersion = if ($downloadMethod -eq "MCT") { "" } else { $Version }
    Write-Host "  Architecture: $Architecture | Method: $downloadMethod | Version intent: $Version" -ForegroundColor Gray

    $cachedISO = $null
    $isoInfo = $null
    $cachedRejections = @()

    foreach ($candidate in @(Get-ChildItem $MasterPath -Filter "Win11*.iso" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)) {
        $observed = Get-WinBotISOVersion -ISOPath $candidate.FullName
        $identityMatches =
            $observed.Edition -eq $WindowsEdition -and
            $observed.Architecture -eq $Architecture -and
            (-not $expectedVersion -or $observed.Version -eq $expectedVersion)

        if (-not $identityMatches) {
            $cachedRejections += "$($candidate.Name): recorded identity is incompatible or unknown"
            continue
        }

        $verified = Get-WinBotISOVersion -ISOPath $candidate.FullName -VerifyHash -ExpectedEdition $WindowsEdition -ExpectedVersion $expectedVersion -ExpectedArchitecture $Architecture
        if ($verified.Ready) {
            $cachedISO = $candidate
            $isoInfo = $verified
            break
        }
        $cachedRejections += "$($candidate.Name): $($verified.Reason)"
    }

    if ($cachedISO) {
        $isoPath = $cachedISO.FullName
        Write-Host "  Cached verified ISO: $($cachedISO.Name) ($([math]::Round($cachedISO.Length/1GB,1)) GB)" -ForegroundColor Green
    } elseif ($SkipDownload) {
        $detail = if ($cachedRejections.Count -gt 0) { " Candidates rejected: $($cachedRejections -join '; ')" } else { "" }
        throw "No verified compatible ISO found and -SkipDownload set.$detail"
    } else {
        Write-Host "  Downloading ISO..." -ForegroundColor Yellow
        $dlScript = Join-Path $scriptDir "download-windows-iso.ps1"
        $isoFile = "Win11_$($WindowsEdition)_$($Version)_$($downloadMethod)_$($Architecture).iso"
        $downloadArgs = @{
            OutputPath = (Join-Path $MasterPath $isoFile)
            WindowsEdition = $WindowsEdition
            Architecture = $Architecture
            Version = $Version
        }
        if ($downloadMethod -eq "MCT") { $downloadArgs.UseMCT = $true }
        & $dlScript @downloadArgs
        $isoPath = Join-Path $MasterPath $isoFile
        if (-not (Test-Path $isoPath)) { throw "ISO download failed." }
        $isoInfo = Get-WinBotISOVersion -ISOPath $isoPath -VerifyHash -ExpectedEdition $WindowsEdition -ExpectedVersion $expectedVersion -ExpectedArchitecture $Architecture
        if (-not $isoInfo.Ready) {
            throw "Downloaded ISO failed post-acquisition verification: $($isoInfo.Reason)"
        }
    }
}

# Credentials are consumed only after source identity is decision-grade.
# Credential creation/rotation/registration is a separate lifecycle transition.
if (-not $Password) {
    try {
        $Password = Get-WinBotCredential -Name "vm-password" -Username $Username -AsPlaintext -NoPrompt
    }
    catch {
        $Password = $null
    }
    if (-not $Password) {
        throw "VM credential is not available. EstablishMasterCredential must complete before BuildMaster."
    }
}
if ($SourceISO -and -not $ProductKey) {
    try {
        $ProductKey = Get-WinBotCredential -Name "product-key" -Username "windows" -AsPlaintext -NoPrompt
    }
    catch {
        $ProductKey = $null
    }
    if ($ProductKey) { Write-Host "  Optional product key from CredMan." -ForegroundColor Green }
}

# ============================================================
# 3. Build provisioning VHD (guest files)
# ============================================================
Write-Host "[3/5] Building provisioning VHD..." -ForegroundColor Cyan
$ts = Get-Date -Format 'yyyyMMdd-HHmmss'
$provisionVhdPath = Join-Path $MasterPath "provision-$ts.vhdx"
$provisionOwned = -not (Test-Path -LiteralPath $provisionVhdPath)
try {
    & (Join-Path $scriptDir "build-provision-vhd.ps1") -OutputPath $provisionVhdPath -GuestDir $scriptDir
    Write-Host "  Provisioning VHD: $provisionVhdPath" -ForegroundColor Green
}
catch {
    if ($provisionOwned -and (Test-Path -LiteralPath $provisionVhdPath)) {
        Dismount-VHD -Path $provisionVhdPath -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $provisionVhdPath -Force -ErrorAction SilentlyContinue
    }
    throw
}

# ============================================================
# 4. DISM-deploy Windows + configure offline
# ============================================================
Write-Host "[4/5] Deploying Windows via DISM..." -ForegroundColor Cyan

# Credentials are inputs to this build only. Do not create, rotate, or
# register credential authority from inside the builder.
Write-Host "  Authorized credentials loaded for build use." -ForegroundColor Green

# 4a: Create blank VHD
$ts = Get-Date -Format 'yyyyMMdd-HHmmss'
$tempVhd = Join-Path $MasterPath "build-$ts.vhdx"
if (Test-Path $tempVhd) { try { Remove-Item $tempVhd -Force } catch {} }

# Suppress Explorer during VHD operations
try { $shellSvc = Get-Service ShellHWDetection -ErrorAction SilentlyContinue; $shellWasRunning = ($shellSvc.Status -eq 'Running') } catch { $shellWasRunning = $false }
if ($shellWasRunning) { Stop-Service ShellHWDetection -Force -ErrorAction SilentlyContinue }

$deploymentSucceeded = $false
$tempVhdOwned = -not (Test-Path -LiteralPath $tempVhd)
$mount = $null
try {
    Write-Host "  Creating VHDX (127 GB) and partitioning..." -ForegroundColor Gray
    New-VHD -Path $tempVhd -SizeBytes 127GB -Dynamic -ErrorAction Stop | Out-Null
    $mount = Mount-VHD -Path $tempVhd -Passthru -ErrorAction Stop
    Start-Sleep -Seconds 2
    # Enable privileges needed by DISM and reg.exe on mounted VHDXs
    Add-Type @"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
namespace WinBot { public static class WbPriv {
    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern bool OpenProcessToken(IntPtr h, uint a, out IntPtr t);
    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern bool LookupPrivilegeValue(string host, string name, out long luid);
    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern bool AdjustTokenPrivileges(IntPtr t, bool disable, ref long p, int len, IntPtr prev, IntPtr rel);
    public static void Enable(string priv) {
        IntPtr token;
        if (!OpenProcessToken(System.Diagnostics.Process.GetCurrentProcess().Handle, 0x20|0x8, out token))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        long luid;
        if (!LookupPrivilegeValue(null, priv, out luid))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        long enabled = ((long)2 << 32) | (long)luid;
        if (!AdjustTokenPrivileges(token, false, ref enabled, Marshal.SizeOf(typeof(long))*2, IntPtr.Zero, IntPtr.Zero))
            throw new Win32Exception(Marshal.GetLastWin32Error());
    }
}}
"@
    [WinBot.WbPriv]::Enable("SeManageVolumePrivilege")
    [WinBot.WbPriv]::Enable("SeBackupPrivilege")
    [WinBot.WbPriv]::Enable("SeRestorePrivilege")

    $diskNum = ($mount | Get-Disk).Number
    if (-not $diskNum) { $diskNum = (Get-Disk | Where-Object { $_.Location -like "*$tempVhd*" } | Select-Object -First 1).Number }
    Write-Host "  Disk: $diskNum" -ForegroundColor Gray

    # GPT: EFI (100MB) + MSR (16MB) + Windows (rest)
    # NOTE: Initialize-Disk -PartitionStyle GPT auto-creates an MSR partition.
    # Remove it so we can place EFI first (correct UEFI boot order).
    Clear-Disk -Number $diskNum -RemoveData -RemoveOEM -Confirm:$false -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    Initialize-Disk -Number $diskNum -PartitionStyle GPT -ErrorAction Stop
    Start-Sleep -Seconds 1

    # Remove the auto-created MSR — EFI must be partition 1 for UEFI boot
    $autoMsr = Get-Partition -DiskNumber $diskNum | Where-Object { $_.GptType -eq '{e3c9e316-0b5c-4db8-817d-f92df00215ae}' }
    if ($autoMsr) {
        Remove-Partition -DiskNumber $diskNum -PartitionNumber $autoMsr.PartitionNumber -Confirm:$false -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
    }

    $efiPart = New-Partition -DiskNumber $diskNum -Size 100MB -GptType '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}' -ErrorAction Stop
    Start-Sleep -Seconds 1
    $efiPart | Set-Partition -NewDriveLetter S -ErrorAction Stop
    Format-Volume -DriveLetter S -FileSystem FAT32 -NewFileSystemLabel "EFI" -Confirm:$false -Force -ErrorAction Stop | Out-Null

    New-Partition -DiskNumber $diskNum -Size 16MB -GptType '{e3c9e316-0b5c-4db8-817d-f92df00215ae}' -ErrorAction SilentlyContinue | Out-Null

    $winPart = New-Partition -DiskNumber $diskNum -UseMaximumSize -GptType '{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}' -ErrorAction Stop
    Start-Sleep -Seconds 1
    $winPart | Set-Partition -NewDriveLetter T -ErrorAction Stop
    Format-Volume -DriveLetter T -FileSystem NTFS -NewFileSystemLabel "Windows" -Confirm:$false -Force -ErrorAction Stop | Out-Null

    # 4b: Apply Windows using an explicitly selected image engine.
    # DISM remains the compatibility default. Hosted public RDTE explicitly
    # selects pinned wimlib because DISM/WIMGAPI is known-negative there.
    Write-Host "  Applying Windows image (engine: $ImageApplyEngine)..." -ForegroundColor Yellow
    $isoMount = Mount-DiskImage -ImagePath $isoPath -Passthru -ErrorAction Stop
    $isoDrive = ($isoMount | Get-Volume).DriveLetter
    $wimPath = "${isoDrive}:\sources\install.wim"
    if (-not (Test-Path $wimPath)) { $wimPath = "${isoDrive}:\sources\install.esd" }
    if (-not (Test-Path $wimPath)) { throw "install.wim/install.esd not found in source media" }

    $applyStart = Get-Date
    $applyLog = Join-Path $MasterPath "image-apply.log"
    if ($ImageApplyEngine -eq "Wimlib") {
        if (-not $WimlibImagexPath -or -not (Test-Path -LiteralPath $WimlibImagexPath)) {
            throw "ImageApplyEngine=Wimlib requires an existing -WimlibImagexPath"
        }
        Write-Host "  wimlib-imagex: $WimlibImagexPath" -ForegroundColor Gray
        & $WimlibImagexPath apply $wimPath 1 'T:\' *>&1 |
            Set-Content -LiteralPath $applyLog -Encoding utf8
        $applyExit = $LASTEXITCODE
        if ($applyExit -ne 0) { throw "wimlib image apply failed (exit $applyExit). Check log: $applyLog" }
    }
    else {
        $dism = "dism.exe"
        Write-Host "  DISM: $dism (system)" -ForegroundColor Gray
        $dismResult = & $dism /English /Apply-Image /ImageFile:$wimPath /Index:1 /ApplyDir:T:\ /Compact:Off /LogPath:$applyLog 2>&1 | Out-String
        Write-Host $dismResult
        $applyExit = $LASTEXITCODE
        if ($applyExit -ne 0) { throw "DISM apply failed (exit $applyExit). Check log: $applyLog" }
    }
    Write-Host "  Image applied in $([math]::Round(((Get-Date)-$applyStart).TotalMinutes,1)) min." -ForegroundColor Green

    # 4c: BCDBOOT
    Write-Host "  Configuring boot loader..." -ForegroundColor Gray
    bcdboot T:\Windows /s S: /f UEFI 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "BCDBOOT failed." }

    # 4d: Generate and deploy autounattend
    Write-Host "  Deploying answer file..." -ForegroundColor Gray
    $xml = Get-WinBotDismAutounattend -Password $Password -Username $Username -ComputerName $MasterVMName -ProductKey $ProductKey -WindowsEdition $WindowsEdition
    $pantherDir = "T:\Windows\Panther"
    New-Item -ItemType Directory -Path $pantherDir -Force | Out-Null
    $xml | Out-File -FilePath "$pantherDir\Unattend.xml" -Encoding utf8
    $xml | Out-File -FilePath "T:\autounattend.xml" -Encoding utf8

    # 4e: Offline registry - AutoLogon (SKIPPED - see note)
    # reg load on a foreign SOFTWARE hive reliably hangs the build.
    # AutoLogon is handled by:
    #   1. autounattend.xml OOBE pass (first boot)
    #   2. .vm-password + provision.ps1 Step 1.2 (every subsequent boot)
    # Neither requires offline registry manipulation.
    Write-Host "  AutoLogon offline registry: skipped (non-critical)." -ForegroundColor Yellow
    Write-Host "    (handled by autounattend.xml + .vm-password)" -ForegroundColor Gray

    # 4f: Copy WinBot guest files to VHD (idempotent â€" survives DISM re-apply)
    Write-Host "  Staging WinBot guest files..." -ForegroundColor Gray
    Dismount-VHD -Path $provisionVhdPath -ErrorAction SilentlyContinue
    $provMount = Mount-VHD -Path $provisionVhdPath -Passthru -ErrorAction Stop
    Start-Sleep -Seconds 2
    $provDisk = $provMount | Get-Disk
    if (-not $provDisk) { $provDisk = Get-Disk | Where-Object { $_.Location -like "*$provisionVhdPath*" } | Select-Object -First 1 }
    $provDrive = (Get-Partition -DiskNumber $provDisk.Number | Select-Object -First 1 | Get-Volume).DriveLetter
    if (-not $provDrive) { Get-Partition -DiskNumber $provDisk.Number | Select-Object -First 1 | Set-Partition -NewDriveLetter P -ErrorAction SilentlyContinue; $provDrive = "P" }

    New-Item -ItemType Directory -Path "T:\WinBot" -Force | Out-Null
    New-Item -ItemType Directory -Path "T:\WinBot\logs" -Force | Out-Null
    Copy-Item "${provDrive}:\api" "T:\WinBot\api" -Recurse -Force -ErrorAction SilentlyContinue
    Copy-Item "${provDrive}:\tools" "T:\WinBot\tools" -Recurse -Force -ErrorAction SilentlyContinue
    Copy-Item "${provDrive}:\setup-remote.ps1" "T:\WinBot\" -Force -ErrorAction SilentlyContinue
    Copy-Item "${provDrive}:\setup-service.ps1" "T:\WinBot\" -Force -ErrorAction SilentlyContinue
    # Event log helper — deployed to clones for consistent logging
    $notifySrc = Join-Path $projectDir "notify.ps1"
    if (Test-Path $notifySrc) { Copy-Item $notifySrc "T:\WinBot\notify.ps1" -Force }
    if (Test-Path "${provDrive}:\tools\stage-provision.ps1") {
        Copy-Item "${provDrive}:\tools\stage-provision.ps1" "T:\WinBot\provision.ps1" -Force
    }

    # 4g: Stage product key and password for slmgr and AutoLogon re-establishment
    if ($ProductKey) { $ProductKey | Out-File -FilePath "T:\WinBot\.product-key" -Encoding ascii -NoNewline }
    $Password | Out-File -FilePath "T:\WinBot\.vm-password" -Encoding ascii -NoNewline

    # 4h: SetupComplete.cmd
    $setupDir = "T:\Windows\Setup\Scripts"
    New-Item -ItemType Directory -Path $setupDir -Force | Out-Null
    @"
@echo off
if not exist C:\WinBot\logs mkdir C:\WinBot\logs
echo %date% %time% WinBot: SetupComplete starting >> C:\WinBot\logs\setupcomplete.log
powershell -ExecutionPolicy Bypass -File C:\WinBot\provision.ps1 >> C:\WinBot\logs\setupcomplete.log 2>&1
echo %date% %time% WinBot: SetupComplete finished (exit code: %ERRORLEVEL%) >> C:\WinBot\logs\setupcomplete.log
"@ | Out-File -FilePath "$setupDir\SetupComplete.cmd" -Encoding ascii
    Write-Host "  Guest files staged." -ForegroundColor Green

    # 4i: Inject cross-hypervisor drivers (virtio, VMXNET3, PVSCSI, etc.)
    if ($Hypervisors -or $InjectDrivers) {
        Write-Host "  Injecting cross-hypervisor drivers..." -ForegroundColor Gray
        if ($Hypervisors) {
            $hypervisorList = $Hypervisors -join ","
            Write-Host "    Hypervisors: $hypervisorList" -ForegroundColor Gray
            $injectScript = Join-Path $scriptDir "tools\inject-drivers.ps1"
            if (Test-Path $injectScript) {
                $injectArgs = @{
                    TargetVHDX = $tempVhd
                    Hypervisors = $Hypervisors
                    WindowsVersion = "auto"
                    DriverRoot = $DriverRoot
                }
                if ($NICOnly) { $injectArgs['NICOnly'] = $true }
                if ($StorageOnly) { $injectArgs['StorageOnly'] = $true }
                if ($CriticalOnly) { $injectArgs['CriticalOnly'] = $true }
                Write-Host "    Running inject-drivers.ps1..."
                & $injectScript @injectArgs
            } else {
                Write-Host "WARNING: inject-drivers.ps1 not found, skipping driver injection"
                Write-Host "Download drivers: .\guest\tools\download-drivers.ps1 -Hypervisors $hypervisorList"
            }
        }
        if ($InjectDrivers) {
            $customPaths = $InjectDrivers -split ";" | Where-Object { $_ -and (Test-Path $_) }
            foreach ($drvPath in $customPaths) {
                Write-Host "    Injecting: $drvPath" -ForegroundColor Gray
                $dismResult = dism /Image:"T:\" /Add-Driver /Driver:"$drvPath" /Recurse 2>&1
                if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 2) {
                    Write-Host "    Drivers injected." -ForegroundColor Green
                } else {
                    Write-Host "WARNING: DISM exit code $LASTEXITCODE for: $drvPath"
                }
            }
        }
        Write-Host "  Driver injection complete." -ForegroundColor Green
    }

    $deploymentSucceeded = $true
} finally {
    Dismount-VHD -Path $tempVhd -ErrorAction SilentlyContinue
    Dismount-VHD -Path $provisionVhdPath -ErrorAction SilentlyContinue
    Dismount-DiskImage -ImagePath $isoPath -ErrorAction SilentlyContinue
    if ($shellWasRunning) { Start-Service ShellHWDetection -ErrorAction SilentlyContinue }

    if ($provisionOwned -and (Test-Path -LiteralPath $provisionVhdPath)) {
        Remove-Item -LiteralPath $provisionVhdPath -Force -ErrorAction SilentlyContinue
    }
    if (-not $deploymentSucceeded -and $tempVhdOwned -and (Test-Path -LiteralPath $tempVhd)) {
        Remove-Item -LiteralPath $tempVhd -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "  DISM deployment complete." -ForegroundColor Green

# ============================================================
# 5. Finalize - validate structure, publish once, then bind accepted identity
# ============================================================
Write-Host "[5/5] Finalizing golden master..." -ForegroundColor Cyan

$configPath = Join-Path $projectDir "config.json"
$configBackupExists = Test-Path -LiteralPath $configPath
$configBackupBytes = if ($configBackupExists) { [IO.File]::ReadAllBytes($configPath) } else { $null }
$configTouched = $false
$publishedMaster = $false

try {
    if ($tempVhd -ne $MasterVHDPath) {
        if (Test-Path -LiteralPath $MasterVHDPath) {
            if (-not $Force) {
                throw "Master target appeared during the build and is not owned by this invocation: $MasterVHDPath"
            }
            Remove-Item -LiteralPath $MasterVHDPath -Force -ErrorAction Stop
        }

        Move-Item -LiteralPath $tempVhd -Destination $MasterVHDPath -ErrorAction Stop
        $publishedMaster = $true
    }

    if (-not (Get-Command Test-VHD -ErrorAction SilentlyContinue)) {
        throw "Test-VHD is unavailable; refusing to accept an unvalidated master."
    }
    if (-not (Test-VHD -Path $MasterVHDPath -ErrorAction Stop)) {
        throw "Structural Test-VHD validation failed before master acceptance."
    }

    $masterSizeBytes = (Get-Item -LiteralPath $MasterVHDPath -ErrorAction Stop).Length
    if ($masterSizeBytes -lt 1GB) {
        throw "Built master is suspiciously small before acceptance: $masterSizeBytes bytes."
    }

    Set-ItemProperty -Path $MasterVHDPath -Name IsReadOnly -Value $true
    # Set-WinBotMasterHash persists config.json itself, so mark the config as
    # potentially touched before invoking it. If that write partially fails,
    # the catch path restores the exact pre-build bytes.
    $configTouched = $true
    Set-WinBotMasterHash -VHDXPath $MasterVHDPath

    if (-not (Test-WinBotMasterIntegrity -VHDXPath $MasterVHDPath)) {
        throw "Accepted master integrity verification failed after binding the hash."
    }

    if (Test-Path -LiteralPath $configPath) {
        $config = Get-Content $configPath -Raw | ConvertFrom-Json
        $config.master.vmName = $MasterVMName
        $config.master.vhdxPath = $MasterVHDPath
        $config.master.vmPath = $MasterPath
        $config.credentials.vmUsername = $Username
        $config | ConvertTo-Json -Depth 5 | Out-File -FilePath $configPath -Encoding utf8
        $configTouched = $true
    }
}
catch {
    $finalizeFailure = $_

    if ($configTouched) {
        if ($configBackupExists) {
            [IO.File]::WriteAllBytes($configPath, $configBackupBytes)
        }
        elseif (Test-Path -LiteralPath $configPath) {
            Remove-Item -LiteralPath $configPath -Force -ErrorAction SilentlyContinue
        }
    }

    if ($publishedMaster -and -not $masterExistedAtStart -and (Test-Path -LiteralPath $MasterVHDPath)) {
        try { Set-ItemProperty -Path $MasterVHDPath -Name IsReadOnly -Value $false -ErrorAction SilentlyContinue } catch {}
        Remove-Item -LiteralPath $MasterVHDPath -Force -ErrorAction SilentlyContinue
    }
    elseif (Test-Path -LiteralPath $tempVhd) {
        Remove-Item -LiteralPath $tempVhd -Force -ErrorAction SilentlyContinue
    }

    throw $finalizeFailure
}

# Scrub sensitive files
Remove-Item (Join-Path $MasterPath "autounattend.xml") -Force -ErrorAction SilentlyContinue
Get-ChildItem $MasterPath -Filter "autounattend*.xml" -ErrorAction SilentlyContinue | Remove-Item -Force

$vhdSize = [math]::Round((Get-Item $MasterVHDPath).Length / 1GB, 1)
Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Golden Master Built: ${vhdSize}GB" -ForegroundColor Green
Write-Host "  Path: $MasterVHDPath" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Next: Create a VM and boot it" -ForegroundColor White
Write-Host "    Import-Module .\host\WinBot.psm1" -ForegroundColor Cyan
Write-Host "    New-WinBotClone -Name test" -ForegroundColor Cyan
Write-Host "  Or: configure any Windows machine for remote access" -ForegroundColor White
Write-Host "    .\guest\configure-remote.ps1" -ForegroundColor Cyan

return @{ Success = $true; MasterVHDPath = $MasterVHDPath; SizeGB = $vhdSize }
}
finally {
    if ($transcriptStarted) {
        Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
    }
}
