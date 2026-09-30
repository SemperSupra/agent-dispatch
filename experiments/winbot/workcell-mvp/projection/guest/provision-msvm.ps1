# ╔══════════════════════════════════════════════════════════════╗
# ║  DEPRECATED — use build-master.ps1 -DownloadMSVM instead.    ║
# ║  This script is kept for reference.                          ║
# ║  Canonical pipeline: build-master.ps1 → configure-remote.ps1 ║
# ║  See docs/layer-map.md for the full architecture.            ║
# ╚══════════════════════════════════════════════════════════════╝
#
# WinBot: Provision a golden master from Microsoft's Windows 11 Dev Environment VM (DEPRECATED)
# Usage:
#   .\provision-msvm.ps1 -VMName "MS-DevVM"
#   .\provision-msvm.ps1 -ZipPath "C:\Downloads\WinDev2411Eval.zip"

param(
    [string]$ZipPath,
    [string]$VMName,
    [switch]$OpenDownloadPage,
    [string]$MasterVHDPath = "C:\WinBot\master\Win11ENT.vhdx",
    [string]$MasterPath = "C:\WinBot\master",
    [string]$VMPassword = "",    # REQUIRED: MS Dev VM default password (must be supplied, not hardcoded)
    [string]$VMUser = "User",
    [string]$WinBotPassword = "",
    [string]$WinBotUser = "winbot",
    [int]$SetupTimeoutMinutes = 30,
    [switch]$KeepSourceVM,
    [string]$ExtractPath = ""
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectDir = Split-Path -Parent $scriptDir
$hostDir = Join-Path $projectDir "host"

$modulePath = Join-Path $hostDir "WinBot.psm1"
Import-Module $modulePath -Force -DisableNameChecking -ErrorAction Stop

$srcLabel = "download"
if ($VMName) { $srcLabel = "Existing VM: $VMName" }
elseif ($ZipPath) { $srcLabel = "Zip: $ZipPath" }

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  WinBot - MS Dev VM Provisioner" -ForegroundColor Cyan
Write-Host "  Microsoft Dev Environment to Golden Master" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Source:     $srcLabel" -ForegroundColor Gray
Write-Host "  Master:     $MasterVHDPath" -ForegroundColor Gray
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# ============================================================
# Step 1: Prerequisites
# ============================================================
Write-Host "[1/5] Checking prerequisites..." -ForegroundColor Cyan
Assert-Administrator

$hvStatus = Test-HyperVAvailable
if (-not $hvStatus.Available) { throw "Hyper-V is required." }
Write-Host "  Hyper-V: OK" -ForegroundColor Green

if (-not (Test-Path $MasterPath)) {
    New-Item -ItemType Directory -Path $MasterPath -Force | Out-Null
}

# Validate MS Dev VM password — no hardcoded defaults allowed
if (-not $VMPassword) {
    throw "MS Dev VM password is required. Use -VMPassword <password>."
}
Write-Host "  MS Dev VM password provided." -ForegroundColor Green

# Manage credentials
if (-not $WinBotPassword) {
    $existingPw = Get-WinBotCredential -Name "vm-password" -Username $WinBotUser -AsPlaintext -ErrorAction SilentlyContinue
    if ($existingPw) {
        Write-Host "  Using existing VM password from Credential Manager." -ForegroundColor Green
        $WinBotPassword = $existingPw
    } else {
        $WinBotPassword = New-WinBotPassword
        Write-Host "  Generated random VM password." -ForegroundColor Green
    }
}
Register-WinBotCredential -Name "vm-password" -Username $WinBotUser -Password $WinBotPassword
Write-Host "  VM password stored in Credential Manager." -ForegroundColor Green
Write-Host ""

# ============================================================
# Step 2: Obtain the MS VM
# ============================================================
Write-Host "[2/5] Obtaining Microsoft Dev VM..." -ForegroundColor Cyan

$sourceVMName = $null

if ($VMName) {
    $vm = Get-VM -Name $VMName -ErrorAction Stop
    $gen = $vm.Generation
    Write-Host "  Using existing VM: $VMName - Gen$gen" -ForegroundColor Green
    $sourceVMName = $VMName
} elseif ($ZipPath) {
    if (-not (Test-Path $ZipPath)) { throw "Zip file not found: $ZipPath" }
    if (-not $ExtractPath) { $ExtractPath = Join-Path $MasterPath "msvm-extract" }

    Write-Host "  Extracting: $ZipPath" -ForegroundColor Gray
    Write-Host "  To: $ExtractPath" -ForegroundColor Gray
    Write-Host "  ~20GB - this will take several minutes" -ForegroundColor Yellow

    if (Test-Path $ExtractPath) { Remove-Item $ExtractPath -Recurse -Force }
    Expand-Archive -Path $ZipPath -DestinationPath $ExtractPath -Force -ErrorAction Stop
    Write-Host "  Extraction complete." -ForegroundColor Green

    $vmcxFile = Get-ChildItem $ExtractPath -Recurse -Filter "*.vmcx" | Select-Object -First 1
    if (-not $vmcxFile) { throw "No .vmcx file found. Valid MS Dev VM download?" }

    $importName = "WinBot-MSVM-Source"
    Write-Host "  Importing VM: $importName from $($vmcxFile.FullName)" -ForegroundColor Gray

    $existingVM = Get-VM -Name $importName -ErrorAction SilentlyContinue
    if ($existingVM) {
        if ($existingVM.State -ne "Off") { Stop-VM -Name $importName -Force -ErrorAction SilentlyContinue }
        Remove-VM -Name $importName -Force -ErrorAction SilentlyContinue
    }

    Import-VM -Path $vmcxFile.FullName -Copy -GenerateNewId -VhdDestinationPath $MasterPath -VirtualMachinePath $MasterPath -ErrorAction Stop

    $importedVM = Get-VM | Where-Object { $_.Path -like "*$MasterPath*" } | Select-Object -First 1
    if ($importedVM) {
        Rename-VM -VMName $importedVM.Name -NewName $importName -ErrorAction SilentlyContinue
    }

    $sourceVMName = $importName
    Write-Host "  VM imported: $sourceVMName" -ForegroundColor Green
} else {
    Write-Host "[WinBot] Opening Microsoft Dev VM download page..." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Download page:" -ForegroundColor Cyan
    Write-Host "  https://developer.microsoft.com/windows/downloads/virtual-machines/" -ForegroundColor White
    Write-Host ""
    Write-Host "  1. Select Hyper-V as the platform" -ForegroundColor White
    Write-Host "  2. Click Download zip" -ForegroundColor White
    Write-Host "  3. Save to: C:\WinBot\master\" -ForegroundColor White
    Write-Host "  4. Re-run: .\provision-msvm.ps1 -ZipPath path-to-zip" -ForegroundColor White
    Write-Host ""

    Start-Process "https://developer.microsoft.com/windows/downloads/virtual-machines/"
    Write-Host "[WinBot] After downloading, re-run this script with -ZipPath." -ForegroundColor Yellow
    exit 0
}

# ============================================================
# Step 3: Start VM and install WinBot
# ============================================================
Write-Host "[3/5] Starting VM and installing WinBot..." -ForegroundColor Cyan

$sourceVM = Get-VM -Name $sourceVMName -ErrorAction Stop
if ($sourceVM.State -ne "Running") {
    Write-Host "  Starting VM..." -ForegroundColor Gray
    Start-VM -Name $sourceVMName -ErrorAction Stop
}

# Wait for boot
Write-Host "  Waiting for boot..." -ForegroundColor Gray
$bootTimeout = 300
$elapsed = 0
$booted = $false
while ($elapsed -lt $bootTimeout) {
    $heartbeat = Get-VMIntegrationService -VMName $sourceVMName -Name "Heartbeat" -ErrorAction SilentlyContinue
    if ($heartbeat.PrimaryOperationalStatus -eq "Ok") {
        $booted = $true
        Write-Host "  VM booted - $elapsed s" -ForegroundColor Green
        break
    }
    Start-Sleep -Seconds 10
    $elapsed = $elapsed + 10
    if ($elapsed % 60 -eq 0) { Write-Host "  ... waited $elapsed s" -ForegroundColor Gray }
}
if (-not $booted) { throw "VM did not boot within $bootTimeout s." }

# Try PowerShell Direct to set up WinBot
Write-Host "  Setting up WinBot API via PowerShell Direct..." -ForegroundColor Gray

$securePw = ConvertTo-SecureString $VMPassword -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($VMUser, $securePw)

$apiFound = $false
try {
    $session = New-PSSession -VMName $sourceVMName -Credential $cred -ErrorAction Stop
    Write-Host "  PowerShell Direct session established." -ForegroundColor Green

    $result = Invoke-Command -Session $session -ScriptBlock {
        param($wbUser, $wbPw)
        $ErrorActionPreference = "Continue"

        # Create WinBot user
        try {
            $u = Get-LocalUser -Name $wbUser -ErrorAction SilentlyContinue
            if ($u) {
                $sp = ConvertTo-SecureString $wbPw -AsPlainText -Force
                Set-LocalUser -Name $wbUser -Password $sp
            } else {
                $sp = ConvertTo-SecureString $wbPw -AsPlainText -Force
                New-LocalUser -Name $wbUser -Password $sp -FullName "WinBot Automation" -PasswordNeverExpires -AccountNeverExpires
            }
            Add-LocalGroupMember -Group "Administrators" -Member $wbUser -ErrorAction SilentlyContinue
        } catch { }

        # Install NSSM
        if (-not (Get-Command nssm -ErrorAction SilentlyContinue)) {
            try { choco install nssm -y --no-progress 2>&1 | Out-Null } catch { }
        }

        # Auto-logon
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value "1" -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultUserName" -Value $wbUser -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultPassword" -Value $wbPw -Force

        # Disable UAC and sleep
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0 -Type DWord -Force
        powercfg -change -standby-timeout-ac 0 2>$null

        return @{Success = $true}
    } -ArgumentList $WinBotUser, $WinBotPassword -ErrorAction SilentlyContinue

    Remove-PSSession $session
    Write-Host "  WinBot account configured." -ForegroundColor Green
} catch {
    Write-Warning "PowerShell Direct setup failed: $_"
}

# Check for API
Write-Host "  Checking for WinBot API..." -ForegroundColor Gray
$vmNetwork = Get-VMNetworkAdapter -VMName $sourceVMName -ErrorAction SilentlyContinue
$vmIp = $null
if ($vmNetwork) {
    $vmIp = $vmNetwork.IPAddresses | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+' } | Select-Object -First 1
}

if ($vmIp) {
    $checkElapsed = 0
    while ($checkElapsed -lt 120) {
        try {
            $response = Invoke-WebRequest -Uri "http://${vmIp}:8000/health" -TimeoutSec 5 -ErrorAction SilentlyContinue -UseBasicParsing
            if ($response.StatusCode -eq 200) {
                $apiFound = $true
                Write-Host "  WinBot API is HEALTHY on ${vmIp}:8000" -ForegroundColor Green
                break
            }
        } catch {}
        Start-Sleep -Seconds 10
        $checkElapsed = $checkElapsed + 10
    }
    if (-not $apiFound) {
        Write-Host "  WinBot API not detected. Run setup-service.ps1 on the VM." -ForegroundColor Yellow
    }
}

# ============================================================
# Step 4: Finalize master VHDX
# ============================================================
Write-Host "[4/5] Finalizing golden master..." -ForegroundColor Cyan

if ((Get-VM -Name $sourceVMName -ErrorAction SilentlyContinue).State -ne "Off") {
    Write-Host "  Stopping VM..." -ForegroundColor Gray
    Stop-VM -Name $sourceVMName -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 10
    if ((Get-VM -Name $sourceVMName).State -ne "Off") {
        Stop-VM -Name $sourceVMName -Force
        Start-Sleep -Seconds 5
    }
}

$disks = Get-VMHardDiskDrive -VMName $sourceVMName -ErrorAction SilentlyContinue
$sourceVHDX = $disks[0].Path
if (-not $sourceVHDX -or -not (Test-Path $sourceVHDX)) {
    throw "Could not find source VHDX for VM: $sourceVMName"
}

Write-Host "  Source VHDX: $sourceVHDX" -ForegroundColor Gray

if ($sourceVHDX -ne $MasterVHDPath) {
    Write-Host "  Copying VHDX..." -ForegroundColor Gray
    if (Test-Path $MasterVHDPath) { Remove-Item $MasterVHDPath -Force }
    Copy-Item $sourceVHDX $MasterVHDPath -Force
    Write-Host "  VHDX copied to: $MasterVHDPath" -ForegroundColor Green
}

Set-ItemProperty -Path $MasterVHDPath -Name IsReadOnly -Value $true
Write-Host "  Master VHDX set to read-only." -ForegroundColor Green

Set-WinBotMasterHash -VHDXPath $MasterVHDPath

$configPath = Join-Path $projectDir "config.json"
if (Test-Path $configPath) {
    $config = Get-Content $configPath -Raw | ConvertFrom-Json -AsHashtable
    $config.master.vmName = "WinBot-Master"
    $config.master.vhdxPath = $MasterVHDPath
    $config.master.vmPath = $MasterPath
    $config | ConvertTo-Json -Depth 5 | Out-File -FilePath $configPath -Encoding utf8
    Write-Host "  Config updated." -ForegroundColor Green
}

# ============================================================
# Step 5: Cleanup
# ============================================================
Write-Host "[5/5] Cleanup..." -ForegroundColor Cyan

if (-not $KeepSourceVM) {
    Remove-VM -Name $sourceVMName -Force -ErrorAction SilentlyContinue
    Write-Host "  Source VM removed." -ForegroundColor Gray
} else {
    Write-Host "  Source VM preserved: $sourceVMName" -ForegroundColor Yellow
}

if ($ZipPath -and $ExtractPath -and (Test-Path $ExtractPath)) {
    Remove-Item $ExtractPath -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "  Extracted files cleaned up." -ForegroundColor Gray
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  WinBot Golden Master Ready" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Master VHDX: $MasterVHDPath" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Create a clone:" -ForegroundColor White
Write-Host "    Import-Module .\host\WinBot.psm1" -ForegroundColor Cyan
Write-Host "    New-WinBotClone -Name test -TimeoutMinutes 10" -ForegroundColor Cyan
Write-Host ""

return @{
    Success = $true
    MasterVHDPath = $MasterVHDPath
    SourceVM = $sourceVMName
    APIHealthy = $apiFound
}
