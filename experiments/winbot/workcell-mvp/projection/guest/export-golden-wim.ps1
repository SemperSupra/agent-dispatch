# WinBot: Export Golden Master as WIM for PXE deployment
# Layer 1 — Captures a sysprepped WIM from the golden master VHDX.
# The WIM can be deployed to physical machines via PXE/WinPE.
#
# Process:
#   1. Create temp VM from master VHDX
#   2. Boot VM, wait for provisioning + API online
#   3. Inside VM: sysprep /generalize /oobe /shutdown
#   4. After shutdown: DISM /Capture-Image → WIM
#   5. Optionally inject drivers (Wyse 5070 NIC, storage)
#   6. Output: C:\WinBot\pxe\WinBot-Golden.wim
#
# Usage:
#   .\export-golden-wim.ps1
#   .\export-golden-wim.ps1 -MasterVHDPath "C:\WinBot\master\Win11ENT.vhdx" -Force
#   .\export-golden-wim.ps1 -InjectDrivers "C:\Drivers\Wyse5070" -Edition "Enterprise"

param(
    [string]$MasterVHDPath = "C:\WinBot\master\Win11ENT.vhdx",
    [string]$OutputDir = "C:\WinBot\pxe",
    [string]$OutputName = "WinBot-Golden.wim",
    [string]$ImageName = "WinBot Golden Master",
    [string]$ImageDescription = "WinBot automated Windows 11 - PXE deployable",
    [string]$InjectDrivers = "",           # Path to driver folder for injection
    [string[]]$Hypervisors = @(),          # e.g. -Hypervisors "kvm","vmware" (uses download-drivers.ps1 cache)
    [string]$DriverRoot = "C:\WinBot\drivers",
    [string]$WindowsEdition = "Enterprise",
    [int]$MemoryForVM = 4096,
    [int]$TimeoutMinutes = 45,
    [switch]$Force,
    [switch]$SkipProvisioning,             # Skip boot + provision — capture offline (no sysprep)
    [switch]$KeepTempVM                    # Don't delete the temp VM after capture
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectDir = Split-Path -Parent $scriptDir
$hostDir = Join-Path $projectDir "host"
$modulePath = Join-Path $hostDir "WinBot.psm1"
if (-not (Test-Path $modulePath)) { throw "WinBot module not found: $modulePath" }
Import-Module $modulePath -Force -ErrorAction Stop

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  WinBot - Golden WIM Exporter" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Master VHDX: $MasterVHDPath" -ForegroundColor Gray
Write-Host "  Output:      $OutputDir\$OutputName" -ForegroundColor Gray
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# ============================================================
# 1. Prerequisites
# ============================================================
Write-Host "[1/6] Checking prerequisites..." -ForegroundColor Cyan
Assert-Administrator

if (-not (Test-Path $MasterVHDPath)) {
    throw "Golden master VHDX not found: $MasterVHDPath`nRun .\guest\build-master.ps1 first."
}

$masterSize = [math]::Round((Get-Item $MasterVHDPath).Length / 1GB, 1)
Write-Host "  Master VHDX: ${masterSize}GB" -ForegroundColor Green

if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }
$freeGB = [math]::Round((Get-PSDrive -Name $OutputDir.Substring(0,1)).Free / 1GB, 1)
if ($freeGB -lt 25) { Write-Warning "Only $freeGB GB free — need ~25GB (15GB temp VHD + 8GB WIM)" }
Write-Host "  Disk space: $freeGB GB free" -ForegroundColor Green

$outputWim = Join-Path $OutputDir $OutputName
if (Test-Path $outputWim -and -not $Force) {
    $wimSize = [math]::Round((Get-Item $outputWim).Length / 1GB, 1)
    Write-Host "  WIM already exists: ${wimSize}GB. Use -Force to rebuild." -ForegroundColor Yellow
    exit 0
}

# ============================================================
# 2. Skip-provisioning mode: capture VHDX directly (no sysprep)
# ============================================================
if ($SkipProvisioning) {
    Write-Host "[2/6] Capturing WIM from master VHDX (offline, no sysprep)..." -ForegroundColor Cyan
    Write-Warning "SkipProvisioning: no sysprep. WIM may have VM-specific state. Use only for VM-to-VM cloning."

    $ts = Get-Date -Format 'yyyyMMdd-HHmmss'

    # Suppress Explorer
    try { $shellSvc = Get-Service ShellHWDetection -ErrorAction SilentlyContinue; $shellWasRunning = ($shellSvc.Status -eq 'Running') } catch { $shellWasRunning = $false }
    if ($shellWasRunning) { Stop-Service ShellHWDetection -Force -ErrorAction SilentlyContinue }

    try {
        # Mount the master VHDX
        $mount = Mount-VHD -Path $MasterVHDPath -Passthru -ErrorAction Stop
        Start-Sleep -Seconds 2

        $disk = $mount | Get-Disk
        if (-not $disk) { $disk = Get-Disk | Where-Object { $_.Location -like "*$MasterVHDPath*" } | Select-Object -First 1 }
        $winPart = Get-Partition -DiskNumber $disk.Number | Where-Object { $_.Size -gt 1GB } | Select-Object -First 1
        $srcLetter = ($winPart | Get-Volume).DriveLetter
        if (-not $srcLetter) { $winPart | Set-Partition -NewDriveLetter Z -ErrorAction SilentlyContinue; $srcLetter = "Z" }

        Write-Host "  Capturing from ${srcLetter}:\..." -ForegroundColor Yellow
        $captureStart = Get-Date
        dism /Capture-Image /ImageFile:$outputWim /CaptureDir:"${srcLetter}:\" /Name:"$ImageName" /Description:"$ImageDescription" /Compress:max /CheckIntegrity 2>&1 | ForEach-Object { Write-Host "  $_" }
        if ($LASTEXITCODE -ne 0) { throw "DISM capture failed." }
        $captureDuration = [math]::Round(((Get-Date) - $captureStart).TotalMinutes, 1)
        Write-Host "  WIM captured in ${captureDuration} min." -ForegroundColor Green

    } finally {
        Dismount-VHD -Path $MasterVHDPath -ErrorAction SilentlyContinue
        if ($shellWasRunning) { Start-Service ShellHWDetection -ErrorAction SilentlyContinue }
    }

    $wimSize = [math]::Round((Get-Item $outputWim).Length / 1GB, 1)
    Write-Host "  Output: $outputWim (${wimSize}GB)" -ForegroundColor Green
    exit 0
}

# ============================================================
# 3. Create temp VM from master
# ============================================================
Write-Host "[2/6] Creating temp VM from master VHDX..." -ForegroundColor Cyan

$ts = Get-Date -Format 'yyyyMMdd-HHmmss'
$tempVMName = "WinBot-Sysprep-$ts"
$tempVHDPath = Join-Path $OutputDir "temp-sysprep-$ts.vhdx"

# Create differencing disk from master (read-only parent)
try {
    New-VHD -ParentPath $MasterVHDPath -Path $tempVHDPath -Differencing -ErrorAction Stop | Out-Null
    Write-Host "  Differencing VHD: $tempVHDPath" -ForegroundColor Green
} catch {
    throw "Failed to create differencing disk: $_`nEnsure master VHDX is read-only."
}

# Create VM
$switchName = (Get-WinBotConfig).master.switchName
if (-not $switchName) { $switchName = "Default Switch" }

New-VM -Name $tempVMName -MemoryStartupBytes ($MemoryForVM * 1MB) -Generation 2 -SwitchName $switchName -ErrorAction Stop | Out-Null
Set-VM -Name $tempVMName -ProcessorCount 4 -ErrorAction SilentlyContinue
Set-VM -Name $tempVMName -AutomaticCheckpointsEnabled $false -ErrorAction SilentlyContinue

# Attach the differencing disk
$vhdPathInVM = $tempVHDPath
Add-VMHardDiskDrive -VMName $tempVMName -Path $tempVHDPath -ErrorAction Stop

# Enable TPM for Win11
try { Enable-VMTPM -VMName $tempVMName -ErrorAction SilentlyContinue } catch {}
Set-VMFirmware -VMName $tempVMName -EnableSecureBoot On -ErrorAction SilentlyContinue
Write-Host "  VM created: $tempVMName" -ForegroundColor Green

# ============================================================
# 4. Boot VM and wait for provisioning
# ============================================================
Write-Host "[3/6] Booting VM and waiting for provisioning (~10-15 min)..." -ForegroundColor Cyan
Start-VM -Name $tempVMName -ErrorAction Stop

# Wait for heartbeat
Write-Host "  Waiting for heartbeat..." -ForegroundColor Gray
$heartbeatTimeout = 120
$heartbeatElapsed = 0
do {
    Start-Sleep -Seconds 5
    $heartbeatElapsed += 5
    $hb = Get-VMIntegrationService -VMName $tempVMName -Name "Heartbeat" -ErrorAction SilentlyContinue
} while ($hb.PrimaryOperationalStatus -ne "Ok" -and $heartbeatElapsed -lt $heartbeatTimeout)

if ($hb.PrimaryOperationalStatus -ne "Ok") {
    Write-Warning "Heartbeat not detected after ${heartbeatTimeout}s. VM may still be booting."
}

# Wait for WinBot API to come online (signals provisioning done)
# The API is installed as a Windows service by stage-provision.ps1
Write-Host "  Waiting for WinBot API (provisioning in progress)..." -ForegroundColor Gray
$apiReady = $false
$apiTimeout = $TimeoutMinutes * 60
$apiElapsed = 0

# Get VM IP
do {
    Start-Sleep -Seconds 10
    $apiElapsed += 10
    $net = Get-VMNetworkAdapter -VMName $tempVMName -ErrorAction SilentlyContinue
    $vmIP = $net.IPAddresses | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+' } | Select-Object -First 1

    if ($vmIP) {
        try {
            $result = Invoke-RestMethod -Uri "http://${vmIP}:8000/health" -TimeoutSec 5 -ErrorAction Stop
            if ($result) {
                $apiReady = $true
                Write-Host "  WinBot API online at ${vmIP}:8000" -ForegroundColor Green
                Write-Host "  WinBot Version: $($result.winbot_version)" -ForegroundColor Green
            }
        } catch {
            # API not ready yet — provisioning still running
        }
    }

    if ($apiElapsed % 60 -eq 0) {
        Write-Host "  Still waiting... ($([math]::Round($apiElapsed/60))m elapsed)" -ForegroundColor Gray
    }
} while (-not $apiReady -and $apiElapsed -lt $apiTimeout)

if (-not $apiReady) { throw "WinBot API never came online after $TimeoutMinutes minutes. Provisioning may have failed." }

# ============================================================
# 5. Run sysprep inside the VM
# ============================================================
Write-Host "[4/6] Running sysprep /generalize /oobe..." -ForegroundColor Cyan

# Generate a fresh autounattend.xml for the generalized image
# This will be the answer file for machines deployed from this WIM
$password = Get-WinBotCredential -Name "vm-password" -Username "winbot" -AsPlaintext
if (-not $password) { throw "VM password not found in CredMan. Run build-master.ps1 first." }
$productKey = Get-WinBotCredential -Name "product-key" -Username "windows" -AsPlaintext -ErrorAction SilentlyContinue

# Copy the answer file into the VM for sysprep to use
$autounattendXml = Get-WinBotDismAutounattend -Password $password -Username "winbot" -ComputerName "WinBot-Node" -ProductKey $productKey -WindowsEdition $WindowsEdition

# Write autounattend to a temp file, copy into VM, then run sysprep
$tempXmlPath = Join-Path $OutputDir "autounattend-sysprep-$ts.xml"
$autounattendXml | Out-File -FilePath $tempXmlPath -Encoding utf8

# Copy answer file into the VM via PS Direct
try {
    $psSession = New-PSSession -VMName $tempVMName -ErrorAction Stop
    Copy-Item -ToSession $psSession -Path $tempXmlPath -Destination "C:\Windows\System32\Sysprep\unattend.xml" -Force

    # Run sysprep
    Write-Host "  Executing sysprep..." -ForegroundColor Yellow
    $sysprepScript = {
        $logPath = "C:\WinBot\logs\sysprep.log"
        New-Item -ItemType Directory -Path "C:\WinBot\logs" -Force | Out-Null
        & C:\Windows\System32\Sysprep\sysprep.exe /generalize /oobe /shutdown /unattend:C:\Windows\System32\Sysprep\unattend.xml /quiet 2>&1 | Out-File -FilePath $logPath -Encoding utf8
    }
    Invoke-Command -Session $psSession -ScriptBlock $sysprepScript -ErrorAction SilentlyContinue
    Write-Host "  Sysprep initiated. Waiting for VM to shut down..." -ForegroundColor Green
    Remove-PSSession $psSession
} catch {
    Write-Warning "PS Direct failed: $_. Trying WinRM fallback..."
    # Fallback: use the API to run sysprep via Python
    $token = (Get-WinBotCredential -Name "api-key-winbot" -Username "apikey" -AsPlaintext -ErrorAction SilentlyContinue)
    $headers = @{ "X-API-Key" = $token }
    $sysprepScript = @"
import subprocess, os
log_path = r"C:\WinBot\logs\sysprep.log"
os.makedirs(os.path.dirname(log_path), exist_ok=True)
with open(log_path, 'w') as f:
    subprocess.Popen(
        [r"C:\Windows\System32\Sysprep\sysprep.exe", "/generalize", "/oobe", "/shutdown",
         "/unattend:C:\Windows\System32\Sysprep\unattend.xml", "/quiet"],
        stdout=f, stderr=f
    )
print("Sysprep started")
"@
    Invoke-RestMethod -Uri "http://${vmIP}:8000/run/python" -Method Post -Headers $headers -Body (@{script = $sysprepScript} | ConvertTo-Json) -ContentType "application/json" | Out-Null
}

# Wait for VM to stop (sysprep shuts down when done)
Write-Host "  Waiting for sysprep to complete and VM to stop..." -ForegroundColor Gray
$shutdownTimeout = 600  # 10 minutes max
$shutdownElapsed = 0
do {
    Start-Sleep -Seconds 10
    $shutdownElapsed += 10
    $vmState = (Get-VM -Name $tempVMName -ErrorAction SilentlyContinue).State
    if ($shutdownElapsed % 60 -eq 0) {
        Write-Host "  VM state: $vmState ($([math]::Round($shutdownElapsed/60))m elapsed)" -ForegroundColor Gray
    }
} while ($vmState -ne "Off" -and $shutdownElapsed -lt $shutdownTimeout)

if ($vmState -ne "Off") {
    Write-Warning "VM did not shut down after sysprep. Force-stopping..."
    Stop-VM -Name $tempVMName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 5
}
Write-Host "  VM stopped." -ForegroundColor Green

# ============================================================
# 6. Capture WIM from the generalized VHDX
# ============================================================
Write-Host "[5/6] Capturing WIM from generalized disk..." -ForegroundColor Cyan

# Suppress Explorer during VHD mount
try { $shellSvc = Get-Service ShellHWDetection -ErrorAction SilentlyContinue; $shellWasRunning = ($shellSvc.Status -eq 'Running') } catch { $shellWasRunning = $false }
if ($shellWasRunning) { Stop-Service ShellHWDetection -Force -ErrorAction SilentlyContinue }

try {
    # Mount the differencing VHDX (contains the generalized Windows)
    $mount = Mount-VHD -Path $tempVHDPath -Passthru -ErrorAction Stop
    Start-Sleep -Seconds 2

    $disk = $mount | Get-Disk
    if (-not $disk) { $disk = Get-Disk | Where-Object { $_.Location -like "*$tempVHDPath*" } | Select-Object -First 1 }
    $winPart = Get-Partition -DiskNumber $disk.Number | Where-Object { $_.Size -gt 1GB } | Select-Object -First 1
    $srcLetter = ($winPart | Get-Volume).DriveLetter
    if (-not $srcLetter) { $winPart | Set-Partition -NewDriveLetter Z -ErrorAction SilentlyContinue; $srcLetter = "Z" }
    Write-Host "  Source drive: ${srcLetter}:" -ForegroundColor Green

    # Remove any existing WIM
    if (Test-Path $outputWim) { Remove-Item $outputWim -Force }

    Write-Host "  Running DISM /Capture-Image (compression: max)..." -ForegroundColor Yellow
    Write-Host "  This may take 10-20 minutes..." -ForegroundColor Gray
    $captureStart = Get-Date

    $captureLog = Join-Path $OutputDir "capture-dism.log"
    dism /Capture-Image /ImageFile:$outputWim /CaptureDir:"${srcLetter}:\" /Name:"$ImageName" /Description:"$ImageDescription" /Compress:max 2>&1 | Tee-Object -FilePath $captureLog

    if ($LASTEXITCODE -ne 0) { throw "DISM capture failed. Check $captureLog" }
    $captureDuration = [math]::Round(((Get-Date) - $captureStart).TotalMinutes, 1)
    Write-Host "  WIM captured in ${captureDuration} min." -ForegroundColor Green

} finally {
    Dismount-VHD -Path $tempVHDPath -ErrorAction SilentlyContinue
    if ($shellWasRunning) { Start-Service ShellHWDetection -ErrorAction SilentlyContinue }
}

# ============================================================
# 6a. Inject drivers (if requested)
# ============================================================
$hasCustomDrivers = ($InjectDrivers -and (Test-Path $InjectDrivers))
$hasHypervisorPresets = ($Hypervisors -and $Hypervisors.Count -gt 0)

if ($hasCustomDrivers -or $hasHypervisorPresets) {
    Write-Host "[5a/6] Injecting drivers into WIM..." -ForegroundColor Cyan

    $injectScript = Join-Path (Split-Path $scriptDir) "guest\tools\inject-drivers.ps1"
    if (-not (Test-Path $injectScript)) {
        $injectScript = Join-Path $scriptDir "tools\inject-drivers.ps1"
    }

    if ($hasHypervisorPresets -and (Test-Path $injectScript)) {
        $injectArgs = @("-TargetWIM", $outputWim, "-Hypervisors") + $Hypervisors
        if ($DriverRoot) { $injectArgs += @("-DriverRoot", $DriverRoot) }
        & $injectScript @injectArgs
    } elseif ($hasCustomDrivers) {
        # Use the existing custom driver path injection
        $driverFolders = Get-ChildItem $InjectDrivers -Directory -ErrorAction SilentlyContinue
        if (-not $driverFolders) { $driverFolders = @($InjectDrivers) }

        foreach ($driverDir in $driverFolders) {
            Write-Host "  Injecting: $driverDir" -ForegroundColor Gray
            dism /Mount-Image /ImageFile:$outputWim /Index:1 /MountDir:"C:\WinBot\pxe\mount" /Optimize 2>&1 | Out-Null
            try {
                dism /Image:"C:\WinBot\pxe\mount" /Add-Driver /Driver:"$driverDir" /Recurse 2>&1 | Out-Null
                if ($LASTEXITCODE -ne 0) { Write-Warning "Driver injection may have failed for: $driverDir" }
                dism /Unmount-Image /MountDir:"C:\WinBot\pxe\mount" /Commit 2>&1 | Out-Null
            } catch {
                dism /Unmount-Image /MountDir:"C:\WinBot\pxe\mount" /Discard 2>&1 | Out-Null
                throw
            }
        }
    }
    Write-Host "  Driver injection complete." -ForegroundColor Green
}

# ============================================================
# 6b. Validate WIM
# ============================================================
Write-Host "[6/6] Validating WIM..." -ForegroundColor Cyan
$wimInfo = dism /Get-ImageInfo /ImageFile:$outputWim
if ($LASTEXITCODE -ne 0) { throw "WIM validation failed." }
Write-Host "  WIM valid." -ForegroundColor Green

$wimSize = [math]::Round((Get-Item $outputWim).Length / 1GB, 1)
$wimInfo = dism /Get-WimInfo /WimFile:$outputWim
$indexCount = ($wimInfo | Select-String "Index :").Count

# ============================================================
# Cleanup
# ============================================================
if (-not $KeepTempVM) {
    Write-Host "  Cleaning up temp VM..." -ForegroundColor Gray
    Stop-VM -Name $tempVMName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Remove-VM -Name $tempVMName -Force -ErrorAction SilentlyContinue
    Remove-Item $tempVHDPath -Force -ErrorAction SilentlyContinue
    Remove-Item $tempXmlPath -Force -ErrorAction SilentlyContinue
    Write-Host "  Temp VM removed." -ForegroundColor Green
}

# ============================================================
# Done
# ============================================================
Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Golden WIM Exported" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host "  File:    $outputWim" -ForegroundColor Cyan
Write-Host "  Size:    ${wimSize}GB" -ForegroundColor Cyan
Write-Host "  Indexes: $indexCount" -ForegroundColor Cyan
Write-Host "  Name:    $ImageName" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Next: Build WinPE boot image" -ForegroundColor White
Write-Host "    .\guest\winpe\build-winpe.ps1" -ForegroundColor Cyan
Write-Host "  Or: Set up PXE server" -ForegroundColor White
Write-Host "    .\host\setup-pxe.ps1" -ForegroundColor Cyan

return @{
    Success = $true
    WimPath = $outputWim
    SizeGB = $wimSize
    IndexCount = $indexCount
    ImageName = $ImageName
}
