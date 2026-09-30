# WinBot: Inject Cross-Hypervisor Drivers into Images
# Injects NIC, storage, and GPU drivers for multiple hypervisors
# into VHDX, WIM, or WinPE images using DISM.
#
# Injection points (pick one):
#   -TargetVHDX    -> Inject into golden master VHDX (offline, before first boot)
#   -TargetWIM     -> Inject into captured WIM (for PXE deployment)
#   -TargetWinPE   -> Inject into WinPE boot.wim (NIC drivers for network deployment)
#
# Hypervisor presets:
#   kvm      -> virtio-win (NetKVM, viostor, vioscsi, vioinput, viogpudo)
#   vmware   -> VMXNET3, PVSCSI, SVGA
#   vbox     -> VirtualBox Guest Additions drivers
#   hyperv   -> Hyper-V Integration Services (mostly built-in, adds synthetic drivers)
#   wyse5070 -> Realtek RTL8168 NIC + Intel UHD Graphics 600
#   all      -> All of the above
#
# Usage:
#   # Inject into master VHDX at build time
#   .\inject-drivers.ps1 -TargetVHDX "C:\WinBot\master\Win11ENT.vhdx" -Hypervisors "kvm","vmware"
#
#   # Inject into WIM after sysprep capture
#   .\inject-drivers.ps1 -TargetWIM "C:\WinBot\pxe\WinBot-Golden.wim" -Hypervisors all
#
#   # Inject only NIC + storage drivers (for WinPE -- skip GPU, audio, etc.)
#   .\inject-drivers.ps1 -TargetWinPE "C:\WinBot\pxe\boot\boot.wim" -Hypervisors "kvm","vmware"
#     -NICOnly
#
#   # Inject ONLY boot-critical drivers (minimum to boot, fastest injection)
#   .\inject-drivers.ps1 -TargetVHDX "..." -Hypervisors all -CriticalOnly
#
#   # Inject custom driver folder
#   .\inject-drivers.ps1 -TargetVHDX "C:\WinBot\master\Win11ENT.vhdx" -DriverPath "C:\MyDrivers"
#
#   # Dry run -- show what would be injected
#   .\inject-drivers.ps1 -TargetVHDX "..." -Hypervisors all -WhatIf
#
# Default behavior: ALL drivers injected (critical + nice-to-have).
# Use -CriticalOnly to inject only boot-critical (NIC + storage).
# Use -NICOnly for WinPE (NIC drivers only, smallest boot.wim).

param(
    # Target image (at least one required)
    [string]$TargetVHDX,
    [string]$TargetWIM,
    [string]$TargetWinPE,

    # Hypervisor presets (or custom driver path)
    [ValidateSet("kvm","vmware","vbox","hyperv","wyse5070","all")]
    [string[]]$Hypervisors = @(),

    [string]$DriverPath = "",          # Custom driver folder (takes precedence over presets)

    [string]$DriverRoot = "C:\WinBot\drivers",  # Root of downloaded drivers

    # Driver scope (by default ALL drivers are injected -- critical + nice-to-have)
    [switch]$CriticalOnly,             # Only boot-critical drivers (NIC + storage). DEFAULT: ALL.
    [switch]$NICOnly,                  # Only NIC drivers (smallest WinPE footprint)
    [switch]$StorageOnly,              # Only storage drivers (absolute minimum)

    # Windows version for driver subdirectory mapping
    [ValidateSet("auto","win11","win10","w11","w10")]
    [string]$WindowsVersion = "auto",  # "auto" detects from image, or force a target

    # DISM options
    [string]$MountDir = "",            # Temp mount directory (auto-generated if empty)
    [int]$WimIndex = 1,                # WIM index to inject into
    [switch]$WhatIf,                   # Dry run -- show what would happen
    [switch]$Force                     # Overwrite existing mount dirs
)

$ErrorActionPreference = "Stop"

function Write-Step($msg) { Write-Host $msg -ForegroundColor Cyan }
function Write-OK($msg) { Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "  [WARN] $msg" -ForegroundColor Yellow }
function Write-Skip($msg) { Write-Host "  [SKIP] $msg" -ForegroundColor Gray }

# ============================================================
# Driver presets -- which subdirectories to inject per hypervisor
# ============================================================
#
# Subdirectory naming: the download-drivers.ps1 script names extracted folders
# as "<Category>_<WinVer>_<Arch>" (e.g., "NetKVM_w11_amd64").
# The Windows version suffix comes from virtio-win ISO layout:
#   w11 = Windows 11 (also used for Windows Server 2022/2025)
#   w10 = Windows 10 (also used for Windows Server 2016/2019)
#   2k22 = Windows Server 2022 specifically
#
# For VMware: Win10 subdirectory covers both Win10 and Win11.
# For VirtualBox: drivers are not Windows-version-specific.
# For Wyse 5070: extracted Dell CABs use the CAB base name as folder name.
#
# By default, ALL drivers are injected (SubDirs = critical + nice-to-have).
# Use -CriticalOnly to inject only boot-critical (NIC + storage).
# Use -NICOnly for the smallest WinPE image.
$driverPresets = @{
    "kvm" = @{
        Label = "KVM/QEMU virtio"
        WinVer = "w11"   # virtio-win subdirectory suffix
        # ALL drivers (critical + nice-to-have) -- injected by default
        SubDirs = @("NetKVM_w11_amd64", "viostor_w11_amd64", "vioscsi_w11_amd64",
                     "vioserial_w11_amd64", "vioinput_w11_amd64", "viogpudo_w11_amd64",
                     "viofs_w11_amd64", "Balloon_w11_amd64",
                     "pvpanic_w11_amd64", "qemupciserial_w11_amd64")
        # Boot-critical only (injected with -CriticalOnly)
        CriticalSubDirs = @("NetKVM_w11_amd64", "viostor_w11_amd64", "vioscsi_w11_amd64")
        # NIC-only (for WinPE)
        NICSubDirs = @("NetKVM_w11_amd64")
        # Storage-only (absolute minimum to boot)
        StorageSubDirs = @("viostor_w11_amd64", "vioscsi_w11_amd64")
    }
    "vmware" = @{
        Label = "VMware Tools"
        WinVer = "Win10"  # VMware uses "Win10" for Win10+Win11
        SubDirs = @("VMware_Drivers_vmxnet3_Win10", "VMware_Drivers_pvscsi_Win10",
                     "VMware_Drivers_efifw_Win10", "VMware_Drivers_vmusb_Win10",
                     "VMware_Drivers_vmware-svga_Win10", "VMware_Drivers_vmaudio_Win10")
        CriticalSubDirs = @("VMware_Drivers_vmxnet3_Win10", "VMware_Drivers_pvscsi_Win10")
        NICSubDirs = @("VMware_Drivers_vmxnet3_Win10")
        StorageSubDirs = @("VMware_Drivers_pvscsi_Win10")
    }
    "vbox" = @{
        Label = "VirtualBox Guest Additions"
        WinVer = ""  # VBox drivers are not version-specific
        SubDirs = @("cert", "NT3x")   # certs + all guest drivers
        CriticalSubDirs = @("NT3x")   # Only guest drivers, skip certs
        NICSubDirs = @("NT3x")
        StorageSubDirs = @("NT3x")
    }
    "hyperv" = @{
        Label = "Hyper-V Integration Services"
        WinVer = ""   # Built into modern Windows -- no injection needed
        SubDirs = @()
        CriticalSubDirs = @()
        NICSubDirs = @()
        StorageSubDirs = @()
        BuiltIn = $true
    }
    "wyse5070" = @{
        Label = "Dell Wyse 5070 Thin Client"
        WinVer = ""   # Hardware drivers, not Windows-version-specific
        # ALL drivers: critical + nice-to-have. Injected by default.
        # These match the folder names created by download-drivers.ps1
        # when it extracts Dell CAB files or organizes INF directories.
        SubDirs = @(
            # --- Boot-critical ---
            "Network_Realtek",         # Realtek RTL8168/8111 NIC (PNP: PCI\VEN_10EC&DEV_8168)
            "Chipset_Intel",           # Intel Gemini Lake SoC INF + GPIO (PNP: PCI\VEN_8086&DEV_31F0)
            # --- Nice-to-have ---
            "Video_Intel",             # Intel UHD Graphics 600/605 (PNP: PCI\VEN_8086&DEV_3185)
            "SerialIO_Intel",          # Intel Serial IO I2C/SPI/UART (PNP: PCI\VEN_8086&DEV_31AC)
            "Audio_Realtek",           # Realtek ALC3253 HD Audio (PNP: HDAUDIO\FUNC_01&VEN_10EC&DEV_0325)
            "TXE_Intel",               # Intel Trusted Execution Engine (PNP: PCI\VEN_8086&DEV_319A)
            "DPTF_Intel"               # Intel Dynamic Platform & Thermal Framework (PNP: ACPI\VEN_INT&DEV_3403)
        )
        # Boot-critical only
        CriticalSubDirs = @("Network_Realtek", "Chipset_Intel")
        # NIC-only for WinPE
        NICSubDirs = @("Network_Realtek")
        # Storage-only -- Wyse uses standard SATA/NVMe (built into Windows), nothing extra
        StorageSubDirs = @()
        # Wyse-specific: drivers may be nested in CAB-extracted subdirectories.
        # If the expected folder names don't exist, we fall back to injecting
        # ALL discovered INF folders from the wyse5070 driver root.
        DiscoverDynamic = $true
    }
}

# ============================================================
# Resolve driver paths from presets -- inject ALL by default
# ============================================================
#
# By default (no flags): injects ALL drivers (SubDirs = critical + nice-to-have).
# -CriticalOnly: injects only CriticalSubDirs (NIC + storage -- minimum to boot).
# -NICOnly: injects only NICSubDirs (smallest WinPE footprint).
# -StorageOnly: injects only StorageSubDirs (absolute minimum).
#
# For Wyse 5070: if the expected folder names don't exist (Dell CAB structure
# varies per driver pack), falls back to DiscoverDynamic mode which injects
# ALL discovered INF directories from the wyse5070 driver root.
function Get-DriverPaths {
    param([string[]]$Hypervisors, [string]$DriverRoot)

    $paths = @()

    if ($Hypervisors -contains "all") {
        $Hypervisors = @("kvm", "vmware", "vbox", "wyse5070")
    }

    foreach ($hv in $Hypervisors) {
        $hvDir = Join-Path $DriverRoot $hv

        if (-not (Test-Path $hvDir)) {
            Write-Warn "$hv drivers not found at: $hvDir"
            Write-Warn "  Run: .\guest\tools\download-drivers.ps1 -Hypervisors $hv"
            continue
        }

        $preset = $driverPresets[$hv]
        if (-not $preset) {
            Write-Warn "No preset for: $hv"
            continue
        }

        if ($preset.BuiltIn) {
            Write-OK "$($preset.Label): built into Windows -- no injection needed"
            continue
        }

        # ---- Determine which subdir list to use ----
        $subDirs = $preset.SubDirs   # DEFAULT: ALL drivers (critical + nice-to-have)

        if ($StorageOnly) {
            $subDirs = $preset.StorageSubDirs
            Write-Info "Mode: StorageOnly -- absolute minimum to boot"
        } elseif ($NICOnly) {
            $subDirs = $preset.NICSubDirs
            Write-Info "Mode: NICOnly -- network drivers only (WinPE footprint)"
        } elseif ($CriticalOnly) {
            $subDirs = $preset.CriticalSubDirs
            Write-Info "Mode: CriticalOnly -- boot-critical drivers only (NIC + storage)"
        } else {
            Write-Info "Mode: ALL -- injecting critical + nice-to-have drivers"
        }

        # ---- Windows version remapping ----
        # If targeting a different Windows version, remap the subdir suffix.
        # Example: w11 -> w10 if targeting Windows 10.
        $targetWinVer = if ($WindowsVersion -eq "auto") { "w11" } else { $WindowsVersion }
        if ($WindowsVersion -eq "auto" -and $hv -eq "kvm") {
            # Auto-detect from mounted image happens at injection time.
            # For now, default to w11 (virtio-win stable always ships w11 drivers).
            $targetWinVer = "w11"
        } elseif ($hv -eq "kvm" -and $targetWinVer -ne $preset.WinVer) {
            # Remap: replace w11 with w10 in subdir names
            Write-Info "Windows version: remapping $($preset.WinVer) -> $targetWinVer"
            $subDirs = $subDirs | ForEach-Object { $_ -replace $preset.WinVer, $targetWinVer }
        }

        # ---- Find matching subdirectories ----
        $found = $false
        foreach ($subDir in $subDirs) {
            $fullPath = Join-Path $hvDir $subDir
            if (Test-Path $fullPath) {
                $infCount = (Get-ChildItem $fullPath -Recurse -Filter "*.inf" -ErrorAction SilentlyContinue | Measure-Object).Count
                if ($infCount -gt 0) {
                    $paths += $fullPath
                    Write-OK "$($preset.Label): $subDir ($infCount INF)"
                    $found = $true
                } else {
                    Write-Warn "$($preset.Label): $subDir -- directory exists but no INF files"
                }
            } else {
                # Try fuzzy match (Dell CABs produce names like "Network_Driver_XXXXX" not "Network_Realtek")
                $fuzzy = Get-ChildItem $hvDir -Directory -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -like "*$($subDir.Split('_')[0])*" } |
                    Select-Object -First 1
                if ($fuzzy) {
                    $infCount = (Get-ChildItem $fuzzy.FullName -Recurse -Filter "*.inf" -ErrorAction SilentlyContinue | Measure-Object).Count
                    if ($infCount -gt 0) {
                        $paths += $fuzzy.FullName
                        Write-OK "$($preset.Label): $($fuzzy.Name) (fuzzy match, $infCount INF)"
                        $found = $true
                    }
                }
            }
        }

        # ---- Wyse 5070 dynamic discovery fallback ----
        if (-not $found -and $preset.DiscoverDynamic) {
            Write-Info "Expected folders not found -- using dynamic discovery (all INF dirs in $hvDir)"
            $allDirs = Get-ChildItem $hvDir -Directory -ErrorAction SilentlyContinue
            $injected = 0
            foreach ($dir in $allDirs) {
                $infCount = (Get-ChildItem $dir.FullName -Recurse -Filter "*.inf" -ErrorAction SilentlyContinue | Measure-Object).Count
                if ($infCount -gt 0) {
                    $paths += $dir.FullName
                    Write-OK "$($preset.Label): $($dir.Name) (discovered, $infCount INF)"
                    $found = $true
                    $injected++
                }
            }
            if (-not $found) {
                Write-Warn "$($preset.Label): no INF directories found anywhere in $hvDir"
            }
        } elseif (-not $found) {
            # For non-Wyse hypervisors: if none of the expected subdirs matched,
            # try using the whole hvDir as a single driver path
            $infCount = (Get-ChildItem $hvDir -Recurse -Filter "*.inf" -ErrorAction SilentlyContinue | Measure-Object).Count
            if ($infCount -gt 0) {
                $paths += $hvDir
                Write-OK "$($preset.Label): injecting all drivers from root ($infCount INF)"
                $found = $true
            } else {
                Write-Warn "$($preset.Label): no drivers found -- check download/extraction"
            }
        }
    }

    return $paths
}

# ============================================================
# Find DISM
# ============================================================
function Get-WinBotDism {
    $adkDism = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\DISM\dism.exe"
    if (Test-Path $adkDism) { return $adkDism }
    $adkDism = Join-Path $env:ProgramFiles "Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\DISM\dism.exe"
    if (Test-Path $adkDism) { return $adkDism }
    return "dism.exe"
}

# ============================================================
# Inject drivers into a mounted directory
# ============================================================
function Invoke-DriverInjection {
    param([string]$MountPath, [string[]]$DriverPaths, [string]$DismExe)

    foreach ($drvPath in $DriverPaths) {
        Write-Host "  Injecting: $drvPath" -ForegroundColor Gray

        if ($WhatIf) {
            $infCount = (Get-ChildItem $drvPath -Recurse -Filter "*.inf" -ErrorAction SilentlyContinue | Measure-Object).Count
            Write-Host "    [WhatIf] Would inject $infCount INF files" -ForegroundColor Cyan
            continue
        }

        $result = & $DismExe /Image:$MountPath /Add-Driver /Driver:"$drvPath" /Recurse 2>&1
        if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 2) {
            # Exit code 0 = all drivers injected, 2 = some already present (fine)
            $injected = ($result | Select-String "installed driver package").Count
            $skipped = ($result | Select-String "already installed").Count
            Write-OK "Injected: $injected, Already present: $skipped"
        } elseif ($LASTEXITCODE -eq 50) {
            Write-Warn "DISM exit 50 -- may need /ForceUnsigned flag for non-WHQL drivers"
            $resultNoSign = & $DismExe /Image:$MountPath /Add-Driver /Driver:"$drvPath" /Recurse /ForceUnsigned 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-OK "Injected with /ForceUnsigned"
            } else {
                Write-Warn "Injection failed even with /ForceUnsigned. Check driver compatibility."
                Write-Host "    $($resultNoSign -join ' ')" -ForegroundColor Red
            }
        } else {
            Write-Warn "DISM exit code $LASTEXITCODE -- some drivers may have failed"
            Write-Host "    $($result -join ' ')" -ForegroundColor Gray
        }
    }
}

# ============================================================
# Main
# ============================================================
$dismExe = Get-WinBotDism
Write-Step "=== WinBot Driver Injection ==="
Write-Step "DISM: $dismExe"
Write-Host ""

# Resolve driver paths
$driverPaths = @()
if ($DriverPath -and (Test-Path $DriverPath)) {
    $driverPaths = @($DriverPath)
    Write-Step "Custom driver path: $DriverPath"
} elseif ($DriverPath) {
    Write-Warn "Custom driver path not found: $DriverPath"
}

if ($Hypervisors -and $Hypervisors.Count -gt 0) {
    $presetPaths = Get-DriverPaths -Hypervisors $Hypervisors -DriverRoot $DriverRoot
    $driverPaths += $presetPaths
}

if ($driverPaths.Count -eq 0) {
    Write-Warn "No driver paths resolved. Nothing to inject."
    Write-Host "  Download drivers first: .\guest\tools\download-drivers.ps1" -ForegroundColor Yellow
    Write-Host "  Or provide: -DriverPath 'C:\MyDrivers'" -ForegroundColor Yellow
    exit 1
}

Write-Step "Drivers to inject: $($driverPaths.Count) paths"
Write-Host ""

# Generate mount directory
if (-not $MountDir) {
    $ts = Get-Date -Format 'yyyyMMdd-HHmmss'
    $MountDir = Join-Path $env:TEMP "winbot-inject-$ts"
}

# ============================================================
# VHDX Injection
# ============================================================
if ($TargetVHDX) {
    Write-Step "Target: VHDX -- $TargetVHDX"

    if (-not (Test-Path $TargetVHDX)) {
        throw "VHDX not found: $TargetVHDX"
    }

    if ($WhatIf) {
        Write-Host "  [WhatIf] Would mount VHDX, inject drivers, dismount with commit" -ForegroundColor Cyan
        $infCount = ($driverPaths | ForEach-Object { Get-ChildItem $_ -Recurse -Filter "*.inf" -ErrorAction SilentlyContinue } | Measure-Object).Count
        Write-Host "  [WhatIf] Total INF files: $infCount" -ForegroundColor Cyan
        exit 0
    }

    # Suppress Explorer
    try { $shellSvc = Get-Service ShellHWDetection -ErrorAction SilentlyContinue; $shellWasRunning = ($shellSvc.Status -eq 'Running') } catch { $shellWasRunning = $false }
    if ($shellWasRunning) { Stop-Service ShellHWDetection -Force -ErrorAction SilentlyContinue }

    try {
        $mount = Mount-VHD -Path $TargetVHDX -Passthru -ErrorAction Stop
        Start-Sleep -Seconds 2

        $disk = $mount | Get-Disk
        if (-not $disk) { $disk = Get-Disk | Where-Object { $_.Location -like "*$TargetVHDX*" } | Select-Object -First 1 }
        $winPart = Get-Partition -DiskNumber $disk.Number | Where-Object { $_.Size -gt 1GB } | Select-Object -First 1
        $srcLetter = ($winPart | Get-Volume).DriveLetter
        if (-not $srcLetter) { $winPart | Set-Partition -NewDriveLetter Z -ErrorAction SilentlyContinue; $srcLetter = "Z" }
        Write-OK "Mounted at ${srcLetter}:"

        Invoke-DriverInjection -MountPath "${srcLetter}:\" -DriverPaths $driverPaths -DismExe $dismExe

    } finally {
        Dismount-VHD -Path $TargetVHDX -ErrorAction SilentlyContinue
        if ($shellWasRunning) { Start-Service ShellHWDetection -ErrorAction SilentlyContinue }
    }
}

# ============================================================
# WIM Injection
# ============================================================
if ($TargetWIM) {
    Write-Step "Target: WIM -- $TargetWIM (Index: $WimIndex)"

    if (-not (Test-Path $TargetWIM)) {
        throw "WIM not found: $TargetWIM"
    }

    if ($WhatIf) {
        Write-Host "  [WhatIf] Would mount WIM index $WimIndex, inject drivers, commit" -ForegroundColor Cyan
        $infCount = ($driverPaths | ForEach-Object { Get-ChildItem $_ -Recurse -Filter "*.inf" -ErrorAction SilentlyContinue } | Measure-Object).Count
        Write-Host "  [WhatIf] Total INF files: $infCount" -ForegroundColor Cyan
        exit 0
    }

    $mountPath = $MountDir
    if (Test-Path $mountPath) {
        if ($Force) { Remove-Item $mountPath -Recurse -Force } else { throw "Mount dir exists: $mountPath. Use -Force." }
    }
    New-Item -ItemType Directory -Path $mountPath -Force | Out-Null

    try {
        Write-Host "  Mounting WIM..." -ForegroundColor Gray
        & $dismExe /Mount-Image /ImageFile:$TargetWIM /Index:$WimIndex /MountDir:$mountPath /Optimize 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Failed to mount WIM index $WimIndex" }
        Write-OK "WIM mounted"

        Invoke-DriverInjection -MountPath $mountPath -DriverPaths $driverPaths -DismExe $dismExe

        Write-Host "  Committing changes..." -ForegroundColor Gray
        & $dismExe /Unmount-Image /MountDir:$mountPath /Commit 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Failed to commit WIM changes" }
        Write-OK "WIM committed"

    } catch {
        Write-Warn "Error: $_"
        & $dismExe /Unmount-Image /MountDir:$mountPath /Discard 2>&1 | Out-Null
        Remove-Item $mountPath -Recurse -Force -ErrorAction SilentlyContinue
        throw
    }

    Remove-Item $mountPath -Recurse -Force -ErrorAction SilentlyContinue
}

# ============================================================
# WinPE Injection
# ============================================================
if ($TargetWinPE) {
    Write-Step "Target: WinPE boot.wim -- $TargetWinPE"

    if (-not (Test-Path $TargetWinPE)) {
        throw "WinPE boot.wim not found: $TargetWinPE"
    }

    if ($WhatIf) {
        Write-Host "  [WhatIf] Would mount boot.wim, inject NIC/storage drivers, commit" -ForegroundColor Cyan
        Write-Host "  [WhatIf] WinPE typically only needs NIC + storage drivers" -ForegroundColor Cyan
        $infCount = ($driverPaths | ForEach-Object { Get-ChildItem $_ -Recurse -Filter "*.inf" -ErrorAction SilentlyContinue } | Measure-Object).Count
        Write-Host "  [WhatIf] Total INF files: $infCount" -ForegroundColor Cyan
        exit 0
    }

    $mountPath = $MountDir
    if (Test-Path $mountPath) {
        if ($Force) { Remove-Item $mountPath -Recurse -Force } else { throw "Mount dir exists: $mountPath. Use -Force." }
    }
    New-Item -ItemType Directory -Path $mountPath -Force | Out-Null

    try {
        Write-Host "  Mounting WinPE boot.wim..." -ForegroundColor Gray
        & $dismExe /Mount-Image /ImageFile:$TargetWinPE /Index:1 /MountDir:$mountPath /Optimize 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Failed to mount WinPE boot.wim" }
        Write-OK "WinPE mounted"

        Invoke-DriverInjection -MountPath $mountPath -DriverPaths $driverPaths -DismExe $dismExe

        # Set scratch space to handle driver bloat
        try { & $dismExe /Image:$mountPath /Set-ScratchSpace:512 2>&1 | Out-Null } catch {}

        Write-Host "  Committing changes..." -ForegroundColor Gray
        & $dismExe /Unmount-Image /MountDir:$mountPath /Commit 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Failed to commit WinPE changes" }
        Write-OK "WinPE committed"

    } catch {
        Write-Warn "Error: $_"
        & $dismExe /Unmount-Image /MountDir:$mountPath /Discard 2>&1 | Out-Null
        Remove-Item $mountPath -Recurse -Force -ErrorAction SilentlyContinue
        throw
    }

    Remove-Item $mountPath -Recurse -Force -ErrorAction SilentlyContinue
}

# ============================================================
# Summary
# ============================================================
Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Driver Injection Complete" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green

if ($TargetVHDX) {
    Write-Host "  Injected into: $TargetVHDX" -ForegroundColor Cyan
    Write-Host "  Next: Boot in any hypervisor -- drivers preloaded" -ForegroundColor White
} elseif ($TargetWIM) {
    Write-Host "  Injected into: $TargetWIM" -ForegroundColor Cyan
    Write-Host "  Next: Deploy via PXE to any hypervisor or physical machine" -ForegroundColor White
} elseif ($TargetWinPE) {
    Write-Host "  Injected into: $TargetWinPE" -ForegroundColor Cyan
    Write-Host "  Next: WinPE boots with full network + storage on injected hypervisors" -ForegroundColor White
}
Write-Host "========================================" -ForegroundColor Green
