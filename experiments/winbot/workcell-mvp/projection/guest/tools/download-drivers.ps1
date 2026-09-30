# WinBot: Download Cross-Hypervisor Drivers
# Downloads and extracts NIC/storage/GPU drivers for all major hypervisors
# and physical hardware targets. Drivers are organized for DISM injection.
#
# Supported targets:
#   - KVM/QEMU:   virtio-win (Fedora signed, auto-updates to latest stable)
#   - VMware:      VMXNET3, PVSCSI, SVGA (from VMware Tools ISO)
#   - VirtualBox:  Guest Additions drivers (from VBoxAdditions ISO)
#   - Hyper-V:     Built into Windows 10+ (no download needed)
#   - Wyse5070:    Realtek RTL8168 NIC + Intel UHD 600/605 GPU + Intel Serial IO
#                  + Realtek ALC3253 Audio + Intel chipset INF
#
# Cache: ISOs cached in $OutputDir\_downloads\ with a cache.json manifest.
#        Re-download when -CheckForUpdates is passed or cache TTL expired.
#
# Versioning:
#   virtio-win:  Fedora's "stable-virtio" redirects to latest (auto-fresh)
#   VMware:      Uses "releases/latest" path + ETag check via HEAD request
#   VirtualBox:  Version pinned -- update URL when new major version ships
#   Wyse 5070:   Dell URL changes per driver pack -- set URL manually or use Dell
#                Command Update (dcu-cli.exe) to find latest drivers
#
# Usage:
#   .\download-drivers.ps1                           # Download all, use cache
#   .\download-drivers.ps1 -CheckForUpdates          # Check for newer versions
#   .\download-drivers.ps1 -Hypervisors "kvm"        # Just virtio
#   .\download-drivers.ps1 -Hypervisors "kvm","vmware","wyse5070"
#   .\download-drivers.ps1 -OutputDir "C:\WinBot\drivers"
#   .\download-drivers.ps1 -List                     # Show catalog + cache status
#   .\download-drivers.ps1 -List -Verbose            # Full Wyse 5070 hardware map

param(
    [ValidateSet("kvm","vmware","vbox","hyperv","wyse5070","all")]
    [string[]]$Hypervisors = @("all"),

    [string]$OutputDir = "C:\WinBot\drivers",

    [switch]$List,                      # List available drivers + URLs + cache status
    [switch]$CheckForUpdates,           # Check upstream for newer versions (HEAD request)
    [switch]$SkipDownload,              # Only extract from already-downloaded ISOs
    [switch]$Force,                     # Force re-download + re-extract even if cached
    [int]$CacheTTLDays = 90             # Re-download if cache older than this
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function Write-Step($msg) { Write-Host $msg -ForegroundColor Cyan }
function Write-OK($msg) { Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "  [WARN] $msg" -ForegroundColor Yellow }
function Write-Info($msg) { Write-Host "  [INFO] $msg" -ForegroundColor Gray }

# ============================================================
# Driver Catalog -- URLs, paths, hardware details
# ============================================================
$driverCatalog = @{
    "kvm" = @{
        Label = "KVM/QEMU (virtio-win)"
        # Fedora's stable-virtio redirect ALWAYS points to the latest stable build.
        # No version pinning needed -- this is the canonical auto-fresh URL.
        DownloadUrl = "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso"
        IsoName = "virtio-win.iso"
        VersionCheckUrl = "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/"
        AutoVersioned = $true    # URL auto-redirects to latest stable
        DriverMap = @(
            @{ SubDir = "NetKVM\w11\amd64";    Name = "VirtIO Network (NetKVM)";     Critical = $true }
            @{ SubDir = "viostor\w11\amd64";   Name = "VirtIO Block Storage";        Critical = $true }
            @{ SubDir = "vioscsi\w11\amd64";   Name = "VirtIO SCSI Storage";         Critical = $true }
            @{ SubDir = "vioserial\w11\amd64"; Name = "VirtIO Serial";               Critical = $false }
            @{ SubDir = "vioinput\w11\amd64";  Name = "VirtIO Input (mouse/keyb)";   Critical = $false }
            @{ SubDir = "viogpudo\w11\amd64";  Name = "VirtIO GPU";                  Critical = $false }
            @{ SubDir = "viofs\w11\amd64";     Name = "VirtIO FS (shared folders)";  Critical = $false }
            @{ SubDir = "Balloon\w11\amd64";   Name = "VirtIO Memory Balloon";       Critical = $false }
            @{ SubDir = "pvpanic\w11\amd64";   Name = "VirtIO Panic Device";         Critical = $false }
            @{ SubDir = "qemupciserial\w11\amd64"; Name = "QEMU PCI Serial";         Critical = $false }
        )
    }
    "vmware" = @{
        Label = "VMware (VMXNET3, PVSCSI, SVGA)"
        # VMware publishes at packages.vmware.com/tools/releases/latest/
        # The URL path after /latest/ changes per release. This pinned URL
        # is the last known-good. CheckForUpdates scrapes the /latest/ redirect.
        DownloadUrl = "https://packages.vmware.com/tools/releases/latest/windows/VMware-tools-windows-12.5.0-24276846.iso"
        IsoName = "VMware-tools.iso"
        VersionCheckUrl = "https://packages.vmware.com/tools/releases/latest/windows/"
        AutoVersioned = $false   # Must manually update pinned URL or use -CheckForUpdates
        VersionHint = "Check https://customerconnect.vmware.com/downloads for latest VMware Tools"
        DriverMap = @(
            @{ SubDir = "VMware\Drivers\vmxnet3\Win10";  Name = "VMware VMXNET3 NIC";     Critical = $true }
            @{ SubDir = "VMware\Drivers\pvscsi\Win10";   Name = "VMware PVSCSI Storage";  Critical = $true }
            @{ SubDir = "VMware\Drivers\efifw\Win10";    Name = "VMware EFI Firmware";    Critical = $false }
            @{ SubDir = "VMware\Drivers\vmusb\Win10";    Name = "VMware USB";             Critical = $false }
            @{ SubDir = "VMware\Drivers\vmware-svga\Win10"; Name = "VMware SVGA Graphics"; Critical = $false }
            @{ SubDir = "VMware\Drivers\vmaudio\Win10";  Name = "VMware HD Audio";        Critical = $false }
        )
    }
    "vbox" = @{
        Label = "VirtualBox (Guest Additions)"
        # VirtualBox releases page: https://download.virtualbox.org/virtualbox/
        # Pin to current stable. CheckForUpdates scrapes the directory listing.
        DownloadUrl = "https://download.virtualbox.org/virtualbox/7.1.6/VBoxGuestAdditions_7.1.6.iso"
        IsoName = "VBoxGuestAdditions.iso"
        VersionCheckUrl = "https://download.virtualbox.org/virtualbox/"
        AutoVersioned = $false
        VersionHint = "Check https://www.virtualbox.org/wiki/Downloads for latest"
        DriverMap = @(
            @{ SubDir = "cert";                Name = "VBox Certificates";         Critical = $false }
            @{ SubDir = "NT3x";                Name = "VBox Guest Drivers";        Critical = $false }
        )
    }
    "wyse5070" = @{
        Label = "Dell Wyse 5070 Thin Client"
        # Dell Wyse 5070 hardware inventory:
        #   CPU: Intel Celeron J4105/J5005 (Gemini Lake, 4C/4T)
        #   NIC: Realtek RTL8168/8111 PCIe Gigabit Ethernet
        #        PNP: PCI\VEN_10EC&DEV_8168
        #        Dell CAB: Network_Driver_XXXXX.cab (Realtek LAN 10.072)
        #   GPU: Intel UHD Graphics 600/605 (Gemini Lake integrated)
        #        PNP: PCI\VEN_8086&DEV_3185 / 3184
        #        Dell CAB: Video_Driver_XXXXX.cab (Intel Graphics 31.x)
        #   Audio: Realtek ALC3253 HD Audio
        #        PNP: HDAUDIO\FUNC_01&VEN_10EC&DEV_0325
        #        Dell CAB: Audio_Driver_XXXXX.cab
        #   Chipset: Intel Gemini Lake SoC
        #        PNP: PCI\VEN_8086&DEV_31F0
        #        Dell CAB: Chipset_Driver_XXXXX.cab (Intel chipset INF 10.1.x)
        #   Serial IO: Intel Serial IO (I2C0-I2C5, SPI, UART)
        #        PNP: PCI\VEN_8086&DEV_31AC/31AE/31B0/31B2/31B4/31B6/31B8/31BA/31BC/31BE/31C0/31C2/31C6/31EE
        #        Dell CAB: SerialIO_Driver_XXXXX.cab (Intel Serial IO 30.100.x)
        #   TXE: Intel Trusted Execution Engine
        #        PNP: PCI\VEN_8086&DEV_319A
        #        Dell CAB: TXE_Driver_XXXXX.cab
        #   GPIO: Intel GPIO controller Gemini Lake
        #        PNP: ACPI\VEN_INT&DEV_3453 (multiple instances)
        #        Dell CAB: Chipset_Driver_XXXXX.cab (included in chipset package)
        #   DPTF: Intel Dynamic Platform & Thermal Framework
        #        PNP: ACPI\VEN_INT&DEV_3403
        #        Dell CAB: DPTF_Driver_XXXXX.cab

        # Dell Command Update can find latest: dcu-cli.exe /scan -outputReport=drivers.xml
        DownloadUrl = "https://dl.dell.com/FOLDER11726105M/1/Wyse_5070_Driver_Pack.zip"
        IsoName = "Wyse5070-Drivers.zip"
        VersionCheckUrl = "https://www.dell.com/support/home/en-us/product-support/product/wyse-5070-thin-client/drivers"
        AutoVersioned = $false
        # Alternate: use Dell's direct CAB download URLs per driver category
        DriverNote = "Dell URL may change. Use Dell Command Update (dcu-cli.exe) to find latest CABs."
        DriverMap = @(
            @{
                SubDir = "Network\Realtek"
                Name = "Realtek RTL8168/8111 PCIe Gigabit NIC"
                Critical = $true
                PNPID = "PCI\VEN_10EC&DEV_8168"
                DellCAB = "Network_Driver_*.cab"
                Importance = "Boot-critical -- no NIC = no WinRM = no management"
            }
            @{
                SubDir = "Video\Intel"
                Name = "Intel UHD Graphics 600/605 (Gemini Lake)"
                Critical = $false
                PNPID = "PCI\VEN_8086&DEV_3185"
                DellCAB = "Video_Driver_*.cab"
                Importance = "Needed for GUI automation + screenshots (headless may skip)"
            }
            @{
                SubDir = "Chipset\Intel"
                Name = "Intel Gemini Lake Chipset INF + GPIO"
                Critical = $true
                PNPID = "PCI\VEN_8086&DEV_31F0"
                DellCAB = "Chipset_Driver_*.cab"
                Importance = "Boot-critical -- chipset INF identifies all SoC devices"
            }
            @{
                SubDir = "SerialIO\Intel"
                Name = "Intel Serial IO (I2C, SPI, UART)"
                Critical = $false
                PNPID = "PCI\VEN_8086&DEV_31AC"
                DellCAB = "SerialIO_Driver_*.cab"
                Importance = "Needed for some GPIO-dependent peripherals"
            }
            @{
                SubDir = "Audio\Realtek"
                Name = "Realtek ALC3253 HD Audio"
                Critical = $false
                PNPID = "HDAUDIO\FUNC_01&VEN_10EC&DEV_0325"
                DellCAB = "Audio_Driver_*.cab"
                Importance = "Optional -- agents don't use audio"
            }
            @{
                SubDir = "TXE\Intel"
                Name = "Intel Trusted Execution Engine"
                Critical = $false
                PNPID = "PCI\VEN_8086&DEV_319A"
                DellCAB = "TXE_Driver_*.cab"
                Importance = "Optional for automation -- needed for TPM/secure boot"
            }
            @{
                SubDir = "DPTF\Intel"
                Name = "Intel Dynamic Platform & Thermal Framework"
                Critical = $false
                PNPID = "ACPI\VEN_INT&DEV_3403"
                DellCAB = "DPTF_Driver_*.cab"
                Importance = "Power management -- useful for fanless 24/7 operation"
            }
        )
    }
}

# ============================================================
# Cache Manifest
# ============================================================
$cacheDir = Join-Path $OutputDir "_downloads"
$cacheManifest = Join-Path $cacheDir "cache.json"

function Load-CacheManifest {
    if (Test-Path $cacheManifest) {
        try { return Get-Content $cacheManifest -Raw | ConvertFrom-Json -AsHashtable } catch { return @{} }
    }
    return @{}
}

function Save-CacheManifest($manifest) {
    if (-not (Test-Path $cacheDir)) { New-Item -ItemType Directory -Path $cacheDir -Force | Out-Null }
    $manifest | ConvertTo-Json -Depth 3 | Out-File -FilePath $cacheManifest -Encoding utf8
}

function Test-CacheFresh {
    param($hv, $isoPath)
    $manifest = Load-CacheManifest
    $entry = $manifest[$hv]

    # No cache entry
    if (-not $entry) { return $false }

    # File missing
    if (-not (Test-Path $isoPath)) { return $false }

    # Force always bypasses cache
    if ($Force) { return $false }

    # TTL check
    $cachedAt = try { [DateTime]::Parse($entry.cached_at) } catch { [DateTime]::MinValue }
    $age = [math]::Round(((Get-Date) - $cachedAt).TotalDays, 1)
    if ($age -gt $CacheTTLDays) {
        Write-Info "Cache expired (${age}d > ${CacheTTLDays}d TTL) -- re-downloading"
        return $false
    }

    # If -CheckForUpdates, do a lightweight HEAD request to check for changes
    if ($CheckForUpdates) {
        $cat = $driverCatalog[$hv]
        if ($cat.VersionCheckUrl) {
            try {
                Write-Info "Checking for updates: $($cat.Label)..."
                $head = Invoke-WebRequest -Uri $cat.VersionCheckUrl -Method Head -TimeoutSec 10 -ErrorAction SilentlyContinue
                $remoteLastModified = $head.Headers["Last-Modified"]
                $remoteETag = $head.Headers["ETag"]

                if ($remoteLastModified -and $entry.last_modified) {
                    $remoteDate = try { [DateTime]::Parse($remoteLastModified) } catch { [DateTime]::MinValue }
                    $localDate = try { [DateTime]::Parse($entry.last_modified) } catch { [DateTime]::MinValue }
                    if ($remoteDate -gt $localDate) {
                        Write-Info "Remote modified ($remoteLastModified) > local ($($entry.last_modified)) -- updating"
                        return $false
                    }
                }
                if ($remoteETag -and $entry.etag -and $remoteETag -ne $entry.etag) {
                    Write-Info "ETag changed ($remoteETag vs $($entry.etag)) -- updating"
                    return $false
                }
                Write-OK "Cache fresh -- remote has not changed (age: ${age}d)"
            } catch {
                Write-Warn "Could not check for updates (network issue?) -- using cache"
            }
        } elseif ($cat.AutoVersioned) {
            Write-OK "Auto-versioned URL -- always points to latest stable (age: ${age}d, TTL: ${CacheTTLDays}d)"
        } else {
            Write-OK "Using cache (age: ${age}d, TTL: ${CacheTTLDays}d)"
            Write-Info "Version is pinned. Update URL manually or check: $($cat.VersionHint)"
        }
    } else {
        Write-OK "Using cache (age: ${age}d, TTL: ${CacheTTLDays}d)"
    }

    return $true
}

function Update-CacheEntry($hv, $isoPath, $cat) {
    $manifest = Load-CacheManifest
    $entry = @{
        hv = $hv
        iso = $cat.IsoName
        download_url = $cat.DownloadUrl
        cached_at = (Get-Date).ToUniversalTime().ToString("o")
        file_size = (Get-Item $isoPath).Length
        ttl_days = $CacheTTLDays
    }

    # Record remote headers for future freshness checks
    if ($cat.VersionCheckUrl) {
        try {
            $head = Invoke-WebRequest -Uri $cat.VersionCheckUrl -Method Head -TimeoutSec 10 -ErrorAction SilentlyContinue
            if ($head.Headers["Last-Modified"]) { $entry.last_modified = $head.Headers["Last-Modified"] }
            if ($head.Headers["ETag"]) { $entry.etag = $head.Headers["ETag"] }
        } catch {}
    }
    $manifest[$hv] = $entry
    Save-CacheManifest $manifest
}

# ============================================================
# List Mode -- show catalog with cache status
# ============================================================
if ($List) {
    Write-Host "=== Cross-Hypervisor Driver Catalog ===" -ForegroundColor Cyan
    Write-Host ""
    $manifest = Load-CacheManifest

    foreach ($hv in $driverCatalog.Keys | Sort-Object) {
        $cat = $driverCatalog[$hv]
        $entry = $manifest[$hv]

        Write-Host "$($cat.Label):" -ForegroundColor White
        Write-Host "  URL:      $($cat.DownloadUrl)" -ForegroundColor Gray
        if ($cat.AutoVersioned) {
            Write-Host "  Version:  AUTO (always latest stable)" -ForegroundColor Green
        } elseif ($cat.VersionHint) {
            Write-Host "  Version:  PINNED -- $($cat.VersionHint)" -ForegroundColor Yellow
        }

        if ($entry) {
            $age = [math]::Round(((Get-Date) - [DateTime]::Parse($entry.cached_at)).TotalDays, 1)
            $size = [math]::Round($entry.file_size / 1MB, 1)
            $fresh = if ($age -le $CacheTTLDays) { "FRESH" } else { "STALE" }
            $color = if ($fresh -eq "FRESH") { "Green" } else { "Yellow" }
            Write-Host "  Cache:    $fresh -- ${size}MB, cached $age days ago" -ForegroundColor $color
            if ($entry.etag) { Write-Host "  ETag:     $($entry.etag)" -ForegroundColor Gray }
            if ($entry.last_modified) { Write-Host "  Modified: $($entry.last_modified)" -ForegroundColor Gray }
        } else {
            Write-Host "  Cache:    [not downloaded]" -ForegroundColor Red
        }

        $extractedPath = Join-Path $OutputDir $hv
        if (Test-Path $extractedPath -and (Get-ChildItem $extractedPath -Recurse -Filter "*.inf" -ErrorAction SilentlyContinue)) {
            $infCount = (Get-ChildItem $extractedPath -Recurse -Filter "*.inf" -ErrorAction SilentlyContinue | Measure-Object).Count
            $extSize = [math]::Round((Get-ChildItem $extractedPath -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1MB, 1)
            Write-Host "  Extracted: $infCount INF files, ${extSize}MB" -ForegroundColor Green
        }

        Write-Host "  Drivers:" -ForegroundColor Gray
        foreach ($drv in $cat.DriverMap) {
            $crit = if ($drv.Critical) { "CRITICAL" } else { "optional" }
            $color = if ($drv.Critical) { "Yellow" } else { "Gray" }
            Write-Host "    - $($drv.Name) [$crit]" -ForegroundColor $color
            if ($drv.PNPID) {
                Write-Host "      PNP: $($drv.PNPID)" -ForegroundColor DarkGray
            }
        }
        Write-Host ""
    }

    Write-Host "=== Injection Points ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Drivers should be injected at three points:" -ForegroundColor White
    Write-Host "  1. Master VHDX  -- build-master.ps1 (boot drivers for first boot)" -ForegroundColor Gray
    Write-Host "  2. Golden WIM    -- export-golden-wim.ps1 (drivers for PXE deployment)" -ForegroundColor Gray
    Write-Host "  3. WinPE boot.wim -- build-winpe.ps1 (NIC drivers for PXE network access)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Minimum injection per target:" -ForegroundColor White
    Write-Host "  QEMU/KVM:   NetKVM + viostor (2 drivers, ~2MB)" -ForegroundColor Yellow
    Write-Host "  VMware:     VMXNET3 + PVSCSI (2 drivers, ~1MB)" -ForegroundColor Yellow
    Write-Host "  VirtualBox: NT3x driver folder (~500KB)" -ForegroundColor Yellow
    Write-Host "  Wyse 5070:  RTL8168 NIC + Intel chipset (2 drivers, boot-critical)" -ForegroundColor Yellow
    Write-Host "  Wyse 5070:  + Intel UHD Graphics 600 (for GUI automation)" -ForegroundColor Gray
    Write-Host "  Wyse 5070:  + Intel Serial IO + DPTF (for full functionality)" -ForegroundColor Gray

    exit 0
}

# ============================================================
# Main: Download and Extract
# ============================================================
if ($Hypervisors -contains "all") {
    $Hypervisors = @("kvm", "vmware", "vbox", "wyse5070")
}

if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }
if (-not (Test-Path $cacheDir)) { New-Item -ItemType Directory -Path $cacheDir -Force | Out-Null }

Write-Step "=== WinBot Driver Downloader ==="
Write-Step "Output:   $OutputDir"
Write-Step "Cache:    $cacheDir"
Write-Step "Targets:  $($Hypervisors -join ', ')"
Write-Step "TTL:      $CacheTTLDays days"
if ($CheckForUpdates) { Write-Step "Mode:     Check for updates (HEAD requests)" }
Write-Host ""

$results = @{}

foreach ($hv in $Hypervisors) {
    $cat = $driverCatalog[$hv]
    if (-not $cat) {
        Write-Warn "Unknown hypervisor: $hv -- skipping"
        continue
    }

    Write-Step "--- $($cat.Label) ---"

    $hvDir = Join-Path $OutputDir $hv
    $isoPath = Join-Path $cacheDir $cat.IsoName

    # Check if we need to re-download
    $needsDownload = $false
    $needsExtract = $false

    if (-not (Test-Path $isoPath)) {
        $needsDownload = $true
    } elseif (-not (Test-CacheFresh -hv $hv -isoPath $isoPath)) {
        $needsDownload = $true
    }

    if ((Test-Path $hvDir) -and -not $Force) {
        # Check if extraction has real INF files (not empty dirs)
        $infCount = (Get-ChildItem $hvDir -Recurse -Filter "*.inf" -ErrorAction SilentlyContinue | Measure-Object).Count
        if ($infCount -eq 0) {
            Write-Warn "Extracted dir exists but has no INF files -- re-extracting"
            Remove-Item $hvDir -Recurse -Force
            $needsExtract = $true
        } else {
            Write-OK "Already extracted: $hvDir ($infCount INF files)"
        }
    } else {
        $needsExtract = $true
    }

    # If download not needed and extraction is done, skip
    if (-not $needsDownload -and -not $needsExtract) {
        Write-OK "$($cat.Label) -- up to date"
        $results[$hv] = "cached"
        continue
    }

    # --- Download ---
    if ($needsDownload -and -not $SkipDownload) {
        Write-Host "  Downloading: $($cat.DownloadUrl)" -ForegroundColor Gray
        try {
            # Show progress for large files
            Invoke-WebRequest -Uri $cat.DownloadUrl -OutFile $isoPath -ErrorAction Stop
            $size = [math]::Round((Get-Item $isoPath).Length / 1MB, 1)
            Write-OK "Downloaded: $($cat.IsoName) (${size}MB)"

            # Record in cache manifest
            Update-CacheEntry -hv $hv -isoPath $isoPath -cat $cat
        } catch {
            Write-Warn "Download failed: $($_.Exception.Message)"
            if ($cat.DriverNote) { Write-Warn $cat.DriverNote }
            Write-Warn "Skipping $hv. Place the file manually at: $isoPath"
            $results[$hv] = "download-failed"
            continue
        }
    } elseif ($needsDownload) {
        Write-Warn "SkipDownload set -- looking for cached: $isoPath"
        if (-not (Test-Path $isoPath)) {
            Write-Warn "Not found. Skipping $hv."
            $results[$hv] = "missing"
            continue
        }
    }

    # --- Extract ---
    if ($needsExtract) {
        if (Test-Path $hvDir) { Remove-Item $hvDir -Recurse -Force }

        $ext = [IO.Path]::GetExtension($isoPath).ToLower()

        if ($ext -eq ".iso") {
            Write-Host "  Mounting ISO..." -ForegroundColor Gray
            try {
                $mount = Mount-DiskImage -ImagePath $isoPath -Passthru -ErrorAction Stop
                $driveLetter = ($mount | Get-Volume).DriveLetter
                if (-not $driveLetter) {
                    Start-Sleep -Seconds 2
                    $driveLetter = ($mount | Get-Volume).DriveLetter
                }
                Write-Host "  Mounted at ${driveLetter}:" -ForegroundColor Green

                New-Item -ItemType Directory -Path $hvDir -Force | Out-Null

                foreach ($drv in $cat.DriverMap) {
                    $srcPath = "${driveLetter}:\$($drv.SubDir)"
                    if (Test-Path $srcPath) {
                        $destName = $drv.SubDir -replace '\\', '_'
                        $destPath = Join-Path $hvDir $destName
                        Copy-Item $srcPath $destPath -Recurse -Force -ErrorAction SilentlyContinue
                        $infCount = (Get-ChildItem $destPath -Recurse -Filter "*.inf" -ErrorAction SilentlyContinue | Measure-Object).Count
                        Write-OK "Extracted: $($drv.Name) ($infCount INF files) -> $destName"
                    } else {
                        Write-Warn "Not found in ISO: $($drv.SubDir) ($($drv.Name))"
                    }
                }
                Dismount-DiskImage -ImagePath $isoPath -ErrorAction SilentlyContinue
            } catch {
                Write-Warn "ISO mount/extract failed: $_"
                Write-Warn "Try extracting with 7-Zip: 7z x $isoPath -oC:\WinBot\drivers\$hv"
            }

        } elseif ($ext -eq ".zip") {
            Write-Host "  Extracting ZIP..." -ForegroundColor Gray
            try {
                $extractDir = Join-Path $cacheDir "extract-$hv"
                if (Test-Path $extractDir) { Remove-Item $extractDir -Recurse -Force }
                Expand-Archive -Path $isoPath -DestinationPath $extractDir -Force -ErrorAction Stop

                # For Dell driver packs: look for INF files in CABs or directly.
                # Dell structure is typically flat or one level deep.
                $allInfs = Get-ChildItem $extractDir -Recurse -Filter "*.inf" -ErrorAction SilentlyContinue
                if ($allInfs) {
                    New-Item -ItemType Directory -Path $hvDir -Force | Out-Null
                    # Group by immediate parent directory name (driver category)
                    foreach ($inf in $allInfs) {
                        $categoryName = $inf.Directory.Name
                        $catDir = Join-Path $hvDir $categoryName
                        if (-not (Test-Path $catDir)) { New-Item -ItemType Directory -Path $catDir -Force | Out-Null }
                        # Copy all files from this INF's directory (INF + SYS + CAT + DLL)
                        Get-ChildItem $inf.DirectoryName | Copy-Item -Destination $catDir -Force -ErrorAction SilentlyContinue
                    }
                    $categories = (Get-ChildItem $hvDir -Directory).Name -join ', '
                    Write-OK "Extracted $($allInfs.Count) INF files across $((Get-ChildItem $hvDir -Directory | Measure-Object).Count) categories"
                    Write-OK "Categories: $categories"

                    # Validate: check which driver categories are populated
                    foreach ($drv in $cat.DriverMap) {
                        if ($drv.PNPID) {
                            $match = $allInfs | Where-Object {
                                (Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue) -match [regex]::Escape($drv.PNPID)
                            } | Select-Object -First 1
                            if ($match) {
                                Write-OK "Driver found for $($drv.Name) (PNP: $($drv.PNPID))"
                            } else {
                                Write-Warn "Driver NOT found for $($drv.Name) (PNP: $($drv.PNPID)) -- may need manual driver download"
                            }
                        }
                    }

                } else {
                    Write-Warn "No INF files found in archive."
                    Write-Info "The Dell driver pack may contain CAB files. Expand each CAB:"
                    Write-Info "  expand.exe *.cab -F:* C:\WinBot\drivers\wyse5070\"
                    # Try to expand CABs if present
                    $cabFiles = Get-ChildItem $extractDir -Recurse -Filter "*.cab" -ErrorAction SilentlyContinue
                    if ($cabFiles) {
                        Write-Host "  Found $($cabFiles.Count) CAB files -- expanding..." -ForegroundColor Gray
                        New-Item -ItemType Directory -Path $hvDir -Force | Out-Null
                        foreach ($cab in $cabFiles) {
                            $cabOutDir = Join-Path $hvDir $cab.BaseName
                            New-Item -ItemType Directory -Path $cabOutDir -Force | Out-Null
                            try {
                                expand.exe $cab.FullName -F:* $cabOutDir 2>&1 | Out-Null
                            } catch {
                                # PowerShell expand fallback
                                try { & dism /Online /Add-Package /PackagePath:$($cab.FullName) /IgnoreCheck 2>&1 | Out-Null } catch {}
                            }
                        }
                    }
                    $infCount = (Get-ChildItem $hvDir -Recurse -Filter "*.inf" -ErrorAction SilentlyContinue | Measure-Object).Count
                    if ($infCount -gt 0) {
                        Write-OK "Extracted $infCount INF files from CABs"
                    } else {
                        Write-Warn "No drivers extracted. Copy raw contents to: $hvDir"
                        Copy-Item "$extractDir\*" $hvDir -Recurse -Force -ErrorAction SilentlyContinue
                    }
                }
            } catch {
                Write-Warn "ZIP extraction failed: $_"
                Write-Info "Extract manually and place INF/CAT/SYS files in: $hvDir"
            }
        } else {
            Write-Warn "Unknown file type: $ext. Copy extracted drivers to: $hvDir"
        }
    }

    # Final validation
    $infCount = (Get-ChildItem $hvDir -Recurse -Filter "*.inf" -ErrorAction SilentlyContinue | Measure-Object).Count
    $size = [math]::Round((Get-ChildItem $hvDir -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1MB, 1)
    if ($infCount -gt 0) {
        Write-OK "$($cat.Label) -- $infCount INF files, ${size}MB ready"
        $results[$hv] = "ready"
    } else {
        Write-Warn "$($cat.Label) -- $infCount INF files, ${size}MB -- check extraction"
        $results[$hv] = "extraction-issue"
    }

    Write-Host ""
}

# ============================================================
# Summary
# ============================================================
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Driver Download Complete" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green

foreach ($hv in $Hypervisors) {
    $cat = $driverCatalog[$hv]
    $entry = $results[$hv]
    $color = switch ($entry) {
        "ready"   { "Green" }
        "cached"  { "Green" }
        default    { "Red" }
    }
    Write-Host "  $($cat.Label): $entry" -ForegroundColor $color
}

# Clean up intermediate extract dirs
Get-ChildItem $cacheDir -Directory -Filter "extract-*" -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

$cacheInfo = Load-CacheManifest
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Cache: $($cacheInfo.Count) entries, TTL: $CacheTTLDays days" -ForegroundColor Cyan
Write-Host "  Cache dir: $cacheDir" -ForegroundColor Gray
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Next: Inject drivers into images" -ForegroundColor White
Write-Host "    .\inject-drivers.ps1 -TargetVHDX C:\WinBot\master\Win11ENT.vhdx -Hypervisors kvm,vmware,vbox" -ForegroundColor Cyan
Write-Host "    .\inject-drivers.ps1 -TargetWIM C:\WinBot\pxe\WinBot-Golden.wim -Hypervisors all" -ForegroundColor Cyan
Write-Host "    .\inject-drivers.ps1 -TargetWinPE C:\WinBot\pxe\boot\boot.wim -Hypervisors kvm" -ForegroundColor Cyan
