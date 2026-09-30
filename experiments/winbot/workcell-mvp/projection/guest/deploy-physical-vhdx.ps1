# WinBot: Deploy to Physical Machine via Native VHDX Boot
# Sets up the golden master VHDX + a differencing child VHDX for native boot.
# The physical machine boots directly from the VHDX file on its local disk.
#
# This mirrors the Hyper-V differencing disk model exactly:
#   Master VHDX (read-only) → Child VHDX (differencing, read-write)
#   Reset = delete child VHDX + create new child from master
#
# Windows 10/11 supports native VHDX boot natively (Windows To Go uses this).
#
# Usage:
#   .\deploy-physical-vhdx.ps1 -MasterVHDPath "D:\WinBot-Master.vhdx"
#   .\deploy-physical-vhdx.ps1 -MasterVHDPath "\\server\pxe\WinBot-Master.vhdx" -SystemDrive "C:"
#   .\deploy-physical-vhdx.ps1 -Reset   # Reset by recreating child VHDX

param(
    [string]$MasterVHDPath = "C:\WinBot\vhdx\WinBot-Master.vhdx",
    [string]$ChildVHDPath = "C:\WinBot\vhdx\WinBot-Child.vhdx",
    [string]$SystemDrive = "C:",
    [int]$ChildDiskSizeGB = 127,
    [string]$BootEntryName = "WinBot (VHDX Boot)",
    [switch]$Reset,                       # Reset = delete child + recreate
    [switch]$Status,                      # Show VHDX boot configuration
    [switch]$Remove,                      # Remove VHDX boot entries
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$WinBotDir = Join-Path $SystemDrive "WinBot"
$VHDXDir = Join-Path $WinBotDir "vhdx"

function Write-Step($msg) { Write-Host $msg -ForegroundColor Cyan }
function Write-OK($msg) { Write-Host "  [OK] $msg" -ForegroundColor Green }

# ============================================================
# Status mode
# ============================================================
if ($Status) {
    Write-Step "=== VHDX Boot Configuration ==="

    # Show BCD entries
    Write-Host "  Boot Configuration Data (BCD):" -ForegroundColor White
    bcdedit /enum /v 2>&1 | Select-String -Pattern "identifier|description|device|path|file"

    # Check VHDX files
    Write-Host ""
    Write-Host "  VHDX Files:" -ForegroundColor White
    $vhdxFiles = @($MasterVHDPath, $ChildVHDPath)
    foreach ($f in $vhdxFiles) {
        if (Test-Path $f) {
            $size = [math]::Round((Get-Item $f).Length / 1GB, 1)
            $readOnly = (Get-Item $f).IsReadOnly
            Write-OK "$f (${size}GB, ReadOnly=$readOnly)"
        } else {
            Write-Host "  [MISSING] $f" -ForegroundColor Red
        }
    }

    exit 0
}

# ============================================================
# Reset mode — delete child VHDX and recreate
# ============================================================
if ($Reset) {
    Write-Step "=== Resetting Physical Node (VHDX differencing) ==="

    if (-not (Test-Path $MasterVHDPath)) {
        throw "Master VHDX not found: $MasterVHDPath"
    }

    # Remove boot entry for the old child
    Write-Host "  Removing old BCD entry..." -ForegroundColor Gray
    $entries = bcdedit /enum /v 2>&1 | Out-String
    if ($entries -match "description\s+$([regex]::Escape($BootEntryName))") {
        $identifier = ($entries | Select-String -Pattern "identifier\s+(\{.+\})" -Context 0,5 | Select-Object -First 1).Matches.Groups[1].Value
        if ($identifier) {
            bcdedit /delete $identifier /cleanup 2>&1 | Out-Null
            Write-OK "Old BCD entry removed"
        }
    }

    # Delete old child VHDX
    if (Test-Path $ChildVHDPath) {
        Remove-Item $ChildVHDPath -Force
        Write-OK "Old child VHDX deleted"
    }

    # Create new child VHDX
    Write-Host "  Creating new child VHDX..." -ForegroundColor Gray
    if (-not (Get-Item $MasterVHDPath).IsReadOnly) {
        Write-Warning "Master VHDX is not read-only. Setting read-only now."
        Set-ItemProperty -Path $MasterVHDPath -Name IsReadOnly -Value $true
    }

    New-VHD -ParentPath $MasterVHDPath -Path $ChildVHDPath -Differencing -ErrorAction Stop | Out-Null
    Write-OK "New child VHDX created: $ChildVHDPath"

    # Add BCD entry
    Write-Host "  Adding BCD entry..." -ForegroundColor Gray
    $tempDrive = Mount-VHD -Path $ChildVHDPath -Passthru -ErrorAction Stop
    Start-Sleep -Seconds 2
    try {
        $disk = $tempDrive | Get-Disk
        if (-not $disk) { $disk = Get-Disk | Where-Object { $_.Location -like "*$ChildVHDPath*" } | Select-Object -First 1 }
        $winPart = Get-Partition -DiskNumber $disk.Number | Where-Object { $_.Size -gt 1GB } | Select-Object -First 1
        $letter = ($winPart | Get-Volume).DriveLetter
        if (-not $letter) { $winPart | Set-Partition -NewDriveLetter V -ErrorAction SilentlyContinue; $letter = "V" }

        bcdboot "${letter}:\Windows" /s $SystemDrive /f ALL
        if ($LASTEXITCODE -ne 0) { throw "BCDBOOT failed." }
    } finally {
        Dismount-VHD -Path $ChildVHDPath -ErrorAction SilentlyContinue
    }

    # Rename the boot entry
    $entries = bcdedit /enum /v 2>&1 | Out-String
    $identifier = ($entries | Select-String -Pattern "identifier\s+(\{.+\})" | Select-Object -First 1).Matches.Groups[1].Value
    if ($identifier) {
        bcdedit /set $identifier description "$BootEntryName" 2>&1 | Out-Null
        Write-OK "BCD entry: $BootEntryName"
    }

    Write-Host ""
    Write-OK "Reset complete. Reboot to boot into fresh WinBot node."
    Write-Host "  Run: shutdown /r /t 10" -ForegroundColor Yellow

    return @{
        Success = $true
        Action = "Reset"
        ChildVHDPath = $ChildVHDPath
        RebootRequired = $true
    }
}

# ============================================================
# Remove mode
# ============================================================
if ($Remove) {
    Write-Step "=== Removing VHDX Boot Configuration ==="

    # Remove BCD entry
    $entries = bcdedit /enum /v 2>&1 | Out-String
    if ($entries -match "description\s+$([regex]::Escape($BootEntryName))") {
        $identifier = ($entries | Select-String -Pattern "identifier\s+(\{.+\})" -Context 0,5 | Select-Object -First 1).Matches.Groups[1].Value
        if ($identifier) {
            bcdedit /delete $identifier /cleanup 2>&1 | Out-Null
            Write-OK "BCD entry removed"
        }
    }

    # Optionally remove VHDX files
    Get-ChildItem $VHDXDir -Filter "*.vhdx" -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Host "  VHDX remains: $($_.FullName) ($([math]::Round($_.Length/1GB,1)) GB)" -ForegroundColor Gray
        Write-Host "    Delete manually if no longer needed." -ForegroundColor Gray
    }

    exit 0
}

# ============================================================
# Initial setup: deploy VHDX boot for first time
# ============================================================
Write-Step "=== Deploying Physical VHDX Boot ==="

# 1. Ensure directories
if (-not (Test-Path $VHDXDir)) { New-Item -ItemType Directory -Path $VHDXDir -Force | Out-Null }

# 2. Copy master VHDX if needed
if (-not (Test-Path $MasterVHDPath)) {
    Write-Host "  Master VHDX not found locally." -ForegroundColor Yellow
    Write-Host "  Copy the golden master VHDX to: $MasterVHDPath" -ForegroundColor Yellow
    Write-Host "  Or provide path via -MasterVHDPath" -ForegroundColor Yellow

    # Try to find it in common locations
    $searchPaths = @(
        "C:\WinBot\master\Win11ENT.vhdx",
        "\\$env:COMPUTERNAME\WinBot\master\Win11ENT.vhdx"
    )
    $found = $false
    foreach ($search in $searchPaths) {
        if (Test-Path $search) {
            Write-Host "  Found master VHDX at: $search" -ForegroundColor Green
            Copy-Item $search $MasterVHDPath -Force
            $found = $true
            break
        }
    }
    if (-not $found) {
        throw "Master VHDX not found. Copy it from the build machine first."
    }
}
Write-OK "Master VHDX: $MasterVHDPath"

# 3. Ensure master is read-only
if (-not (Get-Item $MasterVHDPath).IsReadOnly) {
    Set-ItemProperty -Path $MasterVHDPath -Name IsReadOnly -Value $true
    Write-OK "Master VHDX set to read-only"
}

# 4. Create child differencing VHDX
if (Test-Path $ChildVHDPath) {
    if (-not $Force) {
        Write-Warn "Child VHDX already exists: $ChildVHDPath"
        Write-Host "  Use -Reset to recreate, or -Force to overwrite." -ForegroundColor Yellow
        exit 1
    }
    Remove-Item $ChildVHDPath -Force
}

Write-Host "  Creating child VHDX (${ChildDiskSizeGB} GB)..." -ForegroundColor Gray
New-VHD -ParentPath $MasterVHDPath -Path $ChildVHDPath -Differencing -SizeBytes ($ChildDiskSizeGB * 1GB) -Dynamic -ErrorAction Stop | Out-Null
Write-OK "Child VHDX created: $ChildVHDPath"

# 5. Configure BCD for VHDX boot
Write-Host "  Configuring boot loader..." -ForegroundColor Gray

$childMount = Mount-VHD -Path $ChildVHDPath -Passthru -ErrorAction Stop
Start-Sleep -Seconds 2
try {
    $disk = $childMount | Get-Disk
    if (-not $disk) { $disk = Get-Disk | Where-Object { $_.Location -like "*$ChildVHDPath*" } | Select-Object -First 1 }
    $winPart = Get-Partition -DiskNumber $disk.Number | Where-Object { $_.Size -gt 1GB } | Select-Object -First 1
    $letter = ($winPart | Get-Volume).DriveLetter
    if (-not $letter) { $winPart | Set-Partition -NewDriveLetter V -ErrorAction SilentlyContinue; $letter = "V" }

    # BCDBOOT adds the VHDX as a boot option
    bcdboot "${letter}:\Windows" /s $SystemDrive /f ALL
    if ($LASTEXITCODE -ne 0) { throw "BCDBOOT failed." }
    Write-OK "Boot entry added"
} finally {
    Dismount-VHD -Path $ChildVHDPath -ErrorAction SilentlyContinue
}

# 6. Name the boot entry
$entries = bcdedit /enum /v 2>&1 | Out-String
$identifiers = ($entries | Select-String -Pattern "identifier\s+(\{.+\})" -AllMatches).Matches | ForEach-Object { $_.Groups[1].Value }
$vhdIdentifier = $identifiers | Where-Object { $_ -like "{*}" } | Select-Object -Last 1
if ($vhdIdentifier) {
    bcdedit /set $vhdIdentifier description "$BootEntryName" 2>&1 | Out-Null
    bcdedit /set $vhdIdentifier osdevice "vhd=[$SystemDrive]$ChildVHDPath" 2>&1 | Out-Null

    # Disable recovery and automatic repair (they interfere with VHDX differencing)
    bcdedit /set $vhdIdentifier recoveryenabled No 2>&1 | Out-Null

    Write-OK "BCD entry: $BootEntryName"
}

# 7. Set VHDX boot as default
$bootmgrEntries = bcdedit /enum "{bootmgr}" /v 2>&1 | Out-String
$defaultMatch = ($bootmgrEntries | Select-String -Pattern "displayorder\s+(.+)" | Select-Object -First 1)
if ($vhdIdentifier) {
    bcdedit /default $vhdIdentifier 2>&1 | Out-Null
    bcdedit /timeout 5 2>&1 | Out-Null
    Write-OK "Default boot: $BootEntryName (5s timeout)"
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  VHDX Boot Deployed" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Master:    $MasterVHDPath" -ForegroundColor Cyan
Write-Host "  Child:     $ChildVHDPath" -ForegroundColor Cyan
Write-Host "  Boot:      $BootEntryName" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "  To reset this node at any time:" -ForegroundColor White
Write-Host "    .\deploy-physical-vhdx.ps1 -Reset" -ForegroundColor Cyan
Write-Host "  This deletes the child VHDX and creates a fresh one." -ForegroundColor Gray
Write-Host "  (Same model as Hyper-V differencing disks!)" -ForegroundColor Gray
Write-Host ""
Write-Host "  Reboot to boot into WinBot on VHDX:" -ForegroundColor Yellow
Write-Host "    shutdown /r /t 0" -ForegroundColor Cyan

return @{
    Success = $true
    MasterVHDPath = $MasterVHDPath
    ChildVHDPath = $ChildVHDPath
    BootEntry = $BootEntryName
    RebootRequired = $true
}
