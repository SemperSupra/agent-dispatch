# WinBot: Unified Node Reset (Self-Discovering)
# Runs INSIDE the guest/VM/physical node.
# Detects available reset methods, picks the best one, and executes it locally.
#
# Reset methods (auto-detected in priority order):
#   1. UWF  — Unified Write Filter: reboot clears RAM overlay instantly (~30s)
#   2. VHDX — Native VHDX boot: delete child VHDX, recreate, add BCD entry (~60s)
#   3. Reboot — Simple restart: no state change (fastest, least thorough)
#   4. PXE  — Set PXE-next-boot flag + reboot → network re-image (~10 min)
#
# This script is called by NodePool.psm1 (Reset-WinBotNode) via WinRM.
# It can also be run manually inside the machine for local resets.
#
# Usage:
#   .\reset-node.ps1                     # Auto-detect best method
#   .\reset-node.ps1 -Method UWF         # Force UWF reset
#   .\reset-node.ps1 -Method VHDX        # Force VHDX child rebuild
#   .\reset-node.ps1 -Method PXE         # Force PXE re-image
#   .\reset-node.ps1 -Method Reboot      # Simple restart
#   .\reset-node.ps1 -WhatIf             # Show what would happen
#   .\reset-node.ps1 -Detect             # Show detected methods (no action)

param(
    [ValidateSet("Auto","UWF","VHDX","PXE","Reboot")]
    [string]$Method = "Auto",

    [int]$DelaySeconds = 30,      # Countdown before reset executes
    [switch]$WhatIf,              # Dry run
    [switch]$Detect,              # Show detected methods and exit
    [switch]$Force                # Skip confirmation
)

$ErrorActionPreference = "Stop"

function Write-Step($msg) { Write-Host $msg -ForegroundColor Cyan }
function Write-OK($msg) { Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "  [WARN] $msg" -ForegroundColor Yellow }
function Write-Skip($msg) { Write-Host "  [SKIP] $msg" -ForegroundColor Gray }

# ============================================================
# Detect available reset methods
# ============================================================
function Detect-ResetMethods {
    $methods = @{
        UWF = $false
        VHDX = $false
        Reboot = $true     # Always available
        PXE = $false
    }

    # 1. UWF: check if Unified Write Filter is enabled
    try {
        $uwfOutput = uwfmgr get-config 2>&1 | Out-String
        if ($uwfOutput -match "Filter enabled:\s+Yes") {
            $methods.UWF = $true
        }
        # UWF may be installed but not enabled — still report status
        if ($uwfOutput -match "UWF") {
            $methods.UWFStatus = $uwfOutput
        }
    } catch {
        # UWF not available (not Enterprise/Education edition)
    }

    # 2. VHDX: check if booting from a VHDX (native VHDX boot)
    try {
        $bcdOutput = bcdedit /enum /v 2>&1 | Out-String
        if ($bcdOutput -match "\.vhdx" -or $bcdOutput -match "\.vhd") {
            $methods.VHDX = $true
            # Extract VHDX path from BCD
            if ($bcdOutput -match "device\s+.*vhd=\[([^\]]+)\]([^\s]+\.vhdx)") {
                $methods.VHDXPath = "$($matches[2])"
            }
        }
    } catch {
        # BCD not readable
    }

    # 3. PXE: check if firmware supports UEFI PXE boot
    try {
        $fwBootMgr = bcdedit /enum "{fwbootmgr}" /v 2>&1 | Out-String
        if ($fwBootMgr -match "displayorder" -and $fwBootMgr -match "uefi|network|pxe") {
            $methods.PXE = $true
        }
    } catch {
        # fwbootmgr not available on all systems
    }

    # 4. Check for WinBot VHDX deployment specifically
    if (-not $methods.VHDX) {
        $vhdxDir = "C:\WinBot\vhdx"
        if (Test-Path $vhdxDir) {
            $childVhdx = Get-ChildItem $vhdxDir -Filter "*Child*.*" -ErrorAction SilentlyContinue | Select-Object -First 1
            $masterVhdx = Get-ChildItem $vhdxDir -Filter "*Master*.*" -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($childVhdx -and $masterVhdx) {
                $methods.VHDX = $true
                $methods.VHDXChild = $childVhdx.FullName
                $methods.VHDXMaster = $masterVhdx.FullName
            }
        }
    }

    return $methods
}

# ============================================================
# Detect mode
# ============================================================
if ($Detect) {
    Write-Step "=== Reset Method Detection ==="
    $methods = Detect-ResetMethods

    Write-Host ""
    Write-Host "Available reset methods:" -ForegroundColor White
    Write-Host "  UWF:    $($methods.UWF)     (Unified Write Filter)" -ForegroundColor $(if ($methods.UWF) { "Green" } else { "Gray" })
    Write-Host "  VHDX:   $($methods.VHDX)    (Native VHDX boot)" -ForegroundColor $(if ($methods.VHDX) { "Green" } else { "Gray" })
    Write-Host "  PXE:    $($methods.PXE)    (UEFI PXE network boot)" -ForegroundColor $(if ($methods.PXE) { "Green" } else { "Gray" })
    Write-Host "  Reboot: $($methods.Reboot)     (Always available)" -ForegroundColor Green

    if ($methods.VHDXChild) {
        Write-Host ""
        Write-Host "VHDX deployment detected:" -ForegroundColor White
        Write-Host "  Master: $($methods.VHDXMaster)" -ForegroundColor Gray
        Write-Host "  Child:  $($methods.VHDXChild)" -ForegroundColor Gray
    }

    if ($methods.UWFStatus) {
        Write-Host ""
        Write-Host "UWF status:" -ForegroundColor White
        Write-Host ($methods.UWFStatus | Out-String) -ForegroundColor Gray
    }

    exit 0
}

# ============================================================
# Auto-select best method
# ============================================================
$methods = Detect-ResetMethods

if ($Method -eq "Auto") {
    if ($methods.UWF) {
        $Method = "UWF"
    } elseif ($methods.VHDX) {
        $Method = "VHDX"
    } else {
        $Method = "Reboot"
    }
    Write-Step "Auto-selected reset method: $Method"
} else {
    Write-Step "Forced reset method: $Method"
}

# Validate requested method is available
switch ($Method) {
    "UWF" {
        if (-not $methods.UWF) {
            throw "UWF reset requested but UWF is not enabled on this machine."
        }
    }
    "VHDX" {
        if (-not $methods.VHDX) {
            throw "VHDX reset requested but no VHDX boot configuration detected."
        }
    }
    "PXE" {
        Write-Warn "PXE reset requested. This requires PXE infrastructure on the network."
    }
}

# ============================================================
# WhatIf mode
# ============================================================
if ($WhatIf) {
    Write-Host ""
    Write-Host "[WhatIf] Would reset via: $Method" -ForegroundColor Cyan
    switch ($Method) {
        "UWF"   { Write-Host "[WhatIf] Would reboot — UWF overlay discarded automatically." -ForegroundColor Cyan }
        "VHDX"  {
            Write-Host "[WhatIf] Would delete child VHDX: $($methods.VHDXChild)" -ForegroundColor Cyan
            Write-Host "[WhatIf] Would create new child from master: $($methods.VHDXMaster)" -ForegroundColor Cyan
            Write-Host "[WhatIf] Would add BCD entry and reboot." -ForegroundColor Cyan
        }
        "PXE"   { Write-Host "[WhatIf] Would set PXE as next boot option and reboot." -ForegroundColor Cyan }
        "Reboot" { Write-Host "[WhatIf] Would reboot in $DelaySeconds seconds." -ForegroundColor Cyan }
    }
    exit 0
}

# ============================================================
# Execute Reset
# ============================================================
Write-Host ""

switch ($Method) {
    "UWF" {
        Write-Step "=== UWF Reset ==="
        Write-OK "Unified Write Filter is active."
        Write-OK "All changes since last boot are in RAM overlay."
        Write-OK "Reboot will discard overlay — system returns to pristine state."

        $cmd = "shutdown /r /t $DelaySeconds /c `"WinBot: UWF reset — overlay will be discarded`""
    }

    "VHDX" {
        Write-Step "=== VHDX Child Rebuild ==="

        $masterPath = $methods.VHDXMaster
        $childPath = $methods.VHDXChild
        if (-not $childPath) { $childPath = "C:\WinBot\vhdx\WinBot-Child.vhdx" }
        if (-not $masterPath) { $masterPath = "C:\WinBot\vhdx\WinBot-Master.vhdx" }

        if (-not (Test-Path $masterPath)) {
            throw "Master VHDX not found: $masterPath. Cannot rebuild child."
        }

        Write-OK "Master VHDX: $masterPath"
        Write-OK "Child VHDX:  $childPath"

        # Remove BCD entry for current VHDX boot
        Write-Host "  Removing old BCD entries..." -ForegroundColor Gray
        $bcdOutput = bcdedit /enum /v 2>&1 | Out-String
        $vhdxEntries = ($bcdOutput -split "`n") | Select-String -Pattern "identifier\s+(\{.+\})" -Context 0,8 |
            Where-Object { $_ -match "\.vhdx|WinBot" }
        if ($vhdxEntries) {
            $ids = ($vhdxEntries | Select-String -Pattern "identifier\s+(\{[^}]+\})" -AllMatches).Matches |
                ForEach-Object { $_.Groups[1].Value }
            foreach ($id in $ids) {
                bcdedit /delete $id /cleanup 2>&1 | Out-Null
                Write-OK "Removed BCD entry: $id"
            }
        }

        # Delete old child VHDX
        if (Test-Path $childPath) {
            Remove-Item $childPath -Force -ErrorAction Stop
            Write-OK "Deleted old child VHDX"
        }

        # Ensure master is read-only
        if (-not (Get-Item $masterPath).IsReadOnly) {
            Set-ItemProperty -Path $masterPath -Name IsReadOnly -Value $true
        }

        # Create new child VHDX
        Write-Host "  Creating new differencing child..." -ForegroundColor Gray
        try {
            New-VHD -ParentPath $masterPath -Path $childPath -Differencing -ErrorAction Stop | Out-Null
            Write-OK "New child VHDX created"
        } catch {
            # If differencing fails, try dynamic disk
            Write-Warn "Differencing creation failed: $_"
            Write-Host "  Falling back to dynamic disk..." -ForegroundColor Yellow
            New-VHD -Path $childPath -SizeBytes 127GB -Dynamic -ErrorAction Stop | Out-Null
            Write-OK "Dynamic VHDX created (not differencing — larger space usage)"
        }

        # Add BCD entry
        Write-Host "  Adding BCD entry..." -ForegroundColor Gray
        $childMount = Mount-VHD -Path $childPath -Passthru -ErrorAction Stop
        Start-Sleep -Seconds 2
        try {
            $disk = $childMount | Get-Disk
            if (-not $disk) { $disk = Get-Disk | Where-Object { $_.Location -like "*$childPath*" } | Select-Object -First 1 }
            $winPart = Get-Partition -DiskNumber $disk.Number | Where-Object { $_.Size -gt 1GB } | Select-Object -First 1
            $letter = ($winPart | Get-Volume).DriveLetter
            if (-not $letter) { $winPart | Set-Partition -NewDriveLetter V -ErrorAction SilentlyContinue; $letter = "V" }

            bcdboot "${letter}:\Windows" /s C: /f ALL
            if ($LASTEXITCODE -ne 0) { throw "BCDBOOT failed with exit code $LASTEXITCODE" }

            # Label the entry
            $bcdAfter = bcdedit /enum /v 2>&1 | Out-String
            $newId = ($bcdAfter | Select-String -Pattern "identifier\s+(\{[^}]+\})" -AllMatches).Matches |
                Select-Object -Last 1 | ForEach-Object { $_.Groups[1].Value }
            if ($newId) {
                bcdedit /set $newId description "WinBot (VHDX Boot)" 2>&1 | Out-Null
                bcdedit /set $newId recoveryenabled No 2>&1 | Out-Null
                bcdedit /default $newId 2>&1 | Out-Null
                bcdedit /timeout 5 2>&1 | Out-Null
            }
            Write-OK "BCD entry configured"
        } finally {
            Dismount-VHD -Path $childPath -ErrorAction SilentlyContinue
        }

        $cmd = "shutdown /r /t $DelaySeconds /c `"WinBot: VHDX child rebuilt — fresh node on next boot`""
    }

    "PXE" {
        Write-Step "=== PXE Re-Image Reset ==="

        # Set UEFI to network boot next
        Write-Host "  Configuring UEFI firmware for next boot..." -ForegroundColor Gray
        try {
            # bcdedit can set a one-time boot entry pointing to the network
            $fwEntries = bcdedit /enum "{fwbootmgr}" /v 2>&1 | Out-String
            $networkEntry = ($fwEntries | Select-String -Pattern "identifier\s+(\{[^}]+\})" -Context 0,3 |
                Where-Object { $_ -match "network|PXE|uefi.*nic" } |
                Select-Object -First 1) -replace '.*identifier\s+(\{[^}]+\}).*', '$1'

            if ($networkEntry -and $networkEntry -match '\{.+\}') {
                bcdedit /set "{fwbootmgr}" bootsequence $networkEntry 2>&1 | Out-Null
                Write-OK "UEFI configured for PXE boot on next restart"
            } else {
                Write-Warn "Could not find UEFI PXE entry. Machine may need manual BIOS PXE selection."
                Write-Warn "Ensure PXE/Network Boot is enabled in BIOS boot order."
            }
        } catch {
            Write-Warn "Could not set PXE boot flag: $_"
            Write-Warn "Manually select PXE/Network Boot from BIOS boot menu (F12 on most systems)."
        }

        $cmd = "shutdown /r /t $DelaySeconds /c `"WinBot: PXE re-image — machine will network-boot to WinPE`""
    }

    "Reboot" {
        Write-Step "=== Simple Reboot ==="
        Write-Warn "This does NOT reset system state. All changes persist."
        Write-Warn "Use UWF or VHDX reset for thorough state removal."

        $cmd = "shutdown /r /t $DelaySeconds /c `"WinBot: Node reboot — state preserved`""
    }
}

# ============================================================
# Execute the shutdown
# ============================================================
Write-Host ""
Write-Step "Reset will execute in $DelaySeconds seconds..."

if (-not $Force) {
    Write-Host "  Press Ctrl+C to cancel." -ForegroundColor Yellow
}

Write-Host "  Method: $Method" -ForegroundColor Cyan
Write-Host "  Hostname: $env:COMPUTERNAME" -ForegroundColor Cyan
Write-Host ""

# Execute the shutdown command
Invoke-Expression $cmd

# Return status for WinRM caller
return @{
    Success = $true
    Method = $Method
    Hostname = $env:COMPUTERNAME
    DelaySeconds = $DelaySeconds
    Message = "Reset initiated via $Method. Machine will reboot in $DelaySeconds seconds."
    AvailableMethods = $methods
}
