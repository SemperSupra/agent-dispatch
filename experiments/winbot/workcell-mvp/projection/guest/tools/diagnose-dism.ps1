# WinBot: DISM Privilege Diagnostic
# Gathers evidence on why DISM /Apply-Image fails with error 1314
# Usage: .\diagnose-dism.ps1
# NOTE: Run this when you have a mounted VHDX at T:\ and an ISO mounted

param(
    [switch]$TestScheduledTask,  # Also try DISM via SYSTEM scheduled task
    [string]$TargetDrive = "T:",  # Mounted VHDX drive letter
    [string]$IsoDrive = "",       # ISO drive letter (auto-detect if empty)
    [string]$LogDir = "C:\WinBot\logs\dism-diag"
)

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
$diagLog = Join-Path $LogDir "diagnostic-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
function Log($msg) { $line = "$(Get-Date -Format 'HH:mm:ss') $msg"; Write-Host $line; Add-Content $diagLog $line -Encoding utf8 }

Log "=== WinBot DISM Diagnostic ==="
Log "Windows: $(Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty Caption)"
Log "Build: $(Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty Version)"
Log ""

# ============================================================
# 1. WHOAMI /PRIV — full token privilege dump
# ============================================================
Log "--- [1/7] Token Privileges (whoami /priv) ---"
$privs = whoami /priv 2>&1
Log ($privs | Out-String)
Log ""

# Check for critical privileges
$privText = $privs | Out-String
$checks = @(
    @{Name="SeBackupPrivilege"; Need="Enabled"},
    @{Name="SeRestorePrivilege"; Need="Enabled"},
    @{Name="SeManageVolumePrivilege"; Need="Enabled"},
    @{Name="SeTakeOwnershipPrivilege"; Need="Enabled"},
    @{Name="SeSecurityPrivilege"; Need="Present"}
)
foreach ($c in $checks) {
    if ($privText -match $c.Name) {
        $line = $privs | Where-Object { $_ -match $c.Name }
        $state = if ($line -match "Enabled") { "ENABLED" } else { "DISABLED" }
        if ($state -eq $c.Need) { Log "  $($c.Name): $state [OK]" }
        else { Log "  $($c.Name): $state [NEEDS: $($c.Need)]" }
    } else {
        Log "  $($c.Name): MISSING FROM TOKEN [CRITICAL]"
    }
}
Log ""

# ============================================================
# 2. Local Security Policy — User Rights Assignment
# ============================================================
Log "--- [2/7] User Rights Assignments ---"
try {
    $rights = & secedit /export /areas USER_RIGHTS /cfg "$LogDir\secpol-export.inf" 2>&1
    $infContent = Get-Content "$LogDir\secpol-export.inf" -Raw
    $wantedRights = @(
        "SeBackupPrivilege",
        "SeRestorePrivilege",
        "SeManageVolumePrivilege",
        "SeTakeOwnershipPrivilege",
        "SeSecurityPrivilege",
        "SeSystemProfilePrivilege"
    )
    $wantedRights | ForEach-Object {
        $short = $_ -replace "Se(.*)Privilege", '$1'
        if ($infContent -match $short) {
            $line = ($infContent -split "`n" | Where-Object { $_ -match $short })
            Log "  $short : $($line.Trim())"
        } else {
            Log "  $short : NOT FOUND in secpol"
        }
    }
} catch {
    Log "  secedit failed: $_"
}
Log ""

# ============================================================
# 3. DISM version and capabilities
# ============================================================
Log "--- [3/7] DISM Information ---"
$dismPaths = @(
    "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\DISM\dism.exe",
    "C:\Program Files\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\DISM\dism.exe"
)
foreach ($dp in $dismPaths) {
    if (Test-Path $dp) {
        $ver = & $dp /English /? 2>&1 | Select-Object -Last 1
        Log "  ADK DISM: $dp"
        Log "    Version: $($ver -join ' ')"
        $dismExe = $dp
        break
    }
}
if (-not $dismExe) {
    $dismExe = (Get-Command dism -ErrorAction SilentlyContinue).Source
    if (-not $dismExe) { $dismExe = "C:\Windows\System32\dism.exe" }
    $ver = & $dismExe /English /? 2>&1 | Select-Object -Last 1
    Log "  System DISM: $dismExe"
    Log "    Version: $($ver -join ' ')"
}
Log ""

# ============================================================
# 4. Check existing DISM log for 1314 errors
# ============================================================
Log "--- [4/7] Existing DISM Log Analysis ---"
$dismLogPath = "$env:WINDIR\Logs\DISM\dism.log"
if (Test-Path $dismLogPath) {
    $dismLog = Get-Content $dismLogPath -Tail 200
    $errors = $dismLog | Select-String "Error|Warning" | Select-Object -Last 20
    if ($errors) {
        Log "  Last 20 error/warning lines from ${dismLogPath}:"
        $errors | ForEach-Object { Log "    $_" }
    }
    # Copy for analysis
    Copy-Item $dismLogPath "$LogDir\dism-captured.log" -Force -ErrorAction SilentlyContinue
    Log "  Full log copied to $LogDir\dism-captured.log"
    Log "  Log file size: $((Get-Item $dismLogPath).Length) bytes, last write: $((Get-Item $dismLogPath).LastWriteTime)"
} else {
    Log "  DISM log not found at $dismLogPath"
}
Log ""

# ============================================================
# 5. Check for mounted VHDX and what process holds it
# ============================================================
Log "--- [5/7] VHDX State ---"
$vhdImages = Get-DiskImage -ErrorAction SilentlyContinue
if ($vhdImages) {
    $vhdImages | ForEach-Object {
        Log "  Image: $($_.ImagePath)"
        Log "    Attached: $($_.Attached), Size: $([math]::Round($_.Size/1GB,2))GB, Type: $($_.StorageType)"
    }
} else {
    Log "  No VHDX images mounted (or Get-DiskImage failed)"
}

# Check drive T:
Log "  Drive T: state:"
$tDrive = Get-PSDrive T -ErrorAction SilentlyContinue
if ($tDrive) {
    Log "    Used: $([math]::Round($tDrive.Used/1GB,1))GB, Free: $([math]::Round($tDrive.Free/1GB,1))GB"
    # Check if Windows files are partially applied
    $tPaths = @()
    if (Test-Path "T:\Windows\System32") { $tPaths += "Windows\System32 exists" }
    if (Test-Path "T:\Windows\System32\config\SOFTWARE") { $tPaths += "SOFTWARE hive exists" }
    if (Test-Path "T:\Program Files") { $tPaths += "Program Files exists" }
    if (Test-Path "T:\Windows\Panther\Unattend.xml") { $tPaths += "Autounattend exists" }
    if ($tPaths.Count -eq 0) { Log "    T: is empty (DISM never wrote)" }
    else { $tPaths | ForEach-Object { Log "    $_" } }
} else {
    Log "    T: is not mounted or inaccessible"
}
Log ""

# ============================================================
# 6. Process holding file handles
# ============================================================
Log "--- [6/7] Processes With VHDX Handles ---"
try {
    $handleLines = & handle64 -a -u 2>&1 | Select-String "vhdx|WinBot" -ErrorAction SilentlyContinue
    if ($handleLines) {
        $handleLines | ForEach-Object { Log "  $_" }
    } else {
        Log "  No VHDX handles found (or Sysinternals handle64.exe not installed)"
    }
} catch {
    Log "  handle64.exe not available: $_"
}
Log ""

# ============================================================
# 7. Test SCHTASKS approach (if requested)
# ============================================================
if ($TestScheduledTask -and $dismExe) {
    Log "--- [7/7] SCHTASKS DISM Test ---"

    # Need an ISO or WIM path
    if (-not $IsoDrive) {
            # Auto-detect
            $iso = Get-DiskImage | Where-Object { $_.ImagePath -like "*.iso" -and $_.ImagePath -like "*Win11*" }
            if ($iso) {
                $isoVol = $iso | Get-Volume
                $IsoDrive = "$($isoVol.DriveLetter):"
                Log "  Auto-detected ISO: $($iso.ImagePath) at $IsoDrive"
            }
        }

        if ($IsoDrive -and (Test-Path "$IsoDrive\sources\install.wim")) {
            $wimPath = "$IsoDrive\sources\install.wim"
        } elseif ($IsoDrive -and (Test-Path "$IsoDrive\sources\install.esd")) {
            $wimPath = "$IsoDrive\sources\install.esd"
        } else {
            Log "  Cannot find install.wim. Provide -IsoDrive or mount the Windows ISO."
            Log "  Use: Mount-DiskImage -ImagePath 'C:\WinBot\master\*.iso'"
            $wimPath = ""
        }

        if ($wimPath) {
            Log "  WIM: $wimPath"
            Log "  Target: $TargetDrive"

            $taskName = "WinBot-Diag-DISM"
            $taskLog = Join-Path $LogDir "dism-task-output.log"

            Log "  Creating scheduled task '$taskName' as SYSTEM..."
            try {
                $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c `"$dismExe`" /English /Apply-Image /ImageFile:`"$wimPath`" /Index:1 /ApplyDir:$TargetDrive\ /Compact:Off /LogPath:`"$taskLog`" > `"$LogDir\stdout.txt`" 2>&1"
                $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
                $stSet = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
                Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $stSet -Force | Out-Null

                Log "  Starting task..."
                Start-ScheduledTask -TaskName $taskName

                # Wait up to 5 minutes
                $timeout = 300
                $waited = 0
                while ($waited -lt $timeout) {
                    Start-Sleep -Seconds 10
                    $waited += 10
                    $tsk = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
                    if ($tsk.State -eq "Ready") { break }
                    if ($waited % 30 -eq 0) { Log "    Waiting... (${waited}s)" }
                }
                Log "  Task finished after ${waited}s"

                # Gather results
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

                if (Test-Path $taskLog) {
                    $taskOutput = Get-Content $taskLog -Tail 30
                    Log "  DISM log output:"
                    $taskOutput | ForEach-Object { Log "    $_" }
                    if ($taskOutput -match "operation completed successfully") {
                        Log "  SCHTASKS APPROACH: SUCCESS"
                    } else {
                        Log "  SCHTASKS APPROACH: FAILED"
                    }
                }
                if (Test-Path "$LogDir\stdout.txt") {
                    $stdout = Get-Content "$LogDir\stdout.txt"
                    if ($stdout) {
                        Log "  stdout:"
                        $stdout | ForEach-Object { Log "    $_" }
                    }
                }
            } catch {
                Log "  SCHTASKS test failed with: $_"
            }
        }
}

Log ""
Log "=== Diagnostic complete ==="
Log "Results saved to: $diagLog"
Log "Artifacts in: $LogDir"
