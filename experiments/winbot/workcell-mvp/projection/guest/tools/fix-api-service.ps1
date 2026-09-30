# WinBot: Fix API service on existing clone
# Run inside the VM (via PowerShell Direct) to diagnose and repair
# the WinBot API service/Scheduled Task.
#
# Usage: powershell -ExecutionPolicy Bypass -File fix-api-service.ps1

$ErrorActionPreference = "Stop"
$logDir = "C:\WinBot\logs"
$ts = Get-Date -Format "yyyyMMdd-HHmmss"
$logFile = Join-Path $logDir "fix-api-service-${ts}.log"

function _log { param([string]$msg, [string]$level = "INFO")
$line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff') [$level] $msg"
$line | Out-File -Append $logFile -Encoding utf8
$host.ui.RawUI.ForegroundColor = switch($level) { "OK" { "Green" } "ERR" { "Red" } "WARN" { "Yellow" } "HDR" { "Cyan" } default { "Gray" } }
Write-Host $line; $host.ui.RawUI.ForegroundColor = "Gray"
}

_log "=== WinBot API Service Fix ===" "HDR"
_log "Log: $logFile" "INFO"

# =============================================================
# Step 1: Find Python (prefer SYSTEM-accessible paths)
# =============================================================
_log "Step 1: Finding Python..." "HDR"
$pyExe = $null

# Helper: invoke Python and capture stdout via .NET Process
# (handles paths with spaces unlike PS5.1 & and cmd.exe /c)
function _Invoke-Python {
    param([string]$Exe, [string]$Arguments)
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $Exe
        $psi.Arguments = $Arguments
        $psi.RedirectStandardOutput = $true
        $psi.UseShellExecute = $false
        $p = [System.Diagnostics.Process]::Start($psi)
        if (-not $p.WaitForExit(10000)) { return $null }
        $p.StandardOutput.ReadToEnd().Trim()
    } catch { $null }
}

# NOTE: PS5.1 @() array parser breaks on "MethodCall() + 'string'".
# Pre-compute folder paths into variables to avoid the parser bug.
$pf = [Environment]::GetFolderPath("ProgramFiles")
$lapp = [Environment]::GetFolderPath("LocalApplicationData")

# Search by known version numbers (Chocolatey installs to C:\Python$ver\)
foreach ($ver in @("314", "313", "312", "311")) {
    foreach ($p in @(
        "C:\Python$ver\python.exe",
        "$pf\Python$ver\python.exe",
        "${pf} (x86)\Python$ver\python.exe",
        "$lapp\Programs\Python\Python$ver\python.exe"
    )) {
        _log "  Searching: $p -> exists=$(Test-Path $p)" "INFO"
        if ((Test-Path $p) -and (_Invoke-Python $p "--version")) {
            $pyExe = $p
            $pyIsSystemWide = ($p -notmatch 'AppData\\Local')
            _log "  Found: $pyExe" "OK"
            break
        }
    }
    if ($pyExe) { break }
}

# Wildcard scan for any C:\Python*\ directory
if (-not $pyExe) {
    $wildMatches = Get-ChildItem "C:\Python*\python.exe" -ErrorAction SilentlyContinue
    foreach ($f in $wildMatches) {
        $verCheck = _Invoke-Python $f.FullName "--version"
        if ($verCheck) { $pyExe = $f.FullName; $pyIsSystemWide = $true; _log "Wildcard found: $pyExe ($verCheck)" "OK"; break }
    }
}

# Fall back to PATH lookup (skip Windows Apps stub - returns Access Denied)
if (-not $pyExe) {
    $g = Get-Command python -ErrorAction SilentlyContinue
    if ($g) {
        $src = $g.Source
        if ($src -notmatch 'WindowsApps') {
            $verCheck = _Invoke-Python $src "--version"
            if ($verCheck) { $pyExe = $src; $pyIsSystemWide = ($src -notmatch 'AppData\\Local'); _log "PATH Python: $pyExe ($verCheck)" "OK" }
        }
    }
}

# Install Python via Chocolatey if not found (without version pin -
# the exact version number varies and `--version 3.13.0` may not
# exist in the community feed)
if (-not $pyExe) {
    _log "No real Python installation found. Installing Python via Chocolatey..." "WARN"
    $choco = Get-Command choco -ErrorAction SilentlyContinue
    if ($choco) {
        try {
            & choco install python -y --force --no-progress 2>&1 | ForEach-Object { _log $_ "INFO" }
            # Refresh PATH in-process
            $env:Path = [Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [Environment]::GetEnvironmentVariable("Path","User")
            # Re-check for installed Python (choco installs to C:\Python$ver\)
            foreach ($p in @("C:\Python313\python.exe", "C:\Python312\python.exe", "C:\Python311\python.exe")) {
                if ((Test-Path $p) -and (_Invoke-Python $p "--version")) {
                    $pyExe = $p; $pyIsSystemWide = $true; break
                }
            }
            # Also check via refreshed PATH
            if (-not $pyExe) {
                $g = Get-Command python -ErrorAction SilentlyContinue
                if ($g -and ($g.Source -notmatch 'WindowsApps')) {
                    $verCheck = _Invoke-Python $g.Source "--version"
                    if ($verCheck) { $pyExe = $g.Source; $pyIsSystemWide = ($g.Source -notmatch 'AppData\\Local') }
                }
            }
        } catch { _log "Chocolatey install failed: $_" "ERR" }
    } else {
        _log "Chocolatey not available. Cannot install Python automatically." "ERR"
    }
}

if (-not $pyExe -or -not (Test-Path $pyExe)) {
    _log "No Python found. Install Python manually and retry." "ERR"
    _log "  Recommended: choco install python -y" "INFO"
    exit 1
}

$pyVer = _Invoke-Python $pyExe "--version"
_log "Python: $pyExe ($pyVer)" "OK"
_log "SYSTEM-accessible: $pyIsSystemWide" "INFO"

# If Python is per-user, grant SYSTEM read+execute access
if (-not $pyIsSystemWide) {
    _log "Per-user Python detected granting SYSTEM read/execute access..." "WARN"
    $pyDir = Split-Path $pyExe -Parent
    try {
        icacls $pyDir /grant "SYSTEM:(RX)" /T /Q 2>&1 | Out-Null
        _log "SYSTEM access granted to: $pyDir" "OK"
    } catch {
        _log "Failed to grant SYSTEM access: $_" "ERR"
        _log "Will try alternative approach..." "WARN"
    }
} else {
    _log "System-wide Python SYSTEM can access it." "OK"
}

# =============================================================
# Step 2: Install pip dependencies (uvicorn, fastapi, etc.)
# =============================================================
_log "Step 2: Installing pip dependencies..." "HDR"
$pipDeps = @("uvicorn", "fastapi", "pydantic", "pywinrm", "python-multipart", "psutil")
foreach ($dep in $pipDeps) {
    $check = _Invoke-Python $pyExe "-m pip show $dep"
    if ($check) {
        _log "  $dep already installed." "OK"
    } else {
        _log "  Installing $dep..." "INFO"
        try {
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = $pyExe
            $psi.Arguments = "-m pip install $dep --quiet"
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $psi.UseShellExecute = $false
            $p = [System.Diagnostics.Process]::Start($psi)
            if ($p.WaitForExit(60000)) {
                $out = $p.StandardOutput.ReadToEnd().Trim()
                $err = $p.StandardError.ReadToEnd().Trim()
                if ($p.ExitCode -eq 0) {
                    _log "  $dep installed." "OK"
                } else {
                    _log "  $dep install failed (exit $($p.ExitCode)): $err" "WARN"
                }
            } else {
                _log "  $dep install timed out." "WARN"
            }
        } catch { _log "  $dep install error: $_" "WARN" }
    }
}

# =============================================================
# Step 3: Remove broken NSSM service (if exists)
# =============================================================
_log "Step 3: Checking for broken NSSM service..." "HDR"
$nssmPath = "C:\ProgramData\chocolatey\bin\nssm.exe"
if (-not (Test-Path $nssmPath)) { $nssmPath = (Get-Command nssm -ErrorAction SilentlyContinue).Source }

$svc = Get-Service -Name "WinBotAPI" -ErrorAction SilentlyContinue
if ($svc) {
    _log "Found WinBotAPI service (Status: $($svc.Status), StartType: $($svc.StartType))" "INFO"

    if ($nssmPath) {
        # Check what Python path NSSM is configured with
        $nssmPy = & $nssmPath get WinBotAPI Application 2>&1
        _log "NSSM configured Python: $nssmPy" "INFO"

        # Check if the configured path is valid
        if ($nssmPy -and (Test-Path $nssmPy)) {
            _log "NSSM Python path is valid." "OK"
        } else {
            _log "NSSM Python path is INVALID or inaccessible. Reconfiguring..." "WARN"
            try {
                Stop-Service -Name "WinBotAPI" -Force -ErrorAction SilentlyContinue
                Start-Sleep 2
                & $nssmPath set WinBotAPI Application $pyExe
                & $nssmPath set WinBotAPI AppDirectory "C:\WinBot\api"
                & $nssmPath set WinBotAPI AppEnvironmentExtra "WINBOT_API_TOKEN=$(Get-Content C:\WinBot\.api_token -Raw -ErrorAction SilentlyContinue)"
                & $nssmPath set WinBotAPI Start SERVICE_AUTO_START
                & $nssmPath start WinBotAPI 2>$null
                Start-Sleep 5
                $s = Get-Service WinBotAPI
                _log "NSSM service restarted: $($s.Status)" "OK"
            } catch { _log "NSSM reconfig failed: $_" "ERR" }
        }
    } else {
        _log "NSSM not found. Removing service via sc.exe..." "WARN"
        try {
            Stop-Service -Name "WinBotAPI" -Force -ErrorAction SilentlyContinue
            Start-Sleep 2
            sc.exe delete WinBotAPI 2>$null
            _log "Service removed." "OK"
        } catch { _log "Service removal failed: $_" "ERR" }
    }
} else {
    _log "No NSSM WinBotAPI service found." "OK"
}

# =============================================================
# Step 4: Create / verify Scheduled Task
# =============================================================
_log "Step 4: Setting up Scheduled Task..." "HDR"
$taskName = "WinBot API Server"
$task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue

if (-not (Test-Path "C:\WinBot\api\main.py")) {
    _log "ERROR: C:\WinBot\api\main.py not found! Deploy code first." "ERR"
    exit 1
}

# Get or generate API token
$apiToken = Get-Content "C:\WinBot\.api_token" -Raw -ErrorAction SilentlyContinue
if (-not $apiToken) {
    $tokenBytes = New-Object byte[] 32
    (New-Object Security.Cryptography.RNGCryptoServiceProvider).GetBytes($tokenBytes)
    $apiToken = -join ($tokenBytes | ForEach-Object { "{0:x2}" -f $_ })
    $apiToken | Out-File -FilePath "C:\WinBot\.api_token" -Encoding ascii -NoNewline
    _log "Generated new API token" "OK"
}
$apiToken = $apiToken.Trim()

# Also set as machine-level env var so all processes (Scheduled Task,
# direct start, etc.) can read it without needing WINBOT_API_TOKEN
# on the task itself
[Environment]::SetEnvironmentVariable("WINBOT_API_TOKEN", $apiToken, "Machine")
_log "Machine env WINBOT_API_TOKEN set." "INFO"

# Update the current process env var too for direct-start fallback
$env:WINBOT_API_TOKEN = $apiToken

# Ensure Windows Firewall allows inbound connections on port 8000
_log "Adding Windows Firewall rule for port 8000..." "INFO"
try {
    $fwRule = Get-NetFirewallRule -DisplayName "WinBot API (port 8000)" -ErrorAction SilentlyContinue
    if (-not $fwRule) {
        New-NetFirewallRule -DisplayName "WinBot API (port 8000)" `
            -Direction Inbound -Protocol TCP -LocalPort 8000 `
            -Action Allow -Profile Any -ErrorAction Stop | Out-Null
        _log "Firewall rule created for TCP/8000." "OK"
    } else {
        _log "Firewall rule already exists." "OK"
    }
} catch {
    _log "Failed to create firewall rule: $_ (non-critical)" "WARN"
}

# Remove old task if it exists
if ($task) {
    _log "Existing Scheduled Task found (State: $($task.State)). Recreating..." "INFO"
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    Start-Sleep 1
}

# Create Scheduled Task that runs as winbot user (Interactive - has desktop access)
try {
    $taskAction = New-ScheduledTaskAction -Execute $pyExe `
        -Argument "-m uvicorn main:app --host 0.0.0.0 --port 8000" `
        -WorkingDirectory "C:\WinBot\api"
    $taskTrigger = New-ScheduledTaskTrigger -AtLogOn
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId "winbot" -LogonType Interactive
    $taskSettings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1) `
        -ExecutionTimeLimit (New-TimeSpan -Days 365)
    $envBlock = @{"WINBOT_API_TOKEN" = $apiToken}

    Register-ScheduledTask -TaskName $taskName `
        -Action $taskAction -Trigger $taskTrigger `
        -Principal $taskPrincipal -Settings $taskSettings `
        -Description "WinBot REST API - runs in user session for desktop/screenshot access" `
        -Force -ErrorAction Stop | Out-Null

    _log "Scheduled Task created." "OK"
} catch {
    _log "Failed to create Scheduled Task: $_" "ERR"
}

# =============================================================
# Step 5: Stop any running uvicorn, start the task
# =============================================================
_log "Step 5: Starting API..." "HDR"

# Kill any stale uvicorn processes
Get-WmiObject Win32_Process -Filter "Name='python.exe'" | Where-Object {
    $_.CommandLine -match "uvicorn"
} | ForEach-Object { $_.Terminate() } 2>$null
Start-Sleep 2

# Start via Scheduled Task (runs in winbot's session)
Start-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
Start-Sleep 8

# Check if uvicorn actually started. If not, launch directly as SYSTEM
# (Scheduled Task with Interactive logon may not start on headless VMs
# where winbot has no active session)
$uvProc = Get-WmiObject Win32_Process -Filter "Name='python.exe'" | Where-Object { $_.CommandLine -match "uvicorn" }
if (-not $uvProc) {
    _log "Scheduled Task did not start. Launching uvicorn directly..." "WARN"
    try {
        $apiLogDir = "C:\WinBot\logs"
        $startTs = Get-Date -Format "yyyyMMdd-HHmmss"
        $pidFile = Join-Path $apiLogDir "api-pid-${startTs}.txt"
        $errFile = Join-Path $apiLogDir "api-startup-err-${startTs}.log"
        $outFile = Join-Path $apiLogDir "api-startup-out-${startTs}.log"
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $pyExe
        $psi.Arguments = "-m uvicorn main:app --host 0.0.0.0 --port 8000"
        $psi.WorkingDirectory = "C:\WinBot\api"
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.UseShellExecute = $false
        $psi.EnvironmentVariables["WINBOT_API_TOKEN"] = $apiToken
        $p = [System.Diagnostics.Process]::Start($psi)
        # Write PID for later reference
        $p.Id | Out-File $pidFile -Encoding ascii
        # Wait briefly then check if still alive
        Start-Sleep 3
        if (-not $p.HasExited) {
            _log "Direct start PID: $($p.Id) (running)" "OK"
        } else {
            $err = $p.StandardError.ReadToEnd()
            $out = $p.StandardOutput.ReadToEnd()
            $err | Out-File $errFile -Encoding utf8
            $out | Out-File $outFile -Encoding utf8
            _log "API process exited immediately (code: $($p.ExitCode))" "ERR"
            if ($err) { _log "  stderr: $err" "ERR" }
            if ($out) { _log "  stdout: $out" "ERR" }
        }
    } catch { _log "Direct start failed: $_" "WARN" }
}

# =============================================================
# Step 6: Verify
# =============================================================
_log "Step 6: Verifying..." "HDR"

# Check Scheduled Task state
$task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($task) {
    _log "Scheduled Task State: $($task.State)" "INFO"
}

# Check for Python processes running uvicorn
$uvicornProcs = Get-WmiObject Win32_Process -Filter "Name='python.exe'" | Where-Object {
    $_.CommandLine -match "uvicorn"
}
$procCount = ($uvicornProcs | Measure-Object).Count
_log "Uvicorn processes: $procCount" "INFO"

# Check port 8000
$portCheck = netstat -an 2>&1 | Select-String ":8000" | Select-Object -First 1
if ($portCheck) {
    _log "Port 8000: LISTENING" "OK"
} else {
    _log "Port 8000: NOT LISTENING" "ERR"
}

# Try local curl to verify API responds
try {
    $resp = Invoke-WebRequest -Uri "http://localhost:8000/health" -TimeoutSec 5 -UseBasicParsing -Headers @{"X-API-Key"=$apiToken}
    _log "API Health: $($resp.StatusCode)" "OK"
} catch {
    try {
        $resp = Invoke-WebRequest -Uri "http://127.0.0.1:8000/health" -TimeoutSec 5 -UseBasicParsing -Headers @{"X-API-Key"=$apiToken}
        _log "API Health (127.0.0.1): $($resp.StatusCode)" "OK"
    } catch {
        _log "API not responding: $($_.Exception.Message)" "ERR"
        # Dump API logs for diagnostics
        foreach ($logPath in @("C:\WinBot\logs\api-stderr.log", "C:\WinBot\logs\api-stdout.log")) {
            if (Test-Path $logPath) {
                $logContent = Get-Content $logPath -Tail 30 -ErrorAction SilentlyContinue
                if ($logContent) { _log "--- $logPath (last 30 lines) ---" "INFO"; $logContent | ForEach-Object { _log "  | $_" "INFO" } }
            } else { _log "  $logPath not found" "INFO" }
        }
        # Check Windows Application event log for WinBot source
        try { $evt = Get-WinEvent -LogName Application -MaxEvents 5 | Where-Object { $_.ProviderName -match "WinBot|Python"} | ForEach-Object { _log "  Event: $($_.TimeCreated) [$($_.LevelDisplayName)] $($_.Message)" "INFO" } } catch {}
    }
}

_log "=== Fix complete ===" "HDR"
_log "If the API is still not responding, check:" "INFO"
_log " 1. C:\WinBot\logs\api-stderr.log" "INFO"
_log " 2. C:\WinBot\logs\api-stdout.log" "INFO"
_log " 3. Windows Event Viewer -> Windows Logs -> Application (source: WinBot)" "INFO"
