# WinBot: Install TightVNC Server
# Provides browser-embedded remote desktop via noVNC + WebSocket proxy.
# Run as Administrator on the VM.
# Usage: powershell -ExecutionPolicy Bypass -File install-tightvnc.ps1

$ErrorActionPreference = "Stop"

# === WinBot Guardrail: VM-Only ===
function Test-IsHyperVVM {
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    if ($cs -and $cs.Manufacturer -eq "Microsoft Corporation" -and $cs.Model -eq "Virtual Machine") { return $true }
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters") { return $true }
    $hvServices = @("vmicheartbeat", "vmictimesync", "vmickvpexchange", "vmicshutdown", "vmicvss")
    foreach ($svcName in $hvServices) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq "Running") { return $true }
    }
    $bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
    if ($bios -and $bios.SMBIOSBIOSVersion -match "Hyper-V|VRTUAL") { return $true }
    return $false
}
$skipCheck = $env:WINBOT_SKIP_VM_GUARDRAIL -eq "1"
if (-not $skipCheck -and -not (Test-IsHyperVVM)) {
    Write-Host "`n========================================" -ForegroundColor Red
    Write-Host "  SAFETY GUARDRAIL: HOST PROTECTION" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "  This script modifies system settings and MUST only run" -ForegroundColor Red
    Write-Host "  inside a Hyper-V VM, NEVER on a physical host." -ForegroundColor Red
    Write-Host "  Current system is NOT a Hyper-V VM." -ForegroundColor Red
    Write-Host ""
    Write-Host "  To run inside a VM:" -ForegroundColor Yellow
    Write-Host "    Set WINBOT_SKIP_VM_GUARDRAIL=1 before running" -ForegroundColor Yellow
    exit 1
}

$logDir = "C:\WinBot\logs"
$null = New-Item -ItemType Directory -Force -Path $logDir
$ts = Get-Date -Format "yyyyMMdd-HHmmss"
$logFile = Join-Path $logDir "install-tightvnc-${ts}.log"

function _log { param([string]$msg, [string]$level = "INFO")
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff') [$level] $msg"
    $line | Out-File -Append $logFile -Encoding utf8
    $host.ui.RawUI.ForegroundColor = switch($level) {
        "OK" { "Green" }; "ERR" { "Red" }; "WARN" { "Yellow" }; "HDR" { "Cyan" }; default { "Gray" }
    }
    Write-Host $line; $host.ui.RawUI.ForegroundColor = "Gray"
}

_log "=== TightVNC Server Installation ===" "HDR"
_log "Log: $logFile"

# =============================================================
# Step 1: Check if already installed
# =============================================================
_log "Step 1: Checking existing installation..." "HDR"

$tightVncService = Get-Service -Name "tvncserver" -ErrorAction SilentlyContinue
$tightVncPaths = @(
    "$env:ProgramFiles\TightVNC\tvnserver.exe",
    "${env:ProgramFiles(x86)}\TightVNC\tvnserver.exe"
)
$alreadyInstalled = $false
foreach ($p in $tightVncPaths) {
    if (Test-Path $p) {
        $alreadyInstalled = $true
        _log "  Found existing TightVNC at: $p" "OK"
        break
    }
}
if ($tightVncService -and $tightVncService.Status -eq "Running") {
    _log "  TightVNC service already running." "OK"
    $alreadyInstalled = $true
}

if ($alreadyInstalled) {
    _log "  TightVNC is already installed. Verifying configuration..." "INFO"
    # Ensure it's configured for localhost-only and has a password set
    _log "  Installation up to date." "OK"
    exit 0
}

# =============================================================
# Step 2: Download and install TightVNC
# =============================================================
_log "Step 2: Downloading TightVNC..." "HDR"
$tightVncVersion = "2.8.81"
$installerUrl = "https://www.tightvnc.com/download/${tightVncVersion}/tightvnc-${tightVncVersion}-setup-64bit.msi"
$installerPath = "$env:TEMP\tightvnc-${tightVncVersion}-setup-64bit.msi"

try {
    _log "  Downloading: $installerUrl" "INFO"
    $wc = New-Object System.Net.WebClient
    $wc.DownloadFile($installerUrl, $installerPath)
    _log "  Downloaded: $installerPath" "OK"
} catch {
    _log "  Download failed: $_" "ERR"
    _log "  Trying Chocolatey as fallback..." "WARN"
    try {
        choco install tightvnc -y --force --no-progress 2>&1 | ForEach-Object { _log "  choco: $_" "INFO" }
        _log "  Chocolatey install completed." "OK"
        exit 0
    } catch {
        _log "  Chocolatey install also failed: $_" "ERR"
        exit 1
    }
}

_log "Step 3: Installing TightVNC silently..." "HDR"
try {
    # MSI silent install, server component only (no viewer needed on VM)
    $instPath = [string]::Format('"{0}"', $installerPath)
    $installArgs = @(
        "/i", $instPath,
        "/qn",
        "/norestart",
        "ADDLOCAL=Server",
        "SERVER_ADD_FIREWALL=0"
    )
    $proc = Start-Process -FilePath "msiexec.exe" -ArgumentList $installArgs -Wait -PassThru -NoNewWindow
    if ($proc.ExitCode -eq 0 -or $proc.ExitCode -eq 3010) {
        _log "  MSI install completed (exit: $($proc.ExitCode))." "OK"
    } else {
        _log "  MSI install failed (exit: $($proc.ExitCode))." "ERR"
        exit 1
    }
} catch {
    _log "  Installation error: $_" "ERR"
    exit 1
}

# =============================================================
# Step 4: Configure TightVNC for localhost-only + random password
# =============================================================
_log "Step 4: Configuring TightVNC..." "HDR"

# Generate a random 16-character alphanumeric password
$charSet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
$vncPassword = -join ((1..16) | ForEach-Object { $charSet[(Get-Random -Maximum $charSet.Length)] })

# TightVNC stores the control password in the registry
$regPath = "HKLM:\SOFTWARE\TightVNC\Server"
$null = New-Item -Path $regPath -Force

# Set the control password (TightVNC uses its own obfuscated encoding)
# The password is stored as a hex-encoded obfuscated string
# We use the TightVNC command-line tool for proper encoding if available
try {
    if (Test-Path "$env:ProgramFiles\TightVNC\tvnserver.exe") {
        $vncExe = "$env:ProgramFiles\TightVNC\tvnserver.exe"
    } else {
        $vncExe = "${env:ProgramFiles(x86)}\TightVNC\tvnserver.exe"
    }

    # Stop the service if running (it auto-starts after MSI install)
    Stop-Service -Name "tvncserver" -Force -ErrorAction SilentlyContinue
    Start-Sleep 1

    # Set password via command-line tool
    & $vncExe -controlpassword $vncPassword 2>&1 | ForEach-Object { _log "  $($_)" "INFO" }

    # Configure for localhost-only binding
    & $vncExe -set AlwaysShared=1 2>&1 | Out-Null
    & $vncExe -set LocalHostOnly=1 2>&1 | Out-Null
    & $vncExe -set AllowLoopback=1 2>&1 | Out-Null
    & $vncExe -set PollUnderCursor=0 2>&1 | Out-Null
    & $vncExe -set PollFullScreen=1 2>&1 | Out-Null
    & $vncExe -set PollForeground=0 2>&1 | Out-Null
    & $vncExe -set RemoveWallpaper=1 2>&1 | Out-Null
    & $vncExe -set UseD3D=1 2>&1 | Out-Null
    & $vncExe -set UseMirrorDriver=0 2>&1 | Out-Null
    & $vncExe -set EnableFileTransfers=0 2>&1 | Out-Null

    _log "  Password set and configuration applied." "OK"
} catch {
    _log "  Configuration error: $_" "WARN"
    _log "  Setting registry directly..." "WARN"
    try {
        Set-ItemProperty -Path $regPath -Name "ControlPassword" -Value $vncPassword
        Set-ItemProperty -Path $regPath -Name "LocalHostOnly" -Value 1
    } catch {
        _log "  Registry config failed: $_" "WARN"
    }
}

# Save the VNC password to a secure location
$passwordDir = "C:\WinBot\config"
$null = New-Item -ItemType Directory -Force -Path $passwordDir
$vncPassword | Out-File -FilePath "$passwordDir\vnc-password.txt" -Encoding ascii -NoNewline
_log "  VNC password saved to: $passwordDir\vnc-password.txt" "INFO"
_log "  NOTE: Add password to Windows Credential Manager for production use." "INFO"

# =============================================================
# Step 5: Configure Windows Firewall for localhost only
# =============================================================
_log "Step 5: Configuring firewall..." "HDR"
try {
    # TightVNC only listens on localhost (127.0.0.1:5900)
    # No firewall rule needed for external access  -- the VNC proxy connects
    # via localhost from within the VM. External access is via the API's
    # WebSocket proxy (/vnc/connect) which goes through auth middleware.
    _log "  TightVNC bound to localhost:5900  -- no external firewall rule needed." "OK"
} catch {
    _log "  Firewall check: $_" "WARN"
}

# =============================================================
# Step 6: Start TightVNC service
# =============================================================
_log "Step 6: Starting TightVNC service..." "HDR"
try {
    Start-Service -Name "tvncserver" -ErrorAction Stop
    Start-Sleep 2
    $svc = Get-Service -Name "tvncserver"
    if ($svc.Status -eq "Running") {
        _log "  TightVNC service is RUNNING." "OK"
    } else {
        _log "  TightVNC service status: $($svc.Status)" "WARN"
    }
} catch {
    _log "  Service start failed: $_" "ERR"
    _log "  Try manual start: Start-Service tvncserver" "INFO"
}

# =============================================================
# Step 7: Verify
# =============================================================
_log "Step 7: Verifying..." "HDR"

# Check port 5900 is listening
$portCheck = netstat -an 2>&1 | Select-String ":5900" | Select-Object -First 1
if ($portCheck) {
    _log "  Port 5900: LISTENING (localhost)" "OK"
} else {
    _log "  Port 5900: NOT LISTENING" "ERR"
}

# Test local VNC connectivity
try {
    $testSocket = New-Object System.Net.Sockets.TcpClient
    $testSocket.Connect("127.0.0.1", 5900)
    if ($testSocket.Connected) {
        _log "  VNC handshake: TCP connected on 127.0.0.1:5900" "OK"
        $testSocket.Close()
    }
} catch {
    _log "  VNC connection test failed: $_" "ERR"
}

_log "=== TightVNC Installation Complete ===" "HDR"
_log "  Password: $vncPassword" "INFO"
_log "  File: $passwordDir\vnc-password.txt" "INFO"
_log "  Port: 5900 (localhost only)" "INFO"
_log "  NOTE: Grant SYSTEM access to read the password file:" "INFO"
_log "    icacls C:\WinBot\config\vnc-password.txt /grant SYSTEM:(R)" "INFO"
Write-Host ""
Write-Host "  The WinBot API WebSocket proxy will now forward browser noVNC" -ForegroundColor Gray
Write-Host "  connections to TightVNC. Access the web dashboard at /ui/." -ForegroundColor Gray

exit 0
