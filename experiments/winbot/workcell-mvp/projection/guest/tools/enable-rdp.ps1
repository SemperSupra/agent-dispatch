# WinBot: Enable RDP Server on the guest VM
# RDP server (TermService) is built into every Windows system  -- no installation needed.
# Run as Administrator.
# Usage: powershell -ExecutionPolicy Bypass -File enable-rdp.ps1
#
# This enables native mstsc.exe access for the best possible user experience:
# full 60 FPS, clipboard, audio, drive redirection, NLA security.

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
    return $false
}
$skipCheck = $env:WINBOT_SKIP_VM_GUARDRAIL -eq "1"
if (-not $skipCheck -and -not (Test-IsHyperVVM)) {
    Write-Host "SAFETY GUARDRAIL: HOST PROTECTION  -- This script must run inside a Hyper-V VM." -ForegroundColor Red
    Write-Host "Set WINBOT_SKIP_VM_GUARDRAIL=1 to bypass." -ForegroundColor Yellow
    exit 1
}

$logDir = "C:\WinBot\logs"
$null = New-Item -ItemType Directory -Force -Path $logDir
$ts = Get-Date -Format "yyyyMMdd-HHmmss"
$logFile = Join-Path $logDir "enable-rdp-${ts}.log"

function _log { param([string]$msg, [string]$level = "INFO")
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff') [$level] $msg"
    $line | Out-File -Append $logFile -Encoding utf8
    $host.ui.RawUI.ForegroundColor = switch($level) { "OK"{"Green"} "ERR"{"Red"} "WARN"{"Yellow"} "HDR"{"Cyan"} default{"Gray"} }
    Write-Host $line; $host.ui.RawUI.ForegroundColor = "Gray"
}

_log "=== Enable RDP Server ===" "HDR"
_log "Log: $logFile"

# Step 1: Enable RDP in the registry
_log "Step 1: Enabling RDP in registry..." "HDR"
try {
    $current = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
    if ($current.fDenyTSConnections -eq 0) {
        _log "  RDP already enabled (fDenyTSConnections=0)." "OK"
    } else {
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
        _log "  fDenyTSConnections set to 0 (RDP enabled)." "OK"
    }
} catch {
    _log "  Registry update failed: $_" "ERR"
    exit 1
}

# Step 2: Open Windows Firewall for RDP (port 3389)
_log "Step 2: Configuring Windows Firewall..." "HDR"
try {
    $rule = Get-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
    if (-not $rule) {
        _log "  Remote Desktop firewall group not found. Creating custom rule..." "WARN"
        New-NetFirewallRule -DisplayName "RDP (TCP/3389)" `
            -Direction Inbound -Protocol TCP -LocalPort 3389 `
            -Action Allow -Profile Any -ErrorAction Stop | Out-Null
        _log "  Firewall rule created." "OK"
    } else {
        $enabled = $rule | Where-Object { $_.Enabled -eq "True" }
        if ($enabled) {
            _log "  Remote Desktop firewall rules already enabled." "OK"
        } else {
            $rule | Set-NetFirewallRule -Enabled True
            _log "  Remote Desktop firewall rules enabled." "OK"
        }
    }
} catch {
    _log "  Firewall config failed: $_ (non-critical)" "WARN"
}

# Step 3: Ensure RDP service is running
_log "Step 3: Checking RDP service..." "HDR"
try {
    $svc = Get-Service -Name "TermService" -ErrorAction Stop
    if ($svc.Status -eq "Running") {
        _log "  TermService (RDP) is RUNNING." "OK"
    } else {
        Start-Service -Name "TermService" -ErrorAction Stop
        _log "  TermService started." "OK"
    }
    # Ensure auto-start
    Set-Service -Name "TermService" -StartupType Automatic
    _log "  TermService set to Automatic start." "OK"
} catch {
    _log "  Service check failed: $_" "ERR"
}

# Step 4: Verify
_log "Step 4: Verifying..." "HDR"
$port3389 = netstat -an 2>&1 | Select-String ":3389" | Select-Object -First 1
if ($port3389) {
    _log "  Port 3389: LISTENING" "OK"
} else {
    _log "  Port 3389: NOT LISTENING" "WARN"
    _log "  RDP may need a reboot to start listening." "INFO"
}

_log "=== RDP Enablement Complete ===" "HDR"
_log "  Connect from the host:" "INFO"
_log "    mstsc.exe /v:<vm-ip>:3389" "INFO"
_log "  Or use the web dashboard's 'Open RDP' button to download a .rdp file." "INFO"
_log "  The WinBot API also serves a .rdp file at: http://<vm-ip>:8000/vnc/rdpfile" "INFO"

exit 0
