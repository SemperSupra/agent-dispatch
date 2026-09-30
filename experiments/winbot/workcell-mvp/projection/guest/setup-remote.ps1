# ╔══════════════════════════════════════════════════════════════╗
# ║  DEPRECATED — use configure-remote.ps1 instead.              ║
# ║  configure-remote.ps1 supports OFFLINE/VM/WinRM/LOCAL modes. ║
# ║  This script is kept for reference.                          ║
# ║  See docs/layer-map.md for the full architecture.            ║
# ╚══════════════════════════════════════════════════════════════╝
#
# WinBot: Configure remote access (DEPRECATED — use configure-remote.ps1)
# Run as Administrator on the VM
# Usage: powershell -ExecutionPolicy Bypass -File setup-remote.ps1

param(
    [string]$WinBotPassword,        # VM password (env var WINBOT_VM_PASSWORD or -WinBotPassword)
    [string]$WinBotUser = "winbot"
)

# Resolve password: env var > parameter > prompt
if (-not $WinBotPassword) { $WinBotPassword = $env:WINBOT_VM_PASSWORD }
if (-not $WinBotPassword) {
    $securePw = Read-Host -AsSecureString -Prompt "Enter password for VM user '$WinBotUser'"
    $WinBotPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePw)
    )
}

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
    Write-Host "    winbotctl.ps1 connect <name>" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  To override (DANGEROUS â€” testing only):" -ForegroundColor Yellow
    Write-Host "    Set WINBOT_SKIP_VM_GUARDRAIL=1 and run again." -ForegroundColor Yellow
    Write-Host "  Run PowerShell as Administrator to use this script." -ForegroundColor Yellow
    Write-Host "========================================`n" -ForegroundColor Red
    exit 1
}
if ($skipCheck) {
    Write-Host "[WinBot] WARNING: VM guardrail overridden via WINBOT_SKIP_VM_GUARDRAIL" -ForegroundColor Yellow
}
# === End Guardrail ===

Write-Host "========================================" -ForegroundColor Magenta
Write-Host "  WinBot â€” Remote Access Setup" -ForegroundColor Magenta
Write-Host "========================================" -ForegroundColor Magenta

# ============================================================
# 1. Create WinBot local admin user
# ============================================================
Write-Host "`n[1/5] Creating WinBot user account..." -ForegroundColor Cyan

try {
    $user = Get-LocalUser -Name $WinBotUser -ErrorAction SilentlyContinue
    if ($user) {
        Write-Host "[WinBot] User '$WinBotUser' already exists, updating password..." -ForegroundColor Yellow
        $user | Set-LocalUser -Password (ConvertTo-SecureString $WinBotPassword -AsPlainText -Force)
    }
} catch {
    Write-Host "[WinBot] Creating new user: $WinBotUser" -ForegroundColor Gray
    New-LocalUser -Name $WinBotUser -Password (ConvertTo-SecureString $WinBotPassword -AsPlainText -Force) `
        -FullName "WinBot Automation" -Description "WinBot automation account" `
        -PasswordNeverExpires -AccountNeverExpires
}

# Ensure user is in Administrators group
$adminGroup = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -like "*$WinBotUser*" }
if (-not $adminGroup) {
    Add-LocalGroupMember -Group "Administrators" -Member $WinBotUser
    Write-Host "[WinBot] Added $WinBotUser to Administrators group" -ForegroundColor Green
}

# Set auto-logon for this user (needed for GUI automation on boot)
Write-Host "[WinBot] Configuring auto-logon for $WinBotUser..." -ForegroundColor Gray
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
Set-ItemProperty -Path $regPath -Name "AutoAdminLogon" -Value "1" -Type String -Force
Set-ItemProperty -Path $regPath -Name "DefaultUserName" -Value $WinBotUser -Type String -Force
Set-ItemProperty -Path $regPath -Name "DefaultPassword" -Value $WinBotPassword -Type String -Force
Set-ItemProperty -Path $regPath -Name "DefaultDomainName" -Value $env:COMPUTERNAME -Type String -Force

# ============================================================
# 2. Enable RDP
# ============================================================
Write-Host "`n[2/5] Enabling Remote Desktop..." -ForegroundColor Cyan

Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" `
    -Name "fDenyTSConnections" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
    -Name "UserAuthentication" -Value 0 -Type DWord -Force

# Add WinBot user to Remote Desktop Users group
$rdpGroup = "Remote Desktop Users"
try {
    $inGroup = Get-LocalGroupMember -Group $rdpGroup -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like "*$WinBotUser*" }
    if (-not $inGroup) {
        Add-LocalGroupMember -Group $rdpGroup -Member $WinBotUser
    }
} catch {
    Write-Host "[WinBot] Warning: Could not add to $rdpGroup ($_)" -ForegroundColor Yellow
}

# Enable RDP firewall rules
Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue

Write-Host "[WinBot] RDP enabled" -ForegroundColor Green

# ============================================================
# 3. Configure WinRM
# ============================================================
Write-Host "`n[3/5] Configuring WinRM..." -ForegroundColor Cyan

# Enable PSRemoting
try {
    Enable-PSRemoting -Force -ErrorAction Stop
} catch {
    Write-Host "[WinBot] WinRM enable via Enable-PSRemoting failed, trying manual setup..." -ForegroundColor Yellow
    winrm quickconfig -force 2>$null
}

# Set WinRM to allow basic auth (needed for cross-machine remoting)
Set-Item -Path "WSMan:\localhost\Service\Auth\Basic" -Value $true -Force -ErrorAction SilentlyContinue
Set-Item -Path "WSMan:\localhost\Service\AllowUnencrypted" -Value $true -Force -ErrorAction SilentlyContinue

# Allow all hosts (for automation convenience -- restrict in production)
Set-Item -Path "WSMan:\localhost\Client\TrustedHosts" -Value "*" -Force

# Enable WinRM firewall rules
Enable-NetFirewallRule -Name "WINRM*" -ErrorAction SilentlyContinue
netsh advfirewall firewall add rule name="WinRM HTTP" dir=in protocol=TCP localport=5985 action=allow 2>$null

# Restart WinRM service
Restart-Service WinRM -Force
Set-Service -Name WinRM -StartupType Automatic

Write-Host "[WinBot] WinRM configured" -ForegroundColor Green

# ============================================================
# 4. Configure Firewall for WinBot API (port 8000)
# ============================================================
Write-Host "`n[4/5] Configuring Firewall for WinBot API..." -ForegroundColor Cyan

# Remove existing rule if present
netsh advfirewall firewall delete rule name="WinBot API" 2>$null

# Add firewall rule for port 8000
netsh advfirewall firewall add rule name="WinBot API" `
    dir=in action=allow protocol=TCP localport=8000 `
    description="WinBot automation API server"

Write-Host "[WinBot] Firewall configured for port 8000" -ForegroundColor Green

# ============================================================
# 5. Disable sleep / screen saver / UAC for automation
# ============================================================
Write-Host "`n[5/5] Configuring power settings for automation..." -ForegroundColor Cyan

# Disable sleep
powercfg -change -standby-timeout-ac 0
powercfg -change -standby-timeout-dc 0
powercfg -change -hibernate-timeout-ac 0
powercfg -change -hibernate-timeout-dc 0
powercfg -change -monitor-timeout-ac 30
powercfg -change -monitor-timeout-dc 30

# Disable screen saver
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveActive" -Value 0 -Force -ErrorAction SilentlyContinue

# Disable UAC (needed for some automation tools to interact with elevated windows)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "EnableLUA" -Value 0 -Type DWord -Force

# Disable Windows Defender real-time monitoring (performance, fewer popups)
Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue

Write-Host "[WinBot] Power settings configured" -ForegroundColor Green

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "  WinBot â€” Remote access configured!" -ForegroundColor Green
Write-Host "  User:   $WinBotUser" -ForegroundColor Green
Write-Host "  RDP:    Enabled (port 3389)" -ForegroundColor Green
Write-Host "  WinRM:  Enabled (port 5985)" -ForegroundColor Green
Write-Host "  API:    Port 8000 allowed" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
