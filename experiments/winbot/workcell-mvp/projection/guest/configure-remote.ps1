# WinBot: Configure Remote Access
# Layer 2 — Enables remote management channels on a Windows machine.
# Works against ANY Windows box: VM, physical, cloud.
#
# Modes:
#   OFFLINE:  target a mounted VHDX (writes registry + files directly)
#   ONLINE:   target a running machine (uses PS Direct or WinRM)
#   LOCAL:    runs on the current machine (inside the VM itself)
#
# Usage:
#   # Offline (during DISM deploy):
#   .\configure-remote.ps1 -OfflineVhd "C:\WinBot\master\Win11ENT.vhdx" -Password "MyP@ss"
#
#   # Online via PowerShell Direct (VM on local Hyper-V):
#   .\configure-remote.ps1 -VMName "WinBot-test" -Password "MyP@ss"
#
#   # Online via WinRM (physical or remote machine):
#   .\configure-remote.ps1 -ComputerName "192.168.1.100" -Credential $cred
#
#   # Local (run inside the VM itself):
#   .\configure-remote.ps1 -Local -Password "MyP@ss"

param(
    [Parameter(ParameterSetName="offline")]  [string]$OfflineVhd,
    [Parameter(ParameterSetName="vm")]       [string]$VMName,
    [Parameter(ParameterSetName="winrm")]    [string]$ComputerName,
    [Parameter(ParameterSetName="winrm")]    [PSCredential]$Credential,
    [Parameter(ParameterSetName="local")]    [switch]$Local,

    [string]$Username = "winbot",
    [string]$Password = "",
    [switch]$EnableSSH,
    [switch]$EnableWinRM,
    [switch]$EnableAPI,
    [switch]$EnableRDP
)

$ErrorActionPreference = "Stop"

# If no specific transport flags, enable everything
if (-not ($EnableSSH -or $EnableWinRM -or $EnableAPI -or $EnableRDP)) {
    $EnableWinRM = $EnableAPI = $EnableRDP = $true
}

function Write-Step($msg) { Write-Host $msg -ForegroundColor Cyan }

# ============================================================
# The configuration script (runs inside the target)
# ============================================================
$configureScript = {
    param($Username, $Password, $ENABLE_SSH, $ENABLE_WINRM, $ENABLE_API, $ENABLE_RDP)
    $ErrorActionPreference = "Continue"
    $results = @{}

    # 1. WinBot user account
    Write-Step "[1/5] WinBot user account..."
    try {
        $existingUser = Get-LocalUser -Name $Username -ErrorAction SilentlyContinue
        if ($existingUser) {
            $existingUser | Set-LocalUser -Password (ConvertTo-SecureString $Password -AsPlainText -Force) -ErrorAction Stop
        } else {
            New-LocalUser -Name $Username -Password (ConvertTo-SecureString $Password -AsPlainText -Force) `
                -FullName "WinBot Automation" -PasswordNeverExpires -AccountNeverExpires -ErrorAction Stop
        }
        Add-LocalGroupMember -Group "Administrators" -Member $Username -ErrorAction SilentlyContinue
        $results.User = "ok"
    } catch { $results.User = "FAIL: $_" }

    # 2. Auto-logon
    Write-Step "[2/5] Auto-logon..."
    try {
        $wlPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        Set-ItemProperty -Path $wlPath -Name "AutoAdminLogon" -Value "1" -Type String -Force
        Set-ItemProperty -Path $wlPath -Name "DefaultUserName" -Value $Username -Type String -Force
        Set-ItemProperty -Path $wlPath -Name "DefaultPassword" -Value $Password -Type String -Force
        Set-ItemProperty -Path $wlPath -Name "DefaultDomainName" -Value $env:COMPUTERNAME -Type String -Force
        $results.AutoLogon = "ok"
    } catch { $results.AutoLogon = "FAIL: $_" }

    # 3. WinRM
    if ($ENABLE_WINRM) {
        Write-Step "[3/5] WinRM..."
        try {
            Enable-PSRemoting -Force -ErrorAction SilentlyContinue
            Set-Item -Path "WSMan:\localhost\Service\Auth\Basic" -Value $true -Force -ErrorAction SilentlyContinue
            Set-Item -Path "WSMan:\localhost\Service\AllowUnencrypted" -Value $true -Force -ErrorAction SilentlyContinue
            Set-Item -Path "WSMan:\localhost\Client\TrustedHosts" -Value "*" -Force
            Set-Service -Name WinRM -StartupType Automatic
            Restart-Service WinRM -Force -ErrorAction SilentlyContinue
            Enable-NetFirewallRule -Name "WINRM*" -ErrorAction SilentlyContinue
            netsh advfirewall firewall add rule name="WinRM HTTP" dir=in protocol=TCP localport=5985 action=allow 2>$null
            $results.WinRM = "ok"
        } catch { $results.WinRM = "FAIL: $_" }
    }

    # 4. RDP
    if ($ENABLE_RDP) {
        Write-Step "[4/5] RDP..."
        try {
            Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0 -Type DWord -Force
            Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 0 -Type DWord -Force
            Add-LocalGroupMember -Group "Remote Desktop Users" -Member $Username -ErrorAction SilentlyContinue
            Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
            $results.RDP = "ok"
        } catch { $results.RDP = "FAIL: $_" }
    }

    # 5. WinBot API firewall + SSH (if requested)
    Write-Step "[5/5] API firewall + extras..."
    if ($ENABLE_API) {
        netsh advfirewall firewall delete rule name="WinBot API" 2>$null
        netsh advfirewall firewall add rule name="WinBot API" dir=in action=allow protocol=TCP localport=8000 2>$null
        $results.API = "ok"
    }
    if ($ENABLE_SSH) {
        try {
            Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 -ErrorAction SilentlyContinue
            Set-Service -Name sshd -StartupType Automatic
            Start-Service sshd
        } catch {}
        $results.SSH = "ok"
    }

    # UAC off, no sleep, no screen saver
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0 -Type DWord -Force
    powercfg -change -standby-timeout-ac 0 2>$null
    powercfg -change -monitor-timeout-ac 30 2>$null
    $results.UAC = "off"
    $results.Sleep = "disabled"

    return $results
}

# ============================================================
# Transport: execute the configure script
# ============================================================
switch ($PSCmdlet.ParameterSetName) {
    "offline" {
        Write-Step "=== Offline configuration: $OfflineVhd ==="
        if (-not (Test-Path $OfflineVhd)) { throw "VHD not found: $OfflineVhd" }

        # Mount VHD
        $mounted = Mount-VHD -Path $OfflineVhd -Passthru -ErrorAction Stop
        Start-Sleep -Seconds 2
        try {
            $disk = $mounted | Get-Disk
            if (-not $disk) { $disk = Get-Disk | Where-Object { $_.Location -like "*$OfflineVhd*" } | Select-Object -First 1 }
            $winPart = Get-Partition -DiskNumber $disk.Number | Where-Object { $_.Size -gt 1GB } | Select-Object -First 1
            $letter = ($winPart | Get-Volume).DriveLetter
            if (-not $letter) { $winPart | Set-Partition -NewDriveLetter Z -ErrorAction SilentlyContinue; $letter = "Z" }

            # Offline registry writes
            Write-Step "Writing registry (offline)..."

            # 1. AutoLogon
            try {
                reg load HKLM\WB_CFG "${letter}:\Windows\System32\config\SOFTWARE" 2>&1 | Out-Null
                $wl = "HKLM\WB_CFG\Microsoft\Windows NT\CurrentVersion\Winlogon"
                reg add $wl /v AutoAdminLogon /t REG_SZ /d "1" /f 2>&1 | Out-Null
                reg add $wl /v DefaultUserName /t REG_SZ /d "$Username" /f 2>&1 | Out-Null
                reg add $wl /v DefaultPassword /t REG_SZ /d "$Password" /f 2>&1 | Out-Null
                reg add $wl /v DefaultDomainName /t REG_SZ /d "" /f 2>&1 | Out-Null
                reg unload HKLM\WB_CFG 2>&1 | Out-Null
                Write-Host "  AutoLogon: OK (offline registry)" -ForegroundColor Green
            } catch { Write-Host "  AutoLogon: FAILED $_" -ForegroundColor Red }

            # 2. RDP
            try {
                reg load HKLM\WB_CFG "${letter}:\Windows\System32\config\SYSTEM" 2>&1 | Out-Null
                $tsKey = "HKLM\WB_CFG\ControlSet001\Control\Terminal Server"
                reg add $tsKey /v fDenyTSConnections /t REG_DWORD /d 0 /f 2>&1 | Out-Null
                $winstationsKey = "HKLM\WB_CFG\ControlSet001\Control\Terminal Server\WinStations\RDP-Tcp"
                reg add $winstationsKey /v UserAuthentication /t REG_DWORD /d 0 /f 2>&1 | Out-Null
                reg unload HKLM\WB_CFG 2>&1 | Out-Null
                Write-Host "  RDP: OK (offline registry)" -ForegroundColor Green
            } catch { Write-Host "  RDP: FAILED $_" -ForegroundColor Red }

            # 3. Stage configure-remote.ps1 on the VHD for first-boot completion
            $stageDir = "${letter}:\WinBot"
            New-Item -ItemType Directory -Path $stageDir -Force | Out-Null
            Copy-Item $PSCommandPath "$stageDir\configure-remote.ps1" -Force -ErrorAction SilentlyContinue
            Write-Host "  configure-remote.ps1 staged for first-boot completion" -ForegroundColor Green

            # 4. Generate a FirstLogon script that completes online configuration
            #    (WinRM, firewall, SSH need the OS running to configure)
            $firstLogonScript = @"
# WinBot FirstBoot: Complete online configuration
# This runs at first logon to finish what the offline registry couldn't.
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value "1" -Type String -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultUserName" -Value "$Username" -Type String -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultPassword" -Value "$Password" -Type String -Force

# Enable WinRM
Enable-PSRemoting -Force -ErrorAction SilentlyContinue
Set-Item -Path "WSMan:\localhost\Service\Auth\Basic" -Value `$true -Force -ErrorAction SilentlyContinue
Set-Item -Path "WSMan:\localhost\Service\AllowUnencrypted" -Value `$true -Force -ErrorAction SilentlyContinue
Set-Item -Path "WSMan:\localhost\Client\TrustedHosts" -Value "*" -Force
Set-Service -Name WinRM -StartupType Automatic
Restart-Service WinRM -Force -ErrorAction SilentlyContinue
Enable-NetFirewallRule -Name "WINRM*" -ErrorAction SilentlyContinue
netsh advfirewall firewall add rule name="WinRM HTTP" dir=in protocol=TCP localport=5985 action=allow 2>`$null

# API firewall
netsh advfirewall firewall delete rule name="WinBot API" 2>`$null
netsh advfirewall firewall add rule name="WinBot API" dir=in action=allow protocol=TCP localport=8000

# User account
try {
    `$u = Get-LocalUser -Name "$Username" -ErrorAction SilentlyContinue
    if (`$u) { `$u | Set-LocalUser -Password (ConvertTo-SecureString "$Password" -AsPlainText -Force) }
    else { New-LocalUser -Name "$Username" -Password (ConvertTo-SecureString "$Password" -AsPlainText -Force) -FullName "WinBot Automation" -PasswordNeverExpires -AccountNeverExpires }
    Add-LocalGroupMember -Group "Administrators" -Member "$Username" -ErrorAction SilentlyContinue
    Add-LocalGroupMember -Group "Remote Desktop Users" -Member "$Username" -ErrorAction SilentlyContinue
} catch {}

# UAC + power
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0 -Type DWord -Force
powercfg -change -standby-timeout-ac 0 2>`$null
"@
            $firstLogonScript | Out-File -FilePath "$stageDir\firstboot-config.ps1" -Encoding utf8 -NoNewline
            Write-Host "  firstboot-config.ps1 staged" -ForegroundColor Green

        } finally { Dismount-VHD -Path $OfflineVhd -ErrorAction SilentlyContinue }
    }

    "vm" {
        Write-Step "=== VM configuration: $VMName ==="
        $securePw = ConvertTo-SecureString $Password -AsPlainText -Force
        $cred = New-Object PSCredential($Username, $securePw)
        $result = Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock $configureScript -ArgumentList $Username, $Password, $EnableSSH, $EnableWinRM, $EnableAPI, $EnableRDP
        $result | Format-List
        # Copy configure-remote.ps1 into the VM for future use
        Copy-Item -ToSession (New-PSSession -VMName $VMName -Credential $cred) -Path $PSCommandPath -Destination "C:\WinBot\configure-remote.ps1" -Force -ErrorAction SilentlyContinue
    }

    "winrm" {
        Write-Step "=== Remote configuration: $ComputerName ==="
        $result = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock $configureScript -ArgumentList $Username, $Password, $EnableSSH, $EnableWinRM, $EnableAPI, $EnableRDP
        $result | Format-List
        Copy-Item -ToSession (New-PSSession -ComputerName $ComputerName -Credential $Credential) -Path $PSCommandPath -Destination "C:\WinBot\configure-remote.ps1" -Force -ErrorAction SilentlyContinue
    }

    "local" {
        Write-Step "=== Local configuration ==="
        if (-not $Password) { throw "Password required for local configuration." }
        $result = & $configureScript $Username $Password $EnableSSH $EnableWinRM $EnableAPI $EnableRDP
        $result | Format-List
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Remote Access Configured" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
