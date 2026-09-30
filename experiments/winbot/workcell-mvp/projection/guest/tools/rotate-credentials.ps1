# WinBot Guest-Side Credential Rotation
# Runs inside a live clone via PowerShell Direct (Invoke-Command -VMName).
# Updates the local user account password, AutoLogon registry keys, and .vm-password file.
#
# Called by: Sync-WinBotCredentialToClones (host/WinBot.psm1)
#
# Usage (inside VM):
#   .\rotate-credentials.ps1 -Username "winbot" -Password "newpass"
#   .\rotate-credentials.ps1 -Username "botuser" -Password "newpass" -OldUsername "winbot" -UsernameChange

param(
    [Parameter(Mandatory=$true)]
    [string]$Username,

    [Parameter(Mandatory=$true)]
    [string]$Password,

    [string]$OldUsername = "",

    [switch]$UsernameChange
)

$ErrorActionPreference = "Continue"
$results = @{
    Success = $false
    UsernameChanged = $UsernameChange.IsPresent
    OldUsername = $OldUsername
    NewUsername = $Username
    LocalUserUpdated = $false
    AutoLogonUpdated = $false
    PasswordFileUpdated = $false
    Warnings = @()
}

function _warn($msg) {
    Write-Warning $msg
    $results.Warnings += $msg
}

# ---- 1: Handle username change ----
if ($UsernameChange -and $OldUsername -and $OldUsername -ne $Username) {
    try {
        $existing = Get-LocalUser -Name $Username -ErrorAction SilentlyContinue
        if (-not $existing) {
            Write-Host "  Creating new local user: $Username"
            $securePw = ConvertTo-SecureString $Password -AsPlainText -Force
            New-LocalUser -Name $Username -Password $securePw -FullName "WinBot Automation" `
                -Description "WinBot automation account" -PasswordNeverExpires -ErrorAction Stop
            Add-LocalGroupMember -Group "Administrators" -Member $Username -ErrorAction SilentlyContinue
            $results.LocalUserUpdated = $true
            Write-Host "  User '$Username' created and added to Administrators." -ForegroundColor Green
        } else {
            Write-Host "  User '$Username' already exists -- updating password."
            $securePw = ConvertTo-SecureString $Password -AsPlainText -Force
            Set-LocalUser -Name $Username -Password $securePw -ErrorAction Stop
            $results.LocalUserUpdated = $true
            Write-Host "  User '$Username' password updated." -ForegroundColor Green
        }
        # Note: Old user account is left intact for safety. Operator can remove manually.
        if ($OldUsername -and (Get-LocalUser -Name $OldUsername -ErrorAction SilentlyContinue)) {
            Write-Host "  Old user '$OldUsername' left intact -- remove manually if desired." -ForegroundColor Yellow
        }
    } catch {
        _warn "Username change failed: $_"
        $results.Success = $false
        return $results
    }
} else {
    # Password-only rotation on existing user
    try {
        $user = Get-LocalUser -Name $Username -ErrorAction SilentlyContinue
        if (-not $user) {
            _warn "User '$Username' does not exist on this VM. Use -UsernameChange to create."
            $results.Success = $false
            return $results
        }
        $securePw = ConvertTo-SecureString $Password -AsPlainText -Force
        Set-LocalUser -Name $Username -Password $securePw -ErrorAction Stop
        $results.LocalUserUpdated = $true
        Write-Host "  User '$Username' password updated." -ForegroundColor Green
    } catch {
        _warn "Password update for '$Username' failed: $_"
        $results.Success = $false
        return $results
    }
}

# ---- 2: Update AutoLogon registry keys ----
try {
    $wl = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    Set-ItemProperty -Path $wl -Name "AutoAdminLogon" -Value "1" -Type String -Force
    Set-ItemProperty -Path $wl -Name "DefaultUserName" -Value $Username -Type String -Force
    Set-ItemProperty -Path $wl -Name "DefaultPassword" -Value $Password -Type String -Force
    Set-ItemProperty -Path $wl -Name "DefaultDomainName" -Value "" -Type String -Force
    New-ItemProperty -Path $wl -Name "AutoLogonCount" -Value 999999 -PropertyType DWord -Force | Out-Null
    $results.AutoLogonUpdated = $true
    Write-Host "  AutoLogon registry keys updated for user '$Username'." -ForegroundColor Green
} catch {
    _warn "AutoLogon registry update failed: $_"
}

# ---- 3: Update .vm-password file (secure overwrite) ----
try {
    $pwFile = "C:\WinBot\.vm-password"
    $pwDir = Split-Path $pwFile -Parent
    if (-not (Test-Path $pwDir)) {
        New-Item -ItemType Directory -Path $pwDir -Force | Out-Null
    }
    # Overwrite existing file with random data first (defense against forensic recovery)
    if (Test-Path $pwFile) {
        $rand = New-Object byte[] 256
        (New-Object Security.Cryptography.RNGCryptoServiceProvider).GetBytes($rand)
        [IO.File]::WriteAllBytes($pwFile, $rand)
    }
    # Write new password
    $Password | Out-File -FilePath $pwFile -Encoding ascii -NoNewline -Force
    $results.PasswordFileUpdated = $true
    Write-Host "  .vm-password file updated." -ForegroundColor Green
} catch {
    _warn ".vm-password file update failed: $_"
}

# ---- Done ----
$results.Success = $true
Write-Host "  Credential rotation complete on $env:COMPUTERNAME." -ForegroundColor Green
return $results
