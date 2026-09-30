# Stage: 1.2-autologon — Re-establish AutoLogon for winbot account
# Extracted from stage-provision.ps1 Step 1.2

Write-Host "  Re-establishing AutoLogon..." -ForegroundColor Gray
$pwFile = "C:\WinBot\.vm-password"
$winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$autoLogonOK = $false

if (Test-Path $pwFile) {
    $vmPassword = Get-Content $pwFile -Raw -ErrorAction SilentlyContinue
    if ($vmPassword) {
        $vmPassword = $vmPassword.Trim()
        try {
            Set-ItemProperty -Path $winlogonPath -Name "AutoAdminLogon" -Value "1" -Type String -Force -ErrorAction Stop
            Set-ItemProperty -Path $winlogonPath -Name "DefaultUserName" -Value "winbot" -Type String -Force -ErrorAction Stop
            Set-ItemProperty -Path $winlogonPath -Name "DefaultPassword" -Value $vmPassword -Type String -Force -ErrorAction Stop
            Set-ItemProperty -Path $winlogonPath -Name "AutoLogonCount" -Value "999" -Type String -Force -ErrorAction Stop
            $autoLogonOK = $true
            Write-Host "  AutoLogon re-established for winbot" -ForegroundColor Green
        } catch { Write-Warning "  AutoLogon registry write failed: $_" }
    } else { Write-Warning "  .vm-password file empty" }
} else { Write-Warning "  .vm-password not found - skipping AutoLogon" }

if (-not $autoLogonOK) { Write-Warning "  AutoLogon NOT re-established" }
