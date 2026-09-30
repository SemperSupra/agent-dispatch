# WinBot Stage Provision Script
# Runs on first Windows logon (via SetupComplete.cmd).
# Installs tools, tunes system for automation + OCR/CV, starts WinBot API.

param([switch]$SkipChoco, [switch]$SkipTools)

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"
$global:stopwatch = [Diagnostics.Stopwatch]::StartNew()

# Event Log helper (deployed to VMs by build-master.ps1)
$notifyPath = "C:\WinBot\notify.ps1"
if (Test-Path $notifyPath) { . $notifyPath }
function _evt { param([string]$m, [int]$id)
if (Get-Command Send-WBInfo -ErrorAction SilentlyContinue) { Send-WBInfo $m $id }
}

# === Logging ===
$logFile = "C:\WinBot\logs\provision.log"
$statusFile = "C:\WinBot\logs\.provision-status.txt"
$traceFile = "C:\WinBot\logs\provision-trace.jsonl"
$logDir = "C:\WinBot\logs"
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }

# Provisioning phase tracing: structured JSON events for historical analysis
$script:phaseStart = @{}
function _trace($phase, $status, $detail = "") {
$now = Get-Date
$elapsed = [math]::Round($global:stopwatch.Elapsed.TotalSeconds, 1)
$startTime = $script:phaseStart[$phase]
$phaseElapsed = if ($startTime) { [math]::Round(($now - $startTime).TotalSeconds, 1) } else { 0 }
if ($status -eq "start") { $script:phaseStart[$phase] = $now }
@{
timestamp = $now.ToUniversalTime().ToString("o")
hostname = $env:COMPUTERNAME
phase = $phase
status = $status
totalElapsed = $elapsed
phaseElapsed = $phaseElapsed
detail = $detail
} | ConvertTo-Json -Compress | Add-Content -Path $traceFile -Encoding utf8
}

function _now { return Get-Date -Format "yyyy-MM-dd HH:mm:ss" }
function _elapsed { return [math]::Round($global:stopwatch.Elapsed.TotalSeconds, 0) }

function _status($msg, $step, $pct) {
$e = _elapsed
$line = (_now) + " [+" + $e + "s] [" + $step + "] " + $msg
Add-Content -Path $logFile -Value $line -Encoding utf8
Write-Host $line
# Auto-trace phase transitions (step changes like "1/8-dirs" -> "1.1-data")
_trace $step "progress" ($e + "s: " + $msg)
}
function _warn($msg, $step) {
$line = (_now) + " [+" + (_elapsed) + "s] [" + $step + "] WARNING: " + $msg
Add-Content -Path $logFile -Value $line -Encoding utf8
Write-Warning $msg
Add-Content -Path $statusFile -Value $line -Encoding utf8
}
function _err($msg, $step) {
$line = (_now) + " [+" + (_elapsed) + "s] [" + $step + "] ERROR: " + $msg
Add-Content -Path $logFile -Value $line -Encoding utf8
Write-Error $msg
Add-Content -Path $statusFile -Value $line -Encoding utf8
}

# === Begin ===
_status "WinBot Provisioning v0.3.0" "START" 0
_evt "Provisioning started on $env:COMPUTERNAME" 2030
_status ("Hostname: " + $env:COMPUTERNAME + ", User: " + $env:UserName) "INFO" 0

if (Test-Path "C:\WinBot\.provisioned") {
_status "Already provisioned. Exiting." "DONE" 100
exit 0
}

# ---- Step 1: Create directories ----
_status "Creating directory structure..." "1/8-dirs" 5
try {
$dirs = @(
"C:\WinBot\api\endpoints","C:\WinBot\sessions\screenshots",
"C:\WinBot\sessions\logs","C:\WinBot\sessions\scripts",
"C:\WinBot\sessions\artifacts","C:\WinBot\tools","C:\WinBot\logs"
)
foreach ($d in $dirs) {
if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}
_status "Directories created" "1/8-dirs" 10
} catch { _err "Directory creation failed: $_" "1/8-dirs" }

# ---- Step 1.1: Detect & mount shared data partition (exFAT, cross-OS) ----
# Looks for a non-system drive with .artifact-store marker.
# Mounts read-only during provisioning, remounted read-write by API startup.
_status "Detecting shared data partition..." "1.1-data" 12
$script:DataDrive = $null
try {
$systemDrive = [System.IO.Path]::GetPathRoot($env:SystemRoot).TrimEnd('\')[0]
Get-Volume -ErrorAction SilentlyContinue | Where-Object {
$_.DriveLetter -and $_.DriveLetter -ne $systemDrive -and $_.DriveType -eq "Fixed"
} | ForEach-Object {
$testPath = "$($_.DriveLetter):\WinBot\.artifact-store"
if (Test-Path $testPath) {
$script:DataDrive = "$($_.DriveLetter):"
_status "Data partition found: $script:DataDrive ($($_.FileSystem))" "1.1-data" 13
}
}
if (-not $script:DataDrive) {
_status "No data partition detected (single-disk deployment)" "1.1-data" 13
}
} catch {
_warn "Data partition detection failed: $_" "1.1-data"
}

# ---- Step 1.2: Re-establish AutoLogon (survives provisioning reboots) ----
try {
$pwFile = "C:\WinBot\.vm-password"
if (Test-Path $pwFile) {
$vmPassword = (Get-Content $pwFile -Raw).Trim()
if ($vmPassword) {
_status "Re-establishing AutoLogon for provisioning..." "1.2-autologon" 11
$wl = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
Set-ItemProperty -Path $wl -Name "AutoAdminLogon" -Value "1" -Type String -Force
Set-ItemProperty -Path $wl -Name "DefaultUserName" -Value "winbot" -Type String -Force
Set-ItemProperty -Path $wl -Name "DefaultPassword" -Value $vmPassword -Type String -Force
Set-ItemProperty -Path $wl -Name "DefaultDomainName" -Value "" -Type String -Force
New-ItemProperty -Path $wl -Name "AutoLogonCount" -Value 999999 -PropertyType DWord -Force | Out-Null
_status "AutoLogon re-established (LogonCount=999999)" "1.2-autologon" 12
} else { _warn ".vm-password file empty" "1.2-autologon" }
} else { _warn ".vm-password not found - AutoLogon not re-established" "1.2-autologon" }
} catch { _warn ("AutoLogon re-establish failed: " + $_) "1.2-autologon" }

# ---- Step 1.5: Activate Windows with product key (if available) ----
try {
$productKeyFile = "C:\WinBot\.product-key"
if (Test-Path $productKeyFile) {
$pk = Get-Content $productKeyFile -Raw
if ($pk -and $pk.Trim() -ne "") {
$pk = $pk.Trim()
_status "Activating Windows with product key..." "1.5-activate" 12
$slmgrResult = cscript //B //Nologo "$env:WINDIR\System32\slmgr.vbs" /ipk $pk 2>&1
Start-Sleep -Seconds 5
cscript //B //Nologo "$env:WINDIR\System32\slmgr.vbs" /ato 2>&1 | Out-Null
_status "Windows activated" "1.5-activate" 13
# Scrub the key file (security)
Remove-Item $productKeyFile -Force -ErrorAction SilentlyContinue
}
}
} catch { _warn ("Product key activation failed: " + $_) "1.5-activate" }

# ---- Step 2: Verify API files ----
_status "Verifying WinBot API files..." "2/8-files" 15
if (-not (Test-Path "C:\WinBot\api\main.py")) {
_warn "API files not found at C:\WinBot\api - scanning provisioning VHD" "2/8-files"
$srcDrive = $null
foreach ($d in @("D:","E:","F:","G:")) {
if (Test-Path ($d + "\api\main.py")) { $srcDrive = $d; break }
}
if ($srcDrive) {
_status ("Copying files from provisioning VHD " + $srcDrive) "2/8-files" 18
Copy-Item ($srcDrive + "\api") "C:\WinBot\api" -Recurse -Force
Copy-Item ($srcDrive + "\tools") "C:\WinBot\tools" -Recurse -Force -ErrorAction SilentlyContinue
Get-ChildItem $srcDrive -Filter "*.ps1" -File | Copy-Item -Destination "C:\WinBot\" -Force
} else { _err "No provisioning VHD found - API files missing" "2/8-files" }
}
if (Test-Path "C:\WinBot\api\main.py") {
$apiSize = (Get-ChildItem "C:\WinBot\api" -Recurse -File | Measure-Object -Property Length -Sum).Sum
_status ("API files present (" + [math]::Round($apiSize/1KB,0) + " KB)") "2/8-files" 20
} else { _err "API files still missing - service install will fail" "2/8-files" }

function Get-WinBotWingetPackageIdsFromConfig {
    <#
    .SYNOPSIS
    Read WinGet package IDs from the authoritative WinGet Configuration file.

    .DESCRIPTION
    Keeps the individual-package fallback subordinate to configuration.winget
    instead of maintaining a second writable package list in this script.
    Only Microsoft.WinGet.DSC/WinGetPackage resource settings are projected.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "WinGet configuration not found: $Path"
    }

    $ids = @()
    $packageResource = $false
    $inSettings = $false

    foreach ($line in Get-Content -LiteralPath $Path -ErrorAction Stop) {
        if ($line -match '^\s*-\s+resource:\s*(\S+)\s*$') {
            $packageResource = ($Matches[1] -eq 'Microsoft.WinGet.DSC/WinGetPackage')
            $inSettings = $false
            continue
        }

        if (-not $packageResource) { continue }

        if ($line -match '^\s+settings:\s*$') {
            $inSettings = $true
            continue
        }

        if ($inSettings -and $line -match '^\s+id:\s*([^#\r\n]+?)\s*$') {
            $id = $Matches[1].Trim().Trim('"').Trim("'")
            if (-not [string]::IsNullOrWhiteSpace($id)) {
                $ids += $id
            }
            $inSettings = $false
        }
    }

    return @($ids | Select-Object -Unique)
}

# ---- Step 3: Ensure WinGet + DSC v3.0 (replaces Chocolatey) ----
_status "Ensuring WinGet package manager + DSC v3.0..." "3/8-winget" 25
$useChocoFallback = $false
if (-not $SkipChoco) {
try {
# WinGet is built into Windows 11 (App Installer package). Verify it's functional.
$wingetCmd = Get-Command winget -ErrorAction SilentlyContinue
if (-not $wingetCmd) {
_warn "WinGet not found -- this is unexpected on Windows 11. Falling back to Chocolatey." "3/8-winget"
$useChocoFallback = $true
} else {
$wingetVer = & winget --version 2>&1
_status ("WinGet version: " + ($wingetVer -join " ")) "3/8-winget" 27

# Install DSC v3.0 (required for winget configure)
_status "Installing DSC v3.0 module..." "3/8-winget" 28
try {
winget install --id Microsoft.DSC --accept-package-agreements --accept-source-agreements 2>&1 | Out-File -Append (Join-Path $logDir "winget-dsc.log") -Encoding utf8
_status "DSC v3.0 installed" "3/8-winget" 29
} catch {
_warn ("DSC install failed: " + $_) "3/8-winget"
_warn "winget configure may be unavailable. Will use individual winget install." "3/8-winget"
}
}
} catch {
_warn ("WinGet setup failed: " + $_) "3/8-winget"
$useChocoFallback = $true
}
}

# ---- Step 3b: Chocolatey fallback (if winget unavailable) ----
if ($useChocoFallback -and -not $SkipChoco) {
_status "Installing Chocolatey package manager (fallback)..." "3b/8-choco" 30
if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
$chocoStart = [Diagnostics.Stopwatch]::StartNew()
try {
Set-ExecutionPolicy Bypass -Scope Process -Force
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11
iex ((New-Object Net.WebClient).DownloadString("https://community.chocolatey.org/install.ps1"))
$env:ChocolateyInstall = ($env:ProgramData + "\chocolatey")
$env:PATH = ($env:ChocolateyInstall + "\bin;" + $env:PATH)
$chocoStart.Stop()
_status ("Chocolatey installed in " + [math]::Round($chocoStart.Elapsed.TotalSeconds,1) + "s") "3b/8-choco" 31
} catch { _warn ("Chocolatey install failed: " + $_) "3b/8-choco" }
} else { _status "Chocolatey already installed" "3b/8-choco" 31 }
}

# ---- Step 4: Install packages (winget configure winget install Chocolatey fallback) ----
_status "Installing packages (WinGet declarative)..." "4/8-pkgs" 35
if (-not $SkipTools) {
# ----- Path A: winget configure (declarative, idempotent) -----
$configFile = "C:\WinBot\tools\configuration.winget"
$useWingetConfigure = $false
if (-not $useChocoFallback -and (Get-Command winget -ErrorAction SilentlyContinue)) {
if (Test-Path $configFile) {
try {
_status "Validating winget configuration..." "4/8-pkgs" 36
$validateOutput = winget configure validate -f $configFile 2>&1
if ($LASTEXITCODE -eq 0) {
_status "Applying winget configuration (this may take several minutes)..." "4/8-pkgs" 37
$cfgLog = Join-Path $logDir "winget-configure.log"
winget configure -f $configFile --accept-configuration-agreements 2>&1 | Out-File -Append $cfgLog -Encoding utf8
if ($LASTEXITCODE -eq 0) {
$useWingetConfigure = $true
_status "All packages installed via winget configure" "4/8-pkgs" 50
} else {
_warn ("winget configure exited with code " + $LASTEXITCODE + ". Check log: " + $cfgLog) "4/8-pkgs"
_status "Falling back to individual winget install..." "4/8-pkgs" 50
}
} else {
_warn ("winget configure validation failed. Falling back to individual installs.") "4/8-pkgs"
}
} catch {
_warn ("winget configure failed: " + $_) "4/8-pkgs"
}
} else {
_warn ("Configuration file not found: " + $configFile) "4/8-pkgs"
}
}

# ----- Path B: Individual winget install (fallback when configure unavailable) -----
# The configuration file remains the package authority. This path changes only
# the execution mechanism when 'winget configure' is unavailable.
if (-not $useWingetConfigure -and -not $useChocoFallback -and (Get-Command winget -ErrorAction SilentlyContinue)) {
try {
$wingetPackageIds = @(Get-WinBotWingetPackageIdsFromConfig -Path $configFile)
} catch {
_warn ("Cannot derive individual WinGet fallback from authoritative configuration: " + $_) "4/8-pkgs"
$wingetPackageIds = @()
}

if ($wingetPackageIds.Count -eq 0) {
_warn "No authoritative WinGet package IDs are available; refusing to invent a fallback package set." "4/8-pkgs"
}

$pkgLog = Join-Path $logDir "winget-install.log"
foreach ($packageId in $wingetPackageIds) {
_status ("Installing " + $packageId + "...") "4/8-pkgs" 52
try {
winget install --id $packageId --accept-package-agreements --accept-source-agreements --silent 2>&1 | Out-File -Append $pkgLog -Encoding utf8
# winget exit codes: 0=success, -1978335189=already installed (0x8D150015), -1978335222=no applicable installer
if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq -1978335189 -or $LASTEXITCODE -eq 1641 -or $LASTEXITCODE -eq 3010) {
_status ($packageId + " installed") "4/8-pkgs" 53
} else {
_warn ($packageId + " winget exit code: " + $LASTEXITCODE) "4/8-pkgs"
}
} catch { _warn ($packageId + " install failed: " + $_) "4/8-pkgs" }
}
}

# ----- Path C: Chocolatey fallback (original behavior) -----
if ($useChocoFallback -and (Get-Command choco -ErrorAction SilentlyContinue)) {
# Python via Chocolatey
try {
$pyStart = [Diagnostics.Stopwatch]::StartNew()
_status "Running: choco install python313..." "4/8-pkgs" 38
choco install python313 -y --no-progress --limit-output 2>&1 | Out-File -Append (Join-Path $logDir "choco-python.log") -Encoding utf8
refreshenv 2>$null
$machinePath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
$userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
$env:PATH = ($machinePath + ";" + $userPath)
$pyExe = Get-Command python -ErrorAction SilentlyContinue
if (-not $pyExe) {
foreach ($ver in @("313", "312")) {
foreach ($c in @("C:\Python$ver\python.exe", "$env:ProgramFiles\Python$ver\python.exe", "C:\Program Files\Python$ver\python.exe", "$env:LOCALAPPDATA\Programs\Python\Python$ver\python.exe")) {
if (Test-Path $c) { $env:PATH = ((Split-Path $c) + ";" + (Join-Path (Split-Path $c) "Scripts") + ";" + $env:PATH); $pyExe = $c; break }
}
if ($pyExe) { break }
}
}
$pyVer = & python --version 2>&1
$pyStart.Stop()
_status ("Python installed: " + $pyVer + " (" + [math]::Round($pyStart.Elapsed.TotalSeconds,1) + "s)") "4/8-pkgs" 45

# Critical tools via Chocolatey (must complete for API service)
_status "Installing NSSM (critical)..." "4/8-pkgs" 60
try {
$nssmLog = Join-Path $logDir "choco-nssm.log"
choco install nssm -y --no-progress --limit-output 2>&1 | Out-File -Append $nssmLog -Encoding utf8
_status "nssm installed" "4/8-pkgs" 62
} catch { _warn ("NSSM install failed: " + $_) "4/8-pkgs" }

# Optional automation tools (non-critical API works without them)
_status "Installing optional tools..." "4/8-pkgs" 64
foreach ($tool in @("autoit", "autohotkey")) {
_status ("Installing $tool (timeout: 60s)...") "4/8-pkgs" 65
try {
$toolLog = Join-Path $logDir ("choco-" + $tool + ".log")
$job = Start-Job -ScriptBlock { param($t, $l)
choco install $t -y --no-progress --limit-output *>&1 | Out-File -Append $l -Encoding utf8
} -ArgumentList $tool, $toolLog
if ($job | Wait-Job -Timeout 60) {
$job | Receive-Job
$job | Remove-Job
_status ("$tool installed") "4/8-pkgs" 66
} else {
$job | Stop-Job | Remove-Job
_warn ("$tool install timed out after 60s (skipping)") "4/8-pkgs"
}
} catch { _warn ("$tool install failed: $_ (skipping)") "4/8-pkgs" }
}
} catch { _warn ("Package install failed: " + $_) "4/8-pkgs" }
}
}

# Refresh PATH after package installs
$env:PATH = [Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" + [Environment]::GetEnvironmentVariable("PATH", "User")

# ---- Step 4b: Install Python pip packages + ffmpeg (recording) ----
_status "Installing pip packages (fastapi, uvicorn, pyautogui...) + ffmpeg" "4b/8-pip" 69
try { choco install ffmpeg -y --no-progress --limit-output 2>&1 | Out-File (Join-Path $logDir "choco-ffmpeg.log") -Encoding utf8 } catch { _warn "ffmpeg install failed (recording will be unavailable)" "4b/8-pip" }
_status "Installing pip packages (fastapi, uvicorn, pyautogui...)" "4b/8-pip" 70
try {
# Locate Python executable (winget installs to different path than Chocolatey)
$pyExe = Get-Command python -ErrorAction SilentlyContinue
if (-not $pyExe) {
$candidates = @(
"C:\Python313\python.exe",
($env:LOCALAPPDATA + "\Programs\Python\Python313\python.exe"),
($env:LOCALAPPDATA + "\Microsoft\WindowsApps\python.exe"),
($env:ProgramFiles + "\Python313\python.exe")
)
foreach ($c in $candidates) {
if (Test-Path $c) {
$env:PATH = ((Split-Path $c) + ";" + (Join-Path (Split-Path $c) "Scripts") + ";" + $env:PATH)
break
}
}
}
$pipLog = Join-Path $logDir "pip-install.log"
python -m pip install --upgrade pip --log $pipLog --quiet 2>&1 | Out-Null
python -m pip install fastapi uvicorn pyautogui pywin32 pillow pynput psutil mss --log $pipLog --quiet 2>&1 | Out-Null
_status "Python packages installed (log: logs/pip-install.log)" "4b/8-pip" 75
} catch { _warn ("pip install failed: " + $_) "4b/8-pip" }

# ---- Step 5: Configure remote access ----
_status "Configuring remote access (RDP, WinRM, firewall)..." "5/8-remote" 70
try {
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 0 -Type DWord -Force
Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
Add-LocalGroupMember -Group "Remote Desktop Users" -Member $env:UserName -ErrorAction SilentlyContinue
Enable-PSRemoting -Force -ErrorAction SilentlyContinue
Set-Item -Path "WSMan:\localhost\Client\TrustedHosts" -Value "*" -Force -ErrorAction SilentlyContinue
Set-Service -Name WinRM -StartupType Automatic
netsh advfirewall firewall delete rule name="WinBot API" 2>$null
netsh advfirewall firewall add rule name="WinBot API" dir=in action=allow protocol=TCP localport=8000 profile=any
# Set network to Private so WinRM + API port work (default is Public = blocked)
try { Get-NetConnectionProfile -ErrorAction SilentlyContinue | Set-NetConnectionProfile -NetworkCategory Private -ErrorAction SilentlyContinue } catch {}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0 -Type DWord -Force
powercfg -change -standby-timeout-ac 0 2>$null
powercfg -change -monitor-timeout-ac 0 2>$null
_status "Remote access configured (UAC off, sleep disabled)" "5/8-remote" 85
} catch { _warn ("Remote access config failed: " + $_) "5/8-remote" }

# ---- Step 6: System tuning (automation + OCR/CV optimized) ----
_status "Tuning Windows for automation + OCR/CV..." "6/8-tuning" 87

# Save original values for reversibility
$originalsFile = "C:\WinBot\.system-originals.json"
$originals = @{}
function _backup($path, $name) {
try { $originals[$name] = @{ Path = $path; Value = (Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue).$name }; $originals[$name].Existed = $true } catch { $originals[$name] = @{ Path = $path; Value = $null; Existed = $false } }
}
_backup "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" "VisualFXSetting"
_backup "HKCU:\Control Panel\Desktop\WindowMetrics" "MinAnimate"
_backup "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" "EnableTransparency"
_backup "HKCU:\Control Panel\Desktop" "FontSmoothing"
_backup "HKCU:\Control Panel\Desktop" "FontSmoothingType"
_backup "HKCU:\Control Panel\Desktop" "LogPixels"
_backup "HKCU:\Control Panel\Desktop" "ScreenSaveActive"
_backup "HKCU:\Control Panel\Desktop" "WallpaperStyle"
_backup "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" "Win32PrioritySeparation"
$originals | ConvertTo-Json -Depth 3 | Out-File -FilePath $originalsFile -Encoding utf8
_status "Original settings backed up to .system-originals.json" "6/8-tuning" 87.5

# 7a: Remove bloatware (Xbox, Skype, Bing, etc.)
$bloat = @(
"Microsoft.BingWeather","Microsoft.BingNews","Microsoft.GetHelp",
"Microsoft.Getstarted","Microsoft.Messaging","Microsoft.Microsoft3DViewer",
"Microsoft.MicrosoftOfficeHub","Microsoft.MicrosoftSolitaireCollection",
"Microsoft.MixedReality.Portal","Microsoft.Office.OneNote",
"Microsoft.People","Microsoft.SkypeApp","Microsoft.Wallet",
"Microsoft.WindowsAlarms","Microsoft.WindowsCamera",
"Microsoft.WindowsFeedbackHub","Microsoft.WindowsMaps","Microsoft.WindowsSoundRecorder",
"Microsoft.Xbox*","Microsoft.YourPhone","Microsoft.Zune*",
"Microsoft.Advertising.Xaml","Microsoft.Teams"
)
foreach ($app in $bloat) {
try { Get-AppxPackage -Name $app -AllUsers -ErrorAction SilentlyContinue | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue } catch {}
}
try { Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -match "Bing|Xbox|Skype|Solitaire|Zune|OfficeHub|GetHelp|People|Wallet|Maps|Camera|Alarms|SoundRecorder|Feedback|3DViewer|MixedReality|OneNote|Teams|Advertising" } | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue } catch {}
_status "Bloatware removed" "6/8-tuning" 88

# 7b: Visual effects OFF (faster screenshots, less GPU)
try {
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Value 2 -Type DWord -Force
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
# Disable window shadows (artifacts in screenshots)
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
SystemPropertiesPerformance.exe /visualeffects 2>$null
_status "Visual effects minimized" "6/8-tuning" 88.5
} catch { _warn "Visual effects tuning failed" "6/8-tuning" }

# 7c: OCR/CV-friendly display settings
_status "Configuring OCR/CV-optimized display..." "6/8-tuning" 89
try {
# High contrast OFF (messes with some OCR engines), but solid backgrounds ON
# ClearType OFF -- anti-aliased text reduces OCR accuracy
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "FontSmoothing" -Value 0 -Type String -Force -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "FontSmoothingType" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
# Standard DPI 100% (96 DPI) -- consistent coordinate mapping
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "LogPixels" -Value 96 -Type DWord -Force -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "Win8DpiScaling" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
# Solid desktop background (no gradients -- cleaner screenshots)
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "WallpaperStyle" -Value 0 -Type String -Force -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\Control Panel\Colors" -Name "Background" -Value "192 192 192" -Type String -Force -ErrorAction SilentlyContinue
# Standard system font (no custom fonts)
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "IconFont" -Value ([byte[]](0xF4,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x90,0x01,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x53,0x00,0x65,0x00,0x67,0x00,0x6F,0x00,0x65,0x00,0x20,0x00,0x55,0x00,0x49,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)) -Type Binary -Force -ErrorAction SilentlyContinue
# Disable screensaver (blank screen blocks automation)
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveActive" -Value 0 -Type String -Force -ErrorAction SilentlyContinue
_status "Display optimized for OCR/CV" "6/8-tuning" 89.5
} catch { _warn "Display tuning failed" "6/8-tuning" }

# 7d: Disable non-essential services (save RAM + CPU)
$svcsToStop = @(
"DiagTrack","dmwappushservice","MapsBroker","lfsvc","PcaSvc",
"WSearch","SysMain","TabletInputService","WerSvc","WMPNetworkSvc",
"XblAuthManager","XblGameSave","XboxNetApiSvc","XboxGipSvc",
"RetailDemo","SensorDataService","SensrSvc",
"PhoneSvc","BthAvctpSvc","FrameServer","icssvc","wlidsvc",
"WpnService","StiSvc","wisvc","FontCache"
)
foreach ($svcName in $svcsToStop) {
try { Set-Service -Name $svcName -StartupType Disabled -ErrorAction SilentlyContinue; Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue } catch {}
}
_status "Non-essential services disabled" "6/8-tuning" 90

# 7e: Processor scheduling -> Background services (better for agent workloads)
try { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Value 24 -Type DWord -Force } catch {}
_status "Processor scheduling tuned" "6/8-tuning" 91

# 7f: Defer Windows Update (prevent unexpected reboots)
try {
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Value 2 -Type DWord -Force -ErrorAction SilentlyContinue
} catch {}
_status "Windows Update deferred (manual only)" "6/8-tuning" 92

# 7g: Disable system restore + error reporting
try { Disable-ComputerRestore -Drive "C:\" -ErrorAction SilentlyContinue } catch {}
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Force -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
_status "System restore + error reporting off" "6/8-tuning" 93

# 7h: Disk cleanup (DISM WinSxS, temp files, event logs)
_status "Running DISM cleanup (~1-2 min)..." "6/8-tuning" 93
try { dism /Online /Cleanup-Image /StartComponentCleanup /ResetBase /Quiet 2>&1 | Out-Null; _status "DISM WinSxS cleanup complete" "6/8-tuning" 94 } catch { _warn "DISM cleanup failed" "6/8-tuning" }
try {
$tempPaths = @("$env:TEMP", "$env:WINDIR\Temp", "C:\Windows\Prefetch")
foreach ($tp in $tempPaths) {
Get-ChildItem $tp -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
}
wevtutil el 2>$null | ForEach-Object { wevtutil cl $_ 2>$null }
_status "Temp files + event logs cleared" "6/8-tuning" 95
} catch { _warn "Temp cleanup failed" "6/8-tuning" }

# 7i: High performance power plan
try { powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 2>$null } catch {}
# Monitor: never turn off (important for headless operation)
powercfg /change -monitor-timeout-ac 0 2>$null
_status "Power: High Performance, monitor never off" "6/8-tuning" 96

# ---- Step 7: Install WinBot API as logon-triggered Scheduled Task ----
# NSSM service runs in Session 0 no desktop access for screenshots.
# Scheduled Task at user logon runs in the user's session (Session 1+),
# giving full desktop access for mss/DXGI screenshot capture.
_status "Installing WinBot API as logon Scheduled Task..." "7/8-task" 97
try {
$pyExe = $null
# Prefer system-wide Python (Chocolatey installs to C:\Python313\)
foreach ($ver in @("313", "312")) {
foreach ($p in @("C:\Python$ver\python.exe", "$env:ProgramFiles\Python$ver\python.exe", "C:\Program Files\Python$ver\python.exe", "$env:LOCALAPPDATA\Programs\Python\Python$ver\python.exe")) {
if (Test-Path $p) { $pyExe = $p; break }
}
if ($pyExe) { break }
}
if (-not $pyExe) { $pyExe = (Get-Command python -ErrorAction SilentlyContinue).Source }
_status ("Python: " + $pyExe) "7/8-task" 97.5

if ($pyExe -and (Test-Path "C:\WinBot\api\main.py")) {
_status "Generating API token..." "7/8-task" 98
$tokenBytes = New-Object byte[] 32
(New-Object Security.Cryptography.RNGCryptoServiceProvider).GetBytes($tokenBytes)
$apiToken = -join ($tokenBytes | ForEach-Object { "{0:x2}" -f $_ })
$apiToken | Out-File -FilePath "C:\WinBot\.api_token" -Encoding ascii -NoNewline
_status ("API token generated (first 8: " + $apiToken.Substring(0,8) + "...)") "7/8-task" 98.5

# Remove any stale NSSM service
Stop-Service -Name "WinBotAPI" -Force -ErrorAction SilentlyContinue
$nssmPath = "C:\ProgramData\chocolatey\bin\nssm.exe"
if (-not (Test-Path $nssmPath)) { $nssmPath = (Get-Command nssm -ErrorAction SilentlyContinue).Source }
if ($nssmPath) { & $nssmPath remove WinBotAPI confirm 2>$null }

# Create Scheduled Task: runs at user logon, survives reboots, restarts on failure
$taskName = "WinBot API Server"
$taskAction = New-ScheduledTaskAction -Execute $pyExe `
-Argument "-m uvicorn main:app --host 0.0.0.0 --port 8000" `
-WorkingDirectory "C:\WinBot\api"
$taskTrigger = New-ScheduledTaskTrigger -AtLogOn
$taskPrincipal = New-ScheduledTaskPrincipal -UserId "winbot" -LogonType Interactive
$taskSettings = New-ScheduledTaskSettingsSet `
-AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
-RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1) `
-ExecutionTimeLimit (New-TimeSpan -Days 365)
$envBlock = @{"WINBOT_API_TOKEN"=$apiToken}

Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName $taskName `
-Action $taskAction -Trigger $taskTrigger `
-Principal $taskPrincipal -Settings $taskSettings `
-Description "WinBot REST API - runs in user session for desktop/screenshot access" `
-Force -ErrorAction Stop | Out-Null

# Start the task immediately (user is already logged in via AutoLogon)
Start-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
Start-Sleep -Seconds 6

# Verify: look for python process listening on port 8000
$listening = $false
for ($retry = 0; $retry -lt 10; $retry++) {
$p = Get-Process python -ErrorAction SilentlyContinue | Where-Object { $_.Id -gt 0 }
if ($p) {
$port = netstat -an 2>&1 | Select-String ":8000.*LISTENING"
if ($port) { $listening = $true; break }
}
Start-Sleep -Seconds 2
}

if ($listening) {
_status "WINBOT API TASK: RUNNING (port 8000 listening)" "7/8-task" 100
_evt "WinBot API started (logon task) on $env:COMPUTERNAME" 2031
} else {
_warn "API task started but not yet listening on port 8000" "7/8-task"
}
} else {
_err ("Cannot install API task: Python=" + $pyExe + " API=" + (Test-Path "C:\WinBot\api\main.py").ToString()) "7/8-task"
}
} catch { _err ("API service install crashed: " + $_) "7/8-service" }

# ---- Step 8: Node Enrollment (physical machines register with host) ----
_status "Registering node with WinBot host..." "8/8-enroll" 100
try {
$nodesDir = "C:\WinBot\nodes"
if (-not (Test-Path $nodesDir)) { New-Item -ItemType Directory -Path $nodesDir -Force | Out-Null }

# Get the host address from environment or DHCP option
$hostAddress = $env:WINBOT_HOST_IP
if (-not $hostAddress) {
# Try to auto-detect: if we're on an Internal switch, host is the gateway
$hostAddress = (Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | Select-Object -First 1).NextHop
}
if (-not $hostAddress) {
_warn "No host address configured -- skipping enrollment" "8/8-enroll"
$hostAddress = "unknown"
}

# Read the API token
$apiToken = ""
if (Test-Path "C:\WinBot\.api_token") {
$apiToken = (Get-Content "C:\WinBot\.api_token" -Raw).Trim()
}

if ($hostAddress -and $hostAddress -ne "unknown" -and $apiToken) {
_status ("Enrolling with host at " + $hostAddress) "8/8-enroll" 100

# Detect capabilities
$caps = @{}
try { if (Get-Command python -ErrorAction SilentlyContinue) { $caps["run_python"] = $true } } catch { $caps["run_python"] = $false }
try { if (Get-Command AutoHotkey.exe -ErrorAction SilentlyContinue) { $caps["run_ahk"] = $true } } catch { $caps["run_ahk"] = $false }
try { if (Get-Command AutoIt3.exe -ErrorAction SilentlyContinue) { $caps["run_autoit"] = $true } } catch { $caps["run_autoit"] = $false }
$caps["input_automation"] = $true

# Determine reset method
$resetMethod = "Reboot"
try {
$uwfCheck = uwfmgr get-config 2>&1 | Out-String
if ($uwfCheck -match "Filter enabled: Yes") { $resetMethod = "UWF" }
} catch {}

# Detect IP address
$myIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" } | Select-Object -First 1).IPAddress
if (-not $myIP) { $myIP = "unknown" }

# POST enrollment to host (via WinBot API on localhost because the host MCP calls PS)
# We write a node file locally which the host's NodePool will pick up
$nodeRecord = @{
hostname = $env:COMPUTERNAME
ip = $myIP
api_port = 8000
node_type = "Physical"
reset_method = $resetMethod
labels = @()
capabilities = $caps
api_online = $true
registered_at = (Get-Date).ToUniversalTime().ToString("o")
last_seen_at = (Get-Date).ToUniversalTime().ToString("o")
}
$nodeRecord | ConvertTo-Json -Depth 5 | Out-File -FilePath "C:\WinBot\nodes\$env:COMPUTERNAME.json" -Encoding utf8

# Also POST to the host's enrollment endpoint if reachable
try {
$body = @{
hostname = $env:COMPUTERNAME
ip = $myIP
node_type = "Physical"
reset_method = $resetMethod
capabilities = $caps
labels = @()
} | ConvertTo-Json

# Try the host's MCP API (typically port 8000 on host too, or via WinRM)
$enrollUrl = "http://${hostAddress}:8000/nodes/register"
Invoke-RestMethod -Uri $enrollUrl -Method Post -Body $body `
-ContentType "application/json" -Headers @{"X-API-Key" = $apiToken} `
-TimeoutSec 10 -ErrorAction SilentlyContinue | Out-Null
_status "Node enrolled with host at $hostAddress" "8/8-enroll" 100
} catch {
_warn ("Host enrollment POST failed: " + $_.Exception.Message) "8/8-enroll"
_status "Node record saved locally -- host can import manually" "8/8-enroll" 100
}
} else {
_warn "Skipping enrollment (no host address or API token)" "8/8-enroll"
}
} catch {
_warn ("Node enrollment failed: " + $_) "8/8-enroll"
}

# ---- Step 9: Security Cleanup ----
_status "Scrubbing credential artifacts..." "9/9-cleanup" 100
try {
# Remove password file (no longer needed -- AutoLogon keys are in registry)
$pwFile = "C:\WinBot\.vm-password"
if (Test-Path $pwFile) {
# Overwrite with random data before deletion (defense against forensic recovery)
$rand = New-Object byte[] 256
(New-Object Security.Cryptography.RNGCryptoServiceProvider).GetBytes($rand)
[IO.File]::WriteAllBytes($pwFile, $rand)
Remove-Item $pwFile -Force
_status "Password file securely scrubbed" "9/9-cleanup" 100
} else { _status "No password file to scrub" "9/9-cleanup" 100 }

# Product key file (if not already removed by step 1.5)
$pkFile = "C:\WinBot\.product-key"
if (Test-Path $pkFile) {
$rand = New-Object byte[] 128
(New-Object Security.Cryptography.RNGCryptoServiceProvider).GetBytes($rand)
[IO.File]::WriteAllBytes($pkFile, $rand)
Remove-Item $pkFile -Force
}
} catch { _warn ("Security cleanup failed: " + $_) "9/9-cleanup" }

# === Done ===
$global:stopwatch.Stop()
$duration = [math]::Round($global:stopwatch.Elapsed.TotalSeconds, 0)
$marker = @{
timestamp = (Get-Date).ToUniversalTime().ToString("o")
duration_seconds = $global:stopwatch.Elapsed.TotalSeconds
version = "0.3.0"
} | ConvertTo-Json -Compress
$marker | Out-File -FilePath "C:\WinBot\.provisioned" -Encoding utf8

# Post-provisioning: retry firewall + network (may fail in step 5 if NIC not ready)
_status "Post-provision: ensuring firewall + network..." "DONE" 99
for ($i = 0; $i -lt 5; $i++) {
netsh advfirewall firewall add rule name="WinBot API" dir=in action=allow protocol=TCP localport=8000 profile=any 2>$null | Out-Null
try { Get-NetConnectionProfile -ErrorAction SilentlyContinue | Set-NetConnectionProfile -NetworkCategory Private -ErrorAction SilentlyContinue; break } catch { Start-Sleep 5 }
}
$ruleOk = (netsh advfirewall firewall show rule name="WinBot API" 2>&1 | Select-String "Enabled.*Yes")
$netOk = ((Get-NetConnectionProfile -ErrorAction SilentlyContinue).NetworkCategory -eq "Private")
if ($ruleOk -and $netOk) {
_status "Firewall + network confirmed (Private)" "DONE" 100
} else {
_warn "Network fix incomplete. Run: .\winbot-run.ps1 -Operation fix-network" "DONE"
}

_trace "complete" "complete" "Provisioning complete in $duration seconds"
_status ("=== WINBOT PROVISIONING COMPLETE (" + $duration + "s) ===") "DONE" 100
_evt "Provisioning complete on $env:COMPUTERNAME (${duration}s)" 2032
