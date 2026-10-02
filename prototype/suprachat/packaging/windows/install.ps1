param(
  [switch]$NoLaunch,
  [switch]$DesktopShortcut
)

$ErrorActionPreference = 'Stop'

$Source = Split-Path -Parent $MyInvocation.MyCommand.Path
$InstallRoot = Join-Path $env:LOCALAPPDATA 'Programs\SupraChat'
$StartMenu = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs'
$Shortcut = Join-Path $StartMenu 'SupraChat.lnk'
$Desktop = [Environment]::GetFolderPath('Desktop')
$DesktopLink = Join-Path $Desktop 'SupraChat.lnk'
$UninstallKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\SupraChat'
$ProtocolKey = 'HKCU:\Software\Classes\suprachat'
$ApplicationKey = 'HKCU:\Software\Classes\Applications\SupraChat.exe'
$UserEnvironmentKey = 'HKCU:\Environment'

$ObservabilityRoot = Join-Path $env:LOCALAPPDATA 'SemperSupra\SupraChat\diagnostics'
$InstallerEventLog = Join-Path $ObservabilityRoot 'installer-events.jsonl'
$InstallReceiptPath = Join-Path $ObservabilityRoot 'install-receipt.json'
$InstallSessionId = [Guid]::NewGuid().ToString('N')
$TraceId = [Guid]::NewGuid().ToString('N')
$InstallerStarted = [System.Diagnostics.Stopwatch]::StartNew()
$InstallerSequence = 0

function Get-UtcIsoTimestamp {
  [DateTime]::UtcNow.ToString('O', [Globalization.CultureInfo]::InvariantCulture)
}

function New-SpanId {
  [Guid]::NewGuid().ToString('N').Substring(0,16)
}

function Write-InstallerEvent {
  param(
    [Parameter(Mandatory=$true)][string]$Event,
    [Parameter(Mandatory=$true)][string]$Outcome,
    [string]$CorrelationId = $null,
    [hashtable]$Fields = $null,
    [Nullable[long]]$DurationMs = $null
  )
  try {
    New-Item -ItemType Directory -Force -Path $ObservabilityRoot | Out-Null
    $script:InstallerSequence++
    $record = [ordered]@{
      schema = 'suprachat-installer-event/v2'
      timestamp_utc = Get-UtcIsoTimestamp
      install_session_id = $InstallSessionId
      sequence = $script:InstallerSequence
      component = 'windows-installer'
      event = $Event
      outcome = $Outcome
      correlation_id = $CorrelationId
      trace_id = $TraceId
      span_id = New-SpanId
      parent_span_id = $null
      duration_ms = $DurationMs
      process_elapsed_ms = [long]$InstallerStarted.Elapsed.TotalMilliseconds
      fields = $Fields
    }
    ($record | ConvertTo-Json -Depth 6 -Compress) |
      Add-Content -LiteralPath $InstallerEventLog -Encoding UTF8
  } catch {
    # Diagnostics must never make installation fail.
  }
}

Write-InstallerEvent -Event 'install-start' -Outcome 'start' -Fields @{
  no_launch = [bool]$NoLaunch
  desktop_shortcut = [bool]$DesktopShortcut
  source_has_app = (Test-Path (Join-Path $Source 'SupraChat.exe'))
  source_has_automation = (Test-Path (Join-Path $Source 'SupraChat.Automation.exe'))
  source_has_codex = (Test-Path (Join-Path $Source 'runtime\codex\codex.exe'))
}

if (!(Test-Path (Join-Path $Source 'SupraChat.exe'))) {
  Write-InstallerEvent -Event 'source-validation' -Outcome 'failure' -Fields @{ reason = 'SupraChat.exe missing' }
  throw 'Run install.ps1 from the extracted SupraChat Windows artifact.'
}
Write-InstallerEvent -Event 'source-validation' -Outcome 'success'

New-Item -ItemType Directory -Force -Path $InstallRoot | Out-Null

$copyStarted = [System.Diagnostics.Stopwatch]::StartNew()
Get-ChildItem -Force $Source | Where-Object {
  $_.Name -notin @('install.ps1')
} | ForEach-Object {
  Copy-Item $_.FullName $InstallRoot -Recurse -Force
}
$copyStarted.Stop()
Write-InstallerEvent -Event 'payload-copy' -Outcome 'success' -DurationMs ([long]$copyStarted.Elapsed.TotalMilliseconds) -Fields @{
  installed_app = (Test-Path (Join-Path $InstallRoot 'SupraChat.exe'))
  installed_automation = (Test-Path (Join-Path $InstallRoot 'SupraChat.Automation.exe'))
  installed_codex = (Test-Path (Join-Path $InstallRoot 'runtime\codex\codex.exe'))
}

$UninstallScript = @'
$ErrorActionPreference = "Stop"
$InstallRoot = Join-Path $env:LOCALAPPDATA "Programs\SupraChat"
$StartMenuLink = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\SupraChat.lnk"
$DesktopLink = Join-Path ([Environment]::GetFolderPath("Desktop")) "SupraChat.lnk"
Remove-Item $StartMenuLink -Force -ErrorAction SilentlyContinue
Remove-Item $DesktopLink -Force -ErrorAction SilentlyContinue
Remove-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\SupraChat" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "HKCU:\Software\Classes\suprachat" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "HKCU:\Software\Classes\Applications\SupraChat.exe" -Recurse -Force -ErrorAction SilentlyContinue
$currentUserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($currentUserPath) {
  $target = $InstallRoot.TrimEnd("\")
  $filtered = @($currentUserPath.Split(";") | Where-Object {
    $_ -and $_.Trim().TrimEnd("\") -ne $target
  })
  [Environment]::SetEnvironmentVariable("Path", ($filtered -join ";"), "User")
}
Start-Process powershell.exe -WindowStyle Hidden -ArgumentList @(
  "-NoProfile","-Command",
  "Start-Sleep -Milliseconds 500; Remove-Item -LiteralPath '$InstallRoot' -Recurse -Force -ErrorAction SilentlyContinue"
)
'@
$UninstallPath = Join-Path $InstallRoot 'uninstall.ps1'
Set-Content -LiteralPath $UninstallPath -Value $UninstallScript -Encoding UTF8

$WshShell = New-Object -ComObject WScript.Shell
$lnk = $WshShell.CreateShortcut($Shortcut)
$lnk.TargetPath = Join-Path $InstallRoot 'SupraChat.exe'
$lnk.WorkingDirectory = $InstallRoot
$lnk.Description = 'SupraChat'
$lnk.Save()

if ($DesktopShortcut) {
  $desktopLnk = $WshShell.CreateShortcut($DesktopLink)
  $desktopLnk.TargetPath = Join-Path $InstallRoot 'SupraChat.exe'
  $desktopLnk.WorkingDirectory = $InstallRoot
  $desktopLnk.Description = 'SupraChat'
  $desktopLnk.Save()
}

New-Item -Force $UninstallKey | Out-Null
New-ItemProperty -Path $UninstallKey -Name DisplayName -Value 'SupraChat' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $UninstallKey -Name Publisher -Value 'SemperSupra' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $UninstallKey -Name InstallLocation -Value $InstallRoot -PropertyType String -Force | Out-Null
New-ItemProperty -Path $UninstallKey -Name DisplayIcon -Value (Join-Path $InstallRoot 'SupraChat.exe') -PropertyType String -Force | Out-Null
New-ItemProperty -Path $UninstallKey -Name NoModify -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $UninstallKey -Name NoRepair -Value 1 -PropertyType DWord -Force | Out-Null
$quotedUninstall = '"' + $UninstallPath + '"'
$uninstallCommand = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File ' + $quotedUninstall
New-ItemProperty -Path $UninstallKey -Name UninstallString -Value $uninstallCommand -PropertyType String -Force | Out-Null

$ExePath = Join-Path $InstallRoot 'SupraChat.exe'
$AutomationPath = Join-Path $InstallRoot 'SupraChat.Automation.exe'
$CliShimPath = Join-Path $InstallRoot 'suprachat-cli.cmd'
if (!(Test-Path $AutomationPath)) {
  throw 'SupraChat.Automation.exe is missing from the artifact.'
}
Set-Content -LiteralPath $CliShimPath -Encoding ASCII -Value '@echo off
"%~dp0SupraChat.Automation.exe" %*'

$currentUserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$pathParts = @()
if ($currentUserPath) {
  $pathParts = @($currentUserPath.Split(';') | Where-Object { $_ })
}
if (-not ($pathParts | Where-Object { $_.Trim().TrimEnd('\') -eq $InstallRoot.TrimEnd('\') })) {
  $nextPath = (($pathParts + $InstallRoot) -join ';')
  [Environment]::SetEnvironmentVariable('Path', $nextPath, 'User')
}

$OpenCommand = '"' + $ExePath + '" "%1"'

New-Item -Force $ProtocolKey | Out-Null
Set-Item -Path $ProtocolKey -Value 'URL:SupraChat Protocol'
New-ItemProperty -Path $ProtocolKey -Name 'URL Protocol' -Value '' -PropertyType String -Force | Out-Null
New-Item -Force (Join-Path $ProtocolKey 'DefaultIcon') | Out-Null
Set-Item -Path (Join-Path $ProtocolKey 'DefaultIcon') -Value ('"' + $ExePath + '",0')
New-Item -Force (Join-Path $ProtocolKey 'shell\open\command') | Out-Null
Set-Item -Path (Join-Path $ProtocolKey 'shell\open\command') -Value $OpenCommand

New-Item -Force (Join-Path $ApplicationKey 'shell\open\command') | Out-Null
Set-Item -Path (Join-Path $ApplicationKey 'shell\open\command') -Value $OpenCommand
New-Item -Force (Join-Path $ApplicationKey 'SupportedTypes') | Out-Null
@('.png','.jpg','.jpeg','.webp','.gif','.pdf','.txt','.md','.json','.csv','.tsv','.html','.htm','.xml','.rtf','.odt','.doc','.docx','.ppt','.pptx','.xls','.xlsx') |
  ForEach-Object {
    New-ItemProperty -Path (Join-Path $ApplicationKey 'SupportedTypes') -Name $_ -Value '' -PropertyType String -Force | Out-Null
  }

$installedExeHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $ExePath).Hash.ToLowerInvariant()
$automationHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $AutomationPath).Hash.ToLowerInvariant()
$codexPath = Join-Path $InstallRoot 'runtime\codex\codex.exe'
$codexHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $codexPath).Hash.ToLowerInvariant()

$installReceipt = [ordered]@{
  schema = 'suprachat-install-receipt/v2'
  completed_at_utc = Get-UtcIsoTimestamp
  install_session_id = $InstallSessionId
  trace_id = $TraceId
  installer_elapsed_ms = [long]$InstallerStarted.Elapsed.TotalMilliseconds
  platform = 'windows'
  install_mode = 'per-user'
  app_sha256 = $installedExeHash
  automation_sha256 = $automationHash
  codex_sha256 = $codexHash
  registrations = [ordered]@{
    start_menu = (Test-Path $Shortcut)
    protocol = (Test-Path $ProtocolKey)
    open_with = (Test-Path $ApplicationKey)
    add_remove_programs = (Test-Path $UninstallKey)
    path = [bool]([Environment]::GetEnvironmentVariable('Path','User').Split(';') |
      Where-Object { $_.Trim().TrimEnd('\') -eq $InstallRoot.TrimEnd('\') })
  }
  privacy = [ordered]@{
    contains_tokens = $false
    contains_cookies = $false
    contains_prompts = $false
    contains_outputs = $false
  }
}
New-Item -ItemType Directory -Force -Path $ObservabilityRoot | Out-Null
$installReceipt | ConvertTo-Json -Depth 8 |
  Set-Content -LiteralPath $InstallReceiptPath -Encoding UTF8
Write-InstallerEvent -Event 'install-complete' -Outcome 'success' -Fields @{
  app_hash_prefix = $installedExeHash.Substring(0,16)
  automation_hash_prefix = $automationHash.Substring(0,16)
  codex_hash_prefix = $codexHash.Substring(0,16)
}

Write-Host "SupraChat installed to $InstallRoot"
Write-Host "Protocol: suprachat://"
Write-Host "Open With registration: supported Agent Lab attachment types"
Write-Host "Automation/agent CLI: $CliShimPath"
Write-Host "User PATH includes: $InstallRoot"
Write-Host "Bundled Codex runtime: $codexPath"
Write-Host "Privacy-safe diagnostics: $ObservabilityRoot"
Write-Host "Install trace: $TraceId"

if (-not $NoLaunch) {
  $priorTrace = $env:SUPRACHAT_INSTALL_TRACE_ID
  $priorInstallSession = $env:SUPRACHAT_INSTALL_SESSION_ID
  $priorDogfoodSession = $env:SUPRACHAT_DOGFOOD_SESSION_ID
  try {
    $env:SUPRACHAT_INSTALL_TRACE_ID = $TraceId
    $env:SUPRACHAT_INSTALL_SESSION_ID = $InstallSessionId
    $env:SUPRACHAT_DOGFOOD_SESSION_ID = $InstallSessionId
    Write-InstallerEvent -Event 'first-launch' -Outcome 'start' -CorrelationId $InstallSessionId
    Start-Process $ExePath
    Write-InstallerEvent -Event 'first-launch' -Outcome 'dispatched' -CorrelationId $InstallSessionId
  } catch {
    Write-InstallerEvent -Event 'first-launch' -Outcome 'failure' -CorrelationId $InstallSessionId -Fields @{
      exception_type = $_.Exception.GetType().FullName
      hresult = $_.Exception.HResult
    }
    throw
  } finally {
    $env:SUPRACHAT_INSTALL_TRACE_ID = $priorTrace
    $env:SUPRACHAT_INSTALL_SESSION_ID = $priorInstallSession
    $env:SUPRACHAT_DOGFOOD_SESSION_ID = $priorDogfoodSession
  }
}
