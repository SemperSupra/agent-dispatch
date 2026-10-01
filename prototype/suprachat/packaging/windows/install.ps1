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

if (!(Test-Path (Join-Path $Source 'SupraChat.exe'))) {
  throw 'Run install.ps1 from the extracted SupraChat Windows artifact.'
}

New-Item -ItemType Directory -Force -Path $InstallRoot | Out-Null

Get-ChildItem -Force $Source | Where-Object {
  $_.Name -notin @('install.ps1')
} | ForEach-Object {
  Copy-Item $_.FullName $InstallRoot -Recurse -Force
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

Write-Host "SupraChat installed to $InstallRoot"
Write-Host "Protocol: suprachat://"
Write-Host "Open With registration: supported Agent Lab attachment types"
Write-Host "Automation/agent CLI: $CliShimPath"
Write-Host "User PATH includes: $InstallRoot"
Write-Host "Bundled Codex runtime: $(Join-Path $InstallRoot 'runtime\codex\codex.exe')"

if (-not $NoLaunch) {
  Start-Process (Join-Path $InstallRoot 'SupraChat.exe')
}
