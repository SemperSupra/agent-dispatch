Set-StrictMode -Version Latest

function Enable-AndroidEdgeManagedTools {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Root
    )

    if (-not $Root) {
        if ($IsWindows) {
            $base = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { Join-Path $HOME 'AppData/Local' }
            $Root = Join-Path $base 'AndroidEdgeApplianceKit'
        }
        else {
            $Root = Join-Path $HOME '.local/share/android-edge-appliance-kit'
        }
    }

    $toolDir = Join-Path $Root 'platform-tools'
    $adbName = if ($IsWindows) { 'adb.exe' } else { 'adb' }
    $fastbootName = if ($IsWindows) { 'fastboot.exe' } else { 'fastboot' }
    $adbPath = Join-Path $toolDir $adbName
    $fastbootPath = Join-Path $toolDir $fastbootName

    $missing = @()
    if (-not (Test-Path -LiteralPath $adbPath -PathType Leaf)) { $missing += 'adb' }
    if (-not (Test-Path -LiteralPath $fastbootPath -PathType Leaf)) { $missing += 'fastboot' }
    if ($missing.Count -gt 0) {
        throw "Managed Android host tools are incomplete under '$toolDir': missing $($missing -join ', '). Run the host converger apply command first."
    }

    $separator = [IO.Path]::PathSeparator
    $segments = @($env:PATH -split [Regex]::Escape([string]$separator))
    if ($segments -notcontains $toolDir) {
        $env:PATH = "$toolDir$separator$env:PATH"
    }

    $resolvedAdb = (Get-Command adb -ErrorAction Stop).Source
    $resolvedFastboot = (Get-Command fastboot -ErrorAction Stop).Source
    [pscustomobject]@{
        Schema = 'android-edge-host-tool-resolution/v1'
        Root = $Root
        ToolDirectory = $toolDir
        Adb = $resolvedAdb
        Fastboot = $resolvedFastboot
        PathChangedForProcess = ($segments -notcontains $toolDir)
    }
}
