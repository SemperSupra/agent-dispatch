# WinBot: Download Windows 11 Enterprise ISO
# Two methods:
#   1. Media Creation Tool (preferred) - downloads full multi-edition ISO from Microsoft.
#      Supports Enterprise, Pro, Education with /MediaEdition switch.
#      IMPORTANT: MCT ALWAYS downloads the LATEST Windows release.
#      There is NO /Version switch for MCT. It always gives the current public build.
#      For specific versions, use the CDN fallback (method 2) or download manually.
#   2. CDN fallback - downloads from known Microsoft CDN URLs.
#      URLs are build-specific. They change each release.
#      If a CDN URL goes stale, visit the Evaluation Center for the new URL.
#
# Version selection guide:
#   MCT:          Always latest (no version control). Best for production.
#   CDN eval:     Specific builds (23H2, 24H2). Best for reproducibility.
#   UUP dump:     Any build. See https://uupdump.net for specific build ISOs.
#   VLSC/MSDN:    Any version. Requires volume licensing or subscription.
#
# Usage:
#   .\download-windows-iso.ps1 -UseMCT -WindowsEdition Enterprise
#   .\download-windows-iso.ps1 -Version "24H2"              # CDN eval ISO
#   .\download-windows-iso.ps1 -Version "23H2"              # Older CDN eval
#   .\download-windows-iso.ps1 -DownloadUrl "https://..."     # Custom URL

param(
    [string]$OutputPath = "C:\WinBot\master\Win11_Eval.iso",
    [string]$Version = "24H2",
    [string]$Language = "English",
    [string]$WindowsEdition = "Enterprise",
    [string]$Architecture = "x64",
    [string]$DownloadUrl = "",
    [string]$MCTPath = "",
    [switch]$UseMCT,
    [switch]$SkipDownload,
    [switch]$Force,
    [switch]$UseBITS,     # Use BITS transfer (resumable, survives reboots)
    [switch]$NonInteractive
)

$ErrorActionPreference = "Continue"

function Write-WinBotISOProvenance {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$Method,
        [string]$Source = "",
        [string]$Version = "unknown",
        [string]$Build = "unknown",
        [string]$Edition = "unknown",
        [string]$Architecture = "unknown",
        [string]$Language = "unknown"
    )

    $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    $hash = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToUpperInvariant()
    $record = [ordered]@{
        timestamp = (Get-Date).ToUniversalTime().ToString("o")
        filename = $item.Name
        path = $item.FullName
        size_bytes = [int64]$item.Length
        sha256 = $hash
        method = $Method
        source = $Source
        version = if ($Version) { $Version } else { "unknown" }
        build = if ($Build) { $Build } else { "unknown" }
        edition = if ($Edition) { $Edition } else { "unknown" }
        architecture = if ($Architecture) { $Architecture } else { "unknown" }
        language = if ($Language) { $Language } else { "unknown" }
    }
    $log = Join-Path $item.DirectoryName "iso-provenance.jsonl"
    ($record | ConvertTo-Json -Compress) | Add-Content -LiteralPath $log -Encoding UTF8
    return [PSCustomObject]$record
}

Write-Host "[WinBot] Windows 11 Enterprise ISO Downloader" -ForegroundColor Cyan

# Known download URLs from Microsoft CDN
# These are build-specific and WILL CHANGE when new releases ship.
# To find the latest URL: https://www.microsoft.com/evalcenter/evaluate-windows-11-enterprise
$knownUrls = @(
    @{
        Version = "24H2"
        Language = "English"
        Build = "26100.1742"
        Edition = "Enterprise"
        Architecture = "x64"
        Url = "https://software-static.download.prss.microsoft.com/dbazure/888969d5-f34g-4e03-ac9d-1f9786c66749/26100.1742.240906-0331.ge_release_svc_refresh_CLIENTENTERPRISEEVAL_OEMRET_x64FRE_en-us.iso"
        Description = "Windows 11 24H2 Enterprise Evaluation - English x64 (Build 26100)"
    }
    @{
        Version = "23H2"
        Language = "English"
        Build = "22631.2428"
        Edition = "Enterprise"
        Architecture = "x64"
        Url = "https://software-static.download.prss.microsoft.com/dbazure/988969d5-f34g-4e03-ac9d-1f9786c66750/22631.2428.231004-1721.ni_release_svc_refresh_CLIENTENTERPRISEEVAL_OEMRET_x64FRE_en-us.iso"
        Description = "Windows 11 23H2 Enterprise Evaluation - English x64 (Build 22631)"
    }
)

# Resolve URL
if ($DownloadUrl) {
    # A caller-provided URL is only a location. Do not attest edition/version/
    # architecture from caller intent until the artifact is independently identified.
    $match = @{
        Version = "unknown"
        Language = "unknown"
        Build = "unknown"
        Edition = "unknown"
        Architecture = "unknown"
        Url = $DownloadUrl
        Description = "Custom download URL (identity unverified)"
    }
    Write-Host "[WinBot] Using provided download URL; media identity remains unverified." -ForegroundColor Gray
} else {
    $match = $knownUrls | Where-Object {
        $_.Version -eq $Version -and
        $_.Language -eq $Language -and
        $_.Edition -eq $WindowsEdition -and
        $_.Architecture -eq $Architecture
    } | Select-Object -First 1
}

if (-not $match -and -not $UseMCT) {
    $missingSource = "No known CDN source for Windows 11 $Version - $Language - $WindowsEdition - $Architecture"
    if ($SkipDownload -or $NonInteractive) {
        throw $missingSource
    }
    Write-Host "[WinBot] $missingSource" -ForegroundColor Yellow
    Write-Host "[WinBot] Known versions: $($knownUrls.Version -join ', ')" -ForegroundColor Gray
    Write-Host "[WinBot] Opening Microsoft Evaluation Center..." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Microsoft Evaluation Center:" -ForegroundColor White
    Write-Host "  https://www.microsoft.com/evalcenter/evaluate-windows-11-enterprise" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  1. Visit the page above" -ForegroundColor Yellow
    Write-Host "  2. Select ISO - Enterprise and click Continue" -ForegroundColor Yellow
    Write-Host "  3. Fill in your details and download the ISO" -ForegroundColor Yellow
    Write-Host "  4. Save to: $OutputPath" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  For ANY Windows build (not just eval):" -ForegroundColor White
    Write-Host "  https://uupdump.net - Download UUP files and create your own ISO" -ForegroundColor Cyan
    Write-Host ""
    Start-Process "https://www.microsoft.com/evalcenter/evaluate-windows-11-enterprise"
    throw $missingSource
}

# If product key is available, prefer MCT for a fully-licensed ISO
# MCT downloads the official multi-edition ISO with Enterprise included
# NOTE: MCT always downloads the LATEST Windows release. No version selection.
if ($UseMCT) {
    if ($NonInteractive) {
        throw "Media Creation Tool acquisition is interactive and is not authorized by the non-interactive lifecycle path."
    }
    Write-Host "[WinBot] Downloading via Media Creation Tool - $WindowsEdition edition" -ForegroundColor Cyan
    Write-Host "[WinBot] NOTE: MCT always downloads the LATEST Windows release." -ForegroundColor Yellow
    Write-Host "[WinBot] For a specific version, use -Version '23H2' or '24H2' without -UseMCT." -ForegroundColor Gray
    Write-Host ""

    # Find or download MCT
    $mctExe = if ($MCTPath -and (Test-Path $MCTPath)) {
        $MCTPath
    } else {
        $defaultMCT = Join-Path (Split-Path $OutputPath -Parent) "MediaCreationToolW11.exe"
        if (-not (Test-Path $defaultMCT)) {
            Write-Host "  Downloading Media Creation Tool..." -ForegroundColor Gray
            $mctUrl = "https://go.microsoft.com/fwlink/?linkid=2156295"
            try {
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                Invoke-WebRequest -Uri $mctUrl -OutFile $defaultMCT -UseBasicParsing -ErrorAction Stop
                Write-Host "  MCT downloaded." -ForegroundColor Green
            } catch {
                Write-Host "  MCT download failed: $_" -ForegroundColor Red
                Write-Host "  Download manually: https://www.microsoft.com/software-download/windows11" -ForegroundColor Yellow
                throw "Media Creation Tool download failed: $($_.Exception.Message)"
            }
        }
        $defaultMCT
    }

    # Set ISO output to a temp location - MCT writes its own filename
    $mctOutDir = Split-Path $OutputPath -Parent
    if (-not (Test-Path $mctOutDir)) { New-Item -ItemType Directory -Path $mctOutDir -Force | Out-Null }

    Write-Host "  Running Media Creation Tool..." -ForegroundColor Gray
    Write-Host "  Edition: $WindowsEdition" -ForegroundColor Gray
    Write-Host "  Version: LATEST (no version selection available)" -ForegroundColor Gray
    Write-Host "  This will take 30-60 minutes depending on connection speed." -ForegroundColor Yellow
    Write-Host ""

    $startTime = Get-Date
    $mctArgs = @(
        "/Eula", "Accept",
        "/Retail",
        "/MediaArch", $Architecture,
        "/MediaLangCode", "en-US",
        "/MediaEdition", $WindowsEdition
    )

    # MCT runs interactively but writes ISO to a known pattern
    $proc = Start-Process -FilePath $mctExe -ArgumentList $mctArgs -Wait -PassThru -NoNewWindow

    # MCT names ISO by arch: Win11_24H2_English_x64.iso or Win11_24H2_English_arm64.iso
    # Find the generated ISO, preferring our architecture
    $allISOs = Get-ChildItem $mctOutDir -Filter "Win11*.iso" |
        Where-Object { $_.LastWriteTime -ge $startTime.AddSeconds(-5) } |
        Sort-Object LastWriteTime -Descending
    $generatedISO = $allISOs | Where-Object { $_.Name -match $Architecture } | Select-Object -First 1
    if (-not $generatedISO) { $generatedISO = $allISOs | Select-Object -First 1 }

    if ($generatedISO) {
        if ($generatedISO.FullName -ne $OutputPath) {
            Move-Item $generatedISO.FullName $OutputPath -Force
        }
        $duration = [math]::Round(((Get-Date) - $startTime).TotalMinutes, 1)
        $fileSize = (Get-Item $OutputPath).Length
        $fileSizeGB = [math]::Round($fileSize / 1GB, 2)

        Write-Host ""
        Write-Host "[WinBot] ISO created successfully via Media Creation Tool" -ForegroundColor Green
        Write-Host "  File: $OutputPath" -ForegroundColor Green
        Write-Host "  Size: $fileSizeGB GB" -ForegroundColor Green
        Write-Host "  Time: $duration min" -ForegroundColor Green

        $generatedName = $generatedISO.Name
        $actualVersion = if ($generatedName -match '^Win11_([^_]+)_') { $Matches[1] } else { "unknown" }
        $actualArchitecture = if ($generatedName -match '(?i)(x64|arm64)') { $Matches[1].ToLowerInvariant() } else { "unknown" }
        $provenance = Write-WinBotISOProvenance -Path $OutputPath -Method "MCT" -Source "Microsoft Media Creation Tool (latest channel)" -Version $actualVersion -Build "unknown" -Edition $WindowsEdition -Architecture $actualArchitecture -Language "English"

        return @{
            OutputPath = $OutputPath; Size = $fileSize
            DurationMinutes = $duration; Downloaded = $true; Method = "MCT"
            Url = "MCT (latest release)"; SHA256 = $provenance.sha256
            Version = $provenance.version; Architecture = $provenance.architecture
        }
    } else {
        Write-Host ""
        Write-Host "[WinBot] MCT completed but ISO not found in $mctOutDir" -ForegroundColor Yellow
        Write-Host "[WinBot] Check for ISO files or try the CDN eval download without -UseMCT" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Falling back to CDN eval download..." -ForegroundColor Gray
        # Continue to CDN fallback below
    }
}

# CDN fallback - evaluation ISO
$matchUrl = if ($match) { $match.Url } else { $knownUrls[0].Url }
$matchDesc = if ($match) { $match.Description } else { "Windows 11 Enterprise Evaluation ISO" }

if ($SkipDownload) {
    if ($UseMCT) { return @{} }  # Already handled above
    Write-Host "[WinBot] Download URL - no download:" -ForegroundColor Cyan
    Write-Host "  $matchUrl" -ForegroundColor White
    return @{ Url = $matchUrl; OutputPath = $OutputPath; Downloaded = $false }
}

if ((Test-Path $OutputPath) -and -not $Force) {
    $existingSize = (Get-Item $OutputPath).Length
    if ($existingSize -gt 4GB) {
        $sizeGB = [math]::Round($existingSize / 1GB, 1)
        Write-Host "[WinBot] ISO already exists at $OutputPath - $sizeGB GB" -ForegroundColor Green
        Write-Host "[WinBot] Use -Force to re-download." -ForegroundColor Gray
        Write-Host "[WinBot] Note: CDN URLs change per build. The cached ISO may be from a different version." -ForegroundColor Gray
        return @{ Url = $matchUrl; OutputPath = $OutputPath; Downloaded = $false; AlreadyExists = $true }
    }
}

$outDir = Split-Path $OutputPath -Parent
if (-not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}

$outputExistedBefore = Test-Path -LiteralPath $OutputPath

Write-Host "[WinBot] Downloading: $matchDesc" -ForegroundColor Cyan
Write-Host "  URL:  $matchUrl" -ForegroundColor Gray
Write-Host "  Save: $OutputPath" -ForegroundColor Gray
Write-Host "  Size: ~6 GB - this will take a while..." -ForegroundColor Yellow
Write-Host ""

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # Report elapsed time periodically while downloading
    $startTime = Get-Date

    # Use a background runspace for the download so the main thread can show progress
    # BITS transfer supports resume, bandwidth throttling, and survives reboots
    if ($UseBITS -and (Get-Command Start-BitsTransfer -ErrorAction SilentlyContinue)) {
        Write-Host "  Using BITS transfer (resumable)..." -ForegroundColor Gray
        try {
            Start-BitsTransfer -Source $matchUrl -Destination $OutputPath -DisplayName "WinBot ISO Download" -ErrorAction Stop
            # Skip the runspace-based download below
            $duration = [math]::Round(((Get-Date) - $startTime).TotalMinutes, 1)
            $fileSize = (Get-Item $OutputPath).Length
            $fileSizeGB = [math]::Round($fileSize / 1GB, 2)
            Write-Host ""
            Write-Host "[WinBot] Download complete (BITS)" -ForegroundColor Green
            Write-Host "  File: $OutputPath" -ForegroundColor Green
            Write-Host "  Size: $fileSizeGB GB" -ForegroundColor Green
            Write-Host "  Time: $duration min" -ForegroundColor Green
            $provenance = Write-WinBotISOProvenance -Path $OutputPath -Method "CDN-BITS" -Source $matchUrl -Version $match.Version -Build $match.Build -Edition $match.Edition -Architecture $match.Architecture -Language $match.Language
            return @{
                Url = $matchUrl; OutputPath = $OutputPath; Size = $fileSize
                DurationMinutes = $duration; Downloaded = $true
                Build = $match.Build; Version = $match.Version; Method = "CDN-BITS"
                SHA256 = $provenance.sha256
            }
        } catch {
            Write-Warning "BITS transfer failed: $_ Falling back to Invoke-WebRequest."
        }
    }

    $ps = [PowerShell]::Create().AddScript({
        param($url, $out)
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing -ErrorAction Stop
    }).AddParameters(@{ url = $matchUrl; out = $OutputPath })

    try {
        $handle = $ps.BeginInvoke()

        # Show elapsed time while download runs
        while (-not $handle.IsCompleted) {
            $elapsed = [math]::Round(((Get-Date) - $startTime).TotalSeconds, 0)
            $min = [math]::Floor($elapsed / 60)
            $sec = $elapsed % 60

            # Show file size so far if file exists
            $sizeStr = ""
            if (Test-Path $OutputPath) {
                $mb = [math]::Round((Get-Item $OutputPath).Length / 1MB, 0)
                $sizeStr = " - $mb MB so far"
            }

            Write-Host "  ... $min min $sec s elapsed$sizeStr" -ForegroundColor Gray
            Start-Sleep -Seconds 15
        }

        # Collect result
        $ps.EndInvoke($handle)
    } finally {
        # Clean up runspace even if download fails or script is interrupted
        if ($handle -and -not $handle.IsCompleted) {
            $ps.Stop() | Out-Null
        }
        $ps.Dispose()
    }

    $duration = [math]::Round(((Get-Date) - $startTime).TotalMinutes, 1)

    $fileSize = (Get-Item $OutputPath).Length
    $fileSizeGB = [math]::Round($fileSize / 1GB, 2)
    Write-Host ""
    Write-Host "[WinBot] Download complete" -ForegroundColor Green
    Write-Host "  File: $OutputPath" -ForegroundColor Green
    Write-Host "  Size: $fileSizeGB GB" -ForegroundColor Green
    Write-Host "  Time: $duration min" -ForegroundColor Green
    Write-Host "  Build: $($match.Build) ($($match.Version))" -ForegroundColor Gray

    $provenance = Write-WinBotISOProvenance -Path $OutputPath -Method "CDN" -Source $matchUrl -Version $match.Version -Build $match.Build -Edition $match.Edition -Architecture $match.Architecture -Language $match.Language
    return @{
        Url = $matchUrl
        OutputPath = $OutputPath
        Size = $fileSize
        DurationMinutes = $duration
        Downloaded = $true
        Build = $match.Build
        Version = $match.Version
        Method = "CDN"
        SHA256 = $provenance.sha256
    }
} catch {
    Write-Host ""
    Write-Host "[WinBot] Download failed: $_" -ForegroundColor Red
    Write-Host "[WinBot] The Microsoft CDN URL may have changed." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Visit the evaluation center for the current URL:" -ForegroundColor Yellow
    Write-Host "  https://www.microsoft.com/evalcenter/evaluate-windows-11-enterprise" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  For specific builds, use UUP dump:" -ForegroundColor Yellow
    Write-Host "  https://uupdump.net" -ForegroundColor Cyan
    Write-Host ""
    if (-not $outputExistedBefore -and (Test-Path -LiteralPath $OutputPath)) {
        Remove-Item -LiteralPath $OutputPath -Force -ErrorAction SilentlyContinue
    }
    throw "Windows ISO acquisition failed: $($_.Exception.Message)"
}
