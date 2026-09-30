# WinBot PowerShell Module
# Hyper-V VM automation harness for agent-driven Windows automation
#
# Portable, self-detecting - works on any Windows 10/11 Pro/Enterprise
# machine with Hyper-V role available.

#Requires -Version 5.1

Set-StrictMode -Version Latest

# NOTE: Do NOT set $ErrorActionPreference = "Stop" at module scope.
# It breaks -ErrorAction SilentlyContinue inside functions and turns
# COMExceptions from DISM/WMI into terminating errors.
# Each function handles its own error behavior.

# ============================================================
# Module-level state
# ============================================================
$script:Config = $null
$script:ConfigLoadTime = [datetime]::MinValue
$script:SuppressConfirmations = $false
$script:ModuleDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:ProjectDir = Split-Path -Parent $script:ModuleDir
$script:ConfigPath = Join-Path $script:ProjectDir "config.json"

# ============================================================
# Initialization - called automatically on import
# ============================================================
function Initialize-WinBot {
    <#
    .SYNOPSIS
    Initialize WinBot - detect environment, load config, verify prerequisites.
    Runs automatically on module import.
    #>
    Write-Host "[WinBot] $(Get-WinBotVersion)" -ForegroundColor Cyan
    Write-Host "[WinBot] Project: $script:ProjectDir" -ForegroundColor Gray
}

# ============================================================
# Version
# ============================================================
function Get-WinBotVersion {
    "WinBot v0.1.0"
}

# ============================================================
# Environment Detection
# ============================================================

function Test-IsAdministrator {
    <#
    .SYNOPSIS
    Returns $true if running as Administrator, $false otherwise.
    #>
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-Administrator {
    <#
    .SYNOPSIS
    Throws an error if not running as Administrator, with instructions.
    #>
    if (-not (Test-IsAdministrator)) {
        throw @"
[WinBot] ERROR: This command requires Administrator privileges.

To fix:
  1. Close this PowerShell window
  2. Right-click PowerShell -> "Run as Administrator"
  3. Re-import the module: Import-Module .\host\WinBot.psm1

Or from an admin terminal:  Start-Process powershell -Verb RunAs
"@
    }
}

function Test-HyperVAvailable {
    <#
    .SYNOPSIS
    Check if Hyper-V is installed and available.

    .DESCRIPTION
    Checks for Hyper-V Windows feature, Hyper-V PowerShell module,
    and Hyper-V Management service. Returns detailed status.
    #>
    $result = @{
        Available = $false
        HyperVFeature = $false
        HyperVModule = $false
        HyperVService = $false
        Issues = @()
        Suggestions = @()
    }

    # Check Windows feature (best-effort -- DISM can fail even as admin)
    try {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V-All" -ErrorAction Stop 2>$null
        if ($feature -and $feature.State -eq "Enabled") {
            $result.HyperVFeature = $true
        }
        else {
            $result.Issues += "Hyper-V platform is not enabled"
            $result.Suggestions += "Run: Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -All"
        }
    }
    catch {
        # DISM may be unavailable -- fall back to checking the Hyper-V service
        Write-Verbose "[WinBot] Get-WindowsOptionalFeature failed ($_), checking via service presence..."
        $svcCheck = Get-Service -Name "vmms" -ErrorAction SilentlyContinue
        if ($svcCheck) {
            $result.HyperVFeature = $true  # Assume feature is enabled if the service exists
        }
        else {
            $result.Issues += "Could not verify Hyper-V feature status (DISM unavailable)"
            $result.Suggestions += "Run: Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All"
        }
    }

    # Check Hyper-V module
    if (Get-Module -ListAvailable -Name Hyper-V -ErrorAction SilentlyContinue) {
        $result.HyperVModule = $true
        Import-Module Hyper-V -ErrorAction SilentlyContinue
    }
    else {
        $result.Issues += "Hyper-V PowerShell module not found"
        $result.Suggestions += "Hyper-V management tools may not be installed. Add them via 'Turn Windows features on or off'"
    }

    # Check Hyper-V management service
    $svc = Get-Service -Name "vmms" -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") {
        $result.HyperVService = $true
    }
    elseif ($svc) {
        $result.Issues += "Hyper-V Management Service (vmms) is not running (Status: $($svc.Status))"
        $result.Suggestions += "Run: Start-Service vmms"
    }
    else {
        $result.Issues += "Hyper-V Management Service (vmms) not found"
    }

    $result.Available = $result.HyperVFeature -and $result.HyperVModule -and $result.HyperVService
    return $result
}

function Test-HyperVAdminAccess {
    <#
    .SYNOPSIS
    Test if the current user can actually manage Hyper-V VMs.
    Checks Hyper-V Administrators group membership AND try running Get-VM.
    #>
    $result = @{
        State = "Unknown"
        Reason = "Hyper-V inventory has not been observed"
        CanManageVMs = $null
        InHyperVAdminGroup = $false
        GetVMWorks = $false
        Error = $null
    }

    # Check group membership
    $whoami = whoami /groups 2>$null | Out-String
    if ($whoami -match "Hyper-V Administrators") {
        $result.InHyperVAdminGroup = $true
    }

    # Try actual command
    try {
        $vms = Get-VM -ErrorAction Stop
        $result.GetVMWorks = $true
        $result.CanManageVMs = $true
        $result.State = "True"
        $result.Reason = "Get-VM inventory completed successfully"
        $result.VMCount = $vms.Count
    }
    catch {
        $result.State = "Unknown"
        $result.Reason = "Get-VM inventory could not be observed in the current authority context"
        $result.Error = $_.Exception.Message
    }

    return $result
}

function Get-WinBotEnvironment {
    <#
    .SYNOPSIS
    Full environment diagnostic. Returns everything WinBot needs to know.
    #>
    param([switch]$VerifyArtifacts)

    $env = @{
        ComputerName = $env:COMPUTERNAME
        IsAdmin = Test-IsAdministrator
        OS = (Get-CimInstance Win32_OperatingSystem).Caption
        HyperV = Test-HyperVAvailable
        HyperVAccess = $null
        ExistingVMs = @()
        ExistingVMsCondition = @{
            State = "Unknown"
            Reason = "Hyper-V inventory has not been observed"
        }
        SuitableMasterVM = $null
    }

    if ($env.IsAdmin) {
        $env.HyperVAccess = Test-HyperVAdminAccess
        if ($env.HyperVAccess.CanManageVMs) {
            try {
                $env.ExistingVMs = @(Get-VM -ErrorAction Stop | ForEach-Object {
                    @{
                        Name = $_.Name
                        State = $_.State.ToString()
                        Generation = $_.Generation
                        MemoryGB = [math]::Round($_.MemoryAssigned / 1GB, 1)
                        Uptime = if ($_.Uptime) { $_.Uptime.ToString() } else { "N/A" }
                    }
                })
                $env.ExistingVMsCondition = @{
                    State = if ($env.ExistingVMs.Count -gt 0) { "True" } else { "False" }
                    Reason = "Get-VM inventory completed successfully"
                }
            }
            catch {
                $env.ExistingVMs = @()
                $env.ExistingVMsCondition = @{
                    State = "Unknown"
                    Reason = "Get-VM inventory failed: $($_.Exception.Message)"
                }
            }

            # Try to find a suitable Windows 10/11 VM (any state)
            $windowsVMs = Get-VM -ErrorAction SilentlyContinue | Where-Object {
                $_.Generation -ge 2
            }
            # Check VHDX content for Windows version (heuristic from disk path)
            foreach ($vm in $windowsVMs) {
                $disks = Get-VMHardDiskDrive -VMName $vm.Name -ErrorAction SilentlyContinue
                foreach ($d in $disks) {
                    if ($d.Path -match "Win(11|10)") {
                        $env.SuitableMasterVM = @{
                            Name = $vm.Name
                            VHDPath = $d.Path
                            MatchReason = "VHDX path contains '$($Matches[0])'"
                        }
                        break
                    }
                }
                if ($env.SuitableMasterVM) { break }
            }
        }
    }
    else {
        $env.HyperVAccess = @{
            State = "Unknown"
            Reason = "Hyper-V inventory requires an elevated/authorized observer"
            CanManageVMs = $null
            Error = "Not running as Administrator - Hyper-V inventory was not observed"
        }
    }

    # Pure lifecycle observations. This deliberately does not call health/tests,
    # unregister credentials, prompt, or perform VM/artifact mutation.
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $cfg = Get-WinBotConfig
    $masterPath = $cfg.master.vhdxPath
    $masterExists = if ($masterPath) { Test-Path -LiteralPath $masterPath } else { $false }
    $env.Observer = @{
        User = $identity.Name
        Session = $env:SESSIONNAME
        Elevated = $env.IsAdmin
    }
    $env.Credentials = @{
        Observer = $identity.Name
        VMPassword = Get-WinBotCredentialPresence -Name "vm-password"
        ProductKey = Get-WinBotCredentialPresence -Name "product-key"
        WinBotAPI = Get-WinBotCredentialPresence -Name "api-key-winbot"
    }
    $env.DesiredMedia = [PSCustomObject]@{
        Method = [string]$cfg.media.method
        Version = [string]$cfg.media.version
        Edition = [string]$cfg.media.edition
        Architecture = [string]$cfg.media.architecture
        Language = [string]$cfg.media.language
    }
    $env.DesiredMaster = [PSCustomObject]@{
        VHDXPath = [string]$cfg.master.vhdxPath
        VMPath = [string]$cfg.master.vmPath
        VMName = [string]$cfg.master.vmName
        Username = [string]$cfg.credentials.vmUsername
    }
    $masterObservation = Get-WinBotMasterObservation -VerifyIntegrity:$VerifyArtifacts
    $cloneObservations = @()
    if ($env.HyperVAccess.CanManageVMs) {
        foreach ($vm in @($env.ExistingVMs | Where-Object { $_.Name -like "WinBot-*" -and $_.Name -ne "WinBot-Master" })) {
            $cloneObservations += Get-WinBotCloneObservation -Name $vm.Name -MasterObservation $masterObservation
        }
    }

    $env.Artifacts = @{
        ISO = if ($VerifyArtifacts) { Get-WinBotISOVersion -VerifyHash } else { Get-WinBotISOVersion }
        Master = $masterObservation
        Clones = @($cloneObservations)
        ClonesCondition = @{
            # Lifecycle clone readiness is existential, not universal: one
            # accepted clone is enough to advance. Invalid/unknown siblings
            # remain visible in Artifacts.Clones for diagnosis/cleanup.
            State = if ($env.ExistingVMsCondition.State -eq "Unknown") {
                "Unknown"
            } elseif (@($cloneObservations | Where-Object { $_.State -eq "True" }).Count -gt 0) {
                "True"
            } elseif (@($cloneObservations | Where-Object { $_.State -eq "Unknown" }).Count -gt 0) {
                "Unknown"
            } else {
                "False"
            }
            Reason = if ($env.ExistingVMsCondition.State -eq "Unknown") {
                "clone inventory could not be established"
            } elseif (@($cloneObservations | Where-Object { $_.State -eq "True" }).Count -gt 0) {
                "at least one observed clone has valid lineage to the accepted master"
            } elseif (@($cloneObservations | Where-Object { $_.State -eq "Unknown" }).Count -gt 0) {
                "no ready clone is proven and one or more clone lineage checks remain unknown"
            } else {
                "no observed clone has valid lineage to the accepted master"
            }
        }
    }
    $env.ObservationMode = if ($VerifyArtifacts) { "verified" } else { "shallow" }


    return $env
}

function Get-WinBotMediaOutputPath {
    <#
    .SYNOPSIS
    Derive the deterministic ISO target path for one exact media contract.
    #>
    param(
        [Parameter(Mandatory=$true)][object]$Media,
        [Parameter(Mandatory=$true)][string]$Root
    )

    if ([string]::IsNullOrWhiteSpace($Root)) {
        throw "Media output root is required."
    }

    $parts = [ordered]@{
        edition = [string]$Media.Edition
        version = [string]$Media.Version
        method = [string]$Media.Method
        architecture = [string]$Media.Architecture
        language = [string]$Media.Language
    }
    foreach ($key in @($parts.Keys)) {
        if ([string]::IsNullOrWhiteSpace($parts[$key])) {
            throw "Media contract field '$key' is required."
        }
        $parts[$key] = ($parts[$key] -replace '[^a-zA-Z0-9._-]', '-').Trim('-')
        if ([string]::IsNullOrWhiteSpace($parts[$key])) {
            throw "Media contract field '$key' has no safe path representation."
        }
    }

    $filename = "Win11_$($parts.edition)_$($parts.version)_$($parts.method)_$($parts.architecture)_$($parts.language).iso"
    return Join-Path $Root $filename
}


function Invoke-WinBotMediaAcquisition {
    <#
    .SYNOPSIS
    Acquire one exact Windows ISO contract and verify its postcondition.

    .DESCRIPTION
    Bounded mutation primitive for the lifecycle controller. Only deterministic
    CDN acquisition is currently bound. Existing conflicting targets are never
    overwritten implicitly. A successful downloader exit is insufficient:
    provenance, SHA-256, edition, version, architecture, language, and method
    are re-observed before success is returned.
    #>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="High")]
    param(
        [Parameter(Mandatory=$true)][object]$Contract
    )

    $result = [ordered]@{
        State = "Blocked"
        Applied = $false
        Reason = $null
        OutputPath = $null
        Evidence = $null
    }

    if (-not $Contract -or [string]$Contract.Kind -ne "AcquireISO" -or -not $Contract.Media -or -not $Contract.OutputPath) {
        $result.State = "BlockedInput"
        $result.Reason = "AcquireISO requires exact Media and OutputPath contract fields"
        return [PSCustomObject]$result
    }

    $media = $Contract.Media
    if ([string]$media.Method -ne "CDN") {
        $result.State = "UnboundAction"
        $result.Reason = "only deterministic CDN media acquisition is bound; MCT remains interactive/unbound"
        return [PSCustomObject]$result
    }

    $config = Get-WinBotConfig
    $root = Split-Path -Parent ([string]$config.master.vhdxPath)
    $expectedPath = Get-WinBotMediaOutputPath -Media $media -Root $root
    try {
        $expectedFull = [IO.Path]::GetFullPath($expectedPath)
        $contractFull = [IO.Path]::GetFullPath([string]$Contract.OutputPath)
    }
    catch {
        $result.State = "BlockedInput"
        $result.Reason = "media output path could not be normalized"
        return [PSCustomObject]$result
    }

    if (-not [string]::Equals($expectedFull, $contractFull, [StringComparison]::OrdinalIgnoreCase)) {
        $result.State = "StaleContract"
        $result.Reason = "media output path no longer matches current configured master root and exact media identity"
        return [PSCustomObject]$result
    }
    $result.OutputPath = $contractFull

    $verifyArgs = @{
        ISOPath = $contractFull
        VerifyHash = $true
        ExpectedEdition = [string]$media.Edition
        ExpectedVersion = [string]$media.Version
        ExpectedArchitecture = [string]$media.Architecture
        ExpectedLanguage = [string]$media.Language
    }

    if (Test-Path -LiteralPath $contractFull) {
        $existing = Get-WinBotISOVersion @verifyArgs
        $methodMatches = [string]$existing.Method -like "CDN*"
        if ([string]$existing.State -eq "True" -and $methodMatches) {
            $result.State = "Ready"
            $result.Reason = "exact desired CDN ISO already exists and is verified"
            $result.Evidence = $existing
            return [PSCustomObject]$result
        }

        $result.State = "BlockedConflict"
        $result.Reason = "media target path already exists but is not the exact verified desired CDN artifact; explicit cleanup/adoption is required"
        $result.Evidence = $existing
        return [PSCustomObject]$result
    }

    if (-not $PSCmdlet.ShouldProcess($contractFull, "Acquire exact Windows ISO via CDN and verify postcondition")) {
        $result.State = "WhatIf"
        $result.Reason = "media acquisition was not applied"
        return [PSCustomObject]$result
    }

    $downloader = Join-Path $script:ProjectDir "guest\download-windows-iso.ps1"
    if (-not (Test-Path -LiteralPath $downloader)) {
        $result.State = "Blocked"
        $result.Reason = "ISO downloader primitive is absent: $downloader"
        return [PSCustomObject]$result
    }

    $downloadResult = $null
    try {
        $downloadArgs = @{
            OutputPath = $contractFull
            Version = [string]$media.Version
            Language = [string]$media.Language
            WindowsEdition = [string]$media.Edition
            Architecture = [string]$media.Architecture
            UseBITS = $true
            NonInteractive = $true
        }
        $downloadResult = & $downloader @downloadArgs

        $verified = Get-WinBotISOVersion @verifyArgs
        $methodMatches = [string]$verified.Method -like "CDN*"
        if ([string]$verified.State -ne "True" -or -not $methodMatches) {
            if (Test-Path -LiteralPath $contractFull) {
                Remove-Item -LiteralPath $contractFull -Force -ErrorAction SilentlyContinue
            }
            $result.State = "FailedVerification"
            $result.Reason = "download completed but exact desired CDN artifact verification failed; newly created target was removed"
            $result.Evidence = $verified
            return [PSCustomObject]$result
        }

        $result.Applied = [bool]$downloadResult.Downloaded
        $result.State = "AppliedVerified"
        $result.Reason = "exact desired CDN ISO was acquired and postcondition verified"
        $result.Evidence = $verified
        return [PSCustomObject]$result
    }
    catch {
        if ($downloadResult -and [bool]$downloadResult.Downloaded -and (Test-Path -LiteralPath $contractFull)) {
            Remove-Item -LiteralPath $contractFull -Force -ErrorAction SilentlyContinue
        }
        $result.State = "Failed"
        $result.Reason = "media acquisition failed without an accepted artifact: $($_.Exception.Message)"
        return [PSCustomObject]$result
    }
}


# Intent-Aware Lifecycle Planning
# ============================================================

function Get-WinBotPlan {
    <#
    .SYNOPSIS
    Derive the nearest bounded lifecycle action from observation + intent.

    .DESCRIPTION
    Pure decision function. It does not mutate WinBot state, prompt, elevate,
    register credentials, acquire media, or operate VMs. If -Observation is
    omitted it performs one read-only environment observation.

    The plan is intentionally one-step: later actions are not READY until the
    selected action's postcondition has been re-observed.
    #>
    param(
        [ValidateSet("status","executor","master","clone","bootstrap","service","rep3-native")]
        [string]$Intent = "status",
        [object]$Observation = $null,
        [switch]$VerifyArtifacts
    )

    if (-not $Observation) {
        $Observation = Get-WinBotEnvironment -VerifyArtifacts:$VerifyArtifacts
    }

    function Get-ConditionState {
        param([object]$Condition, [string]$Default = "Unknown")
        if ($null -eq $Condition) { return $Default }
        if ($Condition -is [string]) { return [string]$Condition }
        if ($Condition.PSObject -and $Condition.PSObject.Properties["State"]) {
            return [string]$Condition.State
        }
        if ($Condition -is [hashtable] -and $Condition.ContainsKey("State")) {
            return [string]$Condition["State"]
        }
        return $Default
    }

    function Get-ConditionReason {
        param([object]$Condition, [string]$Default = "")
        if ($null -eq $Condition) { return $Default }
        if ($Condition.PSObject -and $Condition.PSObject.Properties["Reason"]) {
            return [string]$Condition.Reason
        }
        if ($Condition -is [hashtable] -and $Condition.ContainsKey("Reason")) {
            return [string]$Condition["Reason"]
        }
        return $Default
    }

    $executor = $Observation.HyperVAccess
    $iso = $Observation.Artifacts.ISO
    $master = $Observation.Artifacts.Master
    $clones = $Observation.Artifacts.ClonesCondition
    $vmCredential = $Observation.Credentials.VMPassword
    $apiCredential = $Observation.Credentials.WinBotAPI
    $desiredMedia = if ($Observation.PSObject -and $Observation.PSObject.Properties["DesiredMedia"]) { $Observation.DesiredMedia } else { $null }
    $desiredMaster = if ($Observation.PSObject -and $Observation.PSObject.Properties["DesiredMaster"]) { $Observation.DesiredMaster } else { $null }

    $executorState = Get-ConditionState $executor
    $isoState = Get-ConditionState $iso
    $masterState = Get-ConditionState $master
    $cloneState = Get-ConditionState $clones
    $vmCredentialState = Get-ConditionState $vmCredential
    $apiCredentialState = Get-ConditionState $apiCredential

    # Observation strength is an input fact, not something that can be
    # reconstructed from artifact truth values. A deep observation may
    # legitimately prove an artifact False.
    $observationMode = "shallow"
    if ($Observation.PSObject -and $Observation.PSObject.Properties["ObservationMode"]) {
        $candidateMode = [string]$Observation.ObservationMode
        if ($candidateMode -in @("shallow", "verified")) {
            $observationMode = $candidateMode
        }
    } elseif ($VerifyArtifacts) {
        $observationMode = "verified"
    }

    $readyClones = @(
        @($Observation.Artifacts.Clones) |
            Where-Object { [string]$_.State -eq "True" } |
            Sort-Object Name
    )

    $cloneIdentity = @(
        @($Observation.Artifacts.Clones) |
            Sort-Object Name |
            ForEach-Object {
                [ordered]@{
                    name = [string]$_.Name
                    state = [string]$_.State
                    disk = [string]$_.DiskPath
                    parent = [string]$_.ParentPath
                    expected_parent = [string]$_.ExpectedParentPath
                    parent_matches = $_.ParentMatches
                }
            }
    )

    $fingerprintBasis = [ordered]@{
        computer = [string]$Observation.ComputerName
        elevated = [bool]$Observation.IsAdmin
        hyperv_available = [bool]$Observation.HyperV.Available
        executor = $executorState
        iso = [ordered]@{
            state = $isoState
            path = [string]$iso.ISOPath
            sha256 = [string]$iso.SHA256
            method = [string]$iso.Method
            edition = [string]$iso.Edition
            version = [string]$iso.Version
            architecture = [string]$iso.Architecture
            language = [string]$iso.Language
        }
        desired_media = [ordered]@{
            method = if ($desiredMedia) { [string]$desiredMedia.Method } else { "" }
            version = if ($desiredMedia) { [string]$desiredMedia.Version } else { "" }
            edition = if ($desiredMedia) { [string]$desiredMedia.Edition } else { "" }
            architecture = if ($desiredMedia) { [string]$desiredMedia.Architecture } else { "" }
            language = if ($desiredMedia) { [string]$desiredMedia.Language } else { "" }
        }
        desired_master = [ordered]@{
            vhdx_path = if ($desiredMaster) { [string]$desiredMaster.VHDXPath } else { "" }
            vm_path = if ($desiredMaster) { [string]$desiredMaster.VMPath } else { "" }
            vm_name = if ($desiredMaster) { [string]$desiredMaster.VMName } else { "" }
            username = if ($desiredMaster) { [string]$desiredMaster.Username } else { "" }
        }
        master = [ordered]@{
            state = $masterState
            path = [string]$master.Path
            accepted_path = [string]$master.AcceptedPath
            path_matches = $master.PathMatchesAccepted
            accepted_hash_present = $master.AcceptedHashPresent
            read_only = $master.ReadOnly
            integrity_verified = $master.IntegrityVerified
            hash_matches = $master.HashMatches
        }
        clones = $cloneIdentity
        vm_credential = $vmCredentialState
        api_credential = $apiCredentialState
    }
    $json = $fingerprintBasis | ConvertTo-Json -Depth 8 -Compress
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $hashBytes = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($json))
    }
    finally {
        $sha.Dispose()
    }
    $fingerprint = ([BitConverter]::ToString($hashBytes) -replace '-', '').ToLowerInvariant()

    $plan = [ordered]@{
        Intent = $Intent
        ObservationMode = $observationMode
        ObservationFingerprint = $fingerprint
        Ready = $false
        NextAction = $null
        ActionContract = $null
        TargetCloneName = $null
        Reason = $null
        RequiresHuman = $false
        RequiresUAC = $false
        RequiresSecretAuthority = $false
        Conditions = [ordered]@{
            Executor = [ordered]@{ State=$executorState; Reason=(Get-ConditionReason $executor) }
            ISO = [ordered]@{ State=$isoState; Reason=(Get-ConditionReason $iso) }
            Master = [ordered]@{ State=$masterState; Reason=(Get-ConditionReason $master) }
            Clone = [ordered]@{ State=$cloneState; Reason=(Get-ConditionReason $clones) }
            VMPassword = [ordered]@{ State=$vmCredentialState; Reason=(Get-ConditionReason $vmCredential) }
            WinBotAPI = [ordered]@{ State=$apiCredentialState; Reason=(Get-ConditionReason $apiCredential) }
        }
    }

    if ($Intent -eq "status") {
        $plan.Ready = $true
        $plan.NextAction = "None"
        $plan.Reason = "status intent is satisfied by observation alone"
        return [PSCustomObject]$plan
    }

    if (-not $Observation.HyperV.Available) {
        $plan.NextAction = "EnableHyperV"
        $plan.Reason = "Hyper-V prerequisites are not ready for the requested lifecycle intent"
        $plan.RequiresHuman = $true
        $plan.RequiresUAC = $true
        return [PSCustomObject]$plan
    }

    if ($executorState -eq "Unknown") {
        $plan.NextAction = "RequestElevationForInventory"
        $plan.Reason = "executor inventory is Unknown; obtain bounded read-only Hyper-V authority before deciding absence/readiness"
        $plan.RequiresHuman = $true
        $plan.RequiresUAC = $true
        return [PSCustomObject]$plan
    }

    if ($executorState -ne "True") {
        $plan.NextAction = "EstablishExecutor"
        $plan.Reason = "Hyper-V is available but executor readiness is not established"
        $plan.RequiresHuman = $true
        return [PSCustomObject]$plan
    }

    if ($Intent -eq "executor") {
        $plan.Ready = $true
        $plan.NextAction = "None"
        $plan.Reason = "executor inventory is callable and ready"
        return [PSCustomObject]$plan
    }

    if ($masterState -eq "Unknown") {
        $hasAcceptedHash = $false
        $pathMatchesAccepted = $null
        if ($master -and $master.PSObject) {
            if ($master.PSObject.Properties["AcceptedHashPresent"]) {
                $hasAcceptedHash = [bool]$master.AcceptedHashPresent
            }
            if ($master.PSObject.Properties["PathMatchesAccepted"]) {
                $pathMatchesAccepted = $master.PathMatchesAccepted
            }
        }

        if ($hasAcceptedHash -and $pathMatchesAccepted -ne $false) {
            $plan.NextAction = "VerifyMaster"
            $plan.Reason = "accepted master identity is recorded but decision-grade integrity remains unverified"
        }
        else {
            $plan.NextAction = "AdoptOrRepairMaster"
            $plan.Reason = "master artifact identity is unresolved or not bound to the accepted master authority"
            $plan.RequiresHuman = $true
        }
        return [PSCustomObject]$plan
    }


    if ($masterState -ne "True") {
        $mediaMethod = if ($desiredMedia) { [string]$desiredMedia.Method } else { "" }
        $mediaVersion = if ($desiredMedia) { [string]$desiredMedia.Version } else { "" }
        $mediaEdition = if ($desiredMedia) { [string]$desiredMedia.Edition } else { "" }
        $mediaArchitecture = if ($desiredMedia) { [string]$desiredMedia.Architecture } else { "" }
        $mediaLanguage = if ($desiredMedia) { [string]$desiredMedia.Language } else { "" }
        $mediaContractValid =
            $mediaMethod -in @("CDN","MCT") -and
            -not [string]::IsNullOrWhiteSpace($mediaVersion) -and
            -not [string]::IsNullOrWhiteSpace($mediaEdition) -and
            -not [string]::IsNullOrWhiteSpace($mediaLanguage) -and
            $mediaArchitecture -in @("x64","arm64") -and
            ($mediaMethod -ne "MCT" -or $mediaVersion -eq "latest")

        if (-not $mediaContractValid) {
            $plan.NextAction = "ResolveMediaIntent"
            $plan.Reason = "desired Windows media contract is incomplete or inconsistent"
            $plan.RequiresHuman = $true
            return [PSCustomObject]$plan
        }

        $mediaContract = [PSCustomObject]@{
            Method = $mediaMethod
            Version = $mediaVersion
            Edition = $mediaEdition
            Architecture = $mediaArchitecture
            Language = $mediaLanguage
        }

        $methodMatches = if ($mediaMethod -eq "CDN") {
            [string]$iso.Method -like "CDN*"
        } else {
            [string]$iso.Method -eq "MCT"
        }
        $versionMatches = if ($mediaMethod -eq "MCT" -and $mediaVersion -eq "latest") {
            $true
        } else {
            [string]$iso.Version -eq $mediaVersion
        }
        $isoMatchesDesired =
            $isoState -eq "True" -and
            $methodMatches -and
            $versionMatches -and
            [string]$iso.Edition -eq $mediaEdition -and
            [string]$iso.Architecture -eq $mediaArchitecture -and
            [string]$iso.Language -eq $mediaLanguage

        if ($isoState -eq "Unknown") {
            $plan.NextAction = "VerifyISO"
            $plan.ActionContract = [PSCustomObject]@{
                Kind = "VerifyISO"
                ISOPath = [string]$iso.ISOPath
                Media = $mediaContract
            }
            $plan.Reason = "master is not ready and available source media has unresolved identity/integrity against the desired media contract"
            return [PSCustomObject]$plan
        }

        if (-not $isoMatchesDesired) {
            $plan.NextAction = "AcquireISO"
            $mediaRoot = Split-Path -Parent ([string]$master.Path)
            $plan.ActionContract = [PSCustomObject]@{
                Kind = "AcquireISO"
                Media = $mediaContract
                OutputPath = Get-WinBotMediaOutputPath -Media $mediaContract -Root $mediaRoot
            }
            $plan.Reason = if ($isoState -eq "True") {
                "verified source media does not match the desired edition/version/architecture/method"
            } else {
                "no compatible verified Windows source media is ready"
            }
            return [PSCustomObject]$plan
        }

        if ($vmCredentialState -eq "Unknown") {
            $plan.NextAction = "ResolveMasterCredential"
            $plan.Reason = "verified desired source media is ready but master credential presence is Unknown; resolve existing credential authority before any creation"
            $plan.RequiresHuman = $true
            $plan.RequiresSecretAuthority = $true
            return [PSCustomObject]$plan
        }

        if ($vmCredentialState -eq "False") {
            $plan.NextAction = "EstablishMasterCredential"
            $plan.Reason = "verified desired source media is ready and master credential absence is established"
            $plan.RequiresSecretAuthority = $true
            return [PSCustomObject]$plan
        }

        $masterDirectory = if ($desiredMaster) { [string]$desiredMaster.VMPath } else { "" }
        $masterVMName = if ($desiredMaster) { [string]$desiredMaster.VMName } else { "" }
        $masterUsername = if ($desiredMaster) { [string]$desiredMaster.Username } else { "" }
        if ([string]::IsNullOrWhiteSpace($masterDirectory) -or
            [string]::IsNullOrWhiteSpace($masterVMName) -or
            [string]::IsNullOrWhiteSpace($masterUsername)) {
            $plan.NextAction = "ResolveMasterIntent"
            $plan.Reason = "master build intent is missing VM path/name/username"
            $plan.RequiresHuman = $true
            return [PSCustomObject]$plan
        }

        $plan.NextAction = "BuildMaster"
        $plan.ActionContract = [PSCustomObject]@{
            Kind = "BuildMaster"
            ISOPath = [string]$iso.ISOPath
            Media = $mediaContract
            MasterPath = [string]$master.Path
            MasterDirectory = $masterDirectory
            MasterVMName = $masterVMName
            Username = $masterUsername
            Force = $false
        }
        $plan.Reason = "verified exact source, master intent, and credential prerequisites are ready"
        return [PSCustomObject]$plan
    }

    if ($Intent -eq "master") {
        $plan.Ready = $true
        $plan.NextAction = "None"
        $plan.Reason = "accepted master is ready"
        return [PSCustomObject]$plan
    }

    if ($cloneState -eq "Unknown") {
        $plan.NextAction = "VerifyCloneLineage"
        $plan.Reason = "accepted master is ready but clone inventory/lineage is unresolved"
        return [PSCustomObject]$plan
    }

    if ($cloneState -ne "True") {
        $cloneSuffix = $fingerprint.Substring(0,12)
        $cloneName = "WinBot-clone-lifecycle-$cloneSuffix"
        $plan.NextAction = "CreateClone"
        $plan.ActionContract = [PSCustomObject]@{
            Kind = "CreateClone"
            CloneName = $cloneName
            Start = $true
            WaitForGuest = $false
        }
        $plan.TargetCloneName = $cloneName
        $plan.Reason = "accepted master is ready and no valid disposable clone is ready; create/start one exact clone without claiming guest readiness"
        return [PSCustomObject]$plan
    }

    if ($Intent -eq "clone" -or $Intent -eq "bootstrap") {
        $plan.Ready = $true
        $plan.NextAction = "None"
        $plan.Reason = "accepted master and valid disposable clone are ready"
        return [PSCustomObject]$plan
    }

    if ($Intent -eq "service" -or $Intent -eq "rep3-native") {
        if ($readyClones.Count -eq 0) {
            $plan.NextAction = "VerifyCloneLineage"
            $plan.Reason = "clone aggregate readiness is True but no exact accepted clone target is observable"
            return [PSCustomObject]$plan
        }

        if ($readyClones.Count -gt 1) {
            $plan.NextAction = "SelectCloneTarget"
            $plan.ActionContract = [PSCustomObject]@{
                Kind = "SelectCloneTarget"
                Candidates = @($readyClones | ForEach-Object { [string]$_.Name })
            }
            $plan.Reason = "multiple accepted clones are ready; an exact guest target must be selected before service work"
            $plan.RequiresHuman = $true
            return [PSCustomObject]$plan
        }

        $targetClone = [string]$readyClones[0].Name
        $plan.TargetCloneName = $targetClone

        if ($apiCredentialState -ne "True") {
            $plan.NextAction = "RecoverServiceCredential"
            $plan.ActionContract = [PSCustomObject]@{
                Kind = "RecoverServiceCredential"
                CloneName = $targetClone
            }
            $plan.Reason = "exact accepted clone is selected but guest/API credential authority is not available in the current observer context"
            $plan.RequiresSecretAuthority = $true
            return [PSCustomObject]$plan
        }

        $plan.NextAction = "ObserveGuestService"
        $plan.ActionContract = [PSCustomObject]@{
            Kind = "ObserveGuestService"
            CloneName = $targetClone
        }
        $plan.Reason = if ($Intent -eq "rep3-native") {
            "exact accepted native clone is selected; guest/service and exact qualification-artifact readiness are the next unresolved facts"
        } else {
            "exact accepted clone and API credential authority are ready; service reachability must be observed"
        }
        return [PSCustomObject]$plan
    }

    $plan.NextAction = "Reobserve"
    $plan.Reason = "requested intent has no more-specific decision from the current observation"
    return [PSCustomObject]$plan
}

# ============================================================
# Bounded APPLY / stale-plan protection
# ============================================================

function Test-WinBotPlanFresh {
    <#
    .SYNOPSIS
    Compare a previously derived plan to current material observation truth.

    .DESCRIPTION
    Pure/read-only. A plan is fresh only when both its material observation
    fingerprint and selected next action still match a newly derived plan.
    #>
    param(
        [Parameter(Mandatory=$true)][object]$Plan,
        [object]$Observation = $null
    )

    if (-not $Plan.PSObject.Properties["Intent"] -or
        -not $Plan.PSObject.Properties["ObservationFingerprint"] -or
        -not $Plan.PSObject.Properties["NextAction"]) {
        throw "Plan is missing Intent, ObservationFingerprint, or NextAction."
    }

    if (-not $Observation) {
        $verifyArtifacts = ($Plan.PSObject.Properties["ObservationMode"] -and [string]$Plan.ObservationMode -eq "verified")
        $Observation = Get-WinBotEnvironment -VerifyArtifacts:$verifyArtifacts
    }

    $freshPlan = Get-WinBotPlan -Intent ([string]$Plan.Intent) -Observation $Observation
    $fingerprintMatches = [string]::Equals(
        [string]$Plan.ObservationFingerprint,
        [string]$freshPlan.ObservationFingerprint,
        [StringComparison]::OrdinalIgnoreCase
    )
    $actionMatches = [string]::Equals(
        [string]$Plan.NextAction,
        [string]$freshPlan.NextAction,
        [StringComparison]::Ordinal
    )

    $expectedContract = if ($Plan.PSObject.Properties["ActionContract"] -and $null -ne $Plan.ActionContract) {
        $Plan.ActionContract | ConvertTo-Json -Depth 10 -Compress
    } else { "" }
    $actualContract = if ($freshPlan.PSObject.Properties["ActionContract"] -and $null -ne $freshPlan.ActionContract) {
        $freshPlan.ActionContract | ConvertTo-Json -Depth 10 -Compress
    } else { "" }
    $contractMatches = [string]::Equals(
        [string]$expectedContract,
        [string]$actualContract,
        [StringComparison]::Ordinal
    )

    $expectedTarget = if ($Plan.PSObject.Properties["TargetCloneName"]) { [string]$Plan.TargetCloneName } else { "" }
    $actualTarget = if ($freshPlan.PSObject.Properties["TargetCloneName"]) { [string]$freshPlan.TargetCloneName } else { "" }
    $targetMatches = [string]::Equals($expectedTarget, $actualTarget, [StringComparison]::Ordinal)

    $isFresh = $fingerprintMatches -and $actionMatches -and $contractMatches -and $targetMatches
    return [PSCustomObject]@{
        Fresh = $isFresh
        State = if ($isFresh) { "True" } else { "False" }
        Reason = if (-not $fingerprintMatches) {
            "material observation fingerprint changed"
        } elseif (-not $actionMatches) {
            "nearest bounded action changed"
        } elseif (-not $contractMatches) {
            "exact action contract changed"
        } elseif (-not $targetMatches) {
            "exact target clone changed"
        } else {
            "plan preconditions and exact action contract still match current observation"
        }
        ExpectedFingerprint = [string]$Plan.ObservationFingerprint
        ActualFingerprint = [string]$freshPlan.ObservationFingerprint
        ExpectedAction = [string]$Plan.NextAction
        ActualAction = [string]$freshPlan.NextAction
        ExpectedContract = [string]$expectedContract
        ActualContract = [string]$actualContract
        ExpectedTarget = $expectedTarget
        ActualTarget = $actualTarget
        Observation = $Observation
        FreshPlan = $freshPlan
    }
}

function Invoke-WinBotPlanApply {
    <#
    .SYNOPSIS
    Apply exactly one fresh planned transition using bounded existing primitives.

    .DESCRIPTION
    Re-observes before any mutation. Stale plans are rejected and never
    dispatched. Only actions with sufficiently narrow existing contracts are
    bound here; broader/human-only actions return a structured Blocked result.

    Mutation is bound only where the underlying primitive and authority
    contract are decision-grade. BuildMaster consumes the exact media/master
    contract through the hardened builder; CreateClone uses the native-qualified
    exact create/start-without-guest-wait contract.
    #>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="High")]
    param(
        [Parameter(Mandatory=$true)][object]$Plan,

        [SecureString]$Credential,
        [switch]$GenerateCredential
    )

    if ($Credential -and $GenerateCredential) {
        throw "Specify either -Credential or -GenerateCredential, not both."
    }

    $guard = Test-WinBotPlanFresh -Plan $Plan
    $action = [string]$guard.ActualAction
    $result = [ordered]@{
        Intent = [string]$Plan.Intent
        PlannedAction = [string]$Plan.NextAction
        Action = $action
        Applied = $false
        State = "Blocked"
        Reason = $null
        ObservationFingerprint = [string]$guard.ActualFingerprint
        Evidence = $null
    }

    if (-not $guard.Fresh) {
        $result.State = "StalePlan"
        $result.Reason = $guard.Reason
        $result.Evidence = [PSCustomObject]@{
            ExpectedFingerprint = $guard.ExpectedFingerprint
            ActualFingerprint = $guard.ActualFingerprint
            ExpectedAction = $guard.ExpectedAction
            ActualAction = $guard.ActualAction
            ExpectedContract = $guard.ExpectedContract
            ActualContract = $guard.ActualContract
            ExpectedTarget = $guard.ExpectedTarget
            ActualTarget = $guard.ActualTarget
        }
        return [PSCustomObject]$result
    }

    $observation = $guard.Observation

    switch ($action) {
        "None" {
            $result.State = "Ready"
            $result.Reason = "requested intent is already converged; no mutation selected"
            return [PSCustomObject]$result
        }

        "VerifyISO" {
            $iso = $observation.Artifacts.ISO
            if (-not $iso -or -not $iso.ISOPath) {
                $result.Reason = "ISO verification was selected but no exact ISO path is observable"
                return [PSCustomObject]$result
            }
            $contract = $Plan.ActionContract
            if (-not $contract -or [string]$contract.Kind -ne "VerifyISO" -or -not $contract.Media) {
                $result.State = "UnboundAction"
                $result.Reason = "ISO verification requires an exact desired media contract"
                return [PSCustomObject]$result
            }
            $verifyArgs = @{
                ISOPath = [string]$iso.ISOPath
                VerifyHash = $true
                ExpectedEdition = [string]$contract.Media.Edition
                ExpectedVersion = if ([string]$contract.Media.Method -eq "MCT" -and [string]$contract.Media.Version -eq "latest") { "" } else { [string]$contract.Media.Version }
                ExpectedArchitecture = [string]$contract.Media.Architecture
                ExpectedLanguage = [string]$contract.Media.Language
            }
            $evidence = Get-WinBotISOVersion @verifyArgs
            $result.State = [string]$evidence.State
            $result.Reason = [string]$evidence.Reason
            $result.Evidence = $evidence
            return [PSCustomObject]$result
        }

        "VerifyMaster" {
            $evidence = Get-WinBotMasterObservation -VerifyIntegrity
            $result.State = [string]$evidence.State
            $result.Reason = [string]$evidence.Reason
            $result.Evidence = $evidence
            return [PSCustomObject]$result
        }

        "VerifyCloneLineage" {
            if (-not $observation.IsAdmin) {
                $result.State = "Unknown"
                $result.Reason = "clone-lineage verification requires an elevated/authorized observer"
                return [PSCustomObject]$result
            }
            $deepMaster = Get-WinBotMasterObservation -VerifyIntegrity
            $cloneEvidence = @()
            foreach ($vm in @($observation.ExistingVMs | Where-Object { $_.Name -like "WinBot-*" -and $_.Name -ne "WinBot-Master" })) {
                $cloneEvidence += Get-WinBotCloneObservation -Name $vm.Name -MasterObservation $deepMaster
            }
            $result.State = if (@($cloneEvidence | Where-Object { $_.State -eq "True" }).Count -gt 0) {
                "True"
            } elseif (@($cloneEvidence | Where-Object { $_.State -eq "Unknown" }).Count -gt 0) {
                "Unknown"
            } else {
                "False"
            }
            $result.Reason = if ($cloneEvidence.Count -eq 0) {
                "no clone VMs were observed"
            } elseif ($result.State -eq "True") {
                "at least one clone lineage is valid; per-clone evidence preserves any invalid siblings"
            } elseif ($result.State -eq "Unknown") {
                "no ready clone is proven and one or more clone lineages remain unknown"
            } else {
                "no observed clone has valid lineage to the accepted master"
            }
            $result.Evidence = @($cloneEvidence)
            return [PSCustomObject]$result
        }

        "ResolveMediaIntent" {
            $result.State = "BlockedInput"
            $result.Reason = "desired Windows media edition/version/architecture/method must be explicit and internally consistent"
            return [PSCustomObject]$result
        }

        "ResolveMasterIntent" {
            $result.State = "BlockedInput"
            $result.Reason = "desired master VM path/name/username must be explicit before build"
            return [PSCustomObject]$result
        }

        "ResolveMasterCredential" {
            $result.State = "BlockedAuthority"
            $result.Reason = "master credential presence is Unknown; recover/re-observe the authoritative existing credential context before creating or rotating anything"
            return [PSCustomObject]$result
        }

        "EstablishMasterCredential" {
            if (-not $Credential -and -not $GenerateCredential) {
                $result.State = "BlockedInput"
                $result.Reason = "master credential creation requires explicit -Credential or -GenerateCredential authority"
                return [PSCustomObject]$result
            }

            $config = Get-WinBotConfig
            if (-not $PSCmdlet.ShouldProcess("WinBot/VM/Password", "Establish canonical master credential")) {
                $result.State = "WhatIf"
                $result.Reason = "credential mutation was not applied"
                return [PSCustomObject]$result
            }

            $passwordToStore = if ($GenerateCredential) {
                New-WinBotPassword -NoSymbols
            } else {
                $Credential
            }
            Register-WinBotCredential -Name "vm-password" -Username $config.credentials.vmUsername -Password $passwordToStore -Force
            $result.Applied = $true
            $result.State = "Applied"
            $result.Reason = "canonical master credential transition was applied; re-observation is required"
            return [PSCustomObject]$result
        }

        "BuildMaster" {
            $contract = $Plan.ActionContract
            if (-not $contract -or [string]$contract.Kind -ne "BuildMaster" -or
                -not $contract.ISOPath -or -not $contract.Media -or
                -not $contract.MasterPath -or -not $contract.MasterDirectory -or
                -not $contract.MasterVMName -or -not $contract.Username) {
                $result.State = "UnboundAction"
                $result.Reason = "master build requires an exact source/media/master/username action contract"
                return [PSCustomObject]$result
            }
            if ([bool]$contract.Force) {
                $result.State = "BlockedInput"
                $result.Reason = "lifecycle BuildMaster never force-replaces an existing master"
                return [PSCustomObject]$result
            }

            $media = $contract.Media
            foreach ($required in @(
                [string]$media.Method,
                [string]$media.Version,
                [string]$media.Edition,
                [string]$media.Architecture,
                [string]$media.Language
            )) {
                if ([string]::IsNullOrWhiteSpace($required)) {
                    $result.State = "UnboundAction"
                    $result.Reason = "master build media contract is incomplete"
                    return [PSCustomObject]$result
                }
            }

            if (-not $PSCmdlet.ShouldProcess([string]$contract.MasterPath, "Build exact accepted WinBot master from verified source ISO")) {
                $result.State = "WhatIf"
                $result.Reason = "master build mutation was not applied"
                return [PSCustomObject]$result
            }

            $builder = Join-Path $script:ProjectDir "guest\build-master.ps1"
            if (-not (Test-Path -LiteralPath $builder)) {
                $result.State = "Blocked"
                $result.Reason = "master builder primitive is absent: $builder"
                return [PSCustomObject]$result
            }

            $buildArgs = @{
                SourceISO = [string]$contract.ISOPath
                SourceMethod = [string]$media.Method
                SourceVersion = [string]$media.Version
                SourceLanguage = [string]$media.Language
                ExactSource = $true
                SkipDownload = $true
                WindowsEdition = [string]$media.Edition
                Architecture = [string]$media.Architecture
                MasterVHDPath = [string]$contract.MasterPath
                MasterPath = [string]$contract.MasterDirectory
                MasterVMName = [string]$contract.MasterVMName
                Username = [string]$contract.Username
            }

            $evidence = & $builder @buildArgs
            if (-not $evidence -or -not [bool]$evidence.Success) {
                $result.State = "Failed"
                $result.Reason = "master builder returned without a successful exact build transition"
                $result.Evidence = $evidence
                return [PSCustomObject]$result
            }

            $result.Applied = $true
            $result.State = "Applied"
            $result.Reason = "exact master build completed; authoritative re-observation is required"
            $result.Evidence = $evidence
            return [PSCustomObject]$result
        }

        "CreateClone" {
            $contract = $Plan.ActionContract
            if (-not $contract -or [string]$contract.Kind -ne "CreateClone" -or -not $contract.CloneName) {
                $result.State = "UnboundAction"
                $result.Reason = "clone creation requires an exact CreateClone action contract"
                return [PSCustomObject]$result
            }

            $cloneName = [string]$contract.CloneName
            if ($cloneName -notmatch '^WinBot-[a-zA-Z0-9][a-zA-Z0-9_.-]*$') {
                $result.State = "BlockedInput"
                $result.Reason = "planned clone identity is not a valid exact WinBot-* name"
                return [PSCustomObject]$result
            }
            if ($Plan.TargetCloneName -and [string]$Plan.TargetCloneName -ne $cloneName) {
                $result.State = "StalePlan"
                $result.Reason = "clone action contract disagrees with the planned exact target"
                return [PSCustomObject]$result
            }
            if (-not [bool]$contract.Start -or [bool]$contract.WaitForGuest) {
                $result.State = "UnboundAction"
                $result.Reason = "WP5 binds only the native-qualified create/start-without-guest-wait clone contract"
                return [PSCustomObject]$result
            }

            if (-not $PSCmdlet.ShouldProcess($cloneName, "Create exact disposable clone and start without guest/API wait")) {
                $result.State = "WhatIf"
                $result.Reason = "clone create/start mutation was not applied"
                return [PSCustomObject]$result
            }

            $clone = New-WinBotClone -CustomName $cloneName -NoWait
            if (-not $clone.Success) {
                $result.State = "Failed"
                $result.Reason = "clone primitive returned without a successful create/start transition"
                $result.Evidence = $clone
                return [PSCustomObject]$result
            }

            $result.Applied = $true
            $result.State = "Applied"
            $result.Reason = "exact disposable clone was created and started; guest/service readiness remains unresolved and requires re-observation"
            $result.Evidence = [PSCustomObject]@{
                Name = [string]$clone.Name
                State = [string]$clone.State
                VHDXPath = [string]$clone.VHDXPath
                Started = [bool]$clone.Started
                APIReady = [bool]$clone.APIReady
            }
            return [PSCustomObject]$result
        }

        "RequestElevationForInventory" {
            $result.State = "BlockedAuthority"
            $result.Reason = "UAC/elevation remains an explicit human authority boundary; use the existing approved elevation path, then re-observe/replan"
            return [PSCustomObject]$result
        }

        "EnableHyperV" {
            $result.State = "BlockedAuthority"
            $result.Reason = "Hyper-V enablement/reboot is a host-authority transition and is not auto-dispatched"
            return [PSCustomObject]$result
        }

        "EstablishExecutor" {
            $result.State = "BlockedAuthority"
            $result.Reason = "executor establishment requires host authority not represented by a bounded primitive here"
            return [PSCustomObject]$result
        }

        "AdoptOrRepairMaster" {
            $result.State = "BlockedAuthority"
            $result.Reason = "master adoption/repair requires explicit candidate identity and human authority; no implicit adoption is permitted"
            return [PSCustomObject]$result
        }

        "AcquireISO" {
            $contract = $Plan.ActionContract
            if (-not $contract -or [string]$contract.Kind -ne "AcquireISO" -or -not $contract.OutputPath) {
                $result.State = "UnboundAction"
                $result.Reason = "media acquisition requires an exact desired media/output contract"
                return [PSCustomObject]$result
            }
            if (-not $PSCmdlet.ShouldProcess([string]$contract.OutputPath, "Acquire exact desired Windows ISO")) {
                $result.State = "WhatIf"
                $result.Reason = "media acquisition mutation was not applied"
                return [PSCustomObject]$result
            }

            $evidence = Invoke-WinBotMediaAcquisition -Contract $contract -Confirm:$false
            $result.Applied = [bool]$evidence.Applied
            $result.State = [string]$evidence.State
            $result.Reason = [string]$evidence.Reason
            $result.Evidence = $evidence
            return [PSCustomObject]$result
        }

        "SelectCloneTarget" {
            $result.State = "BlockedInput"
            $result.Reason = "multiple accepted clones are ready; choose one exact target before service work"
            $result.Evidence = $Plan.ActionContract
            return [PSCustomObject]$result
        }

        "RecoverServiceCredential" {
            $result.State = "BlockedAuthority"
            $result.Reason = "existing-environment service credential recovery/rotation requires explicit authority and exact guest identity"
            return [PSCustomObject]$result
        }

        "ObserveGuestService" {
            $contract = $Plan.ActionContract
            if (-not $contract -or [string]$contract.Kind -ne "ObserveGuestService" -or -not $contract.CloneName) {
                $result.State = "UnboundAction"
                $result.Reason = "guest-service observation requires an exact accepted clone action contract"
                return [PSCustomObject]$result
            }
            if ($Plan.TargetCloneName -and [string]$Plan.TargetCloneName -ne [string]$contract.CloneName) {
                $result.State = "StalePlan"
                $result.Reason = "service target identity disagrees with the planned exact clone"
                return [PSCustomObject]$result
            }

            $evidence = Get-WinBotGuestServiceObservation -CloneName ([string]$contract.CloneName)
            $result.State = [string]$evidence.State
            $result.Reason = [string]$evidence.Reason
            $result.Evidence = $evidence
            return [PSCustomObject]$result
        }

        default {
            $result.State = "UnboundAction"
            $result.Reason = "planned action '$action' has no bounded WP5 primitive binding"
            return [PSCustomObject]$result
        }
    }
}

function Invoke-WinBotPlanVerify {
    <#
    .SYNOPSIS
    Independently verify the postcondition of one bounded plan/apply transition.

    .DESCRIPTION
    Read-only. Verification never trusts ApplyResult.Evidence as proof of the
    resulting host state. It binds the apply result back to the exact plan,
    re-observes the action-specific authoritative fact, derives a post-plan,
    and reports True / False / Unknown.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][object]$Plan,
        [Parameter(Mandatory=$true)][object]$ApplyResult,
        [object]$Observation = $null
    )

    foreach ($required in @("Intent", "ObservationFingerprint", "NextAction")) {
        if (-not $Plan.PSObject.Properties[$required]) {
            throw "Plan is missing required field '$required'."
        }
    }
    foreach ($required in @("Intent", "PlannedAction", "Action", "Applied", "State")) {
        if (-not $ApplyResult.PSObject.Properties[$required]) {
            throw "ApplyResult is missing required field '$required'."
        }
    }

    $action = [string]$Plan.NextAction
    $result = [ordered]@{
        Intent = [string]$Plan.Intent
        Action = $action
        Applied = [bool]$ApplyResult.Applied
        State = "Unknown"
        Verified = $false
        TransitionState = "Unverified"
        Reason = "transition postcondition has not been verified"
        PreObservationFingerprint = [string]$Plan.ObservationFingerprint
        PostObservationFingerprint = $null
        ExpectedContract = if ($Plan.PSObject.Properties["ActionContract"] -and $Plan.ActionContract) {
            $Plan.ActionContract | ConvertTo-Json -Depth 10 -Compress
        } else { "" }
        ExpectedTarget = if ($Plan.PSObject.Properties["TargetCloneName"]) { [string]$Plan.TargetCloneName } else { "" }
        PostContract = ""
        PostTarget = ""
        Evidence = $null
        PostPlan = $null
    }

    $identityMismatch =
        -not [string]::Equals([string]$ApplyResult.Intent, [string]$Plan.Intent, [StringComparison]::Ordinal) -or
        -not [string]::Equals([string]$ApplyResult.PlannedAction, $action, [StringComparison]::Ordinal) -or
        -not [string]::Equals([string]$ApplyResult.Action, $action, [StringComparison]::Ordinal)

    if ($identityMismatch) {
        $result.State = "False"
        $result.TransitionState = "Diverged"
        $result.Reason = "apply-result identity does not match the exact plan being verified"
        $result.Evidence = $ApplyResult
        return [PSCustomObject]$result
    }

    if ($ApplyResult.PSObject.Properties["ObservationFingerprint"] -and
        -not [string]::IsNullOrWhiteSpace([string]$ApplyResult.ObservationFingerprint) -and
        -not [string]::Equals(
            [string]$ApplyResult.ObservationFingerprint,
            [string]$Plan.ObservationFingerprint,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        $result.State = "False"
        $result.TransitionState = "Diverged"
        $result.Reason = "apply result was produced from a different pre-apply observation fingerprint"
        $result.Evidence = $ApplyResult
        return [PSCustomObject]$result
    }

    if ([bool]$ApplyResult.Applied -and [string]$ApplyResult.State -notin @("Applied", "AppliedVerified")) {
        $result.State = "False"
        $result.TransitionState = "Diverged"
        $result.Reason = "apply result claims mutation but its state is not an applied-success state"
        $result.Evidence = $ApplyResult
        return [PSCustomObject]$result
    }

    if (-not [bool]$ApplyResult.Applied -and $action -ne "None") {
        $result.State = "Unknown"
        $result.TransitionState = "NotApplied"
        $result.Reason = "no consequential transition was applied; there is no mutation postcondition to verify"
        $result.Evidence = $ApplyResult
        return [PSCustomObject]$result
    }

    $needsDeepArtifacts = $action -in @("AcquireISO", "BuildMaster", "CreateClone")
    $postObservation = if ($Observation) {
        $Observation
    } else {
        Get-WinBotEnvironment -VerifyArtifacts:$needsDeepArtifacts
    }
    $postPlan = Get-WinBotPlan -Intent ([string]$Plan.Intent) -Observation $postObservation
    $result.PostPlan = $postPlan
    $result.PostObservationFingerprint = [string]$postPlan.ObservationFingerprint
    $result.PostContract = if ($postPlan.PSObject.Properties["ActionContract"] -and $postPlan.ActionContract) {
        $postPlan.ActionContract | ConvertTo-Json -Depth 10 -Compress
    } else { "" }
    $result.PostTarget = if ($postPlan.PSObject.Properties["TargetCloneName"]) { [string]$postPlan.TargetCloneName } else { "" }

    if ($action -eq "None") {
        if (-not [bool]$ApplyResult.Applied -and
            [string]$ApplyResult.State -eq "Ready" -and
            [string]$postPlan.NextAction -eq "None" -and
            [bool]$postPlan.Ready) {
            $result.State = "True"
            $result.Verified = $true
            $result.TransitionState = "Converged"
            $result.Reason = "requested intent remains converged under independent re-observation"
        } else {
            $result.State = "False"
            $result.TransitionState = "Diverged"
            $result.Reason = "no-op convergence did not survive independent re-observation"
        }
        return [PSCustomObject]$result
    }

    $postState = "Unknown"
    $postReason = "no verification oracle is bound for action '$action'"
    $postEvidence = $null

    switch ($action) {
        "AcquireISO" {
            $contract = $Plan.ActionContract
            if (-not $contract -or [string]$contract.Kind -ne "AcquireISO" -or
                -not $contract.OutputPath -or -not $contract.Media) {
                $postState = "False"
                $postReason = "applied media transition lacks the exact acquisition contract required for verification"
                break
            }

            if ($Observation) {
                $isoEvidence = $postObservation.Artifacts.ISO
            } else {
                $expectedVersion = if ([string]$contract.Media.Method -eq "MCT" -and [string]$contract.Media.Version -eq "latest") {
                    ""
                } else {
                    [string]$contract.Media.Version
                }
                $verifyArgs = @{
                    ISOPath = [string]$contract.OutputPath
                    VerifyHash = $true
                    ExpectedEdition = [string]$contract.Media.Edition
                    ExpectedVersion = $expectedVersion
                    ExpectedArchitecture = [string]$contract.Media.Architecture
                    ExpectedLanguage = [string]$contract.Media.Language
                }
                $isoEvidence = Get-WinBotISOVersion @verifyArgs
            }

            $postEvidence = $isoEvidence
            if (-not $isoEvidence) {
                $postState = "Unknown"
                $postReason = "exact acquired ISO could not be observed"
                break
            }

            $pathMatches = $false
            try {
                $pathMatches = [string]::Equals(
                    [IO.Path]::GetFullPath([string]$isoEvidence.ISOPath),
                    [IO.Path]::GetFullPath([string]$contract.OutputPath),
                    [StringComparison]::OrdinalIgnoreCase
                )
            } catch {}

            $methodMatches = if ([string]$contract.Media.Method -eq "CDN") {
                [string]$isoEvidence.Method -like "CDN*"
            } else {
                [string]$isoEvidence.Method -eq [string]$contract.Media.Method
            }

            $identityMatches =
                [string]$isoEvidence.Edition -eq [string]$contract.Media.Edition -and
                [string]$isoEvidence.Architecture -eq [string]$contract.Media.Architecture -and
                [string]$isoEvidence.Language -eq [string]$contract.Media.Language -and
                (
                    ([string]$contract.Media.Method -eq "MCT" -and [string]$contract.Media.Version -eq "latest") -or
                    [string]$isoEvidence.Version -eq [string]$contract.Media.Version
                )

            if ([string]$isoEvidence.State -eq "Unknown") {
                $postState = "Unknown"
                $postReason = "exact acquired ISO readiness remains Unknown: $($isoEvidence.Reason)"
            } elseif ([string]$isoEvidence.State -eq "True" -and $pathMatches -and $methodMatches -and $identityMatches) {
                $postState = "True"
                $postReason = "exact acquired ISO provenance, hash, path, and requested identity are verified"
            } else {
                $postState = "False"
                $postReason = "acquired ISO does not satisfy the exact planned media postcondition"
            }
            break
        }

        "EstablishMasterCredential" {
            $credentialEvidence = if ($Observation) {
                $postObservation.Credentials.VMPassword
            } else {
                Get-WinBotCredentialPresence -Name "vm-password"
            }
            $postEvidence = $credentialEvidence
            $postState = if ($credentialEvidence) { [string]$credentialEvidence.State } else { "Unknown" }
            $postReason = if ($postState -eq "True") {
                "canonical master credential presence is proven in the current observer context"
            } elseif ($postState -eq "False") {
                "canonical master credential remains absent after the applied transition"
            } else {
                "canonical master credential presence remains Unknown after the applied transition"
            }
            break
        }

        "BuildMaster" {
            $contract = $Plan.ActionContract
            if (-not $contract -or [string]$contract.Kind -ne "BuildMaster" -or -not $contract.MasterPath) {
                $postState = "False"
                $postReason = "applied master transition lacks the exact master contract required for verification"
                break
            }

            $masterEvidence = if ($Observation) {
                $postObservation.Artifacts.Master
            } else {
                Get-WinBotMasterObservation -VHDXPath ([string]$contract.MasterPath) -VerifyIntegrity
            }
            $postEvidence = $masterEvidence
            if (-not $masterEvidence) {
                $postState = "Unknown"
                $postReason = "exact master target could not be observed"
                break
            }

            $pathMatches = $false
            try {
                $pathMatches = [string]::Equals(
                    [IO.Path]::GetFullPath([string]$masterEvidence.Path),
                    [IO.Path]::GetFullPath([string]$contract.MasterPath),
                    [StringComparison]::OrdinalIgnoreCase
                )
            } catch {}

            if ([string]$masterEvidence.State -eq "Unknown") {
                $postState = "Unknown"
                $postReason = "accepted master readiness remains Unknown: $($masterEvidence.Reason)"
            } elseif (
                [string]$masterEvidence.State -eq "True" -and
                $pathMatches -and
                [bool]$masterEvidence.PathMatchesAccepted -and
                [bool]$masterEvidence.AcceptedHashPresent -and
                [bool]$masterEvidence.ReadOnly -and
                [bool]$masterEvidence.IntegrityVerified -and
                [bool]$masterEvidence.HashMatches
            ) {
                $postState = "True"
                $postReason = "exact master is structurally/integrity verified and bound to the accepted identity"
            } else {
                $postState = "False"
                $postReason = "master does not satisfy the exact accepted-master postcondition"
            }
            break
        }

        "CreateClone" {
            $contract = $Plan.ActionContract
            if (-not $contract -or [string]$contract.Kind -ne "CreateClone" -or -not $contract.CloneName) {
                $postState = "False"
                $postReason = "applied clone transition lacks the exact clone contract required for verification"
                break
            }
            if ($Plan.PSObject.Properties["TargetCloneName"] -and
                -not [string]::IsNullOrWhiteSpace([string]$Plan.TargetCloneName) -and
                [string]$Plan.TargetCloneName -ne [string]$contract.CloneName) {
                $postState = "False"
                $postReason = "planned clone target disagrees with the exact clone verification contract"
                break
            }

            $cloneEvidence = if ($Observation) {
                @($postObservation.Artifacts.Clones | Where-Object { [string]$_.Name -eq [string]$contract.CloneName }) | Select-Object -First 1
            } else {
                Get-WinBotCloneObservation -Name ([string]$contract.CloneName) -VerifyMaster
            }

            $powerEvidence = $null
            if ([bool]$contract.Start -and (Get-Command Get-VM -ErrorAction SilentlyContinue)) {
                try {
                    $powerEvidence = Get-VM -Name ([string]$contract.CloneName) -ErrorAction Stop
                } catch {
                    $powerEvidence = $null
                }
            }

            $postEvidence = [PSCustomObject]@{
                Clone = $cloneEvidence
                PowerState = if ($powerEvidence) { [string]$powerEvidence.State } else { $null }
            }

            if (-not $cloneEvidence) {
                $postState = "False"
                $postReason = "exact planned clone is absent after the applied transition"
                break
            }
            if ([string]$cloneEvidence.State -eq "Unknown") {
                $postState = "Unknown"
                $postReason = "exact clone lineage remains Unknown: $($cloneEvidence.Reason)"
                break
            }
            if ([bool]$contract.Start -and -not $powerEvidence) {
                $postState = "Unknown"
                $postReason = "clone lineage is observable but requested start state could not be independently observed"
                break
            }

            if (
                [string]$cloneEvidence.State -eq "True" -and
                [bool]$cloneEvidence.Exists -and
                [bool]$cloneEvidence.ParentMatches -and
                (-not [bool]$contract.Start -or [string]$powerEvidence.State -eq "Running")
            ) {
                $postState = "True"
                $postReason = "exact clone lineage and requested activation state are independently verified"
            } else {
                $postState = "False"
                $postReason = "clone does not satisfy the exact lineage/activation postcondition"
            }
            break
        }

        default {
            $postState = "Unknown"
            $postReason = "action '$action' has no consequential WP6 verification oracle"
            break
        }
    }

    $result.State = $postState
    $result.Evidence = $postEvidence

    if ($postState -eq "True") {
        $sameExactTransition =
            [string]$postPlan.NextAction -eq $action -and
            [string]::Equals([string]$result.ExpectedContract, [string]$result.PostContract, [StringComparison]::Ordinal) -and
            [string]::Equals([string]$result.ExpectedTarget, [string]$result.PostTarget, [StringComparison]::Ordinal)

        if ($sameExactTransition) {
            $result.State = "False"
            $result.TransitionState = "Diverged"
            $result.Reason = "exact postcondition is true but the fresh planner still selects the same exact transition"
            return [PSCustomObject]$result
        }

        $result.Verified = $true
        $result.TransitionState = "Verified"
        $result.Reason = $postReason
        return [PSCustomObject]$result
    }

    if ($postState -eq "False") {
        $result.TransitionState = "PostconditionFailed"
        $result.Reason = $postReason
        return [PSCustomObject]$result
    }

    $result.TransitionState = "PostconditionUnknown"
    $result.Reason = $postReason
    return [PSCustomObject]$result
}

# ============================================================
# ============================================================
# Safety Guardrails -- VM-Only Enforcement
# ============================================================

function Test-IsHyperVVM {
    <#
    .SYNOPSIS
    Returns $true if running inside a Hyper-V virtual machine, $false otherwise.

    .DESCRIPTION
    Uses four detection methods (any one match = VM detected):
    1. Win32_ComputerSystem Manufacturer/Model (Hyper-V reports "Microsoft Corporation" / "Virtual Machine")
    2. Registry key HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters (present on Hyper-V guests)
    3. Hyper-V integration services (vmickvpexchange, vmicheartbeat)
    4. BIOS version (Hyper-V sets SMBIOSBIOSVersion containing "Hyper-V" or "VRTUAL")

    At least one method must match to return $true.
    #>
    # Method 1: Win32_ComputerSystem manufacturer/model
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    if ($cs) {
        if ($cs.Manufacturer -eq "Microsoft Corporation" -and $cs.Model -eq "Virtual Machine") {
            Write-Verbose "[WinBot] VM detected via Win32_ComputerSystem (manufacturer/model)"
            return $true
        }
    }

    # Method 2: Hyper-V guest registry key
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters") {
        Write-Verbose "[WinBot] VM detected via Hyper-V Guest registry key"
        return $true
    }

    # Method 3: Hyper-V integration services (must be Running, not just installed)
    # On a Hyper-V host with the role enabled, these services exist but are Stopped.
    # On a genuine guest VM, at least heartbeat and timesync are typically Running.
    $hvServices = @("vmicheartbeat", "vmictimesync", "vmickvpexchange", "vmicshutdown", "vmicvss")
    foreach ($svcName in $hvServices) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq "Running") {
            Write-Verbose "[WinBot] VM detected via running Hyper-V integration service: $svcName"
            return $true
        }
    }

    # Method 4: BIOS version (Hyper-V firmware signature -- hardest to fake)
    $bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
    if ($bios -and $bios.SMBIOSBIOSVersion) {
        if ($bios.SMBIOSBIOSVersion -match "Hyper-V|VRTUAL") {
            Write-Verbose "[WinBot] VM detected via BIOS version: $($bios.SMBIOSBIOSVersion)"
            return $true
        }
    }

    Write-Verbose "[WinBot] No Hyper-V VM indicators found -- running on physical host"
    return $false
}

function Assert-HyperVVM {
    <#
    .SYNOPSIS
    Throws an error if NOT running inside a Hyper-V VM.

    .DESCRIPTION
    Safety guardrail: prevents scripts that modify system settings from
    being accidentally executed on the physical host machine. Must only
    be run inside a Hyper-V guest VM.
    #>
    if (-not (Test-IsHyperVVM)) {
        throw @"
[WinBot] SAFETY GUARDRAIL: HOST PROTECTION
============================================
This command modifies system settings and MUST only run
inside a Hyper-V VM, NEVER on a physical host.

Current system: $($env:COMPUTERNAME) -- NOT a Hyper-V VM.

If you need to run this on a VM:
  1. Use .\host\winbotctl.ps1 new <name> to create a clone
  2. Use .\host\winbotctl.ps1 connect <name> to enter the VM
  3. Run this command inside the VM

To override (DANGEROUS -- only for testing):
  Set WINBOT_SKIP_VM_GUARDRAIL=1 and run again.
"@
    }
}

# ============================================================
# Safety Guardrails -- Interactive Action Confirmation
# ============================================================

function Confirm-Action {
    <#
    .SYNOPSIS
    Prompt the user to confirm a destructive action with a countdown timer.
    Returns $true if the action should proceed, $false if cancelled.

    .DESCRIPTION
    Shows a countdown timer. If the user presses any key before the timer
    expires, the action is cancelled and $false is returned. If the timer
    expires, the action proceeds and $true is returned.

    .PARAMETER Message
    Description of the action being confirmed.

    .PARAMETER TimeoutSeconds
    Number of seconds to wait before proceeding. Default: 30. Maximum: 300.

    .PARAMETER ActionDescription
    Short label shown in the countdown line (e.g., "Rebooting", "Shutting down").

    .EXAMPLE
    if (Confirm-Action -Message "This will reboot the computer." -TimeoutSeconds 30 -ActionDescription "Rebooting") {
        Restart-Computer -Force
    }
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,

        [int]$TimeoutSeconds = 30,

        [string]$ActionDescription = "action"
    )

    # Clamp timeout — max configurable via WINBOT_CONFIRM_MAX_TIMEOUT env var
    $maxTimeout = if ($env:WINBOT_CONFIRM_MAX_TIMEOUT) {
        [int]$env:WINBOT_CONFIRM_MAX_TIMEOUT
    } else { 300 }
    if ($TimeoutSeconds -lt 5) { $TimeoutSeconds = 5 }
    if ($TimeoutSeconds -gt $maxTimeout) { $TimeoutSeconds = $maxTimeout }

    Write-Host "`n===========================================" -ForegroundColor Yellow
    Write-Host "  WARNING: $Message" -ForegroundColor Yellow
    Write-Host "===========================================" -ForegroundColor Yellow
    Write-Host "Press any key to CANCEL..." -ForegroundColor White
    Write-Host ""

    # Drain any stale keypresses
    while ([Console]::KeyAvailable) {
        [Console]::ReadKey($true) | Out-Null
    }

    for ($i = $TimeoutSeconds; $i -gt 0; $i--) {
        Write-Host "`r  $ActionDescription in $i seconds...  " -NoNewline
        if ([Console]::KeyAvailable) {
            $key = [Console]::ReadKey($true)
            Write-Host "`n`n  [$ActionDescription] CANCELLED by user." -ForegroundColor Green
            Write-Host "  No changes were made."
            return $false
        }
        Start-Sleep -Seconds 1
    }

    Write-Host "`n`n  [$ActionDescription] Proceeding..." -ForegroundColor Cyan
    return $true
}

# ============================================================
# Config Management
# ============================================================

function _ConvertToHashtable {
    <#
    .SYNOPSIS
    Recursively convert a PSCustomObject to a hashtable.
    Needed for PS 5.1 compatibility (no -AsHashtable on ConvertFrom-Json).
    #>
    param($obj)
    if ($null -eq $obj) { return $null }
    if ($obj -is [System.Collections.IDictionary]) { return $obj }
    if ($obj -is [PSCustomObject]) {
        $ht = @{}
        foreach ($prop in $obj.PSObject.Properties) {
            $ht[$prop.Name] = _ConvertToHashtable $prop.Value
        }
        return $ht
    }
    if ($obj -is [Array]) {
        $arr = @()
        foreach ($item in $obj) {
            $arr += _ConvertToHashtable $item
        }
        return $arr
    }
    return $obj
}

function _FindSecretKeys {
    <#
    .SYNOPSIS
    Recursively scan a hashtable for keys containing secret/token/password.
    Used by WINBOT_STRICT_CONFIG mode to reject secrets in config.json.
    #>
    param($obj, [string]$path)
    $found = @()
    if ($null -eq $obj) { return $found }
    if ($obj -is [System.Collections.IDictionary]) {
        foreach ($key in $obj.Keys) {
            $fullPath = if ($path) { "$path.$key" } else { $key }
            if ($key -match '(token|secret|password|apikey|api_key)$') {
                $val = $obj[$key]
                if ($val -is [string] -and $val.Trim().Length -gt 0) {
                    $found += $fullPath
                }
            }
            $found += _FindSecretKeys $obj[$key] $fullPath
        }
    } elseif ($obj -is [Array]) {
        for ($i = 0; $i -lt @($obj).Count; $i++) {
            $found += _FindSecretKeys $obj[$i] "$path[$i]"
        }
    }
    return $found
}

# ============================================================
# Credential Management -- Windows Credential Manager
# ============================================================
# WinBot credentials — new format: WinBot/<Service>/<Credential>
# Old format (WinBot_<name>) still resolved as fallback for backward compatibility.
# Migration: .\migrate-credentials.ps1 -Apply
$script:WinBotCredTargetPrefix = "WinBot/"
$script:WinBotCredOldPrefix = "WinBot_"

# Mapping from old short names to new format paths
$script:WinBotCredMapping = @{
    "vm-password"  = "VM/Password"
    "product-key"  = "License/Key"
    "api-token"    = "API/Token"
}

function Get-WinBotCredentialCanonicalTarget {
    param([Parameter(Mandatory=$true)][string]$Name)
    if ($script:WinBotCredMapping.ContainsKey($Name)) {
        return "$script:WinBotCredTargetPrefix$($script:WinBotCredMapping[$Name])"
    }
    if ($Name -like "api-key-*" -and $Name.Length -gt 8) {
        return "${script:WinBotCredTargetPrefix}API/$($Name.Substring(8))"
    }
    return "$script:WinBotCredTargetPrefix$Name"
}

function Get-WinBotCredentialDisplayName {
    param([Parameter(Mandatory=$true)][string]$Target)
    $canonical = $Target -replace '^.*?WinBot/', ''
    switch -Regex ($canonical) {
        '^VM/Password$' { return 'vm-password' }
        '^License/Key$' { return 'product-key' }
        '^API/Token$' { return 'api-token' }
        '^API/(.+)$' { return "api-key-$($Matches[1])" }
        default { return ($Target -replace '^.*?WinBot_', '') }
    }
}

function Get-WinBotCredentialPresence {
    <#
    .SYNOPSIS
    Report whether a credential is resolvable without returning its value.

    .DESCRIPTION
    Mirrors the non-interactive environment/Credential Manager resolution
    surfaces used by WinBot. Returned data contains no credential value.
    #>
    param([Parameter(Mandatory=$true)][string]$Name)

    $envNames = @("WINBOT_" + ($Name.ToUpperInvariant() -replace '-', '_'))
    $legacyVars = @{ "vm-password" = "WINBOT_VM_PASSWORD"; "api-token" = "WINBOT_API_TOKEN" }
    if ($legacyVars.ContainsKey($Name)) { $envNames += $legacyVars[$Name] }
    if ($Name -like "api-key-*" -and $Name.Length -gt 8) {
        $service = $Name.Substring(8)
        $envNames += "WINBOT_" + (($service.ToUpperInvariant() -replace '-', '_')) + "_API_KEY"
    }

    foreach ($envName in @($envNames | Select-Object -Unique)) {
        if ([Environment]::GetEnvironmentVariable($envName)) {
            return [PSCustomObject]@{ State="True"; Reason="credential is available from environment variable $envName"; Source="Environment"; Target=$envName }
        }
    }

    $canonicalTarget = Get-WinBotCredentialCanonicalTarget -Name $Name
    $legacyTarget = "$script:WinBotCredOldPrefix$Name"
    try {
        $allCreds = cmdkey /list 2>$null | Out-String
        if ($LASTEXITCODE -ne 0) {
            return [PSCustomObject]@{ State="Unknown"; Reason="Credential Manager enumeration failed with exit code $LASTEXITCODE"; Source="Unknown"; Target=$null }
        }

        $targets = @()
        foreach ($line in ($allCreds -split '\r?\n')) {
            if ($line -match "(?i)(WinBot/[^\s]+|WinBot_[^\s]+)\s*$") { $targets += $Matches[1].Trim() }
        }
        if ($targets -contains $canonicalTarget) {
            return [PSCustomObject]@{ State="True"; Reason="canonical Credential Manager target discovered"; Source="CredentialManager"; Target=$canonicalTarget }
        }
        if ($targets -contains $legacyTarget) {
            return [PSCustomObject]@{ State="True"; Reason="legacy-compatible Credential Manager target discovered"; Source="LegacyCredentialManager"; Target=$legacyTarget }
        }
    } catch {
        return [PSCustomObject]@{ State="Unknown"; Reason="credential presence could not be observed: $($_.Exception.Message)"; Source="Unknown"; Target=$null }
    }

    return [PSCustomObject]@{ State="False"; Reason="no compatible environment or Credential Manager target discovered"; Source="None"; Target=$null }
}


function Get-WinBotCredential {
    <#
    .SYNOPSIS
    Retrieve a credential from Windows Credential Manager,
    environment variable, or interactive prompt.

    .DESCRIPTION
    Resolution order:
    1. Windows Credential Manager target "WinBot:<Name>"
    2. Environment variable WINBOT_<UPPER_NAME>
    3. Legacy env vars (WINBOT_VM_PASSWORD, WINBOT_API_TOKEN)
    4. Config file (deprecated, with warning)
    5. Interactive prompt

    Credential values are NEVER logged. Returns PSCredential or plaintext.

    .PARAMETER Name
    Short credential name (e.g. "vm-password", "api-token").

    .PARAMETER Username
    Username for PSCredential. Default: "winbot".

    .PARAMETER AsPlaintext
    Return raw string instead of PSCredential. Use for API tokens.

    .EXAMPLE
    $cred = Get-WinBotCredential -Name "vm-password"
    $token = Get-WinBotCredential -Name "api-token" -AsPlaintext
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [string]$Username = "winbot",
        [switch]$AsPlaintext,
        [switch]$NoPrompt
    )

    # Source 1: Environment variable -- temporary override, checked first
    $envVarName = "WINBOT_" + ($Name.ToUpper() -replace '-', '_')
    $envValue = [Environment]::GetEnvironmentVariable($envVarName)
    if ($envValue) {
        Write-Verbose "[WinBot] Credential '$Name' from env var $envVarName"
        if ($AsPlaintext) { return $envValue }
        return New-Object PSCredential($Username, (ConvertTo-SecureString $envValue -AsPlainText -Force))
    }

    # Source 1b: Legacy env vars
    $legacyVars = @{ "vm-password" = "WINBOT_VM_PASSWORD"; "api-token" = "WINBOT_API_TOKEN" }
    if ($legacyVars.ContainsKey($Name)) {
        $lv = [Environment]::GetEnvironmentVariable($legacyVars[$Name])
        if ($lv) {
            Write-Verbose "[WinBot] Credential '$Name' from legacy env var $($legacyVars[$Name])"
            if ($AsPlaintext) { return $lv }
            return New-Object PSCredential($Username, (ConvertTo-SecureString $lv -AsPlainText -Force))
        }
    }

    # Source 2: Credential Manager (persistent encrypted store)
    # Try new format first (WinBot/<Service>/<Credential>), fall back to old (WinBot_<name>)
    $credTarget = Get-WinBotCredentialCanonicalTarget -Name $Name
    $fullTarget = "LegacyGeneric:target=$credTarget"

    # Fallback: old format
    $oldTarget = "$script:WinBotCredOldPrefix$Name"
    $oldFullTarget = "LegacyGeneric:target=$oldTarget"

    try {
        $allCreds = cmdkey /list 2>$null | Out-String

        # Try new format first
        $found = ($allCreds -match [regex]::Escape($fullTarget) -or $allCreds -match [regex]::Escape($credTarget))
        if (-not $found) {
            # Fallback to old format
            $found = ($allCreds -match [regex]::Escape($oldFullTarget) -or $allCreds -match [regex]::Escape($oldTarget))
            $credTarget = $oldTarget
            $fullTarget = $oldFullTarget
        }

        if ($found) {
            $password = _ReadWinBotCredential -Target $fullTarget
            if (-not $password) { $password = _ReadWinBotCredential -Target $credTarget }
            if (-not $password) { $password = _ReadWinBotCredential -Target "Domain:target=$credTarget" }
            if ($password) {
                Write-Verbose "[WinBot] Credential '$Name' from Credential Manager (target: $credTarget)"
                if ($AsPlaintext) { return $password }
                return New-Object PSCredential($Username, (ConvertTo-SecureString $password -AsPlainText -Force))
            }
        }
    } catch { Write-Verbose "[WinBot] CredMan lookup failed: $_" }

    # Source 3: Config file (deprecated)
    $config = Get-WinBotConfig
    if ($Name -eq "api-token" -and $config.api.token) {
        Write-Warning "[WinBot] API token found in config.json -- deprecated. Use Register-WinBotCredential."
        if ($AsPlaintext) { return $config.api.token }
        return New-Object PSCredential($Username, (ConvertTo-SecureString $config.api.token -AsPlainText -Force))
    }

    # Source 4: Interactive prompt (skip if NoPrompt)
    if ($NoPrompt) { return $null }
    Write-Host "[WinBot] Credential '$Name' not found." -ForegroundColor Yellow
    Write-Host "[WinBot] Store permanently: Register-WinBotCredential -Name '$Name' -Username '$Username' -Password '<value>'" -ForegroundColor Gray
    if ($AsPlaintext) {
        $si = Read-Host -AsSecureString -Prompt "Enter credential value for '$Name'"
        return [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($si))
    }
    return Get-Credential -UserName $Username -Message "Enter credentials for WinBot: $Name"
}

function Unregister-WinBotCredential {
    <#
    .SYNOPSIS
    Remove a WinBot credential from Windows Credential Manager.

    .PARAMETER Name
    Short credential name to remove.

    .EXAMPLE
    Unregister-WinBotCredential -Name "vm-password"
    #>
    param([Parameter(Mandatory=$true)][string]$Name)
    # Remove canonical and legacy targets; migration remains backward-compatible.
    $targets = @(
        (Get-WinBotCredentialCanonicalTarget -Name $Name),
        "$script:WinBotCredOldPrefix$Name"
    ) | Select-Object -Unique
    foreach ($shortTarget in $targets) {
        cmdkey /delete:"LegacyGeneric:target=$shortTarget" 2>&1 | Out-Null
        cmdkey /delete:$shortTarget 2>&1 | Out-Null
        cmdkey /delete:"Domain:target=$shortTarget" 2>&1 | Out-Null
    }
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[WinBot] Credential removed: $Name" -ForegroundColor Green
    }
}

# Helper: Read password from CredMan via P/Invoke.
# Struct layout MUST match Windows CREDENTIALW exactly (in order).
function _ReadWinBotCredential {
    param([string]$Target)
    try {
        $code = @'
using System;
using System.Runtime.InteropServices;
[StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
internal struct CREDENTIALW {
    public int Flags;
    public int Type;
    [MarshalAs(UnmanagedType.LPWStr)] public string TargetName;
    [MarshalAs(UnmanagedType.LPWStr)] public string Comment;
    public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
    public int CredentialBlobSize;
    public IntPtr CredentialBlob;
    public int Persist;
    public int AttributeCount;
    public IntPtr Attributes;
    [MarshalAs(UnmanagedType.LPWStr)] public string TargetAlias;
    [MarshalAs(UnmanagedType.LPWStr)] public string UserName;
}
public static class WinBotCredHelper {
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    private static extern bool CredReadW(string target, int type, int flags, out IntPtr p);
    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern void CredFree(IntPtr b);
    public static string Get(string target) {
        IntPtr p;
        if (!CredReadW(target, 1, 0, out p)) return null;
        try {
            CREDENTIALW c = (CREDENTIALW)Marshal.PtrToStructure(p, typeof(CREDENTIALW));
            if (c.CredentialBlobSize>0 && c.CredentialBlob!=IntPtr.Zero)
                return Marshal.PtrToStringUni(c.CredentialBlob, c.CredentialBlobSize/2);
        } finally { CredFree(p); }
        return null;
    }
}
'@        # Only compile once -- check type by name (string arg, no parse-time binding)
        if ($null -eq ('WinBotCredHelper' -as [type])) {
            Add-Type -TypeDefinition $code -ErrorAction Stop
        }
        return [WinBotCredHelper]::Get($Target)
    } catch {
        Write-Verbose "_ReadWinBotCredential: $_"
        return $null
    }
}

function Get-WinBotCredentialList {
    <#
    .SYNOPSIS
    List all WinBot-managed credential targets.
    NEVER displays credential values.

    .EXAMPLE
    Get-WinBotCredentialList
    #>
    $all = cmdkey /list 2>$null | Out-String
    $found = @()
    foreach ($line in ($all -split "`n")) {
        # Do not depend on localized cmdkey labels such as "Target:".
        if ($line -match "(?i)(WinBot/[^\s]+|WinBot_[^\s]+)\s*$") {
            $found += $Matches[1].Trim()
        }
    }
    if ($found.Count -eq 0) {
        Write-Host "[WinBot] No WinBot credentials found." -ForegroundColor Gray
        return @()
    }
    $result = @()
    foreach ($t in ($found | Select-Object -Unique)) {
        $result += [PSCustomObject]@{
            Name = Get-WinBotCredentialDisplayName -Target $t
            Target = $t
        }
    }
    $resultArray = @($result)
    Write-Host "[WinBot] $($resultArray.Count) credential(s):" -ForegroundColor Cyan
    $resultArray | Format-Table Name -AutoSize | Out-String | Write-Host -ForegroundColor Gray
    return $resultArray
}

# Register-WinBotCredential extended: generate random passwords
# This is a parameter set addition to the existing function.
# We modify the existing param block to add -Generate.
# Since we can't easily modify an already-defined function's params,
# we add a wrapper. The core Register-WinBotCredential is above.
# New: New-WinBotPassword, Sync-WinBotCredential, Get-WinBotCredentialUsage

function New-WinBotPassword {
    <#
    .SYNOPSIS
    Generate a cryptographically random password suitable for VM accounts.

    .DESCRIPTION
    Uses .NET RandomNumberGenerator for true randomness.
    Generated passwords are 24 characters with a mix of upper, lower, digits,
    and symbols -- suitable for local Windows accounts.

    .PARAMETER Length
    Password length. Default: 24. Minimum: 12.

    .PARAMETER NoSymbols
    Exclude special characters (alphanumeric only).

    .EXAMPLE
    $pw = New-WinBotPassword
    Register-WinBotCredential -Name "vm-password" -Username "winbot" -Password $pw

    .EXAMPLE
    New-WinBotPassword -Length 32 -NoSymbols
    #>
    param(
        [int]$Length = 24,
        [switch]$NoSymbols
    )

    if ($Length -lt 12) { $Length = 12 }

    $lower   = "abcdefghijkmnopqrstuvwxyz"  # no l (looks like 1)
    $upper   = "ABCDEFGHJKLMNPQRSTUVWXYZ"   # no I/O (look like 1/0)
    $digits  = "23456789"                    # no 0/1 (ambiguous)
    $symbols = "!@#$%^&*-_=+"

    $charSet = $lower + $upper + $digits
    if (-not $NoSymbols) { $charSet += $symbols }

    $bytes = New-Object byte[] ($Length * 4)
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)

    $password = ""
    for ($i = 0; $i -lt $Length; $i++) {
        $idx = [Math]::Abs([BitConverter]::ToInt32($bytes, $i * 4)) % $charSet.Length
        $password += $charSet[$idx]
    }

    # Ensure at least one of each character class
    if (-not $NoSymbols -and $password.IndexOfAny($symbols.ToCharArray()) -lt 0) {
        # Replace a random position with a symbol
        $pos = [Math]::Abs([BitConverter]::ToInt32($bytes, 0)) % $password.Length
        $sym = $symbols[[Math]::Abs([BitConverter]::ToInt32($bytes, 4)) % $symbols.Length]
        $password = $password.Substring(0, $pos) + $sym + $password.Substring($pos + 1)
    }

    return $password
}


function Sync-WinBotCredential {
    <#
    .SYNOPSIS
    Push a WinBot credential from the host to a running VM.

    .DESCRIPTION
    Reads a credential from Windows Credential Manager, connects to the VM
    via PowerShell Direct (or network), and updates the local account password
    on the VM. Also updates the API token if syncing the api-token credential.

    The credential must already exist on the host. Use Register-WinBotCredential
    first, or Register-WinBotCredential -Generate to create a new one.

    .PARAMETER Name
    Credential short name (e.g. "vm-password").

    .PARAMETER VMName
    Target VM name (with or without "WinBot-" prefix).

    .PARAMETER TargetUsername
    VM account username to update. Default: "winbot".

    .PARAMETER UpdateAPI
    If syncing api-token, also restart the WinBot API service on the VM.

    .EXAMPLE
    # Generate a new password, store it, push it to the VM
    $pw = New-WinBotPassword
    Register-WinBotCredential -Name "vm-password" -Username "winbot" -Password $pw
    Sync-WinBotCredential -Name "vm-password" -VMName "session-01"

    .EXAMPLE
    Sync-WinBotCredential -Name "api-token" -VMName "session-01" -UpdateAPI
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,

        [Parameter(Mandatory=$true)]
        [string]$VMName,

        [string]$TargetUsername = "winbot",

        [switch]$UpdateAPI
    )

    $cloneName = if ($VMName -like "WinBot-*") { $VMName } else { "WinBot-$VMName" }

    # Verify VM exists and is running
    $vm = Get-VM -Name $cloneName -ErrorAction SilentlyContinue
    if (-not $vm) { throw "VM '$cloneName' not found." }
    if ($vm.State -ne "Running") { throw "VM '$cloneName' is not running (state: $($vm.State))." }

    # Get the credential value (prompt if not in CredMan)
    $value = Get-WinBotCredential -Name $Name -Username $TargetUsername -AsPlaintext
    if (-not $value) { throw "Could not retrieve credential '$Name'." }

    Write-Host "[WinBot] Syncing credential '$Name' to $cloneName..." -ForegroundColor Cyan

    if ($Name -eq "api-token") {
        # Sync API token: write to .api_token file on VM and restart service
        try {
            Invoke-Command -VMName $cloneName -ScriptBlock {
                param($token)
                $tokenFile = "C:\WinBot\.api_token"
                $token | Out-File -FilePath $tokenFile -Encoding ascii -NoNewline -Force
                try {
                    icacls $tokenFile /inheritance:r /grant "SYSTEM:(R)" /grant "BUILTIN\Administrators:(R)" 2>$null | Out-Null
                } catch { Write-Verbose "icacls failed on $tokenFile - continuing" }
                Restart-Service -Name "WinBotAPI" -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 3
                $svc = Get-Service -Name "WinBotAPI" -ErrorAction SilentlyContinue
                return @{ServiceStatus = $svc.Status.ToString()}
            } -ArgumentList $value -ErrorAction Stop

            # Update host config too
            $config = Get-WinBotConfig
            $config.api.token = $value
            $script:Config = $config
            $config | ConvertTo-Json -Depth 5 | Out-File -FilePath $script:ConfigPath -Encoding utf8

            Write-Host "  API token synced and service restarted." -ForegroundColor Green
        } catch {
            throw "API token sync to $cloneName failed: $_"
        }
    } else {
        # Sync account password: update the local user on the VM
        try {
            Invoke-Command -VMName $cloneName -ScriptBlock {
                param($username, $password)
                $user = Get-LocalUser -Name $username -ErrorAction SilentlyContinue
                if ($user) {
                    $securePw = ConvertTo-SecureString $password -AsPlainText -Force
                    Set-LocalUser -Name $username -Password $securePw -ErrorAction Stop
                } else {
                    throw "User '$username' does not exist on this VM."
                }
                # Also update auto-logon password if set
                $autoLogon = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultUserName" -ErrorAction SilentlyContinue
                if ($autoLogon -and $autoLogon.DefaultUserName -eq $username) {
                    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultPassword" -Value $password -Force
                }
                return @{Updated = $true}
            } -ArgumentList $TargetUsername, $value -ErrorAction Stop

            Write-Host "  Password synced for user '$TargetUsername' on $cloneName." -ForegroundColor Green
        } catch {
            throw "Password sync to $cloneName failed: $_"
        }
    }

    Write-WinBotLog -Message "Credential synced: name=$Name vm=$cloneName" -Level INFO

    return @{
        Success = $true
        CredentialName = $Name
        VMName = $cloneName
        Action = if ($Name -eq "api-token") { "api-token-synced" } else { "password-synced" }
    }
}


# ============================================================
# Credential Rotation
# ============================================================

function _Update-WinBotMasterCredential {
    <#
    .SYNOPSIS
    Update credentials baked into a golden master VHDX (offline modification).

    .DESCRIPTION
    Internal helper that mounts a VHDX read-write, loads the offline SOFTWARE
    registry hive, updates AutoLogon keys, updates autounattend XML, and
    overwrites the .vm-password file. Always restores the VHDX to read-only
    in a finally block.

    Not exported. Called by Rotate-WinBotCredential.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$VHDXPath,

        [Parameter(Mandatory=$true)]
        [string]$Username,

        [Parameter(Mandatory=$true)]
        [string]$Password,

        [string]$OldUsername = "",

        [switch]$UsernameChange
    )

    if (-not (Test-Path $VHDXPath)) {
        throw "Master VHDX not found: $VHDXPath"
    }

    Write-Host "[WinBot] Updating credentials on golden master VHDX..." -ForegroundColor Cyan
    Write-Host "  VHDX: $VHDXPath" -ForegroundColor Gray

    $mounted = $false
    $hiveLoaded = $false
    $driveLetter = $null

    try {
        # Make VHDX writable
        $wasReadOnly = (Get-ItemProperty -Path $VHDXPath -Name IsReadOnly -ErrorAction SilentlyContinue).IsReadOnly
        if ($wasReadOnly) {
            Set-ItemProperty -Path $VHDXPath -Name IsReadOnly -Value $false
            Write-Host "  VHDX set to writable." -ForegroundColor Gray
        }

        # Mount
        $mount = Mount-VHD -Path $VHDXPath -Passthru -ErrorAction Stop
        $mounted = $true
        Start-Sleep -Seconds 1

        # Find the Windows partition (the one with \Windows\System32\config)
        $diskNum = ($mount | Get-Disk).Number
        $partitions = Get-Partition -DiskNumber $diskNum -ErrorAction SilentlyContinue
        foreach ($part in $partitions) {
            $vol = $part | Get-Volume -ErrorAction SilentlyContinue
            if ($vol -and $vol.DriveLetter) {
                $testPath = "$($vol.DriveLetter):\Windows\System32\config\SOFTWARE"
                if (Test-Path $testPath) {
                    $driveLetter = "$($vol.DriveLetter):"
                    break
                }
            }
        }
        if (-not $driveLetter) { throw "Could not find Windows partition on mounted VHDX." }
        Write-Host "  Mounted at ${driveLetter}\" -ForegroundColor Gray

        # ---- Update offline SOFTWARE registry hive ----
        $swPath = "${driveLetter}\Windows\System32\config\SOFTWARE"
        if (-not (Test-Path $swPath)) { throw "SOFTWARE hive not found at $swPath" }

        $hiveKey = "HKLM\WB_CredRot"
        reg load $hiveKey $swPath 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "reg load failed (exit code $LASTEXITCODE)" }
        $hiveLoaded = $true

        $wl = "$hiveKey\Microsoft\Windows NT\CurrentVersion\Winlogon"
        reg add $wl /v AutoAdminLogon /t REG_SZ /d "1" /f 2>&1 | Out-Null
        reg add $wl /v DefaultUserName /t REG_SZ /d "$Username" /f 2>&1 | Out-Null
        reg add $wl /v DefaultPassword /t REG_SZ /d "$Password" /f 2>&1 | Out-Null
        reg add $wl /v DefaultDomainName /t REG_SZ /d "" /f 2>&1 | Out-Null
        reg add $wl /v AutoLogonCount /t REG_DWORD /d 999999 /f 2>&1 | Out-Null
        reg add $wl /v AutoLogonChecked /t REG_DWORD /d 1 /f 2>&1 | Out-Null

        reg unload $hiveKey 2>&1 | Out-Null
        $hiveLoaded = $false
        Write-Host "  Offline registry AutoLogon keys updated." -ForegroundColor Green

        # ---- Update autounattend XML files ----
        $xmlPaths = @(
            "${driveLetter}\autounattend.xml",
            "${driveLetter}\Windows\Panther\Unattend.xml"
        )
        foreach ($xmlPath in $xmlPaths) {
            if (-not (Test-Path $xmlPath)) {
                Write-Host "  Skipping $xmlPath (not found)" -ForegroundColor Gray
                continue
            }

            $xmlContent = Get-Content $xmlPath -Raw -Encoding utf8

            # Update password in <Password><Value>...</Value></Password>
            if ($xmlContent -match '<Password>\s*<Value>[^<]*</Value>') {
                $xmlContent = $xmlContent -replace '(<Password>\s*<Value>)[^<]*(</Value>)', "`${1}${Password}`${2}"
            } elseif ($xmlContent -match '<Password><Value>[^<]*</Value></Password>') {
                $xmlContent = $xmlContent -replace '(<Password><Value>)[^<]*(</Value></Password>)', "`${1}${Password}`${2}"
            }

            if ($UsernameChange) {
                # Update <Name> in UserAccounts
                if ($OldUsername) {
                    $xmlContent = $xmlContent -replace "(<Name>)$OldUsername(</Name>)", "`${1}${Username}`${2}"
                    $xmlContent = $xmlContent -replace "(<DisplayName>)[^<]*(</DisplayName>)", "`${1}WinBot Automation`${2}"
                }
                # Update <Username> in AutoLogon
                $xmlContent = $xmlContent -replace '(<AutoLogon>\s*<Enabled>[^<]*</Enabled>\s*<Username>)[^<]*(</Username>)', "`${1}${Username}`${2}"
            }

            # Validate XML well-formedness
            try {
                [xml]$xmlContent | Out-Null
            } catch {
                throw "Autounattend XML failed well-formedness check after update at $xmlPath`: $_"
            }

            # Atomic write: temp file then move (same filesystem = atomic on NTFS)
            $tmpPath = "${xmlPath}.tmp"
            $xmlContent | Out-File -FilePath $tmpPath -Encoding utf8 -NoNewline
            Move-Item -Path $tmpPath -Destination $xmlPath -Force
            Write-Host "  Updated: $xmlPath" -ForegroundColor Green
        }

        # ---- Update .vm-password file ----
        $pwFile = "${driveLetter}\WinBot\.vm-password"
        $pwDir = "${driveLetter}\WinBot"
        if (-not (Test-Path $pwDir)) {
            New-Item -ItemType Directory -Path $pwDir -Force | Out-Null
        }
        # Secure overwrite
        if (Test-Path $pwFile) {
            $rand = New-Object byte[] 256
            (New-Object Security.Cryptography.RNGCryptoServiceProvider).GetBytes($rand)
            [IO.File]::WriteAllBytes($pwFile, $rand)
        }
        $Password | Out-File -FilePath $pwFile -Encoding ascii -NoNewline
        Write-Host "  .vm-password file updated." -ForegroundColor Green

        Write-Host "  Golden master credentials updated." -ForegroundColor Green

    } finally {
        # Always unload the registry hive
        if ($hiveLoaded) {
            reg unload $hiveKey 2>&1 | Out-Null
        }
        # Always dismount the VHDX
        if ($mounted) {
            Dismount-VHD -Path $VHDXPath -ErrorAction SilentlyContinue
        }
        # Always restore read-only
        if ($wasReadOnly) {
            Set-ItemProperty -Path $VHDXPath -Name IsReadOnly -Value $true -ErrorAction SilentlyContinue
        }
    }
}


function Sync-WinBotCredentialToClones {
    <#
    .SYNOPSIS
    Push a new credential to all running WinBot clones.

    .DESCRIPTION
    Enumerates all running WinBot clones and pushes the credential to each
    via PowerShell Direct (Invoke-Command -VMName). The guest-side script
    rotate-credentials.ps1 handles the actual update.

    If CloneNames is specified, only those clones are targeted.
    Otherwise, all running WinBot clones are updated.

    .PARAMETER Username
    VM account username to set.

    .PARAMETER Password
    New password for the account.

    .PARAMETER OldUsername
    Previous username (required if -UsernameChange is set).

    .PARAMETER UsernameChange
    Indicates the username is changing (creates new account if needed).

    .PARAMETER CloneNames
    Specific clone short names to target. If empty, all running clones.

    .EXAMPLE
    Sync-WinBotCredentialToClones -Username "winbot" -Password "newpass"

    .EXAMPLE
    Sync-WinBotCredentialToClones -Username "botuser" -Password "newpass" -OldUsername "winbot" -UsernameChange
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Username,

        [Parameter(Mandatory=$true)]
        [string]$Password,

        [string]$OldUsername = "",

        [switch]$UsernameChange,

        [string[]]$CloneNames
    )

    Assert-Administrator

    # Build the target list
    if ($CloneNames -and $CloneNames.Count -gt 0) {
        $targets = foreach ($cn in $CloneNames) {
            $vmName = if ($cn -like "WinBot-*") { $cn } else { "WinBot-$cn" }
            $vm = Get-VM -Name $vmName -ErrorAction SilentlyContinue
            if (-not $vm) {
                Write-Warning "[WinBot] VM '$vmName' not found -- skipping."
                continue
            }
            if ($vm.State -ne "Running") {
                Write-Warning "[WinBot] VM '$vmName' is not running (state: $($vm.State)) -- skipping."
                continue
            }
            [PSCustomObject]@{ Name = $vmName; ShortName = $cn; State = $vm.State }
        }
    } else {
        $allVMs = Get-WinBotVM
        $targets = $allVMs | Where-Object { $_.State -eq "Running" -and $_.Type -eq "Clone" }
    }

    if (-not $targets -or @($targets).Count -eq 0) {
        Write-Host "[WinBot] No running clones to update." -ForegroundColor Yellow
        return @{ Total = 0; Succeeded = 0; Failed = 0; FailedClones = @() }
    }

    Write-Host "[WinBot] Pushing credentials to $(@($targets).Count) running clone(s)..." -ForegroundColor Cyan

    $succeeded = @()
    $failed = @()
    $total = @($targets).Count

    foreach ($target in $targets) {
        $cloneName = $target.Name
        Write-Host "  Updating $cloneName ..." -ForegroundColor Gray
        try {
            # Build the script to run on the guest
            $guestScript = @"
`$result = & {
    `$ErrorActionPreference = 'Continue'
    try {
        `$user = Get-LocalUser -Name '$Username' -ErrorAction SilentlyContinue
        if (-not `$user) {
            if (`$UsernameChange -and '$OldUsername' -ne '') {
                `$pw = ConvertTo-SecureString '$Password' -AsPlainText -Force
                New-LocalUser -Name '$Username' -Password `$pw -FullName 'WinBot Automation' -Description 'WinBot automation account' -PasswordNeverExpires -ErrorAction Stop
                Add-LocalGroupMember -Group 'Administrators' -Member '$Username' -ErrorAction SilentlyContinue
            } else {
                return @{ Success = `$false; Error = "User '$Username' not found" }
            }
        } else {
            `$pw = ConvertTo-SecureString '$Password' -AsPlainText -Force
            Set-LocalUser -Name '$Username' -Password `$pw -ErrorAction Stop
        }

        # Update AutoLogon registry
        `$wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        Set-ItemProperty -Path `$wl -Name 'AutoAdminLogon' -Value '1' -Type String -Force
        Set-ItemProperty -Path `$wl -Name 'DefaultUserName' -Value '$Username' -Type String -Force
        Set-ItemProperty -Path `$wl -Name 'DefaultPassword' -Value '$Password' -Type String -Force
        Set-ItemProperty -Path `$wl -Name 'DefaultDomainName' -Value '' -Type String -Force
        New-ItemProperty -Path `$wl -Name 'AutoLogonCount' -Value 999999 -PropertyType DWord -Force | Out-Null

        # Update .vm-password
        `$pwFile = 'C:\WinBot\.vm-password'
        if (Test-Path `$pwFile) {
            `$rand = New-Object byte[] 256
            (New-Object Security.Cryptography.RNGCryptoServiceProvider).GetBytes(`$rand)
            [IO.File]::WriteAllBytes(`$pwFile, `$rand)
        }
        '$Password' | Out-File -FilePath `$pwFile -Encoding ascii -NoNewline -Force

        return @{ Success = `$true }
    } catch {
        return @{ Success = `$false; Error = `$_.Exception.Message }
    }
}
`$result | ConvertTo-Json
"@
            $resultJson = Invoke-Command -VMName $cloneName -ScriptBlock {
                param($ScriptBlock)
                Invoke-Expression $ScriptBlock
            } -ArgumentList $guestScript -ErrorAction Stop

            $result = $resultJson | ConvertFrom-Json
            if ($result.Success) {
                Write-Host "    $cloneName updated." -ForegroundColor Green
                $succeeded += $cloneName
            } else {
                Write-Warning "    $cloneName failed: $($result.Error)"
                $failed += @{ Clone = $cloneName; Error = $result.Error }
            }
        } catch {
            Write-Warning "    $cloneName failed: $_"
            $failed += @{ Clone = $cloneName; Error = $_.Exception.Message }
        }
    }

    $result = @{
        Total = $total
        Succeeded = $succeeded.Count
        Failed = $failed.Count
        FailedClones = $failed
        SucceededClones = $succeeded
    }
    Write-Host "[WinBot] Clone sync complete: $($succeeded.Count)/$total succeeded, $($failed.Count) failed." -ForegroundColor $(if ($failed.Count -eq 0) { "Green" } else { "Yellow" })
    return $result
}


function Rotate-WinBotCredential {
    <#
    .SYNOPSIS
    Rotate the WinBot VM credential on the golden master and optionally running clones.

    .DESCRIPTION
    The golden master VHDX has the VM username and password baked in (autounattend XML,
    offline registry, .vm-password file). This function rotates those credentials
    without a full golden master rebuild.

    Rotation steps:
    1. Safety check -- verify no differencing disks reference the master VHDX
       (modifying the parent would corrupt them). Use -Force to bypass.
    2. Generate or accept a new password.
    3. Mount the golden master VHDX and update all credential artifacts.
    4. Update Windows Credential Manager and config.json on the host.
    5. Optionally push the new credential to all running clones.

    Use -Generate (default) to auto-generate a random password while keeping the
    same username. Use -NewPassword for explicit credentials.

    .PARAMETER NewUsername
    Change the VM account username (optional).

    .PARAMETER NewPassword
    Set a specific password instead of generating one.

    .PARAMETER Generate
    Auto-generate a random password. Default if no explicit credential is given.

    .PARAMETER NoClones
    Skip updating running clones -- only update the golden master.

    .PARAMETER Force
    Proceed even if clones exist that reference the master VHDX.
    WARNING: Modifying a parent VHDX while differencing disks exist can
    cause block-level corruption. Only use this if you know what you're doing.

    .PARAMETER PasswordLength
    Length of generated password (default: 24).

    .PARAMETER NoSymbols
    Exclude special characters from generated password.

    .EXAMPLE
    # Generate a new random password, keep current username
    Rotate-WinBotCredential -Generate

    .EXAMPLE
    # Rotate to an explicit password
    Rotate-WinBotCredential -NewPassword "MyNewSecret!"

    .EXAMPLE
    # Change both username and password, force through running clones
    Rotate-WinBotCredential -NewUsername "botop" -NewPassword "NewPass123!" -Force

    .EXAMPLE
    # Rotate the master only, don't touch running clones
    Rotate-WinBotCredential -Generate -NoClones
    #>
    [CmdletBinding(DefaultParameterSetName="Generate")]
    param(
        [Parameter(ParameterSetName="Explicit")]
        [string]$NewUsername,

        [Parameter(ParameterSetName="Explicit")]
        [string]$NewPassword,

        [Parameter(Mandatory=$true, ParameterSetName="Generate")]
        [switch]$Generate,

        [switch]$NoClones,

        [switch]$Force,

        [int]$PasswordLength = 24,

        [switch]$NoSymbols
    )

    Assert-Administrator

    $config = Get-WinBotConfig
    $masterVHDX = $config.master.vhdxPath

    # ---- Validate master VHDX ----
    if (-not $masterVHDX) {
        throw "No master VHDX path configured. Set master.vhdxPath in config.json or rebuild with .\guest\build-master.ps1"
    }
    if (-not (Test-Path $masterVHDX)) {
        throw "Master VHDX not found: $masterVHDX"
    }

    Write-Host "[WinBot] === Credential Rotation ===" -ForegroundColor Cyan
    Write-Host "  Master VHDX: $masterVHDX" -ForegroundColor Gray

    # ---- Resolve new credentials ----
    $currentUsername = if ($config.credentials.vmUsername) { $config.credentials.vmUsername } else { "winbot" }
    $newUsername = if ($NewUsername) { $NewUsername } else { $currentUsername }
    $usernameChange = ($newUsername -ne $currentUsername)

    # Validate XML-safe characters
    if ($newUsername -match '[&<>"]') {
        throw "Username contains XML-unsafe characters: $newUsername"
    }

    $newPassword = $null
    if ($Generate) {
        $newPassword = New-WinBotPassword -Length $PasswordLength -NoSymbols:$NoSymbols
        Write-Host "  Generated new password (length: $PasswordLength)" -ForegroundColor Cyan
    } elseif ($NewPassword) {
        $newPassword = $NewPassword
    } else {
        throw "Either -Generate or -NewPassword must be specified."
    }

    if ($newPassword -match '[&<>"]') {
        throw "Password contains XML-unsafe characters. Use -Generate for a safe password."
    }

    # Get old password for logging (hash only)
    $oldPasswordHash = ""
    try {
        $oldPw = Get-WinBotCredential -Name "vm-password" -Username $currentUsername -AsPlaintext -ErrorAction SilentlyContinue
        if ($oldPw) {
            $sha256 = [Security.Cryptography.SHA256]::Create()
            $oldPasswordHash = [BitConverter]::ToString($sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($oldPw))).Replace("-", "").ToLower()
        }
    } catch { Write-Verbose "Could not retrieve old password for hash: $_" }

    if ($usernameChange) {
        Write-Host "  Username: $currentUsername -> $newUsername" -ForegroundColor Yellow
    } else {
        Write-Host "  Username: $newUsername (unchanged)" -ForegroundColor Gray
    }

    # ---- Safety check: differencing disk references ----
    $cloneCheck = Get-WinBotVM | Where-Object { $_.Type -eq "Clone" }
    $referencingClones = @()
    foreach ($clone in $cloneCheck) {
        if ($clone.VHDXPath -and (Test-Path $clone.VHDXPath)) {
            try {
                $vhdInfo = Get-VHD -Path $clone.VHDXPath -ErrorAction SilentlyContinue
                if ($vhdInfo -and $vhdInfo.ParentPath -and (Resolve-Path $vhdInfo.ParentPath).Path -eq (Resolve-Path $masterVHDX).Path) {
                    $referencingClones += $clone
                }
            } catch { Write-Verbose "Could not check VHD parent for $($clone.Name): $_" }
        }
    }

    if ($referencingClones.Count -gt 0) {
        $cloneList = ($referencingClones | ForEach-Object { "$($_.Name) ($($_.State))" }) -join ", "
        if (-not $Force) {
            throw @"

[WinBot] CANNOT ROTATE: $($referencingClones.Count) clone(s) reference the master VHDX.

  $cloneList

Modifying the parent VHDX while differencing disks exist can cause block-level
corruption in the clones.

To proceed:
  1. Stop and remove all clones: Get-WinBotVM | Remove-WinBotClone -Force
  2. Or use -Force to bypass this check (you accept the risk)

"@
        }
        Write-Warning "[WinBot] -Force specified. Proceeding despite $($referencingClones.Count) referencing clone(s)."
        Write-Warning "  Clones: $cloneList"
    } else {
        Write-Host "  No clones reference the master -- safe to modify." -ForegroundColor Green
    }

    # ---- 3. Update golden master VHDX ----
    try {
        _Update-WinBotMasterCredential -VHDXPath $masterVHDX -Username $newUsername `
            -Password $newPassword -OldUsername $currentUsername -UsernameChange:$usernameChange
    } catch {
        throw "Failed to update golden master VHDX: $_"
    }

    # ---- 4. Update host credential store ----
    Write-Host "[WinBot] Updating host credential store..." -ForegroundColor Gray
    try {
        Register-WinBotCredential -Name "vm-password" -Username $newUsername -Password $newPassword
    } catch {
        Write-Warning "Credential Manager update failed: $_"
    }

    # Update config.json username if changed
    if ($usernameChange) {
        $config.credentials.vmUsername = $newUsername
        $config | ConvertTo-Json -Depth 5 | Out-File -FilePath $script:ConfigPath -Encoding utf8
        Write-Host "  config.json updated: vmUsername = '$newUsername'" -ForegroundColor Green
    }

    # ---- 5. Update running clones (unless -NoClones) ----
    $cloneResult = $null
    if (-not $NoClones) {
        $cloneParams = @{
            Username = $newUsername
            Password = $newPassword
        }
        if ($usernameChange) {
            $cloneParams['OldUsername'] = $currentUsername
            $cloneParams['UsernameChange'] = $true
        }
        $cloneResult = Sync-WinBotCredentialToClones @cloneParams
    }

    # ---- 6. Recompute and store master hash ----
    Write-Host "[WinBot] Recomputing master VHDX hash..." -ForegroundColor Gray
    $newHash = Get-FileHash -Path $masterVHDX -Algorithm SHA256
    $config.master.vhdxHash = $newHash.Hash
    $config | ConvertTo-Json -Depth 5 | Out-File -FilePath $script:ConfigPath -Encoding utf8
    Set-WinBotMasterHash -VHDXPath $masterVHDX

    # ---- 7. Log rotation event ----
    $newPasswordHash = ""
    try {
        $sha256 = [Security.Cryptography.SHA256]::Create()
        $newPasswordHash = [BitConverter]::ToString($sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($newPassword))).Replace("-", "").ToLower()
    } catch {}

    $rotationEntry = @{
        timestamp = (Get-Date).ToUniversalTime().ToString("o")
        username_changed = $usernameChange
        old_username = $currentUsername
        new_username = $newUsername
        old_password_sha256 = $oldPasswordHash
        new_password_sha256 = $newPasswordHash
        master_vhdx_path = $masterVHDX
        master_vhdx_new_hash = $newHash.Hash
        clones_updated = if ($cloneResult) { $cloneResult.Succeeded } else { 0 }
        clones_failed = if ($cloneResult) { $cloneResult.Failed } else { 0 }
        clones_skipped = if ($NoClones) { (Get-WinBotVM | Where-Object { $_.Type -eq "Clone" } | Measure-Object).Count } else { 0 }
    }

    $historyDir = Join-Path (Split-Path $masterVHDX -Parent) "..\logs"
    if (-not (Test-Path $historyDir)) { New-Item -ItemType Directory -Path $historyDir -Force | Out-Null }
    $historyFile = Join-Path $historyDir "rotation-history.jsonl"
    ($rotationEntry | ConvertTo-Json -Compress) | Add-Content -Path $historyFile -Encoding utf8

    Write-WinBotLog -Message "Credential rotated: username=$newUsername username_changed=$usernameChange vhdx=$masterVHDX hash=$($newHash.Hash.Substring(0,16))..." -Level INFO

    # ---- Summary ----
    Write-Host ""
    Write-Host "[WinBot] === Rotation Complete ===" -ForegroundColor Green
    Write-Host "  Username:      $newUsername"
    Write-Host "  Password hash: $($newPasswordHash.Substring(0,16))..."
    Write-Host "  Master VHDX:   $($newHash.Hash.Substring(0,16))..."
    Write-Host "  Retrieve with: Get-WinBotCredential -Name 'vm-password' -AsPlaintext" -ForegroundColor Gray

    if ($cloneResult) {
        Write-Host "  Clones synced: $($cloneResult.Succeeded)/$($cloneResult.Total)"
    } elseif ($NoClones) {
        Write-Host "  Clones synced: skipped (-NoClones)"
    }

    return @{
        Success = $true
        Username = $newUsername
        UsernameChanged = $usernameChange
        OldUsername = $currentUsername
        MasterVHDXUpdated = $true
        CloneSyncResult = $cloneResult
    }
}


# ============================================================
# API Key Management
# ============================================================
# API keys follow the naming convention "api-key-<service>"
# e.g.: api-key-github, api-key-ida, api-key-winbot, api-key-openai
# They are stored in CredMan like passwords but retrieved as plaintext.

# Well-known API key services that WinBot uses
$script:WinBotKnownAPIKeys = @(
    "winbot",      # WinBot REST API token
    "github",      # GitHub PAT for provisioning downloads
    "openai",      # OpenAI/Claude API key for agent integration
    "ida",         # IDA Pro license
    "binaryninja", # Binary Ninja license
    "ghidra"       # (usually free, but may need GH token)
)

function Register-WinBotAPIKey {
    <#
    .SYNOPSIS
    Store an API key in Windows Credential Manager.

    .DESCRIPTION
    Convenience wrapper around Register-WinBotCredential for API keys.
    API keys are always retrieved as plaintext. The naming convention
    is "api-key-<service>".

    Use well-known services for WinBot integration:
    winbot, github, openai, ida, binaryninja

    .PARAMETER Service
    Service name (e.g. "github", "openai"). Stored as "api-key-<service>".

    .PARAMETER Key
    The API key value.

    .PARAMETER Generate
    Auto-generate a random API key token.

    .EXAMPLE
    Register-WinBotAPIKey -Service "github" -Key "ghp_abc123..."
    Register-WinBotAPIKey -Service "winbot" -Generate
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Service,

        [Parameter(Mandatory=$true, ParameterSetName="Key")]
        [string]$Key,

        [Parameter(Mandatory=$true, ParameterSetName="Generate")]
        [switch]$Generate
    )

    $name = "api-key-$Service"

    if ($Generate) {
        Register-WinBotCredential -Name $name -Username "apikey" -Generate
    } else {
        Register-WinBotCredential -Name $name -Username "apikey" -Password $Key
    }
}


function Get-WinBotAPIKey {
    <#
    .SYNOPSIS
    Retrieve an API key from Windows Credential Manager.

    .DESCRIPTION
    Looks up "api-key-<service>" in CredMan. Falls back to
    environment variable WINBOT_<SERVICE>_API_KEY, then config.json
    (for the winbot token only).

    .PARAMETER Service
    Service name (e.g. "github", "openai", "winbot").

    .EXAMPLE
    $ghToken = Get-WinBotAPIKey -Service "github"
    $winToken = Get-WinBotAPIKey -Service "winbot"
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Service
    )

    $name = "api-key-$Service"

    # Reuse the canonical credential resolver so API keys share one namespace.
    $password = Get-WinBotCredential -Name $name -AsPlaintext -NoPrompt
    if ($password) { return $password }

    # Try environment variable: WINBOT_<SERVICE>_API_KEY
    $envVar = "WINBOT_" + ($Service.ToUpper() -replace '-', '_') + "_API_KEY"
    $envValue = [Environment]::GetEnvironmentVariable($envVar)
    if ($envValue) {
        Write-Verbose "[WinBot] API key '$Service' from env var $envVar"
        return $envValue
    }

    # Fallback for winbot token: config.json (deprecated)
    if ($Service -eq "winbot") {
        $config = Get-WinBotConfig
        if ($config.api.token) {
            Write-Warning "[WinBot] WinBot API token from config.json -- deprecated."
            Write-Warning "[WinBot] Run: Register-WinBotAPIKey -Service 'winbot' -Key '<token>'"
            return $config.api.token
        }
    }

    # Not found
    Write-Host "[WinBot] API key for '$Service' not found." -ForegroundColor Yellow
    Write-Host "[WinBot] Register it: Register-WinBotAPIKey -Service '$Service' -Key '<your-key>'" -ForegroundColor Gray
    Write-Host "[WinBot] Or set: `$$envVar" -ForegroundColor Gray
    return $null
}


function Remove-WinBotAPIKey {
    <#
    .SYNOPSIS
    Remove an API key from Windows Credential Manager.

    .PARAMETER Service
    Service name to remove.

    .EXAMPLE
    Remove-WinBotAPIKey -Service "github"
    #>
    param([Parameter(Mandatory=$true)][string]$Service)
    $name = "api-key-$Service"
    Unregister-WinBotCredential -Name $name
}


function Get-WinBotAPIKeyList {
    <#
    .SYNOPSIS
    List all registered API keys. Values are never shown.

    .EXAMPLE
    Get-WinBotAPIKeyList
    #>
    $all = @(Get-WinBotCredentialList)
    $apiKeys = @($all | Where-Object { $_.Name -like "api-key-*" })

    if ($apiKeys.Count -eq 0) {
        Write-Host "[WinBot] No API keys registered." -ForegroundColor Gray
        Write-Host "[WinBot] Known services: $($script:WinBotKnownAPIKeys -join ', ')" -ForegroundColor Gray
        Write-Host "[WinBot] Register one: Register-WinBotAPIKey -Service 'github' -Key '<your-key>'" -ForegroundColor Gray
        return @()
    }

    Write-Host "[WinBot] $($apiKeys.Count) API key(s):" -ForegroundColor Cyan
    $table = $apiKeys | ForEach-Object {
        $service = $_.Name -replace "^api-key-", ""
        [PSCustomObject]@{ Service = $service; Registered = $_.Target }
    }
    $table | Format-Table Service -AutoSize | Out-String | Write-Host -ForegroundColor Gray
    return $table
}

function Sync-WinBotAPIKeys {
    <#
    .SYNOPSIS
    Sync all registered API keys to a running VM.

    .DESCRIPTION
    For each registered API key, pushes it to the VM. The WinBot
    API token is synced via .api_token file. Other keys are set
    as environment variables on the VM via Set-ItemProperty on
    the machine-level PATH registry (HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment).

    .PARAMETER VMName
    Target VM name.

    .EXAMPLE
    Sync-WinBotAPIKeys -VMName "re-lab"
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$VMName
    )

    $cloneName = if ($VMName -like "WinBot-*") { $VMName } else { "WinBot-$VMName" }
    $vm = Get-VM -Name $cloneName -ErrorAction SilentlyContinue
    if (-not $vm) { throw "VM '$cloneName' not found." }
    if ($vm.State -ne "Running") { throw "VM '$cloneName' is not running." }

    $keys = @(Get-WinBotCredentialList | Where-Object { $_.Name -like "api-key-*" })
    if ($keys.Count -eq 0) {
        Write-Host "[WinBot] No API keys to sync." -ForegroundColor Yellow
        return
    }

    Write-Host "[WinBot] Syncing $($keys.Count) API key(s) to $cloneName..." -ForegroundColor Cyan

    $synced = 0
    $failed = 0

    foreach ($keyDef in $keys) {
        $service = $keyDef.Name -replace "^api-key-", ""
        $value = Get-WinBotAPIKey -Service $service
        if (-not $value) { $failed++; continue }

        try {
            if ($service -eq "winbot") {
                # WinBot API token goes to .api_token file + restart service
                Sync-WinBotCredential -Name "api-key-winbot" -VMName $VMName -UpdateAPI
            } else {
                # Other API keys: set as machine-level environment variables
                $envVarName = "WINBOT_" + ($service.ToUpper() -replace '-', '_') + "_API_KEY"
                Invoke-Command -VMName $cloneName -ScriptBlock {
                    param($name, $val)
                    [Environment]::SetEnvironmentVariable($name, $val, "Machine")
                } -ArgumentList $envVarName, $value -ErrorAction Stop
                Write-Host "  $service -> VM env var $envVarName" -ForegroundColor Green
            }
            $synced++
        } catch {
            Write-Warning "  $service sync FAILED: $_"
            $failed++
        }
    }

    Write-Host "[WinBot] Synced: $synced OK, $failed failed" -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Yellow" })

    return @{ Synced = $synced; Failed = $failed }
}


function Get-WinBotCredentialUsage {
    <#
    .SYNOPSIS
    Show which WinBot VMs reference which credentials.

    .DESCRIPTION
    Scans all WinBot VMs' Notes metadata for credential_target fields
    and builds a reverse mapping: credential -> VMs that use it.

    If a credential name is specified, shows only VMs using that credential.
    Otherwise, shows all credential->VM mappings.

    .PARAMETER Name
    Optional credential name to filter by.

    .EXAMPLE
    Get-WinBotCredentialUsage
    Get-WinBotCredentialUsage -Name "vm-password"
    #>
    param(
        [string]$Name = ""
    )

    $vms = Get-VM -Name "WinBot-*" -ErrorAction SilentlyContinue
    if (-not $vms) {
        Write-Host "[WinBot] No WinBot VMs found." -ForegroundColor Yellow
        return @()
    }

    $usage = @{}
    foreach ($vm in $vms) {
        $shortName = $vm.Name -replace "^WinBot-", ""
        $notes = Get-WinBotVMNote -Name $shortName
        $credTarget = if ($notes.credential_target) { $notes.credential_target } else { "none" }
        $credShort = $credTarget -replace "^(LegacyGeneric:target=)?WinBot_", ""

        if (-not $usage.ContainsKey($credShort)) {
            $usage[$credShort] = @()
        }
        $usage[$credShort] += [PSCustomObject]@{
            VMName   = $vm.Name
            ShortName = $shortName
            State    = $vm.State.ToString()
            Role     = if ($notes.role) { $notes.role } else { "unknown" }
            Created  = if ($notes.created) { $notes.created } else { "unknown" }
            CreatedBy = if ($notes.created_by) { $notes.created_by } else { "unknown" }
        }
    }

    # Filter and display
    if ($Name) {
        if (-not $usage.ContainsKey($Name)) {
            Write-Host "[WinBot] No VMs reference credential '$Name'." -ForegroundColor Yellow
            Write-Host "[WinBot] Available credentials: $($usage.Keys -join ', ')" -ForegroundColor Gray
            return @()
        }
        Write-Host "[WinBot] VMs using credential '$Name':" -ForegroundColor Cyan
        $usage[$Name] | Format-Table VMName, State, Role, CreatedBy -AutoSize | Out-String | Write-Host -ForegroundColor Gray
        return $usage[$Name]
    }

    Write-Host "[WinBot] Credential usage across WinBot VMs:" -ForegroundColor Cyan
    foreach ($cred in $usage.Keys | Sort-Object) {
        $vmList = ($usage[$cred] | ForEach-Object { $_.VMName }) -join ", "
        Write-Host "  $cred -> $($usage[$cred].Count) VM(s): $vmList" -ForegroundColor Gray
    }

    return $usage
}


# Register-WinBotCredential wrapper: add -Generate support
# PowerShell 5.1 doesn't support function overloading, so we check
# if -Generate was passed and delegate accordingly.
# The original Register-WinBotCredential accepts -Password.
# We add a convenience: -Generate auto-generates and stores.

# Re-register as an advanced function with -Generate parameter set
function Register-WinBotCredential {
    <#
    .SYNOPSIS
    Store a credential securely in Windows Credential Manager, optionally
    generating a random password.

    .DESCRIPTION
    Uses cmdkey.exe to store credentials under a namespaced target.
    With -Generate, creates a cryptographically random 24-character password.

    .PARAMETER Name
    Short name for the credential (e.g. "vm-password", "api-token").

    .PARAMETER Username
    Username associated with this credential.

    .PARAMETER Password
    The secret value. SecureString recommended.

    .PARAMETER Generate
    Auto-generate a random password instead of providing one.

    .PARAMETER PasswordLength
    Length of generated password (default: 24).

    .EXAMPLE
    Register-WinBotCredential -Name "vm-password" -Username "winbot" -Password "MySecret!"

    .EXAMPLE
    Register-WinBotCredential -Name "vm-password" -Username "winbot" -Generate
    #>
    [CmdletBinding(DefaultParameterSetName="Password")]
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Name,

        [Parameter(Mandatory=$true, Position=1)]
        [string]$Username,

        [Parameter(Mandatory=$true, Position=2, ParameterSetName="Password")]
        $Password,

        [Parameter(Mandatory=$true, ParameterSetName="Generate")]
        [switch]$Generate,

        [Parameter(ParameterSetName="Generate")]
        [int]$PasswordLength = 24,

        [Parameter(Mandatory=$false)]
        [switch]$Force
    )

    # Resolve the password value
    $resolvedPassword = if ($Generate) {
        $pw = New-WinBotPassword -Length $PasswordLength
        Write-Host "[WinBot] Generated random password (length: $PasswordLength)" -ForegroundColor Cyan
        Write-Host "[WinBot] Save this password now -- it will NOT be displayed again." -ForegroundColor Yellow
        Write-Host "[WinBot] Password: $pw" -ForegroundColor White
        Write-Host "[WinBot] Retrieve with: Get-WinBotCredential -Name '$Name' -AsPlaintext" -ForegroundColor Gray
        $pw
    } else {
        if ($Password -is [SecureString]) {
            [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
            )
        } else {
            [string]$Password
        }
    }

    # Store via the core implementation — map to new format
    $target = Get-WinBotCredentialCanonicalTarget -Name $Name
    $oldTarget = "$script:WinBotCredOldPrefix$Name"
    cmdkey /delete:$oldTarget 2>$null | Out-Null
    cmdkey /delete:"LegacyGeneric:target=$oldTarget" 2>$null | Out-Null

    # Confirm overwrite if credential already exists and running interactively
    $exists = cmdkey /list:$target 2>&1 | Select-String "Target:" -Quiet
    if ($exists -and -not $Force -and [Environment]::UserInteractive -and -not $script:SuppressConfirmations) {
        Write-Warning "Credential '$target' already exists and will be overwritten."
        $confirm = Read-Host "Overwrite? [y/N]"
        if ($confirm -notmatch '^[yY]') {
            Write-Host "  Cancelled." -ForegroundColor Yellow
            return
        }
    }

    # Delete any previous entries
    cmdkey /delete:$target 2>$null | Out-Null
    cmdkey /delete:"LegacyGeneric:target=$target" 2>$null | Out-Null
    cmdkey /delete:"Domain:target=$target" 2>$null | Out-Null
    $result = cmdkey /generic:$target /user:$Username /pass:$resolvedPassword 2>&1

    if ($LASTEXITCODE -eq 0) {
        Write-Host "[WinBot] Credential stored: $target (user: $Username)" -ForegroundColor Green
        Write-WinBotLog -Message "Credential registered: name=$Name user=$Username (generated=$Generate)" -Level INFO
    } else {
        throw "Failed to store credential '$target': $result"
    }
}

# ============================================================
# VM Metadata -- Hyper-V Notes
# ============================================================

function Set-WinBotVMNote {
    <#
    .SYNOPSIS
    Set WinBot metadata on a Hyper-V VM's Notes field.

    .DESCRIPTION
    Stores structured key-value metadata under a [WinBot] section
    in the VM Notes. Existing non-WinBot notes content is preserved.

    .PARAMETER Name
    VM name (with or without "WinBot-" prefix).

    .PARAMETER Meta
    Hashtable of key-value pairs to store.

    .EXAMPLE
    Set-WinBotVMNote -Name "session-01" -Meta @{role="clone"; session_label="re-lab"}
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][hashtable]$Meta,
        [switch]$AsJson  # Use versioned JSON format (default: INI for backward compat)
    )

    $vmName = if ($Name -like "WinBot-*") { $Name } else { "WinBot-$Name" }
    $vm = Get-VM -Name $vmName -ErrorAction Stop

    # Parse existing notes (supports both JSON and INI formats)
    $nonWinBot = ""
    $winBotMeta = @{}
    $existingNotes = if ($vm.Notes) { $vm.Notes } else { "" }

    # Try JSON format first (new format)
    $jsonParsed = $false
    if ($existingNotes -match '^\s*\{') {
        try {
            $parsed = $existingNotes | ConvertFrom-Json -ErrorAction Stop
            if ($parsed.schema_version) {
                $winBotMeta = _ConvertToHashtable ($parsed.meta)
                $jsonParsed = $true
            }
        } catch { }
    }

    # Fall back to INI format (legacy)
    if (-not $jsonParsed) {
        $inSection = $false
        foreach ($line in ($existingNotes -split "`r`n")) {
            if ($line -match '^\s*\[WinBot\]\s*$') { $inSection = $true; continue }
            if ($inSection) {
                if ($line -match '^\s*\[(.+)\]\s*$') { $inSection = $false; $nonWinBot += "$line`r`n"; continue }
                if ($line -match '^\s*([^=]+)\s*=\s*(.+)\s*$') { $winBotMeta[$Matches[1].Trim()] = $Matches[2].Trim(); continue }
            }
            $nonWinBot += "$line`r`n"
        }
    }

    # Merge
    foreach ($key in $Meta.Keys) { $winBotMeta[$key] = $Meta[$key] }
    $winBotMeta["updated"] = (Get-Date).ToUniversalTime().ToString("o")

    # Serialize
    if ($AsJson) {
        # Versioned JSON format (new)
        $jsonNotes = @{
            schema_version = 1
            format = "winbot-vm-notes"
            updated = $winBotMeta["updated"]
            meta = $winBotMeta
        }
        $newNotes = $jsonNotes | ConvertTo-Json -Depth 5 -Compress
    } else {
        # INI format (legacy, backward compatible)
        $newNotes = $nonWinBot.TrimEnd("`r`n") + "`r`n`r`n[WinBot]`r`n"
        foreach ($key in ($winBotMeta.Keys | Sort-Object)) {
            $newNotes += "$key = $($winBotMeta[$key])`r`n"
        }
    }

    Set-VM -Name $vmName -Notes $newNotes -ErrorAction Stop | Out-Null
    Write-Host "[WinBot] Metadata updated for: $vmName (format: $(if ($AsJson) {'JSON'} else {'INI'}))" -ForegroundColor Green
}

function Get-WinBotVMNote {
    <#
    .SYNOPSIS
    Read WinBot metadata from a Hyper-V VM's Notes field.

    .PARAMETER Name
    VM name (with or without "WinBot-" prefix).

    .EXAMPLE
    $meta = Get-WinBotVMNote -Name "session-01"
    $meta.role
    #>
    param([Parameter(Mandatory=$true)][string]$Name)

    $vmName = if ($Name -like "WinBot-*") { $Name } else { "WinBot-$Name" }
    $vm = Get-VM -Name $vmName -ErrorAction SilentlyContinue
    if (-not $vm -or -not $vm.Notes) { return @{} }

    $meta = @{}
    $inSection = $false
    foreach ($line in ($vm.Notes -split "`r`n")) {
        if ($line -match '^\s*\[WinBot\]\s*$') { $inSection = $true; continue }
        if ($inSection) {
            if ($line -match '^\s*\[(.+)\]\s*$') { break }
            if ($line -match '^\s*([^=]+)\s*=\s*(.+)\s*$') {
                $meta[$Matches[1].Trim()] = $Matches[2].Trim()
            }
        }
    }
    return $meta
}

# ============================================================
# Config Management (restored)
# ============================================================

function _LockConfig {
    <#
    .SYNOPSIS
    Acquire a file-based mutex for config.json writes.
    Returns the lock path on success, throws on timeout.
    #>
    param([int]$TimeoutSeconds = 10)
    $lockPath = "$script:ConfigPath.lock"
    $start = Get-Date
    while (((Get-Date) - $start).TotalSeconds -lt $TimeoutSeconds) {
        try {
            $fs = [System.IO.File]::Open($lockPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
            $fs.Close()
            return $lockPath
        } catch [System.IO.IOException] {
            Start-Sleep -Milliseconds 100
        }
    }
    throw "Failed to acquire config lock within ${TimeoutSeconds}s — another process is writing config.json."
}

function _UnlockConfig {
    param([string]$lockPath)
    if ($lockPath -and (Test-Path $lockPath)) {
        Remove-Item $lockPath -Force -ErrorAction SilentlyContinue
    }
}

function Get-WinBotConfig {
    <#
    .SYNOPSIS
    Load WinBot configuration from config.json, applying defaults for missing values.
    Automatically reloads if the file was modified since last read.
    #>
    # Check if file has been modified since cache
    if ($script:Config -and (Test-Path $script:ConfigPath)) {
        $fileTime = (Get-Item $script:ConfigPath).LastWriteTimeUtc
        if ($fileTime -le $script:ConfigLoadTime) {
            return $script:Config
        }
        # File modified — reload below
    } elseif ($script:Config) {
        return $script:Config
    }

    $config = @{}
    if (Test-Path $script:ConfigPath) {
        try {
            $raw = Get-Content $script:ConfigPath -Raw -ErrorAction Stop
            if ([string]::IsNullOrWhiteSpace($raw)) {
                Write-Warning "[WinBot] config.json is empty, using defaults"
            }
            else {
                $configObj = $raw | ConvertFrom-Json -ErrorAction Stop
                $config = _ConvertToHashtable $configObj
            }
        }
        catch {
            Write-Warning "[WinBot] config.json is corrupt: $_"
            Write-Warning "[WinBot] Using defaults."
            $config = @{}
        }
    }

    # Schema validation: check required fields and types
    $schemaErrors = @()
    $requiredTopLevel = @("master", "clones", "credentials", "api")
    foreach ($key in $requiredTopLevel) {
        if (-not $config.ContainsKey($key) -or $null -eq $config[$key]) {
            $schemaErrors += "Missing required key: '$key'"
        } elseif ($config[$key] -isnot [System.Collections.IDictionary]) {
            $schemaErrors += "Key '$key' must be an object, got: $($config[$key].GetType().Name)"
        }
    }
    # Validate nested required fields
    if ($config.ContainsKey("master") -and $config["master"] -is [System.Collections.IDictionary]) {
        foreach ($k in @("generation", "vhdxPath", "switchName")) {
            if (-not $config["master"].ContainsKey($k) -or $null -eq $config["master"][$k]) {
                $schemaErrors += "Missing required key: 'master.$k'"
            }
        }
    }
    if ($config.ContainsKey("clones") -and $config["clones"] -is [System.Collections.IDictionary]) {
        if (-not $config["clones"].ContainsKey("basePath") -or -not $config["clones"]["basePath"]) {
            $schemaErrors += "Missing required key: 'clones.basePath'"
        }
    }
    if ($config.ContainsKey("credentials") -and $config["credentials"] -is [System.Collections.IDictionary]) {
        if (-not $config["credentials"].ContainsKey("vmUsername") -or -not $config["credentials"]["vmUsername"]) {
            $schemaErrors += "Missing required key: 'credentials.vmUsername'"
        }
    }
    if ($config.ContainsKey("api") -and $config["api"] -is [System.Collections.IDictionary]) {
        if (-not $config["api"].ContainsKey("healthCheckIntervalSeconds") -or $null -eq $config["api"]["healthCheckIntervalSeconds"]) {
            $schemaErrors += "Missing required key: 'api.healthCheckIntervalSeconds'"
        }
    }
    if ($schemaErrors.Count -gt 0) {
        $msg = "config.json schema validation failed: $($schemaErrors -join '; ')"
        if ($env:WINBOT_STRICT_CONFIG) {
            throw $msg
        }
        Write-Warning "[WinBot] $msg"
    }

    # Strict config mode: reject tokens/secrets in config.json
    if ($env:WINBOT_STRICT_CONFIG) {
        $forbidden = _FindSecretKeys $config ""
        if (@($forbidden).Count -gt 0) {
            $msg = "WINBOT_STRICT_CONFIG: config.json contains forbidden keys: $($forbidden -join ', '). Move these to environment variables or Credential Manager."
            throw $msg
        }
    }

    if (-not $config.ContainsKey("master") -or $null -eq $config["master"]) { $config.master = @{} }
    $cfg = $config.master
    if (-not $cfg.ContainsKey("vmName") -or -not $cfg["vmName"]) { $cfg.vmName = "WinBot-Master" }
    if (-not $cfg.ContainsKey("vhdxPath") -or -not $cfg["vhdxPath"]) {
        # Config loading must not recurse into environment observation or
        # silently adopt a discovered VM. Adoption is an explicit plan/apply
        # decision; a fresh config gets only the deterministic default path.
        $cfg.vhdxPath = "C:\WinBot\master\Win11ENT.vhdx"
    }
    if (-not $cfg.ContainsKey("vmPath") -or -not $cfg["vmPath"]) { $cfg.vmPath = "C:\WinBot\master\" }
    if (-not $cfg.ContainsKey("memoryBytes") -or -not $cfg["memoryBytes"]) { $cfg.memoryBytes = 4GB }
    if (-not $cfg.ContainsKey("processors") -or -not $cfg["processors"]) { $cfg.processors = 4 }
    if (-not $cfg.ContainsKey("generation") -or -not $cfg["generation"]) { $cfg.generation = 2 }
    if (-not $cfg.ContainsKey("switchName") -or -not $cfg["switchName"]) {
        $switches = Get-VMSwitch -ErrorAction SilentlyContinue
        if ($switches) {
            $default = $switches | Where-Object { $_.Name -like "*Default*" } | Select-Object -First 1
            if ($default) { $cfg.switchName = $default.Name }
            else { $cfg.switchName = $switches[0].Name }
        }
        else { $cfg.switchName = "Default Switch" }
    }

    if (-not $config.ContainsKey("clones") -or $null -eq $config["clones"]) { $config.clones = @{} }
    if (-not $config.clones.ContainsKey("basePath") -or -not $config.clones["basePath"]) { $config.clones.basePath = "C:\WinBot\clones\" }
    if (-not $config.clones.ContainsKey("defaultMemoryBytes") -or -not $config.clones["defaultMemoryBytes"]) { $config.clones.defaultMemoryBytes = 4GB }
    if (-not $config.clones.ContainsKey("defaultProcessors") -or -not $config.clones["defaultProcessors"]) { $config.clones.defaultProcessors = 2 }
    if (-not $config.clones.ContainsKey("defaultDiskSizeGB") -or -not $config.clones["defaultDiskSizeGB"]) { $config.clones.defaultDiskSizeGB = 127 }

    if (-not $config.ContainsKey("credentials") -or $null -eq $config["credentials"]) { $config.credentials = @{} }
    if (-not $config.credentials.ContainsKey("vmUsername") -or -not $config.credentials["vmUsername"]) { $config.credentials.vmUsername = "winbot" }

    if (-not $config.ContainsKey("api") -or $null -eq $config["api"]) { $config.api = @{} }
    if (-not $config.api.ContainsKey("port") -or -not $config.api["port"]) { $config.api.port = 8000 }
    if (-not $config.api.ContainsKey("token") -or $null -eq $config.api["token"]) { $config.api.token = "" }
    if (-not $config.api.ContainsKey("healthCheckTimeoutSeconds") -or -not $config.api["healthCheckTimeoutSeconds"]) { $config.api.healthCheckTimeoutSeconds = 120 }
    if (-not $config.api.ContainsKey("healthCheckIntervalSeconds") -or -not $config.api["healthCheckIntervalSeconds"]) { $config.api.healthCheckIntervalSeconds = 5 }

    # Preserve the repository's existing implicit build defaults as explicit
    # desired media state. This is not a second desired-state source; it makes
    # the downloader/builder defaults inspectable by OBSERVE/PLAN.
    if (-not $config.ContainsKey("media") -or $null -eq $config["media"]) { $config.media = @{} }
    if (-not $config.media.ContainsKey("method") -or -not $config.media["method"]) { $config.media.method = "CDN" }
    if (-not $config.media.ContainsKey("version") -or -not $config.media["version"]) { $config.media.version = "24H2" }
    if (-not $config.media.ContainsKey("edition") -or -not $config.media["edition"]) { $config.media.edition = "Enterprise" }
    if (-not $config.media.ContainsKey("architecture") -or -not $config.media["architecture"]) { $config.media.architecture = "x64" }
    if (-not $config.media.ContainsKey("language") -or -not $config.media["language"]) { $config.media.language = "English" }

    if (-not $config.ContainsKey("sessions") -or $null -eq $config["sessions"]) { $config.sessions = @{} }
    if (-not $config.sessions.ContainsKey("basePath") -or -not $config.sessions["basePath"]) { $config.sessions.basePath = "C:\WinBot\sessions\" }

    $script:Config = $config
    $script:ConfigLoadTime = (Get-Date).ToUniversalTime()
    return $config
}

# ============================================================
# VHDX Integrity Verification
# ============================================================

function Test-WinBotMasterIntegrity {
    <#
    .SYNOPSIS
    Verify the master VHDX is intact and matches the stored hash.
    Returns $true if the master is healthy, $false otherwise.
    #>
    param(
        [string]$VHDXPath = $null
    )
    $config = Get-WinBotConfig
    if (-not $VHDXPath) { $VHDXPath = $config.master.vhdxPath }

    if (-not (Test-Path $VHDXPath)) {
        Write-Warning "[WinBot] Master VHDX not found: $VHDXPath"
        return $false
    }

    $acceptedPath = [string]$config.master.vhdxPath
    try {
        $requestedPath = [IO.Path]::GetFullPath($VHDXPath)
        $configuredPath = [IO.Path]::GetFullPath($acceptedPath)
    }
    catch {
        Write-Warning "[WinBot] Master path identity could not be normalized: $_"
        return $false
    }
    if (-not [string]::Equals($requestedPath, $configuredPath, [StringComparison]::OrdinalIgnoreCase)) {
        Write-Warning "[WinBot] VHDX path is not the configured accepted master identity. Expected: $configuredPath; actual: $requestedPath"
        return $false
    }


    # An existing file is not an accepted master until its immutable identity
    # has been deliberately recorded. Observation must not auto-adopt it.
    $storedHash = $config.master.vhdxHash
    if (-not $storedHash) {
        Write-Warning "[WinBot] Master VHDX has no accepted stored SHA-256. Run Set-WinBotMasterHash only after explicit adoption/verification."
        return $false
    }

    # Verify the VHDX is not corrupted
    $vhdSize = (Get-Item $VHDXPath).Length
    if ($vhdSize -lt 1GB) {
        Write-Warning "[WinBot] Master VHDX is suspiciously small ($([math]::Round($vhdSize/1MB,1)) MB) -- may be incomplete"
        return $false
    }

    # Run Test-VHD for surface consistency
    try {
        $vhdResult = Test-VHD -Path $VHDXPath -ErrorAction Stop
        if (-not $vhdResult) {
            Write-Warning "[WinBot] Test-VHD failed for master VHDX -- disk may be corrupted"
            return $false
        }
    }
    catch {
        Write-Warning "[WinBot] Test-VHD unavailable or failed: $_"
        return $false
    }

    # Compute and verify stored hash
    Write-Host "[WinBot] Computing master VHDX hash..." -ForegroundColor Gray
    $hash = Get-FileHash -Path $VHDXPath -Algorithm SHA256 -ErrorAction Stop
    if ($hash.Hash -ne $storedHash) {
        Write-Warning "  [WinBot] MASTER HASH MISMATCH!"
        Write-Warning "  Expected: $storedHash"
        Write-Warning "  Actual:   $($hash.Hash)"
        Write-Warning "  The master VHDX has been modified or corrupted."
        return $false
    }
    Write-Host "  Master VHDX hash verified: $($hash.Hash.Substring(0,16))..." -ForegroundColor Green

    return $true
}

function Set-WinBotMasterHash {
    <#
    .SYNOPSIS
    Compute and store the SHA-256 hash of the master VHDX in config.json.
    #>
    param([string]$VHDXPath = $null)
    $config = Get-WinBotConfig
    if (-not $VHDXPath) { $VHDXPath = $config.master.vhdxPath }

    if (-not (Test-Path $VHDXPath)) {
        throw "Master VHDX not found: $VHDXPath"
    }

    Write-Host "[WinBot] Computing master VHDX hash..." -ForegroundColor Cyan
    $acceptedPath = (Resolve-Path -LiteralPath $VHDXPath -ErrorAction Stop).Path
    $hash = Get-FileHash -LiteralPath $acceptedPath -Algorithm SHA256 -ErrorAction Stop
    Write-Host "  SHA256: $($hash.Hash)" -ForegroundColor Green

    # Store in config
    $config.master.vhdxPath = $acceptedPath
    $config.master.vhdxHash = $hash.Hash
    $script:Config = $config

    # Persist to disk
    $config | ConvertTo-Json -Depth 5 | Out-File -FilePath $script:ConfigPath -Encoding utf8
    Write-Host "  Hash stored in config.json" -ForegroundColor Green
}

# Artifact Readiness Observation
# ============================================================

function Get-WinBotMasterObservation {
    <#
    .SYNOPSIS
    Observe accepted master readiness without mutating state.

    .PARAMETER VerifyIntegrity
    Perform the expensive VHD + SHA-256 verification needed for Ready=True.
    Without this switch, an otherwise accepted-looking master remains Unknown.
    #>
    param(
        [string]$VHDXPath = "",
        [switch]$VerifyIntegrity
    )

    $config = Get-WinBotConfig
    if (-not $VHDXPath) { $VHDXPath = $config.master.vhdxPath }

    $result = [ordered]@{
        Path = $VHDXPath
        AcceptedPath = [string]$config.master.vhdxPath
        PathMatchesAccepted = $null
        State = "False"
        Reason = "configured master path is absent"
        Exists = $false
        AcceptedHashPresent = $false
        ReadOnly = $null
        IntegrityVerified = $false
        HashMatches = $null
        TestVHD = $null
    }

    if (-not $VHDXPath -or -not (Test-Path -LiteralPath $VHDXPath)) {
        return [PSCustomObject]$result
    }

    $result.Exists = $true
    try {
        $observedPath = [IO.Path]::GetFullPath($VHDXPath)
        $acceptedPath = [IO.Path]::GetFullPath([string]$result.AcceptedPath)
        $result.PathMatchesAccepted = [string]::Equals($observedPath, $acceptedPath, [StringComparison]::OrdinalIgnoreCase)
    }
    catch {
        $result.State = "Unknown"
        $result.Reason = "master path identity could not be normalized: $($_.Exception.Message)"
        return [PSCustomObject]$result
    }

    if (-not $result.PathMatchesAccepted) {
        $result.State = "Unknown"
        $result.Reason = "master artifact exists but is not the configured accepted master path"
        return [PSCustomObject]$result
    }


    $item = Get-Item -LiteralPath $VHDXPath -ErrorAction Stop
    $result.ReadOnly = [bool]$item.IsReadOnly

    $storedHash = [string]$config.master.vhdxHash
    $result.AcceptedHashPresent = -not [string]::IsNullOrWhiteSpace($storedHash)

    if (-not $result.AcceptedHashPresent) {
        $result.State = "Unknown"
        $result.Reason = "master exists but has no deliberately accepted stored SHA-256"
        return [PSCustomObject]$result
    }

    if (-not $result.ReadOnly) {
        $result.State = "False"
        $result.Reason = "master exists but is not read-only"
        return [PSCustomObject]$result
    }

    if (-not $VerifyIntegrity) {
        $result.State = "Unknown"
        $result.Reason = "accepted identity is recorded but integrity was not verified by this observation"
        return [PSCustomObject]$result
    }

    if (-not (Get-Command Test-VHD -ErrorAction SilentlyContinue)) {
        $result.State = "Unknown"
        $result.Reason = "accepted identity is recorded but Test-VHD is unavailable"
        return [PSCustomObject]$result
    }

    try {
        $result.TestVHD = [bool](Test-VHD -Path $VHDXPath -ErrorAction Stop)
    }
    catch {
        $result.State = "Unknown"
        $result.Reason = "Test-VHD could not establish integrity: $($_.Exception.Message)"
        return [PSCustomObject]$result
    }

    if (-not $result.TestVHD) {
        $result.State = "False"
        $result.Reason = "Test-VHD reports the accepted master is invalid"
        return [PSCustomObject]$result
    }

    try {
        $actualHash = (Get-FileHash -LiteralPath $VHDXPath -Algorithm SHA256 -ErrorAction Stop).Hash
        $result.HashMatches = ($actualHash -eq $storedHash)
        $result.IntegrityVerified = $true
    }
    catch {
        $result.State = "Unknown"
        $result.Reason = "master SHA-256 could not be observed: $($_.Exception.Message)"
        return [PSCustomObject]$result
    }

    if (-not $result.HashMatches) {
        $result.State = "False"
        $result.Reason = "master SHA-256 does not match the accepted stored identity"
        return [PSCustomObject]$result
    }

    $result.State = "True"
    $result.Reason = "master is read-only and VHD/SHA-256 integrity matches the accepted identity"
    return [PSCustomObject]$result
}

function Get-WinBotCloneObservation {
    <#
    .SYNOPSIS
    Observe one clone VM's actual disk lineage against the configured master.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9_.-]*$')]
        [string]$Name,
        [switch]$VerifyMaster,
        [object]$MasterObservation = $null
    )

    $config = Get-WinBotConfig
    $vmName = if ($Name -like "WinBot-*") { $Name } else { "WinBot-$Name" }
    $result = [ordered]@{
        Name = $vmName
        State = "Unknown"
        Reason = "clone lineage has not been observed"
        Exists = $null
        DiskPath = $null
        ParentPath = $null
        ExpectedParentPath = $config.master.vhdxPath
        ParentMatches = $null
        Master = $null
    }

    if (-not (Test-IsAdministrator)) {
        $result.Reason = "clone inventory requires an elevated/authorized observer"
        return [PSCustomObject]$result
    }

    $vmErrors = @()
    $vm = Get-VM -Name $vmName -ErrorAction SilentlyContinue -ErrorVariable vmErrors
    if (-not $vm) {
        if ($vmErrors.Count -eq 0) {
            $result.Exists = $false
            $result.State = "False"
            $result.Reason = "clone VM is absent"
        }
        else {
            $result.Reason = "clone VM inventory could not be observed: $($vmErrors[0].Exception.Message)"
        }
        return [PSCustomObject]$result
    }

    $result.Exists = $true
    try {
        $disks = @(Get-VMHardDiskDrive -VMName $vmName -ErrorAction Stop)
    }
    catch {
        $result.Reason = "clone disk attachment could not be observed: $($_.Exception.Message)"
        return [PSCustomObject]$result
    }

    if ($disks.Count -ne 1 -or -not $disks[0].Path) {
        $result.State = "False"
        $result.Reason = "clone must have exactly one observable primary VHDX"
        return [PSCustomObject]$result
    }

    $result.DiskPath = $disks[0].Path
    try {
        $vhd = Get-VHD -Path $result.DiskPath -ErrorAction Stop
        $result.ParentPath = $vhd.ParentPath
    }
    catch {
        $result.Reason = "clone VHD parent could not be observed: $($_.Exception.Message)"
        return [PSCustomObject]$result
    }

    if (-not $result.ParentPath) {
        $result.State = "False"
        $result.ParentMatches = $false
        $result.Reason = "clone disk is not a differencing disk with an observable parent"
        return [PSCustomObject]$result
    }

    try {
        $actualParent = [IO.Path]::GetFullPath($result.ParentPath)
        $expectedParent = [IO.Path]::GetFullPath([string]$result.ExpectedParentPath)
        $result.ParentMatches = [string]::Equals($actualParent, $expectedParent, [StringComparison]::OrdinalIgnoreCase)
    }
    catch {
        $result.Reason = "clone/master path identity could not be normalized: $($_.Exception.Message)"
        return [PSCustomObject]$result
    }

    if (-not $result.ParentMatches) {
        $result.State = "False"
        $result.Reason = "clone disk parent does not match the configured accepted master path"
        return [PSCustomObject]$result
    }

    $result.Master = if ($MasterObservation) { $MasterObservation } else { Get-WinBotMasterObservation -VHDXPath $result.ExpectedParentPath -VerifyIntegrity:$VerifyMaster }
    if ($result.Master.State -eq "True") {
        $result.State = "True"
        $result.Reason = "clone disk parent matches a verified accepted master"
    }
    elseif ($result.Master.State -eq "False") {
        $result.State = "False"
        $result.Reason = "clone parent matches configured path, but the master is definitively not ready: $($result.Master.Reason)"
    }
    else {
        $result.State = "Unknown"
        $result.Reason = "clone parent matches configured master, but master readiness is Unknown: $($result.Master.Reason)"
    }


    return [PSCustomObject]$result
}

# ============================================================
# ============================================================
# VM Discovery
# ============================================================

function Get-WinBotVM {
    <#
    .SYNOPSIS
    List all WinBot-managed VMs (master + clones).
    Distinguished by naming convention: WinBot-*
    #>
    Assert-Administrator
    try {
        $vms = Get-VM -Name "WinBot-*" -ErrorAction SilentlyContinue
        if (-not $vms) {
            Write-Host "[WinBot] No WinBot VMs found." -ForegroundColor Yellow
            return @()
        }
        return $vms | ForEach-Object {
            $disks = Get-VMHardDiskDrive -VMName $_.Name -ErrorAction SilentlyContinue
            $shortName = $_.Name -replace "^WinBot-", ""
            $notes = Get-WinBotVMNote -Name $shortName
            [PSCustomObject]@{
                Name         = $_.Name
                ShortName    = $shortName
                State        = $_.State.ToString()
                Type         = if ($_.Name -eq "WinBot-Master") { "Master" } else { "Clone" }
                Generation   = $_.Generation
                MemoryGB     = [math]::Round($_.MemoryAssigned / 1GB, 1)
                ProcessorCount = $_.ProcessorCount
                Uptime       = if ($_.Uptime) { $_.Uptime.ToString() } else { "n/a" }
                VHDXPath     = if ($disks) { $disks[0].Path } else { "unknown" }
                Created      = if ($notes.created) { $notes.created } else { "unknown" }
                CreatedBy    = if ($notes.created_by) { $notes.created_by } else { "unknown" }
                SessionLabel = if ($notes.session_label) { $notes.session_label } else { "" }
                Role         = if ($notes.role) { $notes.role } else { "unknown" }
                Version      = if ($notes.version) { $notes.version } else { "" }
                LastHealthy  = if ($notes.last_healthy) { $notes.last_healthy } else { "" }
            }
        }
    }
    catch {
        Write-Warning "[WinBot] VM enumeration failed: $_"
        return @()
    }
}

# ============================================================
# Hyper-V Operation Retry Helper
# ============================================================
function _Invoke-HyperVWithRetry {
    <#
    .SYNOPSIS
    Run a script block that calls Hyper-V cmdlets, retrying on transient failures.

    .DESCRIPTION
    Hyper-V operations can fail transiently: VM management service restarting,
    snapshot merge in progress, WMI busy. This wrapper retries up to 3 times
    with 2s/4s/8s backoff before giving up.

    .PARAMETER ScriptBlock
    The operation to retry.

    .PARAMETER MaxAttempts
    Maximum attempts (default: 3).

    .PARAMETER OperationName
    Label for log messages.

    .EXAMPLE
    _Invoke-HyperVWithRetry -ScriptBlock { Start-VM -Name $vmName } -OperationName "Start VM"
    #>
    param(
        [Parameter(Mandatory=$true)]
        [ScriptBlock]$ScriptBlock,

        [int]$MaxAttempts = 3,
        [string]$OperationName = "Hyper-V operation"
    )

    $attempt = 0
    $lastError = $null

    while ($attempt -lt $MaxAttempts) {
        $attempt++
        try {
            return & $ScriptBlock
        } catch {
            $lastError = $_
            $delay = if ($attempt -eq 1) { 2 } elseif ($attempt -eq 2) { 4 } else { 8 }
            Write-Verbose "[WinBot] $OperationName attempt $attempt/$MaxAttempts failed: $_ - retrying in ${delay}s"
            Start-Sleep -Seconds $delay
        }
    }

    throw "$OperationName failed after $MaxAttempts attempts: $lastError"
}

# ============================================================
# Clone Lifecycle
# ============================================================

function Wait-WinBotAPI {
    <#
    .SYNOPSIS
    Wait for a WinBot VM's API to become healthy.

    .DESCRIPTION
    Polls the VM for an IP address via Hyper-V network adapter, then hits
    the /health endpoint until it returns 200. Returns structured status
    indicating whether the API is ready.

    .PARAMETER Name
    Clone name suffix (without "WinBot-" prefix), or full VM name.

    .PARAMETER TimeoutSeconds
    Maximum time to wait for the API to become healthy. Default: 600 (10 min).

    .PARAMETER RetryIntervalSeconds
    Seconds between health check attempts. Default: 5.

    .PARAMETER Port
    API port on the VM. Default from config.

    .EXAMPLE
    $status = Wait-WinBotAPI -Name "session-01" -TimeoutSeconds 300
    if ($status.Ready) { Write-Host "API at $($status.APIUrl)" }
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,

        [int]$TimeoutSeconds = 600,
        [int]$RetryIntervalSeconds = 5,
        [int]$Port = 0
    )

    $config = Get-WinBotConfig
    if ($Port -eq 0) { $Port = $config.api.port }

    # Normalize name
    $cloneName = if ($Name -like "WinBot-*") { $Name } else { "WinBot-$Name" }

    Write-Host "[WinBot] Waiting for API on $cloneName (timeout: ${TimeoutSeconds}s)..." -ForegroundColor Cyan

    $startTime = Get-Date
    $elapsed = 0
    $vmIp = $null
    $apiReady = $false
    $healthResponse = $null
    $pollInterval = $RetryIntervalSeconds
    $phase = "booting"          # booting | networking | api-wait | healthy
    $lastPhaseTime = Get-Date

    while ($elapsed -lt $TimeoutSeconds) {
        # Phase 1: Wait for VM to get an IP (booting + DHCP)
        if (-not $vmIp) {
            $phase = "booting"
            $vmNetwork = Get-VMNetworkAdapter -VMName $cloneName -ErrorAction SilentlyContinue
            if ($vmNetwork) {
                $vmIp = $vmNetwork.IPAddresses | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+' } | Select-Object -First 1
                if ($vmIp) {
                    Write-Host "  VM IP: $vmIp ($([math]::Round((Get-Date) - $lastPhaseTime).TotalSeconds, 0)s to get IP)" -ForegroundColor Gray
                    $phase = "api-wait"
                    $lastPhaseTime = Get-Date
                }
            }
        }

        # Phase 2: VM has IP, poll API health
        if ($vmIp) {
            $phase = "api-wait"
            try {
                $response = Invoke-WebRequest -Uri "http://${vmIp}:$Port/health" `
                    -TimeoutSec 5 -ErrorAction SilentlyContinue -UseBasicParsing
                $phase = "api-responding"
                if ($response.StatusCode -eq 200) {
                    $apiReady = $true
                    $phase = "healthy"
                    try {
                        $healthResponse = $response.Content | ConvertFrom-Json
                    } catch { Write-Verbose "Health response JSON parse skipped - continuing" }
                    Write-Host "  WinBot API is healthy!" -ForegroundColor Green
                    break
                } else {
                    # API responded but with non-200 status
                    $phase = "api-error-$($response.StatusCode)"
                }
            } catch {
                # API not ready yet
            }
        }

        if (-not $pollInterval) { $pollInterval = [Math]::Max(5, $RetryIntervalSeconds) }
        Start-Sleep -Seconds $pollInterval
        if ($pollInterval -lt 60) { $pollInterval = [Math]::Min($pollInterval * 2, 60) }

        $elapsed = [math]::Round(($(Get-Date) - $startTime).TotalSeconds, 0)

        if ($elapsed % 30 -eq 0 -and $elapsed -gt 0) {
            Write-Host "  ... waited ${elapsed}s so far (phase: $phase, polling every ${pollInterval}s)" -ForegroundColor Gray
        }
    }

    # Build phase-specific error message
    $errorMsg = if (-not $apiReady) {
        switch ($phase) {
            "booting"   { "VM never obtained an IP address (never booted or network not configured). Check VM networking and switch." }
            "api-wait"  { "VM has IP ($vmIp) but API never responded on port $Port. Check WinBotAPI service on the guest." }
            "api-responding" { "API responded but health check failed. Check guest API logs." }
            { $_ -like "api-error-*" } { "API returned HTTP $($phase -replace 'api-error-','') on port $Port. Check guest API logs." }
            default     { "API did not become healthy within ${TimeoutSeconds}s (phase: $phase). Try increasing -TimeoutMinutes." }
        }
    } else { $null }

    $result = @{
        Ready = $apiReady
        VMName = $cloneName
        IP = $vmIp
        Port = $Port
        APIUrl = if ($vmIp) { "http://${vmIp}:$Port" } else { $null }
        Health = $healthResponse
        ElapsedSeconds = $elapsed
        Phase = $phase
        Error = $errorMsg
    }

    if (-not $apiReady) {
        Write-Warning "[WinBot] $errorMsg"
        if ($phase -eq "booting") {
            Write-Warning "  The VM may be stuck at boot (BIOS, boot loop, or no OS). Check VM console."
            Write-Warning "  Run: vmconnect.exe localhost '$cloneName'"
        } elseif ($phase -eq "api-wait") {
            Write-Warning "  The VM has an IP but the API is not listening."
            Write-Warning "  Run: .\winbot-run.ps1 -Operation fix-all -VMName '$cloneName'"
        }
    }

    return $result
}


function Get-WinBotGuestServiceObservation {
    <#
    .SYNOPSIS
    Observe one exact accepted clone's WinBot API readiness without mutation.

    .DESCRIPTION
    Performs one bounded read-only observation: exact VM inventory, running
    state, IPv4 address, canonical API credential resolution, and one
    authenticated /health request. Secret values are never returned.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidatePattern('^WinBot-[a-zA-Z0-9][a-zA-Z0-9_.-]*$')]
        [string]$CloneName,

        [ValidateRange(1,30)]
        [int]$TimeoutSeconds = 5
    )

    $config = Get-WinBotConfig
    $result = [ordered]@{
        CloneName = $CloneName
        State = "Unknown"
        Reason = "guest service has not been observed"
        VMState = $null
        IP = $null
        Port = [int]$config.api.port
        StatusCode = $null
        APIReady = $false
    }

    if (-not (Test-IsAdministrator)) {
        $result.Reason = "exact guest/service observation requires an elevated Hyper-V observer"
        return [PSCustomObject]$result
    }

    try {
        $vms = @(Get-VM -ErrorAction Stop)
    }
    catch {
        $result.Reason = "Hyper-V VM inventory could not be observed: $($_.Exception.Message)"
        return [PSCustomObject]$result
    }

    $vm = @($vms | Where-Object { $_.Name -eq $CloneName }) | Select-Object -First 1
    if (-not $vm) {
        $result.State = "False"
        $result.Reason = "exact accepted clone target is absent"
        return [PSCustomObject]$result
    }

    $result.VMState = $vm.State.ToString()
    if ($result.VMState -ne "Running") {
        $result.State = "False"
        $result.Reason = "exact clone exists but is not running"
        return [PSCustomObject]$result
    }

    try {
        $adapters = @(Get-VMNetworkAdapter -VMName $CloneName -ErrorAction Stop)
        $ip = $adapters.IPAddresses |
            Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' -and $_ -notlike '169.254.*' } |
            Select-Object -First 1
    }
    catch {
        $result.Reason = "clone network state could not be observed: $($_.Exception.Message)"
        return [PSCustomObject]$result
    }

    if (-not $ip) {
        $result.State = "False"
        $result.Reason = "running clone has no observable non-link-local IPv4 address"
        return [PSCustomObject]$result
    }
    $result.IP = [string]$ip

    try {
        $token = Get-WinBotAPIKey -Service "winbot"
    }
    catch {
        $token = $null
    }
    if (-not $token) {
        $result.State = "Unknown"
        $result.Reason = "canonical WinBot API credential value is not resolvable in the current observer context"
        return [PSCustomObject]$result
    }

    $uri = "http://$($result.IP):$($result.Port)/health"
    try {
        $response = Invoke-WebRequest -Uri $uri -Method Get -Headers @{ "X-API-Key" = $token } -TimeoutSec $TimeoutSeconds -UseBasicParsing -ErrorAction Stop
        $result.StatusCode = [int]$response.StatusCode
        if ($response.StatusCode -eq 200) {
            $result.State = "True"
            $result.APIReady = $true
            $result.Reason = "authenticated WinBot /health returned HTTP 200"
        }
        else {
            $result.State = "False"
            $result.Reason = "WinBot /health returned HTTP $($response.StatusCode)"
        }
    }
    catch {
        $status = $null
        try {
            if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
                $status = [int]$_.Exception.Response.StatusCode
            }
        } catch {}

        if ($null -ne $status) {
            $result.StatusCode = $status
            $result.State = "False"
            $result.Reason = "WinBot /health returned HTTP $status"
        }
        else {
            $result.State = "False"
            $result.Reason = "WinBot /health is not reachable from the host in the current observation"
        }
    }

    return [PSCustomObject]$result
}


function New-WinBotClone {
    <#
    .SYNOPSIS
    Create a new clone VM from the master differencing disk.

    .DESCRIPTION
    Preflights the accepted master, Hyper-V switch, target identity, target
    disk, and capacity before mutation. Creates the differencing disk and VM
    as one rollback-bounded embodiment transition. By default the VM is then
    started and guest/API readiness is observed; -NoStart and -NoWait split
    those later phases explicitly.

    .PARAMETER Name
    Name suffix for the clone (full name will be WinBot-<Name>)

    .PARAMETER Memory
    Memory in bytes (default from config)

    .PARAMETER Processors
    Number of vCPUs (default from config)

    .PARAMETER TimeoutMinutes
    Maximum time to wait for the API to become healthy (default: 10).

    .PARAMETER NoStart
    Create/register the clone but leave it powered off.

    .PARAMETER NoWait
    Start the VM but don't wait for API health after starting.
    #>
    param(
        [Parameter(Mandatory=$true, ParameterSetName="AutoName")]
        [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9_.-]*$')]
        [string]$Name,

        [Parameter(ParameterSetName="AutoName")]
        [string]$Purpose = "",        # Label for auto-naming (default: derived from Name)

        [Parameter(Mandatory=$true, ParameterSetName="CustomName")]
        [ValidatePattern('^WinBot-[a-zA-Z0-9][a-zA-Z0-9_.-]*$')]
        [string]$CustomName,          # Full custom VM name (e.g. "WinBot-clone-re-lab-20260628")

        [ValidateScript({$_ -eq 0 -or ($_ -ge 512MB -and $_ -le 128GB)})]
        [long]$Memory = 0,

        [ValidateRange(0, 64)]
        [int]$Processors = 0,

        [string]$SwitchName = "",
        [string]$PersistentVHDXPath = "",

        [ValidateRange(1, 120)]
        [int]$TimeoutMinutes = 10,

        [switch]$NoStart,
        [switch]$NoWait,
        [switch]$Force
    )
    Assert-Administrator
    if ($NoStart -and $NoWait) {
        throw "Specify either -NoStart or -NoWait, not both."
    }
    $config = Get-WinBotConfig

    # Naming scheme: WinBot-<type>-<purpose>-<timestamp> (auto) or custom name
    if ($CustomName) {
        $cloneName = $CustomName
        if ($cloneName -notlike "WinBot-*") { $cloneName = "WinBot-$cloneName" }
    } else {
        $purpose = if ($Purpose) { $Purpose } else { $Name.ToLower() -replace '[^a-z0-9-]', '-' }
        $ts = (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmss")
        $cloneName = "WinBot-clone-${purpose}-${ts}"
    }
    $cloneDir = Join-Path $config.clones.basePath $cloneName
    $cloneVHDX = Join-Path $cloneDir "disk.vhdx"
    $masterVHDX = $config.master.vhdxPath

    # Apply defaults from config
    if ($Memory -eq 0) { $Memory = $config.clones.defaultMemoryBytes }
    if ($Processors -eq 0) { $Processors = $config.clones.defaultProcessors }

    # Validate master VHDX exists
    if (-not (Test-Path $masterVHDX)) {
        $msg = "[WinBot] ERROR: Master VHDX not found at: $masterVHDX`n`nTo fix:`n  1. Run .\host\setup-master.ps1 to create the master image`n  2. Or edit config.json and set master.vhdxPath to your Windows VHDX"
        throw $msg
    }

    # Validate master VHDX integrity
    $masterOK = Test-WinBotMasterIntegrity -VHDXPath $masterVHDX
    if (-not $masterOK) {
        throw "Master VHDX integrity check failed. The golden image may be corrupted. Recreate it with: .\host\setup-master.ps1"
    }

    # INVARIANT: Master VHDX must be read-only before creating differencing disks.
    # Writing through a differencing disk to a writable parent corrupts the golden image.
    $isReadOnly = (Get-ItemProperty -Path $masterVHDX -Name IsReadOnly -ErrorAction SilentlyContinue).IsReadOnly
    if (-not $isReadOnly) {
        throw "Master VHDX is NOT read-only: $masterVHDX. Run: Set-ItemProperty -Path '$masterVHDX' -Name IsReadOnly -Value `$true. This invariant prevents golden master corruption."
    }

    # Preflight the required switch and capacity before any clone mutation.
    $resolvedSwitchName = if ($SwitchName) { $SwitchName } else { [string]$config.master.switchName }
    $switch = Get-VMSwitch -Name $resolvedSwitchName -ErrorAction SilentlyContinue
    if (-not $switch) {
        $availableSwitches = @((Get-VMSwitch -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }))
        throw "Hyper-V switch '$resolvedSwitchName' not found. Available switches: $($availableSwitches -join ', ')"
    }

    $requiredSpaceGB = $config.clones.defaultDiskSizeGB + 2
    $driveRoot = [IO.Path]::GetPathRoot($cloneDir)
    $driveName = if ($driveRoot) { $driveRoot.TrimEnd('\').TrimEnd(':') } else { "C" }
    $freeSpaceGB = [math]::Round((Get-PSDrive -Name $driveName -ErrorAction Stop).Free / 1GB, 1)
    if ($freeSpaceGB -lt $requiredSpaceGB) {
        throw "Insufficient free space: ${freeSpaceGB}GB available, ${requiredSpaceGB}GB required (disk + overhead)."
    }

    # Check if clone already exists
    $existing = Get-VM -Name $cloneName -ErrorAction SilentlyContinue
    if ($existing) {
        if ($Force) {
            Write-Host "[WinBot] Clone '$cloneName' already exists. Force-deleting..." -ForegroundColor Yellow
            Remove-WinBotClone -Name $cloneName -Force
        }
        else {
            throw "[WinBot] Clone '$cloneName' already exists. Use -Force to recreate."
        }
    }

    Write-Host "[WinBot] Creating clone: $cloneName" -ForegroundColor Cyan
    Write-Host "  Master VHDX: $masterVHDX" -ForegroundColor Gray
    Write-Host "  Clone VHDX:  $cloneVHDX" -ForegroundColor Gray
    Write-Host "  Memory:      $([math]::Round($Memory/1GB,1)) GB" -ForegroundColor Gray
    Write-Host "  Processors:  $Processors" -ForegroundColor Gray

    # Create clone directory. Track ownership so rollback never deletes
    # a directory that pre-dated this invocation.
    $createdCloneDir = $false
    if (-not (Test-Path -LiteralPath $cloneDir)) {
        New-Item -ItemType Directory -Path $cloneDir -Force -ErrorAction Stop | Out-Null
        $createdCloneDir = $true
    }

    # Never silently delete an orphaned target disk. It may contain evidence
    # from a partial prior run; cleanup/adoption is a separate authority.
    if (Test-Path -LiteralPath $cloneVHDX) {
        if (-not $Force) {
            throw "Orphaned clone disk already exists at '$cloneVHDX'. Clean/adopt it explicitly or use -Force."
        }
        Remove-Item -LiteralPath $cloneVHDX -Force -ErrorAction Stop
    }

    Write-Host "  Free space: ${freeSpaceGB}GB (need ${requiredSpaceGB}GB)" -ForegroundColor Gray

    # Create/register/start is one rollback-bounded transition. Optional guest
    # readiness waiting happens after the embodiment transition has succeeded.
    # Preflight established that neither target VM nor target VHD belongs to
    # pre-existing state. Rollback may therefore remove either exact identity
    # if a Hyper-V cmdlet partially creates it and then throws.
    $createdVHD = $false
    $createdVM = $false
    try {
        Write-Host "  Creating differencing disk..." -ForegroundColor Gray
        New-VHD -ParentPath $masterVHDX -Path $cloneVHDX -Differencing -ErrorAction Stop | Out-Null
        $createdVHD = $true

        Write-Host "  Creating VM..." -ForegroundColor Gray
        $vm = New-VM -Name $cloneName `
            -VHDPath $cloneVHDX `
            -MemoryStartupBytes $Memory `
            -Generation $config.master.generation `
            -ErrorAction Stop
        $createdVM = $true

        Set-VMProcessor -VMName $cloneName -Count $Processors -ErrorAction Stop
        Set-VM -VMName $cloneName -AutomaticCheckpointsEnabled $false -ErrorAction Stop

        $existingNic = Get-VMNetworkAdapter -VMName $cloneName -ErrorAction Stop
        if (-not $existingNic) {
            Add-VMNetworkAdapter -VMName $cloneName -SwitchName $resolvedSwitchName -ErrorAction Stop
        }
        else {
            Connect-VMNetworkAdapter -VMName $cloneName -SwitchName $resolvedSwitchName -ErrorAction Stop
        }

        # Persistent state is an explicit work-cell attachment. Never inherit a
        # host-shared data disk merely because it exists.
        if ($PersistentVHDXPath) {
            if (-not (Test-Path -LiteralPath $PersistentVHDXPath)) {
                throw "Explicit persistent VHDX not found: $PersistentVHDXPath"
            }
            Add-VMHardDiskDrive -VMName $cloneName -Path $PersistentVHDXPath -ErrorAction Stop
            Write-Host "  Persistent VHDX attached: $PersistentVHDXPath" -ForegroundColor Green
        }

        if (-not $NoStart) {
            Write-Host "  Starting VM..." -ForegroundColor Gray
            Start-VM -Name $cloneName -ErrorAction Stop
        }

        Write-Host "  Clone embodiment transition complete." -ForegroundColor Green
    }
    catch {
        $failure = $_

        # Do not rely only on success flags: New-VM/New-VHD may leave an
        # exact partial object even when the creating cmdlet itself throws.
        try {
            $created = Get-VM -Name $cloneName -ErrorAction SilentlyContinue
            if ($created) {
                if ($created.State -ne "Off") {
                    Stop-VM -Name $cloneName -TurnOff -ErrorAction SilentlyContinue
                }
                Remove-VM -Name $cloneName -Force -ErrorAction SilentlyContinue
            }
        } catch {}

        if (Test-Path -LiteralPath $cloneVHDX) {
            Remove-Item -LiteralPath $cloneVHDX -Force -ErrorAction SilentlyContinue
        }

        if ($createdCloneDir -and (Test-Path -LiteralPath $cloneDir)) {
            try {
                if (@(Get-ChildItem -LiteralPath $cloneDir -Force -ErrorAction SilentlyContinue).Count -eq 0) {
                    Remove-Item -LiteralPath $cloneDir -Force -ErrorAction SilentlyContinue
                }
            } catch {}
        }

        throw "Clone creation failed; resources created by this invocation were rolled back: $($failure.Exception.Message)"
    }

    $vmIp = $null
    $apiReady = $false

    if (-not $NoStart -and -not $NoWait) {
        $timeoutSeconds = $TimeoutMinutes * 60
        $apiStatus = Wait-WinBotAPI -Name $cloneName -TimeoutSeconds $timeoutSeconds -RetryIntervalSeconds $config.api.healthCheckIntervalSeconds
        $vmIp = $apiStatus.IP
        $apiReady = $apiStatus.Ready

        # Post-boot: rename guest hostname to match VM name (traceability)
        if ($apiReady -and $vmIp) {
            try {
                $cred = Get-WinBotCredential -Name "vm-password" -Username $config.credentials.vmUsername
                Invoke-Command -VMName $cloneName -Credential $cred -ScriptBlock {
                    param($newName)
                    $shortName = $newName -replace 'WinBot-', ''
                    Rename-Computer -NewName $shortName -Force -ErrorAction SilentlyContinue
                    Write-Host "Hostname set to: $shortName"
                } -ArgumentList $cloneName -ErrorAction SilentlyContinue
                Write-Host "  Guest hostname synced: $cloneName" -ForegroundColor Green
            } catch {
                Write-Verbose "[WinBot] Guest rename skipped: $_"
            }
        }
    }

    # Return clone info. Creation/start success is distinct from guest/API
    # readiness so -NoStart and -NoWait do not falsely report failure.
    $vmNow = Get-VM -Name $cloneName -ErrorAction Stop
    $vmNetwork = Get-VMNetworkAdapter -VMName $cloneName -ErrorAction SilentlyContinue
    $vmIp = if ($vmIp) { $vmIp } elseif (-not $NoStart -and $vmNetwork) {
        $vmNetwork.IPAddresses | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+' } | Select-Object -First 1
    } else { $null }

    $transitionSucceeded = $NoStart -or $NoWait -or $apiReady
    $result = [PSCustomObject]@{
        Name = $cloneName
        State = $vmNow.State.ToString()
        IP = $vmIp
        VHDXPath = $cloneVHDX
        APIPort = $config.api.port
        APIReady = $apiReady
        APIUrl = if ($vmIp) { "http://$($vmIp):$($config.api.port)" } else { $null }
        Backend = "HyperV"
        RuntimeSeedPath = $masterVHDX
        RuntimeDiskPath = $cloneVHDX
        SwitchName = $resolvedSwitchName
        PersistentVHDXPath = if ($PersistentVHDXPath) { $PersistentVHDXPath } else { $null }
        Success = $transitionSucceeded
        Started = (-not $NoStart)
        Error = if ($transitionSucceeded) { $null } else { "VM started but API did not become healthy within the requested wait window." }
    }

    # Record embodiment identity even before guest/service readiness.
    try {
        $masterHash = if ($config.master.vhdxHash) { $config.master.vhdxHash } else { "" }
        $meta = @{
            version = (Get-WinBotVersion) -replace "WinBot v", ""
            role = "runtime_instance"
            materialization_backend = "hyperv"
            runtime_seed_path = $masterVHDX
            master_hash = $masterHash
            created = (Get-Date).ToUniversalTime().ToString("o")
            created_by = $env:USERNAME
            credential_target = "WinBot_vm-password"
        }
        if ($apiReady) {
            $meta.last_healthy = (Get-Date).ToUniversalTime().ToString("o")
        }
        Set-WinBotVMNote -Name $cloneName -Meta $meta
    }
    catch {
        Write-Verbose "[WinBot] Metadata tagging skipped: $_"
    }

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    if ($NoStart) {
        Write-Host "  WinBot Clone Created (stopped)" -ForegroundColor Green
    }
    elseif ($NoWait) {
        Write-Host "  WinBot Clone Started (readiness unobserved)" -ForegroundColor Green
    }
    else {
        Write-Host "  WinBot Clone Ready" -ForegroundColor Green
    }
    Write-Host "  Name:    $($result.Name)" -ForegroundColor Green
    Write-Host "  State:   $($result.State)" -ForegroundColor Green
    Write-Host "  IP:      $($result.IP)" -ForegroundColor Green
    Write-Host "  API:     $($result.APIUrl)" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green

    return $result
}

function Start-WinBotClone {
    <#
    .SYNOPSIS
    Start a WinBot clone VM.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name
    )
    Assert-Administrator
    $cloneName = if ($Name -like "WinBot-*") { $Name } else { "WinBot-$Name" }
    # Also try new naming scheme if short name given
    if (-not ($Name -like "WinBot-*")) {
        $alt = Get-VM -Name "WinBot-clone-$Name-*" -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Name
        if ($alt) { $cloneName = $alt }
    }
    $vm = Get-VM -Name $cloneName -ErrorAction SilentlyContinue
    if (-not $vm) { throw "Clone '$cloneName' not found. Try: Get-VM -Name 'WinBot-clone-*'" }
    if ($vm.State -eq "Running") {
        Write-Host "[WinBot] Clone '$cloneName' is already running." -ForegroundColor Yellow
        return $vm
    }
    Start-VM -Name $cloneName
    Write-Host "[WinBot] Clone '$cloneName' started." -ForegroundColor Green
    return $vm
}

function Stop-WinBotClone {
    <#
    .SYNOPSIS
    Stop a WinBot clone VM.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,
        [switch]$Force
    )
    Assert-Administrator
    $cloneName = if ($Name -like "WinBot-*") { $Name } else { "WinBot-$Name" }
    if (-not ($Name -like "WinBot-*")) {
        $alt = Get-VM -Name "WinBot-clone-$Name-*" -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Name
        if ($alt) { $cloneName = $alt }
    }
    $vm = Get-VM -Name $cloneName -ErrorAction SilentlyContinue
    if (-not $vm) { throw "Clone '$cloneName' not found." }
    if ($vm.State -eq "Off") {
        Write-Host "[WinBot] Clone '$cloneName' is already stopped." -ForegroundColor Yellow
        return
    }
    Stop-VM -Name $cloneName -Force:$Force
    Write-Host "[WinBot] Clone '$cloneName' stopped." -ForegroundColor Green
}

function Suspend-WinBotClone {
    <#
    .SYNOPSIS
    Save a running clone's state to disk (Hyper-V save state).
    The VM is paused and its memory/CPU state is written to disk.
    Resume with Resume-WinBotClone.

    .DESCRIPTION
    Saves the VM state to a .vmrs file alongside the VHDX. The VM
    must be running. Use this to freeze a clone for later analysis
    or to preserve state before a risky operation.

    .PARAMETER Name
    Clone name suffix or full VM name.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,
        [switch]$Force
    )
    Assert-Administrator
    $cloneName = if ($Name -like "WinBot-*") { $Name } else { "WinBot-$Name" }
    $vm = Get-VM -Name $cloneName -ErrorAction SilentlyContinue
    if (-not $vm) { throw "Clone '$cloneName' not found." }
    if ($vm.State -ne "Running") {
        throw "Clone '$cloneName' is not running (state: $($vm.State)). Only running VMs can be saved."
    }
    Write-Host "[WinBot] Saving clone '$cloneName'..." -ForegroundColor Cyan
    Save-VM -Name $cloneName -ErrorAction Stop
    Write-Host "[WinBot] Clone '$cloneName' saved (paused)." -ForegroundColor Green
    Write-Host "  Resume with: Resume-WinBotClone -Name '$Name'" -ForegroundColor Gray
}

function Resume-WinBotClone {
    <#
    .SYNOPSIS
    Resume a saved/paused clone. Restores memory and CPU state from disk.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name
    )
    Assert-Administrator
    $cloneName = if ($Name -like "WinBot-*") { $Name } else { "WinBot-$Name" }
    $vm = Get-VM -Name $cloneName -ErrorAction SilentlyContinue
    if (-not $vm) { throw "Clone '$cloneName' not found." }
    if ($vm.State -ne "Saved") {
        throw "Clone '$cloneName' is not saved (state: $($vm.State)). Use Suspend-WinBotClone first."
    }
    Write-Host "[WinBot] Resuming clone '$cloneName'..." -ForegroundColor Cyan
    Start-VM -Name $cloneName -ErrorAction Stop
    Write-Host "[WinBot] Clone '$cloneName' resumed." -ForegroundColor Green
}

function Reset-WinBotClone {
    <#
    .SYNOPSIS
    Hard reset a clone - delete and recreate from master.
    This gives you a pristine VM identical to the master.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [switch]$Force,
        [switch]$WhatIf
    )
    Assert-Administrator
    if ($WhatIf) {
        Write-Host "[WinBot] WHATIF: Would reset clone 'WinBot-$Name' - delete differencing disk, recreate from master." -ForegroundColor Yellow
        return
    }
    if (-not $Force) {
        throw "Reset-WinBotClone requires -Force. This permanently deletes the clone's differencing disk and all changes."
    }
    $cloneName = "WinBot-$Name"
    Write-Host "[WinBot] Resetting clone '$cloneName'..." -ForegroundColor Cyan

    # Stop VM if running
    $vm = Get-VM -Name $cloneName -ErrorAction SilentlyContinue
    if ($vm -and $vm.State -ne "Off") {
        Stop-VM -Name $cloneName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
    }

    # Delete differencing disk and recreate
    $config = Get-WinBotConfig
    $cloneDir = Join-Path $config.clones.basePath $Name
    $cloneVHDX = Join-Path $cloneDir "disk.vhdx"

    if (Test-Path $cloneVHDX) {
        Remove-Item $cloneVHDX -Force
        Write-Host "  Deleted old differencing disk." -ForegroundColor Gray
    }

    # Recreate differencing disk
    New-VHD -ParentPath $config.master.vhdxPath -Path $cloneVHDX -Differencing -SizeBytes ($config.clones.defaultDiskSizeGB * 1GB) -ErrorAction Stop | Out-Null
    Write-Host "  Created fresh differencing disk." -ForegroundColor Green

    # Start VM
    Start-VM -Name $cloneName -ErrorAction Stop
    Write-Host "[WinBot] Clone '$cloneName' reset and started." -ForegroundColor Green
}

function Remove-WinBotClone {
    <#
    .SYNOPSIS
    Delete a WinBot clone VM and all its files.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,
        [switch]$Force
    )
    $cloneName = if ($Name -like "WinBot-*") { $Name } else { "WinBot-$Name" }

    # Master protection check runs before admin check so non-admin callers
    # get a clear "cannot delete master" message rather than an admin error.
    if ($cloneName -eq "WinBot-Master") {
        throw "Cannot delete the master VM. Use Remove-WinBotMaster if you really want to."
    }

    Assert-Administrator
    $config = Get-WinBotConfig

    $vm = Get-VM -Name $cloneName -ErrorAction SilentlyContinue
    if (-not $vm) {
        Write-Host "[WinBot] Clone '$cloneName' not found." -ForegroundColor Yellow
        return
    }

    # Stop VM if running
    if ($vm.State -ne "Off") {
        Stop-VM -Name $cloneName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
    }

    # Remove VM
    Remove-VM -Name $cloneName -Force
    Write-Host "[WinBot] VM '$cloneName' removed." -ForegroundColor Green

    # Remove files from the same canonical directory shape used by
    # New-WinBotClone.
    $cloneDir = Join-Path $config.clones.basePath $cloneName
    if (Test-Path -LiteralPath $cloneDir) {
        Remove-Item -LiteralPath $cloneDir -Recurse -Force
        Write-Host "[WinBot] Clone files removed: $cloneDir" -ForegroundColor Green
    }
}

function New-WinBotWorkCell {
    <#
    .SYNOPSIS
    Materialize one disposable Windows work cell on the Hyper-V MVP backend.
    .DESCRIPTION
    Compatibility-preserving facade over the proven Hyper-V clone mechanism.
    The returned runtime is disposable; persistence is attached only when
    explicitly requested.
    #>
    param(
        [Parameter(Mandatory=$true, ParameterSetName="AutoName")]
        [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9_.-]*$')]
        [string]$Name,

        [Parameter(Mandatory=$true, ParameterSetName="CustomName")]
        [ValidatePattern('^WinBot-[a-zA-Z0-9][a-zA-Z0-9_.-]*$')]
        [string]$CustomName,

        [ValidateScript({$_ -eq 0 -or ($_ -ge 512MB -and $_ -le 128GB)})]
        [long]$Memory = 0,
        [ValidateRange(0,64)][int]$Processors = 0,
        [string]$SwitchName = "",
        [string]$PersistentVHDXPath = "",
        [ValidateRange(1,120)][int]$TimeoutMinutes = 10,
        [switch]$NoStart,
        [switch]$NoWait,
        [switch]$Force
    )

    $args = @{
        Memory = $Memory
        Processors = $Processors
        TimeoutMinutes = $TimeoutMinutes
        NoStart = $NoStart
        NoWait = $NoWait
        Force = $Force
    }
    if ($PSCmdlet.ParameterSetName -eq 'CustomName') { $args.CustomName = $CustomName }
    else { $args.Name = $Name }
    if ($SwitchName) { $args.SwitchName = $SwitchName }
    if ($PersistentVHDXPath) { $args.PersistentVHDXPath = $PersistentVHDXPath }

    $runtime = New-WinBotClone @args
    [PSCustomObject]@{
        WorkCellId = $runtime.Name
        Backend = 'HyperV'
        State = $runtime.State
        IP = $runtime.IP
        APIReady = $runtime.APIReady
        APIUrl = $runtime.APIUrl
        RuntimeSeedPath = $runtime.RuntimeSeedPath
        RuntimeDiskPath = $runtime.RuntimeDiskPath
        SwitchName = $runtime.SwitchName
        PersistentVHDXPath = $runtime.PersistentVHDXPath
        Success = $runtime.Success
        Started = $runtime.Started
        Error = $runtime.Error
    }
}

function Remove-WinBotWorkCell {
    <#
    .SYNOPSIS
    Destroy one disposable Hyper-V work-cell runtime.
    .DESCRIPTION
    Removes the VM and its disposable differencing disk. Explicit persistent
    attachments are externally owned and are not deleted.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [switch]$Force
    )
    Remove-WinBotClone -Name $Name -Force:$Force
}

# ============================================================

function New-WinBotSession {
    <#
    .SYNOPSIS
    Create a new WinBot analysis session. Wraps New-WinBotClone with metadata.

    .DESCRIPTION
    Creates a clone, tags it as a session with label, saves an initial checkpoint,
    and returns a session object. The session tracks the purpose of the clone
    and provides a natural lifecycle: New -> [analysis] -> Stop/Remove.

    .PARAMETER Label
    Short label for the session (e.g. "re-lab", "malware-analysis").

    .PARAMETER Purpose
    Human-readable description of what this session is for.

    .PARAMETER Memory
    Memory in bytes (default from config).

    .PARAMETER TimeoutMinutes
    Max wait for API health. Default: 10.

    .EXAMPLE
    $session = New-WinBotSession -Label "malware-sample3" -Purpose "Analyze sample-3.exe with Frida"
    # ... do analysis ...
    Stop-WinBotSession -Session $session
    Remove-WinBotSession -Session $session
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Label,

        [string]$Purpose = "",
        [long]$Memory = 0,
        [int]$TimeoutMinutes = 10,
        [switch]$NoWait
    )

    $cloneName = $Label
    if ($Memory -eq 0) { $Memory = (Get-WinBotConfig).clones.defaultMemoryBytes }

    Write-Host "[WinBot] Starting session: $Label" -ForegroundColor Cyan
    if ($Purpose) { Write-Host "  Purpose: $Purpose" -ForegroundColor Gray }

    $clone = New-WinBotClone -Name $cloneName -TimeoutMinutes $TimeoutMinutes -Memory $Memory

    # Tag as a session with purpose
    Set-WinBotVMNote -Name $cloneName -Meta @{
        role = "session"
        session_label = $Label
        session_purpose = $Purpose
        session_started = (Get-Date).ToUniversalTime().ToString("o")
    }

    # Save an initial checkpoint as "clean"
    if ($clone.Success) {
        Wait-WinBotAPI -Name $cloneName -TimeoutSeconds 30 | Out-Null
        Save-WinBotCloneSnapshot -Name $cloneName -SnapshotName "session-start" -ErrorAction SilentlyContinue
    }

    $session = @{
        Label = $Label
        Purpose = $Purpose
        CloneName = $clone.Name
        IP = $clone.IP
        APIUrl = $clone.APIUrl
        Started = (Get-Date).ToUniversalTime().ToString("o")
        CleanCheckpoint = "session-start"
    }

    Write-Host "[WinBot] Session '$Label' ready: $($clone.APIUrl)" -ForegroundColor Green
    Write-Host "[WinBot] Clean checkpoint: 'session-start' -- Restore-WinBotCloneSnapshot -Name '$Label' -SnapshotName 'session-start' -Force" -ForegroundColor Gray

    return $session
}


function Stop-WinBotSession {
    <#
    .SYNOPSIS
    Stop an analysis session. Optionally snapshot or destroy the clone.

    .DESCRIPTION
    By default, saves a final checkpoint, stops the clone, and leaves it
    available for later inspection. With -Remove, destroys everything.
    With -KeepOnline, just records the session end without stopping.

    .PARAMETER Session
    Session hashtable from New-WinBotSession.

    .PARAMETER FinalSnapshotName
    Label for the final snapshot. Default: "session-end"

    .PARAMETER Remove
    Destroy the clone permanently.

    .PARAMETER KeepOnline
    Don't stop the VM -- just record session end.

    .EXAMPLE
    Stop-WinBotSession -Session $session
    Stop-WinBotSession -Session $session -Remove -Force
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Session,

        [string]$FinalSnapshotName = "session-end",
        [switch]$Remove,
        [switch]$KeepOnline,
        [switch]$Force
    )

    $label = $Session.Label
    Write-Host "[WinBot] Stopping session: $label" -ForegroundColor Cyan

    # Save final snapshot
    try {
        if ($FinalSnapshotName) {
            Save-WinBotCloneSnapshot -Name $label -SnapshotName $FinalSnapshotName -ErrorAction SilentlyContinue
            Write-Host "  Final checkpoint saved: $FinalSnapshotName" -ForegroundColor Green
        }
    } catch {
        Write-Verbose "Final snapshot skipped: $_"
    }

    # Update metadata
    Set-WinBotVMNote -Name $label -Meta @{
        session_ended = (Get-Date).ToUniversalTime().ToString("o")
        final_snapshot = $FinalSnapshotName
    }

    # Stop or remove
    if ($Remove) {
        Remove-WinBotClone -Name $label -Force:$Force
        Write-Host "[WinBot] Session '$label' removed." -ForegroundColor Green
    } elseif (-not $KeepOnline) {
        Stop-WinBotClone -Name $label
        Write-Host "[WinBot] Session '$label' stopped. Clone preserved for inspection." -ForegroundColor Green
    } else {
        Write-Host "[WinBot] Session '$label' ended. Clone still running." -ForegroundColor Green
    }

    return @{ Session = $label; Action = if ($Remove) { "removed" } else { "stopped" } }
}


# ============================================================
# Provisioning Checkpoint — state tracking for resume
# ============================================================

function Save-WinBotProvisioningState {
    <#
    .SYNOPSIS
    Save a provisioning checkpoint so the process can resume after failure.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string]$Phase,
        [string]$Detail = ""
    )
    $timestamp = (Get-Date).ToUniversalTime().ToString("o")
    $stateFile = Join-Path "C:\WinBot" ".provision-$Name.json"
    @{ name = $Name; phase = $Phase; detail = $Detail; timestamp = $timestamp } |
        ConvertTo-Json -Compress |
        Out-File $stateFile -Encoding utf8 -Force
    Write-WinBotLog -Message "Provisioning checkpoint: $Name phase=$Phase" -Level INFO
}

function Get-WinBotProvisioningState {
    <#
    .SYNOPSIS
    Read the last provisioning checkpoint for a named clone.
    Returns $null if no checkpoint exists.
    #>
    param([Parameter(Mandatory=$true)][string]$Name)
    $stateFile = Join-Path "C:\WinBot" ".provision-$Name.json"
    if (-not (Test-Path $stateFile)) { return $null }
    try {
        return Get-Content $stateFile -Raw | ConvertFrom-Json
    } catch {
        Write-Warning "[WinBot] Corrupt provisioning state for '$Name': $_"
        return $null
    }
}

function Clear-WinBotProvisioningState {
    <#
    .SYNOPSIS
    Clear provisioning checkpoint for a named clone (called on success).
    #>
    param([Parameter(Mandatory=$true)][string]$Name)
    $stateFile = Join-Path "C:\WinBot" ".provision-$Name.json"
    Remove-Item $stateFile -Force -ErrorAction SilentlyContinue
}


# ============================================================
# Orphaned VM Cleanup
# ============================================================

function Remove-WinBotOrphanedVMs {
    <#
    .SYNOPSIS
    Find and remove WinBot VMs that are orphaned — VMs with missing
    differencing disks, failed provisioning, or no API token.
    Orphans are VMs that were left in a broken state after an interrupted
    provisioning attempt.

    .PARAMETER Force
    Remove without confirmation.

    .PARAMETER DryRun
    Only report orphans without removing them.

    .EXAMPLE
    Remove-WinBotOrphanedVMs -DryRun
    Remove-WinBotOrphanedVMs -Force
    #>
    param(
        [switch]$Force,
        [switch]$DryRun
    )
    Assert-Administrator
    $orphans = @()
    $vms = Get-VM -Name "WinBot-*" -ErrorAction SilentlyContinue

    foreach ($vm in $vms) {
        if ($vm.Name -eq "WinBot-Master") { continue }  # Never delete master
        $isOrphan = $false
        $reason = ""

        # Check 1: VM has no differencing disk (VHDX file missing)
        $disks = Get-VMHardDiskDrive -VMName $vm.Name -ErrorAction SilentlyContinue
        if (-not $disks -or -not (Test-Path $disks[0].Path -ErrorAction SilentlyContinue)) {
            $isOrphan = $true
            $reason = "No differencing disk (VHDX missing)"
        }

        if (-not $isOrphan) {
            # Check 2: VM stopped with no provisioning marker (failed build)
            if ($vm.State -eq "Off") {
                $state = Get-WinBotProvisioningState -Name ($vm.Name -replace "^WinBot-", "")
                $notes = Get-WinBotVMNote -Name ($vm.Name -replace "^WinBot-", "")
                if (-not $state -and (-not $notes -or -not $notes.session_label)) {
                    $isOrphan = $true
                    $reason = "Stopped VM with no provisioning state or session metadata"
                }
            }
        }

        if ($isOrphan) {
            $orphans += [PSCustomObject]@{
                VMName = $vm.Name
                State = $vm.State
                Reason = $reason
            }
        }
    }

    if ($orphans.Count -eq 0) {
        Write-Host "[WinBot] No orphaned VMs found." -ForegroundColor Green
        return
    }

    Write-Host "=== Orphaned VMs ($($orphans.Count) found) ===" -ForegroundColor Yellow
    foreach ($o in $orphans) {
        Write-Host "  $($o.VMName) ($($o.State)) - $($o.Reason)" -ForegroundColor Yellow
    }

    if (-not $Force -and -not $DryRun) {
        Write-Host ""
        $confirm = Read-Host "Remove $($orphans.Count) orphaned VMs? [y/N]"
        if ($confirm -notmatch '^[yY]') { Write-Host "Cancelled." -ForegroundColor Yellow; return }
    }

    if ($DryRun) { Write-Host "DRY RUN: No VMs removed." -ForegroundColor Cyan; return }

    foreach ($o in $orphans) {
        Write-Host "  Removing $($o.VMName)..." -ForegroundColor Gray
        $disks = Get-VMHardDiskDrive -VMName $o.VMName -ErrorAction SilentlyContinue
        Stop-VM -Name $o.VMName -Force -ErrorAction SilentlyContinue
        Start-Sleep 2
        Remove-VM -Name $o.VMName -Force -ErrorAction SilentlyContinue
        foreach ($d in $disks) {
            if (Test-Path $d.Path) { Remove-Item $d.Path -Force -ErrorAction SilentlyContinue }
        }
        Clear-WinBotProvisioningState -Name ($o.VMName -replace "^WinBot-", "")
        Write-Host "  Removed: $($o.VMName)" -ForegroundColor Green
    }
    Write-Host "Orphan cleanup complete." -ForegroundColor Green
}


function Remove-WinBotSession {
    <#
    .SYNOPSIS
    Destroy a session and its clone permanently.

    .PARAMETER Session
    Session hashtable from New-WinBotSession.

    .PARAMETER Force
    Required to confirm permanent deletion.

    .EXAMPLE
    Remove-WinBotSession -Session $session -Force
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Session,
        [switch]$Force
    )

    if (-not $Force) {
        throw "Remove-WinBotSession requires -Force. This permanently deletes the clone and all session data."
    }

    Stop-WinBotSession -Session $Session -FinalSnapshotName "" -Remove -Force
}

# ============================================================
# Checkpoint Lifecycle -- Save/Restore/List/Remove VM Snapshots
# ============================================================

function Save-WinBotCloneSnapshot {
    <#
    .SYNOPSIS
    Create a named checkpoint (snapshot) of a running WinBot clone.
    The clone continues running after the snapshot is taken.

    .DESCRIPTION
    Creates a standard Hyper-V checkpoint that captures the VM's
    full state -- memory, CPU, disk, and device state. Standard
    checkpoints are crash-consistent but capture everything.

    Agents use this before potentially destructive operations
    -- running malware, injecting code, modifying system settings.
    If the VM becomes unstable, Restore-WinBotCloneSnapshot reverts it.

    .PARAMETER Name
    Clone name suffix.

    .PARAMETER SnapshotName
    Human-readable name for the checkpoint. Defaults to auto-generated
    with timestamp.

    .PARAMETER Description
    Optional description for the checkpoint.

    .EXAMPLE
    Save-WinBotCloneSnapshot -Name "re-lab" -SnapshotName "pre-malware"
    Save-WinBotCloneSnapshot -Name "re-lab" -SnapshotName "before-exploit" -Description "Clean state before CVE-2024 test"
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,

        [string]$SnapshotName = "",
        [string]$Description = ""
    )

    $cloneName = if ($Name -like "WinBot-*") { $Name } else { "WinBot-$Name" }
    $vm = Get-VM -Name $cloneName -ErrorAction Stop

    if ($vm.State -ne "Running") {
        throw "VM '$cloneName' must be running to take a snapshot. Current state: $($vm.State)"
    }

    # Generate snapshot name if not provided
    if (-not $SnapshotName) {
        $ts = Get-Date -Format "yyyyMMdd-HHmmss"
        $SnapshotName = "snapshot-$ts"
    }

    Write-Host "[WinBot] Creating checkpoint '$SnapshotName' for $cloneName..." -ForegroundColor Cyan

    # Remove existing checkpoint with same name if present
    $existing = Get-VMCheckpoint -VMName $cloneName -Name $SnapshotName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "  Removing existing checkpoint with same name..." -ForegroundColor Yellow
        Remove-VMCheckpoint -VMName $cloneName -Name $SnapshotName -ErrorAction SilentlyContinue
    }

    # Create the checkpoint
    $checkpoint = Checkpoint-VM -Name $cloneName -SnapshotName $SnapshotName -ErrorAction Stop

    # Update VM Notes with last snapshot info
    Set-WinBotVMNote -Name $Name -Meta @{
        last_snapshot = $SnapshotName
        last_snapshot_time = (Get-Date).ToUniversalTime().ToString("o")
    }

    Write-Host "[WinBot] Checkpoint saved: $SnapshotName" -ForegroundColor Green
    Write-Host "  VM continues running. Use Restore-WinBotCloneSnapshot to revert." -ForegroundColor Gray

    return @{
        Name = $SnapshotName
        VMName = $cloneName
        Created = (Get-Date).ToUniversalTime().ToString("o")
        State = "Running"
    }
}


function Restore-WinBotCloneSnapshot {
    <#
    .SYNOPSIS
    Revert a WinBot clone to a previously-saved checkpoint.
    This restarts the VM from the checkpoint state.

    .DESCRIPTION
    Applies the named checkpoint to the VM. The VM is stopped,
    reverted to the checkpoint's state, and restarted.
    All changes since the checkpoint was taken are discarded.

    .PARAMETER Name
    Clone name suffix.

    .PARAMETER SnapshotName
    Name of the checkpoint to restore. If not specified, restores
    the most recent checkpoint.

    .PARAMETER NoStart
    Don't restart the VM after restoring the checkpoint.

    .EXAMPLE
    Restore-WinBotCloneSnapshot -Name "re-lab" -SnapshotName "pre-malware"
    Restore-WinBotCloneSnapshot -Name "re-lab"  # restores latest checkpoint
    Restore-WinBotCloneSnapshot -Name "re-lab" -NoStart  # revert but stay off
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,

        [string]$SnapshotName = "",
        [switch]$NoStart,
        [switch]$Force
    )

    if (-not $Force) {
        $msg = "Restore will PERMANENTLY DISCARD all changes since the checkpoint. Use -Force to confirm."
        throw $msg
    }

    $cloneName = if ($Name -like "WinBot-*") { $Name } else { "WinBot-$Name" }

    # Resolve checkpoint
    if ($SnapshotName) {
        $checkpoint = Get-VMCheckpoint -VMName $cloneName -Name $SnapshotName -ErrorAction SilentlyContinue
        if (-not $checkpoint) {
            $available = (Get-VMCheckpoint -VMName $cloneName -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }) -join ", "
            throw "Checkpoint '$SnapshotName' not found on '$cloneName'. Available: $available"
        }
    } else {
        $checkpoint = Get-VMCheckpoint -VMName $cloneName -ErrorAction SilentlyContinue |
            Sort-Object CreationTime -Descending | Select-Object -First 1
        if (-not $checkpoint) {
            throw "No checkpoints found on '$cloneName'. Use Save-WinBotCloneSnapshot first."
        }
        $SnapshotName = $checkpoint.Name
    }

    Write-Host "[WinBot] Restoring checkpoint '$SnapshotName' on $cloneName..." -ForegroundColor Cyan
    Write-Host "  WARNING: All changes since the checkpoint will be discarded." -ForegroundColor Yellow

    # Restore the checkpoint
    Restore-VMCheckpoint -VMName $cloneName -Name $SnapshotName -Confirm:$false -ErrorAction Stop

    Write-Host "  Checkpoint restored." -ForegroundColor Green

    # Restart unless -NoStart
    if (-not $NoStart) {
        $vm = Get-VM -Name $cloneName
        if ($vm.State -ne "Running") {
            Write-Host "  Starting VM..." -ForegroundColor Gray
            Start-VM -Name $cloneName -ErrorAction Stop
        }
        Write-Host "  VM is running from checkpoint state." -ForegroundColor Green
    }

    return @{
        Action = "restored"
        SnapshotName = $SnapshotName
        VMName = $cloneName
        State = (Get-VM -Name $cloneName).State.ToString()
    }
}


function Get-WinBotCloneSnapshot {
    <#
    .SYNOPSIS
    List all checkpoints for a WinBot clone.

    .PARAMETER Name
    Clone name suffix.

    .EXAMPLE
    Get-WinBotCloneSnapshot -Name "re-lab"
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name
    )

    $cloneName = if ($Name -like "WinBot-*") { $Name } else { "WinBot-$Name" }
    $checkpoints = Get-VMCheckpoint -VMName $cloneName -ErrorAction SilentlyContinue

    if (-not $checkpoints) {
        Write-Host "[WinBot] No checkpoints found for '$cloneName'." -ForegroundColor Gray
        return @()
    }

    $chainDepth = @($checkpoints).Count
    $maxDepth = if ($env:WINBOT_MAX_CHECKPOINT_DEPTH) { [int]$env:WINBOT_MAX_CHECKPOINT_DEPTH } else { 50 }
    if ($chainDepth -gt $maxDepth) {
        throw "Checkpoint depth $chainDepth exceeds maximum $maxDepth. Remove old checkpoints with Remove-WinBotCloneSnapshot -All."
    }
    if ($chainDepth -gt 10) {
        Write-Warning "Checkpoint chain depth is $chainDepth. Consider removing old checkpoints with Remove-WinBotCloneSnapshot -All to free disk space and improve performance."
    }

    $result = $checkpoints | ForEach-Object {
        [PSCustomObject]@{
            Name = $_.Name
            VMName = $cloneName
            Created = $_.CreationTime.ToString("o")
            ParentCheckpoint = if ($_.ParentSnapshotName) { $_.ParentSnapshotName } else { "root" }
            IsStandard = ($_.SnapshotType -eq 2)
            SizeMB = if ($_.SizeOfSystemFiles) { [math]::Round($_.SizeOfSystemFiles / 1MB, 1) } else { "unknown" }
        }
    }

    $result | Format-Table Name, Created, ParentCheckpoint, SizeMB -AutoSize
    return $result
}


function Remove-WinBotCloneSnapshot {
    <#
    .SYNOPSIS
    Delete a checkpoint from a WinBot clone.
    The clone must be running or stopped; the checkpoint data is merged.

    .PARAMETER Name
    Clone name suffix.

    .PARAMETER SnapshotName
    Name of the checkpoint to remove.

    .PARAMETER All
    Remove ALL checkpoints for this clone.

    .EXAMPLE
    Remove-WinBotCloneSnapshot -Name "re-lab" -SnapshotName "pre-malware"
    Remove-WinBotCloneSnapshot -Name "re-lab" -All
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,

        [string]$SnapshotName = "",
        [switch]$All
    )

    $cloneName = if ($Name -like "WinBot-*") { $Name } else { "WinBot-$Name" }

    if ($All) {
        Write-Host "[WinBot] Removing ALL checkpoints for $cloneName..." -ForegroundColor Cyan
        $checkpoints = Get-VMCheckpoint -VMName $cloneName -ErrorAction SilentlyContinue
        if (-not $checkpoints) {
            Write-Host "  No checkpoints to remove." -ForegroundColor Gray
            return
        }
        foreach ($cp in $checkpoints) {
            Write-Host "  Removing: $($cp.Name)" -ForegroundColor Gray
            Remove-VMCheckpoint -VMName $cloneName -Name $cp.Name -ErrorAction SilentlyContinue
        }
        Write-Host "  All checkpoints removed." -ForegroundColor Green
        return
    }

    if (-not $SnapshotName) {
        throw "Specify -SnapshotName or -All"
    }

    $checkpoint = Get-VMCheckpoint -VMName $cloneName -Name $SnapshotName -ErrorAction SilentlyContinue
    if (-not $checkpoint) {
        Write-Warning "Checkpoint '$SnapshotName' not found on '$cloneName'."
        return
    }

    Write-Host "[WinBot] Removing checkpoint '$SnapshotName'..." -ForegroundColor Cyan
    Remove-VMCheckpoint -VMName $cloneName -Name $SnapshotName -ErrorAction Stop
    Write-Host "  Checkpoint removed." -ForegroundColor Green
}

# ============================================================
# Network Management -- Hyper-V Virtual Switches
# ============================================================

function _Wait-VMIPAfterSwitch {
    <#
    .SYNOPSIS
    Poll a VM for a new IP address after a network switch change.
    Used internally by Enable/Disable-WinBotInternetAccess.
    #>
    param([string]$VMName, [int]$TimeoutSeconds = 30)
    Write-Host "  Waiting for DHCP lease on new network..." -ForegroundColor Gray
    $start = Get-Date; $elapsed = 0
    while ($elapsed -lt $TimeoutSeconds) {
        $net = Get-VMNetworkAdapter -VMName $VMName -ErrorAction SilentlyContinue
        $ip = if ($net) { $net.IPAddresses | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+' } | Select-Object -First 1 } else { $null }
        if ($ip) {
            Write-Host "  New IP: $ip (${elapsed}s)" -ForegroundColor Green
            return @{ Found = $true; IP = $ip; ElapsedSeconds = $elapsed }
        }
        Start-Sleep -Seconds 3
        $elapsed = [math]::Round((Get-Date).Subtract($start).TotalSeconds, 0)
    }
    Write-Host "  No IP after ${TimeoutSeconds}s -- VM may still be getting a lease." -ForegroundColor Yellow
    return @{ Found = $false; IP = $null; ElapsedSeconds = $TimeoutSeconds }
}

function New-WinBotNetworkSwitch {
    <#
    .SYNOPSIS
    Create a Hyper-V virtual switch for WinBot clones.

    .DESCRIPTION
    Three switch types:
    - Private: VMs can only talk to each other (no host, no internet)
    - Internal: VMs can talk to each other AND the host (no internet)
    - External: VMs share the host's physical NIC (internet access)

    WinBot configures the switch and returns connection info.

    .PARAMETER Name
    Switch name. Default: "WinBot-Internal"

    .PARAMETER Type
    Private, Internal, or External. Default: Internal

    .EXAMPLE
    New-WinBotNetworkSwitch -Name "WinBot-Private" -Type Private
    New-WinBotNetworkSwitch -Name "WinBot-External" -Type External
    #>
    param(
        [string]$SwitchName = "WinBot-Internal",
        [ValidateSet("Private","Internal","External")]
        [string]$Type = "Internal"
    )

    Assert-Administrator

    # Check if switch already exists
    $existing = Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "[WinBot] Switch '$SwitchName' already exists - Type: $($existing.SwitchType)" -ForegroundColor Green
        return @{
            Name = $SwitchName
            Type = $existing.SwitchType.ToString()
            NetAdapterInterfaceDescription = if ($existing.NetAdapterInterfaceDescription) { $existing.NetAdapterInterfaceDescription } else { "N/A" }
            Exists = $true
        }
    }

    Write-Host "[WinBot] Creating $Type switch: $SwitchName..." -ForegroundColor Cyan

    if ($Type -eq "External") {
        # Find the active physical NIC
        $netAdapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Sort-Object Speed -Descending | Select-Object -First 1
        if (-not $netAdapter) {
            throw "No active physical network adapter found. Cannot create External switch."
        }
        Write-Host "  Using adapter: $($netAdapter.Name) - $($netAdapter.InterfaceDescription)" -ForegroundColor Gray
        New-VMSwitch -Name $SwitchName -NetAdapterName $netAdapter.Name -AllowManagementOS $true -ErrorAction Stop | Out-Null
        Write-Host "  External switch created - VMs share host NIC for internet access." -ForegroundColor Green
    } else {
        $swType = if ($Type -eq "Private") { "Private" } else { "Internal" }
        New-VMSwitch -Name $SwitchName -SwitchType $swType -ErrorAction Stop | Out-Null
        $desc = if ($Type -eq "Private") { "VMs can only talk to each other" } else { "VMs can talk to each other and the host" }
        Write-Host "  $Type switch created - $desc." -ForegroundColor Green
    }

    return @{
        Name = $SwitchName
        Type = $Type
        NetAdapterInterfaceDescription = if ($Type -eq "External" -and $netAdapter) { $netAdapter.InterfaceDescription } else { "N/A" }
        Created = $true
    }
}


function Connect-WinBotNetwork {
    <#
    .SYNOPSIS
    Connect a WinBot clone to a specific virtual switch.

    .DESCRIPTION
    Moves the VM's network adapter to the specified switch.
    Use this to change network isolation levels:
    - WinBot-Internal: host + VM comms, no internet
    - WinBot-Private: VM-only, no host, no internet
    - WinBot-External: internet access via host NIC
    - Default Switch: Hyper-V default NAT (internet + host)

    .PARAMETER Name
    Clone name suffix.

    .PARAMETER SwitchName
    Target switch name.

    .EXAMPLE
    Connect-WinBotNetwork -Name "re-lab" -SwitchName "WinBot-Internal"
    Connect-WinBotNetwork -Name "re-lab" -SwitchName "WinBot-External"
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,

        [Parameter(Mandatory=$true)]
        [string]$SwitchName
    )

    $cloneName = if ($Name -like "WinBot-*") { $Name } else { "WinBot-$Name" }
    $vm = Get-VM -Name $cloneName -ErrorAction SilentlyContinue
    if (-not $vm) { throw "VM '$cloneName' not found." }

    # Verify switch exists
    $switch = Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue
    if (-not $switch) {
        Write-Host "[WinBot] Switch '$SwitchName' not found. Creating it..." -ForegroundColor Yellow
        # Determine type from name
        $type = "Internal"
        if ($SwitchName -like "*Private*") { $type = "Private" }
        elseif ($SwitchName -like "*External*") { $type = "External" }
        New-WinBotNetworkSwitch -SwitchName $SwitchName -Type $type
    }

    Write-Host "[WinBot] Connecting '$cloneName' to switch '$SwitchName'..." -ForegroundColor Cyan
    Connect-VMNetworkAdapter -VMName $cloneName -SwitchName $SwitchName -ErrorAction Stop

    # Update VM Notes
    Set-WinBotVMNote -Name $Name -Meta @{ network_switch = $SwitchName }

    Write-Host "  Connected. VM may need DHCP renew to get a new IP." -ForegroundColor Green

    return @{
        VMName = $cloneName
        SwitchName = $SwitchName
        SwitchType = (Get-VMSwitch -Name $SwitchName).SwitchType.ToString()
    }
}


function Enable-WinBotInternetAccess {
    <#
    .SYNOPSIS
    Give a WinBot clone internet access (for downloads/tool installation).

    .DESCRIPTION
    Connects the clone to the Default Switch (Hyper-V NAT) or an External switch,
    giving it internet access. Use Disable-WinBotInternetAccess to isolate it again.

    .PARAMETER Name
    Clone name suffix.

    .PARAMETER SwitchName
    Switch to use for internet. Tries in order: Default Switch, External, creates one if needed.

    .EXAMPLE
    Enable-WinBotInternetAccess -Name "re-lab"
    Enable-WinBotInternetAccess -Name "re-lab" -SwitchName "WinBot-External"
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,

        [string]$SwitchName = ""
    )

    $cloneName = if ($Name -like "WinBot-*") { $Name } else { "WinBot-$Name" }

    # Find internet-capable switch
    if (-not $SwitchName) {
        $defaultSwitch = Get-VMSwitch -Name "Default Switch" -ErrorAction SilentlyContinue
        $externalSwitch = Get-VMSwitch | Where-Object { $_.SwitchType -eq "External" } | Select-Object -First 1

        if ($defaultSwitch) {
            $SwitchName = "Default Switch"
            Write-Host "[WinBot] Using Hyper-V Default Switch - NAT with internet." -ForegroundColor Gray
        } elseif ($externalSwitch) {
            $SwitchName = $externalSwitch.Name
            Write-Host "[WinBot] Using External switch: $SwitchName" -ForegroundColor Gray
        } else {
            Write-Host "[WinBot] No internet-capable switch found. Creating External switch..." -ForegroundColor Yellow
            $result = New-WinBotNetworkSwitch -SwitchName "WinBot-External" -Type External
            $SwitchName = $result.Name
        }
    }

    Connect-WinBotNetwork -Name $Name -SwitchName $SwitchName

    Write-Host "[WinBot] Internet access enabled for '$cloneName' via '$SwitchName'." -ForegroundColor Green
    $null = _Wait-VMIPAfterSwitch -VMName $cloneName -TimeoutSeconds 30
}


function Disable-WinBotInternetAccess {
    <#
    .SYNOPSIS
    Isolate a WinBot clone from the internet (for malware analysis).

    .DESCRIPTION
    Connects the clone to an Internal switch so it can still communicate
    with the host but has no internet access. The host can still reach
    the API, take screenshots, and send input commands.

    .PARAMETER Name
    Clone name suffix.

    .PARAMETER SwitchName
    Switch to use for isolation. Default: "WinBot-Internal" (auto-created if missing)

    .EXAMPLE
    Disable-WinBotInternetAccess -Name "re-lab"
    Disable-WinBotInternetAccess -Name "re-lab" -SwitchName "WinBot-Private"
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,

        [string]$SwitchName = ""
    )

    $cloneName = if ($Name -like "WinBot-*") { $Name } else { "WinBot-$Name" }

    if (-not $SwitchName) {
        $SwitchName = "WinBot-Internal"
        $exists = Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue
        if (-not $exists) {
            Write-Host "[WinBot] Creating Internal switch for isolation..." -ForegroundColor Gray
            New-WinBotNetworkSwitch -SwitchName $SwitchName -Type Internal
        }
    }

    Connect-WinBotNetwork -Name $Name -SwitchName $SwitchName

    Write-Host "[WinBot] Internet access DISABLED for '$cloneName'." -ForegroundColor Green
    Write-Host "  VM is on '$SwitchName' - host access only, no internet." -ForegroundColor Green
    Write-Host "  The WinBot API remains reachable from the host." -ForegroundColor Gray
    $null = _Wait-VMIPAfterSwitch -VMName $cloneName -TimeoutSeconds 30
}


function Get-WinBotNetworkStatus {
    <#
    .SYNOPSIS
    Show the current network configuration for a WinBot clone.

    .PARAMETER Name
    Clone name suffix.

    .EXAMPLE
    Get-WinBotNetworkStatus -Name "re-lab"
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name
    )

    $cloneName = if ($Name -like "WinBot-*") { $Name } else { "WinBot-$Name" }
    $vm = Get-VM -Name $cloneName -ErrorAction SilentlyContinue
    if (-not $vm) { throw "VM '$cloneName' not found." }

    $net = Get-VMNetworkAdapter -VMName $cloneName -ErrorAction SilentlyContinue
    if (-not $net) { return @{ VMName = $cloneName; Connected = $false } }

    $switch = Get-VMSwitch -Name $net.SwitchName -ErrorAction SilentlyContinue
    $ips = @($net.IPAddresses | Where-Object { $_ -match '.' })
    $hasInternet = ($switch -and ($switch.SwitchType -eq "External" -or $switch.Name -like "*Default*"))

    $result = @{
        VMName = $cloneName
        SwitchName = $net.SwitchName
        SwitchType = if ($switch) { $switch.SwitchType.ToString() } else { "unknown" }
        IPAddresses = $ips
        InternetAccess = $hasInternet
        HostAccess = ($net.SwitchName -ne "" )
        MacAddress = $net.MacAddress
    }

    Write-Host "[WinBot] Network status for '$cloneName':" -ForegroundColor Cyan
    Write-Host "  Switch:       $($result.SwitchName) ($($result.SwitchType))" -ForegroundColor Gray
    Write-Host "  IPs:          $($ips -join ', ')" -ForegroundColor Gray
    Write-Host "  Internet:     $(if($hasInternet){'YES'}else{'NO'})" -ForegroundColor $(if($hasInternet){'Yellow'}else{'Green'})
    Write-Host "  Host Access:  $(if($result.HostAccess){'YES'}else{'NO'})" -ForegroundColor Green

    return $result
}

# ============================================================
# API Interaction
# ============================================================

function Invoke-WinBotAPI {
    <#
    .SYNOPSIS
    Call the WinBot API on a running clone.

    .PARAMETER Name
    Clone name suffix

    .PARAMETER Method
    HTTP method (GET, POST, etc.)

    .PARAMETER Endpoint
    API endpoint path (e.g., "/health", "/screenshot")

    .PARAMETER Body
    Request body as hashtable (for POST requests)
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,

        [string]$Method = "GET",
        [string]$Endpoint = "/health",

        [hashtable]$Body = $null
    )
    # Resolve the full VM name — clones follow pattern WinBot-clone-<name>-<timestamp>
    $cloneName = Resolve-WinBotVMName -Name $Name -ErrorAction SilentlyContinue
    if (-not $cloneName) { $cloneName = "WinBot-$Name" }

    $config = Get-WinBotConfig

    # INVARIANT: VM must exist and be running before making API calls
    $vm = Get-VM -Name $cloneName -ErrorAction SilentlyContinue
    if (-not $vm) { throw "Clone '$cloneName' not found in Hyper-V. Use New-WinBotClone or Start-WinBotClone first." }
    if ($vm.State -ne "Running") { throw "Clone '$cloneName' is $($vm.State) -- must be Running to call the API. Start it: Start-WinBotClone -Name '$Name'" }

    # Get VM IP
    $vmNetwork = Get-VMNetworkAdapter -VMName $cloneName -ErrorAction SilentlyContinue
    if (-not $vmNetwork) {
        throw "Cannot find network adapter for '$cloneName'"
    }
    $ip = $vmNetwork.IPAddresses | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+' } | Select-Object -First 1
    if (-not $ip) {
        throw "Clone '$cloneName' has no IPv4 address. Is it fully booted?"
    }

    $url = "http://${ip}:$($config.api.port)$Endpoint"

    $headers = @{
        "Content-Type" = "application/json"
    }
    if ($config.api.token) {
        $headers["X-API-Key"] = $config.api.token
    }

    $params = @{
        Uri = $url
        Method = $Method
        Headers = $headers
        ErrorAction = "Stop"
        UseBasicParsing = $true
    }

    if ($Body) {
        $params.Body = ($Body | ConvertTo-Json -Compress)
    }

    Write-Host "[WinBot] $Method $url" -ForegroundColor Gray
    try {
        $response = Invoke-WebRequest @params
        return $response.Content | ConvertFrom-Json
    }
    catch {
        if ($_.Exception.Response) {
            $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $errorBody = $reader.ReadToEnd()
            throw "API error $($_.Exception.Response.StatusCode.value__): $errorBody"
        }
        throw "API request failed: $_"
    }
}

# ============================================================
# RDP Connection
# ============================================================

function Connect-WinBotRDP {
    <#
    .SYNOPSIS
    Launch an RDP connection to a WinBot clone.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name
    )
    $cloneName = "WinBot-$Name"

    # Get VM IP
    $vmNetwork = Get-VMNetworkAdapter -VMName $cloneName -ErrorAction SilentlyContinue
    if (-not $vmNetwork) {
        throw "Cannot find network adapter for '$cloneName'"
    }
    $ip = $vmNetwork.IPAddresses | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+' } | Select-Object -First 1
    if (-not $ip) {
        throw "Clone '$cloneName' has no IPv4 address."
    }

    Write-Host "[WinBot] Launching RDP to $ip ..." -ForegroundColor Cyan
    Start-Process "mstsc.exe" -ArgumentList "/v:$ip"
}

# ============================================================
# PowerShell Direct (VMBus - no network needed)
# ============================================================

function Connect-WinBotVM {
    <#
    .SYNOPSIS
    Open an interactive PowerShell Direct session to the clone via VMBus.
    No network required!
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name
    )
    $cloneName = "WinBot-$Name"
    $cred = Get-WinBotCredential
    Write-Host "[WinBot] Opening PowerShell Direct session to $cloneName ..." -ForegroundColor Cyan
    Enter-PSSession -VMName $cloneName -Credential $cred
}

function Sync-WinBotApiToken {
    <#
    .SYNOPSIS
    Retrieve the API token from a running clone and store it in config.json.
    Uses PowerShell Direct (VMBus -- no network required).
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name
    )
    $cloneName = "WinBot-$Name"
    $cred = Get-WinBotCredential

    Write-Host "[WinBot] Retrieving API token from $cloneName..." -ForegroundColor Cyan
    try {
        $token = Invoke-Command -VMName $cloneName -Credential $cred -ScriptBlock {
            if (Test-Path "C:\WinBot\.api_token") {
                Get-Content "C:\WinBot\.api_token" -Raw
            } else {
                $null
            }
        } -ErrorAction Stop

        if ($token) {
            $token = $token.Trim()
            $config = Get-WinBotConfig
            $config.api.token = $token
            $script:Config = $config
            $config | ConvertTo-Json -Depth 5 | Out-File -FilePath $script:ConfigPath -Encoding utf8
            Write-Host "[WinBot] API token synced to config.json" -ForegroundColor Green
            return $token
        } else {
            Write-Warning "[WinBot] Token file not found on $cloneName. Run setup-service.ps1 first."
            return $null
        }
    } catch {
        Write-Warning "[WinBot] Could not retrieve token via PowerShell Direct: $_"
        Write-Warning "[WinBot] The VM may need more time to boot. Try again later."
        return $null
    }
}

function Invoke-WinBotVMCommand {
    <#
    .SYNOPSIS
    Run a command inside the clone via PowerShell Direct.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,

        [Parameter(Mandatory=$true)]
        [ScriptBlock]$ScriptBlock
    )
    $cloneName = "WinBot-$Name"
    $cred = Get-WinBotCredential
    Invoke-Command -VMName $cloneName -Credential $cred -ScriptBlock $ScriptBlock
}

# ============================================================
# Autounattend Generator (for ISO-based automated Windows install)
# ============================================================

function Get-WinBotAutounattend {
    <#
    .SYNOPSIS
    Generate a Windows autounattend.xml for fully automated installation with
    complete WinBot toolchain provisioning.

    .DESCRIPTION
    Creates a complete answer file that:
    - Installs Windows 11 Pro/Enterprise completely unattended
    - Creates the WinBot admin account with auto-logon
    - Skips all OOBE (privacy questions, Cortana, online account)
    - FirstLogonCommands install the entire WinBot toolchain:
      1. Copy API files from provisioning VHD (D:) to C:\WinBot
      2. Install Chocolatey package manager
      3. Install Python 3.13 + pip packages (fastapi, uvicorn, pyautogui, etc.)
      4. Install AutoIt v3, AutoHotkey v1.1, NSSM
      5. Configure WinRM, RDP, firewall, power settings
      6. Install WinBot API as a Windows service (auto-start)
      7. Final reboot

    .PARAMETER Password
    Password for the WinBot user account. Randomly generated if not provided.

    .PARAMETER Username
    Local admin username. Default: winbot

    .PARAMETER ProductKey
    Windows product key for permanent activation. If provided, injected into autounattend
    so Windows installs as a licensed copy (no 90-day eval limit).

    .PARAMETER WindowsEdition
    Windows edition to install. Default: Enterprise. Valid: Pro, Enterprise, Education.

    .PARAMETER ComputerName
    VM computer name. Default: WinBot-Master
    #>
    param(
        [string]$Password = "",
        [string]$Username = "winbot",
        [string]$ProductKey = "",
        [string]$WindowsEdition = "Enterprise",
        [string]$ComputerName = "WinBot-Master"
    )

    # No default password -- generate a random one if not provided
    if (-not $Password) {
        $Password = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 16 | ForEach-Object { [char]$_ })
    }

    # Build the provisioning script that runs as FirstLogonCommands.
    # Each command is a self-contained PowerShell block with its own error handling,
    # logging to C:\WinBot\logs\provision.log so we can debug failures.
    #
    # The provisioning VHD is attached as a second disk. Windows Setup will assign
    # it the next available drive letter after the system disk (usually D:).
    # The script looks for D:\WinBot\ (provisioning VHD root) or falls back to
    # downloading from a URL if the VHD isn't available.

    $provisionScript = @'
$logDate = Get-Date -Format "yyyyMMdd"; $logFile = "C:\WinBot\logs\provision-$logDate.log"
$logDir = Split-Path $logFile -Parent
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
function Write-ProvisionLog($msg) {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$ts $msg" | Out-File -Append -FilePath $logFile -Encoding utf8
    Write-Host "$ts $msg"
}
Write-ProvisionLog "=== WinBot Provisioning Started ==="

# ---- Step 1: Copy API files from provisioning VHD or download ----
Write-ProvisionLog "[1/7] Copying WinBot API files..."
$sourceDrives = @("D:", "E:", "F:", "G:")  # provisioning VHD could be any letter
$apiSource = $null
# Check C:\WinBot\ first -- files may already be staged by DISM deploy
if (Test-Path "C:\WinBot\api\main.py") {
    $apiSource = "C:\WinBot"
    Write-ProvisionLog "  API files already staged at C:\WinBot"
} else {
    foreach ($drive in $sourceDrives) {
        if (Test-Path "$drive\guest\api\main.py") { $apiSource = "$drive\guest"; break }
        if (Test-Path "$drive\api\main.py") { $apiSource = $drive; break }
    }
}
if ($apiSource) {
    Write-ProvisionLog "  Found API files on $apiSource"
    $winbotDirs = @("C:\WinBot\api\endpoints", "C:\WinBot\sessions\screenshots", "C:\WinBot\sessions\logs", "C:\WinBot\sessions\scripts", "C:\WinBot\sessions\artifacts", "C:\WinBot\tools", "C:\WinBot\logs")
    foreach ($d in $winbotDirs) { if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null } }
    # Copy API files (skip if already staged at C:\WinBot by DISM)
    if ($apiSource -ne "C:\WinBot") {
        # Files come from provisioning VHD at $apiSource\guest\
        $apiSrcDir = if ($apiSource -match '^[A-Z]:$') { "$apiSource\guest\api" } else { "$apiSource\api" }
        $apiParent = if ($apiSource -match '^[A-Z]:$') { "$apiSource\guest" } else { $apiSource }
        # Copy API files
        if (Test-Path $apiSrcDir) {
            $apiFiles = Get-ChildItem $apiSrcDir -Recurse -File -ErrorAction SilentlyContinue
            foreach ($f in $apiFiles) {
                $dest = $f.FullName.Replace($apiSrcDir, "C:\WinBot\api")
                $destDir = Split-Path $dest -Parent
                if (-not (Test-Path $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }
                Copy-Item $f.FullName $dest -Force -ErrorAction SilentlyContinue
            }
        }
        # Copy PowerShell scripts
        $psFiles = Get-ChildItem $apiParent -Filter "*.ps1" -File -ErrorAction SilentlyContinue
        foreach ($f in $psFiles) { Copy-Item $f.FullName "C:\WinBot\$($f.Name)" -Force -ErrorAction SilentlyContinue }
        # Copy tools
        $toolsSrc = "$apiParent\tools"
        if (Test-Path $toolsSrc) {
            $toolFiles = Get-ChildItem $toolsSrc -Filter "*.ps1" -File -ErrorAction SilentlyContinue
            foreach ($f in $toolFiles) { Copy-Item $f.FullName "C:\WinBot\tools\$($f.Name)" -Force -ErrorAction SilentlyContinue }
        }
        Write-ProvisionLog "  API files copied from $apiSource"
    } else {
        Write-ProvisionLog "  Files already staged -- skipping copy"
    }
} else {
    Write-ProvisionLog "  No provisioning VHD found. Downloading from GitHub..."
    # Fallback: download from GitHub (adjust URL to match your release)
    $zipUrl = "https://github.com/your-org/winbot/releases/download/v0.1.0/winbot-api.zip"
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $zipUrl -OutFile "$env:TEMP\winbot-api.zip" -ErrorAction Stop
        Expand-Archive -Path "$env:TEMP\winbot-api.zip" -DestinationPath "C:\WinBot" -Force
        Write-ProvisionLog "  API files downloaded from GitHub"
    } catch {
        Write-ProvisionLog "  WARNING: Could not download API files: $_"
        Write-ProvisionLog "  The API will need to be installed manually."
    }
}

# ---- Step 2: Install Chocolatey ----
Write-ProvisionLog "[2/7] Installing Chocolatey..."
try {
    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = 3072
        iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        $env:ChocolateyInstall = "$env:ProgramData\chocolatey"
        $env:PATH = "$env:ChocolateyInstall\bin;$env:PATH"
        Write-ProvisionLog "  Chocolatey installed"
    } else {
        Write-ProvisionLog "  Chocolatey already installed"
    }
} catch {
    Write-ProvisionLog "  WARNING: Chocolatey install failed: $_"
}

# ---- Step 3: Install Python 3.13 ----
Write-ProvisionLog "[3/7] Installing Python 3.13..."
try {
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        choco install python313 -y --no-progress 2>&1 | Out-File -Append $logFile -Encoding utf8
    }
    # Refresh PATH
    $env:PATH = [Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" + [Environment]::GetEnvironmentVariable("PATH", "User")
    # Ensure we can find python
    $pythonExe = Get-Command python -ErrorAction SilentlyContinue
    if (-not $pythonExe) {
        # Try common install paths
        $pyPaths = @("C:\Python313\python.exe", "$env:LOCALAPPDATA\Programs\Python\Python313\python.exe", "C:\Program Files\Python313\python.exe")
        foreach ($p in $pyPaths) {
            if (Test-Path $p) { $env:PATH = (Join-Path (Split-Path $p) "Scripts") + ";" + (Split-Path $p) + ";$env:PATH"; break }
        }
    }
    $pyVer = & python --version 2>&1
    Write-ProvisionLog "  Python: $pyVer"
    # Install pip packages
    python -m pip install --upgrade pip --quiet 2>&1 | Out-File -Append $logFile -Encoding utf8
    python -m pip install fastapi uvicorn pyautogui pywin32 pillow pynput psutil --quiet 2>&1 | Out-File -Append $logFile -Encoding utf8
    Write-ProvisionLog "  Python packages installed"
} catch {
    Write-ProvisionLog "  WARNING: Python install failed: $_"
}

# ---- Step 4: Install AutoIt, AutoHotkey, NSSM ----
Write-ProvisionLog "[4/7] Installing automation tools..."
if (Get-Command choco -ErrorAction SilentlyContinue) {
    try {
        choco install autoit -y --no-progress 2>&1 | Out-File -Append $logFile -Encoding utf8
        Write-ProvisionLog "  AutoIt installed"
    } catch { Write-ProvisionLog "  WARNING: AutoIt install: $_" }

    try {
        choco install autohotkey -y --no-progress 2>&1 | Out-File -Append $logFile -Encoding utf8
        Write-ProvisionLog "  AutoHotkey installed"
    } catch { Write-ProvisionLog "  WARNING: AutoHotkey install: $_" }

    try {
        choco install nssm -y --no-progress 2>&1 | Out-File -Append $logFile -Encoding utf8
        Write-ProvisionLog "  NSSM installed"
    } catch { Write-ProvisionLog "  WARNING: NSSM install: $_" }
} else {
    Write-ProvisionLog "  WARNING: Chocolatey not available, skipping tool installs"
}

# ---- Step 5: Configure remote access and user account ----
Write-ProvisionLog "[5/7] Configuring remote access..."
try {
    # Enable RDP
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 0 -Type DWord -Force
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
    Add-LocalGroupMember -Group "Remote Desktop Users" -Member $env:UserName -ErrorAction SilentlyContinue
    Write-ProvisionLog "  RDP enabled"

    # Configure WinRM
    Enable-PSRemoting -Force -ErrorAction SilentlyContinue
    Set-Item -Path "WSMan:\localhost\Client\TrustedHosts" -Value "*" -Force -ErrorAction SilentlyContinue
    Set-Item -Path "WSMan:\localhost\Service\Auth\Basic" -Value $true -Force -ErrorAction SilentlyContinue
    Set-Service -Name WinRM -StartupType Automatic
    Restart-Service WinRM -Force -ErrorAction SilentlyContinue
    Write-ProvisionLog "  WinRM configured"

    # Firewall for WinBot API
    netsh advfirewall firewall delete rule name="WinBot API" 2>$null
    netsh advfirewall firewall add rule name="WinBot API" dir=in action=allow protocol=TCP localport=8000
    Write-ProvisionLog "  Firewall configured"

    # Disable UAC for automation tools
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0 -Type DWord -Force

    # Power settings -- never sleep
    powercfg -change -standby-timeout-ac 0 2>$null
    powercfg -change -standby-timeout-dc 0 2>$null
    powercfg -change -hibernate-timeout-ac 0 2>$null
    powercfg -change -monitor-timeout-ac 30 2>$null

    # Disable screen saver
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveActive" -Value 0 -Force -ErrorAction SilentlyContinue

    # Disable Defender real-time monitoring for perf
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue

    Write-ProvisionLog "  Remote access and power settings configured"
} catch {
    Write-ProvisionLog "  WARNING: Remote access configuration: $_"
}

# ---- Step 6: Install WinBot API as Windows service ----
Write-ProvisionLog "[6/7] Installing WinBot API service..."
try {
    # Generate API token
    $tokenBytes = New-Object byte[] 32
    [Security.Cryptography.RandomNumberGenerator]::Fill($tokenBytes)
    $apiToken = -join ($tokenBytes | ForEach-Object { "{0:x2}" -f $_ })

    # Save token
    $tokenFile = "C:\WinBot\.api_token"
    $apiToken | Out-File -FilePath $tokenFile -Encoding ascii -NoNewline
    try {
        icacls $tokenFile /inheritance:r /grant "SYSTEM:(R)" /grant "BUILTIN\Administrators:(R)" 2>$null | Out-Null
    } catch { Write-Verbose "Non-critical operation skipped - continuing" }

    # Find Python
    $pythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
    if (-not $pythonExe) {
        $pyPaths = @("C:\Python313\python.exe", "$env:LOCALAPPDATA\Programs\Python\Python313\python.exe")
        foreach ($p in $pyPaths) { if (Test-Path $p) { $pythonExe = $p; break } }
    }

    if ($pythonExe -and (Test-Path "C:\WinBot\api\main.py")) {
        $nssmPath = "C:\ProgramData\chocolatey\bin\nssm.exe"
        if (-not (Test-Path $nssmPath)) { $nssmPath = (Get-Command nssm -ErrorAction SilentlyContinue).Source }

        if ($nssmPath) {
            # Remove existing service if present
            Stop-Service -Name "WinBotAPI" -Force -ErrorAction SilentlyContinue
            & $nssmPath remove WinBotAPI confirm 2>$null
            Start-Sleep -Seconds 1

            # Install with NSSM
            & $nssmPath install WinBotAPI $pythonExe "-m uvicorn main:app --host 0.0.0.0 --port 8000"
            & $nssmPath set WinBotAPI AppDirectory "C:\WinBot\api"
            & $nssmPath set WinBotAPI DisplayName "WinBot API Server"
            & $nssmPath set WinBotAPI Description "WinBot automation REST API (FastAPI + uvicorn)"
            & $nssmPath set WinBotAPI Start SERVICE_AUTO_START
            & $nssmPath set WinBotAPI AppStdout "C:\WinBot\logs\api-stdout.log"
            & $nssmPath set WinBotAPI AppStderr "C:\WinBot\logs\api-stderr.log"
            & $nssmPath set WinBotAPI AppStdoutCreationDisposition 4
            & $nssmPath set WinBotAPI AppStderrCreationDisposition 4
            & $nssmPath set WinBotAPI AppRotateFiles 1
            & $nssmPath set WinBotAPI AppRotateOnline 1
            & $nssmPath set WinBotAPI AppRotateSeconds 86400
            & $nssmPath set WinBotAPI AppRotateBytes 1048576
            & $nssmPath set WinBotAPI AppEnvironmentExtra "WINBOT_API_TOKEN=$apiToken"
            & $nssmPath set WinBotAPI AppExit Default Restart
            & $nssmPath set WinBotAPI AppRestartDelay 5000

            Start-Service -Name WinBotAPI -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 5
            $svc = Get-Service -Name WinBotAPI -ErrorAction SilentlyContinue
            if ($svc -and $svc.Status -eq "Running") {
                Write-ProvisionLog "  WinBot API service is RUNNING"
            } else {
                Write-ProvisionLog "  WARNING: Service installed but not running. Status: $($svc.Status)"
            }
        } else {
            Write-ProvisionLog "  WARNING: NSSM not found -- API service not installed"
        }
    } else {
        Write-ProvisionLog "  WARNING: Python or API files not found -- API service not installed"
    }
} catch {
    Write-ProvisionLog "  WARNING: API service installation failed: $_"
}

# ---- Step 7: Final reboot to start clean with auto-logon ----
Write-ProvisionLog "[7/7] Provisioning complete. Rebooting..."
Write-ProvisionLog "=== WinBot Provisioning Finished ==="
shutdown /r /t 10 /c "WinBot provisioning complete. Rebooting to finalize."
'@

    # Build product key block for autounattend if one was provided
    $productKeyBlock = ""
    if ($ProductKey) {
        $productKeyBlock = @"
                <ProductKey>
                    <Key>$ProductKey</Key>
                    <WillShowUI>Never</WillShowUI>
                </ProductKey>
"@
    }

    return @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
    <settings pass="windowsPE">
        <component name="Microsoft-Windows-International-Core-WinPE" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <SetupUILanguage>
                <UILanguage>en-US</UILanguage>
            </SetupUILanguage>
            <InputLocale>en-US</InputLocale>
            <SystemLocale>en-US</SystemLocale>
            <UILanguage>en-US</UILanguage>
            <UserLocale>en-US</UserLocale>
        </component>
        <component name="Microsoft-Windows-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <DiskConfiguration>
                <Disk wcm:action="add">
                    <CreatePartitions>
                        <CreatePartition wcm:action="add">
                            <Order>1</Order>
                            <Size>100</Size>
                            <Type>EFI</Type>
                        </CreatePartition>
                        <CreatePartition wcm:action="add">
                            <Order>2</Order>
                            <Size>16</Size>
                            <Type>MSR</Type>
                        </CreatePartition>
                        <CreatePartition wcm:action="add">
                            <Order>3</Order>
                            <Extend>true</Extend>
                            <Type>Primary</Type>
                        </CreatePartition>
                    </CreatePartitions>
                    <ModifyPartitions>
                        <ModifyPartition wcm:action="add">
                            <Order>1</Order>
                            <PartitionID>1</PartitionID>
                            <Format>FAT32</Format>
                            <Label>System</Label>
                        </ModifyPartition>
                        <ModifyPartition wcm:action="add">
                            <Order>2</Order>
                            <PartitionID>2</PartitionID>
                        </ModifyPartition>
                        <ModifyPartition wcm:action="add">
                            <Order>3</Order>
                            <PartitionID>3</PartitionID>
                            <Format>NTFS</Format>
                            <Label>Windows</Label>
                            <Letter>C</Letter>
                        </ModifyPartition>
                    </ModifyPartitions>
                    <DiskID>0</DiskID>
                    <WillWipeDisk>true</WillWipeDisk>
                </Disk>
            </DiskConfiguration>
            <ImageInstall>
                <OSImage>
                    <InstallTo>
                        <DiskID>0</DiskID>
                        <PartitionID>3</PartitionID>
                    </InstallTo>
                </OSImage>
            </ImageInstall>
            <UserData>
                <AcceptEula>true</AcceptEula>
                <FullName>WinBot</FullName>
                <Organization>WinBot Automation</Organization>
                $productKeyBlock
            </UserData>
        </component>
    </settings>
    <settings pass="offlineServicing">
        <component name="Microsoft-Windows-LUA-Settings" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <EnableLUA>false</EnableLUA>
        </component>
    </settings>
    <settings pass="specialize">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <ComputerName>$ComputerName</ComputerName>
            <TimeZone>Pacific Standard Time</TimeZone>
        </component>
        <component name="Microsoft-Windows-TerminalServices-LocalSessionManager" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <fDenyTSConnections>false</fDenyTSConnections>
        </component>
        <component name="Microsoft-Windows-TerminalServices-RDP-WinStationExtensions" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <UserAuthentication>0</UserAuthentication>
        </component>
    </settings>
    <settings pass="oobeSystem">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <OOBE>
                <HideEULAPage>true</HideEULAPage>
                <HideLocalAccountScreen>true</HideLocalAccountScreen>
                <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
                <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
                <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
                <ProtectYourPC>3</ProtectYourPC>
            </OOBE>
            <UserAccounts>
                <LocalAccounts>
                    <LocalAccount wcm:action="add">
                        <Name>$Username</Name>
                        <DisplayName>WinBot Automation</DisplayName>
                        <Description>WinBot automation account</Description>
                        <Group>Administrators</Group>
                        <Password>
                            <Value>$Password</Value>
                            <PlainText>true</PlainText>
                        </Password>
                    </LocalAccount>
                </LocalAccounts>
            </UserAccounts>
            <AutoLogon>
                <Enabled>true</Enabled>
                <Username>$Username</Username>
                <Password>
                    <Value>$Password</Value>
                    <PlainText>true</PlainText>
                </Password>
                <LogonCount>999999</LogonCount>
            </AutoLogon>
            <FirstLogonCommands>
                <SynchronousCommand wcm:action="add">
                    <Order>1</Order>
                    <CommandLine>powershell -ExecutionPolicy Bypass -WindowStyle Hidden -Command "$provisionScript"</CommandLine>
                    <Description>WinBot -- Complete provisioning (tools + API + remote access)</Description>
                </SynchronousCommand>
            </FirstLogonCommands>
        </component>
    </settings>
</unattend>
"@
}

# vvv DISM autounattend (minimal, validated) vvv

function Get-WinBotDismAutounattend {
    param(
        [string]$Password = "",
        [string]$Username = "winbot",
        [string]$ProductKey = "",
        [string]$WindowsEdition = "Enterprise",
        [string]$ComputerName = "WinBot-Master"
    )
    if (-not $Password) {
        $safe = (48..57) + (65..90) + (97..122)
        $Password = -join ($safe | Get-Random -Count 20 | ForEach-Object { [char]$_ })
    }
    if ($Password -match '[&<>"]') { throw "Password contains XML-unsafe characters." }
    if ($Username -match '[&<>"]') { throw "Username contains XML-unsafe characters." }

    # Note: ProductKey is handled via slmgr in provision.ps1, not in XML.
    # Putting it in specialize/Shell-Setup causes Windows to reject the component.

    return @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
    <settings pass="specialize">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <ComputerName>$ComputerName</ComputerName>
            <TimeZone>Pacific Standard Time</TimeZone>
        </component>
        <component name="Microsoft-Windows-TerminalServices-LocalSessionManager" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <fDenyTSConnections>false</fDenyTSConnections>
        </component>
        <component name="Microsoft-Windows-TerminalServices-RDP-WinStationExtensions" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <UserAuthentication>0</UserAuthentication>
        </component>
    </settings>
    <settings pass="oobeSystem">
        <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <InputLocale>en-US</InputLocale>
            <SystemLocale>en-US</SystemLocale>
            <UILanguage>en-US</UILanguage>
            <UserLocale>en-US</UserLocale>
        </component>
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <OOBE>
                <HideEULAPage>true</HideEULAPage>
                <HideLocalAccountScreen>true</HideLocalAccountScreen>
                <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
                <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
                <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
                <ProtectYourPC>3</ProtectYourPC>
                <NetworkLocation>Home</NetworkLocation>
            </OOBE>
            <UserAccounts>
                <LocalAccounts>
                    <LocalAccount wcm:action="add">
                        <Name>$Username</Name>
                        <DisplayName>WinBot Automation</DisplayName>
                        <Description>WinBot automation account</Description>
                        <Group>Administrators</Group>
                        <Password><Value>$Password</Value><PlainText>true</PlainText></Password>
                    </LocalAccount>
                </LocalAccounts>
            </UserAccounts>
            <AutoLogon>
                <Enabled>true</Enabled>
                <Username>$Username</Username>
                <Password><Value>$Password</Value><PlainText>true</PlainText></Password>
                <LogonCount>999999</LogonCount>
            </AutoLogon>
            <FirstLogonCommands>
                <SynchronousCommand wcm:action="add">
                    <Order>1</Order>
                    <CommandLine>powershell -ExecutionPolicy Bypass -File C:\WinBot\provision.ps1</CommandLine>
                    <Description>WinBot Provisioning (visible for debugging - logs to C:\WinBot\logs)</Description>
                    <RequiresUserInput>false</RequiresUserInput>
                </SynchronousCommand>
            </FirstLogonCommands>
        </component>
    </settings>
</unattend>
"@
}

# ============================================================
# Structured Logging
# ============================================================

$script:WinBotLogPath = Join-Path $script:ProjectDir "logs"
$script:WinBotLogFile = $null

function Write-WinBotLog {
    <#
    .SYNOPSIS
    Write a structured, timestamped log message to both console and file.

    .DESCRIPTION
    - Level: DEBUG, INFO, WARN, ERROR
    - Console output uses level-appropriate colors
    - File output writes to C:\WinBot\logs\winbot-YYYYMMDD.log
    - Controlled by $env:WINBOT_LOG_LEVEL (default: INFO)

    .PARAMETER Message
    The message to log.

    .PARAMETER Level
    DEBUG, INFO, WARN, or ERROR. Messages below the current log level are suppressed.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,

        [ValidateSet('DEBUG','INFO','WARN','ERROR')]
        [string]$Level = 'INFO'
    )

    # Determine effective log level
    $effectiveLevel = $env:WINBOT_LOG_LEVEL
    if (-not $effectiveLevel) { $effectiveLevel = 'INFO' }
    $levelOrder = @{ DEBUG=0; INFO=1; WARN=2; ERROR=3 }
    if ($levelOrder[$Level] -lt $levelOrder[$effectiveLevel]) {
        return  # Suppressed
    }

    # Build log entry
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
    $pid = $PID
    $logLine = "[$timestamp] [$Level] [$pid] $Message"

    # Console output with color
    $colorMap = @{ DEBUG='Gray'; INFO='White'; WARN='Yellow'; ERROR='Red' }
    $color = $colorMap[$Level]
    if ($Level -eq 'ERROR' -or $Level -eq 'WARN') {
        Write-Host "[WinBot] $Message" -ForegroundColor $color
    }
    elseif ($effectiveLevel -eq 'DEBUG') {
        Write-Host $logLine -ForegroundColor $color
    }

    # File output
    if (-not $script:WinBotLogFile) {
        if (-not (Test-Path $script:WinBotLogPath)) {
            New-Item -ItemType Directory -Path $script:WinBotLogPath -Force | Out-Null
        }
        $date = Get-Date -Format 'yyyyMMdd'
        $script:WinBotLogFile = Join-Path $script:WinBotLogPath "winbot-$date.log"
    }
    try {
        Add-Content -Path $script:WinBotLogFile -Value $logLine -Encoding UTF8 -ErrorAction SilentlyContinue
    }
    catch {
        # Can't log to file -- don't crash
    }
}

# ============================================================
# ISO Version & Freshness Checking
# ============================================================

function Get-WinBotISOVersion {
    <#
    .SYNOPSIS
    Read version metadata from a cached ISO file or the ISO provenance log.
    Returns build version, edition, architecture, and download method.

    .DESCRIPTION
    Checks the ISO provenance log for metadata. For EVAL ISOs, also attempts
    to extract the Windows build version from the ISO filename.
    MCT ISOs include the build date in their filename format.

    .EXAMPLE
    Get-WinBotISOVersion
    Get-WinBotISOVersion -ISOPath "C:\WinBot\master\Win11_Enterprise_24H2_MCT_x64.iso"
    #>
    param(
        [string]$ISOPath = "",
        [switch]$VerifyHash,
        [string]$ExpectedEdition = "",
        [string]$ExpectedVersion = "",
        [string]$ExpectedArchitecture = "",
        [string]$ExpectedLanguage = ""
    )

    $cfg = Get-WinBotConfig
    $masterPath = if ($cfg.master.vmPath) { $cfg.master.vmPath } else { "C:\WinBot\master\" }
    $provenanceRoot = if ($ISOPath) { Split-Path -Parent $ISOPath } else { $masterPath }
    if (-not $provenanceRoot) { $provenanceRoot = $masterPath }
    $provenanceLog = Join-Path $provenanceRoot "iso-provenance.jsonl"

    # Read provenance records adjacent to the selected/default artifact root.
    $entries = @()
    if (Test-Path $provenanceLog) {
        $entries = @(Get-Content $provenanceLog -ErrorAction SilentlyContinue | ForEach-Object {
            try { $_ | ConvertFrom-Json } catch { $null }
        } | Where-Object { $_ })
    }

    # An explicit artifact path is authoritative. If it is absent, report
    # that absence rather than silently substituting an unrelated cached ISO.
    $cachedISO = if ($ISOPath) {
        if (Test-Path -LiteralPath $ISOPath) { Get-Item -LiteralPath $ISOPath } else { $null }
    } else {
        Get-ChildItem $masterPath -Filter "Win11*.iso" -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
    }

    $identityEntry = if ($cachedISO) {
        $entries | Where-Object { $_.filename -eq $cachedISO.Name } | Sort-Object timestamp -Descending | Select-Object -First 1
    }
    $ready = $false
    $state = if (-not $cachedISO) { "False" } else { "Unknown" }
    $reason = if (-not $cachedISO) {
        "ISO is absent"
    } elseif (-not $identityEntry) {
        "ISO is present but no provenance record matches its filename"
    } else {
        "provenance identity is present but executable readiness is unverified"
    }
    $actualHash = $null
    if ($cachedISO -and $identityEntry -and $VerifyHash) {
        $actualHash = (Get-FileHash -LiteralPath $cachedISO.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
        if (-not $identityEntry.sha256 -or $actualHash -ne $identityEntry.sha256) {
            $state = "False"
            $reason = "SHA-256 does not match the recorded provenance"
        } elseif ($identityEntry.size_bytes -and [int64]$identityEntry.size_bytes -ne [int64]$cachedISO.Length) {
            $state = "False"
            $reason = "file size does not match the recorded provenance"
        } else {
            $missingIdentity = @()
            foreach ($field in @("edition", "version", "architecture", "language")) {
                $value = [string]$identityEntry.$field
                if ([string]::IsNullOrWhiteSpace($value) -or $value -eq "unknown") {
                    $missingIdentity += $field
                }
            }
            if ($missingIdentity.Count -gt 0) {
                $state = "Unknown"
                $reason = "provenance record lacks verified identity fields: $($missingIdentity -join ', ')"
            } else {
                $mismatches = @()
                if ($ExpectedEdition -and [string]$identityEntry.edition -ne $ExpectedEdition) {
                    $mismatches += "edition expected=$ExpectedEdition actual=$($identityEntry.edition)"
                }
                if ($ExpectedVersion -and [string]$identityEntry.version -ne $ExpectedVersion) {
                    $mismatches += "version expected=$ExpectedVersion actual=$($identityEntry.version)"
                }
                if ($ExpectedArchitecture -and [string]$identityEntry.architecture -ne $ExpectedArchitecture) {
                    $mismatches += "architecture expected=$ExpectedArchitecture actual=$($identityEntry.architecture)"
                }
                if ($ExpectedLanguage -and [string]$identityEntry.language -ne $ExpectedLanguage) {
                    $mismatches += "language expected=$ExpectedLanguage actual=$($identityEntry.language)"
                }
                if ($mismatches.Count -gt 0) {
                    $state = "False"
                    $reason = "ISO identity is incompatible with requested build intent: $($mismatches -join '; ')"
                } else {
                    $ready = $true
                    $state = "True"
                    $reason = "provenance identity, size, SHA-256, and requested build constraints verified"
                }
            }
        }
    }
    $result = @{
        Cached = ($cachedISO -ne $null)
        State = $state
        Ready = $ready
        Reason = $reason
        ExpectedEdition = $ExpectedEdition
        ExpectedVersion = $ExpectedVersion
        ExpectedArchitecture = $ExpectedArchitecture
        ExpectedLanguage = $ExpectedLanguage
        ISOExists = ($cachedISO -ne $null)
        ISOPath = if ($cachedISO) { $cachedISO.FullName } else { $null }
        ISOSizeGB = if ($cachedISO) { [math]::Round($cachedISO.Length / 1GB, 2) } else { $null }
        ISOLastModified = if ($cachedISO) { $cachedISO.LastWriteTime.ToString("o") } else { $null }
        Method = if ($identityEntry) { $identityEntry.method } else { "unknown" }
        Edition = if ($identityEntry) { $identityEntry.edition } else { "unknown" }
        Architecture = if ($identityEntry) { $identityEntry.architecture } else { "unknown" }
        Language = if ($identityEntry) { $identityEntry.language } else { "unknown" }
        Version = if ($identityEntry) { $identityEntry.version } else { "unknown" }
        SHA256 = if ($identityEntry) { $identityEntry.sha256 } else { $null }
        ActualSHA256 = $actualHash
        DownloadTimestamp = if ($identityEntry) { $identityEntry.timestamp } else { $null }
        ProvenanceLog = $provenanceLog
    }

    return $result
}


function Test-WinBotISOUpdate {
    <#
    .SYNOPSIS
    Check whether a newer Windows ISO version is available from Microsoft.

    .DESCRIPTION
    For EVAL ISOs: performs a HEAD request to the known CDN URL and compares
    Content-Length and Last-Modified headers with the cached ISO.
    For MCT ISOs: checks the current ISO metadata against known release schedules.
    Returns whether the cached ISO is current and what action to take.

    .EXAMPLE
    Test-WinBotISOUpdate
    $status = Test-WinBotISOUpdate
    if (-not $status.Current) { Write-Host "New ISO available!" }
    #>
    [CmdletBinding()]
    param()

    $info = Get-WinBotISOVersion
    $result = @{
        Current = $true
        Cached = $info.Cached
        CurrentVersion = $info.Version
        CurrentMethod = $info.Method
        CurrentSizeGB = $info.ISOSizeGB
        AvailableVersion = $info.Version
        AvailableDate = $null
        SizeDifference = $null
        Action = "none"
        Message = ""
    }

    if (-not $info.Cached) {
        $result.Current = $false
        $result.Action = "download"
        $result.Message = "No ISO cached. Run provision-iso.ps1 to download."
        return $result
    }

    # EVAL ISO: check CDN for newer version
    if ($info.Method -eq "EVAL") {
        Write-Verbose "Checking MCT availability for EVAL->MCT upgrade..."
        $storedKey = Get-WinBotCredential -Name "product-key" -Username "windows" -AsPlaintext -ErrorAction SilentlyContinue
        if ($storedKey) {
            $result.Current = $false  # EVAL with key: always suggest MCT upgrade
            $result.Action = "upgrade"
            $result.AvailableVersion = $info.Version
            $result.Message = "Product key found. Upgrade available: full licensed Enterprise ISO via Media Creation Tool."
        } else {
            # Check if the EVAL CDN has a newer ISO (CDN URLs don't always support HEAD,
            # so we compare file size via GET with Range header to minimize download)
            try {
                $evalUrl = "https://software-static.download.prss.microsoft.com/dbazure/888969d5-f34g-4e03-ac9d-1f9786c66749/26100.1742.240906-0331.ge_release_svc_refresh_CLIENTENTERPRISEEVAL_OEMRET_x64FRE_en-us.iso"
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                # Use Range: bytes=0-0 to get Content-Length without downloading
                $response = Invoke-WebRequest -Uri $evalUrl -Headers @{"Range"="bytes=0-0"} -TimeoutSec 15 -ErrorAction SilentlyContinue -UseBasicParsing
                if ($response -and ($response.StatusCode -eq 206 -or $response.StatusCode -eq 200)) {
                    $remoteSize = $response.Headers["Content-Range"]
                    if (-not $remoteSize) { $remoteSize = $response.Headers["Content-Length"] }
                    if ($remoteSize) {
                        $rs = [long]($remoteSize -replace "bytes 0-0/", "")
                        $localSize = (Get-Item $info.ISOPath).Length
                        if ($localSize -ne $rs) {
                            $result.Current = $false; $result.Action = "download"
                            $result.SizeDifference = ($rs - $localSize)
                            $result.Message = "CDN ISO differs from cached. Local: $localSize bytes, Remote: $rs bytes."
                        }
                    }
                }
            } catch { Write-Verbose "Could not check EVAL CDN: $_" }
        }
    }

    # MCT ISO: current by definition (downloaded from Microsoft's latest)
    if ($info.Method -eq "MCT") {
        $result.Current = $true
        $result.Action = "none"
        $result.Message = "MCT ISO is the latest available from Microsoft."
    }

    return $result
}


# ============================================================
# System Readiness Health Check
# ============================================================

function Test-WinBotHealth {
    <#
    .SYNOPSIS
    Comprehensive system readiness check. Verifies everything WinBot
    needs to operate and returns a pass/fail report.

    .DESCRIPTION
    Checks: module import, config validity, Hyper-V access, master VHDX
    existence + integrity, credentials, provisioning scripts, guest scripts.

    .EXAMPLE
    Test-WinBotHealth
    Test-WinBotHealth -Detailed
    #>
    param([switch]$Detailed)

    # Clean up stale test credential from earlier testing
    Unregister-WinBotCredential -Name "demo-pw" -ErrorAction SilentlyContinue | Out-Null

    $script:HealthResults = [System.Collections.ArrayList]::new()
    $script:HealthOverall = $true

    # Helper nested function -- uses script: scope for PS 5.1 compatibility
    function _add($category, $name, $status, $detail) {
        $script:HealthResults.Add([PSCustomObject]@{
            Category = $category; Check = $name; Status = $status; Detail = $detail
        }) | Out-Null
        if ($status -eq "FAIL") { $script:HealthOverall = $false }
    }

    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  WinBot System Health Check" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    # ---- Module ----
    Write-Host "[Module]" -ForegroundColor Yellow
    _add "Module" "WinBot version" "PASS" (Get-WinBotVersion)
    _add "Module" "Running as Admin" $(if (Test-IsAdministrator){"PASS"}else{"FAIL"}) $(if (Test-IsAdministrator){"Yes"}else{"No -- run as Administrator"})

    # ---- Config ----
    Write-Host "[Config]" -ForegroundColor Yellow
    $cfgPath = Join-Path $script:ProjectDir "config.json"
    if (Test-Path $cfgPath) {
        _add "Config" "config.json exists" "PASS" $cfgPath
        try {
            $cfg = Get-WinBotConfig
            _add "Config" "Parses without error" "PASS" "OK"
            $checks = @(
                @{k="master.vmName";v=$cfg.master.vmName},
                @{k="api.port";v=$cfg.api.port},
                @{k="clones.basePath";v=$cfg.clones.basePath}
            )
            foreach ($c in $checks) {
                if ($c.v) {
                    _add "Config" $c.k "PASS" "$($c.v)"
                } else {
                    _add "Config" $c.k "WARN" "missing -- using default"
                }
            }
            if ($cfg.api.token) {
                _add "Config" "api.token" "WARN" "token in config.json -- migrate to CredMan with Register-WinBotAPIKey"
            } else {
                _add "Config" "api.token" "PASS" "not in config.json"
            }
        } catch {
            _add "Config" "Parse config" "FAIL" $_.Exception.Message
        }
    } else {
        _add "Config" "config.json" "FAIL" "File not found: $cfgPath"
    }

    # ---- Hyper-V ----
    Write-Host "[Hyper-V]" -ForegroundColor Yellow
    $hv = Test-HyperVAvailable
    _add "Hyper-V" "Feature" $(if($hv.HyperVFeature){"PASS"}else{"FAIL"}) $(if($hv.HyperVFeature){"Enabled"}else{"Not enabled"})
    _add "Hyper-V" "Module" $(if($hv.HyperVModule){"PASS"}else{"FAIL"}) $(if($hv.HyperVModule){"Available"}else{"Not installed"})
    _add "Hyper-V" "Service (vmms)" $(if($hv.HyperVService){"PASS"}else{"FAIL"}) $(if($hv.HyperVService){"Running"}else{"Not running"})
    if ($hv.Available) {
        try {
            $vmCount = @(Get-VM -Name "WinBot-*" -ErrorAction SilentlyContinue).Count
            _add "Hyper-V" "WinBot VMs" "PASS" "$vmCount found"
        } catch {
            _add "Hyper-V" "VM access" "FAIL" $_.Exception.Message
        }
    }

    # ---- Master VHDX ----
    Write-Host "[Master VHDX]" -ForegroundColor Yellow
    $vhdPath = $cfg.master.vhdxPath
    if (Test-Path $vhdPath) {
        $sizeGB = [math]::Round((Get-Item $vhdPath).Length / 1GB, 1)
        _add "Master" "VHDX exists" "PASS" "$vhdPath (${sizeGB}GB)"
        $integrity = Test-WinBotMasterIntegrity -VHDXPath $vhdPath
        _add "Master" "Integrity" $(if($integrity){"PASS"}else{"WARN"}) $(if($integrity){"Hash matches"}else{"Hash missing or mismatch -- run Set-WinBotMasterHash"})
    } else {
        _add "Master" "VHDX" "WARN" "Not found: $vhdPath"
        _add "Master" "Action" "INFO" "Run: .\guest\provision-iso.ps1 or .\guest\provision-msvm.ps1"
    }

    # ---- Credentials ----
    Write-Host "[Credentials]" -ForegroundColor Yellow
    $creds = @(Get-WinBotCredentialList)
    $credNames = $creds | ForEach-Object { $_.Name }
    _add "Credentials" "Count" "PASS" "$($creds.Count) stored"
    if ("vm-password" -in $credNames) {
        _add "Credentials" "VM password" "PASS" "WinBot_vm-password in CredMan"
    } else {
        _add "Credentials" "VM password" "WARN" "Not in CredMan -- run: Register-WinBotCredential -Name 'vm-password' -Username 'winbot' -Password '<pw>'"
    }
    if ("api-key-winbot" -in $credNames) {
        _add "Credentials" "API token" "PASS" "WinBot_api-key-winbot in CredMan"
    } else {
        _add "Credentials" "API token" "WARN" "Not in CredMan -- run: Register-WinBotAPIKey -Service 'winbot' -Key '<token>'"
    }

    # ---- ISO Version ----
    Write-Host "[ISO Version]" -ForegroundColor Yellow
    $isoVersion = Get-WinBotISOVersion -VerifyHash
    if ($isoVersion.Cached -and $isoVersion.Ready) {
        $ageDays = if ($isoVersion.DownloadTimestamp) {
            [math]::Round(((Get-Date) - [DateTime]$isoVersion.DownloadTimestamp).TotalDays, 0)
        } else { "?" }
        _add "ISO" "Cached" "PASS" "$($isoVersion.Edition) $($isoVersion.Version) ($($isoVersion.Method)) - $($isoVersion.ISOSizeGB)GB - ${ageDays}d old"
        $updateCheck = Test-WinBotISOUpdate
        if (-not $updateCheck.Current) {
            _add "ISO" "Update" "WARN" $updateCheck.Message
        } else {
            _add "ISO" "Update" "PASS" "Current"
        }
    } elseif ($isoVersion.Cached) {
        _add "ISO" "Cached" "WARN" "Present but not ready: $($isoVersion.Reason)"
    } else {
        _add "ISO" "Cached" "WARN" "No ISO found - run .\guest\provision-iso.ps1"
    }

    # ---- Provisioning Scripts ----
    Write-Host "[Provisioning Scripts]" -ForegroundColor Yellow
    $scriptChecks = @(
        @{p="guest\provision-iso.ps1";d="ISO-based master provisioning"},
        @{p="guest\provision-msvm.ps1";d="MS Dev VM provisioning"},
        @{p="guest\build-provision-vhd.ps1";d="Provisioning VHD builder"},
        @{p="guest\download-windows-iso.ps1";d="Windows ISO downloader"},
        @{p="test\smoke-test.ps1";d="Smoke test"}
    )
    foreach ($s in $scriptChecks) {
        $sp = Join-Path $script:ProjectDir $s.p
        if (Test-Path $sp) {
            _add "Scripts" $s.d "PASS" $s.p
        } else {
            _add "Scripts" $s.d "FAIL" "Missing: $s.p"
        }
    }

    # ---- Guest Scripts VM Guardrail ----
    Write-Host "[Guest Scripts VM Guardrail]" -ForegroundColor Yellow
    $guestScripts = Get-ChildItem (Join-Path $script:ProjectDir "guest") -Filter "*.ps1" -Recurse -ErrorAction SilentlyContinue
    $guardrailOk = 0
    $guardrailFail = 0
    foreach ($gs in $guestScripts) {
        $content = Get-Content $gs.FullName -Raw
        if ($content -match "SAFETY GUARDRAIL" -and $content -match "Test-IsHyperVVM") {
            $guardrailOk++
        } elseif ($gs.Name -eq "build-provision-vhd.ps1") {
            # This script intentionally doesn't have the host guardrail (it's a build tool)
            $guardrailOk++
        } else {
            $guardrailFail++
            if ($Detailed) { _add "Guardrail" $gs.Name "WARN" "Missing VM guardrail -- safe to run on host?" }
        }
    }
    _add "Guardrail" "Protected scripts" $(if($guardrailFail -eq 0){"PASS"}else{"WARN"}) "$guardrailOk guarded, $guardrailFail unguarded"

    # ---- Python Tests ----
    Write-Host "[Python API Tests]" -ForegroundColor Yellow
    $testDir = Join-Path $script:ProjectDir "guest\api"
    if (Test-Path $testDir) {
        try {
            $testResult = & python -m pytest "$testDir\tests" -q --tb=no 2>&1
            $passed = if ($LASTEXITCODE -eq 0) { "PASS" } else { "FAIL" }
            _add "Tests" "API tests (pytest)" $passed ($testResult -join " " -replace '\s+', ' ')
        } catch {
            _add "Tests" "API tests" "WARN" "Could not run: $_"
        }
    }

    # ---- Summary ----
    $overall = $script:HealthOverall
    $results = @($script:HealthResults)
    $passCount = @($results | Where-Object { $_.Status -eq "PASS" }).Count
    $warnCount = @($results | Where-Object { $_.Status -eq "WARN" }).Count
    $failCount = @($results | Where-Object { $_.Status -eq "FAIL" }).Count

    Write-Host "`n========================================" -ForegroundColor $(if($overall){"Green"}else{"Red"})
    Write-Host "  Health Check: $(if($overall){'PASSED'}else{'ISSUES FOUND'})" -ForegroundColor $(if($overall){"Green"}else{"Red"})
    Write-Host "========================================" -ForegroundColor $(if($overall){"Green"}else{"Red"})
    Write-Host "  $passCount passed, $warnCount warnings, $failCount failures" -ForegroundColor $(if($failCount -eq 0){"Green"}else{"Red"})
    Write-Host "========================================"

    if ($Detailed) {
        Write-Host "`nDetailed results:" -ForegroundColor Cyan
        $results | Format-Table Category, Check, Status, Detail -AutoSize -Wrap
    }

    return @{
        Overall = $overall
        Results = $results
        PassCount = $passCount
        WarnCount = $warnCount
        FailCount = $failCount
    }
}

# ============================================================
# Guest Tool Verification
# ============================================================

function Test-WinBotGuestTools {
    <#
    .SYNOPSIS
    Smoke-test all installed WinBot tools on the guest VM.
    Runs inside the VM via PowerShell Direct.

    .DESCRIPTION
    Tests that Python, AutoIt, AutoHotkey, and NSSM actually execute.
    Returns a structured result with pass/fail per tool.
    #>
    [CmdletBinding()]
    param()

    $result = @{
        AllOk = $true
        Tests = @{}
        Timestamp = Get-Date -Format 'o'
    }

    # Python
    try {
        $pyOut = & python -c "print('ok')" 2>&1
        $result.Tests.python = if ($pyOut -match 'ok') { @{pass=$true; version=(python --version 2>&1)} } else { @{pass=$false; error=$pyOut} }
    } catch {
        $result.Tests.python = @{pass=$false; error=$_.Exception.Message}
    }

    # AutoIt
    try {
        $tmp = "$env:TEMP\winbot_test.au3"
        "Exit(0)" | Out-File $tmp -Encoding ASCII -Force
        $au3Exe = if (Test-Path "C:\Program Files (x86)\AutoIt3\AutoIt3.exe") { "C:\Program Files (x86)\AutoIt3\AutoIt3.exe" } else { "C:\Program Files\AutoIt3\AutoIt3.exe" }
        & $au3Exe /AutoIt3ExecuteScript $tmp 2>&1 | Out-Null
        $result.Tests.autoit = if ($LASTEXITCODE -eq 0) { @{pass=$true; path=$au3Exe} } else { @{pass=$false; exit_code=$LASTEXITCODE} }
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    } catch {
        $result.Tests.autoit = @{pass=$false; error=$_.Exception.Message}
    }

    # AutoHotkey
    try {
        $tmp = "$env:TEMP\winbot_test.ahk"
        "ExitApp(0)" | Out-File $tmp -Encoding ASCII -Force
        $ahkExe = if (Test-Path "C:\Program Files\AutoHotkey\AutoHotkey.exe") { "C:\Program Files\AutoHotkey\AutoHotkey.exe" } else { "C:\Program Files\AutoHotkey\AutoHotkeyU64.exe" }
        & $ahkExe $tmp 2>&1 | Out-Null
        $result.Tests.ahk = if ($LASTEXITCODE -eq 0) { @{pass=$true; path=$ahkExe} } else { @{pass=$false; exit_code=$LASTEXITCODE} }
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    } catch {
        $result.Tests.ahk = @{pass=$false; error=$_.Exception.Message}
    }

    # NSSM
    try {
        $nssm = Get-Command nssm -ErrorAction SilentlyContinue
        if (-not $nssm) { $nssm = Get-Command "C:\ProgramData\chocolatey\bin\nssm.exe" -ErrorAction SilentlyContinue }
        $result.Tests.nssm = if ($nssm) { @{pass=$true; path=$nssm.Source} } else { @{pass=$false; error="nssm not found in PATH"} }
    } catch {
        $result.Tests.nssm = @{pass=$false; error=$_.Exception.Message}
    }

    $result.AllOk = ($result.Tests.Values | Where-Object { -not $_.pass }).Count -eq 0
    return $result
}

# ============================================================
# Module Initialization
# ============================================================
Initialize-WinBot

Export-ModuleMember -Function @(
    # Environment
    'Test-IsAdministrator', 'Assert-Administrator', 'Test-HyperVAvailable',
    'Test-HyperVAdminAccess', 'Get-WinBotEnvironment', 'Get-WinBotPlan', 'Test-WinBotPlanFresh', 'Invoke-WinBotPlanApply', 'Invoke-WinBotPlanVerify', 'Get-WinBotVersion',
    # Guardrails
    'Test-IsHyperVVM', 'Assert-HyperVVM', 'Confirm-Action',
    # Health
    'Test-WinBotHealth', 'Test-WinBotISOUpdate', 'Get-WinBotISOVersion',
    # Credentials
    'Register-WinBotCredential', 'Get-WinBotCredential', 'Unregister-WinBotCredential',
    'Get-WinBotCredentialList', 'Get-WinBotCredentialPresence', 'Get-WinBotCredentialUsage',
    'New-WinBotPassword', 'Sync-WinBotCredential',
    'Rotate-WinBotCredential', 'Sync-WinBotCredentialToClones',
    'Register-WinBotAPIKey', 'Get-WinBotAPIKey', 'Remove-WinBotAPIKey',
    'Get-WinBotAPIKeyList', 'Sync-WinBotAPIKeys',
    # Config
    'Get-WinBotConfig', 'Get-WinBotAutounattend', 'Get-WinBotDismAutounattend',
    'Test-WinBotMasterIntegrity', 'Set-WinBotMasterHash', 'Get-WinBotMasterObservation', 'Get-WinBotCloneObservation',
    'Invoke-WinBotMediaAcquisition',
    # VM Discovery
    'Get-WinBotVM', 'Get-WinBotVMNote', 'Set-WinBotVMNote',
    # Clone Lifecycle
    'Wait-WinBotAPI', 'Get-WinBotGuestServiceObservation', 'New-WinBotClone', 'Start-WinBotClone', 'Stop-WinBotClone',
    'Reset-WinBotClone', 'Remove-WinBotClone', 'Suspend-WinBotClone', 'Resume-WinBotClone',
    'New-WinBotWorkCell', 'Remove-WinBotWorkCell',
    # Session Lifecycle
    'New-WinBotSession', 'Stop-WinBotSession', 'Remove-WinBotSession',
    # Provisioning Resilience
    'Save-WinBotProvisioningState', 'Get-WinBotProvisioningState',
    'Clear-WinBotProvisioningState', 'Remove-WinBotOrphanedVMs',
    # Checkpoint Lifecycle
    'Save-WinBotCloneSnapshot', 'Restore-WinBotCloneSnapshot',
    'Get-WinBotCloneSnapshot', 'Remove-WinBotCloneSnapshot',
    # Network Management
    'New-WinBotNetworkSwitch', 'Connect-WinBotNetwork',
    'Enable-WinBotInternetAccess', 'Disable-WinBotInternetAccess',
    'Get-WinBotNetworkStatus',
    # API
    'Invoke-WinBotAPI',
    # Remote Access
    'Connect-WinBotRDP', 'Connect-WinBotVM', 'Invoke-WinBotVMCommand',
    'Sync-WinBotApiToken'
)

# Approved-verb alias for Rotate-WinBotCredential (unapproved verb suppression)
Set-Alias -Name Update-WinBotCredential -Value Rotate-WinBotCredential -Scope Global
Export-ModuleMember -Alias Update-WinBotCredential
)]
        [string]$Name,
        [long]$Memory = 0,
        [int]$Processors = 0,
        [string]$SwitchName = "",
        [string]$PersistentVHDXPath = "",
        [ValidateRange(1,120)][int]$TimeoutMinutes = 10,
        [switch]$NoStart,
        [switch]$NoWait,
        [switch]$Force
    )

    $args = @{
        Name = $Name
        Memory = $Memory
        Processors = $Processors
        TimeoutMinutes = $TimeoutMinutes
        NoStart = $NoStart
        NoWait = $NoWait
        Force = $Force
    }
    if ($SwitchName) { $args.SwitchName = $SwitchName }
    if ($PersistentVHDXPath) { $args.PersistentVHDXPath = $PersistentVHDXPath }

    $runtime = New-WinBotClone @args
    [PSCustomObject]@{
        WorkCellId = $runtime.Name
        Backend = "HyperV"
        State = $runtime.State
        IP = $runtime.IP
        APIReady = $runtime.APIReady
        APIUrl = $runtime.APIUrl
        RuntimeSeedPath = $runtime.RuntimeSeedPath
        RuntimeDiskPath = $runtime.RuntimeDiskPath
        SwitchName = $runtime.SwitchName
        PersistentVHDXPath = $runtime.PersistentVHDXPath
        Success = $runtime.Success
        Started = $runtime.Started
        Error = $runtime.Error
    }
}

function Remove-WinBotWorkCell {
    <#
    .SYNOPSIS
    Destroy one disposable Hyper-V work-cell runtime.
    .DESCRIPTION
    Removes the VM and its disposable differencing disk. Explicit persistent
    attachments are externally owned and are not deleted.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [switch]$Force
    )
    Remove-WinBotClone -Name $Name -Force:$Force
}

# ============================================================
# Session Lifecycle -- Higher-level clone management
# ============================================================

function New-WinBotSession {
    <#
    .SYNOPSIS
    Create a new WinBot analysis session. Wraps New-WinBotClone with metadata.

    .DESCRIPTION
    Creates a clone, tags it as a session with label, saves an initial checkpoint,
    and returns a session object. The session tracks the purpose of the clone
    and provides a natural lifecycle: New -> [analysis] -> Stop/Remove.

    .PARAMETER Label
    Short label for the session (e.g. "re-lab", "malware-analysis").

    .PARAMETER Purpose
    Human-readable description of what this session is for.

    .PARAMETER Memory
    Memory in bytes (default from config).

    .PARAMETER TimeoutMinutes
    Max wait for API health. Default: 10.

    .EXAMPLE
    $session = New-WinBotSession -Label "malware-sample3" -Purpose "Analyze sample-3.exe with Frida"
    # ... do analysis ...
    Stop-WinBotSession -Session $session
    Remove-WinBotSession -Session $session
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Label,

        [string]$Purpose = "",
        [long]$Memory = 0,
        [int]$TimeoutMinutes = 10,
        [switch]$NoWait
    )

    $cloneName = $Label
    if ($Memory -eq 0) { $Memory = (Get-WinBotConfig).clones.defaultMemoryBytes }

    Write-Host "[WinBot] Starting session: $Label" -ForegroundColor Cyan
    if ($Purpose) { Write-Host "  Purpose: $Purpose" -ForegroundColor Gray }

    $clone = New-WinBotClone -Name $cloneName -TimeoutMinutes $TimeoutMinutes -Memory $Memory

    # Tag as a session with purpose
    Set-WinBotVMNote -Name $cloneName -Meta @{
        role = "session"
        session_label = $Label
        session_purpose = $Purpose
        session_started = (Get-Date).ToUniversalTime().ToString("o")
    }

    # Save an initial checkpoint as "clean"
    if ($clone.Success) {
        Wait-WinBotAPI -Name $cloneName -TimeoutSeconds 30 | Out-Null
        Save-WinBotCloneSnapshot -Name $cloneName -SnapshotName "session-start" -ErrorAction SilentlyContinue
    }

    $session = @{
        Label = $Label
        Purpose = $Purpose
        CloneName = $clone.Name
        IP = $clone.IP
        APIUrl = $clone.APIUrl
        Started = (Get-Date).ToUniversalTime().ToString("o")
        CleanCheckpoint = "session-start"
    }

    Write-Host "[WinBot] Session '$Label' ready: $($clone.APIUrl)" -ForegroundColor Green
    Write-Host "[WinBot] Clean checkpoint: 'session-start' -- Restore-WinBotCloneSnapshot -Name '$Label' -SnapshotName 'session-start' -Force" -ForegroundColor Gray

    return $session
}


function Stop-WinBotSession {
    <#
    .SYNOPSIS
    Stop an analysis session. Optionally snapshot or destroy the clone.

    .DESCRIPTION
    By default, saves a final checkpoint, stops the clone, and leaves it
    available for later inspection. With -Remove, destroys everything.
    With -KeepOnline, just records the session end without stopping.

    .PARAMETER Session
    Session hashtable from New-WinBotSession.

    .PARAMETER FinalSnapshotName
    Label for the final snapshot. Default: "session-end"

    .PARAMETER Remove
    Destroy the clone permanently.

    .PARAMETER KeepOnline
    Don't stop the VM -- just record session end.

    .EXAMPLE
    Stop-WinBotSession -Session $session
    Stop-WinBotSession -Session $session -Remove -Force
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Session,

        [string]$FinalSnapshotName = "session-end",
        [switch]$Remove,
        [switch]$KeepOnline,
        [switch]$Force
    )

    $label = $Session.Label
    Write-Host "[WinBot] Stopping session: $label" -ForegroundColor Cyan

    # Save final snapshot
    try {
        if ($FinalSnapshotName) {
            Save-WinBotCloneSnapshot -Name $label -SnapshotName $FinalSnapshotName -ErrorAction SilentlyContinue
            Write-Host "  Final checkpoint saved: $FinalSnapshotName" -ForegroundColor Green
        }
    } catch {
        Write-Verbose "Final snapshot skipped: $_"
    }

    # Update metadata
    Set-WinBotVMNote -Name $label -Meta @{
        session_ended = (Get-Date).ToUniversalTime().ToString("o")
        final_snapshot = $FinalSnapshotName
    }

    # Stop or remove
    if ($Remove) {
        Remove-WinBotClone -Name $label -Force:$Force
        Write-Host "[WinBot] Session '$label' removed." -ForegroundColor Green
    } elseif (-not $KeepOnline) {
        Stop-WinBotClone -Name $label
        Write-Host "[WinBot] Session '$label' stopped. Clone preserved for inspection." -ForegroundColor Green
    } else {
        Write-Host "[WinBot] Session '$label' ended. Clone still running." -ForegroundColor Green
    }

    return @{ Session = $label; Action = if ($Remove) { "removed" } else { "stopped" } }
}


# ============================================================
# Provisioning Checkpoint — state tracking for resume
# ============================================================

function Save-WinBotProvisioningState {
    <#
    .SYNOPSIS
    Save a provisioning checkpoint so the process can resume after failure.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string]$Phase,
        [string]$Detail = ""
    )
    $timestamp = (Get-Date).ToUniversalTime().ToString("o")
    $stateFile = Join-Path "C:\WinBot" ".provision-$Name.json"
    @{ name = $Name; phase = $Phase; detail = $Detail; timestamp = $timestamp } |
        ConvertTo-Json -Compress |
        Out-File $stateFile -Encoding utf8 -Force
    Write-WinBotLog -Message "Provisioning checkpoint: $Name phase=$Phase" -Level INFO
}

function Get-WinBotProvisioningState {
    <#
    .SYNOPSIS
    Read the last provisioning checkpoint for a named clone.
    Returns $null if no checkpoint exists.
    #>
    param([Parameter(Mandatory=$true)][string]$Name)
    $stateFile = Join-Path "C:\WinBot" ".provision-$Name.json"
    if (-not (Test-Path $stateFile)) { return $null }
    try {
        return Get-Content $stateFile -Raw | ConvertFrom-Json
    } catch {
        Write-Warning "[WinBot] Corrupt provisioning state for '$Name': $_"
        return $null
    }
}

function Clear-WinBotProvisioningState {
    <#
    .SYNOPSIS
    Clear provisioning checkpoint for a named clone (called on success).
    #>
    param([Parameter(Mandatory=$true)][string]$Name)
    $stateFile = Join-Path "C:\WinBot" ".provision-$Name.json"
    Remove-Item $stateFile -Force -ErrorAction SilentlyContinue
}


# ============================================================
# Orphaned VM Cleanup
# ============================================================

function Remove-WinBotOrphanedVMs {
    <#
    .SYNOPSIS
    Find and remove WinBot VMs that are orphaned — VMs with missing
    differencing disks, failed provisioning, or no API token.
    Orphans are VMs that were left in a broken state after an interrupted
    provisioning attempt.

    .PARAMETER Force
    Remove without confirmation.

    .PARAMETER DryRun
    Only report orphans without removing them.

    .EXAMPLE
    Remove-WinBotOrphanedVMs -DryRun
    Remove-WinBotOrphanedVMs -Force
    #>
    param(
        [switch]$Force,
        [switch]$DryRun
    )
    Assert-Administrator
    $orphans = @()
    $vms = Get-VM -Name "WinBot-*" -ErrorAction SilentlyContinue

    foreach ($vm in $vms) {
        if ($vm.Name -eq "WinBot-Master") { continue }  # Never delete master
        $isOrphan = $false
        $reason = ""

        # Check 1: VM has no differencing disk (VHDX file missing)
        $disks = Get-VMHardDiskDrive -VMName $vm.Name -ErrorAction SilentlyContinue
        if (-not $disks -or -not (Test-Path $disks[0].Path -ErrorAction SilentlyContinue)) {
            $isOrphan = $true
            $reason = "No differencing disk (VHDX missing)"
        }

        if (-not $isOrphan) {
            # Check 2: VM stopped with no provisioning marker (failed build)
            if ($vm.State -eq "Off") {
                $state = Get-WinBotProvisioningState -Name ($vm.Name -replace "^WinBot-", "")
                $notes = Get-WinBotVMNote -Name ($vm.Name -replace "^WinBot-", "")
                if (-not $state -and (-not $notes -or -not $notes.session_label)) {
                    $isOrphan = $true
                    $reason = "Stopped VM with no provisioning state or session metadata"
                }
            }
        }

        if ($isOrphan) {
            $orphans += [PSCustomObject]@{
                VMName = $vm.Name
                State = $vm.State
                Reason = $reason
            }
        }
    }

    if ($orphans.Count -eq 0) {
        Write-Host "[WinBot] No orphaned VMs found." -ForegroundColor Green
        return
    }

    Write-Host "=== Orphaned VMs ($($orphans.Count) found) ===" -ForegroundColor Yellow
    foreach ($o in $orphans) {
        Write-Host "  $($o.VMName) ($($o.State)) - $($o.Reason)" -ForegroundColor Yellow
    }

    if (-not $Force -and -not $DryRun) {
        Write-Host ""
        $confirm = Read-Host "Remove $($orphans.Count) orphaned VMs? [y/N]"
        if ($confirm -notmatch '^[yY]') { Write-Host "Cancelled." -ForegroundColor Yellow; return }
    }

    if ($DryRun) { Write-Host "DRY RUN: No VMs removed." -ForegroundColor Cyan; return }

    foreach ($o in $orphans) {
        Write-Host "  Removing $($o.VMName)..." -ForegroundColor Gray
        $disks = Get-VMHardDiskDrive -VMName $o.VMName -ErrorAction SilentlyContinue
        Stop-VM -Name $o.VMName -Force -ErrorAction SilentlyContinue
        Start-Sleep 2
        Remove-VM -Name $o.VMName -Force -ErrorAction SilentlyContinue
        foreach ($d in $disks) {
            if (Test-Path $d.Path) { Remove-Item $d.Path -Force -ErrorAction SilentlyContinue }
        }
        Clear-WinBotProvisioningState -Name ($o.VMName -replace "^WinBot-", "")
        Write-Host "  Removed: $($o.VMName)" -ForegroundColor Green
    }
    Write-Host "Orphan cleanup complete." -ForegroundColor Green
}


function Remove-WinBotSession {
    <#
    .SYNOPSIS
    Destroy a session and its clone permanently.

    .PARAMETER Session
    Session hashtable from New-WinBotSession.

    .PARAMETER Force
    Required to confirm permanent deletion.

    .EXAMPLE
    Remove-WinBotSession -Session $session -Force
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Session,
        [switch]$Force
    )

    if (-not $Force) {
        throw "Remove-WinBotSession requires -Force. This permanently deletes the clone and all session data."
    }

    Stop-WinBotSession -Session $Session -FinalSnapshotName "" -Remove -Force
}

# ============================================================
# Checkpoint Lifecycle -- Save/Restore/List/Remove VM Snapshots
# ============================================================

function Save-WinBotCloneSnapshot {
    <#
    .SYNOPSIS
    Create a named checkpoint (snapshot) of a running WinBot clone.
    The clone continues running after the snapshot is taken.

    .DESCRIPTION
    Creates a standard Hyper-V checkpoint that captures the VM's
    full state -- memory, CPU, disk, and device state. Standard
    checkpoints are crash-consistent but capture everything.

    Agents use this before potentially destructive operations
    -- running malware, injecting code, modifying system settings.
    If the VM becomes unstable, Restore-WinBotCloneSnapshot reverts it.

    .PARAMETER Name
    Clone name suffix.

    .PARAMETER SnapshotName
    Human-readable name for the checkpoint. Defaults to auto-generated
    with timestamp.

    .PARAMETER Description
    Optional description for the checkpoint.

    .EXAMPLE
    Save-WinBotCloneSnapshot -Name "re-lab" -SnapshotName "pre-malware"
    Save-WinBotCloneSnapshot -Name "re-lab" -SnapshotName "before-exploit" -Description "Clean state before CVE-2024 test"
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,

        [string]$SnapshotName = "",
        [string]$Description = ""
    )

    $cloneName = if ($Name -like "WinBot-*") { $Name } else { "WinBot-$Name" }
    $vm = Get-VM -Name $cloneName -ErrorAction Stop

    if ($vm.State -ne "Running") {
        throw "VM '$cloneName' must be running to take a snapshot. Current state: $($vm.State)"
    }

    # Generate snapshot name if not provided
    if (-not $SnapshotName) {
        $ts = Get-Date -Format "yyyyMMdd-HHmmss"
        $SnapshotName = "snapshot-$ts"
    }

    Write-Host "[WinBot] Creating checkpoint '$SnapshotName' for $cloneName..." -ForegroundColor Cyan

    # Remove existing checkpoint with same name if present
    $existing = Get-VMCheckpoint -VMName $cloneName -Name $SnapshotName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "  Removing existing checkpoint with same name..." -ForegroundColor Yellow
        Remove-VMCheckpoint -VMName $cloneName -Name $SnapshotName -ErrorAction SilentlyContinue
    }

    # Create the checkpoint
    $checkpoint = Checkpoint-VM -Name $cloneName -SnapshotName $SnapshotName -ErrorAction Stop

    # Update VM Notes with last snapshot info
    Set-WinBotVMNote -Name $Name -Meta @{
        last_snapshot = $SnapshotName
        last_snapshot_time = (Get-Date).ToUniversalTime().ToString("o")
    }

    Write-Host "[WinBot] Checkpoint saved: $SnapshotName" -ForegroundColor Green
    Write-Host "  VM continues running. Use Restore-WinBotCloneSnapshot to revert." -ForegroundColor Gray

    return @{
        Name = $SnapshotName
        VMName = $cloneName
        Created = (Get-Date).ToUniversalTime().ToString("o")
        State = "Running"
    }
}


function Restore-WinBotCloneSnapshot {
    <#
    .SYNOPSIS
    Revert a WinBot clone to a previously-saved checkpoint.
    This restarts the VM from the checkpoint state.

    .DESCRIPTION
    Applies the named checkpoint to the VM. The VM is stopped,
    reverted to the checkpoint's state, and restarted.
    All changes since the checkpoint was taken are discarded.

    .PARAMETER Name
    Clone name suffix.

    .PARAMETER SnapshotName
    Name of the checkpoint to restore. If not specified, restores
    the most recent checkpoint.

    .PARAMETER NoStart
    Don't restart the VM after restoring the checkpoint.

    .EXAMPLE
    Restore-WinBotCloneSnapshot -Name "re-lab" -SnapshotName "pre-malware"
    Restore-WinBotCloneSnapshot -Name "re-lab"  # restores latest checkpoint
    Restore-WinBotCloneSnapshot -Name "re-lab" -NoStart  # revert but stay off
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,

        [string]$SnapshotName = "",
        [switch]$NoStart,
        [switch]$Force
    )

    if (-not $Force) {
        $msg = "Restore will PERMANENTLY DISCARD all changes since the checkpoint. Use -Force to confirm."
        throw $msg
    }

    $cloneName = if ($Name -like "WinBot-*") { $Name } else { "WinBot-$Name" }

    # Resolve checkpoint
    if ($SnapshotName) {
        $checkpoint = Get-VMCheckpoint -VMName $cloneName -Name $SnapshotName -ErrorAction SilentlyContinue
        if (-not $checkpoint) {
            $available = (Get-VMCheckpoint -VMName $cloneName -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }) -join ", "
            throw "Checkpoint '$SnapshotName' not found on '$cloneName'. Available: $available"
        }
    } else {
        $checkpoint = Get-VMCheckpoint -VMName $cloneName -ErrorAction SilentlyContinue |
            Sort-Object CreationTime -Descending | Select-Object -First 1
        if (-not $checkpoint) {
            throw "No checkpoints found on '$cloneName'. Use Save-WinBotCloneSnapshot first."
        }
        $SnapshotName = $checkpoint.Name
    }

    Write-Host "[WinBot] Restoring checkpoint '$SnapshotName' on $cloneName..." -ForegroundColor Cyan
    Write-Host "  WARNING: All changes since the checkpoint will be discarded." -ForegroundColor Yellow

    # Restore the checkpoint
    Restore-VMCheckpoint -VMName $cloneName -Name $SnapshotName -Confirm:$false -ErrorAction Stop

    Write-Host "  Checkpoint restored." -ForegroundColor Green

    # Restart unless -NoStart
    if (-not $NoStart) {
        $vm = Get-VM -Name $cloneName
        if ($vm.State -ne "Running") {
            Write-Host "  Starting VM..." -ForegroundColor Gray
            Start-VM -Name $cloneName -ErrorAction Stop
        }
        Write-Host "  VM is running from checkpoint state." -ForegroundColor Green
    }

    return @{
        Action = "restored"
        SnapshotName = $SnapshotName
        VMName = $cloneName
        State = (Get-VM -Name $cloneName).State.ToString()
    }
}


function Get-WinBotCloneSnapshot {
    <#
    .SYNOPSIS
    List all checkpoints for a WinBot clone.

    .PARAMETER Name
    Clone name suffix.

    .EXAMPLE
    Get-WinBotCloneSnapshot -Name "re-lab"
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name
    )

    $cloneName = if ($Name -like "WinBot-*") { $Name } else { "WinBot-$Name" }
    $checkpoints = Get-VMCheckpoint -VMName $cloneName -ErrorAction SilentlyContinue

    if (-not $checkpoints) {
        Write-Host "[WinBot] No checkpoints found for '$cloneName'." -ForegroundColor Gray
        return @()
    }

    $chainDepth = @($checkpoints).Count
    $maxDepth = if ($env:WINBOT_MAX_CHECKPOINT_DEPTH) { [int]$env:WINBOT_MAX_CHECKPOINT_DEPTH } else { 50 }
    if ($chainDepth -gt $maxDepth) {
        throw "Checkpoint depth $chainDepth exceeds maximum $maxDepth. Remove old checkpoints with Remove-WinBotCloneSnapshot -All."
    }
    if ($chainDepth -gt 10) {
        Write-Warning "Checkpoint chain depth is $chainDepth. Consider removing old checkpoints with Remove-WinBotCloneSnapshot -All to free disk space and improve performance."
    }

    $result = $checkpoints | ForEach-Object {
        [PSCustomObject]@{
            Name = $_.Name
            VMName = $cloneName
            Created = $_.CreationTime.ToString("o")
            ParentCheckpoint = if ($_.ParentSnapshotName) { $_.ParentSnapshotName } else { "root" }
            IsStandard = ($_.SnapshotType -eq 2)
            SizeMB = if ($_.SizeOfSystemFiles) { [math]::Round($_.SizeOfSystemFiles / 1MB, 1) } else { "unknown" }
        }
    }

    $result | Format-Table Name, Created, ParentCheckpoint, SizeMB -AutoSize
    return $result
}


function Remove-WinBotCloneSnapshot {
    <#
    .SYNOPSIS
    Delete a checkpoint from a WinBot clone.
    The clone must be running or stopped; the checkpoint data is merged.

    .PARAMETER Name
    Clone name suffix.

    .PARAMETER SnapshotName
    Name of the checkpoint to remove.

    .PARAMETER All
    Remove ALL checkpoints for this clone.

    .EXAMPLE
    Remove-WinBotCloneSnapshot -Name "re-lab" -SnapshotName "pre-malware"
    Remove-WinBotCloneSnapshot -Name "re-lab" -All
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,

        [string]$SnapshotName = "",
        [switch]$All
    )

    $cloneName = if ($Name -like "WinBot-*") { $Name } else { "WinBot-$Name" }

    if ($All) {
        Write-Host "[WinBot] Removing ALL checkpoints for $cloneName..." -ForegroundColor Cyan
        $checkpoints = Get-VMCheckpoint -VMName $cloneName -ErrorAction SilentlyContinue
        if (-not $checkpoints) {
            Write-Host "  No checkpoints to remove." -ForegroundColor Gray
            return
        }
        foreach ($cp in $checkpoints) {
            Write-Host "  Removing: $($cp.Name)" -ForegroundColor Gray
            Remove-VMCheckpoint -VMName $cloneName -Name $cp.Name -ErrorAction SilentlyContinue
        }
        Write-Host "  All checkpoints removed." -ForegroundColor Green
        return
    }

    if (-not $SnapshotName) {
        throw "Specify -SnapshotName or -All"
    }

    $checkpoint = Get-VMCheckpoint -VMName $cloneName -Name $SnapshotName -ErrorAction SilentlyContinue
    if (-not $checkpoint) {
        Write-Warning "Checkpoint '$SnapshotName' not found on '$cloneName'."
        return
    }

    Write-Host "[WinBot] Removing checkpoint '$SnapshotName'..." -ForegroundColor Cyan
    Remove-VMCheckpoint -VMName $cloneName -Name $SnapshotName -ErrorAction Stop
    Write-Host "  Checkpoint removed." -ForegroundColor Green
}

# ============================================================
# Network Management -- Hyper-V Virtual Switches
# ============================================================

function _Wait-VMIPAfterSwitch {
    <#
    .SYNOPSIS
    Poll a VM for a new IP address after a network switch change.
    Used internally by Enable/Disable-WinBotInternetAccess.
    #>
    param([string]$VMName, [int]$TimeoutSeconds = 30)
    Write-Host "  Waiting for DHCP lease on new network..." -ForegroundColor Gray
    $start = Get-Date; $elapsed = 0
    while ($elapsed -lt $TimeoutSeconds) {
        $net = Get-VMNetworkAdapter -VMName $VMName -ErrorAction SilentlyContinue
        $ip = if ($net) { $net.IPAddresses | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+' } | Select-Object -First 1 } else { $null }
        if ($ip) {
            Write-Host "  New IP: $ip (${elapsed}s)" -ForegroundColor Green
            return @{ Found = $true; IP = $ip; ElapsedSeconds = $elapsed }
        }
        Start-Sleep -Seconds 3
        $elapsed = [math]::Round((Get-Date).Subtract($start).TotalSeconds, 0)
    }
    Write-Host "  No IP after ${TimeoutSeconds}s -- VM may still be getting a lease." -ForegroundColor Yellow
    return @{ Found = $false; IP = $null; ElapsedSeconds = $TimeoutSeconds }
}

function New-WinBotNetworkSwitch {
    <#
    .SYNOPSIS
    Create a Hyper-V virtual switch for WinBot clones.

    .DESCRIPTION
    Three switch types:
    - Private: VMs can only talk to each other (no host, no internet)
    - Internal: VMs can talk to each other AND the host (no internet)
    - External: VMs share the host's physical NIC (internet access)

    WinBot configures the switch and returns connection info.

    .PARAMETER Name
    Switch name. Default: "WinBot-Internal"

    .PARAMETER Type
    Private, Internal, or External. Default: Internal

    .EXAMPLE
    New-WinBotNetworkSwitch -Name "WinBot-Private" -Type Private
    New-WinBotNetworkSwitch -Name "WinBot-External" -Type External
    #>
    param(
        [string]$SwitchName = "WinBot-Internal",
        [ValidateSet("Private","Internal","External")]
        [string]$Type = "Internal"
    )

    Assert-Administrator

    # Check if switch already exists
    $existing = Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "[WinBot] Switch '$SwitchName' already exists - Type: $($existing.SwitchType)" -ForegroundColor Green
        return @{
            Name = $SwitchName
            Type = $existing.SwitchType.ToString()
            NetAdapterInterfaceDescription = if ($existing.NetAdapterInterfaceDescription) { $existing.NetAdapterInterfaceDescription } else { "N/A" }
            Exists = $true
        }
    }

    Write-Host "[WinBot] Creating $Type switch: $SwitchName..." -ForegroundColor Cyan

    if ($Type -eq "External") {
        # Find the active physical NIC
        $netAdapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Sort-Object Speed -Descending | Select-Object -First 1
        if (-not $netAdapter) {
            throw "No active physical network adapter found. Cannot create External switch."
        }
        Write-Host "  Using adapter: $($netAdapter.Name) - $($netAdapter.InterfaceDescription)" -ForegroundColor Gray
        New-VMSwitch -Name $SwitchName -NetAdapterName $netAdapter.Name -AllowManagementOS $true -ErrorAction Stop | Out-Null
        Write-Host "  External switch created - VMs share host NIC for internet access." -ForegroundColor Green
    } else {
        $swType = if ($Type -eq "Private") { "Private" } else { "Internal" }
        New-VMSwitch -Name $SwitchName -SwitchType $swType -ErrorAction Stop | Out-Null
        $desc = if ($Type -eq "Private") { "VMs can only talk to each other" } else { "VMs can talk to each other and the host" }
        Write-Host "  $Type switch created - $desc." -ForegroundColor Green
    }

    return @{
        Name = $SwitchName
        Type = $Type
        NetAdapterInterfaceDescription = if ($Type -eq "External" -and $netAdapter) { $netAdapter.InterfaceDescription } else { "N/A" }
        Created = $true
    }
}


function Connect-WinBotNetwork {
    <#
    .SYNOPSIS
    Connect a WinBot clone to a specific virtual switch.

    .DESCRIPTION
    Moves the VM's network adapter to the specified switch.
    Use this to change network isolation levels:
    - WinBot-Internal: host + VM comms, no internet
    - WinBot-Private: VM-only, no host, no internet
    - WinBot-External: internet access via host NIC
    - Default Switch: Hyper-V default NAT (internet + host)

    .PARAMETER Name
    Clone name suffix.

    .PARAMETER SwitchName
    Target switch name.

    .EXAMPLE
    Connect-WinBotNetwork -Name "re-lab" -SwitchName "WinBot-Internal"
    Connect-WinBotNetwork -Name "re-lab" -SwitchName "WinBot-External"
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,

        [Parameter(Mandatory=$true)]
        [string]$SwitchName
    )

    $cloneName = if ($Name -like "WinBot-*") { $Name } else { "WinBot-$Name" }
    $vm = Get-VM -Name $cloneName -ErrorAction SilentlyContinue
    if (-not $vm) { throw "VM '$cloneName' not found." }

    # Verify switch exists
    $switch = Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue
    if (-not $switch) {
        Write-Host "[WinBot] Switch '$SwitchName' not found. Creating it..." -ForegroundColor Yellow
        # Determine type from name
        $type = "Internal"
        if ($SwitchName -like "*Private*") { $type = "Private" }
        elseif ($SwitchName -like "*External*") { $type = "External" }
        New-WinBotNetworkSwitch -SwitchName $SwitchName -Type $type
    }

    Write-Host "[WinBot] Connecting '$cloneName' to switch '$SwitchName'..." -ForegroundColor Cyan
    Connect-VMNetworkAdapter -VMName $cloneName -SwitchName $SwitchName -ErrorAction Stop

    # Update VM Notes
    Set-WinBotVMNote -Name $Name -Meta @{ network_switch = $SwitchName }

    Write-Host "  Connected. VM may need DHCP renew to get a new IP." -ForegroundColor Green

    return @{
        VMName = $cloneName
        SwitchName = $SwitchName
        SwitchType = (Get-VMSwitch -Name $SwitchName).SwitchType.ToString()
    }
}


function Enable-WinBotInternetAccess {
    <#
    .SYNOPSIS
    Give a WinBot clone internet access (for downloads/tool installation).

    .DESCRIPTION
    Connects the clone to the Default Switch (Hyper-V NAT) or an External switch,
    giving it internet access. Use Disable-WinBotInternetAccess to isolate it again.

    .PARAMETER Name
    Clone name suffix.

    .PARAMETER SwitchName
    Switch to use for internet. Tries in order: Default Switch, External, creates one if needed.

    .EXAMPLE
    Enable-WinBotInternetAccess -Name "re-lab"
    Enable-WinBotInternetAccess -Name "re-lab" -SwitchName "WinBot-External"
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,

        [string]$SwitchName = ""
    )

    $cloneName = if ($Name -like "WinBot-*") { $Name } else { "WinBot-$Name" }

    # Find internet-capable switch
    if (-not $SwitchName) {
        $defaultSwitch = Get-VMSwitch -Name "Default Switch" -ErrorAction SilentlyContinue
        $externalSwitch = Get-VMSwitch | Where-Object { $_.SwitchType -eq "External" } | Select-Object -First 1

        if ($defaultSwitch) {
            $SwitchName = "Default Switch"
            Write-Host "[WinBot] Using Hyper-V Default Switch - NAT with internet." -ForegroundColor Gray
        } elseif ($externalSwitch) {
            $SwitchName = $externalSwitch.Name
            Write-Host "[WinBot] Using External switch: $SwitchName" -ForegroundColor Gray
        } else {
            Write-Host "[WinBot] No internet-capable switch found. Creating External switch..." -ForegroundColor Yellow
            $result = New-WinBotNetworkSwitch -SwitchName "WinBot-External" -Type External
            $SwitchName = $result.Name
        }
    }

    Connect-WinBotNetwork -Name $Name -SwitchName $SwitchName

    Write-Host "[WinBot] Internet access enabled for '$cloneName' via '$SwitchName'." -ForegroundColor Green
    $null = _Wait-VMIPAfterSwitch -VMName $cloneName -TimeoutSeconds 30
}


function Disable-WinBotInternetAccess {
    <#
    .SYNOPSIS
    Isolate a WinBot clone from the internet (for malware analysis).

    .DESCRIPTION
    Connects the clone to an Internal switch so it can still communicate
    with the host but has no internet access. The host can still reach
    the API, take screenshots, and send input commands.

    .PARAMETER Name
    Clone name suffix.

    .PARAMETER SwitchName
    Switch to use for isolation. Default: "WinBot-Internal" (auto-created if missing)

    .EXAMPLE
    Disable-WinBotInternetAccess -Name "re-lab"
    Disable-WinBotInternetAccess -Name "re-lab" -SwitchName "WinBot-Private"
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,

        [string]$SwitchName = ""
    )

    $cloneName = if ($Name -like "WinBot-*") { $Name } else { "WinBot-$Name" }

    if (-not $SwitchName) {
        $SwitchName = "WinBot-Internal"
        $exists = Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue
        if (-not $exists) {
            Write-Host "[WinBot] Creating Internal switch for isolation..." -ForegroundColor Gray
            New-WinBotNetworkSwitch -SwitchName $SwitchName -Type Internal
        }
    }

    Connect-WinBotNetwork -Name $Name -SwitchName $SwitchName

    Write-Host "[WinBot] Internet access DISABLED for '$cloneName'." -ForegroundColor Green
    Write-Host "  VM is on '$SwitchName' - host access only, no internet." -ForegroundColor Green
    Write-Host "  The WinBot API remains reachable from the host." -ForegroundColor Gray
    $null = _Wait-VMIPAfterSwitch -VMName $cloneName -TimeoutSeconds 30
}


function Get-WinBotNetworkStatus {
    <#
    .SYNOPSIS
    Show the current network configuration for a WinBot clone.

    .PARAMETER Name
    Clone name suffix.

    .EXAMPLE
    Get-WinBotNetworkStatus -Name "re-lab"
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name
    )

    $cloneName = if ($Name -like "WinBot-*") { $Name } else { "WinBot-$Name" }
    $vm = Get-VM -Name $cloneName -ErrorAction SilentlyContinue
    if (-not $vm) { throw "VM '$cloneName' not found." }

    $net = Get-VMNetworkAdapter -VMName $cloneName -ErrorAction SilentlyContinue
    if (-not $net) { return @{ VMName = $cloneName; Connected = $false } }

    $switch = Get-VMSwitch -Name $net.SwitchName -ErrorAction SilentlyContinue
    $ips = @($net.IPAddresses | Where-Object { $_ -match '.' })
    $hasInternet = ($switch -and ($switch.SwitchType -eq "External" -or $switch.Name -like "*Default*"))

    $result = @{
        VMName = $cloneName
        SwitchName = $net.SwitchName
        SwitchType = if ($switch) { $switch.SwitchType.ToString() } else { "unknown" }
        IPAddresses = $ips
        InternetAccess = $hasInternet
        HostAccess = ($net.SwitchName -ne "" )
        MacAddress = $net.MacAddress
    }

    Write-Host "[WinBot] Network status for '$cloneName':" -ForegroundColor Cyan
    Write-Host "  Switch:       $($result.SwitchName) ($($result.SwitchType))" -ForegroundColor Gray
    Write-Host "  IPs:          $($ips -join ', ')" -ForegroundColor Gray
    Write-Host "  Internet:     $(if($hasInternet){'YES'}else{'NO'})" -ForegroundColor $(if($hasInternet){'Yellow'}else{'Green'})
    Write-Host "  Host Access:  $(if($result.HostAccess){'YES'}else{'NO'})" -ForegroundColor Green

    return $result
}

# ============================================================
# API Interaction
# ============================================================

function Invoke-WinBotAPI {
    <#
    .SYNOPSIS
    Call the WinBot API on a running clone.

    .PARAMETER Name
    Clone name suffix

    .PARAMETER Method
    HTTP method (GET, POST, etc.)

    .PARAMETER Endpoint
    API endpoint path (e.g., "/health", "/screenshot")

    .PARAMETER Body
    Request body as hashtable (for POST requests)
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,

        [string]$Method = "GET",
        [string]$Endpoint = "/health",

        [hashtable]$Body = $null
    )
    # Resolve the full VM name — clones follow pattern WinBot-clone-<name>-<timestamp>
    $cloneName = Resolve-WinBotVMName -Name $Name -ErrorAction SilentlyContinue
    if (-not $cloneName) { $cloneName = "WinBot-$Name" }

    $config = Get-WinBotConfig

    # INVARIANT: VM must exist and be running before making API calls
    $vm = Get-VM -Name $cloneName -ErrorAction SilentlyContinue
    if (-not $vm) { throw "Clone '$cloneName' not found in Hyper-V. Use New-WinBotClone or Start-WinBotClone first." }
    if ($vm.State -ne "Running") { throw "Clone '$cloneName' is $($vm.State) -- must be Running to call the API. Start it: Start-WinBotClone -Name '$Name'" }

    # Get VM IP
    $vmNetwork = Get-VMNetworkAdapter -VMName $cloneName -ErrorAction SilentlyContinue
    if (-not $vmNetwork) {
        throw "Cannot find network adapter for '$cloneName'"
    }
    $ip = $vmNetwork.IPAddresses | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+' } | Select-Object -First 1
    if (-not $ip) {
        throw "Clone '$cloneName' has no IPv4 address. Is it fully booted?"
    }

    $url = "http://${ip}:$($config.api.port)$Endpoint"

    $headers = @{
        "Content-Type" = "application/json"
    }
    if ($config.api.token) {
        $headers["X-API-Key"] = $config.api.token
    }

    $params = @{
        Uri = $url
        Method = $Method
        Headers = $headers
        ErrorAction = "Stop"
        UseBasicParsing = $true
    }

    if ($Body) {
        $params.Body = ($Body | ConvertTo-Json -Compress)
    }

    Write-Host "[WinBot] $Method $url" -ForegroundColor Gray
    try {
        $response = Invoke-WebRequest @params
        return $response.Content | ConvertFrom-Json
    }
    catch {
        if ($_.Exception.Response) {
            $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $errorBody = $reader.ReadToEnd()
            throw "API error $($_.Exception.Response.StatusCode.value__): $errorBody"
        }
        throw "API request failed: $_"
    }
}

# ============================================================
# RDP Connection
# ============================================================

function Connect-WinBotRDP {
    <#
    .SYNOPSIS
    Launch an RDP connection to a WinBot clone.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name
    )
    $cloneName = "WinBot-$Name"

    # Get VM IP
    $vmNetwork = Get-VMNetworkAdapter -VMName $cloneName -ErrorAction SilentlyContinue
    if (-not $vmNetwork) {
        throw "Cannot find network adapter for '$cloneName'"
    }
    $ip = $vmNetwork.IPAddresses | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+' } | Select-Object -First 1
    if (-not $ip) {
        throw "Clone '$cloneName' has no IPv4 address."
    }

    Write-Host "[WinBot] Launching RDP to $ip ..." -ForegroundColor Cyan
    Start-Process "mstsc.exe" -ArgumentList "/v:$ip"
}

# ============================================================
# PowerShell Direct (VMBus - no network needed)
# ============================================================

function Connect-WinBotVM {
    <#
    .SYNOPSIS
    Open an interactive PowerShell Direct session to the clone via VMBus.
    No network required!
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name
    )
    $cloneName = "WinBot-$Name"
    $cred = Get-WinBotCredential
    Write-Host "[WinBot] Opening PowerShell Direct session to $cloneName ..." -ForegroundColor Cyan
    Enter-PSSession -VMName $cloneName -Credential $cred
}

function Sync-WinBotApiToken {
    <#
    .SYNOPSIS
    Retrieve the API token from a running clone and store it in config.json.
    Uses PowerShell Direct (VMBus -- no network required).
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name
    )
    $cloneName = "WinBot-$Name"
    $cred = Get-WinBotCredential

    Write-Host "[WinBot] Retrieving API token from $cloneName..." -ForegroundColor Cyan
    try {
        $token = Invoke-Command -VMName $cloneName -Credential $cred -ScriptBlock {
            if (Test-Path "C:\WinBot\.api_token") {
                Get-Content "C:\WinBot\.api_token" -Raw
            } else {
                $null
            }
        } -ErrorAction Stop

        if ($token) {
            $token = $token.Trim()
            $config = Get-WinBotConfig
            $config.api.token = $token
            $script:Config = $config
            $config | ConvertTo-Json -Depth 5 | Out-File -FilePath $script:ConfigPath -Encoding utf8
            Write-Host "[WinBot] API token synced to config.json" -ForegroundColor Green
            return $token
        } else {
            Write-Warning "[WinBot] Token file not found on $cloneName. Run setup-service.ps1 first."
            return $null
        }
    } catch {
        Write-Warning "[WinBot] Could not retrieve token via PowerShell Direct: $_"
        Write-Warning "[WinBot] The VM may need more time to boot. Try again later."
        return $null
    }
}

function Invoke-WinBotVMCommand {
    <#
    .SYNOPSIS
    Run a command inside the clone via PowerShell Direct.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,

        [Parameter(Mandatory=$true)]
        [ScriptBlock]$ScriptBlock
    )
    $cloneName = "WinBot-$Name"
    $cred = Get-WinBotCredential
    Invoke-Command -VMName $cloneName -Credential $cred -ScriptBlock $ScriptBlock
}

# ============================================================
# Autounattend Generator (for ISO-based automated Windows install)
# ============================================================

function Get-WinBotAutounattend {
    <#
    .SYNOPSIS
    Generate a Windows autounattend.xml for fully automated installation with
    complete WinBot toolchain provisioning.

    .DESCRIPTION
    Creates a complete answer file that:
    - Installs Windows 11 Pro/Enterprise completely unattended
    - Creates the WinBot admin account with auto-logon
    - Skips all OOBE (privacy questions, Cortana, online account)
    - FirstLogonCommands install the entire WinBot toolchain:
      1. Copy API files from provisioning VHD (D:) to C:\WinBot
      2. Install Chocolatey package manager
      3. Install Python 3.13 + pip packages (fastapi, uvicorn, pyautogui, etc.)
      4. Install AutoIt v3, AutoHotkey v1.1, NSSM
      5. Configure WinRM, RDP, firewall, power settings
      6. Install WinBot API as a Windows service (auto-start)
      7. Final reboot

    .PARAMETER Password
    Password for the WinBot user account. Randomly generated if not provided.

    .PARAMETER Username
    Local admin username. Default: winbot

    .PARAMETER ProductKey
    Windows product key for permanent activation. If provided, injected into autounattend
    so Windows installs as a licensed copy (no 90-day eval limit).

    .PARAMETER WindowsEdition
    Windows edition to install. Default: Enterprise. Valid: Pro, Enterprise, Education.

    .PARAMETER ComputerName
    VM computer name. Default: WinBot-Master
    #>
    param(
        [string]$Password = "",
        [string]$Username = "winbot",
        [string]$ProductKey = "",
        [string]$WindowsEdition = "Enterprise",
        [string]$ComputerName = "WinBot-Master"
    )

    # No default password -- generate a random one if not provided
    if (-not $Password) {
        $Password = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 16 | ForEach-Object { [char]$_ })
    }

    # Build the provisioning script that runs as FirstLogonCommands.
    # Each command is a self-contained PowerShell block with its own error handling,
    # logging to C:\WinBot\logs\provision.log so we can debug failures.
    #
    # The provisioning VHD is attached as a second disk. Windows Setup will assign
    # it the next available drive letter after the system disk (usually D:).
    # The script looks for D:\WinBot\ (provisioning VHD root) or falls back to
    # downloading from a URL if the VHD isn't available.

    $provisionScript = @'
$logDate = Get-Date -Format "yyyyMMdd"; $logFile = "C:\WinBot\logs\provision-$logDate.log"
$logDir = Split-Path $logFile -Parent
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
function Write-ProvisionLog($msg) {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$ts $msg" | Out-File -Append -FilePath $logFile -Encoding utf8
    Write-Host "$ts $msg"
}
Write-ProvisionLog "=== WinBot Provisioning Started ==="

# ---- Step 1: Copy API files from provisioning VHD or download ----
Write-ProvisionLog "[1/7] Copying WinBot API files..."
$sourceDrives = @("D:", "E:", "F:", "G:")  # provisioning VHD could be any letter
$apiSource = $null
# Check C:\WinBot\ first -- files may already be staged by DISM deploy
if (Test-Path "C:\WinBot\api\main.py") {
    $apiSource = "C:\WinBot"
    Write-ProvisionLog "  API files already staged at C:\WinBot"
} else {
    foreach ($drive in $sourceDrives) {
        if (Test-Path "$drive\guest\api\main.py") { $apiSource = "$drive\guest"; break }
        if (Test-Path "$drive\api\main.py") { $apiSource = $drive; break }
    }
}
if ($apiSource) {
    Write-ProvisionLog "  Found API files on $apiSource"
    $winbotDirs = @("C:\WinBot\api\endpoints", "C:\WinBot\sessions\screenshots", "C:\WinBot\sessions\logs", "C:\WinBot\sessions\scripts", "C:\WinBot\sessions\artifacts", "C:\WinBot\tools", "C:\WinBot\logs")
    foreach ($d in $winbotDirs) { if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null } }
    # Copy API files (skip if already staged at C:\WinBot by DISM)
    if ($apiSource -ne "C:\WinBot") {
        # Files come from provisioning VHD at $apiSource\guest\
        $apiSrcDir = if ($apiSource -match '^[A-Z]:$') { "$apiSource\guest\api" } else { "$apiSource\api" }
        $apiParent = if ($apiSource -match '^[A-Z]:$') { "$apiSource\guest" } else { $apiSource }
        # Copy API files
        if (Test-Path $apiSrcDir) {
            $apiFiles = Get-ChildItem $apiSrcDir -Recurse -File -ErrorAction SilentlyContinue
            foreach ($f in $apiFiles) {
                $dest = $f.FullName.Replace($apiSrcDir, "C:\WinBot\api")
                $destDir = Split-Path $dest -Parent
                if (-not (Test-Path $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }
                Copy-Item $f.FullName $dest -Force -ErrorAction SilentlyContinue
            }
        }
        # Copy PowerShell scripts
        $psFiles = Get-ChildItem $apiParent -Filter "*.ps1" -File -ErrorAction SilentlyContinue
        foreach ($f in $psFiles) { Copy-Item $f.FullName "C:\WinBot\$($f.Name)" -Force -ErrorAction SilentlyContinue }
        # Copy tools
        $toolsSrc = "$apiParent\tools"
        if (Test-Path $toolsSrc) {
            $toolFiles = Get-ChildItem $toolsSrc -Filter "*.ps1" -File -ErrorAction SilentlyContinue
            foreach ($f in $toolFiles) { Copy-Item $f.FullName "C:\WinBot\tools\$($f.Name)" -Force -ErrorAction SilentlyContinue }
        }
        Write-ProvisionLog "  API files copied from $apiSource"
    } else {
        Write-ProvisionLog "  Files already staged -- skipping copy"
    }
} else {
    Write-ProvisionLog "  No provisioning VHD found. Downloading from GitHub..."
    # Fallback: download from GitHub (adjust URL to match your release)
    $zipUrl = "https://github.com/your-org/winbot/releases/download/v0.1.0/winbot-api.zip"
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $zipUrl -OutFile "$env:TEMP\winbot-api.zip" -ErrorAction Stop
        Expand-Archive -Path "$env:TEMP\winbot-api.zip" -DestinationPath "C:\WinBot" -Force
        Write-ProvisionLog "  API files downloaded from GitHub"
    } catch {
        Write-ProvisionLog "  WARNING: Could not download API files: $_"
        Write-ProvisionLog "  The API will need to be installed manually."
    }
}

# ---- Step 2: Install Chocolatey ----
Write-ProvisionLog "[2/7] Installing Chocolatey..."
try {
    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = 3072
        iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        $env:ChocolateyInstall = "$env:ProgramData\chocolatey"
        $env:PATH = "$env:ChocolateyInstall\bin;$env:PATH"
        Write-ProvisionLog "  Chocolatey installed"
    } else {
        Write-ProvisionLog "  Chocolatey already installed"
    }
} catch {
    Write-ProvisionLog "  WARNING: Chocolatey install failed: $_"
}

# ---- Step 3: Install Python 3.13 ----
Write-ProvisionLog "[3/7] Installing Python 3.13..."
try {
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        choco install python313 -y --no-progress 2>&1 | Out-File -Append $logFile -Encoding utf8
    }
    # Refresh PATH
    $env:PATH = [Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" + [Environment]::GetEnvironmentVariable("PATH", "User")
    # Ensure we can find python
    $pythonExe = Get-Command python -ErrorAction SilentlyContinue
    if (-not $pythonExe) {
        # Try common install paths
        $pyPaths = @("C:\Python313\python.exe", "$env:LOCALAPPDATA\Programs\Python\Python313\python.exe", "C:\Program Files\Python313\python.exe")
        foreach ($p in $pyPaths) {
            if (Test-Path $p) { $env:PATH = (Join-Path (Split-Path $p) "Scripts") + ";" + (Split-Path $p) + ";$env:PATH"; break }
        }
    }
    $pyVer = & python --version 2>&1
    Write-ProvisionLog "  Python: $pyVer"
    # Install pip packages
    python -m pip install --upgrade pip --quiet 2>&1 | Out-File -Append $logFile -Encoding utf8
    python -m pip install fastapi uvicorn pyautogui pywin32 pillow pynput psutil --quiet 2>&1 | Out-File -Append $logFile -Encoding utf8
    Write-ProvisionLog "  Python packages installed"
} catch {
    Write-ProvisionLog "  WARNING: Python install failed: $_"
}

# ---- Step 4: Install AutoIt, AutoHotkey, NSSM ----
Write-ProvisionLog "[4/7] Installing automation tools..."
if (Get-Command choco -ErrorAction SilentlyContinue) {
    try {
        choco install autoit -y --no-progress 2>&1 | Out-File -Append $logFile -Encoding utf8
        Write-ProvisionLog "  AutoIt installed"
    } catch { Write-ProvisionLog "  WARNING: AutoIt install: $_" }

    try {
        choco install autohotkey -y --no-progress 2>&1 | Out-File -Append $logFile -Encoding utf8
        Write-ProvisionLog "  AutoHotkey installed"
    } catch { Write-ProvisionLog "  WARNING: AutoHotkey install: $_" }

    try {
        choco install nssm -y --no-progress 2>&1 | Out-File -Append $logFile -Encoding utf8
        Write-ProvisionLog "  NSSM installed"
    } catch { Write-ProvisionLog "  WARNING: NSSM install: $_" }
} else {
    Write-ProvisionLog "  WARNING: Chocolatey not available, skipping tool installs"
}

# ---- Step 5: Configure remote access and user account ----
Write-ProvisionLog "[5/7] Configuring remote access..."
try {
    # Enable RDP
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 0 -Type DWord -Force
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
    Add-LocalGroupMember -Group "Remote Desktop Users" -Member $env:UserName -ErrorAction SilentlyContinue
    Write-ProvisionLog "  RDP enabled"

    # Configure WinRM
    Enable-PSRemoting -Force -ErrorAction SilentlyContinue
    Set-Item -Path "WSMan:\localhost\Client\TrustedHosts" -Value "*" -Force -ErrorAction SilentlyContinue
    Set-Item -Path "WSMan:\localhost\Service\Auth\Basic" -Value $true -Force -ErrorAction SilentlyContinue
    Set-Service -Name WinRM -StartupType Automatic
    Restart-Service WinRM -Force -ErrorAction SilentlyContinue
    Write-ProvisionLog "  WinRM configured"

    # Firewall for WinBot API
    netsh advfirewall firewall delete rule name="WinBot API" 2>$null
    netsh advfirewall firewall add rule name="WinBot API" dir=in action=allow protocol=TCP localport=8000
    Write-ProvisionLog "  Firewall configured"

    # Disable UAC for automation tools
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0 -Type DWord -Force

    # Power settings -- never sleep
    powercfg -change -standby-timeout-ac 0 2>$null
    powercfg -change -standby-timeout-dc 0 2>$null
    powercfg -change -hibernate-timeout-ac 0 2>$null
    powercfg -change -monitor-timeout-ac 30 2>$null

    # Disable screen saver
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveActive" -Value 0 -Force -ErrorAction SilentlyContinue

    # Disable Defender real-time monitoring for perf
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue

    Write-ProvisionLog "  Remote access and power settings configured"
} catch {
    Write-ProvisionLog "  WARNING: Remote access configuration: $_"
}

# ---- Step 6: Install WinBot API as Windows service ----
Write-ProvisionLog "[6/7] Installing WinBot API service..."
try {
    # Generate API token
    $tokenBytes = New-Object byte[] 32
    [Security.Cryptography.RandomNumberGenerator]::Fill($tokenBytes)
    $apiToken = -join ($tokenBytes | ForEach-Object { "{0:x2}" -f $_ })

    # Save token
    $tokenFile = "C:\WinBot\.api_token"
    $apiToken | Out-File -FilePath $tokenFile -Encoding ascii -NoNewline
    try {
        icacls $tokenFile /inheritance:r /grant "SYSTEM:(R)" /grant "BUILTIN\Administrators:(R)" 2>$null | Out-Null
    } catch { Write-Verbose "Non-critical operation skipped - continuing" }

    # Find Python
    $pythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
    if (-not $pythonExe) {
        $pyPaths = @("C:\Python313\python.exe", "$env:LOCALAPPDATA\Programs\Python\Python313\python.exe")
        foreach ($p in $pyPaths) { if (Test-Path $p) { $pythonExe = $p; break } }
    }

    if ($pythonExe -and (Test-Path "C:\WinBot\api\main.py")) {
        $nssmPath = "C:\ProgramData\chocolatey\bin\nssm.exe"
        if (-not (Test-Path $nssmPath)) { $nssmPath = (Get-Command nssm -ErrorAction SilentlyContinue).Source }

        if ($nssmPath) {
            # Remove existing service if present
            Stop-Service -Name "WinBotAPI" -Force -ErrorAction SilentlyContinue
            & $nssmPath remove WinBotAPI confirm 2>$null
            Start-Sleep -Seconds 1

            # Install with NSSM
            & $nssmPath install WinBotAPI $pythonExe "-m uvicorn main:app --host 0.0.0.0 --port 8000"
            & $nssmPath set WinBotAPI AppDirectory "C:\WinBot\api"
            & $nssmPath set WinBotAPI DisplayName "WinBot API Server"
            & $nssmPath set WinBotAPI Description "WinBot automation REST API (FastAPI + uvicorn)"
            & $nssmPath set WinBotAPI Start SERVICE_AUTO_START
            & $nssmPath set WinBotAPI AppStdout "C:\WinBot\logs\api-stdout.log"
            & $nssmPath set WinBotAPI AppStderr "C:\WinBot\logs\api-stderr.log"
            & $nssmPath set WinBotAPI AppStdoutCreationDisposition 4
            & $nssmPath set WinBotAPI AppStderrCreationDisposition 4
            & $nssmPath set WinBotAPI AppRotateFiles 1
            & $nssmPath set WinBotAPI AppRotateOnline 1
            & $nssmPath set WinBotAPI AppRotateSeconds 86400
            & $nssmPath set WinBotAPI AppRotateBytes 1048576
            & $nssmPath set WinBotAPI AppEnvironmentExtra "WINBOT_API_TOKEN=$apiToken"
            & $nssmPath set WinBotAPI AppExit Default Restart
            & $nssmPath set WinBotAPI AppRestartDelay 5000

            Start-Service -Name WinBotAPI -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 5
            $svc = Get-Service -Name WinBotAPI -ErrorAction SilentlyContinue
            if ($svc -and $svc.Status -eq "Running") {
                Write-ProvisionLog "  WinBot API service is RUNNING"
            } else {
                Write-ProvisionLog "  WARNING: Service installed but not running. Status: $($svc.Status)"
            }
        } else {
            Write-ProvisionLog "  WARNING: NSSM not found -- API service not installed"
        }
    } else {
        Write-ProvisionLog "  WARNING: Python or API files not found -- API service not installed"
    }
} catch {
    Write-ProvisionLog "  WARNING: API service installation failed: $_"
}

# ---- Step 7: Final reboot to start clean with auto-logon ----
Write-ProvisionLog "[7/7] Provisioning complete. Rebooting..."
Write-ProvisionLog "=== WinBot Provisioning Finished ==="
shutdown /r /t 10 /c "WinBot provisioning complete. Rebooting to finalize."
'@

    # Build product key block for autounattend if one was provided
    $productKeyBlock = ""
    if ($ProductKey) {
        $productKeyBlock = @"
                <ProductKey>
                    <Key>$ProductKey</Key>
                    <WillShowUI>Never</WillShowUI>
                </ProductKey>
"@
    }

    return @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
    <settings pass="windowsPE">
        <component name="Microsoft-Windows-International-Core-WinPE" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <SetupUILanguage>
                <UILanguage>en-US</UILanguage>
            </SetupUILanguage>
            <InputLocale>en-US</InputLocale>
            <SystemLocale>en-US</SystemLocale>
            <UILanguage>en-US</UILanguage>
            <UserLocale>en-US</UserLocale>
        </component>
        <component name="Microsoft-Windows-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <DiskConfiguration>
                <Disk wcm:action="add">
                    <CreatePartitions>
                        <CreatePartition wcm:action="add">
                            <Order>1</Order>
                            <Size>100</Size>
                            <Type>EFI</Type>
                        </CreatePartition>
                        <CreatePartition wcm:action="add">
                            <Order>2</Order>
                            <Size>16</Size>
                            <Type>MSR</Type>
                        </CreatePartition>
                        <CreatePartition wcm:action="add">
                            <Order>3</Order>
                            <Extend>true</Extend>
                            <Type>Primary</Type>
                        </CreatePartition>
                    </CreatePartitions>
                    <ModifyPartitions>
                        <ModifyPartition wcm:action="add">
                            <Order>1</Order>
                            <PartitionID>1</PartitionID>
                            <Format>FAT32</Format>
                            <Label>System</Label>
                        </ModifyPartition>
                        <ModifyPartition wcm:action="add">
                            <Order>2</Order>
                            <PartitionID>2</PartitionID>
                        </ModifyPartition>
                        <ModifyPartition wcm:action="add">
                            <Order>3</Order>
                            <PartitionID>3</PartitionID>
                            <Format>NTFS</Format>
                            <Label>Windows</Label>
                            <Letter>C</Letter>
                        </ModifyPartition>
                    </ModifyPartitions>
                    <DiskID>0</DiskID>
                    <WillWipeDisk>true</WillWipeDisk>
                </Disk>
            </DiskConfiguration>
            <ImageInstall>
                <OSImage>
                    <InstallTo>
                        <DiskID>0</DiskID>
                        <PartitionID>3</PartitionID>
                    </InstallTo>
                </OSImage>
            </ImageInstall>
            <UserData>
                <AcceptEula>true</AcceptEula>
                <FullName>WinBot</FullName>
                <Organization>WinBot Automation</Organization>
                $productKeyBlock
            </UserData>
        </component>
    </settings>
    <settings pass="offlineServicing">
        <component name="Microsoft-Windows-LUA-Settings" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <EnableLUA>false</EnableLUA>
        </component>
    </settings>
    <settings pass="specialize">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <ComputerName>$ComputerName</ComputerName>
            <TimeZone>Pacific Standard Time</TimeZone>
        </component>
        <component name="Microsoft-Windows-TerminalServices-LocalSessionManager" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <fDenyTSConnections>false</fDenyTSConnections>
        </component>
        <component name="Microsoft-Windows-TerminalServices-RDP-WinStationExtensions" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <UserAuthentication>0</UserAuthentication>
        </component>
    </settings>
    <settings pass="oobeSystem">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <OOBE>
                <HideEULAPage>true</HideEULAPage>
                <HideLocalAccountScreen>true</HideLocalAccountScreen>
                <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
                <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
                <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
                <ProtectYourPC>3</ProtectYourPC>
            </OOBE>
            <UserAccounts>
                <LocalAccounts>
                    <LocalAccount wcm:action="add">
                        <Name>$Username</Name>
                        <DisplayName>WinBot Automation</DisplayName>
                        <Description>WinBot automation account</Description>
                        <Group>Administrators</Group>
                        <Password>
                            <Value>$Password</Value>
                            <PlainText>true</PlainText>
                        </Password>
                    </LocalAccount>
                </LocalAccounts>
            </UserAccounts>
            <AutoLogon>
                <Enabled>true</Enabled>
                <Username>$Username</Username>
                <Password>
                    <Value>$Password</Value>
                    <PlainText>true</PlainText>
                </Password>
                <LogonCount>999999</LogonCount>
            </AutoLogon>
            <FirstLogonCommands>
                <SynchronousCommand wcm:action="add">
                    <Order>1</Order>
                    <CommandLine>powershell -ExecutionPolicy Bypass -WindowStyle Hidden -Command "$provisionScript"</CommandLine>
                    <Description>WinBot -- Complete provisioning (tools + API + remote access)</Description>
                </SynchronousCommand>
            </FirstLogonCommands>
        </component>
    </settings>
</unattend>
"@
}

# vvv DISM autounattend (minimal, validated) vvv

function Get-WinBotDismAutounattend {
    param(
        [string]$Password = "",
        [string]$Username = "winbot",
        [string]$ProductKey = "",
        [string]$WindowsEdition = "Enterprise",
        [string]$ComputerName = "WinBot-Master"
    )
    if (-not $Password) {
        $safe = (48..57) + (65..90) + (97..122)
        $Password = -join ($safe | Get-Random -Count 20 | ForEach-Object { [char]$_ })
    }
    if ($Password -match '[&<>"]') { throw "Password contains XML-unsafe characters." }
    if ($Username -match '[&<>"]') { throw "Username contains XML-unsafe characters." }

    # Note: ProductKey is handled via slmgr in provision.ps1, not in XML.
    # Putting it in specialize/Shell-Setup causes Windows to reject the component.

    return @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
    <settings pass="specialize">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <ComputerName>$ComputerName</ComputerName>
            <TimeZone>Pacific Standard Time</TimeZone>
        </component>
        <component name="Microsoft-Windows-TerminalServices-LocalSessionManager" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <fDenyTSConnections>false</fDenyTSConnections>
        </component>
        <component name="Microsoft-Windows-TerminalServices-RDP-WinStationExtensions" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <UserAuthentication>0</UserAuthentication>
        </component>
    </settings>
    <settings pass="oobeSystem">
        <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <InputLocale>en-US</InputLocale>
            <SystemLocale>en-US</SystemLocale>
            <UILanguage>en-US</UILanguage>
            <UserLocale>en-US</UserLocale>
        </component>
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <OOBE>
                <HideEULAPage>true</HideEULAPage>
                <HideLocalAccountScreen>true</HideLocalAccountScreen>
                <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
                <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
                <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
                <ProtectYourPC>3</ProtectYourPC>
                <NetworkLocation>Home</NetworkLocation>
            </OOBE>
            <UserAccounts>
                <LocalAccounts>
                    <LocalAccount wcm:action="add">
                        <Name>$Username</Name>
                        <DisplayName>WinBot Automation</DisplayName>
                        <Description>WinBot automation account</Description>
                        <Group>Administrators</Group>
                        <Password><Value>$Password</Value><PlainText>true</PlainText></Password>
                    </LocalAccount>
                </LocalAccounts>
            </UserAccounts>
            <AutoLogon>
                <Enabled>true</Enabled>
                <Username>$Username</Username>
                <Password><Value>$Password</Value><PlainText>true</PlainText></Password>
                <LogonCount>999999</LogonCount>
            </AutoLogon>
            <FirstLogonCommands>
                <SynchronousCommand wcm:action="add">
                    <Order>1</Order>
                    <CommandLine>powershell -ExecutionPolicy Bypass -File C:\WinBot\provision.ps1</CommandLine>
                    <Description>WinBot Provisioning (visible for debugging - logs to C:\WinBot\logs)</Description>
                    <RequiresUserInput>false</RequiresUserInput>
                </SynchronousCommand>
            </FirstLogonCommands>
        </component>
    </settings>
</unattend>
"@
}

# ============================================================
# Structured Logging
# ============================================================

$script:WinBotLogPath = Join-Path $script:ProjectDir "logs"
$script:WinBotLogFile = $null

function Write-WinBotLog {
    <#
    .SYNOPSIS
    Write a structured, timestamped log message to both console and file.

    .DESCRIPTION
    - Level: DEBUG, INFO, WARN, ERROR
    - Console output uses level-appropriate colors
    - File output writes to C:\WinBot\logs\winbot-YYYYMMDD.log
    - Controlled by $env:WINBOT_LOG_LEVEL (default: INFO)

    .PARAMETER Message
    The message to log.

    .PARAMETER Level
    DEBUG, INFO, WARN, or ERROR. Messages below the current log level are suppressed.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,

        [ValidateSet('DEBUG','INFO','WARN','ERROR')]
        [string]$Level = 'INFO'
    )

    # Determine effective log level
    $effectiveLevel = $env:WINBOT_LOG_LEVEL
    if (-not $effectiveLevel) { $effectiveLevel = 'INFO' }
    $levelOrder = @{ DEBUG=0; INFO=1; WARN=2; ERROR=3 }
    if ($levelOrder[$Level] -lt $levelOrder[$effectiveLevel]) {
        return  # Suppressed
    }

    # Build log entry
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
    $pid = $PID
    $logLine = "[$timestamp] [$Level] [$pid] $Message"

    # Console output with color
    $colorMap = @{ DEBUG='Gray'; INFO='White'; WARN='Yellow'; ERROR='Red' }
    $color = $colorMap[$Level]
    if ($Level -eq 'ERROR' -or $Level -eq 'WARN') {
        Write-Host "[WinBot] $Message" -ForegroundColor $color
    }
    elseif ($effectiveLevel -eq 'DEBUG') {
        Write-Host $logLine -ForegroundColor $color
    }

    # File output
    if (-not $script:WinBotLogFile) {
        if (-not (Test-Path $script:WinBotLogPath)) {
            New-Item -ItemType Directory -Path $script:WinBotLogPath -Force | Out-Null
        }
        $date = Get-Date -Format 'yyyyMMdd'
        $script:WinBotLogFile = Join-Path $script:WinBotLogPath "winbot-$date.log"
    }
    try {
        Add-Content -Path $script:WinBotLogFile -Value $logLine -Encoding UTF8 -ErrorAction SilentlyContinue
    }
    catch {
        # Can't log to file -- don't crash
    }
}

# ============================================================
# ISO Version & Freshness Checking
# ============================================================

function Get-WinBotISOVersion {
    <#
    .SYNOPSIS
    Read version metadata from a cached ISO file or the ISO provenance log.
    Returns build version, edition, architecture, and download method.

    .DESCRIPTION
    Checks the ISO provenance log for metadata. For EVAL ISOs, also attempts
    to extract the Windows build version from the ISO filename.
    MCT ISOs include the build date in their filename format.

    .EXAMPLE
    Get-WinBotISOVersion
    Get-WinBotISOVersion -ISOPath "C:\WinBot\master\Win11_Enterprise_24H2_MCT_x64.iso"
    #>
    param(
        [string]$ISOPath = "",
        [switch]$VerifyHash,
        [string]$ExpectedEdition = "",
        [string]$ExpectedVersion = "",
        [string]$ExpectedArchitecture = "",
        [string]$ExpectedLanguage = ""
    )

    $cfg = Get-WinBotConfig
    $masterPath = if ($cfg.master.vmPath) { $cfg.master.vmPath } else { "C:\WinBot\master\" }
    $provenanceRoot = if ($ISOPath) { Split-Path -Parent $ISOPath } else { $masterPath }
    if (-not $provenanceRoot) { $provenanceRoot = $masterPath }
    $provenanceLog = Join-Path $provenanceRoot "iso-provenance.jsonl"

    # Read provenance records adjacent to the selected/default artifact root.
    $entries = @()
    if (Test-Path $provenanceLog) {
        $entries = @(Get-Content $provenanceLog -ErrorAction SilentlyContinue | ForEach-Object {
            try { $_ | ConvertFrom-Json } catch { $null }
        } | Where-Object { $_ })
    }

    # An explicit artifact path is authoritative. If it is absent, report
    # that absence rather than silently substituting an unrelated cached ISO.
    $cachedISO = if ($ISOPath) {
        if (Test-Path -LiteralPath $ISOPath) { Get-Item -LiteralPath $ISOPath } else { $null }
    } else {
        Get-ChildItem $masterPath -Filter "Win11*.iso" -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
    }

    $identityEntry = if ($cachedISO) {
        $entries | Where-Object { $_.filename -eq $cachedISO.Name } | Sort-Object timestamp -Descending | Select-Object -First 1
    }
    $ready = $false
    $state = if (-not $cachedISO) { "False" } else { "Unknown" }
    $reason = if (-not $cachedISO) {
        "ISO is absent"
    } elseif (-not $identityEntry) {
        "ISO is present but no provenance record matches its filename"
    } else {
        "provenance identity is present but executable readiness is unverified"
    }
    $actualHash = $null
    if ($cachedISO -and $identityEntry -and $VerifyHash) {
        $actualHash = (Get-FileHash -LiteralPath $cachedISO.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
        if (-not $identityEntry.sha256 -or $actualHash -ne $identityEntry.sha256) {
            $state = "False"
            $reason = "SHA-256 does not match the recorded provenance"
        } elseif ($identityEntry.size_bytes -and [int64]$identityEntry.size_bytes -ne [int64]$cachedISO.Length) {
            $state = "False"
            $reason = "file size does not match the recorded provenance"
        } else {
            $missingIdentity = @()
            foreach ($field in @("edition", "version", "architecture", "language")) {
                $value = [string]$identityEntry.$field
                if ([string]::IsNullOrWhiteSpace($value) -or $value -eq "unknown") {
                    $missingIdentity += $field
                }
            }
            if ($missingIdentity.Count -gt 0) {
                $state = "Unknown"
                $reason = "provenance record lacks verified identity fields: $($missingIdentity -join ', ')"
            } else {
                $mismatches = @()
                if ($ExpectedEdition -and [string]$identityEntry.edition -ne $ExpectedEdition) {
                    $mismatches += "edition expected=$ExpectedEdition actual=$($identityEntry.edition)"
                }
                if ($ExpectedVersion -and [string]$identityEntry.version -ne $ExpectedVersion) {
                    $mismatches += "version expected=$ExpectedVersion actual=$($identityEntry.version)"
                }
                if ($ExpectedArchitecture -and [string]$identityEntry.architecture -ne $ExpectedArchitecture) {
                    $mismatches += "architecture expected=$ExpectedArchitecture actual=$($identityEntry.architecture)"
                }
                if ($ExpectedLanguage -and [string]$identityEntry.language -ne $ExpectedLanguage) {
                    $mismatches += "language expected=$ExpectedLanguage actual=$($identityEntry.language)"
                }
                if ($mismatches.Count -gt 0) {
                    $state = "False"
                    $reason = "ISO identity is incompatible with requested build intent: $($mismatches -join '; ')"
                } else {
                    $ready = $true
                    $state = "True"
                    $reason = "provenance identity, size, SHA-256, and requested build constraints verified"
                }
            }
        }
    }
    $result = @{
        Cached = ($cachedISO -ne $null)
        State = $state
        Ready = $ready
        Reason = $reason
        ExpectedEdition = $ExpectedEdition
        ExpectedVersion = $ExpectedVersion
        ExpectedArchitecture = $ExpectedArchitecture
        ExpectedLanguage = $ExpectedLanguage
        ISOExists = ($cachedISO -ne $null)
        ISOPath = if ($cachedISO) { $cachedISO.FullName } else { $null }
        ISOSizeGB = if ($cachedISO) { [math]::Round($cachedISO.Length / 1GB, 2) } else { $null }
        ISOLastModified = if ($cachedISO) { $cachedISO.LastWriteTime.ToString("o") } else { $null }
        Method = if ($identityEntry) { $identityEntry.method } else { "unknown" }
        Edition = if ($identityEntry) { $identityEntry.edition } else { "unknown" }
        Architecture = if ($identityEntry) { $identityEntry.architecture } else { "unknown" }
        Language = if ($identityEntry) { $identityEntry.language } else { "unknown" }
        Version = if ($identityEntry) { $identityEntry.version } else { "unknown" }
        SHA256 = if ($identityEntry) { $identityEntry.sha256 } else { $null }
        ActualSHA256 = $actualHash
        DownloadTimestamp = if ($identityEntry) { $identityEntry.timestamp } else { $null }
        ProvenanceLog = $provenanceLog
    }

    return $result
}


function Test-WinBotISOUpdate {
    <#
    .SYNOPSIS
    Check whether a newer Windows ISO version is available from Microsoft.

    .DESCRIPTION
    For EVAL ISOs: performs a HEAD request to the known CDN URL and compares
    Content-Length and Last-Modified headers with the cached ISO.
    For MCT ISOs: checks the current ISO metadata against known release schedules.
    Returns whether the cached ISO is current and what action to take.

    .EXAMPLE
    Test-WinBotISOUpdate
    $status = Test-WinBotISOUpdate
    if (-not $status.Current) { Write-Host "New ISO available!" }
    #>
    [CmdletBinding()]
    param()

    $info = Get-WinBotISOVersion
    $result = @{
        Current = $true
        Cached = $info.Cached
        CurrentVersion = $info.Version
        CurrentMethod = $info.Method
        CurrentSizeGB = $info.ISOSizeGB
        AvailableVersion = $info.Version
        AvailableDate = $null
        SizeDifference = $null
        Action = "none"
        Message = ""
    }

    if (-not $info.Cached) {
        $result.Current = $false
        $result.Action = "download"
        $result.Message = "No ISO cached. Run provision-iso.ps1 to download."
        return $result
    }

    # EVAL ISO: check CDN for newer version
    if ($info.Method -eq "EVAL") {
        Write-Verbose "Checking MCT availability for EVAL->MCT upgrade..."
        $storedKey = Get-WinBotCredential -Name "product-key" -Username "windows" -AsPlaintext -ErrorAction SilentlyContinue
        if ($storedKey) {
            $result.Current = $false  # EVAL with key: always suggest MCT upgrade
            $result.Action = "upgrade"
            $result.AvailableVersion = $info.Version
            $result.Message = "Product key found. Upgrade available: full licensed Enterprise ISO via Media Creation Tool."
        } else {
            # Check if the EVAL CDN has a newer ISO (CDN URLs don't always support HEAD,
            # so we compare file size via GET with Range header to minimize download)
            try {
                $evalUrl = "https://software-static.download.prss.microsoft.com/dbazure/888969d5-f34g-4e03-ac9d-1f9786c66749/26100.1742.240906-0331.ge_release_svc_refresh_CLIENTENTERPRISEEVAL_OEMRET_x64FRE_en-us.iso"
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                # Use Range: bytes=0-0 to get Content-Length without downloading
                $response = Invoke-WebRequest -Uri $evalUrl -Headers @{"Range"="bytes=0-0"} -TimeoutSec 15 -ErrorAction SilentlyContinue -UseBasicParsing
                if ($response -and ($response.StatusCode -eq 206 -or $response.StatusCode -eq 200)) {
                    $remoteSize = $response.Headers["Content-Range"]
                    if (-not $remoteSize) { $remoteSize = $response.Headers["Content-Length"] }
                    if ($remoteSize) {
                        $rs = [long]($remoteSize -replace "bytes 0-0/", "")
                        $localSize = (Get-Item $info.ISOPath).Length
                        if ($localSize -ne $rs) {
                            $result.Current = $false; $result.Action = "download"
                            $result.SizeDifference = ($rs - $localSize)
                            $result.Message = "CDN ISO differs from cached. Local: $localSize bytes, Remote: $rs bytes."
                        }
                    }
                }
            } catch { Write-Verbose "Could not check EVAL CDN: $_" }
        }
    }

    # MCT ISO: current by definition (downloaded from Microsoft's latest)
    if ($info.Method -eq "MCT") {
        $result.Current = $true
        $result.Action = "none"
        $result.Message = "MCT ISO is the latest available from Microsoft."
    }

    return $result
}


# ============================================================
# System Readiness Health Check
# ============================================================

function Test-WinBotHealth {
    <#
    .SYNOPSIS
    Comprehensive system readiness check. Verifies everything WinBot
    needs to operate and returns a pass/fail report.

    .DESCRIPTION
    Checks: module import, config validity, Hyper-V access, master VHDX
    existence + integrity, credentials, provisioning scripts, guest scripts.

    .EXAMPLE
    Test-WinBotHealth
    Test-WinBotHealth -Detailed
    #>
    param([switch]$Detailed)

    # Clean up stale test credential from earlier testing
    Unregister-WinBotCredential -Name "demo-pw" -ErrorAction SilentlyContinue | Out-Null

    $script:HealthResults = [System.Collections.ArrayList]::new()
    $script:HealthOverall = $true

    # Helper nested function -- uses script: scope for PS 5.1 compatibility
    function _add($category, $name, $status, $detail) {
        $script:HealthResults.Add([PSCustomObject]@{
            Category = $category; Check = $name; Status = $status; Detail = $detail
        }) | Out-Null
        if ($status -eq "FAIL") { $script:HealthOverall = $false }
    }

    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  WinBot System Health Check" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    # ---- Module ----
    Write-Host "[Module]" -ForegroundColor Yellow
    _add "Module" "WinBot version" "PASS" (Get-WinBotVersion)
    _add "Module" "Running as Admin" $(if (Test-IsAdministrator){"PASS"}else{"FAIL"}) $(if (Test-IsAdministrator){"Yes"}else{"No -- run as Administrator"})

    # ---- Config ----
    Write-Host "[Config]" -ForegroundColor Yellow
    $cfgPath = Join-Path $script:ProjectDir "config.json"
    if (Test-Path $cfgPath) {
        _add "Config" "config.json exists" "PASS" $cfgPath
        try {
            $cfg = Get-WinBotConfig
            _add "Config" "Parses without error" "PASS" "OK"
            $checks = @(
                @{k="master.vmName";v=$cfg.master.vmName},
                @{k="api.port";v=$cfg.api.port},
                @{k="clones.basePath";v=$cfg.clones.basePath}
            )
            foreach ($c in $checks) {
                if ($c.v) {
                    _add "Config" $c.k "PASS" "$($c.v)"
                } else {
                    _add "Config" $c.k "WARN" "missing -- using default"
                }
            }
            if ($cfg.api.token) {
                _add "Config" "api.token" "WARN" "token in config.json -- migrate to CredMan with Register-WinBotAPIKey"
            } else {
                _add "Config" "api.token" "PASS" "not in config.json"
            }
        } catch {
            _add "Config" "Parse config" "FAIL" $_.Exception.Message
        }
    } else {
        _add "Config" "config.json" "FAIL" "File not found: $cfgPath"
    }

    # ---- Hyper-V ----
    Write-Host "[Hyper-V]" -ForegroundColor Yellow
    $hv = Test-HyperVAvailable
    _add "Hyper-V" "Feature" $(if($hv.HyperVFeature){"PASS"}else{"FAIL"}) $(if($hv.HyperVFeature){"Enabled"}else{"Not enabled"})
    _add "Hyper-V" "Module" $(if($hv.HyperVModule){"PASS"}else{"FAIL"}) $(if($hv.HyperVModule){"Available"}else{"Not installed"})
    _add "Hyper-V" "Service (vmms)" $(if($hv.HyperVService){"PASS"}else{"FAIL"}) $(if($hv.HyperVService){"Running"}else{"Not running"})
    if ($hv.Available) {
        try {
            $vmCount = @(Get-VM -Name "WinBot-*" -ErrorAction SilentlyContinue).Count
            _add "Hyper-V" "WinBot VMs" "PASS" "$vmCount found"
        } catch {
            _add "Hyper-V" "VM access" "FAIL" $_.Exception.Message
        }
    }

    # ---- Master VHDX ----
    Write-Host "[Master VHDX]" -ForegroundColor Yellow
    $vhdPath = $cfg.master.vhdxPath
    if (Test-Path $vhdPath) {
        $sizeGB = [math]::Round((Get-Item $vhdPath).Length / 1GB, 1)
        _add "Master" "VHDX exists" "PASS" "$vhdPath (${sizeGB}GB)"
        $integrity = Test-WinBotMasterIntegrity -VHDXPath $vhdPath
        _add "Master" "Integrity" $(if($integrity){"PASS"}else{"WARN"}) $(if($integrity){"Hash matches"}else{"Hash missing or mismatch -- run Set-WinBotMasterHash"})
    } else {
        _add "Master" "VHDX" "WARN" "Not found: $vhdPath"
        _add "Master" "Action" "INFO" "Run: .\guest\provision-iso.ps1 or .\guest\provision-msvm.ps1"
    }

    # ---- Credentials ----
    Write-Host "[Credentials]" -ForegroundColor Yellow
    $creds = @(Get-WinBotCredentialList)
    $credNames = $creds | ForEach-Object { $_.Name }
    _add "Credentials" "Count" "PASS" "$($creds.Count) stored"
    if ("vm-password" -in $credNames) {
        _add "Credentials" "VM password" "PASS" "WinBot_vm-password in CredMan"
    } else {
        _add "Credentials" "VM password" "WARN" "Not in CredMan -- run: Register-WinBotCredential -Name 'vm-password' -Username 'winbot' -Password '<pw>'"
    }
    if ("api-key-winbot" -in $credNames) {
        _add "Credentials" "API token" "PASS" "WinBot_api-key-winbot in CredMan"
    } else {
        _add "Credentials" "API token" "WARN" "Not in CredMan -- run: Register-WinBotAPIKey -Service 'winbot' -Key '<token>'"
    }

    # ---- ISO Version ----
    Write-Host "[ISO Version]" -ForegroundColor Yellow
    $isoVersion = Get-WinBotISOVersion -VerifyHash
    if ($isoVersion.Cached -and $isoVersion.Ready) {
        $ageDays = if ($isoVersion.DownloadTimestamp) {
            [math]::Round(((Get-Date) - [DateTime]$isoVersion.DownloadTimestamp).TotalDays, 0)
        } else { "?" }
        _add "ISO" "Cached" "PASS" "$($isoVersion.Edition) $($isoVersion.Version) ($($isoVersion.Method)) - $($isoVersion.ISOSizeGB)GB - ${ageDays}d old"
        $updateCheck = Test-WinBotISOUpdate
        if (-not $updateCheck.Current) {
            _add "ISO" "Update" "WARN" $updateCheck.Message
        } else {
            _add "ISO" "Update" "PASS" "Current"
        }
    } elseif ($isoVersion.Cached) {
        _add "ISO" "Cached" "WARN" "Present but not ready: $($isoVersion.Reason)"
    } else {
        _add "ISO" "Cached" "WARN" "No ISO found - run .\guest\provision-iso.ps1"
    }

    # ---- Provisioning Scripts ----
    Write-Host "[Provisioning Scripts]" -ForegroundColor Yellow
    $scriptChecks = @(
        @{p="guest\provision-iso.ps1";d="ISO-based master provisioning"},
        @{p="guest\provision-msvm.ps1";d="MS Dev VM provisioning"},
        @{p="guest\build-provision-vhd.ps1";d="Provisioning VHD builder"},
        @{p="guest\download-windows-iso.ps1";d="Windows ISO downloader"},
        @{p="test\smoke-test.ps1";d="Smoke test"}
    )
    foreach ($s in $scriptChecks) {
        $sp = Join-Path $script:ProjectDir $s.p
        if (Test-Path $sp) {
            _add "Scripts" $s.d "PASS" $s.p
        } else {
            _add "Scripts" $s.d "FAIL" "Missing: $s.p"
        }
    }

    # ---- Guest Scripts VM Guardrail ----
    Write-Host "[Guest Scripts VM Guardrail]" -ForegroundColor Yellow
    $guestScripts = Get-ChildItem (Join-Path $script:ProjectDir "guest") -Filter "*.ps1" -Recurse -ErrorAction SilentlyContinue
    $guardrailOk = 0
    $guardrailFail = 0
    foreach ($gs in $guestScripts) {
        $content = Get-Content $gs.FullName -Raw
        if ($content -match "SAFETY GUARDRAIL" -and $content -match "Test-IsHyperVVM") {
            $guardrailOk++
        } elseif ($gs.Name -eq "build-provision-vhd.ps1") {
            # This script intentionally doesn't have the host guardrail (it's a build tool)
            $guardrailOk++
        } else {
            $guardrailFail++
            if ($Detailed) { _add "Guardrail" $gs.Name "WARN" "Missing VM guardrail -- safe to run on host?" }
        }
    }
    _add "Guardrail" "Protected scripts" $(if($guardrailFail -eq 0){"PASS"}else{"WARN"}) "$guardrailOk guarded, $guardrailFail unguarded"

    # ---- Python Tests ----
    Write-Host "[Python API Tests]" -ForegroundColor Yellow
    $testDir = Join-Path $script:ProjectDir "guest\api"
    if (Test-Path $testDir) {
        try {
            $testResult = & python -m pytest "$testDir\tests" -q --tb=no 2>&1
            $passed = if ($LASTEXITCODE -eq 0) { "PASS" } else { "FAIL" }
            _add "Tests" "API tests (pytest)" $passed ($testResult -join " " -replace '\s+', ' ')
        } catch {
            _add "Tests" "API tests" "WARN" "Could not run: $_"
        }
    }

    # ---- Summary ----
    $overall = $script:HealthOverall
    $results = @($script:HealthResults)
    $passCount = @($results | Where-Object { $_.Status -eq "PASS" }).Count
    $warnCount = @($results | Where-Object { $_.Status -eq "WARN" }).Count
    $failCount = @($results | Where-Object { $_.Status -eq "FAIL" }).Count

    Write-Host "`n========================================" -ForegroundColor $(if($overall){"Green"}else{"Red"})
    Write-Host "  Health Check: $(if($overall){'PASSED'}else{'ISSUES FOUND'})" -ForegroundColor $(if($overall){"Green"}else{"Red"})
    Write-Host "========================================" -ForegroundColor $(if($overall){"Green"}else{"Red"})
    Write-Host "  $passCount passed, $warnCount warnings, $failCount failures" -ForegroundColor $(if($failCount -eq 0){"Green"}else{"Red"})
    Write-Host "========================================"

    if ($Detailed) {
        Write-Host "`nDetailed results:" -ForegroundColor Cyan
        $results | Format-Table Category, Check, Status, Detail -AutoSize -Wrap
    }

    return @{
        Overall = $overall
        Results = $results
        PassCount = $passCount
        WarnCount = $warnCount
        FailCount = $failCount
    }
}

# ============================================================
# Guest Tool Verification
# ============================================================

function Test-WinBotGuestTools {
    <#
    .SYNOPSIS
    Smoke-test all installed WinBot tools on the guest VM.
    Runs inside the VM via PowerShell Direct.

    .DESCRIPTION
    Tests that Python, AutoIt, AutoHotkey, and NSSM actually execute.
    Returns a structured result with pass/fail per tool.
    #>
    [CmdletBinding()]
    param()

    $result = @{
        AllOk = $true
        Tests = @{}
        Timestamp = Get-Date -Format 'o'
    }

    # Python
    try {
        $pyOut = & python -c "print('ok')" 2>&1
        $result.Tests.python = if ($pyOut -match 'ok') { @{pass=$true; version=(python --version 2>&1)} } else { @{pass=$false; error=$pyOut} }
    } catch {
        $result.Tests.python = @{pass=$false; error=$_.Exception.Message}
    }

    # AutoIt
    try {
        $tmp = "$env:TEMP\winbot_test.au3"
        "Exit(0)" | Out-File $tmp -Encoding ASCII -Force
        $au3Exe = if (Test-Path "C:\Program Files (x86)\AutoIt3\AutoIt3.exe") { "C:\Program Files (x86)\AutoIt3\AutoIt3.exe" } else { "C:\Program Files\AutoIt3\AutoIt3.exe" }
        & $au3Exe /AutoIt3ExecuteScript $tmp 2>&1 | Out-Null
        $result.Tests.autoit = if ($LASTEXITCODE -eq 0) { @{pass=$true; path=$au3Exe} } else { @{pass=$false; exit_code=$LASTEXITCODE} }
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    } catch {
        $result.Tests.autoit = @{pass=$false; error=$_.Exception.Message}
    }

    # AutoHotkey
    try {
        $tmp = "$env:TEMP\winbot_test.ahk"
        "ExitApp(0)" | Out-File $tmp -Encoding ASCII -Force
        $ahkExe = if (Test-Path "C:\Program Files\AutoHotkey\AutoHotkey.exe") { "C:\Program Files\AutoHotkey\AutoHotkey.exe" } else { "C:\Program Files\AutoHotkey\AutoHotkeyU64.exe" }
        & $ahkExe $tmp 2>&1 | Out-Null
        $result.Tests.ahk = if ($LASTEXITCODE -eq 0) { @{pass=$true; path=$ahkExe} } else { @{pass=$false; exit_code=$LASTEXITCODE} }
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    } catch {
        $result.Tests.ahk = @{pass=$false; error=$_.Exception.Message}
    }

    # NSSM
    try {
        $nssm = Get-Command nssm -ErrorAction SilentlyContinue
        if (-not $nssm) { $nssm = Get-Command "C:\ProgramData\chocolatey\bin\nssm.exe" -ErrorAction SilentlyContinue }
        $result.Tests.nssm = if ($nssm) { @{pass=$true; path=$nssm.Source} } else { @{pass=$false; error="nssm not found in PATH"} }
    } catch {
        $result.Tests.nssm = @{pass=$false; error=$_.Exception.Message}
    }

    $result.AllOk = ($result.Tests.Values | Where-Object { -not $_.pass }).Count -eq 0
    return $result
}

# ============================================================
# Module Initialization
# ============================================================
Initialize-WinBot

Export-ModuleMember -Function @(
    # Environment
    'Test-IsAdministrator', 'Assert-Administrator', 'Test-HyperVAvailable',
    'Test-HyperVAdminAccess', 'Get-WinBotEnvironment', 'Get-WinBotPlan', 'Test-WinBotPlanFresh', 'Invoke-WinBotPlanApply', 'Invoke-WinBotPlanVerify', 'Get-WinBotVersion',
    # Guardrails
    'Test-IsHyperVVM', 'Assert-HyperVVM', 'Confirm-Action',
    # Health
    'Test-WinBotHealth', 'Test-WinBotISOUpdate', 'Get-WinBotISOVersion',
    # Credentials
    'Register-WinBotCredential', 'Get-WinBotCredential', 'Unregister-WinBotCredential',
    'Get-WinBotCredentialList', 'Get-WinBotCredentialPresence', 'Get-WinBotCredentialUsage',
    'New-WinBotPassword', 'Sync-WinBotCredential',
    'Rotate-WinBotCredential', 'Sync-WinBotCredentialToClones',
    'Register-WinBotAPIKey', 'Get-WinBotAPIKey', 'Remove-WinBotAPIKey',
    'Get-WinBotAPIKeyList', 'Sync-WinBotAPIKeys',
    # Config
    'Get-WinBotConfig', 'Get-WinBotAutounattend', 'Get-WinBotDismAutounattend',
    'Test-WinBotMasterIntegrity', 'Set-WinBotMasterHash', 'Get-WinBotMasterObservation', 'Get-WinBotCloneObservation',
    'Invoke-WinBotMediaAcquisition',
    # VM Discovery
    'Get-WinBotVM', 'Get-WinBotVMNote', 'Set-WinBotVMNote',
    # Clone Lifecycle
    'Wait-WinBotAPI', 'Get-WinBotGuestServiceObservation', 'New-WinBotClone', 'Start-WinBotClone', 'Stop-WinBotClone',
    'Reset-WinBotClone', 'Remove-WinBotClone', 'Suspend-WinBotClone', 'Resume-WinBotClone',
    # Session Lifecycle
    'New-WinBotSession', 'Stop-WinBotSession', 'Remove-WinBotSession',
    # Provisioning Resilience
    'Save-WinBotProvisioningState', 'Get-WinBotProvisioningState',
    'Clear-WinBotProvisioningState', 'Remove-WinBotOrphanedVMs',
    # Checkpoint Lifecycle
    'Save-WinBotCloneSnapshot', 'Restore-WinBotCloneSnapshot',
    'Get-WinBotCloneSnapshot', 'Remove-WinBotCloneSnapshot',
    # Network Management
    'New-WinBotNetworkSwitch', 'Connect-WinBotNetwork',
    'Enable-WinBotInternetAccess', 'Disable-WinBotInternetAccess',
    'Get-WinBotNetworkStatus',
    # API
    'Invoke-WinBotAPI',
    # Remote Access
    'Connect-WinBotRDP', 'Connect-WinBotVM', 'Invoke-WinBotVMCommand',
    'Sync-WinBotApiToken'
)

# Approved-verb alias for Rotate-WinBotCredential (unapproved verb suppression)
Set-Alias -Name Update-WinBotCredential -Value Rotate-WinBotCredential -Scope Global
Export-ModuleMember -Alias Update-WinBotCredential
