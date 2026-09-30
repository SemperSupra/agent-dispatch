param(
    [Parameter(Mandatory = $true)]
    [string]$ReceiptPath,

    [Parameter(Mandatory = $true)]
    [string]$EvidencePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$capabilityName = 'windows:hyper-v-vm-lifecycle'
$runId = if ($env:GITHUB_RUN_ID) { $env:GITHUB_RUN_ID } else { 'local' }
$attempt = if ($env:GITHUB_RUN_ATTEMPT) { $env:GITHUB_RUN_ATTEMPT } else { '0' }
$vmName = "ad-hv-$runId-$attempt"
$vmRoot = Join-Path $env:RUNNER_TEMP "agent-dispatch-hyperv-$runId-$attempt"

$stages = [System.Collections.Generic.List[object]]::new()
$classification = 'HARNESS_FAILURE'
$reason = 'probe did not reach a classified terminal state'
$createAttempted = $false
$oracleSatisfied = $false
$cleanupOk = $false
$vmCreated = $false
$vmStarted = $false
$vmInspected = $false
$vmStopped = $false
$vmRemoved = $false

function Add-Stage {
    param(
        [string]$Name,
        [string]$Outcome,
        [hashtable]$Evidence = @{}
    )
    $stages.Add([pscustomobject]@{
        name = $Name
        outcome = $Outcome
        evidence = [pscustomobject]$Evidence
    })
}

function Get-PublicError {
    param([System.Management.Automation.ErrorRecord]$ErrorRecord)
    return [ordered]@{
        exception_type = $ErrorRecord.Exception.GetType().FullName
        error_id = $ErrorRecord.FullyQualifiedErrorId
        category = $ErrorRecord.CategoryInfo.Category.ToString()
    }
}

function Get-OptionalFeatureState {
    param([string]$Name)
    try {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName $Name -ErrorAction Stop
        return [ordered]@{
            source = 'Get-WindowsOptionalFeature'
            state = $feature.State.ToString()
        }
    } catch {
        return [ordered]@{
            source = 'Get-WindowsOptionalFeature'
            state = 'query-failed'
            error = Get-PublicError $_
        }
    }
}

function Get-ServerFeatureState {
    param([string]$Name)
    $cmd = Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue
    if (-not $cmd) {
        return [ordered]@{
            source = 'Get-WindowsFeature'
            state = 'command-unavailable'
        }
    }
    try {
        $feature = Get-WindowsFeature -Name $Name -ErrorAction Stop
        return [ordered]@{
            source = 'Get-WindowsFeature'
            state = if ($feature.Installed) { 'Installed' } else { 'Available' }
        }
    } catch {
        return [ordered]@{
            source = 'Get-WindowsFeature'
            state = 'query-failed'
            error = Get-PublicError $_
        }
    }
}

function Write-Results {
    param(
        [string]$FinalClassification,
        [string]$FinalReason,
        [bool]$FinalOracleSatisfied,
        [bool]$FinalCleanupOk,
        [hashtable]$Preflight
    )

    $evidence = [ordered]@{
        probe = 'windows-2025-hyperv-lifecycle/1'
        receipt_schema = 'github-runner-capability/v1'
        authority = 'SemperSupra/agent-dispatch-private#405'
        consumer = 'mark-e-deyoung/WinBot#70'
        runner = [ordered]@{
            requested_label = 'windows-2025'
            runner_os = $env:RUNNER_OS
            runner_arch = $env:RUNNER_ARCH
            image_os = $env:ImageOS
            image_version = $env:ImageVersion
            repository_visibility = 'public'
            execution_model = 'native-host'
        }
        constraints = [ordered]@{
            guest_image = $false
            network_connection = $false
            secrets = $false
            private_winbot_assets = $false
            feature_enablement = $false
            reboot = $false
            vm_count = 1
        }
        preflight = [pscustomobject]$Preflight
        lifecycle = [ordered]@{
            create_attempted = $createAttempted
            created = $vmCreated
            started = $vmStarted
            inspected = $vmInspected
            stopped = $vmStopped
            removed = $vmRemoved
        }
        stages = @($stages)
        cleanup = [ordered]@{
            satisfied = $FinalCleanupOk
            vm_absent = $vmRemoved
            run_directory_absent = -not (Test-Path -LiteralPath $vmRoot)
        }
        classification = $FinalClassification
        oracle_satisfied = $FinalOracleSatisfied
        reason = $FinalReason
    }

    $evidenceDir = Split-Path -Parent $EvidencePath
    if ($evidenceDir) {
        New-Item -ItemType Directory -Force -Path $evidenceDir | Out-Null
    }
    $evidence | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $EvidencePath -Encoding utf8NoBOM

    $receipt = Get-Content -LiteralPath $ReceiptPath -Raw | ConvertFrom-Json
    $capability = [ordered]@{
        name = $capabilityName
        advertised = $null
        observed = [bool]($Preflight.hyper_v_module_present -or $Preflight.vmms_service_present -or $Preflight.hypervisor_present)
        installed = [bool]$Preflight.hyper_v_module_present
        callable = [bool]$Preflight.vmhost_query_succeeded
        exercised = $createAttempted
        oracleSatisfied = $FinalOracleSatisfied
        classification = $FinalClassification
        reason = $FinalReason
        evidence = [ordered]@{
            requested_label = 'windows-2025'
            probe = 'windows-2025-hyperv-lifecycle/1'
            hyper_v_module_present = $Preflight.hyper_v_module_present
            hyper_v_module_version = $Preflight.hyper_v_module_version
            vmms_service_present = $Preflight.vmms_service_present
            vmms_service_status = $Preflight.vmms_service_status
            vmhost_query_succeeded = $Preflight.vmhost_query_succeeded
            hypervisor_present = $Preflight.hypervisor_present
            optional_feature = $Preflight.optional_feature
            server_feature = $Preflight.server_feature
            lifecycle = $evidence.lifecycle
            cleanup = $evidence.cleanup
        }
    }

    $receipt.capabilities = @($receipt.capabilities) + [pscustomobject]$capability
    $receipt.warnings = @($receipt.warnings) + @(
        'Hyper-V placement is accepted only when the explicit VM lifecycle and cleanup oracle pass.',
        'This targeted probe does not authorize projection of private WinBot VHDX/ISO/credentials into public GitHub Actions.'
    )
    $receipt | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $ReceiptPath -Encoding utf8NoBOM

    Write-Host "HYPERV_CLASSIFICATION=$FinalClassification"
    Write-Host "HYPERV_ORACLE_SATISFIED=$FinalOracleSatisfied"
    Write-Host "HYPERV_CLEANUP_SATISFIED=$FinalCleanupOk"
}

$preflight = [ordered]@{
    hyper_v_module_present = $false
    hyper_v_module_version = $null
    required_commands = @()
    vmms_service_present = $false
    vmms_service_status = $null
    vmhost_query_succeeded = $false
    vmhost_query_error = $null
    hypervisor_present = $null
    processor_virtualization_firmware_enabled = $null
    processor_slat = $null
    processor_vm_monitor_mode_extensions = $null
    optional_feature = Get-OptionalFeatureState 'Microsoft-Hyper-V-All'
    server_feature = Get-ServerFeatureState 'Hyper-V'
}

try {
    $module = Get-Module -ListAvailable Hyper-V | Sort-Object Version -Descending | Select-Object -First 1
    if ($module) {
        $preflight.hyper_v_module_present = $true
        $preflight.hyper_v_module_version = $module.Version.ToString()
    }

    $required = @('Get-VM', 'New-VM', 'Start-VM', 'Stop-VM', 'Remove-VM', 'Get-VMHost', 'Get-VMNetworkAdapter', 'Remove-VMNetworkAdapter', 'Get-VMHardDiskDrive')
    $preflight.required_commands = @(
        foreach ($name in $required) {
            [ordered]@{
                name = $name
                present = [bool](Get-Command $name -ErrorAction SilentlyContinue)
            }
        }
    )

    $service = Get-Service vmms -ErrorAction SilentlyContinue
    if ($service) {
        $preflight.vmms_service_present = $true
        $preflight.vmms_service_status = $service.Status.ToString()
    }

    try {
        $hostInfo = Get-VMHost -ErrorAction Stop
        $preflight.vmhost_query_succeeded = $true
        Add-Stage 'vmhost-query' 'PASS' @{
            virtual_hard_disk_path_configured = [bool]$hostInfo.VirtualHardDiskPath
            virtual_machine_path_configured = [bool]$hostInfo.VirtualMachinePath
        }
    } catch {
        $preflight.vmhost_query_error = Get-PublicError $_
        Add-Stage 'vmhost-query' 'ENVIRONMENT_FAILURE' @{ error = $preflight.vmhost_query_error }
    }

    try {
        $computer = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $preflight.hypervisor_present = [bool]$computer.HypervisorPresent
    } catch {
        Add-Stage 'computer-system-query' 'INCONCLUSIVE' @{ error = Get-PublicError $_ }
    }

    try {
        $processor = Get-CimInstance Win32_Processor -ErrorAction Stop | Select-Object -First 1
        $preflight.processor_virtualization_firmware_enabled = [bool]$processor.VirtualizationFirmwareEnabled
        $preflight.processor_slat = [bool]$processor.SecondLevelAddressTranslationExtensions
        $preflight.processor_vm_monitor_mode_extensions = [bool]$processor.VMMonitorModeExtensions
    } catch {
        Add-Stage 'processor-virtualization-query' 'INCONCLUSIVE' @{ error = Get-PublicError $_ }
    }

    $newVmPresent = ($preflight.required_commands | Where-Object { $_.name -eq 'New-VM' }).present
    if (-not $newVmPresent) {
        $classification = 'ENVIRONMENT_FAILURE'
        $reason = 'Hyper-V New-VM cmdlet is not available on the hosted runner image.'
        Add-Stage 'create' 'ENVIRONMENT_FAILURE' @{ reason = 'New-VM command unavailable' }
    } else {
        New-Item -ItemType Directory -Force -Path $vmRoot | Out-Null
        $createAttempted = $true

        try {
            New-VM -Name $vmName -Generation 2 -MemoryStartupBytes 64MB -NoVHD -Path $vmRoot -ErrorAction Stop | Out-Null
            $vmCreated = [bool](Get-VM -Name $vmName -ErrorAction SilentlyContinue)
            if (-not $vmCreated) {
                $classification = 'ORACLE_FAILURE'
                $reason = 'New-VM returned without an observable run-owned VM.'
                Add-Stage 'create' 'ORACLE_FAILURE' @{ observable = $false }
            } else {
                Add-Stage 'create' 'PASS' @{
                    generation = 2
                    startup_memory_mib = 64
                    guest_image = $false
                }

                $adapters = @(Get-VMNetworkAdapter -VMName $vmName -ErrorAction Stop)
                foreach ($adapter in $adapters) {
                    Remove-VMNetworkAdapter -VMNetworkAdapter $adapter -ErrorAction Stop
                }

                $diskCount = @(Get-VMHardDiskDrive -VMName $vmName -ErrorAction Stop).Count
                $adapterCount = @(Get-VMNetworkAdapter -VMName $vmName -ErrorAction Stop).Count
                if ($diskCount -ne 0 -or $adapterCount -ne 0) {
                    $classification = 'ORACLE_FAILURE'
                    $reason = 'Run-owned VM did not satisfy the no-disk/no-network invariant before start.'
                    Add-Stage 'isolation-before-start' 'ORACLE_FAILURE' @{
                        disk_count = $diskCount
                        network_adapter_count = $adapterCount
                    }
                } else {
                    Add-Stage 'isolation-before-start' 'PASS' @{
                        disk_count = 0
                        network_adapter_count = 0
                    }

                    try {
                        Start-VM -Name $vmName -ErrorAction Stop
                        for ($i = 0; $i -lt 20; $i++) {
                            $state = (Get-VM -Name $vmName -ErrorAction Stop).State.ToString()
                            if ($state -eq 'Running') { break }
                            Start-Sleep -Milliseconds 250
                        }
                        $state = (Get-VM -Name $vmName -ErrorAction Stop).State.ToString()
                        if ($state -ne 'Running') {
                            $classification = 'ORACLE_FAILURE'
                            $reason = "VM start returned but running state was not observed; state=$state."
                            Add-Stage 'start' 'ORACLE_FAILURE' @{ observed_state = $state }
                        } else {
                            $vmStarted = $true
                            Add-Stage 'start' 'PASS' @{ observed_state = $state }

                            $vm = Get-VM -Name $vmName -ErrorAction Stop
                            $diskCount = @(Get-VMHardDiskDrive -VMName $vmName -ErrorAction Stop).Count
                            $adapterCount = @(Get-VMNetworkAdapter -VMName $vmName -ErrorAction Stop).Count
                            $vmInspected = ($vm.State.ToString() -eq 'Running' -and $diskCount -eq 0 -and $adapterCount -eq 0)
                            if (-not $vmInspected) {
                                $classification = 'ORACLE_FAILURE'
                                $reason = 'Running VM inspection failed the state/no-disk/no-network oracle.'
                                Add-Stage 'inspect' 'ORACLE_FAILURE' @{
                                    observed_state = $vm.State.ToString()
                                    disk_count = $diskCount
                                    network_adapter_count = $adapterCount
                                }
                            } else {
                                Add-Stage 'inspect' 'PASS' @{
                                    observed_state = 'Running'
                                    generation = $vm.Generation
                                    startup_memory_bytes = $vm.MemoryStartup
                                    disk_count = 0
                                    network_adapter_count = 0
                                }

                                Stop-VM -Name $vmName -TurnOff -Force -ErrorAction Stop
                                for ($i = 0; $i -lt 20; $i++) {
                                    $state = (Get-VM -Name $vmName -ErrorAction Stop).State.ToString()
                                    if ($state -eq 'Off') { break }
                                    Start-Sleep -Milliseconds 250
                                }
                                $state = (Get-VM -Name $vmName -ErrorAction Stop).State.ToString()
                                if ($state -ne 'Off') {
                                    $classification = 'ORACLE_FAILURE'
                                    $reason = "VM stop returned but Off state was not observed; state=$state."
                                    Add-Stage 'stop' 'ORACLE_FAILURE' @{ observed_state = $state }
                                } else {
                                    $vmStopped = $true
                                    Add-Stage 'stop' 'PASS' @{ observed_state = 'Off' }

                                    Remove-VM -Name $vmName -Force -ErrorAction Stop
                                    $vmRemoved = -not [bool](Get-VM -Name $vmName -ErrorAction SilentlyContinue)
                                    if (-not $vmRemoved) {
                                        $classification = 'ORACLE_FAILURE'
                                        $reason = 'Remove-VM returned but the run-owned VM remained observable.'
                                        Add-Stage 'remove' 'ORACLE_FAILURE' @{ vm_absent = $false }
                                    } else {
                                        Add-Stage 'remove' 'PASS' @{ vm_absent = $true }
                                        $classification = 'SUPPORTED'
                                        $reason = 'Run-owned Hyper-V VM create/start/inspect/stop/remove lifecycle passed.'
                                    }
                                }
                            }
                        }
                    } catch {
                        $err = Get-PublicError $_
                        if (-not $vmStarted) {
                            $classification = 'ENVIRONMENT_FAILURE'
                            $reason = 'The hosted environment rejected Hyper-V VM start/control despite the cmdlet surface being present.'
                            Add-Stage 'start-or-control' 'ENVIRONMENT_FAILURE' @{ error = $err }
                        } else {
                            $classification = 'ORACLE_FAILURE'
                            $reason = 'Hyper-V lifecycle control failed after the run-owned VM had started.'
                            Add-Stage 'lifecycle-control' 'ORACLE_FAILURE' @{ error = $err }
                        }
                    }
                }
            }
        } catch {
            $classification = 'ENVIRONMENT_FAILURE'
            $reason = 'The hosted environment rejected creation of the run-owned Hyper-V VM.'
            Add-Stage 'create' 'ENVIRONMENT_FAILURE' @{ error = Get-PublicError $_ }
        }
    }
} catch {
    $classification = 'HARNESS_FAILURE'
    $reason = 'The probe harness failed outside a classified Hyper-V lifecycle operation.'
    Add-Stage 'harness' 'HARNESS_FAILURE' @{ error = Get-PublicError $_ }
} finally {
    try {
        $leftover = Get-VM -Name $vmName -ErrorAction SilentlyContinue
        if ($leftover) {
            if ($leftover.State.ToString() -ne 'Off') {
                Stop-VM -Name $vmName -TurnOff -Force -ErrorAction Stop
            }
            Remove-VM -Name $vmName -Force -ErrorAction Stop
        }

        if (Test-Path -LiteralPath $vmRoot) {
            Remove-Item -LiteralPath $vmRoot -Recurse -Force -ErrorAction Stop
        }

        $vmAbsent = -not [bool](Get-VM -Name $vmName -ErrorAction SilentlyContinue)
        $dirAbsent = -not (Test-Path -LiteralPath $vmRoot)
        $cleanupOk = $vmAbsent -and $dirAbsent
        $vmRemoved = $vmRemoved -or $vmAbsent
        if ($cleanupOk) {
            Add-Stage 'cleanup' 'PASS' @{ vm_absent = $vmAbsent; run_directory_absent = $dirAbsent }
        } else {
            Add-Stage 'cleanup' 'ORACLE_FAILURE' @{ vm_absent = $vmAbsent; run_directory_absent = $dirAbsent }
            $classification = 'ORACLE_FAILURE'
            $reason = 'Run-owned Hyper-V cleanup oracle failed.'
        }
    } catch {
        $cleanupOk = $false
        $classification = 'ORACLE_FAILURE'
        $reason = 'Run-owned Hyper-V cleanup raised an error.'
        Add-Stage 'cleanup' 'ORACLE_FAILURE' @{ error = Get-PublicError $_ }
    }

    $oracleSatisfied = (
        $classification -eq 'SUPPORTED' -and
        $vmCreated -and $vmStarted -and $vmInspected -and $vmStopped -and $vmRemoved -and $cleanupOk
    )

    if ($classification -eq 'SUPPORTED' -and -not $oracleSatisfied) {
        $classification = 'ORACLE_FAILURE'
        $reason = 'The lifecycle classification reached SUPPORTED but the independent lifecycle/cleanup oracle was incomplete.'
    }

    try {
        Write-Results -FinalClassification $classification -FinalReason $reason -FinalOracleSatisfied $oracleSatisfied -FinalCleanupOk $cleanupOk -Preflight $preflight
    } catch {
        Write-Error "HARNESS_FAILURE: unable to preserve probe evidence/receipt: $($_.Exception.GetType().FullName)"
        exit 2
    }
}

exit 0
