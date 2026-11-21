#requires -Version 5.1
# PUBLIC synthetic-only. Executes inside a newly created, no-network Win11 Eval
# guest through Hyper-V PowerShell Direct. Never supply private product source.
param([Parameter(Mandatory=$true)][string]$ExpectedBinarySha256)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$name='PublicRDTECanary'
$root='C:\RDTE'
$binary=Join-Path $root 'public-rdte-service.exe'
$events=New-Object System.Collections.Generic.List[object]
$failed=$null
$serviceCreated=$false
$cleanupDone=$false

function Witness([string]$stage,[bool]$success) {
    $events.Add([pscustomobject]@{ stage=$stage; success=$success })
    if (-not $success) {throw "FAILED_ORACLE_$stage"}
}
function HasService {
    return ($null -ne (Get-Service -Name $name -ErrorAction SilentlyContinue))
}
function VerifyBinary([string]$claimed) {
    if ($claimed -notmatch '^[a-fA-F0-9]{64}$') {return $false}
    if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {return $false}
    $observed=(Get-FileHash -LiteralPath $binary -Algorithm SHA256 -ErrorAction Stop).Hash
    return $observed.Equals($claimed,[System.StringComparison]::OrdinalIgnoreCase)
}
try {
    if (HasService) {throw 'SERVICE_COLLISION_UNOWNED'}
    if (-not (VerifyBinary $ExpectedBinarySha256)) {throw 'SERVICE_BINARY_PROVENANCE_MISMATCH'}
    Witness 'BINARY_VERIFIED' $true

    # This is a real native Windows service registration on an isolated guest,
    # but the program only writes two harmless marker files. No listener/NIC.
    & sc.exe create $name 'binPath=' $binary 'start=' 'demand' 'type=' 'own' | Out-Null
    if ($LASTEXITCODE -ne 0) {throw "SC_CREATE_EXIT_$LASTEXITCODE"}
    $serviceCreated=$true
    Witness 'SERVICE_CREATED' (HasService)

    Start-Service -Name $name -ErrorAction Stop
    $service=Get-Service -Name $name -ErrorAction Stop
    $service.WaitForStatus('Running',[TimeSpan]::FromSeconds(20))
    $marker=Join-Path $root 'public-service-running.ok'
    $healthy=(Test-Path -LiteralPath $marker -PathType Leaf)
    if ($healthy) {$healthy=((Get-Content -LiteralPath $marker -Raw).Trim() -eq 'synthetic-public-service-running-v1')}
    Witness 'SERVICE_RUNNING' ($healthy -and $service.Status -eq 'Running')

    # Idempotence = observe registered owned service and exact binary, do not
    # issue a duplicate sc.exe create or reconfigure any service.
    $again=Get-Service -Name $name -ErrorAction Stop
    Witness 'IDEMPOTENT_READBACK' ($again.Status -eq 'Running' -and (VerifyBinary $ExpectedBinarySha256))

    # Fault injection: an intentionally incorrect binary hash must deny a
    # change before it reaches Windows service control. No policy bypass.
    $wrong=('0' * 64)
    if ($ExpectedBinarySha256 -eq $wrong) {$wrong=('f'*64)}
    Witness 'WRONG_HASH_DENIED' (-not (VerifyBinary $wrong))

    Stop-Service -Name $name -ErrorAction Stop
    $service=Get-Service -Name $name -ErrorAction Stop
    $service.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(20))
    $marker=Join-Path $root 'public-service-stopped.ok'
    $stopped=(Test-Path -LiteralPath $marker -PathType Leaf)
    if ($stopped) {$stopped=((Get-Content -LiteralPath $marker -Raw).Trim() -eq 'synthetic-public-service-stopped-v1')}
    Witness 'SERVICE_STOPPED' ($stopped -and $service.Status -eq 'Stopped')

    & sc.exe delete $name | Out-Null
    if ($LASTEXITCODE -ne 0) {throw "SC_DELETE_EXIT_$LASTEXITCODE"}
    for ($i=0;$i -lt 20 -and (HasService);$i++) {Start-Sleep -Milliseconds 500}
    Witness 'SERVICE_REMOVED' (-not (HasService))
    $serviceCreated=$false
    Remove-Item -LiteralPath $binary -Force -ErrorAction Stop
    Witness 'BINARY_REMOVED' (-not (Test-Path -LiteralPath $binary))
} catch {
    $failed=$_.Exception.Message
} finally {
    # Independent cleanup even if one stage fails. Never delete any service
    # other than the exact name created by this test run.
    try {
        if ($serviceCreated) {
            if (HasService) {
                $active=Get-Service -Name $name
                if ($active.Status -ne 'Stopped') {Stop-Service -Name $name -ErrorAction Stop}
                & sc.exe delete $name | Out-Null
                if ($LASTEXITCODE -ne 0) {throw 'SECONDARY_SERVICE_DELETE_FAILED'}
                for ($i=0;$i -lt 20 -and (HasService);$i++) {Start-Sleep -Milliseconds 500}
            }
        }
        if (Test-Path -LiteralPath $binary -PathType Leaf) {
            # This marker is run-created on an otherwise fresh guest; if source
            # hash no longer matches, preserve for VM-level teardown instead.
            if (-not (VerifyBinary $ExpectedBinarySha256)) {
                throw 'OWNED_BINARY_MUTATED_PRESERVED_FOR_VM_DESTROY'
            }
            Remove-Item -LiteralPath $binary -Force -ErrorAction Stop
        }
        $cleanupDone=(-not (HasService) -and -not (Test-Path -LiteralPath $binary))
    } catch {
        $cleanupDone=$false
    }
}
# A failed oracle still yields a machine-readable receipt; caller must fail.
[pscustomobject]@{
    schema='public-guest-service-rdte/guest-v1'
    events=@($events.ToArray())
    guest_service_cleanup=$cleanupDone
    guest_failure=$failed
    service_name=$name
}
