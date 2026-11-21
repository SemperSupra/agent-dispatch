#requires -Version 5.1
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
function Ensure([bool]$condition,[string]$reason){if(-not $condition){throw $reason}}
$script=Join-Path (Split-Path -Parent $PSScriptRoot) 'public_wyse_r58_windows_host.ps1'
Ensure (Test-Path -LiteralPath $script -PathType Leaf) 'Public PS5.1 harness absent.'
$o=(& $script -Phase Observe | Out-String)|ConvertFrom-Json
Ensure ($o.schema -ceq 'wyse-r58-public-host-observation/v1') 'Bad observation schema.'
Ensure ($o.physical_wyse -ceq 'NOT_TESTED') 'False physical pass.'
$p=@(& $script -Phase Plan)
$q=@(& $script -Phase Plan)
Ensure (($p -join [Environment]::NewLine) -ceq ($q -join [Environment]::NewLine)) 'Non-deterministic Plan.'
Ensure ($p.Count -eq 2) 'Unexpected plan fields.'
$plan=$p[0]|ConvertFrom-Json
Ensure ($plan.schema -ceq 'wyse-r58-public-host-plan/v1') 'Bad plan.'
Ensure ($plan.allow_apply -eq $false) 'Unsafe plan admission.'
Ensure ($plan.host_installs -ceq 'FORBIDDEN') 'Host-taint contract drift.'
$hash=($p[1] -replace '^PLAN_SHA256=','')
Ensure ($hash -cmatch '^[0-9a-f]{64}$') 'Invalid immutable plan digest.'
$v=@(& $script -Phase Verify -ExpectedPlanSha256 $hash)
Ensure ($v[0] -ceq 'R58_WINDOWS_PLAN_HASH_VERIFY=PASS') 'Fresh verification failed.'
$denied=$false
try {$null=& $script -Phase Verify -ExpectedPlanSha256 ('0'*64)}catch{$denied=$true}
Ensure $denied 'Wrong digest accepted.'
$denied=$false
try {$null=& $script -Phase Apply -ExpectedPlanSha256 $hash}catch{$denied=$true}
Ensure $denied 'Public APPLY accepted.'
Write-Output 'R58_WINDOWS_PS51_OBSERVE_PLAN_VERIFY_DENY_APPLY=PASS'
