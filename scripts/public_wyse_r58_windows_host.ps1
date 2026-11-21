#requires -Version 5.1
<#
Public synthetic R58: bounded, zero-install Windows developer-host census and
deterministic plan. No physical KVM, new drivers, services, external virtual
switch, USB media, DHCP, or device mutation; GHA cannot qualify private HIL.
#>
[CmdletBinding()]
param(
 [ValidateSet('Observe','Plan','Apply','Verify')][string]$Phase='Observe',
 [string]$ExpectedPlanSha256=''
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
function HasCommand([string]$cmd) {return [bool](Get-Command -Name $cmd -ErrorAction SilentlyContinue)}
function Sha([string]$value){
  $sha=[Security.Cryptography.SHA256]::Create()
  try {return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($value)))).Replace('-','').ToLowerInvariant()}
  finally{$sha.Dispose()}
}
function GetObserved {
  $os='UNKNOWN'
  try {$os=[string](Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).Version}catch{}
  $tools=[ordered]@{
    powershell51=($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -eq 1)
    hyperv_vm_present=(HasCommand 'Get-VM')
    hyperv_vhdx_present=(HasCommand 'New-VHD')
    hyperv_copy_vmfile_present=(HasCommand 'Copy-VMFile')
    pnpenumeration_present=(HasCommand 'Get-PnpDevice')
    git_present=(HasCommand 'git.exe')
  }
  return [ordered]@{
    schema='wyse-r58-public-host-observation/v1'
    runtime='GITHUB_PUBLIC_SYNTHETIC_OR_LOCAL_READONLY'
    os_version=$os;tools=$tools
    physical_wyse='NOT_TESTED'
    usb_target_control='NOT_TESTED'
    hyperv_vm_hil='NOT_TESTED'
  }
}
function GetPlan($obs) {
 $missing=New-Object System.Collections.Generic.List[string]
 foreach($key in @('powershell51','hyperv_vm_present','hyperv_vhdx_present','hyperv_copy_vmfile_present','pnpenumeration_present')) {
   if(-not $obs.tools[$key]){$missing.Add($key)}
 }
 return [ordered]@{
   schema='wyse-r58-public-host-plan/v1'
   observed=$obs
   blockers=@($missing.ToArray() | Sort-Object)
   eligible_for_separate_local_census=($missing.Count -eq 0)
   allow_apply=$false
   host_installs='FORBIDDEN'
   physical_wyse='NOT_TESTED'
   external_network='FORBIDDEN'
 }
}
$obs=GetObserved
$plan=GetPlan $obs
$json=$plan|ConvertTo-Json -Depth 12 -Compress
$digest=Sha $json
switch($Phase) {
 'Observe' {$obs|ConvertTo-Json -Depth 12;break}
 'Plan' {
   Write-Output $json
   Write-Output ('PLAN_SHA256='+$digest)
   break
 }
 'Verify' {
   if($ExpectedPlanSha256 -cnotmatch '^[a-f0-9]{64}$' -or $ExpectedPlanSha256 -cne $digest){throw 'Stale or unknown public synthetic plan.'}
   Write-Output 'R58_WINDOWS_PLAN_HASH_VERIFY=PASS'
   break
 }
 'Apply' {throw 'DENIED: this public RDTE harness cannot install host tooling, create Hyper-V guests, touch USB, or change private site configuration.'}
}
