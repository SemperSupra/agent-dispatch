param([Parameter(Mandatory=$true)][string]$Workflow)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$raw = Get-Content -LiteralPath $Workflow -Raw
$start = $raw.IndexOf('      - name: Derive bounded authority-repair diagnostic v2 receipt', [StringComparison]::Ordinal)
if ($start -lt 0) { throw 'bounded receipt step missing' }
$block = $raw.IndexOf("        run: |`n", $start, [StringComparison]::Ordinal)
if ($block -lt 0) { throw 'bounded receipt run block missing' }
$block += "        run: |`n".Length
$end = $raw.IndexOf('      - name: Upload bounded authority-repair diagnostic v2 evidence', $block, [StringComparison]::Ordinal)
if ($end -le $block) { throw 'bounded receipt step end missing' }
$part = $raw.Substring($block, $end - $block)
$lines = $part -split "`n" | ForEach-Object {
    if ($_ -match '^          ') { $_.Substring(10) } else { $_ }
}
$script = $lines -join "`n"
$tokens=$null; $errors=$null
[void][System.Management.Automation.Language.Parser]::ParseInput($script,[ref]$tokens,[ref]$errors)
if ($errors.Count -ne 0) { throw 'bounded receipt PowerShell parser failure' }
$start = $script.IndexOf('# Validate again on the trusted side', [StringComparison]::Ordinal)
$end = $script.IndexOf('$out = [ordered]@{', $start, [StringComparison]::Ordinal)
if ($start -lt 0 -or $end -le $start) { throw 'trusted whitelist injection missing' }
$validator = [ScriptBlock]::Create($script.Substring($start, $end-$start))
$required = @(
    'api_present','python_present','token_present','task_present',
    'authenticated_health','gsudo_present','sshd_capability_installed',
    'sshd_running','sshd_startup_automatic','ssh_firewall_enabled'
)
function Invoke-Whitelist {
    param([System.Collections.IDictionary]$InputFlags,[string]$Status='valid')
    $r = @{work_cells=@{a=@{critical_failure_marker_state=$Status;critical_failure_flags=$InputFlags}}}
    $criticalState='absent'
    $criticalFlags=$null
    . $validator
    return [PSCustomObject]@{State=$criticalState;Flags=$criticalFlags}
}
$required = @('api_present','python_present','token_present','task_present','authenticated_health','gsudo_present','sshd_capability_installed','sshd_running','sshd_startup_automatic','ssh_firewall_enabled')
$base=[ordered]@{}
foreach($name in $required) { $base[$name]=$true }
foreach($name in $required) {
    $fixture=[ordered]@{}
    foreach($key in $required) { $fixture[$key]=($key -ne $name) }
    $result=Invoke-Whitelist $fixture
    if ($result.State -ne 'valid' -or $result.Flags.Count -ne 10 -or $result.Flags[$name]) {
        throw ('trusted flag visibility failed: ' + $name)
    }
}
$bad=[ordered]@{}
foreach($name in $required) { $bad[$name]=$true }
$bad['token_canary']='must-never-appear'
$result=Invoke-Whitelist $bad
if ($result.State -ne 'malformed' -or $null -ne $result.Flags) { throw 'trusted unknown key disclosed' }
$bad=[ordered]@{}
foreach($name in $required) { $bad[$name]=$true }
$bad['python_present']='false'
$result=Invoke-Whitelist $bad
if ($result.State -ne 'malformed' -or $null -ne $result.Flags) { throw 'trusted false string coerced' }
$result=Invoke-Whitelist $base -Status 'unreadable'
if ($result.State -ne 'unreadable' -or $null -ne $result.Flags) { throw 'trusted unreadable marker leaked' }
Write-Host 'WINBOT_95_TRUSTED_RECEIPT_CONTRACT_PASS'
