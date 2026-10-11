param([Parameter(Mandatory=$true)][string]$Control)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$source = Get-Content -LiteralPath $Control -Raw
$startToken = '                        if ([string]$phase -ceq ''9.5/9-ready'''
$endToken = '                        if ($null -ne $failureObj.route_ready)'
$start = $source.IndexOf($startToken, [StringComparison]::Ordinal)
if ($start -lt 0) { throw 'critical marker extraction anchor missing' }
$end = $source.IndexOf($endToken, $start, [StringComparison]::Ordinal)
if ($end -le $start) { throw 'critical marker extraction end missing' }
$probe = [ScriptBlock]::Create($source.Substring($start, $end - $start))
$names = @(
    'api_present','python_present','token_present','task_present',
    'authenticated_health','gsudo_present','sshd_capability_installed',
    'sshd_running','sshd_startup_automatic','ssh_firewall_enabled'
)
function Invoke-SyntheticMarker {
    param([hashtable]$Values,[string]$Phase='9.5/9-ready',[string]$Status='failed')
    $phase = $Phase
    $phaseStatus = $Status
    $criticalMarkerState = 'malformed'
    $criticalFlags = $null
    $failureObj = ($Values | ConvertTo-Json -Depth 5 -Compress) | ConvertFrom-Json
    . $probe
    return [PSCustomObject]@{ State = $criticalMarkerState; Flags = $criticalFlags }
}
$base = @{ phase = '9.5/9-ready'; timestamp = 'not-published' }
foreach ($name in $names) { $base[$name] = $true }
$r = Invoke-SyntheticMarker $base
if ($r.State -ne 'valid' -or $r.Flags.Count -ne 10) { throw 'all-true fixture rejected' }
foreach ($name in $names) {
    $v = $base.Clone()
    $v[$name] = $false
    $r = Invoke-SyntheticMarker $v
    if ($r.State -ne 'valid' -or $r.Flags[$name] -ne $false -or $r.Flags.Count -ne 10) {
        throw ('false-key fixture rejected: ' + $name)
    }
}
$bad = $base.Clone(); $bad.Remove('api_present')
if ((Invoke-SyntheticMarker $bad).State -ne 'malformed') { throw 'missing key accepted' }
$bad = $base.Clone(); $bad['api_present'] = 'false'
if ((Invoke-SyntheticMarker $bad).State -ne 'malformed') { throw 'string false accepted' }
$bad = $base.Clone(); $bad['api_present'] = $null
if ((Invoke-SyntheticMarker $bad).State -ne 'malformed') { throw 'null accepted' }
$bad = $base.Clone(); $bad['token_canary'] = 'never-publish'
if ((Invoke-SyntheticMarker $bad).State -ne 'malformed') { throw 'unknown field accepted' }
$bad = $base.Clone(); $bad.Remove('api_present'); $bad['API_present'] = $true
if ((Invoke-SyntheticMarker $bad).State -ne 'malformed') { throw 'case variation accepted' }
if ((Invoke-SyntheticMarker $base -Status 'running').State -ne 'malformed') {
    throw 'nonterminal accepted'
}
if ((Invoke-SyntheticMarker $base -Phase '8/8-enroll').State -ne 'malformed') {
    throw 'wrong phase accepted'
}
if ($source -notmatch '\(\[string\]\$provisionPhase -eq ''9\.5/9-ready''\)') {
    throw 'terminal blank-reason early exit not implemented'
}
Write-Host 'WINBOT_95_MARKER_CONTRACT_PASS'
