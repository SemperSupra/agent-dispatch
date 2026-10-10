param(
    [Parameter(Mandatory=$true)][string]$Guard
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $Guard)) { throw 'Immutable guard parser input missing' }
$root = Join-Path ([IO.Path]::GetTempPath()) ('winbot95-oneuse-' + [Guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Force -Path $root)
$sha = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
$path = '.github/workflows/winbot-95-owner-approved-a-only.yml'
$branch = 'refs/heads/exp/winbot-95-bounded-diagnostic-20261009'
$passed = 0
function Check([string]$shell,[string]$case,[bool]$wantPass) {
    $env:GITHUB_RUN_ATTEMPT = '1'
    $env:GITHUB_EVENT_NAME = 'push'
    $env:GITHUB_REF = $branch
    $env:GITHUB_SHA = $sha
    $env:GITHUB_EVENT_PATH = Join-Path $root ('event-' + $shell.Replace('.','-') + '-' + $case + '.json')
    $evt = @{
        after = $sha
        head_commit = @{ id = $sha; added = @($path); modified = @() }
        commits = @(@{ id = $sha })
    }
    switch ($case) {
        'initial' { }
        'rerun' { $env:GITHUB_RUN_ATTEMPT = '2' }
        'wrong-event' { $env:GITHUB_EVENT_NAME = 'workflow_dispatch' }
        'wrong-branch' { $env:GITHUB_REF = 'refs/heads/main' }
        'second-commit' { $evt.commits = @(@{id=$sha},@{id=$sha}) }
        'mismatched-head' { $evt.head_commit.id = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' }
        'mismatched-after' { $evt.after = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' }
        'modified-only' { $evt.head_commit.added = @(); $evt.head_commit.modified = @($path) }
        'other-file-added' { $evt.head_commit.added = @('README.md') }
        'missing-event' { }
        default { throw 'Unrecognized test case' }
    }
    if ($case -ne 'missing-event') {
        $evt | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $env:GITHUB_EVENT_PATH -Encoding UTF8
    }
    $priorPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    if ($shell -eq 'powershell.exe') {
        $output = & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $Guard 2>&1
    } else {
        $output = & pwsh -NoProfile -NonInteractive -File $Guard 2>&1
    }
    $exit = $LASTEXITCODE
    $ErrorActionPreference = $priorPreference
    if ($wantPass -and ($exit -ne 0 -or -not (($output | Out-String).Contains('WINBOT_95_ONE_RUN_INITIAL_PUBLICATION_PASS')))) {
        throw ('Initial-only admission unexpectedly rejected: ' + $shell + '/' + $case)
    }
    if (-not $wantPass -and $exit -eq 0) {
        throw ('Single-use guard accepted forbidden case: ' + $shell + '/' + $case)
    }
    $script:passed++
}
try {
    foreach ($shell in @('powershell.exe','pwsh')) {
        Check $shell 'initial' $true
        foreach ($case in @('rerun','wrong-event','wrong-branch','second-commit','mismatched-head',
                'mismatched-after','modified-only','other-file-added','missing-event')) {
            Check $shell $case $false
        }
    }
    if ($script:passed -ne 20) { throw 'Single-use test matrix was incomplete' }
    Write-Host ('WINBOT_95_SINGLE_USE_GUARD_BEHAVIOR_PASS cases=' + $script:passed)
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
