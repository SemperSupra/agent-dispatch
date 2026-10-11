param([Parameter(Mandatory=$true)][string]$Control)
$ErrorActionPreference='Stop'
$tokens=$null
$errors=$null
[void][System.Management.Automation.Language.Parser]::ParseFile($Control,[ref]$tokens,[ref]$errors)
if ($errors.Count -ne 0) {
  Write-Error ("PS51_PARSE_ERROR_COUNT=" + $errors.Count)
  exit 1
}
Write-Host 'WINBOT_95_DEPENDENCY_PS51_PARSE_PASS'
