param([Parameter(Mandatory=$true)][string]$Workflow)
$ErrorActionPreference='Stop'
$src=Get-Content -LiteralPath $Workflow -Raw
$required=@('winget_version_seen','winget_not_found_seen','winget_config_apply_seen','winget_individual_fallback_seen','winget_config_warning_seen','choco_fallback_seen','choco_python_attempt_seen','choco_gsudo_attempt_seen','ssh_capability_install_attempt_seen','remote_config_failure_seen','api_task_install_attempt_seen','python_command_visible_at_probe','gsudo_command_visible_at_probe','winget_command_visible_at_probe','choco_command_visible_at_probe','python_binary_known_location_at_probe','sshd_service_exists_at_probe','psdirect_elevated_at_probe')
foreach($k in $required){ if($src -notmatch [regex]::Escape("'$k'")){ throw 'Allowlist missing field' }}
if($src -notmatch 'dependency_probe = \$dependencyFlags'){throw 'Bounded reducer entry missing'}
if($src -match 'dependency_probe = \$r.work_cells.a.dependency_probe'){throw 'Unchecked raw forwarding'}
Write-Host 'WINBOT_95_DEPENDENCY_RECEIPT_STATIC_PASS'
