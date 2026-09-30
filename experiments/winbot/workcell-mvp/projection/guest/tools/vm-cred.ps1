# WinBot Guest-Side Credential Manager CRUD
# Manages Windows Credential Manager entries inside a VM via cmdkey.
# Can be run directly on the guest, or invoked remotely via PowerShell Direct.
#
# Called by: winbot-cred.ps1 (host wrapper, -VM parameter)
#
# Usage (inside VM):
#   .\vm-cred.ps1 -List
#   .\vm-cred.ps1 -Get -Target "WinBot_vm-password"
#   .\vm-cred.ps1 -Add -Target "github" -User "mark" -Pass "ghp_..."
#   .\vm-cred.ps1 -Remove -Target "old-entry"
#
# Output: JSON structured result (always the last line written to stdout)

param(
    [switch]$List,              # List all stored credentials
    [switch]$Get,               # Show details for a specific credential
    [string]$Target = "",       # Credential target name (for Get/Add/Remove)
    [string]$User = "",         # Username (for Add)
    [string]$Pass = "",         # Password (for Add)
    [switch]$Add,               # Add or update a credential
    [switch]$Remove             # Delete a credential entry
)

$ErrorActionPreference = "Continue"

$result = @{
    Success   = $false
    Operation = ""
    Entries   = @()
    Message   = ""
    Warnings  = @()
}

function _warn($msg) {
    Write-Warning $msg
    $result.Warnings += $msg
}

# ---- LIST: Enumerate all stored credentials ----
if ($List) {
    $result.Operation = "List"
    try {
        $raw = cmdkey /list 2>&1
        $entries = @()
        $current = @{}
        foreach ($line in $raw) {
            if ($line -match '^---') { continue }
            if ($line -match '^\s*Target:\s*(.+)') {
                if ($current.ContainsKey('Target') -and $current.Target) {
                    $entries += [PSCustomObject]@{
                        Target   = $current.Target.Trim()
                        Type     = $current.Type.Trim()
                        User     = $current.User.Trim()
                        SavedFor = $current.SavedFor.Trim()
                    }
                }
                $current = @{ Target = $matches[1].Trim(); Type = ""; User = ""; SavedFor = "" }
            } elseif ($line -match '^\s*Type:\s*(.+)$') {
                $current.Type = $matches[1].Trim()
            } elseif ($line -match '^\s*User:\s*(.+)$') {
                $current.User = $matches[1].Trim()
            } elseif ($line -match '^\s*Saved for this logon only') {
                $current.SavedFor = "This logon only"
            } elseif ($line -match '^\s*Local machine persistence') {
                $current.SavedFor = "Local machine"
            }
        }
        # Last entry
        if ($current.ContainsKey('Target') -and $current.Target) {
            $entries += [PSCustomObject]@{
                Target   = $current.Target.Trim()
                Type     = $current.Type.Trim()
                User     = $current.User.Trim()
                SavedFor = $current.SavedFor.Trim()
            }
        }
        $result.Entries = $entries
        $result.Message = "Found $($entries.Count) credential(s)."
        $result.Success = $true
    } catch {
        _warn "Failed to list credentials: $_"
    }
    Write-Output ($result | ConvertTo-Json -Depth 3 -Compress)
    exit
}

# ---- GET: Show details for a specific credential ----
if ($Get) {
    $result.Operation = "Get"
    $result.Entries = @(@{ Target = $Target })
    if (-not $Target) {
        _warn "-Target is required for -Get."
        Write-Output ($result | ConvertTo-Json -Depth 3 -Compress)
        exit
    }
    try {
        $raw = cmdkey /list:$Target 2>&1
        $found = $false
        $details = @{ Target = $Target; Type = ""; User = ""; SavedFor = "" }
        foreach ($line in $raw) {
            if ($line -match '^\s*Target:\s*(.+)') {
                $found = $true
                $details.Target = $matches[1].Trim()
            } elseif ($line -match '^\s*Type:\s*(.+)$') {
                $details.Type = $matches[1].Trim()
            } elseif ($line -match '^\s*User:\s*(.+)$') {
                $details.User = $matches[1].Trim()
            } elseif ($line -match '^\s*Saved for this logon only') {
                $details.SavedFor = "This logon only"
            } elseif ($line -match '^\s*Local machine persistence') {
                $details.SavedFor = "Local machine"
            }
        }
        if ($found) {
            $result.Entries = @($details)
            $result.Message = "Found credential '$Target'."
            $result.Success = $true
        } else {
            $result.Message = "Credential '$Target' not found."
            $result.Success = $true  # Not an error -- just not found
        }
    } catch {
        _warn "Failed to get credential '$Target': $_"
    }
    Write-Output ($result | ConvertTo-Json -Depth 3 -Compress)
    exit
}

# ---- ADD: Create or update a credential ----
if ($Add) {
    $result.Operation = "Add"
    $result.Entries = @(@{ Target = $Target; User = $User })
    if (-not $Target) { _warn "-Target is required for -Add."; Write-Output ($result | ConvertTo-Json -Depth 3 -Compress); exit }
    if (-not $User)   { _warn "-User is required for -Add.";   Write-Output ($result | ConvertTo-Json -Depth 3 -Compress); exit }
    if (-not $Pass)   { _warn "-Pass is required for -Add.";   Write-Output ($result | ConvertTo-Json -Depth 3 -Compress); exit }
    try {
        # Delete existing entry first (cmdkey /generic fails if target exists with different type)
        cmdkey /delete:$Target 2>$null | Out-Null
        cmdkey /delete:"LegacyGeneric:target=$Target" 2>$null | Out-Null
        cmdkey /delete:"Domain:target=$Target" 2>$null | Out-Null
        $output = cmdkey /generic:$Target /user:$User /pass:$Pass 2>&1
        if ($LASTEXITCODE -eq 0) {
            $result.Message = "Credential '$Target' stored for user '$User'."
            $result.Success = $true
        } else {
            _warn "cmdkey failed: $output"
        }
    } catch {
        _warn "Failed to add credential '$Target': $_"
    }
    Write-Output ($result | ConvertTo-Json -Depth 3 -Compress)
    exit
}

# ---- REMOVE: Delete a credential ----
if ($Remove) {
    $result.Operation = "Remove"
    $result.Entries = @(@{ Target = $Target })
    if (-not $Target) {
        _warn "-Target is required for -Remove."
        Write-Output ($result | ConvertTo-Json -Depth 3 -Compress)
        exit
    }
    try {
        # Try all target variants
        $output1 = cmdkey /delete:$Target 2>&1
        $output2 = cmdkey /delete:"LegacyGeneric:target=$Target" 2>&1
        $output3 = cmdkey /delete:"Domain:target=$Target" 2>&1
        $result.Message = "Removal attempted for '$Target'."
        $result.Success = $true
    } catch {
        _warn "Failed to remove credential '$Target': $_"
    }
    Write-Output ($result | ConvertTo-Json -Depth 3 -Compress)
    exit
}

# ---- No operation specified ----
$result.Message = "No operation specified. Use -List, -Get, -Add, or -Remove."
Write-Output ($result | ConvertTo-Json -Depth 3 -Compress)
