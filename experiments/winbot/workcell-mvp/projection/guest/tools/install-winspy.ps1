# WinBot: Install WinSpy window inspection utility
# Run as Administrator on the VM
# Usage: powershell -ExecutionPolicy Bypass -File install-winspy.ps1

$ErrorActionPreference = "Stop"

# === WinBot Guardrail: VM-Only ===
function Test-IsHyperVVM {
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    if ($cs -and $cs.Manufacturer -eq "Microsoft Corporation" -and $cs.Model -eq "Virtual Machine") { return $true }
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters") { return $true }
    $hvServices = @("vmicheartbeat", "vmictimesync", "vmickvpexchange", "vmicshutdown", "vmicvss")
    foreach ($svcName in $hvServices) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq "Running") { return $true }
    }
    $bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
    if ($bios -and $bios.SMBIOSBIOSVersion -match "Hyper-V|VRTUAL") { return $true }
    return $false
}
$skipCheck = $env:WINBOT_SKIP_VM_GUARDRAIL -eq "1"
if (-not $skipCheck -and -not (Test-IsHyperVVM)) {
    Write-Host "`n========================================" -ForegroundColor Red
    Write-Host "  SAFETY GUARDRAIL: HOST PROTECTION" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "  This script modifies system settings and MUST only run" -ForegroundColor Red
    Write-Host "  inside a Hyper-V VM, NEVER on a physical host." -ForegroundColor Red
    Write-Host "  Current system is NOT a Hyper-V VM." -ForegroundColor Red
    Write-Host ""
    Write-Host "  To run inside a VM:" -ForegroundColor Yellow
    Write-Host "    winbotctl.ps1 connect <name>" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  To override (DANGEROUS â€” testing only):" -ForegroundColor Yellow
    Write-Host "    Set WINBOT_SKIP_VM_GUARDRAIL=1 and run again." -ForegroundColor Yellow
    Write-Host "  Run PowerShell as Administrator to use this script." -ForegroundColor Yellow
    Write-Host "========================================`n" -ForegroundColor Red
    exit 1
}
if ($skipCheck) {
    Write-Host "[WinBot] WARNING: VM guardrail overridden via WINBOT_SKIP_VM_GUARDRAIL" -ForegroundColor Yellow
}
# === End Guardrail ===

Write-Host "[WinBot] Installing WinSpy++..." -ForegroundColor Cyan

$installDir = "C:\WinBot\tools\WinSpy"
$exePath = "$installDir\WinSpy.exe"

# Check if already installed
if (Test-Path $exePath) {
    Write-Host "[WinBot] WinSpy already installed at: $exePath" -ForegroundColor Green
    exit 0
}

# Create tools directory
if (-not (Test-Path $installDir)) {
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
}

# Download WinSpy++ (portable â€” no installer needed)
# Using a well-known mirror of the WinSpy++ tool
$url = "https://www.nirsoft.net/utils/windowspy.zip"
$zipPath = "$env:TEMP\windowspy.zip"

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $url -OutFile $zipPath -ErrorAction Stop

    # Extract
    Expand-Archive -Path $zipPath -DestinationPath $installDir -Force
    Remove-Item $zipPath -Force

    Write-Host "[WinBot] WinSpy installed to: $installDir" -ForegroundColor Green
} catch {
    Write-Host "[WinBot] WARNING: Could not download WinSpy++ ($_). Continuing without it." -ForegroundColor Yellow
    Write-Host "[WinBot] Window inspection can still be done via PowerShell/Get-Process" -ForegroundColor Yellow
}

# Alternative: Create a simple PowerShell-based window lister
$windowListerPath = "$installDir\Get-Windows.ps1"
@'
# WinBot Window Lister â€” PowerShell-based window enumeration
# Replaces some WinSpy functionality via .NET P/Invoke

Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public class Win32Window {
    [DllImport("user32.dll")]
    public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);
    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll")]
    public static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);

    [DllImport("user32.dll")]
    public static extern int GetWindowTextLength(IntPtr hWnd);

    [DllImport("user32.dll")]
    public static extern bool IsWindowVisible(IntPtr hWnd);

    [DllImport("user32.dll")]
    public static extern bool GetWindowRect(IntPtr hWnd, out RECT rect);

    [StructLayout(LayoutKind.Sequential)]
    public struct RECT {
        public int Left, Top, Right, Bottom;
        public int Width => Right - Left;
        public int Height => Bottom - Top;
    }
}
"@

$windows = @()
$callback = {
    param([IntPtr]$hwnd, [IntPtr]$lParam)
    if ([Win32Window]::IsWindowVisible($hwnd)) {
        $length = [Win32Window]::GetWindowTextLength($hwnd)
        if ($length -gt 0) {
            $sb = New-Object System.Text.StringBuilder($length + 1)
            [Win32Window]::GetWindowText($hwnd, $sb, $sb.Capacity) | Out-Null
            $rect = New-Object Win32Window+RECT
            [Win32Window]::GetWindowRect($hwnd, [ref]$rect) | Out-Null
            $script:windows += [PSCustomObject]@{
                Handle = $hwnd.ToString("X8")
                Title = $sb.ToString()
                Left = $rect.Left
                Top = $rect.Top
                Width = $rect.Width
                Height = $rect.Height
            }
        }
    }
    return $true
}

$delegate = [Win32Window+EnumWindowsProc]$callback
[Win32Window]::EnumWindows($delegate, [IntPtr]::Zero) | Out-Null
$windows | Format-Table Handle, Title, Left, Top, Width, Height -AutoSize
$windows | ConvertTo-Json -Depth 2
'@ | Out-File -FilePath $windowListerPath -Encoding utf8

Write-Host "[WinBot] PowerShell window lister created at: $windowListerPath" -ForegroundColor Green
