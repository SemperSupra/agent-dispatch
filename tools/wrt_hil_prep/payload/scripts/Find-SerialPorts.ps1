$ports = Get-CimInstance Win32_SerialPort | Select-Object DeviceID,Name,Description,PNPDeviceID
if (-not $ports) {
    Write-Host "No COM serial devices detected."
    exit 1
}
$ports | Format-Table -AutoSize
Write-Host ""
Write-Host "WRT3200ACM: 115200 8N1, 3.3V TTL, GND/RX/TX only; do not connect VCC."
