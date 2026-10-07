#requires -Version 7.0
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$artifactRoot = Join-Path $env:GITHUB_WORKSPACE 'artifacts\hyperv-guest-ubuntu2404'
New-Item -ItemType Directory -Force -Path $artifactRoot | Out-Null

$runId = if ($env:GITHUB_RUN_ID) { $env:GITHUB_RUN_ID } else { [guid]::NewGuid().ToString('N').Substring(0,8) }
$suffix = if ($runId.Length -gt 8) { $runId.Substring($runId.Length - 8) } else { $runId }
$vmName = "HvG-Ub2404-$suffix"
$netName = "HvG-$suffix"
$prefix = '172.29.240.0/24'
$hostIp = '172.29.240.1'
$guestIp = '172.29.240.10'
$release = '20260814'
$imageName = 'ubuntu-24.04-server-cloudimg-amd64.img'
$baseUrl = "https://cloud-images.ubuntu.com/releases/noble/release-$release"
$imageUrl = "$baseUrl/$imageName"
$sumsUrl = "$baseUrl/SHA256SUMS"

$workRoot = Join-Path $env:RUNNER_TEMP "hyperv-guest-$suffix"
$imagePath = Join-Path $workRoot $imageName
$osDisk = Join-Path $workRoot 'ubuntu-24.04.vhdx'
$seedDisk = Join-Path $workRoot 'cidata.vhdx'
$keyPath = Join-Path $workRoot 'id_ed25519'
$beforePng = Join-Path $artifactRoot 'gui-before.png'
$afterPng = Join-Path $artifactRoot 'gui-after.png'
$receiptPath = Join-Path $artifactRoot 'receipt.json'
New-Item -ItemType Directory -Force -Path $workRoot | Out-Null

$receipt = [ordered]@{
  schema = 'hyperv-guest-qualification/v1'
  authority = 'mark-e-deyoung/WinBot#103'
  evidenceAuthority = 'SemperSupra/agent-dispatch-private#509'
  candidate = 'ubuntu-24.04-lts'
  source = [ordered]@{
    url = $imageUrl
    release = $release
    file = $imageName
    sha256 = $null
    bytes = $null
  }
  host = [ordered]@{
    image = $env:ImageOS
    imageVersion = $env:ImageVersion
    runner = $env:RUNNER_NAME
    hyperv = $null
    freeBytesBefore = $null
  }
  hyperv = [ordered]@{
    generation = 2
    secureBoot = $true
    secureBootTemplate = 'MicrosoftUEFICertificateAuthority'
    cpus = 2
    memoryMB = 4096
    disk = 'dynamic-vhdx-from-canonical-qcow2'
    network = $netName
    prefix = $prefix
  }
  gates = [ordered]@{
    sourceHash = $false
    vmBoot = $false
    ssh = $false
    outbound = $false
    hypervDrivers = $false
    integrationDaemons = $false
    xrdp = $false
    vncRender = $false
    vncInput = $false
    reboot = $false
    sshAfterReboot = $false
    xrdpAfterReboot = $false
    productionCheckpoint = $false
    cleanup = $false
  }
  observations = [ordered]@{}
  status = 'FAIL'
  productionAdmission = $false
  error = $null
}

function Test-TcpPort {
  param([string]$HostName,[int]$Port,[int]$TimeoutMs=1000)
  $client = [System.Net.Sockets.TcpClient]::new()
  try {
    $task = $client.ConnectAsync($HostName,$Port)
    if (-not $task.Wait($TimeoutMs)) { return $false }
    return $client.Connected
  } catch { return $false } finally { $client.Dispose() }
}

function Wait-TcpPort {
  param([string]$HostName,[int]$Port,[int]$TimeoutSeconds=420)
  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  do {
    if (Test-TcpPort -HostName $HostName -Port $Port -TimeoutMs 1500) { return $true }
    Start-Sleep -Seconds 5
  } while ((Get-Date) -lt $deadline)
  return $false
}

function Get-SshExe {
  $cmd = Get-Command ssh.exe -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  $candidate = "$env:WINDIR\System32\OpenSSH\ssh.exe"
  if (Test-Path $candidate) { return $candidate }
  throw 'ssh.exe not found'
}

$sshExe = $null
$sshArgs = @()
function Invoke-Guest {
  param([Parameter(Mandatory)][string]$Command,[switch]$AllowFailure)
  $all = @($sshArgs + @("gh@$guestIp",$Command))
  $out = & $sshExe @all 2>&1
  $code = $LASTEXITCODE
  $resultText = ($out | Out-String).Trim()
  if (($code -ne 0) -and -not $AllowFailure) {
    throw ("guest command failed ({0}): {1}{2}{3}" -f $code,$Command,[Environment]::NewLine,$resultText)
  }
  return $resultText
}

$failure = $null
try {
  Import-Module Hyper-V -ErrorAction Stop
  $receipt.host.hyperv = (Get-VMHost | Select-Object -Property ComputerName,VirtualHardDiskPath,VirtualMachinePath)
  $receipt.host.freeBytesBefore = (Get-PSDrive -Name C).Free

  $conflicts = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -eq $hostIp }
  if ($conflicts) { throw "network prefix conflict: $hostIp already present" }

  New-VMSwitch -Name $netName -SwitchType Internal | Out-Null
  $ifIndex = (Get-NetAdapter -Name "vEthernet ($netName)").ifIndex
  New-NetIPAddress -InterfaceIndex $ifIndex -IPAddress $hostIp -PrefixLength 24 | Out-Null
  New-NetNat -Name $netName -InternalIPInterfaceAddressPrefix $prefix | Out-Null

  & curl.exe -L --fail --retry 3 --retry-delay 3 -o (Join-Path $workRoot 'SHA256SUMS') $sumsUrl
  if ($LASTEXITCODE -ne 0) { throw 'failed to download SHA256SUMS' }
  $sumLine = Get-Content (Join-Path $workRoot 'SHA256SUMS') | Where-Object { $_ -match [regex]::Escape($imageName) } | Select-Object -First 1
  if (-not $sumLine) { throw "checksum entry missing for $imageName" }
  $expectedSha = ($sumLine -split '\s+')[0].ToLowerInvariant()
  & curl.exe -L --fail --retry 3 --retry-delay 3 -o $imagePath $imageUrl
  if ($LASTEXITCODE -ne 0) { throw 'failed to download Canonical cloud image' }
  $actualSha = (Get-FileHash -Algorithm SHA256 $imagePath).Hash.ToLowerInvariant()
  $receipt.source.sha256 = $actualSha
  $receipt.source.bytes = (Get-Item $imagePath).Length
  if ($actualSha -ne $expectedSha) { throw "source SHA256 mismatch expected=$expectedSha actual=$actualSha" }
  $receipt.gates.sourceHash = $true

  $qemu = Get-Command qemu-img.exe -ErrorAction SilentlyContinue
  if ($qemu) {
    $qemuPath = $qemu.Source
  } else {
    & choco.exe install qemu -y --no-progress
    if ($LASTEXITCODE -ne 0) { throw 'qemu installation failed' }
    $candidate = 'C:\Program Files\qemu\qemu-img.exe'
    if (Test-Path $candidate) { $qemuPath = $candidate } else { $qemuPath = (Get-Command qemu-img.exe -ErrorAction Stop).Source }
  }
  # qemu-img on Windows can mark VHDX output with the NTFS sparse attribute; Hyper-V
  # refuses such a backing file with 0xC03A001A. Disable sparse conversion and
  # explicitly clear/verify the NTFS sparse flag before attaching the disk.
  & $qemuPath convert -p -S 0 -f qcow2 -O vhdx -o subformat=dynamic $imagePath $osDisk
  if ($LASTEXITCODE -ne 0 -or -not (Test-Path $osDisk)) { throw 'qemu-img conversion to VHDX failed' }
  $sparseFlag = [System.IO.FileAttributes]::SparseFile
  if (((Get-Item -LiteralPath $osDisk -Force).Attributes -band $sparseFlag) -ne 0) {
    & fsutil.exe sparse setflag $osDisk 0 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'failed to clear NTFS sparse flag from converted VHDX' }
  }
  if (((Get-Item -LiteralPath $osDisk -Force).Attributes -band $sparseFlag) -ne 0) {
    throw 'converted VHDX remains NTFS sparse after explicit de-sparsification'
  }
  # Cloud images are intentionally small. Give the guest enough virtual capacity
  # for a real desktop/tooling workload; Ubuntu cloud-init grows the root FS at first boot.
  Resize-VHD -Path $osDisk -SizeBytes 16GB
  if (((Get-Item -LiteralPath $osDisk -Force).Attributes -band $sparseFlag) -ne 0) {
    throw 'VHDX became NTFS sparse after Resize-VHD'
  }
  $vhdInfo = Get-VHD -Path $osDisk
  $receipt.observations.vhdx = [ordered]@{
    bytes = (Get-Item -LiteralPath $osDisk).Length
    virtualBytes = $vhdInfo.Size
    sparse = $false
  }
  Remove-Item -Force $imagePath

  $sshKeygen = (Get-Command ssh-keygen.exe -ErrorAction Stop).Source
  & $sshKeygen -q -t ed25519 -N "" -f $keyPath
  if ($LASTEXITCODE -ne 0) { throw 'ssh-keygen failed' }
  $pubKey = (Get-Content "$keyPath.pub" -Raw).Trim()
  & icacls.exe $keyPath /inheritance:r | Out-Null
  & icacls.exe $keyPath /grant:r "$($env:USERNAME):(R)" | Out-Null
  $sshExe = Get-SshExe
  $sshArgs = @('-i',$keyPath,'-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile=NUL','-o','ConnectTimeout=10')

  New-VHD -Path $seedDisk -Dynamic -SizeBytes 128MB | Out-Null
  $disk = Mount-VHD -Path $seedDisk -Passthru | Get-Disk
  Initialize-Disk -Number $disk.Number -PartitionStyle GPT -PassThru | Out-Null
  $part = New-Partition -DiskNumber $disk.Number -UseMaximumSize -AssignDriveLetter
  Format-Volume -Partition $part -FileSystem FAT32 -NewFileSystemLabel 'CIDATA' -Confirm:$false | Out-Null
  $drive = "$($part.DriveLetter):"

  $userData = @"
#cloud-config
hostname: ubuntu-hv
manage_etc_hosts: true
users:
  - default
  - name: gh
    gecos: Hyper-V qualification
    groups: [adm, sudo]
    sudo: ["ALL=(ALL) NOPASSWD:ALL"]
    shell: /bin/bash
    ssh_authorized_keys:
      - $pubKey
ssh_pwauth: false
package_update: true
packages:
  - openssh-server
runcmd:
  - systemctl enable --now ssh
final_message: "hyperv qualification cloud-init complete"
"@
  $metaData = @"
instance-id: hv-$suffix
local-hostname: ubuntu-hv
"@
  $networkConfig = @"
version: 2
ethernets:
  eth0:
    match:
      driver: hv_netvsc
    set-name: eth0
    dhcp4: false
    addresses:
      - $guestIp/24
    routes:
      - to: default
        via: $hostIp
    nameservers:
      addresses: [1.1.1.1, 8.8.8.8]
"@
  Set-Content -NoNewline -Encoding utf8 -Path (Join-Path $drive 'user-data') -Value $userData
  Set-Content -NoNewline -Encoding utf8 -Path (Join-Path $drive 'meta-data') -Value $metaData
  Set-Content -NoNewline -Encoding utf8 -Path (Join-Path $drive 'network-config') -Value $networkConfig
  Dismount-VHD -Path $seedDisk

  New-VM -Name $vmName -Generation 2 -MemoryStartupBytes 4GB -VHDPath $osDisk -SwitchName $netName | Out-Null
  Set-VM -Name $vmName -AutomaticCheckpointsEnabled $false
  Set-VMProcessor -VMName $vmName -Count 2
  Set-VMFirmware -VMName $vmName -EnableSecureBoot On -SecureBootTemplate MicrosoftUEFICertificateAuthority
  Add-VMHardDiskDrive -VMName $vmName -Path $seedDisk -ControllerType SCSI -ControllerNumber 0 -ControllerLocation 1
  $bootDisk = Get-VMHardDiskDrive -VMName $vmName | Where-Object Path -eq $osDisk
  Set-VMFirmware -VMName $vmName -FirstBootDevice $bootDisk
  Start-VM -Name $vmName | Out-Null

  $deadline = (Get-Date).AddMinutes(7)
  do {
    $heartbeat = Get-VMIntegrationService -VMName $vmName -Name Heartbeat -ErrorAction SilentlyContinue
    if ($heartbeat -and $heartbeat.PrimaryStatusDescription -eq 'OK') { $receipt.gates.vmBoot = $true; break }
    Start-Sleep -Seconds 5
  } while ((Get-Date) -lt $deadline)

  if (-not (Wait-TcpPort -HostName $guestIp -Port 22 -TimeoutSeconds 420)) {
    $receipt.observations.vmState = (Get-VM -Name $vmName | Select-Object State,Status,Uptime)
    $receipt.observations.integrationAtFailure = @(Get-VMIntegrationService -VMName $vmName | Select-Object Name,Enabled,PrimaryStatusDescription,SecondaryStatusDescription)
    throw 'guest SSH did not become reachable'
  }
  $receipt.gates.ssh = $true

  $first = Invoke-Guest 'cloud-init status --wait; printf "OS="; . /etc/os-release; echo "$PRETTY_NAME"; uname -r; lsblk -o NAME,SIZE,FSTYPE,MOUNTPOINTS; df -h /; ip -brief address; ip route; systemctl is-active ssh'
  $receipt.observations.firstBoot = $first
  $outbound = Invoke-Guest "getent hosts archive.ubuntu.com >/dev/null && curl -fsS --max-time 20 https://archive.ubuntu.com/ >/dev/null && echo outbound-ok"
  if ($outbound -match 'outbound-ok') { $receipt.gates.outbound = $true }

  $guestSetup = @'
set -euxo pipefail
export DEBIAN_FRONTEND=noninteractive
avail_kb=$(df --output=avail -k / | tail -1 | tr -d ' ')
if [ "$avail_kb" -lt 6000000 ]; then
  echo "root filesystem did not grow to production minimum: available_kb=$avail_kb" >&2
  exit 41
fi
sudo apt-get update
sudo apt-get install -y linux-cloud-tools-virtual xfce4 xfce4-terminal xterm xrdp tigervnc-standalone-server dbus-x11
printf '%s\n' 'startxfce4' > "$HOME/.xsession"
chmod 700 "$HOME/.xsession"
sudo adduser xrdp ssl-cert || true
sudo systemctl enable --now xrdp
sudo systemctl enable --now hv-kvp-daemon.service || true
sudo systemctl enable --now hv-vss-daemon.service || true
sudo systemctl enable --now hv-fcopy-daemon.service || true
pkill -u "$USER" Xtigervnc || true
nohup Xtigervnc :1 -geometry 1024x768 -depth 24 -rfbport 5901 -SecurityTypes None -localhost no >"$HOME/vnc.log" 2>&1 &
sleep 3
DISPLAY=:1 nohup dbus-launch --exit-with-session startxfce4 >"$HOME/xfce.log" 2>&1 &
sleep 8
systemctl is-active xrdp
ss -ltn | egrep ':(22|3389|5901)\b'
'@
  # PowerShell source is checked out with CRLF on Windows; normalize before
  # transporting the shell payload or bash sees option names with a trailing CR.
  $guestSetupLf = $guestSetup.Replace("`r`n","`n")
  $guestSetupB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($guestSetupLf))
  $setupOut = Invoke-Guest "echo $guestSetupB64 | base64 -d | bash"
  $receipt.observations.desktopSetup = $setupOut

  $drivers = Invoke-Guest "lsmod | egrep '(^| )(hv_vmbus|hv_storvsc|hv_netvsc|hv_utils|hyperv_fb|hyperv_keyboard)( |$)' || true"
  $receipt.observations.hypervDrivers = $drivers
  if ($drivers -match 'hv_vmbus' -and $drivers -match 'hv_storvsc' -and $drivers -match 'hv_netvsc') { $receipt.gates.hypervDrivers = $true }

  $daemons = Invoke-Guest 'for s in hv-kvp-daemon.service hv-vss-daemon.service hv-fcopy-daemon.service; do printf "%s=" "$s"; systemctl is-active "$s" || true; done'
  $receipt.observations.integrationDaemons = $daemons
  if ($daemons -match 'hv-kvp-daemon.service=active' -and $daemons -match 'hv-vss-daemon.service=active') { $receipt.gates.integrationDaemons = $true }

  $receipt.observations.hostIntegration = @(Get-VMIntegrationService -VMName $vmName | Select-Object Name,Enabled,PrimaryStatusDescription,SecondaryStatusDescription)

  if (Wait-TcpPort -HostName $guestIp -Port 3389 -TimeoutSeconds 60) { $receipt.gates.xrdp = $true }
  if (-not (Wait-TcpPort -HostName $guestIp -Port 5901 -TimeoutSeconds 60)) { throw 'TigerVNC did not become reachable' }

  & python.exe -m pip install --disable-pip-version-check --quiet vncdotool pillow
  if ($LASTEXITCODE -ne 0) { throw 'vncdotool install failed' }
  $guiOracle = @"
from vncdotool import api
from PIL import Image, ImageChops
import time, sys, hashlib
host = '$($guestIp)::5901'
before = r'$beforePng'
after = r'$afterPng'
with api.connect(host, password=None, timeout=30) as c:
    c.captureScreen(before)
    c.keyPress('alt-f2')
    for ch in 'xterm':
        c.keyPress(ch)
    c.keyPress('enter')
    time.sleep(5)
    c.captureScreen(after)
a = Image.open(before).convert('RGB')
b = Image.open(after).convert('RGB')
diff = ImageChops.difference(a,b)
changed = diff.getbbox() is not None
print('before_sha256=' + hashlib.sha256(open(before,'rb').read()).hexdigest())
print('after_sha256=' + hashlib.sha256(open(after,'rb').read()).hexdigest())
print('pixels_changed=' + str(changed).lower())
if not changed:
    sys.exit(3)
"@
  $guiOraclePath = Join-Path $workRoot 'gui_oracle.py'
  Set-Content -Encoding utf8 -Path $guiOraclePath -Value $guiOracle
  $guiOut = & python.exe $guiOraclePath 2>&1
  if ($LASTEXITCODE -ne 0) { throw "GUI interaction oracle failed: $($guiOut | Out-String)" }
  $receipt.observations.guiOracle = ($guiOut | Out-String).Trim()
  $receipt.gates.vncRender = (Test-Path $beforePng) -and ((Get-Item $beforePng).Length -gt 1000)
  $receipt.gates.vncInput = ($guiOut | Out-String) -match 'pixels_changed=true'

  $bootId1 = (Invoke-Guest "cat /proc/sys/kernel/random/boot_id").Trim()
  Invoke-Guest "sudo reboot" -AllowFailure | Out-Null
  Start-Sleep -Seconds 10
  $downObserved = -not (Test-TcpPort -HostName $guestIp -Port 22 -TimeoutMs 1000)
  if (-not (Wait-TcpPort -HostName $guestIp -Port 22 -TimeoutSeconds 420)) { throw 'SSH did not recover after reboot' }
  $bootId2 = (Invoke-Guest "cat /proc/sys/kernel/random/boot_id").Trim()
  if ($bootId1 -ne $bootId2) { $receipt.gates.reboot = $true }
  $receipt.gates.sshAfterReboot = $true
  if (Wait-TcpPort -HostName $guestIp -Port 3389 -TimeoutSeconds 90) { $receipt.gates.xrdpAfterReboot = $true }
  $receipt.observations.reboot = [ordered]@{ before=$bootId1; after=$bootId2; sshDownObserved=$downObserved }

  try {
    Invoke-Guest "echo baseline | sudo tee /var/tmp/hv-qualification-baseline >/dev/null; sudo rm -f /var/tmp/hv-qualification-mutation"
    Set-VM -Name $vmName -CheckpointType ProductionOnly
    Checkpoint-VM -VMName $vmName -SnapshotName 'production-oracle' | Out-Null
    Invoke-Guest "echo mutation | sudo tee /var/tmp/hv-qualification-mutation >/dev/null"
    Restore-VMSnapshot -VMName $vmName -Name 'production-oracle' -Confirm:$false
    if ((Get-VM -Name $vmName).State -eq 'Off') { Start-VM -Name $vmName | Out-Null }
    if (-not (Wait-TcpPort -HostName $guestIp -Port 22 -TimeoutSeconds 420)) { throw 'SSH did not recover after checkpoint restore' }
    $cp = Invoke-Guest "test -f /var/tmp/hv-qualification-baseline && test ! -e /var/tmp/hv-qualification-mutation && echo checkpoint-ok"
    if ($cp -match 'checkpoint-ok') { $receipt.gates.productionCheckpoint = $true }
    Remove-VMSnapshot -VMName $vmName -Name 'production-oracle' -Confirm:$false
  } catch {
    $receipt.observations.productionCheckpointError = $_.Exception.Message
    Get-VMSnapshot -VMName $vmName -ErrorAction SilentlyContinue | Remove-VMSnapshot -Confirm:$false -ErrorAction SilentlyContinue
  }

  $requiredCore = @('sourceHash','vmBoot','ssh','outbound','hypervDrivers','xrdp','vncRender','vncInput','reboot','sshAfterReboot','xrdpAfterReboot')
  $corePass = $true
  foreach ($g in $requiredCore) { if (-not $receipt.gates[$g]) { $corePass = $false } }
  if (-not $corePass) { throw 'one or more core qualification gates failed' }

  $receipt.status = 'PASS'
  $receipt.productionAdmission = [bool]($receipt.gates.integrationDaemons -and $receipt.gates.productionCheckpoint)
}
catch {
  $failure = $_
  $receipt.error = $_.Exception.Message
}
finally {
  try {
    if (Get-VM -Name $vmName -ErrorAction SilentlyContinue) {
      Stop-VM -Name $vmName -TurnOff -Force -ErrorAction SilentlyContinue
      Remove-VM -Name $vmName -Force -ErrorAction SilentlyContinue
    }
    if (Get-NetNat -Name $netName -ErrorAction SilentlyContinue) { Remove-NetNat -Name $netName -Confirm:$false -ErrorAction SilentlyContinue }
    if (Get-VMSwitch -Name $netName -ErrorAction SilentlyContinue) { Remove-VMSwitch -Name $netName -Force -ErrorAction SilentlyContinue }
    $receipt.gates.cleanup = -not (Get-VM -Name $vmName -ErrorAction SilentlyContinue) -and -not (Get-NetNat -Name $netName -ErrorAction SilentlyContinue) -and -not (Get-VMSwitch -Name $netName -ErrorAction SilentlyContinue)
  } catch {
    $receipt.observations.cleanupError = $_.Exception.Message
  }

  if (-not $receipt.gates.cleanup) {
    if ($receipt.status -eq 'PASS') { $receipt.status = 'FAIL' }
    if (-not $receipt.error) { $receipt.error = 'cleanup oracle failed' }
  }

  $receipt.observations.freeBytesAfter = (Get-PSDrive -Name C).Free
  $receipt | ConvertTo-Json -Depth 12 | Set-Content -Encoding utf8 -Path $receiptPath
  Get-Content $receiptPath
  Remove-Item -Recurse -Force $workRoot -ErrorAction SilentlyContinue
}

if ($failure -or $receipt.status -ne 'PASS') { exit 1 }
exit 0

# launch-stamp: 2026-10-07T16:00Z

# launch-stamp: corrected-harness-rep

# launch-stamp: nonsparse-vhdx-rep

# launch-stamp: lf-normalized-guest-setup

# launch-stamp: expanded-guest-disk-rep
