# WinBot: Create VM on Target Hypervisor
# Reads vm-templates.json to create a correctly-shaped VM for PXE boot.
# Supports Proxmox VE, TrueNAS SCALE, VMware ESXi, VirtualBox, Hyper-V.
#
# Usage:
#   .\create-vm.ps1 -Hypervisor proxmox -Name "winbot-01" -PxeServerIP 192.168.1.10 -TargetHost 192.168.1.100
#   .\create-vm.ps1 -Hypervisor vbox -Name "winbot-test" -PxeServerIP 192.168.1.10
#   .\create-vm.ps1 -Hypervisor esxi -Name "winbot-02" -PxeServerIP 192.168.1.10 -TargetHost esxi.local -Credential $cred
#   .\create-vm.ps1 -Hypervisor proxmox -Name "winbot-03" -PxeServerIP 192.168.1.10 -WhatIf

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("proxmox","truenas","esxi","vbox","hyperv")]
    [string]$Hypervisor,

    [Parameter(Mandatory=$true)]
    [string]$Name,

    [Parameter(Mandatory=$true)]
    [string]$PxeServerIP,

    [string]$TargetHost = "",

    [PSCredential]$Credential = $null,

    [string]$TemplatePath = "",

    [string]$StoragePool = "",
    [string]$NetworkBridge = "",
    [int]$MemoryMB = 0,
    [int]$Cpus = 0,
    [int]$DiskSizeGB = 0,
    [string]$PxeHttpPort = "8080",

    [switch]$SkipStart,
    [switch]$WhatIf
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectDir = Split-Path -Parent $scriptDir

function Write-Step($msg) { Write-Host $msg -ForegroundColor Cyan }
function Write-OK($msg) { Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "  [WARN] $msg" -ForegroundColor Yellow }
function Write-Info($msg) { Write-Host "  [INFO] $msg" -ForegroundColor Gray }

# ============================================================
# 1. Load and validate template
# ============================================================
Write-Step "[1/4] Loading VM template..."

if (-not $TemplatePath) {
    $TemplatePath = Join-Path $scriptDir "vm-templates.json"
}
if (-not (Test-Path $TemplatePath)) {
    throw "Template file not found: $TemplatePath"
}

$templates = Get-Content $TemplatePath -Raw | ConvertFrom-Json
$template = $templates.templates.$Hypervisor
if (-not $template) {
    throw "No template found for hypervisor: $Hypervisor. Available: $($templates.templates.PSObject.Properties.Name -join ', ')"
}
Write-OK "Loaded template: $($template.label)"

# Apply CLI overrides
if ($MemoryMB -gt 0) { $template.memoryMB = $MemoryMB }
if ($Cpus -gt 0) { $template.cpus = $Cpus }
if ($DiskSizeGB -gt 0) { $template.diskSizeGB = $DiskSizeGB }
if ($NetworkBridge) { $template.networkBridge = $NetworkBridge }

Write-Info "Shape: $($template.cpus) vCPU, $($template.memoryMB) MB, $($template.diskSizeGB) GB disk"
Write-Info "NIC: $($template.nicType), Disk: $($template.diskController), Firmware: $($template.firmware)"
Write-Info "Boot order: $($template.bootOrder -join ' -> ')"
Write-Info "PXE server: ${PxeServerIP}:$PxeHttpPort"

# ============================================================
# 2. SSH helper for remote hypervisors
# ============================================================
function Invoke-SshCommand {
    param([string]$Hostname, [string]$Command, [int]$TimeoutSeconds = 60)

    $sshArgs = @("-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10", "-o", "BatchMode=no")

    if ($Credential) {
        $user = $Credential.UserName
        $pass = $Credential.GetNetworkCredential().Password
        # Use sshpass if available, otherwise fall back to interactive
        $sshpass = Get-Command sshpass -ErrorAction SilentlyContinue
        if ($sshpass) {
            $result = & sshpass -p $pass ssh @sshArgs "${user}@${Hostname}" $Command 2>&1
        } else {
            # Use SSH with password via SSH_ASKPASS or plink
            $plink = Get-Command plink -ErrorAction SilentlyContinue
            if ($plink) {
                $result = echo y | & plink -pw $pass -ssh "${user}@${Hostname}" $Command 2>&1
            } else {
                Write-Warn "sshpass/plink not found -- SSH may prompt for password"
                $result = ssh @sshArgs "${user}@${Hostname}" $Command 2>&1
            }
        }
    } else {
        $result = ssh @sshArgs "root@${Hostname}" $Command 2>&1
    }

    if ($LASTEXITCODE -ne 0) {
        $errMsg = ($result | Out-String).Trim()
        if ($errMsg.Length -gt 200) { $errMsg = $errMsg.Substring(0, 200) + "..." }
        Write-Warn "SSH exit code ${LASTEXITCODE}: $errMsg"
    }
    return $result
}

# ============================================================
# 3. Create VM on target hypervisor
# ============================================================
Write-Step "[2/4] Creating VM on $Hypervisor..."

switch ($Hypervisor) {

    "proxmox" {
        if (-not $TargetHost) { throw "TargetHost is required for Proxmox (e.g. -TargetHost 192.168.1.100)" }
        if (-not $Credential) { Write-Warn "No credential provided -- using root@$TargetHost with SSH key" }

        $pool = if ($StoragePool) { $StoragePool } else { $template.platform.proxmox.storagePool }
        $bridge = if ($NetworkBridge) { $NetworkBridge } else { $template.platform.proxmox.bridge }
        $memsize = [Math]::Floor($template.memoryMB / 1024 * 100) / 100  # MB to GB with 2 decimals
        $disksize = "$($template.diskSizeGB)G"
        $machine = $template.platform.proxmox.machine
        $ostype = $template.platform.proxmox.ostype
        $qemuArgs = $template.platform.proxmox.qemuArgs

        # Find next available VMID
        $existingIds = Invoke-SshCommand -Hostname $TargetHost -Command "qm list 2>/dev/null | tail -n+2 | awk '{print \$1}'"
        $nextId = 100
        foreach ($line in $existingIds) {
            $id = [int]($line.Trim())
            if ($id -ge $nextId) { $nextId = $id + 1 }
        }

        Write-Info "VMID: $nextId, Pool: $pool, Bridge: $bridge"

        $createCmd = "qm create $nextId --name '$Name' --memory $($template.memoryMB) --cores $($template.cpus) --net0 $($template.nicType),bridge=$bridge --scsihw virtio-scsi-pci --scsi0 ${pool}:$disksize --bios ovmf --efidisk0 ${pool}:1,format=raw --machine $machine --boot order=scsi0;net0 --ostype $ostype --agent 1 --args '$qemuArgs'"

        if ($WhatIf) {
            Write-Info "[WhatIf] Would run: ssh root@$TargetHost $createCmd"
        } else {
            $result = Invoke-SshCommand -Hostname $TargetHost -Command $createCmd
            Write-OK "VM created (VMID: $nextId)"

            if (-not $SkipStart) {
                Write-Info "Starting VM..."
                Invoke-SshCommand -Hostname $TargetHost -Command "qm start $nextId" | Out-Null
                Write-OK "VM started -- PXE boot should begin"
            }
        }
        return @{ Hypervisor = "proxmox"; VMID = $nextId; Name = $Name; Host = $TargetHost }
    }

    "truenas" {
        if (-not $TargetHost) { throw "TargetHost is required for TrueNAS (e.g. -TargetHost 192.168.1.100)" }
        if (-not $Credential) { Write-Warn "No credential provided -- using root@$TargetHost with SSH key" }

        $pool = if ($StoragePool) { $StoragePool } else { $template.platform.truenas.pool }
        $bridge = if ($NetworkBridge) { $NetworkBridge } else { $template.platform.truenas.bridge }
        $zvolSize = $template.diskSizeGB * 1024 * 1024 * 1024
        $zvolName = "$Name-boot"
        $blocksize = $template.platform.truenas.zvolBlocksize

        # Build midclt JSON payload
        $vmPayload = @{
            name = $Name
            vcpus = $template.cpus
            memory = $template.memoryMB
            bootloader = "UEFI"
            devices = @(
                @{ dtype = "DISK"; attributes = @{ create_zvol = $true; zvol_name = $zvolName; zvol_volsize = $zvolSize; zvol_blocksize = $blocksize } },
                @{ dtype = "NIC"; attributes = @{ type = "VIRTIO"; nic_attach = $bridge } }
            )
        } | ConvertTo-Json -Depth 6 -Compress

        # Escape for shell
        $escapedPayload = $vmPayload -replace "'", "'\''"

        if ($WhatIf) {
            Write-Info "[WhatIf] Would create VM via midclt on $TargetHost"
            Write-Info "[WhatIf] Payload: $vmPayload"
        } else {
            $result = Invoke-SshCommand -Hostname $TargetHost -Command "midclt call vm.create '$escapedPayload'"
            Write-OK "VM '$Name' created on TrueNAS"

            if (-not $SkipStart) {
                $vmId = ($result | Select-String '\d+').Matches.Value | Select-Object -First 1
                if ($vmId) {
                    Invoke-SshCommand -Hostname $TargetHost -Command "midclt call vm.start $vmId" | Out-Null
                    Write-OK "VM started (ID: $vmId)"
                }
            }
        }
        return @{ Hypervisor = "truenas"; Name = $Name; Host = $TargetHost }
    }

    "esxi" {
        if (-not $TargetHost) { throw "TargetHost is required for ESXi (e.g. -TargetHost 192.168.1.100)" }
        if (-not $Credential) { Write-Warn "No credential provided -- using root@$TargetHost with SSH key" }

        $ds = if ($StoragePool) { $StoragePool } else { $template.platform.esxi.datastore }
        $bridge = if ($NetworkBridge) { $NetworkBridge } else { $template.networkBridge }

        if ($WhatIf) {
            Write-Info "[WhatIf] Would create VM on ESXi host $TargetHost (datastore: $ds)"
        } else {
            # Create VM directory and base VMX
            $vmDir = "/vmfs/volumes/$ds/$Name"
            $createVmCmd = "mkdir -p '$vmDir' && vim-cmd vmsvc/createdummyvm '$Name' '[$ds] $Name/$Name.vmx' 2>&1"
            $result = Invoke-SshCommand -Hostname $TargetHost -Command $createVmCmd
            Write-Info "vim-cmd result: $($result -join ' ')"

            # Get VMID
            $vmidResult = Invoke-SshCommand -Hostname $TargetHost -Command "vim-cmd vmsvc/getallvms 2>/dev/null | grep '$Name' | awk '{print \$1}'"
            $vmid = $vmidResult.Trim()
            if (-not $vmid) { throw "Could not determine VMID after creation" }
            Write-Info "VMID: $vmid"

            # Configure VM settings via vim-cmd
            $setCmds = @(
                "vim-cmd vmsvc/setsimplecfg $vmid memSize $($template.memoryMB)",
                "vim-cmd vmsvc/setsimplecfg $vmid numvcpus $($template.cpus)"
            )
            foreach ($cmd in $setCmds) {
                Invoke-SshCommand -Hostname $TargetHost -Command $cmd | Out-Null
            }

            # Write VMX settings for NIC, disk controller, firmware
            $vmxFile = "$vmDir/$Name.vmx"
            $vmxLines = @(
                'ethernet0.virtualDev = "vmxnet3"',
                'ethernet0.networkName = "' + $bridge + '"',
                'scsi0.virtualDev = "pvscsi"',
                'firmware = "efi"',
                'guestOS = "windows9_64Guest"',
                'bootOptions.secureBoot.enabled = "FALSE"'
            )
            $vmxLineStr = ($vmxLines | ForEach-Object { "echo '$_' >> $vmxFile" }) -join "; "
            Invoke-SshCommand -Hostname $TargetHost -Command $vmxLineStr | Out-Null

            # Create virtual disk
            $vmdkPath = "$vmDir/$Name.vmdk"
            $diskCmd = "vmkfstools -c $($template.diskSizeGB)G -d thin '$vmdkPath' 2>&1"
            $diskResult = Invoke-SshCommand -Hostname $TargetHost -Command $diskCmd
            Write-Info "Disk: $($diskResult -join ' ')"

            # Attach disk
            Invoke-SshCommand -Hostname $TargetHost -Command "echo 'scsi0:0.fileName = \"$Name.vmdk\"' >> $vmxFile" | Out-Null

            Write-OK "VM '$Name' created on ESXi (VMID: $vmid)"

            if (-not $SkipStart) {
                Invoke-SshCommand -Hostname $TargetHost -Command "vim-cmd vmsvc/power.on $vmid 2>&1" | Out-Null
                Write-OK "VM started -- PXE boot should begin"
            }
        }
        return @{ Hypervisor = "esxi"; Name = $Name; Host = $TargetHost }
    }

    "vbox" {
        # Local VirtualBox
        $vboxManage = $null
        $vboxPaths = @(
            "$env:ProgramFiles\Oracle\VirtualBox\VBoxManage.exe",
            "${env:ProgramFiles(x86)}\Oracle\VirtualBox\VBoxManage.exe"
        )
        foreach ($p in $vboxPaths) {
            if (Test-Path $p) { $vboxManage = $p; break }
        }
        if (-not $vboxManage) {
            $which = (Get-Command VBoxManage -ErrorAction SilentlyContinue).Source
            if ($which) { $vboxManage = $which }
        }
        if (-not $vboxManage) { throw "VBoxManage.exe not found. Install VirtualBox or add to PATH." }
        Write-Info "VBoxManage: $vboxManage"

        $ostype = $template.platform.vbox.ostype
        $chipset = $template.platform.vbox.chipset

        if ($WhatIf) {
            Write-Info "[WhatIf] Would run: VBoxManage createvm --name '$Name' --ostype $ostype --register"
        } else {
            # Create VM
            $result = & $vboxManage createvm --name $Name --ostype $ostype --register 2>&1
            if ($LASTEXITCODE -ne 0) { throw "VBoxManage createvm failed: $result" }
            Write-OK "VM registered"

            # Configure
            & $vboxManage modifyvm $Name --memory $template.memoryMB --cpus $template.cpus --firmware efi --chipset $chipset --hpet on 2>&1 | Out-Null
            Write-OK "Memory: $($template.memoryMB)MB, CPUs: $($template.cpus), EFI"

            # Create and attach disk
            $vmdir = Split-Path (& $vboxManage showvminfo $Name --machinereadable 2>&1 | Select-String "CfgFile" | ForEach-Object { $_ -replace '.*="([^"]+)".*', '$1' }) -Parent
            if (-not $vmdir) { $vmdir = "$env:USERPROFILE\VirtualBox VMs\$Name" }
            $vdiPath = Join-Path $vmdir "$Name.vdi"
            & $vboxManage createhd --filename $vdiPath --size $($template.diskSizeGB * 1024) --format VDI 2>&1 | Out-Null
            & $vboxManage storagectl $Name --name SATA --add sata --controller IntelAhci 2>&1 | Out-Null
            & $vboxManage storageattach $Name --storagectl SATA --port 0 --device 0 --type hdd --medium $vdiPath 2>&1 | Out-Null
            Write-OK "Disk: $($template.diskSizeGB)GB VDI attached (SATA AHCI)"

            # Network
            $bridge = if ($NetworkBridge) { $NetworkBridge } else { $template.networkBridge }
            & $vboxManage modifyvm $Name --nic1 bridged --bridgeadapter1 $bridge --nictype1 $template.nicType 2>&1 | Out-Null
            Write-OK "Network: bridged ($bridge), NIC type $($template.nicType)"

            # Boot order: network first
            & $vboxManage modifyvm $Name --boot1 net --boot2 disk 2>&1 | Out-Null

            # Apply extra data
            foreach ($kv in $template.platform.vbox.extraData.PSObject.Properties) {
                & $vboxManage setextradata $Name $kv.Name $kv.Value 2>&1 | Out-Null
            }

            if (-not $SkipStart) {
                & $vboxManage startvm $Name --type headless 2>&1 | Out-Null
                Write-OK "VM started (headless) -- PXE boot should begin"
            }
        }
        return @{ Hypervisor = "vbox"; Name = $Name }
    }

    "hyperv" {
        # Local Hyper-V via WinBot.psm1
        $hostModule = Join-Path $projectDir "host\WinBot.psm1"
        if (-not (Test-Path $hostModule)) { throw "WinBot module not found: $hostModule" }
        Import-Module $hostModule -Force -ErrorAction Stop

        $memoryBytes = $template.memoryMB * 1MB
        $processors = $template.cpus

        if ($WhatIf) {
            Write-Info "[WhatIf] Would run: New-WinBotClone -Name '$Name' -MemoryBytes $memoryBytes -Processors $processors"
        } else {
            $cloneResult = New-WinBotClone -Name $Name -MemoryBytes $memoryBytes -Processors $processors -StartVM:(-not $SkipStart)
            Write-OK "VM clone created: $Name"
            Write-Info "Use 'vmconnect localhost WinBot-$Name' to view console"
        }
        return @{ Hypervisor = "hyperv"; Name = $Name }
    }
}

# ============================================================
# 4. Verify and report
# ============================================================
Write-Step "[3/4] Verifying..."

if ($WhatIf) {
    Write-Info "[WhatIf] Dry run complete. No VMs were created."
} else {
    Write-OK "VM creation complete."
}

Write-Step "[4/4] Next steps"
Write-Info "1. Watch the VM console for iPXE boot menu"
Write-Info "2. Select 'WinBot Auto-Deploy' to start installation"
Write-Info "3. After deployment, the VM will reboot and provision itself"
Write-Info "4. Check API health: Invoke-RestMethod http://<VM-IP>:8000/health"
Write-Info "5. Enroll node: the provision script auto-registers with the host"
Write-Host ""

Write-Host "========================================" -ForegroundColor Green
Write-Host "  VM '$Name' ready for PXE deployment" -ForegroundColor Green
Write-Host "  PXE Server: ${PxeServerIP}:$PxeHttpPort" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Green
