param(
  [string]$Authority = 'SemperSupra/agent-dispatch-private#406',
  [string]$Consumer = 'mark-e-deyoung/WinBot#70',
  [string]$OutputDir = (Join-Path $env:RUNNER_TEMP 'winbot-workcell-materialization')
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$work = Join-Path $env:RUNNER_TEMP 'winbot-workcell-work'
New-Item -ItemType Directory -Force -Path $OutputDir,$work | Out-Null

$isoUrl='https://software-static.download.prss.microsoft.com/dbazure/26300.9457.260913-1737.26h2_ge_release_svc_refresh_CLIENTENTERPRISEEVAL_OEMRET_x64FRE_en-us.iso'
$isoSha='bc3f24086ebadc94489066b5ad78089e2cf5c3491e90e790bb81a2b199c10e38'
$isoSize=[int64]8225329152
$wimlibUrl='https://wimlib.net/downloads/wimlib-1.14.5-windows-x86_64-bin.zip'
$wimlibSha='2f446d6fa3866582175f1a22a7be198eeee0aec7aba5b4e04ad25c99eae2d265'
$iso=Join-Path $work 'windows.iso'
$seed=Join-Path $work 'seed.vhdx'
$persist=Join-Path $work 'persist.vhdx'
$aDir=Join-Path $work 'a'; $bDir=Join-Path $work 'b'
$aDisk=Join-Path $aDir 'runtime.vhdx'; $bDisk=Join-Path $bDir 'runtime.vhdx'
$vmA='WinBot-WC-A-'+$env:GITHUB_RUN_ID; $vmB='WinBot-WC-B-'+$env:GITHUB_RUN_ID
$r=[ordered]@{
 schema_version=1; authority=$Authority; consumer=$Consumer
 profile='HyperVWorkCellMaterializationPrimitive'
 scope='public synthetic substrate/work-cell proof; not WinBot product/API qualification'
 runner=[ordered]@{image_os=$env:ImageOS;image_version=$env:ImageVersion}
 seed=[ordered]@{};materialization=[ordered]@{};persistence=[ordered]@{}
 actor_control=[ordered]@{};oracles=[ordered]@{};cleanup=[ordered]@{}
 classification='HARNESS_FAILURE';failure_domain=$null;error_type=$null;error_message=$null
}
$rc=1;$isoMounted=$false;$seedMounted=$false

function Fail([string]$c,[string]$d,[string]$m){$script:r.classification=$c;$script:r.failure_domain=$d;$script:r.error_message=$m;throw $m}
function Remove-Cell([string]$n,[string]$d,[string]$dir){
 $v=Get-VM -Name $n -ErrorAction SilentlyContinue
 if($v){if($v.State-ne'Off'){Stop-VM -Name $n -TurnOff -Force -ErrorAction SilentlyContinue};Remove-VM -Name $n -Force -ErrorAction SilentlyContinue}
 if(Test-Path $d){Remove-Item $d -Force -ErrorAction SilentlyContinue}
 if(Test-Path $dir){Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue}
}
function Wait-PSD([string]$n,[Management.Automation.PSCredential]$c){
 $end=(Get-Date).AddMinutes(20);$last=''
 while((Get-Date)-lt$end){try{return Invoke-Command -VMName $n -Credential $c -ScriptBlock {[pscustomobject]@{computer=$env:COMPUTERNAME;os=[Environment]::OSVersion.VersionString}} -ErrorAction Stop}catch{$last=$_.Exception.Message};Start-Sleep 10}
 throw "PowerShell Direct timeout for $n; last=$last"
}
function New-Cell([string]$n,[string]$d,[string]$dir,[string]$sw){
 New-Item -ItemType Directory -Force $dir|Out-Null;$t=Get-Date
 New-VHD -Path $d -ParentPath $seed -Differencing|Out-Null;$vh=Get-VHD $d
 New-VM -Name $n -VHDPath $d -Generation 2 -MemoryStartupBytes 2GB -SwitchName $sw|Out-Null
 Set-VMProcessor $n -Count 2;Set-VM $n -AutomaticCheckpointsEnabled $false
 Add-VMHardDiskDrive -VMName $n -Path $persist;Start-VM $n|Out-Null
 [pscustomobject]@{seconds=[math]::Round(((Get-Date)-$t).TotalSeconds,3);parent=[string]$vh.ParentPath;initial_bytes=[int64](Get-Item $d).Length;started=((Get-VM $n).State-eq'Running')}
}
try{
 $free=[int64](Get-PSDrive -Name ([IO.Path]::GetPathRoot($work).Substring(0,1))).Free;$r.materialization.free_bytes_before=$free
 if($free-lt45GB){Fail ENVIRONMENT_FAILURE runner-storage 'less than 45 GiB free'}
 Get-VMHost|Out-Null
 $switches=@(Get-VMSwitch|% Name);$r.materialization.observed_switches=$switches
 $sw=@('Default Switch','nat')|?{$_-in$switches}|select -First 1
 if(!$sw){Fail ENVIRONMENT_FAILURE hyperv-network 'no authorized existing switch'};$r.materialization.selected_switch=$sw

 $dl=Get-Date
 try{Start-BitsTransfer -Source $isoUrl -Destination $iso -ErrorAction Stop;$r.seed.download_method='BITS'}catch{Invoke-WebRequest $isoUrl -OutFile $iso -UseBasicParsing;$r.seed.download_method='Invoke-WebRequest'}
 $r.seed.download_seconds=[math]::Round(((Get-Date)-$dl).TotalSeconds,3)
 $it=Get-Item $iso;$actual=(Get-FileHash $iso -Algorithm SHA256).Hash.ToLowerInvariant()
 $r.seed.source_iso_sha256=$actual;$r.seed.source_iso_size=[int64]$it.Length
 $r.oracles.media_pin=($actual-eq$isoSha-and$it.Length-eq$isoSize);if(!$r.oracles.media_pin){Fail ORACLE_FAILURE media-identity 'media pin mismatch'}

 $im=Mount-DiskImage $iso -PassThru;$isoMounted=$true;$vol=$im|Get-Volume|? DriveLetter|select -First 1
 $wim=Join-Path "$($vol.DriveLetter):\" 'sources\install.wim';if(!(Test-Path $wim)){$wim=Join-Path "$($vol.DriveLetter):\" 'sources\install.esd'}
 $img=Get-WindowsImage -ImagePath $wim -Index 1;$r.seed.image_name=[string]$img.ImageName
 if($img.ImageName-notlike'*Enterprise Evaluation*'){Fail ORACLE_FAILURE media-image 'wrong install image'}

 $wz=Join-Path $work 'wimlib.zip';$wr=Join-Path $work 'wimlib';Invoke-WebRequest $wimlibUrl -OutFile $wz -UseBasicParsing
 $wa=(Get-FileHash $wz -Algorithm SHA256).Hash.ToLowerInvariant();$r.seed.wimlib_sha256=$wa;$r.oracles.wimlib_pin=($wa-eq$wimlibSha)
 if(!$r.oracles.wimlib_pin){Fail ORACLE_FAILURE wimlib-identity 'wimlib pin mismatch'}
 Expand-Archive $wz $wr -Force;$wx=Get-ChildItem $wr -Recurse -Filter wimlib-imagex.exe|select -First 1

 $bt=Get-Date;New-VHD $seed -SizeBytes 80GB -Dynamic|Out-Null;$m=Mount-VHD $seed -Passthru;$seedMounted=$true;Start-Sleep 1
 $dn=($m|Get-Disk).Number;Initialize-Disk $dn -PartitionStyle GPT;Start-Sleep 1
 $amsr=Get-Partition -DiskNumber $dn|? GptType -eq '{e3c9e316-0b5c-4db8-817d-f92df00215ae}';if($amsr){Remove-Partition -DiskNumber $dn -PartitionNumber $amsr.PartitionNumber -Confirm:$false -ErrorAction SilentlyContinue}
 $efi=New-Partition -DiskNumber $dn -Size 100MB -GptType '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}';$efi|Set-Partition -NewDriveLetter S;Format-Volume S -FileSystem FAT32 -Confirm:$false -Force|Out-Null
 New-Partition -DiskNumber $dn -Size 16MB -GptType '{e3c9e316-0b5c-4db8-817d-f92df00215ae}'|Out-Null
 $wp=New-Partition -DiskNumber $dn -UseMaximumSize -GptType '{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}';$wp|Set-Partition -NewDriveLetter T;Format-Volume T -FileSystem NTFS -Confirm:$false -Force|Out-Null
 & $wx.FullName apply $wim 1 'T:\' *> (Join-Path $work 'apply.log');$r.seed.image_apply_exit=$LASTEXITCODE
 if($LASTEXITCODE-ne0){Fail ENVIRONMENT_FAILURE image-apply 'wimlib apply failed'}
 & bcdboot.exe T:\Windows /s S: /f UEFI;if($LASTEXITCODE-ne0){Fail ENVIRONMENT_FAILURE bcdboot 'bcdboot failed'}

 $pw='Wb9!'+[guid]::NewGuid().ToString('N')+'Aa'
 New-Item -ItemType Directory -Force 'T:\Windows\Panther'|Out-Null
 $xml=@'
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
 <settings pass="specialize">
  <component name="Microsoft-Windows-Deployment" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
   <RunSynchronous>
    <RunSynchronousCommand wcm:action="add"><Order>1</Order><Path>cmd /c net user winbot __PASSWORD__ /add /y</Path></RunSynchronousCommand>
    <RunSynchronousCommand wcm:action="add"><Order>2</Order><Path>cmd /c net localgroup Administrators winbot /add</Path></RunSynchronousCommand>
   </RunSynchronous>
  </component>
 </settings>
 <settings pass="oobeSystem">
  <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"><InputLocale>en-US</InputLocale><SystemLocale>en-US</SystemLocale><UILanguage>en-US</UILanguage><UserLocale>en-US</UserLocale></component>
  <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"><OOBE><HideEULAPage>true</HideEULAPage><HideOnlineAccountScreens>true</HideOnlineAccountScreens><HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE><ProtectYourPC>3</ProtectYourPC></OOBE><AutoLogon><Password><Value>__PASSWORD__</Value><PlainText>true</PlainText></Password><Enabled>true</Enabled><LogonCount>1</LogonCount><Username>winbot</Username></AutoLogon></component>
 </settings>
</unattend>
'@
 Set-Content 'T:\Windows\Panther\unattend.xml' ($xml.Replace('__PASSWORD__',$pw)) -Encoding utf8
 Dismount-VHD $seed;$seedMounted=$false;Dismount-DiskImage $iso|Out-Null;$isoMounted=$false;Remove-Item $iso
 $r.seed.test_vhd=[bool](Test-VHD $seed);$r.seed.physical_bytes=[int64](Get-Item $seed).Length;$r.seed.build_seconds=[math]::Round(((Get-Date)-$bt).TotalSeconds,3)
 if(!$r.seed.test_vhd){Fail ORACLE_FAILURE seed-validation 'Test-VHD failed'}
 Set-ItemProperty $seed -Name IsReadOnly -Value $true;$h0=(Get-FileHash $seed -Algorithm SHA256).Hash.ToLowerInvariant();$r.seed.sha256_before=$h0

 New-VHD $persist -Dynamic -SizeBytes 1GB|Out-Null;$r.persistence.explicit_attachment=$true
 $cred=[Management.Automation.PSCredential]::new('winbot',(ConvertTo-SecureString $pw -AsPlainText -Force))
 $can='persist-'+[guid]::NewGuid().ToString('N');$taint='taint-'+[guid]::NewGuid().ToString('N')

 $a=New-Cell $vmA $aDisk $aDir $sw;$r.materialization.cell_a=$a;$r.oracles.a_lineage=([IO.Path]::GetFullPath($a.parent)-eq[IO.Path]::GetFullPath($seed))
 if(!$a.started-or!$r.oracles.a_lineage){Fail ORACLE_FAILURE materialize-a 'A start/lineage failed'}
 $ta=Get-Date;$r.actor_control.a_ready=Wait-PSD $vmA $cred;$r.actor_control.a_ready_seconds=[math]::Round(((Get-Date)-$ta).TotalSeconds,3)
 $mut=Invoke-Command -VMName $vmA -Credential $cred -ArgumentList $can,$taint -ScriptBlock {
  param($can,$taint);$d=Get-Disk|?{!$_.IsBoot-and!$_.IsSystem-and$_.Size-le2GB}|sort Number|select -First 1;if(!$d){throw'persist disk absent'}
  if($d.PartitionStyle-eq'RAW'){Initialize-Disk $d.Number -PartitionStyle GPT|Out-Null;New-Partition -DiskNumber $d.Number -UseMaximumSize -DriveLetter P|Format-Volume -FileSystem NTFS -Confirm:$false -Force|Out-Null}else{$p=Get-Partition -DiskNumber $d.Number|? Type -ne Reserved|select -First 1;if(!$p.DriveLetter){$p|Set-Partition -NewDriveLetter P}}
  New-Item -ItemType Directory -Force C:\WinBot|Out-Null;Set-Content C:\WinBot\taint.txt $taint;Set-Content P:\canary.txt $can
  [pscustomobject]@{taint=[IO.File]::ReadAllText('C:\WinBot\taint.txt').Trim();canary=[IO.File]::ReadAllText('P:\canary.txt').Trim()}
 }
 $r.actor_control.a_taint=($mut.taint-eq$taint);$r.persistence.canary_written=($mut.canary-eq$can)
 Remove-Cell $vmA $aDisk $aDir;$r.cleanup.a_absent=(-not(Get-VM $vmA -ErrorAction SilentlyContinue)-and-not(Test-Path $aDisk));$r.persistence.survived_a=Test-Path $persist

 $b=New-Cell $vmB $bDisk $bDir $sw;$r.materialization.cell_b=$b;$r.oracles.b_lineage=([IO.Path]::GetFullPath($b.parent)-eq[IO.Path]::GetFullPath($seed))
 if(!$b.started-or!$r.oracles.b_lineage){Fail ORACLE_FAILURE materialize-b 'B start/lineage failed'}
 $tb=Get-Date;$r.actor_control.b_ready=Wait-PSD $vmB $cred;$r.actor_control.b_ready_seconds=[math]::Round(((Get-Date)-$tb).TotalSeconds,3)
 $obs=Invoke-Command -VMName $vmB -Credential $cred -ArgumentList $can -ScriptBlock {param($can);$d=Get-Disk|?{!$_.IsBoot-and!$_.IsSystem-and$_.Size-le2GB}|sort Number|select -First 1;$p=Get-Partition -DiskNumber $d.Number|? Type -ne Reserved|select -First 1;if(!$p.DriveLetter){$p|Set-Partition -NewDriveLetter P};[pscustomobject]@{canary=([IO.File]::ReadAllText('P:\canary.txt').Trim()-eq$can);no_taint=(-not(Test-Path C:\WinBot\taint.txt))}}
 $r.persistence.canary_survived=[bool]$obs.canary;$r.actor_control.prior_taint_absent=[bool]$obs.no_taint
 Remove-Cell $vmB $bDisk $bDir;$r.cleanup.b_absent=(-not(Get-VM $vmB -ErrorAction SilentlyContinue)-and-not(Test-Path $bDisk));$r.persistence.survived_b=Test-Path $persist

 $h1=(Get-FileHash $seed -Algorithm SHA256).Hash.ToLowerInvariant();$r.seed.sha256_after=$h1;$r.oracles.seed_unchanged=($h0-eq$h1)
 $r.oracles.actor_control=$r.actor_control.a_taint
 $r.oracles.disposable_runtime=($r.cleanup.a_absent-and$r.cleanup.b_absent-and$r.actor_control.prior_taint_absent)
 $r.oracles.explicit_persistence=($r.persistence.canary_written-and$r.persistence.canary_survived-and$r.persistence.survived_b)
 $r.oracles.materialization=($r.oracles.a_lineage-and$r.oracles.b_lineage)
 $r.oracles.accepted=($r.oracles.media_pin-and$r.oracles.wimlib_pin-and$r.oracles.seed_unchanged-and$r.oracles.actor_control-and$r.oracles.disposable_runtime-and$r.oracles.explicit_persistence-and$r.oracles.materialization)
 if(!$r.oracles.accepted){Fail ORACLE_FAILURE workcell-oracle 'work-cell acceptance failed'}
 $r.classification='SUPPORTED';$rc=0
}catch{
 if(!$r.error_type){$r.error_type=$_.Exception.GetType().FullName};if(!$r.error_message){$r.error_message=$_.Exception.Message}
 if($r.classification-eq'HARNESS_FAILURE'){$rc=3}elseif($rc-eq1){$rc=2}
}finally{
 try{
  Remove-Cell $vmA $aDisk $aDir;Remove-Cell $vmB $bDisk $bDir
  if($seedMounted){Dismount-VHD $seed -ErrorAction SilentlyContinue};if($isoMounted){Dismount-DiskImage $iso -ErrorAction SilentlyContinue|Out-Null}
  if(Test-Path $seed){Set-ItemProperty $seed -Name IsReadOnly -Value $false -ErrorAction SilentlyContinue}
  if(Test-Path $work){Remove-Item $work -Recurse -Force}
  $r.cleanup.final_a_absent=-not[bool](Get-VM $vmA -ErrorAction SilentlyContinue);$r.cleanup.final_b_absent=-not[bool](Get-VM $vmB -ErrorAction SilentlyContinue);$r.cleanup.work_absent=-not(Test-Path $work)
  $r.cleanup.oracle_satisfied=($r.cleanup.final_a_absent-and$r.cleanup.final_b_absent-and$r.cleanup.work_absent)
  if(!$r.cleanup.oracle_satisfied){$r.classification='ORACLE_FAILURE';$rc=4}
 }catch{$r.cleanup.oracle_satisfied=$false;$r.cleanup.error=$_.Exception.Message;$r.classification='ORACLE_FAILURE';$rc=4}
 $r|ConvertTo-Json -Depth 16|Set-Content (Join-Path $OutputDir 'receipt.json') -Encoding utf8
}
exit $rc
