#!/usr/bin/env python3
"""PUBLIC cheap W0.5: exercise OWNED synthetic libvirt Windows-shaped devices, not Windows.
No private source, Windows media, W1 provider Apply, or network uplink.
"""
from __future__ import annotations
import hashlib,json,shutil,subprocess,sys,time,uuid
from pathlib import Path
import xml.etree.ElementTree as ET
from scripts.compute_guest_profile_contract import load
from scripts.windows_w1_libvirt_plan import libvirt_w1_plan,MEDIA_SIZE,MEDIA_SHA256
from scripts.windows_w1_libvirt_domain import render_w1_libvirt_xml

OUT=Path('/tmp/winbot-w05-receipt')
BASE=Path('/var/lib/libvirt/images')
def cmd(*args,check=True):
    return subprocess.run(args,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=check)
def virsh(*args,check=True):
    return cmd('virsh','-c','qemu:///system',*args,check=check)
def absent(kind,name):
    return virsh('dominfo' if kind=='domain' else 'net-info',name,check=False).returncode!=0
def receipt(name,x):
    (OUT/name).write_text(json.dumps(x,indent=2,sort_keys=True)+'\n')
def main():
    if OUT.exists(): raise RuntimeError('refuse preexisting evidence directory')
    OUT.mkdir(mode=0o755)
    uid=str(uuid.uuid4()); he=uuid.UUID(uid).hex
    owner='ad-w1-'+he; root=BASE/owner
    defined=False; net_defined=False; own_root=False; failure=None
    try:
        assert absent('domain',uid) and absent('network',owner) and not root.exists(), 'preexisting resource'
        assert Path('/dev/kvm').is_char_device(),'KVM absent'
        assert Path('/usr/share/OVMF/OVMF_CODE_4M.secboot.fd').is_file()
        assert Path('/usr/share/OVMF/OVMF_VARS_4M.ms.fd').is_file()
        root.mkdir(mode=0o750); own_root=True
        shutil.chown(root,user='libvirt-qemu',group='kvm')
        # Bind a NEW run-specific GPT GUID to the EXACT qcow2 later attached to
        # the KVM VM, not to a separate host-only rehearsal. All bytes are
        # written only inside this fresh run-owned disposable directory.
        from scripts.windows_w1_gpt_header import verify_gpt_primary
        gpt_guid = str(uuid.uuid4())
        raw = root/'preseed-gpt-sparse.raw'
        with raw.open('xb') as handle:
            handle.truncate(64 * 1024**3)
        cmd('sgdisk','--clear','--disk-guid='+gpt_guid,str(raw))
        cmd('sgdisk','--verify',str(raw))
        target = root/'system.qcow2'
        cmd('qemu-img','convert','-f','raw','-O','qcow2','-S','4096',str(raw),str(target))
        raw.unlink()
        early = root/'first-34-sectors.raw'
        cmd('qemu-img','dd','-f','qcow2','bs=512','count=34',
            'if='+str(target),'of='+str(early))
        gpt_info = verify_gpt_primary(early.read_bytes(),
                                      expected_guid=gpt_guid,
                                      virtual_size_bytes=64*1024**3)
        early.unlink()
        receipt('run-owned-guest-gpt-preseed.json',{
            'schema':'winbot-w1-live-owned-gpt-preseed/v1',
            'classification':'HOST_GPT_ANCHORED_TO_VM_SOURCE',
            'run_uuid':uid,'source_path':str(target),
            'gpt_observation':gpt_info,
            'winpe_guest_guid_observed':False,
            'windows_setup_authorized':False,
            'winbot_guest_qualified':False,
        })
        shutil.chown(root/'system.qcow2',user='libvirt-qemu',group='kvm')
        (OUT/'synthetic.txt').write_text('SYNTHETIC NONBOOTABLE; NOT WINDOWS\n')
        hashes={}
        for name in ('windows11-install.iso','unattended-seed.iso'):
            p=root/name
            cmd('xorriso','-as','mkisofs','-quiet','-V','SYNTHETIC','-o',str(p),str(OUT/'synthetic.txt'))
            assert p.stat().st_size<1048576
            digest=hashlib.sha256(p.read_bytes()).hexdigest()
            assert digest!=MEDIA_SHA256
            hashes[name]={'sha256':digest,'bytes':p.stat().st_size}
            shutil.chown(p,user='libvirt-qemu',group='kvm')
        receipt('synthetic-media.json',{'classification':'SYNTHETIC_NONBOOTABLE_ONLY','files':hashes})
        nx=ET.Element('network')
        ET.SubElement(nx,'name').text=owner
        ET.SubElement(nx,'uuid').text=str(uuid.uuid4())
        ET.SubElement(nx,'bridge',{'name':'wb'+he[:10],'stp':'off','delay':'0'})
        (OUT/'network.xml').write_text(ET.tostring(nx,encoding='unicode')+'\n')
        virsh('net-define',str(OUT/'network.xml'));net_defined=True
        virsh('net-start',owner)
        (OUT/'realized-network.xml').write_text(virsh('net-dumpxml',owner).stdout)
        # Deliberately synthetic observations: these do NOT admit real W1 Apply.
        obs={
            'owned_root':str(root),'libvirt_uri':'qemu:///system',
            'kvm_vcpu_exercised':True,'host_passthrough_supported':True,
            'secureboot_firmware_observed':True,'enrolled_keys_observed':True,
            'swtpm2_startup_exercised':True,'owned_isolated_network_observed':True,
            'domain_uuid_absent':True,'owned_root_absent':True,
            'installer_media_digest_verified':True,'unattended_seed_secret_free':True,
            'windows_wipe_target_is_single_run_owned_disk':True,
            'installer_media_sha256':MEDIA_SHA256,'installer_media_size_bytes':MEDIA_SIZE,
            'network':owner,'unattended_seed_sha256':'f'*64
        }
        plan=libvirt_w1_plan(load(Path('config/compute-guest-profiles.json')),obs,uid)
        assert plan['mutation_authorized'] is False
        (OUT/'synthetic-domain.xml').write_text(render_w1_libvirt_xml(plan))
        receipt('claim-boundary.json',{
            'schema':'winbot-w05-synthetic-topology/v1',
            'classification':'SYNTHETIC_TOPOLOGY_ONLY',
            'all_w1_observations_are_synthetic_test_doubles':True,
            'microsoft_iso_present':False,'windows_setup_executed':False,
            'windows_guest_qualified':False,'winbot_guest_qualified':False,
            'windows_w1_plan_mutation_authorized':False,
            'scope':'separately authorized disposable public synthetic device lab'
        })
        cmd('virt-xml-validate',str(OUT/'synthetic-domain.xml'),'domain')
        virsh('define',str(OUT/'synthetic-domain.xml'));defined=True
        # Independent HOST-only destructive-target preflight against realized
        # libvirt readback + actual qcow2 headers; guest DiskID=0 remains UNKNOWN.
        from scripts.windows_w1_libvirt_disk_guard import (
            disk_image_observation, verify_host_disk_guard
        )
        defined_xml=virsh('dumpxml',uid).stdout
        host_disk=verify_host_disk_guard(
            defined_xml, run_uuid=uid,
            image=disk_image_observation(str(root/'system.qcow2')),
        )
        receipt('host-disk-guard.json',host_disk)
        assert host_disk['windows_unattended_wipe_authorized'] is False
        virsh('start',uid)
        time.sleep(3)
        assert virsh('domstate',uid).stdout.strip()=='running'
        live=virsh('dumpxml',uid).stdout
        (OUT/'realized-domain.xml').write_text(live)
        (OUT/'native-argv.txt').write_text(virsh('domxml-to-native','qemu-argv',str(OUT/'realized-domain.xml')).stdout)
        r=ET.fromstring(live)
        assert r.attrib['type']=='kvm'
        assert r.find('./os/loader').get('secure')=='yes'
        assert r.find('./features/smm').get('state')=='on'
        assert r.find('./devices/tpm/backend').get('version')=='2.0'
        disks=r.findall('./devices/disk')
        assert len(disks)==3
        writable=[d for d in disks if d.find('readonly') is None]
        assert len(writable)==1 and writable[0].get('device')=='disk'
        assert writable[0].find('source').get('file')==str(root/'system.qcow2')
        assert writable[0].find('target').get('bus')=='sata'
        assert all(d.find('source').get('file').startswith(str(root)+'/') for d in disks)
        assert all(d.find('readonly') is not None for d in disks if d.get('device')=='cdrom')
        assert r.find('./devices/interface/source').get('network')==owner
        assert r.find('./devices/interface/model').get('type')=='e1000'
        found=[]
        for p in Path('/proc').iterdir():
            if not p.name.isdecimal():continue
            try:
                a=(p/'cmdline').read_bytes().rstrip(b'\0').decode(errors='replace').split('\0')
                if a and a[0].endswith('qemu-system-x86_64') and any(uid in x for x in a[1:]):found.append(a)
            except (OSError,PermissionError):pass
        assert len(found)==1,'cannot verify exact KVM process'
        args=found[0]
        assert '-enable-kvm' in args or any(args[i]=='-accel' and args[i+1]=='kvm' for i in range(len(args)-1))
        assert any('tpm-tis' in x for x in args) and any('tpmdev' in x for x in args)
        receipt('observed-qemu-argv.json',args)
        receipt('realization.json',{
            'schema':'winbot-w05-realized-device-topology/v1',
            'classification':'SYNTHETIC_DEVICE_TOPOLOGY_CONFIRMED',
            'real_kvm_cpu':True,'one_run_owned_writable_sata_disk':True,
            'two_owned_readonly_placeholder_cdroms':True,
            'owned_isolated_network':True,'secure_ovmf_smm_vtpm2':True,
            'windows_guest_qualified':False,'winbot_guest_qualified':False
        })
    except Exception as ex:
        failure=type(ex).__name__+': '+str(ex)
        receipt('error.json',{'classification':'HARNESS_OR_ENVIRONMENT_FAILURE','detail':failure})
    finally:
        errors=[]
        if defined:
            virsh('destroy',uid,check=False)
            x=virsh('undefine',uid,'--nvram','--tpm',check=False)
            if x.returncode:errors.append('undefine: '+x.stderr[:150])
        if net_defined:
            virsh('net-destroy',owner,check=False)
            x=virsh('net-undefine',owner,check=False)
            if x.returncode:errors.append('net-undefine: '+x.stderr[:150])
        if own_root:shutil.rmtree(root)
        good={
            'domain_absent':absent('domain',uid),
            'network_absent':absent('network',owner),
            'owned_storage_absent':not root.exists(),
            'tpm_state_absent':not (Path('/var/lib/libvirt/swtpm')/uid).exists(),
        }
        receipt('cleanup.json',{'schema':'winbot-w05-cleanup/v1',**good,
                'cleanup_errors':errors,'primary_failure':failure})
        if not all(good.values()) or errors:failure='CLEANUP_FAILURE: '+str(good)+' '+str(errors)
    if failure:print(failure,file=sys.stderr)
    else:print('SYNTHETIC KVM DEVICE TOPOLOGY PASS; WINDOWS/WINBOT NOT TESTED')
    return 3 if failure else 0
if __name__=='__main__':raise SystemExit(main())
