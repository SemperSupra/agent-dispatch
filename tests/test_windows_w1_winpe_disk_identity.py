"""Synthetic negative matrix for read-only Windows PE DiskPart GPT identity.

Not an observed Windows guest/WinPE receipt. No Windows media or host mutation.
"""
from __future__ import annotations
import copy
import unittest
from scripts.windows_w1_winpe_disk_identity import (
    classify_winpe_serial, diskpart_readonly_commands, DiskIdentityRefused, SCHEMA
)

RUN="c31d4df2-9ab1-4ea7-b317-75b9c633b9b1"
GPT="52aa5640-1a2d-4624-a3b2-67c2fa84ce92"
NONCE="winbotDiskProbe20261020"

def host():
    return {
        "schema":"windows-w1-libvirt-host-disk-guard/v1",
        "classification":"HOST_SINGLE_OWNED_DISK_CONFIRMED",
        "resource_uuid":RUN,
        "source_file":"/var/lib/libvirt/images/ad-w1-"+RUN.replace("-","")+"/system.qcow2",
        "one_writable_host_disk":True,
        "windows_unattended_wipe_authorized":False,
    }

def transcript(guid=GPT,disk_lines="  Disk 0    Online      64 GB      64 GB        *"):
    return (
        "AD_W1_WINPE_BEGIN="+NONCE+"\n"
        "Microsoft DiskPart version 10.0.26300.1\n"
        "DISKPART> list disk\n"
        "  Disk ###  Status       Size     Free     Dyn Gpt\n"
        "  --------  ---------    -------  -------  --- ---\n"
        +disk_lines+"\n"
        "DISKPART> select disk 0\n"
        "Disk 0 is now the selected disk.\n"
        "DISKPART> uniqueid disk\n"
        "Disk ID: {"+guid+"}\n"
        "DISKPART> exit\n"
        "AD_W1_WINPE_END="+NONCE+"\n"
    )

def run(txt=None, **k):
    args={
        "text": transcript() if txt is None else txt,
        "expected_nonce":NONCE,
        "expected_run_uuid":RUN,
        "host_gpt_disk_guid":GPT,
        "host_gpt_guid_observed":True,
        "host_guard":host(),
    }
    args.update(k)
    return classify_winpe_serial(**args)

class WinPEReadOnlyIdentity(unittest.TestCase):
    def test_exact_host_gpt_and_guest_disk_zero_equality(self):
        p=run()
        self.assertEqual(p["schema"],SCHEMA)
        self.assertEqual(p["observed_guest_gpt_guid"],GPT)
        self.assertEqual(p["observed_disk_index"],0)
        self.assertTrue(p["host_guard_matched"])
        self.assertFalse(p["guest_media_provenance_independently_proved"])
        self.assertFalse(p["destructive_windows_setup_authorized"])

    def test_readonly_diskpart_script_has_no_mutating_command(self):
        script=diskpart_readonly_commands()
        self.assertEqual(script,"list disk\nselect disk 0\nuniqueid disk\nexit\n")
        self.assertNotIn("id=",script.lower())
        self.assertEqual(script.splitlines()[-1],"exit")

    def test_missing_or_untrusted_host_observation_fails(self):
        for field,value in (
            ("host_gpt_guid_observed",False),("host_gpt_guid_observed",None),
            ("host_gpt_disk_guid","00000000-0000-0000-0000-000000000000"),
            ("expected_run_uuid","another"),
            ("expected_nonce","short"),
        ):
            with self.subTest(field=field),self.assertRaises(DiskIdentityRefused):
                run(**{field:value})
        for field,value in (
            ("schema","other"),("classification","UNKNOWN"),
            ("resource_uuid","wrong"),("source_file","/dev/sda"),
            ("one_writable_host_disk",False),
            ("windows_unattended_wipe_authorized",True),
        ):
            p=host();p[field]=value
            with self.subTest(field=field),self.assertRaises(DiskIdentityRefused):
                run(host_guard=p)

    def test_guest_guid_mismatch_or_multiple_guids_fails(self):
        wrong="baf784e7-6bbd-4cfb-aaac-e86c96e166ee"
        with self.assertRaises(DiskIdentityRefused):run(transcript(wrong))
        with self.assertRaises(DiskIdentityRefused):
            run(transcript()+"Disk ID: {"+GPT+"}\n")  # outside envelope refused in separate test
        with self.assertRaises(DiskIdentityRefused):
            run(transcript().replace("Disk ID: {"+GPT+"}","Disk ID: {"+GPT+"}\nDisk ID: {"+GPT+"}"))

    def test_extra_disk_or_wrong_size_fails(self):
        extra="  Disk 0    Online      64 GB      64 GB        *\n  Disk 1    Online      4 GB       4 GB"
        for listing in (extra,"  Disk 1    Online      64 GB      64 GB",
                        "  Disk 0    Offline     64 GB      64 GB",
                        "  Disk 0    Online      128 GB     128 GB"):
            with self.subTest(row=listing),self.assertRaises(DiskIdentityRefused):
                run(transcript(disk_lines=listing))

    def test_reordered_or_missing_commands_fail(self):
        bads=(
            transcript().replace("DISKPART> select disk 0","DISKPART> select disk 1"),
            transcript().replace("DISKPART> uniqueid disk",""),
            transcript().replace("Disk 0 is now the selected disk.",""),
            transcript().replace("AD_W1_WINPE_BEGIN","WRONG_BEGIN"),
            transcript().replace("AD_W1_WINPE_END","WRONG_END"),
            transcript().replace("DISKPART> uniqueid disk","DISKPART> uniqueid disk id="+GPT),
        )
        for i,v in enumerate(bads):
            with self.subTest(i=i),self.assertRaises(DiskIdentityRefused):run(v)

    def test_duplicate_envelope_and_winpe_errors_fail(self):
        for txt in (
            transcript()+transcript(),
            transcript().replace("Disk 0 is now the selected disk.","DiskPart has encountered an error"),
            transcript().replace("Disk 0 is now the selected disk.","There is no disk selected"),
        ):
            with self.assertRaises(DiskIdentityRefused):run(txt)

if __name__=="__main__":
    unittest.main()
