"""Native DiskPart /s output (no echoed commands) negative matrix; SOURCE only."""
from __future__ import annotations
import copy,hashlib,unittest
from scripts.windows_w1_winpe_disk_identity import (
    classify_winpe_serial,diskpart_readonly_commands,DiskIdentityRefused,SCHEMA
)

RUN="c31d4df2-9ab1-4ea7-b317-75b9c633b9b1"
GPT="52aa5640-1a2d-4624-a3b2-67c2fa84ce92"
NONCE="winbotDiskProbe20261020"
DIGEST=hashlib.sha256(diskpart_readonly_commands().encode("utf-8")).hexdigest()

def host():
    return {
        "schema":"windows-w1-libvirt-host-disk-guard/v1",
        "classification":"HOST_SINGLE_OWNED_DISK_CONFIRMED",
        "resource_uuid":RUN,
        "source_file":"/var/lib/libvirt/images/ad-w1-"+RUN.replace("-","")+"/system.qcow2",
        "one_writable_host_disk":True,
        "windows_unattended_wipe_authorized":False,
    }

def transcript(guid=GPT,disk_lines="  Disk 0    Online           64 GB    63 GB        *"):
    return (
        "AD_W1_WINPE_BEGIN="+NONCE+"\n"
        "Microsoft DiskPart version 10.0.26100.1150\n"
        "Copyright (C) Microsoft Corporation.\n"
        "On computer: synthetic-winpe\n\n"
        "  Disk ###  Status         Size     Free     Dyn  Gpt\n"
        "  --------  -------------  -------  -------  ---  ---\n"
        +disk_lines+"\n\n"
        "Disk 0 is now the selected disk.\n"
        "Disk ID: {"+guid.upper()+"}\n"
        "Leaving DiskPart...\n"
        "AD_W1_WINPE_END="+NONCE+"\n"
    )

def run(txt=None,**k):
    args={
        "text":transcript() if txt is None else txt,
        "expected_nonce":NONCE,
        "expected_run_uuid":RUN,
        "host_gpt_disk_guid":GPT,
        "host_gpt_guid_observed":True,
        "host_guard":host(),
        "read_only_script_sha256":DIGEST,
        "read_only_script_independently_verified":True,
    }
    args.update(k)
    return classify_winpe_serial(**args)

class WinPENativeReadOnlyOracle(unittest.TestCase):
    def test_strict_native_no_echo_fixture_matches_owned_gpt(self):
        p=run()
        self.assertEqual(p["schema"],SCHEMA)
        self.assertEqual(p["observed_guest_gpt_guid"],GPT)
        self.assertEqual(p["observed_disk_index"],0)
        self.assertTrue(p["host_guard_matched"])
        self.assertTrue(p["read_only_script_sha256_matched"])
        self.assertFalse(p["guest_media_provenance_independently_proved"])
        self.assertFalse(p["destructive_windows_setup_authorized"])

    def test_command_script_is_readonly_and_digest_bound(self):
        self.assertEqual(diskpart_readonly_commands(),
                         "list disk\nselect disk 0\nuniqueid disk\nexit\n")
        with self.assertRaises(DiskIdentityRefused):
            run(read_only_script_sha256="0"*64)
        with self.assertRaises(DiskIdentityRefused):
            run(read_only_script_independently_verified=False)
        with self.assertRaises(DiskIdentityRefused):
            run(read_only_script_independently_verified=None)
        with self.assertRaises(DiskIdentityRefused):
            run(transcript().replace("Disk 0 is now the selected disk.",
                                     "DISKPART> select disk 0\nDisk 0 is now the selected disk."))

    def test_host_provenance_is_strict(self):
        for f,v in (
            ("host_gpt_guid_observed",False),("host_gpt_guid_observed",None),
            ("host_gpt_disk_guid","00000000-0000-0000-0000-000000000000"),
            ("expected_run_uuid","not-a-uuid"),("expected_nonce","short"),
        ):
            with self.subTest(f=f),self.assertRaises(DiskIdentityRefused):
                run(**{f:v})
        for f,v in (
            ("schema","wrong"),("classification","OTHER"),
            ("resource_uuid","different"),("source_file","/dev/sda"),
            ("one_writable_host_disk",False),
            ("windows_unattended_wipe_authorized",True),
        ):
            h=host();h[f]=v
            with self.subTest(f=f),self.assertRaises(DiskIdentityRefused):
                run(host_guard=h)

    def test_native_host_multidisk_report_not_accepted_as_winpe_disk_zero(self):
        host_rows=("  Disk 0    Online          150 GB    0 B       *\n"
                   "  Disk 1    Online          150 GB    0 B\n"
                   "  Disk 2    Online           64 GB    63 GB        *")
        with self.assertRaises(DiskIdentityRefused):
            run(transcript(disk_lines=host_rows))
        with self.assertRaises(DiskIdentityRefused):
            run(transcript(disk_lines="  Disk 1    Online  64 GB   63 GB *"))
        with self.assertRaises(DiskIdentityRefused):
            run(transcript(disk_lines="  Disk 0    Offline 64 GB   64 GB *"))
        with self.assertRaises(DiskIdentityRefused):
            run(transcript(disk_lines="  Disk 0    Online 128 GB 128 GB *"))

    def test_wrong_guid_duplicate_id_or_external_id_refused(self):
        with self.assertRaises(DiskIdentityRefused):
            run(transcript(guid="baf784e7-6bbd-4cfb-aaac-e86c96e166ee"))
        with self.assertRaises(DiskIdentityRefused):
            run(transcript().replace("Leaving DiskPart...",
                                     "Disk ID: {"+GPT+"}\nLeaving DiskPart..."))
        with self.assertRaises(DiskIdentityRefused):
            run(transcript()+"Disk ID: {"+GPT+"}\n")

    def test_missing_selection_banner_finish_or_errors_refused(self):
        for txt in (
            transcript().replace("Disk 0 is now the selected disk.",""),
            transcript().replace("Microsoft DiskPart version","Not DiskPart version"),
            transcript().replace("Leaving DiskPart...",""),
            transcript().replace("Disk 0 is now the selected disk.",
                                 "DiskPart has encountered an error"),
            transcript().replace("Disk 0 is now the selected disk.",
                                 "There is no disk selected"),
        ):
            with self.assertRaises(DiskIdentityRefused):
                run(txt)

    def test_nonce_reorder_duplicate_or_wrong_size_refused(self):
        for txt in (
            transcript()+transcript(),
            transcript().replace("AD_W1_WINPE_BEGIN","WRONG_BEGIN"),
            transcript().replace("AD_W1_WINPE_END","WRONG_END"),
            transcript().replace("Disk 0    Online           64 GB",
                                 "Disk 0    Online          128 GB"),
        ):
            with self.assertRaises(DiskIdentityRefused):
                run(txt)

if __name__=="__main__":
    unittest.main()
