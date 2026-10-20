"""Pure-source refusal tests for non-destructive WinPE observation seed.

NO Windows PE boot, ISO download, unattended install or disk writes.
"""
from __future__ import annotations
import hashlib
import unittest
import xml.etree.ElementTree as ET

from scripts.windows_w1_winpe_observer_seed import (
    build_probe_seed, probe_batch, probe_unattend, WinPEProbeSeedRefused, U
)
from scripts.windows_w1_winpe_disk_identity import diskpart_readonly_commands

NONCE="winbotDiskProbe20261020"

class NonDestructiveSeed(unittest.TestCase):
    def test_unattend_is_only_synchronous_winpe_observation(self):
        x=build_probe_seed(NONCE)
        root=ET.fromstring(x["files"]["Autounattend.xml"])
        self.assertEqual(len(root.findall(".//{"+U+"}RunSynchronousCommand")),1)
        self.assertEqual(root.findtext(".//{"+U+"}Order"),"1")
        self.assertIn("adw1pe.cmd",root.findtext(".//{"+U+"}Path"))
        self.assertEqual(root.findtext(".//{"+U+"}UseConfigurationSet"),"true")
        self.assertIn("%configsetroot%",root.findtext(".//{"+U+"}Path"))
        self.assertNotIn("for %D",root.findtext(".//{"+U+"}Path"))
        self.assertNotIn("ADW1PE.tag",root.findtext(".//{"+U+"}Path"))
        self.assertLessEqual(len(root.findtext(".//{"+U+"}Path")),259)
        for tag in ("DiskConfiguration","ImageInstall","InstallTo","ProductKey",
                    "Credentials","UserData"):
            self.assertEqual(root.findall(".//{"+U+"}"+tag),[])
        self.assertFalse(x["windows_installation_authorized"])
        self.assertFalse(x["disk_identity_real_guest_observed"])

    def test_no_diskpart_mutations_or_native_storage_access(self):
        x=build_probe_seed(NONCE)
        commands=x["files"]["diskpart-readonly.txt"].lower().splitlines()
        self.assertEqual(commands,["list disk","select disk 0","uniqueid disk","exit"])
        script=x["files"]["adw1pe.cmd"].lower()
        self.assertIn("diskpart /s",script)
        self.assertIn("ad_w1_winpe_begin="+NONCE.lower(),script)
        self.assertIn("ad_w1_winpe_end="+NONCE.lower(),script)
        self.assertIn("> com1",script)
        self.assertIn("%systemroot%\\temp",script)
        self.assertIn("exit /b 88",script)
        for banned in ("willwipedisk","diskpart /clean","clean all","convert gpt",
                       "create partition","format fs=","uniqueid disk id=",
                       "productkey","password","powershell"):
            for name,txt in x["files"].items():
                with self.subTest(name=name,banned=banned):
                    self.assertNotIn(banned,txt.lower())

    def test_seed_file_hashes_deterministic_with_nonce(self):
        a=build_probe_seed(NONCE);b=build_probe_seed(NONCE)
        self.assertEqual(a,b)
        self.assertEqual(set(a["files"]),{"Autounattend.xml","adw1pe.cmd",
                                            "diskpart-readonly.txt"})
        for name,value in a["files"].items():
            self.assertEqual(a["file_sha256"][name],
                             hashlib.sha256(value.encode("utf-8")).hexdigest())
        self.assertEqual(a["files"]["diskpart-readonly.txt"],diskpart_readonly_commands())

    def test_no_drive_enumeration_or_marker_execution(self):
        seed=build_probe_seed(NONCE)
        self.assertEqual(seed["unique_seed_binding"],"CONFIGURATION_SET_ROOT_CANDIDATE_UNQUALIFIED")
        self.assertIs(seed["guest_configsetroot_expansion_proved"],False)
        self.assertEqual(set(seed["files"]),{"Autounattend.xml","adw1pe.cmd","diskpart-readonly.txt"})
        xml=seed["files"]["Autounattend.xml"].lower()
        self.assertIn("%configsetroot%",xml)
        self.assertNotIn("adw1pe.tag",xml)
        self.assertNotIn("for %d in",xml)
        self.assertNotIn("if exist %d:",xml)
        self.assertEqual(xml.count("runsynchronouscommand"),2)  # opening and closing XML tags

    def test_no_source_claim_of_guest_runtime(self):
        seed=build_probe_seed(NONCE)
        self.assertFalse(seed["winpe_executed"])
        self.assertFalse(seed["windows_installation_authorized"])
        self.assertFalse(seed["guest_configsetroot_expansion_proved"])

    def test_invalid_nonce_refused(self):
        for bad in ("short","contains space!" ,"a\n"*12, "!"*20, "x"*65, "",None):
            with self.subTest(bad=bad),self.assertRaises(WinPEProbeSeedRefused):
                build_probe_seed(bad)

    def test_no_windows_or_winbot_acceptance_from_source(self):
        x=build_probe_seed(NONCE)
        self.assertEqual(x["classification"],"SOURCE_ONLY_INERT_OBSERVER")
        for k in ("winpe_executed","disk_identity_real_guest_observed",
                  "windows_installation_authorized","windows_installed",
                  "winbot_guest_qualified"):
            self.assertIs(x[k],False)
        self.assertIn("RunSynchronousCommand",probe_unattend())
        self.assertIn("exit /b 88",probe_batch(NONCE))

if __name__=="__main__":
    unittest.main()
