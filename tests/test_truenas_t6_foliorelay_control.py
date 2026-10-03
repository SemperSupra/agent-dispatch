#!/usr/bin/env python3
import importlib.util
import pathlib
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "truenas_middleware_foliorelay_t6_probe.py"
SPEC = importlib.util.spec_from_file_location("foliorelay_t6_probe", SCRIPT)
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MOD)

class FolioRelayT6ContractTests(unittest.TestCase):
    def test_exact_product_and_foundry_identity_is_pinned(self):
        self.assertEqual(MOD.EXPECTED_FOUNDRY_REF, "fb41afd3d112f361b8c490aeb5915a978b956b20")
        self.assertIn("@sha256:", MOD.EXPECTED_CONTROL)
        self.assertIn("@sha256:", MOD.EXPECTED_CUPS)
        self.assertEqual(MOD.DATASET, "rdtepool/foliorelay-t6")
        self.assertEqual(MOD.PUBLIC_URI, "ipp://foliorelay-t6.local:8634/printers/FolioRelay")

    def test_probe_preserves_product_oracles_and_zero_residue(self):
        text = SCRIPT.read_text(encoding="utf-8")
        for needle in (
            '"/api/v1/printer"', '"/api/v1/jobs"', 'application/pdf', 'image/urf',
            'ipptool', 'UNIRAST', '"pool.dataset.create"', '"pool.dataset.delete"',
            '"app.create"', '"app.stop"', '"app.start"', '"app.delete"',
            '"zero_residue":True', '_universal._sub._ipp._tcp.local',
            'dnssd_uuid_match', 'restart_preserved_identity_and_inbox',
        ):
            self.assertIn(needle, text)
        self.assertIn(MOD.OBSERVER_IMAGE, text)
        self.assertNotIn("avahi-publish-service", text)
        self.assertNotIn("/run/dbus", text)
        self.assertNotIn("/var/run/docker.sock", text)

    def test_observer_is_separate_host_network_app(self):
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('OBSERVER_APP_NAME = "rdte-t6-foliorelay-observer"', text)
        self.assertIn('"network_mode":"host"', text)
        self.assertIn('"entrypoint":["python3","/observer/mdns_observer.py"]', text)
        self.assertIn('"distinct_observer_context":True', text)

    def test_workflow_and_harness_route_exact_foliorelay_export(self):
        workflow=(ROOT/".github"/"workflows"/"gha-kvm-system-rdte.yml").read_text(encoding="utf-8")
        harness=(ROOT/"scripts"/"gha_kvm_truenas_rdte.sh").read_text(encoding="utf-8")
        self.assertIn("truenas_t6_product == 'foliorelay'", workflow)
        self.assertIn("export-foliorelay-t6-control.yml@" + MOD.EXPECTED_FOUNDRY_REF, workflow)
        self.assertIn("name: foliorelay-t6-beta3-control", workflow)
        self.assertIn('foundry_commit="' + MOD.EXPECTED_FOUNDRY_REF + '"', workflow)
        self.assertIn("truenas_middleware_foliorelay_t6_probe.py", harness)
        self.assertIn('FOLIORELAY_CONTROL_HOST_PORT', harness)
        self.assertIn('FOLIORELAY_IPP_HOST_PORT', harness)
        self.assertIn('FOLIORELAY_OBSERVER_HOST_PORT', harness)
        self.assertIn('--observer-port "$FOLIORELAY_OBSERVER_HOST_PORT"', harness)

    def test_probe_compiles(self):
        cp=subprocess.run([sys.executable,"-m","py_compile",str(SCRIPT)],capture_output=True,text=True)
        self.assertEqual(cp.returncode,0,cp.stderr)

if __name__ == "__main__":
    unittest.main()
