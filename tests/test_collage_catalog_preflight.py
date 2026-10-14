"""Offline source tests: preflight must reject missing pins, not launch a VM."""
import unittest
import pathlib
from scripts.check_collage_catalog_preflight import evaluate, version_inventory, URI

class CatalogPreflightTests(unittest.TestCase):
    def test_public_vendor_catalog_uses_real_master_not_nonexistent_main(self):
        # 2026-10-14 causal failure of guest run 38488438084:
        # official truenas/apps default branch = master; ?ref=main HTTP 404.
        self.assertEqual(
            URI,
            "https://api.github.com/repos/truenas/apps/contents/trains/community/minecraft?ref=master",
        )
        self.assertNotIn("?ref=main", URI)

    def test_available_exact_pin(self):
        rows=[{"name":"1.15.29","type":"dir"},{"name":"item.yaml","type":"file"}]
        v=evaluate(rows,"1.15.29")
        self.assertEqual(v["classification"],"PRE_KVM_CATALOG_VERSION_AVAILABLE")
        self.assertFalse(v["guest_catalog_observed"])
        self.assertFalse(v["world_mutated"])

    def test_upstream_retires_exact_pin(self):
        rows=[{"name":"1.15.30","type":"dir"},{"name":"item.yaml","type":"file"}]
        v=evaluate(rows,"1.15.29")
        self.assertEqual(v["classification"],"PRE_KVM_CATALOG_DRIFT")
        self.assertEqual(v["visible_versions"],["1.15.30"])
        self.assertFalse(v["live_minecraft_qualified"])

    def test_malformed_catalog_fails_closed(self):
        for value in ({}, None, [], [{"name":"1.15.29"}],
                      [{"name":"1.15.29","type":"dir"}]*2):
            with self.subTest(value=value),self.assertRaises(ValueError):
                version_inventory(value)

    def test_causal_preflight_is_in_truenas_job_not_proxmox(self):
        root=pathlib.Path(__file__).resolve().parents[1]
        yml=(root/".github/workflows/gha-kvm-system-rdte.yml").read_text()
        prox=yml.split("  proxmox-9-2:",1)[1].split("  truenas-26-beta3:",1)[0]
        guest=yml.split("  truenas-26-beta3:",1)[1]
        guard="python3 scripts/check_collage_catalog_preflight.py --expected 1.15.30"
        self.assertNotIn(guard,prox)
        self.assertIn(guard,guest)
        self.assertLess(guest.index(guard),
                        guest.index("      - name: Ensure bounded QEMU/KVM prerequisites"))

    def test_no_float_latest_pin(self):
        rows=[{"name":"1.15.30","type":"dir"}]
        for version in ("latest","1.15","1.15.29\n",None):
            with self.subTest(version=version),self.assertRaises(ValueError):
                evaluate(rows,version)

if __name__=="__main__":
    unittest.main()
