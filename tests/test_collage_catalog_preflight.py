"""Offline source tests: preflight must reject missing pins, not launch a VM."""
import unittest
from scripts.check_collage_catalog_preflight import evaluate, version_inventory

class CatalogPreflightTests(unittest.TestCase):
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

    def test_no_float_latest_pin(self):
        rows=[{"name":"1.15.30","type":"dir"}]
        for version in ("latest","1.15","1.15.29\n",None):
            with self.subTest(version=version),self.assertRaises(ValueError):
                evaluate(rows,version)

if __name__=="__main__":
    unittest.main()
