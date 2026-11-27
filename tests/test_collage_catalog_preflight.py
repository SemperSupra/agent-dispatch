"""Offline source tests: preflight must reject missing pins, not launch a VM."""
import unittest
import pathlib
import urllib.error
from scripts.check_collage_catalog_preflight import (evaluate, version_inventory,
                                                       fixed_catalog_failure_reason, URI)

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

    def test_live_native_source_contract_separate_from_retired_paper(self):
        rows=[{"name":"1.15.33","type":"dir"},{"name":"item.yaml","type":"file"}]
        native=evaluate(rows,"1.15.33")
        paper=evaluate(rows,"1.15.30")
        self.assertEqual(native["classification"],"PRE_KVM_CATALOG_VERSION_AVAILABLE")
        self.assertEqual(paper["classification"],"PRE_KVM_CATALOG_DRIFT")
        self.assertFalse(native["guest_catalog_observed"])
        self.assertFalse(native["live_minecraft_qualified"])
        workflow=(pathlib.Path(__file__).resolve().parents[1]/
                  ".github/workflows/official-minecraft-catalog-preflight.yml").read_text()
        self.assertIn("python3 scripts/check_collage_catalog_preflight.py --expected 1.15.33",workflow)
        self.assertIn('assert "1.15.30" not in v["visible_versions"]',workflow)

    def test_catalog_http_and_transport_are_inconclusive_not_retired(self):
        # The OP4K-018 standalone cheap CI returned exit 3 (not version drift).
        # Classify without copying URLs, GitHub error bodies, tokens or traces.
        cases = (
            (urllib.error.HTTPError("https://private.example/SECRET", 403,
                                    "SECRET", None, None),
             "OFFICIAL_CATALOG_HTTP_THROTTLED_OR_FORBIDDEN"),
            (urllib.error.HTTPError("https://private.example/SECRET", 429,
                                    "SECRET", None, None),
             "OFFICIAL_CATALOG_HTTP_THROTTLED_OR_FORBIDDEN"),
            (urllib.error.HTTPError("https://private.example/SECRET", 404,
                                    "SECRET", None, None),
             "OFFICIAL_CATALOG_HTTP_NOT_FOUND"),
            (urllib.error.HTTPError("https://private.example/SECRET", 502,
                                    "SECRET", None, None),
             "OFFICIAL_CATALOG_HTTP_OTHER"),
            (urllib.error.URLError("SECRET-transport"),
             "OFFICIAL_CATALOG_TRANSPORT_UNAVAILABLE"),
            (OSError("SECRET-network"), "OFFICIAL_CATALOG_TRANSPORT_UNAVAILABLE"),
            (ValueError("SECRET-json"), "OFFICIAL_CATALOG_RESPONSE_INVALID"),
        )
        for exc, code in cases:
            with self.subTest(code=code):
                category = fixed_catalog_failure_reason(exc)
                self.assertEqual(category, code)
                self.assertNotIn("SECRET", category)

    def test_no_float_latest_pin(self):
        rows=[{"name":"1.15.30","type":"dir"}]
        for version in ("latest","1.15","1.15.29\n",None):
            with self.subTest(version=version),self.assertRaises(ValueError):
                evaluate(rows,version)

if __name__=="__main__":
    unittest.main()
