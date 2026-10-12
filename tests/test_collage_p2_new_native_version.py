"""Cheap negative and isolation tests for new opt-in COLLAGE catalog product."""
import pathlib
import unittest

from scripts.truenas_middleware_minecraft_t6_probe import (
    CATALOG_PROFILES, EXPECTED_APPS_COMMIT, EXPECTED_IMAGE_FRAGMENT,
    qualified_native_image,
)

ROOT=pathlib.Path(__file__).resolve().parents[1]
NEW_COMMIT="559b9fe85212c800bc6770f152a65211df137a44"
NEW_IMAGE=("ghcr.io/itzg/minecraft-server:2026.10.0-java21@sha256:"
           "d4057e7019e9b19f25e039d4a204cc502e1a112d1a2305966a534f3d7079e644")
OLD_COMMIT="bb96ef6fd8c2708765012a4a3ca3739370a4f92c"

class CatalogProfilesTests(unittest.TestCase):
    def test_existing_legacy_default_does_not_migrate(self):
        self.assertEqual(EXPECTED_APPS_COMMIT, OLD_COMMIT)
        self.assertEqual(CATALOG_PROFILES["1.15.29"]["apps_commit"], OLD_COMMIT)
        self.assertEqual(CATALOG_PROFILES["1.15.29"]["image"], EXPECTED_IMAGE_FRAGMENT)
        self.assertNotEqual(CATALOG_PROFILES["1.15.29"]["image"], NEW_IMAGE)

    def test_new_exact_image_match_and_old_image_refusal(self):
        self.assertEqual(CATALOG_PROFILES["1.15.30"],
                         {"apps_commit": NEW_COMMIT, "image": NEW_IMAGE})
        old=EXPECTED_IMAGE_FRAGMENT
        self.assertEqual(qualified_native_image({"active_workloads": {
            "images": [NEW_IMAGE]}}, image_fragment=NEW_IMAGE), NEW_IMAGE)
        self.assertIsNone(qualified_native_image({"active_workloads": {
            "images": [old]}}, image_fragment=NEW_IMAGE))

    def test_runner_binds_real_new_producer_separately(self):
        workflow=(ROOT/".github/workflows/gha-kvm-system-rdte.yml").read_text()
        shell=(ROOT/"scripts/gha_kvm_truenas_rdte.sh").read_text()
        self.assertIn("foundry-collage-paper-11530-t6-control:", workflow)
        self.assertIn("export-minecraft-paper-11530-t6-control.yml@", workflow)
        self.assertIn("403321031b6d4e66aa64a8299fd7621eee290b0d", workflow)
        self.assertIn("minecraft-paper-11530-truenas-t6-candidate", workflow)
        self.assertIn("--native-catalog-profile", shell)
        self.assertIn('"1.15.30"', shell)
        self.assertIn("python3 scripts/check_collage_catalog_preflight.py --expected 1.15.30", workflow)
        self.assertIn("needs['foundry-collage-paper-11530-t6-control'].result == 'success'", workflow)


if __name__=="__main__":
    unittest.main()
