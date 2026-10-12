"""Cheap source/contract tests for COLLAGE P2 disposable TrueNAS observer.

These tests DO NOT impersonate a real TrueNAS guest or satisfy the live oracle.
"""
from __future__ import annotations

import copy
import pathlib
import subprocess
import unittest

from scripts.assert_collage_p2_receipt import check

ROOT = pathlib.Path(__file__).resolve().parents[1]


class CollageP2SourceTests(unittest.TestCase):
    def test_success_requires_real_native_guest_receipt(self):
        with self.assertRaisesRegex(ValueError, "root contract"):
            check({})
        with self.assertRaisesRegex(ValueError, "root failed"):
            check({
                "contract": "gha-kvm-system-lab/v1",
                "target": {"version": "25.04.1", "rung": "T6", "product": "truenas"},
                "classification": "HARNESS_FAILURE", "oracleSatisfied": False,
            })

    def test_paper_success_is_not_collage_readback_success(self):
        native = {
            "contract": "gha-kvm-system-lab/v1",
            "target": {"version": "25.04.1", "rung": "T6", "product": "truenas"},
            "classification": "SUPPORTED", "oracleSatisfied": True,
            "foundry_materialization": {
                "schema": "truenas-minecraft-paper-t6/v1",
                "classification": "SUPPORTED", "oracleSatisfied": True,
                "catalog_version_verified": True,
                "foundry_ref": "403321031b6d4e66aa64a8299fd7621eee290b0d",
                "catalog_discovery": {
                    "requested_version": "1.15.30",
                    "upstream_apps_commit": "559b9fe85212c800bc6770f152a65211df137a44",
                },
                "image_digest_qualification": "SOURCE_AND_GUEST_REF_MATCH",
                "observed_image_reference": "ghcr.io/itzg/minecraft-server:2026.10.0-java21@sha256:d4057e7019e9b19f25e039d4a204cc502e1a112d1a2305966a534f3d7079e644",
                "world_retained_on_delete": True,
                "world_rebound_after_reinstall": True,
                "cleanup": {"zero_residue": True, "app_absent": True,
                            "owned_world_dataset_absent": True},
                "readiness": {key: {
                    "protocol": {"oracleSatisfied": True, "server_protocol": 774,
                                 "server_implementation": "paper"},
                    "level": {"size": 123},
                } for key in ("first", "restart", "redeploy", "reinstall")},
            },
        }
        with self.assertRaisesRegex(ValueError, "observation missing"):
            check(native)
        fake = copy.deepcopy(native)
        fake["foundry_materialization"]["collage_readback"] = {
            "schema": "semper-supra.collage-native-readback-p2/1",
            "classification": "PROVIDER_READBACK_MATCH",
            "source_sha": "fbda94f3fea0a216ddd9c35b38a09d325bed3640",
            "native_app": "rdte-t6-minecraft-paper",
            "service_id": "11111111-1111-4111-8111-111111111111",
            "ownership_fields_matched": 6,
            "credential_scope": "FULL_ADMIN",
            "transport": "isolated_guest_tls_verified",
            "observation_mutation_count": 0,
            "world_activated": False,
            "cloudnet_adoption_executed": False,
            "physical_true_nas_mutated": False,
            "tls_cert_sha256": "a" * 64,
        }
        with self.assertRaisesRegex(ValueError, "observation missing"):
            check(fake)
        fake["foundry_materialization"]["collage_readback"]["credential_scope"] = "APPS_READ"
        check(fake)  # Only pure receipt predicate; NEVER live product acceptance.
        fake["foundry_materialization"]["collage_readback"]["observation_mutation_count"] = 1
        with self.assertRaisesRegex(ValueError, "observation missing"):
            check(fake)

    def test_old_catalog_and_image_cannot_fake_new_collage_p2(self):
        native = {
            "contract": "gha-kvm-system-lab/v1",
            "target": {"version": "25.04.1", "rung": "T6", "product": "truenas"},
            "classification": "SUPPORTED", "oracleSatisfied": True,
            "foundry_materialization": {
                "schema": "truenas-minecraft-paper-t6/v1",
                "classification": "SUPPORTED", "oracleSatisfied": True,
                "catalog_version_verified": True,
                "foundry_ref": "2cc7e1fe3772f8c532e933b3d7832e6cf985db4e",
                "catalog_discovery": {"requested_version": "1.15.29",
                                      "upstream_apps_commit":
                                      "bb96ef6fd8c2708765012a4a3ca3739370a4f92c"},
                "image_digest_qualification": "SOURCE_AND_GUEST_REF_MATCH",
                "observed_image_reference": "ghcr.io/itzg/minecraft-server:2026.9.2-java21@sha256:edf50d431ddc6f73929368e82f4334a405796874f7b0ae11f1edcbb267d670aa",
                "world_retained_on_delete": True,
                "world_rebound_after_reinstall": True,
            },
        }
        with self.assertRaisesRegex(ValueError, "new immutable native catalog"):
            check(native)

    def test_existing_paper_fixture_is_opt_in_unchanged(self):
        paper = (ROOT / "scripts/truenas_middleware_minecraft_t6_probe.py").read_text()
        shell = (ROOT / "scripts/gha_kvm_truenas_rdte.sh").read_text()
        workflow = (ROOT / ".github/workflows/gha-kvm-system-rdte.yml").read_text()
        helper = (ROOT / "scripts/truenas_middleware_collage_readback_p2.py").read_text()
        self.assertIn("if a.collage_source_dir is not None:", paper)
        self.assertIn('if [[ "$T6_PRODUCT" == "collage-native-paper" ]]; then', shell)
        self.assertIn('--collage-source-ref "fbda94f3fea0a216ddd9c35b38a09d325bed3640"', shell)
        self.assertIn("ref: fbda94f3fea0a216ddd9c35b38a09d325bed3640", workflow)
        self.assertIn('"roles": ["APPS_READ"]', helper)
        self.assertIn('"web_shell": False', helper)
        self.assertIn('env["SSL_CERT_FILE"]', helper)
        self.assertIn("observation_mutation_count", helper)
        self.assertNotIn("InsecureSkipVerify: true", helper)

    def test_bash_static_syntax(self):
        for path in ("scripts/gha_kvm_truenas_rdte.sh",):
            p = subprocess.run(["bash", "-n", str(ROOT / path)],
                               capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)


if __name__ == "__main__":
    unittest.main()
