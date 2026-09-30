#!/usr/bin/env python3
import importlib.util, json, pathlib, unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("truenas_rdte_target", ROOT/"scripts"/"truenas_rdte_target.py")
MOD=importlib.util.module_from_spec(SPEC); assert SPEC.loader; SPEC.loader.exec_module(MOD)
REG=ROOT/"config"/"truenas-rdte-targets.json"
RUN_REQUEST=ROOT/"config"/"truenas-rdte-run-request.json"

class TargetRegistryTests(unittest.TestCase):
    def setUp(self):
        self.targets=MOD.load_registry(REG)
    def test_exact_supported_matrix(self):
        self.assertEqual(set(self.targets), {"25.04.1","25.10.7","26.0.0-BETA.3"})
    def test_exact_source_anchors(self):
        self.assertEqual(self.targets["25.04.1"]["middleware_commit"], "74ab5a2d373be4097dece257d00e1086376333ba")
        self.assertEqual(self.targets["25.10.7"]["middleware_commit"], "8ede398839710e56893d88ce85088139d8fab18e")
        self.assertEqual(self.targets["26.0.0-BETA.3"]["middleware_commit"], "81e1265a86083888ba94a2bdfc02ff5c9c5ef6a3")
    def test_vendor_media_is_exact_and_has_digest_sidecar(self):
        for version,target in self.targets.items():
            self.assertIn(version, target["iso_name"])
            self.assertEqual(target["sha256_url"], target["iso_url"]+".sha256")
            lower=target["iso_url"].lower()
            self.assertNotIn("latest", lower)
            self.assertNotIn("nightly", lower)
            self.assertNotIn("master+", lower)
    def test_exact_installed_version_identity_for_stable_target(self):
        self.assertEqual(self.targets["25.10.7"]["system_version"], "TrueNAS-25.10.7")

    def test_exact_installed_version_identity_for_legacy_target(self):
        self.assertEqual(self.targets["25.04.1"]["system_version"], "TrueNAS-25.04.1")

    def test_apps_gate_deltas_are_not_normalized_away(self):
        self.assertEqual(self.targets["25.04.1"]["ha_apps_gate"], "system.license:JAILS")
        self.assertEqual(self.targets["25.10.7"]["ha_apps_gate"], "system.license:JAILS")
        self.assertEqual(self.targets["26.0.0-BETA.3"]["ha_apps_gate"], "system.feature_enabled:APPS")
    def test_unknown_exact_version_fails_closed(self):
        with self.assertRaises(MOD.TargetError):
            targets=self.targets
            if "26.0.0-RC.1" not in targets:
                raise MOD.TargetError("exact TrueNAS target is not registered: 26.0.0-RC.1")


    def test_run_request_is_exact_registered_target(self):
        request=json.loads(RUN_REQUEST.read_text(encoding="utf-8"))
        self.assertEqual(request["schema"], "gha-kvm-truenas-run-request/v1")
        self.assertIn(request["rung"], {"t0","t1","t2","t3","t4","t5","t6"})
        self.assertIn(request["version"], self.targets)
        target=self.targets[request["version"]]
        self.assertEqual(request["authority_issue"], target["authority_issue"])
        if request["rung"] == "t6":
            self.assertIn(request.get("product", "litellm"), {"litellm","wow-sidecar"})
        if request.get("product") == "wow-sidecar":
            self.assertEqual(request.get("consumer_authority_issue"), 276)
        self.assertNotIn("latest", request["version"].lower())
        self.assertNotIn("nightly", request["version"].lower())


if __name__=="__main__":
    unittest.main()
