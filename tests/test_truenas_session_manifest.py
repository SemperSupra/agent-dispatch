#!/usr/bin/env python3
import importlib.util
import json
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "truenas_session_manifest", ROOT / "scripts" / "truenas_session_manifest.py"
)
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MOD)
TARGETS = ROOT / "config" / "truenas-rdte-targets.json"
PROVIDERS = ROOT / "config" / "truenas-capsule-providers.json"

def base_manifest():
    doc = {
        "schema": "truenas-session/v1",
        "session_id": "tn-26-beta3-session-contract-001",
        "version": "26.0.0-BETA.3",
        "authority": {
            "repository": "SemperSupra/agent-dispatch-private",
            "issue": 480
        },
        "budget": {
            "guest_memory_mib": 8192,
            "download_mib": 1536,
            "timeout_minutes": 45
        },
        "pool": {"name": "rdtepool", "data_disks": 2},
        "capsules": [{
            "schema": "truenas-capsule/v1",
            "id": "official-catalog-control-001",
            "kind": "official-catalog-control",
            "provider": "official-catalog-t6",
            "authority": {
                "repository": "SemperSupra/truenas-app-foundry-private",
                "issue": 281
            },
            "exact": {
                "source_ref": "60d56cc1752bc825cb232d72b397ff17fe6d47c4",
                "artifact": "official-catalog-truenas-t6-control"
            },
            "namespace": "rdte-official-catalog-001",
            "ports": [18080],
            "requirements": ["apps", "zfs-pool", "native-catalog"],
            "resources": {
                "memory_mib": 1024,
                "download_mib": 512,
                "estimated_minutes": 10
            },
            "phases": {
                "setup": True, "apply": True, "verify": True, "cleanup": True
            },
            "oracle": "native catalog lifecycle readback plus zero-residue cleanup",
            "receipt_contract": "truenas-capsule-receipt/v1",
            "retry_policy": "read-only-reconcile",
            "mutating": True,
            "cleanup_required": True,
            "dependencies": []
        }]
    }
    doc["manifest_sha256"] = MOD.manifest_digest(doc)
    return doc

class SessionManifestTests(unittest.TestCase):
    def write(self, doc):
        tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        with tmp:
            json.dump(doc, tmp, indent=2, sort_keys=True)
            tmp.write("\n")
        path = pathlib.Path(tmp.name)
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        return path

    def validate(self, doc):
        doc["manifest_sha256"] = MOD.manifest_digest(doc)
        return MOD.validate_manifest(self.write(doc), TARGETS, PROVIDERS)

    def test_valid_single_capsule_manifest(self):
        result = self.validate(base_manifest())
        self.assertEqual(result["capsule_count"], 1)
        self.assertEqual(result["mutating_capsule_count"], 1)
        self.assertEqual(result["version"], "26.0.0-BETA.3")

    def test_manifest_hash_fails_closed_on_drift(self):
        doc = base_manifest()
        path = self.write(doc)
        loaded = json.loads(path.read_text())
        loaded["capsules"][0]["namespace"] = "rdte-mutated-after-lock"
        path.write_text(json.dumps(loaded), encoding="utf-8")
        with self.assertRaisesRegex(MOD.SessionError, "manifest_sha256 mismatch"):
            MOD.validate_manifest(path, TARGETS, PROVIDERS)

    def test_unknown_target_fails_closed(self):
        doc = base_manifest()
        doc["version"] = "26.0.0-RC.1"
        with self.assertRaisesRegex(MOD.SessionError, "not registered"):
            self.validate(doc)

    def test_unknown_provider_fails_closed(self):
        doc = base_manifest()
        doc["capsules"][0]["provider"] = "invented-provider"
        with self.assertRaisesRegex(MOD.SessionError, "not registered"):
            self.validate(doc)

    def test_mutating_capsule_requires_cleanup(self):
        doc = base_manifest()
        doc["capsules"][0]["cleanup_required"] = False
        with self.assertRaisesRegex(MOD.SessionError, "must require cleanup"):
            self.validate(doc)

    def test_duplicate_namespace_rejected(self):
        doc = base_manifest()
        second = json.loads(json.dumps(doc["capsules"][0]))
        second["id"] = "official-catalog-control-002"
        second["ports"] = [18081]
        doc["capsules"].append(second)
        with self.assertRaisesRegex(MOD.SessionError, "namespaces must be unique"):
            self.validate(doc)

    def test_global_port_collision_rejected(self):
        doc = base_manifest()
        second = json.loads(json.dumps(doc["capsules"][0]))
        second["id"] = "official-catalog-control-002"
        second["namespace"] = "rdte-official-catalog-002"
        doc["capsules"].append(second)
        with self.assertRaisesRegex(MOD.SessionError, "ports must be globally unique"):
            self.validate(doc)

    def test_resource_budget_rejected_before_runtime(self):
        doc = base_manifest()
        doc["capsules"][0]["resources"]["estimated_minutes"] = 46
        with self.assertRaisesRegex(MOD.SessionError, "estimated time exceeds"):
            self.validate(doc)

    def test_dependency_cycle_rejected(self):
        doc = base_manifest()
        first = doc["capsules"][0]
        second = json.loads(json.dumps(first))
        second["id"] = "official-catalog-control-002"
        second["namespace"] = "rdte-official-catalog-002"
        second["ports"] = [18081]
        first["dependencies"] = [second["id"]]
        second["dependencies"] = [first["id"]]
        doc["capsules"].append(second)
        with self.assertRaisesRegex(MOD.SessionError, "dependency cycle"):
            self.validate(doc)

    def test_provider_registry_wraps_existing_probes(self):
        registry = json.loads(PROVIDERS.read_text(encoding="utf-8"))
        expected = {
            "litellm-t6": "scripts/truenas_middleware_litellm_t6_probe.py",
            "wow-sidecar-t6": "scripts/truenas_middleware_wow_sidecar_t6_probe.py",
            "garm-t6": "scripts/truenas_middleware_garm_t6_probe.py",
            "official-catalog-t6": "scripts/truenas_middleware_official_catalog_t6_probe.py",
            "foliorelay-t6": "scripts/truenas_middleware_foliorelay_t6_probe.py"
        }
        actual = {item["id"]: item["probe"] for item in registry["providers"]}
        self.assertEqual(actual, expected)
        for probe in actual.values():
            self.assertTrue((ROOT / probe).is_file(), probe)

if __name__ == "__main__":
    unittest.main()
