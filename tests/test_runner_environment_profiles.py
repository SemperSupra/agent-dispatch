import copy
import json
import pathlib
import unittest

from scripts.runner_environment_profiles import RegistryError, validate

ROOT = pathlib.Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "config" / "runner-environment-profiles.json"


class RunnerEnvironmentProfileTests(unittest.TestCase):
    def load(self):
        return json.loads(REGISTRY.read_text(encoding="utf-8"))

    def test_repository_registry_is_valid(self):
        validate(self.load())

    def test_support_inheritance_fails_closed(self):
        doc = self.load()
        doc["policy"]["support_inheritance_allowed"] = True
        with self.assertRaises(RegistryError):
            validate(doc)

    def test_parity_template_cannot_smuggle_sovereign_delta(self):
        doc = self.load()
        row = next(x for x in doc["local_templates"] if x["environment_class"] == "GHA_PARITY")
        row["required_capability_deltas"] = ["gpu-compute"]
        with self.assertRaises(RegistryError):
            validate(doc)

    def test_sovereign_extension_requires_explicit_delta(self):
        doc = self.load()
        row = next(x for x in doc["local_templates"] if x["environment_class"] == "SOVEREIGN_EXTENSION")
        row["required_capability_deltas"] = []
        with self.assertRaises(RegistryError):
            validate(doc)

    def test_cloud_only_reference_cannot_claim_local_substrate(self):
        doc = self.load()
        row = next(x for x in doc["local_templates"] if x["environment_class"] == "REFERENCE_ONLY")
        row["candidate_substrates"] = ["truenas-vm"]
        with self.assertRaises(RegistryError):
            validate(doc)


if __name__ == "__main__":
    unittest.main()
