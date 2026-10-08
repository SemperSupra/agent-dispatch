import copy
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import truenas_garm_vm_pre_b4_fixture as vm

PRODUCER = "5944d1dc62b4da2a247dda9754cfe674caedf5cf"


def fixture():
    name = "garm_nested_vm_01"
    owner = {
        "schema": "semper-supra.garm-vm-owner/1",
        "managed_by": "garm-provider-truenas",
        "controller_id": "controller",
        "pool_id": "pool",
        "runner_name": "runner",
        "profile": "truenas-vm-linux-general",
    }
    marker = vm.MARKER_PREFIX + name
    flags = {key: True for key in vm.REQUIRED_TRUE}
    flags.update({key: False for key in vm.REQUIRED_FALSE})
    return {
        "schema": vm.SCHEMA,
        "producer_source": PRODUCER,
        "authority": "SemperSupra/garm-provider-truenas-private#43",
        "target": {
            "version": "26.0.0-BETA.3",
            "system_version": vm.TARGET,
            "driver": "vm-v1",
            "control_surface": "vm.*",
            "middleware_commit": vm.MIDDLEWARE,
            "required_methods": sorted(vm.REQUIRED_METHODS),
            "status": "OPEN",
        },
        "profile": "truenas-vm-linux-general",
        "template_family": "ubuntu-24.04-amd64-template",
        "template_version": "ubuntu-24.04-release-20260926-amd64",
        "template_runtime_name": vm.TEMPLATE_NAME,
        "template_source_url": vm.IMAGE_URL,
        "template_source_sha256": vm.IMAGE_SHA256,
        "expected_name": name,
        "expected_ownership": owner,
        "clone": {
            "description": "garm-provider-truenas managed VM",
            "vcpus": 4,
            "memory_bytes": 8 * 1024**3,
            "autostart": False,
        },
        "seed": {
            "run_local_token_placeholder": vm.TOKEN_PLACEHOLDER,
            "transport": "provider-owned child dataset + public filesystem.put input pipe",
            "attach_device": "owned vm.device CDROM",
            "retain_while_active": True,
            "delete_only_when_stopped": True,
            "consumption_signal_required": True,
            "consumption_marker": marker,
            "meta_data": "instance-id: owned-1",
            "user_data": "\n".join([
                vm.TOKEN_PLACEHOLDER,
                marker,
                "path: /usr/local/libexec/garm-runner-bootstrap",
                "path: /usr/local/libexec/garm-bootstrap",
                "name: garm-runner",
                "/usr/sbin/runuser -u garm-runner",
                'rm -f "$env_file"',
                "/dev/console",
            ]),
        },
        "source_oracles": flags,
        "retirement": [
            "stop VM through vm.stop", "verify STOPPED",
            "delete owned NoCloud CDROM through vm.device.delete",
            "verify seed device absence", "delete provider-owned seed dataset",
            "verify seed dataset absence",
            "delete provider-owned VM and cloned boot ZVOL",
            "verify final VM absence",
        ],
        "runner": {
            "tool_url": "https://github.com/actions/runner/releases/download/v2.336.0/test.tar.gz",
            "tool_sha256": "a" * 64,
        },
    }


class VMStaticContractTests(unittest.TestCase):
    def test_exact_fixture_is_static_only(self):
        receipt = vm.validate_fixture(fixture(), PRODUCER)
        self.assertEqual(receipt["classification"], "STATIC_CONTRACT_PASS")
        self.assertTrue(receipt["source_only"])
        self.assertFalse(receipt["vm_runtime_admitted"])
        self.assertFalse(receipt["bootstrap_consumption_observed"])
        self.assertFalse(receipt["github_jit_exercised"])
        self.assertFalse(receipt["zero_residue_runtime_proven"])
        self.assertNotIn(vm.TOKEN_PLACEHOLDER, str(receipt))

    def test_rejects_exact_version_and_producer_drift(self):
        original = fixture()
        for key, value in [
            ("system_version", "TrueNAS-25.10.7"),
            ("middleware_commit", "0" * 40),
            ("status", "PASS"),
            ("driver", "virt-instance-vm"),
        ]:
            doc = copy.deepcopy(original)
            doc["target"][key] = value
            with self.subTest(key=key), self.assertRaises(vm.FixtureError):
                vm.validate_fixture(doc, PRODUCER)
        with self.assertRaises(vm.FixtureError):
            vm.validate_fixture(original, "0" * 40)

    def test_rejects_template_and_vm_name_drift(self):
        original = fixture()
        for key, value in [
            ("template_runtime_name", "ubuntu_current"),
            ("template_source_sha256", "0" * 64),
            ("expected_name", "garm-runner-with-hyphens"),
        ]:
            doc = copy.deepcopy(original)
            doc[key] = value
            with self.subTest(key=key), self.assertRaises(vm.FixtureError):
                vm.validate_fixture(doc, PRODUCER)

    def test_rejects_unearned_claims(self):
        for flag in vm.REQUIRED_FALSE:
            doc = fixture()
            doc["source_oracles"][flag] = True
            with self.subTest(flag=flag), self.assertRaises(vm.FixtureError):
                vm.validate_fixture(doc, PRODUCER)

    def test_rejects_ownership_and_privilege_drift(self):
        doc = fixture()
        doc["expected_ownership"]["managed_by"] = "foreign-controller"
        with self.assertRaises(vm.FixtureError):
            vm.validate_fixture(doc, PRODUCER)
        doc = fixture()
        doc["clone"]["autostart"] = True
        with self.assertRaises(vm.FixtureError):
            vm.validate_fixture(doc, PRODUCER)
        doc = fixture()
        doc["seed"]["user_data"] = "missing bootstrap"
        with self.assertRaises(vm.FixtureError):
            vm.validate_fixture(doc, PRODUCER)
        doc = fixture()
        doc["seed"]["meta_data"] = vm.TOKEN_PLACEHOLDER
        with self.assertRaises(vm.FixtureError):
            vm.validate_fixture(doc, PRODUCER)

    def test_rejects_cleanup_and_missing_methods(self):
        doc = fixture()
        doc["target"]["required_methods"].remove("vm.device.delete")
        with self.assertRaises(vm.FixtureError):
            vm.validate_fixture(doc, PRODUCER)
        doc = fixture()
        doc["retirement"] = []
        with self.assertRaises(vm.FixtureError):
            vm.validate_fixture(doc, PRODUCER)


if __name__ == "__main__":
    unittest.main()
