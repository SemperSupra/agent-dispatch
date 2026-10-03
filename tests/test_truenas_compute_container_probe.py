import unittest

from scripts.truenas_compute_container_probe import (
    ProbeError,
    build_create_payload,
    method_shapes,
    normalize_system_version,
    observed_state,
    update_payload,
)


class ContainerProbeContractTests(unittest.TestCase):
    def test_version_normalization(self):
        self.assertEqual(normalize_system_version("TrueNAS-25.04.1"), "25.04.1")
        self.assertEqual(normalize_system_version("26.0.0-BETA.3"), "26.0.0-BETA.3")

    def test_legacy_create_is_native_incus_container(self):
        payload = build_create_payload(
            "truenas-virt-incus-container",
            "rdte-c0",
            "nonce",
            legacy_image="ubuntu/24.04",
        )
        self.assertEqual(payload["instance_type"], "CONTAINER")
        self.assertEqual(payload["source_type"], "IMAGE")
        self.assertFalse(payload["autostart"])
        self.assertEqual(payload["environment"]["RDTE_NONCE"], "nonce")

    def test_lxc_create_uses_public_image_tuple_and_safe_idmap(self):
        payload = build_create_payload(
            "truenas-container-lxc",
            "rdte-c0",
            "nonce",
            image_name="ubuntu",
            image_version="24.04",
        )
        self.assertEqual(payload["image"], {"name": "ubuntu", "version": "24.04"})
        self.assertEqual(payload["idmap"], {"type": "DEFAULT"})
        self.assertEqual(payload["capabilities_policy"], "DEFAULT")
        self.assertFalse(payload["autostart"])

    def test_missing_image_identity_fails(self):
        with self.assertRaises(ProbeError):
            build_create_payload("truenas-virt-incus-container", "x", "n")
        with self.assertRaises(ProbeError):
            build_create_payload("truenas-container-lxc", "x", "n", image_name="ubuntu")

    def test_update_generation_is_adapter_specific(self):
        self.assertEqual(
            update_payload("truenas-virt-incus-container", "n")["environment"]["RDTE_GENERATION"],
            "2",
        )
        self.assertEqual(
            update_payload("truenas-container-lxc", "n")["initenv"]["RDTE_GENERATION"],
            "2",
        )

    def test_state_normalizes_legacy_and_lxc(self):
        self.assertEqual(observed_state({"status": "RUNNING"}), "RUNNING")
        self.assertEqual(observed_state({"status": {"state": "RUNNING"}}), "RUNNING")
        self.assertEqual(observed_state(None), "ABSENT")

    def test_method_shapes_never_use_private_shell(self):
        legacy = method_shapes("truenas-virt-incus-container", "x")
        self.assertEqual(legacy["query"][0], "virt.instance.query")
        self.assertNotIn("get_shell", {v[0] for v in legacy.values()})
        lxc = method_shapes("truenas-container-lxc", "x", 7)
        self.assertEqual(lxc["start"][0], "container.start")
        self.assertNotIn("nsenter", {v[0] for v in lxc.values()})


if __name__ == "__main__":
    unittest.main()
