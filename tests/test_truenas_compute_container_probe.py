import unittest

from scripts.truenas_compute_container_probe import (
    ProbeError,
    build_create_payload,
    method_shapes,
    normalize_system_version,
    observed_state,
    resolve_image_identity,
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

    def test_legacy_image_resolution_requires_exact_admitted_alias(self):
        adapter = {
            "id": "truenas-virt-incus-container",
            "image_discovery": {
                "method": "virt.instance.image_choices",
                "request": {"remote": "LINUX_CONTAINERS"},
                "source": "https://images.linuxcontainers.org",
                "selection": {"alias": "debian/trixie", "instance_type": "CONTAINER", "arch": "amd64"},
            },
        }
        def call(method, params):
            self.assertEqual(method, "virt.instance.image_choices")
            self.assertEqual(params, [{"remote": "LINUX_CONTAINERS"}])
            return {"debian/trixie": {"instance_types": ["CONTAINER", "VM"], "archs": ["amd64"]}}
        resolved, evidence = resolve_image_identity(adapter, call)
        self.assertEqual(resolved, {"legacy_image": "debian/trixie"})
        self.assertEqual(evidence["selected"]["alias"], "debian/trixie")

    def test_lxc_image_resolution_retains_exact_returned_version(self):
        adapter = {
            "id": "truenas-container-lxc",
            "image_discovery": {
                "method": "container.image.query_registry",
                "source": "https://images.sys.truenas.net/streams",
                "selection": {"name": "ubuntu:noble:amd64:default", "version_policy": "last-returned-exact"},
            },
        }
        def call(method, params):
            self.assertEqual(method, "container.image.query_registry")
            self.assertEqual(params, [])
            return [{
                "name": "ubuntu:noble:amd64:default",
                "versions": [{"version": "20261001"}, {"version": "20261005"}],
            }]
        resolved, evidence = resolve_image_identity(adapter, call)
        self.assertEqual(resolved, {
            "image_name": "ubuntu:noble:amd64:default",
            "image_version": "20261005",
        })
        self.assertEqual(evidence["selected"]["version"], "20261005")

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
