import unittest

from scripts.compute_materialization_contract import ContractError, choose_adapter, semantic_plan, validate


def registry():
    return {
        "schema": "semper-supra.compute-materialization-targets/v1",
        "platforms": {
            "truenas": {
                "targets": [
                    {
                        "version": "25.04.1",
                        "source_fingerprint": {"virt.instance": "a" * 40},
                        "api_schema_fingerprint": {"virt_instance": {"path": "api/v25_04_0/virt_instance.py", "blob_sha": "d" * 40}},
                        "container_adapters": [{
                            "id": "truenas-virt-incus-container",
                            "source_api_family": "v25_04_0",
                            "required_methods": ["virt.instance.query", "virt.instance.create", "virt.instance.image_choices"],
                            "image_discovery": {
                                "method": "virt.instance.image_choices",
                                "source": "https://images.linuxcontainers.org",
                                "selection": {"alias": "debian/trixie"},
                            },
                            "restart_semantics": "native",
                        }],
                        "vm_adapters": [{
                            "id": "truenas-virt-incus-vm",
                            "source_api_family": "v25_04_0",
                            "required_methods": ["virt.instance.query", "virt.instance.create"],
                        }],
                    },
                    {
                        "version": "26.0.0-BETA.3",
                        "source_fingerprint": {"container.container": "b" * 40},
                        "api_schema_fingerprint": {"container": {"path": "api/v26_0_0/container.py", "blob_sha": "e" * 40}, "vm": {"path": "api/v26_0_0/vm.py", "blob_sha": "f" * 40}},
                        "container_adapters": [{
                            "id": "truenas-container-lxc",
                            "source_api_family": "v26_0_0",
                            "required_methods": ["container.query", "container.create", "container.image.query_registry"],
                            "image_discovery": {
                                "method": "container.image.query_registry",
                                "source": "https://images.sys.truenas.net/streams",
                                "selection": {"name": "ubuntu:noble:amd64:default"},
                            },
                            "restart_semantics": "compose-stop-start",
                        }],
                        "vm_adapters": [{
                            "id": "truenas-vm-libvirt",
                            "source_api_family": "v26_0_0",
                            "preferred": True,
                            "required_methods": ["vm.query", "vm.create"],
                        }],
                    },
                ]
            },
            "proxmox": {
                "targets": [
                    {
                        "version": "9.2-1",
                        "source_fingerprint": {"iso_sha256": "c" * 64},
                        "container_adapters": [{
                            "id": "proxmox-lxc-rest",
                            "required_api_templates": ["POST /nodes/{node}/lxc"],
                        }],
                        "vm_adapters": [{
                            "id": "proxmox-vm-rest",
                            "required_api_templates": ["POST /nodes/{node}/qemu"],
                        }],
                    }
                ],
                "candidate_targets": [
                    {
                        "version": "9.1-1",
                        "iso_sha256": "d" * 64,
                        "state": "source-profile-open",
                    }
                ],
            },
        },
    }


class ContractTests(unittest.TestCase):
    def test_registry_contract(self):
        self.assertEqual(validate(registry())["status"], "PASS")

    def test_missing_truenas_api_schema_fails_closed(self):
        data = registry()
        del data["platforms"]["truenas"]["targets"][0]["api_schema_fingerprint"]
        with self.assertRaises(ContractError):
            validate(data)

    def test_missing_container_image_discovery_fails_closed(self):
        data = registry()
        del data["platforms"]["truenas"]["targets"][0]["container_adapters"][0]["image_discovery"]
        with self.assertRaises(ContractError):
            validate(data)

    def test_2504_selects_legacy_incus_container(self):
        a = choose_adapter(
            registry(), "truenas", "25.04.1", "container",
            {"virt.instance.query", "virt.instance.create", "virt.instance.image_choices"},
        )
        self.assertEqual(a["id"], "truenas-virt-incus-container")

    def test_26_selects_lxc_container(self):
        a = choose_adapter(
            registry(), "truenas", "26.0.0-BETA.3", "container",
            {"container.query", "container.create", "container.image.query_registry"},
        )
        self.assertEqual(a["id"], "truenas-container-lxc")
        self.assertIn("stop+start", semantic_plan("container", a))

    def test_missing_observed_method_fails_closed(self):
        with self.assertRaises(ContractError):
            choose_adapter(registry(), "truenas", "26.0.0-BETA.3", "vm", {"vm.query"})

    def test_proxmox_selects_exact_profile_adapter(self):
        a = choose_adapter(registry(), "proxmox", "9.2-1", "vm", None)
        self.assertEqual(a["id"], "proxmox-vm-rest")

    def test_discovery_candidate_is_not_apply_admitted(self):
        with self.assertRaises(ContractError):
            choose_adapter(registry(), "proxmox", "9.1-1", "vm", None)

    def test_unknown_target_fails(self):
        with self.assertRaises(ContractError):
            choose_adapter(registry(), "proxmox", "8.4-1", "vm", None)


if __name__ == "__main__":
    unittest.main()
