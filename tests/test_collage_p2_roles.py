"""Source-only checks for the TrueNAS 25.04 privilege.roles response contract."""
import unittest

from scripts.truenas_middleware_collage_readback_p2 import (
    ObservationError, available_role_names, provision_guest_readonly,
    exact_source_readback_request, VANILLA263_OWNER, VANILLA263_WORLD,
)


class RolesTests(unittest.TestCase):
    def test_native_vanilla263_source_readback_mode_exact_and_nonplayable(self):
        source = {
            "request_id": "original-source",
            "target": {"provider": "truenas"},
            "artifact": {"kind": "world-save", "sha256": "a" * 64},
        }
        native,app,world = exact_source_readback_request(source, profile="vanilla263")
        self.assertEqual(app,VANILLA263_OWNER)
        self.assertEqual(world,VANILLA263_WORLD)
        self.assertEqual(native["target"]["deployment_id"], "rdte-t6-minecraft-vanilla-263")
        self.assertEqual(native["target"]["backend"], "vanilla")
        self.assertEqual(native["target"]["minecraft_version"], "26.3")
        self.assertEqual(native["target"]["world_id"], "lantern-rdte")
        self.assertEqual(native["target"]["service_id"], "11111111-1111-4111-8111-111111111111")
        self.assertEqual(native["artifact"]["kind"], "datapack")
        self.assertEqual(native["artifact"]["minecraft_version"], "26.3")
        self.assertEqual(native["artifact"]["world_id"], "lantern-rdte")
        self.assertEqual(source["target"], {"provider": "truenas"})
        self.assertEqual(source["artifact"]["kind"], "world-save")
        paper,oldapp,oldworld = exact_source_readback_request(source, profile="paper")
        self.assertEqual(oldapp,"rdte-t6-minecraft-paper")
        self.assertEqual(oldworld,"world-rdte-001")
        self.assertEqual(paper["artifact"]["kind"],"world-save")
        with self.assertRaisesRegex(ObservationError,"COLLAGE_READBACK_PROFILE_UNSUPPORTED"):
            exact_source_readback_request(source,profile="operations")

    def test_role_descriptors_are_an_array(self):
        rows = [
            {"name": "APPS_READ", "includes": [], "builtin": False, "stig": None},
            {"name": "READONLY_ADMIN", "includes": ["APPS_READ"],
             "builtin": True, "stig": None},
        ]
        self.assertEqual(available_role_names(rows), {"APPS_READ", "READONLY_ADMIN"})

    def test_reject_schema_drift(self):
        for rows in ({"APPS_READ": {}}, None, [{"name": "APPS_READ"}],
                     [{"name": "APPS_READ", "includes": "string"}],
                     [{"name": "APPS_READ", "includes": []},
                      {"name": "APPS_READ", "includes": []}]):
            with self.subTest(rows=rows), self.assertRaises(ObservationError):
                available_role_names(rows)

    def test_unknown_role_does_not_provision(self):
        methods = []

        def only_discovery(method, params):
            methods.append(method)
            if method == "privilege.roles":
                return [{"name": "POOL_READ", "includes": []}]
            if method in ("user.query", "privilege.query"):
                return []
            raise AssertionError("unexpected method")
        with self.assertRaisesRegex(ObservationError, "APPS_READ_ROLE_NOT_AVAILABLE"):
            provision_guest_readonly(only_discovery)
        self.assertEqual(methods,
                         ["user.query", "privilege.query", "privilege.roles"])


if __name__ == "__main__":
    unittest.main()
