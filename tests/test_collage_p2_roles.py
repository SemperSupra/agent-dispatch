"""Source-only checks for the TrueNAS 25.04 privilege.roles response contract."""
import unittest

from scripts.truenas_middleware_collage_readback_p2 import (
    ObservationError, available_role_names, provision_guest_readonly,
)


class RolesTests(unittest.TestCase):
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
