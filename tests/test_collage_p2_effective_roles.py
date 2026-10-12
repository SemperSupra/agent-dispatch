"""Pure request/response policy checks; never claims a running TrueNAS guest."""
import unittest

from scripts.truenas_middleware_collage_readback_p2 import (
    ObservationError, provision_guest_readonly,
)

ROLE = "APPS_READ"
USER = "collage_p2_observer"
PRIVILEGE = "collage-p2-apps-read"
GROUP_ID = 1013


def authority_responses(*, primary_roles=None, user_roles=None,
                        user_group_id=GROUP_ID, privilege_roles=None):
    primary_roles = [ROLE] if primary_roles is None else primary_roles
    user_roles = [ROLE] if user_roles is None else user_roles
    privilege_roles = [ROLE] if privilege_roles is None else privilege_roles
    responses = [
        ("user.query", []),
        ("privilege.query", []),
        ("privilege.roles", [{"name": ROLE, "includes": []}]),
        ("user.create", {"username": USER, "group": {"id": GROUP_ID}}),
        ("privilege.create", {"name": PRIVILEGE, "roles": privilege_roles}),
        ("group.query", {"id": GROUP_ID, "roles": primary_roles}),
        ("user.query", {"username": USER, "group": {"id": user_group_id},
                        "roles": user_roles}),
        ("api_key.create", {"key": "disposable-test-only-key-value-not-real"}),
    ]
    return responses


class RoleLinkageTests(unittest.TestCase):
    def call_with(self, responses):
        called = []

        def call(method, params):
            self.assertLess(len(called), len(responses), "unexpected API call")
            want, result = responses[len(called)]
            self.assertEqual(method, want, f"wrong operation at position {len(called)}")
            called.append(method)
            return result
        return call, called

    def test_source_contract_allows_only_exact_role_linkage(self):
        fn, methods = self.call_with(authority_responses())
        self.assertEqual(provision_guest_readonly(fn),
                         "disposable-test-only-key-value-not-real")
        self.assertEqual(methods[-1], "api_key.create")

    def test_unauthorized_roles_never_receive_api_key(self):
        cases = [
            ({"user_roles": []}, "OBSERVER_USER_REQUIRED_ROLE_ABSENT"),
            ({"user_roles": ["APPS_READ", "FULL_ADMIN"]},
             "OBSERVER_USER_EXTRA_ROLES_REFUSED"),
            ({"user_roles": "APPS_READ"}, "OBSERVER_USER_ROLES_SHAPE_DRIFT"),
            ({"user_group_id": GROUP_ID + 1},
             "OBSERVER_USER_PRIMARY_GROUP_DRIFT"),
            ({"primary_roles": []}, "OBSERVER_PRIMARY_GROUP_ROLE_NOT_EXACT"),
            ({"primary_roles": ["FULL_ADMIN"]},
             "OBSERVER_PRIMARY_GROUP_ROLE_NOT_EXACT"),
            ({"privilege_roles": ["APPS_READ", "FULL_ADMIN"]},
             "CREATED_PRIVILEGE_ROLES_NOT_EXACT"),
        ]
        for opts, reason in cases:
            with self.subTest(opts=opts):
                fn, methods = self.call_with(authority_responses(**opts))
                with self.assertRaisesRegex(ObservationError, reason):
                    provision_guest_readonly(fn)
                self.assertNotIn("api_key.create", methods)


if __name__ == "__main__":
    unittest.main()
