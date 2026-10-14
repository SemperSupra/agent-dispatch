"""Pure request/response policy checks; never claims a running TrueNAS guest."""
import unittest

from scripts.truenas_middleware_collage_readback_p2 import (
    ObservationError, provision_guest_readonly, bounded_rbac_call, RBAC_CALL_SEQUENCE,
    classify_scoped_key_ddp_failure,
)

ROLE = "APPS_READ"
USER = "collage_p2_observer"
PRIVILEGE = "collage-p2-apps-read"
GROUP_ID = 1013
GROUP_GID = 32013  # POSIX GID, deliberately not middleware group datastore id


def authority_responses(*, primary_roles=None, user_roles=None,
                        user_group_id=GROUP_ID, privilege_roles=None,
                        group_gid=GROUP_GID, privilege_group_gid=GROUP_GID,
                        group_local=True, group_found=True):
    primary_roles = [ROLE] if primary_roles is None else primary_roles
    user_roles = [ROLE] if user_roles is None else user_roles
    privilege_roles = [ROLE] if privilege_roles is None else privilege_roles
    responses = [
        ("user.query", []),
        ("privilege.query", []),
        ("privilege.roles", [{"name": ROLE, "includes": []}]),
        ("user.create", {"username": USER, "group": {"id": GROUP_ID}}),
        ("group.query", {"id": GROUP_ID, "gid": group_gid, "local": group_local}
         if group_found else None),
        ("privilege.create", {"name": PRIVILEGE, "roles": privilege_roles,
                               "local_groups": [{"gid": privilege_group_gid}]}),
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
            if method == "privilege.create":
                # Caller must send UNIX GID, not middleware group datastore id.
                self.assertEqual(params[0]["local_groups"], [GROUP_GID])
                self.assertNotEqual(params[0]["local_groups"], [GROUP_ID])
                self.assertEqual(params[0]["roles"], ["APPS_READ"])
            if method == "group.query":
                self.assertEqual(params[0][0][0], "id")
                self.assertEqual(params[0][0][2], GROUP_ID)
            called.append(method)
            return result
        return call, called

    def test_api_key_create_ddp_rejection_only_emits_allowlisted_error_number(self):
        for code in (13,22,400,403,422,500):
            err=RuntimeError('api_key.create: {"error": '+str(code)+
                             ', "reason": "API-SECRET-NEVER-LOG-THIS"}')
            self.assertEqual(classify_scoped_key_ddp_failure(err),"_E"+str(code))
            def remote(method, params):
                if method=="api_key.create":
                    raise err
                return next(x[1] for x in authority_responses() if x[0]==method)
            # The actual guest call order is exercised separately below.
            fn,seq=self.call_with(authority_responses())
            def failing(method,params):
                if method=="api_key.create": raise err
                return fn(method,params)
            with self.assertRaises(ObservationError) as caught:
                provision_guest_readonly(bounded_rbac_call(failing))
            self.assertEqual(str(caught.exception),
                             "GUEST_RBAC_ISSUE_SCOPED_KEY_API_FAILED_E"+str(code))
            self.assertNotIn("API-SECRET",str(caught.exception))
        malformed = (
            ('api_key.create: {"error": 987654,"reason":"SECRET"}',
             "_DDP_UNRECOGNIZED_CODE"),
            ('api_key.create: {"error":"CUSTOM_PRIVATE"}',
             "_DDP_UNRECOGNIZED_CODE"),
            ('api_key.create: {"error": {"error":403},"reason":"SECRET"}',
             "_DDP_NESTED_ERROR"),
            ('api_key.create: {"error":[{"field":"PRIVATE"}]}',
             "_DDP_VALIDATION_LIST"),
            ('api_key.create: bad-json', "_DDP_MALFORMED_ERROR"),
            ('other.method: {"error": 403}', "_DDP_UNSTRUCTURED_ERROR"),
            ("api_key.create: "+("secret"*2000), "_DDP_OVERSIZE_ERROR"),
        )
        for msg, category in malformed:
            with self.subTest(category=category):
                self.assertEqual(classify_scoped_key_ddp_failure(RuntimeError(msg)),category)
        for exc, category in (
            (TimeoutError("PRIVATE-KEY-NEVER-LOG"), "_TRANSPORT_TIMEOUT_INDETERMINATE"),
            (ConnectionError("PRIVATE-USER-NEVER-LOG"), "_TRANSPORT_DISCONNECTED"),
            (OSError("PRIVATE-ENDPOINT-NEVER-LOG"), "_TRANSPORT_IO_FAILURE"),
            (ValueError("PRIVATE-ROLE-NEVER-LOG"), "_LOCAL_UNEXPECTED_FAILURE"),
        ):
            self.assertEqual(classify_scoped_key_ddp_failure(exc),category)
            self.assertNotIn("PRIVATE",classify_scoped_key_ddp_failure(exc))
        # Failures propagate through the actual nine-operation RBAC wrapper,
        # but the caller sees neither raw DDP text nor a spurious success.
        for exc,category in (
            (TimeoutError("DO-NOT-EMIT"),"_TRANSPORT_TIMEOUT_INDETERMINATE"),
            (RuntimeError('api_key.create: {"error":[{"secret":"DO-NOT-EMIT"}]}'),
             "_DDP_VALIDATION_LIST"),
        ):
            responses=authority_responses()
            called=[]
            def failure(method,params):
                ordinal=len(called)
                called.append(method)
                if method=="api_key.create":
                    raise exc
                return responses[ordinal][1]
            with self.assertRaises(ObservationError) as caught:
                provision_guest_readonly(bounded_rbac_call(failure))
            self.assertEqual(str(caught.exception),
                             "GUEST_RBAC_ISSUE_SCOPED_KEY_API_FAILED"+category)
            self.assertNotIn("DO-NOT-EMIT",str(caught.exception))

    def test_source_contract_allows_only_exact_role_linkage(self):
        fn, methods = self.call_with(authority_responses())
        self.assertEqual(provision_guest_readonly(fn),
                         "disposable-test-only-key-value-not-real")
        self.assertEqual(methods[-1], "api_key.create")
        self.assertEqual(methods.count("group.query"),2)
        self.assertLess(methods.index("group.query"),methods.index("privilege.create"))

    def test_all_nine_real_guest_rbac_rpc_failure_phases_are_bounded_and_private(self):
        sequence=authority_responses()
        self.assertEqual([item[0] for item in sequence],
                         [item[0] for item in RBAC_CALL_SEQUENCE])
        for failing in range(len(RBAC_CALL_SEQUENCE)):
            seen=[]
            def remote(method, params):
                number=len(seen)
                seen.append(method)
                self.assertEqual(method,sequence[number][0])
                if number==failing:
                    raise RuntimeError("API-SECRET-EXAMPLE MUST NEVER APPEAR")
                return sequence[number][1]
            with self.subTest(failing=failing):
                label=RBAC_CALL_SEQUENCE[failing][1].upper()
                with self.assertRaises(ObservationError) as caught:
                    provision_guest_readonly(bounded_rbac_call(remote))
                suffix = "_DDP_UNSTRUCTURED_ERROR" if failing == 8 else ""
                self.assertEqual(str(caught.exception),
                                 "GUEST_RBAC_"+label+"_API_FAILED"+suffix)
                self.assertNotIn("API-SECRET",str(caught.exception))
                self.assertEqual(len(seen),failing+1)
                if failing<8:
                    self.assertNotIn("api_key.create",seen)
        fn,_=self.call_with(authority_responses())
        self.assertTrue(provision_guest_readonly(bounded_rbac_call(fn)).startswith(
            "disposable-test-only-key-value"))

    def test_bounded_rbac_method_sequence_prevents_out_of_contract_rpc(self):
        cb=bounded_rbac_call(lambda method,params: [])
        with self.assertRaisesRegex(ObservationError,"GUEST_RBAC_API_SEQUENCE_DRIFT"):
            cb("app.delete",[])

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
            ({"privilege_group_gid": GROUP_GID + 1},
             "CREATED_PRIVILEGE_GID_LINK_NOT_EXACT"),
        ]
        cases += [
            ({"group_gid": None}, "READONLY_ACCOUNT_PRIMARY_GROUP_GID_UNAVAILABLE"),
            ({"group_local": False}, "READONLY_ACCOUNT_PRIMARY_GROUP_GID_UNAVAILABLE"),
            ({"group_found": False}, "READONLY_ACCOUNT_PRIMARY_GROUP_GID_UNAVAILABLE"),
        ]
        for opts, reason in cases:
            with self.subTest(opts=opts):
                fn, methods = self.call_with(authority_responses(**opts))
                with self.assertRaisesRegex(ObservationError, reason):
                    provision_guest_readonly(fn)
                self.assertNotIn("api_key.create", methods)


if __name__ == "__main__":
    unittest.main()
