"""Pure request/response policy checks; never claims a running TrueNAS guest."""
import unittest
import json
import datetime as dt

from scripts.truenas_middleware_collage_readback_p2 import (
    ObservationError, provision_guest_readonly, bounded_rbac_call, RBAC_CALL_SEQUENCE,
    classify_scoped_key_ddp_failure, scoped_key_record_count_suffix,
    scoped_key_expiry_ejson, validated_native_join_verdict,
    SERVICE_UUID, VANILLA263_OWNER, VANILLA263_WORLD,
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
            if method == "api_key.create":
                # Assert the exact 25.04.2.6 legacy DDP EJSON datetime shape,
                # NOT the previously E11-refused ISO string or nonexpiring key.
                expires = params[0]["expires_at"]
                self.assertEqual(set(expires), {"$date"})
                self.assertIs(type(expires["$date"]), int)
                seconds_ahead = expires["$date"] / 1000 - dt.datetime.now(
                    dt.timezone.utc).timestamp()
                self.assertLess(seconds_ahead, 3605)
                self.assertGreater(seconds_ahead, 3550)
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
             "_E403"),
            ('api_key.create: {"error":[{"field":"PRIVATE"}]}',
             "_DDP_VALIDATION_LIST"),
            ('api_key.create: bad-json', "_DDP_MALFORMED_ERROR"),
            ('other.method: {"error": 403}', "_DDP_UNSTRUCTURED_ERROR"),
            ("api_key.create: "+("secret"*2000), "_DDP_MALFORMED_ERROR"),
            ('api_key.create: {"error": 403, "reason": "' + ("SENSITIVE"*3000) + '"}',
             "_E403"),
            ('api_key.create: {"error": {"errno": 422, "reason": "PRIVATE"}}',
             "_E422"),
            ('api_key.create: {"error": {"errno": 99999, "reason": "PRIVATE"}}',
             "_DDP_NESTED_ERROR"),
            ('api_key.create: {"error": 500, "reason": "' + ("PRIVATE"*40000) + '"}',
             "_DDP_OVERSIZE_ERROR"),
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
                             "GUEST_RBAC_ISSUE_SCOPED_KEY_API_FAILED"+category+
                             ("_KEY_COUNT_UNAVAILABLE" if category ==
                              "_TRANSPORT_TIMEOUT_INDETERMINATE" else ""))
            self.assertNotIn("DO-NOT-EMIT",str(caught.exception))

    def test_scoped_expiry_is_timezone_aware_pinned_ejson_datetime_not_string(self):
        # Frozen trueNAS_api_client release/25.04.2.6 ejson.JSONEncoder
        # emits UTC milliseconds; object_hook restores timezone-aware datetime.
        original = dt.datetime(2026, 10, 14, 15, 0, 0, 456000,
                               tzinfo=dt.timezone.utc)
        value = scoped_key_expiry_ejson(original)
        self.assertEqual(value, {"$date": 1791993600000})
        restored = dt.datetime.fromtimestamp(value["$date"] / 1000,
                                            tz=dt.timezone.utc)
        self.assertIs(type(restored), dt.datetime)
        self.assertEqual(restored, dt.datetime(2026, 10, 14, 16, 0,
                                               tzinfo=dt.timezone.utc))
        self.assertNotIsInstance(value, str)
        different_zone = original.astimezone(dt.timezone(dt.timedelta(hours=7)))
        self.assertEqual(scoped_key_expiry_ejson(different_zone), value)
        with self.assertRaisesRegex(ObservationError, "AWARE_DATETIME"):
            scoped_key_expiry_ejson(dt.datetime(2026, 10, 14, 15))
        for invalid in (None, "2026-10-14T16:00:00Z", 1791990000, {}):
            # None uses the live clock by documented default; malformed
            # non-null inputs must fail closed.
            if invalid is None:
                assert set(scoped_key_expiry_ejson()) == {"$date"}
            else:
                with self.assertRaises(ObservationError):
                    scoped_key_expiry_ejson(invalid)

    def test_validation_error_field_allowlist_and_no_provider_data_leakage(self):
        # Frozen TrueNAS 25.04 websocket_app turns ValidationErrors into
        # errno EAGAIN (11) with extra [field, message, errno] tuples.
        cases = (
            ("api_key_create", "_E11_VALIDATION_GENERAL"),
            ("api_key_create.name", "_E11_VALIDATION_NAME"),
            ("api_key_create.username", "_E11_VALIDATION_USERNAME"),
            ("api_key_create.expires_at", "_E11_VALIDATION_EXPIRES_AT"),
            ("api_key_create.username.extra", "_E11_VALIDATION_FIELD_UNKNOWN"),
            ("api_key_create.password", "_E11_VALIDATION_FIELD_UNKNOWN"),
            ("evil.api_key_create.username", "_E11_VALIDATION_FIELD_UNKNOWN"),
        )
        for field, expected in cases:
            payload = {"error": 11, "type": "VALIDATION",
                       "extra": [[field, "SENSITIVE-KEY-DO-NOT-EMIT", 22]],
                       "reason": "SENSITIVE-USER-DO-NOT-EMIT",
                       "trace": {"formatted": "SENSITIVE-TRACE-DO-NOT-EMIT"}}
            value = classify_scoped_key_ddp_failure(
                RuntimeError("api_key.create: " + json.dumps(payload)))
            with self.subTest(field=field):
                self.assertEqual(value, expected)
                self.assertNotIn("SENSITIVE", value)
                self.assertNotIn(field, value)
        extra_cases = (
            ([], "_E11_VALIDATION_FIELD_UNKNOWN"),
            (["api_key_create.username"], "_E11_VALIDATION_FIELD_UNKNOWN"),
            ([["api_key_create.username", "secret"]], "_E11_VALIDATION_FIELD_UNKNOWN"),
            ([[True, "secret", 22]], "_E11_VALIDATION_FIELD_UNKNOWN"),
            ([[["api_key_create.username"], "secret", 22]], "_E11_VALIDATION_FIELD_UNKNOWN"),
            ([[ "api_key_create.username", "secret", 22]]*13,
             "_E11_VALIDATION_FIELD_UNKNOWN"),
            ([["api_key_create.username", "secret", 22],
              ["api_key_create.name", "secret", 22]], "_E11_VALIDATION_MULTI"),
        )
        for extra, expected in extra_cases:
            payload = {"error": 11, "type": "VALIDATION", "extra": extra,
                       "trace": "DO-NOT-EMIT"*1000}
            self.assertEqual(classify_scoped_key_ddp_failure(
                RuntimeError("api_key.create: " + json.dumps(payload))), expected)
        for bad_type in (None, False, "VALIDATION_WRONG", [], {}):
            payload = {"error": 11, "type": bad_type,
                       "extra": [["api_key_create.name", "secret", 22]]}
            self.assertEqual(classify_scoped_key_ddp_failure(
                RuntimeError("api_key.create: " + json.dumps(payload))), "_E11")

    def test_failed_nonidempotent_key_creation_performs_only_one_exact_readonly_count(self):
        for count, expected in ((0, "_KEY_COUNT0"), (1, "_KEY_COUNT1"),
                                (2, "_KEY_COUNT_MULTIPLE"), (False, "_KEY_COUNT_INVALID"),
                                (-1, "_KEY_COUNT_INVALID"), ([], "_KEY_COUNT_INVALID")):
            calls = []
            def read_only(method, params):
                calls.append((method, params))
                self.assertEqual(method, "api_key.query")
                self.assertEqual(params, [
                    [["username", "=", USER], ["name", "=", "disposable-collage-p2"]],
                    {"count": True},
                ])
                return count
            with self.subTest(count=count):
                self.assertEqual(scoped_key_record_count_suffix(read_only), expected)
                self.assertEqual(len(calls), 1)
        def fail_query(method, params):
            raise RuntimeError("SECRET-NEVER-PUBLISH")
        self.assertEqual(scoped_key_record_count_suffix(fail_query),
                         "_KEY_COUNT_UNAVAILABLE")

        responses = authority_responses()
        called = []
        def failed_key(method, params):
            called.append(method)
            if method == "api_key.create":
                raise RuntimeError("api_key.create: " + json.dumps({
                    "error": 11, "type": "VALIDATION",
                    "extra": [["api_key_create.username", "SECRET", 22]],
                    "trace": "SECRET-NEVER-PUBLISH"}))
            if method == "api_key.query":
                self.assertEqual(params[1], {"count": True})
                return 0
            return responses[len(called)-1][1]
        with self.assertRaises(ObservationError) as raised:
            provision_guest_readonly(bounded_rbac_call(failed_key))
        self.assertEqual(str(raised.exception),
                         "GUEST_RBAC_ISSUE_SCOPED_KEY_API_FAILED"
                         "_E11_VALIDATION_USERNAME_KEY_COUNT0")
        self.assertEqual(called[-2:], ["api_key.create", "api_key.query"])
        self.assertEqual(called.count("api_key.create"), 1)
        self.assertNotIn("SECRET", str(raised.exception))

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


class NativeJoin018Tests(unittest.TestCase):
    """Pure sanitized child-result classification; no guest or API calls."""

    def document(self):
        return {
            "schema": "collage.native-readback/1",
            "classification": "PROVIDER_READBACK_MATCH",
            "mutation_authorized": False,
            "ownership_fields_matched": 6,
            "service_id": SERVICE_UUID,
            "native_app": VANILLA263_OWNER,
            "world_id": VANILLA263_WORLD,
            "native_app_version": "1.15.31",
            "truenas_version": "25.04.2.6",
            "source_plan_sha256": "a" * 64,
        }

    def adjudicate(self, code, result):
        return validated_native_join_verdict(
            code, json.dumps(result) if not isinstance(result, str) else result,
            owner=VANILLA263_OWNER, world=VANILLA263_WORLD)

    def refused(self, code, result, expected):
        with self.assertRaises(ObservationError) as caught:
            self.adjudicate(code, result)
        self.assertEqual(str(caught.exception), expected)
        self.assertNotIn("SECRET-DO-NOT-EMIT", str(caught.exception))

    def test_independent_exact_positive_requires_readback_and_sha(self):
        result = self.adjudicate(0, self.document())
        self.assertEqual(result["ownership_fields_matched"], 6)
        self.assertEqual(result["native_app_version"], "1.15.31")

    def test_version_owner_service_replay_and_shape_fail_closed(self):
        base = self.document()
        for field, bad, reason in (
            ("native_app_version", "1.15.30", "EXACT_CATALOG_INVALID"),
            ("truenas_version", "25.04.2.7", "EXACT_CATALOG_INVALID"),
            ("native_app", "foreign", "TARGET_INVALID"),
            ("world_id", "foreign", "TARGET_INVALID"),
            ("service_id", "foreign", "OWNER_FIELDS_INVALID"),
            ("ownership_fields_matched", 5, "OWNER_FIELDS_INVALID"),
            ("source_plan_sha256", "wrong", "SOURCE_DIGEST_INVALID"),
            ("mutation_authorized", True, "OWNER_FIELDS_INVALID"),
            ("classification", "REFUSED", "CLASSIFICATION_INVALID"),
            ("schema", "foreign", "SCHEMA_INVALID"),
        ):
            d = dict(base)
            d[field] = bad
            with self.subTest(field=field):
                self.refused(0, d, "NATIVE_READONLY_GUEST_JOIN_" + reason)

    def test_fixed_child_codes_only_no_raw_private_reflection(self):
        error = {"schema": "collage.native-readback/1",
                 "classification": "REFUSED",
                 "mutation_authorized": False,
                 "reason": "NATIVE_VANILLA263_GUEST_PROFILE_DRIFT",
                 "private": "SECRET-DO-NOT-EMIT"}
        self.refused(2, error,
                     "NATIVE_READONLY_GUEST_JOIN_REFUSED_NATIVE_VANILLA263_GUEST_PROFILE_DRIFT")
        error["reason"] = "SENSITIVE_SECRET-DO-NOT-EMIT"
        self.refused(2, error, "NATIVE_READONLY_GUEST_JOIN_REFUSED_OTHER")
        error["reason"] = "NATIVE_READONLY_PROBE_FAILED"
        self.refused(2, error,
                     "NATIVE_READONLY_GUEST_JOIN_REFUSED_NATIVE_READONLY_PROBE_FAILED")
        error["mutation_authorized"] = True
        self.refused(2, error, "NATIVE_READONLY_GUEST_JOIN_CLIENT_EXIT")
        self.refused(1, error, "NATIVE_READONLY_GUEST_JOIN_CLIENT_EXIT")
        self.refused(0, "SECRET-DO-NOT-EMIT not json",
                     "NATIVE_READONLY_GUEST_JOIN_NONJSON")
        self.refused(0, "x" * 32768,
                     "NATIVE_READONLY_GUEST_JOIN_OUTPUT_INVALID")
        inconclusive = {"schema": "collage.native-readback/1",
                        "classification": "INCONCLUSIVE",
                        "mutation_authorized": False,
                        "reason": "PROBE_EXECUTION_UNAVAILABLE"}
        self.refused(3, inconclusive,
                     "NATIVE_READONLY_GUEST_JOIN_CLIENT_INCONCLUSIVE")


if __name__ == "__main__":
    unittest.main()
