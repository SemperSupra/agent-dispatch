"""OP4G G3 disposable world transaction cheap red/blue contract tests.

Mock-only local transport for source validation. No native guest or AUTHORIZED
COLLAGE APPLY may be inferred from these unit tests.
"""
from __future__ import annotations
import unittest

from scripts.qualify_vanilla263_native_world_rollback import (
    APP, DATASET, NAME, SNAPSHOT, WORLD, SCHEMA, Refused,
    app_state, take_owned_pre_stage_snapshot,
    restore_owned_baseline_after_injected_fault,
)


class SimulatedOwnedGuest:
    def __init__(self):
        self.state = "STOPPED"
        self.pack = False
        self.snapshot = False
        self.call_log = []
        self.replayed = False
        self.unknown_app = False
        self.foreign_snapshot = False
        self.forced_failure = None

    def __call__(self, method, args):
        self.call_log.append((method, args))
        if method == self.forced_failure:
            raise ConnectionError("UNTRUSTED SECRET MUST NEVER ESCAPE")
        if method == "app.query":
            return ([{"name": "foreign", "state": self.state}] if self.unknown_app
                    else [{"name": APP, "state": self.state}])
        if method == "filesystem.listdir":
            assert args == [WORLD + "/datapacks"]
            return [{"name": NAME, "type": "FILE"}] if self.pack else []
        if method == "zfs.snapshot.query":
            assert args == [[["id", "=", SNAPSHOT]]]
            if self.foreign_snapshot:
                return [{"id": "foreign/snapshot"}]
            return [{"id": SNAPSHOT}] if self.snapshot else []
        if method == "zfs.snapshot.create":
            assert args[0]["dataset"] == DATASET
            assert args[0]["name"] == "op4g-pre-lantern"
            assert args[0]["recursive"] is False
            assert args[0]["suspend_vms"] is False
            assert not self.snapshot
            self.snapshot = True
            return {"id": SNAPSHOT}
        if method == "app.stop":
            assert args == [APP]
            self.state = "STOPPED"
            return 11
        if method == "zfs.snapshot.rollback":
            assert args == [SNAPSHOT, {"recursive": False,
                    "recursive_clones": False, "force": False,
                    "recursive_rollback": False}]
            assert self.state == "STOPPED"
            assert self.snapshot
            self.pack = False
            return None
        if method == "app.start":
            assert args == [APP]
            self.state = "RUNNING"
            return 12
        raise AssertionError(method)


class NativeRollbackContract(unittest.TestCase):
    def test_exact_stop_snapshot_stage_fault_restore_and_restart(self):
        api = SimulatedOwnedGuest()
        baseline = take_owned_pre_stage_snapshot(api)
        self.assertEqual(baseline["schema"], SCHEMA)
        self.assertFalse(baseline["world_activation_authorized_by_collage"])
        self.assertFalse(baseline["actual_player_gameplay_verified"])
        self.assertFalse(baseline["physical_true_nas_mutated"])
        api.pack = True  # independent actual stage is separately admitted
        api.state = "RUNNING"
        events = []
        def job(i, label):
            self.assertIn(i, (11, 12))
            events.append(("job", label))
        def wait_app():
            self.assertEqual(api.state, "RUNNING")
            events.append(("app", "ready"))
        def wait_status(which):
            self.assertEqual(which, "g3-rollback")
            events.append(("game", which))
        receipt = restore_owned_baseline_after_injected_fault(
            api, job, wait_app, wait_status)
        self.assertTrue(receipt["candidate_absent_after_rollback"])
        self.assertTrue(receipt["native_game_status_rechecked"])
        self.assertFalse(receipt["collage_managed_deployment"])
        self.assertFalse(receipt["actual_player_gameplay_verified"])
        order = [x[0] for x in api.call_log]
        self.assertLess(order.index("zfs.snapshot.create"),
                        order.index("zfs.snapshot.rollback"))
        self.assertLess(order.index("app.stop"),
                        order.index("zfs.snapshot.rollback"))
        self.assertLess(order.index("zfs.snapshot.rollback"),
                        order.index("app.start"))
        self.assertEqual(len([x for x in api.call_log if x[0] ==
                              "zfs.snapshot.rollback"]), 1)
        self.assertIn(("game", "g3-rollback"), events)

    def test_quiescence_owner_replay_and_existing_candidate_negatives(self):
        for state, pack, snapshot, foreign, expected in (
            ("RUNNING", False, False, False, "G3_QUIESCE_REQUIRED"),
            ("STOPPED", True, False, False, "G3_CANDIDATE_ALREADY_PRESENT"),
            ("STOPPED", False, True, False, "G3_SNAPSHOT_REPLAY_REFUSED"),
            ("STOPPED", False, False, True, "G3_APP_OWNER_NOT_EXACT"),
        ):
            api = SimulatedOwnedGuest()
            api.state, api.pack, api.snapshot, api.unknown_app = (
                state, pack, snapshot, foreign)
            with self.subTest(expected=expected):
                with self.assertRaisesRegex(Refused, expected):
                    take_owned_pre_stage_snapshot(api)
                self.assertFalse(any(x[0] == "zfs.snapshot.create"
                                     for x in api.call_log))
        api = SimulatedOwnedGuest()
        api.foreign_snapshot = True
        with self.assertRaisesRegex(Refused, "G3_SNAPSHOT_QUERY_AMBIGUOUS"):
            take_owned_pre_stage_snapshot(api)

    def test_rollback_refuses_absent_artifact_or_unowned_app(self):
        for state, pack, snapshot, reason in (
            ("STOPPED", True, True, "G3_PREFAULT_APP_NOT_RUNNING"),
            ("RUNNING", False, True, "G3_CANDIDATE_MISSING_PREFAULT"),
            ("RUNNING", True, False, "G3_SNAPSHOT_NOT_DURABLE"),
        ):
            api = SimulatedOwnedGuest()
            api.state, api.pack, api.snapshot = state, pack, snapshot
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(Refused, reason):
                    restore_owned_baseline_after_injected_fault(
                        api, lambda *_: None, lambda: None, lambda *_: None)
                self.assertNotIn("app.stop", [x[0] for x in api.call_log])

    def test_snapshot_and_inventory_malformed_shapes_rejected_before_mutation(self):
        class BadShape(SimulatedOwnedGuest):
            def __init__(self, method, result):
                super().__init__()
                self.bad_method, self.bad_result = method, result
            def __call__(self, method, args):
                if method == self.bad_method:
                    self.call_log.append((method, args))
                    return self.bad_result
                return super().__call__(method, args)
        for method, response in (
            ("filesystem.listdir", [{"name": "../../foreign"}] * 4097),
            ("filesystem.listdir", [{"name": 5}]),
            ("zfs.snapshot.query", [{"id": SNAPSHOT}, {"id": SNAPSHOT}]),
            ("zfs.snapshot.query", {"id": SNAPSHOT}),
            ("app.query", [{"name": APP, "state": "STOPPED"}] * 2),
        ):
            api = BadShape(method, response)
            with self.subTest(method=method):
                with self.assertRaises(Refused):
                    take_owned_pre_stage_snapshot(api)
                self.assertNotIn("zfs.snapshot.create",
                                 [x[0] for x in api.call_log])


if __name__ == "__main__":
    unittest.main()
