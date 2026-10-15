"""CPU-only injected fake DDP stream tests; no TrueNAS or Docker access."""
import unittest

from truenas_takeout_ddp_subscription import arm, collect_worker_until_die, WitnessBlocked

PROJECT = "ix-rdte-takeout"
SERVICE = "takeoutsynthetic"
CID = "a" * 64


class FakeSocket:
    def __init__(self, messages):
        self.messages = iter(messages)
        self.sent = []

    def send_json(self, obj):
        self.sent.append(obj)

    def recv_json(self):
        try:
            return next(self.messages)
        except StopIteration:
            raise EOFError("synthetic closed socket")


def event(action="create", *, project=PROJECT, service=SERVICE, cid=CID, exit_code=None):
    attrs = {
        "com.docker.compose.project": project,
        "com.docker.compose.service": service,
        "com.docker.compose.container-number": "1",
    }
    if exit_code is not None:
        attrs["exitCode"] = exit_code
    return {
        "msg": "added", "collection": "docker.events", "id": project,
        "fields": {
            "Type": "container", "Action": action,
            "Actor": {"ID": cid, "Attributes": attrs},
            "timeNano": 1760000000000000000,
        },
    }


def capture(ws, **kwargs):
    return collect_worker_until_die(ws, project=PROJECT, service=SERVICE,
                                    container_id=CID, **kwargs)


class DDPTests(unittest.TestCase):
    def test_subscribe_ready(self):
        ws = FakeSocket([{"msg": "ready", "subs": ["takeout-events"]}])
        self.assertEqual(arm(ws)["status"], "READY")
        self.assertEqual(ws.sent, [
            {"msg": "sub", "id": "takeout-events", "name": "docker.events"}])
        self.assertFalse(arm(FakeSocket([{"msg": "ready", "subs": ["takeout-events"]}]))["live_rbac_qualified"])

    def test_ping_pong(self):
        ws = FakeSocket([
            {"msg": "ping", "id": "123"},
            {"msg": "ready", "subs": ["takeout-events"]},
        ])
        self.assertEqual(arm(ws)["stream"], "docker.events")
        self.assertEqual(ws.sent[-1], {"msg": "pong", "id": "123"})

    def test_subscription_rejection(self):
        for kind in ("error", "nosub", "failed", "removed"):
            with self.subTest(kind=kind):
                with self.assertRaises(WitnessBlocked):
                    arm(FakeSocket([{"msg": kind}]))

    def test_wrong_ack_and_event_before_ready(self):
        for message in ({"msg": "ready", "subs": ["wrong"]}, event()):
            with self.subTest(message=message):
                with self.assertRaises(WitnessBlocked):
                    arm(FakeSocket([message]))

    def test_missing_ack_or_bounded_wait(self):
        with self.assertRaises(WitnessBlocked):
            arm(FakeSocket([]))
        with self.assertRaisesRegex(WitnessBlocked, "READY_MISSING"):
            arm(FakeSocket([{"msg": "ping"}]), max_messages=1)

    def test_expected_worker_and_unrelated_events(self):
        ws = FakeSocket([
            event("start", project="ix-unrelated"),
            event("die", service="permissions", exit_code="0"),
            event("create"), event("start"), event("die", exit_code="0"),
        ])
        result = capture(ws)
        self.assertEqual([x["fields"]["Action"] for x in result],
                         ["create", "start", "die"])
        self.assertTrue(all(x["id"] == PROJECT for x in result))

    def test_wrong_worker_id(self):
        with self.assertRaisesRegex(WitnessBlocked, "WORKER_IDENTITY_MISMATCH"):
            capture(FakeSocket([event(cid="b" * 64)]))

    def test_forged_project_label(self):
        bad = event()
        bad["fields"]["Actor"]["Attributes"]["com.docker.compose.project"] = "ix-foreign"
        with self.assertRaisesRegex(WitnessBlocked, "PROJECT_LABEL_MISMATCH"):
            capture(FakeSocket([bad]))

    def test_missing_die(self):
        with self.assertRaises(WitnessBlocked):
            capture(FakeSocket([event("create"), event("start")]))

    def test_subscription_break_during_capture(self):
        for kind in ("nosub", "error", "ready", "removed"):
            with self.subTest(kind=kind):
                with self.assertRaisesRegex(WitnessBlocked, "SUBSCRIPTION_INTERRUPTED"):
                    capture(FakeSocket([event("create"), {"msg": kind}]))

    def test_bad_event_payload(self):
        bad = event()
        del bad["fields"]["Actor"]["Attributes"]
        with self.assertRaises(WitnessBlocked):
            capture(FakeSocket([bad]))

    def test_message_budget(self):
        with self.assertRaisesRegex(WitnessBlocked, "DIE_EVENT_MISSING"):
            capture(FakeSocket([event("create")]), max_messages=1)

    def test_boolean_budget_rejected(self):
        with self.assertRaises(WitnessBlocked):
            capture(FakeSocket([]), max_messages=True)

    def test_wrong_collection_fail_closed(self):
        bad = event()
        bad["collection"] = "app.query"
        with self.assertRaisesRegex(WitnessBlocked, "UNEXPECTED_ENVELOPE"):
            capture(FakeSocket([bad]))

    def test_invalid_expected_identity(self):
        with self.assertRaisesRegex(WitnessBlocked, "INVALID_CONTAINER_ID"):
            collect_worker_until_die(FakeSocket([]), project=PROJECT,
                                     service=SERVICE, container_id="bad")


if __name__ == "__main__":
    unittest.main()
