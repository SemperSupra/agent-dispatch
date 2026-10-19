"""Pure mock-native TrueNAS 25.04.2.6 readback, no guest or credentials."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("takeout_native", ROOT/"scripts/observe_takeout_t6_native_app.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
CONTROL = json.loads((ROOT/"config/takeout-synthetic-guest-control-candidate.json").read_text())

COMPOSE = {"services": {"takeoutsynthetic": {
    "image": "takeout-synthetic:local", "restart": "no",
    "network_mode": "none", "read_only": True, "user": "10001:10001",
    "volumes": [
        {"type": "bind", "source": "/mnt/rdtepool/takeout-t6-archives", "target": "/archive"},
        {"type": "bind", "source": "/mnt/rdtepool/takeout-t6-state", "target": "/state"},
    ],
    "ports": [], "privileged": False,
}}}


class FakeReadOnly:
    allowed = {"system.version", "app.query", "app.config",
               "pool.dataset.query", "filesystem.stat"}

    def __init__(self, stage):
        self.stage = stage
        self.calls = []
        self.version = "TrueNAS-25.04.2.6"
        self.app = {"id": CONTROL["data"]["app_name"],
                    "custom_app": True, "state": "STOPPED"} if stage == "BEFORE_NATIVE_APP_DELETE" else None
        self.compose = copy.deepcopy(COMPOSE)
        self.datasets = {
            "rdtepool/takeout-t6-archives": {"id": "rdtepool/takeout-t6-archives",
                                              "mountpoint": "/mnt/rdtepool/takeout-t6-archives"},
            "rdtepool/takeout-t6-state": {"id": "rdtepool/takeout-t6-state",
                                           "mountpoint": "/mnt/rdtepool/takeout-t6-state"},
        }
        self.stats = {v["mountpoint"]: {"type": "DIRECTORY", "uid":10001,"gid":10001}
                      for v in self.datasets.values()}

    def __call__(self, method, params):
        assert method in self.allowed, f"unadmitted method {method}"
        self.calls.append((method,params))
        if method == "system.version":return self.version
        if method == "app.query":
            assert params[0][0][2] == CONTROL["data"]["app_name"]
            return self.app
        if method == "app.config":return self.compose
        if method == "pool.dataset.query":
            name=params[0][0][2]
            return [self.datasets[name]] if name in self.datasets else []
        if method == "filesystem.stat":
            return self.stats[params[0]]


def observe(f, stage="BEFORE_NATIVE_APP_DELETE", control=None, compose=None):
    return m.observe(f, CONTROL if control is None else control, stage=stage,
                     exact_compose=(COMPOSE if compose is None else compose) if
                     stage=="BEFORE_NATIVE_APP_DELETE" else None)


class NativeShapeTests(unittest.TestCase):
    def test_before_native_app_observation_is_not_accepted_guest(self):
        f=FakeReadOnly("BEFORE_NATIVE_APP_DELETE")
        result=observe(f)
        self.assertEqual(result["classification"], "NATIVE_APP_READBACK_SHAPE_ONLY")
        self.assertFalse(result["native_guest_execution_attested"])
        self.assertFalse(result["independent_file_bytes_verified"])
        self.assertFalse(result["docker_read_required"])
        self.assertEqual([m for m,_ in f.calls],
                         ["system.version","app.query","pool.dataset.query",
                          "pool.dataset.query","filesystem.stat","filesystem.stat","app.config"])

    def test_after_native_app_delete_retains_datasets_not_bytes(self):
        f=FakeReadOnly("AFTER_NATIVE_APP_DELETE")
        result=observe(f,stage="AFTER_NATIVE_APP_DELETE")
        self.assertEqual(result["classification"], "NATIVE_APP_ABSENCE_SHAPE_ONLY")
        self.assertTrue(result["retained_datasets_observed"])
        self.assertFalse(result["independent_file_bytes_verified"])
        self.assertNotIn("app.config", [v[0] for v in f.calls])

    def test_wrong_native_system_version(self):
        f=FakeReadOnly("BEFORE_NATIVE_APP_DELETE");f.version="TrueNAS-25.10.7"
        with self.assertRaisesRegex(m.ObservationBlocked, "NATIVE_SYSTEM_VERSION_MISMATCH"):
            observe(f)

    def test_wrong_app_identity(self):
        f=FakeReadOnly("BEFORE_NATIVE_APP_DELETE");f.app["id"]="foreign"
        with self.assertRaisesRegex(m.ObservationBlocked, "NATIVE_APP_NOT_STOPPED"):
            observe(f)

    def test_app_still_running_fails(self):
        f=FakeReadOnly("BEFORE_NATIVE_APP_DELETE");f.app["state"]="RUNNING"
        with self.assertRaisesRegex(m.ObservationBlocked, "NATIVE_APP_NOT_STOPPED"):
            observe(f)

    def test_app_crashed_fails(self):
        f=FakeReadOnly("BEFORE_NATIVE_APP_DELETE");f.app["state"]="CRASHED"
        with self.assertRaisesRegex(m.ObservationBlocked, "NATIVE_APP_NOT_STOPPED"):
            observe(f)

    def test_foreign_custom_app_rejected(self):
        f=FakeReadOnly("BEFORE_NATIVE_APP_DELETE");f.app["custom_app"]=False
        with self.assertRaisesRegex(m.ObservationBlocked, "NATIVE_APP_NOT_STOPPED"):
            observe(f)

    def test_compose_tag_changed(self):
        f=FakeReadOnly("BEFORE_NATIVE_APP_DELETE");f.compose["services"]["takeoutsynthetic"]["image"]="foreign:latest"
        with self.assertRaisesRegex(m.ObservationBlocked, "NATIVE_COMPOSE_READBACK_DRIFT"):
            observe(f)

    def test_expected_compose_forged_to_other_image_rejected(self):
        f=FakeReadOnly("BEFORE_NATIVE_APP_DELETE")
        value=copy.deepcopy(COMPOSE)
        value["services"]["takeoutsynthetic"]["image"]="foreign:latest"
        f.compose=value
        with self.assertRaisesRegex(m.ObservationBlocked, "NATIVE_WORKER_SECURITY_DRIFT"):
            observe(f,compose=value)

    def test_rootless_or_isolation_changes(self):
        for key,value in (("user","0:0"),("network_mode","host"),
                          ("restart","always"),("read_only",False),
                          ("privileged",True),("ports",[443])):
            with self.subTest(key=key):
                f=FakeReadOnly("BEFORE_NATIVE_APP_DELETE")
                value_compose=copy.deepcopy(COMPOSE)
                value_compose["services"]["takeoutsynthetic"][key]=value
                f.compose=value_compose
                with self.assertRaisesRegex(m.ObservationBlocked,"NATIVE_WORKER_SECURITY_DRIFT"):
                    observe(f,compose=value_compose)

    def test_extra_worker_rejected(self):
        f=FakeReadOnly("BEFORE_NATIVE_APP_DELETE")
        value=copy.deepcopy(COMPOSE);value["services"]["other"]={"image":"other"}
        with self.assertRaisesRegex(m.ObservationBlocked,"EXPECTED_COMPOSE_UNBOUND"):
            observe(f,compose=value)

    def test_foreign_mount_rejected(self):
        f=FakeReadOnly("BEFORE_NATIVE_APP_DELETE")
        value=copy.deepcopy(COMPOSE)
        value["services"]["takeoutsynthetic"]["volumes"][0]["source"]="/mnt/other"
        f.compose=value
        with self.assertRaisesRegex(m.ObservationBlocked,"NATIVE_DATA_MOUNT_MISMATCH"):
            observe(f,compose=value)

    def test_state_dataset_not_owned(self):
        f=FakeReadOnly("BEFORE_NATIVE_APP_DELETE");f.stats["/mnt/rdtepool/takeout-t6-state"]["uid"]=0
        with self.assertRaisesRegex(m.ObservationBlocked,"HOSTPATH_OWNERSHIP_MISMATCH"):
            observe(f)

    def test_dataset_missing_or_foreign_path(self):
        for kind in ("missing","drift"):
            f=FakeReadOnly("BEFORE_NATIVE_APP_DELETE")
            if kind=="missing":del f.datasets["rdtepool/takeout-t6-state"]
            else:f.datasets["rdtepool/takeout-t6-state"]["mountpoint"]="/mnt/foreign"
            with self.assertRaises(m.ObservationBlocked):
                observe(f)

    def test_delete_not_absent(self):
        f=FakeReadOnly("AFTER_NATIVE_APP_DELETE")
        f.app={"id":CONTROL["data"]["app_name"],"state":"STOPPED"}
        with self.assertRaisesRegex(m.ObservationBlocked,"NATIVE_APP_STILL_PRESENT_AFTER_DELETE"):
            observe(f,stage="AFTER_NATIVE_APP_DELETE")

    def test_mutated_control_is_never_accepted(self):
        c=copy.deepcopy(CONTROL);c["decision"]="ADMITTED"
        f=FakeReadOnly("BEFORE_NATIVE_APP_DELETE")
        with self.assertRaisesRegex(m.ObservationBlocked,"UNTRUSTED_GUEST_CONTROL"):
            observe(f,control=c)

    def test_unauthorized_source_method_does_not_become_mutation(self):
        f=FakeReadOnly("BEFORE_NATIVE_APP_DELETE")
        observe(f)
        self.assertTrue(set(method for method,_ in f.calls) <= f.allowed)
        self.assertFalse(any(method.endswith(("create","delete","update","stop"))
                             for method,_ in f.calls))


if __name__ == "__main__":
    unittest.main()
