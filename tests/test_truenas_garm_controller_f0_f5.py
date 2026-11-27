#!/usr/bin/env python3
import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "truenas_middleware_garm_f0_f5_probe",
    ROOT / "scripts" / "truenas_middleware_garm_f0_f5_probe.py",
)
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MOD)


class GarmControllerF0F5Tests(unittest.TestCase):
    def test_reconciliation_actions_are_fail_closed(self):
        desired = {"services": {"garm": {"image": "x"}}}
        self.assertEqual(MOD.reconciliation_action(None, None, desired), "CREATE")
        for state in ("DEPLOYING", "STOPPING"):
            self.assertEqual(
                MOD.reconciliation_action(state, desired, desired), "WAIT"
            )
        for state in ("CRASHED", "ERROR", "UNKNOWN"):
            self.assertEqual(
                MOD.reconciliation_action(state, desired, desired), "FAIL_CLOSED"
            )
        self.assertEqual(
            MOD.reconciliation_action("RUNNING", None, desired), "FAIL_CLOSED"
        )
        self.assertEqual(
            MOD.reconciliation_action("RUNNING", desired, desired), "NOOP"
        )
        self.assertEqual(
            MOD.reconciliation_action(
                "RUNNING", {"services": {"garm": {"image": "drift"}}}, desired
            ),
            "UPDATE",
        )

    def test_required_methods_cover_f0_f5_mutations_and_readback(self):
        expected = {
            "system.version",
            "app.query",
            "app.config",
            "app.create",
            "app.update",
            "app.redeploy",
            "app.stop",
            "app.start",
            "app.delete",
            "pool.dataset.query",
            "pool.dataset.create",
            "pool.dataset.delete",
            "filesystem.mkdir",
            "filesystem.stat",
        }
        self.assertTrue(expected.issubset(MOD.REQUIRED_METHODS))

    def test_secret_normalization_is_stable(self):
        compose = {
            "configs": {
                MOD.BOOTSTRAP_CONFIG: {"content": "secret"},
                MOD.TLS_CERT_CONFIG: {"content": "cert"},
                MOD.TLS_KEY_CONFIG: {"content": "key"},
            }
        }
        normalized = MOD.normalize_secret_configs(compose)
        self.assertEqual(
            normalized["configs"][MOD.BOOTSTRAP_CONFIG]["content"],
            MOD.BOOTSTRAP_PLACEHOLDER,
        )
        self.assertEqual(
            normalized["configs"][MOD.TLS_CERT_CONFIG]["content"],
            MOD.TLS_PREFIX + MOD.TLS_CERT_CONFIG,
        )
        self.assertEqual(
            normalized["configs"][MOD.TLS_KEY_CONFIG]["content"],
            MOD.TLS_PREFIX + MOD.TLS_KEY_CONFIG,
        )


if __name__ == "__main__":
    unittest.main()
