import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "github_runner_environment_v2",
    ROOT / "scripts" / "github_runner_environment_v2.py",
)
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MOD)


class RunnerEnvironmentV2Tests(unittest.TestCase):
    def test_reuses_v1_contract(self):
        receipt = MOD.build_receipt("test-v2")
        self.assertEqual(receipt["schema"], "github-runner-capability/v1")
        self.assertEqual(receipt["provenance"]["requested_label"], "test-v2")
        self.assertEqual(receipt["provenance"]["probe_version"], "public-environment-v2/1")
        self.assertIn("execution_model", receipt["environment"])

    def test_filesystem_semantics_are_public_safe(self):
        data = MOD._filesystem_semantics()
        self.assertEqual(
            set(data),
            {
                "case_insensitive",
                "symlink_create_and_read",
                "symlink_error_type",
                "hardlink_create_and_read",
                "hardlink_error_type",
                "executable_bit_semantics",
            },
        )

    def test_loopback_is_an_oracle_not_presence_only(self):
        cap = MOD._loopback_family(MOD.socket.AF_INET, "127.0.0.1")
        self.assertTrue(cap["exercised"])
        self.assertIn(cap["classification"], {"SUPPORTED", "NEGATIVE_OBSERVATION", "ORACLE_FAILURE"})

    def test_service_probe_is_opt_in(self):
        old_host = MOD.os.environ.pop("CENSUS_SERVICE_HOST", None)
        old_port = MOD.os.environ.pop("CENSUS_SERVICE_PORT", None)
        try:
            self.assertIsNone(MOD._service_container_probe())
        finally:
            if old_host is not None:
                MOD.os.environ["CENSUS_SERVICE_HOST"] = old_host
            if old_port is not None:
                MOD.os.environ["CENSUS_SERVICE_PORT"] = old_port


if __name__ == "__main__":
    unittest.main()
