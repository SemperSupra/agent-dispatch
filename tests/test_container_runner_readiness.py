import importlib.util
import pathlib
import unittest
from unittest import mock

ROOT=pathlib.Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location(
    "container_runner_readiness", ROOT/"scripts"/"container_runner_readiness.py"
)
MOD=importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MOD)


class RunnerReadinessTests(unittest.TestCase):
    def test_runner_assets_are_pinned(self):
        self.assertEqual(MOD.RUNNER_VERSION, "2.337.0")
        self.assertEqual(MOD.LINUX_X64_SHA256, "70920811a4f8ad4328818682bca5c6469c1c942fab52448868071d0063816613")
        self.assertEqual(MOD.WINDOWS_X64_SHA256, "1150692afa94e71f872017e254ea55b6eece1eece3fe7e3a6d4c93d0a1b85cfc")

    def test_linux_path_consumes_immutable_qualified_runner_kit(self):
        script=MOD.linux_stage_shell()
        self.assertIn(MOD.RUNNER_KIT_REF, script)
        self.assertIn(MOD.RUNNER_KIT_BLOB_SHA1, script)
        self.assertIn("Runner.Listener", (ROOT/"scripts"/"container_runner_readiness.py").read_text())

    def test_windows_dockerfile_has_digest_and_version_oracle(self):
        dockerfile=MOD.windows_dockerfile()
        self.assertIn(MOD.WINDOWS_X64_SHA256, dockerfile)
        self.assertIn("Runner.Listener.exe", dockerfile)
        self.assertIn("Get-FileHash", dockerfile)

    def test_no_runner_registration_or_control_plane_authority(self):
        text=(ROOT/"scripts"/"container_runner_readiness.py").read_text()
        forbidden=("config.sh --url","registration-token","jitconfig","ACTIONS_RUNNER_INPUT_TOKEN","--token")
        for needle in forbidden:
            self.assertNotIn(needle, text)

    def test_windows_wrong_host_stops_at_guardrail(self):
        with mock.patch.object(MOD.platform,"system",return_value="Linux"):
            r=MOD.qualify_windows()
        self.assertEqual(r["classification"],"SKIPPED_GUARDRAIL")
        self.assertFalse(r["oracleSatisfied"])

    def test_result_schema_separates_verdict_from_ci_transport(self):
        r=MOD.result("ORACLE_FAILURE",False,"fixture",lane="lxc")
        self.assertEqual(r["schema"],"container-runner-readiness/v1")
        self.assertFalse(r["oracleSatisfied"])
        self.assertEqual(r["lane"],"lxc")


if __name__=="__main__":
    unittest.main()
