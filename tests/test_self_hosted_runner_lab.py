import json
import pathlib
import stat
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
KIT = ROOT / "scripts" / "self_hosted_runner_kit.sh"
PROVIDER = ROOT / "scripts" / "gha_kvm_surrogate.sh"

def run(*args, check=True):
    return subprocess.run(args, cwd=ROOT, text=True, capture_output=True, check=check)

class SelfHostedRunnerLabTests(unittest.TestCase):
    def test_kit_contract_is_provider_neutral(self):
        cp = run("bash", str(KIT), "contract")
        data = json.loads(cp.stdout)
        self.assertEqual(data["contract"], "self-hosted-runner-kit/v1")
        self.assertTrue(data["provider_neutral"])
        self.assertEqual(data["credential_acquisition"], "control-side")

    def test_kit_contains_no_actions_host_specific_context(self):
        text = KIT.read_text(encoding="utf-8")
        self.assertNotIn("GITHUB_", text)
        self.assertNotIn("/home/runner/work", text)
        self.assertNotIn("RUNNER_TEMP", text)

    def test_plan_requires_pinned_version_and_checksum(self):
        cp = run("bash", str(KIT), "plan", "--version", "0.0.0", "--sha256", "nope", check=False)
        self.assertNotEqual(cp.returncode, 0)
        good = "a" * 64
        cp = run("bash", str(KIT), "plan", "--version", "2.999.0", "--sha256", good, "--arch", "x64")
        data = json.loads(cp.stdout)
        self.assertEqual(data["version"], "2.999.0")
        self.assertEqual(data["sha256"], good)
        self.assertIn("actions-runner-linux-x64-2.999.0.tar.gz", data["download_url"])

    def test_opaque_input_is_consumed_without_disclosure_and_removed(self):
        secret = "synthetic-sensitive-value-that-must-not-appear"
        with tempfile.TemporaryDirectory() as td:
            path = pathlib.Path(td) / ".runner-jit-test"
            path.write_text(secret, encoding="utf-8")
            path.chmod(stat.S_IRUSR | stat.S_IWUSR)
            cp = run("bash", str(KIT), "consume-opaque-input", str(path))
            self.assertNotIn(secret, cp.stdout)
            self.assertNotIn(secret, cp.stderr)
            data = json.loads(cp.stdout)
            self.assertTrue(data["opaque_input_present"])
            run("bash", str(KIT), "sanitize-input", str(path))
            self.assertFalse(path.exists())

    def test_opaque_input_rejects_group_or_other_permissions(self):
        with tempfile.TemporaryDirectory() as td:
            path = pathlib.Path(td) / ".runner-jit-test"
            path.write_text("synthetic", encoding="utf-8")
            path.chmod(0o644)
            cp = run("bash", str(KIT), "consume-opaque-input", str(path), check=False)
            self.assertNotEqual(cp.returncode, 0)

    def test_provider_has_no_registration_control_plane(self):
        text = PROVIDER.read_text(encoding="utf-8")
        forbidden = ["config.sh --url", "registration-token", "jitconfig", "ACTIONS_RUNNER_INPUT_TOKEN"]
        for needle in forbidden:
            self.assertNotIn(needle, text)

if __name__ == "__main__":
    unittest.main()
