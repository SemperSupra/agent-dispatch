import importlib.util
import pathlib
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "github_runner_census", ROOT / "scripts" / "github_runner_census.py"
)
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MOD)

class PassiveRunnerCensusTests(unittest.TestCase):
    def test_receipt_has_common_contract(self):
        receipt = MOD.build_receipt("test-runner")
        self.assertEqual(receipt["schema"], "github-runner-capability/v1")
        self.assertEqual(receipt["provenance"]["requested_label"], "test-runner")
        self.assertIn("cpu", receipt["resources"])
        self.assertIn("memory", receipt["resources"])
        self.assertIn("storage", receipt["resources"])
        self.assertIsInstance(receipt["capabilities"], list)

    def test_presence_is_not_promoted_to_supported(self):
        cap = MOD._presence_capability("test", True, "evidence")
        self.assertEqual(cap["classification"], "INCONCLUSIVE")
        self.assertTrue(cap["observed"])
        self.assertFalse(cap["exercised"])
        self.assertFalse(cap["oracleSatisfied"])
        self.assertIsNone(cap["callable"])

    def test_absence_is_negative_observation_not_harness_failure(self):
        cap = MOD._presence_capability("test", False)
        self.assertEqual(cap["classification"], "NEGATIVE_OBSERVATION")
        self.assertNotEqual(cap["classification"], "HARNESS_FAILURE")

    def test_windows_hyperv_presence_remains_passive(self):
        evidence = '{"HypervisorPresent":true,"GetVMHostPresent":true,"GetVMSwitchPresent":true,"VMMSPresent":true,"VMMSStatus":"Running"}'
        with mock.patch.object(MOD.shutil, "which", return_value="powershell.exe"), \
             mock.patch.object(MOD, "_run_text", return_value=evidence):
            caps = MOD._windows_hyperv_capabilities()
        self.assertEqual(len(caps), 1)
        cap = caps[0]
        self.assertEqual(cap["name"], "windows:hyperv-control-plane")
        self.assertTrue(cap["observed"])
        self.assertEqual(cap["classification"], "INCONCLUSIVE")
        self.assertFalse(cap["exercised"])
        self.assertFalse(cap["oracleSatisfied"])

    def test_windows_hyperv_absence_is_negative_observation(self):
        evidence = '{"HypervisorPresent":false,"GetVMHostPresent":false,"GetVMSwitchPresent":false,"VMMSPresent":false,"VMMSStatus":null}'
        with mock.patch.object(MOD.shutil, "which", return_value="powershell.exe"), \
             mock.patch.object(MOD, "_run_text", return_value=evidence):
            cap = MOD._windows_hyperv_capabilities()[0]
        self.assertFalse(cap["observed"])
        self.assertEqual(cap["classification"], "NEGATIVE_OBSERVATION")
        self.assertFalse(cap["oracleSatisfied"])

    def test_environment_is_allowlisted_not_dumped(self):
        receipt = MOD.build_receipt("test-runner")
        self.assertEqual(
            set(receipt["environment"]),
            {
                "github_actions",
                "runner_environment",
                "runner_temp_present",
                "runner_tool_cache_present",
                "cgroup_version",
            },
        )

    def test_linux_dev_shm_presence(self):
        with mock.patch("pathlib.Path.exists", return_value=True), \
             mock.patch("pathlib.Path.is_dir", return_value=True), \
             mock.patch("shutil.disk_usage", return_value=mock.Mock(total=16000000000, free=15000000000)), \
             mock.patch("os.access", return_value=True):
            cap = MOD._linux_dev_shm_capability()
        self.assertEqual(cap["name"], "linux:dev-shm-tmpfs")
        self.assertTrue(cap["observed"])
        self.assertTrue(cap["installed"])
        self.assertEqual(cap["evidence"]["total_bytes"], 16000000000)

    def test_linux_kvm_access_capabilities(self):
        with mock.patch("pathlib.Path.exists", return_value=True), \
             mock.patch("os.access", return_value=False), \
             mock.patch("subprocess.run", return_value=mock.Mock(returncode=0)):
            caps = MOD._linux_kvm_access_capabilities()
        self.assertEqual(len(caps), 2)
        user_cap, sudo_cap = caps
        self.assertEqual(user_cap["name"], "linux:kvm-user-accessible")
        self.assertFalse(user_cap["observed"])
        self.assertEqual(sudo_cap["name"], "linux:kvm-sudo-accessible")
        self.assertTrue(sudo_cap["observed"])

    def test_docker_daemon_responsive_vs_unresponsive(self):
        with mock.patch("shutil.which", return_value="/usr/bin/docker"), \
             mock.patch.object(MOD, "_run_text", return_value="28.0.4"):
            cap = MOD._docker_daemon_capability()
        self.assertTrue(cap["observed"])
        self.assertTrue(cap["installed"])
        self.assertEqual(cap["evidence"]["server_version"], "28.0.4")

        with mock.patch("shutil.which", return_value="/usr/bin/docker"), \
             mock.patch.object(MOD, "_run_text", return_value=None):
            cap = MOD._docker_daemon_capability()
        self.assertFalse(cap["observed"])
        self.assertFalse(cap["installed"])

    def test_android_capabilities(self):
        with mock.patch.dict("os.environ", {"ANDROID_HOME": "/opt/android-sdk"}), \
             mock.patch("pathlib.Path.exists", return_value=True), \
             mock.patch("shutil.which", side_effect=lambda cmd: f"/opt/android-sdk/platform-tools/{cmd}"):
            caps = MOD._android_capabilities()
        names = {c["name"] for c in caps}
        self.assertIn("android:sdk-present", names)
        self.assertIn("android:emulator-present", names)

    def test_macos_simctl_and_metal_capabilities(self):
        sim_json = '{"runtimes": [{"name": "iOS 18.2", "identifier": "com.apple.CoreSimulator.SimRuntime.iOS-18-2"}]}'
        with mock.patch("shutil.which", return_value="/usr/bin/xcrun"), \
             mock.patch.object(MOD, "_run_text", return_value=sim_json):
            caps = MOD._macos_simctl_capabilities()
        self.assertTrue(caps[0]["observed"])
        self.assertIn("iOS 18.2", caps[0]["evidence"]["runtimes"])

        with mock.patch("pathlib.Path.exists", return_value=True), \
             mock.patch.object(MOD, "_run_text", return_value="Chipset Model: Apple M1 Max\nMetal Support: Metal 3"):
            cap = MOD._macos_metal_capability()
        self.assertTrue(cap["observed"])
        self.assertEqual(cap["evidence"].get("Chipset Model"), "Apple M1 Max")

    def test_windows_additional_capabilities(self):
        evidence = '{"UserInteractive":true,"MountVHDPresent":true,"DockerServicePresent":true,"DockerServiceStatus":"Running","WSLPresent":true}'
        with mock.patch("shutil.which", return_value="powershell.exe"), \
             mock.patch.object(MOD, "_run_text", return_value=evidence) as run_mock:
            caps = MOD._windows_additional_capabilities()
        run_mock.assert_called_once()
        self.assertEqual(run_mock.call_args.kwargs.get("timeout"), 15)
        names = {c["name"] for c in caps}
        self.assertIn("windows:interactive-session", names)
        self.assertIn("windows:vhd-cmdlet", names)
        self.assertIn("windows:docker-daemon", names)
        self.assertIn("windows:wsl", names)
        self.assertTrue(all(c["observed"] for c in caps))

    def test_windows_docker_daemon_requires_running_status(self):
        stopped_evidence = '{"UserInteractive":true,"MountVHDPresent":true,"DockerServicePresent":true,"DockerServiceStatus":"Stopped","WSLPresent":true}'
        with mock.patch("shutil.which", return_value="powershell.exe"), \
             mock.patch.object(MOD, "_run_text", return_value=stopped_evidence):
            caps = {c["name"]: c for c in MOD._windows_additional_capabilities()}
        docker_cap = caps["windows:docker-daemon"]
        self.assertFalse(docker_cap["observed"])
        self.assertTrue(docker_cap["installed"])
        self.assertEqual(docker_cap["classification"], "NEGATIVE_OBSERVATION")

    def test_windows_hyperv_uses_extended_timeout(self):
        evidence = '{"HypervisorPresent":true,"GetVMHostPresent":true,"GetVMSwitchPresent":true,"VMMSPresent":true,"VMMSStatus":"Running"}'
        with mock.patch.object(MOD.shutil, "which", return_value="powershell.exe"), \
             mock.patch.object(MOD, "_run_text", return_value=evidence) as run_mock:
            MOD._windows_hyperv_capabilities()
        self.assertEqual(run_mock.call_args.kwargs.get("timeout"), 15)

    def test_resources_contain_cpu_extensions(self):
        receipt = MOD.build_receipt("test-runner")
        self.assertIn("features", receipt["resources"]["cpu"])
        self.assertIsInstance(receipt["resources"]["cpu"]["features"], list)
        self.assertIn("steal_ticks", receipt["resources"]["cpu"])

    def test_optimization_benchmark_receipt_contract(self):
        bench_spec = importlib.util.spec_from_file_location(
            "runner_optimization_benchmarks",
            ROOT / "scripts" / "runner_optimization_benchmarks.py",
        )
        bench_mod = importlib.util.module_from_spec(bench_spec)
        assert bench_spec.loader
        bench_spec.loader.exec_module(bench_mod)
        io_res = bench_mod.benchmark_ramdisk_io(n_pairs=2, payload_mb=1)
        self.assertEqual(io_res["scope"], "microbenchmark_sequential_write_fsync_only")
        self.assertEqual(io_res["design"], "interleaved_ab_ba_pairs")
        self.assertEqual(io_res["n_samples"], 2)
        self.assertEqual(io_res["n_abba_blocks"], 1)
        self.assertEqual(io_res["payload_mb"], 1)
        self.assertIn("paired_diff_mean_seconds", io_res)


if __name__ == "__main__":
    unittest.main()
