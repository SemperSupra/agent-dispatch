import importlib.util
import json
import pathlib
import unittest
from unittest import mock

ROOT=pathlib.Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("github_runner_frontier",ROOT/"scripts"/"github_runner_frontier.py")
MOD=importlib.util.module_from_spec(SPEC); assert SPEC.loader; SPEC.loader.exec_module(MOD)

class FrontierTests(unittest.TestCase):
    def test_kvm_wrong_platform_skips(self):
        with mock.patch.object(MOD.platform,"system",return_value="Darwin"):
            cap=MOD.probe_kvm_vcpu_nonce()[0]
        self.assertEqual(cap["classification"],"SKIPPED_GUARDRAIL")
        self.assertFalse(cap["exercised"])

    def test_simulator_wrong_platform_has_three_distinct_rungs(self):
        with mock.patch.object(MOD.platform,"system",return_value="Linux"):
            caps=MOD.probe_simulator_state()
        self.assertEqual([c["name"] for c in caps],[
            "macos:simulator-device-boot","macos:simulator-service-query","macos:simulator-guest-spawn"])
        self.assertTrue(all(c["classification"]=="SKIPPED_GUARDRAIL" for c in caps))

    def test_simulator_separates_boot_service_and_spawn(self):
        runtime={"identifier":"com.apple.CoreSimulator.SimRuntime.iOS-27-0","version":"27.0"}
        devtype={"identifier":"com.apple.CoreSimulator.SimDeviceType.iPhone-18-Pro"}
        with mock.patch.object(MOD.platform,"system",return_value="Darwin"),              mock.patch.object(MOD.shutil,"which",return_value="/usr/bin/xcrun"),              mock.patch.object(MOD,"_latest_ios_and_iphone",return_value=(runtime,devtype,{})),              mock.patch.object(MOD,"_device_state",return_value=("Booted",None)),              mock.patch.object(MOD,"_run",side_effect=[
                 (0,"UDID",""), (0,"",""), (0,"/Users/mobile",""), (None,"","timeout after 15s"),
                 (0,"",""), (0,"","")]):
            caps=MOD.probe_simulator_state()
        self.assertEqual(caps[0]["classification"],"SUPPORTED")
        self.assertEqual(caps[1]["classification"],"SUPPORTED")
        self.assertEqual(caps[2]["classification"],"ORACLE_FAILURE")

    def test_build_receipt_marks_frontier_only(self):
        with mock.patch.dict(MOD.PROBES,{"kvm-vcpu-nonce":lambda:[]}):
            receipt=MOD.build_receipt("kvm-vcpu-nonce","ubuntu-26.04")
        self.assertIn("frontier result proves only",receipt["warnings"][-1])

    def test_device_selection_prefers_newest_runtime_family(self):
        runtimes={"runtimes":[{"isAvailable":True,
            "identifier":"com.apple.CoreSimulator.SimRuntime.iOS-26-5","version":"26.5"}]}
        devtypes={"devicetypes":[
            {"identifier":"com.apple.CoreSimulator.SimDeviceType.iPhone-XS-Max",
             "name":"iPhone XS Max","modelIdentifier":"iPhone11,4","minRuntimeVersionString":"12.0.0"},
            {"identifier":"com.apple.CoreSimulator.SimDeviceType.iPhone-17-Pro",
             "name":"iPhone 17 Pro","modelIdentifier":"iPhone18,1","minRuntimeVersionString":"26.0.0"}]}
        with mock.patch.object(MOD,"_run",side_effect=[
            (0,json.dumps(runtimes),""),(0,json.dumps(devtypes),"")]):
            runtime,device,_=MOD._latest_ios_and_iphone("/usr/bin/xcrun")
        self.assertEqual(runtime["version"],"26.5")
        self.assertEqual(device["identifier"],"com.apple.CoreSimulator.SimDeviceType.iPhone-17-Pro")

if __name__=="__main__": unittest.main()
