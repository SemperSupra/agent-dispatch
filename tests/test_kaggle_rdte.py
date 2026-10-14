#!/usr/bin/env python3
"""Offline GitHub/Kaggle protocol tests. No credential, provider call, or GPU allocation."""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace, ModuleType
from unittest.mock import patch
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("kaggle_rdte", ROOT/"scripts"/"kaggle_rdte.py")
import sys
m = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = m
SPEC.loader.exec_module(m)

class FakeKernelRequest:
    def __init__(self):
        self.user_name = None
        self.kernel_slug = None

# The offline protocol tests inject just the Kaggle SDK request class;
# the real package and network are validated separately by pinned SDK CI.
_fake_sdk = ModuleType("kagglesdk")
_fake_sdk.__path__ = []
_fake_kernels = ModuleType("kagglesdk.kernels")
_fake_kernels.__path__ = []
_fake_types = ModuleType("kagglesdk.kernels.types")
_fake_types.__path__ = []
_fake_service = ModuleType("kagglesdk.kernels.types.kernels_api_service")
_fake_service.ApiGetKernelRequest = FakeKernelRequest
_sdk_modules = {
    "kagglesdk":_fake_sdk,
    "kagglesdk.kernels":_fake_kernels,
    "kagglesdk.kernels.types":_fake_types,
    "kagglesdk.kernels.types.kernels_api_service":_fake_service,
}

class Fake:
    CONFIG_NAME_USER = "username"
    def __init__(self, owned=(), version=1, error=None, status="KernelWorkerStatus.COMPLETE", output=None,
                 current_version=3, observed_versions=None):
        self.owned=list(owned)
        self.version=version
        self.error=error
        self.status=status
        self.output=output
        self.pushed=0
        self.calls=[]
        self.current_version = current_version
        self.observed_versions = list(observed_versions or [])
    def build_kaggle_client(self):
        parent = self
        class Client:
            def __enter__(self): return self
            def __exit__(self, exc_type, exc_value, traceback): return False
            @property
            def kernels(self):
                def get_kernel(request):
                    parent.calls.append(("get_kernel",request.kernel_slug))
                    version=(parent.observed_versions.pop(0)
                             if parent.observed_versions else parent.current_version)
                    return SimpleNamespace(metadata=SimpleNamespace(current_version_number=version))
                return SimpleNamespace(kernels_api_client=SimpleNamespace(get_kernel=get_kernel))
        return Client()
    def authenticate(self): pass
    def get_config_value(self,k):
        return "publicresearcher"
    def quota_view(self):
        import datetime
        q=SimpleNamespace(time_used=datetime.timedelta(hours=0),
                          total_time_allowed=datetime.timedelta(hours=20))
        return SimpleNamespace(gpu_quota=q,tpu_quota=q)
    def kernels_list_with_response(self,**kw):
        return SimpleNamespace(kernels=[SimpleNamespace(ref=x) for x in self.owned],next_page_token=None)
    def kernels_push(self,folder,timeout,acc):
        self.pushed+=1
        meta=json.loads((Path(folder)/"kernel-metadata.json").read_text())
        self.calls.append(("push",meta,timeout,acc))
        return SimpleNamespace(versionNumber=self.version,error=self.error)
    def kernels_status(self,ref):
        self.calls.append(("status",ref))
        return SimpleNamespace(status=self.status)
    def kernels_output(self,ref,path,**kw):
        self.calls.append(("output",ref,kw))
        if self.output is not None:
            (Path(path)/"kaggle_rdte_result.json").write_text(json.dumps(self.output))
        return ([], "")

class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._sdk_patch = patch.dict(sys.modules,_sdk_modules)
        cls._sdk_patch.start()
    @classmethod
    def tearDownClass(cls):
        cls._sdk_patch.stop()
    def plan(self,action="submit",assignment="test-rep-0001",workload="gpu-cuda-smoke-v1",version=0):
        return m.validate(action,assignment,workload,version)
    def test_cpu_reasoning_controls_real_work_fixture(self):
        source = ROOT/"experiments"/"kaggle_rdte"/"cpu_reasoning_controls.py"
        spec = importlib.util.spec_from_file_location("cpu_reasoning_controls",source)
        module=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        first=module.evaluate(module.tasks())
        second=module.evaluate(module.tasks())
        self.assertEqual(first,second)
        self.assertEqual(first["tasks"],256)
        self.assertEqual(first["wrong_answer_rejected"],256)
        self.assertEqual(first["corrupted_trace_rejected"],256)
        self.assertFalse(first["model_inference_performed"])

    def test_privileged_launcher_is_main_only_with_no_pr_secrets(self):
        workflow=(ROOT/".github"/"workflows"/"kaggle-rdte-executor.yml").read_text()
        self.assertIn("workflow_dispatch:",workflow)
        self.assertNotIn("pull_request:",workflow)
        self.assertNotIn("pull_request_target:",workflow)
        self.assertIn("github.ref == 'refs/heads/main'",workflow)
        self.assertIn("environment: kaggle-rdte",workflow)
        self.assertIn("KAGGLE_API_TOKEN: ${{ secrets.KAGGLE_API_TOKEN }}",workflow)
        self.assertIn("persist-credentials: false",workflow)
        self.assertIn("permissions:\\n  contents: read".replace("\\n","\n"),workflow)
        self.assertIn("timeout-minutes: 10",workflow)
        # Provider secrets are confined to the exact actuator step, not checkout,
        # dependency installation, artifact upload or PR contract tests.
        self.assertEqual(workflow.count("secrets.KAGGLE_API_TOKEN"),1)
        self.assertIn("cancel-in-progress: false",workflow)
        self.assertIn("inputs.action != 'plan' && github.ref == 'refs/heads/main'",workflow)

    def test_main_blocked_submit_persists_sanitized_receipt(self):
        import io
        from contextlib import redirect_stderr
        mock_kaggle=ModuleType("kaggle")
        mock_kaggle.api=object()
        with tempfile.TemporaryDirectory() as td:
            argv=["kaggle_rdte.py","--action","submit","--assignment",
                  "test-rep-0001","--workload","gpu-cuda-smoke-v1",
                  "--out-dir",td]
            with patch.object(sys,"argv",argv), patch.dict(sys.modules,{"kaggle":mock_kaggle}), \
                 patch.object(m,"submit",side_effect=m.Denied("PROVIDER_QUOTA_INSUFFICIENT")):
                stderr=io.StringIO()
                with redirect_stderr(stderr):
                    rc=m.main()
            self.assertEqual(rc,2)
            self.assertIn("PROVIDER_QUOTA_INSUFFICIENT",stderr.getvalue())
            evidence=json.loads((Path(td)/"control-receipt.json").read_text())
            self.assertEqual(evidence["state"],"BLOCKED")
            self.assertEqual(evidence["failure_class"],"PROVIDER_QUOTA_INSUFFICIENT")
            self.assertEqual(evidence["classification"],"FAIL_CLOSED")
            self.assertEqual(evidence["workload"],"gpu-cuda-smoke-v1")
            self.assertNotIn("provider_ref",evidence)

    def test_main_unknown_provider_failure_redacts_secret_and_writes_receipt(self):
        import io
        from contextlib import redirect_stderr
        fake=ModuleType("kaggle")
        fake.api=object()
        with tempfile.TemporaryDirectory() as td:
            argv=["kaggle_rdte.py","--action","submit","--assignment",
                  "test-rep-0001","--workload","gpu-cuda-smoke-v1",
                  "--out-dir",td]
            with patch.object(sys,"argv",argv), patch.dict(sys.modules,{"kaggle":fake}), \
                 patch.object(m,"submit",side_effect=RuntimeError("SUPERSECRET_token_should_never_show")):
                stderr=io.StringIO()
                with redirect_stderr(stderr):
                    rc=m.main()
            raw=(Path(td)/"control-receipt.json").read_text()
            self.assertEqual(rc,2)
            self.assertIn("PROVIDER_RUNTIME_UNKNOWN_RECONCILE",raw)
            self.assertNotIn("SUPERSECRET",raw)
            self.assertNotIn("SUPERSECRET",stderr.getvalue())

    def test_main_terminal_provider_failure_is_nonzero_and_durable(self):
        fake=ModuleType("kaggle")
        fake.api=object()
        with tempfile.TemporaryDirectory() as td:
            argv=["kaggle_rdte.py","--action","observe","--assignment",
                  "test-rep-0001","--workload","gpu-cuda-smoke-v1",
                  "--version","3","--out-dir",td]
            with patch.object(sys,"argv",argv), patch.dict(sys.modules,{"kaggle":fake}), \
                 patch.object(m,"observe",return_value={"state":"TERMINAL_FAILED",
                      "is_terminal":True,"classification":"FAIL_DEVICE_NOT_ATTESTED",
                      "failure_class":"CUDA_DEVICE_UNAVAILABLE","native_version":3}):
                rc=m.main()
            self.assertEqual(rc,2)
            evidence=json.loads((Path(td)/"control-receipt.json").read_text())
            self.assertEqual(evidence["state"],"TERMINAL_FAILED")
            self.assertEqual(evidence["classification"],"FAIL_DEVICE_NOT_ATTESTED")
            self.assertTrue(evidence["is_terminal"])

    def test_allowlist_and_ids(self):
        for kw in ({"workload":"arbitrary-command"},{"assignment":"../bad"},
                   {"assignment":"x"}, {"action":"shell"}):
            with self.subTest(kw=kw),self.assertRaises(m.Denied):
                self.plan(**kw)
    def test_observe_requires_version(self):
        with self.assertRaises(m.Denied):
            self.plan("observe")
    def test_plan_is_version_stable(self):
        a=self.plan()
        self.assertEqual(a["accelerator"],"NvidiaTeslaT4")
        self.assertEqual(len(a["source_sha256"]),64)
        self.assertEqual(a["notebook_slug"],"ad-rdte-test-rep-0001")
    def test_tpu_plan(self):
        a=self.plan(workload="tpu-v5e8-device-v1")
        self.assertEqual(a["accelerator"],"TpuV5E8")
        self.assertEqual(a["quota_kind"],"TPU")
        self.assertEqual(a["limit_seconds"],600)
        b=self.plan(workload="tpu-jax-bridge-v1")
        self.assertEqual(b["limit_seconds"],1200)
    def test_submit_once_positive(self):
        f=Fake()
        receipt=m.submit(f,self.plan())
        self.assertEqual(f.pushed,1)
        self.assertEqual(receipt["native_version"],1)
        self.assertTrue(f.calls[0][1]["is_private"])
        self.assertFalse(f.calls[0][1]["enable_internet"])
        self.assertEqual(f.calls[0][1]["machine_shape"],"NvidiaTeslaT4")
        self.assertEqual(f.calls[0][1]["docker_image_pinning_type"],"latest")
        self.assertNotIn("docker_image",f.calls[0][1])
    def test_tpu_submission_is_unpinned(self):
        f=Fake()
        m.submit(f,self.plan(workload="tpu-jax-bridge-v1"))
        meta=f.calls[0][1]
        self.assertTrue(meta["enable_tpu"])
        self.assertFalse(meta["enable_gpu"])
        self.assertEqual(meta["machine_shape"],"TpuV5E8")
        self.assertEqual(meta["docker_image_pinning_type"],"latest")
        self.assertNotIn("docker_image",meta)
    def test_existing_blocks_no_mutation(self):
        f=Fake(owned=["publicresearcher/ad-rdte-test-rep-0001"])
        with self.assertRaises(m.Denied):
            m.submit(f,self.plan())
        self.assertEqual(f.pushed,0)
    def test_other_queued_agent_dispatch_job_blocks(self):
        f=Fake(owned=["publicresearcher/ad-rdte-earlier-0001"],
               status="KernelWorkerStatus.QUEUED")
        with self.assertRaisesRegex(m.Denied,"ANOTHER_AGENT_DISPATCH_KAGGLE_JOB_ACTIVE"):
            m.submit(f,self.plan())
        self.assertEqual(f.pushed,0)

    def test_other_running_agent_dispatch_job_blocks(self):
        f=Fake(owned=["publicresearcher/ad-rdte-earlier-0001"],
               status="KernelWorkerStatus.RUNNING")
        with self.assertRaisesRegex(m.Denied,"ANOTHER_AGENT_DISPATCH_KAGGLE_JOB_ACTIVE"):
            m.submit(f,self.plan())
        self.assertEqual(f.pushed,0)

    def test_other_terminal_job_does_not_block(self):
        f=Fake(owned=["publicresearcher/ad-rdte-earlier-0001"],
               status="KernelWorkerStatus.COMPLETE")
        receipt=m.submit(f,self.plan())
        self.assertEqual(receipt["native_version"],1)
        self.assertEqual(f.pushed,1)

    def test_unknown_owned_state_fails_closed(self):
        f=Fake(owned=["publicresearcher/ad-rdte-earlier-0001"],
               status="KernelWorkerStatus.MYSTERY")
        with self.assertRaisesRegex(m.Denied,"EXISTING_KAGGLE_JOB_STATE_UNKNOWN"):
            m.submit(f,self.plan())
        self.assertEqual(f.pushed,0)

    def test_provider_semantic_error(self):
        f=Fake(error="provider-rejected")
        with self.assertRaises(m.Denied):
            m.submit(f,self.plan())
        self.assertEqual(f.pushed,1)
    def test_version_unknown_blocks(self):
        f=Fake(version=None)
        with self.assertRaises(m.Denied):
            m.submit(f,self.plan())
    def test_gpu_positive_oracle(self):
        d={"schema":"kaggle-rdte-result/v1","workload":"gpu-cuda-smoke-v1",
           "status":"PASS","accelerator":"gpu","gpu_count":2,"checksum":8386560.0,
           "device_arithmetic_checksums":[8386560.0,8386560.0]}
        self.assertIsNone(m.verify(d,"gpu-cuda-smoke-v1"))
    def test_second_gpu_without_arithmetic_is_not_qualified(self):
        d={"schema":"kaggle-rdte-result/v1","workload":"gpu-cuda-smoke-v1",
           "status":"PASS","accelerator":"gpu","gpu_count":2,
           "checksum":8386560.0,"device_arithmetic_checksums":[8386560.0,8386560.0]}
        self.assertIsNone(m.verify(d,"gpu-cuda-smoke-v1"))
        for invalid in ([8386560.0], [8386560.0,0.0],
                        [8386560.0,8386560.0,8386560.0], None):
            d["device_arithmetic_checksums"]=invalid
            with self.subTest(invalid=invalid), self.assertRaisesRegex(m.Denied,"CUDA_ORACLE_FAILED"):
                m.verify(d,"gpu-cuda-smoke-v1")

    def test_gpu_probe_source_targets_both_devices(self):
        source=(ROOT/"experiments"/"kaggle_rdte"/"gpu_smoke.py").read_text()
        import ast
        tree=ast.parse(source)
        self.assertIn('for gpu_id in range(2):',source)
        self.assertIn('torch.cuda.synchronize(gpu_id)',source)
        self.assertIn('torch.cuda.device(gpu_id)',source)
        self.assertIn('device_arithmetic_checksums',source)

    def test_gpu_false_claim(self):
        d={"schema":"kaggle-rdte-result/v1","workload":"gpu-cuda-smoke-v1",
           "status":"PASS","accelerator":"cpu","gpu_count":0,"checksum":8386560.0}
        with self.assertRaises(m.Denied):
            m.verify(d,"gpu-cuda-smoke-v1")
    def test_tpu_positive_control(self):
        d={"schema":"kaggle-rdte-result/v1","workload":"tpu-jax-bridge-v1","status":"PASS",
           "metrics":{"accelerator":"tpu","tpu_count":8,"scope":"synthetic-method-sanity-only",
                      "heldout_cosine":0.9,"shuffled_control_cosine":0.1}}
        self.assertIsNone(m.verify(d,"tpu-jax-bridge-v1"))
        d["metrics"]["tpu_count"]=0
        with self.assertRaises(m.Denied):
            m.verify(d,"tpu-jax-bridge-v1")
    def test_cuda_readiness_is_not_equivalent_to_device_allocation(self):
        source = ROOT/"experiments"/"kaggle_rdte"/"gpu_smoke.py"
        spec = importlib.util.spec_from_file_location("gpu_readiness_probe",source)
        module=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        cases = [
            ((None,False,0,2,True),"CPU_ONLY_TORCH_ON_GPU"),
            ((None,False,0,0,False),"CUDA_BUILD_UNAVAILABLE_DEVICE_UNKNOWN"),
            (("12.1",False,0,2,True),"CUDA_RUNTIME_MISMATCH_ON_VISIBLE_GPU"),
            (("12.1",False,0,0,False),"CUDA_DEVICE_UNAVAILABLE"),
            (("12.1",True,2,2,True),None),
        ]
        for parameters,expected in cases:
            with self.subTest(case=parameters):
                self.assertEqual(module.classify_cuda_readiness(*parameters),expected)

    def test_terminal_failed_receipt_preserves_runtime_category(self):
        d={"schema":"kaggle-rdte-result/v1","workload":"gpu-cuda-smoke-v1",
           "status":"FAIL","failure_class":"CPU_ONLY_TORCH_ON_GPU"}
        f=Fake(status="KernelWorkerStatus.ERROR",output=d,current_version=5)
        with tempfile.TemporaryDirectory() as td:
            r=m.observe(f,self.plan("observe",version=5),Path(td))
        self.assertEqual(r["classification"],"FAIL_RUNTIME_SOFTWARE")
        self.assertEqual(r["native_version"],5)

    def test_terminal_failed_receipt_keeps_unattested_device_unknown(self):
        d={"schema":"kaggle-rdte-result/v1","workload":"tpu-v5e8-device-v1",
           "status":"FAIL","failure_class":"TPU_DEVICE_UNAVAILABLE"}
        f=Fake(status="KernelWorkerStatus.ERROR",output=d,current_version=4)
        with tempfile.TemporaryDirectory() as td:
            r=m.observe(f,self.plan("observe",version=4,workload="tpu-v5e8-device-v1"),Path(td))
        self.assertEqual(r["classification"],"FAIL_DEVICE_NOT_ATTESTED")

    def test_tpu_device_positive_oracle(self):
        d={"schema":"kaggle-rdte-result/v1","workload":"tpu-v5e8-device-v1",
           "status":"PASS",
           "metrics":{"requested_accelerator":"TpuV5E8","tpu_count":8,
                      "jax_backend_tpu":True,"tpu_arithmetic":True}}
        self.assertIsNone(m.verify(d,"tpu-v5e8-device-v1"))

    def test_tpu_device_cpu_fallback_negative(self):
        d={"schema":"kaggle-rdte-result/v1","workload":"tpu-v5e8-device-v1",
           "status":"PASS",
           "metrics":{"requested_accelerator":"TpuV5E8","tpu_count":0,
                      "jax_backend_tpu":False,"tpu_arithmetic":False}}
        with self.assertRaises(m.Denied):
            m.verify(d,"tpu-v5e8-device-v1")
        d["metrics"]["tpu_count"]=8
        d["metrics"]["jax_backend_tpu"]=True
        with self.assertRaises(m.Denied):
            m.verify(d,"tpu-v5e8-device-v1")

    def test_tpu_probe_missing_libs_is_failed_receipt(self):
        import ast
        source=ROOT/"experiments"/"kaggle_rdte"/"tpu_device.py"
        ast.parse(source.read_text(encoding="utf-8"))
        self.assertIn("TPU_JAX_RUNTIME_MISSING",source.read_text(encoding="utf-8"))

    def test_observe_version_exact_and_receipt(self):
        d={"schema":"kaggle-rdte-result/v1","workload":"gpu-cuda-smoke-v1","status":"PASS",
           "accelerator":"gpu","gpu_count":2,"checksum":8386560.0,
           "device_arithmetic_checksums":[8386560.0,8386560.0]}
        f=Fake(output=d)
        with tempfile.TemporaryDirectory() as td:
            receipt=m.observe(f,self.plan("observe",version=3),Path(td))
            self.assertEqual(receipt["state"],"TERMINAL_VERIFIED")
        self.assertEqual(f.calls[1][1],"publicresearcher/ad-rdte-test-rep-0001/3")
    def test_provider_error_no_download(self):
        f=Fake(status="KernelWorkerStatus.ERROR")
        with tempfile.TemporaryDirectory() as td:
            r=m.observe(f,self.plan("observe",version=3),Path(td))
        self.assertEqual(r["state"],"TERMINAL_FAILED")
        self.assertEqual(len(f.calls),4)
    def test_error_carries_missing_hardware_fail_receipt(self):
        d={"schema":"kaggle-rdte-result/v1","workload":"gpu-cuda-smoke-v1",
           "status":"FAIL","failure_class":"CUDA_BUILD_UNAVAILABLE",
           "observed_cuda":False,"observed_gpu_count":0}
        f=Fake(status="KernelWorkerStatus.ERROR",output=d)
        with tempfile.TemporaryDirectory() as td:
            r=m.observe(f,self.plan("observe",version=3),Path(td))
        self.assertEqual(r["classification"],"FAIL_WORKLOAD")
        self.assertEqual(r["failure_class"],"CUDA_BUILD_UNAVAILABLE")
        self.assertEqual(r["native_version"],3)
        self.assertEqual(len(r["result_digest"]),64)
    def test_one_gpu_is_not_t4x2(self):
        d={"schema":"kaggle-rdte-result/v1","workload":"gpu-cuda-smoke-v1",
           "status":"PASS","accelerator":"gpu","gpu_count":1,"checksum":8386560.0}
        with self.assertRaises(m.Denied):
            m.verify(d,"gpu-cuda-smoke-v1")
    def test_nonterminal_no_download(self):
        f=Fake(status="KernelWorkerStatus.RUNNING")
        with tempfile.TemporaryDirectory() as td:
            r=m.observe(f,self.plan("observe",version=3),Path(td))
        self.assertFalse(r["is_terminal"])
        self.assertEqual(len(f.calls),2)

    def test_observe_refuses_mismatched_native_version(self):
        f=Fake(current_version=4)
        with tempfile.TemporaryDirectory() as td, self.assertRaisesRegex(m.Denied,"PROVIDER_VERSION_CHANGED_RECONCILE"):
            m.observe(f,self.plan("observe",version=3),Path(td))
        self.assertEqual(len(f.calls),1)

    def test_observe_refuses_version_change_during_retrieval(self):
        d={"schema":"kaggle-rdte-result/v1","workload":"gpu-cuda-smoke-v1",
           "status":"PASS","accelerator":"gpu","gpu_count":2,"checksum":8386560.0,
           "device_arithmetic_checksums":[8386560.0,8386560.0]}
        f=Fake(output=d,observed_versions=[3,4])
        with tempfile.TemporaryDirectory() as td, self.assertRaisesRegex(m.Denied,"PROVIDER_VERSION_CHANGED_RECONCILE"):
            m.observe(f,self.plan("observe",version=3),Path(td))

if __name__=="__main__":
    unittest.main(verbosity=2)
