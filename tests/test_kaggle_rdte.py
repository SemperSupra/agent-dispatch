#!/usr/bin/env python3
"""Offline GitHub/Kaggle protocol tests. No credential, provider call, or GPU allocation."""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("kaggle_rdte", ROOT/"scripts"/"kaggle_rdte.py")
import sys
m = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = m
SPEC.loader.exec_module(m)

class Fake:
    CONFIG_NAME_USER = "username"
    def __init__(self, owned=(), version=1, error=None, status="KernelWorkerStatus.COMPLETE", output=None):
        self.owned=list(owned)
        self.version=version
        self.error=error
        self.status=status
        self.output=output
        self.pushed=0
        self.calls=[]
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
           "status":"PASS","accelerator":"gpu","gpu_count":2,"checksum":8386560.0}
        self.assertIsNone(m.verify(d,"gpu-cuda-smoke-v1"))
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
        f=Fake(status="KernelWorkerStatus.ERROR",output=d)
        with tempfile.TemporaryDirectory() as td:
            r=m.observe(f,self.plan("observe",version=5),Path(td))
        self.assertEqual(r["classification"],"FAIL_RUNTIME_SOFTWARE")
        self.assertEqual(r["native_version"],5)

    def test_terminal_failed_receipt_keeps_unattested_device_unknown(self):
        d={"schema":"kaggle-rdte-result/v1","workload":"tpu-v5e8-device-v1",
           "status":"FAIL","failure_class":"TPU_DEVICE_UNAVAILABLE"}
        f=Fake(status="KernelWorkerStatus.ERROR",output=d)
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
           "accelerator":"gpu","gpu_count":2,"checksum":8386560.0}
        f=Fake(output=d)
        with tempfile.TemporaryDirectory() as td:
            receipt=m.observe(f,self.plan("observe",version=3),Path(td))
            self.assertEqual(receipt["state"],"TERMINAL_VERIFIED")
        self.assertEqual(f.calls[0][1],"publicresearcher/ad-rdte-test-rep-0001/3")
    def test_provider_error_no_download(self):
        f=Fake(status="KernelWorkerStatus.ERROR")
        with tempfile.TemporaryDirectory() as td:
            r=m.observe(f,self.plan("observe",version=3),Path(td))
        self.assertEqual(r["state"],"TERMINAL_FAILED")
        self.assertEqual(len(f.calls),2)
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
        self.assertEqual(len(f.calls),1)

if __name__=="__main__":
    unittest.main(verbosity=2)
