#!/usr/bin/env python3
"""Public synthetic CUDA GPU T4x2 hardware qualification; no credential/network."""
import json
import sys
from pathlib import Path

SCHEMA = "kaggle-rdte-result/v1"

def main():
    result = {"schema":SCHEMA,"workload":"gpu-cuda-smoke-v1","status":"FAIL",
              "requested_accelerator":"NvidiaTeslaT4",
              "observed_cuda":False,"observed_gpu_count":0}
    try:
        import torch
        result["torch_version"] = str(torch.__version__)
        result["torch_cuda_build"] = str(torch.version.cuda) if torch.version.cuda else None
        if not torch.version.cuda:
            raise RuntimeError("CUDA_BUILD_UNAVAILABLE")
        result["observed_cuda"] = bool(torch.cuda.is_available())
        result["observed_gpu_count"] = int(torch.cuda.device_count())
        if not result["observed_cuda"] or result["observed_gpu_count"] == 0:
            raise RuntimeError("CUDA_DEVICE_UNAVAILABLE")
        if result["observed_gpu_count"] != 2:
            raise RuntimeError("GPU_COUNT_MISMATCH")
        devices = [torch.cuda.get_device_properties(i).name
                   for i in range(result["observed_gpu_count"])]
        if not all("T4" in name for name in devices):
            raise RuntimeError("GPU_MODEL_MISMATCH")
        x = torch.arange(4096, device="cuda:0", dtype=torch.float32).reshape(64,64)
        y = x @ torch.eye(64, device="cuda:0")
        torch.cuda.synchronize()
        checksum = float(y.sum().item())
        if not torch.equal(x,y) or checksum != 8386560.0:
            raise RuntimeError("CHECKSUM_MISMATCH")
        result.update(status="PASS", accelerator="gpu", gpu_count=len(devices),
                      device_models=devices, checksum=checksum)
    except Exception as exc:
        result["failure_class"] = str(exc) if str(exc) in {
            "CUDA_BUILD_UNAVAILABLE","CUDA_DEVICE_UNAVAILABLE","GPU_COUNT_MISMATCH",
            "GPU_MODEL_MISMATCH","CHECKSUM_MISMATCH"} else type(exc).__name__
    output = Path("/kaggle/working") if Path("/kaggle/working").is_dir() else Path.cwd()
    (output/"kaggle_rdte_result.json").write_text(json.dumps(result,sort_keys=True)+"\n")
    print("KAGGLE_RDTE="+result["status"])
    return 0 if result["status"]=="PASS" else 2

if __name__=="__main__":
    sys.exit(main())
