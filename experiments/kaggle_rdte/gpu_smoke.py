#!/usr/bin/env python3
"""Public-safe single-GPU numerical check; no credentials or private inputs."""
import json
import sys
from pathlib import Path

def main():
    import torch
    result = {"schema":"kaggle-rdte-result/v1","workload":"gpu-cuda-smoke-v1","status":"FAIL"}
    try:
        if not torch.cuda.is_available():
            raise RuntimeError("CUDA_DEVICE_UNAVAILABLE")
        x = torch.arange(4096, device="cuda:0", dtype=torch.float32).reshape(64,64)
        y = x @ torch.eye(64, device="cuda:0")
        torch.cuda.synchronize()
        checksum = float(y.sum().item())
        if not torch.equal(x,y) or checksum != 8386560.0:
            raise AssertionError("CHECKSUM_MISMATCH")
        result.update(status="PASS", accelerator="gpu", gpu_count=torch.cuda.device_count(), checksum=checksum)
    except Exception as exc:
        result["failure_class"] = type(exc).__name__
    output = Path("/kaggle/working") if Path("/kaggle/working").is_dir() else Path.cwd()
    (output / "kaggle_rdte_result.json").write_text(json.dumps(result,sort_keys=True)+"\n")
    print("KAGGLE_RDTE=" + result["status"])
    return 0 if result["status"] == "PASS" else 2

if __name__ == "__main__":
    sys.exit(main())
