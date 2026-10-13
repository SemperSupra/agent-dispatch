#!/usr/bin/env python3
"""Synthetic JAX/TPU latent-bridge training pipeline smoke, NOT real Neuralese evidence."""
import json
import sys
from pathlib import Path

def train():
    import jax
    import jax.numpy as jnp
    import numpy as np
    devices = jax.devices()
    tpus = [d for d in devices if d.platform == "tpu"]
    if not tpus or jax.default_backend() != "tpu":
        raise RuntimeError("TPU_DEVICE_UNAVAILABLE")
    rng = np.random.default_rng(20261013)
    width, ntrain, ntest = 16, 512, 128
    basis_a, _ = np.linalg.qr(rng.normal(size=(width,width)))
    basis_b, _ = np.linalg.qr(rng.normal(size=(width,width)))
    z = rng.normal(size=(ntrain+ntest,width)).astype("float32")
    x = (z @ basis_a).astype("float32")
    y = (z @ basis_b).astype("float32")
    tx,ty = jnp.array(x[:ntrain]),jnp.array(y[:ntrain])
    hx,hy = jnp.array(x[ntrain:]),jnp.array(y[ntrain:])
    shuffled = jnp.array(y[:ntrain][rng.permutation(ntrain)])
    @jax.jit
    def step(w,x,y):
        return w - 0.5 * jax.grad(lambda a: jnp.mean((x@a-y)**2))(w)
    w = jnp.eye(width, dtype=jnp.float32)
    null = jnp.eye(width, dtype=jnp.float32)
    for _ in range(160):
        w = step(w,tx,ty)
        null = step(null,tx,shuffled)
    def heldout(a):
        pred = hx @ a
        return float(jnp.mean(jnp.sum(pred*hy,axis=1)/(jnp.linalg.norm(pred,axis=1)*jnp.linalg.norm(hy,axis=1)+1e-9)))
    score, control = heldout(w), heldout(null)
    if score < 0.75 or score-control < 0.45:
        raise AssertionError("SYNTHETIC_BRIDGE_CONTROL_FAILED")
    return {"accelerator":"tpu","tpu_count":len(tpus),"jax_version":jax.__version__,
            "seed":20261013,"training_examples":ntrain,"holdout_examples":ntest,
            "updates":160,"heldout_cosine":round(score,6),"shuffled_control_cosine":round(control,6),
            "scope":"synthetic-method-sanity-only"}

def main():
    result = {"schema":"kaggle-rdte-result/v1","workload":"tpu-jax-bridge-v1","status":"FAIL"}
    try:
        result.update(metrics=train(),status="PASS")
    except Exception as exc:
        result["failure_class"]=type(exc).__name__
    output=Path("/kaggle/working") if Path("/kaggle/working").is_dir() else Path.cwd()
    (output/"kaggle_rdte_result.json").write_text(json.dumps(result,sort_keys=True)+"\n")
    print("KAGGLE_RDTE="+result["status"])
    return 0 if result["status"]=="PASS" else 2

if __name__=="__main__":
    sys.exit(main())
