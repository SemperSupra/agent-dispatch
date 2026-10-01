#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, pathlib, re
from typing import Any

SHA=re.compile(r"^[0-9a-f]{64}$")
class FixtureError(RuntimeError): pass

def load(p:pathlib.Path)->dict[str,Any]:
    try: v=json.loads(p.read_text(encoding="utf-8"))
    except (OSError,json.JSONDecodeError) as exc: raise FixtureError(f"cannot read {p}: {exc}") from exc
    if not isinstance(v,dict): raise FixtureError("fixture registry must be object")
    return v

def validate(c:dict[str,Any],root:pathlib.Path)->dict[str,Any]:
    if c.get("schema")!="semper-supra.compute-guest-fixtures/v1": raise FixtureError("unsupported schema")
    v1=c.get("linux_v1",{}); src=v1.get("source",{})
    if v1.get("state")!="SOURCE_PINNED": raise FixtureError("V1 source must be pinned")
    if not SHA.fullmatch(str(src.get("sha256",""))): raise FixtureError("V1 sha256 invalid")
    url=str(src.get("url",""))
    if "release-20260926" not in url or "/release/" in url.replace("release-20260926",""):
        raise FixtureError("V1 URL must remain dated, not moving release alias")
    ci=v1.get("cloud_init",{})
    for key in ("user_data_template","meta_data_template"):
        p=root/ci.get(key,"")
        if not p.is_file(): raise FixtureError(f"missing cloud-init template {p}")
    user=(root/ci["user_data_template"]).read_text(encoding="utf-8")
    meta=(root/ci["meta_data_template"]).read_text(encoding="utf-8")
    if "{{RDTE_NONCE}}" not in user or "{{RUN_ID}}" not in meta: raise FixtureError("cloud-init placeholders missing")
    oracle=v1.get("oracle",{})
    if oracle.get("external_observation_required") is not True or oracle.get("guest_port")!=18080:
        raise FixtureError("V1 external nonce oracle invalid")
    fc=c.get("firecracker_v2",{}); rel=fc.get("release",{})
    if fc.get("state")!="BINARY_PINNED_INNER_GUEST_OPEN": raise FixtureError("V2 state must preserve inner guest gap")
    if len(str(rel.get("source_commit","")) )!=40 or not SHA.fullmatch(str(rel.get("sha256",""))):
        raise FixtureError("Firecracker source/asset identity invalid")
    inner=fc.get("inner_microvm",{})
    if any(inner.get(x,{}).get("state")!="OPEN" for x in ("kernel","rootfs","nonce_oracle")):
        raise FixtureError("V2 inner microVM must remain OPEN until exact artifacts are pinned")
    win=c.get("windows_w1",{}); pol=win.get("source_policy",{})
    if win.get("state")!="MEDIA_ACQUISITION_OPEN": raise FixtureError("Windows W1 media must remain acquisition-open")
    if pol.get("product_key_required") is not False or pol.get("exact_sha256_required") is not True:
        raise FixtureError("Windows source policy invalid")
    if win.get("winbot_backend_status")!="NOT_ELIGIBLE_UNTIL_W1_ACCEPTED":
        raise FixtureError("WinBot boundary weakened")
    return {"schema":"semper-supra.compute-guest-fixtures-validation/v1","status":"PASS",
            "linux_v1":v1["id"],"firecracker_v2":fc["id"],"windows_w1":win["id"],
            "claim_boundary":"source fixtures only; runtime rungs remain OPEN"}

def main()->int:
    p=argparse.ArgumentParser()
    p.add_argument("--registry",type=pathlib.Path,default=pathlib.Path("config/compute-guest-fixtures.json"))
    p.add_argument("--repo-root",type=pathlib.Path,default=pathlib.Path("."))
    a=p.parse_args()
    try: out=validate(load(a.registry),a.repo_root)
    except FixtureError as exc:
        print(json.dumps({"status":"ERROR","error":str(exc)},sort_keys=True)); return 2
    print(json.dumps(out,indent=2,sort_keys=True)); return 0
if __name__=="__main__": raise SystemExit(main())
