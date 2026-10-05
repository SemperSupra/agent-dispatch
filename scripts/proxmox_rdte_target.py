#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, pathlib, re, sys

SHA40=re.compile(r"^[0-9a-f]{40}$")
SHA256=re.compile(r"^[0-9a-f]{64}$")
SHA512=re.compile(r"^[0-9a-f]{128}$")

class TargetError(RuntimeError):
    pass

def load_registry(path:pathlib.Path):
    try:
        doc=json.loads(path.read_text(encoding="utf-8"))
    except (OSError,json.JSONDecodeError) as exc:
        raise TargetError(f"cannot read target registry: {exc}") from exc
    if not isinstance(doc,dict) or doc.get("schema")!="gha-kvm-proxmox-targets/v1":
        raise TargetError("unsupported target registry schema")
    targets=doc.get("targets")
    if not isinstance(targets,list) or not targets:
        raise TargetError("target registry has no targets")
    result={}
    for i,t in enumerate(targets):
        if not isinstance(t,dict):
            raise TargetError(f"targets[{i}] must be an object")
        version=t.get("version")
        if not isinstance(version,str) or not version or version in result:
            raise TargetError(f"invalid or duplicate target version at index {i}")
        if not isinstance(t.get("runtime_admitted"),bool):
            raise TargetError(f"{version}: runtime_admitted must be boolean")
        if not isinstance(t.get("authority_issue"),int):
            raise TargetError(f"{version}: authority_issue must be integer")
        for key in (
            "iso_name","iso_url","installer_source_version","vm_source_status",
            "pve_manager_package_version","pve_container_package_version","pve_qemu_package_version",
        ):
            if not isinstance(t.get(key),str) or not t[key]:
                raise TargetError(f"{version}: missing {key}")
        for key in (
            "installer_source_commit","pve_manager_source_commit","pve_manager_apt_api_blob",
            "pve_access_control_source_commit","pve_container_source_commit","pve_container_lxc_api_blob",
            "pve_container_status_api_blob","pve_qemu_source_commit","pve_qemu_submodule_commit",
        ):
            if not isinstance(t.get(key),str) or not SHA40.fullmatch(t[key]):
                raise TargetError(f"{version}: {key} must be exact 40-hex")
        if not isinstance(t.get("iso_sha256"),str) or not SHA256.fullmatch(t["iso_sha256"]):
            raise TargetError(f"{version}: iso_sha256 must be exact 64-hex")
        fixture=t.get("container_fixture")
        if not isinstance(fixture,dict):
            raise TargetError(f"{version}: container_fixture missing")
        for key in ("template_name","template_url"):
            if not isinstance(fixture.get(key),str) or not fixture[key]:
                raise TargetError(f"{version}: container_fixture.{key} missing")
        if not isinstance(fixture.get("template_sha512"),str) or not SHA512.fullmatch(fixture["template_sha512"]):
            raise TargetError(f"{version}: container_fixture.template_sha512 must be exact 128-hex")
        for url in (t["iso_url"],fixture["template_url"]):
            if any(token in url.lower() for token in ("latest","nightly","master+")):
                raise TargetError(f"{version}: floating URL prohibited")
        surfaces=t.get("required_rest_surfaces")
        if not isinstance(surfaces,list) or not surfaces or not all(isinstance(x,str) and x.startswith("/") for x in surfaces):
            raise TargetError(f"{version}: required_rest_surfaces invalid")
        result[version]=t
    return result

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--registry",type=pathlib.Path,required=True)
    p.add_argument("--version",required=True)
    p.add_argument("--require-runtime-admitted",action="store_true")
    a=p.parse_args()
    try:
        targets=load_registry(a.registry)
        if a.version not in targets:
            raise TargetError(f"exact Proxmox target is not registered: {a.version}")
        target=targets[a.version]
        if a.require_runtime_admitted and target["runtime_admitted"] is not True:
            raise TargetError(f"Proxmox target is source-profiled but not runtime-admitted: {a.version}")
        print(json.dumps(target,indent=2,sort_keys=True))
        return 0
    except TargetError as exc:
        print(f"ERROR: {exc}",file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
