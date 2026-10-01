#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
import time
from typing import Any

try:
    from scripts.compute_materialization_contract import ContractError, choose_adapter, load, target, validate
    from scripts.truenas_middleware_ddp_probe import WebSocket, ddp_call, wait_for
except ModuleNotFoundError:
    from compute_materialization_contract import ContractError, choose_adapter, load, target, validate
    from truenas_middleware_ddp_probe import WebSocket, ddp_call, wait_for


class ProbeError(RuntimeError):
    pass


def normalize_system_version(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ProbeError(f"invalid system.version: {value!r}")
    return value.removeprefix("TrueNAS-")


def native_vm_create_payload(name: str, generation: int = 1) -> dict[str, Any]:
    return {
        "name": name,
        "description": f"Agent Dispatch disposable VM V0 fixture generation {generation}",
        "vcpus": 1,
        "cores": 1,
        "threads": 1,
        "memory": 512,
        "cpu_mode": "HOST-MODEL",
        "autostart": False,
        "ensure_display_device": False,
        "time": "UTC",
        "bootloader": "UEFI",
        "trusted_platform_module": False,
        "hyperv_enlightenments": False,
        "enable_secure_boot": False,
        "shutdown_timeout": 30,
    }


def legacy_vm_create_payload(name: str, image: str, generation: int = 1) -> dict[str, Any]:
    if not image:
        raise ProbeError("legacy Incus VM adapter requires --legacy-image")
    return {
        "name": name,
        "source_type": "IMAGE",
        "image": image,
        "remote": "LINUX_CONTAINERS",
        "instance_type": "VM",
        "autostart": False,
        "environment": {"RDTE_GENERATION": str(generation)},
        "memory": 512 * 1024 * 1024,
        "root_disk_size": 5,
        "root_disk_io_bus": "VIRTIO-BLK",
        "secure_boot": False,
        "enable_vnc": False,
    }


def owned_zvol_device(vm_id: int, zvol_name: str, size_bytes: int) -> dict[str, Any]:
    if not zvol_name or "/" not in zvol_name:
        raise ProbeError("owned ZVOL name must include a pool/dataset prefix")
    return {
        "vm": vm_id,
        "attributes": {
            "dtype": "DISK",
            "path": None,
            "type": "VIRTIO",
            "create_zvol": True,
            "zvol_name": zvol_name,
            "zvol_volsize": size_bytes,
            "boot": False,
        },
        "order": 1000,
    }


def main() -> int:
    p=argparse.ArgumentParser()
    p.add_argument("--registry",type=pathlib.Path,default=pathlib.Path("config/compute-materialization-targets.json"))
    p.add_argument("--target-version",required=True)
    p.add_argument("--name",default="rdte-compute-vm-v0")
    p.add_argument("--legacy-image")
    p.add_argument("--zvol-name")
    p.add_argument("--zvol-size-bytes",type=int,default=2*1024*1024*1024)
    p.add_argument("--host",default="127.0.0.1")
    p.add_argument("--port",type=int)
    p.add_argument("--tls",action="store_true")
    p.add_argument("--password-file",type=pathlib.Path)
    p.add_argument("--timeout",type=float,default=8.0)
    p.add_argument("--job-timeout",type=float,default=600.0)
    p.add_argument("--apply",action="store_true")
    p.add_argument("--out",type=pathlib.Path)
    a=p.parse_args()

    receipt={
        "schema":"truenas-compute-vm-v0/v1",
        "classification":"ORACLE_FAILURE",
        "oracleSatisfied":False,
        "v0_oracle_satisfied":False,
        "v1_guest_oracle_satisfied":False,
        "v2_firecracker_oracle_satisfied":False,
        "windows_w1_oracle_satisfied":False,
        "target_version_requested":a.target_version,
        "name":a.name,
        "cleanup":{"attempted":False,"vm_absent":False,"device_absent":False},
        "claim_boundary":"V0 native VM/device lifecycle only; Linux guest, Firecracker and Windows 11 remain separate rungs",
    }
    ws=None
    call=None
    vm_id=None
    device_id=None
    adapter_id=None

    def emit()->int:
        payload=json.dumps(receipt,indent=2,sort_keys=True)+"\n"
        if a.out:
            a.out.write_text(payload,encoding="utf-8")
        print(payload,end="")
        return 0 if receipt.get("oracleSatisfied") else 2

    try:
        registry=load(a.registry)
        validate(registry)
        row=target(registry,"truenas",a.target_version)
        receipt["source_fingerprint"]=row["source_fingerprint"]
        receipt["api_schema_fingerprint"]=row["api_schema_fingerprint"]

        if not a.apply:
            receipt.update({
                "classification":"SUPPORTED",
                "oracleSatisfied":True,
                "phase":"plan-only",
                "detail":"V0 probe contract validated; apply was not requested",
                "apply_authorized":False,
            })
            return emit()

        if not a.port or not a.password_file:
            raise ProbeError("--apply requires --port and --password-file")
        password=a.password_file.read_text(encoding="utf-8").strip()
        if not password:
            raise ProbeError("password file was empty")

        ws=WebSocket(a.host,a.port,timeout=a.timeout,tls=a.tls)
        ws.send_json({"msg":"connect","version":"1","support":["1"]})
        connected=wait_for(ws,lambda m:m.get("msg") in {"connected","failed"})
        if connected.get("msg")!="connected":
            raise ProbeError(f"DDP connection failed: {connected!r}")
        request_id=1

        def _call(method:str,params:list[Any]):
            nonlocal request_id
            result=ddp_call(ws,str(request_id),method,params)
            request_id+=1
            return result
        call=_call

        auth=call("auth.login_ex",[{
            "mechanism":"PASSWORD_PLAIN","username":"truenas_admin","password":password,
        }])
        if not isinstance(auth,dict) or auth.get("response_type")!="SUCCESS":
            raise ProbeError("authentication did not return SUCCESS")

        observed=normalize_system_version(call("system.version",[]))
        receipt["target_version_observed"]=observed
        if observed!=a.target_version:
            raise ProbeError(f"target mismatch: expected {a.target_version}, observed {observed}")

        methods=call("core.get_methods",[])
        if not isinstance(methods,dict):
            raise ProbeError("core.get_methods did not return method map")
        adapter=choose_adapter(registry,"truenas",observed,"vm",set(methods))
        adapter_id=adapter["id"]
        receipt["adapter"]=adapter
        required_device=set(adapter.get("required_device_methods",[]))
        missing_device=sorted(required_device-set(methods))
        if missing_device:
            raise ProbeError(f"required VM device methods missing: {missing_device}")

        if adapter_id=="truenas-virt-incus-vm":
            rows=call("virt.instance.query",[[["id","=",a.name]]])
            if rows:
                raise ProbeError(f"preexisting VM {a.name!r} blocks ownership-safe apply")
            payload=legacy_vm_create_payload(a.name,a.legacy_image,1)
            receipt["desired_create"]=payload
            job=call("virt.instance.create",[payload])
            if not isinstance(job,int) or isinstance(job,bool):
                raise ProbeError(f"virt.instance.create did not return job id: {job!r}")
            deadline=time.monotonic()+a.job_timeout
            while time.monotonic()<deadline:
                state=call("core.get_jobs",[[["id","=",job]],{"get":True}])
                if state and state.get("state")=="SUCCESS":
                    break
                if state and state.get("state") in {"FAILED","ABORTED"}:
                    raise ProbeError(f"legacy VM create failed: {state.get('error') or state.get('exception')}")
                time.sleep(1)
            else:
                raise ProbeError("legacy VM create timeout")
            rows=call("virt.instance.query",[[["id","=",a.name]]])
            if not rows or rows[0].get("type")!="VM":
                raise ProbeError("legacy VM readback failed")
            call("virt.instance.update",[a.name,{"environment":{"RDTE_GENERATION":"2"}}])
            rows=call("virt.instance.query",[[["id","=",a.name]]])
            if not rows or rows[0].get("environment",{}).get("RDTE_GENERATION")!="2":
                raise ProbeError("legacy VM update readback failed")
            djob=call("virt.instance.delete",[a.name])
            if not isinstance(djob,int) or isinstance(djob,bool):
                raise ProbeError(f"virt.instance.delete did not return job id: {djob!r}")
            deadline=time.monotonic()+a.job_timeout
            while time.monotonic()<deadline:
                state=call("core.get_jobs",[[["id","=",djob]],{"get":True}])
                if state and state.get("state")=="SUCCESS":
                    break
                if state and state.get("state") in {"FAILED","ABORTED"}:
                    raise ProbeError(f"legacy VM delete failed: {state.get('error') or state.get('exception')}")
                time.sleep(1)
            rows=call("virt.instance.query",[[["id","=",a.name]]])
            receipt["cleanup"]={"attempted":True,"vm_absent":not rows,"device_absent":True}
            if rows:
                raise ProbeError("legacy VM remained after delete")
        elif adapter_id=="truenas-vm-libvirt":
            rows=call("vm.query",[[["name","=",a.name]]])
            if rows:
                raise ProbeError(f"preexisting VM {a.name!r} blocks ownership-safe apply")
            payload=native_vm_create_payload(a.name,1)
            receipt["desired_create"]=payload
            created=call("vm.create",[payload])
            if not isinstance(created,dict) or not isinstance(created.get("id"),int):
                raise ProbeError(f"vm.create readback invalid: {created!r}")
            vm_id=created["id"]
            rows=call("vm.query",[[["id","=",vm_id]]])
            if not rows or rows[0].get("name")!=a.name:
                raise ProbeError("native VM readback failed")
            call("vm.update",[vm_id,{"description":"Agent Dispatch disposable VM V0 fixture generation 2"}])
            rows=call("vm.query",[[["id","=",vm_id]]])
            if not rows or "generation 2" not in rows[0].get("description",""):
                raise ProbeError("native VM update readback failed")

            if not a.zvol_name:
                raise ProbeError("native VM V0 requires --zvol-name for ownership-bound device test")
            device_payload=owned_zvol_device(vm_id,a.zvol_name,a.zvol_size_bytes)
            receipt["desired_device"]=device_payload
            device=call("vm.device.create",[device_payload])
            if not isinstance(device,dict) or not isinstance(device.get("id"),int):
                raise ProbeError(f"vm.device.create readback invalid: {device!r}")
            device_id=device["id"]
            devices=call("vm.device.query",[[["id","=",device_id],["vm","=",vm_id]]])
            if not devices or devices[0].get("attributes",{}).get("zvol_name")!=a.zvol_name:
                raise ProbeError("owned ZVOL device readback failed")
            call("vm.device.update",[device_id,{"order":900}])
            devices=call("vm.device.query",[[["id","=",device_id]]])
            if not devices or devices[0].get("order")!=900:
                raise ProbeError("VM device update readback failed")
            call("vm.device.delete",[device_id,{"force":True,"zvol":True,"raw_file":False}])
            devices=call("vm.device.query",[[["id","=",device_id]]])
            if devices:
                raise ProbeError("VM device remained after owned ZVOL deletion")
            receipt["cleanup"]["device_absent"]=True
            call("vm.delete",[vm_id,{"zvols":False,"force":True}])
            rows=call("vm.query",[[["id","=",vm_id]]])
            receipt["cleanup"].update({"attempted":True,"vm_absent":not rows})
            if rows:
                raise ProbeError("native VM remained after delete")
        else:
            raise ProbeError(f"unsupported VM adapter: {adapter_id}")

        receipt.update({
            "classification":"SUPPORTED",
            "oracleSatisfied":True,
            "v0_oracle_satisfied":True,
            "phase":"v0-native-vm-device-lifecycle",
            "detail":"native TrueNAS VM/device CRUD, mutation readback and ownership-bound cleanup passed",
        })
        return emit()
    except (ProbeError,ContractError,OSError,RuntimeError,ValueError) as exc:
        receipt["detail"]=f"{type(exc).__name__}: {exc}"
        receipt["cleanup"]["attempted"]=bool(a.apply)
        # Do not perform speculative blind cleanup here. Runtime integration must wrap this V0
        # probe in an experiment-owned target and reconcile exact observed IDs before retry.
        return emit()
    finally:
        if ws is not None:
            try:
                ws.close()
            except Exception:
                pass

if __name__=="__main__":
    raise SystemExit(main())
