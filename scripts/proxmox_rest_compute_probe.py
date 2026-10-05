#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any


class ProxmoxProbeError(RuntimeError):
    pass

PVE_CONTAINER_SOURCE = {
    "repository": "proxmox/pve-container",
    "commit": "5eb5574ee9158ac40a5230de2cf18d7d6345709f",
    "lxc_api_blob": "88067ddebf5a0bd540f91ffd1db11f8eec40cefb",
    "lxc_status_api_blob": "c95fc3c7732d637639ab29e496bc27eafb9d222d",
    "package_version": "6.1.10",
}
PVE_QEMU_PACKAGE_SOURCE = {
    "repository": "proxmox/pve-qemu",
    "commit": "684796e835289dab11af8606fbf7358b93526dd6",
    "package_version": "11.0.0-3",
}
PVE_QEMU_SERVER_SOURCE = {
    "repository": "proxmox/qemu-server",
    "commit": "6785065b3f766f15f6f151af8ec27ec8bb5b07ab",
    "package_version": "9.1.15",
    "api2_qemu_blob": "e029a204d121f3c8b104457ef14eb6d5ce029464",
    "qemu_server_blob": "118f26bc94d9ee8e8c4c39a3d710e67c14f61bc0",
    "changelog_blob": "63ded16d9d06ae0dd114a67d19bb36e14c71c980",
}
PVE_MANAGER_API_SOURCE = {
    "repository": "proxmox/pve-manager",
    "commit": "b9984c6d90a4bd80ab72dc2088c1b9103fb167b1",
    "apt_api_blob": "9cb6e473436719f3024ac09fffaad8faf0d7160d",
    "manager_version": "9.2.2",
}



@dataclass
class Response:
    status: int
    data: Any


class PveApi:
    def __init__(self, base_url: str, username: str, password: str, verify_tls: bool = False, timeout: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.timeout = timeout
        self.ctx = ssl.create_default_context()
        if not verify_tls:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE
        self.ticket: str | None = None
        self.csrf: str | None = None

    def _request(self, method: str, path: str, fields: dict[str, Any] | None = None) -> Response:
        url = self.base_url + "/api2/json" + path
        body = None
        headers = {"Accept": "application/json"}
        if fields is not None:
            body = urllib.parse.urlencode({k: str(v) for k, v in fields.items()}).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if self.ticket:
            headers["Cookie"] = f"PVEAuthCookie={self.ticket}"
        if self.csrf and method not in {"GET", "HEAD"}:
            headers["CSRFPreventionToken"] = self.csrf
        req = urllib.request.Request(url, data=body, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=self.timeout) as r:
                raw = r.read()
                payload = json.loads(raw.decode()) if raw else {}
                return Response(r.status, payload.get("data"))
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode(errors="replace")
            raise ProxmoxProbeError(f"{method} {path}: HTTP {exc.code}: {raw}") from exc

    def login(self) -> None:
        r = self._request("POST", "/access/ticket", {"username": self.username, "password": self.password})
        if not isinstance(r.data, dict) or not r.data.get("ticket") or not r.data.get("CSRFPreventionToken"):
            raise ProxmoxProbeError("ticket response missing ticket/CSRF token")
        self.ticket = r.data["ticket"]
        self.csrf = r.data["CSRFPreventionToken"]

    def get(self, path: str) -> Any:
        return self._request("GET", path).data

    def post(self, path: str, fields: dict[str, Any] | None = None) -> Any:
        return self._request("POST", path, fields or {}).data

    def put(self, path: str, fields: dict[str, Any] | None = None) -> Any:
        return self._request("PUT", path, fields or {}).data

    def delete(self, path: str, fields: dict[str, Any] | None = None) -> Any:
        return self._request("DELETE", path, fields or {}).data


def wait_task(api: PveApi, node: str, upid: str, timeout: float = 180.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    encoded = urllib.parse.quote(upid, safe="")
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        data = api.get(f"/nodes/{node}/tasks/{encoded}/status")
        if isinstance(data, dict):
            last = data
            if data.get("status") == "stopped":
                if data.get("exitstatus") != "OK":
                    raise ProxmoxProbeError(f"task failed: {data!r}")
                return data
        time.sleep(1)
    raise ProxmoxProbeError(f"task timeout: {last!r}")


def node_name(api: PveApi) -> str:
    rows = api.get("/nodes")
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0].get("node"), str):
        raise ProxmoxProbeError(f"expected one disposable PVE node: {rows!r}")
    return rows[0]["node"]


def lxc_create_fields(vmid: int, template: str) -> dict[str, Any]:
    return {
        "vmid": vmid,
        "hostname": f"rdte-lxc-{vmid}",
        "ostemplate": template,
        "rootfs": "local-lvm:2",
        "memory": 256,
        "cores": 1,
        "unprivileged": 1,
        "start": 0,
        "description": "Agent Dispatch disposable REST C0 container",
    }


def vm_create_fields(vmid: int, *, memory: int = 1024) -> dict[str, Any]:
    return {
        "vmid": vmid,
        "name": f"rdte-vm-{vmid}",
        "memory": memory,
        "cores": 1,
        "sockets": 1,
        "cpu": "host",
        "bios": "ovmf",
        "machine": "q35",
        "scsihw": "virtio-scsi-pci",
        "net0": "virtio,bridge=vmbr0",
        "ostype": "l26",
        "start": 0,
        "description": "Agent Dispatch disposable REST V0 VM shell",
    }


def plan_only(kind: str, vmid: int, template: str | None) -> dict[str, Any]:
    if kind == "container":
        if not template:
            raise ProxmoxProbeError("--template is required for container plan")
        create = lxc_create_fields(vmid, template)
        path = f"/nodes/{{node}}/lxc"
    elif kind == "vm":
        create = vm_create_fields(vmid)
        path = f"/nodes/{{node}}/qemu"
    else:
        raise ProxmoxProbeError(f"unsupported kind {kind!r}")
    return {
        "schema": "proxmox-rest-compute-plan/v1",
        "kind": kind,
        "create_path": path,
        "create_fields": create,
        "lifecycle": ["observe-absent", "create", "readback", "start", "stop", "delete", "absence"],
        "claim_boundary": "plan only; guest oracle and runtime qualification are separate",
    }


def main() -> int:
    p=argparse.ArgumentParser()
    p.add_argument("--base-url", default="https://127.0.0.1:8006")
    p.add_argument("--username", default="root@pam")
    p.add_argument("--password-file", type=pathlib.Path)
    p.add_argument("--verify-tls", action="store_true")
    p.add_argument("--kind", choices=["container","vm"], required=True)
    p.add_argument("--vmid", type=int, default=9101)
    p.add_argument("--template")
    p.add_argument("--observe-only", action="store_true")
    p.add_argument("--expected-qemu-server-version")
    p.add_argument("--apply", action="store_true")
    p.add_argument("--out", type=pathlib.Path)
    a=p.parse_args()

    receipt: dict[str,Any] = {
        "schema":"proxmox-rest-compute-c0-v1",
        "kind":a.kind,
        "vmid":a.vmid,
        "classification":"ORACLE_FAILURE",
        "oracleSatisfied":False,
        "api_materialization_oracle":False,
        "guest_oracle":False,
        "claim_boundary":"C0/V0 product REST lifecycle only; guest workload oracle remains separate",
        "cleanup":{"attempted":False,"absent":False},
        "tasks":{},
        "source_contract":{
            "pve_container":PVE_CONTAINER_SOURCE,
            "pve_qemu_package":PVE_QEMU_PACKAGE_SOURCE,
            "qemu_server":PVE_QEMU_SERVER_SOURCE,
            "pve_manager_api":PVE_MANAGER_API_SOURCE,
            "qemu_server_api":"SOURCE_BOUND: exact installed qemu-server 9.1.15 is admitted for V0 product-REST shell lifecycle; runtime VM qualification remains separate",
        },
    }
    def emit(code:int)->int:
        payload=json.dumps(receipt,indent=2,sort_keys=True)+"\n"
        if a.out: a.out.write_text(payload,encoding="utf-8")
        print(payload,end="")
        return code

    api: PveApi | None = None
    node: str | None = None
    base: str | None = None
    ownership_claimed = False

    try:
        plan=plan_only(a.kind,a.vmid,a.template)
        receipt["plan"]=plan
        if not a.apply and not a.observe_only:
            receipt.update({"classification":"SUPPORTED","oracleSatisfied":True,"phase":"plan-only"})
            return emit(0)
        if not a.password_file:
            raise ProxmoxProbeError("--apply/--observe-only requires --password-file")
        password=a.password_file.read_text(encoding="utf-8").strip()
        if not password:
            raise ProxmoxProbeError("password file empty")
        api=PveApi(a.base_url,a.username,password,a.verify_tls)
        api.login()
        version=api.get("/version")
        receipt["pve_version"]=version
        node=node_name(api)
        receipt["node"]=node
        try:
            package_rows=api.get(f"/nodes/{node}/apt/versions")
        except ProxmoxProbeError as package_exc:
            package_rows=[]
            receipt["package_census_error"]=str(package_exc)
        receipt["package_census"]=[
            x for x in (package_rows or [])
            if isinstance(x,dict) and x.get("Package") in {"pve-container","pve-qemu-kvm","qemu-server","pve-manager"}
        ]
        if a.observe_only:
            receipt.update({
                "classification":"SUPPORTED",
                "oracleSatisfied":True,
                "phase":"observe-only",
                "detail":"authenticated PVE API/version/package census completed without compute mutation",
            })
            return emit(0)
        if a.kind=="vm" and not a.expected_qemu_server_version:
            raise ProxmoxProbeError(
                "VM apply blocked: --expected-qemu-server-version must explicitly select the source-bound installed package"
            )
        if a.kind=="vm":
            observed_qemu=[
                x for x in receipt["package_census"]
                if x.get("Package")=="qemu-server"
            ]
            installed_versions={
                str(x.get("OldVersion")) for x in observed_qemu
                if x.get("CurrentState")=="Installed" and x.get("OldVersion")
            }
            available_versions={str(x.get("Version")) for x in observed_qemu if x.get("Version")}
            receipt["qemu_server_package_observation"]={
                "installed_versions":sorted(installed_versions),
                "available_versions":sorted(available_versions),
            }
            if a.expected_qemu_server_version != PVE_QEMU_SERVER_SOURCE["package_version"]:
                raise ProxmoxProbeError(
                    f"VM apply blocked: requested qemu-server source version {a.expected_qemu_server_version!r} "
                    f"is not the admitted {PVE_QEMU_SERVER_SOURCE['package_version']!r}"
                )
            if a.expected_qemu_server_version not in installed_versions:
                raise ProxmoxProbeError(
                    f"VM apply blocked: expected installed qemu-server {a.expected_qemu_server_version!r}, "
                    f"observed installed {sorted(installed_versions)!r}; available={sorted(available_versions)!r}"
                )
        base=f"/nodes/{node}/{'lxc' if a.kind=='container' else 'qemu'}"
        rows=api.get(base)
        if any(int(x.get("vmid",-1))==a.vmid for x in (rows or [])):
            raise ProxmoxProbeError("preexisting vmid blocks ownership-safe apply")
        fields=plan["create_fields"]
        upid=api.post(base,fields)
        if not isinstance(upid,str): raise ProxmoxProbeError(f"create did not return UPID: {upid!r}")
        ownership_claimed=True
        receipt["tasks"]["create"]=wait_task(api,node,upid)
        cfg=api.get(f"{base}/{a.vmid}/config")
        if not isinstance(cfg,dict): raise ProxmoxProbeError("config readback missing")
        receipt["config_readback"]=cfg
        upid=api.post(f"{base}/{a.vmid}/status/start")
        if not isinstance(upid,str): raise ProxmoxProbeError("start did not return UPID")
        receipt["tasks"]["start"]=wait_task(api,node,upid)
        status=api.get(f"{base}/{a.vmid}/status/current")
        if not isinstance(status,dict) or status.get("status")!="running":
            raise ProxmoxProbeError(f"instance not running after start: {status!r}")
        upid=api.post(f"{base}/{a.vmid}/status/stop")
        if not isinstance(upid,str): raise ProxmoxProbeError("stop did not return UPID")
        receipt["tasks"]["stop"]=wait_task(api,node,upid)
        receipt["cleanup"]["attempted"]=True
        upid=api.delete(f"{base}/{a.vmid}",{"purge":1})
        if not isinstance(upid,str): raise ProxmoxProbeError("delete did not return UPID")
        receipt["tasks"]["delete"]=wait_task(api,node,upid)
        rows=api.get(base)
        absent=not any(int(x.get("vmid",-1))==a.vmid for x in (rows or []))
        receipt["cleanup"]["absent"]=absent
        if not absent: raise ProxmoxProbeError("instance remained after REST delete")
        receipt.update({
            "classification":"SUPPORTED",
            "oracleSatisfied":True,
            "api_materialization_oracle":True,
            "phase":"rest-api-lifecycle",
            "detail":"PVE REST create/readback/start/stop/delete/absence passed",
        })
        return emit(0)
    except (OSError,ValueError,ProxmoxProbeError) as exc:
        receipt["detail"]=f"{type(exc).__name__}: {exc}"
        if a.apply and ownership_claimed and api is not None and node is not None and base is not None:
            receipt["cleanup"]["attempted"]=True
            cleanup_errors=[]
            try:
                rows=api.get(base)
                present=any(int(x.get("vmid",-1))==a.vmid for x in (rows or []))
                if present:
                    try:
                        status=api.get(f"{base}/{a.vmid}/status/current")
                    except ProxmoxProbeError:
                        status={}
                    if isinstance(status,dict) and status.get("status")=="running":
                        stop_upid=api.post(f"{base}/{a.vmid}/status/stop")
                        if isinstance(stop_upid,str):
                            receipt["tasks"]["failure_cleanup_stop"]=wait_task(api,node,stop_upid,timeout=60.0)
                        else:
                            cleanup_errors.append(f"failure cleanup stop did not return UPID: {stop_upid!r}")
                    delete_upid=api.delete(f"{base}/{a.vmid}",{"purge":1})
                    if isinstance(delete_upid,str):
                        receipt["tasks"]["failure_cleanup_delete"]=wait_task(api,node,delete_upid,timeout=60.0)
                    else:
                        cleanup_errors.append(f"failure cleanup delete did not return UPID: {delete_upid!r}")
                rows=api.get(base)
                receipt["cleanup"]["absent"]=not any(
                    int(x.get("vmid",-1))==a.vmid for x in (rows or [])
                )
            except (OSError,ValueError,ProxmoxProbeError) as cleanup_exc:
                cleanup_errors.append(f"{type(cleanup_exc).__name__}: {cleanup_exc}")
            if cleanup_errors:
                receipt["cleanup"]["errors"]=cleanup_errors
        return emit(2)


if __name__=="__main__":
    raise SystemExit(main())
