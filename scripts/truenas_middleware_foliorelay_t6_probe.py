#!/usr/bin/env python3
"""TrueNAS T6 oracle for the exact Foundry-exported FolioRelay control."""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import pathlib
import re
import socket
import ssl
import struct
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

from truenas_middleware_ddp_probe import WebSocket, ddp_call, wait_for

EXPECTED_SCHEMA = "semper-supra.foliorelay-truenas-t6-control/1"
EXPECTED_APP_NAME = "rdte-t6-foliorelay"
DBUS_SOCKET = "/run/dbus/system_bus_socket"
AVAHI_TARGETS = {"25.04.1","25.04.2.6","25.10.7"}
DIRECT_TARGETS = {"26.0.0-BETA.3"}
AVAHI_DISCOVERY_USER = "65534:10001"
AVAHI_DISCOVERY_COMMAND = [
    "-identity-file","/var/lib/foliorelay-control/config/printer.json",
    "-backend","avahi",
    "-dbus-address","unix:path=/run/dbus/system_bus_socket",
]
OBSERVER_APP_NAME = "rdte-t6-foliorelay-observer"
EXPECTED_CONTROL = "ghcr.io/sempersupra/foliorelay-control@sha256:c8d5787162db919f84e9607d13f368995138861355f3fa269cbb10561f24d80d"
EXPECTED_CUPS = "ghcr.io/sempersupra/foliorelay-cups@sha256:0997ad2054ca5e57f34291372aed55f549eee9ff201f171b430436b0655c0814"
OBSERVER_IMAGE = "docker.io/library/hello-world@sha256:5e23090353324d887c48ad5e5c56d294eab81588df9605b07d1afe895f9cc8f8"
DATASET = "rdtepool/foliorelay-t6"
ROOT = "/mnt/rdtepool/foliorelay-t6"
TOKEN_PATH = ROOT + "/secrets/control.token"
OBSERVER_DIR = ROOT + "/observer"
TOKEN = b"foliorelay-t6-public-fixture-token-0001\n"
PUBLIC_HOST = "foliorelay-t6.local"
PUBLIC_IPP_PORT = 8634
PUBLIC_RESOURCE_PATH = "/printers/FolioRelay"
PUBLIC_URI = f"ipp://{PUBLIC_HOST}:{PUBLIC_IPP_PORT}{PUBLIC_RESOURCE_PATH}"
OBSERVER_LOG_TAIL_LINES = 200
OBSERVER_LOG_MAX_EVENTS = 200
OBSERVER_LOG_CAPTURE_SECONDS = 2.0

def canonical_sha256(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def reconciliation_action(app_state, live_compose, desired_compose):
    if app_state is None:
        return "CREATE"
    if app_state in {"DEPLOYING","STOPPING"}:
        return "WAIT"
    if app_state not in {"RUNNING","STOPPED"}:
        return "FAIL_CLOSED"
    if not isinstance(live_compose, dict):
        return "FAIL_CLOSED"
    return "NOOP" if canonical_sha256(live_compose)==canonical_sha256(desired_compose) else "UPDATE"

def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()

def load_json(path: pathlib.Path):
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"{path.name} must be an object")
    return value

def validate_discovery_materialization(services: dict, target_version: str):
    discovery=services.get("discovery") or {}
    dbus_mounts=[]
    for service_name,service in services.items():
        for mount in (service or {}).get("volumes") or []:
            if not isinstance(mount,dict):
                continue
            paths=[mount.get("source"),mount.get("target")]
            if any(isinstance(x,str) and (x=="/run/dbus" or x.startswith("/run/dbus/") or x=="/var/run/dbus" or x.startswith("/var/run/dbus/")) for x in paths):
                dbus_mounts.append((service_name,mount))
    if target_version in AVAHI_TARGETS:
        if discovery.get("command")!=AVAHI_DISCOVERY_COMMAND:
            raise RuntimeError("25.x discovery command drifted from exact Avahi contract")
        if discovery.get("user")!=AVAHI_DISCOVERY_USER:
            raise RuntimeError("25.x discovery user drifted from exact Avahi contract")
        if len(dbus_mounts)!=1:
            raise RuntimeError("25.x requires exactly one host D-Bus mount")
        service_name,mount=dbus_mounts[0]
        if not (
            service_name=="discovery"
            and mount.get("type")=="bind"
            and mount.get("source")==DBUS_SOCKET
            and mount.get("target")==DBUS_SOCKET
            and mount.get("read_only") is True
        ):
            raise RuntimeError("25.x host D-Bus coupling exceeds exact read-only Avahi socket")
        return "avahi"
    if target_version in DIRECT_TARGETS:
        if dbus_mounts:
            raise RuntimeError("direct discovery target must not couple to host D-Bus")
        command=discovery.get("command") or []
        if "-backend" in command or "-dbus-address" in command or "user" in discovery:
            raise RuntimeError("direct discovery target drifted into Avahi materialization")
        return "direct"
    raise RuntimeError(f"unsupported FolioRelay target version {target_version!r}")

def validate_host_path_requirements(control: dict, target_version: str):
    runtime=control.get("runtime") or {}
    requirements=runtime.get("host_path_requirements")
    if not isinstance(requirements,list):
        raise RuntimeError("Foundry control missing host_path_requirements")
    expected={
        ROOT+"/control":("directory","0710" if target_version in AVAHI_TARGETS else "0700"),
        ROOT+"/artifacts":("directory","0700"),
        ROOT+"/cups-state":("directory","0755"),
        ROOT+"/cups-spool":("directory","0755"),
        ROOT+"/secrets":("directory","0700"),
        TOKEN_PATH:("file","0400"),
    }
    scheme=(runtime.get("management_scheme") or "http").lower()
    if scheme=="https":
        tls_root=runtime.get("management_tls_root")
        if tls_root!=ROOT+"/tls":
            raise RuntimeError("HTTPS management TLS root drifted")
        expected[tls_root]=("directory","0700")
    elif scheme!="http":
        raise RuntimeError(f"unsupported management scheme {scheme!r}")
    by_path={}
    for item in requirements:
        if not isinstance(item,dict):
            raise RuntimeError("host_path_requirements entries must be objects")
        path=item.get("path")
        if not isinstance(path,str) or path in by_path:
            raise RuntimeError("host_path_requirements path missing or duplicated")
        by_path[path]=item
    if set(by_path)!=set(expected):
        raise RuntimeError("Foundry host path set drifted")
    for path,(kind,mode) in expected.items():
        item=by_path[path]
        if item.get("kind")!=kind or item.get("mode")!=mode:
            raise RuntimeError(f"Foundry host path kind/mode drifted: {path}")
        if item.get("uid")!=10001 or item.get("gid")!=10001:
            raise RuntimeError(f"Foundry host path ownership drifted: {path}")
    return [by_path[item["path"]] for item in requirements]

def middleware_mode(mode: str) -> str:
    if not isinstance(mode,str) or not re.fullmatch(r"0?[0-7]{3}",mode):
        raise RuntimeError(f"invalid host path mode {mode!r}")
    return mode[-3:]

def load_control(root: pathlib.Path, foundry_ref: str, target_version: str):
    control = load_json(root / "control.json")
    compose = load_json(root / "compose.json")
    if control.get("schema") != EXPECTED_SCHEMA:
        raise RuntimeError("unexpected FolioRelay T6 control schema")
    if control.get("foundry_ref") != foundry_ref:
        raise RuntimeError("Foundry source ref drifted")
    if control.get("secrets_captured") is not False:
        raise RuntimeError("control bundle does not assert secrets_captured=false")
    candidate = control.get("candidate") or {}
    if candidate.get("truenas_version") != target_version:
        raise RuntimeError("TrueNAS target drifted")
    if candidate.get("control_image") != EXPECTED_CONTROL:
        raise RuntimeError("control image drifted")
    if candidate.get("cups_image") != EXPECTED_CUPS:
        raise RuntimeError("CUPS image drifted")
    if canonical_sha256(compose) != (control.get("artifacts") or {}).get("compose_canonical_sha256"):
        raise RuntimeError("Compose identity does not match control")
    services = compose.get("services") or {}
    if set(services) != {"control", "cups", "discovery"}:
        raise RuntimeError("expected exact control/cups/discovery service set")
    if services["control"].get("image") != EXPECTED_CONTROL or services["discovery"].get("image") != EXPECTED_CONTROL:
        raise RuntimeError("control/discovery exact image identity drifted")
    if services["cups"].get("image") != EXPECTED_CUPS:
        raise RuntimeError("CUPS exact image identity drifted")
    discovery_backend=validate_discovery_materialization(services,target_version)
    if candidate.get("discovery_backend") not in (None,discovery_backend):
        raise RuntimeError("control discovery backend disagrees with rendered Compose")
    required = set(control.get("required_oracles") or [])
    expected = {
        "app-create-running", "config-readback-exact-compose", "portal-ready",
        "ipp-get-printer-attributes", "canonical-uri-coherence",
        "control-cups-dnssd-uuid-coherence", "dnssd-universal-visible",
        "pdf-exact-source-inbox", "urf-exact-source-inbox",
        "restart-preserves-identity-and-inbox", "delete-zero-residue",
    }
    if not expected.issubset(required):
        raise RuntimeError("required FolioRelay oracle contract drifted")
    validate_host_path_requirements(control,target_version)
    validate_management_transport(control, services)
    return control, compose

def validate_management_transport(control: dict, services: dict) -> str:
    runtime=control.get("runtime") or {}
    scheme=(runtime.get("management_scheme") or "http").lower()
    if scheme=="http":
        return scheme
    if scheme!="https":
        raise RuntimeError(f"unsupported management scheme {scheme!r}")
    if runtime.get("management_tls_root")!=ROOT+"/tls":
        raise RuntimeError("HTTPS management TLS root drifted")
    if runtime.get("management_tls_state")!="/var/lib/foliorelay-tls":
        raise RuntimeError("HTTPS management TLS state target drifted")
    required=set(control.get("required_oracles") or [])
    for oracle in ("management-tls-ready","management-tls-identity-persistent"):
        if oracle not in required:
            raise RuntimeError(f"HTTPS control missing required oracle {oracle}")
    tls_root=runtime["management_tls_root"]
    tls_target=runtime["management_tls_state"]
    control_service=services.get("control") or {}
    mounts=[m for m in (control_service.get("volumes") or []) if isinstance(m,dict)]
    if not any(m.get("source")==tls_root and m.get("target")==tls_target and m.get("read_only") is not True for m in mounts):
        raise RuntimeError("HTTPS control missing writable dedicated TLS mount")
    for service_name in ("cups","discovery"):
        for mount in (services.get(service_name) or {}).get("volumes") or []:
            if isinstance(mount,dict) and (mount.get("source")==tls_root or mount.get("target")==tls_target):
                raise RuntimeError(f"{service_name} must not receive management TLS state")
    return scheme

def multipart_upload(host, port, tls, username, password, remote_path, content, mode, timeout):
    boundary = "----semper-supra-foliorelay-t6"
    data = json.dumps({"method":"filesystem.put","params":[remote_path,{"append":False,"mode":mode}]}, separators=(",",":"))
    chunks = [
        f"--{boundary}\r\n".encode(), b'Content-Disposition: form-data; name="data"\r\n\r\n',
        data.encode(), b"\r\n", f"--{boundary}\r\n".encode(),
        b'Content-Disposition: form-data; name="file"; filename="payload"\r\n',
        b"Content-Type: application/octet-stream\r\n\r\n", content, b"\r\n",
        f"--{boundary}--\r\n".encode(),
    ]
    body = b"".join(chunks)
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    headers = {"Authorization":f"Basic {token}","Content-Type":f"multipart/form-data; boundary={boundary}","Content-Length":str(len(body))}
    if tls:
        ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
        conn=http.client.HTTPSConnection(host,port,timeout=timeout,context=ctx)
    else:
        conn=http.client.HTTPConnection(host,port,timeout=timeout)
    try:
        conn.request("POST","/_upload/",body=body,headers=headers)
        resp=conn.getresponse(); payload=resp.read()
    finally:
        conn.close()
    if not (200 <= resp.status < 300):
        raise RuntimeError(f"filesystem.put HTTP {resp.status}")
    job_id=json.loads(payload.decode()).get("job_id")
    if not isinstance(job_id,int):
        raise RuntimeError("filesystem.put did not return job_id")
    return job_id

def http_bytes(host, port, path, token=None, method="GET", timeout=8.0):
    req=urllib.request.Request(f"http://{host}:{port}{path}", method=method)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()

def middleware_http_bytes(host, port, tls, path, timeout=8.0):
    if tls:
        ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
        conn=http.client.HTTPSConnection(host,port,timeout=timeout,context=ctx)
    else:
        conn=http.client.HTTPConnection(host,port,timeout=timeout)
    try:
        conn.request("GET",path)
        resp=conn.getresponse(); payload=resp.read()
    finally:
        conn.close()
    if not (200 <= resp.status < 300):
        raise RuntimeError(f"middleware download HTTP {resp.status}")
    return payload

def wait_http(host, port, path, timeout_s):
    deadline=time.monotonic()+timeout_s
    while time.monotonic()<deadline:
        try:
            http_bytes(host,port,path,timeout=3)
            return True
        except Exception:
            time.sleep(1)
    return False

def write_pdf(path: pathlib.Path):
    data=(b"%PDF-1.4\n1 0 obj<< /Type /Catalog /Pages 2 0 R >>endobj\n"
          b"2 0 obj<< /Type /Pages /Kids [3 0 R] /Count 1 >>endobj\n"
          b"3 0 obj<< /Type /Page /Parent 2 0 R /MediaBox [0 0 72 72] >>endobj\n"
          b"trailer<< /Root 1 0 R >>\n%%EOF\n")
    path.write_bytes(data)

URF_C = r"""
#include <cups/raster.h>
#include <cups/pwg.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(int argc,char **argv){
  cups_page_header2_t h;
  cups_raster_t *r;
  pwg_media_t *m;
  unsigned char *line;
  unsigned y;
  int fd;

  if(argc!=2) return 64;
  m=pwgMediaForPWG("iso_a4_210x297mm");
  if(!m) return 1;
  if(!cupsRasterInitPWGHeader(&h,m,"sgray_8",300,300,"one-sided",NULL)) return 1;
  h.cupsInteger[CUPS_RASTER_PWG_TotalPageCount]=1;

  fd=open(argv[1],O_CREAT|O_TRUNC|O_WRONLY,0600);
  if(fd<0) return 1;
  r=cupsRasterOpen(fd,CUPS_RASTER_WRITE_APPLE);
  if(!r) return 1;
  if(!cupsRasterWriteHeader2(r,&h)) return 1;

  line=malloc(h.cupsBytesPerLine);
  if(!line) return 1;
  memset(line,0xff,h.cupsBytesPerLine);
  for(y=0;y<h.cupsHeight;y++){
    if(cupsRasterWritePixels(r,line,h.cupsBytesPerLine)!=h.cupsBytesPerLine) return 1;
  }
  free(line);
  cupsRasterClose(r);
  return close(fd)==0?0:1;
}
"""

def generate_urf(root: pathlib.Path):
    src=root/"generate-urf.c"; exe=root/"generate-urf"; out=root/"probe.urf"
    src.write_text(URF_C,encoding="utf-8")
    compile_result=subprocess.run(
        ["cc","-O2","-Wall","-Wextra","-Werror","-o",str(exe),str(src),"-lcups"],
        text=True,capture_output=True,check=False,
    )
    if compile_result.returncode:
        diagnostic=(compile_result.stderr or compile_result.stdout or "unknown compiler failure").strip()
        raise RuntimeError(f"URF fixture compile failed: {diagnostic[:2000]}")
    subprocess.run([str(exe),str(out)],check=True)
    if out.read_bytes()[:7] != b"UNIRAST":
        raise RuntimeError("generated URF missing UNIRAST signature")
    return out

def ipptool_attrs(port:int, root:pathlib.Path):
    test="/usr/share/cups/ipptool/get-printer-attributes.test"
    if not pathlib.Path(test).exists():
        found=list(pathlib.Path("/usr/share/cups").rglob("get-printer-attributes.test"))
        if not found: raise RuntimeError("CUPS get-printer-attributes test missing")
        test=str(found[0])
    out=subprocess.run(["ipptool","-tv",f"ipp://127.0.0.1:{port}/printers/FolioRelay",test],text=True,capture_output=True)
    (root/"ipp-attrs.txt").write_text(out.stdout+"\n"+out.stderr,encoding="utf-8")
    if out.returncode: raise RuntimeError("IPP Get-Printer-Attributes failed")
    return out.stdout+"\n"+out.stderr

def extract_printer_uuid(attrs: str):
    match = re.search(r"printer-uuid[^\n]*= (urn:uuid:[^\s]+)", attrs)
    return match.group(1) if match else None

def extract_printer_uri(attrs: str):
    match = re.search(r"printer-uri-supported[^\n]*= (ipp://[^\s]+)", attrs)
    return match.group(1) if match else None

def dnssd_txt_uuid(printer_uuid: str) -> str:
    prefix="urn:uuid:"
    if not isinstance(printer_uuid,str) or not printer_uuid.lower().startswith(prefix):
        raise RuntimeError("canonical printer UUID is not urn:uuid form")
    value=printer_uuid[len(prefix):]
    if not value:
        raise RuntimeError("canonical printer UUID is empty")
    return value

def forwarded_ipp_uri_has_product_path(uri: str | None) -> bool:
    if not uri or not uri.startswith("ipp://"):
        return False
    tail = uri.split("://", 1)[1]
    slash = tail.find("/")
    return slash >= 0 and tail[slash:] == PUBLIC_RESOURCE_PATH

def ipptool_print(port:int, media:str, source:pathlib.Path, label:str, root:pathlib.Path):
    t=root/f"print-{label}.test"
    t.write_text("""{
  NAME "FolioRelay T6"
  OPERATION Print-Job
  GROUP operation-attributes-tag
  ATTR charset attributes-charset utf-8
  ATTR language attributes-natural-language en
  ATTR uri printer-uri %s
  ATTR name requesting-user-name rdte
  ATTR name job-name "FolioRelay T6 %s"
  ATTR mimeMediaType document-format %s
  FILE "%s"
  STATUS successful-ok
}
""" % (PUBLIC_URI,label,media,str(source)),encoding="utf-8")
    p=subprocess.run(["ipptool","-tv",f"ipp://127.0.0.1:{port}/printers/FolioRelay",str(t)],text=True,capture_output=True)
    (root/f"print-{label}.txt").write_text(p.stdout+"\n"+p.stderr,encoding="utf-8")
    if p.returncode: raise RuntimeError(f"{label} Print-Job failed")


class JobFailure(RuntimeError):
    def __init__(self, label: str, job: dict):
        self.label = label
        self.job = job
        detail = job.get("error") or job.get("exception") or job.get("exc_info") or "no job diagnostic"
        super().__init__(f"{label} job {job.get('state')}: {detail}")

def bounded_text(value, limit=8000):
    if value is None:
        return None
    text = str(value)
    return text if len(text) <= limit else text[:limit] + "...<truncated>"

def bounded_head_tail_text(value, limit=8000):
    if value is None:
        return None
    text = str(value)
    if len(text) <= limit:
        return text
    marker = "\n...<truncated-middle>...\n"
    if limit <= len(marker):
        return text[-limit:]
    available = limit - len(marker)
    head = max(1, available // 3)
    tail = available - head
    return text[:head] + marker + text[-tail:]

def bounded_observer_lifecycle_excerpt(value, app_name=OBSERVER_APP_NAME, before=2, after=24, limit=8000):
    if value is None:
        return None
    lines=str(value).splitlines()
    needles=(app_name, f"ix-{app_name}")
    hits=[i for i,line in enumerate(lines) if any(needle in line for needle in needles)]
    if not hits:
        return None
    selected=set()
    for i in hits:
        selected.update(range(max(0,i-before), min(len(lines),i+after+1)))
    excerpt="\n".join(lines[i] for i in sorted(selected))
    excerpt=re.sub(r"(auth_token=)[^&\s]+", r"\1<redacted>", excerpt)
    return bounded_head_tail_text(excerpt,limit)

def bounded_job_snapshot(job):
    if not isinstance(job, dict):
        return None
    return {
        key: (bounded_text(job.get(key)) if key in {"error", "exception", "exc_info", "logs_excerpt"} else job.get(key))
        for key in ("id", "state", "progress", "error", "exception", "exc_info", "logs_excerpt")
        if key in job
    }

def bounded_app_snapshot(app):
    if not isinstance(app, dict):
        return None
    workloads = app.get("active_workloads") or {}
    details = workloads.get("container_details") or []
    containers = []
    for item in details[:8]:
        if not isinstance(item, dict):
            continue
        containers.append({
            key: item.get(key)
            for key in ("id", "container_id", "service_name", "image", "state", "health")
            if item.get(key) is not None
        })
    return {
        "id": app.get("id"),
        "name": app.get("name"),
        "state": app.get("state"),
        "error_reason": bounded_text(app.get("error_reason")),
        "containers": containers,
    }

def capture_container_log_tail(ws, app_name, container_id, tail_lines=OBSERVER_LOG_TAIL_LINES):
    params = {"app_name": app_name, "container_id": container_id, "tail_lines": tail_lines}
    subscription = "app.container_log_follow:" + json.dumps(params, sort_keys=True, separators=(",", ":"))
    sub_id = "observer-log-" + hashlib.sha256(container_id.encode()).hexdigest()[:12]
    old_timeout = ws.sock.gettimeout()
    events = []
    try:
        ws.sock.settimeout(min(float(old_timeout or 2.0), OBSERVER_LOG_CAPTURE_SECONDS))
        ws.send_json({"msg": "sub", "id": sub_id, "name": subscription, "params": []})
        deadline = time.monotonic() + OBSERVER_LOG_CAPTURE_SECONDS
        while len(events) < OBSERVER_LOG_MAX_EVENTS and time.monotonic() < deadline:
            try:
                message = ws.recv_json()
            except (socket.timeout, TimeoutError):
                break
            if message.get("msg") == "ping":
                pong = {"msg": "pong"}
                if "id" in message:
                    pong["id"] = message["id"]
                ws.send_json(pong)
                continue
            if message.get("msg") == "added":
                fields = message.get("fields") or {}
                data = fields.get("data")
                if data is not None:
                    events.append({
                        "timestamp": fields.get("timestamp"),
                        "data": bounded_text(data, 4000),
                    })
            if message.get("msg") == "nosub" and message.get("id") == sub_id:
                break
    finally:
        try:
            ws.send_json({"msg": "unsub", "id": sub_id})
        except Exception:
            pass
        ws.sock.settimeout(old_timeout)
    return {
        "app_name": app_name,
        "container_id": container_id,
        "tail_lines": tail_lines,
        "events": events,
    }


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--host",default="127.0.0.1"); p.add_argument("--port",type=int,required=True)
    p.add_argument("--control-port",type=int,required=True); p.add_argument("--ipp-port",type=int,required=True); p.add_argument("--observer-port",type=int,required=True)
    p.add_argument("--observer-binary",type=pathlib.Path,required=True)
    p.add_argument("--password-file",required=True); p.add_argument("--control-dir",type=pathlib.Path,required=True); p.add_argument("--foundry-commit",required=True)
    p.add_argument("--target-version",required=True); p.add_argument("--expected-system-version",required=True)
    p.add_argument("--out",required=True); p.add_argument("--tls",action="store_true"); p.add_argument("--timeout",type=float,default=8); p.add_argument("--job-timeout",type=float,default=300); p.add_argument("--state-timeout",type=float,default=300)
    a=p.parse_args()
    if not a.observer_binary.is_file():
        raise RuntimeError("minimal observer binary is missing")
    observer_bytes=a.observer_binary.read_bytes()
    if not observer_bytes:
        raise RuntimeError("minimal observer binary is empty")
    if len(observer_bytes) > 6291456:
        raise RuntimeError("minimal observer binary exceeds 6 MiB budget")
    started=time.time(); ws=None; dataset_owned=False; app_created=False; observer_created=False
    payload={"schema":"truenas-foliorelay-foundry-t6/v1","classification":"ORACLE_FAILURE","oracleSatisfied":False,"expected_version":a.expected_system_version,"target_version":a.target_version,"foundry_commit":a.foundry_commit,"app_name":EXPECTED_APP_NAME,"secret_values_captured":False}
    payload["observer_fixture"]={
        "implementation":"go-static",
        "carrier_image":OBSERVER_IMAGE,
        "binary_sha256":sha256_bytes(observer_bytes),
        "binary_size_bytes":len(observer_bytes),
        "run_as":"65534:65534",
    }
    try:
        control,compose=load_control(a.control_dir,a.foundry_commit,a.target_version)
        payload["materialization"]={"schema":control["schema"],"foundry_ref":control["foundry_ref"],"compose_canonical_sha256":canonical_sha256(compose),"control_image":EXPECTED_CONTROL,"cups_image":EXPECTED_CUPS}
        password=pathlib.Path(a.password_file).read_text().strip()
        ws=WebSocket(a.host,a.port,timeout=a.timeout,tls=a.tls); ws.send_json({"msg":"connect","version":"1","support":["1"]})
        if wait_for(ws,lambda m:m.get("msg") in {"connected","failed"}).get("msg")!="connected": raise RuntimeError("DDP connection failed")
        rid=1
        def call(method,params):
            nonlocal rid
            v=ddp_call(ws,str(rid),method,params); rid+=1; return v
        def query_optional(method,filters):
            rows=call(method,[filters])
            if not isinstance(rows,list):
                raise RuntimeError(f"{method} optional query did not return list")
            if len(rows)>1:
                raise RuntimeError(f"{method} optional query returned multiple rows")
            return rows[0] if rows else None
        def wait_job(j,label):
            deadline=time.monotonic()+a.job_timeout
            while time.monotonic()<deadline:
                x=call("core.get_jobs",[[["id","=",j]],{"get":True}])
                if x and x.get("state")=="SUCCESS": return x
                if x and x.get("state") in {"FAILED","ABORTED"}:
                    raise JobFailure(label, x)
                time.sleep(1)
            raise RuntimeError(f"{label} job timeout")
        def capture_product_runtime_failure(name,app):
            diagnostic={"app":bounded_app_snapshot(app)}
            try:
                download=call("core.download",["filesystem.get",["/var/log/app_lifecycle.log"],"app_lifecycle.log",True])
                if not (isinstance(download,list) and len(download)==2 and isinstance(download[0],int) and isinstance(download[1],str)):
                    raise RuntimeError("core.download app_lifecycle contract drifted")
                wait_job(download[0],"product app lifecycle log download")
                lifecycle=middleware_http_bytes(a.host,a.port,a.tls,download[1],timeout=a.timeout).decode("utf-8","replace")
                diagnostic["app_lifecycle_excerpt"]=bounded_observer_lifecycle_excerpt(lifecycle,app_name=name)
            except Exception as lifecycle_exc:
                diagnostic["app_lifecycle_capture_error"]=f"{type(lifecycle_exc).__name__}: {lifecycle_exc}"
            try:
                log_tails=[]
                details=((app.get("active_workloads") or {}).get("container_details") or []) if isinstance(app,dict) else []
                for detail in details[:8]:
                    container_id=detail.get("id") or detail.get("container_id")
                    if not container_id:
                        continue
                    service_name=detail.get("service_name")
                    container_state=str(detail.get("state") or "").lower()
                    if service_name!="discovery" and container_state not in {"crashed","exited","restarting"}:
                        continue
                    try:
                        entry=capture_container_log_tail(ws,name,str(container_id))
                        entry["service_name"]=service_name
                        entry["container_state"]=container_state
                        log_tails.append(entry)
                    except Exception as log_exc:
                        log_tails.append({
                            "container_id":str(container_id),
                            "service_name":service_name,
                            "container_state":container_state,
                            "capture_error":f"{type(log_exc).__name__}: {log_exc}",
                        })
                diagnostic["container_log_tails"]=log_tails
            except Exception as log_group_exc:
                diagnostic["container_log_capture_error"]=f"{type(log_group_exc).__name__}: {log_group_exc}"
            payload["product_runtime_failure"]=diagnostic

        def wait_state(name,state):
            deadline=time.monotonic()+a.state_timeout
            while time.monotonic()<deadline:
                x=call("app.query",[[["id","=",name]],{"get":True}])
                if x and x.get("state")==state: return x
                if x and x.get("state") in {"CRASHED","ERROR"}:
                    if name==EXPECTED_APP_NAME:
                        try:
                            capture_product_runtime_failure(name,x)
                        except Exception as diagnostic_exc:
                            payload["product_runtime_failure"]={
                                "app":bounded_app_snapshot(x),
                                "diagnostic_error":f"{type(diagnostic_exc).__name__}: {diagnostic_exc}",
                            }
                    raise RuntimeError(f"{name} entered {x.get('state')}")
                time.sleep(1)
            raise RuntimeError(f"{name} did not reach {state}")
        auth=call("auth.login_ex",[{"mechanism":"PASSWORD_PLAIN","username":"truenas_admin","password":password}])
        if not isinstance(auth,dict) or auth.get("response_type")!="SUCCESS": raise RuntimeError("authentication failed")
        if call("system.version",[])!=a.expected_system_version: raise RuntimeError("target version drifted")
        if call("app.query",[[["id","in",[EXPECTED_APP_NAME,OBSERVER_APP_NAME]]]]): raise RuntimeError("refusing adopted FolioRelay app state")
        if call("pool.dataset.query",[[["id","=",DATASET]]]): raise RuntimeError("refusing adopted FolioRelay dataset")
        ds=call("pool.dataset.create",[{"name":DATASET,"type":"FILESYSTEM","share_type":"GENERIC","comments":"SemperSupra disposable FolioRelay T6 fixture"}])
        if not isinstance(ds,dict) or ds.get("id")!=DATASET: raise RuntimeError("dataset identity mismatch")
        dataset_owned=True
        host_requirements=validate_host_path_requirements(control,a.target_version)
        for item in host_requirements:
            if item["kind"]!="directory":
                continue
            path=item["path"]; mode=middleware_mode(item["mode"]); uid=item["uid"]; gid=item["gid"]
            d=call("filesystem.mkdir",[{"path":path,"options":{"mode":mode,"raise_chmod_error":True}}])
            if not isinstance(d,dict) or d.get("path")!=path: raise RuntimeError(f"mkdir failed: {path}")
            j=call("filesystem.setperm",[{"path":path,"uid":uid,"gid":gid,"mode":mode,"options":{"stripacl":True,"recursive":False,"traverse":False}}])
            if isinstance(j,int): wait_job(j,f"setperm {path}")
        d=call("filesystem.mkdir",[{"path":OBSERVER_DIR,"options":{"mode":"755","raise_chmod_error":True}}])
        if not isinstance(d,dict) or d.get("path")!=OBSERVER_DIR: raise RuntimeError(f"mkdir failed: {OBSERVER_DIR}")
        j=call("filesystem.setperm",[{"path":OBSERVER_DIR,"uid":0,"gid":0,"mode":"755","options":{"stripacl":True,"recursive":False,"traverse":False}}])
        if isinstance(j,int): wait_job(j,f"setperm {OBSERVER_DIR}")
        token_req=next(item for item in host_requirements if item["path"]==TOKEN_PATH)
        token_mode=middleware_mode(token_req["mode"])
        tj=multipart_upload(a.host,a.port,a.tls,"truenas_admin",password,TOKEN_PATH,TOKEN,int(token_req["mode"],8),a.timeout); wait_job(tj,"token upload")
        j=call("filesystem.setperm",[{"path":TOKEN_PATH,"uid":token_req["uid"],"gid":token_req["gid"],"mode":token_mode,"options":{"stripacl":True,"recursive":False,"traverse":False}}])
        if isinstance(j,int): wait_job(j,"token setperm")
        create=call("app.create",[{"app_name":EXPECTED_APP_NAME,"custom_app":True,"custom_compose_config":compose}])
        if not isinstance(create,int): raise RuntimeError("app.create did not return job")
        app_created=True
        wait_job(create,"app.create"); app=wait_state(EXPECTED_APP_NAME,"RUNNING")
        details=(app.get("active_workloads") or {}).get("container_details") or []
        exact={(x.get("service_name"),x.get("image"),x.get("state")) for x in details}
        for needed in [("control",EXPECTED_CONTROL,"running"),("cups",EXPECTED_CUPS,"running"),("discovery",EXPECTED_CONTROL,"running")]:
            if needed not in exact: raise RuntimeError(f"container identity mismatch: {needed[0]}")
        readback=call("app.config",[EXPECTED_APP_NAME])
        if canonical_sha256(readback)!=canonical_sha256(compose): raise RuntimeError("app.config readback drifted")
        if not wait_http(a.host,a.control_port,"/readyz",a.state_timeout): raise RuntimeError("control readyz failed")
        tok=TOKEN.decode().strip()
        printer=json.loads(http_bytes(a.host,a.control_port,"/api/v1/printer",tok,timeout=a.timeout))
        uuid=(printer.get("identity") or {}).get("printer_uuid"); uri=printer.get("public_uri")
        if not isinstance(uuid,str) or not uuid or uri!=PUBLIC_URI: raise RuntimeError("control canonical printer identity drifted")
        with tempfile.TemporaryDirectory() as td:
            root=pathlib.Path(td)
            attrs=ipptool_attrs(a.ipp_port,root)
            cups_uuid=extract_printer_uuid(attrs)
            if cups_uuid!=uuid: raise RuntimeError("CUPS UUID does not match control")
            cups_transport_uri=extract_printer_uri(attrs)
            if not forwarded_ipp_uri_has_product_path(cups_transport_uri):
                raise RuntimeError("CUPS forwarded IPP URI does not preserve product resource path")
            if "application/pdf" not in attrs or "image/urf" not in attrs: raise RuntimeError("CUPS document formats drifted")
            pdf=root/"probe.pdf"; write_pdf(pdf); urf=generate_urf(root)
            ipptool_print(a.ipp_port,"application/pdf",pdf,"pdf",root); ipptool_print(a.ipp_port,"image/urf",urf,"urf",root)
            expected={"application/pdf":sha256_bytes(pdf.read_bytes()),"image/urf":sha256_bytes(urf.read_bytes())}
            deadline=time.monotonic()+60; jobs=None
            while time.monotonic()<deadline:
                jobs=json.loads(http_bytes(a.host,a.control_port,"/api/v1/jobs",tok,timeout=a.timeout))
                if len(jobs.get("items") or [])==2: break
                time.sleep(1)
            items=jobs.get("items") or []
            if len(items)!=2: raise RuntimeError("Inbox did not contain exactly two jobs")
            for media,sha in expected.items():
                matches=[x for x in items if x.get("media_type")==media]
                if len(matches)!=1 or matches[0].get("artifact_sha256")!=sha or matches[0].get("substrate")!="cups": raise RuntimeError(f"{media} Inbox metadata drifted")
                blob=http_bytes(a.host,a.control_port,f"/api/v1/jobs/{matches[0]['job_id']}/artifact",tok,timeout=a.timeout)
                if sha256_bytes(blob)!=sha: raise RuntimeError(f"{media} downloaded artifact drifted")
        sj=multipart_upload(a.host,a.port,a.tls,"truenas_admin",password,OBSERVER_DIR+"/foliorelay-observer",observer_bytes,0o555,a.timeout); wait_job(sj,"observer upload")
        observer_command=["--uuid",uuid,"--txt-uuid",dnssd_txt_uuid(uuid),"--expected-host",PUBLIC_HOST,"--expected-ipp-port",str(PUBLIC_IPP_PORT),"--port","18081"]
        expected_observer_transport="multicast-5353"
        if a.target_version in AVAHI_TARGETS:
            observer_command.append("--legacy-unicast")
            expected_observer_transport="legacy-unicast"
        obs_compose={"services":{"observer":{"image":OBSERVER_IMAGE,"network_mode":"host","read_only":True,"user":"65534:65534","cap_drop":["ALL"],"security_opt":["no-new-privileges:true"],"volumes":[{"type":"bind","source":OBSERVER_DIR+"/foliorelay-observer","target":"/observer/foliorelay-observer","read_only":True}],"entrypoint":["/observer/foliorelay-observer"],"command":observer_command}}}
        oj=call("app.create",[{"app_name":OBSERVER_APP_NAME,"custom_app":True,"custom_compose_config":obs_compose}])
        if not isinstance(oj,int): raise RuntimeError("observer app.create did not return job")
        observer_created=True
        try:
            wait_job(oj,"observer app.create"); wait_state(OBSERVER_APP_NAME,"RUNNING")
        except Exception as observer_exc:
            diagnostic={"detail":f"{type(observer_exc).__name__}: {observer_exc}"}
            if isinstance(observer_exc,JobFailure): diagnostic["job"]=bounded_job_snapshot(observer_exc.job)
            try:
                download=call("core.download",["filesystem.get",["/var/log/app_lifecycle.log"],"app_lifecycle.log",True])
                if not (isinstance(download,list) and len(download)==2 and isinstance(download[0],int) and isinstance(download[1],str)):
                    raise RuntimeError("core.download app_lifecycle contract drifted")
                wait_job(download[0],"app lifecycle log download")
                lifecycle=middleware_http_bytes(a.host,a.port,a.tls,download[1],timeout=a.timeout).decode("utf-8","replace")
                diagnostic["app_lifecycle_excerpt"]=bounded_observer_lifecycle_excerpt(lifecycle)
            except Exception as lifecycle_exc:
                diagnostic["app_lifecycle_capture_error"]=f"{type(lifecycle_exc).__name__}: {lifecycle_exc}"
            try:
                observer_app=query_optional("app.query",[["id","=",OBSERVER_APP_NAME]])
                diagnostic["app"]=bounded_app_snapshot(observer_app)
                state=observer_app.get("state") if isinstance(observer_app,dict) else None
                if state in {"RUNNING","CRASHED","DEPLOYING"}:
                    log_tails=[]
                    for detail in ((observer_app.get("active_workloads") or {}).get("container_details") or [])[:4]:
                        container_id=detail.get("id") or detail.get("container_id")
                        if not container_id: continue
                        try:
                            log_tails.append(capture_container_log_tail(ws,OBSERVER_APP_NAME,str(container_id)))
                        except Exception as log_exc:
                            log_tails.append({"container_id":str(container_id),"capture_error":f"{type(log_exc).__name__}: {log_exc}"})
                    diagnostic["container_log_tails"]=log_tails
            except Exception as diagnostic_exc:
                diagnostic["diagnostic_error"]=f"{type(diagnostic_exc).__name__}: {diagnostic_exc}"
            payload["observer_create_failure"]=diagnostic
            raise
        if not wait_http(a.host,a.observer_port,"/",60): raise RuntimeError("DNS-SD observer HTTP witness did not become reachable")
        deadline=time.monotonic()+45; observed=None
        while time.monotonic()<deadline:
            observed=json.loads(http_bytes(a.host,a.observer_port,"/",timeout=a.timeout))
            status=observed.get("status")
            if status=="success": break
            if status=="error":
                raise RuntimeError(f"DNS-SD observer oracle failed: {observed.get('error')}")
            time.sleep(1)
        if not observed or observed.get("status")!="success":
            raise RuntimeError("DNS-SD observer oracle remained pending")
        if (observed.get("query_transport")!=expected_observer_transport
            or observed.get("universal_ptr") is not True or observed.get("uuid")!=uuid
            or (observed.get("srv_target") or "").rstrip(".").lower()!=PUBLIC_HOST.lower()
            or observed.get("srv_port")!=PUBLIC_IPP_PORT):
            raise RuntimeError("DNS-SD observer public URI identity mismatch")
        before_jobs=json.loads(http_bytes(a.host,a.control_port,"/api/v1/jobs",tok,timeout=a.timeout))
        stop=call("app.stop",[EXPECTED_APP_NAME]); wait_job(stop,"app.stop"); wait_state(EXPECTED_APP_NAME,"STOPPED")
        start=call("app.start",[EXPECTED_APP_NAME]); wait_job(start,"app.start"); wait_state(EXPECTED_APP_NAME,"RUNNING")
        if not wait_http(a.host,a.control_port,"/readyz",a.state_timeout): raise RuntimeError("readyz failed after restart")
        after_printer=json.loads(http_bytes(a.host,a.control_port,"/api/v1/printer",tok,timeout=a.timeout))
        after_jobs=json.loads(http_bytes(a.host,a.control_port,"/api/v1/jobs",tok,timeout=a.timeout))
        if (after_printer.get("identity") or {}).get("printer_uuid")!=uuid or after_jobs!=before_jobs: raise RuntimeError("identity or Inbox drifted after restart")
        # F4: second-plan from exact live read-back must be a stable NOOP.
        second_plan_app=query_optional("app.query",[["id","=",EXPECTED_APP_NAME]])
        second_plan_state=(second_plan_app or {}).get("state")
        live_compose=call("app.config",[EXPECTED_APP_NAME]) if second_plan_app else None
        second_plan_action=reconciliation_action(second_plan_state,live_compose,compose)
        replan_action=second_plan_action
        if second_plan_action!="NOOP":
            raise RuntimeError(f"second-plan reconciliation was {second_plan_action}, expected NOOP")
        # Exercise the public update/redeploy path separately from stop/start while preserving durable identity and Inbox.
        uj=call("app.update",[EXPECTED_APP_NAME,{"custom_compose_config":compose}])
        if not isinstance(uj,int): raise RuntimeError("app.update did not return job")
        wait_job(uj,"app.update"); wait_state(EXPECTED_APP_NAME,"RUNNING")
        rj=call("app.redeploy",[EXPECTED_APP_NAME])
        if not isinstance(rj,int): raise RuntimeError("app.redeploy did not return job")
        wait_job(rj,"app.redeploy"); wait_state(EXPECTED_APP_NAME,"RUNNING")
        if not wait_http(a.host,a.control_port,"/readyz",a.state_timeout): raise RuntimeError("readyz failed after update/redeploy")
        redeploy_printer=json.loads(http_bytes(a.host,a.control_port,"/api/v1/printer",tok,timeout=a.timeout))
        redeploy_jobs=json.loads(http_bytes(a.host,a.control_port,"/api/v1/jobs",tok,timeout=a.timeout))
        if (redeploy_printer.get("identity") or {}).get("printer_uuid")!=uuid or redeploy_jobs!=before_jobs:
            raise RuntimeError("identity or Inbox drifted after update/redeploy")

        # F5: product App deletion must retain the experiment-owned external dataset,
        # and exact reinstall must recover durable identity, Inbox metadata, and bytes.
        retained_before_delete=query_optional("pool.dataset.query",[["id","=",DATASET]])
        if retained_before_delete is None:
            raise RuntimeError("fixture dataset missing before retain-data delete")
        md=call("app.delete",[EXPECTED_APP_NAME,{"remove_images":False,"remove_ix_volumes":False,"force_remove_custom_app":False}])
        wait_job(md,"retain-data app delete"); app_created=False
        if query_optional("app.query",[["id","=",EXPECTED_APP_NAME]]) is not None:
            raise RuntimeError("product App remained after retain-data delete")
        if query_optional("pool.dataset.query",[["id","=",DATASET]]) is None:
            raise RuntimeError("external fixture dataset was not retained across App delete")
        call("filesystem.stat",[TOKEN_PATH])

        reinstall=call("app.create",[{"app_name":EXPECTED_APP_NAME,"custom_app":True,"custom_compose_config":compose}])
        if not isinstance(reinstall,int): raise RuntimeError("reinstall app.create did not return job")
        app_created=True
        wait_job(reinstall,"reinstall app.create"); reinstall_app=wait_state(EXPECTED_APP_NAME,"RUNNING")
        if canonical_sha256(call("app.config",[EXPECTED_APP_NAME]))!=canonical_sha256(compose):
            raise RuntimeError("reinstall app.config readback drifted")
        if not wait_http(a.host,a.control_port,"/readyz",a.state_timeout):
            raise RuntimeError("readyz failed after retain-data reinstall")
        reinstall_printer=json.loads(http_bytes(a.host,a.control_port,"/api/v1/printer",tok,timeout=a.timeout))
        reinstall_jobs=json.loads(http_bytes(a.host,a.control_port,"/api/v1/jobs",tok,timeout=a.timeout))
        if ((reinstall_printer.get("identity") or {}).get("printer_uuid")!=uuid
            or reinstall_printer.get("public_uri")!=PUBLIC_URI
            or reinstall_jobs!=before_jobs):
            raise RuntimeError("identity or Inbox drifted after retain-data reinstall")
        for item in (reinstall_jobs.get("items") or []):
            artifact_sha=item.get("artifact_sha256")
            job_id=item.get("job_id")
            if not artifact_sha or not job_id:
                raise RuntimeError("reinstalled Inbox item missing artifact identity")
            blob=http_bytes(a.host,a.control_port,f"/api/v1/jobs/{job_id}/artifact",tok,timeout=a.timeout)
            if sha256_bytes(blob)!=artifact_sha:
                raise RuntimeError("retained artifact bytes drifted after reinstall")
        reinstall_live=call("app.config",[EXPECTED_APP_NAME])
        reinstall_plan_action=reconciliation_action((reinstall_app or {}).get("state"),reinstall_live,compose)
        if reinstall_plan_action!="NOOP":
            raise RuntimeError(f"post-reinstall reconciliation was {reinstall_plan_action}, expected NOOP")
        od=call("app.delete",[OBSERVER_APP_NAME,{"remove_images":False,"remove_ix_volumes":False,"force_remove_custom_app":False}]); wait_job(od,"observer delete"); observer_created=False
        md=call("app.delete",[EXPECTED_APP_NAME,{"remove_images":False,"remove_ix_volumes":False,"force_remove_custom_app":False}]); wait_job(md,"app delete"); app_created=False
        if call("app.query",[[["id","in",[EXPECTED_APP_NAME,OBSERVER_APP_NAME]]]]): raise RuntimeError("app residue remains")
        deleted=call("pool.dataset.delete",[DATASET,{"recursive":True,"force":False}])
        if deleted is not True: raise RuntimeError("dataset delete did not return true")
        dataset_owned=False
        if call("pool.dataset.query",[[["id","=",DATASET]]]): raise RuntimeError("dataset residue remains")
        absent=False
        try: call("filesystem.stat",[ROOT])
        except RuntimeError: absent=True
        if not absent: raise RuntimeError("fixture mountpoint remains")
        payload.update({
            "classification":"SUPPORTED","oracleSatisfied":True,
            "identity":{"printer_uuid":uuid,"public_uri":PUBLIC_URI,"control_cups_uuid_match":True,"dnssd_uuid_match":True,"dnssd_public_uri_match":True},
            "runtime":{"three_services_exact":True,"compose_readback_exact":True,"portal_ready":True,"ipp_get_printer_attributes":True,"forwarded_ipp_resource_path_match":True,"pdf_exact_source_inbox":True,"urf_exact_source_inbox":True,"restart_preserved_identity_and_inbox":True,"update_redeploy_preserved_identity_and_inbox":True,"replan_action":"NOOP","second_plan_noop":True,"retain_data_reinstall":True},
            "dnssd":{"observer_app":OBSERVER_APP_NAME,"universal_visible":True,"distinct_observer_context":True,"service_instance":observed.get("service_instance"),"srv_target":PUBLIC_HOST,"srv_port":PUBLIC_IPP_PORT,"resource_path":PUBLIC_RESOURCE_PATH},
            "cleanup":{"apps_absent":True,"fixture_dataset_absent":True,"fixture_mountpoint_absent":True,"zero_residue":True},
            "reconciliation":{"second_plan_action":second_plan_action,"post_reinstall_action":reinstall_plan_action,"inflight_policy":"WAIT","ambiguous_policy":"FAIL_CLOSED"},
            "owned_data":{"policy":"RETAIN_EXTERNAL_DATASET_ON_APP_DELETE_THEN_EXPLICIT_FIXTURE_CLEANUP","dataset_retained_across_app_delete":True,"identity_preserved_after_reinstall":True,"inbox_preserved_after_reinstall":True,"artifact_bytes_preserved_after_reinstall":True},
            "producer_gate":{"replan_noop_required":True,"runtime_does_not_reconstruct_foundry_control":True},
            "detail":"exact Foundry-exported FolioRelay control realized on TrueNAS; exact three-service identity, portal/IPP, PDF+URF source preservation, independent in-guest DNS-SD observation, restart/update/redeploy persistence, second-plan NOOP reconciliation, retain-data delete/reinstall persistence, and final zero-residue cleanup passed"
        })
    except Exception as exc:
        payload["detail"]=f"{type(exc).__name__}: {exc}"
        if isinstance(exc,JobFailure): payload["failure_job"]=bounded_job_snapshot(exc.job)
        cleanup={"attempted":bool(dataset_owned or app_created or observer_created),"observer_app":None,"product_app":None,"fixture_dataset":None,"errors":[]}
        if ws is not None:
            for name,owned,key in ((OBSERVER_APP_NAME,observer_created,"observer_app"),(EXPECTED_APP_NAME,app_created,"product_app")):
                if not owned: continue
                try:
                    before=query_optional("app.query",[["id","=",name]])
                    entry={"present_before":bool(before),"before":bounded_app_snapshot(before)}
                    if before:
                        delete_job=call("app.delete",[name,{"remove_images":False,"remove_ix_volumes":False,"force_remove_custom_app":False}])
                        if not isinstance(delete_job,int): raise RuntimeError(f"{name} cleanup delete did not return job")
                        entry["delete_job"]=bounded_job_snapshot(wait_job(delete_job,f"{name} cleanup delete"))
                    entry["absent_after"]=query_optional("app.query",[["id","=",name]]) is None
                    cleanup[key]=entry
                except Exception as cleanup_exc:
                    cleanup["errors"].append(f"{name}: {type(cleanup_exc).__name__}: {cleanup_exc}")
            if dataset_owned:
                try:
                    before=query_optional("pool.dataset.query",[["id","=",DATASET]])
                    entry={"present_before":bool(before)}
                    if before:
                        deleted=call("pool.dataset.delete",[DATASET,{"recursive":True,"force":False}])
                        if deleted is not True: raise RuntimeError("fixture cleanup dataset delete did not return true")
                    entry["absent_after"]=query_optional("pool.dataset.query",[["id","=",DATASET]]) is None
                    cleanup["fixture_dataset"]=entry
                except Exception as cleanup_exc:
                    cleanup["errors"].append(f"{DATASET}: {type(cleanup_exc).__name__}: {cleanup_exc}")
        checked=[x for x in (cleanup["observer_app"],cleanup["product_app"],cleanup["fixture_dataset"]) if isinstance(x,dict)]
        cleanup["zero_residue"]=bool(cleanup["attempted"]) and not cleanup["errors"] and all(x.get("absent_after") is True for x in checked) and len(checked)==sum(1 for x in (observer_created,app_created,dataset_owned) if x)
        payload["cleanup"]=cleanup
        payload["cleanup_needed"]=not cleanup["zero_residue"] if cleanup["attempted"] else False
    finally:
        if ws is not None: ws.close()
    payload["elapsed_seconds"]=round(time.time()-started,3)
    pathlib.Path(a.out).write_text(json.dumps(payload,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(json.dumps(payload,indent=2,sort_keys=True))
    return 0

if __name__=="__main__":
    raise SystemExit(main())
