#!/usr/bin/env python3
"""Qualify official GitHub Actions runner package staging inside container substrates."""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import platform
import tempfile
import time
import uuid

import container_substrate_qualification as substrate

RUNNER_VERSION = "2.337.0"
LINUX_X64_SHA256 = "70920811a4f8ad4328818682bca5c6469c1c942fab52448868071d0063816613"
WINDOWS_X64_SHA256 = "1150692afa94e71f872017e254ea55b6eece1eece3fe7e3a6d4c93d0a1b85cfc"
RUNNER_KIT_REF = "1c99e41df085783b8451263735021e126037097a"
RUNNER_KIT_BLOB_SHA1 = "f59ef40e6e6aa7625c870afe4f0dbae000308f29"


def result(classification, oracle, detail, **extra):
    return {
        "schema": "container-runner-readiness/v1",
        "classification": classification,
        "oracleSatisfied": oracle,
        "detail": detail,
        "runner": {
            "version": RUNNER_VERSION,
            "linux_x64_sha256": LINUX_X64_SHA256,
            "windows_x64_sha256": WINDOWS_X64_SHA256,
        },
        **extra,
    }


def linux_stage_shell():
    return f"""set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends bash ca-certificates curl python3 coreutils tar gzip >/tmp/runner-readiness-apt.log 2>&1
kit=/tmp/self_hosted_runner_kit.sh
curl -fsSL --retry 3 'https://raw.githubusercontent.com/SemperSupra/agent-dispatch/{RUNNER_KIT_REF}/scripts/self_hosted_runner_kit.sh' -o "$kit"
python3 - "$kit" '{RUNNER_KIT_BLOB_SHA1}' <<'PY'
import hashlib, pathlib, sys
data=pathlib.Path(sys.argv[1]).read_bytes()
actual=hashlib.sha1(("blob %d\\0" % len(data)).encode()+data).hexdigest()
if actual != sys.argv[2]:
    raise SystemExit("runner-kit git blob mismatch: " + actual)
PY
chmod 0755 "$kit"
"$kit" preflight --work-dir /opt/actions-runner > /tmp/preflight.json
"$kit" stage --version '{RUNNER_VERSION}' --sha256 '{LINUX_X64_SHA256}' --arch x64 --work-dir /opt/actions-runner > /tmp/stage.json
python3 - <<'PY'
import json
pre=json.load(open('/tmp/preflight.json'))
stage=json.load(open('/tmp/stage.json'))
ok=(not pre.get('missing') and stage.get('observed_version') == stage.get('version'))
print(json.dumps({{
  'classification':'SUPPORTED' if ok else 'ORACLE_FAILURE',
  'oracleSatisfied':bool(ok),
  'runner_kit_ref':'{RUNNER_KIT_REF}',
  'runner_kit_blob_sha1':'{RUNNER_KIT_BLOB_SHA1}',
  'preflight':pre,
  'stage':stage,
}}, sort_keys=True))
PY
"""


def windows_dockerfile():
    return f"""FROM mcr.microsoft.com/windows/servercore:ltsc2025
SHELL ["powershell","-NoProfile","-NonInteractive","-Command"]
RUN $ErrorActionPreference='Stop'; \\
    $version='{RUNNER_VERSION}'; \\
    $expected='{WINDOWS_X64_SHA256}'; \\
    $url='https://github.com/actions/runner/releases/download/v{RUNNER_VERSION}/actions-runner-win-x64-{RUNNER_VERSION}.zip'; \\
    Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile C:\\runner.zip; \\
    $observed=(Get-FileHash -Algorithm SHA256 C:\\runner.zip).Hash.ToLowerInvariant(); \\
    if ($observed -ne $expected) {{ throw 'runner package SHA256 mismatch' }}; \\
    Expand-Archive C:\\runner.zip C:\\actions-runner -Force; \\
    $actual=(& C:\\actions-runner\\bin\\Runner.Listener.exe --version | Select-Object -Last 1).Trim(); \\
    if ($actual -ne $version) {{ throw ('Runner.Listener version mismatch: ' + $actual) }}; \\
    Set-Content -NoNewline C:\\runner-version.txt $actual
ENTRYPOINT ["powershell","-NoProfile","-NonInteractive","-Command","$v=(Get-Content C:\\runner-version.txt -Raw).Trim(); $actual=(& C:\\actions-runner\\bin\\Runner.Listener.exe --version | Select-Object -Last 1).Trim(); [ordered]@{{version=$v;observed_version=$actual;oracleSatisfied=($v -eq $actual)}} | ConvertTo-Json -Compress"]
"""


def qualify_windows():
    if platform.system() != "Windows":
        return result("SKIPPED_GUARDRAIL", False, "Windows readiness requires Windows host", lane="windows")
    docker = substrate.command("docker")
    if not docker:
        return result("NEGATIVE_OBSERVATION", False, "docker CLI absent", lane="windows")
    daemon = substrate.run([docker, "version", "--format", "{{json .Server}}"], timeout=30)
    if not substrate.ok(daemon):
        start = substrate.sh(
            "$svc=Get-Service docker -ErrorAction SilentlyContinue; if ($null -eq $svc) { exit 3 }; if ($svc.Status -ne 'Running') { Start-Service docker }; (Get-Service docker).Status",
            timeout=60,
        )
        daemon = substrate.run([docker, "version", "--format", "{{json .Server}}"], timeout=30)
        if not substrate.ok(daemon):
            return result("ENVIRONMENT_FAILURE", False, "Windows container daemon unavailable", lane="windows", service_start=start)
    with tempfile.TemporaryDirectory(prefix="win-runner-ready-") as td:
        root = pathlib.Path(td)
        (root / "Dockerfile").write_text(windows_dockerfile())
        tag = "agent-dispatch/windows-runner-ready:" + uuid.uuid4().hex[:8]
        build = substrate.run([docker, "build", "--pull", "-t", tag, str(root)], timeout=900)
        if not substrate.ok(build):
            return result("ORACLE_FAILURE", False, "Windows runner package image build/version oracle failed", lane="windows", build=build)
        run_result = substrate.run([docker, "run", "--rm", "--isolation=process", tag], timeout=180)
        cleanup = substrate.run([docker, "image", "rm", "-f", tag], timeout=60)
        parsed = substrate.parse_json_stdout(run_result)
        passed = substrate.ok(run_result) and isinstance(parsed, dict) and parsed.get("oracleSatisfied") is True
        return result(
            "SUPPORTED" if passed else "ORACLE_FAILURE",
            passed,
            "official Windows x64 Actions runner package staged and executable in process-isolated container" if passed else "Windows container runner version oracle failed",
            lane="windows",
            build=build,
            execution=run_result,
            stage=parsed,
            cleanup=cleanup,
        )


def qualify_lxc():
    if platform.system() != "Linux" or platform.machine().lower() not in ("x86_64", "amd64"):
        return result("SKIPPED_GUARDRAIL", False, "LXC runner readiness currently targets Linux x86_64", lane="lxc")
    for tool in ("lxc-create", "lxc-start", "lxc-attach", "lxc-stop", "lxc-destroy"):
        if not substrate.command(tool):
            return result("NEGATIVE_OBSERVATION", False, "missing LXC tool: " + tool, lane="lxc")
    substrate.ensure_lxc_bridge()
    nat = substrate.ensure_bridge_nat("lxcbr0")
    name = "gha-lxc-runner-" + uuid.uuid4().hex[:8]
    create = substrate.run(["lxc-create", "-n", name, "-t", "download", "--", "-d", "ubuntu", "-r", "noble", "-a", "amd64"], timeout=360)
    start = {"exit_code": None}
    stage = {"exit_code": None}
    stop = {"exit_code": None}
    destroy = {"exit_code": None}
    try:
        if not substrate.ok(create):
            return result("ENVIRONMENT_FAILURE", False, "Ubuntu LXC rootfs creation failed", lane="lxc", create=create, bridge_nat=nat)
        cfg = pathlib.Path("/var/lib/lxc") / name / "config"
        with cfg.open("a") as fp:
            fp.write("\nlxc.net.0.type = veth\nlxc.net.0.link = lxcbr0\nlxc.net.0.flags = up\n")
        start = substrate.run(["lxc-start", "-n", name, "-d"], timeout=60)
        if substrate.ok(start):
            time.sleep(4)
            substrate.run(["lxc-attach", "-n", name, "--", "sh", "-lc", "dhclient -v eth0 >/tmp/dhclient.log 2>&1 || true"], timeout=45)
            stage = substrate.run(["lxc-attach", "-n", name, "--", "bash", "-lc", linux_stage_shell()], timeout=900)
    finally:
        stop = substrate.run(["lxc-stop", "-n", name, "-k"], timeout=30)
        destroy = substrate.run(["lxc-destroy", "-n", name], timeout=60)
        nat_cleanup = substrate.cleanup_bridge_nat(nat)
    parsed = substrate.parse_json_stdout(stage)
    passed = substrate.ok(create) and substrate.ok(start) and substrate.ok(stage) and isinstance(parsed, dict) and parsed.get("oracleSatisfied") is True and substrate.ok(destroy)
    return result(
        "SUPPORTED" if passed else "ORACLE_FAILURE",
        passed,
        "official Linux x64 Actions runner package staged through the provider-neutral #278 runner kit inside LXC" if passed else "LXC runner package readiness oracle failed",
        lane="lxc",
        create=create, start=start, execution=stage, stage=parsed,
        cleanup={"stop": stop, "destroy": destroy, "bridge_nat": nat_cleanup},
    )


def qualify_incus():
    if platform.system() != "Linux" or platform.machine().lower() not in ("x86_64", "amd64"):
        return result("SKIPPED_GUARDRAIL", False, "Incus runner readiness currently targets Linux x86_64", lane="incus")
    incus = substrate.command("incus")
    if not incus:
        return result("NEGATIVE_OBSERVATION", False, "incus CLI absent", lane="incus")
    init = substrate.run([incus, "admin", "init", "--minimal"], timeout=90)
    nets = substrate.run([incus, "network", "list", "--format", "json"], timeout=30)
    parsed_nets = substrate.parse_json_stdout(nets) or []
    managed = [n for n in parsed_nets if n.get("managed") and n.get("type") == "bridge"]
    bridge = (managed[0].get("name") if managed else None) or "incusbr0"
    nat = substrate.ensure_bridge_nat(bridge)
    name = "gha-incus-runner-" + uuid.uuid4().hex[:8]
    launch = substrate.run([incus, "launch", "images:ubuntu/24.04", name], timeout=360)
    stage = {"exit_code": None}
    delete = {"exit_code": None}
    try:
        if substrate.ok(launch):
            for _ in range(20):
                state = substrate.run([incus, "info", name], timeout=15)
                if "Status: RUNNING" in state.get("stdout", ""):
                    break
                time.sleep(2)
            stage = substrate.run([incus, "exec", name, "--", "bash", "-lc", linux_stage_shell()], timeout=900)
    finally:
        delete = substrate.run([incus, "delete", name, "--force"], timeout=60)
        nat_cleanup = substrate.cleanup_bridge_nat(nat)
    parsed = substrate.parse_json_stdout(stage)
    passed = substrate.ok(init) and substrate.ok(launch) and substrate.ok(stage) and isinstance(parsed, dict) and parsed.get("oracleSatisfied") is True and substrate.ok(delete)
    return result(
        "SUPPORTED" if passed else "ORACLE_FAILURE",
        passed,
        "official Linux x64 Actions runner package staged through the provider-neutral #278 runner kit inside Incus" if passed else "Incus runner package readiness oracle failed",
        lane="incus",
        init=init, launch=launch, execution=stage, stage=parsed,
        cleanup={"delete": delete, "bridge_nat": nat_cleanup},
    )


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--lane", required=True, choices=("windows", "lxc", "incus"))
    p.add_argument("--out", required=True)
    a = p.parse_args()
    payload = {"windows": qualify_windows, "lxc": qualify_lxc, "incus": qualify_incus}[a.lane]()
    payload["timestamp_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    out = pathlib.Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"lane": a.lane, "classification": payload["classification"], "oracleSatisfied": payload["oracleSatisfied"], "detail": payload["detail"]}, indent=2))


if __name__ == "__main__":
    main()
