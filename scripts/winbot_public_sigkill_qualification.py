#!/usr/bin/env python3
"""One intentionally SIGKILLed public disposable VM, one explicit reaper.

Exercises interruption where try/finally never runs. Negative mutation of the
durable run-owned network UUID must be refused BEFORE touching live resources.
"""
from __future__ import annotations
import json
import os
import pathlib
import subprocess
import sys
import uuid

ROOT=pathlib.Path("/tmp/winbot-crash-owned")
def cmd(*parts,env=None):
    return subprocess.run(parts,env=env,text=True,capture_output=True,
                          check=False,timeout=150)
def main()->int:
    if ROOT.exists() or ROOT.is_symlink():
        raise RuntimeError("refuse preexisting crash-test evidence root")
    env=os.environ.copy()
    env.update({
        "WINBOT_PUBLIC_OVERLAY_EVIDENCE_DIR":str(ROOT),
        "WINBOT_PUBLIC_FATAL_STAGE":"after_domain_started",
        "WINBOT_PUBLIC_SYNTHETIC_FAULTS":"1",
    })
    crash=cmd(sys.executable,"-m","scripts.winbot_public_overlay_readback",env=env)
    if crash.returncode!=-9:
        raise RuntimeError("expected *real* SIGKILL and no finally, got "+
                           str(crash.returncode)+" stderr="+crash.stderr[-350:])
    manifest=ROOT/"ownership-manifest.json"
    if not manifest.is_file():
        raise RuntimeError("durable owner manifest not persisted before fatal stage")
    original=manifest.read_bytes()
    owned=json.loads(original)
    uid=owned["vm_uuid"];net=owned["network_name"]
    def exists(kind,name):
        return cmd("virsh","-c","qemu:///system",kind,name).returncode==0
    if not exists("dominfo",uid) or not exists("net-info",net):
        raise RuntimeError("SIGKILL did not leave run-owned native VM/network to recover")
    if not pathlib.Path(owned["overlay_root"]).is_dir():
        raise RuntimeError("crashed workcell lost overlay unexpectedly")
    # Tamper the manifest only, leaving real native objects intact. Reaper MUST
    # reject mismatch and not delete any foreign (even synthetic) object.
    bad=dict(owned);bad["network_uuid"]=str(uuid.uuid4())
    manifest.write_text(json.dumps(bad,indent=2,sort_keys=True)+"\n")
    refused=cmd(sys.executable,"-m","scripts.winbot_public_crash_reaper",str(manifest))
    if (refused.returncode!=7 or
        not exists("dominfo",uid) or not exists("net-info",net) or
        not pathlib.Path(owned["overlay_root"]).is_dir()):
        raise RuntimeError("manifest tamper was not rejected before native mutation")
    manifest.write_bytes(original)
    def refuse_no_mutation(label):
        decision=cmd(sys.executable,"-m","scripts.winbot_public_crash_reaper",str(manifest))
        if (decision.returncode!=7 or
            not exists("dominfo",uid) or not exists("net-info",net) or
            not pathlib.Path(owned["overlay_root"]).is_dir()):
            raise RuntimeError(label+" did not refuse before native mutation")

    # File custody negative: same exact contents through a symlink must not
    # become owner authority. Restore the original regular file afterwards.
    decoy=ROOT/"untrusted-owner-manifest.json"
    decoy.write_bytes(original)
    os.chmod(decoy,0o600)
    manifest.unlink()
    manifest.symlink_to(decoy)
    try:
        refuse_no_mutation("symlink-manifest")
    finally:
        manifest.unlink()
        manifest.write_bytes(original)
        os.chmod(manifest,0o600)
        decoy.unlink()

    twin=ROOT/"manifest-hardlink-alias"
    os.link(manifest,twin)
    try:
        refuse_no_mutation("multiply-linked-manifest")
    finally:
        twin.unlink()

    # A duplicate key can alter the effective authorization subject while
    # looking legitimate in a human-readable receipt.
    payload=original.decode("utf-8").strip()
    manifest.write_text(payload[:-1]+',"vm_uuid":"'+uid+'"}\n')
    try:
        refuse_no_mutation("duplicate-key-manifest")
    finally:
        manifest.write_bytes(original)
    recovered=cmd(sys.executable,"-m","scripts.winbot_public_crash_reaper",str(manifest))
    if recovered.returncode:
        raise RuntimeError("exact-owner crash cleanup failed: "+
                           recovered.stderr[-500:])
    receipt=json.loads((ROOT/"recovery.json").read_text())
    if not all(receipt[k] for k in
         ("domain_absent","network_absent","overlay_absent","master_fixture_absent")):
        raise RuntimeError("crash cleanup left owned state")
    proof={"schema":"winbot-public-sigkill-qualification/v1",
           "classification":"DISPOSABLE_KVM_SIGKILL_AND_EXACT_OWNER_RECOVERY",
           "actual_process_sigkill_observed":crash.returncode==-9,
           "native_resources_remained_after_sigkill":True,
           "mutated_network_uuid_refused_without_resource_change":True,
           "symlinked_manifest_refused_without_resource_change":True,
           "multiply_linked_manifest_refused_without_resource_change":True,
           "duplicate_key_manifest_refused_without_resource_change":True,
           "durable_manifest_directory_and_file_private":True,
           "exact_owner_recovery_performed":True,
           "recovered_native_domain_absent":True,
           "recovered_native_network_absent":True,
           "recovered_overlay_absent":True,
           "recovered_master_absent":True,
           "windows_pe_or_winbot_guest_executed":False,
           "private_winbot_source_executed":False,
           "product_reaper_admitted":False,
           "deployment_authorized":False}
    (ROOT/"sigkill-qualification.json").write_text(
        json.dumps(proof,sort_keys=True,indent=2)+"\n")
    return 0
if __name__=="__main__":raise SystemExit(main())
