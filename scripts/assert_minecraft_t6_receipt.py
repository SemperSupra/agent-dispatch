#!/usr/bin/env python3
"""Fail closed unless nested Minecraft T6 proved protocol, persistence and cleanup."""
import argparse
import json
import pathlib
import sys


def check(r):
    def required(ok, message):
        if not ok:
            raise ValueError(message)
    required(isinstance(r, dict) and r.get("contract") == "gha-kvm-system-lab/v1", "root schema")
    target = r.get("target") or {}
    required(target.get("product") == "truenas" and target.get("version") == "25.04.1"
             and target.get("rung") == "T6", "wrong exact guest")
    required(r.get("classification") == "SUPPORTED" and r.get("oracleSatisfied") is True,
             "guest/root oracle failure")
    s = r.get("session_execution") or {}
    required(s.get("schema") == "truenas-session-execution/v1"
             and s.get("classification") == "SESSION_CLEAN" and s.get("session_clean") is True,
             "unclean capsule session")
    capsules = s.get("capsules") or []
    required(isinstance(capsules, list) and len(capsules) == 1, "capsule count")
    c = capsules[0]
    required(c.get("provider") == "minecraft-paper-t6" and c.get("verdict") == "SUPPORTED"
             and c.get("cleanup_satisfied") is True, "provider verdict/cleanup")
    p = c.get("provider_receipt") or {}
    f = r.get("foundry_materialization") or {}
    required(p.get("schema") == "truenas-minecraft-paper-t6/v1"
             and p.get("classification") == "SUPPORTED" and p.get("oracleSatisfied") is True,
             "product oracle failure")
    required(f.get("schema") == p.get("schema") and
             f.get("control_sha256") == p.get("control_sha256"),
             "materialization/provenance mismatch")
    required(p.get("catalog_version_verified") is True, "catalog not confirmed")
    required(p.get("world_retained_on_delete") is True
             and p.get("world_rebound_after_reinstall") is True, "world not persistent")
    cleanup = p.get("cleanup") or {}
    required(all(cleanup.get(k) is True for k in
                 ("zero_residue", "app_absent", "owned_world_dataset_absent")), "cleanup failed")
    readiness = p.get("readiness") or {}
    for phase in ("first", "restart", "redeploy", "reinstall"):
        stage = readiness.get(phase) or {}
        o = stage.get("protocol") or {}
        level = stage.get("level") or {}
        required(o.get("schema") == "minecraft-java-status-oracle/v1"
                 and o.get("oracleSatisfied") is True and o.get("java_version") == "1.21.11"
                 and o.get("status_packet_valid") is True, "status missing: " + phase)
        required(isinstance(level.get("size"), int) and level["size"] > 0,
                 "world level.dat absent: " + phase)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt", type=pathlib.Path, required=True)
    args = parser.parse_args()
    try:
        check(json.loads(args.receipt.read_text(encoding="utf-8")))
    except (OSError, ValueError) as exc:
        print("Minecraft T6 acceptance FAILED: " + str(exc), file=sys.stderr)
        return 2
    print("Minecraft T6 acceptance SUPPORTED: protocol/world/cleanup")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
