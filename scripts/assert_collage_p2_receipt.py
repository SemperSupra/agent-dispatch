#!/usr/bin/env python3
"""Exact product receipt gate for real disposable COLLAGE native readback P2.

Requires full native Paper lifecycle AND TLS-verified provider read-only match.
Cannot pass from a synthetic observation file or a green runner job alone.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

EXPECTED_SOURCE = "fbda94f3fea0a216ddd9c35b38a09d325bed3640"
EXPECTED_SERVICE = "11111111-1111-4111-8111-111111111111"
EXPECTED_APP = "rdte-t6-minecraft-paper"


def check(row: dict) -> None:
    def need(cond, reason):
        if not cond:
            raise ValueError(reason)
    need(type(row) is dict and row.get("contract") == "gha-kvm-system-lab/v1",
         "root contract")
    target = row.get("target") or {}
    need(target.get("version") == "25.04.1"
         and target.get("rung") == "T6"
         and target.get("product") == "truenas", "wrong target")
    need(row.get("classification") == "SUPPORTED"
         and row.get("oracleSatisfied") is True, "root failed")
    p = row.get("foundry_materialization") or {}
    need(p.get("schema") == "truenas-minecraft-paper-t6/v1"
         and p.get("classification") == "SUPPORTED"
         and p.get("oracleSatisfied") is True, "Paper guest failed")
    need(p.get("catalog_version_verified") is True
         and p.get("world_retained_on_delete") is True
         and p.get("world_rebound_after_reinstall") is True,
         "native Paper lifecycle did not qualify")
    stages = p.get("readiness") or {}
    for label in ("first", "restart", "redeploy", "reinstall"):
        stage = stages.get(label) or {}
        status = stage.get("protocol") or {}
        level = stage.get("level") or {}
        need(status.get("oracleSatisfied") is True
             and status.get("server_protocol") == 774
             and status.get("server_implementation") == "paper"
             and type(level.get("size")) is int and level["size"] > 0,
             "exact Java status/world stage absent: " + label)
    cleanup = p.get("cleanup") or {}
    need(all(cleanup.get(k) is True for k in
             ("zero_residue", "app_absent", "owned_world_dataset_absent")),
         "native cleanup not exact")
    observation = p.get("collage_readback") or {}
    need(observation.get("schema") == "semper-supra.collage-native-readback-p2/1"
         and observation.get("classification") == "PROVIDER_READBACK_MATCH"
         and observation.get("source_sha") == EXPECTED_SOURCE
         and observation.get("native_app") == EXPECTED_APP
         and observation.get("service_id") == EXPECTED_SERVICE
         and observation.get("ownership_fields_matched") == 6
         and observation.get("credential_scope") == "APPS_READ"
         and observation.get("transport") == "isolated_guest_tls_verified"
         and observation.get("observation_mutation_count") == 0
         and observation.get("world_activated") is False
         and observation.get("cloudnet_adoption_executed") is False
         and observation.get("physical_true_nas_mutated") is False,
         "real guest read-only provider observation missing")
    need(isinstance(observation.get("tls_cert_sha256"), str)
         and len(observation["tls_cert_sha256"]) == 64,
         "TLS certificate anchor receipt missing")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt", type=pathlib.Path, required=True)
    args = parser.parse_args()
    try:
        check(json.loads(args.receipt.read_text(encoding="utf-8")))
    except (OSError, ValueError) as exc:
        print("COLLAGE P2 native guest acceptance FAILED: " + str(exc), file=sys.stderr)
        return 2
    print("COLLAGE P2 real guest acceptance SUPPORTED: Paper lifecycle + native TLS observation")
    return 0


if __name__ == "__main__":
    sys.exit(main())
