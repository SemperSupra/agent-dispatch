#!/usr/bin/env python3
"""Independent P2 current-vanilla guest + TLS-scoped COLLAGE actual App observer gate.

Source parity, a green native guest, a synthetic provider JSON, or an
admin-privileged readback cannot substitute for this joined true guest receipt.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import sys

from assert_vanilla263_native_t6_receipt import check as check_native_guest
from admit_vanilla263_native_t6_control import APP, OWNER, TARGET

SCHEMA = "semper-supra.collage-native-readback-p2/1"
COLLAGE_REF = "17dfacc4351053fa06f8bdbaed7d931c97c1707e"
ARTIFACT = "da25005e8729e6f013f7108ac5b8869dd46323befc78efdae18221b26cafe5f8"


def require(value: bool, reason: str) -> None:
    if not value:
        raise ValueError(reason)


def check(root: dict) -> None:
    check_native_guest(root)
    p = root["foundry_materialization"]
    r = p.get("collage_readback")
    require(type(r) is dict and r.get("schema") == SCHEMA and
            r.get("classification") == "PROVIDER_READBACK_MATCH",
            "COLLAGE_REAL_GUEST_READBACK_ABSENT")
    require(r.get("native_vanilla263_source_profile") is True and
            r.get("source_sha") == COLLAGE_REF and
            r.get("real_artifact_sha256_verified") == ARTIFACT,
            "COLLAGE_REAL_DATAPACK_PRODUCER_DRIFT")
    require(r.get("native_app") == APP and
            r.get("world_id") == OWNER["SUPRACRAFT_COLLAGE_WORLD_ID"] and
            r.get("service_id") == OWNER["SUPRACRAFT_COLLAGE_SERVICE_ID"] and
            r.get("truenas_version") == TARGET and
            r.get("ownership_fields_matched") == 6,
            "COLLAGE_NATIVE_APP_OWNER_DRIFT")
    require(r.get("transport") == "isolated_guest_tls_verified" and
            type(r.get("tls_cert_sha256")) is str and
            re.fullmatch(r"[0-9a-f]{64}", r["tls_cert_sha256"]) is not None,
            "COLLAGE_TLS_VERIFICATION_UNPROVEN")
    require(r.get("credential_scope") == "APPS_READ" and
            r.get("observation_mutation_count") == 0 and
            r.get("credential_mutation_phase") ==
            "disposable_guest_setup_before_observation",
            "COLLAGE_SCOPED_ZERO_MUTATION_OBSERVATION_UNPROVEN")
    require(type(r.get("source_plan_sha256")) is str and
            re.fullmatch(r"[0-9a-f]{64}", r["source_plan_sha256"]) is not None,
            "COLLAGE_SOURCE_INTENT_UNBOUND")
    require(r.get("world_artifact_format_verified") is False and
            r.get("world_activated") is False and
            r.get("two_rivers_gameplay_qualified") is False and
            r.get("cloudnet_adoption_executed") is False and
            r.get("physical_true_nas_mutated") is False,
            "COLLAGE_UNSUPPORTED_GUEST_PROMOTION")
    require(root["foundry_materialization"]["cleanup"]["zero_residue"] is True,
            "COLLAGE_GUEST_CLEANUP_INCOMPLETE")


def main() -> int:
    p=argparse.ArgumentParser()
    p.add_argument("--receipt",required=True,type=Path)
    a=p.parse_args()
    try:
        check(json.loads(a.receipt.read_text(encoding="utf-8")))
    except (OSError,ValueError,TypeError,KeyError):
        print("COLLAGE vanilla263 real guest observer REFUSED: incomplete exact readback proof",file=sys.stderr)
        return 2
    print("COLLAGE vanilla263 real guest observer SUPPORTED: scoped TLS App readback, exact owner, zero mutation, native world cleanup")
    return 0

if __name__=="__main__":
    sys.exit(main())
