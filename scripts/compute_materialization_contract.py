#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
from typing import Any


class ContractError(RuntimeError):
    pass


def load(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError(f"cannot read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ContractError(f"{path} must contain an object")
    return value


def platform_targets(registry: dict[str, Any], platform: str) -> list[dict[str, Any]]:
    if registry.get("schema") != "semper-supra.compute-materialization-targets/v1":
        raise ContractError("unsupported registry schema")
    platforms = registry.get("platforms")
    if not isinstance(platforms, dict) or platform not in platforms:
        raise ContractError(f"unsupported platform: {platform}")
    targets = platforms[platform].get("targets")
    if not isinstance(targets, list) or not targets:
        raise ContractError(f"{platform}: target list missing")
    versions = [x.get("version") for x in targets if isinstance(x, dict)]
    if len(versions) != len(set(versions)) or any(not isinstance(v, str) or not v for v in versions):
        raise ContractError(f"{platform}: target versions must be unique non-empty strings")
    return targets


def target(registry: dict[str, Any], platform: str, version: str) -> dict[str, Any]:
    rows = [x for x in platform_targets(registry, platform) if x["version"] == version]
    if len(rows) != 1:
        raise ContractError(f"exact target not admitted: {platform}/{version}")
    return rows[0]


def validate_adapter(adapter: dict[str, Any], platform: str, kind: str) -> None:
    if not isinstance(adapter.get("id"), str) or not adapter["id"]:
        raise ContractError(f"{platform}/{kind}: adapter id missing")
    if platform == "truenas":
        methods = adapter.get("required_methods")
        if not isinstance(methods, list) or not methods or any(not isinstance(x, str) or "." not in x for x in methods):
            raise ContractError(f"{adapter['id']}: required_methods invalid")
        if kind == "container":
            discovery = adapter.get("image_discovery")
            if not isinstance(discovery, dict):
                raise ContractError(f"{adapter['id']}: image_discovery missing")
            method = discovery.get("method")
            if not isinstance(method, str) or method not in methods:
                raise ContractError(f"{adapter['id']}: image_discovery method must be required")
            if not isinstance(discovery.get("source"), str) or not discovery["source"].startswith("https://"):
                raise ContractError(f"{adapter['id']}: image_discovery source invalid")
            if not isinstance(discovery.get("selection"), dict) or not discovery["selection"]:
                raise ContractError(f"{adapter['id']}: image_discovery selection missing")
    elif platform == "proxmox":
        templates = adapter.get("required_api_templates")
        if not isinstance(templates, list) or not templates or any(not isinstance(x, str) or " /" not in x for x in templates):
            raise ContractError(f"{adapter['id']}: required_api_templates invalid")


def validate(registry: dict[str, Any]) -> dict[str, Any]:
    seen_adapters: set[tuple[str, str, str]] = set()
    summary: dict[str, Any] = {}
    for platform in ("truenas", "proxmox"):
        rows = platform_targets(registry, platform)
        ps = []
        for row in rows:
            if not isinstance(row.get("source_fingerprint"), dict) or not row["source_fingerprint"]:
                raise ContractError(f"{platform}/{row['version']}: source_fingerprint missing")
            if platform == "truenas":
                api_fp = row.get("api_schema_fingerprint")
                if not isinstance(api_fp, dict) or not api_fp:
                    raise ContractError(f"{platform}/{row['version']}: api_schema_fingerprint missing")
            for kind in ("container", "vm"):
                adapters = row.get(f"{kind}_adapters")
                if not isinstance(adapters, list) or not adapters:
                    raise ContractError(f"{platform}/{row['version']}: {kind}_adapters missing")
                for adapter in adapters:
                    validate_adapter(adapter, platform, kind)
                    if platform == "truenas":
                        family = adapter.get("source_api_family")
                        if not isinstance(family, str) or not family.startswith("v"):
                            raise ContractError(f"{adapter['id']}: source_api_family missing")
                    key = (platform, row["version"], adapter["id"])
                    if key in seen_adapters:
                        raise ContractError(f"duplicate adapter in target: {key}")
                    seen_adapters.add(key)
            ps.append({
                "version": row["version"],
                "management_families": row.get("management_families", []),
                "container_adapters": [a["id"] for a in row["container_adapters"]],
                "vm_adapters": [a["id"] for a in row["vm_adapters"]],
            })
        if platform == "proxmox":
            candidates = registry["platforms"][platform].get("candidate_targets", [])
            if not isinstance(candidates, list):
                raise ContractError("proxmox: candidate_targets must be a list")
            admitted = {x["version"] for x in rows}
            seen_candidates = set()
            for candidate in candidates:
                if not isinstance(candidate, dict):
                    raise ContractError("proxmox: candidate target must be an object")
                version = candidate.get("version")
                digest = candidate.get("iso_sha256")
                if not isinstance(version, str) or not version or version in admitted or version in seen_candidates:
                    raise ContractError(f"proxmox: invalid or duplicate candidate version {version!r}")
                if not isinstance(digest, str) or len(digest) != 64:
                    raise ContractError(f"proxmox/{version}: candidate ISO SHA-256 invalid")
                if candidate.get("state") != "source-profile-open":
                    raise ContractError(f"proxmox/{version}: candidate must remain source-profile-open")
                seen_candidates.add(version)
            summary["proxmox_candidates"] = [
                {"version": x["version"], "state": x["state"]} for x in candidates
            ]
        summary[platform] = ps
    return {
        "schema": "semper-supra.compute-materialization-targets-validation/v1",
        "status": "PASS",
        "platforms": summary,
        "claim_boundary": "profile contract only; no runtime qualification implied",
    }


def choose_adapter(
    registry: dict[str, Any],
    platform: str,
    version: str,
    kind: str,
    observed_methods: set[str] | None,
) -> dict[str, Any]:
    if kind not in {"container", "vm"}:
        raise ContractError(f"unsupported kind: {kind}")
    row = target(registry, platform, version)
    adapters = row[f"{kind}_adapters"]

    if platform == "proxmox":
        if len(adapters) != 1:
            raise ContractError(f"{platform}/{version}/{kind}: ambiguous adapter set")
        return adapters[0]

    if observed_methods is None:
        raise ContractError("TrueNAS adapter selection requires observed method set")

    candidates = []
    for adapter in adapters:
        required = set(adapter["required_methods"])
        if required <= observed_methods:
            candidates.append(adapter)
    if not candidates:
        missing = {
            a["id"]: sorted(set(a["required_methods"]) - observed_methods)
            for a in adapters
        }
        raise ContractError(f"no capability-satisfied adapter; missing={missing}")

    preferred = [a for a in candidates if a.get("preferred") is True]
    if len(preferred) == 1:
        return preferred[0]
    if len(preferred) > 1:
        raise ContractError("multiple preferred adapters satisfied")
    if len(candidates) != 1:
        raise ContractError(f"multiple capability-satisfied adapters without preference: {[a['id'] for a in candidates]}")
    return candidates[0]


def semantic_plan(kind: str, adapter: dict[str, Any]) -> list[str]:
    if kind == "container":
        restart = "restart" if adapter.get("restart_semantics") == "native" else "stop+start"
        return ["observe", "create", "readback", "start", "guest-oracle", "update-if-supported", restart, "stop", "delete", "absence", "noop"]
    return ["observe", "create", "readback", "start", "guest-oracle", "nested-kvm-observe-if-firecracker", "restart", "stop", "delete", "absence", "noop"]


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--registry", type=pathlib.Path, default=pathlib.Path("config/compute-materialization-targets.json"))
    p.add_argument("--platform", choices=["truenas", "proxmox"])
    p.add_argument("--version")
    p.add_argument("--kind", choices=["container", "vm"])
    p.add_argument("--observed-methods", type=pathlib.Path)
    p.add_argument("--validate-only", action="store_true")
    args = p.parse_args()

    try:
        registry = load(args.registry)
        validation = validate(registry)
        if args.validate_only:
            print(json.dumps(validation, indent=2, sort_keys=True))
            return 0
        if not (args.platform and args.version and args.kind):
            raise ContractError("--platform, --version and --kind are required unless --validate-only")
        methods = None
        if args.observed_methods:
            raw = load(args.observed_methods)
            values = raw.get("methods")
            if not isinstance(values, list) or any(not isinstance(x, str) for x in values):
                raise ContractError("observed methods file must contain string array 'methods'")
            methods = set(values)
        adapter = choose_adapter(registry, args.platform, args.version, args.kind, methods)
        row = target(registry, args.platform, args.version)
        result = {
            "schema": "semper-supra.compute-materialization-plan/v1",
            "platform": args.platform,
            "version": args.version,
            "kind": args.kind,
            "adapter": adapter,
            "source_fingerprint": row["source_fingerprint"],
            "api_schema_fingerprint": row.get("api_schema_fingerprint"),
            "semantic_plan": semantic_plan(args.kind, adapter),
            "apply_authorized": False,
            "claim_boundary": "plan only; runtime apply requires separate bounded executor/authority",
        }
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except ContractError as exc:
        print(json.dumps({"status": "ERROR", "error": str(exc)}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
