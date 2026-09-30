"""
WinBot Capability Registry
Maps installed tools → active capabilities → API/MCP features.

Consumed by:
- /health/capabilities endpoint (reports what agents can do)
- MCP server (conditionally registers tools)
- deploy-loadout.ps1 (verifies tool installation)

Reads guest/tools/catalog.json as the single source of truth.
"""

import json
import logging
import os
import subprocess
from pathlib import Path
from typing import Dict, Optional, Set

logger = logging.getLogger("winbot.capabilities")

# Resolve catalog path relative to this module
_CATALOG_PATH = Path(__file__).resolve().parent.parent / "tools" / "catalog.json"

# Cache: load catalog once
_catalog: Optional[dict] = None
# Cache: capability checks (expensive — run once per process lifetime)
_computed_capabilities: Optional[dict] = None


def _load_catalog(validate: bool = True) -> dict:
    """Load the tool catalog from disk. Cached. Validates against JSON Schema on first load."""
    global _catalog
    if _catalog is not None:
        return _catalog
    if not _CATALOG_PATH.exists():
        logger.warning("Tool catalog not found: %s", _CATALOG_PATH)
        _catalog = {"tools": {}, "capability_groups": {}, "loadout_templates": {}}
        return _catalog
    with open(_CATALOG_PATH) as f:
        _catalog = json.load(f)

    # Validate against JSON Schema on first load
    schema_path = _CATALOG_PATH.parent / "catalog.schema.json"
    if validate and schema_path.exists():
        try:
            with open(schema_path) as sf:
                schema = json.load(sf)
            from jsonschema import validate as schema_validate
            schema_validate(instance=_catalog, schema=schema)
        except ImportError:
            logger.debug("jsonschema not installed — skipping catalog validation")
        except Exception as e:
            logger.warning("Catalog schema validation failed: %s", e)
    # Validate dependency DAG for cycles
    _validate_catalog_dag(_catalog)
    return _catalog


def _validate_catalog_dag(catalog: dict) -> None:
    """Detect cycles in tool dependency graph. Warns on detection."""
    tools = catalog.get("tools", {})
    if not tools:
        return

    # Build adjacency list
    deps: dict[str, set[str]] = {}
    for name, tool in tools.items():
        deps[name] = set(tool.get("dependencies", []))

    # DFS-based cycle detection with white/gray/black coloring
    WHITE, GRAY, BLACK = 0, 1, 2
    color: dict[str, int] = {name: WHITE for name in tools}

    def _dfs(node: str, path: list[str]) -> list[str] | None:
        color[node] = GRAY
        path.append(node)
        for dep in deps.get(node, set()):
            if dep not in tools:
                continue  # External dependency — not part of our DAG
            if color.get(dep) == GRAY:
                # Found cycle — extract the cycle from path
                cycle_start = path.index(dep)
                return path[cycle_start:] + [dep]
            if color.get(dep) == WHITE:
                result = _dfs(dep, path)
                if result:
                    return result
        path.pop()
        color[node] = BLACK
        return None

    for name in tools:
        if color.get(name) == WHITE:
            cycle = _dfs(name, [])
            if cycle:
                cycle_str = " -> ".join(cycle)
                logger.warning("Catalog dependency cycle detected: %s", cycle_str)
                return  # Report first cycle only

    logger.debug("Catalog DAG validation: no cycles detected (%d tools)", len(tools))


def _verify_tool(tool: dict) -> bool:
    """Run the tool's verify command/check. Returns True if tool is installed."""
    verify = tool.get("verify", {})
    vtype = verify.get("type", "none")

    if vtype == "command":
        try:
            result = subprocess.run(
                [verify["command"]] + verify.get("args", []),
                capture_output=True, text=True, timeout=15,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            expected = verify.get("expect_exit", 0)
            return result.returncode == expected
        except Exception:
            return False

    elif vtype == "path":
        paths = verify.get("paths", [])
        for p in paths:
            expanded = os.path.expandvars(p)
            if os.path.exists(expanded):
                return True
        return False

    return False  # Unknown verify type — not verifiable


def get_tool_status() -> Dict[str, dict]:
    """Check every tool in the catalog. Returns installed/unavailable per tool."""
    catalog = _load_catalog()
    result = {}
    for tool_name, tool_def in catalog.get("tools", {}).items():
        is_installed = _verify_tool(tool_def)
        result[tool_name] = {
            "name": tool_name,
            "display_name": tool_def.get("display_name", tool_name),
            "installed": is_installed,
            "category": tool_def.get("category", "unknown"),
            "capabilities_enabled": tool_def.get("capabilities_enabled", []) if is_installed else [],
            "dependencies": tool_def.get("dependencies", []),
            "human_only": tool_def.get("human_only", False),
        }
    return result


def get_active_capabilities(force_refresh: bool = False) -> Dict[str, dict]:
    """Compute which capabilities are available based on installed tools.

    Returns dict with:
    - capabilities: {cap_name: active_bool, ...}
    - missing_dependencies: {cap_name: [missing_tool_names], ...}
    - capability_groups: {group_name: {label, description, active_bool}, ...}
    """
    global _computed_capabilities
    if _computed_capabilities is not None and not force_refresh:
        return _computed_capabilities

    catalog = _load_catalog()
    tool_status = get_tool_status()

    # Build active capabilities set
    active_caps: Set[str] = set()
    # Core capabilities are always available on a WinBot VM
    active_caps.update({"screenshot", "window_management", "app_launch", "lifecycle", "health_checking"})

    for tool_name, status in tool_status.items():
        if status["installed"]:
            for cap in status["capabilities_enabled"]:
                active_caps.add(cap)

    # Build comprehensive capability list
    all_caps: Set[str] = set()
    all_caps.update(active_caps)
    for tool_def in catalog.get("tools", {}).values():
        for cap in tool_def.get("capabilities_enabled", []):
            all_caps.add(cap)

    capabilities = {}
    for cap in sorted(all_caps):
        capabilities[cap] = cap in active_caps

    # Compute missing dependencies per capability
    missing_deps = {}
    for cap_name in sorted(all_caps):
        if cap_name in active_caps:
            continue
        # Which tools provide this capability and are they installed?
        missing_tools = []
        for tool_name, tool_def in catalog.get("tools", {}).items():
            if cap_name in tool_def.get("capabilities_enabled", []):
                if not tool_status.get(tool_name, {}).get("installed", False):
                    missing_tools.append(tool_name)
        if missing_tools:
            missing_deps[cap_name] = missing_tools

    # Capability groups
    groups = {}
    for group_name, group_def in catalog.get("capability_groups", {}).items():
        group_caps = group_def.get("capabilities", [])
        all_required_tools = set()
        for tool_name in group_def.get("requires_tools", []):
            all_required_tools.add(tool_name)
        groups[group_name] = {
            "label": group_def.get("label", group_name),
            "description": group_def.get("description", ""),
            "active": all(capabilities.get(c, False) for c in group_caps),
            "capabilities": {c: capabilities.get(c, False) for c in group_caps},
            "required_tools": sorted(all_required_tools),
            "installed_tools": sorted(t for t in all_required_tools if tool_status.get(t, {}).get("installed", False)),
        }

    _computed_capabilities = {
        "capabilities": capabilities,
        "missing_dependencies": missing_deps,
        "capability_groups": groups,
        "tool_count": sum(1 for t in tool_status.values() if t["installed"]),
        "total_tools": len(tool_status),
    }
    return _computed_capabilities


def get_loadout_templates() -> Dict[str, dict]:
    """Return available loadout templates from the catalog."""
    catalog = _load_catalog()
    return catalog.get("loadout_templates", {})


def _detect_platform() -> dict:
    """Detect the current platform and return platform type + unique capabilities."""
    import platform as _platform
    import sys

    result = {
        "os": _platform.system(),
        "os_release": _platform.release(),
        "is_vm": False,
        "vm_type": None,
        "platform": "physical",
        "platform_unique": [],
        "missing_platform": [],
    }

    # Windows platform detection
    if sys.platform == "win32":
        result["platform"] = "windows"
        # Check for Hyper-V guest
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"SOFTWARE\Microsoft\Virtual Machine\Auto")
            result["is_vm"] = True
            result["vm_type"] = "hyperv"
            result["platform"] = "hyperv-guest"
            winreg.CloseKey(key)
        except OSError:
            pass

        # Check for VirtualBox guest
        if not result["is_vm"]:
            try:
                import winreg
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                    r"HARDWARE\ACPI\DSDT\VBOX__")
                result["is_vm"] = True
                result["vm_type"] = "virtualbox"
                result["platform"] = "virtualbox-guest"
                winreg.CloseKey(key)
            except OSError:
                pass

    # Linux platform detection
    elif sys.platform == "linux":
        result["platform"] = "linux"
        # Check for common VM markers
        try:
            with open("/sys/class/dmi/id/product_name") as f:
                product = f.read().strip()
            if "KVM" in product or "QEMU" in product:
                result["is_vm"] = True
                result["vm_type"] = "kvm"
                result["platform"] = "kvm-guest"
            elif "VMware" in product:
                result["is_vm"] = True
                result["vm_type"] = "vmware"
                result["platform"] = "vmware-guest"
        except Exception:
            pass

    # Darwin platform detection
    elif sys.platform == "darwin":
        result["platform"] = "macos"

    # Map platform to unique capabilities
    platform_caps = {
        "hyperv-guest": ["hyperv_management", "vhdx_operations", "dism_servicing",
                         "powershell_direct", "differencing_disks", "credential_rotation"],
        "virtualbox-guest": ["virtualbox_management"],
        "kvm-guest": ["kvm_management", "qemu_guest_agent"],
        "windows": ["powershell_direct", "dism_servicing", "credential_rotation"],
        "linux": ["x11_capture", "wine_prefix", "procfs_health", "shared_memory_ipc"],
        "macos": ["metal_capture", "coreml_inference"],
    }

    all_platform_caps = set()
    for caps in platform_caps.values():
        all_platform_caps.update(caps)

    result["platform_unique"] = platform_caps.get(result["platform"], [])
    result["missing_platform"] = sorted(all_platform_caps - set(result["platform_unique"]))

    return result


def capabilities_for_api() -> dict:
    """Return which API features are active. Consumers use this to gate endpoints."""
    active = get_active_capabilities()
    caps = active["capabilities"]
    platform_info = _detect_platform()

    return {
        # Platform identity (NEW — migration step 1)
        "platform": platform_info["platform"],
        "os": platform_info["os"],
        "os_release": platform_info["os_release"],
        "is_vm": platform_info["is_vm"],
        "vm_type": platform_info["vm_type"],
        "platform_unique": platform_info["platform_unique"],
        "missing_platform": platform_info["missing_platform"],

        # Input features
        "run_python": caps.get("run_python", False),
        "run_ahk": caps.get("run_ahk", False),
        "run_autoit": caps.get("run_autoit", False),
        "input_automation": caps.get("input_automation", False),
        "screenshot_capture": caps.get("screenshot_capture", False),
        "gui_automation": caps.get("gui_automation", False),

        # Core (always available)
        "screenshot": True,
        "window_management": True,
        "app_launch": True,
        "lifecycle": True,
        "health_checking": True,

        # RE
        "static_analysis_headless": caps.get("static_analysis_headless", False),
        "static_analysis_cli": caps.get("static_analysis_cli", False),
        "dynamic_instrumentation": caps.get("dynamic_instrumentation", False),
        "dynamic_debugging_gui": caps.get("dynamic_debugging_gui", False),
        "network_capture": caps.get("network_capture", False),
        "process_monitoring": caps.get("process_monitoring", False),
        "binary_detection": caps.get("binary_detection", False),
        "string_deobfuscation": caps.get("string_deobfuscation", False),
        "python_re_toolkit": caps.get("python_re_toolkit", False),

        # Remote Desktop
        "remote_desktop_vnc": caps.get("remote_desktop_vnc", False),

        # Summary
        "tool_count": active.get("tool_count", 0),
        "total_tools": active.get("total_tools", 0),
        "capability_groups": active.get("capability_groups", {}),
    }
