"""Synthetic provider-selection and device authority contracts.

No Mullvad API requests, no account material, no network or key operations.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class Relay:
    name: str
    country: str
    city: str
    active: bool


@dataclass(frozen=True)
class Selection:
    relay: Relay | None
    reason: str


def select_relay(relays: tuple[Relay, ...], country: str, city: str = "",
                 approved_fallbacks: tuple[tuple[str, str], ...] = ()) -> Selection:
    """Reject unsatisfied *mandatory* geography; no arbitrary first-active exit.

    Fallbacks are distinct *explicitly approved* alternative country/city pairs.
    """
    if not country or not isinstance(country, str):
        return Selection(None, "BLOCKED_NO_MANDATORY_CONSTRAINT")
    preferences = ((country, city),) + tuple(approved_fallbacks)
    for index, (allowed_country, allowed_city) in enumerate(preferences):
        if not allowed_country or not isinstance(allowed_country, str):
            continue
        eligible = [r for r in relays if r.active and r.country.lower() == allowed_country.lower()
                    and (not allowed_city or r.city.lower() == allowed_city.lower())]
        if eligible:
            return Selection(sorted(eligible, key=lambda r: r.name)[0],
                             "PRIMARY" if index == 0 else "EXPLICIT_FALLBACK")
    return Selection(None, "BLOCKED_CONSTRAINT_UNAVAILABLE")


@dataclass(frozen=True)
class Device:
    id: str
    account_alias: str
    active: bool


def authorize_device_change(devices: tuple[Device, ...], selected_id: str,
                            expected_account_alias: str, action: str,
                            explicit_approval: bool) -> bool:
    """Mutations must be specifically authorized; count exhaustion is not approval."""
    if action not in ("rotate-key", "revoke") or not explicit_approval:
        return False
    if not selected_id or not expected_account_alias or selected_id == "*":
        return False
    return sum(
        d.id == selected_id and d.account_alias == expected_account_alias and d.active
        for d in devices
    ) == 1


def public_safe_diagnostic(fields: dict) -> dict:
    """Default-deny public telemetry: validate *values*, not just field names.

    Never reflect arbitrary caller-controlled message text into public output.
    Only fixed enums and short synthetic case IDs are allowed.
    """
    import re

    enums = {
        "phase": frozenset(("boot", "connecting", "connected", "switching",
                            "error", "recovery", "revoked", "synthetic")),
        "result": frozenset(("PASS", "FAIL", "BLOCKED", "NOT_RUN")),
        "error_class": frozenset(("NONE", "ADMISSION", "ENVIRONMENT",
                                 "HARNESS", "ORACLE", "UNKNOWN")),
        "oracle": frozenset(("policy", "provider", "linux", "windows")),
    }
    safe = {}
    for key, choices in enums.items():
        value = fields.get(key)
        if isinstance(value, str) and value in choices:
            safe[key] = value
    case = fields.get("test_case")
    if isinstance(case, str) and re.fullmatch(r"T[0-9]{1,4}", case):
        safe["test_case"] = case
    return safe
