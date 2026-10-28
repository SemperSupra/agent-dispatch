#!/usr/bin/env python3
"""Independent structural interpretation of PUBLIC AUTHORED DEX via Androguard 4.1.4.

Not an Android runtime oracle. Retains bytecode as authority; returns only
bounded counts and named fixture controls. No target APK/source expected.
"""
from __future__ import annotations

from pathlib import Path

from androguard.core.dex import DEX


def inspect_dex(path: str | Path, mode: str, helper_mapping: str) -> dict:
    data = Path(path).read_bytes()
    if not data.startswith(b"dex\n"):
        raise ValueError("not_dex")
    dex = DEX(data)
    classes = {c.get_name(): c for c in dex.get_classes()}
    if "LProbe;" not in classes:
        raise AssertionError("source_known_entry_class_not_in_dex")
    codes = []
    probe_main = None
    for name, cls in classes.items():
        for method in cls.get_methods():
            code = method.get_code()
            if code is None:
                continue
            ops = [instruction.get_name() for instruction in method.get_instructions()]
            row = (name, method.get_name(), len(ops))
            codes.append(row)
            if name == "LProbe;" and method.get_name() == "main":
                probe_main = ops
    if not probe_main or not any(op.startswith("invoke-") for op in probe_main):
        raise AssertionError("entry_has_no_executable_invocations")

    original_helper = "LHelper;" in classes
    original_decoy = "LDecoy;" in classes
    if mode == "d8_only":
        if not original_helper or not original_decoy:
            raise AssertionError("original_fixture_classes_missing")
    if mode == "r8_rename":
        if helper_mapping in ("UNKNOWN", "REMOVED_OR_MERGED", "Helper"):
            raise AssertionError("rename_mapping_not_specific")
        if f"L{helper_mapping.replace('.', '/')};" not in classes:
            raise AssertionError("mapped_helper_descriptor_not_found_in_dex")
    return {
        "oracle_type": "DEX_STATIC_STRUCTURE_ONLY",
        "class_count": len(classes),
        "code_bearing_method_count": len(codes),
        "entry_invocation_opcode_count": sum(x.startswith("invoke-") for x in probe_main),
        "entry_instruction_count": len(probe_main),
        "original_helper_descriptor_present": original_helper,
        "original_decoy_descriptor_present": original_decoy,
        "mapped_helper_descriptor_present": (
            f"L{helper_mapping.replace('.', '/')};" in classes
            if helper_mapping not in ("UNKNOWN", "REMOVED_OR_MERGED") else None
        ),
        "dex_runtime_behavior": "NOT_RUN",
        "dex_exception_semantics": "NOT_INDEPENDENTLY_EXECUTED",
        "method_opcode_counts_independently_observed": len(codes),
        "class_identity_recovery_claim": "UNKNOWN_EXCEPT_MAPPING_OWNED_BY_EVALUATOR",
    }
