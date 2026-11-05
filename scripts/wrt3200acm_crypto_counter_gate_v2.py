#!/usr/bin/env python3
"""Run the W8964 crypto counter consumer gate with a corrected raw-objdump matcher.

This is intentionally a narrow compatibility shim.  The broad frontier
workflow currently carries an over-escaped whitespace regex in
wrt3200acm_crypto_control_counter_consumers.py, which makes every exact
raw_has() assertion false.  Keep the historical script unchanged until this
targeted gate proves the correction; then fold the fix back deliberately.
"""
from __future__ import annotations

import importlib.util
import re
from pathlib import Path

BASE = Path(__file__).with_name("wrt3200acm_crypto_control_counter_consumers.py")
spec = importlib.util.spec_from_file_location("counter_consumers_base", BASE)
base = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(base)


def fixed_raw_ins_at(text: str, address: int):
    m = re.search(
        rf"^\s*0*{address:x}:\s+[0-9a-fA-F]{{8}}\s+"
        rf"([a-zA-Z][a-zA-Z0-9.]*)\s*(.*?)\s*$",
        text,
        re.M | re.I,
    )
    return (m.group(1).lower(), m.group(2).strip().lower()) if m else ("", "")


def self_test() -> None:
    sample = "  24008:\te5903008 \tldr\tr3, [r0, #8]"
    assert fixed_raw_ins_at(sample, 0x24008) == ("ldr", "r3, [r0, #8]")


base.raw_ins_at = fixed_raw_ins_at


if __name__ == "__main__":
    self_test()
    raise SystemExit(base.main())
