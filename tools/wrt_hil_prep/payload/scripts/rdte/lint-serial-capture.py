#!/usr/bin/env python3
"""Source-only fail-closed lint for passive WRT serial capture helpers."""
import argparse
from pathlib import Path

ROOT=Path(__file__).resolve().parent

ap=argparse.ArgumentParser()
ap.add_argument("--shell", default=str(ROOT/"capture_wrt_serial_readonly.sh"))
ap.add_argument("--powershell", default=str(ROOT/"capture_wrt_serial_readonly.ps1"))
args=ap.parse_args()

shell_path=Path(args.shell)
ps_path=Path(args.powershell)
if not shell_path.is_file():
    raise SystemExit(f"serial shell helper not found: {shell_path}")
if not ps_path.is_file():
    raise SystemExit(f"serial PowerShell helper not found: {ps_path}")

shell=shell_path.read_text()
ps=ps_path.read_text()

required_shell=[
    'authority":"SENSOR_ONLY_NO_ACTUATION"',
    '"serial_payload_bytes_transmitted":0',
    'cat -- "$DEV" > "$TRANSCRIPT"',
    'stty -F "$DEV" 115200',
]
required_ps=[
    "authority = 'SENSOR_ONLY_NO_ACTUATION'",
    'serial_payload_bytes_transmitted = 0',
    '$serial.DtrEnable = $false',
    '$serial.RtsEnable = $false',
    '$serial.Read(',
]
for s in required_shell:
    assert s in shell, f"missing shell invariant: {s}"
for s in required_ps:
    assert s in ps, f"missing PowerShell invariant: {s}"

for forbidden in ('.Write(', '.WriteLine(', 'BaseStream.Write'):
    assert forbidden not in ps, f"PowerShell serial transmit primitive found: {forbidden}"
for forbidden in ('> "$DEV"', '>> "$DEV"', 'tee "$DEV"', 'tee -a "$DEV"'):
    assert forbidden not in shell, f"shell serial transmit pattern found: {forbidden}"

print(f"WRT passive serial capture lint PASS: shell={shell_path.name} powershell={ps_path.name}")
