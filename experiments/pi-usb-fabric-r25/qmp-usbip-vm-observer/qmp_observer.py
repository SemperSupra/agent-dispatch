#!/usr/bin/env python3
"""Observe the real R22 USB/IP consumer-A QEMU via upstream qemu.qmp.

READ-ONLY: the VM's name, UUID and runstate are NOT an input-release ACK.
Neither this process nor its results can bind a Linux ConfigFS VUDC.
"""
import asyncio
from pathlib import Path
import sys
import time

from qemu.qmp import QMPClient


async def observe(path: str, expected_name: str, expected_uuid: str) -> int:
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        if not Path(path).is_socket():
            await asyncio.sleep(.12)
            continue
        client = QMPClient("r25-readonly-usbip-consumer-a")
        try:
            await client.connect(path)
        except (ConnectionError, OSError):
            await asyncio.sleep(.15)
            continue
        try:
            name = await client.execute("query-name")
            vm_uuid = await client.execute("query-uuid")
            status = await client.execute("query-status")
        finally:
            await client.disconnect()
        # All values are verified from a real QEMU process connected through
        # its local UNIX socket, not copied from USBIP guest serial text.
        observed_name = name.get("name") if isinstance(name, dict) else None
        observed_uuid = vm_uuid.get("UUID") if isinstance(vm_uuid, dict) else None
        state = status.get("status") if isinstance(status, dict) else None
        if observed_name != expected_name or observed_uuid != expected_uuid:
            print("R25_B_FOREIGN_VM_UUID_REJECTED=PASS", flush=True)
            print("R25_B_WRONG_QMP_VM_DOES_NOT_AUTHORIZE_USBIP=PASS", flush=True)
            return 42
        if state != "running":
            raise RuntimeError(f"actual QMP VM not running: {state!r}")
        print("R25_B_QMP_CONSUMER_A_VM_NAME_UUID_STATUS=PASS", flush=True)
        print("R25_B_QMP_VM_RUNSTATE=running", flush=True)
        print("R25_B_QMP_QUERY_ONLY_RELEASE_AUTHORITY=NOT_TESTED", flush=True)
        return 0
    raise RuntimeError("actual QMP consumer-A socket unavailable")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit("usage: observer.py QMP_UNIX_SOCKET EXPECTED_NAME EXPECTED_UUID")
    raise SystemExit(asyncio.run(observe(*sys.argv[1:])))
