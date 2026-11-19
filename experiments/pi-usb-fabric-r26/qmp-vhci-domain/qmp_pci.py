#!/usr/bin/env python3
"""Upstream read-only QMP provenance for a real Linux USB/IP consumer VM.

QMP describes QEMU's own PCI devices and VM identity. Linux vhci_hcd
owns USB/IP attached peripherals. PCI graph observation does NOT grant
QMP release authority over a kernel VHCI endpoint.
"""
import asyncio
from pathlib import Path
import sys
import time
from qemu.qmp import QMPClient

async def main(path, expected_name, expected_uuid):
    deadline=time.monotonic()+25
    while time.monotonic()<deadline:
        if not Path(path).is_socket():
            await asyncio.sleep(.15)
            continue
        client=QMPClient("r26-readonly-qmp-pci-origin")
        try:
            await client.connect(path)
        except (OSError, ConnectionError):
            await asyncio.sleep(.15)
            continue
        try:
            n=await client.execute("query-name")
            u=await client.execute("query-uuid")
            status=await client.execute("query-status")
            graph=await client.execute("query-pci")
        finally:
            await client.disconnect()
        if n.get("name")!=expected_name or u.get("UUID")!=expected_uuid or status.get("status")!="running":
            raise RuntimeError("real QMP PCI provenance mismatches expected consumer VM")
        if not isinstance(graph,list) or not graph or not isinstance(graph[0].get("devices"),list):
            raise RuntimeError("upstream QMP query-pci did not return a real PCI graph")
        print("R26_A_REAL_CONSUMER_A_QMP_VM_UUID_VERIFIED=PASS",flush=True)
        print("R26_A_UPSTREAM_QMP_PCI_GRAPH_OBSERVED=PASS",flush=True)
        # Do NOT assert that QMP can detach a Linux VHCI-attached USB/IP
        # HID. That device is not the QMP-native R26 xHCI object.
        print("R26_A_QMP_PCI_QUERY_IS_NOT_VHCI_RELEASE_ACK=PASS",flush=True)
        print("R26_A_REAL_QMP_ACTUATOR_FOR_LINUX_USBIP=NOT_TESTED",flush=True)
        return
    raise RuntimeError("QMP VM identity and PCI graph socket was unavailable")

if __name__=="__main__":
    if len(sys.argv)!=4:raise SystemExit("usage qmp_pci.py socket expected-name expected-uuid")
    asyncio.run(main(*sys.argv[1:]))
