#!/usr/bin/env python3
import importlib.util
import pathlib
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    mod=importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


P3=load("p3",ROOT/"scripts"/"proxmox_p3_lxc_probe.py")
P5=load("p5",ROOT/"scripts"/"proxmox_p5_nested_kvm_probe.py")


class ProxmoxFutureProtocolTests(unittest.TestCase):
    def test_p3_reuses_generic_census_contract_and_pct_lifecycle(self):
        self.assertEqual(
            P3.CENSUS_SOURCE_COMMIT,
            "dd9da9961584680f331c338c50849dc93ab5f544",
        )
        for marker in (
            "===UNAME===",
            "===CPU===",
            "===MEMINFO===",
            "===CGROUP===",
            "===NETWORK===",
            "===DEVICES===",
        ):
            self.assertIn(marker,P3.LINUX_INNER)
        remote=P3.REMOTE
        for command in (
            '"pct", "create"',
            '"pct", "start"',
            '"pct", "exec"',
            '"pct", "stop"',
            '"pct", "destroy"',
            '"pveam", "available"',
            '"/cluster/nextid"',
        ):
            self.assertIn(command,remote)
        self.assertIn('"unprivileged", "1"',remote)
        self.assertIn('"nesting=0,keyctl=0"',remote)
        self.assertIn("config_absent",remote)

    def test_p5_boot_sector_is_bios_bootable_and_nonce_bearing(self):
        nonce="P5-NONCE-unit-test"
        image=P5.boot_sector(nonce)
        self.assertEqual(len(image),512)
        self.assertEqual(image[-2:],b"\x55\xaa")
        self.assertIn(nonce.encode(),image)
        self.assertEqual(image[:26].hex(),"31c08ed8fcbae900be1a7cac84c07403eeebf8baf400b02aeef4")

    def test_p5_requires_forced_kvm_and_executed_nonce(self):
        text=P5.REMOTE
        self.assertIn('"-accel","kvm"',text)
        self.assertIn('"-cpu","host"',text)
        self.assertIn('"isa-debugcon,iobase=0xe9,chardev=debug"',text)
        self.assertIn('"isa-debug-exit,iobase=0xf4,iosize=0x04"',text)
        self.assertIn("EXPECTED_DEBUG_EXIT_RC=85",text)
        self.assertIn("nonce not in cp.stdout",text)
        self.assertIn('pathlib.Path("/dev/kvm").exists()',text)


if __name__=="__main__":
    unittest.main()
