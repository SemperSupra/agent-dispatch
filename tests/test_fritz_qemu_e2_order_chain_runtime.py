import importlib.util
import pathlib
import unittest

SCRIPT = pathlib.Path(__file__).parents[1] / "scripts" / "fritz_qemu_e2_order_chain_runtime.py"
SPEC = importlib.util.spec_from_file_location("r6", SCRIPT)
r6 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(r6)


class R6Tests(unittest.TestCase):
    def paths(self, **counts):
        out = {}
        for key, value in counts.items():
            out[key] = {
                "path": "/" + key,
                "hitCount": 1,
                "firstSeenIndex": value[0],
                "syscalls": {"execve": value[1]} if value[1] else {},
            }
        return out

    def receipt(self, paths):
        return {
            "classification": "E2_R5_CTLMGR_UNIT_READ",
            "oracleSatisfied": True,
            "runtime": {
                "supervisorArguments": ["/lib/systemd/system", "prodtest-network.target"],
                "fixedPathTrace": {"paths": paths, "ctlmgrExecveCount": 0},
                "httpAttempts": [],
                "ctlmgrProcessObserved": False,
                "svctlStatusAttempted": True,
                "svctlStatusExitCode": 0,
                "controlSocketObserved": True,
            },
            "safety": {},
        }

    def test_classifies_avmipcd_exec_before_ctlmgr(self):
        p = self.paths(avmipcd_unit_relative=(1,0), avmipcd_exec=(2,1), ctlmgr_unit_relative=(3,0))
        self.assertEqual(r6.classify(self.receipt(p)), "E2_R6_AVMIPCD_EXEC_REACHED_CTLMGR_NOT_REACHED")

    def test_classifies_ctlmgr_exec(self):
        p = self.paths(ctlmgr_unit_relative=(1,0), ctlmgr_exec=(2,1))
        self.assertEqual(r6.classify(self.receipt(p)), "E2_R6_CTLMGR_EXEC_REACHED")

    def test_first_seen_order(self):
        p = self.paths(avmipcd_exec=(8,1), net_basic_exec=(4,1), ctlmgr_unit_relative=(9,0))
        seq = r6.observed_order(p)
        self.assertEqual([x["key"] for x in seq], ["net_basic_exec","avmipcd_exec","ctlmgr_unit_relative"])

    def test_trace_sanitizer_tracks_execve_and_order(self):
        raw = (
            '1 openat(AT_FDCWD,"net_basic.service",O_RDONLY) = 3\n'
            '1 execve("/etc/net_basic.sh",0x1,0x2) = 0\n'
            '1 openat(AT_FDCWD,"avmipcd.service",O_RDONLY) = 3\n'
            '1 execve("/bin/avmipcd",0x1,0x2) = -1 errno=2\n'
        )
        e = r6.r5.r4.r3.fixed_trace_evidence(raw)
        self.assertEqual(e["paths"]["net_basic_exec"]["syscalls"]["execve"],1)
        self.assertEqual(e["paths"]["avmipcd_exec"]["syscalls"]["execve"],1)
        self.assertLess(e["paths"]["net_basic_exec"]["firstSeenIndex"], e["paths"]["avmipcd_exec"]["firstSeenIndex"])


if __name__=="__main__":
    unittest.main()
