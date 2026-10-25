"""Second GDB replay red-team tests: correct temporal evidence and file custody."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import struct
import unittest

P = Path(__file__).resolve().parents[1] / "scripts/reversing_benchmark_native_replay.py"
SPEC = importlib.util.spec_from_file_location("replay_test", P)
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
ENTRY, TARGET, BASE = 0x401000, 0x401068, 0x400000

def elf_fixture(machine=62, etype=2, ident_version=1, object_version=1):
    """Header-only synthetic bytes for mocked GDB tests, never executed."""
    data = bytearray(64)
    data[:7] = bytes((127, 69, 76, 70, 2, 1, ident_version))
    struct.pack_into("<H", data, 16, etype)
    struct.pack_into("<H", data, 18, machine)
    struct.pack_into("<I", data, 20, object_version)
    return bytes(data) + b"PUBLIC_SYNTHETIC_FIXTURE"
HIT = "Breakpoint 2, 0x401068 in ?? ()"
EXIT = "[Inferior 1 (process 1122) exited normally]"

def output(n, tail):
    return (
        "Breakpoint 1 at 0x401000\n"
        "Breakpoint 2 at 0x401068\n"
        "Breakpoint 1, 0x401000 in ?? ()\n"
        "RVR_ENTRY_PC=0x401000\n"
        "RVR_BEFORE=7\n"
        "RVR_AFTER=%d\n" % n
    ) + tail + "\n"

class ReplayTests(unittest.TestCase):
    def test_positive_and_negative_native_classifications(self):
        self.assertEqual(M.parse_replay(output(0, HIT), ENTRY, TARGET, 0),
                         "NATIVE_PC_WITNESS")
        self.assertEqual(M.parse_replay(output(1, EXIT), ENTRY, TARGET, 1),
                         "NOT_OBSERVED_SAMPLE")

    def test_refuse_contradictory_hit_plus_exit(self):
        with self.assertRaises(M.ReplayError):
            M.parse_replay(output(0, HIT+"\n"+EXIT), ENTRY, TARGET, 0)

    def test_refuse_wrong_branch_target_hit(self):
        with self.assertRaises(M.ReplayError):
            M.parse_replay(output(0, "Breakpoint 2, 0x401069 in ?? ()"),
                           ENTRY, TARGET, 0)

    def test_refuse_forged_changed_register(self):
        with self.assertRaises(M.ReplayError):
            M.parse_replay(output(1, EXIT).replace("RVR_AFTER=1","RVR_AFTER=0"),
                           ENTRY, TARGET, 1)

    def test_refuse_out_of_order_target_or_exit(self):
        for end in (HIT, EXIT):
            with self.subTest(end=end):
                inp=output(0, end).replace("RVR_AFTER=0\n", "")
                inp=inp.replace("RVR_BEFORE=7\n", "RVR_BEFORE=7\n"+end+"\n")
                inp+="RVR_AFTER=0\n"
                with self.assertRaises(M.ReplayError):
                    M.parse_replay(inp, ENTRY, TARGET, 0)

    def test_refuse_missing_or_duplicate_markers(self):
        for bad in (output(0,HIT).replace("RVR_BEFORE=7\n",""),
                    output(0,HIT)+"RVR_AFTER=0\n",
                    output(0,HIT)+"Breakpoint 2, 0x401068 in ?? ()\n",
                    output(1,EXIT)+EXIT+"\n"):
            with self.assertRaises(M.ReplayError):
                M.parse_replay(bad, ENTRY, TARGET, 0)

    def test_refuse_signal_or_fake_exit_substring(self):
        for bad in (output(1,"Program received signal SIGSEGV, Segmentation fault.\n"+EXIT),
                    output(1,"Program says: exited normally"),
                    output(1,"[Inferior 1 (process 1122) exited with code 01]")):
            with self.assertRaises(M.ReplayError):
                M.parse_replay(bad, ENTRY, TARGET, 1)

    def test_exact_stripped_artifact_rehashed_and_two_fresh_gdb_calls(self):
        with tempfile.TemporaryDirectory() as d:
            f=Path(d)/"stripped"
            f.write_bytes(elf_fixture())
            digest=hashlib.sha256(f.read_bytes()).hexdigest()
            calls=[]
            def mocked(argv, timeout):
                calls.append((argv, timeout))
                self.assertEqual(argv[:4],
                                 ["gdb", "--batch", "--nx", "--quiet"])
                self.assertEqual(argv[4],str(f))
                n=0 if "set $rdi = 0" in argv else 1
                return output(n, HIT if n==0 else EXIT)
            got=M.replay_fixed_stripped(f, ENTRY, TARGET, BASE, digest, mocked)
            self.assertEqual([x["verdict"] for x in got["cases"]],
                             ["NATIVE_PC_WITNESS","NOT_OBSERVED_SAMPLE"])
            self.assertEqual([x["input_n"] for x in got["cases"]],[0,1])
            self.assertEqual(len(calls),2)
            self.assertTrue(all(x[1]==35 for x in calls))
            self.assertEqual(got["artifact_sha256"],digest)
            self.assertEqual(got["target_rva"],0x1068)
            self.assertEqual(got["independence"],
                             "FRESH_GDB_PROCESSES_SAME_HOST_SAME_INSTRUMENTATION")

    def test_swapped_file_rejected_before_running(self):
        with tempfile.TemporaryDirectory() as d:
            f=Path(d)/"stripped"
            f.write_bytes(elf_fixture())
            with self.assertRaises(M.ReplayError):
                M.replay_fixed_stripped(f, ENTRY, TARGET, BASE, "a"*64,
                                       lambda *a,**k: self.fail("must not execute"))

    def test_invalid_binary_magic_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            f=Path(d)/"stripped"
            f.write_bytes(b"MZ"+b"\x00"*30)
            with self.assertRaises(M.ReplayError):
                M.replay_fixed_stripped(f, ENTRY, TARGET, BASE,
                                       hashlib.sha256(f.read_bytes()).hexdigest(),
                                       lambda *a,**k: self.fail("must not execute"))

    def test_replay_file_tamper_between_runs_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            f=Path(d)/"stripped"
            f.write_bytes(elf_fixture())
            sha=hashlib.sha256(f.read_bytes()).hexdigest()
            def modify(argv,timeout):
                f.write_bytes(f.read_bytes()+b"MUTATED")
                return output(0,HIT)
            with self.assertRaises(M.ReplayError):
                M.replay_fixed_stripped(f,ENTRY,TARGET,BASE,sha,modify)

    def test_reject_wrong_elf_machine_before_gdb(self):
        for machine in (183, 243):  # AArch64, RISC-V
            with self.subTest(machine=machine), tempfile.TemporaryDirectory() as d:
                f = Path(d)/"stripped"
                f.write_bytes(elf_fixture(machine=machine))
                digest = hashlib.sha256(f.read_bytes()).hexdigest()
                with self.assertRaises(M.ReplayError):
                    M.replay_fixed_stripped(f, ENTRY, TARGET, BASE, digest,
                                            lambda *args, **kwargs: self.fail("must not invoke GDB"))

    def test_reject_wrong_elf_type_before_gdb(self):
        for etype in (1, 3):  # ET_REL, ET_DYN; fixed fixture is ET_EXEC
            with self.subTest(etype=etype), tempfile.TemporaryDirectory() as d:
                f = Path(d)/"stripped"
                f.write_bytes(elf_fixture(etype=etype))
                digest = hashlib.sha256(f.read_bytes()).hexdigest()
                with self.assertRaises(M.ReplayError):
                    M.replay_fixed_stripped(f, ENTRY, TARGET, BASE, digest,
                                            lambda *args, **kwargs: self.fail("must not invoke GDB"))

    def test_reject_wrong_elf_version_and_truncated_header(self):
        for content in (elf_fixture(ident_version=0), elf_fixture(object_version=0),
                        b"\\x7fELF\\x02\\x01"):
            with self.subTest(case=content[:10]), tempfile.TemporaryDirectory() as d:
                f = Path(d)/"stripped"
                f.write_bytes(content)
                digest = hashlib.sha256(f.read_bytes()).hexdigest()
                with self.assertRaises(M.ReplayError):
                    M.replay_fixed_stripped(f, ENTRY, TARGET, BASE, digest,
                                            lambda *args, **kwargs: self.fail("must not invoke GDB"))

if __name__=="__main__":
    unittest.main()
