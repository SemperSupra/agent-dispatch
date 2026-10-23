"""Adversarial fixed-fixture strace parser and receipt tests (public synthetic)."""
import importlib.util
from pathlib import Path
import unittest
import tempfile
from unittest import mock
import sys
import json

PATH = Path(__file__).resolve().parents[1] / "scripts" / "reversing_strace_fixture_probe.py"
S = importlib.util.spec_from_file_location("reversing_strace_fixture_probe", PATH)
T = importlib.util.module_from_spec(S)
S.loader.exec_module(T)

VALID = '\n'.join([
 'openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3',
 'close(3) = 0',
 'openat(AT_FDCWD, "trace-proof-output.bin", O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0600) = 3',
 'write(3, "trace-proof-v1\\n", 15) = 15',
 'close(3) = 0',
 'exit_group(0) = ?',
 '+++ exited with 0 +++',
])

class TraceTests(unittest.TestCase):
    def test_valid_trace(self):
        self.assertEqual(T.check_trace(VALID)["wrote_bytes"], 15)

    def fails(self, trace):
        with self.assertRaises(T.OracleError):
            T.check_trace(trace)

    def test_duplicate_open(self):
        l = 'openat(AT_FDCWD, "trace-proof-output.bin", O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0600) = 3'
        self.fails(VALID.replace(l, l + '\n' + l))

    def test_duplicate_write(self):
        l = 'write(3, "trace-proof-v1\\n", 15) = 15'
        self.fails(VALID.replace(l, l + '\n' + l))

    def test_wrong_fd(self):
        self.fails(VALID.replace('write(3,', 'write(4,'))

    def test_partial_write(self):
        self.fails(VALID.replace(' = 15', ' = 14'))

    def test_reordered_close(self):
        self.fails(VALID.replace('write(3, "trace-proof-v1\\n", 15) = 15\nclose(3) = 0', 'close(3) = 0\nwrite(3, "trace-proof-v1\\n", 15) = 15'))

    def test_mismatched_payload(self):
        self.fails(VALID.replace('trace-proof-v1\\n', 'trace-wrong-v1\\n'))

    def test_missing_close(self):
        self.fails(VALID.replace('write(3, "trace-proof-v1\\n", 15) = 15\nclose(3) = 0', 'write(3, "trace-proof-v1\\n", 15) = 15'))

    def test_failed_open(self):
        self.fails(VALID.replace('0600) = 3', '0600) = -1 EACCES'))

    def test_abnormal_exit(self):
        self.fails(VALID.replace('exit_group(0)', 'exit_group(41)'))

    def test_forged_partial_substring(self):
        self.fails(VALID.replace('+++ exited with 0 +++', 'fake message: +++ exited with 0 +++'))

    def test_unfinished_call(self):
        self.fails(VALID.replace('write(3,', 'write(3, <unfinished ...>'))

    def test_missing_final(self):
        self.fails(VALID.replace('+++ exited with 0 +++', ''))

    def test_duplicate_final(self):
        self.fails(VALID + '\n+++ exited with 0 +++')

    def test_prefixed_pid(self):
        s = '\n'.join('[pid  1234] ' + l for l in VALID.splitlines())
        self.assertEqual(T.check_trace(s)["opened_fd"], 3)

    def test_mixed_pid_evidence_rejected(self):
        lines = VALID.splitlines()
        lines[2] = '[pid  1234] ' + lines[2]
        lines[3] = '[pid  5678] ' + lines[3]
        self.fails('\n'.join(lines))

    def test_mixed_prefix_evidence_rejected(self):
        lines = VALID.splitlines()
        lines[2] = '[pid  1234] ' + lines[2]
        self.fails('\n'.join(lines))

    def test_extra_write_after_fixture_open_rejected(self):
        self.fails(VALID.replace('write(3, "trace-proof-v1\\n", 15) = 15',
                                 'write(9, "unexpected", 10) = 10\nwrite(3, "trace-proof-v1\\n", 15) = 15'))

    def test_extra_open_after_fixture_open_rejected(self):
        self.fails(VALID.replace('write(3, "trace-proof-v1\\n", 15) = 15',
                                 'openat(AT_FDCWD, "other.dat", O_RDONLY) = 9\nwrite(3, "trace-proof-v1\\n", 15) = 15'))

    def test_extra_completion_after_clean_exit_rejected(self):
        self.fails(VALID + '\n+++ killed by SIGSEGV +++')

    def test_receipt_existing_path_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'receipt.json'
            path.write_text('previous-receipt', encoding='utf-8')
            with mock.patch.object(T, 'execute', return_value={'status': 'PASS'}):
                with mock.patch.object(sys, 'argv', ['trace_probe.py', '--output', str(path)]):
                    with self.assertRaises(T.OracleError):
                        T.main()
            self.assertEqual(path.read_text(encoding='utf-8'), 'previous-receipt')

    def test_receipt_fresh_path_written_once(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'receipt.json'
            with mock.patch.object(T, 'execute', return_value={'status': 'PASS'}):
                with mock.patch.object(sys, 'argv', ['trace_probe.py', '--output', str(path)]):
                    T.main()
            self.assertEqual(json.loads(path.read_text(encoding='utf-8'))['status'], 'PASS')

    def test_oversized_trace(self):
        self.fails(VALID + '\n' * 520)

    def test_close_failure(self):
        self.fails(VALID.replace('write(3, "trace-proof-v1\\n", 15) = 15\nclose(3) = 0', 'write(3, "trace-proof-v1\\n", 15) = 15\nclose(3) = -1 EBADF'))

if __name__ == '__main__':
    unittest.main()
