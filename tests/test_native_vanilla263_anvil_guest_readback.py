"""Stubbed middleware admission and negative surface tests; NOT a live guest."""
from __future__ import annotations

import unittest

from scripts.qualify_native_vanilla263_anvil_guest_readback import capture, PATH, record_phase
from scripts.qualify_native_vanilla263_anvil_blocks import Refused
from scripts.qualify_vanilla263_native_world_rollback import APP
from tests.test_native_vanilla263_anvil_blocks import build


class NativeReadbackTests(unittest.TestCase):
    def setUp(self):
        self.blob = build("candidate")
        self.state = "STOPPED"
        self.stat = {"type": "FILE", "size": len(self.blob)}
        self.token = "/_download/synthetic-test-opaque"
        self.record = []
        self.downloaded = []

    def call(self, name, args):
        self.record.append((name, args))
        if name == "app.query":
            self.assertEqual(args, [[["id", "=", APP]]])
            return [{"name": APP, "state": self.state}]
        if name == "filesystem.stat":
            self.assertEqual(args, [PATH])
            return self.stat
        if name == "core.download":
            self.assertEqual(args, ["filesystem.get", [PATH],
                                    "g4-owned-region-candidate.mca", True])
            return [1001, self.token]
        self.fail("unexpected middleware RPC: " + name)

    def wait(self, job, label):
        self.downloaded.append((job, label))

    def fetch(self, token):
        self.assertEqual(token, self.token)
        return self.blob

    def capture_stage(self, stage="candidate"):
        return capture(call=self.call, wait_job=self.wait,
                       fetch_bytes=self.fetch, stage=stage)

    def reject(self, reason):
        with self.assertRaises(Refused) as cm:
            self.capture_stage()
        self.assertEqual(str(cm.exception), reason)

    def test_fixed_native_quiesced_read_only_path_and_nonclaim(self):
        result = self.capture_stage()
        self.assertEqual(result["classification"],
                         "SOURCE_ONLY_OWNED_ANVIL_DOWNLOAD_SEAM")
        self.assertEqual(result["downloaded_file_size"], len(self.blob))
        self.assertTrue(result["requested_native_world_file_fixed"])
        self.assertFalse(result["live_guest_identity_independently_verified"])
        self.assertFalse(result["backend_independent_world_oracle_pass"])
        self.assertFalse(result["raw_region_published"])
        self.assertEqual(result["physical_true_nas_apply"], "HOLD")
        self.assertEqual([name for name, _ in self.record],
                         ["app.query", "filesystem.stat", "core.download"])
        self.assertEqual(self.downloaded, [(1001, "G4 read-only owned Anvil file download")])

    def test_wrong_stage_has_zero_provider_calls(self):
        with self.assertRaisesRegex(Refused, "BACKEND_STAGE_NOT_ADMITTED"):
            self.capture_stage("other")
        self.assertEqual(self.record, [])

    def test_refuse_running_app_before_file_read(self):
        self.state = "RUNNING"
        self.reject("BACKEND_QUIESCENCE_NOT_OBSERVED")
        self.assertEqual([name for name, _ in self.record], ["app.query"])

    def test_refuse_missing_or_unsafe_file_stat(self):
        for attr in ({"type": "DIRECTORY", "size": len(self.blob)},
                     {"type": "FILE", "size": 0}, {"type": "FILE", "size": True},
                     None):
            with self.subTest(stat=attr):
                self.stat = attr
                self.reject("BACKEND_REGION_FILE_NOT_EXACT")

    def test_refuse_injected_redirect_or_query(self):
        for path in ("https://foreign.invalid/a", "/_download/../secrets",
                     "/_download/a?x=secret", "/_download/a#fragment", "/outside"):
            with self.subTest(path=path):
                self.token = path
                self.reject("BACKEND_DOWNLOAD_ROUTE_INVALID")

    def test_refuse_wrong_file_bytes(self):
        self.blob = self.blob[:-1]
        self.reject("BACKEND_DOWNLOADED_FILE_DRIFT")

    def test_refuse_wrong_effect_inside_download(self):
        self.blob = build("rollback")
        self.reject("SERVER_BLOCK_CONSEQUENCE_ABSENT")


    def test_phase_census_is_literal_and_contains_no_provider_values(self):
        seen = []
        got = capture(call=self.call, wait_job=self.wait, fetch_bytes=self.fetch,
                      stage="candidate", on_phase=seen.append)
        self.assertTrue(got["block_state_expectations_matched"])
        self.assertEqual(seen, [
            "candidate.app_state_query",
            "candidate.app_stopped_verified",
            "candidate.file_stat",
            "candidate.file_stat_verified",
            "candidate.download_request",
            "candidate.download_route_verified",
            "candidate.download_job",
            "candidate.download_job_completed",
            "candidate.bytes_fetch",
            "candidate.bytes_verified",
            "candidate.anvil_decode",
            "candidate.anvil_verified",
        ])
        self.assertNotIn("/mnt/", str(seen))
        self.assertNotIn("/_download/", str(seen))
        self.assertNotIn("credential", str(seen))

    def test_native_rpc_failure_identifies_operation_not_exception(self):
        for fail_method, last_phase in (
            ("app.query", "candidate.app_state_query"),
            ("filesystem.stat", "candidate.file_stat"),
            ("core.download", "candidate.download_request"),
        ):
            with self.subTest(fail_method=fail_method):
                previous = self.call
                phases = []
                def injected(method, args):
                    if method == fail_method:
                        raise RuntimeError("secret-password provider-path /mnt/private")
                    return previous(method, args)
                with self.assertRaises(RuntimeError):
                    capture(call=injected, wait_job=self.wait, fetch_bytes=self.fetch,
                            stage="candidate", on_phase=phases.append)
                self.assertEqual(phases[-1], last_phase)
                self.assertNotIn("secret-password", str(phases))
                self.assertNotIn("/mnt/private", str(phases))

    def test_download_job_and_http_failures_are_distinct(self):
        cases = (
            (lambda job, label: (_ for _ in ()).throw(
                RuntimeError("untrusted job exception")), self.fetch,
             "candidate.download_job"),
            (self.wait, lambda token: (_ for _ in ()).throw(
                RuntimeError("untrusted URL exception")), "candidate.bytes_fetch"),
        )
        for wait, fetch, wanted in cases:
            with self.subTest(wanted=wanted):
                phases = []
                with self.assertRaises(RuntimeError):
                    capture(call=self.call, wait_job=wait, fetch_bytes=fetch,
                            stage="candidate", on_phase=phases.append)
                self.assertEqual(phases[-1], wanted)
                self.assertNotIn("untrusted", str(phases))

    def test_unknown_phase_and_stage_not_emitted(self):
        phases = []
        with self.assertRaisesRegex(Refused, "BACKEND_PHASE_CODE_INVALID"):
            record_phase("candidate", "secret=PASSWORD", phases.append)
        with self.assertRaisesRegex(Refused, "BACKEND_PHASE_CODE_INVALID"):
            record_phase("foreign", "download_request", phases.append)
        self.assertEqual(phases, [])



if __name__ == "__main__":
    unittest.main()
