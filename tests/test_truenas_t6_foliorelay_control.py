#!/usr/bin/env python3
import importlib.util
import pathlib
import subprocess
import tempfile
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
SCRIPT = SCRIPTS / "truenas_middleware_foliorelay_t6_probe.py"
SPEC = importlib.util.spec_from_file_location("foliorelay_t6_probe", SCRIPT)
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MOD)

class FolioRelayT6ContractTests(unittest.TestCase):
    def test_exact_product_and_foundry_identity_is_pinned(self):
        self.assertEqual(MOD.EXPECTED_FOUNDRY_REF, "fb41afd3d112f361b8c490aeb5915a978b956b20")
        self.assertIn("@sha256:", MOD.EXPECTED_CONTROL)
        self.assertIn("@sha256:", MOD.EXPECTED_CUPS)
        self.assertEqual(MOD.DATASET, "rdtepool/foliorelay-t6")
        self.assertEqual(MOD.PUBLIC_URI, "ipp://foliorelay-t6.local:8634/printers/FolioRelay")

    def test_probe_preserves_product_oracles_and_zero_residue(self):
        text = SCRIPT.read_text(encoding="utf-8")
        for needle in (
            '"/api/v1/printer"', '"/api/v1/jobs"', 'application/pdf', 'image/urf',
            'ipptool', 'UNIRAST', '"pool.dataset.create"', '"pool.dataset.delete"',
            '"app.create"', '"app.stop"', '"app.start"', '"app.delete"',
            '"zero_residue":True', '_universal._sub._ipp._tcp.local',
            'dnssd_uuid_match', 'restart_preserved_identity_and_inbox',
            'app.update', 'app.redeploy', 'replan_action', '"NOOP"',
            'update_redeploy_preserved_identity_and_inbox',
        ):
            self.assertIn(needle, text)
        self.assertIn(MOD.OBSERVER_IMAGE, text)
        self.assertNotIn("avahi-publish-service", text)
        self.assertNotIn("/run/dbus", text)
        self.assertNotIn("/var/run/docker.sock", text)

    def test_observer_is_separate_host_network_app(self):
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('OBSERVER_APP_NAME = "rdte-t6-foliorelay-observer"', text)
        self.assertIn('"network_mode":"host"', text)
        self.assertIn('"entrypoint":["/observer/foliorelay-observer"]', text)
        self.assertIn('"user":"65534:65534"', text)
        self.assertEqual(
            MOD.OBSERVER_IMAGE,
            "docker.io/library/hello-world@sha256:5e23090353324d887c48ad5e5c56d294eab81588df9605b07d1afe895f9cc8f8",
        )
        self.assertNotIn("ghcr.io/truenas/apps_validation", MOD.OBSERVER_IMAGE)
        self.assertIn('"distinct_observer_context":True', text)

    def test_observer_lifecycle_is_independent_from_mdns_oracle_result(self):
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('result={"status":"pending"}', text)
        self.assertIn('threading.Thread(target=run_observer', text)
        self.assertIn('{"status":"success",**result}', text)
        self.assertIn('{"status":"error","error":', text)
        self.assertIn('p.add_argument("--seconds",type=float,default=25)', text)
        self.assertIn('DNS-SD observer oracle failed:', text)
        self.assertIn('DNS-SD observer oracle remained pending', text)


    def test_failed_observer_create_preserves_diagnostics_and_cleans_owned_state(self):
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("class JobFailure", text)
        self.assertIn('observer_created=True', text)
        self.assertLess(
            text.index('observer_created=True'),
            text.index('wait_job(oj,"observer app.create")'),
        )
        self.assertIn('payload["observer_create_failure"]', text)
        self.assertIn('p.add_argument("--observer-bin"', text)
        self.assertIn('OBSERVER_DIR+"/foliorelay-observer"', text)
        self.assertIn('observer_bytes,0o555', text)
        self.assertIn('"app.container_log_follow:"', text)
        self.assertIn('"tail_lines": tail_lines', text)
        self.assertIn('"container_log_tails"', text)
        self.assertIn('bounded_job_snapshot(observer_exc.job)', text)
        self.assertIn('"logs_excerpt"', text)
        self.assertIn('def query_optional(method,filters):', text)
        self.assertIn('observer_app=query_optional("app.query"', text)
        self.assertIn('before=query_optional("app.query"', text)
        self.assertIn('query_optional("app.query",[["id","=",name]]) is None', text)
        self.assertIn('before=query_optional("pool.dataset.query"', text)
        self.assertIn('query_optional("pool.dataset.query",[["id","=",DATASET]]) is None', text)
        self.assertIn('f"{name} cleanup delete"', text)
        self.assertIn('"zero_residue"', text)
        self.assertIn('payload["cleanup_needed"]', text)

        self.assertIn('call("core.download",["filesystem.get",["/var/log/app_lifecycle.log"]', text)
        self.assertIn('"app_lifecycle_excerpt"', text)
        self.assertIn('"app_lifecycle_capture_error"', text)

    def test_observer_lifecycle_excerpt_is_bounded_scoped_and_redacted(self):
        sample = "\n".join([
            "unrelated-before",
            "2026 app_lifecycle Failed 'up' action for 'rdte-t6-foliorelay-observer' app auth_token=secret-value",
            "compose detail: failed to start container",
            "compose detail: permission denied",
            "unrelated-after",
        ])
        excerpt = MOD.bounded_observer_lifecycle_excerpt(sample, before=0, after=2, limit=1000)
        self.assertIn("rdte-t6-foliorelay-observer", excerpt)
        self.assertIn("failed to start container", excerpt)
        self.assertIn("permission denied", excerpt)
        self.assertNotIn("unrelated-before", excerpt)
        self.assertNotIn("secret-value", excerpt)
        self.assertIn("auth_token=<redacted>", excerpt)

    def test_observer_lifecycle_excerpt_preserves_terminal_error_when_long_line_is_bounded(self):
        prefix = "pull progress " * 900
        terminal = "failed to register layer: write /var/lib/docker/overlay2: no space left on device"
        sample = (
            "2026 app_lifecycle Failed 'up' action for 'rdte-t6-foliorelay-observer' app "
            + prefix + terminal
        )
        excerpt = MOD.bounded_observer_lifecycle_excerpt(sample, before=0, after=0, limit=1200)
        self.assertLessEqual(len(excerpt), 1200)
        self.assertIn("rdte-t6-foliorelay-observer", excerpt)
        self.assertIn("...<truncated-middle>...", excerpt)
        self.assertIn(terminal, excerpt)

    def test_workflow_and_harness_route_exact_foliorelay_export(self):
        workflow=(ROOT/".github"/"workflows"/"gha-kvm-system-rdte.yml").read_text(encoding="utf-8")
        harness=(ROOT/"scripts"/"gha_kvm_truenas_rdte.sh").read_text(encoding="utf-8")
        self.assertIn("truenas_t6_product == 'foliorelay'", workflow)
        self.assertIn("export-foliorelay-t6-control.yml@" + MOD.EXPECTED_FOUNDRY_REF, workflow)
        self.assertIn("name: foliorelay-t6-beta3-control", workflow)
        self.assertIn('foundry_commit="' + MOD.EXPECTED_FOUNDRY_REF + '"', workflow)
        self.assertIn("truenas_middleware_foliorelay_t6_probe.py", harness)
        self.assertIn('FOLIORELAY_CONTROL_HOST_PORT', harness)
        self.assertIn('FOLIORELAY_IPP_HOST_PORT', harness)
        self.assertIn('FOLIORELAY_OBSERVER_HOST_PORT', harness)
        self.assertIn('--observer-port "$FOLIORELAY_OBSERVER_HOST_PORT"', harness)
        self.assertIn('--observer-bin "$FOLIORELAY_OBSERVER_BIN"', harness)
        self.assertIn('CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build', harness)
        self.assertIn('tools/foliorelay-observer', harness)

    def test_cups_uuid_oracle_preserves_canonical_urn_prefix(self):
        attrs = """
        printer-uuid (uri) = urn:uuid:01234567-89ab-4def-8123-456789abcdef
        printer-uri-supported (uri) = ipp://foliorelay-t6.local:8634/printers/FolioRelay
        """
        self.assertEqual(
            MOD.extract_printer_uuid(attrs),
            "urn:uuid:01234567-89ab-4def-8123-456789abcdef",
        )
        self.assertIsNone(MOD.extract_printer_uuid("printer-name = FolioRelay"))

    def test_forwarded_ipp_uri_preserves_product_resource_path_without_claiming_public_host(self):
        attrs = """
        printer-uri-supported (uri) = ipp://127.0.0.1:48634/printers/FolioRelay
        """
        uri = MOD.extract_printer_uri(attrs)
        self.assertEqual(uri, "ipp://127.0.0.1:48634/printers/FolioRelay")
        self.assertTrue(MOD.forwarded_ipp_uri_has_product_path(uri))
        self.assertFalse(MOD.forwarded_ipp_uri_has_product_path("ipp://127.0.0.1:48634/printers/Other"))

    def test_dnssd_observer_proves_public_host_port_and_resource_path(self):
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('"--expected-host",PUBLIC_HOST', text)
        self.assertIn('"--expected-ipp-port",str(PUBLIC_IPP_PORT)', text)
        self.assertIn('srv_target', text)
        self.assertIn('srv_port', text)
        self.assertIn('"rp=printers/FolioRelay"', text)
        self.assertIn('"dnssd_public_uri_match":True', text)
        self.assertNotIn('if PUBLIC_URI not in attrs', text)

    @unittest.skipUnless(pathlib.Path("/usr/include/cups/raster.h").is_file(), "CUPS development headers not installed")
    def test_synthetic_urf_generator_builds_and_emits_unirast(self):
        with tempfile.TemporaryDirectory() as td:
            out = MOD.generate_urf(pathlib.Path(td))
            self.assertTrue(out.is_file())
            self.assertEqual(out.read_bytes()[:7], b"UNIRAST")

    def test_probe_compiles(self):
        cp=subprocess.run([sys.executable,"-m","py_compile",str(SCRIPT)],capture_output=True,text=True)
        self.assertEqual(cp.returncode,0,cp.stderr)

if __name__ == "__main__":
    unittest.main()
