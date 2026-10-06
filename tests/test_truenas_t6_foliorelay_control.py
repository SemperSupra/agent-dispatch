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
            '"zero_residue":True',
            'dnssd_uuid_match', 'restart_preserved_identity_and_inbox',
            'app.update', 'app.redeploy', 'replan_action', '"NOOP"',
            'update_redeploy_preserved_identity_and_inbox',
            'second_plan_noop', 'retain_data_reinstall',
        ):
            self.assertIn(needle, text)
        observer = (ROOT/"tools"/"foliorelay-observer"/"main.go").read_text(encoding="utf-8")
        self.assertIn('_universal._sub._ipp._tcp.local', observer)
        self.assertIn(MOD.OBSERVER_IMAGE, text)
        self.assertNotIn("avahi-publish-service", text)
        self.assertIn('DBUS_SOCKET = "/run/dbus/system_bus_socket"', text)
        self.assertIn('25.x requires exactly one host D-Bus mount', text)
        self.assertIn('direct discovery target must not couple to host D-Bus', text)
        self.assertNotIn("/var/run/docker.sock", text)

    def test_discovery_materialization_is_exact_per_target(self):
        base={
            "control":{"volumes":[]},
            "cups":{"volumes":[]},
            "discovery":{
                "volumes":[],
                "command":["-identity-file","/var/lib/foliorelay-control/config/printer.json"],
            },
        }
        self.assertEqual(MOD.validate_discovery_materialization(base,"26.0.0-BETA.3"),"direct")

        avahi=json.loads(json.dumps(base))
        avahi["discovery"]["user"]="65534:10001"
        avahi["discovery"]["command"]=list(MOD.AVAHI_DISCOVERY_COMMAND)
        avahi["discovery"]["volumes"].append({
            "type":"bind",
            "source":MOD.DBUS_SOCKET,
            "target":MOD.DBUS_SOCKET,
            "read_only":True,
        })
        self.assertEqual(MOD.validate_discovery_materialization(avahi,"25.10.7"),"avahi")

        widened=json.loads(json.dumps(avahi))
        widened["control"]["volumes"].append({
            "type":"bind","source":"/run/dbus/other","target":"/run/dbus/other","read_only":True,
        })
        with self.assertRaisesRegex(RuntimeError,"exactly one host D-Bus mount"):
            MOD.validate_discovery_materialization(widened,"25.10.7")

        wrong_user=json.loads(json.dumps(avahi))
        wrong_user["discovery"]["user"]="10001:10001"
        with self.assertRaisesRegex(RuntimeError,"discovery user"):
            MOD.validate_discovery_materialization(wrong_user,"25.10.7")

        direct_dbus=json.loads(json.dumps(base))
        direct_dbus["discovery"]["volumes"].append({
            "type":"bind","source":MOD.DBUS_SOCKET,"target":MOD.DBUS_SOCKET,"read_only":True,
        })
        with self.assertRaisesRegex(RuntimeError,"must not couple to host D-Bus"):
            MOD.validate_discovery_materialization(direct_dbus,"26.0.0-BETA.3")

    def test_f4_reconciliation_policy_and_f5_retention_contract(self):
        exact={"services":{"control":{"image":"sha256:exact"}}}
        drift={"services":{"control":{"image":"sha256:drift"}}}
        self.assertEqual(MOD.reconciliation_action(None,None,exact),"CREATE")
        self.assertEqual(MOD.reconciliation_action("DEPLOYING",None,exact),"WAIT")
        self.assertEqual(MOD.reconciliation_action("STOPPING",None,exact),"WAIT")
        self.assertEqual(MOD.reconciliation_action("CRASHED",exact,exact),"FAIL_CLOSED")
        self.assertEqual(MOD.reconciliation_action("ERROR",exact,exact),"FAIL_CLOSED")
        self.assertEqual(MOD.reconciliation_action("RUNNING",exact,exact),"NOOP")
        self.assertEqual(MOD.reconciliation_action("STOPPED",exact,exact),"NOOP")
        self.assertEqual(MOD.reconciliation_action("RUNNING",drift,exact),"UPDATE")

        text = SCRIPT.read_text(encoding="utf-8")
        for needle in (
            'second_plan_action=reconciliation_action',
            'second-plan reconciliation was',
            '"inflight_policy":"WAIT"',
            '"ambiguous_policy":"FAIL_CLOSED"',
            '"retain_data_reinstall":True',
            '"RETAIN_EXTERNAL_DATASET_ON_APP_DELETE_THEN_EXPLICIT_FIXTURE_CLEANUP"',
            'external fixture dataset was not retained across App delete',
            'identity or Inbox drifted after retain-data reinstall',
            'retained artifact bytes drifted after reinstall',
            'post-reinstall reconciliation was',
        ):
            self.assertIn(needle, text)

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
        self.assertNotIn('ghcr.io/truenas/apps_validation@sha256:', text)
        self.assertIn('"distinct_observer_context":True', text)

    def test_observer_lifecycle_is_independent_from_mdns_oracle_result(self):
        text = SCRIPT.read_text(encoding="utf-8")
        observer = (ROOT/"tools"/"foliorelay-observer"/"main.go").read_text(encoding="utf-8")
        self.assertIn('"status": "pending"', observer)
        self.assertIn('r["status"] = "success"', observer)
        self.assertIn('"status": "error"', observer)
        self.assertIn('flag.Float64("seconds", 25', observer)
        self.assertIn('DNS-SD observer oracle failed:', text)
        self.assertIn('DNS-SD observer oracle remained pending', text)
        self.assertNotIn("OBSERVER = r'''", text)


    def test_product_crash_preserves_discovery_diagnostics_before_cleanup(self):
        text = SCRIPT.read_text(encoding="utf-8")
        for needle in (
            'def capture_product_runtime_failure(name,app):',
            'payload["product_runtime_failure"]',
            'bounded_app_snapshot(app)',
            'bounded_observer_lifecycle_excerpt(lifecycle,app_name=name)',
            'service_name!="discovery"',
            'container_state not in {"crashed","exited","restarting"}',
            'capture_container_log_tail(ws,name,str(container_id))',
            '"service_name":service_name',
            '"container_state":container_state',
        ):
            self.assertIn(needle, text)
        self.assertLess(
            text.index('capture_product_runtime_failure(name,x)'),
            text.index('raise RuntimeError(f"{name} entered {x.get(\'state\')}")'),
        )

    def test_failed_observer_create_preserves_diagnostics_and_cleans_owned_state(self):
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("class JobFailure", text)
        self.assertIn('observer_created=True', text)
        self.assertLess(
            text.index('observer_created=True'),
            text.index('wait_job(oj,"observer app.create")'),
        )
        self.assertIn('payload["observer_create_failure"]', text)
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
        self.assertIn("export-foliorelay-t6-control.yml@e4fbab1da4d08dbdf505ecd40c12acd2adba3ff2", workflow)
        self.assertIn("target_version: ${{ needs.changes.outputs.truenas_version }}", workflow)
        self.assertIn("name: foliorelay-t6-control", workflow)
        self.assertIn('foundry_commit="e4fbab1da4d08dbdf505ecd40c12acd2adba3ff2"', workflow)
        self.assertIn("truenas_middleware_foliorelay_t6_probe.py", harness)
        self.assertIn('FOLIORELAY_CONTROL_HOST_PORT', harness)
        self.assertIn('FOLIORELAY_IPP_HOST_PORT', harness)
        self.assertIn('FOLIORELAY_OBSERVER_HOST_PORT', harness)
        self.assertIn('--observer-port "$FOLIORELAY_OBSERVER_HOST_PORT"', harness)
        self.assertIn('--observer-binary "$FOLIORELAY_OBSERVER_BINARY"', harness)
        self.assertIn('--target-version "$VERSION"', harness)
        self.assertIn('--expected-system-version "$EXPECTED_SYSTEM_VERSION"', harness)
        self.assertIn('"$T6_PRODUCT" != "foliorelay"', harness)
        self.assertIn('CGO_ENABLED=0 GOOS=linux GOARCH=amd64', harness)
        self.assertIn('cd "$SCRIPT_DIR/.."', harness)
        self.assertIn('./tools/foliorelay-observer', harness)
        self.assertNotIn('"$SCRIPT_DIR/../tools/foliorelay-observer" ||', harness)
        self.assertIn('observer_size <= 6291456', harness)

    def test_probe_binds_runtime_target_and_foundry_identity_from_arguments(self):
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('control.get("foundry_ref") != foundry_ref', text)
        self.assertIn('candidate.get("truenas_version") != target_version', text)
        self.assertIn('call("system.version",[])!=a.expected_system_version', text)
        self.assertIn('p.add_argument("--target-version",required=True)', text)
        self.assertIn('p.add_argument("--expected-system-version",required=True)', text)
        self.assertNotIn('EXPECTED_FOUNDRY_REF =', text)
        self.assertNotIn('EXPECTED_VERSION =', text)

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

    def test_dnssd_txt_uuid_projection_strips_only_canonical_urn_prefix(self):
        canonical="urn:uuid:01234567-89ab-4def-8123-456789abcdef"
        self.assertEqual(MOD.dnssd_txt_uuid(canonical), "01234567-89ab-4def-8123-456789abcdef")
        with self.assertRaisesRegex(RuntimeError, "urn:uuid form"):
            MOD.dnssd_txt_uuid("01234567-89ab-4def-8123-456789abcdef")
        probe = SCRIPT.read_text(encoding="utf-8")
        observer = (ROOT/"tools"/"foliorelay-observer"/"main.go").read_text(encoding="utf-8")
        prep = (ROOT/".github"/"workflows"/"prep-foliorelay-t6-consumer.yml").read_text(encoding="utf-8")
        self.assertIn('"--txt-uuid",dnssd_txt_uuid(uuid)', probe)
        self.assertIn('flag.String("txt-uuid"', observer)
        self.assertIn('"UUID="+expectedTxtUUID', observer)
        self.assertIn('--txt-uuid 01234567-89ab-4def-8123-456789abcdef', prep)

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
        observer = (ROOT/"tools"/"foliorelay-observer"/"main.go").read_text(encoding="utf-8")
        self.assertIn('"--expected-host",PUBLIC_HOST', text)
        self.assertIn('"--expected-ipp-port",str(PUBLIC_IPP_PORT)', text)
        self.assertIn('"srv_target"', observer)
        self.assertIn('"srv_port"', observer)
        self.assertIn('rp=printers/foliorelay', observer.lower())
        self.assertIn('pdl=application/pdf,image/urf', observer.lower())
        self.assertIn('"dnssd_public_uri_match":True', text)
        self.assertIn('"service_instance"', observer)
        self.assertIn('"service_instance":observed.get("service_instance")', text)
        self.assertIn('matchObservation', observer)
        self.assertIn('o.txtByOwner[owner]', observer)
        self.assertIn('o.srvByOwner[owner]', observer)
        self.assertNotIn('if PUBLIC_URI not in attrs', text)

    @unittest.skipUnless(pathlib.Path("/usr/include/cups/raster.h").is_file(), "CUPS development headers not installed")
    def test_synthetic_urf_generator_builds_and_emits_unirast(self):
        with tempfile.TemporaryDirectory() as td:
            out = MOD.generate_urf(pathlib.Path(td))
            self.assertTrue(out.is_file())
            self.assertEqual(out.read_bytes()[:7], b"UNIRAST")

    def test_probe_cli_reaches_argparse_before_observer_validation(self):
        cp=subprocess.run([sys.executable,str(SCRIPT),"--help"],capture_output=True,text=True)
        self.assertEqual(cp.returncode,0,cp.stderr)
        self.assertIn("--observer-binary",cp.stdout)

    def test_observer_fixture_identity_is_receipted(self):
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('payload["observer_fixture"]', text)
        self.assertIn('"implementation":"go-static"', text)
        self.assertIn('"carrier_image":OBSERVER_IMAGE', text)
        self.assertIn('"binary_sha256":sha256_bytes(observer_bytes)', text)
        self.assertIn('"binary_size_bytes":len(observer_bytes)', text)
        self.assertIn('"run_as":"65534:65534"', text)

    def test_probe_compiles(self):
        cp=subprocess.run([sys.executable,"-m","py_compile",str(SCRIPT)],capture_output=True,text=True)
        self.assertEqual(cp.returncode,0,cp.stderr)

if __name__ == "__main__":
    unittest.main()
