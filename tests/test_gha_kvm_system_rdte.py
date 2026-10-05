import base64
import hashlib
import json
import socket
import struct
import sys
import tempfile
import threading
import pathlib
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
PVE = ROOT / "scripts" / "gha_kvm_proxmox_rdte.sh"
TRUENAS = ROOT / "scripts" / "gha_kvm_truenas_rdte.sh"
TRUENAS_RPC = ROOT / "scripts" / "truenas_installer_rpc_probe.py"
WORKFLOW = ROOT / ".github" / "workflows" / "gha-kvm-system-rdte.yml"
PREP_WORKFLOW = ROOT / ".github" / "workflows" / "prep-rdte-static.yml"
QEMU_TOPOLOGY = ROOT / "scripts" / "gha_qemu_t3_topology_probe.py"
TRUENAS_INSTALL = ROOT / "scripts" / "truenas_installer_rpc_install.py"
TRUENAS_MIDDLEWARE = ROOT / "scripts" / "truenas_middleware_ddp_probe.py"
TRUENAS_POOL = ROOT / "scripts" / "truenas_middleware_pool_probe.py"
TRUENAS_APP = ROOT / "scripts" / "truenas_middleware_app_probe.py"
TRUENAS_LIFECYCLE = ROOT / "scripts" / "truenas_middleware_app_lifecycle_probe.py"
FOLIORELAY_SESSION_EQUIV = ROOT / "config" / "truenas-session-foliorelay-single-equivalence.json"


class SystemRdteContractTests(unittest.TestCase):
    def test_shell_syntax(self):
        for path in (PVE, TRUENAS):
            cp = subprocess.run(["bash", "-n", str(path)], text=True, capture_output=True)
            self.assertEqual(cp.returncode, 0, f"{path}: {cp.stderr}")

    def test_common_evidence_contract(self):
        for path in (PVE, TRUENAS):
            text = path.read_text(encoding="utf-8")
            self.assertIn("gha-kvm-system-lab/v1", text)
            self.assertIn("oracleSatisfied", text)
            self.assertIn("classification", text)
            self.assertIn("passwordless sudo KVM boundary", text)
            self.assertIn("SKIPPED_GUARDRAIL", text)
            self.assertIn('rm -rf -- "$STATE_DIR"', text)

    def test_no_private_runner_or_secret_surface(self):
        forbidden = [
            "self-hosted",
            "garm-provider-truenas-private",
            "agent-dispatch-private.git",
            "ghp_",
            "github_pat_",
            "ACTIONS_RUNNER_INPUT_TOKEN",
        ]
        for path in (PVE, TRUENAS):
            text = path.read_text(encoding="utf-8")
            for needle in forbidden:
                self.assertNotIn(needle, text)

    def test_proxmox_is_pinned_and_uses_vendor_auto_install_contract(self):
        text = PVE.read_text(encoding="utf-8")
        self.assertIn("proxmox-ve_9.2-1.iso", text)
        self.assertIn(
            "4e88fe416df9b527624a175f24c9aa07c714d3332afb1ee3dbf3879573ef2c6c",
            text,
        )
        self.assertIn('mode = "iso"', text)
        self.assertIn('source = "from-dhcp"', text)
        self.assertIn('filesystem = "ext4"', text)
        self.assertIn('disk-list = ["sda"]', text)
        self.assertIn("/api2/json/version", text)
        self.assertIn('PVE_INSTALLER_SOURCE_VERSION="9.2.5"', text)
        self.assertIn('PVE_INSTALLER_SOURCE_COMMIT="32afcd4cd534d8e2f99ae76aa0234a0a5c697ba9"', text)
        self.assertIn("proxmox-first-boot_*.deb", text)
        self.assertIn("ISO_FIRST_BOOT_PACKAGE", text)
        self.assertNotIn("xdotool", text)

    def test_proxmox_first_boot_witness_uses_vendor_hook(self):
        text = PVE.read_text(encoding="utf-8")
        self.assertIn("[first-boot]", text)
        self.assertIn('source = "from-iso"', text)
        self.assertIn('ordering = "network-online"', text)
        self.assertNotIn('ordering = "fully-up"', text)
        self.assertIn("/proxmox-first-boot", text)
        self.assertIn("proxmox-first-boot.iso", text)
        self.assertIn("PVE_INITIAL_SERVICES_BEGIN", text)
        self.assertIn("PVE_FINAL_SERVICES_BEGIN", text)
        self.assertIn("PVEPROXY_JOURNAL_BEGIN", text)
        self.assertIn("PVE_RDTE_WITNESS_BEGIN", text)
        self.assertIn("PVE_RDTE_WITNESS_END", text)
        self.assertIn("rdte-first-boot.log", text)
        self.assertIn("TTY_S0=character-device", text)
        self.assertIn("first_boot_witness_observed", text)
        self.assertIn("guest_local_https_api", text)
        self.assertIn("socket.create_connection((host, port), timeout=5)", text)
        self.assertIn("ssl.create_default_context()", text)
        self.assertIn('"probe_error": "http_status"', text)
        self.assertIn('all(data.get(k) for k in ("version", "release", "repoid"))', text)
        self.assertIn("/api2/json/access/ticket", text)
        self.assertIn("urllib.parse.urlencode", text)
        self.assertIn("PVEAuthCookie={ticket}", text)
        self.assertIn('password = os.environ["PVE_RDTE_PASSWORD"]', text)
        self.assertIn('"stage": stage', text)
        self.assertNotIn("print(json.dumps(ticket_payload", text)
        self.assertNotIn("CSRFPreventionToken:", text)
        self.assertNotIn("openssl s_client", text)
        self.assertIn('request = [f"{method} {path} HTTP/1.0"]', text)
        self.assertIn(r'wire = ("\r\n".join(request) + "\r\n\r\n")', text)
        self.assertNotIn(r'wire = ("\\r\\n".join(request)', text)
        self.assertNotIn("for _ in $(seq 1 120); do\n  if [[ \"$SSH_HOSTFWD_ACCEPTED\" == \"true\" ]]; then", text)
        self.assertIn('API_OBSERVATION_ROUTE="ssh-observed-guest-local-https"', text)
        self.assertIn('"api_observation_route"', text)
        self.assertIn('"guest_local_https_api"', text)
        self.assertIn('"pve_manager_source_commit": "b9984c6d90a4bd80"', text)
        self.assertIn('"pve_access_control_source_commit": "5ccd07d9302562b73374d331b63d25b04b86766c"', text)
        self.assertIn('ROOT_PASSWORD="rdte-proxmox-', text)
        self.assertIn('root-password = "$ROOT_PASSWORD"', text)
        self.assertIn('timezone = "UTC"', text)
        self.assertNotIn('timezone = "Etc/UTC"', text)
        self.assertIn('cat >"$STATE_DIR/answer.toml" <<EOF', text)
        self.assertNotIn(r"\nROOT_PASSWORD", text)
        self.assertNotIn("rdte-proxmox-ephemeral-", text)
        self.assertIn("grep -Fq 'Installation done.'", text)
        self.assertIn("exact post-run_installation success witness", text)
        self.assertIn('payload.get("root_lv") == "/dev/pve/root"', text)
        self.assertIn('"installed_disk_layout"', text)
        self.assertNotIn("installation finished|powering off|rebooting", text)
        self.assertIn("qemu-img convert -f qcow2 -O raw -S 4k", text)
        self.assertIn("losetup --find --show --read-only --partscan", text)
        self.assertNotIn("qemu-nbd --connect", text)

    def test_proxmox_rest_container_c0_is_opt_in_and_api_native(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        script = PVE.read_text(encoding="utf-8")
        self.assertIn("proxmox_compute_fixture", workflow)
        self.assertIn('(.compute_fixture // "none") | select(. == "none" or . == "container-c0")', workflow)
        self.assertIn('--compute-fixture "${{ needs.changes.outputs.proxmox_compute_fixture }}"', workflow)
        self.assertIn("probe_rest_lxc_c0()", script)
        rest = script.split("probe_rest_lxc_c0()", 1)[1].split("probe_lxc_lifecycle()", 1)[0]
        self.assertIn("proxmox_rest_compute_probe.py", rest)
        self.assertIn("--kind container", rest)
        self.assertIn("--apply --out", rest)
        self.assertNotIn("pct create", rest)
        self.assertIn('"transport":"bounded SSH staging only; all container lifecycle mutation uses PVE REST"', rest)
        self.assertIn('"rest_api_container_c0_exercised"', script)
        self.assertIn("superseded-by-rest-c0", script)
        self.assertIn("not-required-for-container-c0", script)
        c0_tail = script.split('if [[ "$COMPUTE_FIXTURE" == "container-c0" ]]; then', 2)[2]
        self.assertIn('NESTED_KVM_INDICATORS="skipped"', c0_tail)

    def test_proxmox_rest_api_census_is_read_only_and_retained(self):
        text = PVE.read_text(encoding="utf-8")
        self.assertIn("proxmox_rest_compute_probe.py", text)
        self.assertIn("--kind vm --observe-only", text)
        self.assertIn('"rest_api_census_observed"', text)
        self.assertIn('"rest_api_census": rest_api_census', text)
        self.assertIn("REST API census is read-only discovery evidence only", text)
        census = text.index("# Read-only native REST census: capture exact installed PVE/package identity only")
        self.assertLess(text.index('WEB_PORT="$(python3 - <<\'PY\''), census)
        self.assertLess(text.index("installed Proxmox HTTPS API did not answer"), census)
        self.assertEqual(text.count('--kind vm --observe-only'), 1)

    def test_proxmox_hostfwd_is_diagnostic_not_guest_or_nested_oracle(self):
        text = PVE.read_text(encoding="utf-8")
        self.assertNotIn('NESTED_KVM="no"', text)
        self.assertIn('"ssh_hostfwd_accepted"', text)
        self.assertIn('"api_hostfwd_accepted"', text)
        self.assertIn("first_boot_witness_observed", text)
        self.assertIn("inspect_installed_disk", text)
        self.assertIn("qemu-nbd", text)
        self.assertIn("first_boot_package_version", text)
        self.assertIn("hook_matches_prepared_iso", text)
        self.assertIn("INSTALLED_DISK_PREBOOT", text)
        self.assertIn("INSTALLED_DISK_POSTBOOT", text)


    def test_proxmox_p5_requires_actual_nested_vcpu_execution(self):
        text = PVE.read_text(encoding="utf-8")
        self.assertIn("probe_nested_kvm_vcpu", text)
        self.assertIn("root@127.0.0.1 'bash -s'", text)
        self.assertNotIn("root@127.0.0.1 'sh -s'", text)
        self.assertIn("-accel kvm", text)
        self.assertIn("-cpu host", text)
        self.assertIn("isa-debug-exit,iobase=0xf4,iosize=0x4", text)
        self.assertIn('bytes.fromhex("fab02abaf400eef4ebfd")', text)
        self.assertIn('"expected_debug_value": 42', text)
        self.assertIn('"expected_exit_code": expected_exit', text)
        self.assertIn("rc == expected_exit", text)
        self.assertIn("pkg == expected_pkg", text)
        self.assertIn('"nested_kvm_vcpu_executed"', text)
        self.assertIn('"p5_nested_kvm"', text)
        self.assertIn('"nested_kvm_indicators_via_ssh"', text)
        self.assertIn('"pve_qemu_source_commit": "684796e835289dab11af8606fbf7358b93526dd6"', text)
        self.assertIn('"pve_qemu_submodule_commit": "98b060da3a4f92b2a994ead5b16a87e783baf77c"', text)
        self.assertIn('"exit_code_rule": "(value << 1) | 1"', text)
        self.assertNotIn('NESTED_KVM="no"', text)


    def test_proxmox_p3_uses_exact_public_template_and_supported_pct_lifecycle(self):
        text = PVE.read_text(encoding="utf-8")
        self.assertIn('P3_TEMPLATE_NAME="debian-13-standard_13.1-2_amd64.tar.zst"', text)
        self.assertIn('P3_TEMPLATE_SHA512="5aec4ab2ac5c16c7c8ecb87bfeeb10213abe96db6b85e2463585cea492fc861d7c390b3f9c95629bf690b95e9dfe1037207fc69c0912429605f208d5cb2621f8"', text)
        self.assertIn('P3_TEMPLATE_URL="http://download.proxmox.com/images/system/$P3_TEMPLATE_NAME"', text)
        self.assertNotIn('P3_TEMPLATE_URL="https://download.proxmox.com/images/system/', text)
        self.assertIn('P3_PVE_CONTAINER_SOURCE_COMMIT="5eb5574ee9158ac40a5230de2cf18d7d6345709f"', text)
        self.assertIn("probe_lxc_lifecycle", text)
        self.assertIn('pct create "$VMID"', text)
        self.assertIn('pct start "$VMID"', text)
        self.assertIn('pct exec "$VMID"', text)
        self.assertIn('pct stop "$VMID"', text)
        self.assertIn('pct destroy "$VMID" --purge 1', text)
        self.assertIn("--unprivileged 1", text)
        self.assertIn("--rootfs local-lvm:2", text)
        self.assertIn('"p3_lxc_lifecycle_exercised"', text)
        self.assertIn('"p3_lxc": p3_lxc', text)
        self.assertIn('"zero_residue":cleanup', text)
        self.assertIn('if [[ "$NESTED_KVM" == "yes" ]]; then', text)
        self.assertNotIn("nsenter", text)

    def test_truenas_uses_exact_target_registry_and_vendor_digest_sidecar(self):
        text = TRUENAS.read_text(encoding="utf-8")
        self.assertIn('TARGET_REGISTRY="$SCRIPT_DIR/../config/truenas-rdte-targets.json"', text)
        self.assertIn('TARGET_VERSION="26.0.0-BETA.3"', text)
        self.assertIn("--target-version", text)
        self.assertIn("truenas_rdte_target.py", text)
        self.assertIn('curl --fail --location --retry 3 --silent --show-error "$SHA_URL"', text)
        self.assertIn('[[ "$OBSERVED_ISO_SHA" == "$EXPECTED_ISO_SHA" ]]', text)
        self.assertIn("RAM_MIB=8192", text)
        self.assertIn("installer-boot", text)
        self.assertIn("installer-rpc", text)
        self.assertIn("truenas_installer_rpc_probe.py", text)
        self.assertIn('INSTALLER_RPC_PATH', text)
        self.assertIn('INSTALLER_RPC_GUEST_PORT', text)
        self.assertIn('INSTALLER_SOURCE_REF', text)
        self.assertIn('INSTALLER_MAIN_BLOB_SHA', text)
        self.assertIn('--path "$INSTALLER_RPC_PATH"', text)
        self.assertIn('hostfwd=tcp:127.0.0.1:$RPC_PORT-:$INSTALLER_RPC_GUEST_PORT', text)
        self.assertNotIn('hostfwd=tcp:127.0.0.1:$RPC_PORT-:8080', text)
        self.assertNotIn("xdotool", text)

    def test_g3_g4_and_g5_nested_guest_meet_fixed_four_cpu_runner_profile(self):
        text = TRUENAS.read_text(encoding="utf-8")
        self.assertIn('VCPUS=2', text)
        self.assertIn(
            'if [[ "$RUNG" == "t6" && ( "$T6_PRODUCT" == "garm-provider-g3" || "$T6_PRODUCT" == "garm-provider-g4" || "$T6_PRODUCT" == "garm-provider-g5" ) ]]; then',
            text,
        )
        self.assertIn('VCPUS=4', text)
        self.assertIn('HOST_CPUS="$(nproc)"', text)
        self.assertIn('(( HOST_CPUS >= VCPUS ))', text)
        self.assertIn('R_VCPUS="$VCPUS"', text)
        self.assertIn('"vcpus": int(os.environ["R_VCPUS"])', text)
        self.assertIn('"ram_mib": int(os.environ["R_RAM_MIB"])', text)
        self.assertIn('"garm-provider-g4-pair"', text)
        self.assertIn('"garm-provider-g5-version-row"', text)
        self.assertIn('"count": 2', text)

    def test_g4_routing_is_source_exact_and_public_safe(self):
        workflow = (ROOT / ".github" / "workflows" / "gha-kvm-system-rdte.yml").read_text(
            encoding="utf-8"
        )
        text = TRUENAS.read_text(encoding="utf-8")
        self.assertIn("garm-provider-g4", workflow)
        self.assertIn(
            "export-g4-nested-fixture.yml@e5fc7c50780de54f7579f64990c87b2e16482613",
            workflow,
        )
        self.assertIn(
            '--g4-fixture-producer "e5fc7c50780de54f7579f64990c87b2e16482613"',
            workflow,
        )
        self.assertIn("truenas_middleware_garm_provider_g4_probe.py", text)
        self.assertIn('G4_FIXTURE_PRODUCER', text)
        self.assertNotIn("GITHUB_TOKEN", (ROOT / "scripts" / "truenas_middleware_garm_provider_g4_probe.py").read_text(encoding="utf-8"))

    def test_g5_routing_is_source_exact_cross_version_and_public_safe(self):
        workflow = (ROOT / ".github" / "workflows" / "gha-kvm-system-rdte.yml").read_text(
            encoding="utf-8"
        )
        text = TRUENAS.read_text(encoding="utf-8")
        self.assertIn("garm-provider-g5", workflow)
        self.assertIn(
            "export-g5-version-matrix.yml@f83a712e095c6962741f93cf86bea69479ce4d4a",
            workflow,
        )
        self.assertIn(
            "export-g3-nested-fixture.yml@e92d4024e6e60c0e2f8bcf5301c11fccb14eaaab",
            workflow,
        )
        self.assertIn(
            '--g5-matrix-producer "f83a712e095c6962741f93cf86bea69479ce4d4a"',
            workflow,
        )
        self.assertIn(
            '--g3-fixture-producer "e92d4024e6e60c0e2f8bcf5301c11fccb14eaaab"',
            workflow,
        )
        self.assertIn("truenas_middleware_garm_provider_g5_probe.py", text)
        self.assertIn('G5_MATRIX_PRODUCER', text)
        self.assertIn(
            'if [[ "$T6_PRODUCT" != "official-catalog" && "$T6_PRODUCT" != "garm-provider-g5" && "$T6_PRODUCT" != "foliorelay" ]]; then',
            text,
        )
        g5_probe = (ROOT / "scripts" / "truenas_middleware_garm_provider_g5_probe.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("GITHUB_TOKEN", g5_probe)
        self.assertNotIn("GH_TOKEN", g5_probe)

    def test_no_literal_escaped_shell_parameter_expansions(self):
        needle = chr(92) + "$" + "{"
        for path in (PVE, TRUENAS):
            self.assertNotIn(needle, path.read_text(encoding="utf-8"))


    def test_truenas_rpc_probe_is_dependency_free_and_read_only(self):
        text = TRUENAS_RPC.read_text(encoding="utf-8")
        for method in ("is_adopted", "system_info", "list_disks", "list_network_interfaces"):
            self.assertIn(method, text)
        self.assertNotIn('"install"', text)
        self.assertIn('p.add_argument("--path", default="/ws")', text)
        self.assertNotIn("pip install", text)
        cp = subprocess.run(
            ["python3", "-m", "py_compile", str(TRUENAS_RPC)],
            text=True,
            capture_output=True,
        )
        self.assertEqual(cp.returncode, 0, cp.stderr)

    def test_proxmox_request_uses_exact_target_registry(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        prep = (ROOT / ".github" / "workflows" / "prep-rdte-static.yml").read_text(encoding="utf-8")
        self.assertIn("config/proxmox-rdte-targets.json", workflow)
        self.assertIn("scripts/proxmox_rdte_target.py", workflow)
        self.assertIn("--require-runtime-admitted", workflow)
        self.assertIn("'config/proxmox-rdte-targets.json'", prep)
        self.assertIn("'scripts/proxmox_rdte_target.py'", prep)
        self.assertIn("'tests/test_proxmox_rdte_target.py'", prep)

    def test_prep_static_gate_watches_proxmox_request_edge(self):
        prep = (ROOT / ".github" / "workflows" / "prep-rdte-static.yml").read_text(encoding="utf-8")
        self.assertIn("'config/proxmox-rdte-run-request.json'", prep)

    def test_workflow_scopes_heavy_targets(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("fetch-depth: 0", text)
        self.assertIn("needs.changes.outputs.proxmox", text)
        self.assertIn("needs.changes.outputs.truenas", text)
        self.assertIn("DISPATCH_TARGET", text)
        self.assertIn("BEFORE_SHA:", text)
        self.assertIn('git diff --name-only "$BEFORE_SHA" "$AFTER_SHA"', text)
        self.assertIn("truenas_version:", text)
        self.assertIn("truenas_rung:", text)
        self.assertIn("needs.changes.outputs.truenas_version", text)
        self.assertIn("needs.changes.outputs.truenas_rung", text)
        self.assertIn("config/truenas-rdte-run-request.json", text)
        self.assertIn("config/proxmox-rdte-run-request.json", text)
        self.assertIn("gha-kvm-proxmox-run-request/v1", text)
        self.assertIn("refusing stale Proxmox request replay", text)
        self.assertIn(
            'if [[ "$EVENT_NAME" != "workflow_dispatch" && "$truenas" == "true" ]]; then',
            text,
        )
        self.assertIn("gha-kvm-truenas-run-request/v1", text)
        self.assertIn("current_request_id=", text)
        self.assertIn("previous_request_id=", text)
        self.assertIn("refusing stale TrueNAS request replay", text)
        self.assertIn('git show "$BEFORE_SHA:$RUN_REQUEST_PATH"', text)
        self.assertIn("truenas_version=\"$(jq -er", text)
        self.assertIn(".version | select(type == \"string\" and length > 0)", text)
        self.assertIn("truenas_rung=\"$(jq -er", text)
        self.assertIn('.rung | select(. == "t0" or . == "t1"', text)

        routing = text.split("while IFS= read -r path; do", 1)[1].split(
            "done < <(git diff --name-only", 1
        )[0]
        self.assertIn("config/truenas-rdte-run-request.json)", routing)
        self.assertIn("config/proxmox-rdte-run-request.json)", routing)
        self.assertNotIn("scripts/gha_kvm_proxmox_rdte.sh)", routing)
        for stale_replay_source in (
            "scripts/gha_kvm_truenas_rdte.sh",
            "scripts/truenas_installer_rpc_probe.py",
            "scripts/truenas_middleware_foliorelay_t6_probe.py",
            "config/truenas-rdte-targets.json",
        ):
            self.assertNotIn(stale_replay_source, routing)

    def test_prep_gate_avoids_duplicate_branch_and_pr_runs_and_scopes_expensive_smokes(self):
        text = PREP_WORKFLOW.read_text(encoding="utf-8")
        trigger = text.split("permissions:", 1)[0]
        self.assertIn("pull_request:", trigger)
        self.assertIn("workflow_dispatch:", trigger)
        self.assertNotIn("\n  push:", trigger)
        self.assertIn("id: expensive_scope", text)
        self.assertIn("provider_smoke=false", text)
        self.assertIn("provider_smoke=true", text)
        self.assertIn(
            "steps.expensive_scope.outputs.provider_smoke == 'true'",
            text,
        )
        self.assertIn("fetch-depth: 0", text)

    def test_only_heavy_jobs_share_non_cancelling_concurrency_group(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        header = text.split("jobs:", 1)[0]
        self.assertNotIn("concurrency:", header)
        for job in ("proxmox-9-2", "truenas-26-beta3"):
            expected = (
                f"  {job}:\n"
                "    concurrency:\n"
                "      group: gha-kvm-system-rdte-heavy\n"
                "      cancel-in-progress: false\n"
            )
            self.assertIn(expected, text)
        self.assertEqual(text.count("group: gha-kvm-system-rdte-heavy"), 2)
        self.assertEqual(text.count("cancel-in-progress: false"), 2)
        self.assertNotIn("cancel-in-progress: true", text)

    def test_single_capsule_session_mode_is_opt_in_and_selector_bound(self):
        text = TRUENAS.read_text(encoding="utf-8")
        self.assertIn('--session-manifest', text)
        self.assertIn('SESSION_MANIFEST=""', text)
        self.assertIn("truenas_single_capsule_adapter.py", text)
        self.assertIn('SESSION_SELECTOR', text)
        self.assertIn('does not match --t6-product', text)
        self.assertIn('truenas_session_runner.py', text)
        self.assertIn('truenas_existing_probe_capsule_executor.py', text)
        self.assertIn('"session_execution":', text)
        self.assertIn('SESSION_CAPSULE_VERDICT=', text)
        self.assertIn('fail_evidence "$SESSION_CAPSULE_VERDICT"', text)
        self.assertIn('SESSION_OK=', text)
        self.assertIn('session.get("classification")=="SESSION_CLEAN"', text)
        self.assertIn('caps[0].get("verdict")=="SUPPORTED"', text)
        self.assertIn('provider.get("classification")!="SUPPORTED"', text)
        self.assertIn('provider.get("oracleSatisfied") is not True', text)

    def test_foliorelay_single_capsule_equivalence_manifest_is_exact_and_valid(self):
        doc = json.loads(FOLIORELAY_SESSION_EQUIV.read_text(encoding="utf-8"))
        self.assertEqual(doc["version"], "26.0.0-BETA.3")
        self.assertEqual(len(doc["capsules"]), 1)
        cap = doc["capsules"][0]
        self.assertEqual(cap["provider"], "foliorelay-t6")
        self.assertEqual(cap["authority"], {"repository":"SemperSupra/folio-relay","issue":29})
        self.assertEqual(cap["exact"]["foundry_ref"], "fb41afd3d112f361b8c490aeb5915a978b956b20")
        self.assertEqual(cap["exact"]["product_head"], "88fd70c8891eaf7b4c886aa928b96e232ca041c6")
        self.assertIn("@sha256:", cap["exact"]["control_image"])
        self.assertIn("@sha256:", cap["exact"]["cups_image"])
        cp = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "truenas_session_manifest.py"),
                "--manifest", str(FOLIORELAY_SESSION_EQUIV),
                "--targets", str(ROOT / "config" / "truenas-rdte-targets.json"),
                "--providers", str(ROOT / "config" / "truenas-capsule-providers.json"),
            ],
            text=True,
            capture_output=True,
        )
        self.assertEqual(cp.returncode, 0, cp.stderr)

    def test_truenas_t1_requires_local_rpc_probe(self):
        text = TRUENAS.read_text(encoding="utf-8")
        self.assertIn("missing TrueNAS installer RPC probe", text)

    def test_truenas_rpc_probe_protocol_round_trip(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        errors = []
        request_lines = []

        def read_exact(conn, count):
            parts = []
            remaining = count
            while remaining:
                part = conn.recv(remaining)
                if not part:
                    raise EOFError("synthetic websocket peer closed")
                parts.append(part)
                remaining -= len(part)
            return b"".join(parts)

        def recv_json(conn):
            b1, b2 = read_exact(conn, 2)
            opcode = b1 & 0x0F
            if opcode == 0x8:
                return None
            if opcode != 0x1:
                raise AssertionError(f"unexpected client opcode {opcode}")
            masked = bool(b2 & 0x80)
            if not masked:
                raise AssertionError("client websocket frame must be masked")
            size = b2 & 0x7F
            if size == 126:
                size = struct.unpack("!H", read_exact(conn, 2))[0]
            elif size == 127:
                size = struct.unpack("!Q", read_exact(conn, 8))[0]
            mask = read_exact(conn, 4)
            payload = read_exact(conn, size)
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
            return json.loads(payload.decode())

        def send_json(conn, value):
            payload = json.dumps(value, separators=(",", ":")).encode()
            if len(payload) < 126:
                header = bytes([0x81, len(payload)])
            else:
                header = bytes([0x81, 126]) + struct.pack("!H", len(payload))
            conn.sendall(header + payload)

        def server():
            try:
                conn, _ = listener.accept()
                with conn:
                    request = bytearray()
                    while b"\r\n\r\n" not in request:
                        request.extend(conn.recv(4096))
                    decoded_request = request.decode()
                    request_lines.append(decoded_request.split("\r\n", 1)[0])
                    headers = {}
                    for line in decoded_request.split("\r\n")[1:]:
                        if ":" in line:
                            key, value = line.split(":", 1)
                            headers[key.lower().strip()] = value.strip()
                    key = headers["sec-websocket-key"]
                    accept = base64.b64encode(
                        hashlib.sha1(
                            (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()
                        ).digest()
                    ).decode()
                    conn.sendall(
                        (
                            "HTTP/1.1 101 Switching Protocols\r\n"
                            "Upgrade: websocket\r\n"
                            "Connection: Upgrade\r\n"
                            f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
                        ).encode()
                    )
                    answers = [
                        ("is_adopted", False),
                        ("system_info", {"version": "synthetic", "installation_running": False}),
                        ("list_disks", [{"name": "sda", "size": 1024}]),
                        ("list_network_interfaces", [{"name": "eth0"}]),
                    ]
                    for method, result in answers:
                        request_obj = recv_json(conn)
                        if request_obj["method"] != method:
                            raise AssertionError(
                                f"expected {method}, got {request_obj['method']}"
                            )
                        send_json(
                            conn,
                            {
                                "jsonrpc": "2.0",
                                "id": request_obj["id"],
                                "result": result,
                            },
                        )
            except Exception as exc:
                errors.append(exc)
            finally:
                listener.close()

        thread = threading.Thread(target=server, daemon=True)
        thread.start()
        with tempfile.TemporaryDirectory() as td:
            out = pathlib.Path(td) / "rpc.json"
            cp = subprocess.run(
                [
                    sys.executable,
                    str(TRUENAS_RPC),
                    "--port",
                    str(port),
                    "--path",
                    "/",
                    "--out",
                    str(out),
                    "--timeout",
                    "2",
                ],
                text=True,
                capture_output=True,
                timeout=10,
            )
            self.assertEqual(cp.returncode, 0, cp.stderr)
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertTrue(payload["oracleSatisfied"])
            self.assertEqual(payload["classification"], "SUPPORTED")
            self.assertFalse(payload["methods"]["is_adopted"])
            self.assertEqual(payload["methods"]["system_info"]["version"], "synthetic")
            self.assertEqual(payload["endpoint"]["path"], "/")
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(request_lines, ["GET / HTTP/1.1"])

    def test_truenas_rpc_probe_preserves_connect_failure_receipt(self):
        with tempfile.TemporaryDirectory() as td:
            out = pathlib.Path(td) / "rpc-failure.json"
            unused = socket.socket()
            unused.bind(("127.0.0.1", 0))
            port = unused.getsockname()[1]
            unused.close()
            cp = subprocess.run(
                [
                    sys.executable,
                    str(TRUENAS_RPC),
                    "--port",
                    str(port),
                    "--path",
                    "/",
                    "--out",
                    str(out),
                    "--timeout",
                    "0.2",
                ],
                text=True,
                capture_output=True,
                timeout=10,
            )
            self.assertEqual(cp.returncode, 0, cp.stderr)
            self.assertTrue(out.is_file())
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertFalse(payload["oracleSatisfied"])
            self.assertEqual(payload["classification"], "ORACLE_FAILURE")
            self.assertEqual(payload["stage"], "connect-or-handshake")
            self.assertEqual(payload["endpoint"]["path"], "/")
            self.assertIn("ConnectionRefusedError", payload["detail"])

    def test_truenas_t1_requires_real_rpc_not_hostfwd_tcp(self):
        text = TRUENAS.read_text(encoding="utf-8")
        self.assertIn("try_rpc_discovery", text)
        self.assertIn("RPC_DISCOVERY_OK", text)
        self.assertIn("installer_rpc_hostfwd_accepted", text)
        self.assertNotIn("RPC_REACHABLE", text)
        self.assertIn("completed vendor WebSocket/JSON-RPC discovery exchange", text)

    def test_future_truenas_mutating_clients_compile_and_refuse_ambiguity(self):
        install = TRUENAS_INSTALL.read_text(encoding="utf-8")
        middleware = TRUENAS_MIDDLEWARE.read_text(encoding="utf-8")
        self.assertIn("expected exactly one non-removable disk", install)
        self.assertIn("expected exactly one non-loopback interface", install)
        self.assertIn('p.add_argument("--path", default="/ws")', install)
        self.assertIn("path=a.path", install)
        self.assertIn('"truenas_admin"', install)
        self.assertIn('"auth.login_ex"', middleware)
        self.assertIn('"PASSWORD_PLAIN"', middleware)
        self.assertIn('"system.version"', middleware)
        self.assertIn('"system.info"', middleware)
        for path in (TRUENAS_INSTALL, TRUENAS_MIDDLEWARE):
            cp = subprocess.run(
                ["python3", "-m", "py_compile", str(path)],
                text=True,
                capture_output=True,
            )
            self.assertEqual(cp.returncode, 0, cp.stderr)

    def test_truenas_t2_keeps_install_and_middleware_oracles_separate(self):
        text = TRUENAS.read_text(encoding="utf-8")
        self.assertIn("t0|t1|t2", text)
        self.assertIn("installer_install_completed", text)
        self.assertIn("installed_middleware_authenticated", text)
        self.assertIn("truenas_installer_rpc_install.py", text)
        self.assertIn("truenas_middleware_ddp_probe.py", text)
        self.assertIn('NIC_MAC="52:54:00:54:4e:26"', text)

    def test_truenas_install_rpc_uses_one_positional_object(self):
        text = TRUENAS_INSTALL.read_text(encoding="utf-8")
        self.assertIn('rpc_call(ws, "install", 4, [install_params]', text)

    def test_truenas_t3_real_harness_contract(self):
        text = TRUENAS.read_text(encoding="utf-8")
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("t0|t1|t2|t3|t4|t5|t6", text)
        self.assertIn('DATA_DISK_SIZE="8G"', text)
        self.assertIn("DATA_DISK_COUNT=2", text)
        self.assertIn('DATA_POOL_NAME="rdtepool"', text)
        self.assertIn('DATA_SERIAL_PREFIX="RDTE_DATA_"', text)
        self.assertEqual(text.count("mac=$NIC_MAC,addr=0x3"), 2)
        self.assertIn("if=none,id=rdteboot", text)
        self.assertIn("id=rdte-boot,addr=0x4,bootindex=1", text)
        self.assertIn("-boot strict=on", text)
        self.assertNotIn("-boot order=c", text)
        self.assertIn("if=none,id=$drive_id", text)
        self.assertIn("pci_slot=$((5 + index))", text)
        self.assertIn(
            "virtio-blk-pci,drive=$drive_id,serial=${DATA_SERIAL_PREFIX}${index},addr=0x${pci_slot}",
            text,
        )
        self.assertIn('--data-serial-prefix "$DATA_SERIAL_PREFIX"', text)
        self.assertIn("data${index}.qcow2", text)
        self.assertIn('"${DATA_DRIVE_ARGS[@]}"', text)
        self.assertIn("truenas_middleware_pool_probe.py", text)
        self.assertIn('"data_pool_created"', text)
        self.assertIn('"data_pool"', text)
        self.assertIn("truenas_rung:", workflow)
        self.assertIn("needs.changes.outputs.truenas_rung", workflow)
        shell_check = subprocess.run(["bash", "-n", str(TRUENAS)], text=True, capture_output=True)
        self.assertEqual(shell_check.returncode, 0, shell_check.stderr)
        py_check = subprocess.run(["python3", "-m", "py_compile", str(TRUENAS_POOL)], text=True, capture_output=True)
        self.assertEqual(py_check.returncode, 0, py_check.stderr)

    def test_truenas_t3_compute_c0_is_opt_in_api_native_and_c1_separate(self):
        text = TRUENAS.read_text(encoding="utf-8")
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn('--compute-fixture', text)
        self.assertIn('COMPUTE_FIXTURE="none"', text)
        self.assertIn('container-c0', text)
        self.assertIn('requires rung t3', text)
        self.assertIn('truenas_compute_container_probe.py', text)
        self.assertIn('config/compute-materialization-targets.json', text)
        self.assertIn('"compute_materialization_exercised"', text)
        self.assertIn('"compute_materialization"', text)
        self.assertIn('"c0_oracle_satisfied"', text)
        self.assertIn('"c1_guest_oracle_satisfied"', text)
        self.assertIn('"image_resolution"', text)
        self.assertIn('truenas_compute_fixture:', workflow)
        self.assertIn('needs.changes.outputs.truenas_compute_fixture', workflow)
        self.assertIn('(.compute_fixture // "none")', workflow)
        self.assertNotIn('scripts/truenas_compute_container_probe.py)', workflow.split("while IFS= read -r path; do", 1)[1].split("done < <(git diff --name-only", 1)[0])
        shell_check = subprocess.run(["bash", "-n", str(TRUENAS)], text=True, capture_output=True)
        self.assertEqual(shell_check.returncode, 0, shell_check.stderr)

    def test_truenas_t3_vm_v0_is_opt_in_and_strictly_pre_guest(self):
        text = TRUENAS.read_text(encoding="utf-8")
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn('vm-v0', workflow)
        self.assertIn('vm-v0', text)
        self.assertIn('truenas_compute_vm_probe.py', text)
        self.assertIn('--zvol-name "$DATA_POOL_NAME/rdte-compute-vm-v0"', text)
        self.assertIn('"v0_oracle_satisfied"', text)
        self.assertIn('"v1_guest_oracle_satisfied"', text)
        self.assertIn('"v2_firecracker_oracle_satisfied"', text)
        self.assertIn('"windows_w1_oracle_satisfied"', text)
        self.assertIn('"vm_absent"', text)
        self.assertIn('"device_absent"', text)
        self.assertIn('"zvol_absent"', text)
        self.assertIn('guest boot, nested KVM, Firecracker and Windows remain unclaimed', text)
        shell_check = subprocess.run(["bash", "-n", str(TRUENAS)], text=True, capture_output=True)
        self.assertEqual(shell_check.returncode, 0, shell_check.stderr)

    def test_truenas_t4_apps_contract(self):
        text = TRUENAS.read_text(encoding="utf-8")
        app = TRUENAS_APP.read_text(encoding="utf-8")
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn('APP_RESULT_JSON=""', text)
        self.assertIn("apps_runtime_exercised", text)
        self.assertIn("truenas_middleware_app_probe.py", text)
        self.assertIn("docker.update", app)
        self.assertIn("docker.status", app)
        self.assertNotIn("truenas.entitlements.check", app)
        self.assertIn('"apps_gate": "docker.license_active"', app)
        self.assertIn('"ha_apps_gate": a.ha_apps_gate', app)
        self.assertIn('"middleware_commit": a.middleware_commit', app)
        self.assertIn('"middleware_ref": a.middleware_ref', app)
        self.assertIn('--expected-version "$EXPECTED_SYSTEM_VERSION"', text)
        self.assertIn('--middleware-commit "$MIDDLEWARE_COMMIT"', text)
        self.assertIn('--ha-apps-gate "$HA_APPS_GATE"', text)
        self.assertIn("app.create", app)
        self.assertIn("app.query", app)
        self.assertIn('payload["docker_update_result"]', app)
        self.assertIn('payload["app_create_result"]', app)
        self.assertIn('"nginx@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10"', app)
        self.assertNotIn('"nginx:1.27-alpine"', app)
        self.assertIn('"state") == "RUNNING"', app)
        self.assertIn("truenas_rung:", workflow)
        self.assertIn("needs.changes.outputs.truenas_rung", workflow)
        py = subprocess.run(
            ["python3", "-m", "py_compile", str(TRUENAS_APP)],
            text=True,
            capture_output=True,
        )
        self.assertEqual(py.returncode, 0, py.stderr)


    def test_truenas_t5_lifecycle_harness_contract(self):
        text = TRUENAS.read_text(encoding="utf-8")
        lifecycle = TRUENAS_LIFECYCLE.read_text(encoding="utf-8")
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("t0|t1|t2|t3|t4|t5", text)
        self.assertIn("truenas_middleware_app_lifecycle_probe.py", text)
        self.assertIn('"app_lifecycle_exercised"', text)
        self.assertIn('"app_lifecycle"', text)
        self.assertIn("nginx@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10", text)
        self.assertNotIn("EXPECTED_VERSION =", lifecycle)
        self.assertIn('p.add_argument("--expected-version", required=True)', lifecycle)
        self.assertIn('"expected_version": a.expected_version', lifecycle)
        self.assertIn('--expected-version "$EXPECTED_SYSTEM_VERSION"', text)
        self.assertIn('APP_IMAGE = "nginx@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10"', lifecycle)
        self.assertIn("truenas_rung:", workflow)
        self.assertIn("needs.changes.outputs.truenas_rung", workflow)
        shell_check = subprocess.run(
            ["bash", "-n", str(TRUENAS)], text=True, capture_output=True
        )
        self.assertEqual(shell_check.returncode, 0, shell_check.stderr)


    def test_truenas_t6_foundry_harness_contract(self):
        text = TRUENAS.read_text(encoding="utf-8")
        workflow = WORKFLOW.read_text(encoding="utf-8")
        litellm = (ROOT / "scripts" / "truenas_middleware_litellm_t6_probe.py").read_text(encoding="utf-8")
        self.assertIn("--foundry-control-dir", text)
        self.assertIn("--foundry-commit", text)
        self.assertIn("truenas_middleware_litellm_t6_probe.py", text)
        self.assertNotIn('python3 "$SCRIPT_DIR/truenas_middleware_foundry_control_probe.py"', text)
        self.assertIn('"foundry_materialization_exercised"', text)
        self.assertIn('"foundry_materialization"', text)
        self.assertIn("truenas_rung:", workflow)
        self.assertIn("needs.changes.outputs.truenas_rung", workflow)
        self.assertIn("4ba12f4a870f9af8a667056f1e2cc32f80f8e2ba", workflow)
        self.assertIn("litellm-truenas-t6-control", workflow)
        self.assertIn("export-litellm-t6-control.yml", workflow)
        self.assertIn("semper-supra.litellm-truenas-t6-control/1", litellm)
        self.assertIn("config_readback_sha", litellm)
        self.assertIn('"secret_values_captured": False', litellm)
        self.assertIn("--service-port", text)
        self.assertIn("-:30401", text)
        shell_check = subprocess.run(
            ["bash", "-n", str(TRUENAS)], text=True, capture_output=True
        )
        self.assertEqual(shell_check.returncode, 0, shell_check.stderr)

    def test_qemu_t3_topology_is_a_cheap_separate_oracle(self):
        probe = QEMU_TOPOLOGY.read_text(encoding="utf-8")
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn('"rdte-nic"', probe)
        self.assertIn('"rdte-boot"', probe)
        self.assertIn('"bootindex": 1', probe)
        self.assertIn('"RDTE_DATA_0"', probe)
        self.assertIn('"RDTE_DATA_1"', probe)
        self.assertIn('"query-pci"', probe)
        self.assertIn('"qom-get"', probe)
        self.assertIn("qemu-t3-topology:", workflow)
        self.assertIn("needs.changes.outputs.qemu_topology", workflow)
        self.assertNotIn(
            "scripts/gha_qemu_t3_topology_probe.py)",
            workflow.split("truenas=true", 1)[0],
        )
        py = subprocess.run(
            ["python3", "-m", "py_compile", str(QEMU_TOPOLOGY)],
            text=True,
            capture_output=True,
        )
        self.assertEqual(py.returncode, 0, py.stderr)

    def test_all_post_t0_rungs_share_installer_rpc_gate(self):
        text = TRUENAS.read_text(encoding="utf-8")
        self.assertIn('if [[ "$RUNG" != "t0" ]]; then', text)
        self.assertNotIn('if [[ "$RUNG" == "t1" || "$RUNG" == "t2" || "$RUNG" == "t3" ]]; then', text)
        self.assertIn("try_rpc_discovery", text)

    def test_t4_uses_exact_target_profile_metadata(self):
        text = (ROOT / "scripts" / "truenas_middleware_app_probe.py").read_text(encoding="utf-8")
        self.assertNotIn("truenas.entitlements.check", text)
        self.assertIn('p.add_argument("--middleware-ref", required=True)', text)
        self.assertIn('p.add_argument("--middleware-commit", required=True)', text)
        self.assertIn('p.add_argument("--ha-apps-gate", required=True)', text)
        self.assertIn('"middleware_ref": a.middleware_ref', text)
        self.assertIn('"middleware_commit": a.middleware_commit', text)
        self.assertIn('"apps_gate": "docker.license_active"', text)
        self.assertIn('"ha_apps_gate": a.ha_apps_gate', text)



class PoolTransportBudgetTests(unittest.TestCase):
    def test_pool_probe_has_wss_tolerant_read_budget_and_phase_receipts(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        harness = (root / "scripts" / "gha_kvm_truenas_rdte.sh").read_text(encoding="utf-8")
        probe = (root / "scripts" / "truenas_middleware_pool_probe.py").read_text(encoding="utf-8")
        pool_call = harness.split('POOL_OUT="$STATE_DIR/data-pool.json"', 1)[1].split('[[ -f "$POOL_OUT" ]]', 1)[0]
        self.assertIn("--timeout 15 --job-timeout 180", pool_call)
        for phase in (
            "connect", "authenticate", "discover-system", "discover-boot-disks",
            "discover-disk-details", "precondition-pool-absence",
            "pool-create-submit", "pool-create-wait", "verify-pool", "verify-pool-disks", "complete",
        ):
            self.assertIn(f'payload["phase"] = "{phase}"', probe)

if __name__ == "__main__":
    unittest.main()
