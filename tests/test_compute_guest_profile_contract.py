import copy, unittest
from scripts.compute_guest_profile_contract import ProfileError, validate

def fixture():
    return {
      "schema":"semper-supra.compute-guest-profiles/v1",
      "dependencies":{
        "firecracker":"SemperSupra/agent-dispatch-private#277",
        "windows_embodiment":"mark-e-deyoung/windows-utilities#26",
      },
      "policy":{
        "source_capability_is_not_runtime_qualification":True,
        "nested_kvm_must_be_observed_in_guest":True,
        "private_hypervisor_escape_hatches_prohibited":True,
        "windows_media_must_be_legal_public_evaluation_or_user_supplied":True,
        "windows_product_key_must_not_be_embedded":True,
        "guest_oracle_required_before_backend_admission":True,
      },
      "fixtures":{
        "linux_v1":{
          "id":"cirros-0.6.3-x86_64-nocloud-serial-nonce",
          "release":"0.6.3",
          "architecture":"x86_64",
          "source":{
            "url":"https://download.cirros-cloud.net/0.6.3/cirros-0.6.3-x86_64-disk.img",
            "sha256":"7d6355852aeb6dbcd191bcda7cd74f1536cfe5cbf8a10495a7283a8396e4b75b",
            "checksum_url":"https://download.cirros-cloud.net/0.6.3/SHA256SUMS",
          },
          "datasource":"nocloud",
          "user_data_contract":"executable-shell",
          "oracle":{
            "transport":"serial-console",
            "nonce_prefix":"AGENT_DISPATCH_V1_NONCE=",
            "must_match_injected_nonce":True,
          },
          "claim_boundary":"x",
        }
      },
      "truenas":{},
      "proxmox":{
        "9.2-1":{
          "windows11":{"runtime_status":"OPEN"},
          "firecracker":{"runtime_status":"OPEN"},
        }
      },
      "rungs":{"V0":"x","V1":"x","V2":"x","W1":"x","WB":"x"},
    }

def tnrow(version):
    legacy=version=="25.04.1"
    row = {
      "windows11":{
        "source_status":"CANDIDATE",
        "runtime_status":"OPEN",
        "capabilities":{
          "secure_boot":{"source_proven":True},
          "tpm":{"source_proven":True},
          "uefi_q35":{"source_proven":not legacy},
        },
      },
      "firecracker":{
        "source_status":"RUNTIME_OBSERVE_ONLY" if legacy else "CANDIDATE",
        "cpu_passthrough_control":None if legacy else "vm.create.cpu_mode=HOST-PASSTHROUGH",
        "runtime_status":"OPEN",
      },
    }
    if version=="26.0.0-BETA.3":
        row["linux_v1"]={
          "source_status":"CANDIDATE",
          "runtime_status":"OPEN",
          "fixture":"cirros-0.6.3-x86_64-nocloud-serial-nonce",
          "public_surfaces":{
            "boot_disk":"vm.device.create RAW exists=true boot=true",
            "seed_media":"vm.device.create CDROM",
            "console_discovery":"vm.get_console",
          },
          "observation_requirement":"consume guest console through supported TrueNAS console surface; do not inject raw.qemu or invoke virsh directly",
        }
    return row

class Tests(unittest.TestCase):
    def profile(self):
        p=fixture()
        for v in ("25.04.1","25.04.2.6","25.10.7","26.0.0-BETA.3"):
            p["truenas"][v]=tnrow(v)
        return p
    def test_contract(self):
        self.assertEqual(validate(self.profile())["status"],"PASS")
    def test_legacy_nested_kvm_cannot_be_source_claimed(self):
        p=self.profile()
        p["truenas"]["25.04.1"]["firecracker"]["cpu_passthrough_control"]="raw.qemu=-cpu host"
        with self.assertRaises(ProfileError):
            validate(p)
    def test_runtime_claim_fails_closed(self):
        p=self.profile()
        p["truenas"]["25.10.7"]["windows11"]["runtime_status"]="PASS"
        with self.assertRaises(ProfileError):
            validate(p)
    def test_linux_v1_fixture_digest_fails_closed(self):
        p=self.profile()
        p["fixtures"]["linux_v1"]["source"]["sha256"]="0"*64
        with self.assertRaises(ProfileError):
            validate(p)
    def test_linux_v1_nonce_oracle_fails_closed(self):
        p=self.profile()
        p["fixtures"]["linux_v1"]["oracle"]["must_match_injected_nonce"]=False
        with self.assertRaises(ProfileError):
            validate(p)
    def test_beta3_v1_console_must_remain_public_surface(self):
        p=self.profile()
        p["truenas"]["26.0.0-BETA.3"]["linux_v1"]["public_surfaces"]["console_discovery"]="virsh console"
        with self.assertRaises(ProfileError):
            validate(p)
    def test_beta3_v1_runtime_claim_fails_closed(self):
        p=self.profile()
        p["truenas"]["26.0.0-BETA.3"]["linux_v1"]["runtime_status"]="PASS"
        with self.assertRaises(ProfileError):
            validate(p)
    def test_target_growth_fails_closed(self):
        p=self.profile()
        p["truenas"]["27.0.0"]=tnrow("27.0.0")
        with self.assertRaises(ProfileError):
            validate(p)

if __name__=="__main__":
    unittest.main()
