import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "fw",
    ROOT / "scripts" / "firecracker_workload_evidence.py",
)
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MOD)


def base_receipt(**overrides):
    data = dict(
        authority_ref="SemperSupra/agent-dispatch-private#415",
        assignment_ref="synthetic/playwright-control",
        assignment_revision="fixture-v1",
        venue="public-gha",
        visibility="public_safe",
        placement_reasons=["stronger_isolation", "body_variation"],
        inputs={"fixture_sha256": "a" * 64},
        body={
            "firecracker": {"version": "v1.17.0", "sha256": "b" * 64},
            "kernel": {"version": "6.18.48", "sha256": "c" * 64},
            "rootfs": {"kind": "test", "sha256": "d" * 64},
            "resources": {"vcpu_count": 1, "mem_size_mib": 1024},
        },
        execution={"classification": "SUPPORTED", "exit_code": 0},
        outputs={"result_sha256": "e" * 64},
        validation=None,
        cleanup={"ok": True},
    )
    data.update(overrides)
    return MOD.make_receipt(**data)


class FirecrackerWorkloadEvidenceTests(unittest.TestCase):
    def test_public_safe_receipt_is_stable(self):
        a = base_receipt()
        b = base_receipt(placement_reasons=["body_variation", "stronger_isolation"])
        self.assertEqual(MOD.canonical_json(a), MOD.canonical_json(b))
        self.assertEqual(MOD.receipt_digest(a), MOD.receipt_digest(b))
        self.assertEqual(len(MOD.receipt_digest(a)), 64)

    def test_receipt_digest_remains_recomputable_after_insertion(self):
        r = base_receipt()
        digest = MOD.receipt_digest(r)
        r["receipt_digest"] = digest
        self.assertEqual(MOD.receipt_digest(r), digest)

    def test_firecracker_requires_material_reason(self):
        with self.assertRaises(MOD.ContractError):
            base_receipt(placement_reasons=[])

    def test_unknown_reason_fails_closed(self):
        with self.assertRaises(MOD.ContractError):
            base_receipt(placement_reasons=["because_microvm"])

    def test_private_bytes_never_fit_public_gha_receipt(self):
        with self.assertRaises(MOD.ContractError):
            base_receipt(visibility="private")

    def test_executor_success_is_not_acceptance(self):
        r = base_receipt()
        self.assertIsNone(r["validation"])
        self.assertEqual(r["execution"]["classification"], "SUPPORTED")

    def test_acceptance_requires_independent_validator_ref(self):
        with self.assertRaises(MOD.ContractError):
            base_receipt(validation={"accepted": True})
        r = base_receipt(validation={"accepted": True, "validator_ref": "held-out/v1"})
        self.assertTrue(r["validation"]["accepted"])

    def test_cleanup_is_required_evidence(self):
        with self.assertRaises(MOD.ContractError):
            base_receipt(cleanup={})

    def test_failure_classes_are_preserved(self):
        for classification in sorted(MOD.RESULT_CLASSIFICATIONS):
            r = base_receipt(execution={"classification": classification})
            self.assertEqual(r["execution"]["classification"], classification)


if __name__ == "__main__":
    unittest.main()
