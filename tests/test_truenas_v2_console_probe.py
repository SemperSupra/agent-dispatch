import unittest

from scripts.truenas_v2_console_probe import parse_v2_observation


class TrueNASV2ConsoleProbeTests(unittest.TestCase):
    NONCE = "rep003nonceABCDEF12"

    def test_positive_nested_kvm_observation(self):
        data = (
            b"boot\nAGENT_DISPATCH_V1_NONCE=" + self.NONCE.encode() +
            b"\nAGENT_DISPATCH_V2_KVM_PRESENT=1\nAGENT_DISPATCH_V2_CPU_VMX_SVM=1\n"
        )
        result = parse_v2_observation(data, self.NONCE)
        self.assertTrue(result["nested_kvm_observed"])
        self.assertTrue(result["firecracker_eligible"])

    def test_negative_is_valid_observation_not_firecracker_eligible(self):
        data = (
            b"AGENT_DISPATCH_V1_NONCE=" + self.NONCE.encode() +
            b"\nAGENT_DISPATCH_V2_KVM_PRESENT=0\nAGENT_DISPATCH_V2_CPU_VMX_SVM=1\n"
        )
        result = parse_v2_observation(data, self.NONCE)
        self.assertFalse(result["nested_kvm_observed"])
        self.assertFalse(result["firecracker_eligible"])
        self.assertTrue(result["nonce_observed"])

    def test_incomplete_markers_do_not_pass(self):
        data = b"AGENT_DISPATCH_V1_NONCE=" + self.NONCE.encode()
        self.assertIsNone(parse_v2_observation(data, self.NONCE))


if __name__ == "__main__":
    unittest.main()
