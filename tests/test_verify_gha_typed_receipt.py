"""Adversarial independent verification of real-shaped GHA typed receipts."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
def module(name,file):
    spec=importlib.util.spec_from_file_location(name,ROOT/"scripts"/file)
    result=importlib.util.module_from_spec(spec)
    sys.modules[spec.name]=result
    spec.loader.exec_module(result)
    return result

m=module("gha_workload_request","gha_workload_request.py")
v=module("verify_gha_typed_receipt","verify_gha_typed_receipt.py")
X64="requests/gha/cpu-x64-arithmetic-v1.json"
ARM="requests/gha/cpu-arm64-contract-v1.json"
SHA="a"*40
RUN="38543350738"


def built(manifest=X64):
    data=m.plan(manifest)
    runner=data["runner"]
    arch=data["expected_machine"]
    with patch.object(m.platform,"system",return_value="Linux"), \
         patch.object(m.platform,"machine",return_value=arch), \
         patch.dict(m.os.environ,{"RUNNER_ARCH":"X64" if arch=="x86_64" else "ARM64",
                                  "GITHUB_RUN_ATTEMPT":"1","GITHUB_SHA":SHA,
                                  "GITHUB_RUN_ID":RUN}), \
         patch.object(m,"_execute",return_value={
             "oracle_verified":True,"classification":"PASS"} if manifest==ARM else
             m._execute("arithmetic-oracle",30)):
        result=m.run(manifest,data["request_sha256"])
    raw=(json.dumps(result,sort_keys=True,indent=2)+"\n").encode()
    return result,raw


def check(raw,manifest=X64,runner=None,sha=SHA,run=RUN,receipt_hash=None):
    expected=m.plan(manifest)
    return v.evaluate(
        manifest_path=manifest,receipt_bytes=raw,
        trusted_source_sha=sha,trusted_run_id=run,
        trusted_runner=runner or expected["runner"],
        trusted_receipt_sha256=receipt_hash or hashlib.sha256(raw).hexdigest())


class IndependentReceiptTests(unittest.TestCase):
    def test_positive_x64_from_fixed_math(self):
        d,raw=built()
        verdict=check(raw)
        self.assertEqual(verdict["classification"],"PASS")
        self.assertEqual(verdict["request_sha256"],d["request_sha256"])

    def test_positive_arm_workload_shape(self):
        d,raw=built(ARM)
        self.assertTrue(d["qualified"])
        self.assertEqual(check(raw,manifest=ARM)["classification"],"PASS")

    def test_reject_artifact_tampering_before_parse(self):
        d,raw=built()
        forged=raw+b"\n"
        with self.assertRaisesRegex(v.VerdictError,"RECEIPT_ARTIFACT_HASH_MISMATCH"):
            check(forged,receipt_hash=hashlib.sha256(raw).hexdigest())

    def test_reject_provider_identity_mismatch(self):
        d,raw=built()
        for kwargs in ({"sha":"b"*40}, {"run":"123"}, {"runner":"ubuntu-24.04-arm"}):
            with self.subTest(kwargs=kwargs), self.assertRaises(v.VerdictError):
                check(raw,**kwargs)

    def test_reject_changed_request_or_unearned_runner(self):
        d,raw=built()
        with self.assertRaises(v.VerdictError):
            check(raw,manifest=ARM)
        for patch_data in (
            {"observed_architecture":"aarch64"},
            {"shape_verified":False},
            {"qualified":False},
            {"run_attempt":"2"},
            {"request_sha256":"0"*64},
            {"data_class":"private"},
            {"result":{"classification":"PASS","oracle_verified":False,
                       "task_count":256,"fixture_sha256":d["result"]["fixture_sha256"]}},
            {"result":{"classification":"PASS","oracle_verified":True,
                       "task_count":256,"fixture_sha256":"f"*64}},
        ):
            invalid=dict(d)
            invalid.update(patch_data)
            raw2=(json.dumps(invalid,sort_keys=True)+"\n").encode()
            with self.subTest(case=patch_data), self.assertRaises(v.VerdictError):
                check(raw2)

    def test_extra_and_duplicate_fields_fail(self):
        d,raw=built()
        d["free_form_shell"]="echo token"
        forged=json.dumps(d).encode()
        with self.assertRaisesRegex(v.VerdictError,"RECEIPT_SCHEMA_FIELDS_UNTRUSTED"):
            check(forged)
        duplicate=raw.replace(b'"qualified": true',b'"qualified": true, "qualified": true')
        with self.assertRaisesRegex(v.VerdictError,"DUPLICATE_RECEIPT_KEY"):
            check(duplicate)

    def test_result_substitution_fails(self):
        d,raw=built()
        d["result"]["task_count"]=257
        forged=json.dumps(d).encode()
        with self.assertRaisesRegex(v.VerdictError,"ARITHMETIC_ORACLE_MISMATCH"):
            check(forged)

    def test_receipt_bound_and_bad_sha(self):
        _,raw=built()
        with self.assertRaisesRegex(v.VerdictError,"RECEIPT_SIZE_OUT_OF_BOUNDS"):
            check(raw+b"0"*8192)
        with self.assertRaisesRegex(v.VerdictError,"TRUSTED_ARTIFACT_SHA_INVALID"):
            check(raw,receipt_hash="secret")

if __name__=="__main__":
    unittest.main()
