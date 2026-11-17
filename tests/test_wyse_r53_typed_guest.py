"""R53 public Linux guest as a reviewed Agent Dispatch typed workload, no new scheduler."""
from __future__ import annotations
from datetime import datetime,timedelta,timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import gha_workload_request as profile
import gha_assignment_contract as assignment
import verify_gha_typed_receipt as verifier

REQUEST="requests/gha/wyse-r53-linux-guest-v1.json"
DIGEST="b4f51231b5956ff6eb520c4a85dc43ff4542405342e5ab8e097b960155898782"
EVIDENCE={
 "R52_C_EVIDENCE_CLASS":"PUBLIC_DISPOSABLE_REAL_LINUX_NOT_DELL_HIL",
 "R52_C_GUEST_BOOT":"LINUX_KERNEL_QEMU_TCG_OBSERVED",
 "R52_C_GUEST_TASK_SHA256":DIGEST,
 "R52_C_HOST_VOLUME_AND_GUEST_NIC":"NOT_ATTACHED",
 "R52_C_AGENT_DISPATCH_REAL_LEASE":"NOT_TESTED",
 "R52_C_WYSE_REAL_KVM_AND_EMMC":"NOT_TESTED",
 "R52_C_GUEST_RESULT_AND_CLEAN_EXIT":"PASS",
}
def receipt(e):
 return "".join(f"{k}={v}\n" for k,v in e.items())
class TypedGuestTests(unittest.TestCase):
 def test_only_reviewed_public_zero_cost_profile_is_admitted(self):
  p=profile.plan(REQUEST)
  self.assertEqual(p["runner"],"ubuntu-24.04")
  self.assertEqual(p["workload"],"wyse-r52-linux-guest")
  self.assertEqual((p["max_cost_usd"],p["max_attempts"],p["timeout_seconds"]),(0,1,240))
  self.assertEqual(assignment.PROFILES["wyse-r53-linux-guest-v1"],REQUEST)
  with self.assertRaises(profile.Denied):
   profile.plan("../../private/wyse.json")
  with self.assertRaises(profile.Denied):
   profile.run(REQUEST,"f"*64)
 def test_existing_assignment_admission_binds_profile_and_nonce(self):
  now=datetime.now(timezone.utc).replace(microsecond=0)
  p=profile.plan(REQUEST)
  body={
   "schema":assignment.SCHEMA,"assignment_id":"wyse-r53-test-001",
   "nonce":"a"*32,"profile_id":"wyse-r53-linux-guest-v1",
   "profile_sha256":p["request_sha256"],"source_sha":"b"*40,
   "authority_sha256":"c"*64,"issued_at":(now-timedelta(seconds=3)).strftime("%Y-%m-%dT%H:%M:%SZ"),
   "expires_at":(now+timedelta(minutes=4)).strftime("%Y-%m-%dT%H:%M:%SZ"),
   "data_class":"public-synthetic","max_attempts":1,"max_cost_usd":0,
  }
  approved=assignment.admit(json.dumps(body),trusted_source_sha="b"*40,now=now)
  self.assertEqual(approved["profile_path"],REQUEST)
  for mutation in ({"profile_sha256":"d"*64},{"max_cost_usd":1},
                   {"data_class":"private"},{"max_attempts":2},
                   {"script":"rm -rf /"},{"profile_id":"arbitrary-command"}):
   bad=dict(body,**mutation)
   with self.subTest(mutation=mutation),self.assertRaises(assignment.Denied):
    assignment.admit(json.dumps(bad),trusted_source_sha="b"*40,now=now)
  with self.assertRaises(assignment.Denied):
   assignment.admit(json.dumps(body),trusted_source_sha="f"*40,now=now)
 def test_fixed_guest_exact_oracle_and_tainted_receipt_denial(self):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);out=root/"evidence/public/r52-linux-guest.txt"
   def fake_run(cmd,**kw):
    self.assertEqual(cmd,["bash","tools/wyse-qemu-bootbench/run-linux-guest.sh","--public-disposable"])
    self.assertEqual(kw["cwd"],root)
    self.assertLessEqual(kw["timeout"],240)
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(receipt(EVIDENCE),encoding="utf-8")
    return subprocess.CompletedProcess(cmd,0)
   with patch.object(profile,"ROOT",root),patch.object(profile.subprocess,"run",side_effect=fake_run):
    good=profile._execute("wyse-r52-linux-guest",240)
    self.assertEqual((good["classification"],good["oracle_verified"]),("PASS",True))
    self.assertFalse(good["physical_wyse_qualified"])
    self.assertFalse(good["agent_dispatch_real_lease"])
    # A previously existing file cannot launder stale jobs as a fresh run.
    stale=profile._execute("wyse-r52-linux-guest",240)
    self.assertFalse(stale["oracle_verified"])
    self.assertEqual(stale["classification"],"FAIL_STALE_GUEST_RECEIPT")
   for name,value in (
      ("R52_C_GUEST_TASK_SHA256","0"*64),
      ("R52_C_AGENT_DISPATCH_REAL_LEASE","PASS"),
      ("R52_C_WYSE_REAL_KVM_AND_EMMC","PASS"),
      ("R52_C_HOST_VOLUME_AND_GUEST_NIC","ATTACHED"),
    ):
    broken=dict(EVIDENCE);broken[name]=value
    out.unlink()
    def fake_bad(cmd,**kw):
     out.write_text(receipt(broken),encoding="utf-8")
     return subprocess.CompletedProcess(cmd,0)
    with patch.object(profile,"ROOT",root),patch.object(profile.subprocess,"run",side_effect=fake_bad):
     self.assertFalse(profile._execute("wyse-r52-linux-guest",240)["oracle_verified"],name)
   out.unlink()
   def fake_dupes(cmd,**kw):
    out.write_text(receipt(EVIDENCE)+"R52_C_GUEST_RESULT_AND_CLEAN_EXIT=PASS\n")
    return subprocess.CompletedProcess(cmd,0)
   with patch.object(profile,"ROOT",root),patch.object(profile.subprocess,"run",side_effect=fake_dupes):
    self.assertFalse(profile._execute("wyse-r52-linux-guest",240)["oracle_verified"])
 def test_independent_verifier_rejects_physical_hil_laundering(self):
  p=profile.plan(REQUEST)
  sample={
   "schema":profile.RECEIPT,"assignment_id":p["assignment_id"],
   "data_class":"public-synthetic","observed_architecture":"x86_64",
   "qualified":True,"request_path":REQUEST,"request_sha256":p["request_sha256"],
   "requested_runner":"ubuntu-24.04","result":{
    "classification":"PASS","oracle_verified":True,"guest_task_sha256":DIGEST,
    "guest_kernel_boot":True,"guest_clean_exit":True,
    "physical_wyse_qualified":False,"agent_dispatch_real_lease":False,
   },
   "run_attempt":"1","run_id":"44111111111","shape_verified":True,
   "source_sha":"a"*40,"workload":"wyse-r52-linux-guest",
  }
  def check(d):
   raw=(json.dumps(d,sort_keys=True)+"\n").encode()
   return verifier.evaluate(manifest_path=REQUEST,receipt_bytes=raw,
    trusted_source_sha="a"*40,trusted_run_id="44111111111",
    trusted_runner="ubuntu-24.04",trusted_receipt_sha256=hashlib.sha256(raw).hexdigest())
  self.assertEqual(check(sample)["classification"],"PASS")
  for key,value in (("physical_wyse_qualified",True),
                    ("agent_dispatch_real_lease",True),
                    ("guest_task_sha256","0"*64),("guest_kernel_boot",False),
                    ("guest_clean_exit",False)):
   changed=dict(sample)
   changed["result"]=dict(sample["result"],**{key:value})
   with self.subTest(field=key),self.assertRaises(verifier.VerdictError):
    check(changed)
