"""Synthetic independent-witness readback to fail CLOSED after real etcd stale restore.

Exit 42 = mandatory HOLD because trusted, separately stored highest known
epoch/budget/UNKNOWN is not present in live etcd; 43 = witness invalid/missing.
Neither the plain-text fixture receipt nor this runner is a production signer
or a durable independent failure domain.
"""
import json, pathlib, subprocess, sys

def main():
    witness=pathlib.Path(sys.argv[1])
    tool=sys.argv[2]
    if not witness.is_file():
        print(json.dumps({"verdict":"HOLD_MISSING_EXTERNAL_WITNESS","receipt":"TEST_ONLY"}))
        return 43
    if witness.read_text().strip()!="epoch=8;budget=0;effect/first=UNKNOWN":
        print(json.dumps({"verdict":"HOLD_WITNESS_NOT_TRUSTWORTHY","receipt":"TEST_ONLY"}))
        return 43
    def get(key):
        result=subprocess.run([tool,"get",key,"--print-value-only"],
            capture_output=True,text=True,timeout=8)
        if result.returncode:
            raise RuntimeError("Native etcd readback unavailable")
        return result.stdout.strip()
    actual={"epoch":get("r62/epoch"),
            "budget":get("r62/budget"),
            "effect/first":get("r62/effect/first")}
    expected={"epoch":"8","budget":"0","effect/first":"UNKNOWN"}
    if actual!=expected:
        print(json.dumps({"verdict":"HOLD_INCONSISTENT_RESTORED_HIGH_WATER",
            "status":"EXPECTED_NEGATIVE","first_effect_missing":actual["effect/first"]!="UNKNOWN",
            "budget_reopened":actual["budget"]=="1","epoch_regressed":actual["epoch"]=="7",
            "effect_dispatched":False,"trusted_external_receipt":"NOT_IMPLEMENTED"},sort_keys=True))
        return 42
    print(json.dumps({"verdict":"MATCH_ONLY_NOT_RELEASE_ACCEPTANCE",
        "trusted_external_receipt":"NOT_IMPLEMENTED"},sort_keys=True))
    return 0
if __name__=="__main__":
    sys.exit(main())
