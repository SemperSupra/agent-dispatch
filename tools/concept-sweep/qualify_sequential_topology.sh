#!/usr/bin/env bash
# Synthetic-only controlled comparator. Two arms, one physical GHA VM,
# sequentially run with a fresh SearXNG Docker container for EVERY arm.
# Repeat order is balanced AB/BA or BA/AB, with randomized first order.
set -euo pipefail
umask 077
[[ "${MCP_GHA_TOPOLOGY_SYNTHETIC_ONLY:-}" == 1 ]] || { echo BLOCKED_NOT_SYNTHETIC; exit 2; }
: "${RUNNER_TEMP:?GitHub runner temp required}"
: "${GITHUB_RUN_ID:?GitHub run ID required}"
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
for utility in bash age age-keygen openssl python3 docker date; do
  command -v "$utility" >/dev/null || { echo BLOCKED_REQUIRED_TOOL; exit 2; }
done
# The key is test-only and never uploaded. The real mailbox uses a
# persistent owner-controlled recipient and PRIVATE re-ingestion instead.
scratch="$(mktemp -d)"
cleanup(){ rm -rf -- "$scratch"; }
trap cleanup EXIT INT TERM
age-keygen -o "$scratch/test-only.key" >/dev/null 2>&1
export MCP_GHA_AGE_RECIPIENT="$(age-keygen -y "$scratch/test-only.key")"
# Prepare image + Go executable ONCE per physical VM outside arm wall timing.
# Each loop below still recreates a fresh SearXNG container.
bash "$root/prepare_runner.sh"
export MCP_GHA_PREWARMED=1
# This draw determines the first arm; the second pass is the inversion.
# It avoids systematic assignment of either arm to first/second place.
random_hex="$(openssl rand -hex 1)"
choice=$((16#$random_hex % 2))
if ((choice == 0)); then first=reference; second=cpe; else first=cpe; second=reference; fi
for pass in 1 2; do
  if ((pass == 1)); then order=("$first" "$second")
  else order=("$second" "$first"); fi
  for arm in "${order[@]}"; do
    out="$scratch/pass-${pass}-${arm}"
    mkdir -p -- "$out"
    start_ms="$(date +%s%3N)"
    MCP_GHA_ARM="$arm" MCP_GHA_SEALED_OUT="$out" \
      bash "$root/run_sealed_arm.sh"
    end_ms="$(date +%s%3N)"
    age --decrypt --identity "$scratch/test-only.key" "$out/result.age" > "$out/raw.json"
    # Guard against cross-arm input/results before reading any source fields.
    export ARM_RESULT_PATH="$out/raw.json"
    export ARM_EXPECTED="$arm"
    python3 - <<'PY'
import json,os
x=json.load(open(os.environ["ARM_RESULT_PATH"],encoding="utf-8"))
assert x["schema"]=="mcp-gha-stage-r-arm-result/v1"
assert x["arm"]==os.environ["ARM_EXPECTED"]
assert {a["track"] for a in x["attempts"]}=={x["arm"]}
assert x["science_class"]=="SYNTHETIC_TRANSPORT_ONLY"
assert x["attempted_network"]==3
PY
    printf '%s' "$((end_ms-start_ms))" > "$out/wall_ms"
  done
done
export CONTROL_TOPOLOGY_TMP="$scratch"
export CONTROL_TOPOLOGY_FIRST="$first"
# Aggregate AFTER BOTH ARMS have completed both passes; no URLs or
# private query/source records enter GitHub summaries, logs or artifacts.
python3 - <<'PY'
import json,os,pathlib,statistics,urllib.parse
root=pathlib.Path(os.environ["CONTROL_TOPOLOGY_TMP"])
prep=json.loads((pathlib.Path(os.environ["RUNNER_TEMP"])/"mcp-gha-prewarm-receipt.json").read_text())
assert prep["schema"]=="mcp-gha-prewarm-qualification/v1"
per=[]
urls_by_arm={"reference":set(),"cpe":set()}
for pass_i in (1,2):
    for arm in ("reference","cpe"):
        d=root/f"pass-{pass_i}-{arm}"
        p=json.loads((d/"raw.json").read_text(encoding="utf-8"))
        r=json.loads((d/"receipt.json").read_text(encoding="utf-8"))
        assert r["arm"]==arm and r["research_status"]=="SYNTHETIC_TRANSPORT_ONLY_NOT_BLIND_RESEARCH"
        assert p["attempted_network"]==r["attempted"]==3
        assert r["runner_prepared_once"] is True
        assert p["succeeded_provider"]==r["succeeded"]
        assert p["failed_provider"]==r["failed"]
        urls=set()
        hosts=set()
        latencies=[]
        for a in p["attempts"]:
            latencies.append(a["elapsed_ms"])
            for h in a["retrieved_evidence"]:
                value=h["url"]
                urls.add(value)
                hosts.add(urllib.parse.urlsplit(value).hostname)
        urls_by_arm[arm].update(urls)
        per.append({
            "pass":pass_i,"arm":arm,
            "network_requests":r["attempted"],
            "provider_success":r["succeeded"],"provider_failure":r["failed"],
            "retrieved_hits":sum(len(a["retrieved_evidence"]) for a in p["attempts"]),
            "unique_url_count":len(urls),
            "unique_origin_count":len(hosts),
            "query_elapsed_ms":sum(latencies),
            "wall_ms":int((d/"wall_ms").read_text()),
            "image_pull_ms":r["image_pull_ms"],
            "provider_ready_ms":r["provider_ready_ms"],
            "go_build_ms":r["go_build_ms"],
        })
by_arm={}
for arm in ("reference","cpe"):
    reps=[x for x in per if x["arm"]==arm]
    by_arm[arm]={
        "runs":len(reps),
        "attempted":sum(x["network_requests"] for x in reps),
        "succeeded":sum(x["provider_success"] for x in reps),
        "failed":sum(x["provider_failure"] for x in reps),
        "retrieved_hits":sum(x["retrieved_hits"] for x in reps),
        "avg_wall_ms":round(statistics.mean(x["wall_ms"] for x in reps)),
        "avg_image_pull_ms":round(statistics.mean(x["image_pull_ms"] for x in reps)),
        "avg_provider_ready_ms":round(statistics.mean(x["provider_ready_ms"] for x in reps)),
        "avg_go_build_ms":round(statistics.mean(x["go_build_ms"] for x in reps)),
        "avg_query_elapsed_ms_per_three_queries":round(statistics.mean(x["query_elapsed_ms"] for x in reps)),
    }
summary={
    "schema":"mcp-gha-topology-qualification/v1",
    "classification":"PUBLIC_SYNTHETIC_TRANSPORT_ONLY_NOT_BLINDED_CPE",
    "topology":"single_runner_sequential_fresh_containers",
    "first_arm_randomized":os.environ["CONTROL_TOPOLOGY_FIRST"],
    "counterbalance":"two passes, reverse second pass",
    "native_run_id":os.environ["GITHUB_RUN_ID"],
    "run_attempt":os.environ.get("GITHUB_RUN_ATTEMPT","1"),
    "runner_os":os.environ.get("RUNNER_OS","unknown"),
    "runner_arch":os.environ.get("RUNNER_ARCH","unknown"),
    "paired_passes":2,
    "order_pass_1":[os.environ["CONTROL_TOPOLOGY_FIRST"],"cpe" if os.environ["CONTROL_TOPOLOGY_FIRST"]=="reference" else "reference"],
    "order_pass_2":["cpe" if os.environ["CONTROL_TOPOLOGY_FIRST"]=="reference" else "reference",os.environ["CONTROL_TOPOLOGY_FIRST"]],
    "arm_replicates":per,
    "one_time_prep":prep,
    "by_arm":by_arm,
    "unique_url_overlap_proxy_count":len(urls_by_arm["reference"]&urls_by_arm["cpe"]),
    "limitations":["upstream rate limits vary","time-of-day drift","one GitHub VM does not prove blinded research","source URL overlap is not independent corroboration"],
}
target=pathlib.Path(os.environ["RUNNER_TEMP"])/"topology-sequential-synthetic-metrics.json"
target.write_text(json.dumps(summary,indent=2,sort_keys=True)+"\n",encoding="utf-8")
print("MCP_GHA_SEQUENTIAL_TOPOLOGY_COUNTERBALANCED_PASS")
print("MCP_GHA_SEQUENTIAL_TOPOLOGY_SUMMARY "+json.dumps({
    "topology":summary["topology"],
    "random_first":summary["first_arm_randomized"],
    "per_arm":summary["by_arm"],
    "per_pass":summary["arm_replicates"],
    "one_time_prep":summary["one_time_prep"],
    "run_attempt":summary["run_attempt"],
    "overlap_url_proxy":summary["unique_url_overlap_proxy_count"],
},sort_keys=True))
with open(os.environ["GITHUB_STEP_SUMMARY"],"a",encoding="utf-8") as f:
    f.write("### MCP GHA single-runner sequential comparator (synthetic only)\n\n")
    f.write("Randomized first arm: **"+summary["first_arm_randomized"]+"**. Second pass reversed. Fresh Docker SearXNG each arm.\n\n")
    f.write("| Arm | Replicates | HTTP attempts | Provider successes | Failures | Hits | Mean wall ms |\n")
    f.write("|---|---:|---:|---:|---:|---:|---:|\n")
    for arm in ("reference","cpe"):
        x=summary["by_arm"][arm]
        f.write(f'| {arm} | {x["runs"]} | {x["attempted"]} | {x["succeeded"]} | {x["failed"]} | {x["retrieved_hits"]} | {x["avg_wall_ms"]} |\n')
    f.write("\nNot scientific CPE validation; source and provider variance uncontrolled. No source URLs or plaintext results uploaded.\n")
PY
