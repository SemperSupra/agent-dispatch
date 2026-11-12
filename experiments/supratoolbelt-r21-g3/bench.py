#!/usr/bin/env python3
"""Paired live MCP transport benchmark: direct upstream vs actual Agentgateway.

Public-safe synthetic fixture. Measures this runner only; no production SLA or
complete-stack vendor comparison. Randomized AB/BA pairs and a concurrent sweep.
"""
import concurrent.futures
import json
import pathlib
import platform
import random
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = pathlib.Path("runtime-receipts")
ROOT.mkdir(exist_ok=True)
VERSION = "2025-06-18"
INIT = {"protocolVersion": VERSION, "capabilities": {},
        "clientInfo": {"name": "m1-paired-g3", "version": "1"}}


def request(port, method, idx, tool=None, token=None, session=None):
    payload = {"jsonrpc": "2.0", "id": idx, "method": method}
    if method == "initialize":
        payload["params"] = INIT
    elif method == "tools/call":
        payload["params"] = {"name": tool, "arguments": {"text": "perf"}}
    headers = {"Content-Type": "application/json",
               "Accept": "application/json, text/event-stream",
               "MCP-Protocol-Version": VERSION}
    if token:
        headers["Authorization"] = "Bearer " + token
    if session:
        headers["Mcp-Session-Id"] = session
    req = urllib.request.Request("http://127.0.0.1:" + str(port) + "/mcp",
          data=json.dumps(payload, separators=(",", ":")).encode(), headers=headers)
    started = time.perf_counter_ns()
    with urllib.request.urlopen(req, timeout=6) as response:
        raw = response.read().decode()
        if "text/event-stream" in response.headers.get("Content-Type", ""):
            rows = [line[5:] for line in raw.splitlines() if line.startswith("data:")]
            if not rows:
                raise ValueError("empty-SSE")
            raw = rows[-1]
        data = json.loads(raw)
        duration_ms = (time.perf_counter_ns() - started) / 1_000_000
        if response.status != 200 or "error" in data:
            raise AssertionError("remote-error")
        if method == "tools/call":
            result = data.get("result", {})
            if result.get("isError") or "alpha:perf" not in json.dumps(result):
                raise AssertionError("wrong-or-denied-synthetic-result")
        return duration_ms, data, response.headers.get("Mcp-Session-Id") or session


def percentile(data, pct):
    ordered = sorted(data)
    if not ordered:
        raise ValueError("no-samples")
    return ordered[min(len(ordered) - 1, max(0, int((len(ordered) - 1) * pct)))]


def describe(data):
    return {"count": len(data), "mean_ms": round(statistics.mean(data), 4),
            "p50_ms": round(statistics.median(data), 4),
            "p95_ms": round(percentile(data, .95), 4)}


def bootstrap_interval(differences, seed=21017):
    rng = random.Random(seed)
    samples = []
    for _ in range(400):
        subset = rng.choices(differences, k=len(differences))
        samples.append(statistics.median(subset))
    return [round(percentile(samples, .025), 4), round(percentile(samples, .975), 4)]


def one_side(name, idx, token, session):
    if name == "direct":
        return request(39101, "tools/call", idx, "echo")
    return request(39200, "tools/call", idx, "alpha_echo", token, session)


def throughput(name, token, session, workers=4, calls=80):
    start = time.perf_counter_ns()
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        result = list(pool.map(lambda i: one_side(name, 10000 + i, token, session), range(calls)))
    elapsed = (time.perf_counter_ns() - start) / 1_000_000_000
    if len(result) != calls:
        raise AssertionError("throughput-missing-results")
    return {"workers": workers, "successful_calls": calls,
            "elapsed_s": round(elapsed, 4), "observed_qps": round(calls / elapsed, 3)}


def resource_snapshot():
    try:
        raw = subprocess.check_output(["docker", "stats", "--no-stream", "--format",
                                       "{{json .}}", "supra-r21-g3"], timeout=10, text=True)
        return json.loads(raw.strip())
    except (OSError, subprocess.SubprocessError, ValueError):
        return {"status": "unavailable"}


def main():
    receipt = {"schema": "m1-g3-paired-live-synthetic-v1",
               "provenance": {"gateway_oci_sha256": "60216aafb03d37f94e952ff3d51d2f630a65b10ecaebdc0a864882f92610c45b",
                              "client_protocol": VERSION, "architecture": platform.machine(),
                              "runner": "free-public-github-actions",
                              "seed": 17, "warmup_per_path": 8},
               "limits": ["one real gateway vs direct upstream only; MCPHub/Obot not benchmarked",
                          "synthetic local MCP, no OAuth/real provider/tenant or model inference",
                          "synthetic P-256 JWT, not a native workset or audited production operation",
                          "single disposable GHA runner results; not an OCI/ARM host SLA",
                          "docker-stats point sample is NOT an interval CPU/memory benchmark"],
               "passed": False}
    try:
        token = (ROOT / "old-research.jwt").read_text()
        direct_init = request(39101, "initialize", 1)
        gateway_init = request(39200, "initialize", 2, token=token)
        direct_session = direct_init[2]
        gateway_session = gateway_init[2]
        tools_direct = request(39101, "tools/list", 3, session=direct_session)[1]["result"]["tools"]
        tools_gateway = request(39200, "tools/list", 4, token=token, session=gateway_session)[1]["result"]["tools"]
        if [t["name"] for t in tools_direct] != ["echo"] or [t["name"] for t in tools_gateway] != ["alpha_echo"]:
            raise AssertionError("incompatible-workload-routing")
        for i in range(8):
            one_side("direct", 30 + i, token, direct_session)
            one_side("gateway", 40 + i, token, gateway_session)
        pairs = []
        order_counts = {"direct_first": 0, "gateway_first": 0}
        rng = random.Random(17)
        for i in range(80):
            order = ("gateway", "direct") if rng.random() < 0.5 else ("direct", "gateway")
            order_counts[order[0] + "_first"] += 1
            sample = {}
            for name in order:
                sample[name] = one_side(name, 100 + i, token,
                                        direct_session if name == "direct" else gateway_session)[0]
            pairs.append(sample)
        d = [p["direct"] for p in pairs]
        g = [p["gateway"] for p in pairs]
        delta = [p["gateway"] - p["direct"] for p in pairs]
        receipt["paired_latency"] = {
            "workload": "single synthetic echo tools/call each path",
            "direct": describe(d), "agentgateway": describe(g),
            "median_added_ms": round(statistics.median(delta), 4),
            "bootstrap_95pct_median_delta_ms": bootstrap_interval(delta),
            "actual_pairs": len(pairs),
            "randomized_order_counts": order_counts}
        # Sequential A/B test first, then reverse order for throughput.
        t1 = throughput("gateway", token, gateway_session)
        t2 = throughput("direct", token, direct_session)
        receipt["four_concurrent_worker_sweep"] = {"agentgateway": t1, "direct": t2,
              "note": "Non-simultaneous same-runner sweeps. CPU noise and order effects remain."}
        receipt["gateway_point_in_time_stats"] = resource_snapshot()
        receipt["passed"] = True
    except Exception as e:
        receipt["error"] = repr(e)[:600]
    (ROOT / "g3-paired-receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if receipt["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
