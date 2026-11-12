#!/usr/bin/env python3
"""Synthetic three-path same-runner MCP microbenchmark, not full product TCO."""
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

OUT = pathlib.Path("three-path-receipts")
OUT.mkdir(exist_ok=True)
INIT = {"protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "m1-r21-three-path", "version": "1"}}
PATHS = {"direct": ("http://127.0.0.1:39101/mcp", None),
         "agentgateway": ("http://127.0.0.1:39200/mcp", pathlib.Path("runtime-receipts/old-research.jwt")),
         "mcphub": ("http://127.0.0.1:3300/mcp/research", pathlib.Path("ephemeral-token.txt"))}


def send(name, method, i, params=None, session=None):
    url, token_path = PATHS[name]
    data = {"jsonrpc": "2.0", "method": method, "id": i}
    if params is not None:
        data["params"] = params
    h = {"Content-Type": "application/json",
         "Accept": "application/json, text/event-stream",
         "MCP-Protocol-Version": "2025-06-18"}
    if token_path is not None:
        h["Authorization"] = "Bearer " + token_path.read_text().strip()
    if session:
        h["Mcp-Session-Id"] = session
    req = urllib.request.Request(url, data=json.dumps(data).encode(), headers=h)
    start = time.perf_counter_ns()
    with urllib.request.urlopen(req, timeout=8) as resp:
        raw = resp.read().decode()
        if "text/event-stream" in resp.headers.get("Content-Type", ""):
            frames = [line[5:] for line in raw.splitlines() if line.startswith("data:")]
            if not frames:
                raise AssertionError("empty-SSE")
            raw = frames[-1]
        obj = json.loads(raw)
        elapsed = (time.perf_counter_ns() - start) / 1e6
        if resp.status != 200 or "error" in obj:
            raise AssertionError(name + "-jsonrpc-error")
        if method == "tools/call":
            body = obj.get("result", {})
            if body.get("isError") or "alpha:perf" not in json.dumps(body):
                raise AssertionError(name + "-wrong-tool-result")
        return elapsed, obj, resp.headers.get("Mcp-Session-Id") or session


def pct(a, q):
    v = sorted(a)
    return v[min(len(v)-1, int((len(v)-1) * q))]


def summary(a):
    return {"n": len(a), "p50_ms": round(statistics.median(a), 4),
            "p95_ms": round(pct(a, .95), 4), "mean_ms": round(statistics.mean(a), 4)}


def bootstrap(a, seed=20261112):
    rng = random.Random(seed)
    out = [statistics.median(rng.choices(a, k=len(a))) for _ in range(400)]
    return [round(pct(out, .025), 4), round(pct(out, .975), 4)]


def docker_stats():
    try:
        raw = subprocess.check_output(["docker", "stats", "--no-stream",
                "--format", "{{json .}}", "supra-r21-three-gateway",
                "m1-three-hub"], timeout=15, text=True)
        return [json.loads(line) for line in raw.splitlines() if line.startswith("{")]
    except (OSError, ValueError, subprocess.SubprocessError):
        return [{"status": "unavailable"}]


def main():
    receipt = {"schema": "m1-three-path-matched-synthetic-g3-v1",
               "passed": False, "architecture": platform.machine(),
               "candidates": ["direct", "agentgateway", "mcphub"],
               "limits": ["synthetic 2025 protocol, not real ChatGPT/Gemini or model traffic",
                 "Agentgateway includes runtime data plane but NOT production GitOps manager, IdP, audit",
                 "MCPHub includes saved-group management but NOT external per-login policy authority",
                 "different route lengths, credentials and container networking affect measurements",
                 "point-in-time docker stats not sustained RAM/CPU measurements",
                 "same free public GHA runner, not production target or complete SLO/TCO",
                 "no live OAuth/workset grants; cannot select final G6 product"]}

    try:
        sessions, tools = {}, {}
        for name in PATHS:
            init = send(name, "initialize", 1, INIT)
            sessions[name] = init[2]
            if "result" not in init[1]:
                raise AssertionError(name + "-init-failed")
            for retry in range(20):
                listed = send(name, "tools/list", 2+retry, session=sessions[name])[1]
                names = [tool["name"] for tool in listed.get("result", {}).get("tools", [])]
                if len(names) == 1:
                    tools[name] = names[0]
                    break
                time.sleep(.4)
            if name not in tools:
                raise AssertionError(name + "-tool-discovery-timeout")
        if tools["direct"] != "echo" or tools["agentgateway"] != "alpha_echo" or not tools["mcphub"].startswith("alpha-"):
            raise AssertionError("non-equivalent-selected-tool-sources")
        receipt["tool_source_qualified"] = {k: "alpha" for k in PATHS}

        def call(name, i):
            return send(name, "tools/call", i,
                 {"name": tools[name], "arguments": {"text": "perf"}}, session=sessions[name])[0]

        for i in range(8):
            for name in PATHS:
                call(name, i + 100)
        rng = random.Random(21121)
        durations = {k: [] for k in PATHS}
        order_histogram = {}
        for i in range(60):
            order = list(PATHS)
            rng.shuffle(order)
            k = ">".join(order)
            order_histogram[k] = order_histogram.get(k, 0) + 1
            for name in order:
                durations[name].append(call(name, 1000+i))
        receipt["paired_tool_call"] = {
            "triplets": 60, "warmups_per_path": 8, "order_counts": order_histogram,
            "latencies": {k: summary(v) for k, v in durations.items()}}
        d = durations["direct"]
        for name in ("agentgateway", "mcphub"):
            delta = [x-y for x, y in zip(durations[name], d)]
            receipt["paired_tool_call"][name+"_minus_direct"] = {
                "median_ms": round(statistics.median(delta), 4),
                "bootstrap_median_delta_95pct_ms": bootstrap(delta)}
        delta = [x-y for x, y in zip(durations["mcphub"], durations["agentgateway"])]
        receipt["paired_tool_call"]["mcphub_minus_agentgateway"] = {
            "median_ms": round(statistics.median(delta), 4),
            "bootstrap_median_delta_95pct_ms": bootstrap(delta)}

        # ABCCBA to limit one-direction order bias; all calls validated.
        sweeps = {k: [] for k in PATHS}
        for name in ("direct", "agentgateway", "mcphub", "mcphub", "agentgateway", "direct"):
            begin = time.perf_counter_ns()
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                done = list(executor.map(lambda i: call(name, 20000+i), range(80)))
            seconds = (time.perf_counter_ns() - begin) / 1e9
            if len(done) != 80:
                raise AssertionError("incomplete-throughput")
            sweeps[name].append(round(80/seconds, 3))
        receipt["qps_4_workers_two_sweeps"] = sweeps
        receipt["docker_point_in_time_stats"] = docker_stats()
        receipt["passed"] = True
    except Exception as e:
        receipt["error"] = repr(e)[:600]
    (OUT/"three-path.json").write_text(json.dumps(receipt, sort_keys=True, indent=2)+"\n")
    print(json.dumps(receipt, sort_keys=True, indent=2))
    return 0 if receipt["passed"] else 1

if __name__ == "__main__":
    sys.exit(main())
