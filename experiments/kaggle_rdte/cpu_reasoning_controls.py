#!/usr/bin/env python3
"""Public-safe CPU falsification fixture for reasoning-task and CoT evaluation.

This validates test-generation and independent oracles; it does NOT evaluate
a language model, prove chain-of-thought improvements, or use private holdouts.
"""
import hashlib
import json
import random

def tasks(seed=20261013, count=256):
    rng=random.Random(seed)
    for index in range(count):
        a,b,c=[rng.randint(-50,50) for _ in range(3)]
        # Two equivalent evaluation presentations of an arithmetic expression.
        expression=f"({a} + {b}) - {c}"
        expected=(a+b)-c
        yield {"id":index,"expression":expression,"values":[a,b,c],
               "expected":expected,
               "trace":[a+b,expected]}

def evaluate(items):
    rows=list(items)
    assert rows and len({r["id"] for r in rows})==len(rows)
    exact=sum((r["values"][0]+r["values"][1]-r["values"][2])==
              r["expected"] for r in rows)
    trace=sum(r["trace"]==[r["values"][0]+r["values"][1],
                           r["expected"]] for r in rows)
    # One adversarial test: flip each correct final answer by a known offset.
    wrong=sum((r["expected"]+1)!=r["expected"] for r in rows)
    # Another: preserve final answer but corrupt the intermediate step.
    corrupted=sum([r["trace"][0]+1,r["expected"]]!=r["trace"] for r in rows)
    assert exact==trace==wrong==corrupted==len(rows)
    canonical=json.dumps(rows,sort_keys=True,separators=(",",":")).encode()
    return {"schema":"reasoning-cpu-oracles/v1","tasks":len(rows),
            "exact_answer_cases":exact,"trace_valid_cases":trace,
            "wrong_answer_rejected":wrong,"corrupted_trace_rejected":corrupted,
            "fixture_sha256":hashlib.sha256(canonical).hexdigest(),
            "model_inference_performed":False,
            "scientific_claim":"harness-fixtures-only"}

if __name__=="__main__":
    print(json.dumps(evaluate(tasks()),sort_keys=True))
