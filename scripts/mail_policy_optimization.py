#!/usr/bin/env python3
"""Offline, bounded policy-candidate selection from synthetic mail retrieval traces.

Not an LLM optimizer: demonstrates independent dev/holdout evaluation, negative
controls, versioned candidate lineage and explicit promotion refusal.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import mail_synthetic_baseline as mail

SCHEMA = "public-synthetic-mail-policy-search/v1"
WRAPPERS = {
    "de": "Bitte finde die Nachricht zu ",
    "en": "Please locate the record about ",
    "th": "กรุณาค้นหาข้อความเกี่ยวกับ ",
}
CANDIDATES = (
    ("raw", ()),
    ("en-prefix", ("en",)),
    ("de-prefix", ("de",)),
    ("th-prefix", ("th",)),
    ("multilingual-prefix", ("de", "en", "th")),
)


def with_wrapper(task: dict) -> str:
    return WRAPPERS[task["language"]] + task["query"]


def rewrite(policy_id: str, task: dict) -> str:
    selected = dict(CANDIDATES)
    if policy_id not in selected:
        raise ValueError("UNREVIEWED_POLICY")
    wrapped = with_wrapper(task)
    allowed = selected[policy_id]
    if task["language"] in allowed:
        prefix = WRAPPERS[task["language"]]
        if not wrapped.startswith(prefix):
            raise ValueError("PREFIX_MISMATCH")
        return wrapped[len(prefix):]
    return wrapped


def evaluate(policy_id: str, db, tasks: list[dict]) -> dict:
    correct, wrong, traces = 0, 0, []
    for task in tasks:
        found = mail.retrieve(db, rewrite(policy_id, task), task["tenant"])
        good = bool(found and any(
            f.startswith(task["expected_occurrence_prefix"]) for f in found))
        bad = bool(found and not good)
        correct += int(good)
        wrong += int(bad)
        traces.append({"task_id": task["query_id"], "hit": good,
                       "wrong_evidence": bad})
    return {"hits": correct, "false_evidence": wrong,
            "total": len(tasks), "traces": traces}


def safety_negatives(policy_id: str, db) -> dict:
    # An invented target containing common document words MUST NOT become a
    # confident citation. A second account's record MUST NOT cross its ACL.
    fictional = [
        {"language": lang,
         "tenant": "alpha",
         "query": "Fictional project zebra",
         "expected_occurrence_prefix": "none-"}
        for lang in WRAPPERS]
    violations = 0
    for task in fictional:
        if mail.retrieve(db, rewrite(policy_id, task), task["tenant"]):
            violations += 1
    for language in WRAPPERS:
        denied = {"language": language, "tenant": "alpha",
                  "query": "Private starling ledger"}
        if mail.retrieve(db, rewrite(policy_id, denied), "alpha"):
            violations += 1
    return {"checked": len(fictional) + len(WRAPPERS),
            "violations": violations}


def select_and_evaluate(seed: int = 19) -> dict:
    rows, tasks = mail.build_corpus(seed)
    database = mail.open_index(rows)
    development = [t for t in tasks if t["partition"] == "development"]
    holdout = [t for t in tasks if t["partition"] == "held-out"]
    if set(t["query_id"] for t in development) & set(t["query_id"] for t in holdout):
        raise ValueError("PARTITION_LEAK")
    if len(development) != 6 or len(holdout) != 3:
        raise ValueError("PARTITION_SIZE_UNEXPECTED")

    observed = []
    for policy_id, languages in CANDIDATES:
        dev = evaluate(policy_id, database, development)
        neg = safety_negatives(policy_id, database)
        observed.append({"candidate": policy_id, "dev_hits": dev["hits"],
                         "dev_false_evidence": dev["false_evidence"],
                         "safety_violations": neg["violations"],
                         "complexity": len(languages)})
    ranking = sorted(
        observed, key=lambda p: (p["safety_violations"], p["dev_false_evidence"],
                                  -p["dev_hits"], p["complexity"], p["candidate"]))
    selected = ranking[0]["candidate"]
    baseline = evaluate("raw", database, holdout)
    winning = evaluate(selected, database, holdout)
    negative = safety_negatives(selected, database)
    return {
        "schema": SCHEMA, "source": "fictional-email-observations",
        "candidate_count": len(CANDIDATES),
        "candidate_trace": observed,
        "selected_policy": selected,
        "dev_queries": len(development),
        "holdout_queries": len(holdout),
        "holdout_baseline_hits": baseline["hits"],
        "holdout_selected_hits": winning["hits"],
        "holdout_false_evidence": winning["false_evidence"],
        "safety_negatives": negative,
        "test_family_disjoint": True,
        "model_inference": False,
        "self_modifying_code": False,
        "promoted_to_runtime": False,
        "classification": "SYNTHETIC_POLICY_SELECTION_ONLY",
        "corpus_sha256": mail.benchmark(seed)["corpus_sha256"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--seed", type=int, default=19)
    args = parser.parse_args()
    result = select_and_evaluate(args.seed)
    if args.receipt:
        args.receipt.parent.mkdir(parents=True, exist_ok=True)
        args.receipt.write_bytes(mail.canonical(result))
    print(json.dumps(result, sort_keys=True, ensure_ascii=False))
    return 0 if (
        result["selected_policy"] == "multilingual-prefix"
        and result["holdout_selected_hits"] == 3
        and result["holdout_selected_hits"] > result["holdout_baseline_hits"]
        and result["holdout_false_evidence"] == 0
        and result["safety_negatives"]["violations"] == 0
        and not result["model_inference"]
        and not result["promoted_to_runtime"]
    ) else 2


if __name__ == "__main__":
    raise SystemExit(main())
