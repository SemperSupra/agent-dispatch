#!/usr/bin/env python3
"""Render the independent machine verdict without changing its acceptance rules."""
import argparse
import html
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.input.exists():
        phase = json.loads(Path(__file__).with_name("campaign.json").read_text())["phase"]
        if phase == "discovery":
            print("Discovery phase: no candidate compatibility verdict exists yet.")
            return
        raise ValueError("Validation evidence is missing")
    d = json.loads(args.input.read_text(encoding="utf-8"))
    e = html.escape
    page = """<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Windows and Wine reconstruction — independent results</title><style>
:root{color-scheme:light dark}body{font:1rem/1.55 system-ui,sans-serif;margin:auto;padding:1.5rem;max-width:90rem}
h1{line-height:1.2}a{color:LinkText}a:focus-visible,summary:focus-visible,[tabindex]:focus-visible{outline:3px solid Highlight;outline-offset:4px}
table{border-collapse:collapse;width:100%;margin:1rem 0}th,td{border:1px solid GrayText;padding:.7rem;text-align:left;vertical-align:top}
caption{text-align:left;font-weight:bold}pre,code{white-space:pre-wrap;overflow-wrap:anywhere;font-size:.9rem}summary{cursor:pointer;padding:.7rem}
.scroll{overflow:auto}.notice{border:2px solid CanvasText;padding:1rem}dt{font-weight:bold}dd{margin:0 0 1rem}
</style><main><h1>Windows and Wine reconstruction</h1>"""
    page += "<p>The same released Windows executable and the same reconstructed executable are compared on both systems. This report presents the independent verifier's complete result.</p>"
    page += f"<p class='notice'>Strict whole-matrix result: <strong>{e(d.get('classification', 'UNAVAILABLE'))}</strong>. A difference remains a difference even when it is intentional or originates in the operating system.</p>"
    if "error" in d:
        page += f"<h2>Evidence problem</h2><pre>{e(str(d['error']))}</pre>"
    page += "<p><a href='validation-report.json'>Complete validation JSON</a> · <a href='sensor-coverage.json'>Sensor coverage and limits</a> · <a href='validation-summary.md'>Text summary</a></p>"
    page += f"<p>Frozen corpus: {d.get('case_count', 0)} cases, including {d.get('primary_case_count', 0)} primary cases and {d.get('challenge_case_count', 0)} explicit binary and encoding challenges. Every challenge remains in the result.</p>"
    page += "<h2>Four comparisons</h2><div class='scroll' role='region' aria-label='Four-way comparison table' tabindex='0'><table><caption>Reconstruction conformance and platform differences are separate comparisons</caption><thead><tr><th scope='col'>Comparison</th><th scope='col'>Behavior matches</th><th scope='col'>Fully accepted cases</th><th scope='col'>All primary cases accepted</th><th scope='col'>All challenges accepted</th></tr></thead><tbody>"
    for c in d.get("comparisons", []):
        total = c.get("case_count", d.get("case_count", 0))
        page += f"<tr><th scope='row'>{e(c['name'])}</th><td>{c['behavior_matches']}/{total}</td><td>{c['accepted_cases']}/{total}</td><td>{'Yes' if c['primary_contract_accepted'] else 'No'}</td><td>{'Yes' if c['challenge_contract_accepted'] else 'No'}</td></tr>"
    page += "</tbody></table></div><p>Behavior comparison includes exit status, stdout, diagnostic content and persistent file effects. Only the declared diagnostic program-name prefix is normalized; raw bytes remain available. Accepted cases additionally require complete and consistent observation evidence.</p>"
    page += "<h2>Controls and sensor coverage</h2><dl>"
    for key, title in (("negative_controls", "Deliberately corrupted output and image identity"),
                       ("actuators", "Real-program breakpoint, early abort and recovery"),
                       ("observer_controls", "Separate synthetic timeout, output limit and unhandled exception")):
        value = d.get(key, {}).get("accepted")
        page += f"<dt>{title}</dt><dd>{'Passed' if value is True else 'Not qualified'}</dd>"
    page += "</dl><p>These controls are separate from the 30 program cases. Full-stack observability, descendant containment and every upstream command option are not established by this exercise.</p>"
    for platform, coverage in d.get("sensor_coverage", {}).get("platforms", {}).items():
        page += f"<h3>{e(platform)} process I/O counters</h3><ul>"
        for label, count in coverage.get("counts", {}).items():
            page += f"<li>{e(label.replace('_', ' '))}: {count} observations</li>"
        page += "</ul>"
    page += "<p>An API returning success does not establish meaningful counter values. Zero totals despite independently observed file or stream effects are explicitly unqualified. Persistent file snapshots establish final effects, not every intermediate write or syscall.</p>"
    page += "<h2>Every nonpassing case</h2>"
    mismatches = 0
    for comparison in d.get("comparisons", []):
        for case in comparison.get("cases", []):
            if case.get("accepted") is True:
                continue
            mismatches += 1
            identifier = case.get("id", case.get("case", "case"))
            page += f"<details><summary>{e(comparison['name'])}: {e(str(identifier))} — {e(case.get('classification', 'UNAVAILABLE'))}</summary><pre>{e(json.dumps(case, ensure_ascii=False, indent=2))}</pre></details>"
    if not mismatches:
        page += "<p>No nonpassing case rows were reported. Inspect control and global evidence status before drawing a conclusion.</p>"
    page += f"<h2>Immutable identities</h2><pre>{e(json.dumps({k: d.get(k) for k in ('case_manifest_sha256','frozen_at_utc','target_sha256','candidate_sha256','report_input_sha256')},indent=2))}</pre>"
    page += "<h2>Interface scope</h2><p>This static report uses semantic headings, native disclosure controls, table headers, keyboard-scrollable regions, system colors and visible focus. Actual browser and assistive-technology acceptance remains a separate qualification; this report makes no such claim.</p></main></html>"
    args.output.write_bytes(page.encode("utf-8"))


if __name__ == "__main__":
    main()
