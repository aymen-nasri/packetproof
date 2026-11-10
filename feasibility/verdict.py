#!/usr/bin/env python3
"""Apply the feasibility GO rules from docs/method.md to the CI results. Rules only, no tuning.

Usage: python3 feasibility/verdict.py results/ > verdict.md   (also writes results/verdict.json)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

A_LIMIT_S = 300   # test A: deploy plus checks under 5 minutes
D_FULL_S = 900    # test D: full run under 15 minutes
D_FAULT_S = 180   # test D: one planted fault under 3 minutes
RUNS = 5


def load(path: Path) -> dict | None:
    return json.loads(path.read_text()) if path.exists() else None


def main() -> int:
    res = Path(sys.argv[1])
    out: dict = {}
    md = ["# Feasibility checks: verdicts from this run", ""]

    # Test A
    a = [load(res / f"A-run{i}.json") for i in range(1, RUNS + 1)]
    a_ok = [r is not None and r["passed"] and r["timings_s"].get("deploy_plus_checks", 1e9) < A_LIMIT_S for r in a]
    out["A"] = {"go": all(a_ok), "runs_ok": sum(a_ok), "runs": RUNS,
                "deploy_plus_checks_s": [r["timings_s"].get("deploy_plus_checks") if r else None for r in a]}
    md += [f"**Test A (containerlab):** {'GO' if out['A']['go'] else 'NO-GO'}: {sum(a_ok)} of {RUNS} runs passed "
           f"every check under {A_LIMIT_S} s; deploy plus checks (s): {out['A']['deploy_plus_checks_s']}", ""]

    # Test B
    b = load(res / "B.json")
    out["B"] = {"go": bool(b and b.get("go")),
                "criteria": [(c["criterion"], c["ok"]) for c in b["criteria"]] if b else "missing"}
    md += [f"**Test B (Batfish):** {'GO' if out['B']['go'] else 'NO-GO'}"]
    if b:
        md += [f"- {'PASS' if ok else 'FAIL'}: {name}" for name, ok in out["B"]["criteria"]]
    md += [""]

    # Test C: the brief's rule is handshake and BGP up in every run; checks 3-5 are evidence.
    c = [load(res / f"C-run{i}.json") for i in range(1, RUNS + 1)]

    def rule_ok(r: dict | None) -> bool:
        if r is None:
            return False
        core = [x for x in r["checks"] if x["check"].startswith(("wg_handshake", "bgp_established"))]
        return bool(core) and all(x["ok"] for x in core)

    c_ok = [rule_ok(r) for r in c]
    c_all = [r is not None and r["passed"] for r in c]
    out["C"] = {"go": all(c_ok), "rule_runs_ok": sum(c_ok), "all_checks_runs_ok": sum(c_all), "runs": RUNS}
    md += [f"**Test C (WireGuard):** {'GO' if out['C']['go'] else 'NO-GO'}: handshake and BGP up in "
           f"{sum(c_ok)} of {RUNS} runs; all checks including tunnel-only evidence in {sum(c_all)} of {RUNS}", ""]

    # Test D
    d = load(res / "D.json")
    if d:
        full, fault = d.get("full_run_s"), d.get("fault_cycle_s")
        go = full is not None and fault is not None and full < D_FULL_S and fault < D_FAULT_S and d.get("fault_detected")
        out["D"] = {"go": bool(go), "full_run_s": full, "fault_cycle_s": fault, "fault_detected": d.get("fault_detected")}
        md += [f"**Test D (time budget):** {'GO' if go else 'NO-GO'}: full run {full} s (limit {D_FULL_S}), "
               f"one planted fault {fault} s (limit {D_FAULT_S}), fault detected: {d.get('fault_detected')}", ""]
    else:
        out["D"] = {"go": False, "detail": "missing"}
        md += ["**Test D (time budget):** NO-GO: result missing", ""]

    md += ["Test E (local development on Windows) is not a CI test; it is recorded in docs/feasibility.md."]
    (res / "verdict.json").write_text(json.dumps(out, indent=2) + "\n")
    print("\n".join(md))
    return 0 if all(v.get("go") for v in out.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
