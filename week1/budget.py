#!/usr/bin/env python3
"""Test D: write results/D.json from the clock files and the fault-cycle results.

Usage: python3 week1/budget.py --t0 F --t1 F --fault-start F --fault-end F --results results/
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

LEAK = "172.16.255.1/32"


def read_time(path: Path) -> float:
    return float(path.read_text().strip())


def main() -> None:
    ap = argparse.ArgumentParser()
    for name in ("t0", "t1", "fault-start", "fault-end"):
        ap.add_argument(f"--{name}", type=Path, required=True)
    ap.add_argument("--results", type=Path, required=True)
    a = ap.parse_args()

    lab = json.loads((a.results / "D-fault-lab.json").read_text())
    leak_check = next((c for c in lab["checks"] if c["check"] == "private_prefixes_exact:isp"), None)
    live_detected = bool(leak_check and not leak_check["ok"] and LEAK in leak_check["detail"].get("extra", []))
    bf_path = a.results / "D-fault-batfish.json"
    bf = json.loads(bf_path.read_text()) if bf_path.exists() else {}
    full_lab = json.loads((a.results / "D-full-lab.json").read_text())

    out = {
        "full_run_s": round(read_time(a.t1) - read_time(a.t0), 1),
        "fault_cycle_s": round(read_time(a.fault_end) - read_time(a.fault_start), 1),
        # Test D needs the live checks to report the leak; Batfish's answer is recorded too.
        "fault_detected": live_detected,
        "fault_detected_by_batfish": bf.get("leak_seen"),
        "full_run_lab_passed": full_lab.get("passed"),
        "fault_lab_timings_s": lab.get("timings_s"),
    }
    (a.results / "D.json").write_text(json.dumps(out, indent=2) + "\n")
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
