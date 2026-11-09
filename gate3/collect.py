#!/usr/bin/env python3
"""Gate 3: record what Gate 1 and Gate 2 said about one change (the baseline or one fault).

Usage: python3 gate3/collect.py --id F07 --gate1 results/gate1.json --gate2 results/gate2.xml \
           --deploy build/lab/deploy.json --seconds 412 --out results/F07.json
"""

from __future__ import annotations

import argparse
import json
import xml.etree.ElementTree as ET
from pathlib import Path


def gate2_failures(path: Path) -> tuple[bool, list[str], int]:
    if not path.exists():
        return False, ["no Gate 2 results (the run did not reach the tests)"], 0
    failed, total = [], 0
    for case in ET.parse(path).getroot().iter("testcase"):
        total += 1
        if case.find("failure") is not None or case.find("error") is not None:
            failed.append(f"{case.get('classname', '').split('.')[-1]}::{case.get('name')}")
    return not failed and total > 0, failed, total


def gate1_failures(path: Path) -> tuple[bool, list[str]]:
    if not path.exists():
        return False, ["no Gate 1 results (rendering failed: schema or reference error)"]
    data = json.loads(path.read_text())
    failing = []
    for c in data["checks"]:
        if not c["ok"]:
            msgs = c["details"] or [""]
            failing += [f"{c['name']}:{m}" for m in msgs]
    return data["passed"], failing


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--id", required=True)
    ap.add_argument("--gate1", type=Path, required=True)
    ap.add_argument("--gate2", type=Path, required=True)
    ap.add_argument("--deploy", type=Path)
    ap.add_argument("--render-failed", action="store_true")
    ap.add_argument("--seconds", type=float)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    g1_ok, g1_fail = gate1_failures(a.gate1)
    if a.render_failed:
        g1_ok, g1_fail = False, ["schema:network.yaml failed schema or reference validation"]
    g2_ok, g2_fail, g2_total = gate2_failures(a.gate2)
    deploy = json.loads(a.deploy.read_text()) if a.deploy and a.deploy.exists() else None
    out = {"id": a.id, "gate1": {"passed": g1_ok, "failing": g1_fail},
           "gate2": {"passed": g2_ok, "failing": g2_fail, "tests": g2_total},
           "deploy": deploy, "seconds": a.seconds}
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(out, indent=2) + "\n")
    print(json.dumps({"id": a.id, "gate1_passed": g1_ok, "gate2_passed": g2_ok,
                      "gate1_failing": len(g1_fail), "gate2_failing": len(g2_fail)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
