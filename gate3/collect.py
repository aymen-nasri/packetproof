#!/usr/bin/env python3
"""Gate 3: record what Gate 1 and Gate 2 said about one change (the baseline or one fault).

Each gate's result is True (passed), False (failed: the change was caught) or None (the gate could
not judge: a tool, the harness or the runner failed). Under docs/method.md (amendment A2) a None is
never a catch: the fault's result is void and re-run.

Usage: python3 gate3/collect.py --id F07 --gate1 results/gate1.json --gate2 results/gate2.xml \
           --render-status results/render-status.json --deploy build/lab/deploy.json \
           --seconds 412 --out results/F07.json
"""

from __future__ import annotations

import argparse
import json
import xml.etree.ElementTree as ET
from pathlib import Path


def gate2_result(path: Path, deploy: dict | None) -> tuple[bool | None, list[str], int]:
    if deploy is not None and deploy.get("deploy_rc") != 0:
        return None, [f"not judged: the lab did not deploy (containerlab exit {deploy.get('deploy_rc')})"], 0
    if not path.exists():
        return None, ["not judged: no Gate 2 results (the run did not reach the tests)"], 0
    failed, total, errors_only = [], 0, True
    for case in ET.parse(path).getroot().iter("testcase"):
        total += 1
        fail, err = case.find("failure"), case.find("error")
        if fail is not None or err is not None:
            failed.append(f"{case.get('classname', '').split('.')[-1]}::{case.get('name')}")
            errors_only = errors_only and fail is None
        else:
            errors_only = False
    if total == 0:
        return None, ["not judged: Gate 2 ran no tests"], 0
    if failed and errors_only and len(failed) == total:
        return None, ["not judged: every Gate 2 test errored (the harness, not the network)"] + failed, total
    return not failed, failed, total


def gate1_result(path: Path, render: dict | None) -> tuple[bool | None, list[str], list[str]]:
    if render and render.get("result") == "rejected":
        return False, [f"schema:{render.get('detail', 'the intent failed schema or reference validation')}"], []
    if render and render.get("result") == "crashed":
        return None, [f"not judged: {render.get('detail')}"], []
    if not path.exists():
        return None, ["not judged: no Gate 1 results (the job failed before Gate 1 finished)"], []
    data = json.loads(path.read_text())
    failing, tool = [], []
    for c in data["checks"]:
        if not c["ok"]:
            msgs = [f"{c['name']}:{m}" for m in (c["details"] or [""])]
            (tool if c.get("tool_error") else failing).extend(msgs)
    if failing:
        return False, failing, tool          # a real check failed: a catch, whatever else broke
    if tool:
        return None, ["not judged: a Gate 1 tool failed"], tool
    return data["passed"], [], []


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--id", required=True)
    ap.add_argument("--gate1", type=Path, required=True)
    ap.add_argument("--gate2", type=Path, required=True)
    ap.add_argument("--render-status", type=Path)
    ap.add_argument("--deploy", type=Path)
    ap.add_argument("--seconds", type=float)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    render = json.loads(a.render_status.read_text()) if a.render_status and a.render_status.exists() else None
    if render is None:  # render.py writes the file on every outcome; missing means the job broke first
        render = {"result": "crashed", "detail": "no render status (the job failed before rendering finished)"}
    deploy = json.loads(a.deploy.read_text()) if a.deploy and a.deploy.exists() else None
    g1_ok, g1_fail, g1_tool = gate1_result(a.gate1, render)
    if render["result"] != "ok":  # nothing could be deployed, so Gate 2 never ran
        g2_ok, g2_fail, g2_total = None, ["not run: the change did not render"], 0
    else:
        g2_ok, g2_fail, g2_total = gate2_result(a.gate2, deploy)
    out = {"id": a.id, "render": render,
           "gate1": {"passed": g1_ok, "failing": g1_fail, "tool_errors": g1_tool},
           "gate2": {"passed": g2_ok, "failing": g2_fail, "tests": g2_total},
           "deploy": deploy, "seconds": a.seconds}
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(out, indent=2) + "\n")
    print(json.dumps({"id": a.id, "gate1_passed": g1_ok, "gate2_passed": g2_ok,
                      "gate1_failing": len(g1_fail), "gate2_failing": len(g2_fail)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
