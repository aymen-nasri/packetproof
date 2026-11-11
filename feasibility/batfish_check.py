#!/usr/bin/env python3
"""Test B: can Batfish read the generated FRR configs? (docs/method.md, part 1)

Loads the rendered Cumulus-style snapshots into a running Batfish service and applies the
five GO criteria. The feas-wg snapshot (B2) is recorded but never changes the verdict.

Usage:
  python3 feasibility/batfish_check.py --baseline build/feas-bgp/batfish --fault build/feas-bgp-FEAS-F/batfish \
      --wg build/feas-wg/batfish --out results/B.json [--evidence DIR] [--routes-only]

--routes-only asks only the routes question of the fault snapshot (used by the time-budget test).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import pandas as pd
from pybatfish.client.session import Session

USED_FEATURE_WORDS = ("bgp", "neighbor", "prefix-list", "prefix list", "route-map", "route map",
                      "interface", "address", "ip route", "static")
LEAK = "172.16.255.1/32"


def connect(host: str, timeout_s: int = 240) -> Session:
    start = time.monotonic()
    while True:
        try:
            bf = Session(host=host)
            bf.set_network("packetproof-feas")
            return bf
        except Exception as exc:  # the service takes a while to start
            if time.monotonic() - start > timeout_s:
                raise SystemExit(f"Batfish not reachable after {timeout_s}s: {exc}")
            time.sleep(5)


def frame(bf: Session, question) -> pd.DataFrame:
    return question.answer().frame()


def records(df: pd.DataFrame) -> list[dict]:
    return json.loads(df.astype(str).to_json(orient="records"))


def isp_networks(bf: Session) -> list[str]:
    df = frame(bf, bf.q.routes(nodes="isp"))
    return sorted(set(df["Network"].astype(str)))


def full_questions(bf: Session, snapshot: Path, name: str) -> dict:
    bf.init_snapshot(str(snapshot), name=name, overwrite=True)
    return {
        "fileParseStatus": records(frame(bf, bf.q.fileParseStatus())),
        "parseWarning": records(frame(bf, bf.q.parseWarning())),
        "initIssues": records(frame(bf, bf.q.initIssues())),
        "bgpSessionCompatibility": records(frame(bf, bf.q.bgpSessionCompatibility())),
        "bgpSessionStatus": records(frame(bf, bf.q.bgpSessionStatus())),
    }


def judge(base: dict, base_isp: list[str], fault_isp: list[str]) -> list[dict]:
    crit = []
    statuses = {r["File_Name"]: r["Status"] for r in base["fileParseStatus"]}
    crit.append({"criterion": "1 every file PASSED", "ok": bool(statuses) and all(s == "PASSED" for s in statuses.values()),
                 "detail": statuses})
    crit.append({"criterion": "2 zero parse warnings", "ok": len(base["parseWarning"]) == 0,
                 "detail": base["parseWarning"]})
    used = [i for i in base["initIssues"]
            if any(w in (i.get("Details", "") + " " + i.get("Line_Text", "")).lower() for w in USED_FEATURE_WORDS)]
    crit.append({"criterion": "3 no init issue on a used feature", "ok": not used,
                 "detail": {"on_used_features": used, "all_init_issues": base["initIssues"]}})
    compat = [r.get("Configured_Status") for r in base["bgpSessionCompatibility"]]
    status = [r.get("Established_Status") for r in base["bgpSessionStatus"]]
    crit.append({"criterion": "4 every session UNIQUE_MATCH and ESTABLISHED",
                 "ok": bool(compat) and all(c == "UNIQUE_MATCH" for c in compat)
                 and bool(status) and all(s == "ESTABLISHED" for s in status),
                 "detail": {"configured_status": compat, "established_status": status}})
    crit.append({"criterion": "5 planted error FEAS-F changes the answer (leak appears on isp)",
                 "ok": LEAK in fault_isp and LEAK not in base_isp,
                 "detail": {"baseline_isp_routes": base_isp, "fault_isp_routes": fault_isp}})
    return crit


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="localhost")
    ap.add_argument("--baseline", type=Path)
    ap.add_argument("--fault", type=Path)
    ap.add_argument("--wg", type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--routes-only", action="store_true")
    args = ap.parse_args()

    bf = connect(args.host)
    result: dict = {"pybatfish": __import__("pybatfish").__version__}
    try:
        result["batfish_version"] = bf.get_component_versions()
    except Exception as exc:  # informational only
        result["batfish_version"] = f"unknown: {exc}"

    if args.routes_only:
        bf.init_snapshot(str(args.fault), name="fault", overwrite=True)
        fault_isp = isp_networks(bf)
        result.update({"fault_isp_routes": fault_isp, "leak_seen": LEAK in fault_isp})
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2) + "\n")
        print(f"routes-only: leak_seen={result['leak_seen']}")
        return 0 if result["leak_seen"] else 1

    base = full_questions(bf, args.baseline, "baseline")
    base_isp = isp_networks(bf)
    fault_isp: list[str] = []
    if args.fault:
        bf.init_snapshot(str(args.fault), name="fault", overwrite=True)
        fault_isp = isp_networks(bf)
    result["baseline"] = base
    result["criteria"] = judge(base, base_isp, fault_isp)
    result["go"] = all(c["ok"] for c in result["criteria"])
    if args.wg:  # B2: recorded, not judged
        result["b2_wg_snapshot"] = full_questions(bf, args.wg, "wg")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, default=str) + "\n")
    for c in result["criteria"]:
        print(f"{'PASS' if c['ok'] else 'FAIL'}  {c['criterion']}")
    if "b2_wg_snapshot" in result:
        b2 = result["b2_wg_snapshot"]
        print("B2 (not judged): parse", [r["Status"] for r in b2["fileParseStatus"]],
              "| sessions", [(r.get("Node"), r.get("Remote_Node"), r.get("Configured_Status")) for r in b2["bgpSessionCompatibility"]],
              "| init issues", len(b2["initIssues"]))
    print(f"test B go={result['go']}")
    return 0 if result["go"] else 1


if __name__ == "__main__":
    sys.exit(main())
