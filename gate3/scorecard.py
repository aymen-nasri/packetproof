#!/usr/bin/env python3
"""Gate 3: grade the gates. Applies docs/method.md, part 6, to one Gate 3 run.

  caught      the gate failed on the fault while the baseline passed in the same run
  related     at least one failing check relates to the fault's layer (gate3/related.yaml);
              otherwise the catch is "incidental", and reported separately from the headline
  escaped     both gates passed on the fault
  void        the baseline failed, or a gate could not judge the fault (a tool, the harness or
              the runner failed: amendment A2), so the fault is re-run, never counted as a catch

Attack paths come from the baseline's Gate 2 run (tests/live/test_attacks.py): each test fails if
its attack gets through or if its legitimate pair fails, and the failure message says which.

Usage: python3 gate3/scorecard.py --results DIR --run-url URL --out site/
"""

from __future__ import annotations

import argparse
import html
import json
import statistics
import xml.etree.ElementTree as ET
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
FAULTS = {f["id"]: f for f in yaml.safe_load((ROOT / "faults" / "faults.yaml").read_text())}
RELATED = yaml.safe_load((ROOT / "gate3" / "related.yaml").read_text())
AP_NAMES = {
    "test_ap01_scan_db_zone": "AP-01 port scan of the DB zone",
    "test_ap02_direct_db_connection": "AP-02 direct database connection",
    "test_ap03_lateral_ssh_to_app": "AP-03 lateral SSH to the app servers",
    "test_ap04_scan_lan_a": "AP-04 scan of the LAN-A user zone",
    "test_ap05_ssh_to_router_dmz_gateway": "AP-05 SSH to rtr-a's DMZ gateway",
    "test_ap06_ssh_to_router_other_addresses": "AP-06 SSH to rtr-a's other addresses",
    "test_ap07_ssh_to_rtr_b_across_tunnel": "AP-07 SSH to rtr-b across the tunnel",
    "test_ap08_scan_lan_b_across_tunnel": "AP-08 scan of LAN-B across the tunnel",
    "test_ap09_outbound_to_outside": "AP-09 new connections to the outside",
    "test_ap10_dns_exfiltration_through_resolver": "AP-10 data hidden in DNS names via the resolver",
    "test_ap11_dns_direct_to_outside": "AP-11 DNS straight to the outside",
    "test_ap12_spoofed_source_into_db": "AP-12 spoofed source into the DB",
}


def is_related(layer: str, gate: str, failing: list[str]) -> bool:
    for f in failing:
        for pattern in RELATED.get(layer, {}).get(gate, []):
            if gate == "gate1":
                check, _, prefix = pattern.partition(":")
                name, _, msg = f.partition(":")
                if name == check and msg.startswith(prefix):
                    return True
            elif f.startswith(pattern):
                return True
    return False


# Each attack path's legitimate pair, as docs/method.md part 5 defines it.
AP_PAIRS = {
    "AP-01": "app1 connects to db 5432", "AP-02": "app2 connects to db 5432",
    "AP-03": "admin connects to app1 on 22", "AP-04": "client-a gets HTTPS from haproxy",
    "AP-05": "admin reaches rtr-a on 22", "AP-06": "admin reaches 172.16.255.1 on 22",
    "AP-07": "admin reaches rtr-b on 22 across the tunnel",
    "AP-08": "client-b gets HTTPS from haproxy across the tunnel",
    "AP-09": "client-a reaches the outside on 443 through NAT",
    "AP-10": "client-a resolves a name through the resolver, and the outside server logs it",
    "AP-11": "the resolver's own query to the outside is answered",
    "AP-12": "real app1 connects to db 5432",
}


def attack_paths(junit: Path) -> list[dict]:
    """Verdicts of the 12 attack paths from the baseline's Gate 2 run. Raises when the file is
    missing or does not hold all 12: "0 of 0 blocked" must never be published."""
    if not junit.exists():
        raise SystemExit(f"no baseline Gate 2 results at {junit}: attack paths cannot be scored")
    out = []
    for case in ET.parse(junit).getroot().iter("testcase"):
        name = case.get("name")
        if name in AP_NAMES:
            fail, err = case.find("failure"), case.find("error")
            if fail is None and err is None:
                verdict, why = "blocked", "attack blocked and legitimate pair passed"
            else:
                el = fail if fail is not None else err
                msg = (el.get("message") or "").splitlines()[0][:300] if (el.get("message") or "") else ""
                if "legitimate pair failed" in msg:
                    verdict = "invalid"
                elif fail is None or "did not run" in msg or "RuntimeError" in msg:
                    verdict = "not run"
                else:
                    verdict = "open"
                why = msg
            ap_id = AP_NAMES[name][:5]
            out.append({"id": ap_id, "name": AP_NAMES[name], "legitimate_pair": AP_PAIRS[ap_id],
                        "verdict": verdict, "detail": why})
    if len(out) != len(AP_NAMES):
        raise SystemExit(f"the baseline ran {len(out)} of {len(AP_NAMES)} attack paths")
    return sorted(out, key=lambda x: x["id"])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", type=Path, required=True)
    ap.add_argument("--run-url", default="")
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()

    base = json.loads((a.results / "baseline.json").read_text())
    baseline_ok = base["gate1"]["passed"] and base["gate2"]["passed"]
    rows = []
    for fid, fault in FAULTS.items():
        path = a.results / f"{fid}.json"
        r = json.loads(path.read_text()) if path.exists() else None
        row = {"id": fid, "layer": fault["layer"], "where": fault["where"], "title": fault["title"],
               "predicted": fault["predicted"]}
        if r is None:
            row.update(verdict="missing")
        elif not baseline_ok:
            row.update(verdict="void", reason="the baseline failed in this run")
        elif r["gate1"]["passed"] is None or (r["gate1"]["passed"] is True and r["gate2"]["passed"] is None):
            # A gate that could not judge is never a catch (amendment A2). Gate 1 failing for real
            # is a catch whatever Gate 2 did; otherwise both gates must have judged.
            why = r["gate1"]["failing"] if r["gate1"]["passed"] is None else r["gate2"]["failing"]
            row.update(verdict="void", reason="a gate could not judge this fault: " + "; ".join(why[:3]),
                       gate1_tool_errors=r["gate1"].get("tool_errors", []))
        else:
            g1, g2 = r["gate1"]["passed"] is False, r["gate2"]["passed"] is False
            row.update(
                gate1_caught=g1, gate2_caught=g2,
                gate1_related=g1 and is_related(fault["layer"], "gate1", r["gate1"]["failing"]),
                gate2_related=g2 and is_related(fault["layer"], "gate2", r["gate2"]["failing"]),
                gate1_failing=r["gate1"]["failing"], gate2_failing=r["gate2"]["failing"],
                seconds=r.get("seconds"),
            )
            if g1:
                row["verdict"] = "caught by gate 1" if row["gate1_related"] else "caught by gate 1 (incidental)"
            elif g2:
                row["verdict"] = "caught by gate 2" if row["gate2_related"] else "caught by gate 2 (incidental)"
            else:
                row["verdict"] = "escaped"
            first = "gate1" if g1 else "gate2" if g2 else "none"
            row["prediction_right"] = first == fault["predicted"]
        rows.append(row)

    scored = [r for r in rows if r["verdict"] not in ("void", "missing")]
    if len(scored) != len(rows):
        print(f"WARNING: {len(rows) - len(scored)} fault(s) void or missing: re-run them (method part 6)")
    summary = {
        "baseline_passed": baseline_ok,
        "faults": len(rows),
        "scored": len(scored),
        "gate1_caught": sum(1 for r in scored if r.get("gate1_caught")),
        "gate2_caught": sum(1 for r in scored if r.get("gate2_caught")),
        # Part 6: an incidental catch is reported separately, so the headline counts related ones.
        "first_caught_by_gate1": sum(1 for r in scored if r["verdict"] == "caught by gate 1"),
        "caught_only_by_gate2": sum(1 for r in scored if r["verdict"] == "caught by gate 2"),
        "escaped": sum(1 for r in scored if r["verdict"] == "escaped"),
        "incidental": sum(1 for r in scored if "incidental" in r["verdict"]),
        "void": sum(1 for r in rows if r["verdict"] == "void"),
        "missing": sum(1 for r in rows if r["verdict"] == "missing"),
        "predictions_right": sum(1 for r in scored if r.get("prediction_right")),
    }
    times = [r["seconds"] for r in scored if r.get("seconds")]
    if times:
        summary["fault_job_seconds"] = {"median": statistics.median(times), "min": min(times), "max": max(times), "n": len(times)}
    aps = attack_paths(a.results / "baseline-gate2.xml")
    summary["attack_paths"] = {"blocked": sum(1 for x in aps if x["verdict"] == "blocked"), "total": len(aps)}
    card = {"run": a.run_url, "summary": summary, "faults": rows, "attack_paths": aps}

    a.out.mkdir(parents=True, exist_ok=True)
    (a.out / "scorecard.json").write_text(json.dumps(card, indent=2) + "\n")
    (a.out / "index.html").write_text(render_html(card))
    print(json.dumps(summary, indent=2))
    return 0


def render_html(card: dict) -> str:
    s = card["summary"]
    e = html.escape

    def cell(v):
        return "yes" if v is True else "no" if v is False else e(str(v if v is not None else ""))

    fault_rows = "\n".join(
        f"<tr class='{e(r['verdict'].split(' (')[0].replace(' ', '-'))}'><td>{e(r['id'])}</td><td>{e(r['layer'])}</td>"
        f"<td>{e(r['title'])}</td><td>{cell(r.get('gate1_caught'))}</td><td>{cell(r.get('gate2_caught'))}</td>"
        f"<td><b>{e(r['verdict'])}</b></td><td>{e(r['predicted'])}</td></tr>"
        for r in card["faults"])
    ap_rows = "\n".join(f"<tr><td>{e(x['name'])}</td><td>{e(x['legitimate_pair'])}</td><td><b>{e(x['verdict'])}</b></td>"
                        f"<td>{e(x['detail'])}</td></tr>" for x in card["attack_paths"])
    extra = (f" {s['incidental']} more were caught incidentally (no failing check related to the fault)."
             if s["incidental"] else "")
    extra += f" {s['void']} could not be judged and must be re-run." if s.get("void") else ""
    headline = (f"Of {s['scored']} planted faults, the static gate caught {s['first_caught_by_gate1']}, "
                f"the live copy caught {s['caught_only_by_gate2']} more, and {s['escaped']} escaped both.{extra} "
                f"{s['attack_paths']['blocked']} of {s['attack_paths']['total']} attack paths were blocked "
                f"with their legitimate flows passing.")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>PacketProof scorecard</title>
<style>
:root {{ --bg:#fff; --fg:#1b1f24; --muted:#59636e; --line:#d1d9e0; --ok:#1a7f37; --bad:#cf222e; --warn:#9a6700; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#0d1117; --fg:#e6edf3; --muted:#9198a1; --line:#3d444d; --ok:#3fb950; --bad:#f85149; --warn:#d29922; }} }}
body {{ background:var(--bg); color:var(--fg); font:15px/1.5 system-ui, sans-serif; margin:0 auto; max-width:1100px; padding:24px 16px; }}
table {{ border-collapse:collapse; width:100%; margin:12px 0 28px; font-size:14px; }}
th, td {{ border-bottom:1px solid var(--line); padding:6px 8px; text-align:left; vertical-align:top; }}
.escaped b {{ color:var(--bad); }} .caught-by-gate-1 b, .caught-by-gate-2 b {{ color:var(--ok); }}
.muted {{ color:var(--muted); }} .wrap {{ overflow-x:auto; }}
</style></head><body>
<h1>PacketProof scorecard</h1>
<p class="muted">Generated by Gate 3 from <a href="{e(card['run'])}">this workflow run</a>. Rules: docs/method.md, part 6.
Baseline passed in this run: {cell(s['baseline_passed'])}.</p>
<p><b>{e(headline)}</b></p>
<h2>Planted faults</h2><div class="wrap"><table>
<tr><th>ID</th><th>Layer</th><th>Fault</th><th>Gate 1 failed</th><th>Gate 2 failed</th><th>Verdict</th><th>Predicted</th></tr>
{fault_rows}
</table></div>
<h2>Attack paths from a compromised DMZ host</h2><div class="wrap"><table>
<tr><th>Attack</th><th>Legitimate pair</th><th>Verdict</th><th>Detail</th></tr>
{ap_rows}
</table></div>
<p class="muted">Read next: <a href="https://github.com/aymen-nasri/packetproof/blob/main/docs/limits.md">what each gate cannot see, and why each escape changed no traffic</a> &middot;
<a href="https://github.com/aymen-nasri/packetproof/blob/main/docs/scorecard.md">every Gate 3 run</a> &middot;
<a href="https://github.com/aymen-nasri/packetproof/blob/main/docs/prod.md">the prod change path</a> &middot;
<a href="https://github.com/aymen-nasri/packetproof/blob/main/docs/method.md">the method, committed before any result</a> &middot;
<a href="https://github.com/aymen-nasri/packetproof">the repository</a></p>
</body></html>
"""


if __name__ == "__main__":
    raise SystemExit(main())
