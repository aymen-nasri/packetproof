#!/usr/bin/env python3
"""Gate 1: static checks on a rendered lab. Nothing is deployed.

  conftest-intent     the hand-written invariants (policy/intent) against network.yaml
  firewall-rendered   each ruleset loaded into a scratch namespace, then policy/rendered
                      against `nft -j list ruleset` (a ruleset that does not load fails here)
  vtysh-dryrun        FRR's own syntax check of every router config, after a self-test
                      proving the check rejects a broken config (the feasibility checks found it can exit 0 unchecked)
  batfish             parse status, BGP session compatibility, and route questions

Usage: python3 scripts/gate1.py --render build/lab --out results/gate1.json [--no-batfish]
Exit code 0 means every check passed.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests" / "live"))
import expect  # noqa: E402  hand-written expectations, shared with Gate 2

ROUTER_IMAGE = "packetproof/router:dev"
BROKEN_FRR = "frr version 10.7.1\nrouter bgp 65001\n neighbor 192.0.2.1 remote-as not-a-number\nthis is not a command\n"


KEEP: Path | None = None


def run(cmd: list[str], timeout: int = 300, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, **kw)


def conftest(conftest_bin: str, policy: str, data: Path) -> tuple[bool, list[str]]:
    res = run([conftest_bin, "test", "--no-color", "-o", "json", "-p", str(ROOT / policy), str(data)])
    try:
        failures = [f["msg"] for r in json.loads(res.stdout) for f in (r.get("failures") or [])]
    except (json.JSONDecodeError, TypeError):
        raise ToolError(f"conftest did not run: {res.stdout[-500:]} {res.stderr[-500:]}")
    return res.returncode == 0 and not failures, failures


class ToolError(Exception):
    """A check that could not run. Gate 1 still fails (a pull request must not pass on a broken
    tool), but Gate 3 records it as "could not judge", never as a catch."""


def check_policy_tests(conftest_bin: str) -> dict:
    """The policies' own unit tests (policy/*/*_test.rego): a policy that cannot catch its known
    holes would make every check above meaningless."""
    details, ok = [], True
    for policy in ("policy/intent", "policy/rendered"):
        res = run([conftest_bin, "verify", "--no-color", "-p", str(ROOT / policy)])
        if res.returncode != 0:
            ok = False
            details.append(f"{policy}: {(res.stdout + res.stderr).strip()[-400:]}")
        else:
            details.append(f"{policy}: {res.stdout.strip().splitlines()[-1] if res.stdout.strip() else 'passed'}")
    return {"name": "policy-tests", "ok": ok, "details": details, "tool_error": not ok}


def check_intent(conftest_bin: str, render: Path) -> dict:
    ok, msgs = conftest(conftest_bin, "policy/intent", render / "intent.json")
    return {"name": "conftest-intent", "ok": ok, "details": msgs}


def check_firewalls(conftest_bin: str, render: Path) -> dict:
    intent = json.loads((render / "intent.json").read_text())
    details, ok = [], True
    for i, site in enumerate(intent["sites"]):
        router = site["router"]
        zone_ifaces = [f"eth{n + 2}" for n in range(len(site["zones"]))]
        ifaces = ["eth1", *zone_ifaces, "wg0"]
        script = (" ".join(f"ip link add {x} type dummy;" for x in ifaces)
                  + " nft -f /r.nft && nft -j list ruleset")
        res = run(["docker", "run", "--rm", "--network", "none", "--cap-add", "NET_ADMIN",
                   "-v", f"{render / 'routers' / router / 'ruleset.nft'}:/r.nft:ro",
                   "--entrypoint", "sh", ROUTER_IMAGE, "-c", script])
        if res.returncode != 0:
            ok = False
            details.append(f"{router}: ruleset does not load: {res.stderr.strip()[-400:]}")
            continue
        doc = {"router": router, "public_prefix": site["public_prefix"], "zone_ifaces": zone_ifaces,
               "nft": json.loads(res.stdout)}
        if KEEP:  # the ruleset as nftables loaded it, kept as evidence next to gate1.json
            (KEEP / f"nft-{router}.json").write_text(json.dumps(doc, indent=1) + "\n")
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(doc, f)
        good, msgs = conftest(conftest_bin, "policy/rendered", Path(f.name))
        ok = ok and good
        details += msgs
    return {"name": "firewall-rendered", "ok": ok, "details": details}


def _dryrun(cfg_dir: Path) -> tuple[bool, str]:
    res = run(["docker", "run", "--rm", "--network", "none", "-v", f"{cfg_dir}:/tmp/cfg:ro",
               "--entrypoint", "vtysh", ROUTER_IMAGE, "--config_dir", "/tmp/cfg", "--dryrun"])
    out = (res.stdout + res.stderr).strip()
    bad = res.returncode != 0 or any(w in out.lower() for w in ("failure", "unknown command", "error", "invalid"))
    return not bad, out


def check_vtysh(render: Path) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        t = Path(tmp)
        (t / "frr.conf").write_text(BROKEN_FRR)
        (t / "vtysh.conf").write_text("service integrated-vtysh-config\n")
        (t / "daemons").write_text((render / "routers" / "rtr-a" / "daemons").read_text())
        t.chmod(0o755)
        for p in t.iterdir():
            p.chmod(0o644)
        rejects_broken, selftest_out = _dryrun(t)
    if rejects_broken:  # the variable holds "the broken config was accepted"
        return {"name": "vtysh-dryrun", "ok": False, "tool_error": True,
                "details": ["self-test failed: a deliberately broken config was accepted, so the check proves nothing",
                            selftest_out[-400:]]}
    details, ok = [], True
    for d in sorted((render / "routers").iterdir()):
        good, out = _dryrun(d)
        ok = ok and good
        if not good:
            details.append(f"{d.name}: {out[-400:]}")
    return {"name": "vtysh-dryrun", "ok": ok, "details": details or ["self-test rejected a broken config; all configs accepted"]}


def check_batfish(render: Path, host: str) -> dict:
    import time

    from pybatfish.client.session import Session

    deadline = time.monotonic() + 240
    while True:  # the service takes a minute or two to start
        try:
            bf = Session(host=host)
            break
        except Exception:
            if time.monotonic() > deadline:
                raise
            time.sleep(5)
    bf.set_network("packetproof")
    bf.init_snapshot(str(render / "batfish"), name="gate1", overwrite=True)
    details, ok = [], True

    status = bf.q.fileParseStatus().answer().frame()
    not_passed = status[status["Status"] != "PASSED"]
    if len(not_passed):
        ok = False
        details.append(f"parse status: {not_passed[['File_Name', 'Status']].to_dict('records')}")
    warnings = bf.q.parseWarning().answer().frame()
    if len(warnings):
        ok = False
        details.append(f"parse warnings: {warnings.head(10).astype(str).to_dict('records')}")
    compat = bf.q.bgpSessionCompatibility().answer().frame()
    bad = compat[compat["Configured_Status"] != "UNIQUE_MATCH"]
    if len(bad):
        ok = False
        details.append(f"BGP sessions not compatible: {bad[['Node', 'Remote_IP', 'Configured_Status']].to_dict('records')}")
    status = bf.q.bgpSessionStatus().answer().frame()
    bad = status[status["Established_Status"] != "ESTABLISHED"]
    if len(bad):
        ok = False
        details.append(f"BGP sessions not established: {bad[['Node', 'Remote_IP', 'Established_Status']].to_dict('records')}")

    routes = bf.q.routes().answer().frame()
    private = ipaddress.ip_network("172.16.0.0/12")
    isp = routes[routes["Node"] == "isp"]
    leaked = sorted({n for n in isp["Network"].astype(str) if ipaddress.ip_network(n).subnet_of(private)})
    if leaked:
        ok = False
        details.append(f"INV-06: private prefixes on isp: {leaked}")
    for node, prefixes in (("rtr-a", expect.SITE_B_PRIVATE), ("rtr-b", expect.SITE_A_PRIVATE)):
        rib = routes[(routes["Node"] == node) & (routes["Protocol"] == "bgp")]
        missing = sorted(set(prefixes) - set(rib["Network"].astype(str)))
        if missing:
            ok = False
            details.append(f"{node} has no BGP route to the other site's {missing}")
    return {"name": "batfish", "ok": ok, "details": details or ["parsed cleanly; sessions compatible; routes as expected"]}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--render", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--conftest", default="conftest")
    ap.add_argument("--batfish-host", default="localhost")
    ap.add_argument("--no-batfish", action="store_true")
    a = ap.parse_args()
    a.render = a.render.resolve()  # docker -v needs absolute paths

    global KEEP
    KEEP = a.out.parent
    KEEP.mkdir(parents=True, exist_ok=True)
    checks = []
    for name, fn in (("policy-tests", lambda: check_policy_tests(a.conftest)),
                     ("conftest-intent", lambda: check_intent(a.conftest, a.render)),
                     ("firewall-rendered", lambda: check_firewalls(a.conftest, a.render)),
                     ("vtysh-dryrun", lambda: check_vtysh(a.render)),
                     *([] if a.no_batfish else [("batfish", lambda: check_batfish(a.render, a.batfish_host))])):
        try:
            checks.append(fn())
        except Exception as exc:  # a crash fails Gate 1, and is marked as a tool error, not a catch
            checks.append({"name": name, "ok": False, "tool_error": True, "details": [f"error: {exc}"]})
    result = {"passed": all(c["ok"] for c in checks), "checks": checks,
              "tool_errors": [c["name"] for c in checks if c.get("tool_error")]}
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(result, indent=2) + "\n")
    lines = [f"### Gate 1 (static): {'passed' if result['passed'] else 'FAILED'}", "", "| Check | Result | Details |", "|---|---|---|"]
    for c in checks:
        lines.append(f"| {c['name']} | {'pass' if c['ok'] else '**fail**'} | {'<br>'.join(d.replace('|', '/') for d in c['details'][:8])} |")
    a.out.with_suffix(".md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
