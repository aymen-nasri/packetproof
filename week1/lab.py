#!/usr/bin/env python3
"""Run one week-1 lab end to end and write a JSON result.

  render -> (keys) -> containerlab deploy -> wait for convergence -> checks -> evidence -> destroy

Usage:
  python3 week1/lab.py --lab w1-bgp --out results/A-run1.json [--fault W1-F] [--evidence DIR]

The timed window is the one docs/method.md defines for test A: from the start of
`containerlab deploy` to the end of the checks. Exit code 0 means every check passed.
Needs: docker, containerlab (run through sudo), and the router image built as packetproof/router:w1.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import platform
import re
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import render  # noqa: E402

CONVERGE_TIMEOUT_S = 120
POLL_S = 3
PRIVATE = ipaddress.ip_network("172.16.0.0/12")


def run(cmd: list[str], check: bool = True, timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=check, capture_output=True, text=True, timeout=timeout)


def dexec(lab: str, node: str, *args: str, check: bool = False) -> subprocess.CompletedProcess:
    return run(["docker", "exec", f"clab-{lab}-{node}", *args], check=check, timeout=60)


def vtysh_json(lab: str, node: str, command: str) -> dict:
    res = dexec(lab, node, "vtysh", "-c", command)
    try:
        return json.loads(res.stdout or "{}")
    except json.JSONDecodeError:
        return {}


def bgp_peers(lab: str, node: str) -> dict[str, dict]:
    data = vtysh_json(lab, node, "show bgp ipv4 unicast summary json")
    return data.get("peers", {})


def bgp_routes(lab: str, node: str) -> dict[str, dict]:
    """Selected routes in the RIB, keyed by prefix, with their protocol."""
    data = vtysh_json(lab, node, "show ip route json")
    routes = {}
    for prefix, entries in data.items():
        for e in entries:
            if e.get("selected"):
                routes[prefix] = {"protocol": e.get("protocol"),
                                  "nexthops": [n.get("ip") or n.get("interfaceName") for n in e.get("nexthops", [])]}
    return routes


def ping(lab: str, node: str, dst: str) -> int:
    res = dexec(lab, node, "ping", "-c", "5", "-W", "2", dst)
    m = re.search(r"(\d+) packets received", res.stdout)
    return int(m.group(1)) if m else 0


def converged(lab: str, expect: dict) -> bool:
    for node, peers in expect["sessions"].items():
        state = bgp_peers(lab, node)
        if any(state.get(p, {}).get("state") != "Established" for p in peers):
            return False
    for node, prefixes in expect["bgp_routes"].items():
        rib = bgp_routes(lab, node)
        if any(rib.get(p, {}).get("protocol") != "bgp" for p in prefixes):
            return False
    return True


def wait_converged(lab: str, expect: dict) -> float | None:
    """Seconds until the expected sessions and routes are present on two polls in a row,
    5 s apart, so that late updates (such as a leak) have arrived before the checks run."""
    start = time.monotonic()
    while time.monotonic() - start < CONVERGE_TIMEOUT_S:
        if converged(lab, expect):
            time.sleep(5)
            if converged(lab, expect):
                return round(time.monotonic() - start, 1)
        time.sleep(POLL_S)
    return None


def check(name: str, ok: bool, detail) -> dict:
    return {"check": name, "ok": bool(ok), "detail": detail}


def run_checks(lab: str, expect: dict) -> list[dict]:
    results = []
    # BGP sessions, seen from both ends.
    for node, peers in expect["sessions"].items():
        state = bgp_peers(lab, node)
        seen = {p: state.get(p, {}).get("state", "absent") for p in peers}
        results.append(check(f"bgp_established:{node}", all(s == "Established" for s in seen.values()), seen))
    # Routes learned by BGP.
    for node, prefixes in expect["bgp_routes"].items():
        rib = bgp_routes(lab, node)
        got = {p: rib.get(p, {}).get("protocol", "absent") for p in prefixes}
        results.append(check(f"bgp_routes:{node}", all(v == "bgp" for v in got.values()), got))
    # Private prefixes on routers that must hold exactly a given set (the leak detector).
    for node, allowed in expect["private_exact"].items():
        rib = bgp_routes(lab, node)
        private = sorted(p for p in rib if ipaddress.ip_network(p).subnet_of(PRIVATE))
        extra = sorted(set(private) - set(allowed))
        missing = sorted(set(allowed) - set(private))
        results.append(check(f"private_prefixes_exact:{node}", not extra and not missing,
                             {"private": private, "extra": extra, "missing": missing}))
    # Prefixes that must be absent (proves traffic can only cross the tunnel).
    for node, prefixes in expect["private_absent"].items():
        rib = bgp_routes(lab, node)
        present = sorted(p for p in prefixes if p in rib)
        results.append(check(f"private_prefixes_absent:{node}", not present, {"present": present}))
    # WireGuard handshakes.
    for node in expect.get("wg_routers", []):
        res = dexec(lab, node, "wg", "show", "wg0", "latest-handshakes")
        stamps = [int(line.split()[-1]) for line in res.stdout.splitlines() if line.strip()]
        # Only the timestamp is logged, never a key.
        results.append(check(f"wg_handshake:{node}", bool(stamps) and all(s > 0 for s in stamps),
                             {"latest_handshake_epoch": stamps, "rc": res.returncode}))
    # Capture on isp during a ping: WireGuard UDP must be seen, clear ICMP between the LANs must not.
    cap = expect.get("capture")
    if cap:
        dexec(lab, cap["node"], "rm", "-f", "/tmp/cap.pcap")
        subprocess.run(["docker", "exec", "-d", f"clab-{lab}-{cap['node']}", "timeout", "12", "tcpdump", "-ni",
                        cap["intf"], "-w", "/tmp/cap.pcap", "udp port 51820 or icmp"], check=True)
        time.sleep(2)
        ping(lab, cap["src"], cap["dst"])
        time.sleep(11)
        res = dexec(lab, cap["node"], "tcpdump", "-nr", "/tmp/cap.pcap")
        lines = res.stdout.splitlines()
        udp = sum(1 for line in lines if ".51820 " in line or ".51820:" in line)
        a, b = cap["lan_pair"]
        clear = sum(1 for line in lines if "ICMP" in line and a in line and b in line)
        results.append(check("capture_tunnel_only", udp > 0 and clear == 0,
                             {"wireguard_udp_packets": udp, "clear_icmp_between_lans": clear}))
    # Pings, at least 4 of 5 replies each way.
    for src, dst in expect["pings"]:
        got = ping(lab, src, dst)
        results.append(check(f"ping:{src}->{dst}", got >= 4, {"received_of_5": got}))
    return results


def make_keys(build: Path, lab: dict) -> None:
    """Generate WireGuard keys inside the router image. They stay in the build directory,
    which is ignored by Git, and are never printed."""
    keys = build / "keys"
    keys.mkdir(exist_ok=True)
    for name, r in lab["routers"].items():
        if "wg" not in r:
            continue
        priv = run(["docker", "run", "--rm", "--entrypoint", "wg", render.ROUTER_IMAGE, "genkey"]).stdout.strip()
        pub = subprocess.run(["docker", "run", "--rm", "-i", "--entrypoint", "wg", render.ROUTER_IMAGE, "pubkey"],
                             input=priv + "\n", capture_output=True, text=True, check=True).stdout.strip()
        (keys / f"{name}.key").write_text(priv + "\n")
        os.chmod(keys / f"{name}.key", 0o600)
        (keys / f"{name}.pub").write_text(pub + "\n")


def save_evidence(lab: str, meta: dict, evidence: Path) -> None:
    evidence.mkdir(parents=True, exist_ok=True)
    for node in render.LABS[meta["lab"]]["routers"]:
        for name, cmd in (("bgp-summary", "show bgp ipv4 unicast summary"), ("routes", "show ip route"),
                          ("running-config", "show running-config")):
            res = dexec(lab, node, "vtysh", "-c", cmd)
            (evidence / f"{node}.{name}.txt").write_text(res.stdout + res.stderr)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--lab", required=True, choices=sorted(render.LABS))
    ap.add_argument("--fault", choices=sorted(render.FAULTS))
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--evidence", type=Path)
    ap.add_argument("--build", type=Path, default=Path("build"))
    args = ap.parse_args()

    tag = args.lab + (f"-{args.fault}" if args.fault else "")
    build = args.build / tag
    meta = render.render(args.lab, build, args.fault)
    lab = render.apply_fault(render.LABS[args.lab], args.fault)
    if any("wg" in r for r in lab["routers"].values()):
        make_keys(build, lab)
    topo = str(build / "topo.clab.yml")

    result = {"lab": args.lab, "fault": args.fault, "host": platform.node(), "kernel": platform.release(),
              "runner_image": os.environ.get("ImageVersion"), "checks": [], "timings_s": {}}
    t0 = time.monotonic()
    try:
        dep = run(["sudo", "containerlab", "deploy", "-t", topo, "--reconfigure"], check=False, timeout=600)
        result["timings_s"]["deploy"] = round(time.monotonic() - t0, 1)
        if dep.returncode != 0:
            result["deploy_error"] = (dep.stdout + dep.stderr)[-4000:]
            result["checks"].append(check("deploy", False, "containerlab deploy failed"))
        else:
            result["timings_s"]["converge"] = wait_converged(args.lab, meta["expect"])
            result["checks"] = run_checks(args.lab, meta["expect"])
        result["timings_s"]["deploy_plus_checks"] = round(time.monotonic() - t0, 1)
        if args.evidence and dep.returncode == 0:
            save_evidence(args.lab, meta, args.evidence)
    finally:
        t1 = time.monotonic()
        run(["sudo", "containerlab", "destroy", "-t", topo, "--cleanup"], check=False, timeout=300)
        result["timings_s"]["destroy"] = round(time.monotonic() - t1, 1)

    result["passed"] = bool(result["checks"]) and all(c["ok"] for c in result["checks"])
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    for c in result["checks"]:
        print(f"{'PASS' if c['ok'] else 'FAIL'}  {c['check']}  {json.dumps(c['detail'])}")
    print(f"timings: {json.dumps(result['timings_s'])}  passed={result['passed']}")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
