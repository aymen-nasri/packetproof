"""Deploy, wait for, collect evidence from, and destroy a rendered lab.

Runs on any Linux host with Docker, containerlab and sudo (CI uses ubuntu-latest). In a pull-request
lab, WireGuard private keys are generated inside each router at start-up and never leave it; only
public keys are read and exchanged. In prod, deploy() takes the decrypted SOPS file instead: each
router's long-lived key is piped into it, and the CA's root is mounted for its start-up only
(docs/secrets.md).
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

from .model import Network
from .render_lab import LAB_NAME, bridge_name

READY_TIMEOUT_S = 240


def run(cmd: list[str], check: bool = True, timeout: int = 300, input: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=check, capture_output=True, text=True, timeout=timeout, input=input)


def container(node: str) -> str:
    return f"clab-{LAB_NAME}-{node}"


def dexec(node: str, *args: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return run(["docker", "exec", container(node), *args], check=False, timeout=timeout)


def load(render_dir: Path) -> Network:
    return Network(json.loads((render_dir / "intent.json").read_text()))


def exchange_keys(render_dir: Path, net: Network, managed: dict | None = None, timeout_s: int = 90) -> dict:
    """Each router generated its own private key at start-up. In prod, the SOPS-managed key replaces
    it, piped straight into the router (never written on the runner's disk). Then read only the
    public keys and give each router its peer's (or the intent's override, which is how fault F09
    is planted)."""
    pub: dict[str, str] = {}
    start = time.monotonic()
    for s in net.data["sites"]:
        r = s["router"]
        while dexec(r, "test", "-f", "/tmp/pp-up-done").returncode != 0:
            if time.monotonic() - start > timeout_s:
                return {"keys_exchanged": False, "waiting_for": r}
            time.sleep(1)
        if managed and r in managed.get("wireguard", {}):
            run(["docker", "exec", "-i", container(r), "sh", "-c",
                 "umask 077; cat > /etc/wireguard/pp-wg.key && wg set wg0 private-key /etc/wireguard/pp-wg.key"],
                input=managed["wireguard"][r].strip() + "\n")
        pub[r] = dexec(r, "wg", "show", "wg0", "public-key").stdout.strip()
        if not pub[r]:
            return {"keys_exchanged": False, "error": f"{r} has no WireGuard public key"}
    for s in net.data["sites"]:
        r = s["router"]
        override = render_dir / "routers" / r / "peer.pub.override"
        peer_key = override.read_text().strip() if override.exists() else pub[net.other_site(s["name"])["router"]]
        res = dexec(r, "sh", "/pp/wg-peer.sh", peer_key)
        if res.returncode != 0:
            return {"keys_exchanged": False, "error": f"wg-peer.sh on {r}: {(res.stdout + res.stderr)[-300:]}"}
    return {"keys_exchanged": True, "managed_identities": bool(managed)}


def deploy(render_dir: Path, secrets: Path | None = None) -> dict:
    """secrets: decrypted SOPS file (JSON) with prod's managed identities; None for a PR lab."""
    net = load(render_dir)
    managed = json.loads(secrets.read_text()) if secrets else None
    ca_dir = render_dir / "secrets" / "ca"  # bind-mounted read-only into the CA container
    ca_dir.mkdir(parents=True, exist_ok=True)
    key = ca_dir / "root_ca.key"
    try:
        return _deploy(render_dir, net, managed, ca_dir, key)
    finally:
        # Whatever happened, the root key has no reason to stay on the runner.
        key.unlink(missing_ok=True)


def _deploy(render_dir: Path, net: Network, managed: dict | None, ca_dir: Path, key: Path) -> dict:
    if managed and managed.get("ca"):
        # The CA finds its long-lived root here at start-up and signs a fresh intermediate with it.
        (ca_dir / "root_ca.crt").write_text(managed["ca"]["root_cert"])
        # Created 0600 from the start: never readable by others, even for an instant.
        fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(managed["ca"]["root_key"])
    run(["sudo", "modprobe", "wireguard"])
    run(["sudo", "modprobe", "br_netfilter"], check=False)
    # Bridged lab traffic must not be filtered by the host's (Docker's) iptables FORWARD policy.
    for sysctl in ("net.bridge.bridge-nf-call-iptables", "net.bridge.bridge-nf-call-ip6tables"):
        run(["sudo", "sysctl", "-qw", f"{sysctl}=0"], check=False)
    for zone in net.zones:
        br = bridge_name(zone)
        if run(["ip", "link", "show", br], check=False).returncode != 0:
            run(["sudo", "ip", "link", "add", br, "type", "bridge"])
        run(["sudo", "ip", "link", "set", br, "up"])
    os.chmod(render_dir / "shared", 0o777)
    t0 = time.monotonic()
    dep = run(["sudo", "containerlab", "deploy", "-t", str(render_dir / "topo.clab.yml"), "--reconfigure"],
              check=False, timeout=600)
    (render_dir / "deploy.log").write_text(dep.stdout + dep.stderr)
    result = {"deploy_rc": dep.returncode, "deploy_s": round(time.monotonic() - t0, 1)}
    if dep.returncode == 0:
        result.update(exchange_keys(render_dir, net, managed))
        result.update(wait_ready(net))
    # Ready: deployed, keys exchanged, every node ready and both sessions up on both site routers.
    # The command's exit code stays containerlab's (Gate 2 must still run on a faulted lab); prod
    # checks this flag.
    result["ready"] = (result["deploy_rc"] == 0 and result.get("keys_exchanged") is True
                       and not result.get("not_ready") and result.get("bgp_up") is True)
    result["total_s"] = round(time.monotonic() - t0, 1)
    (render_dir / "deploy.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def nodes(net: Network) -> list[str]:
    return [s["router"] for s in net.data["sites"]] + [net.data["isp"]["name"]] + [h["name"] for h in net.data["hosts"]]


def wait_ready(net: Network) -> dict:
    """Wait until every node wrote /tmp/pp-ready and both site routers have both BGP sessions up.
    Never raises: what is not ready is reported, and Gate 2's tests say what that broke."""
    start = time.monotonic()
    pending = set(nodes(net))
    expected = {s["router"]: {s["uplink"]["isp_address"], s["wireguard"]["peer_address"]} for s in net.data["sites"]}
    bgp_ok = False
    while time.monotonic() - start < READY_TIMEOUT_S:
        for n in sorted(pending):
            if dexec(n, "test", "-f", "/tmp/pp-ready").returncode == 0:
                pending.discard(n)
        bgp_ok = all(_sessions_up(r, peers) for r, peers in expected.items())
        if not pending and bgp_ok:
            break
        time.sleep(2)
    return {"ready_s": round(time.monotonic() - start, 1), "not_ready": sorted(pending), "bgp_up": bgp_ok}


def _sessions_up(router: str, expected: set[str]) -> bool:
    """Both of this router's sessions (the ISP and the tunnel peer) are Established, not just any."""
    res = dexec(router, "vtysh", "-c", "show bgp ipv4 unicast summary json")
    try:
        peers = json.loads(res.stdout or "{}").get("peers", {})
    except json.JSONDecodeError:
        return False
    return expected <= set(peers) and all(peers[p].get("state") == "Established" for p in expected)


def evidence(render_dir: Path, out: Path) -> None:
    """Logs and state from every node. `wg show` prints public keys only."""
    net = load(render_dir)
    out.mkdir(parents=True, exist_ok=True)
    for name in ("deploy.log", "deploy.json"):
        if (render_dir / name).exists():
            (out / name).write_text((render_dir / name).read_text())
    for r in [s["router"] for s in net.data["sites"]] + [net.data["isp"]["name"]]:
        parts = []
        for cmd in (["cat", "/tmp/pp-up.log"], ["vtysh", "-c", "show bgp ipv4 unicast summary"],
                    ["vtysh", "-c", "show ip route"], ["vtysh", "-c", "show running-config"],
                    ["nft", "list", "ruleset"], ["wg", "show"], ["ip", "-br", "addr"]):
            res = dexec(r, *cmd)
            parts.append(f"$ {' '.join(cmd)}\n{res.stdout}{res.stderr}")
        (out / f"{r}.txt").write_text("\n".join(parts))
    for h in net.data["hosts"]:
        res = dexec(h["name"], "sh", "-c", "cat /tmp/pp-start.log; for f in /tmp/*.log; do echo \"== $f\"; tail -n 50 \"$f\"; done")
        (out / f"{h['name']}.txt").write_text(res.stdout + res.stderr)
    # Packet captures the tests took (attack paths, spoofing, tunnel-only traffic) are evidence too.
    pcaps = out / "pcaps"
    for node in nodes(net):
        listing = dexec(node, "sh", "-c", "ls /tmp/*.pcap 2>/dev/null || true").stdout.split()
        for path in listing:
            pcaps.mkdir(exist_ok=True)
            run(["docker", "cp", f"{container(node)}:{path}", str(pcaps / f"{node}-{Path(path).name}")], check=False)
    # The runner host: AppArmor profiles attach by path and can confine binaries inside
    # privileged containers (this is what blocked `wg` from reading its key, see the docs).
    host = []
    for cmd in (["sh", "-c", "ls /etc/apparmor.d | grep -iE 'wg|wireguard' || true"],
                ["sh", "-c", "cat /etc/apparmor.d/wg 2>/dev/null | head -n 40 || true"],
                ["sh", "-c", "sudo dmesg | grep -i 'apparmor=\"DENIED\"' | tail -n 20 || true"]):
        res = run(cmd, check=False)
        host.append(f"$ {cmd[-1]}\n{res.stdout}{res.stderr}")
    (out / "runner-host.txt").write_text("\n".join(host))


def destroy(render_dir: Path) -> None:
    net = load(render_dir)
    run(["sudo", "containerlab", "destroy", "-t", str(render_dir / "topo.clab.yml"), "--cleanup"],
        check=False, timeout=300)
    for zone in net.zones:
        run(["sudo", "ip", "link", "del", bridge_name(zone)], check=False)
