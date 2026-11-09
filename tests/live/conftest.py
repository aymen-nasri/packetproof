"""Gate 2: tests against a deployed lab. Every check sends real traffic.

Environment: PP_RENDER points at the rendered lab directory (default build/lab). The lab must
already be deployed (`python -m packetproof deploy --render build/lab`).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from pathlib import Path

import pytest

LAB = "pp"
NODE_IMAGE = "packetproof/node:dev"
ROOT_CA = "/shared/pki/root_ca.crt"
RENDER = Path(os.environ.get("PP_RENDER", "build/lab")).resolve()


class Lab:
    def __init__(self, render: Path):
        self.render = render
        self.intent = json.loads((render / "intent.json").read_text())

    # ---- running commands ------------------------------------------------------------------
    def sh(self, node: str, cmd: str, timeout: int = 60) -> subprocess.CompletedProcess:
        return subprocess.run(["docker", "exec", f"clab-{LAB}-{node}", "sh", "-c", cmd],
                              capture_output=True, text=True, timeout=timeout)

    def bg(self, node: str, cmd: str) -> None:
        subprocess.run(["docker", "exec", "-d", f"clab-{LAB}-{node}", "sh", "-c", cmd], check=True)

    def dmz(self, cmd: str, timeout: int = 120) -> subprocess.CompletedProcess:
        """Run a probe from a 'compromised' DMZ host: a throwaway container that shares haproxy's
        network namespace, so every packet carries haproxy's real address."""
        return subprocess.run(["docker", "run", "--rm", "--net", f"container:clab-{LAB}-haproxy",
                               "-v", f"{self.render / 'shared'}:/shared:ro", NODE_IMAGE, "sh", "-c", cmd],
                              capture_output=True, text=True, timeout=timeout)

    # ---- probes ------------------------------------------------------------------------------
    # Every probe must prove it ran: an empty or unknown answer raises, so a broken probe can
    # never make an attack look blocked.
    PROBE_RESULTS = {"open", "refused", "filtered", "unreachable"}

    def _probe(self, res: subprocess.CompletedProcess, what: str) -> str:
        out = res.stdout.strip()
        if out not in self.PROBE_RESULTS:
            raise RuntimeError(f"probe {what} did not run: {out!r} {res.stderr.strip()[-300:]!r}")
        return out

    def tcp(self, src: str, ip: str, port: int, timeout: float = 3) -> str:
        return self._probe(self.sh(src, f"pp-probe.py tcp {ip} {port} --timeout {timeout}"), f"{src}->{ip}:{port}")

    def tcp_from_dmz(self, ip: str, port: int, timeout: float = 3) -> str:
        return self._probe(self.dmz(f"pp-probe.py tcp {ip} {port} --timeout {timeout}"), f"dmz->{ip}:{port}")

    def nmap_from_dmz(self, target: str) -> str:
        res = self.dmz(f"nmap -Pn -sT -n -T4 --max-retries 1 --host-timeout 60s --top-ports 100 {target}", timeout=180)
        if "Nmap done" not in res.stdout:
            raise RuntimeError(f"nmap from the DMZ did not run: {res.stdout[-300:]!r} {res.stderr[-300:]!r}")
        return res.stdout

    def spoof_from(self, where: str, src: str, dst: str, port: int) -> None:
        cmd = f"pp-probe.py spoof {src} {dst} {port} --sport 31337 --count 3"
        res = self.dmz(cmd) if where == "dmz" else self.sh(where, cmd)
        if res.stdout.strip() != "sent":
            raise RuntimeError(f"spoofing probe did not run: {res.stdout!r} {res.stderr[-300:]!r}")

    def dig(self, src: str, server: str, name: str, via_dmz: bool = False) -> tuple[str, list[str]]:
        cmd = f"dig @{server} {name} A +time=2 +tries=1"
        out = (self.dmz(cmd) if via_dmz else self.sh(src, cmd)).stdout
        if "status:" not in out and "timed out" not in out:
            raise RuntimeError(f"dig did not run: {out[-300:]!r}")
        m = re.search(r"status: (\w+)", out)
        answers = re.findall(rf"^{re.escape(name)}\.\s+\d+\s+IN\s+A\s+(\S+)", out, re.M)
        return (m.group(1) if m else "NO-ANSWER"), answers

    def curl(self, src: str, url: str, extra: str = "", timeout: int = 20) -> subprocess.CompletedProcess:
        return self.sh(src, f"curl -sS --max-time {timeout} --cacert {ROOT_CA} {extra} '{url}'", timeout=timeout + 10)

    def vtysh_json(self, router: str, cmd: str) -> dict:
        out = self.sh(router, f"vtysh -c '{cmd} json'").stdout
        try:
            return json.loads(out or "{}")
        except json.JSONDecodeError:
            return {}

    def routes(self, router: str) -> dict[str, dict]:
        out = {}
        for prefix, entries in self.vtysh_json(router, "show ip route").items():
            for e in entries:
                if e.get("selected"):
                    out[prefix] = {"protocol": e.get("protocol"),
                                   "ifaces": [n.get("interfaceName") for n in e.get("nexthops", [])]}
        return out

    def nft_counter(self, router: str, family_table_chain: str) -> int:
        out = self.sh(router, f"nft list chain {family_table_chain}").stdout
        return sum(int(x) for x in re.findall(r"counter packets (\d+)", out))

    def capture(self, node: str, name: str, bpf: str, seconds: int) -> None:
        self.sh(node, f"rm -f /tmp/{name}.pcap")
        self.bg(node, f"timeout {seconds} tcpdump -ni eth1 -w /tmp/{name}.pcap '{bpf}'")
        time.sleep(1.5)

    def captured(self, node: str, name: str) -> list[str]:
        return [line for line in self.sh(node, f"tcpdump -nr /tmp/{name}.pcap 2>/dev/null").stdout.splitlines() if line]

    def host(self, name: str) -> str:
        return next(h["address"] for h in self.intent["hosts"] if h["name"] == name)


@pytest.fixture(scope="session")
def lab() -> Lab:
    return Lab(RENDER)
