"""NAT and the edge: users reach the internet only as their site's NAT address, the outside sees
exactly the published services, and spoofed private sources die at the edge (INV-03, INV-08)."""

import re
import time

from expect import APP1, HAPROXY, NAT_A, NAT_B, OUTSIDE, PUBLIC, ZONE


def test_lan_a_egress_uses_site_a_nat_address(lab):
    out = lab.sh("client-a", f"curl -sS --max-time 10 http://{OUTSIDE}/").stdout
    assert out.strip() == f"outside saw {NAT_A}", out


def test_lan_b_egress_uses_site_b_nat_address(lab):
    out = lab.sh("client-b", f"curl -sS --max-time 10 http://{OUTSIDE}/").stdout
    assert out.strip() == f"outside saw {NAT_B}", out


def test_published_https_from_outside(lab):
    res = lab.curl("outside", f"https://www.{ZONE}/", f"--resolve www.{ZONE}:443:{PUBLIC}")
    assert res.returncode == 0 and re.match(r"app[12] saw " + re.escape(HAPROXY), res.stdout), res.stdout + res.stderr


def test_only_published_ports_answer_from_outside(lab):
    out = lab.sh("outside", f"nmap -Pn -sT -n -T4 --max-retries 1 -p 1-1024,3306,5432,8080,9000 {PUBLIC}",
                 timeout=180).stdout
    open_ports = sorted(int(p) for p in re.findall(r"^(\d+)/tcp\s+open\b", out, re.M))
    assert open_ports == [53, 443], f"open on {PUBLIC}: {open_ports}"


def test_edge_drops_spoofed_private_sources(lab):
    before = lab.nft_counter("rtr-a", "netdev edge uplink_in")
    lab.capture("haproxy", "edge", f"src host {APP1} and src port 31337", 8)
    lab.spoof_from("outside", APP1, PUBLIC, 443)
    time.sleep(7)
    seen = lab.captured("haproxy", "edge")
    after = lab.nft_counter("rtr-a", "netdev edge uplink_in")
    assert not seen, f"spoofed packets from the internet reached haproxy: {seen}"
    assert after > before, f"rtr-a's edge anti-spoof counter did not move ({before} -> {after})"
