"""Routing: BGP sessions, what each router learned and from where, and what the ISP may see."""

import ipaddress
import re
import time

import pytest

from expect import (HAPROXY, RTR_A_DMZ, RTR_A_LO, RTR_A_WG, RTR_B_LAN, RTR_B_LO, RTR_B_WG, SITE_A_PRIVATE,
                    SITE_B_PRIVATE)

SESSIONS = {
    "rtr-a": ["198.51.100.0", RTR_B_WG],
    "rtr-b": ["203.0.113.0", RTR_A_WG],
    "isp": ["198.51.100.1", "203.0.113.1"],
}


@pytest.mark.parametrize("router", sorted(SESSIONS))
def test_bgp_sessions_established(lab, router):
    peers = lab.vtysh_json(router, "show bgp ipv4 unicast summary").get("peers", {})
    states = {p: peers.get(p, {}).get("state", "absent") for p in SESSIONS[router]}
    assert all(s == "Established" for s in states.values()), states


@pytest.mark.parametrize("router", ["rtr-a", "rtr-b"])
def test_wireguard_handshake_recent(lab, router):
    out = lab.sh(router, "wg show wg0 latest-handshakes").stdout.split()
    stamps = [int(x) for x in out[1::2]] if len(out) >= 2 else []
    assert stamps and all(time.time() - s < 180 for s in stamps), f"latest handshake: {stamps}"


@pytest.mark.parametrize("router,prefixes", [("rtr-a", SITE_B_PRIVATE), ("rtr-b", SITE_A_PRIVATE)])
def test_other_site_learned_over_the_tunnel(lab, router, prefixes):
    rib = lab.routes(router)
    wrong = {p: rib.get(p) for p in prefixes if rib.get(p, {}).get("protocol") != "bgp" or rib[p]["ifaces"] != ["wg0"]}
    assert not wrong, f"not learned by BGP over wg0: {wrong}"


def test_isp_holds_no_private_prefix(lab):
    """INV-06: nothing inside 172.16.0.0/12 ever reaches the ISP."""
    private = ipaddress.ip_network("172.16.0.0/12")
    leaked = [p for p in lab.routes("isp") if ipaddress.ip_network(p).subnet_of(private)]
    assert not leaked, f"private prefixes on isp: {leaked}"


def test_isp_routes_each_public_prefix_to_its_site(lab):
    rib = lab.routes("isp")
    assert rib.get("198.51.100.64/27", {}).get("ifaces") == ["eth1"], rib.get("198.51.100.64/27")
    assert rib.get("203.0.113.64/27", {}).get("ifaces") == ["eth2"], rib.get("203.0.113.64/27")


def test_site_b_internet_egress_is_local(lab):
    """Site B's default route points at its own ISP link, never into the tunnel."""
    default = lab.routes("rtr-b").get("0.0.0.0/0", {})
    assert default.get("ifaces") == ["eth1"], default


def test_traceroute_from_site_b_crosses_the_tunnel_not_the_isp(lab):
    """INV-07 as an operator would see it: a TCP traceroute from LAN-B along an allowed flow (443
    to haproxy) shows rtr-b, then rtr-a, then haproxy. The ISP carries the packets too, but only
    inside the encrypted tunnel, so it never appears as a hop."""
    out = lab.sh("client-b", f"nmap -Pn -n -sS -p 443 --traceroute -oX - {HAPROXY}", timeout=120).stdout
    hops = [ip for _, ip in sorted((int(t), ip) for t, ip in re.findall(r'<hop ttl="(\d+)" ipaddr="([\d.]+)"', out))]
    assert hops, f"no traceroute in the nmap output: {out[-400:]}"
    assert len(hops) == 3 and hops[-1] == HAPROXY, hops
    assert hops[0] in {RTR_B_LAN, RTR_B_LO, RTR_B_WG}, f"first hop is not rtr-b: {hops}"
    assert hops[1] in {RTR_A_WG, RTR_A_LO, RTR_A_DMZ}, f"second hop is not rtr-a: {hops}"
