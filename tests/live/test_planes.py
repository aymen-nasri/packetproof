"""No path around the design: every host has only its planned address, and no router accepts a
route inside private space from the ISP. Both were found missing by the review of v1.0.0."""

import ipaddress

import pytest

from expect import HOST_ADDRESSES

PRIVATE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
ISP_PEERS = {"rtr-a": "198.51.100.0", "rtr-b": "203.0.113.0"}


@pytest.mark.parametrize("host", sorted(HOST_ADDRESSES))
def test_host_has_only_its_planned_address(lab, host):
    """A second interface, such as containerlab's management network, would be a path between
    hosts that never crosses a router, so no zone firewall could see it."""
    out = lab.sh(host, "ip -4 -o addr show").stdout
    found = {line.split()[3].split("/")[0] for line in out.splitlines() if len(line.split()) > 3}
    found = {a for a in found if not a.startswith("127.")}
    assert out.strip(), f"no output from ip on {host}"
    assert found == {HOST_ADDRESSES[host]}, f"{host} has {sorted(found)}, planned {HOST_ADDRESSES[host]}"


@pytest.mark.parametrize("router", sorted(ISP_PEERS))
def test_no_private_route_accepted_from_isp(lab, router):
    """The inbound mirror of INV-06: nothing inside private space, at any prefix length, is
    accepted from the ISP."""
    data = lab.vtysh_json(router, f"show bgp ipv4 unicast neighbors {ISP_PEERS[router]} routes")
    assert "routes" in data, f"no BGP answer from {router}: {str(data)[:300]}"
    private = sorted(p for p in data["routes"]
                     if any(ipaddress.ip_network(p).subnet_of(n) for n in PRIVATE))
    assert not private, f"{router} accepted private prefixes from the ISP: {private}"
