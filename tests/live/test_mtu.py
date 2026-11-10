"""MTU: the tunnel carries 1420-byte packets and no more, and path MTU discovery works both across
the tunnel and through NAT to an outside user whose access line is only 1400 bytes."""

import re

from expect import PUBLIC, RTR_B_WG, ZONE

BIG = 1024 * 1024


def _state(lab) -> str:
    return lab.sh("rtr-a", f"ip -o link show wg0; ip route get {RTR_B_WG}").stdout


def test_tunnel_interface_mtu_is_1420(lab):
    out = lab.sh("rtr-a", "ip -o link show wg0").stdout
    assert re.search(r"\bmtu 1420\b", out), out


def test_full_size_packet_crosses_tunnel(lab):
    """1392 bytes of ICMP data + 8 ICMP + 20 IP = 1420, the tunnel MTU, with don't-fragment set."""
    res = lab.sh("rtr-a", f"ping -M do -s 1392 -c 2 -W 2 {RTR_B_WG}")
    assert res.returncode == 0, res.stdout + res.stderr + _state(lab)


def test_oversized_packet_does_not_cross_whole(lab):
    """One byte more must not cross as one packet: the sender is told the MTU, or it is dropped."""
    res = lab.sh("rtr-a", f"ping -M do -s 1393 -c 2 -W 2 {RTR_B_WG}; echo rc=$?")
    out = res.stdout + res.stderr
    assert "rc=0" not in out, f"a 1421-byte don't-fragment packet crossed the tunnel:\n{out}\n{_state(lab)}"


def test_large_download_across_tunnel(lab):
    res = lab.curl("client-b", f"https://www.{ZONE}/big", "-o /dev/null -w '%{size_download}'", timeout=20)
    assert res.stdout.strip() == str(BIG), res.stdout + res.stderr


def test_large_download_from_outside_through_nat(lab):
    res = lab.curl("outside", f"https://www.{ZONE}/big",
                   f"--resolve www.{ZONE}:443:{PUBLIC} -o /dev/null -w '%{{size_download}}'", timeout=20)
    assert res.stdout.strip() == str(BIG), res.stdout + res.stderr


def test_path_mtu_discovery_happened_through_nat(lab):
    """After the download, haproxy must have learned the 1400-byte path to the outside host from
    the ISP's ICMP "fragmentation needed", translated back through rtr-a's NAT. Without this the
    download test could pass without path-MTU discovery ever running (Gate 3, fault F11)."""
    lab.curl("outside", f"https://www.{ZONE}/big", f"--resolve www.{ZONE}:443:{PUBLIC} -o /dev/null", timeout=20)
    out = lab.sh("haproxy", "ip route get 192.0.2.10").stdout
    assert "mtu 1400" in out, out
