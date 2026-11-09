"""MTU: the tunnel carries 1420-byte packets and no more, and path MTU discovery works both across
the tunnel and through NAT to an outside user whose access line is only 1400 bytes."""

from expect import PUBLIC, RTR_B_WG, ZONE

BIG = 1024 * 1024


def test_tunnel_mtu_is_1420(lab):
    fits = lab.sh("rtr-a", f"ping -M do -s 1392 -c 2 -W 2 {RTR_B_WG}")
    assert fits.returncode == 0, fits.stdout + fits.stderr
    too_big = lab.sh("rtr-a", f"ping -M do -s 1393 -c 1 -W 2 {RTR_B_WG}")
    out = (too_big.stdout + too_big.stderr).lower()
    assert too_big.returncode != 0 and ("mtu=1420" in out or "message too long" in out), out


def test_large_download_across_tunnel(lab):
    res = lab.curl("client-b", f"https://www.{ZONE}/big", "-o /dev/null -w '%{size_download}'", timeout=20)
    assert res.stdout.strip() == str(BIG), res.stdout + res.stderr


def test_large_download_from_outside_through_nat(lab):
    res = lab.curl("outside", f"https://www.{ZONE}/big",
                   f"--resolve www.{ZONE}:443:{PUBLIC} -o /dev/null -w '%{{size_download}}'", timeout=20)
    assert res.stdout.strip() == str(BIG), res.stdout + res.stderr
