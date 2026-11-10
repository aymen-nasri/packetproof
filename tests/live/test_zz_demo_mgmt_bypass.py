"""DEMONSTRATION ONLY (not to be merged): can a compromised DMZ host reach the database through
containerlab's management network, around the zone firewall?"""


def test_demo_dmz_reaches_db_management_address(lab):
    out = lab.sh("db", "ip -4 -o addr show dev eth0").stdout.split()
    assert len(out) > 3, f"db has no eth0 address: {out}"
    mgmt = out[3].split("/")[0]
    res = lab.tcp_from_dmz(mgmt, 5432)
    assert res != "open", f"a DMZ host reached db's management address {mgmt}:5432 ({res}), around the zone firewall"
