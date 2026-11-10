"""FRR configs for the two site routers and the ISP.

Style rules carried over from week 1 (docs/go-no-go.md): blocks end with '!' rather than 'exit'
and there is no 'log stdout' line, because Batfish's FRR grammar has neither.

Profile: `frr defaults traditional`, with the fast timers set explicitly. The datacenter profile
was used until prod's drift check caught an FRR 10.7.1 bug it triggers (FRRouting/frr#22939): with
deterministic-med on, which that profile does by default, `show running-config` prints a spurious
`use-underlays-nexthop-weight`, and removing it (as frr-reload.py does) switches deterministic-med
off. Fixed upstream (FRRouting/frr#22552, backported to stable/10.7) but in no release yet. The
traditional profile also keeps RFC 8212's `ebgp-requires-policy` on by default.
"""

from __future__ import annotations

from .model import TUNNEL_IF, UPLINK_IF, Network

FRR_VERSION = "10.7.1"
PROFILE = "traditional"
KEEPALIVE, HOLD, CONNECT_RETRY = 3, 9, 10   # traditional defaults are 60, 180 and 120 seconds

# What a site router accepts from the ISP: the internet, but never private space or its own prefix.
BOGONS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"]

DAEMONS = """\
# Rendered by packetproof. zebra, mgmtd and watchfrr always run.
bgpd=yes
staticd=yes
ospfd=no
ospf6d=no
ripd=no
ripngd=no
isisd=no
pimd=no
ldpd=no
nhrpd=no
eigrpd=no
babeld=no
sharpd=no
pbrd=no
bfdd=no
fabricd=no
vrrpd=no
pathd=no
vtysh_enable=yes
zebra_options="  -A 127.0.0.1 -s 90000000"
mgmtd_options="  -A 127.0.0.1"
bgpd_options="   -A 127.0.0.1"
staticd_options="-A 127.0.0.1"
"""

VTYSH_CONF = "service integrated-vtysh-config\n"


def _header(name: str) -> list[str]:
    return [f"frr version {FRR_VERSION}", f"frr defaults {PROFILE}", f"hostname {name}",
            "service integrated-vtysh-config", "!"]


def _prefix_list(name: str, entries: list[str], action: str = "permit", start: int = 10) -> list[str]:
    return [f"ip prefix-list {name} seq {start + i * 10} {action} {e}" for i, e in enumerate(entries)]


def site_router(net: Network, site: dict) -> str:
    peer_site = net.other_site(site["name"])
    out = _header(site["router"])
    out += [f"interface {UPLINK_IF}", f" ip address {site['uplink']['address']}", "!"]
    for z, iface in zip(site["zones"], net.router_ifaces(site["router"])):
        out += [f"interface {iface.name}", f" ip address {z['gateway']}/{z['prefix'].split('/')[1]}", "!"]
    out += ["interface lo", f" ip address {site['loopback']}", "!"]
    out += [f"interface {TUNNEL_IF}", f" ip address {site['wireguard']['address']}", "!"]

    # The public prefix is nailed to a blackhole so BGP can advertise it; NAT and port-forward
    # addresses inside it are handled by nftables before routing.
    out.append(f"ip route {site['public_prefix']} blackhole")
    for r in site["static_routes"]:
        out.append(f"ip route {r['prefix']} {r['via']}")
    out.append("!")

    isp_in = _prefix_list("PL-ISP-IN", BOGONS + [f"{site['public_prefix']} le 32"], "deny", 10)
    isp_in += ["ip prefix-list PL-ISP-IN seq 100 permit 0.0.0.0/0 le 32"]
    out += isp_in
    out += _prefix_list("PL-ISP-OUT", site["bgp"]["isp"]["advertise"])
    out += _prefix_list("PL-TUNNEL-IN", site["bgp"]["tunnel"]["accept"])
    out += _prefix_list("PL-TUNNEL-OUT", site["bgp"]["tunnel"]["advertise"])
    out.append("!")
    for rm in ("ISP-IN", "ISP-OUT", "TUNNEL-IN", "TUNNEL-OUT"):
        out += [f"route-map RM-{rm} permit 10", f" match ip address prefix-list PL-{rm}", "!"]

    isp_peer = site["uplink"]["isp_address"]
    tun_peer = site["wireguard"]["peer_address"]
    # RFC 8212 (no route in or out of an eBGP session without a policy) is on by default under the
    # traditional profile; Gate 3's fault F06 is what showed it matters.
    out += [f"router bgp {site['asn']}", f" bgp router-id {site['router_id']}",
            f" timers bgp {KEEPALIVE} {HOLD}",
            f" neighbor {isp_peer} remote-as {site['bgp']['isp']['remote_asn']}",
            f" neighbor {isp_peer} description isp",
            f" neighbor {isp_peer} timers connect {CONNECT_RETRY}",
            f" neighbor {tun_peer} remote-as {site['bgp']['tunnel']['remote_asn']}",
            f" neighbor {tun_peer} description {peer_site['router']} over {TUNNEL_IF}",
            f" neighbor {tun_peer} timers connect {CONNECT_RETRY}",
            " !", " address-family ipv4 unicast", "  redistribute connected", "  redistribute static",
            f"  neighbor {isp_peer} route-map RM-ISP-IN in",
            f"  neighbor {isp_peer} route-map RM-ISP-OUT out",
            f"  neighbor {tun_peer} route-map RM-TUNNEL-IN in",
            f"  neighbor {tun_peer} route-map RM-TUNNEL-OUT out"]
    if site["bgp"]["tunnel"]["default_originate"]:
        out.append(f"  neighbor {tun_peer} default-originate")
    out += [" exit-address-family", "!"]
    return "\n".join(out) + "\n"


def isp_router(net: Network) -> str:
    isp = net.data["isp"]
    sites = net.data["sites"]
    out = _header(isp["name"])
    for i, s in enumerate(sites):
        addr, plen = s["uplink"]["isp_address"], s["uplink"]["address"].split("/")[1]
        out += [f"interface eth{i + 1}", f" ip address {addr}/{plen}", "!"]
    out += [f"interface eth{len(sites) + 1}",
            f" ip address {isp['outside']['gateway']}/{isp['outside']['prefix'].split('/')[1]}", "!"]
    # The ISP is "the internet": it passes whatever its customers send and gives them a default.
    out += ["route-map RM-ANY permit 10", "!"]
    out += [f"router bgp {isp['asn']}", f" bgp router-id {isp['router_id']}", f" timers bgp {KEEPALIVE} {HOLD}"]
    for s in sites:
        peer = s["uplink"]["address"].split("/")[0]
        out += [f" neighbor {peer} remote-as {s['asn']}", f" neighbor {peer} timers connect {CONNECT_RETRY}"]
    out += [" !", " address-family ipv4 unicast", "  redistribute connected"]
    for s in sites:
        peer = s["uplink"]["address"].split("/")[0]
        out += [f"  neighbor {peer} route-map RM-ANY in", f"  neighbor {peer} route-map RM-ANY out",
                f"  neighbor {peer} default-originate"]
    out += [" exit-address-family", "!"]
    return "\n".join(out) + "\n"


# Lines Batfish's FRR grammar does not know, left out of the snapshot. Empty since the move to
# the traditional profile made the explicit `bgp ebgp-requires-policy` unnecessary.
BATFISH_UNSUPPORTED: set[str] = set()


def batfish_file(hostname: str, frr_conf: str, interfaces: list[str]) -> str:
    """Cumulus concatenated format, exactly as week 1 proved Batfish reads it. The few lines
    Batfish's FRR grammar does not know are left out of the snapshot (listed above, and in
    docs/limits.md), so Batfish reads the running config minus exactly those lines."""
    frr_conf = "".join(line for line in frr_conf.splitlines(keepends=True)
                       if line.rstrip("\n") not in BATFISH_UNSUPPORTED)
    lines = [hostname, "# This file describes the network interfaces", "auto lo", "iface lo inet loopback", ""]
    for i in interfaces:
        if i != "lo":
            lines += [f"auto {i}", f"iface {i}", ""]
    lines.append("# ports.conf --")
    return "\n".join(lines) + "\n" + frr_conf
