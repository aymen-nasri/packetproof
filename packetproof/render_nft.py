"""nftables rulesets for the site routers.

Layout of each ruleset:
  table netdev edge    stateless filter on the uplink, before conntrack (INV-08, like a NACL)
  table inet pp        reverse-path check on zone interfaces (INV-13), then a stateful zone
                       firewall: input (the router itself) and forward (between zones), both
                       default drop (INV-09); every accept comes from `flows` (INV-12)
  table ip nat         port-forwards (DNAT) and source NAT for internet-bound traffic

Zones are interface-based, as in most zone firewalls: a local zone is the set of router
interfaces labelled with it. Remote zones (across the tunnel) are matched by wg0 plus address.
"""

from __future__ import annotations

from .model import TUNNEL_IF, UPLINK_IF, Network

EDGE_BOGONS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"]


def _set(items: list[str]) -> str:
    items = list(dict.fromkeys(items))
    return items[0] if len(items) == 1 else "{ " + ", ".join(items) + " }"


def _quoted_set(items: list[str]) -> str:
    return _set([f'"{i}"' for i in items])


class _Endpoint:
    """How one flow endpoint is matched on one router. `match` is an nft expression, `local`
    says whether the endpoint is the router itself (input chain) rather than a forwarded host."""

    def __init__(self, match: str | None, to_router: bool = False):
        self.match = match
        self.to_router = to_router


def _src(net: Network, router: str, ep: str) -> list[_Endpoint]:
    site = net.site_by_router[router]
    kind, _, name = ep.partition(":")
    if kind == "zone":
        if net.zone_site[name] == site["name"]:
            ifs = net.zone_ifaces(router, name)
            return [_Endpoint(f"iifname {_quoted_set(ifs)}")] if ifs else []
        return [_Endpoint(f'iifname "{TUNNEL_IF}" ip saddr {net.zones[name]["prefix"]}')]
    if kind == "host":
        return [_Endpoint(f"ip saddr {net.host_address(name)}")]
    if kind == "router":
        return [_Endpoint(f"ip saddr {_set(net.router_addresses(name))}")]
    if kind == "internet":
        return [_Endpoint(f'iifname "{UPLINK_IF}"')]
    if kind == "all":
        return [_Endpoint(f"ip saddr {_set(net.internal_prefixes())}")]
    raise ValueError(ep)


def _dst(net: Network, router: str, ep: str) -> list[_Endpoint]:
    site = net.site_by_router[router]
    kind, _, name = ep.partition(":")
    if kind == "zone":
        if net.zone_site[name] == site["name"]:
            ifs = net.zone_ifaces(router, name)
            return [_Endpoint(f"oifname {_quoted_set(ifs)}")] if ifs else []
        return [_Endpoint(f'oifname "{TUNNEL_IF}" ip daddr {net.zones[name]["prefix"]}')]
    if kind == "host":
        if net.hosts[name]["zone"] == "outside":
            return [_Endpoint(f'oifname "{UPLINK_IF}" ip daddr {net.host_address(name)}')]
        return [_Endpoint(f"ip daddr {net.host_address(name)}")]
    if kind == "router":
        if name == router:
            return [_Endpoint(None, to_router=True)]
        return [_Endpoint(f"ip daddr {_set(net.router_addresses(name))}")]
    if kind == "internet":
        return [_Endpoint(f'oifname "{UPLINK_IF}"')]
    if kind == "all":
        # Every internal host and every site router (the outside host and the ISP are not ours).
        return [_Endpoint(f"ip daddr {_set(net.internal_prefixes())}"), _Endpoint(None, to_router=True)]
    raise ValueError(ep)


def _ports(flow: dict) -> list[str]:
    if flow.get("any_port"):
        return [""]
    out = []
    if flow.get("tcp"):
        out.append(f"tcp dport {_set([str(p) for p in flow['tcp']])}")
    if flow.get("udp"):
        out.append(f"udp dport {_set([str(p) for p in flow['udp']])}")
    return out


def flow_rules(net: Network, router: str) -> tuple[list[str], list[str]]:
    """(forward rules, input rules) for one router, in the order of `flows`."""
    fwd, inp = [], []
    for flow in net.data["flows"]:
        for s_ep in flow["from"]:
            for d_ep in flow["to"]:
                for s in _src(net, router, s_ep):
                    for d in _dst(net, router, d_ep):
                        for p in _ports(flow):
                            parts = [x for x in (s.match, d.match, p) if x]
                            rule = " ".join(parts) + f' accept comment "{flow["name"]}"'
                            (inp if d.to_router else fwd).append(rule)
    return list(dict.fromkeys(fwd)), list(dict.fromkeys(inp))


def ruleset(net: Network, site: dict) -> str:
    router = site["router"]
    zone_ifs = [i.name for i in net.router_ifaces(router)]
    isp_peer = site["uplink"]["isp_address"]
    tun_peer = site["wireguard"]["peer_address"]
    fwd, inp = flow_rules(net, router)

    pf_dnat, pf_accept = [], []
    for pf in net.data["nat"]["port_forwards"]:
        if pf["site"] != site["name"]:
            continue
        target = net.host_address(pf["to"])
        for proto in ("tcp", "udp"):
            for port in pf.get(proto, []):
                to_port = pf.get("to_port", port)
                pf_dnat.append(f'iifname "{UPLINK_IF}" ip daddr {pf["public"]} {proto} dport {port} '
                               f'dnat to {target}:{to_port} comment "publish {pf["to"]} {proto}/{port}"')
                pf_accept.append(f'iifname "{UPLINK_IF}" ip daddr {target} {proto} dport {to_port} ct status dnat '
                                 f'accept comment "publish {pf["to"]} {proto}/{port}"')

    snat = []
    for rule in net.data["nat"]["snat"]:
        if rule["site"] != site["name"]:
            continue
        srcs = [net.zones[z]["prefix"] for z in rule["from"]]
        snat.append(f'oifname "{UPLINK_IF}" ip saddr {_set(srcs)} snat to {rule["to"]} comment "egress NAT"')
        if rule.get("include_tunnel"):
            snat.append(f'oifname "{TUNNEL_IF}" masquerade comment "egress NAT into the tunnel"')

    ind = "        "
    lines = [
        "#!/usr/sbin/nft -f",
        f"# Rendered by packetproof for {router}. Do not edit by hand.",
        "flush ruleset",
        "",
        "table netdev edge {",
        "    # INV-08: stateless edge filter on the uplink, before conntrack (like a NACL).",
        "    chain uplink_in {",
        f'        type filter hook ingress device "{UPLINK_IF}" priority -500; policy accept;',
        f'        ip saddr {_set(EDGE_BOGONS + [site["public_prefix"]])} counter drop comment "edge anti-spoof"',
        "    }",
        "}",
        "",
        "table inet pp {",
        "    # INV-13: on zone interfaces, drop packets whose source is not routed back out of the",
        "    # same interface, so one zone cannot pretend to be another.",
        "    chain antispoof {",
        "        type filter hook prerouting priority -150; policy accept;",
        f'        iifname {_quoted_set(zone_ifs)} fib saddr . iif oif missing counter drop comment "reverse-path check"',
        "    }",
        "",
        "    chain input {",
        "        type filter hook input priority filter; policy drop;",
        '        iif "lo" accept',
        "        ct state established,related accept",
        "        ct state invalid drop",
        f'        iifname != "{UPLINK_IF}" icmp type echo-request accept comment "ping the router from inside"',
        f'        iifname "{UPLINK_IF}" ip saddr {isp_peer} tcp dport 179 accept comment "BGP with the ISP"',
        f'        iifname "{UPLINK_IF}" udp dport {net.data["tunnel"]["port"]} accept comment "WireGuard"',
        f'        iifname "{TUNNEL_IF}" ip saddr {tun_peer} tcp dport 179 accept comment "BGP over the tunnel"',
    ] + [ind + r for r in inp] + [
        "    }",
        "",
        "    chain forward {",
        "        type filter hook forward priority filter; policy drop;",
        "        ct state established,related accept",
        "        ct state invalid drop",
    ] + [ind + r for r in fwd + pf_accept] + [
        "    }",
        "",
        "    chain output {",
        "        type filter hook output priority filter; policy accept;",
        "    }",
        "}",
        "",
        "table ip nat {",
        "    chain prerouting {",
        "        type nat hook prerouting priority dstnat; policy accept;",
    ] + [ind + r for r in pf_dnat] + [
        "    }",
        "",
        "    chain postrouting {",
        "        type nat hook postrouting priority srcnat; policy accept;",
    ] + [ind + r for r in snat] + [
        "    }",
        "}",
    ]
    return "\n".join(lines) + "\n"
