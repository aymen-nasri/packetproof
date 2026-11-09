#!/usr/bin/env python3
"""Render the two week-1 labs from one description.

The same data produces three things, so they cannot drift apart:
  - FRR configs for each router (what the live lab runs),
  - a containerlab topology,
  - a Batfish snapshot in the Cumulus "concatenated" format (what Batfish reads).

Usage:
  python3 week1/render.py --lab w1-bgp --out build/w1-bgp [--fault W1-F]

This is the week-1 prototype of the generator. Week 2 replaces the dicts below with
network.yaml and a schema; the rendering ideas carry over.
"""

from __future__ import annotations

import argparse
import copy
import json
import shutil
from pathlib import Path

FRR_VERSION = "10.7.1"
ROUTER_IMAGE = "packetproof/router:w1"
HOST_IMAGE = "alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf"
MGMT_NETWORK = "pp-mgmt"
MGMT_SUBNET = "192.168.254.0/24"

# The two week-1 topologies, exactly as docs/method.md part 1 describes them.
LABS: dict[str, dict] = {
    "w1-bgp": {
        "routers": {
            "rtr-a": {
                "asn": 65001,
                "router_id": "172.16.255.1",
                "interfaces": [("eth1", "198.51.100.1/31"), ("eth2", "172.16.10.1/24"), ("lo", "172.16.255.1/32")],
                "static": [],
                "bgp": [{"name": "ISP", "peer": "198.51.100.0", "asn": 65000,
                         "in": ["172.24.10.0/24"], "out": ["172.16.10.0/24"]}],
            },
            "isp": {
                "asn": 65000,
                "router_id": "198.51.100.0",
                "interfaces": [("eth1", "198.51.100.0/31"), ("eth2", "203.0.113.0/31")],
                "static": [],
                # The ISP is "the internet": it passes whatever its customers send.
                "bgp": [{"name": "RTR-A", "peer": "198.51.100.1", "asn": 65001, "in": None, "out": None},
                        {"name": "RTR-B", "peer": "203.0.113.1", "asn": 65002, "in": None, "out": None}],
            },
            "rtr-b": {
                "asn": 65002,
                "router_id": "172.24.255.1",
                "interfaces": [("eth1", "203.0.113.1/31"), ("eth2", "172.24.10.1/24"), ("lo", "172.24.255.1/32")],
                "static": [],
                "bgp": [{"name": "ISP", "peer": "203.0.113.0", "asn": 65000,
                         "in": ["172.16.10.0/24"], "out": ["172.24.10.0/24"]}],
            },
        },
        "hosts": {
            "client-a": {"addr": "172.16.10.10/24", "gw": "172.16.10.1"},
            "client-b": {"addr": "172.24.10.10/24", "gw": "172.24.10.1"},
        },
        "links": [("rtr-a:eth1", "isp:eth1"), ("rtr-a:eth2", "client-a:eth1"),
                  ("isp:eth2", "rtr-b:eth1"), ("rtr-b:eth2", "client-b:eth1")],
        "expect": {
            # Every BGP session, seen from both ends.
            "sessions": {"rtr-a": ["198.51.100.0"], "isp": ["198.51.100.1", "203.0.113.1"], "rtr-b": ["203.0.113.0"]},
            # Routes each router must have learned by BGP.
            "bgp_routes": {"rtr-a": ["172.24.10.0/24"], "rtr-b": ["172.16.10.0/24"]},
            # The only private prefixes allowed in isp's table.
            "private_exact": {"isp": ["172.16.10.0/24", "172.24.10.0/24"]},
            "private_absent": {},
            "pings": [("client-a", "172.24.10.10"), ("client-b", "172.16.10.10")],
        },
    },
    "w1-wg": {
        "routers": {
            "rtr-a": {
                "asn": 65001,
                "router_id": "172.16.255.1",
                "interfaces": [("eth1", "198.51.100.1/31"), ("eth2", "172.16.10.1/24"), ("lo", "172.16.255.1/32"),
                               ("wg0", "172.31.255.0/31")],
                "static": [("203.0.113.0/31", "198.51.100.0")],
                "bgp": [{"name": "RTR-B", "peer": "172.31.255.1", "asn": 65002,
                         "in": ["172.24.10.0/24"], "out": ["172.16.10.0/24"]}],
                "wg": {"address": "172.31.255.0/31", "endpoint": "203.0.113.1:51820",
                       "allowed_ips": ["172.31.255.1/32", "172.24.10.0/24"], "peer": "rtr-b"},
            },
            "isp": {
                "asn": None,  # no BGP: isp only knows its two connected links
                "router_id": "198.51.100.0",
                "interfaces": [("eth1", "198.51.100.0/31"), ("eth2", "203.0.113.0/31")],
                "static": [],
                "bgp": [],
            },
            "rtr-b": {
                "asn": 65002,
                "router_id": "172.24.255.1",
                "interfaces": [("eth1", "203.0.113.1/31"), ("eth2", "172.24.10.1/24"), ("lo", "172.24.255.1/32"),
                               ("wg0", "172.31.255.1/31")],
                "static": [("198.51.100.0/31", "203.0.113.0")],
                "bgp": [{"name": "RTR-A", "peer": "172.31.255.0", "asn": 65001,
                         "in": ["172.16.10.0/24"], "out": ["172.24.10.0/24"]}],
                "wg": {"address": "172.31.255.1/31", "endpoint": "198.51.100.1:51820",
                       "allowed_ips": ["172.31.255.0/32", "172.16.10.0/24"], "peer": "rtr-a"},
            },
        },
        "hosts": {
            "client-a": {"addr": "172.16.10.10/24", "gw": "172.16.10.1"},
            "client-b": {"addr": "172.24.10.10/24", "gw": "172.24.10.1"},
        },
        "links": [("rtr-a:eth1", "isp:eth1"), ("rtr-a:eth2", "client-a:eth1"),
                  ("isp:eth2", "rtr-b:eth1"), ("rtr-b:eth2", "client-b:eth1")],
        "expect": {
            "sessions": {"rtr-a": ["172.31.255.1"], "rtr-b": ["172.31.255.0"]},
            "bgp_routes": {"rtr-a": ["172.24.10.0/24"], "rtr-b": ["172.16.10.0/24"]},
            "private_exact": {},
            # isp must not know either LAN, so a successful ping can only have crossed the tunnel.
            "private_absent": {"isp": ["172.16.10.0/24", "172.24.10.0/24"]},
            "pings": [("client-a", "172.24.10.10"), ("client-b", "172.16.10.10")],
            "wg_routers": ["rtr-a", "rtr-b"],
            "capture": {"node": "isp", "intf": "eth1", "src": "client-a", "dst": "172.24.10.10",
                        "lan_pair": ["172.16.10.10", "172.24.10.10"]},
        },
    },
}

# Planted errors. W1-F is the week-1 error from docs/method.md: rtr-a's export prefix-list
# is widened so that its loopback leaks to the ISP.
FAULTS: dict[str, dict] = {
    "W1-F": {"lab": "w1-bgp", "router": "rtr-a", "neighbor": "ISP", "direction": "out",
             "replace": ("172.16.10.0/24", "172.16.0.0/16 le 32")},
}

DAEMONS = """\
# Rendered by week1/render.py. zebra, mgmtd and watchfrr always run.
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


def apply_fault(lab: dict, fault_id: str | None) -> dict:
    """Return a copy of the lab with the planted fault applied (or unchanged)."""
    lab = copy.deepcopy(lab)
    if not fault_id:
        return lab
    fault = FAULTS[fault_id]
    router = lab["routers"][fault["router"]]
    for nbr in router["bgp"]:
        if nbr["name"] == fault["neighbor"]:
            old, new = fault["replace"]
            entries = nbr[fault["direction"]]
            if old not in entries:
                raise SystemExit(f"fault {fault_id}: {old} not found")
            nbr[fault["direction"]] = [new if e == old else e for e in entries]
            return lab
    raise SystemExit(f"fault {fault_id}: neighbor {fault['neighbor']} not found")


def frr_conf(name: str, r: dict) -> str:
    """One router's frr.conf. Blocks end with '!' rather than 'exit': FRR accepts both, and
    Batfish's FRR grammar has no 'exit' token (found by reading the grammar before any run)."""
    out = [f"frr version {FRR_VERSION}", "frr defaults datacenter", f"hostname {name}",
           "service integrated-vtysh-config", "!"]
    for intf, addr in r["interfaces"]:
        out += [f"interface {intf}", f" ip address {addr}", "!"]
    for prefix, nexthop in r["static"]:
        out.append(f"ip route {prefix} {nexthop}")
    if r["static"]:
        out.append("!")
    if not r["bgp"]:
        return "\n".join(out) + "\n"

    for nbr in r["bgp"]:
        for direction in ("in", "out"):
            entries = nbr[direction]
            if entries is None:
                continue
            pl = f"PL-{nbr['name']}-{direction.upper()}"
            for i, entry in enumerate(entries, start=1):
                out.append(f"ip prefix-list {pl} seq {i * 10} permit {entry}")
    out.append("!")
    for nbr in r["bgp"]:
        for direction in ("in", "out"):
            rm = f"RM-{nbr['name']}-{direction.upper()}"
            out.append(f"route-map {rm} permit 10")
            if nbr[direction] is not None:
                out.append(f" match ip address prefix-list PL-{nbr['name']}-{direction.upper()}")
            out.append("!")
    out += [f"router bgp {r['asn']}", f" bgp router-id {r['router_id']}"]
    for nbr in r["bgp"]:
        out.append(f" neighbor {nbr['peer']} remote-as {nbr['asn']}")
    out += [" !", " address-family ipv4 unicast", "  redistribute connected"]
    for nbr in r["bgp"]:
        out.append(f"  neighbor {nbr['peer']} route-map RM-{nbr['name']}-IN in")
        out.append(f"  neighbor {nbr['peer']} route-map RM-{nbr['name']}-OUT out")
    out += [" exit-address-family", "!"]
    return "\n".join(out) + "\n"


def batfish_file(name: str, r: dict) -> str:
    """The Cumulus concatenated format: hostname, /etc/network/interfaces,
    /etc/cumulus/ports.conf, then frr.conf. The interfaces section only declares the
    interfaces; their addresses live in frr.conf, which is what FRR itself applies."""
    lines = [name, "# This file describes the network interfaces", "auto lo", "iface lo inet loopback", ""]
    for intf, _ in r["interfaces"]:
        if intf != "lo":
            lines += [f"auto {intf}", f"iface {intf}", ""]
    lines += ["# ports.conf --"]
    return "\n".join(lines) + "\n" + frr_conf(name, r)


def wg_up_script(name: str, r: dict) -> str:
    """Bring up wg0 with kernel WireGuard. Keys are mounted read-only at run time and never
    rendered into the repository."""
    wg = r["wg"]
    allowed = ",".join(wg["allowed_ips"])
    return f"""#!/bin/sh
# Rendered by week1/render.py for {name}. Keys come from /etc/wireguard (mounted at run time).
set -eu
ip link add wg0 type wireguard
wg set wg0 listen-port 51820 private-key /etc/wireguard/private.key \\
  peer "$(cat /etc/wireguard/peer.pub)" endpoint {wg['endpoint']} \\
  allowed-ips {allowed} persistent-keepalive 25
ip addr replace {wg['address']} dev wg0
ip link set wg0 mtu 1420 up
"""


def clab_topology(lab_name: str, lab: dict) -> str:
    """containerlab topology. Written as YAML by hand so the file reads cleanly in review."""
    out = ["# Rendered by week1/render.py. Do not edit by hand.", f"name: {lab_name}",
           # containerlab's out-of-band management network stays outside 172.16.0.0/12, so it can
           # never be mistaken for a lab prefix (docs/method.md, amendment A1).
           "mgmt:", f"  network: {MGMT_NETWORK}", f"  ipv4-subnet: {MGMT_SUBNET}",
           "topology:", "  nodes:"]
    for name, r in lab["routers"].items():
        out += [f"    {name}:", "      kind: linux", f"      image: {ROUTER_IMAGE}",
                "      sysctls:", "        net.ipv4.ip_forward: 1", "      binds:",
                f"        - configs/{name}/frr.conf:/etc/frr/frr.conf",
                f"        - configs/{name}/daemons:/etc/frr/daemons",
                f"        - configs/{name}/vtysh.conf:/etc/frr/vtysh.conf"]
        if "wg" in r:
            out += [f"        - keys/{name}.key:/etc/wireguard/private.key:ro",
                    f"        - keys/{r['wg']['peer']}.pub:/etc/wireguard/peer.pub:ro",
                    f"        - configs/{name}/wg-up.sh:/etc/wireguard/wg-up.sh:ro",
                    "      exec:", "        - sh /etc/wireguard/wg-up.sh"]
    for name, h in lab["hosts"].items():
        # Hosts run unprivileged with only NET_ADMIN, so they can set their own address.
        out += [f"    {name}:", "      kind: linux", f"      image: {HOST_IMAGE}",
                "      privileged: false", "      cap-add:", "        - NET_ADMIN",
                "      cmd: sleep 86400", "      exec:",
                f"        - ip addr add {h['addr']} dev eth1",
                f"        - ip route replace default via {h['gw']} dev eth1"]
    out += ["  links:"]
    for a, b in lab["links"]:
        out.append(f'    - endpoints: ["{a}", "{b}"]')
    return "\n".join(out) + "\n"


def render(lab_name: str, out_dir: Path, fault: str | None = None) -> dict:
    if fault and FAULTS[fault]["lab"] != lab_name:
        raise SystemExit(f"fault {fault} belongs to {FAULTS[fault]['lab']}, not {lab_name}")
    lab = apply_fault(LABS[lab_name], fault)
    if out_dir.exists():
        shutil.rmtree(out_dir)
    (out_dir / "batfish" / "configs").mkdir(parents=True)
    for name, r in lab["routers"].items():
        cfg = out_dir / "configs" / name
        cfg.mkdir(parents=True)
        (cfg / "frr.conf").write_text(frr_conf(name, r), newline="\n")
        (cfg / "daemons").write_text(DAEMONS, newline="\n")
        (cfg / "vtysh.conf").write_text(VTYSH_CONF, newline="\n")
        if "wg" in r:
            (cfg / "wg-up.sh").write_text(wg_up_script(name, r), newline="\n")
        (out_dir / "batfish" / "configs" / f"{name}.cfg").write_text(batfish_file(name, r), newline="\n")
    (out_dir / "topo.clab.yml").write_text(clab_topology(lab_name, lab), newline="\n")
    meta = {"lab": lab_name, "fault": fault, "expect": lab["expect"]}
    (out_dir / "lab.json").write_text(json.dumps(meta, indent=2) + "\n", newline="\n")
    return meta


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--lab", required=True, choices=sorted(LABS))
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--fault", choices=sorted(FAULTS))
    args = ap.parse_args()
    render(args.lab, args.out, args.fault)
    print(f"rendered {args.lab}{' with ' + args.fault if args.fault else ''} into {args.out}")


if __name__ == "__main__":
    main()
