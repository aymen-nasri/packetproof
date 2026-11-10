"""Render everything for one lab into a directory.

  <out>/topo.clab.yml                containerlab topology (one Linux bridge per zone)
  <out>/routers/<router>/            frr.conf, daemons, vtysh.conf, ruleset.nft, up.sh
  <out>/hosts/<host>/                start.sh plus the host's service configs
  <out>/batfish/configs/<router>.cfg Batfish snapshot (Cumulus concatenated format)
  <out>/intent.json                  network.yaml as JSON, for Conftest
  <out>/shared/                      filled at run time (CA root, test certificates)
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from . import render_frr, render_nft, render_services
from .model import TUNNEL_IF, UPLINK_IF, Network

LAB_NAME = "pp"
MGMT_NETWORK = "pp-mgmt"
MGMT_SUBNET = "192.168.254.0/24"   # outside 172.16.0.0/12 (docs/method.md, amendment A1)
ROUTER_IMAGE = "packetproof/router:dev"
NODE_IMAGE = "packetproof/node:dev"
LINK_MTU = 1500


def bridge_name(zone: str) -> str:
    return f"pp-{zone}"[:15]


def router_up_script(net: Network, router: str) -> str:
    lines = [
        "#!/bin/sh",
        f"# Rendered by packetproof for {router}. Do not edit by hand.",
        "exec >/tmp/pp-up.log 2>&1",
        "set -eux",
        "# containerlab's management network gives every node a default route via eth0. The lab",
        "# must never use it (traffic would leave the lab), so it goes; BGP brings the ISP's default.",
        "ip route del default dev eth0 || true",
    ]
    site = net.site_by_router.get(router)
    if site:
        wg = site["wireguard"]
        port = net.data["tunnel"]["port"]
        lines += [
            "nft -f /pp/ruleset.nft",
            "# The private key is generated here and never leaves this router: the lab runner",
            "# reads only the public key (wg show wg0 public-key) and hands it to the peer.",
            "# It lives under /etc/wireguard because the runner host's AppArmor profile for `wg`",
            "# follows the binary into this container and only lets it read keys there.",
            "mkdir -p /etc/wireguard",
            "umask 077",
            "wg genkey > /etc/wireguard/pp-wg.key",
            "umask 022",
            f"ip link show {TUNNEL_IF} >/dev/null 2>&1 || ip link add {TUNNEL_IF} type wireguard",
            f"wg set {TUNNEL_IF} listen-port {port} private-key /etc/wireguard/pp-wg.key",
            f"ip addr replace {wg['address']} dev {TUNNEL_IF}",
            f"ip link set {TUNNEL_IF} mtu {net.data['tunnel']['mtu']} up",
            "dropbear -R -p 22",
            "touch /tmp/pp-up-done",
        ]
    else:
        mtu = net.data["isp"]["outside"].get("mtu")
        if mtu:
            out_if = f"eth{len(net.data['sites']) + 1}"
            lines += ["# A smaller link in the middle of the path, on the ISP's side only.",
                      f"ip link set {out_if} mtu {mtu}"]
        lines.append("touch /tmp/pp-ready")
    return "\n".join(lines) + "\n"


def wg_peer_script(net: Network, site: dict) -> str:
    """Run by the lab runner with the peer's public key once both routers are up."""
    wg = site["wireguard"]
    port = wg.get("port", net.data["tunnel"]["port"])
    return "\n".join([
        "#!/bin/sh",
        f"# Rendered by packetproof for {site['router']}. Usage: wg-peer.sh PEER_PUBLIC_KEY",
        "set -eu",
        f'wg set {TUNNEL_IF} peer "$1" endpoint {wg["endpoint"]}:{port} '
        f'allowed-ips {",".join(wg["allowed_ips"])} persistent-keepalive 25',
        "touch /tmp/pp-ready",
    ]) + "\n"


def topology(net: Network) -> str:
    sites = net.data["sites"]
    isp = net.data["isp"]
    out = ["# Rendered by packetproof. Do not edit by hand.", f"name: {LAB_NAME}",
           "mgmt:", f"  network: {MGMT_NETWORK}", f"  ipv4-subnet: {MGMT_SUBNET}",
           "topology:", "  nodes:"]
    routers = [s["router"] for s in sites] + [isp["name"]]
    for r in routers:
        out += [f"    {r}:", "      kind: linux", f"      image: {ROUTER_IMAGE}",
                "      sysctls:", "        net.ipv4.ip_forward: 1", "      binds:",
                f"        - routers/{r}/frr.conf:/etc/frr/frr.conf",
                f"        - routers/{r}/daemons:/etc/frr/daemons",
                f"        - routers/{r}/vtysh.conf:/etc/frr/vtysh.conf",
                f"        - routers/{r}:/pp:ro"]
        out += ["      exec:", "        - sh /pp/up.sh"]
    for zone in net.zones:
        out += [f"    {bridge_name(zone)}:", "      kind: bridge"]
    ca = net.data["pki"]["ca"]
    for h in net.data["hosts"]:
        mode = "rw" if h["name"] == ca else "ro"
        out += [f"    {h['name']}:", "      kind: linux", f"      image: {NODE_IMAGE}",
                # Hosts are unprivileged: they only need to set their own address and routes.
                "      privileged: false", "      cap-add:", "        - NET_ADMIN", "      binds:",
                f"        - hosts/{h['name']}:/pp:ro", f"        - shared:/shared:{mode}",
                '      cmd: sh -c "sh /pp/start.sh; exec tail -f /dev/null"']
    out.append("  links:")

    def link(a: str, b: str, mtu: int = LINK_MTU) -> None:
        out.extend([f'    - endpoints: ["{a}", "{b}"]', f"      mtu: {mtu}"])

    for i, s in enumerate(sites):
        link(f"{s['router']}:{UPLINK_IF}", f"{isp['name']}:eth{i + 1}")
    # The outside link is 1500 at both ends; the ISP lowers its own side (see router_up_script),
    # so the outside host still advertises a 1460-byte MSS and path-MTU discovery is really needed.
    link(f"{isp['name']}:eth{len(sites) + 1}", "outside:eth1")
    port_no: dict[str, int] = {}

    def port(zone: str) -> str:
        n = port_no.get(zone, 0)
        port_no[zone] = n + 1
        return f"{bridge_name(zone)}:p-{zone}-{n}"

    for s in sites:
        for z, iface in zip(s["zones"], net.router_ifaces(s["router"])):
            link(f"{s['router']}:{iface.name}", port(z["name"]))
    for h in net.data["hosts"]:
        if h["zone"] != "outside":
            link(f"{h['name']}:eth1", port(h["zone"]))
    return "\n".join(out) + "\n"


def render(net: Network, out: Path) -> None:
    if out.exists():
        shutil.rmtree(out)
    (out / "batfish" / "configs").mkdir(parents=True)
    (out / "shared").mkdir()
    for s in net.data["sites"]:
        r = s["router"]
        d = out / "routers" / r
        d.mkdir(parents=True)
        conf = render_frr.site_router(net, s)
        _write(d / "frr.conf", conf)
        _write(d / "ruleset.nft", render_nft.ruleset(net, s))
        ifaces = [UPLINK_IF] + [i.name for i in net.router_ifaces(r)] + ["lo", TUNNEL_IF]
        _write(out / "batfish" / "configs" / f"{r}.cfg", render_frr.batfish_file(r, conf, ifaces))
        _write(d / "wg-peer.sh", wg_peer_script(net, s))
        if s["wireguard"].get("peer_public_key"):
            _write(d / "peer.pub.override", s["wireguard"]["peer_public_key"] + "\n")
    isp = net.data["isp"]["name"]
    d = out / "routers" / isp
    d.mkdir(parents=True)
    conf = render_frr.isp_router(net)
    _write(d / "frr.conf", conf)
    n = len(net.data["sites"])
    _write(out / "batfish" / "configs" / f"{isp}.cfg",
           render_frr.batfish_file(isp, conf, [f"eth{i}" for i in range(1, n + 2)] + ["lo"]))
    for r in [s["router"] for s in net.data["sites"]] + [isp]:
        d = out / "routers" / r
        _write(d / "daemons", render_frr.DAEMONS)
        _write(d / "vtysh.conf", render_frr.VTYSH_CONF)
        _write(d / "up.sh", router_up_script(net, r))
    for h in net.data["hosts"]:
        d = out / "hosts" / h["name"]
        d.mkdir(parents=True)
        script, files = render_services.start_script(net, h)
        _write(d / "start.sh", script)
        for name, content in files.items():
            _write(d / name, content)
    _write(out / "topo.clab.yml", topology(net))
    _write(out / "intent.json", json.dumps(net.data, indent=2) + "\n")


def _write(path: Path, content: str) -> None:
    path.write_text(content, newline="\n")
