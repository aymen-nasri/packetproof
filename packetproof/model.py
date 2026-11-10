"""Load network.yaml, validate it against the schema, and answer questions about it.

The model is deliberately thin: it resolves names (zones, hosts, routers) to addresses and
interfaces so the renderers never re-derive them differently.
"""

from __future__ import annotations

import copy
import ipaddress
import json
from dataclasses import dataclass
from pathlib import Path

import jsonschema
import yaml

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = ROOT / "schema" / "network.schema.json"
PRIVATE = ipaddress.ip_network("172.16.0.0/12")
UPLINK_IF = "eth1"
TUNNEL_IF = "wg0"


@dataclass(frozen=True)
class Iface:
    name: str      # interface name on the router, e.g. eth3
    zone: str      # zone label used by the firewall (normally the zone's own name)
    prefix: str
    gateway: str


class Network:
    def __init__(self, data: dict):
        jsonschema.validate(data, json.loads(SCHEMA.read_text()))
        self.data = data
        self.domain = data["domain"]
        self.sites = {s["name"]: s for s in data["sites"]}
        self.site_by_router = {s["router"]: s for s in data["sites"]}
        self.hosts = {h["name"]: h for h in data["hosts"]}
        self.zones: dict[str, dict] = {}
        self.zone_site: dict[str, str] = {}
        for s in data["sites"]:
            for z in s["zones"]:
                self.zones[z["name"]] = z
                self.zone_site[z["name"]] = s["name"]
        self._check_references()

    @classmethod
    def load(cls, path: Path | str) -> "Network":
        return cls(yaml.safe_load(Path(path).read_text()))

    def copy_data(self) -> dict:
        return copy.deepcopy(self.data)

    # ---- references -----------------------------------------------------------------------
    def _check_references(self) -> None:
        errors = []
        for h in self.data["hosts"]:
            if h["zone"] != "outside" and h["zone"] not in self.zones:
                errors.append(f"host {h['name']}: unknown zone {h['zone']}")
            elif h["zone"] != "outside":
                if ipaddress.ip_address(h["address"]) not in ipaddress.ip_network(self.zones[h["zone"]]["prefix"]):
                    errors.append(f"host {h['name']}: {h['address']} is outside zone {h['zone']}")
        for f in self.data["flows"]:
            for ep in f["from"] + f["to"]:
                kind, _, name = ep.partition(":")
                if kind == "zone" and name not in self.zones:
                    errors.append(f"flow {f['name']}: unknown zone {name}")
                if kind == "host" and name not in self.hosts:
                    errors.append(f"flow {f['name']}: unknown host {name}")
                if kind == "router" and name not in self.site_by_router:
                    errors.append(f"flow {f['name']}: unknown router {name}")
            if not (f.get("tcp") or f.get("udp") or f.get("any_port")):
                errors.append(f"flow {f['name']}: no ports")
        for pf in self.data["nat"]["port_forwards"]:
            if pf["to"] not in self.hosts:
                errors.append(f"port-forward to unknown host {pf['to']}")
        if errors:
            raise ValueError("network.yaml references: " + "; ".join(errors))

    # ---- interfaces -----------------------------------------------------------------------
    def router_ifaces(self, router: str) -> list[Iface]:
        """Zone-facing interfaces of a site router: eth2, eth3, ... in zone order."""
        site = self.site_by_router[router]
        return [Iface(f"eth{i + 2}", z.get("interface_zone", z["name"]), z["prefix"], z["gateway"])
                for i, z in enumerate(site["zones"])]

    def zone_ifaces(self, router: str, zone: str) -> list[str]:
        """Interfaces of `router` that the firewall treats as part of `zone`."""
        return [i.name for i in self.router_ifaces(router) if i.zone == zone]

    def host_address(self, name: str) -> str:
        return self.hosts[name]["address"]

    def host_site(self, name: str) -> str | None:
        zone = self.hosts[name]["zone"]
        return self.zone_site.get(zone)

    def internal_prefixes(self) -> list[str]:
        """Every private prefix the two sites own: zones, loopbacks and the tunnel."""
        out = [z["prefix"] for z in self.zones.values()]
        out += [s["loopback"] for s in self.data["sites"]]
        out.append(self.data["tunnel"]["prefix"])
        return out

    def site_prefixes(self, site_name: str) -> list[str]:
        """The private prefixes one site owns: its zones and its router's loopback."""
        site = next(s for s in self.data["sites"] if s["name"] == site_name)
        return [z["prefix"] for z in site["zones"]] + [site["loopback"]]

    def router_addresses(self, router: str) -> list[str]:
        site = self.site_by_router[router]
        addrs = [site["loopback"].split("/")[0], site["wireguard"]["address"].split("/")[0]]
        addrs += [z["gateway"] for z in site["zones"]]
        return addrs

    def other_site(self, site_name: str) -> dict:
        return next(s for s in self.data["sites"] if s["name"] != site_name)

    def resolve_dns_target(self, target: str) -> str:
        """A DNS record value is either a host name or a literal address."""
        if target in self.hosts:
            return self.host_address(target)
        ipaddress.ip_address(target)
        return target
