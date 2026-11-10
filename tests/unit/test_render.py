"""Fast checks of the generator: no containers needed. Gate 1 runs these first."""

from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml

from packetproof import faults, render_lab
from packetproof.model import ROOT, Network

NETWORK = yaml.safe_load((ROOT / "network.yaml").read_text())
FAULTS = faults.load_faults()


@pytest.fixture(scope="module")
def baseline(tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp("base") / "lab"
    render_lab.render(Network(copy.deepcopy(NETWORK)), out)
    return out


def test_every_router_and_host_rendered(baseline):
    for r in ("rtr-a", "rtr-b", "isp"):
        assert (baseline / "routers" / r / "frr.conf").is_file()
        assert (baseline / "batfish" / "configs" / f"{r}.cfg").is_file()
    for h in NETWORK["hosts"]:
        assert (baseline / "hosts" / h["name"] / "start.sh").is_file()


def test_frr_has_no_syntax_batfish_cannot_read(baseline):
    """Week-1 finding: Batfish's FRR grammar has no plain 'exit' and no 'log stdout'."""
    for r in ("rtr-a", "rtr-b", "isp"):
        lines = (baseline / "routers" / r / "frr.conf").read_text().splitlines()
        assert "exit" not in lines and not any(line.startswith("log ") for line in lines)


def test_frr_profile_keeps_rfc8212_and_avoids_frr_22939(baseline):
    """The datacenter profile turns RFC 8212's ebgp-requires-policy off and turns deterministic-med
    on, which triggers FRR bug #22939 (frr-reload flips deterministic-med). Stay on traditional,
    with the fast timers set explicitly, and feed Batfish the whole config."""
    for r in ("rtr-a", "rtr-b", "isp"):
        text = (baseline / "routers" / r / "frr.conf").read_text()
        assert "frr defaults traditional" in text and "datacenter" not in text
        assert " timers bgp 3 9" in text and "timers connect 10" in text
        assert "deterministic-med" not in text and "ebgp-requires-policy" not in text
        snapshot = (baseline / "batfish" / "configs" / f"{r}.cfg").read_text()
        assert snapshot.endswith(text)


def test_firewalls_default_drop(baseline):
    for r in ("rtr-a", "rtr-b"):
        text = (baseline / "routers" / r / "ruleset.nft").read_text()
        assert "type filter hook forward priority filter; policy drop;" in text
        assert "type filter hook input priority filter; policy drop;" in text


def test_rendering_is_deterministic(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    render_lab.render(Network(copy.deepcopy(NETWORK)), a)
    render_lab.render(Network(copy.deepcopy(NETWORK)), b)
    files_a = sorted(p.relative_to(a) for p in a.rglob("*") if p.is_file())
    files_b = sorted(p.relative_to(b) for p in b.rglob("*") if p.is_file())
    assert files_a == files_b and len(files_a) > 20, (len(files_a), len(files_b))
    differ = [str(f) for f in files_a if (a / f).read_bytes() != (b / f).read_bytes()]
    assert not differ, differ


def test_thirty_faults_defined():
    assert sorted(FAULTS) == [f"F{i:02d}" for i in range(1, 31)]


@pytest.mark.parametrize("fault_id", sorted(FAULTS))
def test_each_fault_applies_and_changes_something(baseline, tmp_path, fault_id):
    fault = FAULTS[fault_id]
    data = faults.apply_intent(copy.deepcopy(NETWORK), fault)
    out = tmp_path / "lab"
    render_lab.render(Network(data), out)
    faults.apply_render(out, fault)
    changed = []
    for f in out.rglob("*"):
        if f.is_file() and f.name != "intent.json":
            base = baseline / f.relative_to(out)
            if not base.exists() or base.read_bytes() != f.read_bytes():
                changed.append(str(f.relative_to(out)))
    intent_changed = data != NETWORK
    assert changed or intent_changed, f"{fault_id} changed nothing"


def test_only_the_ca_mounts_the_managed_secrets(baseline):
    """Prod's SOPS-managed CA root reaches the CA container and nothing else, read-only."""
    topo = yaml.safe_load((baseline / "topo.clab.yml").read_text())
    ca = NETWORK["pki"]["ca"]
    mounts = {n: [b for b in d.get("binds", []) if "secrets" in b] for n, d in topo["topology"]["nodes"].items()}
    assert mounts.pop(ca) == ["secrets/ca:/pp-secrets:ro"]
    assert not any(mounts.values()), mounts
    assert (baseline / "secrets" / "ca").is_dir() and not any((baseline / "secrets" / "ca").iterdir())
    start = (baseline / "hosts" / ca / "start.sh").read_text()
    assert "[ -s /pp-secrets/root_ca.key ]" in start and "--acme $ROOT" in start


def test_secrets_files_keep_private_material_out_of_the_public_half(tmp_path):
    """scripts/secrets_files.py: the public file has public keys and the root's fingerprint only."""
    import base64
    import hashlib
    import subprocess
    import sys

    der = b"not a real certificate, only bytes to fingerprint"
    pem = "-----BEGIN CERTIFICATE-----\n" + base64.encodebytes(der).decode() + "-----END CERTIFICATE-----\n"
    plain = tmp_path / "plain"
    plain.mkdir()
    for r, (k, p) in {"rtr-a": ("PRIV-A", "PUB-A"), "rtr-b": ("PRIV-B", "PUB-B")}.items():
        (plain / f"{r}.key").write_text(k + "\n")
        (plain / f"{r}.pub").write_text(p + "\n")
    (plain / "root_ca.crt").write_text(pem)
    (plain / "root_ca.key").write_text("-----BEGIN EC PRIVATE KEY-----\nSECRET\n-----END EC PRIVATE KEY-----\n")
    out = subprocess.run([sys.executable, str(ROOT / "scripts" / "secrets_files.py"), "--plain", str(plain),
                          "--out-secret", str(tmp_path / "s.yaml"), "--out-public", str(tmp_path / "p.yaml")],
                         capture_output=True, text=True, check=True).stdout
    public_text = (tmp_path / "p.yaml").read_text()
    for private in ("PRIV-A", "PRIV-B", "SECRET", "PRIVATE KEY"):
        assert private not in public_text and private not in out
    public = yaml.safe_load(public_text)
    assert public["wireguard_public_keys"] == {"rtr-a": "PUB-A", "rtr-b": "PUB-B"}
    assert public["ca_root_fingerprint_sha256"] == hashlib.sha256(der).hexdigest()
    secret = yaml.safe_load((tmp_path / "s.yaml").read_text())
    assert secret["wireguard"] == {"rtr-a": "PRIV-A", "rtr-b": "PRIV-B"}
    assert secret["ca"]["root_cert"] == pem and "SECRET" in secret["ca"]["root_key"]


def test_no_node_joins_the_management_network(baseline):
    """Review of v1.0.0: containerlab's management network put every node on one shared L2
    segment, a path between hosts that never crossed a router. No node may join it."""
    topo = yaml.safe_load((baseline / "topo.clab.yml").read_text())
    nodes = {n: d for n, d in topo["topology"]["nodes"].items() if d.get("kind") == "linux"}
    assert nodes and all(d.get("network-mode") == "none" for d in nodes.values()), \
        {n: d.get("network-mode") for n, d in nodes.items()}


def test_site_routers_forward_only_after_their_firewall_loads(baseline):
    topo = yaml.safe_load((baseline / "topo.clab.yml").read_text())
    for r in ("rtr-a", "rtr-b"):
        assert topo["topology"]["nodes"][r]["sysctls"]["net.ipv4.ip_forward"] == 0
        up = (baseline / "routers" / r / "up.sh").read_text().splitlines()
        assert up.index("nft -f /pp/ruleset.nft") < up.index("echo 1 > /proc/sys/net/ipv4/ip_forward")


def test_isp_filter_refuses_private_space_at_every_length(baseline):
    """Without `le 32`, `deny 172.16.0.0/12` matches only the /12 itself, and a more specific
    private route from the ISP would be accepted (review of v1.0.0)."""
    for r in ("rtr-a", "rtr-b"):
        lines = (baseline / "routers" / r / "frr.conf").read_text().splitlines()
        for bogon in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"):
            assert any(l.startswith("ip prefix-list PL-ISP-IN") and l.endswith(f"deny {bogon} le 32") for l in lines), (r, bogon)


def test_cross_site_rules_are_pinned_to_the_tunnel(baseline):
    """INV-07 and INV-04 as a backstop in the firewall: a rule for the other site's addresses never
    lets traffic leave by the uplink, and a router never forwards the other site's users to the
    internet (their own router does that, with its own NAT)."""
    other = {"rtr-a": ("172.24.",), "rtr-b": ("172.16.",)}
    for r in ("rtr-a", "rtr-b"):
        for line in (baseline / "routers" / r / "ruleset.nft").read_text().splitlines():
            line = line.strip()
            if not line.endswith('"') or " accept " not in line or "ct status dnat" in line:
                continue
            remote = any(f"ip saddr {p}" in line or f"ip daddr {p}" in line for p in other[r]) or \
                any(f"ip saddr {{ {p}" in line or f"ip daddr {{ {p}" in line for p in other[r])
            if remote:
                assert '"wg0"' in line and 'oifname "eth1"' not in line, (r, line)


def test_dmz_and_db_hosts_get_only_the_names_they_use(baseline):
    """A compromised DMZ host is not handed the inside DNS view: haproxy gets the CA's name for
    ACME and nothing else; ns1 and db get none."""
    def hosts_lines(h):
        return [l for l in (baseline / "hosts" / h / "start.sh").read_text().splitlines() if "/etc/hosts" in l]
    assert hosts_lines("haproxy") == ["echo '172.16.50.10 ca.packetproof.example' >> /etc/hosts"]
    assert hosts_lines("ns1") == [] and hosts_lines("db") == []
