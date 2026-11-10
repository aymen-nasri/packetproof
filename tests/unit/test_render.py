"""Fast checks of the generator: no containers needed. Gate 1 runs these first."""

from __future__ import annotations

import copy
import filecmp
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
    cmp = filecmp.dircmp(a, b)
    assert not cmp.diff_files and not cmp.left_only and not cmp.right_only


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
