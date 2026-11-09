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
