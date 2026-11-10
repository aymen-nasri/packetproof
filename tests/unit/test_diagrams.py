"""The architecture diagrams in docs/images/ are drawn from the repository's own sources by
scripts/diagrams.py. A change to network.yaml, faults.yaml or the attack paths must come with
redrawn images, or the README would show a network that no longer exists."""

import importlib.util
import xml.dom.minidom
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
IMAGES = ROOT / "docs" / "images"

spec = importlib.util.spec_from_file_location("diagrams", ROOT / "scripts" / "diagrams.py")
diagrams = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diagrams)


def test_committed_diagrams_are_current():
    drawn = diagrams.draw_all()
    stale = [n for n, body in drawn.items()
             if not (IMAGES / n).exists() or (IMAGES / n).read_text(encoding="utf-8") != body]
    assert not stale, f"out of date: {stale}; redraw them with `make diagrams`"


def test_every_diagram_has_a_light_and_a_dark_version_and_is_valid_svg():
    drawn = diagrams.draw_all()
    for name in diagrams.DIAGRAMS:
        for f in (f"{name}.svg", f"{name}-dark.svg"):
            doc = xml.dom.minidom.parseString(drawn[f])
            assert doc.documentElement.tagName == "svg"
            assert doc.getElementsByTagName("title"), f"{f} has no accessible title"


def test_no_committed_image_is_orphaned():
    expected = {f"{n}{s}.svg" for n in diagrams.DIAGRAMS for s in ("", "-dark")}
    assert {p.name for p in IMAGES.glob("*.svg")} == expected


def test_the_detailed_network_diagram_shows_every_host_address():
    body = diagrams.draw_all()["network-detail.svg"]
    for h in diagrams.Network.load(ROOT / "network.yaml").data["hosts"]:
        assert h["address"] in body, f"{h['name']} {h['address']} is missing from the diagram"
