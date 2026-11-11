#!/usr/bin/env python3
"""Draw the architecture diagrams in docs/images/ from the repository's own sources.

Every diagram is written twice, for GitHub's light and dark themes: <name>.svg and <name>-dark.svg.
The network diagrams read network.yaml through packetproof.model (the same code that renders the
configs), the grading diagram reads faults/faults.yaml, and the attack paths come from
gate3/scorecard.py. So a picture cannot quietly drift from the system it shows:
tests/unit/test_diagrams.py fails when a committed image is not what this script draws.

Usage: python scripts/diagrams.py [--out docs/images] [--check]
"""

from __future__ import annotations

import argparse
import html
import sys
from collections import Counter
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from packetproof.model import TUNNEL_IF, UPLINK_IF, Network  # noqa: E402

FONT = "-apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans', Helvetica, Arial, sans-serif"
MONO = "ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, 'Liberation Mono', monospace"
W = 960

PALETTE = {
    "light": {"bg": "#ffffff", "panel": "#f6f8fa", "card": "#ffffff", "border": "#d1d9e0",
              "text": "#1f2328", "muted": "#59636e", "faint": "#818b98", "line": "#818b98", "row": "#f6f8fa"},
    "dark": {"bg": "#0d1117", "panel": "#151b23", "card": "#0d1117", "border": "#3d444d",
             "text": "#f0f6fc", "muted": "#9198a1", "faint": "#6e7681", "line": "#6e7681", "row": "#151b23"},
}
ACCENT = {  # (fill, stroke) in each theme
    "gray": {"light": ("#f6f8fa", "#59636e"), "dark": ("#212830", "#9198a1")},
    "blue": {"light": ("#ddf4ff", "#0969da"), "dark": ("#0e2a4a", "#4493f8")},
    "green": {"light": ("#dafbe1", "#1a7f37"), "dark": ("#112d1b", "#3fb950")},
    "orange": {"light": ("#fff1e5", "#bc4c00"), "dark": ("#3a2010", "#f0883e")},
    "purple": {"light": ("#fbefff", "#8250df"), "dark": ("#2a1c45", "#ab7df8")},
    "teal": {"light": ("#d8f5f3", "#0b7a75"), "dark": ("#0b2e2d", "#2ec4b6")},
    "red": {"light": ("#ffebe9", "#cf222e"), "dark": ("#3d1418", "#f85149")},
    "yellow": {"light": ("#fff8c5", "#9a6700"), "dark": ("#342a08", "#d29922")},
    "indigo": {"light": ("#eceffe", "#4c5bd4"), "dark": ("#1c2046", "#8b97f6")},
    "pink": {"light": ("#ffeff7", "#bf3989"), "dark": ("#3a1530", "#f778ba")},
}
ZONE_ACCENT = (("lan", "green"), ("dmz", "orange"), ("app", "blue"), ("db", "purple"), ("svc", "teal"))
LAYER_ACCENT = {"BGP": "blue", "Routing": "blue", "Firewall": "orange", "NAT": "orange", "WireGuard": "indigo",
                "MTU": "indigo", "DNS": "teal", "TLS": "purple", "Proxy": "green"}
ROLE_NOUN = {"client": "users", "admin": "admin", "monitor": "monitoring", "proxy": "HTTPS proxy",
             "dns-authoritative": "public DNS", "app": "app servers", "db": "database",
             "dns-resolver": "DNS resolver", "ca": "certificate authority", "outside": "internet server"}
ROLE_SOFTWARE = {"client": "client", "admin": "admin host", "monitor": "Prometheus", "proxy": "HAProxy",
                 "dns-authoritative": "NSD", "app": "HTTP app", "db": "TCP 5432", "dns-resolver": "Unbound",
                 "ca": "step-ca", "outside": "web, DNS"}


def zone_accent(zone: str) -> str:
    return next((a for prefix, a in ZONE_ACCENT if zone.startswith(prefix)), "gray")


# ---- text measurement: an estimate, deliberately on the wide side ------------------------------
NARROW, SEMI, WIDE = set("il.,:;|!'`"), set("fjrtI()[]{}/-·  "), set("mwMW@%")


def text_width(s: str, size: float, mono: bool = False, bold: bool = False) -> float:
    if mono:
        return len(s) * size * 0.61
    w = 0.0
    for ch in s:
        if ch in NARROW:
            w += 0.27
        elif ch in SEMI:
            w += 0.34
        elif ch in WIDE:
            w += 0.84
        elif ch.isupper() or ch in "&→←":
            w += 0.67
        elif ch.isdigit():
            w += 0.57
        else:
            w += 0.53
    return w * size * (1.06 if bold else 1.0)


def wrap(s: str, width: float, size: float, mono: bool = False, bold: bool = False) -> list[str]:
    lines, cur = [], ""
    for word in s.split():
        trial = f"{cur} {word}".strip()
        if cur and text_width(trial, size, mono, bold) > width:
            lines.append(cur)
            cur = word
        else:
            cur = trial
    return lines + ([cur] if cur else [])


# ---- the drawing surface ---------------------------------------------------------------------
class Svg:
    def __init__(self, theme: str, title: str, subtitle: str, source: str, height: int = 600):
        self.theme, self.c = theme, PALETTE[theme]
        self.title, self.subtitle, self.source = title, subtitle, source
        self.h = height
        self.body: list[str] = []
        self.markers: dict[str, str] = {}

    def acc(self, name: str) -> tuple[str, str]:
        return ACCENT[name][self.theme]

    def rect(self, x, y, w, h, fill, stroke=None, rx=8, sw=1.0, dash=None):
        st = f' stroke="{stroke}" stroke-width="{sw:g}"' if stroke else ""
        da = f' stroke-dasharray="{dash}"' if dash else ""
        self.body.append(f'<rect x="{x:g}" y="{y:g}" width="{w:g}" height="{h:g}" rx="{rx:g}" fill="{fill}"{st}{da}/>')

    def text(self, x, y, s, size=13, color=None, weight=400, anchor="start", mono=False, spacing=None):
        fam = "m" if mono else "s"
        ls = f' letter-spacing="{spacing}"' if spacing else ""
        wt = f' font-weight="{weight}"' if weight != 400 else ""
        an = f' text-anchor="{anchor}"' if anchor != "start" else ""
        self.body.append(f'<text x="{x:g}" y="{y:g}" class="{fam}" font-size="{size:g}" fill="{color or self.c["text"]}"'
                         f'{wt}{an}{ls}>{html.escape(s)}</text>')

    def kicker(self, x, y, s, color=None, anchor="start"):
        self.text(x, y, s.upper(), size=10.5, color=color or self.c["muted"], weight=600, spacing="0.06em", anchor=anchor)

    def marker(self, color: str) -> str:
        mid = "a" + color.lstrip("#")
        self.markers[mid] = color
        return mid

    def path(self, pts, color=None, sw=1.5, dash=None, head=True, tail=False, r=8):
        color = color or self.c["line"]
        d = f"M{pts[0][0]:g},{pts[0][1]:g}"
        for i in range(1, len(pts)):
            x, y = pts[i]
            if 0 < i < len(pts) - 1 and r:
                px, py = pts[i - 1]
                nx, ny = pts[i + 1]
                l1, l2 = abs(x - px) + abs(y - py), abs(nx - x) + abs(ny - y)
                rr = min(r, l1 / 2, l2 / 2)
                ax = x - (rr if x > px else -rr if x < px else 0)
                ay = y - (rr if y > py else -rr if y < py else 0)
                bx = x + (rr if nx > x else -rr if nx < x else 0)
                by = y + (rr if ny > y else -rr if ny < y else 0)
                d += f" L{ax:g},{ay:g} Q{x:g},{y:g} {bx:g},{by:g}"
            else:
                d += f" L{x:g},{y:g}"
        m = self.marker(color)
        mk = (f' marker-end="url(#{m})"' if head else "") + (f' marker-start="url(#{m})"' if tail else "")
        da = f' stroke-dasharray="{dash}"' if dash else ""
        self.body.append(f'<path d="{d}" fill="none" stroke="{color}" stroke-width="{sw:g}" stroke-linejoin="round"{da}{mk}/>')

    def line(self, x1, y1, x2, y2, color=None, sw=1.0, dash=None):
        da = f' stroke-dasharray="{dash}"' if dash else ""
        self.body.append(f'<line x1="{x1:g}" y1="{y1:g}" x2="{x2:g}" y2="{y2:g}" stroke="{color or self.c["border"]}" '
                         f'stroke-width="{sw:g}"{da}/>')

    def pill(self, x, y, label, accent="gray", size=11.5, h=22, mono=False, solid=False) -> float:
        fill, stroke = self.acc(accent)
        w = text_width(label, size, mono, bold=True) + 18
        self.rect(x, y, w, h, stroke if solid else fill, None if solid else stroke, rx=h / 2, sw=1)
        self.text(x + w / 2, y + h / 2 + size * 0.36, label, size=size, weight=600, anchor="middle", mono=mono,
                  color=self.c["bg"] if solid else stroke)
        return w

    def badge(self, cx, cy, label, accent="gray", r=10):
        _, stroke = self.acc(accent)
        self.body.append(f'<circle cx="{cx:g}" cy="{cy:g}" r="{r:g}" fill="{stroke}"/>')
        self.text(cx, cy + 4, str(label), size=11, weight=700, anchor="middle", color=self.c["bg"])

    def icon(self, cx, cy, ok: bool, r=8):
        _, stroke = self.acc("green" if ok else "red")
        self.body.append(f'<circle cx="{cx:g}" cy="{cy:g}" r="{r:g}" fill="{stroke}"/>')
        if ok:
            d = f"M{cx - 3.6:g},{cy + 0.2:g} L{cx - 1:g},{cy + 2.8:g} L{cx + 3.8:g},{cy - 2.6:g}"
        else:
            d = f"M{cx - 3:g},{cy - 3:g} L{cx + 3:g},{cy + 3:g} M{cx + 3:g},{cy - 3:g} L{cx - 3:g},{cy + 3:g}"
        self.body.append(f'<path d="{d}" fill="none" stroke="{self.c["bg"]}" stroke-width="1.8" stroke-linecap="round" '
                         f'stroke-linejoin="round"/>')

    def panel(self, x, y, w, h, label=None, dash=None):
        self.rect(x, y, w, h, self.c["panel"], self.c["border"], rx=12, dash=dash)
        if label:
            self.kicker(x + 20, y + 26, label)

    def card(self, x, y, w, h, accent="gray", kicker=None, title=None, body=None, title_size=14.5, body_size=12,
             mono_title=False, fill=None) -> None:
        afill, stroke = self.acc(accent)
        self.rect(x, y, w, h, fill or self.c["card"], self.c["border"], rx=10)
        self.body.append(f'<rect x="{x + 1:g}" y="{y + 1:g}" width="4" height="{h - 2:g}" rx="2" fill="{stroke}"/>')
        ty = y + 22
        if kicker:
            self.kicker(x + 18, ty, kicker, color=stroke)
            ty += 21
        if title:
            for ln in wrap(title, w - 30, title_size, mono_title, bold=True):
                self.text(x + 18, ty, ln, size=title_size, weight=600, mono=mono_title)
                ty += title_size + 5
        if body:
            ty += 1
            for ln in wrap(body, w - 30, body_size):
                self.text(x + 18, ty, ln, size=body_size, color=self.c["muted"])
                ty += body_size + 4.5

    @staticmethod
    def card_height(w, kicker=None, title=None, body=None, title_size=14.5, body_size=12, mono_title=False) -> float:
        h = 22
        if kicker:
            h += 21
        if title:
            h += len(wrap(title, w - 30, title_size, mono_title, bold=True)) * (title_size + 5)
        if body:
            h += 1 + len(wrap(body, w - 30, body_size)) * (body_size + 4.5)
        return h + 6

    def render(self) -> str:
        c = self.c
        defs = "".join(
            f'<marker id="{mid}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" '
            f'markerUnits="userSpaceOnUse" orient="auto-start-reverse"><path d="M0,0.5 L10,5 L0,9.5 z" fill="{col}"/></marker>'
            for mid, col in sorted(self.markers.items()))
        head = [
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {self.h:g}" width="{W}" height="{self.h:g}" '
            f'role="img" aria-labelledby="t d">',
            f'<title id="t">{html.escape(self.title)}</title><desc id="d">{html.escape(self.subtitle)}</desc>',
            f'<style>.s{{font-family:{FONT}}}.m{{font-family:{MONO}}}</style>',
            f"<defs>{defs}</defs>",
            f'<rect x="0.5" y="0.5" width="{W - 1}" height="{self.h - 1:g}" rx="14" fill="{c["bg"]}" stroke="{c["border"]}"/>',
        ]
        title = [f'<text x="32" y="46" class="s" font-size="21" font-weight="650" fill="{c["text"]}">{html.escape(self.title)}</text>']
        for i, ln in enumerate(wrap(self.subtitle, W - 64, 13.5)):
            title.append(f'<text x="32" y="{70 + i * 19}" class="s" font-size="13.5" fill="{c["muted"]}">{html.escape(ln)}</text>')
        foot = [f'<text x="{W - 24}" y="{self.h - 14:g}" class="s" font-size="10.5" fill="{c["faint"]}" '
                f'text-anchor="end">{html.escape(self.source)}</text>']
        return "\n".join(head + title + self.body + foot + ["</svg>"]) + "\n"


def top(subtitle: str) -> int:
    """y where content may start, below the title and the wrapped subtitle."""
    return 70 + 19 * (len(wrap(subtitle, W - 64, 13.5)) - 1) + 30


def spread(n: int, gap: float = 23, left: float = 44, right: float = 916) -> tuple[list[float], float]:
    """x positions and width for n equal cards across a lane."""
    cw = (right - left - gap * (n - 1)) / n
    return [left + i * (cw + gap) for i in range(n)], cw


def row_height(cards, cw, title_size=14, body_size=12) -> float:
    return max(Svg.card_height(cw, k, t, b, title_size, body_size) for _, k, t, b in cards)


def card_row(s: Svg, y0, cards, xs, cw, ch, arrows=True, title_size=14, body_size=12) -> None:
    for i, (acc, k, t, b) in enumerate(cards):
        s.card(xs[i], y0, cw, ch, acc, k, t, b, title_size=title_size, body_size=body_size)
        if arrows and i < len(cards) - 1:
            s.path([(xs[i] + cw + 2, y0 + ch / 2), (xs[i + 1] - 3, y0 + ch / 2)])


# ---- 1. overview -----------------------------------------------------------------------------
def overview(s: Svg, net: Network) -> None:
    y = top(s.subtitle)
    nf = len(yaml.safe_load((ROOT / "faults" / "faults.yaml").read_text()))
    a = [("gray", "Source", "network.yaml", "One file describes every device, zone, flow and service"),
         ("gray", "Generator", "Render", "Router, firewall, DNS, PKI, proxy and lab configs"),
         ("indigo", "Gate 1 · ≈ 1 min", "Static analysis", "Schema, policy as code, nftables, FRR, Batfish"),
         ("blue", "Gate 2 · ≈ 4 min", "Live copy", "The whole network on the runner, tested with real traffic"),
         ("green", "Merge", "Review and merge", "Only when every required check is green")]
    b = [("purple", "Supply chain", "Build and sign", "Reproducible bundle and scanned images, attested and signed"),
         ("green", "Prod · 1", "Verify", "Every signature checked; a tampered bundle must be refused"),
         ("green", "Prod · 2", "Apply in place", "One atomic change per router while probes count failures"),
         ("green", "Prod · 3", "Drift check, retest", "Routers must match the bundle; Gate 2 runs again"),
         ("purple", "On a version tag", "Release", "Rebuilt from the tag, byte-identical, signed, immutable")]
    c = [("red", "Gate 3", f"{nf} planted faults", "Realistic mistakes in BGP, firewall, NAT, DNS, TLS and more"),
         ("red", "One runner each", "Gates 1 and 2", "Run on every fault, next to an unfaulted baseline"),
         ("red", "Rules fixed first", "Grade", "Caught by Gate 1, only by Gate 2, or escaped both"),
         ("red", "Published", "Scorecard", "Every run on GitHub Pages, and every escape explained")]
    xs5, cw5 = spread(5)
    xs4, cw4 = spread(4)
    xa, cwa = spread(4, gap=44)
    single, gates_ = [a[0], a[1], a[4]], [a[2], a[3]]
    ch = max(row_height(single, cwa), row_height(b, cw5), row_height(c, cw4))
    lh = 38 + ch + 18
    # Gates 1 and 2 are separate jobs that start together, so they are drawn side by side in time:
    # stacked in one column, with the change forking into both and both joining at the merge.
    hs = row_height(gates_, cwa)
    ha = max(ch, 2 * hs + 12)
    s.panel(24, y, 912, 38 + ha + 18, "On every pull request · Gates 1 and 2 run in parallel")
    mid = y + 38 + ha / 2
    cy = mid - ch / 2
    for i, (acc, k, t, bd) in zip((0, 1, 3), single):
        s.card(xa[i], cy, cwa, ch, acc, k, t, bd, title_size=14)
    gys = (mid - 6 - hs, mid + 6)
    for gy, (acc, k, t, bd) in zip(gys, gates_):
        s.card(xa[2], gy, cwa, hs, acc, k, t, bd, title_size=14)
    s.path([(xa[0] + cwa + 2, mid), (xa[1] - 3, mid)])
    fx, jx = xa[2] - 22, xa[2] + cwa + 22
    for gy in gys:
        s.path([(xa[1] + cwa + 2, mid), (fx, mid), (fx, gy + hs / 2), (xa[2] - 3, gy + hs / 2)], r=6)
        s.path([(xa[2] + cwa + 2, gy + hs / 2), (jx, gy + hs / 2), (jx, mid), (xa[3] - 3, mid)], r=6)
    y2 = y + 38 + ha + 18 + 22
    # merge -> build: down from the merge card, along the gap between lanes, into the next lane's first card
    s.path([(xa[3] + cwa / 2, cy + ch), (xa[3] + cwa / 2, y2 - 11), (xs5[0] + cw5 / 2, y2 - 11),
            (xs5[0] + cw5 / 2, y2 + 38 - 3)])
    s.panel(24, y2, 912, lh + 24, "After merge · prod runs weekly and on demand")
    card_row(s, y2 + 38, b, xs5, cw5, ch, arrows=False)
    for i in range(3):
        s.path([(xs5[i] + cw5 + 2, y2 + 38 + ch / 2), (xs5[i + 1] - 3, y2 + 38 + ch / 2)])
    yb = y2 + 38 + ch
    s.path([(xs5[0] + cw5 / 2, yb), (xs5[0] + cw5 / 2, yb + 22), (xs5[4] + cw5 / 2, yb + 22), (xs5[4] + cw5 / 2, yb + 3)],
           dash="5 4")
    y3 = y2 + lh + 24 + 22
    s.panel(24, y3, 912, lh, "Every night · Gate 3 grades Gates 1 and 2")
    card_row(s, y3 + 38, c, xs4, cw4, ch)
    s.h = y3 + lh + 34


# ---- 2. network at a glance --------------------------------------------------------------------
def zone_rows(net: Network, site: dict) -> list[tuple[str, str, str, str]]:
    out = []
    for z in site["zones"]:
        hosts = [h for h in net.data["hosts"] if h["zone"] == z["name"]]
        nouns = []
        for h in hosts:
            n = ROLE_NOUN.get(h["role"], h["role"])
            if n not in nouns:
                nouns.append(n)
        purpose = ", ".join(nouns)
        out.append((z["name"], purpose[:1].upper() + purpose[1:], " · ".join(h["name"] for h in hosts), z["prefix"]))
    return out


def network(s: Svg, net: Network) -> None:
    y = top(s.subtitle)
    isp, sa, sb = net.data["isp"], net.data["sites"][0], net.data["sites"][1]
    s.panel(300, y, 360, 166, "Internet")
    s.card(320, y + 38, 320, 54, "gray", None, "ISP router", f"{isp['name']} · AS {isp['asn']} · carries traffic between sites")
    s.card(320, y + 102, 320, 50, "gray", None, "Outside host",
           f"{next(h['name'] for h in net.data['hosts'] if h['role'] == 'outside')} · a server on the internet")
    s.line(480, y + 92, 480, y + 102, s.c["line"], 1.5)
    ys = y + 206
    panels = []
    for i, site in enumerate((sa, sb)):
        x = 24 if i == 0 else 536
        rows = zone_rows(net, site)
        ph = 32 + 74 + len(rows) * 54 + 12
        panels.append((x, ph))
        s.panel(x, ys, 400, ph, f"Site {site['name'].upper()}")
        s.card(x + 20, ys + 36, 360, 60, "gray", None, site["router"],
               f"AS {site['asn']} · BGP, zone firewall, NAT, WireGuard", title_size=15)
        for j, (zone, purpose, hosts, _prefix) in enumerate(rows):
            ry = ys + 106 + j * 54
            s.rect(x + 20, ry, 360, 46, s.c["card"], s.c["border"], rx=8)
            s.pill(x + 32, ry + 12, zone.upper(), zone_accent(zone))
            s.text(x + 112, ry + 20, purpose, size=13, weight=600)
            s.text(x + 112, ry + 37, hosts, size=11.5, color=s.c["muted"], mono=True)
    # uplinks to the ISP
    for i, (x, _ph) in enumerate(panels):
        rx = x + 200
        ix = 320 if i == 0 else 640
        s.path([(rx, ys + 36), (rx, y + 65), (ix + (-2 if i == 0 else 2), y + 65)], sw=1.75, r=10)
        lx = rx + 10
        s.text(lx, ys - 12, "eBGP · public prefixes only", size=11.5, color=s.c["muted"])
    # the tunnel between the routers
    _, ind = s.acc("indigo")
    s.path([(424 - 20 + 2, ys + 66), (536 + 20 - 2, ys + 66)], color=ind, sw=2.5, dash="7 5", head=True, tail=True, r=0)
    s.text(480, ys + 56, "WireGuard", size=12, weight=600, anchor="middle", color=ind)
    s.text(480, ys + 86, "private prefixes", size=11, anchor="middle", color=s.c["muted"])
    # how to read it
    lx, ly = 536, ys + panels[1][1] + 20
    lh = ys + panels[0][1] - ly
    s.panel(lx, ly, 400, lh, "How to read this")
    s.line(lx + 22, ly + 52, lx + 62, ly + 52, s.c["line"], 1.75)
    s.text(lx + 76, ly + 56, "Physical link: eBGP to the ISP carries only", size=12)
    s.text(lx + 76, ly + 72, "each site's public prefix", size=12, color=s.c["muted"])
    s.line(lx + 22, ly + 98, lx + 62, ly + 98, ind, 2.5, dash="7 5")
    s.text(lx + 76, ly + 102, "WireGuard tunnel: eBGP over it carries only", size=12)
    s.text(lx + 76, ly + 118, "the private prefixes, never in clear", size=12, color=s.c["muted"])
    s.text(lx + 22, ly + 150, "Every packet between zones crosses a router and its", size=12)
    s.text(lx + 22, ly + 166, "default-drop zone firewall: nothing shares a segment", size=12)
    s.text(lx + 22, ly + 182, "with another zone.", size=12)
    s.h = ys + panels[0][1] + 38


# ---- 3. addressing and interfaces ------------------------------------------------------------
def network_detail(s: Svg, net: Network) -> None:
    y = top(s.subtitle)
    d = net.data
    isp, sites = d["isp"], d["sites"]
    outside = next(h for h in d["hosts"] if h["role"] == "outside")
    # ISP and the outside host
    s.rect(300, y, 360, 104, s.c["card"], s.c["border"], rx=10)
    s.text(318, y + 26, isp["name"], size=15, weight=650)
    s.text(318 + text_width(isp["name"], 15, bold=True) + 10, y + 26, f"AS {isp['asn']} · transit", size=12, color=s.c["muted"])
    for i, site in enumerate(sites):
        s.text(318, y + 50 + i * 18, f"eth{i + 1}  {site['uplink']['isp_address']}/31 → {site['router']}", size=12, mono=True)
    n = len(sites) + 1
    s.text(318, y + 50 + len(sites) * 18, f"eth{n}  {isp['outside']['gateway']}/{isp['outside']['prefix'].split('/')[1]} → "
           f"{outside['name']}", size=12, mono=True)
    s.rect(690, y, 246, 70, s.c["card"], s.c["border"], rx=10)
    s.text(708, y + 26, outside["name"], size=15, weight=650)
    s.text(708, y + 46, f"{outside['address']} · MTU {isp['outside']['mtu']}", size=12, mono=True)
    s.text(708, y + 62, "a server on the internet (web, DNS)", size=11.5, color=s.c["muted"])
    s.path([(660, y + 30), (690, y + 30)], head=False, sw=1.5)
    # the tunnel band
    t = d["tunnel"]
    _, ind = s.acc("indigo")
    ty = y + 124
    s.rect(24, ty, 912, 54, s.acc("indigo")[0], ind, rx=10, sw=1.25, dash="7 5")
    a_wg, b_wg = sites[0]["wireguard"]["address"].split("/")[0], sites[1]["wireguard"]["address"].split("/")[0]
    s.text(96, ty + 22, f"WireGuard tunnel {t['prefix']} · UDP {t['port']} · MTU {t['mtu']}", size=12.5, weight=600,
           color=ind)
    s.text(96, ty + 41, f"{sites[0]['router']} {TUNNEL_IF} {a_wg} ⟷ {sites[1]['router']} {TUNNEL_IF} {b_wg} · eBGP AS "
           f"{sites[0]['asn']} ⟷ AS {sites[1]['asn']} over it carries only the private prefixes", size=12,
           color=s.c["text"])
    ys = ty + 74
    # sites
    col = 272
    geo = []
    for i, site in enumerate(sites):
        x = 24 if i == 0 else 628
        pw = 588 if i == 0 else 308
        cols = 2 if i == 0 else 1
        cw = col if i == 0 else 276
        zones = site["zones"]
        heights = []
        for z in zones:
            hosts = [h for h in d["hosts"] if h["zone"] == z["name"]]
            heights.append(56 + len(hosts) * 19 + 8)
        rows = [heights[k:k + cols] for k in range(0, len(heights), cols)]
        rh = [max(r) for r in rows]
        rc = 142
        ph = 36 + rc + 12 + sum(rh) + 12 * len(rh) + 6
        geo.append((x, pw, ph))
        s.panel(x, ys, pw, ph, f"Site {site['name'].upper()}")
        # router card
        rx_, ry_ = x + 20, ys + 36
        rw = pw - 40
        s.rect(rx_, ry_, rw, rc, s.c["card"], s.c["border"], rx=10)
        s.text(rx_ + 16, ry_ + 25, site["router"], size=15, weight=650)
        s.text(rx_ + 16 + text_width(site["router"], 15, bold=True) + 10, ry_ + 25,
               f"AS {site['asn']} · router ID {site['router_id']}", size=12, color=s.c["muted"])
        left = [(UPLINK_IF, f"{site['uplink']['address']} → {isp['name']}"),
                (TUNNEL_IF, f"{site['wireguard']['address']} → {net.other_site(site['name'])['router']}"),
                ("lo", site["loopback"])]
        right = [("public", site["public_prefix"]), ("NAT", site["nat_address"])]
        fwd = [p for p in d["nat"]["port_forwards"] if p["site"] == site["name"]]
        if fwd:
            right.append(("publish", fwd[0]["public"]))

        def kv(x0, y0, rows_, col):
            for j, (k_, v_) in enumerate(rows_):
                s.text(x0, y0 + j * 19, k_, size=12, mono=True, color=s.c["muted"])
                s.text(x0 + col, y0 + j * 19, v_, size=12, mono=True)

        if i == 0:
            kv(rx_ + 16, ry_ + 50, left, 44)
            kv(rx_ + 300, ry_ + 50, right, 66)
            if fwd:
                svc = ", ".join(f"{ports(p)} → {p['to']}" for p in fwd)
                s.text(rx_ + 300, ry_ + 50 + len(right) * 19, svc, size=11.5, color=s.c["muted"])
        else:
            kv(rx_ + 16, ry_ + 50, left + right, 66)
        # zones
        zy = ys + 36 + rc + 12
        k = 0
        for r_i, r in enumerate(rows):
            for c_i in range(len(r)):
                z = zones[k]
                zx = x + 20 + c_i * (cw + 12)
                hosts = [h for h in d["hosts"] if h["zone"] == z["name"]]
                iface = next(f.name for f in net.router_ifaces(site["router"]) if f.prefix == z["prefix"])
                acc = zone_accent(z["name"])
                fill, stroke = s.acc(acc)
                s.rect(zx, zy, cw, rh[r_i], s.c["card"], s.c["border"], rx=10)
                s.body.append(f'<rect x="{zx + 1:g}" y="{zy + 1:g}" width="{cw - 2:g}" height="30" rx="9" fill="{fill}"/>')
                s.body.append(f'<rect x="{zx + 1:g}" y="{zy + 22:g}" width="{cw - 2:g}" height="9" fill="{fill}"/>')
                s.text(zx + 14, zy + 21, z["name"].upper(), size=12.5, weight=700, color=stroke)
                s.text(zx + 14 + text_width(z["name"].upper(), 12.5, bold=True) + 10, zy + 21, z["prefix"], size=12, mono=True)
                s.text(zx + cw - 12, zy + 21, iface, size=11.5, mono=True, anchor="end", color=s.c["muted"])
                s.text(zx + 14, zy + 50, f"gateway {z['gateway']}", size=11.5, color=s.c["muted"], mono=True)
                for h_i, h in enumerate(hosts):
                    hy = zy + 70 + h_i * 19
                    s.text(zx + 14, hy, h["name"], size=12, weight=600)
                    s.text(zx + 88, hy, h["address"], size=12, mono=True)
                    s.text(zx + cw - 12, hy, ROLE_SOFTWARE.get(h["role"], h["role"]), size=11.5, anchor="end",
                           color=s.c["muted"])
                k += 1
            zy += rh[r_i] + 12
    # uplinks and tunnel drops
    (ax, aw, aph), (bx, bw, bph) = geo
    s.path([(ax + 56, ys + 36), (ax + 56, y + 40), (300 - 2, y + 40)], sw=1.75, r=10)
    s.path([(bx + bw - 56, ys + 36), (bx + bw - 56, y + 76), (660 + 2, y + 76)], sw=1.75, r=10)
    s.text(ax + 66, y + 34, "eBGP · advertises", size=11, color=s.c["muted"])
    s.text(ax + 66, y + 48, f"{sites[0]['public_prefix']} only", size=11, color=s.c["muted"], mono=True)
    s.text(bx + bw - 66, y + 96, f"eBGP · {sites[1]['public_prefix']} only", size=11, color=s.c["muted"], anchor="end")
    for xx in (ax + aw - 80, bx + 80):
        s.line(xx, ty + 54, xx, ys + 36, ind, 1.75, dash="4 4")
    s.h = ys + max(aph, bph) + 36
    # legend in the space under site B
    lx, ly = bx, ys + bph + 18
    lh = ys + aph - ly
    if lh > 120:
        s.panel(lx, ly, bw, lh, "Notes")
        notes = ["Interfaces eth2 and up face the zones, in the order network.yaml lists them.",
                 "Each zone is one Linux bridge. A router is the only device on more than one, so every packet "
                 "between zones meets its firewall.",
                 "Inside addresses are private (RFC 1918); public ones come from the documentation ranges (RFC 5737)."]
        yy = ly + 50
        for note in notes:
            for ln in wrap(note, bw - 44, 12):
                s.text(lx + 22, yy, ln, size=12, color=s.c["muted"])
                yy += 16.5
            yy += 8


# ---- 4. the zone firewall's allow list --------------------------------------------------------
def endpoint(net: Network, ep: str) -> tuple[str, str]:
    if ep == "internet":
        return "internet", "gray"
    if ep == "all":
        return "every host and router", "gray"
    kind, name = ep.split(":", 1)
    if kind == "zone":
        return name.upper(), zone_accent(name)
    return name, zone_accent(net.hosts[name]["zone"])


def ports(flow: dict) -> str:
    tcp, udp = flow.get("tcp", []), flow.get("udp", [])
    if tcp and udp and tcp == udp:
        return "tcp/udp " + ", ".join(map(str, tcp))
    parts = ([f"tcp {', '.join(map(str, tcp))}"] if tcp else []) + ([f"udp {', '.join(map(str, udp))}"] if udp else [])
    return " · ".join(parts) or "any port"


def firewall(s: Svg, net: Network) -> None:
    y = top(s.subtitle)
    cols = (40, 222, 470, 612)
    for x, label in zip(cols, ("Flow", "From", "Ports", "To")):
        s.kicker(x, y + 6, label)
    ry = y + 18
    for i, f in enumerate(net.data["flows"]):
        if i % 2 == 0:
            s.rect(24, ry, 912, 38, s.c["row"], None, rx=8)
        s.text(cols[0], ry + 24, f["name"], size=12, mono=True, color=s.c["muted"])
        x = cols[1]
        for ep in f["from"]:
            label, acc = endpoint(net, ep)
            x += s.pill(x, ry + 8, label, acc) + 6
        p = ports(f)
        s.path([(cols[2] - 12, ry + 19), (cols[3] - 10, ry + 19)], sw=1.5)
        s.rect(cols[2] + 52 - text_width(p, 11.5, True) / 2 - 8, ry + 9, text_width(p, 11.5, True) + 16, 20, s.c["bg"],
               s.c["border"], rx=10)
        s.text(cols[2] + 52, ry + 23, p, size=11.5, mono=True, anchor="middle")
        x = cols[3]
        for ep in f["to"]:
            label, acc = endpoint(net, ep)
            x += s.pill(x, ry + 8, label, acc) + 6
        ry += 38
    s.rect(24, ry + 4, 912, 40, s.acc("red")[0], s.acc("red")[1], rx=8)
    s.text(cols[0], ry + 29, "everything else", size=12, mono=True, color=s.acc("red")[1], weight=600)
    s.text(cols[1], ry + 29, "Dropped by the default policy, and counted on the router", size=12.5, weight=600,
           color=s.acc("red")[1])
    y2 = ry + 70
    nat = net.data["nat"]
    w2 = 444
    s.panel(24, y2, w2, 30 + 34 * len(nat["port_forwards"]) + 20, "Published to the internet (destination NAT)")
    for i, p in enumerate(nat["port_forwards"]):
        py = y2 + 46 + i * 34
        site = net.sites[p["site"]]
        s.text(44, py + 15, p["public"], size=12, mono=True)
        s.text(166, py + 15, ports(p), size=12, mono=True, color=s.c["muted"])
        s.path([(262, py + 11), (300, py + 11)], sw=1.5)
        s.pill(308, py, p["to"], zone_accent(net.hosts[p["to"]]["zone"]))
        s.text(308 + text_width(p["to"], 11.5, bold=True) + 28, py + 15, f"on {site['router']}", size=11.5, color=s.c["muted"])
    s.panel(492, y2, w2, 30 + 34 * len(nat["snat"]) + 20, "Leaving for the internet (source NAT)")
    for i, p in enumerate(nat["snat"]):
        py = y2 + 46 + i * 34
        x = 512
        for z in p["from"]:
            x += s.pill(x, py, z.upper(), zone_accent(z)) + 6
        s.path([(x + 6, py + 11), (x + 44, py + 11)], sw=1.5)
        s.text(x + 54, py + 15, p["to"], size=12, mono=True)
        s.text(x + 54 + text_width(p["to"], 12, True) + 10, py + 15, f"on {net.sites[p['site']]['router']}", size=11.5,
               color=s.c["muted"])
    s.h = y2 + 30 + 34 * max(len(nat["port_forwards"]), len(nat["snat"])) + 20 + 40


# ---- 5. a packet's path through a site router -------------------------------------------------
def packet_path(s: Svg, net: Network) -> None:
    y = top(s.subtitle)
    sa = net.data["sites"][0]
    fwd = [p for p in net.data["nat"]["port_forwards"] if p["site"] == sa["name"]]
    published = ", ".join(f"{p.get('tcp', p.get('udp'))[0]} → {p['to']}" for p in fwd)
    snat = next(p for p in net.data["nat"]["snat"] if p["site"] == sa["name"])
    zif = [f.name for f in net.router_ifaces(sa["router"])]
    cw, gap, ch = 200, 26, 150
    xs = [41 + i * (cw + gap) for i in range(4)]
    r1, r2, r3 = y, y + ch + 46, y + 2 * (ch + 46)
    cards1 = [("gray", "Ingress", "Packet arrives", f"From the ISP on {UPLINK_IF}, a zone on {zif[0]}–{zif[-1]}, or the tunnel on {TUNNEL_IF}"),
              ("orange", "1 · ingress hook", "Edge filter", f"On {UPLINK_IF}, before connection tracking: drops private, loopback "
                                                            f"and own-prefix sources"),
              ("orange", "2 · prerouting", "Reverse-path check", "On zone interfaces: drops a source that would not be routed "
                                                                 "back out the way it came in"),
              ("purple", "3 · prerouting NAT", "Destination NAT", f"Published services on {fwd[0]['public']}: {published}")]
    cards2 = [("gray", "Egress", "Packet leaves", f"To the ISP, a zone, or the tunnel"),
              ("purple", "6 · postrouting NAT", "Source NAT", f"Internet-bound traffic from "
                                                              f"{', '.join(z.upper() for z in snat['from'])} leaves as {snat['to']}"),
              ("red", "5 · forward hook", "Forward filter", "Replies pass first, invalid packets drop, then the allow list, "
                                                            "pinned to interfaces. Everything else is counted and dropped"),
              ("blue", "4 · routing", "Routing decision", "BGP and connected routes choose the exit; packets for the router "
                                                          "itself go to its input filter")]
    for i, (acc, k, t, b) in enumerate(cards1):
        s.card(xs[i], r1, cw, ch, acc, k, t, b, title_size=14)
        if i < 3:
            s.path([(xs[i] + cw + 2, r1 + ch / 2), (xs[i + 1] - 3, r1 + ch / 2)])
    for i, (acc, k, t, b) in enumerate(cards2):
        s.card(xs[i], r2, cw, ch, acc, k, t, b, title_size=14)
        if i > 0:
            s.path([(xs[i] - 2, r2 + ch / 2), (xs[i - 1] + cw + 3, r2 + ch / 2)])
    s.path([(xs[3] + cw / 2, r1 + ch), (xs[3] + cw / 2, r2 - 3)])
    h3 = 172
    s.card(xs[3], r3, cw, h3, "red", "input hook", "To the router itself",
           f"Only BGP from its two peers, WireGuard on UDP {net.data['tunnel']['port']}, SSH from admin and ping from inside. "
           "Everything else is dropped", title_size=14)
    s.path([(xs[3] + cw / 2, r2 + ch), (xs[3] + cw / 2, r3 - 3)])
    nw = xs[3] - 24 - 41
    s.panel(41, r3, nw, h3)
    s.kicker(61, r3 + 28, "What Gate 1 asserts on this ruleset, as nftables loaded it")
    items = ["The input and forward hooks have a drop policy, and forwarding accepts replies before anything else",
             "Forwarding never drops ICMP destination-unreachable, so path MTU discovery keeps working",
             f"The edge filter is on {UPLINK_IF}'s ingress hook and drops every private and own source prefix",
             "The reverse-path check covers every zone interface, with no accept before it"]
    yy = r3 + 56
    for it in items:
        s.icon(70, yy - 4, True, r=7)
        lines = wrap(it, nw - 70, 12.5)
        for j, ln in enumerate(lines):
            s.text(86, yy + j * 17, ln, size=12.5)
        yy += 17 * len(lines) + 10
    s.h = r3 + h3 + 40


# ---- 6. how the services work together ----------------------------------------------------------
def sequence(s: Svg, y0: float, label: str, parts: list[tuple[str, str, str]], msgs: list[tuple]) -> float:
    s.panel(24, y0, 912, 10, label)  # height patched below
    idx = len(s.body) - 2
    n = len(parts)
    xs = [24 + 100 + i * (712 / (n - 1)) for i in range(n)]
    hy = y0 + 40
    for x, (name, sub, acc) in zip(xs, parts):
        fill, stroke = s.acc(acc)
        s.rect(x - 78, hy, 156, 46, s.c["card"], stroke, rx=9, sw=1.25)
        s.text(x, hy + 20, name, size=13.5, weight=650, anchor="middle")
        s.text(x, hy + 36, sub, size=11, anchor="middle", color=s.c["muted"])
    ly0 = hy + 46
    yy = ly0 + 26
    rows = []
    for m in msgs:
        if m[0] == "group":
            rows.append(("group", yy, m[1]))
            yy += 28
            continue
        rows.append(("msg", yy) + tuple(m))
        yy += 36
    ly1 = yy - 6
    for x in xs:
        s.line(x, ly0, x, ly1, s.c["border"], 1.25, dash="3 4")
    names = [p[0] for p in parts]
    for r in rows:
        if r[0] == "group":
            s.kicker(44, r[1] + 4, r[2], color=s.c["faint"])
            continue
        _, my, a, b, text, num, acc = r[:7]
        ret = len(r) > 7 and r[7] == "return"
        x1, x2 = xs[names.index(a)], xs[names.index(b)]
        _, stroke = s.acc(acc)
        s.path([(x1 + (5 if x2 > x1 else -5), my), (x2 + (-6 if x2 > x1 else 6), my)], color=stroke if not ret else s.c["line"],
               sw=1.5, dash="5 4" if ret else None, r=0)
        left = min(x1, x2)
        lx = left + (30 if num else 14)
        tw_ = text_width(text, 11.5)
        s.rect(lx - 5, my - 21, tw_ + 10, 16, s.c["panel"], None, rx=4)
        s.text(lx, my - 9, text, size=11.5, color=s.c["text"] if not ret else s.c["muted"])
        if num:
            s.badge(left + 16, my, num, acc, r=8)
    h = ly1 - y0 + 18
    s.body[idx] = s.body[idx].replace('height="10"', f'height="{h:g}"')
    return y0 + h


def services(s: Svg, net: Network) -> None:
    y = top(s.subtitle)
    d = net.data
    fqdn = f"www.{d['domain']}"
    proxy = d["proxy"]["host"]
    resolver = next(h["name"] for h in d["hosts"] if h["role"] == "dns-resolver")
    ca = d["pki"]["ca"]
    client_b = next(h["name"] for h in d["hosts"] if h["zone"] == d["sites"][1]["zones"][0]["name"])
    apps = [b["host"] for b in d["proxy"]["backends"]]
    port = d["proxy"]["backends"][0]["port"]
    hc = d["proxy"]["health_check"]
    parts = [(client_b, "user at site B", "green"), (resolver, "Unbound · inside view", "teal"),
             (proxy, "HAProxy · TLS", "orange"), (" · ".join(apps), "HTTP backends", "blue"), (ca, "step-ca · ACME", "teal")]
    pa = [p[0] for p in parts]
    msgs = [("group", "Before any user arrives, and at every renewal"),
            (pa[2], pa[4], f"ACME order for {fqdn} (tcp {d['pki']['port']})", 1, "teal"),
            (pa[4], pa[2], "http-01 challenge on tcp 80", 2, "teal"),
            (pa[4], pa[2], "24-hour certificate, chained to the lab root", 0, "teal", "return"),
            ("group", "A user opens the site"),
            (pa[0], pa[1], f"A {fqdn}? (udp 53, across the tunnel)", 3, "green"),
            (pa[1], pa[0], f"{net.host_address(proxy)}, the inside view", 0, "green", "return"),
            (pa[0], pa[2], f"TLS to {net.host_address(proxy)}:{d['proxy']['listen']}, verified against the lab root", 4, "green"),
            (pa[2], pa[3], f"HTTP {port}, only to backends passing /health", 5, "blue"),
            (pa[3], pa[0], "response, back through the proxy", 0, "blue", "return")]
    y1 = sequence(s, y, "Inside: a user at site B opens https://" + fqdn, parts, msgs)
    out_h = next(h["name"] for h in d["hosts"] if h["role"] == "outside")
    ns1 = next(h["name"] for h in d["hosts"] if h["role"] == "dns-authoritative")
    sa = d["sites"][0]
    pub = d["nat"]["port_forwards"][0]["public"]
    parts2 = [(out_h, "on the internet", "gray"), (sa["router"], "edge · destination NAT", "gray"),
              (ns1, "NSD · outside view", "orange"), (proxy, "HAProxy · TLS", "orange")]
    pb = [p[0] for p in parts2]
    msgs2 = [(pb[0], pb[1], f"A {fqdn}? to {pub}:53", 1, "gray"),
             (pb[1], pb[2], f"DNAT to {net.host_address(ns1)}:53", 0, "orange"),
             (pb[2], pb[0], f"{d['dns']['outside']['www']}, the outside view", 0, "orange", "return"),
             (pb[0], pb[1], f"TLS to {pub}:443", 2, "gray"),
             (pb[1], pb[3], f"DNAT to {net.host_address(proxy)}:443", 0, "orange")]
    y2 = sequence(s, y1 + 20, "Outside: someone on the internet opens the same site", parts2, msgs2)
    mon = next(h for h in d["hosts"] if h["role"] == "monitor")
    probes = ", ".join(p["name"] for p in d["monitoring"]["probes"])
    s.panel(24, y2 + 20, 912, 74, "Watching it")
    s.text(44, y2 + 66, f"{mon['name']} runs Prometheus, blackbox_exporter and Grafana in LAN-A, probing like a user: {probes}.",
           size=12.5)
    s.text(44, y2 + 84, f"Only {resolver} may query the internet; it forwards example.net to the outside test server. "
           f"Health checks: every {hc['inter_ms']} ms, down after {hc['fall']} failures.", size=12, color=s.c["muted"])
    s.h = y2 + 20 + 74 + 34


# ---- 7. what a pull request must pass ---------------------------------------------------------
def gates(s: Svg, net: Network) -> None:
    y = top(s.subtitle)
    pw = 444
    s.panel(24, y, pw, 10)
    i1 = len(s.body) - 1
    _, ind = s.acc("indigo")
    s.kicker(44, y + 28, "Gate 1 · static analysis · ≈ 1 min", color=ind)
    s.text(44, y + 52, "Nothing is deployed", size=16, weight=650)
    items = [("Policy unit tests", "The Rego policies are tested first, so a broken rule cannot wave a change through."),
             ("Schema and references", "network.yaml must match its JSON Schema and refer only to things that exist."),
             ("Intent invariants", "13 hand-written rules on the intent, such as: the database accepts only the app "
                                   "zone, on 5432."),
             ("Firewall as loaded", "Each ruleset is loaded by nftables, then checked: default drop, replies first, "
                                    "edge filter, reverse-path check."),
             ("FRR syntax", "vtysh --dryrun on every router config, after proving it rejects a broken one."),
             ("Batfish", "Parses the router configs; checks BGP sessions, routes, and leaks to the ISP.")]
    yy = y + 82
    for n, (t, b) in enumerate(items, 1):
        s.badge(56, yy - 4, n, "indigo", r=10)
        s.text(76, yy, t, size=13.5, weight=650)
        lines = wrap(b, pw - 76, 12)
        for j, ln in enumerate(lines):
            s.text(76, yy + 18 + j * 16, ln, size=12, color=s.c["muted"])
        yy += 18 + 16 * len(lines) + 12
    s.rect(44, yy - 4, pw - 40, 44, s.c["card"], s.c["border"], rx=8)
    s.text(58, yy + 14, "The change plan is posted on the pull request:", size=12)
    s.text(58, yy + 31, "frr-reload.py --test against the base branch", size=12, mono=True, color=s.c["muted"])
    h1 = yy + 56 - y
    # Gate 2
    x2 = 24 + pw + 24
    _, blue = s.acc("blue")
    s.panel(x2, y, pw, 10)
    i2 = len(s.body) - 1
    s.kicker(x2 + 20, y + 28, "Gate 2 · live copy · ≈ 4 min", color=blue)
    s.text(x2 + 20, y + 52, "The whole network, on the runner", size=16, weight=650)
    n_cont = len(net.data["hosts"]) + len(net.data["sites"]) + 1
    n_br = len(net.zones)
    for j, ln in enumerate(wrap(f"containerlab starts {n_cont} containers and {n_br} zone bridges. Tests send real traffic, "
                                "and every probe must prove it ran, or the test errors.", pw - 40, 12.5)):
        s.text(x2 + 20, y + 76 + j * 17, ln, size=12.5, color=s.c["muted"])
    areas = [("Every node ready", "green"), ("BGP sessions and routes", "blue"), ("Allow and deny matrix", "orange"),
             ("12 attack paths", "red"), ("NAT and the edge", "orange"), ("Split-horizon DNS", "teal"),
             ("TLS and the private CA", "purple"), ("MTU and path MTU", "indigo"), ("Proxy failover", "green"),
             ("Monitoring probes", "green"), ("Listening sockets", "gray"), ("No path around the design", "red")]
    gy = y + 128
    cw = (pw - 40 - 12) / 2
    for k, (label, acc) in enumerate(areas):
        cx = x2 + 20 + (k % 2) * (cw + 12)
        cy = gy + (k // 2) * 46
        fill, stroke = s.acc(acc)
        s.rect(cx, cy, cw, 36, s.c["card"], s.c["border"], rx=8)
        s.body.append(f'<circle cx="{cx + 18:g}" cy="{cy + 18:g}" r="5" fill="{stroke}"/>')
        s.text(cx + 32, cy + 23, label, size=12.5, weight=600)
    ey = gy + 6 * 46 + 4
    s.rect(x2 + 20, ey, pw - 40, 44, s.c["card"], s.c["border"], rx=8)
    s.text(x2 + 34, ey + 18, "Evidence from every node is kept with the run:", size=12)
    s.text(x2 + 34, ey + 35, "BGP state, routes, running config, rulesets, tunnel state", size=12, color=s.c["muted"])
    h2 = ey + 44 + 16 - y
    h = max(h1, h2)
    for i in (i1, i2):
        s.body[i] = s.body[i].replace('height="10"', f'height="{h:g}"')
    yb = y + h + 20
    s.rect(24, yb, 912, 46, s.c["panel"], s.c["border"], rx=10)
    s.kicker(44, yb + 28, "Also required")
    x = 150
    for label in ("generator unit tests", "Gitleaks, full history", "zizmor workflow audit"):
        x += s.pill(x, yb + 12, label, "gray") + 8
    s.text(916, yb + 28, "CodeQL also runs on every pull request", size=12, color=s.c["muted"], anchor="end")
    s.h = yb + 46 + 36


# ---- 8. grading the gates ---------------------------------------------------------------------
def grading(s: Svg, net: Network) -> None:
    y = top(s.subtitle)
    faults = yaml.safe_load((ROOT / "faults" / "faults.yaml").read_text())
    layers = Counter(f["layer"] for f in faults)
    order = sorted(layers, key=lambda k: (-layers[k], k))
    ph = 404
    # left: the faults
    s.panel(24, y, 262, ph)
    _, red = s.acc("red")
    s.kicker(44, y + 28, "Planted on purpose", color=red)
    s.text(44, y + 52, f"{len(faults)} faults", size=16, weight=650)
    s.text(44, y + 72, "Realistic mistakes, each in faults.yaml", size=12, color=s.c["muted"])
    mx = max(layers.values())
    for i, k in enumerate(order):
        ly = y + 100 + i * 31
        fill, stroke = s.acc(LAYER_ACCENT.get(k, "gray"))
        s.text(44, ly + 14, k, size=12.5, weight=600)
        bw = 110 * layers[k] / mx
        s.rect(130, ly + 2, bw, 16, stroke, None, rx=4)
        s.text(130 + bw + 8, ly + 15, str(layers[k]), size=12, mono=True, color=s.c["muted"])
    # middle: the jobs
    mx0 = 306
    mw = 368
    s.panel(mx0, y, mw, ph)
    s.kicker(mx0 + 20, y + 28, "In parallel, one runner each", color=red)
    s.text(mx0 + 20, y + 52, f"{len(faults) + 1} jobs: a baseline, and one per fault", size=15, weight=650)
    tiles = ["base"] + [f["id"] for f in faults]
    tw_, th, g = 38, 26, 5
    for i, tlabel in enumerate(tiles):
        tx = mx0 + 20 + (i % 8) * (tw_ + g)
        ty = y + 70 + (i // 8) * (th + g)
        if tlabel == "base":
            fill, stroke = s.acc("green")
        else:
            fill, stroke = s.acc(LAYER_ACCENT.get(next(f["layer"] for f in faults if f["id"] == tlabel), "gray"))
        s.rect(tx, ty, tw_, th, fill, stroke, rx=5)
        s.text(tx + tw_ / 2, ty + 17, tlabel, size=10.5, mono=True, anchor="middle", color=stroke, weight=600)
    sy = y + 70 + 4 * (th + g) + 20
    s.kicker(mx0 + 20, sy, "Each job")
    steps = ["Render with the fault planted", "Gate 1: static analysis", "Deploy the live copy",
             "Gate 2: the full live suite", "Record what each gate said"]
    for i, st in enumerate(steps):
        yy = sy + 24 + i * 27
        s.badge(mx0 + 32, yy - 4, i + 1, "red", r=9)
        s.text(mx0 + 50, yy, st, size=12.5)
    # right: grading
    rx0 = 694
    rw = 242
    s.panel(rx0, y, rw, ph)
    s.kicker(rx0 + 20, y + 28, "Graded by rules fixed first", color=red)
    s.text(rx0 + 20, y + 52, "Every fault gets one verdict", size=14.5, weight=650)
    verdicts = [("indigo", "Caught by Gate 1", "the cheapest gate saw it"),
                ("blue", "Caught only by Gate 2", "it took real traffic"),
                ("yellow", "Escaped both", "published, with why"),
                ("gray", "Void", "a gate could not judge: re-run, never a catch")]
    vy = y + 76
    for acc, t, b in verdicts:
        fill, stroke = s.acc(acc)
        lines = wrap(b, rw - 70, 11.5)
        bh = 34 + 15 * len(lines)
        s.rect(rx0 + 20, vy, rw - 40, bh, fill, stroke, rx=8)
        s.text(rx0 + 34, vy + 22, t, size=12.5, weight=650, color=stroke)
        for j, ln in enumerate(lines):
            s.text(rx0 + 34, vy + 40 + j * 15, ln, size=11.5, color=s.c["text"])
        vy += bh + 9
    s.text(rx0 + 20, vy + 14, "The scorecard is published to", size=12, color=s.c["muted"])
    s.text(rx0 + 20, vy + 31, "GitHub Pages after every run.", size=12, color=s.c["muted"])
    s.path([(286 + 2, y + ph / 2), (mx0 - 3, y + ph / 2)])
    s.path([(mx0 + mw + 2, y + ph / 2), (rx0 - 3, y + ph / 2)])
    s.h = y + ph + 36


# ---- 9. the supply chain ----------------------------------------------------------------------
def supply_chain(s: Svg, net: Network) -> None:
    y = top(s.subtitle)
    lanes = [
        ("Images · when images/ changes", "purple", [
            ("Build", "router and node images"), ("Scan", "Trivy; a fixable critical blocks"),
            ("SBOM", "CycloneDX, from the built image"), ("Push", "to GHCR, used only by digest"),
            ("Sign", "cosign signature and a signed SBOM attestation")]),
        ("Config bundle · every merge to main", "purple", [
            ("Render", "every config from network.yaml"), ("Pack", "reproducibly: fixed order, owner, mode, time"),
            ("Attest", "GitHub build provenance"), ("Sign", "cosign, keyless, in the public Rekor log")]),
        ("Release · on a version tag", "green", [
            ("Preconditions", "on main, and main's gate passed for it"),
            ("Rebuild", "from the tag; must equal main's bundle byte for byte"),
            ("Record images", "built for this commit; signatures verified"),
            ("Checksums", "SHA256SUMS, signed"), ("Publish", "an immutable GitHub release")]),
    ]
    yy = y
    ch = max(row_height([(a, None, t, b) for t, b in cards], spread(len(cards))[1], 14, 11.5) for _, a, cards in lanes)
    for label, acc, cards in lanes:
        xs, cw = spread(len(cards))
        s.panel(24, yy, 912, 38 + ch + 16, label)
        card_row(s, yy + 38, [(acc, None, t, b) for t, b in cards], xs, cw, ch, title_size=14, body_size=11.5)
        yy += 38 + ch + 16 + 18
    s.rect(24, yy, 912, 64, s.acc("green")[0], s.acc("green")[1], rx=10)
    s.text(44, yy + 26, "Anyone can check a release, and prod checks every bundle and image before using it", size=13.5,
           weight=650, color=s.acc("green")[1])
    s.text(44, yy + 46, "cosign verify-blob · sha256sum -c · gh attestation verify · cosign verify   (docs/verify.md)",
           size=12, mono=True)
    s.h = yy + 64 + 36


# ---- 10. a production change ------------------------------------------------------------------
def prod(s: Svg, net: Network) -> None:
    y = top(s.subtitle)
    cw, gap, ch = 200, 26, 136
    xs = [41 + i * (cw + gap) for i in range(4)]
    steps = [("Verify images", "cosign signatures checked by digest, before any image is used"),
             ("Verify bundles", "attestation and signature; a tampered copy must be refused, for the right reasons"),
             ("Decrypt identities", "WireGuard keys and the CA root, with SOPS and an age key only the prod "
                                    "environment holds"),
             ("Rebuild prod", "from the previous bundle; wait until ready; check it has no drift"),
             ("Apply in place", "frr-reload.py and one atomic nft transaction per router, while probes hold TCP "
                                "connections and ping across the tunnel"),
             ("Check drift", "routers against a fresh FRR from the same file, and the loaded rulesets; then a planted "
                             "drift must be caught"),
             ("Check identities", "prod really runs the managed keys and the committed CA root"),
             ("Run Gate 2 again", "the full live suite of the version just applied")]
    r1, r2 = y, y + ch + 44
    for i in range(4):
        s.card(xs[i], r1, cw, ch, "green", f"Step {i + 1}", steps[i][0], steps[i][1], title_size=14, body_size=11.5)
        if i < 3:
            s.path([(xs[i] + cw + 2, r1 + ch / 2), (xs[i + 1] - 3, r1 + ch / 2)])
    for j in range(4):
        i = 4 + j
        x = xs[3 - j]
        s.card(x, r2, cw, ch, "green", f"Step {i + 1}", steps[i][0], steps[i][1], title_size=14, body_size=11.5)
        if j < 3:
            s.path([(x - 2, r2 + ch / 2), (xs[3 - j - 1] + cw + 3, r2 + ch / 2)])
    s.path([(xs[3] + cw / 2, r1 + ch), (xs[3] + cw / 2, r2 - 3)])
    yb = r2 + ch + 26
    s.panel(24, yb, 912, 92, "A run is green only if")
    x, yy = 44, yb + 44
    for label in ("every signature verifies", "the tampered copy is refused", "the lab is ready", "0 failed requests",
                  "0 broken connections", "no drift", "identities match", "Gate 2 passes"):
        w = text_width(label, 11.5, bold=True) + 18 + 26
        if x + w > 916:
            x, yy = 44, yy + 30
        s.rect(x, yy, w, 24, s.acc("green")[0], s.acc("green")[1], rx=12)
        s.icon(x + 13, yy + 12, True, r=6.5)
        s.text(x + 26, yy + 16.5, label, size=11.5, weight=600, color=s.acc("green")[1])
        x += w + 8
    s.h = yb + 92 + 36


# ---- 11. attack paths -------------------------------------------------------------------------
def attack_paths(s: Svg, net: Network) -> None:
    sys.path.insert(0, str(ROOT / "gate3"))
    import scorecard  # noqa: E402  the attack paths' names and legitimate twins, as Gate 3 reports them
    y = top(s.subtitle)
    names = sorted(scorecard.AP_NAMES.values())
    proxy = net.data["proxy"]["host"]
    rows_y = y + 30
    rh = 40
    # attacker
    ah = 150
    ay = rows_y + (len(names) * rh) / 2 - ah / 2
    s.card(24, ay, 220, ah, "red", "Attacker", "A compromised DMZ host",
           f"A throwaway container in {proxy}'s network namespace: every packet carries {proxy}'s real address, "
           f"{net.host_address(proxy)}", title_size=14.5, body_size=11.5)
    s.kicker(300, y + 14, "Attack · must be blocked")
    s.kicker(640, y + 14, "Legitimate twin · must pass in the same test")
    _, red = s.acc("red")
    for i, full in enumerate(names):
        apid, text = full.split(" ", 1)
        ry = rows_y + i * rh
        if i % 2 == 0:
            s.rect(276, ry, 660, rh - 4, s.c["row"], None, rx=8)
        s.path([(244 + 2, ay + ah / 2), (262, ay + ah / 2), (262, ry + rh / 2 - 2), (282, ry + rh / 2 - 2)], color=red,
               sw=1.1, head=False, r=6)
        s.icon(298, ry + rh / 2 - 2, False, r=8)
        s.text(314, ry + rh / 2 + 2, apid, size=11.5, mono=True, color=s.c["muted"])
        s.text(362, ry + rh / 2 + 2.5, text[:1].upper() + text[1:], size=12.5, weight=600)
        twin = scorecard.AP_PAIRS[apid]
        s.icon(652, ry + rh / 2 - 2, True, r=8)
        lines = wrap(twin, 264, 11.5)
        for j, ln in enumerate(lines[:2]):
            s.text(668, ry + rh / 2 + 2 - (len(lines[:2]) - 1) * 7 + j * 14, ln, size=11.5, color=s.c["text"])
    s.h = rows_y + len(names) * rh + 40


# ---- 12. one source of truth ----------------------------------------------------------------
def source_of_truth(s: Svg, net: Network) -> None:
    y = top(s.subtitle)
    d = net.data
    _, blue = s.acc("blue")
    # network.yaml
    s.card(24, y + 70, 220, 150, "blue", "The intent", "network.yaml",
           f"{len(d['sites'])} sites, {len(net.zones)} zones, {len(d['hosts'])} hosts, {len(d['flows'])} flows, "
           "DNS, PKI, proxy and monitoring", title_size=16, mono_title=True)
    s.card(284, y + 104, 170, 82, "gray", None, "packetproof render", "same input, same bytes", title_size=13,
           body_size=11.5, mono_title=True)
    s.path([(244 + 2, y + 145), (284 - 3, y + 145)])
    outs = [("Routers", "blue", "FRR configs for all three routers; an nftables ruleset and a WireGuard peer for each "
                                "site router"),
            ("Services", "teal", "Unbound, NSD and its zone, HAProxy, step-ca, Prometheus, blackbox_exporter, Grafana"),
            ("The lab", "green", "containerlab topology, one start script per host, readiness checks"),
            ("Analysis", "indigo", "a Batfish snapshot of the router configs")]
    oy = y
    for i, (t, acc, b) in enumerate(outs):
        s.card(494, oy, 442, 66, acc, None, t, b, title_size=13.5, body_size=11.5)
        s.path([(454 + 2, y + 145), (474, y + 145), (474, oy + 33), (494 - 3, oy + 33)], r=8)
        oy += 76
    yb = oy + 24
    s.panel(24, yb, 912, 180, "Written by hand, never generated, so a wrong intent cannot pass both")
    hand = [("policy/intent", "13 invariants on network.yaml, such as: nothing private is advertised to the ISP"),
            ("policy/rendered", "the firewall's structure, checked on each ruleset as nftables loaded it"),
            ("tests/live/expect.py", "the values Gate 2 expects: addresses, routes, who may reach what")]
    for i, (t, b) in enumerate(hand):
        x = 44 + i * 296
        s.card(x, yb + 42, 280, 116, "red", "Checks", t, b, title_size=13.5, body_size=11.5, mono_title=True)
    s.h = yb + 180 + 36


DIAGRAMS = {
    "overview": (overview, "How a change reaches production",
                 "Every pull request is proved on a disposable copy of the whole network. Every night, the proof itself is graded.",
                 "drawn by scripts/diagrams.py"),
    "source-of-truth": (source_of_truth, "One file describes the whole network",
                        "Every config is rendered from network.yaml. The checks that judge it are written separately, by hand.",
                        "from network.yaml · drawn by scripts/diagrams.py"),
    "network": (network, "The network at a glance",
                "Two sites joined by a WireGuard tunnel over an ISP. Site A runs five zones behind one router; site B is one "
                "user network.",
                "from network.yaml · drawn by scripts/diagrams.py"),
    "network-detail": (network_detail, "Addresses, interfaces and routing",
                       "Every address below is read from network.yaml, the same file the configs are rendered from.",
                       "from network.yaml · drawn by scripts/diagrams.py"),
    "firewall": (firewall, "The zone firewall: the complete allow list",
                 "Rendered into nftables on both site routers and pinned to interfaces, so traffic for the other site must use "
                 "the tunnel. Nothing else is allowed.",
                 "from network.yaml · drawn by scripts/diagrams.py"),
    "packet-path": (packet_path, "Inside a site router: the order rules apply in",
                    "rtr-a's rendered nftables ruleset, in the order the kernel's hooks meet a packet.",
                    "from network.yaml and the rendered ruleset's structure · drawn by scripts/diagrams.py"),
    "services": (services, "How the services work together",
                 "Split-horizon DNS, a private CA issuing certificates over ACME, and a health-checked proxy, "
                 "followed message by message.",
                 "from network.yaml · drawn by scripts/diagrams.py"),
    "gates": (gates, "What every pull request must pass",
              "Two gates, run in parallel on separate runners. Both are required checks: main cannot change without them.",
              "drawn by scripts/diagrams.py"),
    "grading": (grading, "Gate 3: grading the gates, every night",
                "Each planted fault runs through Gates 1 and 2 on its own runner, next to an unfaulted baseline in the same run.",
                "from faults/faults.yaml · drawn by scripts/diagrams.py"),
    "supply-chain": (supply_chain, "From merge to a release anyone can verify",
                     "Images and config bundles are signed where they are built; a release is rebuilt and must match.",
                     "drawn by scripts/diagrams.py"),
    "prod": (prod, "A production change, step by step",
             "There is no always-on host, so prod is rebuilt from the previous bundle and the new one is applied to it in "
             "place, as a real change would land.",
             "drawn by scripts/diagrams.py"),
    "attack-paths": (attack_paths, "Twelve attack paths from a compromised DMZ host",
                     "Each attack must be blocked while a legitimate flow of the same kind passes in the same test, so a "
                     "firewall that blocks everything fails.",
                     "from gate3/scorecard.py · drawn by scripts/diagrams.py"),
}


def draw_all() -> dict[str, str]:
    net = Network.load(ROOT / "network.yaml")
    out = {}
    for name, (fn, title, subtitle, source) in DIAGRAMS.items():
        for theme in ("light", "dark"):
            s = Svg(theme, title, subtitle, source)
            fn(s, net)
            out[f"{name}{'-dark' if theme == 'dark' else ''}.svg"] = s.render()
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, default=ROOT / "docs" / "images")
    ap.add_argument("--check", action="store_true", help="fail if a committed image differs from what is drawn")
    a = ap.parse_args()
    files = draw_all()
    if a.check:
        stale = [n for n, body in files.items() if not (a.out / n).exists() or (a.out / n).read_text(encoding="utf-8") != body]
        for n in stale:
            print(f"out of date: {a.out / n}")
        return 1 if stale else 0
    a.out.mkdir(parents=True, exist_ok=True)
    for n, body in files.items():
        (a.out / n).write_text(body, encoding="utf-8", newline="\n")
    print(f"wrote {len(files)} images to {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
